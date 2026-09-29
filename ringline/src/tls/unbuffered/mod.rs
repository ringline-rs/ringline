//! Unbuffered TLS record layer, built on rustls' `UnbufferedConnectionCommon`.
//!
//! Encrypts via `WriteTraffic::encrypt` rather than
//! `writer()`/`write_tls()`. **This engine does not reduce the send-side copy
//! count.** It was built believing it removed a copy into rustls'
//! `sendable_plaintext`; measurement and rustls 0.23.41's source say
//! otherwise, on two counts: `CommonState::send_plain` buffers into
//! `sendable_plaintext` only while `!may_send_application_data` (i.e. before
//! the handshake completes), and `CommonState::write_fragments` seals each
//! record into a freshly allocated `PrefixedPayload` before copying it into
//! the destination. Application data costs 2 copies on either engine. See
//! `docs/tls-unbuffered-design.md`'s top correction block and
//! `docs/journal/2026-09-unbuffered-tls.md` ("Plan 4 — measurement").
//!
//! What the engine is still for: it is the prerequisite for kTLS. rustls'
//! `dangerous_into_kernel_connection` — which yields both the extracted
//! secrets and a `KernelConnection` that can still rekey and absorb session
//! tickets — is public only on `UnbufferedClientConnection` and
//! `UnbufferedServerConnection`. (The older `dangerous_extract_secrets`, which
//! earlier revisions of this comment cited, is `#[deprecated]` and exists on
//! the buffered types too, so it never justified this engine.) It also
//! measures ~4-8% faster on the recv path, which is not a copy-count effect
//! and is not yet explained.
//!
//! Selected per connection by the `tls-unbuffered` feature in
//! `TlsTable::create`, and driven end-to-end on both backends through their
//! dispatcher modules (`super::backend_mio`, `super::backend_uring`). The
//! backends differ only in where the ciphertext lands: a `Vec` on the
//! connection's pending-send FIFO for mio, `SendCopyPool` slots for io_uring
//! (see `docs/journal/2026-09-unbuffered-tls.md`).
//!
//! [`feed`] ingests received ciphertext through
//! [`super::ciphertext::CiphertextBuf`] and runs [`drive`], the
//! `ConnectionState` loop, until it blocks; handshake records and alerts land
//! in the caller's `out` buffer, decrypted plaintext in a [`PlaintextSink`].
//! [`encrypt_to_vec`]/[`encrypt_chunk`] are the send path, and
//! [`queue_close_notify`] the shutdown one.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::pki_types::ServerName;
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};

use super::ciphertext::{CiphertextBuf, INITIAL_SHRINK_TO, MAX_SINGLE_APPEND, MIN_CIPHERTEXT_CAP};
use super::{PlaintextSink, TlsConn};

/// A rustls connection driven through the *unbuffered* API
/// (`process_tls_records` + `WriteTraffic::encrypt`).
pub enum UnbufferedKind {
    Server(UnbufferedServerConnection),
    Client(UnbufferedClientConnection),
}

impl UnbufferedKind {
    pub fn wants_write(&self) -> bool {
        match self {
            UnbufferedKind::Server(c) => c.wants_write(),
            UnbufferedKind::Client(c) => c.wants_write(),
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self {
            UnbufferedKind::Server(c) => c.is_handshaking(),
            UnbufferedKind::Client(c) => c.is_handshaking(),
        }
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            UnbufferedKind::Server(c) => c.alpn_protocol(),
            UnbufferedKind::Client(c) => c.alpn_protocol(),
        }
    }

    pub fn negotiated_cipher_suite(&self) -> Option<rustls::SupportedCipherSuite> {
        match self {
            UnbufferedKind::Server(c) => c.negotiated_cipher_suite(),
            UnbufferedKind::Client(c) => c.negotiated_cipher_suite(),
        }
    }

    pub fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        match self {
            UnbufferedKind::Server(c) => c.protocol_version(),
            UnbufferedKind::Client(c) => c.protocol_version(),
        }
    }

    /// Always `None`: `UnbufferedServerConnection` does not expose the SNI
    /// hostname rustls parsed from the ClientHello — unlike the buffered
    /// `ServerConnection::server_name()`, no equivalent accessor exists on
    /// `UnbufferedServerConnection` or on `CommonState`, which is all that
    /// `UnbufferedConnectionCommon` derefs to (verified against rustls
    /// 0.23.41 source; `server_name()` lives only on the handshake-callback
    /// `ClientHello` type and on the buffered `ServerConnection`). Capturing
    /// SNI for the unbuffered engine would need a `ClientHello` callback on
    /// `ServerConfig` to stash it on `TlsConn` at handshake time — tracked as
    /// follow-on work, out of scope here. See `TlsInfo::sni_hostname` for the
    /// documented limitation this produces.
    pub fn sni_hostname(&self) -> Option<&str> {
        None
    }

    // No `send_close_notify` here: it's buffered-only, not just
    // differently-shaped for this engine. `CommonState::send_close_notify(&mut
    // self)` is unreachable from here at all --
    // `UnbufferedServerConnection`/`UnbufferedClientConnection` `DerefMut`
    // down to `UnbufferedConnectionCommon<Data>`, but
    // `UnbufferedConnectionCommon` implements only `Deref` (not `DerefMut`)
    // to `CommonState` (verified against rustls 0.23.41's `src/conn.rs`),
    // and Rust's deref coercion requires `DerefMut` at every step. This
    // isn't a gap: rustls's unbuffered API expresses close_notify
    // differently on purpose -- `docs/tls-unbuffered-design.md` ("###
    // close_notify") already designs the real mechanism,
    // `WriteTraffic::queue_close_notify(&mut self, outgoing_tls: &mut
    // [u8])`, reachable only from inside the `process_tls_records` state
    // machine. That is what [`queue_close_notify`] below does, and both
    // backends' close paths go through it. `TlsConnKind::send_close_notify`
    // doesn't exist either, for the same reason -- see
    // `buffered::BufferedKind::send_close_notify` and
    // `TlsTable::send_close_notify_queued`, its one caller.
}

/// A TLS connection driven by the unbuffered engine, alongside the state the
/// buffered engine instead keeps inside rustls: the incoming-ciphertext
/// buffer, a stash for plaintext that surfaced on a path with nowhere to put
/// it, and the chunk-sizing cache [`encrypt_chunk`] reads on every send.
pub struct UnbufferedConn {
    kind: UnbufferedKind,
    /// Received ciphertext awaiting `process_tls_records`. Deliberately sized
    /// from the module constants rather than a `Config` knob: the cap only has
    /// to clear `MIN_CIPHERTEXT_CAP`'s no-deadlock floor, and adding public
    /// surface for it would be hard to walk back. Revisit if a rig sweep shows
    /// the cap binding — see `docs/journal/2026-09-unbuffered-tls.md`.
    incoming: CiphertextBuf,
    /// Plaintext popped from `ReadTraffic` while no [`super::PlaintextSink`]
    /// was available (i.e. the send path drove the state machine and found
    /// application data pending). The recv path drains this into the sink
    /// before touching rustls again, so the byte stream keeps its order.
    ///
    /// Expected to stay empty: the recv path always drives until no plaintext
    /// remains. It exists so that a state machine that surprises us loses
    /// throughput, not bytes.
    pending_plaintext: VecDeque<Vec<u8>>,
    /// Largest plaintext slice known to encrypt into one output buffer of
    /// `chunk_basis` bytes. Learned from rustls' `required_size` on the first
    /// `InsufficientSize`, then reused. `0` means "not yet learned".
    max_plaintext_per_chunk: usize,
    /// Output buffer size `max_plaintext_per_chunk` was learned against. A
    /// different size invalidates it.
    ///
    /// One entry, keyed on that size: a connection alternating between two
    /// destination sizes never hits, and pays an `InsufficientSize` round-trip
    /// on every send. Correct, just worthless. It cannot happen today —
    /// `SendCopyPool::alloc_raw` hands back the uniform `slot_size` for every
    /// slot — but `docs/tls-unbuffered-design.md`'s chunk-size open question
    /// floats giving TLS its own slot class, which would introduce exactly
    /// that. Widen the cache then, against the real io_uring shape, not
    /// speculatively now.
    chunk_basis: usize,
}

impl UnbufferedConn {
    pub fn new_server(config: Arc<rustls::ServerConfig>) -> Result<Self, rustls::Error> {
        Ok(Self::wrap(UnbufferedKind::Server(
            UnbufferedServerConnection::new(config)?,
        )))
    }

    pub fn new_client(
        config: Arc<rustls::ClientConfig>,
        server_name: ServerName<'static>,
    ) -> Result<Self, rustls::Error> {
        Ok(Self::wrap(UnbufferedKind::Client(
            UnbufferedClientConnection::new(config, server_name)?,
        )))
    }

    fn wrap(kind: UnbufferedKind) -> Self {
        Self {
            kind,
            incoming: CiphertextBuf::new(INITIAL_SHRINK_TO, MIN_CIPHERTEXT_CAP),
            pending_plaintext: VecDeque::new(),
            max_plaintext_per_chunk: 0,
            chunk_basis: 0,
        }
    }

    /// Test-only: rebuild the incoming-ciphertext buffer with a `cap` below
    /// [`MIN_CIPHERTEXT_CAP`], via [`CiphertextBuf::with_cap_unchecked`], so
    /// [`feed`]'s `WouldBlock` backpressure path becomes reachable. A
    /// conforming peer cannot reach it on a real connection — the floor is
    /// sized to prevent exactly that — which would otherwise leave both the
    /// retry and the anti-spin guard untested.
    ///
    /// Panics if ciphertext is pending: the replacement would silently drop
    /// it, and a test that re-caps mid-stream is measuring nothing.
    #[cfg(test)]
    pub(crate) fn set_ciphertext_cap_for_test(&mut self, initial: usize, cap: usize) {
        assert!(
            self.incoming.is_empty(),
            "re-capping would drop pending ciphertext"
        );
        self.incoming = CiphertextBuf::with_cap_unchecked(initial, cap);
    }

    pub fn kind(&self) -> &UnbufferedKind {
        &self.kind
    }

    /// Borrow the rustls connection, the ciphertext buffer and the deferred
    /// plaintext stash at once. `process_tls_records` borrows the connection
    /// *and* the slice handed to it, so the state machine cannot reach these
    /// through `&mut self` while a `ConnectionState` is alive.
    pub fn split_mut(
        &mut self,
    ) -> (
        &mut UnbufferedKind,
        &mut CiphertextBuf,
        &mut VecDeque<Vec<u8>>,
    ) {
        (
            &mut self.kind,
            &mut self.incoming,
            &mut self.pending_plaintext,
        )
    }
}

/// `process_tls_records` is implemented separately on
/// `UnbufferedConnectionCommon<ClientConnectionData>` and
/// `<ServerConnectionData>` (the shared body is private), and
/// `ConnectionState<'_, '_, Data>` differs between them — so one non-generic
/// function cannot match on both. This trait dispatches once, at the top of
/// [`drive`], and the state machine below monomorphizes over `Data`.
trait UnbufferedEngine {
    type Data;
    fn process<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data>;
}

impl UnbufferedEngine for UnbufferedClientConnection {
    type Data = ClientConnectionData;
    fn process<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(incoming)
    }
}

impl UnbufferedEngine for UnbufferedServerConnection {
    type Data = ServerConnectionData;
    fn process<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(incoming)
    }
}

/// What [`drive`] observed. Mapped to `TlsRecvResult` by the backend wiring.
#[derive(Debug)]
pub(crate) enum DriveOutcome {
    /// The machine ran to a blocking state with nothing else to report.
    Ok,
    /// The handshake completed on this call (edge-triggered, once).
    HandshakeJustCompleted,
    /// The peer sent close_notify, or the connection is fully closed.
    Closed,
    /// Fatal: the connection must be torn down.
    Error(rustls::Error),
}

/// Drive the unbuffered state machine until it blocks.
///
/// Handshake ciphertext (`EncodeTlsData`) is appended to `out`; the caller
/// transmits it in order. Decrypted plaintext goes to `sink` — `None` on the
/// send path, where any plaintext found is stashed on the connection instead
/// (see [`UnbufferedConn::pending_plaintext`]).
///
/// Application data is *not* encrypted here: that is the send path's
/// `WriteTraffic::encrypt`, which writes straight into a pool slot. `out` only
/// ever carries handshake records and alerts.
///
/// When a handshake completion and a close land on the same call, this returns
/// `HandshakeJustCompleted`. That is the same precedence [`fold_outcome`]
/// applies across the chunks of a [`feed`]; its doc comment carries the
/// reasoning, and the rule is stated there alone so the two cannot drift.
pub(crate) fn drive(
    tls_conn: &mut TlsConn,
    mut sink: Option<&mut PlaintextSink<'_>>,
    out: &mut Vec<u8>,
    conn_index: u32,
) -> DriveOutcome {
    let was_handshaking = !tls_conn.handshake_complete;

    // Anything stashed by an earlier sink-less drive comes out first, so the
    // application sees one ordered byte stream.
    if let Some(s) = sink.as_deref_mut()
        && !drain_pending_plaintext(tls_conn, s, conn_index)
    {
        return DriveOutcome::Error(rustls::Error::General(
            "recv accumulator limit exceeded".into(),
        ));
    }

    let Some(conn) = tls_conn.conn.as_unbuffered_mut() else {
        return DriveOutcome::Error(rustls::Error::General(
            "connection not driven by the unbuffered TLS engine".into(),
        ));
    };
    let (kind, incoming, pending) = conn.split_mut();

    // `sink` moves into whichever arm runs — the arms are exclusive, so no
    // reborrow is needed here.
    let (outcome, peer_closed) = match kind {
        UnbufferedKind::Server(c) => drive_inner(c, incoming, pending, sink, out, conn_index),
        UnbufferedKind::Client(c) => drive_inner(c, incoming, pending, sink, out, conn_index),
    };

    if peer_closed {
        tls_conn.peer_sent_close_notify = true;
    }
    if matches!(outcome, DriveOutcome::Error(_)) {
        return outcome;
    }
    if was_handshaking && !tls_conn.conn.is_handshaking() {
        tls_conn.handshake_complete = true;
        return DriveOutcome::HandshakeJustCompleted;
    }
    outcome
}

/// The state machine proper, monomorphized per connection role.
///
/// Returns the outcome plus whether the peer's close_notify was observed (the
/// caller owns `TlsConn`'s flags; this function only sees the rustls half).
fn drive_inner<C: UnbufferedEngine>(
    conn: &mut C,
    incoming: &mut CiphertextBuf,
    pending: &mut VecDeque<Vec<u8>>,
    mut sink: Option<&mut PlaintextSink<'_>>,
    out: &mut Vec<u8>,
    conn_index: u32,
) -> (DriveOutcome, bool) {
    let mut peer_closed = false;
    let mut closed = false;
    let mut sink_overflow = false;

    loop {
        let status = conn.process(incoming.pending());
        let mut discard = status.discard;
        // `blocked` means the machine cannot progress without more input from
        // the peer or another call from us; that is the loop's exit condition.
        let mut blocked = false;
        let mut error: Option<rustls::Error> = None;

        match status.state {
            Err(e) => {
                error = Some(e);
            }
            Ok(ConnectionState::ReadTraffic(mut rt)) => {
                while let Some(record) = rt.next_record() {
                    match record {
                        Ok(r) => {
                            // rustls' contract: this is *additional* discard on
                            // top of `UnbufferedStatus::discard`. Zero in
                            // 0.23.41; honoured so an in-place-decryption
                            // release does not silently desynchronise us.
                            discard += r.discard;
                            // Overflow drops this record where the `None` arm
                            // below would stash it: `status.discard` was fixed
                            // before the loop, so the ciphertext is gone either
                            // way, and overflow returns `Error` — teardown, no
                            // retry. Stashing would only defer bytes nobody
                            // will read.
                            match sink.as_deref_mut() {
                                Some(PlaintextSink::Accumulator(accs)) => {
                                    if !accs.append(conn_index, r.payload) {
                                        sink_overflow = true;
                                        break;
                                    }
                                }
                                #[cfg(has_io_uring)]
                                Some(PlaintextSink::Segments {
                                    hold,
                                    outstanding,
                                    max,
                                }) => {
                                    if outstanding.saturating_add(r.payload.len()) > *max {
                                        sink_overflow = true;
                                        break;
                                    }
                                    hold.push_back(crate::backend::HeldRecvBuf::Owned(
                                        bytes::Bytes::copy_from_slice(r.payload),
                                    ));
                                    *outstanding += r.payload.len();
                                }
                                None => pending.push_back(r.payload.to_vec()),
                            }
                        }
                        Err(e) => {
                            error = Some(e);
                            break;
                        }
                    }
                }
            }
            Ok(ConnectionState::EncodeTlsData(mut enc)) => {
                // `encode` is all-or-nothing and needs one contiguous buffer,
                // which can exceed a send-pool slot — hence the scratch `Vec`.
                // Handshake-only; the data path never comes through here.
                let start = out.len();
                let mut room = out.capacity().saturating_sub(start).max(1024);
                loop {
                    out.resize(start + room, 0);
                    match enc.encode(&mut out[start..]) {
                        Ok(n) => {
                            out.truncate(start + n);
                            break;
                        }
                        Err(EncodeError::InsufficientSize(need)) => {
                            room = need.required_size;
                        }
                        Err(e) => {
                            out.truncate(start);
                            error = Some(rustls::Error::General(e.to_string()));
                            break;
                        }
                    }
                }
            }
            Ok(ConnectionState::TransmitTlsData(mut transmit)) => {
                // Everything encoded so far is in `out`, and the caller queues
                // `out` through the per-connection send queue before any later
                // record — so from rustls' point of view it is transmitted.
                // `may_encrypt_app_data` is deliberately not consulted:
                // ringline exposes no early-data API, so there is never app
                // data waiting at this point.
                let _ = transmit.may_encrypt_app_data();
                transmit.done();
            }
            Ok(ConnectionState::BlockedHandshake) => blocked = true,
            Ok(ConnectionState::WriteTraffic(_)) => blocked = true,
            Ok(ConnectionState::PeerClosed) => {
                peer_closed = true;
            }
            Ok(ConnectionState::Closed) => {
                closed = true;
                blocked = true;
            }
            Ok(ConnectionState::ReadEarlyData(_)) => {
                // Ringline exposes no 0-RTT API. Treated as a protocol error
                // rather than silently dropped, per the design doc.
                error = Some(rustls::Error::General(
                    "TLS early data received but not supported".into(),
                ));
            }
            // `ConnectionState` is `#[non_exhaustive]`: a rustls upgrade can
            // introduce a state this loop does not know how to service.
            // Failing the connection beats spinning on it forever.
            Ok(_) => {
                error = Some(rustls::Error::General(
                    "unhandled rustls unbuffered connection state".into(),
                ));
            }
        }

        // `status` is dead here, so the ciphertext buffer is free again.
        incoming.discard(discard);

        if let Some(e) = error {
            return (DriveOutcome::Error(e), peer_closed);
        }
        if sink_overflow {
            return (
                DriveOutcome::Error(rustls::Error::General(
                    "recv accumulator limit exceeded".into(),
                )),
                peer_closed,
            );
        }
        if blocked {
            break;
        }
    }

    if closed || peer_closed {
        (DriveOutcome::Closed, peer_closed)
    } else {
        (DriveOutcome::Ok, peer_closed)
    }
}

/// Fold a chunk's outcome into the running one. Edge-triggered signals must
/// survive later chunks of the same feed, so this is a rank, not "last wins":
///
///   Error > HandshakeJustCompleted > Closed > Ok
///
/// `HandshakeJustCompleted` outranks `Closed` because the backends act on it
/// to wake a connect waiter (`wake_connect`) or spawn the accept task, while
/// the `Closed` arm does neither and `close_connection` does not wake connect
/// waiters either — so dropping the completion edge hangs an outbound TLS
/// connect until its timeout. A peer can produce both in one feed by putting
/// its last handshake flight and a close_notify in the same segment. The close
/// is not lost: `peer_sent_close_notify` is set, so the following FIN reads as
/// a clean close rather than a truncation.
///
/// `Error` outranks everything, though `feed` returns early on it today.
fn fold_outcome(last: DriveOutcome, next: DriveOutcome) -> DriveOutcome {
    fn rank(o: &DriveOutcome) -> u8 {
        match o {
            DriveOutcome::Ok => 0,
            DriveOutcome::Closed => 1,
            DriveOutcome::HandshakeJustCompleted => 2,
            DriveOutcome::Error(_) => 3,
        }
    }
    if rank(&next) >= rank(&last) {
        next
    } else {
        last
    }
}

/// Append received ciphertext and drive the state machine over it.
///
/// `ciphertext` is chunked at [`MAX_SINGLE_APPEND`]: `CiphertextBuf::append`
/// `debug_assert`s that bound (silent in release), and it is reachable from
/// public config — `ConfigBuilder::recv_buffer` accepts buffer sizes above
/// 64 KiB and the io_uring recv path hands one whole provided buffer here.
///
/// `append` is all-or-nothing and returns `WouldBlock` when the buffer holds
/// only live data. That is backpressure, not an error: drive first (which
/// discards what rustls consumed), then retry. If a drive frees nothing and
/// the append still refuses, the connection is unrecoverable — `append` would
/// otherwise be retried forever. `MIN_CIPHERTEXT_CAP` is sized so this cannot
/// happen for a conforming peer; the check is what stops a non-conforming one
/// from spinning the worker.
pub(crate) fn feed(
    tls_conn: &mut TlsConn,
    mut sink: Option<&mut PlaintextSink<'_>>,
    out: &mut Vec<u8>,
    ciphertext: &[u8],
    conn_index: u32,
) -> DriveOutcome {
    let mut last = DriveOutcome::Ok;
    for chunk in ciphertext.chunks(MAX_SINGLE_APPEND) {
        loop {
            let Some(conn) = tls_conn.conn.as_unbuffered_mut() else {
                return DriveOutcome::Error(rustls::Error::General(
                    "connection not driven by the unbuffered TLS engine".into(),
                ));
            };
            let (_, incoming, _) = conn.split_mut();
            let before = incoming.len();
            match incoming.append(chunk) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Drain, then retry. Each retry requires the drive to have
                    // strictly shrunk the live set, so the loop terminates; a
                    // drive that frees nothing means the buffer is full of data
                    // rustls will not consume.
                    let outcome = drive(tls_conn, sink.as_deref_mut(), out, conn_index);
                    if let DriveOutcome::Error(err) = outcome {
                        return DriveOutcome::Error(err);
                    }
                    let (_, incoming, _) = tls_conn
                        .conn
                        .as_unbuffered_mut()
                        .expect("engine checked above")
                        .split_mut();
                    if incoming.len() >= before {
                        return DriveOutcome::Error(rustls::Error::General(
                            "TLS ciphertext buffer full and undrainable".into(),
                        ));
                    }
                    last = fold_outcome(last, outcome);
                }
                Err(e) => {
                    return DriveOutcome::Error(rustls::Error::General(e.to_string()));
                }
            }
        }
        let outcome = drive(tls_conn, sink.as_deref_mut(), out, conn_index);
        if matches!(outcome, DriveOutcome::Error(_)) {
            return outcome;
        }
        last = fold_outcome(last, outcome);
    }
    // An empty feed is a deliberate flush, not a no-op: `chunks()` yields
    // nothing for an empty slice, so without this the loop body never runs and
    // the machine is never driven. Callers rely on it to make an idle
    // connection emit — a fresh client has a ClientHello waiting with no input
    // to deframe, which is exactly how the backends kick off an outbound
    // handshake once the TCP connect completes.
    if ciphertext.is_empty() {
        return drive(tls_conn, sink, out, conn_index);
    }
    last
}

/// Smallest destination buffer worth attempting. Below roughly this size the
/// per-record overhead (5-byte header plus the AEAD tag, and on TLS 1.2 an
/// explicit nonce) leaves too little room for the shrink loop to converge on:
/// it would walk the chunk down to zero and fail anyway, so the caller is told
/// straight away instead.
const MIN_ENCRYPT_DST: usize = 64;

/// RFC 8446's maximum `TLSPlaintext.length`: 2^14 bytes of plaintext in one
/// record. This is a protocol constant, not a tuning knob — handing rustls
/// more plaintext than this in a single `encrypt` call cannot produce a larger
/// record, it just makes rustls fragment internally and emit more than one.
/// rustls has the same value as `msgs::fragmenter::MAX_FRAGMENT_LEN`, but it
/// is `pub(crate)` there, so ringline carries its own.
const MAX_FRAGMENT_LEN: usize = 16384;

/// Wire size of one maximum-size TLS 1.3 record: 5-byte record header,
/// [`MAX_FRAGMENT_LEN`] of plaintext, the inner content-type byte, and a
/// 16-byte AEAD tag — 16406 bytes.
///
/// Deliberately *not* derived from `MAX_TLS_WIRE_RECORD` (18437), which is the
/// conservative bound on a record we must be prepared to **receive** and
/// carries 2 KiB of slack for TLS 1.2's explicit nonce. Sizing anything we
/// **emit** from that number has produced three separate wrong answers in this
/// area already.
///
/// 16 is the tag length of every TLS 1.3 suite rustls offers, so this is exact
/// for the suites reachable here. It is only ever used to pick the *starting*
/// chunk in [`encrypt_chunk`]; if a future suite made it an underestimate, the
/// `InsufficientSize` retry loop would still converge, just after one extra
/// attempt. Correctness never depends on it.
const MAX_RECORD_WIRE_LEN: usize = 5 + MAX_FRAGMENT_LEN + 1 + 16;

/// Encrypt as much of `plaintext` as fits in `dst`, in one or more TLS
/// records. Returns `(plaintext_consumed, ciphertext_written)`.
///
/// This was believed to remove a copy relative to the buffered engine. **It
/// does not.** rustls 0.23.41's `write_fragments` seals every fragment into a
/// freshly allocated `PrefixedPayload` and then `copy_from_slice`s the record
/// into `dst`, so this path is plaintext -> per-record buffer -> `dst`, the
/// same two passes the buffered engine pays. The `sendable_plaintext` copy it
/// was meant to skip does not happen on an established connection either:
/// `CommonState::send_plain` buffers there only while
/// `!may_send_application_data`. See `docs/tls-unbuffered-design.md`'s top
/// correction block.
///
/// `encrypt` is all-or-nothing on its output: too small a buffer writes
/// nothing and reports `required_size` for the payload it was handed. The
/// chunk size is therefore shrunk from that report — never from a hardcoded
/// record overhead, which differs between TLS 1.2 (explicit nonce) and TLS 1.3
/// (content-type byte). The converged size is cached on the connection so
/// steady-state sends do not pay the retry.
///
/// `dst` also carries any TLS records rustls had queued for sending — a
/// TLS 1.3 `key_update`, most notably: `write_plaintext` drains `sendable_tls`
/// into the front of `outgoing_tls` ahead of the application-data fragments,
/// and sizes `required_size` to include them (verified against rustls
/// 0.23.41's `CommonState::{check_required_size, write_fragments}`). So the
/// caller need only transmit `dst` in order; there is no second stream to
/// interleave, and `ciphertext_written` can exceed what this chunk's own
/// records account for.
pub(crate) fn encrypt_chunk(
    tls_conn: &mut TlsConn,
    plaintext: &[u8],
    dst: &mut [u8],
) -> io::Result<(usize, usize)> {
    if plaintext.is_empty() {
        return Ok((0, 0));
    }
    if dst.len() < MIN_ENCRYPT_DST {
        return Err(io::Error::other(
            "TLS destination buffer too small to hold one record",
        ));
    }
    let conn = tls_conn
        .conn
        .as_unbuffered_mut()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;

    let hint = if conn.chunk_basis == dst.len() && conn.max_plaintext_per_chunk > 0 {
        conn.max_plaintext_per_chunk
    } else {
        // Start from the largest whole number of maximum-size records `dst`
        // can hold, not from `dst.len()`.
        //
        // Asking for `dst.len()` bytes of plaintext always overshoots, because
        // the ciphertext is larger than the plaintext: rustls fragments the
        // request, reports `required_size`, and the retry loop scales the chunk
        // down *proportionally* — which lands just under a fragment boundary
        // rather than on it. At the 16384-byte default slot that caches 16362,
        // so a 256 KiB send is split into 17 records where the buffered engine
        // emits 16. Worse, for any `dst` in (16428, 2 * MAX_RECORD_WIRE_LEN)
        // the loop converges on a chunk spanning a full record *plus a sliver*,
        // doubling the record count outright (31 records for 256 KiB at a
        // 16512-byte slot).
        //
        // Whole records avoid both: `whole * MAX_FRAGMENT_LEN` of plaintext
        // encrypts to exactly `whole * MAX_RECORD_WIRE_LEN` of ciphertext,
        // which fits by construction, so the common case needs no retry at all
        // and each call fills `dst` with none of it wasted on a sliver record.
        //
        // `whole == 0` means `dst` cannot hold even one full record — the
        // 16384-byte default slot is exactly this case, missing it by 22
        // bytes. There is no whole-record answer, so fall back to the previous
        // behaviour and let the retry loop find the largest chunk that fits.
        let whole = dst.len() / MAX_RECORD_WIRE_LEN;
        if whole == 0 {
            dst.len()
        } else {
            whole * MAX_FRAGMENT_LEN
        }
    };
    let mut chunk = plaintext.len().min(hint.max(1));

    // Set only when rustls actually made us shrink. A short final send would
    // otherwise cache its own tiny size as the connection's ceiling and every
    // later send would start from there. The cache only ever shrinks for a
    // given `dst` size, so a one-off inflation of `required_size` — a queued
    // `key_update` riding along in the same buffer — leaves it slightly
    // pessimistic until `dst` changes. That costs a few bytes per record, not
    // correctness.
    let mut learned: Option<usize> = None;

    let (kind, incoming, _) = conn.split_mut();
    let (result, peer_closed) = match kind {
        UnbufferedKind::Server(c) => {
            encrypt_with(c, incoming, plaintext, dst, &mut chunk, &mut learned)
        }
        UnbufferedKind::Client(c) => {
            encrypt_with(c, incoming, plaintext, dst, &mut chunk, &mut learned)
        }
    };
    // Recorded before the `?`: the edge is consumed either way, and an
    // encrypt that fails on a closed connection still owes the flag.
    if peer_closed {
        tls_conn.peer_sent_close_notify = true;
    }
    let written = result?;

    if let Some(learned) = learned {
        let conn = tls_conn
            .conn
            .as_unbuffered_mut()
            .expect("engine checked above");
        conn.chunk_basis = dst.len();
        conn.max_plaintext_per_chunk = learned;
    }
    Ok((chunk, written))
}

/// Obtain `WriteTraffic` and encrypt, shrinking `chunk` until the ciphertext
/// fits `dst`. Returns bytes written into `dst`.
///
/// The state machine is entered exactly once and the retries reuse the same
/// `WriteTraffic`. Re-entering `process_tls_records` between attempts would be
/// wrong, not just wasteful: a failed `encrypt` has already moved a queued
/// `key_update` reply into `sendable_tls` (`write_plaintext` calls
/// `perhaps_write_key_update` before `check_required_size`), so the next
/// `process_tls_records` would hand back `EncodeTlsData` instead of
/// `WriteTraffic` and the retry would fail the send. Holding the state means
/// the successful attempt flushes that record into `dst` itself.
fn encrypt_with<C: UnbufferedEngine>(
    conn: &mut C,
    incoming: &mut CiphertextBuf,
    plaintext: &[u8],
    dst: &mut [u8],
    chunk: &mut usize,
    learned: &mut Option<usize>,
) -> (io::Result<usize>, bool) {
    let mut peer_closed = false;
    let status = conn.process(incoming.pending());
    let discard = status.discard;
    let result = match status.state {
        Ok(ConnectionState::WriteTraffic(mut wt)) => loop {
            match wt.encrypt(&plaintext[..*chunk], dst) {
                Ok(n) => break Ok(n),
                Err(EncryptError::InsufficientSize(need)) => {
                    // Scale down proportionally, and always shrink by at least
                    // one byte so the loop cannot stall.
                    let scaled = chunk
                        .saturating_mul(dst.len())
                        .checked_div(need.required_size.max(1))
                        .unwrap_or(0);
                    let next = scaled.min(chunk.saturating_sub(1));
                    if next == 0 {
                        break Err(io::Error::other(
                            "TLS destination buffer too small to hold one record",
                        ));
                    }
                    *chunk = next;
                    *learned = Some(next);
                }
                // Narrower than it looks: TLS 1.3 key exhaustion queues a
                // `key_update` and keeps going, so this is only reached when
                // the record layer refuses outright (or on TLS 1.2, which
                // cannot rekey). Either way the connection is finished — there
                // is no smaller payload that would succeed.
                Err(EncryptError::EncryptExhausted) => {
                    break Err(io::Error::other(
                        "TLS traffic keys exhausted; connection must close",
                    ));
                }
            }
        },
        // `EncodeTlsData` is destructive to *construct*: `process_tls_records`
        // pops the record out of `sendable_tls` and moves it into this value
        // (rustls 0.23.41 `conn/unbuffered.rs`), and never puts it back. So
        // letting it fall into the catch-all below would drop a queued TLS
        // record permanently while reporting a bland `WouldBlock`. Encoding it
        // into `dst` is not the alternative: `dst` is an application-data pool
        // slot mid-stream, and a handshake record written there reorders the
        // wire. ringline's own call sites cannot reach this — a `ConnCtx` is
        // only handed out once the handshake completes, and any successful
        // `drive` leaves `sendable_tls` empty — but the engine is one direct
        // call away from it, so the arm is explicit rather than
        // assumed-unreachable. The catch-all is what made the hazard invisible.
        Ok(ConnectionState::EncodeTlsData(_)) => Err(io::Error::other(
            "a queued TLS record was dropped by the encrypt path",
        )),
        // `PeerClosed` is edge-triggered (`emitted_peer_closed_state`): if this
        // `process` is the call that deframes the peer's close_notify, nothing
        // else will ever report it. Hand it up so the caller can set
        // `peer_sent_close_notify` — swallowing it turns the following FIN into
        // a spurious truncation report, a false security signal.
        Ok(ConnectionState::PeerClosed) => {
            peer_closed = true;
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TLS connection not ready to encrypt application data",
            ))
        }
        // Genuinely benign for this path: `BlockedHandshake`,
        // `TransmitTlsData`, `ReadTraffic`, `Closed`, `ReadEarlyData`, and
        // whatever `#[non_exhaustive]` adds next. The send path never sees
        // these for a handshaked connection (ringline only hands out a ConnCtx
        // after the handshake completes), so this is a guard, not a workflow.
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "TLS connection not ready to encrypt application data",
        )),
        Err(e) => Err(io::Error::other(e)),
    };
    incoming.discard(discard);
    (result, peer_closed)
}

/// Encrypt all of `plaintext`, appending ciphertext to `out`. The mio backend
/// and the unit tests use this; io_uring drives [`encrypt_chunk`] directly
/// against a pool slot instead (`super::backend_uring::encrypt_to_sends`) —
/// which is the whole point of the engine, so an io_uring lib build has no
/// non-test caller for this and the allow is scoped to exactly that.
#[cfg_attr(has_io_uring, allow(dead_code))]
pub(crate) fn encrypt_to_vec(
    tls_conn: &mut TlsConn,
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> io::Result<()> {
    // One record's worth of destination per call: large enough that the
    // fragmenter amortizes its per-call setup, small enough that a failed
    // shrink is cheap. Chunk size is an internal knob by design — see
    // docs/tls-unbuffered-design.md, open question 1.
    const DST: usize = 32 * 1024;
    let mut offset = 0;
    while offset < plaintext.len() {
        let start = out.len();
        // The zero-fill is redundant work: rustls writes the whole `used_ct`
        // prefix before anything reads it, and the tail is truncated away. It
        // costs roughly one extra pass over the payload, on a path whose point
        // is removing a pass over the payload — but this function backs the
        // mio path and the tests only. io_uring encrypts into pool slots and
        // never comes through here, so the backend this effort targets does
        // not pay it. Removing it means `reserve` + `set_len` and an
        // accompanying safety argument; that trade is not worth taking on an
        // unmeasured cost on the non-target backend. The chunk-size sweep in
        // `docs/tls-unbuffered-design.md`'s open questions is what would
        // measure it.
        out.resize(start + DST, 0);
        // Every exit below trims `out` back: on failure the caller must not be
        // handed the zeroed scratch this resize appended.
        let (used_pt, used_ct) =
            match encrypt_chunk(tls_conn, &plaintext[offset..], &mut out[start..]) {
                Ok(used) => used,
                Err(e) => {
                    out.truncate(start);
                    return Err(e);
                }
            };
        if used_pt == 0 {
            out.truncate(start);
            return Err(io::Error::other("TLS encryption made no progress"));
        }
        out.truncate(start + used_ct);
        offset += used_pt;
    }
    Ok(())
}

/// Encrypt a close_notify alert, appending it to `out`.
///
/// The caller routes `out` through the per-connection send queue, so the alert
/// serializes behind any in-flight send and the deferred Close fires only once
/// it completes — identical to the buffered path's contract, and to the
/// `close_notify_timeout_ms` deadline armed alongside it.
///
/// The unbuffered engine has no `send_close_notify`: `CommonState`'s is
/// unreachable from `UnbufferedConnectionCommon` (`Deref` but no `DerefMut`),
/// and rustls expresses the operation as `WriteTraffic::queue_close_notify`
/// instead — reachable only from inside the `process_tls_records` state
/// machine. See `UnbufferedKind`'s note and `docs/tls-unbuffered-design.md`
/// ("### close_notify").
///
/// A connection that never reached traffic state, or that is already closed,
/// has nothing to queue: `out` is left untouched and `close_notify_sent` stays
/// false. That is not an error — the caller is tearing the connection down
/// either way, and arming the close-notify deadline for an alert that was
/// never sent would only invent a stall to time out on.
pub(crate) fn queue_close_notify(tls_conn: &mut TlsConn, out: &mut Vec<u8>) -> io::Result<()> {
    let conn = tls_conn
        .conn
        .as_unbuffered_mut()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let (kind, incoming, _) = conn.split_mut();
    let (result, peer_closed) = match kind {
        UnbufferedKind::Server(c) => close_notify_with(c, incoming, out),
        UnbufferedKind::Client(c) => close_notify_with(c, incoming, out),
    };
    // Recorded before the `?`, as in `encrypt_chunk`: the edge is consumed
    // whatever the result, and a teardown that loses it makes the FIN it is
    // about to send look like a truncation to nobody's benefit.
    if peer_closed {
        tls_conn.peer_sent_close_notify = true;
    }
    let written = result?;
    if written > 0 {
        tls_conn.close_notify_sent = true;
    }
    Ok(())
}

/// Obtain `WriteTraffic` and queue a close_notify into `out`. Returns the
/// bytes appended.
///
/// Like `encrypt`, `queue_close_notify` is all-or-nothing on its output: too
/// small a buffer writes nothing and reports the exact `required_size`. So the
/// first attempt deliberately offers *no* room and takes rustls' answer, rather
/// than guessing a size that would be either wrong or needlessly padded — the
/// alert's wire length depends on the negotiated cipher suite and TLS version.
/// `required_size` is strictly greater than the buffer that was refused, so the
/// retry loop cannot fail to make progress.
///
/// The state machine is entered exactly once and the retry reuses the same
/// `WriteTraffic`, for the same reason [`encrypt_with`] does — more sharply
/// here: `eager_send_close_notify` queues the alert into `sendable_tls` *before*
/// it checks the size, so a re-entered `process_tls_records` would find that
/// queue non-empty and hand back `EncodeTlsData` instead of `WriteTraffic`,
/// and the retry would silently report "nothing to queue" with the alert
/// stranded inside rustls (verified against rustls 0.23.41's
/// `CommonState::eager_send_close_notify` and `process_tls_records_common`).
///
/// Anything rustls had already queued for sending rides out in `out` ahead of
/// the alert, because `write_fragments` drains `sendable_tls` into the front of
/// the destination and `check_required_size` reserves the room for it. So `out`
/// is transmitted as-is; there is nothing to flush afterwards, and driving the
/// machine again to look would emit those records *after* the alert on the
/// wire.
fn close_notify_with<C: UnbufferedEngine>(
    conn: &mut C,
    incoming: &mut CiphertextBuf,
    out: &mut Vec<u8>,
) -> (io::Result<usize>, bool) {
    let mut peer_closed = false;
    let start = out.len();
    let status = conn.process(incoming.pending());
    let discard = status.discard;
    let result = match status.state {
        Ok(ConnectionState::WriteTraffic(mut wt)) => {
            let mut room = 0;
            loop {
                out.resize(start + room, 0);
                match wt.queue_close_notify(&mut out[start..]) {
                    Ok(n) => break Ok(n),
                    Err(EncryptError::InsufficientSize(need)) => room = need.required_size,
                    Err(e) => break Err(io::Error::other(e.to_string())),
                }
            }
        }
        // Destructive to construct, and dropping it discards the record for
        // good — see the matching arm in [`encrypt_with`] for the rustls
        // reference. It bites harder here: on TLS 1.2 traffic-key exhaustion
        // `write_plaintext` calls `send_close_notify()` itself before returning
        // `EncryptExhausted` (rustls 0.23.41 `common_state.rs`), so the alert
        // this function exists to send can already be sitting in
        // `sendable_tls`. The old catch-all popped it, dropped it and returned
        // `Ok(0)`, leaving `close_notify_sent` false and the peer with a bare
        // FIN. Encoding it into `out` is deliberately *not* the fix: this
        // function enters the state machine exactly once on purpose (see
        // above), so servicing an encode would mean re-entering it and
        // stranding the alert — the failure this design already avoids.
        // Named rather than swallowed; see the test.
        Ok(ConnectionState::EncodeTlsData(_)) => Err(io::Error::other(
            "a queued TLS record was dropped by the close_notify path",
        )),
        // Edge-triggered; see [`encrypt_with`]. Still "nothing to queue" —
        // a closed connection has no alert to send — but the edge goes up.
        Ok(ConnectionState::PeerClosed) => {
            peer_closed = true;
            Ok(0)
        }
        // Already closed, or never reached traffic state: nothing to queue.
        Ok(_) => Ok(0),
        Err(e) => Err(io::Error::other(e)),
    };
    // `status` is dead here, so the ciphertext buffer is free again.
    incoming.discard(discard);
    let result = match result {
        Ok(n) => {
            out.truncate(start + n);
            Ok(n)
        }
        Err(e) => {
            out.truncate(start);
            Err(e)
        }
    };
    (result, peer_closed)
}

/// Move any stashed plaintext into `sink`, oldest first. Returns `false` if
/// the sink hit its bound — the chunk is left in the stash and the caller must
/// kill the connection, matching `drain_tls_plaintext`'s contract.
fn drain_pending_plaintext(
    tls_conn: &mut TlsConn,
    sink: &mut PlaintextSink<'_>,
    conn_index: u32,
) -> bool {
    let Some(conn) = tls_conn.conn.as_unbuffered_mut() else {
        return true;
    };
    let (_, _, pending) = conn.split_mut();
    while let Some(chunk) = pending.front() {
        match sink {
            PlaintextSink::Accumulator(accs) => {
                if !accs.append(conn_index, chunk) {
                    return false;
                }
            }
            #[cfg(has_io_uring)]
            PlaintextSink::Segments {
                hold,
                outstanding,
                max,
            } => {
                if outstanding.saturating_add(chunk.len()) > *max {
                    return false;
                }
                hold.push_back(crate::backend::HeldRecvBuf::Owned(
                    bytes::Bytes::copy_from_slice(chunk),
                ));
                *outstanding += chunk.len();
            }
        }
        pending.pop_front();
    }
    true
}

#[cfg(test)]
pub(crate) mod tests;
