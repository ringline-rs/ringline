//! TLS support.
//!
//! Shared types live here; the record-layer implementation lives in the engine
//! submodules. `buffered` drives rustls' buffered `Connection` API
//! (`read_tls`/`process_new_packets`/`write_tls`).
//!
//! `TlsConnKind` is tagged by engine: [`TlsConnKind::Buffered`] wraps
//! [`buffered::BufferedKind`], which carries the buffered-only surface
//! (`read_tls`/`write_tls`/`process_new_packets`/`reader`/`writer`/
//! `send_close_notify`). `send_close_notify` lives there rather than on
//! `TlsConnKind` because it isn't actually `CommonState`-reachable from the
//! unbuffered connection types (`UnbufferedConnectionCommon` derefs to
//! `CommonState` but doesn't `DerefMut` to it) — a shared-looking method
//! name that turned out to be buffered-only once checked against rustls
//! 0.23.41, the same way `read_tls` et al. are. `TlsConnKind` itself keeps
//! only the methods rustls exposes through `CommonState` and that are
//! actually reachable that way from every engine's connection type — so the
//! feature-gated [`TlsConnKind::Unbuffered`] variant (wrapping
//! [`unbuffered::UnbufferedConn`]) adds a match arm to those, rather than
//! forcing every caller to unwrap an engine first.
//!
//! Which engine drives a connection is decided once, in
//! [`TlsTable::create`]/[`TlsTable::create_client`]: the unbuffered engine,
//! unless the `tls-buffered` cargo feature selects the buffered one. Backends
//! never see that choice: `backend_mio` and `backend_uring` each dispatch their
//! backend's entry points to whichever engine is compiled in, keeping the names
//! and signatures the backend already called. `drain_tls_plaintext` below is
//! the buffered engine's plaintext drain and is reached only from `buffered`
//! (the unbuffered engine drains `ReadTraffic` itself); it is not an
//! engine-agnostic helper despite living here.

#[allow(unused_imports)]
use std::io::{self, Read as _, Write as _};
use std::sync::Arc;

use ringline_tls::pki_types::ServerName;
// Only the buffered engine constructs these directly; the unbuffered build
// reaches rustls through `unbuffered::UnbufferedConn` instead.
#[cfg(feature = "tls-buffered")]
use ringline_tls::{ClientConnection, ServerConnection};

#[allow(unused_imports)]
use crate::accumulator::AccumulatorTable;
#[cfg(has_io_uring)]
#[allow(unused_imports)]
use crate::buffer::send_copy::SendCopyPool;

#[cfg(not(has_io_uring))]
mod backend_mio;
#[cfg(has_io_uring)]
mod backend_uring;
pub(crate) mod buffered;
// The incoming-ciphertext buffer belongs to the unbuffered engine and has no
// other consumer, so it shares the engine's gate; under `tls-buffered` every
// item in the module would be dead code.
#[cfg(not(feature = "tls-buffered"))]
mod ciphertext;
#[cfg(not(feature = "tls-buffered"))]
pub(crate) mod unbuffered;

// Glob re-export keeps call sites at `crate::tls::*`. Both backends' shared
// names now live in their dispatcher module; nothing is re-exported from
// `buffered`, whose halves are all `pub(super)` under `*_buffered` names and
// reachable only from the dispatcher that picks between the engines.
#[cfg(not(has_io_uring))]
pub use backend_mio::*;
#[cfg(has_io_uring)]
pub use backend_uring::*;

/// Information about a negotiated TLS session.
pub struct TlsInfo {
    pub(crate) protocol_version: Option<ringline_tls_config::TlsVersion>,
    pub(crate) cipher_suite: Option<ringline_tls_config::CipherSuite>,
    pub(crate) alpn_protocol: Option<Vec<u8>>,
    pub(crate) sni_hostname: Option<String>,
}

impl TlsInfo {
    /// The negotiated TLS protocol version, if the handshake has completed.
    pub fn protocol_version(&self) -> Option<ringline_tls_config::TlsVersion> {
        self.protocol_version
    }

    /// The negotiated cipher suite, if the handshake has completed. A suite
    /// [`CipherSuite`](ringline_tls_config::CipherSuite) does not name is
    /// [`CipherSuite::Unknown`](ringline_tls_config::CipherSuite::Unknown)
    /// with its IANA code.
    pub fn cipher_suite(&self) -> Option<ringline_tls_config::CipherSuite> {
        self.cipher_suite
    }

    /// The ALPN protocol negotiated for this session, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol.as_deref()
    }

    /// The SNI hostname the peer requested, if any, on a server connection.
    pub fn sni_hostname(&self) -> Option<&str> {
        self.sni_hostname.as_deref()
    }
}

/// A TLS connection, tagged by which record-layer engine drives it.
///
/// Engine-specific surface lives on the inner kinds, so the compiler rejects
/// (say) `read_tls` on an unbuffered connection rather than leaving it a
/// runtime surprise. Only operations rustls exposes through `CommonState` --
/// which both engine families `Deref` to -- stay on this enum.
pub enum TlsConnKind {
    /// Never constructed in a build without `tls-buffered` — see
    /// [`buffered::BufferedKind`] for why the allow is scoped this narrowly.
    #[cfg_attr(not(feature = "tls-buffered"), allow(dead_code))]
    Buffered(buffered::BufferedKind),
    #[cfg(not(feature = "tls-buffered"))]
    Unbuffered(unbuffered::UnbufferedConn),
}

impl TlsConnKind {
    /// The buffered connection, or `None` if another engine drives this one.
    ///
    /// `Some` for every connection when only the buffered engine is
    /// compiled in (`tls-buffered`); `None` for an unbuffered-engine
    /// connection otherwise. Do not collapse this to an infallible accessor.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "unconditionally Some with the tls-buffered feature; kept fallible so both configurations share one signature"
    )]
    pub fn as_buffered_mut(&mut self) -> Option<&mut buffered::BufferedKind> {
        match self {
            Self::Buffered(k) => Some(k),
            #[cfg(not(feature = "tls-buffered"))]
            Self::Unbuffered(_) => None,
        }
    }

    /// The unbuffered connection, or `None` if another engine drives this one.
    ///
    /// Only compiled in a build without `tls-buffered`, where `TlsTable::create`
    /// selects this engine for every connection — so the `Buffered` arm is
    /// unreachable in practice today. It is still spelled out rather than
    /// assumed: that build keeps both variants, and both backend dispatchers
    /// route on the engine tag rather than on the feature alone.
    #[cfg(not(feature = "tls-buffered"))]
    pub fn as_unbuffered_mut(&mut self) -> Option<&mut unbuffered::UnbufferedConn> {
        match self {
            Self::Buffered(_) => None,
            Self::Unbuffered(c) => Some(c),
        }
    }

    /// Whether the unbuffered record layer drives this connection.
    ///
    /// Always `false` with the `tls-buffered` feature, because the variant
    /// does not exist there.
    pub fn is_unbuffered(&self) -> bool {
        match self {
            Self::Buffered(_) => false,
            #[cfg(not(feature = "tls-buffered"))]
            Self::Unbuffered(_) => true,
        }
    }

    pub fn wants_write(&self) -> bool {
        match self {
            Self::Buffered(k) => k.wants_write(),
            #[cfg(not(feature = "tls-buffered"))]
            Self::Unbuffered(c) => c.kind().wants_write(),
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self {
            Self::Buffered(k) => k.is_handshaking(),
            #[cfg(not(feature = "tls-buffered"))]
            Self::Unbuffered(c) => c.kind().is_handshaking(),
        }
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Buffered(k) => k.alpn_protocol(),
            #[cfg(not(feature = "tls-buffered"))]
            Self::Unbuffered(c) => c.kind().alpn_protocol(),
        }
    }

    pub fn negotiated_cipher_suite(&self) -> Option<ringline_tls::SupportedCipherSuite> {
        match self {
            Self::Buffered(k) => k.negotiated_cipher_suite(),
            #[cfg(not(feature = "tls-buffered"))]
            Self::Unbuffered(c) => c.kind().negotiated_cipher_suite(),
        }
    }

    pub fn protocol_version(&self) -> Option<ringline_tls::ProtocolVersion> {
        match self {
            Self::Buffered(k) => k.protocol_version(),
            #[cfg(not(feature = "tls-buffered"))]
            Self::Unbuffered(c) => c.kind().protocol_version(),
        }
    }

    /// The SNI hostname the peer requested, if any. The unbuffered engine
    /// captures it from the ClientHello (see `unbuffered::sni`).
    pub fn sni_hostname(&self) -> Option<&str> {
        match self {
            Self::Buffered(k) => k.sni_hostname(),
            #[cfg(not(feature = "tls-buffered"))]
            Self::Unbuffered(c) => c.sni_hostname(),
        }
    }

    // No `send_close_notify` here: it is buffered-only, like `read_tls` et
    // al. -- see `buffered::BufferedKind::send_close_notify` for why, and
    // `TlsTable::send_close_notify_queued` for the one caller, which goes
    // through `as_buffered_mut()` instead.
}

/// Per-connection TLS state.
pub struct TlsConn {
    pub conn: TlsConnKind,
    pub handshake_complete: bool,
    /// True once the peer's close_notify alert has been processed. A TCP
    /// FIN arriving while this is false is a truncation (possibly an
    /// attacker-injected FIN) and must not look like a clean EOF.
    pub peer_sent_close_notify: bool,
    /// True once this side's close_notify alert has been generated, by
    /// whichever call the driving engine uses for it (the buffered engine's
    /// `send_close_notify`, the unbuffered engine's
    /// `WriteTraffic::queue_close_notify`). On io_uring `encrypt_tls_send`,
    /// `send_bounded` and `send_backpressured` refuse application data once it
    /// is set, since the peer discards any record after the alert.
    pub close_notify_sent: bool,
    /// Plaintext bytes rustls will put in one outgoing record on this
    /// connection, **with the 5-byte record header already subtracted**.
    ///
    /// Recorded once, at [`TlsTable::create`]/[`TlsTable::create_client`],
    /// from `ServerConfig::max_fragment_size` / `ClientConfig::max_fragment_size`
    /// — the only source there is. The `max_fragment_length` extension is
    /// never negotiated by rustls 0.23.41, so there is no per-connection value
    /// to learn later.
    ///
    /// The config field *includes* the header (rustls'
    /// `MessageFragmenter::set_max_fragment_size` subtracts `PACKET_OVERHEAD`
    /// before storing it, 0.23.41 `src/msgs/fragmenter.rs:65`). Storing it
    /// already subtracted is the point of the field: no call site can repeat
    /// the off-by-five.
    ///
    /// Read by [`TlsTable::ciphertext_capacity`].
    // Live only through the capacity API until PR 8's call-site task wires
    // that into `DriverCtx::send_bounded`; removed with the allow on
    // `CiphertextCapacity`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub max_plaintext_per_record: usize,
}

/// Bytes of TLS record header on the wire: content type (1) + legacy record
/// version (2) + length (2).
///
/// rustls calls this `PACKET_OVERHEAD` (0.23.41 `src/msgs/fragmenter.rs:5`).
/// It is `pub(crate)` there, so ringline keeps its own copy — as
/// `tls::unbuffered` already does for the fragment constants, and for the same
/// reason.
const TLS_RECORD_HEADER_LEN: usize = 5;

/// The smallest `max_fragment_size` rustls accepts; anything below it is
/// `Error::BadMaxFragmentSize` and the connection never gets built (0.23.41
/// `src/msgs/fragmenter.rs:65`).
const MIN_MAX_FRAGMENT_SIZE: usize = 32;

/// The largest `max_fragment_size` rustls accepts, and the size a `None`
/// config means: 16384 bytes of plaintext plus the 5-byte header (0.23.41
/// `src/msgs/fragmenter.rs:6`, `MAX_FRAGMENT_SIZE`).
const MAX_MAX_FRAGMENT_SIZE: usize = 16384 + TLS_RECORD_HEADER_LEN;

/// Plaintext bytes per record when no `max_fragment_size` is configured:
/// rustls' `msgs::fragmenter::MAX_FRAGMENT_LEN`, which is `pub(crate)` there.
pub(crate) const DEFAULT_MAX_PLAINTEXT_PER_RECORD: usize =
    MAX_MAX_FRAGMENT_SIZE - TLS_RECORD_HEADER_LEN;

/// Worst-case wire overhead of one record ringline **emits**: the 5-byte
/// header plus the largest AEAD expansion reachable here.
///
/// TLS 1.2 GCM expands by 24 — an 8-byte explicit nonce and a 16-byte tag
/// (0.23.41 `src/crypto/ring/tls12.rs:306`, `encrypted_payload_len`). TLS 1.3
/// expands by 17 (inner content-type byte + 16-byte tag,
/// `src/crypto/ring/tls13.rs:230`) and TLS 1.2 ChaCha20-Poly1305 by 16, so 29
/// covers every suite either engine can negotiate.
///
/// **29, not 22.** The `TlsConfig` and `TlsClientConfig` builders enable
/// TLS 1.2 next to TLS 1.3 by default (`ringline-tls-config` enables rustls's
/// `tls12` feature), so a connection can negotiate a TLS 1.2 GCM suite.
///
/// Deliberately *not* derived from one maximum-size TLS 1.3 record, which
/// assumes TLS 1.3 and explicitly disclaims correctness dependence. Sizing
/// something we emit from the wrong record constant has already produced three
/// separate wrong answers in this area.
pub(crate) const MAX_RECORD_OVERHEAD: usize = TLS_RECORD_HEADER_LEN + 8 + 16;

/// Turn a rustls `max_fragment_size` config value into plaintext bytes per
/// record, with the header subtracted exactly as
/// `MessageFragmenter::set_max_fragment_size` does.
///
/// Values outside rustls' accepted `32..=16389` range fall back to the default.
/// They cannot reach a live connection — `ServerConnection::new` /
/// `ClientConnection::new` propagate `BadMaxFragmentSize` and
/// [`TlsTable::create`] returns the error — but keeping this total means the
/// bound has no panicking input.
pub(crate) fn plaintext_per_record(max_fragment_size: Option<usize>) -> usize {
    match max_fragment_size {
        Some(sz) if (MIN_MAX_FRAGMENT_SIZE..=MAX_MAX_FRAGMENT_SIZE).contains(&sz) => {
            sz - TLS_RECORD_HEADER_LEN
        }
        _ => DEFAULT_MAX_PLAINTEXT_PER_RECORD,
    }
}

/// Bytes rustls adds to one record on a connection that has already
/// negotiated a version: 24 for TLS 1.2 GCM (explicit nonce + tag), 17 for
/// TLS 1.3 (inner content type + tag), plus the 5-byte header either way.
///
/// [`MAX_RECORD_OVERHEAD`] is the version-agnostic worst case and is what the
/// admission bound budgets, because admission must be right before it knows
/// anything. This is the *exact* figure and is for callers that have a
/// handshaked connection in hand — sizing an encryption chunk with the worst
/// case would leave a TLS 1.3 record's worth of destination unused and push
/// the engine into its retry loop for nothing.
///
/// Falls back to the worst case before a version is negotiated.
///
/// Deliberately **not** derived from `ciphertext::MAX_TLS_WIRE_RECORD`, which
/// bounds a record we must be prepared to *receive* and carries 2 KiB of slack.
/// Sizing anything we *emit* from that number has produced three separate wrong
/// answers in this area already.
/// Only the unbuffered engine sizes encryption chunks against a destination,
/// so it is the only caller; gated rather than `allow(dead_code)`d.
#[cfg(not(feature = "tls-buffered"))]
pub(crate) fn negotiated_record_overhead(conn: &TlsConnKind) -> usize {
    match conn.protocol_version() {
        Some(ringline_tls::ProtocolVersion::TLSv1_3) => TLS_RECORD_HEADER_LEN + 1 + 16,
        Some(_) => MAX_RECORD_OVERHEAD,
        None => MAX_RECORD_OVERHEAD,
    }
}

/// How much ciphertext a plaintext send may turn into, computed **before**
/// rustls is allowed to mutate.
///
/// A bounded TLS send has to decide admission up front: once rustls has
/// encrypted a record it has advanced its sequence number, and running out of
/// pool mid-message is not recoverable — the send fails and the connection is
/// closed. So this is a bound, not an estimate, and every term errs upward.
/// Over-reserving costs admission latency; under-reserving costs a connection.
///
/// Obtained from [`TlsTable::ciphertext_capacity`], which supplies the
/// connection's fragment size. The three quantities it answers are the design's
/// `ciphertext_capacity_bytes` ([`Self::bytes`]),
/// `ciphertext_capacity_slots_buffered` ([`Self::slots_buffered`]) and
/// `ciphertext_capacity_slots_unbuffered` ([`Self::slots_unbuffered`]);
/// they are methods on one value rather than three lookups so that the record
/// count is derived once and cannot drift between them.
///
/// See `docs/tls-premutation-bound-design.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CiphertextCapacity {
    /// Records the bound accounts for: `ceil(plaintext_len / F)` plus the
    /// slack record described on [`TlsTable::ciphertext_capacity`].
    records: usize,
    /// The connection's plaintext bytes per record.
    max_plaintext_per_record: usize,
    /// Which engine drives the connection this bound was taken for. Read from
    /// the connection's own tag, not from the cargo feature: the two agree
    /// today, and a call site that assumed so would be silently wrong on the
    /// day they stop agreeing.
    unbuffered: bool,
}

// Same rationale as the `allow` on the struct: PR 8's call-site task removes it.
#[cfg_attr(not(test), allow(dead_code))]
impl CiphertextCapacity {
    /// Records the bound covers, including the slack record — so this is never
    /// zero, even for an empty plaintext.
    pub fn records(&self) -> usize {
        self.records
    }

    /// Upper bound on ciphertext bytes: `records * (F + 29)`.
    ///
    /// Correct for both engines and both backends. `F + 29` is the worst-case
    /// wire size of one record ([`MAX_RECORD_OVERHEAD`]).
    pub fn bytes(&self) -> usize {
        self.records * (self.max_plaintext_per_record + MAX_RECORD_OVERHEAD)
    }

    /// Upper bound on [`crate::buffer::send_copy::SendCopyPool`] slots for the
    /// **buffered** engine: `ceil(bytes / slot_size)`.
    ///
    /// Exact, because the buffered path writes ciphertext through `PoolWriter`,
    /// which packs slots contiguously and lets a single record straddle a slot
    /// boundary. Nothing is wasted at the seam.
    ///
    /// `None` only for `slot_size == 0`, which `ConfigBuilder` already rejects;
    /// the shape matches [`Self::slots_unbuffered`] so a caller handles one
    /// "cannot express a bound for this slot size" arm rather than two.
    pub fn slots_buffered(&self, slot_size: usize) -> Option<usize> {
        if slot_size == 0 {
            return None;
        }
        Some(self.bytes().div_ceil(slot_size))
    }

    /// Upper bound on [`crate::buffer::send_copy::SendCopyPool`] slots for the
    /// **unbuffered** engine: one record per slot, i.e. [`Self::records`].
    ///
    /// `encrypt_chunk` writes whole records into one slot and cannot straddle,
    /// so the byte formula *under*-estimates this engine — at a 32768-byte slot
    /// and 49152 bytes of plaintext the byte formula says 2 slots and the
    /// engine takes 3. One record per slot is safe under the condition below.
    /// It over-reserves whenever a slot holds several records, which costs
    /// admission latency and nothing else.
    ///
    /// The bound holds while each slot carries at least `F` plaintext, apart
    /// from the last and from calls that also carry records rustls had queued
    /// (a key_update); the `+ 1` slack record covers the plaintext those calls
    /// give up.
    ///
    /// Returns `None` when `slot_size` cannot hold one whole worst-case record
    /// (`F + 29`). That is not a nicety: below that size the shrink loop
    /// converges on a chunk smaller than `F`, so the connection emits *more*
    /// records than `ceil(plaintext_len / F)` and this bound would be too
    /// small — the one failure mode that closes connections. At `slot_size`
    /// under `unbuffered::MIN_ENCRYPT_DST` the engine cannot make progress at
    /// all. Callers must turn `None` into an error rather than a guess.
    ///
    /// `Config::validate` rejects a `send_copy_slot_size` below `F + 29` for
    /// every configured rustls config on the unbuffered engine, so a running
    /// connection gets `Some`.
    pub fn slots_unbuffered(&self, slot_size: usize) -> Option<usize> {
        if slot_size < self.max_plaintext_per_record + MAX_RECORD_OVERHEAD {
            return None;
        }
        Some(self.records)
    }

    /// The smallest `send_copy_slot_size` for which a bound is expressible.
    ///
    /// One whole worst-case record, `F + 29`. Only meaningful when
    /// [`Self::slots`] returned `None`; it is what the refusal names so the
    /// operator can fix the configuration rather than guess at it.
    pub fn min_slot_size(&self) -> usize {
        self.max_plaintext_per_record + MAX_RECORD_OVERHEAD
    }

    /// The slot bound for the engine that actually drives this connection.
    ///
    /// This is what admission call sites must use. The two primitives above
    /// are the tested arithmetic; choosing between them at a call site is how
    /// a connection ends up admitted against the buffered formula and then
    /// encrypted by the unbuffered engine, which is the under-estimate that
    /// closes connections.
    ///
    /// `None` carries the same meaning as [`Self::slots_unbuffered`]: no bound
    /// can be expressed for this slot size, and the caller must refuse the
    /// send rather than guess.
    pub fn slots(&self, slot_size: usize) -> Option<usize> {
        if self.unbuffered {
            self.slots_unbuffered(slot_size)
        } else {
            self.slots_buffered(slot_size)
        }
    }
}

/// Table of TLS connections, indexed by connection slot.
/// Stored as a separate EventLoop field for borrow splitting.
pub struct TlsTable {
    conns: Vec<Option<TlsConn>>,
    /// Process-wide fallback, used by any listener without its own config.
    server_config: Option<Arc<ringline_tls::ServerConfig>>,
    /// Per-listener configs indexed by `ListenerId`. A `None` entry, or an
    /// index past the end, falls back to `server_config`.
    listener_configs: Vec<Option<Arc<ringline_tls::ServerConfig>>>,
    client_config: Option<Arc<ringline_tls::ClientConfig>>,
    /// Single shared ciphertext scratch buffer (one per worker thread).
    /// Only used synchronously — we process one connection at a time.
    /// io_uring builds write ciphertext directly into pool slots via
    /// `PoolWriter` and don't need it.
    #[cfg(not(has_io_uring))]
    write_buf: Vec<u8>,
    /// Free buffers for direct receives on the buffered engine, which reads
    /// ciphertext from a slice rather than receiving into its own buffer.
    /// One is taken per receive in flight and returned on its completion.
    #[cfg(all(has_io_uring, feature = "tls-buffered"))]
    recv_buffers: Vec<Vec<u8>>,
}

impl TlsTable {
    /// Create a table with capacity for `max_connections`, able to serve a
    /// different server config per listener.
    ///
    /// `listener_configs` is indexed by `ListenerId`; a `None` entry falls back
    /// to `server_config`.
    pub fn with_listener_configs(
        max_connections: u32,
        server_config: Option<Arc<ringline_tls::ServerConfig>>,
        client_config: Option<Arc<ringline_tls::ClientConfig>>,
        listener_configs: Vec<Option<Arc<ringline_tls::ServerConfig>>>,
    ) -> Self {
        let mut conns = Vec::with_capacity(max_connections as usize);
        conns.resize_with(max_connections as usize, || None);
        // The unbuffered engine learns the SNI hostname through the
        // certificate resolver; see `unbuffered::sni`.
        #[cfg(not(feature = "tls-buffered"))]
        let (server_config, listener_configs) = (
            server_config.map(|c| unbuffered::sni::capture_server_names(&c)),
            listener_configs
                .into_iter()
                .map(|c| c.map(|c| unbuffered::sni::capture_server_names(&c)))
                .collect(),
        );
        TlsTable {
            conns,
            server_config,
            listener_configs,
            client_config,
            #[cfg(not(has_io_uring))]
            write_buf: Vec::new(),
            #[cfg(all(has_io_uring, feature = "tls-buffered"))]
            recv_buffers: Vec::new(),
        }
    }

    /// The server config that should terminate a connection accepted on
    /// `listener`: that listener's own if it has one, else the process-wide
    /// fallback.
    fn server_config_for(
        &self,
        listener: Option<crate::ListenerId>,
    ) -> Option<&Arc<ringline_tls::ServerConfig>> {
        listener
            .and_then(|l| self.listener_configs.get(l.index() as usize))
            .and_then(|slot| slot.as_ref())
            .or(self.server_config.as_ref())
    }

    /// Whether connections accepted on `listener` should terminate TLS.
    pub fn has_server_config_for(&self, listener: Option<crate::ListenerId>) -> bool {
        self.server_config_for(listener).is_some()
    }

    /// Whether a client config is present (for TLS connect on outbound connections).
    pub fn has_client_config(&self) -> bool {
        self.client_config.is_some()
    }

    /// Create a new TLS server connection at the given index.
    ///
    /// The engine is selected here, once per connection, and fixed for its
    /// lifetime: rustls' unbuffered record layer, unless the `tls-buffered`
    /// feature selects the buffered one. See
    /// `docs/tls-unbuffered-design.md` ("Path selection").
    pub fn create(
        &mut self,
        conn_index: u32,
        listener: Option<crate::ListenerId>,
    ) -> Result<(), ringline_tls::Error> {
        let server_config = self
            .server_config_for(listener)
            .expect("create() called without a server config for this listener")
            .clone();
        // Read before the config is moved into the connection, and before any
        // engine selection: the value is the same either way.
        let max_plaintext_per_record = plaintext_per_record(server_config.max_fragment_size);
        #[cfg(not(feature = "tls-buffered"))]
        let conn = TlsConnKind::Unbuffered(unbuffered::UnbufferedConn::new_server(server_config)?);
        #[cfg(feature = "tls-buffered")]
        let conn = TlsConnKind::Buffered(buffered::BufferedKind::Server(ServerConnection::new(
            server_config,
        )?));
        self.conns[conn_index as usize] = Some(TlsConn {
            conn,
            handshake_complete: false,
            peer_sent_close_notify: false,
            close_notify_sent: false,
            max_plaintext_per_record,
        });
        Ok(())
    }

    /// Create a new TLS client connection at the given index. Engine selection
    /// as in [`Self::create`].
    pub fn create_client(
        &mut self,
        conn_index: u32,
        server_name: ServerName<'static>,
    ) -> Result<(), ringline_tls::Error> {
        let client_config = self
            .client_config
            .as_ref()
            .expect("create_client() called without client_config")
            .clone();
        let max_plaintext_per_record = plaintext_per_record(client_config.max_fragment_size);
        #[cfg(not(feature = "tls-buffered"))]
        let conn = TlsConnKind::Unbuffered(unbuffered::UnbufferedConn::new_client(
            client_config,
            server_name,
        )?);
        #[cfg(feature = "tls-buffered")]
        let conn = TlsConnKind::Buffered(buffered::BufferedKind::Client(ClientConnection::new(
            client_config,
            server_name,
        )?));
        self.conns[conn_index as usize] = Some(TlsConn {
            conn,
            handshake_complete: false,
            peer_sent_close_notify: false,
            close_notify_sent: false,
            max_plaintext_per_record,
        });
        Ok(())
    }

    /// The pre-mutation ciphertext bound for encrypting `plaintext_len` bytes
    /// on the connection at `conn_index`, or `None` if that slot has no TLS
    /// state.
    ///
    /// `records = ceil(plaintext_len / F) + 1`, where `F` is the connection's
    /// [`TlsConn::max_plaintext_per_record`]. Zero plaintext still costs one
    /// record.
    ///
    /// **The `+ 1` is a whole record of slack and is not optional.** rustls
    /// drains whatever is already sitting in `sendable_tls` — a TLS 1.3
    /// `key_update`, an alert — into the *front* of the same destination
    /// buffer (ringline-tls 0.1.1 `CommonState::write_fragments`, and
    /// `check_required_size` sizes `required_size` to include it). Its size is
    /// not a function of `plaintext_len`, and the unbuffered engine exposes no
    /// byte count for it at all: `tls_bytes_to_write` is buffered-only. So the
    /// bound carries headroom for it unconditionally rather than pretending it
    /// can be predicted.
    ///
    /// **This is the single source of that number.** PR 9's bounded-send
    /// future must compute the `required_slots` it hands
    /// `SendCompletions::enqueue` with this same function, and its
    /// oversize-rejection test must use it too. If the FIFO admits on a
    /// different number than the backend checks, the queue will admit a
    /// message the backend then refuses — which is the failure this bound
    /// exists to prevent.
    ///
    /// See `docs/tls-premutation-bound-design.md`.
    // PR 8's call-site task is what gives this a non-test caller.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn ciphertext_capacity(
        &self,
        conn_index: u32,
        plaintext_len: usize,
    ) -> Option<CiphertextCapacity> {
        let tls_conn = self.conns[conn_index as usize].as_ref()?;
        let f = tls_conn.max_plaintext_per_record;
        debug_assert!(f > 0, "fragment size is validated at create()");
        Some(CiphertextCapacity {
            records: plaintext_len.div_ceil(f.max(1)) + 1,
            max_plaintext_per_record: f,
            unbuffered: tls_conn.conn.is_unbuffered(),
        })
    }

    /// Install a ready-made connection at `conn_index`.
    ///
    /// Test seam: `create`/`create_client` build a connection that still has
    /// to handshake over a socket, which a unit test has no way to drive.
    /// `buffered::test_support::handshaked` produces a real, already-handshaked
    /// rustls session in memory; this puts one where the driver looks for it.
    #[cfg(test)]
    pub(crate) fn insert_for_test(&mut self, conn_index: u32, conn: TlsConn) {
        self.conns[conn_index as usize] = Some(conn);
    }

    /// Take the TLS state of the connection at `conn_index` out of the table,
    /// to move it with the connection to another worker (park).
    #[cfg(has_io_uring)]
    pub(crate) fn take(&mut self, conn_index: u32) -> Option<TlsConn> {
        self.conns[conn_index as usize].take()
    }

    /// Install TLS state taken from another worker's table ([`Self::take`])
    /// for the connection at `conn_index`.
    #[cfg(has_io_uring)]
    pub(crate) fn install(&mut self, conn_index: u32, conn: TlsConn) {
        self.conns[conn_index as usize] = Some(conn);
    }

    /// Whether the connection at `conn_index` holds decrypted plaintext that
    /// has not reached its accumulator: plaintext the unbuffered engine
    /// found on the send path and stashed. The receive path drains it first,
    /// so it is normally empty.
    #[cfg(has_io_uring)]
    pub(crate) fn has_undelivered_plaintext(&self, conn_index: u32) -> bool {
        #[cfg(not(feature = "tls-buffered"))]
        {
            matches!(
                self.conns[conn_index as usize].as_ref().map(|c| &c.conn),
                Some(TlsConnKind::Unbuffered(u)) if u.has_stashed_plaintext()
            )
        }
        // The buffered engine's plaintext is drained into the accumulator
        // on every feed.
        #[cfg(feature = "tls-buffered")]
        {
            let _ = conn_index;
            false
        }
    }

    /// Get a mutable reference to the TLS connection at the given index.
    pub fn get_mut(&mut self, conn_index: u32) -> Option<&mut TlsConn> {
        self.conns[conn_index as usize].as_mut()
    }

    /// Check if a connection has TLS state.
    pub fn has(&self, conn_index: u32) -> bool {
        self.conns[conn_index as usize].is_some()
    }

    /// Whether this side's close_notify has been generated on a connection.
    #[cfg(has_io_uring)]
    pub fn close_notify_sent(&self, conn_index: u32) -> bool {
        self.conns[conn_index as usize]
            .as_ref()
            .is_some_and(|c| c.close_notify_sent)
    }

    /// Remove TLS state for a connection.
    pub fn remove(&mut self, conn_index: u32) {
        self.conns[conn_index as usize] = None;
    }

    /// Get TLS session information for a connection.
    pub fn get_info(&self, conn_index: u32) -> Option<TlsInfo> {
        let tls_conn = self.conns[conn_index as usize].as_ref()?;
        Some(TlsInfo {
            protocol_version: tls_conn
                .conn
                .protocol_version()
                .and_then(ringline_tls_config::TlsVersion::from_rustls),
            cipher_suite: tls_conn
                .conn
                .negotiated_cipher_suite()
                .map(|s| ringline_tls_config::CipherSuite::from_rustls(s.suite())),
            alpn_protocol: tls_conn.conn.alpn_protocol().map(|s| s.to_vec()),
            sni_hostname: tls_conn.conn.sni_hostname().map(|s| s.to_string()),
        })
    }

    /// Send a TLS close_notify alert, encrypting the ciphertext into
    /// `BuiltSend`s for the caller to route through the per-connection send
    /// queue. Serializing through the queue (rather than pushing linked
    /// SQEs directly) keeps the alert ordered behind any in-flight send and
    /// lets the deferred Close fire only after it completes.
    ///
    /// Generating the alert is engine-specific. `send_close_notify` is
    /// buffered-only (see `buffered::BufferedKind::send_close_notify`), so that
    /// arm goes through `as_buffered_mut()` and then drains rustls' output. The
    /// unbuffered engine has no such call at all -- rustls expresses the
    /// operation as `WriteTraffic::queue_close_notify`, which encrypts the
    /// alert into a caller buffer -- so that arm copies the result into pool
    /// slots itself, per `docs/tls-unbuffered-design.md` ("### close_notify").
    ///
    /// A connection that never reached traffic state has nothing to queue and
    /// leaves `out` untouched. That is not an error: the caller is tearing the
    /// connection down either way.
    #[cfg(has_io_uring)]
    pub fn send_close_notify_queued(
        &mut self,
        conn_index: u32,
        generation: u32,
        send_copy_pool: &mut SendCopyPool,
        out: &mut Vec<crate::handler::BuiltSend>,
    ) {
        let Some(tls_conn) = self.get_mut(conn_index) else {
            return;
        };
        #[cfg(not(feature = "tls-buffered"))]
        {
            // `queue_close_notify` signals "nothing to queue" by leaving
            // `scratch` untouched, not by an error or a count. Anything rustls
            // had already queued rides out inside `scratch` *ahead* of the
            // alert (`write_fragments` drains `sendable_tls` into the front of
            // the destination), so this transmits it as-is and does not drive
            // the machine afterwards looking for leftovers -- that would put
            // them after the alert on the wire.
            let mut scratch = Vec::new();
            if unbuffered::queue_close_notify(tls_conn, &mut scratch).is_err() {
                return;
            }
            // Shared with the recv/flush paths rather than re-chunked here, so
            // the all-or-nothing contract has one implementation: a truncated
            // alert on the wire is worse than none.
            let _ = backend_uring::ciphertext_to_sends(
                send_copy_pool,
                conn_index,
                generation,
                &scratch,
                out,
            );
        }
        // Bound as `b`, not `buffered`: the module of that name is used on the
        // next line, and a value/module name collision here reads as a bug.
        #[cfg(feature = "tls-buffered")]
        if let Some(b) = tls_conn.conn.as_buffered_mut() {
            b.send_close_notify();
            tls_conn.close_notify_sent = true;
            let _ = buffered::take_tls_output_sends(
                tls_conn,
                send_copy_pool,
                conn_index,
                generation,
                out,
            );
        }
    }
}

/// Result of feeding ciphertext into a TLS connection.
pub enum TlsRecvResult {
    /// Data processed successfully.
    Ok,
    /// TLS handshake just completed — caller should fire on_accept, or wake
    /// the connect waiter. `peer_closed` is set when the same feed also
    /// carried the peer's close_notify; the caller then handles the close as
    /// it handles [`Closed`](Self::Closed), after the completion.
    HandshakeJustCompleted { peer_closed: bool },
    /// TLS error occurred.
    #[allow(dead_code)] // variant matched; inner value reserved for future error reporting
    Error(ringline_tls::Error),
    /// Peer sent close_notify or connection is cleanly closed.
    Closed,
}

/// Drain all currently-decrypted plaintext from a TLS connection into its recv
/// accumulator, with no intermediate scratch buffer.
///
/// rustls's `Reader` implements `BufRead`: `fill_buf()` exposes the decrypted
/// plaintext in rustls's own buffer, and `consume()` advances past what we copied.
/// rustls 0.23 keeps one `Vec` per record and `fill_buf` returns the front
/// one, so each chunk is one record's plaintext, at most 16 KiB.
///
/// Returns `false` if the accumulator hit its bound (`max_size`) — the
/// plaintext was NOT consumed from rustls, and the caller must treat the
/// connection as broken (silently consuming would put a permanent gap in the
/// byte stream; an unbounded plaintext flood must kill the connection).
#[must_use]
fn drain_tls_plaintext(
    tls_conn: &mut TlsConn,
    accumulators: &mut AccumulatorTable,
    conn_index: u32,
) -> bool {
    use std::io::BufRead;
    let mut reader = tls_conn
        .conn
        .as_buffered_mut()
        .expect("drain_tls_plaintext: connection not driven by the buffered TLS engine")
        .reader();
    loop {
        let chunk = match reader.fill_buf() {
            Ok([]) => break,
            Ok(b) => b,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        };
        let n = chunk.len();
        if !accumulators.append(conn_index, chunk) {
            return false;
        }
        reader.consume(n);
    }
    true
}

/// Build a pool-backed send SQE entry without submitting it. The caller
/// routes it through the per-connection send queue (`submit_or_queue`) so
/// TLS ciphertext is serialized with every other send on the connection:
/// io_uring does not order independent SQEs, and a partial-send resubmit of
/// chunk A after chunk B already transmitted interleaves ciphertext on the
/// wire (bad_record_mac at the peer).
#[cfg(has_io_uring)]
fn build_pool_send(
    conn_index: u32,
    generation: u32,
    ptr: *const u8,
    len: u32,
    pool_slot: u16,
    tag: crate::completion::OpTag,
) -> crate::handler::BuiltSend {
    let user_data = crate::completion::UserData::encode(
        tag,
        conn_index,
        crate::completion::UserData::send_payload(pool_slot, generation),
    );
    let entry = crate::backend::uring::sqe::Sqe::stream_send(conn_index, ptr, len, user_data.raw());
    crate::handler::BuiltSend {
        entry,
        pool_slot,
        slab_idx: u16::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_config() -> Arc<ringline_tls::ServerConfig> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = ringline_tls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert_der = ringline_tls::pki_types::CertificateDer::from(cert.cert);
        Arc::new(
            ringline_tls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key.into())
                .unwrap(),
        )
    }

    // Engine selection happens once, in `create`, and follows the cargo
    // feature. Without this, every test in `tls_echo.rs` passes with the
    // feature on and the unbuffered engine never actually selected — which is
    // exactly the state this task starts from.
    #[test]
    fn create_selects_the_engine_the_build_asked_for() {
        let mut table = TlsTable::with_listener_configs(4, Some(server_config()), None, Vec::new());
        table.create(0, None).expect("create a server connection");
        let conn = table.get_mut(0).expect("connection exists");

        #[cfg(not(feature = "tls-buffered"))]
        {
            assert!(
                conn.conn.as_unbuffered_mut().is_some(),
                "the default build must select the unbuffered engine"
            );
            assert!(conn.conn.as_buffered_mut().is_none());
        }
        #[cfg(feature = "tls-buffered")]
        assert!(
            conn.conn.as_buffered_mut().is_some(),
            "a tls-buffered build must select the buffered engine"
        );
    }

    /// A server config whose `max_fragment_size` is overridden. 2048 is inside
    /// rustls' accepted `32..=16389`, so the connection still builds.
    fn server_config_with_fragment(max_fragment_size: usize) -> Arc<ringline_tls::ServerConfig> {
        let mut config = Arc::try_unwrap(server_config()).expect("sole owner");
        config.max_fragment_size = Some(max_fragment_size);
        Arc::new(config)
    }

    fn client_config() -> Arc<ringline_tls::ClientConfig> {
        Arc::new(
            ringline_tls::ClientConfig::builder()
                .with_root_certificates(ringline_tls::RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    fn table_with_server(max_fragment_size: Option<usize>) -> TlsTable {
        let config = match max_fragment_size {
            Some(sz) => server_config_with_fragment(sz),
            None => server_config(),
        };
        let mut table =
            TlsTable::with_listener_configs(4, Some(config), Some(client_config()), Vec::new());
        table.create(0, None).expect("create a server connection");
        table
    }

    /// With the buffered engine a receive takes a buffer from the table's
    /// free list and gives it back when it ends, so the list holds at most
    /// as many buffers as receives were in flight at once.
    #[cfg(all(has_io_uring, feature = "tls-buffered"))]
    #[test]
    fn buffered_receives_reuse_the_free_buffers() {
        let mut table = table_with_server(None);
        table.create(1, None).expect("create a second connection");
        let a = tls_recv_arm(&mut table, 0, 1024).expect("arm");
        let b = tls_recv_arm(&mut table, 1, 1024).expect("arm");
        assert!(a.len == 1024 && a.buf.as_ref().is_some_and(|b| b.capacity() >= 1024));
        tls_recv_cancel(&mut table, 0, a.buf);
        tls_recv_cancel(&mut table, 1, b.buf);
        assert_eq!(table.recv_buffers.len(), 2);
        let c = tls_recv_arm(&mut table, 0, 1024).expect("arm");
        assert_eq!(table.recv_buffers.len(), 1, "a free buffer was reused");
        tls_recv_cancel(&mut table, 0, c.buf);
        assert_eq!(table.recv_buffers.len(), 2);
    }

    // The whole point of storing the fragment size already subtracted. The
    // rustls config value *includes* the 5-byte record header; a build that
    // dropped the subtraction would report 16389 / 2048 here.
    #[test]
    fn max_plaintext_per_record_subtracts_the_record_header() {
        let mut table = table_with_server(None);
        assert_eq!(
            table.get_mut(0).unwrap().max_plaintext_per_record,
            16384,
            "default `None` config means one whole maximum-size fragment of plaintext"
        );

        let mut table = table_with_server(Some(2048));
        assert_eq!(
            table.get_mut(0).unwrap().max_plaintext_per_record,
            2043,
            "a configured max_fragment_size includes the 5-byte header"
        );
    }

    // `create_client` must record the same thing from the client config, or an
    // outbound TLS connection gets a bound computed from the wrong fragment
    // size.
    #[test]
    fn create_client_records_the_client_configs_fragment_size() {
        let mut config = Arc::try_unwrap(client_config()).expect("sole owner");
        config.max_fragment_size = Some(2048);
        let mut table =
            TlsTable::with_listener_configs(4, None, Some(Arc::new(config)), Vec::new());
        let name: ringline_tls::pki_types::ServerName<'static> = "localhost".try_into().unwrap();
        table.create_client(1, name).expect("create a client");
        assert_eq!(table.get_mut(1).unwrap().max_plaintext_per_record, 2043);
    }

    // Out-of-range values never reach a live connection (rustls refuses them),
    // but the helper must stay total rather than underflow.
    #[test]
    fn out_of_range_fragment_sizes_fall_back_to_the_default() {
        assert_eq!(plaintext_per_record(Some(0)), 16384);
        assert_eq!(plaintext_per_record(Some(31)), 16384);
        assert_eq!(plaintext_per_record(Some(16390)), 16384);
        assert_eq!(plaintext_per_record(Some(32)), 27);
        assert_eq!(plaintext_per_record(Some(16389)), 16384);
        assert_eq!(plaintext_per_record(None), 16384);
    }

    #[test]
    fn capacity_is_none_for_a_slot_without_tls() {
        let table = table_with_server(None);
        assert!(table.ciphertext_capacity(1, 100).is_none());
    }

    // Record counting across every boundary that matters, including the
    // unconditional slack record.
    #[test]
    fn record_count_covers_the_boundaries_plus_one_slack_record() {
        let table = table_with_server(None);
        let records = |len: usize| table.ciphertext_capacity(0, len).unwrap().records();

        assert_eq!(
            records(0),
            1,
            "an empty plaintext still owes the slack record"
        );
        assert_eq!(records(1), 2);
        assert_eq!(records(16384), 2, "exactly one record");
        assert_eq!(records(16385), 3, "one byte over");
        assert_eq!(records(16384 * 4), 5);
        assert_eq!(records(16384 * 4 + 1), 6);
    }

    #[test]
    fn byte_bound_is_records_times_the_worst_case_record() {
        let table = table_with_server(None);
        let cap = table.ciphertext_capacity(0, 16384 * 4).unwrap();
        assert_eq!(cap.records(), 5);
        assert_eq!(cap.bytes(), 5 * (16384 + 29));

        // Zero plaintext is one whole record of slack, not zero bytes.
        let empty = table.ciphertext_capacity(0, 0).unwrap();
        assert_eq!(empty.bytes(), 16384 + 29);
    }

    // The buffered engine packs `PoolWriter` slots contiguously, so the slot
    // count is exactly the byte count divided by the slot size.
    #[test]
    fn buffered_slots_divide_the_byte_bound() {
        let table = table_with_server(None);
        let cap = table.ciphertext_capacity(0, 16384 * 4).unwrap();
        let bytes = cap.bytes();
        assert_eq!(bytes, 82065);
        assert_eq!(cap.slots_buffered(16448), Some(bytes.div_ceil(16448)));
        assert_eq!(cap.slots_buffered(16448), Some(5));
        // A slot size that divides the bound exactly must not round up.
        assert_eq!(cap.slots_buffered(bytes), Some(1));
        assert_eq!(cap.slots_buffered(bytes / 5), Some(5));
        // Zero is config-rejected; the API stays total.
        assert_eq!(cap.slots_buffered(0), None);
    }

    // One record per slot: the unbuffered engine's own worst case. It
    // over-reserves when a slot holds several records, which is the safe
    // direction.
    #[test]
    fn unbuffered_slots_are_one_record_each() {
        let table = table_with_server(None);
        let cap = table.ciphertext_capacity(0, 16384 * 4).unwrap();
        assert_eq!(cap.slots_unbuffered(16448), Some(5));
        // A slot big enough for several records still reserves one per record.
        assert_eq!(cap.slots_unbuffered(16448 * 4), Some(5));
        assert!(
            cap.slots_unbuffered(16448 * 4).unwrap() > cap.slots_buffered(16448 * 4).unwrap(),
            "the byte formula under-estimates the unbuffered engine"
        );
    }

    /// Encrypt `plaintext` on a real handshaked session pinned to `versions`
    /// and return the ciphertext rustls actually emitted.
    fn real_ciphertext(
        versions: &[&'static ringline_tls::SupportedProtocolVersion],
        plaintext: &[u8],
    ) -> Vec<u8> {
        use std::io::Write as _;
        let (_server, mut client) = buffered::test_support::handshaked_with_versions(versions);
        client.writer().write_all(plaintext).unwrap();
        let mut cipher = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut cipher).unwrap();
        }
        cipher
    }

    // The bound budgets 29 bytes per record for TLS 1.2 GCM (explicit nonce +
    // tag) rather than TLS 1.3's 22. A worst case only ever checked against
    // the cheaper version is not a worst case, so check it against records the
    // expensive version produced.
    #[test]
    fn the_bound_covers_real_tls12_records() {
        let table = table_with_server(None);
        for len in [1usize, 100, 16384, 16385, 16384 * 3 + 7] {
            let plaintext = vec![0xA5u8; len];
            let cipher = real_ciphertext(&[&ringline_tls::version::TLS12], &plaintext);
            let bound = table.ciphertext_capacity(0, len).unwrap();
            assert!(
                cipher.len() <= bound.bytes(),
                "TLS 1.2: {len} plaintext bytes became {} ciphertext bytes, over a bound of {}",
                cipher.len(),
                bound.bytes()
            );
        }
    }

    // The same records under TLS 1.3, which is what the library build actually
    // negotiates. Both versions must fit under the one bound — that is the
    // whole reason it budgets for the more expensive of the two.
    #[test]
    fn the_bound_covers_real_tls13_records() {
        let table = table_with_server(None);
        for len in [1usize, 100, 16384, 16385, 16384 * 3 + 7] {
            let plaintext = vec![0xA5u8; len];
            let cipher = real_ciphertext(&[&ringline_tls::version::TLS13], &plaintext);
            let bound = table.ciphertext_capacity(0, len).unwrap();
            assert!(
                cipher.len() <= bound.bytes(),
                "TLS 1.3: {len} plaintext bytes became {} ciphertext bytes, over a bound of {}",
                cipher.len(),
                bound.bytes()
            );
        }
    }

    /// Bytes rustls adds to one full-size record, measured.
    fn measured_record_overhead(
        versions: &[&'static ringline_tls::SupportedProtocolVersion],
    ) -> usize {
        const ONE_RECORD: usize = DEFAULT_MAX_PLAINTEXT_PER_RECORD;
        let cipher = real_ciphertext(versions, &vec![0xA5u8; ONE_RECORD]);
        cipher.len() - ONE_RECORD
    }

    // `the_bound_covers_real_tls12_records` cannot pin [`MAX_RECORD_OVERHEAD`]
    // on its own: the bound's slack record is ~16 KiB of headroom, which
    // swallows a seven-byte-per-record error whole. Verified by mutation —
    // dropping the constant to TLS 1.3's 22 leaves that test green. So measure
    // one record's overhead directly and pin the constant to it.
    #[test]
    fn max_record_overhead_is_the_measured_tls12_worst_case() {
        assert_eq!(
            measured_record_overhead(&[&ringline_tls::version::TLS12]),
            MAX_RECORD_OVERHEAD,
            "TLS 1.2 GCM: 5-byte header + 8-byte explicit nonce + 16-byte tag"
        );
        assert_eq!(
            measured_record_overhead(&[&ringline_tls::version::TLS13]),
            TLS_RECORD_HEADER_LEN + 17,
            "TLS 1.3: 5-byte header + content-type byte + 16-byte tag"
        );
        assert!(
            measured_record_overhead(&[&ringline_tls::version::TLS12])
                > measured_record_overhead(&[&ringline_tls::version::TLS13]),
            "the bound must budget for the more expensive version"
        );
    }

    // TLS 1.2 really is the more expensive of the two, so the test above is
    // not silently checking the same thing twice.
    #[test]
    fn tls12_records_are_larger_than_tls13_records() {
        let plaintext = vec![0xA5u8; 16384 * 2];
        let twelve = real_ciphertext(&[&ringline_tls::version::TLS12], &plaintext).len();
        let thirteen = real_ciphertext(&[&ringline_tls::version::TLS13], &plaintext).len();
        assert!(
            twelve > thirteen,
            "TLS 1.2 produced {twelve} bytes, TLS 1.3 produced {thirteen}"
        );
    }

    // The call sites must not pick an engine themselves: the wrong pick is
    // silent, and picking `slots_buffered` for an unbuffered connection is the
    // under-estimate that closes connections.
    #[test]
    fn slots_follows_the_connections_own_engine() {
        let table = table_with_server(None);
        let cap = table.ciphertext_capacity(0, 16384 * 4).unwrap();

        #[cfg(not(feature = "tls-buffered"))]
        assert_eq!(cap.slots(16448 * 4), cap.slots_unbuffered(16448 * 4));
        #[cfg(feature = "tls-buffered")]
        assert_eq!(cap.slots(16448 * 4), cap.slots_buffered(16448 * 4));

        // The two disagree at this slot size, so the assertion above is not
        // satisfied by both answers at once.
        assert_ne!(
            cap.slots_unbuffered(16448 * 4),
            cap.slots_buffered(16448 * 4)
        );
    }

    // Below one whole worst-case record the engine's shrink loop converges on
    // a chunk smaller than F, emitting more records than `ceil(len / F)` — so
    // `records` would be an under-estimate and the caller must get an error
    // instead of a number.
    #[test]
    fn unbuffered_refuses_a_slot_smaller_than_one_record() {
        let table = table_with_server(None);
        let cap = table.ciphertext_capacity(0, 16384).unwrap();
        assert_eq!(
            cap.slots_unbuffered(16384 + 29),
            Some(2),
            "exactly one record fits"
        );
        assert_eq!(cap.slots_unbuffered(16384 + 28), None);
        assert_eq!(
            cap.slots_unbuffered(16384),
            None,
            "a bare fragment is not a record"
        );
        assert_eq!(cap.slots_unbuffered(0), None);

        // The shipped default clears the threshold, so the common
        // configuration is not silently unusable.
        let default_slot = crate::config::Config::default().send_copy_slot_size as usize;
        assert!(
            default_slot >= 16384 + 29,
            "default send_copy_slot_size {default_slot} must hold one whole record"
        );
        assert!(cap.slots_unbuffered(default_slot).is_some());
    }

    // The off-by-five is visible here and nowhere else: at F = 2043 a
    // 2048-byte plaintext spans two records, while the unsubtracted F = 2048
    // would say one. Both the record count and the byte bound would be short.
    #[test]
    fn overridden_fragment_size_counts_records_against_the_subtracted_size() {
        let table = table_with_server(Some(2048));
        let cap = table.ciphertext_capacity(0, 2048).unwrap();
        assert_eq!(
            cap.records(),
            3,
            "2048 bytes spans two 2043-byte records, plus the slack record"
        );
        assert_eq!(cap.bytes(), 3 * (2043 + 29));

        // Exactly on the subtracted boundary, and one byte past it.
        assert_eq!(table.ciphertext_capacity(0, 2043).unwrap().records(), 2);
        assert_eq!(table.ciphertext_capacity(0, 2044).unwrap().records(), 3);

        // The overridden size also moves the unbuffered threshold.
        assert_eq!(cap.slots_unbuffered(2043 + 29), Some(3));
        assert_eq!(cap.slots_unbuffered(2043 + 28), None);
    }
}
