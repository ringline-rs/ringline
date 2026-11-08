use std::sync::Arc;

use ringline_tls::pki_types::ServerName;

use super::{
    DriveOutcome, MAX_SINGLE_APPEND, UnbufferedConn, drive, encrypt_chunk, feed, queue_close_notify,
};
use crate::accumulator::AccumulatorTable;
use crate::tls::{DEFAULT_MAX_PLAINTEXT_PER_RECORD, TlsConn, TlsConnKind};

/// Wire size of one maximum-size TLS 1.3 record on a default-configured
/// connection: the 5-byte header, 16384 bytes of plaintext, the inner
/// content-type byte and a 16-byte AEAD tag. Production derives the same
/// number per connection via `tls::negotiated_record_overhead`; this is the
/// default-config value the tests below pin.
const DEFAULT_RECORD_WIRE_LEN: usize = DEFAULT_MAX_PLAINTEXT_PER_RECORD + 5 + 1 + 16;

fn empty_client_config() -> Arc<ringline_tls::ClientConfig> {
    ringline_tls::ClientConfig::builder()
        .with_root_certificates(ringline_tls::RootCertStore::empty())
        .with_no_client_auth()
        .into()
}

fn client_conn() -> UnbufferedConn {
    let server_name: ServerName<'static> = "localhost".try_into().unwrap();
    UnbufferedConn::new_client(empty_client_config(), server_name)
        .expect("constructing an unbuffered client connection does not drive the handshake")
}

// A connection built on the unbuffered engine reports itself as such:
// `as_buffered_mut` returns `None` rather than panicking or silently
// handing back a buffered view.
#[test]
fn unbuffered_connection_is_not_buffered() {
    let mut tls_conn = TlsConn {
        conn: TlsConnKind::Unbuffered(client_conn()),
        handshake_complete: false,
        peer_sent_close_notify: false,
        close_notify_sent: false,
        max_plaintext_per_record: DEFAULT_MAX_PLAINTEXT_PER_RECORD,
    };
    assert!(tls_conn.conn.as_buffered_mut().is_none());
    assert!(tls_conn.conn.as_unbuffered_mut().is_some());
}

// A fresh connection starts with an empty ciphertext buffer and no
// deferred plaintext; `split_mut` hands back all three parts disjointly.
#[test]
fn fresh_conn_has_empty_buffers() {
    let mut conn = client_conn();
    let (_kind, incoming, pending) = conn.split_mut();
    assert!(incoming.is_empty());
    assert!(pending.is_empty());
}

fn test_certs() -> (
    Vec<ringline_tls::pki_types::CertificateDer<'static>>,
    ringline_tls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = ringline_tls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = ringline_tls::pki_types::CertificateDer::from(cert.cert);
    (vec![cert_der], key.into())
}

fn conn_pair() -> (TlsConn, TlsConn) {
    conn_pair_with_fragment(None)
}

/// A connection pair whose configs pin `max_fragment_size`.
///
/// rustls' field counts the 5-byte record header, so the plaintext per record
/// is `max_fragment_size - 5`; `TlsConn::max_plaintext_per_record` stores the
/// subtracted value, exactly as `TlsTable::create` records it.
fn conn_pair_with_fragment(max_fragment_size: Option<usize>) -> (TlsConn, TlsConn) {
    let (certs, key) = test_certs();
    let mut server_config = ringline_tls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    server_config.max_fragment_size = max_fragment_size;
    let server_config = Arc::new(server_config);
    let mut roots = ringline_tls::RootCertStore::empty();
    for c in &certs {
        roots.add(c.clone()).unwrap();
    }
    let mut client_config = ringline_tls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.max_fragment_size = max_fragment_size;
    let client_config: Arc<ringline_tls::ClientConfig> = client_config.into();
    let name: ServerName<'static> = "localhost".try_into().unwrap();

    let f = crate::tls::plaintext_per_record(max_fragment_size);
    let wrap = |c| TlsConn {
        conn: TlsConnKind::Unbuffered(c),
        handshake_complete: false,
        peer_sent_close_notify: false,
        close_notify_sent: false,
        max_plaintext_per_record: f,
    };
    (
        wrap(UnbufferedConn::new_server(server_config).unwrap()),
        wrap(UnbufferedConn::new_client(client_config, name).unwrap()),
    )
}

/// An unbuffered `(server, client)` pair that has not handshaked, for tests
/// outside this module that need a session the record layer refuses to
/// encrypt application data on. Used by the mio driver tests only.
#[cfg_attr(has_io_uring, allow(dead_code))]
pub(crate) fn fresh_pair() -> (TlsConn, TlsConn) {
    conn_pair()
}

/// An already-handshaked unbuffered `(server, client)` pair, for tests
/// outside this module that need real records from the engine this build
/// compiled in, and a peer able to decrypt them. The buffered twin is
/// `tls::buffered::test_support::handshaked`.
pub(crate) fn handshaked_pair() -> (TlsConn, TlsConn) {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new_with_max(4, 64 * 1024, 1 << 20);
    handshake(&mut server, &mut client, &mut accs);
    assert!(
        !server.conn.is_handshaking(),
        "in-memory unbuffered handshake did not complete"
    );
    (server, client)
}

/// Decrypt `ciphertext` at `to` and return the plaintext, or the error the
/// record layer reported (a sequence gap is `bad_record_mac`).
pub(crate) fn decrypt_at(to: &mut TlsConn, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mut accs = AccumulatorTable::new(2, 4 * 1024 * 1024);
    let mut out = Vec::new();
    match feed(to, Some(&mut accs), &mut out, ciphertext, 0) {
        DriveOutcome::Error(e) => Err(e.to_string()),
        _ => Ok(accs.data(0).to_vec()),
    }
}

/// PR 8's unbuffered slot bound is `slots = records`, which is only an upper
/// bound if each slot carries at least `F` plaintext bytes. `encrypt_chunk`'s
/// whole-record hint decides that, and it must read the connection's own
/// fragment size: with the hardcoded default constants, any overridden
/// `max_fragment_size` below ~16382 makes `whole == 0`, the retry loop
/// converges *below* `F`, and the converged value is cached for every later
/// slot — so a long send silently needs more slots than it was admitted for.
/// By departure 1 that closes the connection instead of applying backpressure,
/// which is the one outcome the bound exists to prevent.
#[test]
fn the_chunk_hint_never_caches_less_than_one_record() {
    // 2048 - 5 = 2043 bytes of plaintext per record; the smallest slot for
    // which `CiphertextCapacity::slots_unbuffered` will express a bound is
    // `F + 29`, and that is exactly what the refusal message tells operators
    // to configure — so it is the size that must work.
    const FRAGMENT: usize = 2048;
    let f = crate::tls::plaintext_per_record(Some(FRAGMENT));
    assert_eq!(f, 2043);
    let dst_len = f + crate::tls::MAX_RECORD_OVERHEAD;

    let (mut server, mut client) = conn_pair_with_fragment(Some(FRAGMENT));
    let mut accs = AccumulatorTable::new_with_max(4, 64 * 1024, 1 << 20);
    handshake(&mut server, &mut client, &mut accs);

    // Enough plaintext that the hint, not the message, decides the chunk.
    let plaintext = vec![0xC3u8; 64 * 1024];
    let mut dst = vec![0u8; dst_len];
    let (chunk, _written) =
        encrypt_chunk(&mut server, &plaintext, &mut dst).expect("a slot of F + 29 must encrypt");

    assert!(
        chunk >= f,
        "a slot of {dst_len} bytes took only {chunk} plaintext bytes, under one \
         {f}-byte record — `slots = records` is then an under-estimate"
    );
    let cached = server
        .conn
        .as_unbuffered_mut()
        .unwrap()
        .max_plaintext_per_chunk;
    assert!(
        cached == 0 || cached >= f,
        "the cache keeps {cached} plaintext bytes per slot, under one {f}-byte \
         record; every later slot inherits it"
    );
}

/// A peer KeyUpdate makes rustls queue a key_update reply, which it writes
/// into the front of the next `encrypt` destination. At a slot of `F + 29`
/// one TLS 1.3 record plus that reply does not fit, so that one call takes
/// less than a record. Later calls must take a whole record again: a cached
/// smaller size would make `slots = records` an under-estimate for the rest
/// of the connection.
#[test]
fn a_queued_key_update_reply_does_not_shrink_later_chunks() {
    const FRAGMENT: usize = 2048;
    let f = crate::tls::plaintext_per_record(Some(FRAGMENT));
    let dst_len = f + crate::tls::MAX_RECORD_OVERHEAD;

    let (mut server, mut client) = conn_pair_with_fragment(Some(FRAGMENT));
    let mut accs = AccumulatorTable::new_with_max(4, 64 * 1024, 1 << 20);
    handshake(&mut server, &mut client, &mut accs);

    queue_key_update_reply(&mut server, &mut client, &mut accs);

    let plaintext = vec![0xC3u8; 64 * 1024];
    let mut dst = vec![0u8; dst_len];
    let (first, _) = encrypt_chunk(&mut server, &plaintext, &mut dst).expect("encrypt");
    assert!(
        first < f,
        "the premise: the reply shares the first slot, so it takes {first} < {f} bytes"
    );
    for _ in 0..2 {
        let (chunk, _) = encrypt_chunk(&mut server, &plaintext, &mut dst).expect("encrypt");
        assert!(
            chunk >= f,
            "after the reply went out a slot of {dst_len} bytes took {chunk} plaintext \
             bytes, under one {f}-byte record"
        );
    }
    let cached = server
        .conn
        .as_unbuffered_mut()
        .unwrap()
        .max_plaintext_per_chunk;
    assert!(
        cached == 0 || cached >= f,
        "the cache keeps {cached} plaintext bytes per slot, under one {f}-byte record"
    );
}

/// The client requests a key update; the server reads it and queues its own
/// key_update in reply, which rustls writes in front of the server's next
/// application data.
fn queue_key_update_reply(server: &mut TlsConn, client: &mut TlsConn, accs: &mut AccumulatorTable) {
    {
        let (kind, incoming, _) = client.conn.as_unbuffered_mut().unwrap().split_mut();
        let super::UnbufferedKind::Client(c) = kind else {
            panic!("the client side is a client connection");
        };
        let status = super::UnbufferedEngine::process(c, incoming.pending());
        match status.state {
            Ok(ringline_tls::unbuffered::ConnectionState::WriteTraffic(wt)) => wt
                .refresh_traffic_keys()
                .expect("a TLS 1.3 connection can request a key update"),
            _ => panic!("a handshaked client with no input is in WriteTraffic"),
        }
    }
    let (_, key_update) = pump(client, &[], accs);
    assert!(!key_update.is_empty(), "the client emits its key_update");
    pump(server, &key_update, accs);
}

/// Push `bytes` into `to`'s ciphertext buffer and drive it, collecting its
/// own output. Returns (outcome, output ciphertext).
fn pump(to: &mut TlsConn, bytes: &[u8], accs: &mut AccumulatorTable) -> (DriveOutcome, Vec<u8>) {
    if !bytes.is_empty() {
        let (_, incoming, _) = to.conn.as_unbuffered_mut().unwrap().split_mut();
        incoming
            .append(bytes)
            .expect("test appends stay under the cap");
    }
    let mut out = Vec::new();
    let outcome = drive(to, Some(&mut *accs), &mut out, 0);
    (outcome, out)
}

/// Run both sides to a completed handshake by feeding each one's output to
/// the other, using `drive()` alone. Returns how many times each side
/// reported `HandshakeJustCompleted`, as (client, server).
fn handshake(
    server: &mut TlsConn,
    client: &mut TlsConn,
    accs: &mut AccumulatorTable,
) -> (u32, u32) {
    let mut client_completions = 0;
    let mut server_completions = 0;

    // Client speaks first (ClientHello) with no input.
    let (outcome, mut to_server) = pump(client, &[], accs);
    if matches!(outcome, DriveOutcome::HandshakeJustCompleted) {
        client_completions += 1;
    }
    assert!(!to_server.is_empty(), "client must emit a ClientHello");

    let mut to_client = Vec::new();
    for _ in 0..10 {
        if !to_server.is_empty() {
            let (o, out) = pump(server, &to_server, accs);
            assert!(!matches!(o, DriveOutcome::Error(_)), "server drive: {o:?}");
            if matches!(o, DriveOutcome::HandshakeJustCompleted) {
                server_completions += 1;
            }
            to_server.clear();
            to_client = out;
        }
        if !to_client.is_empty() {
            let (o, out) = pump(client, &to_client, accs);
            assert!(!matches!(o, DriveOutcome::Error(_)), "client drive: {o:?}");
            if matches!(o, DriveOutcome::HandshakeJustCompleted) {
                client_completions += 1;
            }
            to_client.clear();
            to_server = out;
        }
        if !server.conn.is_handshaking() && !client.conn.is_handshaking() {
            break;
        }
    }

    assert!(!client.conn.is_handshaking(), "client handshake stalled");
    assert!(!server.conn.is_handshaking(), "server handshake stalled");
    (client_completions, server_completions)
}

// A full handshake completes when each side's output is fed to the other
// and both are driven by `drive()` alone. Both report
// HandshakeJustCompleted exactly once.
#[test]
fn drive_completes_a_handshake() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);

    let (client_completions, server_completions) = handshake(&mut server, &mut client, &mut accs);

    assert!(client.handshake_complete);
    assert!(server.handshake_complete);
    assert_eq!(client_completions, 1, "completion must be edge-triggered");
    assert_eq!(server_completions, 1, "completion must be edge-triggered");
}

// A plaintext flood that overruns the accumulator's bound must fail the
// connection, not silently drop bytes: the caller's contract for
// `DriveOutcome::Error` is "tear this connection down". Mirrors
// `drain_tls_plaintext`'s `false` return in the buffered engine.
#[test]
fn plaintext_over_the_sink_bound_fails_the_connection() {
    let (mut server, mut client) = conn_pair();
    // Bound the accumulator well below the payload.
    let mut accs = AccumulatorTable::new_with_max(2, 1024, 4096);
    handshake(&mut server, &mut client, &mut accs);
    accs.reset(0);

    // Encrypt more application data than the accumulator will accept.
    // 32 KiB (three records once framed) rather than more: the whole
    // ciphertext goes in through one `CiphertextBuf::append`, which
    // debug-asserts a `MAX_SINGLE_APPEND` (64 KiB) bound.
    let plaintext = vec![0x7Eu8; 32 * 1024];
    let cipher = encrypt_all(&mut client, &plaintext);

    let (_, incoming, _) = server.conn.as_unbuffered_mut().unwrap().split_mut();
    incoming
        .append(&cipher)
        .expect("test append stays under the cap");
    let mut out = Vec::new();
    let outcome = drive(&mut server, Some(&mut accs), &mut out, 0);
    assert!(
        matches!(outcome, DriveOutcome::Error(_)),
        "over-bound plaintext must fail the connection, got {outcome:?}"
    );
}

// Handshake ciphertext delivered in one-byte pieces drives the machine
// without erroring: each partial record leaves it BlockedHandshake, and
// the byte that completes the ClientHello produces the response. This is
// the ingest path's basic contract — `feed` must never treat "not enough
// yet" as failure.
#[test]
fn feed_handshake_bytes_in_small_pieces() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    let (_, hello) = pump(&mut client, &[], &mut accs);

    let mut out = Vec::new();
    for b in &hello {
        let outcome = feed(&mut server, Some(&mut accs), &mut out, &[*b], 0);
        assert!(!matches!(outcome, DriveOutcome::Error(_)), "{outcome:?}");
    }
    assert!(!out.is_empty(), "server must answer a complete ClientHello");
}

// A single `feed` call larger than MAX_SINGLE_APPEND is chunked rather
// than tripping `append`'s debug_assert; the assert is silent in release.
#[test]
fn feed_chunks_oversized_input() {
    let (mut server, _client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);

    // Garbage, but it must be *appended* in chunks before rustls rejects
    // it — the assertion is that we get a clean protocol error rather
    // than a debug_assert panic.
    let junk = vec![0u8; MAX_SINGLE_APPEND * 2 + 7];
    let mut out = Vec::new();
    let outcome = feed(&mut server, Some(&mut accs), &mut out, &junk, 0);
    assert!(
        matches!(outcome, DriveOutcome::Error(_)),
        "unparseable ciphertext must be a protocol error, got {outcome:?}"
    );
}

/// Drive the handshake but hold back the client's final flight, returning
/// it undelivered. Lets a test put that flight and post-handshake records
/// into one `feed` — which is what a peer does by coalescing them onto a
/// single segment.
fn handshake_holding_client_flight(
    server: &mut TlsConn,
    client: &mut TlsConn,
    accs: &mut AccumulatorTable,
) -> Vec<u8> {
    let (_, mut to_server) = pump(client, &[], accs);
    for _ in 0..10 {
        let (_, to_client) = pump(server, &to_server, accs);
        assert!(!to_client.is_empty(), "server must answer");
        let (_, out) = pump(client, &to_client, accs);
        to_server = out;
        if !client.conn.is_handshaking() {
            break;
        }
    }
    assert!(!client.conn.is_handshaking(), "client handshake stalled");
    assert!(
        server.conn.is_handshaking(),
        "the server must still be waiting on the flight held back"
    );
    assert!(!to_server.is_empty(), "client must emit a final flight");
    to_server
}

/// Encrypt `plaintext` on `from`, returning all of its ciphertext, through
/// the same entry point the mio backend uses.
fn encrypt_all(from: &mut TlsConn, plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = Vec::new();
    super::encrypt_to_vec(from, plaintext, &mut cipher).expect("encrypt");
    cipher
}

// A feed that both completes the handshake and sees close_notify must
// report the completion: the backends wake a connect waiter only on
// `HandshakeJustCompleted` — the `Closed` arm does not, and
// `close_connection` does not either — so losing that edge hangs an
// outbound TLS connect until its timeout. The close is not lost:
// `peer_sent_close_notify` still carries it.
//
// The two signals must land in *different* chunks for this to exercise
// `fold_outcome`: one chunk is one `drive`, and `drive` already applies
// the precedence itself. Hence the application data padding the flight
// past `MAX_SINGLE_APPEND` — which is also how a real peer would produce
// it, by coalescing its last flight, some data and the alert.
#[test]
fn handshake_completion_outranks_a_close_in_the_same_feed() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    let mut coalesced = handshake_holding_client_flight(&mut server, &mut client, &mut accs);

    let record = vec![0x5Au8; 8 * 1024];
    while coalesced.len() <= MAX_SINGLE_APPEND {
        coalesced.extend_from_slice(&encrypt_all(&mut client, &record));
    }
    let mut alert = Vec::new();
    queue_close_notify(&mut client, &mut alert).expect("queue close_notify");
    assert!(!alert.is_empty(), "the close must be a real alert");
    coalesced.extend_from_slice(&alert);
    assert!(
        coalesced.len() > MAX_SINGLE_APPEND,
        "the alert must fall in a later chunk than the flight"
    );

    let mut out = Vec::new();
    let outcome = feed(&mut server, Some(&mut accs), &mut out, &coalesced, 0);
    assert!(
        matches!(outcome, DriveOutcome::HandshakeJustCompleted),
        "completion must outrank the close, got {outcome:?}"
    );
    assert!(
        server.peer_sent_close_notify,
        "the close must still be recorded on the connection"
    );
}

// A queued close_notify is a real encrypted alert: the peer sees it as a
// clean close (PeerClosed -> Closed), not as a truncation.
#[test]
fn close_notify_is_seen_as_a_clean_close() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 1024 * 1024);
    handshake(&mut server, &mut client, &mut accs);
    accs.reset(0);

    let mut alert = Vec::new();
    queue_close_notify(&mut client, &mut alert).expect("queue close_notify");
    assert!(!alert.is_empty(), "close_notify must produce ciphertext");
    assert!(client.close_notify_sent);

    let mut out = Vec::new();
    let outcome = feed(&mut server, Some(&mut accs), &mut out, &alert, 0);
    assert!(matches!(outcome, DriveOutcome::Closed), "got {outcome:?}");
    assert!(
        server.peer_sent_close_notify,
        "eof_truncated() depends on this flag being set"
    );
}

// Closing a connection that never reached traffic state is a clean no-op,
// not an error: there is no alert to encrypt, so nothing is queued and the
// close-notify deadline is not armed for a record that was never sent. The
// teardown path calls this unconditionally, including on connections that
// died mid-handshake.
#[test]
fn close_notify_on_a_handshaking_connection_queues_nothing() {
    let (mut server, _client) = conn_pair();
    let mut out = Vec::new();
    queue_close_notify(&mut server, &mut out).expect("a mid-handshake close is not an error");
    assert!(
        out.is_empty(),
        "there is nothing to queue before traffic state"
    );
    assert!(
        !server.close_notify_sent,
        "arming the close deadline for an unsent alert invents a stall"
    );
}

// An empty feed drives the machine rather than doing nothing. A fresh
// client has a ClientHello queued with no ciphertext to deframe, and the
// backends flush it exactly this way once the TCP connect completes — so
// if `feed` short-circuited on an empty slice, outbound TLS would never
// send its first flight.
#[test]
fn an_empty_feed_still_drives_the_machine() {
    let (_server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    let mut out = Vec::new();

    let outcome = feed(&mut client, Some(&mut accs), &mut out, &[], 0);

    assert!(matches!(outcome, DriveOutcome::Ok), "got {outcome:?}");
    assert!(
        !out.is_empty(),
        "an empty feed must still emit the ClientHello"
    );
}

// A `WouldBlock` that a drive can relieve is backpressure, not failure:
// `feed` drains, retries the *same* chunk, and delivers every byte in
// order. `append` is all-or-nothing, so a caller that dropped the chunk
// here would silently lose a whole record.
//
// The buffer is put into the refusing state directly — an unprocessed but
// complete record sitting behind a consumed prefix — because `feed` alone
// cannot produce it: every append it makes is followed by a drive that
// drains everything drainable. The branch exists so a `drive` that ever
// stops short is backpressure rather than data loss.
#[test]
fn feed_retries_an_append_a_drive_can_relieve() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    handshake(&mut server, &mut client, &mut accs);

    // Encrypted in the order they are fed; TLS records are sequenced.
    let marker = encrypt_all(&mut client, &[0xA1u8; 16]);
    let held = encrypt_all(&mut client, &[0xB2u8; 2000]);
    let next = encrypt_all(&mut client, &[0xC3u8; 2000]);

    // `cap == live + additional` is the tightest cap that still admits the
    // append on retry, so `append` must refuse it while `marker`'s
    // consumed prefix keeps `end` ahead of `live`.
    let cap = held.len() + next.len();
    assert!(
        marker.len() < held.len(),
        "compaction must not pay for itself"
    );
    server
        .conn
        .as_unbuffered_mut()
        .unwrap()
        .set_ciphertext_cap_for_test(512, cap);

    // Consume `marker` so `start > 0`, leaving `held` half-delivered.
    let split = held.len() / 2;
    let mut prefix = marker.clone();
    prefix.extend_from_slice(&held[..split]);
    let mut out = Vec::new();
    {
        let outcome = feed(&mut server, Some(&mut accs), &mut out, &prefix, 0);
        assert!(matches!(outcome, DriveOutcome::Ok), "{outcome:?}");
    }

    // Complete `held` without driving, so the refusing buffer is full of
    // data a drive *can* consume.
    {
        let (_, incoming, _) = server.conn.as_unbuffered_mut().unwrap().split_mut();
        incoming
            .append(&held[split..])
            .expect("completing the held record fits under the cap");
    }
    accs.reset(0);

    let outcome = feed(&mut server, Some(&mut accs), &mut out, &next, 0);
    assert!(
        matches!(outcome, DriveOutcome::Ok),
        "relievable backpressure must not fail the connection, got {outcome:?}"
    );
    let mut expected = vec![0xB2u8; 2000];
    expected.extend_from_slice(&[0xC3u8; 2000]);
    assert_eq!(
        accs.data(0),
        &expected[..],
        "the retried chunk must arrive intact and in order"
    );
}

// A `WouldBlock` no drive can relieve fails the connection. Retrying it
// forever would pin a worker thread, and in a thread-per-core runtime
// that is a wedged core, not a slow one.
#[test]
fn feed_fails_rather_than_spinning_on_an_undrainable_buffer() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    handshake(&mut server, &mut client, &mut accs);

    let marker = encrypt_all(&mut client, &[0xA1u8; 16]);
    let stuck = encrypt_all(&mut client, &[0xB2u8; 2000]);
    let next = encrypt_all(&mut client, &[0xC3u8; 2000]);

    // Only half of `stuck` is ever delivered, so rustls buffers it waiting
    // for the rest and discards nothing — no drive can free a byte.
    let split = stuck.len() / 2;
    let cap = split + next.len();
    assert!(marker.len() < split, "compaction must not pay for itself");
    server
        .conn
        .as_unbuffered_mut()
        .unwrap()
        .set_ciphertext_cap_for_test(512, cap);

    let mut prefix = marker.clone();
    prefix.extend_from_slice(&stuck[..split]);
    let mut out = Vec::new();
    {
        let outcome = feed(&mut server, Some(&mut accs), &mut out, &prefix, 0);
        assert!(matches!(outcome, DriveOutcome::Ok), "{outcome:?}");
    }

    let outcome = feed(&mut server, Some(&mut accs), &mut out, &next, 0);
    let DriveOutcome::Error(err) = outcome else {
        panic!("an undrainable buffer must fail the connection, got {outcome:?}");
    };
    assert!(
        err.to_string().contains("undrainable"),
        "must be the anti-spin guard, not an unrelated failure: {err}"
    );
}

// Round-trip: encrypt on the client through the chunking path, decrypt on
// the server through `feed`. Exercises multi-record plaintext (> 16 KiB)
// so the fragmenter and the chunk-size retry both run.
#[test]
fn encrypt_round_trips_multi_record_plaintext() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4 * 1024 * 1024);
    handshake(&mut server, &mut client, &mut accs);
    accs.reset(0);

    let plaintext: Vec<u8> = (0..300_000u32)
        .map(|i| i.wrapping_mul(2654435761) as u8)
        .collect();
    let cipher = encrypt_all(&mut client, &plaintext);

    let mut out = Vec::new();
    let outcome = feed(&mut server, Some(&mut accs), &mut out, &cipher, 0);
    assert!(matches!(outcome, DriveOutcome::Ok), "got {outcome:?}");
    assert_eq!(accs.data(0), &plaintext[..]);
}

// `encrypt_to_vec` sizes each destination to the ciphertext it will hold, so
// `out` is allocated once per send. A destination of 32 KiB per record, as
// before, could grow `out` part-way through a multi-record send, and growing
// a `Vec` can copy the ciphertext already written.
#[test]
fn encrypt_to_vec_allocates_its_ciphertext_once() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4 * 1024 * 1024);
    handshake(&mut server, &mut client, &mut accs);
    accs.reset(0);

    let f = DEFAULT_MAX_PLAINTEXT_PER_RECORD;
    let mut sent = Vec::new();
    let mut wire = Vec::new();
    for len in [
        1,
        64,
        4096,
        f,
        f + 1,
        2 * f - 1,
        4 * f,
        4 * f + 100,
        300_000,
    ] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut out = Vec::new();
        super::encrypt_to_vec(&mut client, &plaintext, &mut out).expect("encrypt");
        assert_eq!(
            out.len(),
            len + len.div_ceil(f) * (DEFAULT_RECORD_WIRE_LEN - f),
            "{len} bytes of plaintext in full-size TLS 1.3 records"
        );
        assert!(
            out.capacity() <= out.len() + 2 * super::QUEUED_RECORD_ROOM,
            "{len} bytes: capacity {} for {} bytes of ciphertext, more than the \
             ciphertext plus the room `encrypt_to_vec` reserves",
            out.capacity(),
            out.len()
        );
        sent.extend_from_slice(&plaintext);
        wire.extend_from_slice(&out);
    }

    let mut out = Vec::new();
    let outcome = feed(&mut server, Some(&mut accs), &mut out, &wire, 0);
    assert!(matches!(outcome, DriveOutcome::Ok), "got {outcome:?}");
    assert_eq!(accs.data(0), &sent[..]);
}

// A key_update rustls has queued rides in front of the next send's records,
// inside the room `encrypt_to_vec` leaves for it: the send still takes one
// allocation, and the peer reads the reply and the data in order.
#[test]
fn encrypt_to_vec_carries_a_queued_key_update() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new_with_max(4, 64 * 1024, 4 << 20);
    handshake(&mut server, &mut client, &mut accs);
    queue_key_update_reply(&mut server, &mut client, &mut accs);
    accs.reset(0);
    accs.reset(1);

    let plaintext: Vec<u8> = (0..3 * DEFAULT_MAX_PLAINTEXT_PER_RECORD + 7)
        .map(|i| (i % 251) as u8)
        .collect();
    let mut out = Vec::new();
    super::encrypt_to_vec(&mut server, &plaintext, &mut out).expect("encrypt");
    // A TLS 1.3 key_update record: 5-byte header, 4-byte handshake header, 1
    // byte of request, content type and tag.
    const KEY_UPDATE_RECORD: usize = 5 + 4 + 1 + 1 + 16;
    assert_eq!(
        out.len(),
        plaintext.len()
            + 4 * (DEFAULT_RECORD_WIRE_LEN - DEFAULT_MAX_PLAINTEXT_PER_RECORD)
            + KEY_UPDATE_RECORD,
        "the key_update reply rides in front of the four data records"
    );
    assert!(
        out.capacity() <= out.len() + 2 * super::QUEUED_RECORD_ROOM,
        "capacity {} for {} bytes of ciphertext",
        out.capacity(),
        out.len()
    );

    let mut back = Vec::new();
    let outcome = feed(&mut client, Some(&mut accs), &mut back, &out, 0);
    assert!(matches!(outcome, DriveOutcome::Ok), "got {outcome:?}");
    assert_eq!(accs.data(0), &plaintext[..]);
}

// A destination buffer far smaller than one record still makes progress:
// the chunk size shrinks from rustls' own `required_size` rather than a
// hardcoded overhead constant.
#[test]
fn encrypt_converges_on_a_small_destination() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 1024 * 1024);
    handshake(&mut server, &mut client, &mut accs);
    accs.reset(0);

    let plaintext = vec![0x42u8; 20_000];
    let mut cipher = Vec::new();
    let mut offset = 0;
    // 512-byte destinations: every call must fit, and the loop must
    // terminate.
    while offset < plaintext.len() {
        let mut dst = vec![0u8; 512];
        let (used_pt, used_ct) = super::encrypt_chunk(&mut client, &plaintext[offset..], &mut dst)
            .expect("encrypt into a small buffer");
        assert!(used_pt > 0, "must make progress");
        assert!(used_ct <= 512);
        cipher.extend_from_slice(&dst[..used_ct]);
        offset += used_pt;
    }

    let mut out = Vec::new();
    let outcome = feed(&mut server, Some(&mut accs), &mut out, &cipher, 0);
    assert!(matches!(outcome, DriveOutcome::Ok), "got {outcome:?}");
    assert_eq!(accs.data(0), &plaintext[..]);
}

// A short send must not teach the connection a small chunk size. The cache
// is a starting point for every later send on the connection and only ever
// shrinks, so a 100-byte send that cached its own size would fragment
// every subsequent send into 100-byte records with no way back.
#[test]
fn a_short_send_does_not_poison_the_chunk_cache() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    handshake(&mut server, &mut client, &mut accs);

    // Two big sends against the same destination size: the first learns
    // the ceiling, the second confirms it has converged.
    let big = vec![0x11u8; 64 * 1024];
    let mut dst = vec![0u8; 4096];
    super::encrypt_chunk(&mut client, &big, &mut dst).expect("encrypt");
    let (converged, _) = super::encrypt_chunk(&mut client, &big, &mut dst).expect("encrypt");
    assert!(
        converged > 1024,
        "a 4 KiB destination fits far more than that"
    );

    // A short send, same destination size.
    let (used, _) = super::encrypt_chunk(&mut client, &[0x22u8; 100], &mut dst).expect("encrypt");
    assert_eq!(used, 100);

    let (after, _) = super::encrypt_chunk(&mut client, &big, &mut dst).expect("encrypt");
    assert_eq!(
        after, converged,
        "a short send must not shrink the cached chunk size"
    );
}

/// A destination that can hold whole maximum-size records must be filled with
/// whole records — one full 2^14 fragment per record, no sliver.
///
/// Starting the chunk at `dst.len()` instead overshoots (ciphertext is bigger
/// than plaintext), and the `InsufficientSize` retry scales down
/// *proportionally*, landing just under a fragment boundary rather than on it.
/// That costs an extra record on any send big enough to be split, and for a
/// `dst` between one and two record wire sizes it converges on a full record
/// plus a sliver — doubling the record count.
#[test]
fn a_whole_record_destination_encrypts_whole_records() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    handshake(&mut server, &mut client, &mut accs);

    let big = vec![0x33u8; 512 * 1024];
    for records in 1..=4usize {
        let mut dst = vec![0u8; records * DEFAULT_RECORD_WIRE_LEN];
        // Twice: the first call may still learn, the second is steady state.
        super::encrypt_chunk(&mut client, &big, &mut dst).expect("encrypt");
        let (used_pt, used_ct) =
            super::encrypt_chunk(&mut client, &big, &mut dst).expect("encrypt");
        assert_eq!(
            used_pt,
            records * DEFAULT_MAX_PLAINTEXT_PER_RECORD,
            "a {records}-record destination must take {records} full fragments"
        );
        assert_eq!(
            used_ct,
            records * DEFAULT_RECORD_WIRE_LEN,
            "and emit exactly {records} full records, filling dst"
        );
    }
}

/// The default send slot (`send_pool`'s slot size) holds one full record, so a
/// send that is a multiple of 16 KiB costs one record per 16 KiB, as on the
/// buffered engine.
#[test]
fn the_default_send_slot_takes_one_full_record() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    handshake(&mut server, &mut client, &mut accs);

    let slot = crate::ConfigBuilder::new()
        .build()
        .expect("default config")
        .send_copy_slot_size as usize;
    let big = vec![0x44u8; 64 * 1024];
    let mut dst = vec![0u8; slot];
    super::encrypt_chunk(&mut client, &big, &mut dst).expect("encrypt");
    let (used_pt, used_ct) = super::encrypt_chunk(&mut client, &big, &mut dst).expect("encrypt");
    assert_eq!(
        used_pt, DEFAULT_MAX_PLAINTEXT_PER_RECORD,
        "one full fragment"
    );
    assert_eq!(used_ct, DEFAULT_RECORD_WIRE_LEN, "in one record");
}

/// A 16384-byte send slot misses a full record by 22 bytes, so there is no
/// whole-record answer for it. It must fall back to the retry loop and
/// still converge on the largest chunk that fits, rather than failing or
/// stalling.
#[test]
fn a_destination_below_one_record_still_converges() {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    handshake(&mut server, &mut client, &mut accs);

    let big = vec![0x44u8; 128 * 1024];
    let mut dst = vec![0u8; 16384];
    super::encrypt_chunk(&mut client, &big, &mut dst).expect("encrypt");
    let (used_pt, used_ct) = super::encrypt_chunk(&mut client, &big, &mut dst).expect("encrypt");
    assert!(used_ct <= dst.len(), "must not overrun dst");
    assert!(
        used_pt > DEFAULT_MAX_PLAINTEXT_PER_RECORD - 64,
        "should still get within a few bytes of a full fragment, got {used_pt}"
    );
}

// `BlockedHandshake` with nothing to send is a quiet return, not an error
// and not a spin: a freshly-created server has no input and emits nothing.
#[test]
fn drive_on_a_blocked_server_is_quiet() {
    let (mut server, _client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 4096);
    let (outcome, out) = pump(&mut server, &[], &mut accs);
    assert!(matches!(outcome, DriveOutcome::Ok), "got {outcome:?}");
    assert!(out.is_empty());
}

/// Stage `ciphertext` in `to`'s incoming buffer *without* driving, so the next
/// call into the state machine — whichever path makes it — is the one that
/// deframes it.
fn stage_incoming(to: &mut TlsConn, ciphertext: &[u8]) {
    let (_, incoming, _) = to.conn.as_unbuffered_mut().unwrap().split_mut();
    incoming
        .append(ciphertext)
        .expect("test appends stay under the cap");
}

/// A handshaked server with the client's close_notify sitting undriven in its
/// ciphertext buffer.
fn server_with_undriven_peer_close() -> TlsConn {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 1024 * 1024);
    handshake(&mut server, &mut client, &mut accs);
    accs.reset(0);

    let mut alert = Vec::new();
    queue_close_notify(&mut client, &mut alert).expect("queue close_notify");
    assert!(!alert.is_empty(), "close_notify must produce ciphertext");
    stage_incoming(&mut server, &alert);
    assert!(
        !server.peer_sent_close_notify,
        "staging must not drive the machine"
    );
    server
}

// `ConnectionState::PeerClosed` is edge-triggered (`emitted_peer_closed_state`
// in rustls): whichever `process_tls_records` call deframes the peer's
// close_notify is the only one that will ever report it. The send path can be
// that call — nothing serialises recv ahead of it — so it has to record the
// flag rather than swallow the state. Dropping it leaves
// `peer_sent_close_notify` false and makes the peer's following FIN read as a
// truncation: `eof_truncated()` would report an attack that did not happen.
#[test]
fn encrypt_records_a_peer_close_it_deframes() {
    let mut server = server_with_undriven_peer_close();

    let mut dst = [0u8; 4096];
    // The result is beside the point — a closed connection cannot encrypt.
    // What matters is that the edge was not lost on the way to that answer.
    let _ = encrypt_chunk(&mut server, b"hello", &mut dst);

    assert!(
        server.peer_sent_close_notify,
        "the send path consumed the PeerClosed edge without recording it"
    );
}

// Same edge, same argument, through the close path: tearing a connection down
// is exactly when a lost `PeerClosed` would be mistaken for a truncation.
#[test]
fn close_notify_records_a_peer_close_it_deframes() {
    let mut server = server_with_undriven_peer_close();

    let mut out = Vec::new();
    queue_close_notify(&mut server, &mut out).expect("a closed connection is not an error");

    assert!(
        server.peer_sent_close_notify,
        "the close path consumed the PeerClosed edge without recording it"
    );
    assert!(
        out.is_empty(),
        "a peer that already closed leaves nothing to queue"
    );
}

/// A server holding the client's first flight in its ciphertext buffer,
/// undriven — so the next `process_tls_records` deframes it, queues the
/// server's reply into `sendable_tls`, and hands back `EncodeTlsData`.
fn server_with_undriven_peer_flight() -> TlsConn {
    let (mut server, mut client) = conn_pair();
    let mut accs = AccumulatorTable::new(2, 1024 * 1024);
    let (_outcome, hello) = pump(&mut client, &[], &mut accs);
    assert!(!hello.is_empty(), "client must emit a ClientHello");
    stage_incoming(&mut server, &hello);
    server
}

// `ConnectionState::EncodeTlsData` is destructive to construct: rustls pops the
// record out of `sendable_tls` and moves it into the value, and never puts it
// back. So a send path that lets it fall into a catch-all silently destroys a
// TLS record that was queued for the wire. The engine must name that instead —
// a generic `WouldBlock` reads as "try again later", which is precisely wrong
// when a record has just been thrown away.
//
// ringline's own call sites cannot reach this (a `Connection` is only handed out
// once the handshake completes), but the engine is one call away from it, which
// is why the arm is explicit rather than assumed-unreachable.
#[test]
fn encrypt_reports_a_dropped_queued_record() {
    let mut server = server_with_undriven_peer_flight();

    let mut dst = [0u8; 4096];
    let err = encrypt_chunk(&mut server, b"hello", &mut dst)
        .expect_err("a server mid-handshake cannot encrypt application data");

    assert_ne!(
        err.kind(),
        std::io::ErrorKind::WouldBlock,
        "a discarded record must not be reported as retryable backpressure"
    );
    assert!(
        err.to_string().contains("queued TLS record was dropped"),
        "the error must name what was lost, got: {err}"
    );
}

/// A handshaked server whose close_notify rustls has already queued into its
/// output without encoding it: the state TLS 1.2 traffic-key exhaustion
/// leaves behind, where `write_plaintext` calls `send_close_notify()` itself
/// before returning `EncryptExhausted`. Reproduced here by asking
/// `WriteTraffic::queue_close_notify` for the alert with no room, which
/// queues it and reports the size it needs.
fn server_with_queued_close_notify() -> (TlsConn, TlsConn) {
    let (mut server, client) = handshaked_pair();
    {
        let conn = server.conn.as_unbuffered_mut().unwrap();
        let (kind, incoming, _) = conn.split_mut();
        let super::UnbufferedKind::Server(c) = kind else {
            panic!("server side");
        };
        let status = super::UnbufferedEngine::process(c, incoming.pending());
        let Ok(ringline_tls::unbuffered::ConnectionState::WriteTraffic(mut wt)) = status.state
        else {
            panic!("a handshaked server is in traffic state");
        };
        let mut none: [u8; 0] = [];
        assert!(
            matches!(
                wt.queue_close_notify(&mut none),
                Err(ringline_tls::unbuffered::EncryptError::InsufficientSize(_))
            ),
            "the alert is queued and reported as needing room"
        );
    }
    (server, client)
}

/// The close path encodes a record rustls already queued instead of dropping
/// it. On TLS 1.2 traffic-key exhaustion that record is the close_notify
/// rustls queued itself, so the peer reads a clean close rather than a
/// truncated stream, and `close_notify_sent` records what went out.
#[test]
fn close_notify_encodes_the_alert_rustls_already_queued() {
    let (mut server, mut client) = server_with_queued_close_notify();

    let mut out = Vec::new();
    queue_close_notify(&mut server, &mut out).expect("the queued alert goes out");
    assert!(
        !out.is_empty() && out[0] == 21,
        "the output holds the alert record, got {out:?}"
    );
    assert!(server.close_notify_sent, "the alert went out");

    let mut accs = AccumulatorTable::new(2, 1024 * 1024);
    let (outcome, _) = pump(&mut client, &out, &mut accs);
    assert!(
        matches!(outcome, DriveOutcome::Closed),
        "the peer reads a clean close, got {outcome:?}"
    );
    assert!(client.peer_sent_close_notify);
}

/// A server closed before its handshake finished has no alert to queue; the
/// handshake records rustls had queued go out ahead of the FIN rather than
/// being dropped, and no alert is recorded as sent.
#[test]
fn close_notify_before_the_handshake_sends_the_queued_flight_and_no_alert() {
    let mut server = server_with_undriven_peer_flight();

    let mut out = Vec::new();
    queue_close_notify(&mut server, &mut out).expect("nothing to queue is not an error");
    assert!(
        !out.is_empty() && out[0] == 22,
        "the queued handshake flight is encoded, got {out:?}"
    );
    assert!(
        !server.close_notify_sent,
        "no alert was sent, so the close deadline must not be armed"
    );
}

/// A receive error leaves the alert rustls generated for it in the engine's
/// output, so the peer learns why the connection ended instead of reading a
/// bare FIN. rustls appends the alert to its output while reporting the
/// error and hands it back only on the next call into the state machine, so
/// the engine has to make that call before it returns the error.
#[test]
fn a_receive_error_puts_the_fatal_alert_in_the_output() {
    let (mut server, mut client) = handshaked_pair();
    let mut accs = AccumulatorTable::new_with_max(4, 64 * 1024, 1 << 20);

    let mut record = vec![0u8; 4096];
    let (_, used_ct) = encrypt_chunk(&mut client, b"hello", &mut record).expect("encrypt");
    record.truncate(used_ct);
    // Flip a byte of the tag: the server reports bad_record_mac.
    let last = record.len() - 1;
    record[last] ^= 0xff;

    let (outcome, out) = pump(&mut server, &record, &mut accs);
    assert!(
        matches!(outcome, DriveOutcome::Error(_)),
        "a corrupted record is a fatal error, got {outcome:?}"
    );
    assert!(
        !out.is_empty() && out[0] == 21,
        "the output holds the alert record (content type 21), got {out:?}"
    );
    let err = decrypt_at(&mut client, &out).expect_err("the client reads a fatal alert");
    assert!(
        err.contains("alert"),
        "the client sees the alert, got: {err}"
    );
}

/// A client that rustls holds a partial post-handshake handshake message
/// for: the server's NewSessionTicket is split across 32-byte records, and
/// only the first has been fed. rustls keeps its offset into the buffer it
/// was handed.
#[cfg(has_io_uring)]
fn client_with_partial_ticket() -> TlsConn {
    let (mut server, mut client) = conn_pair_with_fragment(Some(32));
    let mut accs = AccumulatorTable::new_with_max(4, 64 * 1024, 1 << 20);
    let (_, hello) = pump(&mut client, &[], &mut accs);
    let (_, flight) = pump(&mut server, &hello, &mut accs);
    let mut finished = Vec::new();
    // One record at a time, so no single feed is large.
    for record in split_records(&flight) {
        let (outcome, out) = pump(&mut client, record, &mut accs);
        assert!(!matches!(outcome, DriveOutcome::Error(_)), "{outcome:?}");
        finished.extend_from_slice(&out);
    }
    assert!(!client.conn.is_handshaking());
    let (_, tickets) = pump(&mut server, &finished, &mut accs);
    let records = split_records(&tickets);
    assert!(
        records.len() >= 2,
        "the ticket spans {} records",
        records.len()
    );
    let (outcome, _) = pump(&mut client, records[0], &mut accs);
    assert!(!matches!(outcome, DriveOutcome::Error(_)), "{outcome:?}");
    let (_, incoming, _) = client.conn.as_unbuffered_mut().unwrap().split_mut();
    assert!(
        !incoming.is_empty(),
        "rustls keeps the partial ticket's record"
    );
    client
}

/// Split a buffer of whole TLS records into the records.
#[cfg(has_io_uring)]
fn split_records(bytes: &[u8]) -> Vec<&[u8]> {
    let mut records = Vec::new();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        let len = u16::from_be_bytes([bytes[i + 3], bytes[i + 4]]) as usize;
        records.push(&bytes[i..i + 5 + len]);
        i += 5 + len;
    }
    records
}

/// A send while a receive is in flight hands rustls the same unprocessed
/// bytes as without one. rustls keeps an offset into those bytes for a
/// partial handshake message; handing it fewer panics in rustls.
#[cfg(has_io_uring)]
#[test]
fn a_send_while_a_receive_is_in_flight_sees_the_partial_message() {
    let mut client = client_with_partial_ticket();
    let (_, room) = client
        .conn
        .as_unbuffered_mut()
        .unwrap()
        .arm_recv(32 * 1024)
        .expect("room");
    assert!(room > 0);
    let mut dst = [0u8; 4096];
    encrypt_chunk(&mut client, b"hello", &mut dst).expect("encrypt during the receive");
    // SAFETY: nothing was written.
    unsafe { client.conn.as_unbuffered_mut().unwrap().recv_done(0) };
}

/// As for a send, a close_notify while a receive is in flight.
#[cfg(has_io_uring)]
#[test]
fn a_close_notify_while_a_receive_is_in_flight_sees_the_partial_message() {
    let mut client = client_with_partial_ticket();
    client
        .conn
        .as_unbuffered_mut()
        .unwrap()
        .arm_recv(32 * 1024)
        .expect("room");
    let mut out = Vec::new();
    queue_close_notify(&mut client, &mut out).expect("close_notify during the receive");
    assert!(!out.is_empty(), "the alert was produced");
    // SAFETY: nothing was written.
    unsafe { client.conn.as_unbuffered_mut().unwrap().recv_done(0) };
}
