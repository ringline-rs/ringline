//! `SendHalf::abort` on a peer that has stopped reading
//! (`docs/send-admission-design.md`, section 3). One worker, so that every
//! connection shares a ring: an idle connection opened first keeps its hangup
//! poll pending, which before Linux 6.13 holds a plain or `SO_LINGER` close of
//! a later connection's fixed file. The abort must not wait for it.
//!
//! On io_uring the aborted connection holds a zero-copy send of more than the
//! socket buffers take, a queued send and a send waiting for send-pool
//! capacity. Both backends check the reset, the refusal of a later send and,
//! on TLS, that no close_notify is sent.

#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

mod common;

/// The tests share the statics below, and `cargo test` runs them in one
/// process.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the aborting task saw, for the test thread to check.
#[derive(Debug, Default)]
struct Seen {
    /// When `abort` returned.
    aborted_at: Option<Instant>,
    /// The result of the sends queued behind the first one.
    queued: Option<String>,
    /// The result of the send waiting for send-pool capacity.
    waiting: Option<String>,
    /// The result of a send made after `abort`.
    late: Option<String>,
    /// The result of a bounded send made after `abort`.
    late_admitted: Option<String>,
}

static SEEN: Mutex<Option<Seen>> = Mutex::new(None);

/// When the zero-copy send's guard was dropped: its slab entry was released.
#[cfg(has_io_uring)]
static GUARD_DROPPED_AT: Mutex<Option<Instant>> = Mutex::new(None);

const SLOT: usize = 32768;
const SLOTS: u16 = 8;

/// Larger than the loopback socket buffers hold, and small enough to fit
/// under an 8 MiB `RLIMIT_MEMLOCK`.
#[cfg(has_io_uring)]
const GUARD_LEN: usize = 4 << 20;

#[cfg(has_io_uring)]
struct VecGuard(Vec<u8>);

#[cfg(has_io_uring)]
impl ringline::SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> ringline::RegionId {
        ringline::RegionId::UNREGISTERED
    }
}

#[cfg(has_io_uring)]
impl Drop for VecGuard {
    fn drop(&mut self) {
        *GUARD_DROPPED_AT.lock().unwrap() = Some(Instant::now());
    }
}

/// What `abort`'s sends fail with.
const ABORTED: &str = "ConnectionAborted: connection aborted";

/// A failed send's kind and message, which tells `abort`'s refusal
/// ("connection aborted") from a released connection's ("connection closed").
fn kind(result: io::Result<impl Sized>) -> String {
    match result {
        Ok(_) => panic!("the send succeeded"),
        Err(e) => format!("{:?}: {e}", e.kind()),
    }
}

/// The first byte a peer writes picks the connection's part: `i` reads until
/// the peer closes, and `a` fills its sends and aborts.
struct Aborter;

impl AsyncEventHandler for Aborter {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut first = 0u8;
            conn.with_data(|data| {
                first = data[0];
                ParseResult::Consumed(data.len())
            })
            .await;
            if first == b'i' {
                while conn
                    .with_data(|data| ParseResult::Consumed(data.len()))
                    .await
                    > 0
                {}
                return;
            }
            let mut seen = Seen::default();
            fill_and_abort(&mut conn, &mut seen).await;
            seen.late = Some(kind(conn.send(b"late")));
            *SEEN.lock().unwrap() = Some(seen);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Aborter
    }
}

/// More than the socket buffers take, four bounded sends queued behind it
/// holding send-pool slots, and a bounded send waiting for more slots than are
/// free; then `abort`, the sends' results, and the result of a bounded send
/// made after it.
async fn fill_and_abort(conn: &mut Connection, seen: &mut Seen) {
    static QUEUED: [u8; SLOT] = [1; SLOT];
    static WAITING: [u8; 6 * SLOT] = [2; 6 * SLOT];
    fill(conn);
    let mut queued = Vec::new();
    for _ in 0..4 {
        queued.push(conn.send_admitted(&QUEUED).await.expect("admitted"));
    }
    let mut waiting = std::pin::pin!(conn.send_admitted(&WAITING));
    let first = std::future::poll_fn(|cx| std::task::Poll::Ready(waiting.as_mut().poll(cx))).await;
    assert!(first.is_pending(), "the send waits for capacity");
    ringline::sleep(Duration::from_millis(100)).await;

    conn.abort();
    seen.aborted_at = Some(Instant::now());

    seen.waiting = Some(kind(waiting.await));
    let mut kinds = Vec::new();
    for send in queued {
        kinds.push(kind(send.await));
    }
    assert!(kinds.iter().all(|k| *k == kinds[0]), "{kinds:?}");
    seen.queued = Some(kinds[0].clone());
    seen.late_admitted = Some(kind(conn.send_admitted(b"late").await));
}

/// On io_uring: a zero-copy send the peer will not take in full.
#[cfg(has_io_uring)]
fn fill(conn: &mut Connection) {
    let guard = ringline::GuardBox::new(VecGuard(vec![7; GUARD_LEN]));
    conn.send_parts()
        .build(|b| b.guard(guard).submit())
        .expect("guard send accepted");
}

/// On mio: plain sends, which take no send-pool slot.
#[cfg(not(has_io_uring))]
fn fill(conn: &mut Connection) {
    for _ in 0..64 {
        conn.send_nowait(&[1; 1 << 16]).expect("queued");
    }
}

fn launch<H: AsyncEventHandler>(
    tls: Option<ringline::TlsConfig>,
) -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
) {
    let mut config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(SLOTS, SLOT as u32);
    if let Some(tls) = tls {
        config = config.tls(tls);
    }
    let config = config.build().expect("valid config");
    RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch")
}

fn wait_for_seen() -> Seen {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(seen) = SEEN.lock().unwrap().take() {
            return seen;
        }
        assert!(
            Instant::now() < deadline,
            "the aborting task never finished"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// The aborted connection's peer reads a reset, its sends fail with
/// `ConnectionAborted`, and on io_uring its zero-copy send's buffer is
/// released within 100 ms of the abort although the older idle connection's
/// hangup poll is still pending.
#[test]
fn abort_releases_a_stalled_connection_at_once() {
    let _serial = serial();
    *SEEN.lock().unwrap() = None;
    #[cfg(has_io_uring)]
    {
        *GUARD_DROPPED_AT.lock().unwrap() = None;
    }
    let (runtime, handles) = launch::<Aborter>(None);
    let addr = runtime.bound_addr().expect("bound");
    let mut idle = TcpStream::connect(addr).expect("connect idle");
    idle.write_all(b"i").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let mut peer = TcpStream::connect(addr).expect("connect");
    // Before the reset: macOS refuses the option on a reset socket.
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.write_all(b"a").unwrap();

    let seen = wait_for_seen();
    assert!(seen.aborted_at.is_some());
    let aborted = Some(ABORTED.to_string());
    assert_eq!(seen.queued, aborted);
    assert_eq!(seen.waiting, aborted);
    assert_eq!(seen.late, aborted);
    assert_eq!(seen.late_admitted, aborted);
    #[cfg(has_io_uring)]
    {
        let aborted_at = seen.aborted_at.unwrap();
        // Over `RLIMIT_MEMLOCK` the guard send falls back to a plain send,
        // and no zero-copy notification is held.
        let enomem = ringline::metrics::POOL
            .value(ringline::metrics::pool::SEND_ZC_ENOMEM)
            .unwrap_or(0);
        eprintln!("abort: enomem={enomem}");
        if enomem == 0 {
            let deadline = aborted_at + Duration::from_secs(2);
            let dropped = loop {
                if let Some(at) = *GUARD_DROPPED_AT.lock().unwrap() {
                    break Some(at);
                }
                if Instant::now() > deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let dropped = dropped.expect("the zero-copy buffer was not released within 2 s");
            assert!(dropped >= aborted_at, "released before the abort");
            let took = dropped - aborted_at;
            eprintln!("abort: released {took:?} after the abort");
            assert!(
                took < Duration::from_millis(100),
                "released {took:?} after the abort"
            );
        }
    }

    // On macOS a peer that only read sometimes saw no reset within the 5 s
    // timeout (13 of 210 runs, and the same with a plain socket pair and no
    // ringline); a write first made it see one in every run tried. On Linux
    // the write would take the error, and the read would then return 0.
    #[cfg(target_os = "macos")]
    let _ = peer.write(b"x");
    let mut body = Vec::new();
    let read = peer.read_to_end(&mut body);
    assert!(
        matches!(&read, Err(e) if e.kind() == io::ErrorKind::ConnectionReset),
        "the peer was not reset: {read:?}"
    );
    drop(idle);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// Completes the handshake, reads one request, and aborts.
struct TlsAborter;

impl AsyncEventHandler for TlsAborter {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            conn.abort();
            let seen = Seen {
                aborted_at: Some(Instant::now()),
                late: Some(kind(conn.send(b"late"))),
                late_admitted: Some(kind(conn.send_admitted(b"late").await)),
                ..Seen::default()
            };
            *SEEN.lock().unwrap() = Some(seen);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsAborter
    }
}

/// A TLS connection's abort sends no close_notify: the client reads a reset,
/// not the clean end of stream an alert would give it.
#[test]
fn abort_sends_no_close_notify() {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};

    let _serial = serial();
    *SEEN.lock().unwrap() = None;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let tls = ringline::TlsConfig::builder()
        .cert(vec![der.clone()], key.into())
        .build()
        .expect("tls config");
    let (runtime, handles) = launch::<TlsAborter>(Some(tls));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from("localhost").unwrap();
    let client = rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    let sock = TcpStream::connect(runtime.bound_addr().expect("bound")).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut stream = rustls::StreamOwned::new(client, sock);
    stream.write_all(b"request").expect("handshake and write");

    let seen = wait_for_seen();
    assert_eq!(seen.late, Some(ABORTED.to_string()));
    assert_eq!(seen.late_admitted, Some(ABORTED.to_string()));
    let mut buf = [0u8; 64];
    let read = stream.read(&mut buf);
    assert!(
        matches!(&read, Err(e) if e.kind() == io::ErrorKind::ConnectionReset),
        "expected a reset, not a close_notify: {read:?}"
    );
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// Shuts the write half down, aborts, and sends.
struct ShutdownAborter;

impl AsyncEventHandler for ShutdownAborter {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            conn.shutdown_write();
            conn.abort();
            let seen = Seen {
                aborted_at: Some(Instant::now()),
                late: Some(kind(conn.send(b"late"))),
                late_admitted: Some(kind(conn.send_admitted(b"late").await)),
                ..Seen::default()
            };
            *SEEN.lock().unwrap() = Some(seen);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        ShutdownAborter
    }
}

/// After `shutdown_write`, a send made after `abort` still fails with
/// `ConnectionAborted`, a bounded one included, rather than with the
/// `BrokenPipe` of a shut-down write half.
#[test]
fn abort_after_shutdown_write_refuses_sends_as_aborted() {
    let _serial = serial();
    *SEEN.lock().unwrap() = None;
    let (runtime, handles) = launch::<ShutdownAborter>(None);
    let mut peer = TcpStream::connect(runtime.bound_addr().expect("bound")).expect("connect");
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.write_all(b"x").unwrap();

    let seen = wait_for_seen();
    assert_eq!(seen.late, Some(ABORTED.to_string()));
    assert_eq!(seen.late_admitted, Some(ABORTED.to_string()));
    drop(peer);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// On io_uring a Unix-domain connection closes without a disconnect, and its
/// queued sends fail with `ConnectionAborted`.
#[cfg(has_io_uring)]
#[test]
fn abort_closes_a_unix_connection() {
    use std::os::unix::net::UnixStream;

    struct UnixAborter;

    impl AsyncEventHandler for UnixAborter {
        fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                conn.with_data(|data| ParseResult::Consumed(data.len()))
                    .await;
                // More than a Unix socket's buffer takes, so the next send
                // queues behind it.
                let guard = ringline::GuardBox::new(VecGuard(vec![1; GUARD_LEN]));
                conn.send_parts()
                    .build(|b| b.guard(guard).submit())
                    .expect("guard send accepted");
                let queued = conn.send(&[2; SLOT]).expect("queued");
                ringline::sleep(Duration::from_millis(50)).await;
                conn.abort();
                let seen = Seen {
                    aborted_at: Some(Instant::now()),
                    queued: Some(kind(queued.await)),
                    late: Some(kind(conn.send(b"late"))),
                    ..Seen::default()
                };
                *SEEN.lock().unwrap() = Some(seen);
            }
        }

        fn create_for_worker(_id: usize) -> Self {
            UnixAborter
        }
    }

    let _serial = serial();
    *SEEN.lock().unwrap() = None;
    let dir = std::env::temp_dir().join(format!("ringline-abort-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sock");
    let _ = std::fs::remove_file(&path);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(SLOTS, SLOT as u32)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind_unix(&path)
        .launch::<UnixAborter>()
        .expect("launch");
    let mut peer = UnixStream::connect(&path).expect("connect");
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.write_all(b"a").unwrap();

    let seen = wait_for_seen();
    assert_eq!(seen.queued, Some(ABORTED.to_string()));
    assert_eq!(seen.late, Some(ABORTED.to_string()));
    // The peer reads what reached its buffer, then the end of the stream or
    // a reset; either ends the read.
    let mut body = Vec::new();
    let read = peer.read_to_end(&mut body);
    assert!(
        read.is_ok() || matches!(&read, Err(e) if e.kind() == io::ErrorKind::ConnectionReset),
        "the connection did not close: {read:?}"
    );
    assert!(body.iter().all(|&b| b == 1), "a queued send was written");
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_dir_all(&dir);
}
