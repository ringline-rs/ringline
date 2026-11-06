//! A send that cannot finish waits in the runtime, behind a `POLLOUT` poll, and
//! holds no io-wq worker thread. A send on a full socket whose peer has
//! half-closed used to hold one `iou-wrk` thread per connection, with no limit
//! from `iowq_max_workers` (#605).
//!
//! Each test sends more than loopback's socket buffers hold for a peer that does
//! not read, checks that the send has stalled, and counts the process's
//! `iou-wrk` threads. A send chain is the exception, and the control: its parts
//! keep `MSG_WAITALL`.
//!
//! The tests share counters, so they take a lock.

#![cfg(has_io_uring)]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId,
    RinglineBuilder, SendGuard, SendPart, TlsConfig,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// Serialises the tests, which share the counters below and count the process's
/// threads.
static LOCK: Mutex<()> = Mutex::new(());
/// Handlers whose send finished.
static DONE: AtomicUsize = AtomicUsize::new(0);
/// Bytes each handler sends.
static LEN: AtomicUsize = AtomicUsize::new(0);
/// The errno of the last failed send.
static SEND_ERRNO: AtomicI32 = AtomicI32::new(0);

const CHUNK: usize = 16 * 1024;
/// Holds one TLS record.
const SLOT: u32 = 32 * 1024;
const CONNS: usize = 16;
const CHAIN_PARTS: usize = 128;

const SINGLE_SLOT: u8 = 0;
const SPANS_SLOTS: u8 = 1;
const GUARD: u8 = 2;

/// Byte `i` of every payload: a rolling pattern, so reordered or repeated
/// chunks fail the comparison.
fn pattern(i: usize) -> u8 {
    (i.wrapping_mul(7).wrapping_add(13) % 251) as u8
}

fn payload(start: usize, len: usize) -> Vec<u8> {
    (start..start + len).map(pattern).collect()
}

/// The `iou-wrk` threads of this process.
fn iou_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter(|t| {
            let comm = t.as_ref().unwrap().path().join("comm");
            std::fs::read_to_string(comm).is_ok_and(|c| c.starts_with("iou-wrk"))
        })
        .count()
}

fn config(send_slots: u16) -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        .max_connections(64)
        .send_pool(send_slots, SLOT)
        .build()
        .expect("valid config")
}

fn connect(addr: std::net::SocketAddr) -> TcpStream {
    let stream = (0..200)
        .find_map(|_| match TcpStream::connect(addr) {
            Ok(s) => Some(s),
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
                None
            }
        })
        .expect("server did not accept the connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream
}

/// A small receive buffer, so a peer that reads paces the sender.
fn small_rcvbuf(stream: &TcpStream) {
    let len: libc::c_int = 64 * 1024;
    // SAFETY: `len` outlives the call, and the fd is open.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw const len).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0);
}

fn read_payload(stream: &mut impl Read, len: usize, what: &str) {
    let mut got = vec![0u8; len];
    stream
        .read_exact(&mut got)
        .unwrap_or_else(|e| panic!("{what}: payload not delivered in full: {e}"));
    if let Some(i) = (0..len).find(|&i| got[i] != pattern(i)) {
        panic!("{what}: payload differs at byte {i}");
    }
}

fn stop(runtime: &ringline::Runtime, handles: Vec<JoinHandle<Result<(), ringline::Error>>>) {
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
}

fn wait_for_done(want: usize) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while DONE.load(Ordering::SeqCst) < want {
        assert!(Instant::now() < deadline, "the sends did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn reset(len: usize) {
    DONE.store(0, Ordering::SeqCst);
    SEND_ERRNO.store(0, Ordering::SeqCst);
    LEN.store(len, Ordering::SeqCst);
}

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

/// Sends `LEN` bytes, the way `MODE` names. `SINGLE_SLOT` is one `send` per pool
/// slot, `SPANS_SLOTS` one coalesced `sendmsg` run, and `GUARD` a `SendMsgZc`. A
/// `SendMsgZc` can return `-ENOMEM` under `RLIMIT_MEMLOCK` and continue as plain
/// sends (#642), so only `a_zero_copy_send_waits_for_room` shows a zero-copy wait.
async fn send_all<const MODE: u8>(conn: &mut Connection) {
    let len = LEN.load(Ordering::SeqCst);
    let sent = match MODE {
        SINGLE_SLOT => {
            let mut sent = Ok(0);
            for start in (0..len).step_by(CHUNK) {
                sent = match conn.send(&payload(start, CHUNK.min(len - start))) {
                    Ok(fut) => fut.await,
                    Err(e) => Err(e),
                };
                if sent.is_err() {
                    break;
                }
            }
            sent
        }
        SPANS_SLOTS => match conn.send(&payload(0, len)) {
            Ok(fut) => fut.await,
            Err(e) => Err(e),
        },
        _ => {
            let guard = GuardBox::new(VecGuard(payload(0, len)));
            match conn
                .send_parts()
                .submit_batch_await(vec![SendPart::Guard(guard)])
            {
                Ok((_, fut)) => fut.await,
                Err(e) => Err(e),
            }
        }
    };
    match sent {
        Ok(_) => {
            DONE.fetch_add(1, Ordering::SeqCst);
        }
        Err(e) => SEND_ERRNO.store(e.raw_os_error().unwrap_or(-1), Ordering::SeqCst),
    }
}

/// Reads until the peer's FIN, then sends.
struct SendAfterFin<const MODE: u8>;

impl<const MODE: u8> AsyncEventHandler for SendAfterFin<MODE> {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
            send_all::<MODE>(&mut conn).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SendAfterFin
    }
}

/// Sends once a byte arrives, and leaves the connection open until the peer
/// closes it.
struct SendOnByte<const MODE: u8>;

impl<const MODE: u8> AsyncEventHandler for SendOnByte<MODE> {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            send_all::<MODE>(&mut conn).await;
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SendOnByte
    }
}

/// `CONNS` half-closed peers stall `len` bytes each, with no thread, and every
/// byte arrives once they read.
fn stalled_peers_hold_no_thread<H: AsyncEventHandler>(config: Config, len: usize) {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset(len);
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let mut peers: Vec<TcpStream> = (0..CONNS).map(|_| connect(addr)).collect();
    for peer in &mut peers {
        peer.write_all(b"go").unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(DONE.load(Ordering::SeqCst), 0, "no send may have finished");
    assert_eq!(SEND_ERRNO.load(Ordering::SeqCst), 0);
    assert_eq!(iou_threads(), 0, "a stalled send holds a worker thread");

    for peer in &mut peers {
        read_payload(peer, len, "half-closed peer");
    }
    wait_for_done(CONNS);
    drop(peers);
    stop(&runtime, handles);
}

/// A send of one pool slot on a socket that is already full, whose peer then
/// half-closes: the FIN moves it from the one-shot poll to the multishot poll.
/// The FIN closes the connection when that send finishes, so a later send of
/// the handler's is refused and the peer sees a prefix.
#[test]
fn a_fin_during_a_single_slot_send_holds_no_thread() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset(16 << 20);
    let (runtime, handles) = RinglineBuilder::new(config(64))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SendOnByte<SINGLE_SLOT>>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let mut peers: Vec<TcpStream> = (0..CONNS).map(|_| connect(addr)).collect();
    for peer in &mut peers {
        peer.write_all(b"go").unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(DONE.load(Ordering::SeqCst), 0, "no send may have finished");
    assert_eq!(iou_threads(), 0, "a stalled send holds a worker thread");

    for peer in &mut peers {
        peer.shutdown(Shutdown::Write).unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(iou_threads(), 0, "a stalled send holds a worker thread");

    for peer in &mut peers {
        let mut got = Vec::new();
        peer.read_to_end(&mut got).expect("the peer sees EOF");
        assert!(!got.is_empty());
        if let Some(i) = (0..got.len()).find(|&i| got[i] != pattern(i)) {
            panic!("payload differs at byte {i}");
        }
    }
    drop(peers);
    stop(&runtime, handles);
}

#[test]
fn coalesced_sends_to_half_closed_peers_hold_no_thread() {
    stalled_peers_hold_no_thread::<SendAfterFin<SPANS_SLOTS>>(config(4096), 4 << 20);
}

#[test]
fn guard_sends_to_half_closed_peers_hold_no_thread() {
    stalled_peers_hold_no_thread::<SendAfterFin<GUARD>>(config(64), 8 << 20);
}

#[test]
fn tls_sends_to_half_closed_peers_hold_no_thread() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let len = 4 << 20;
    reset(len);
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let certs = vec![CertificateDer::from(cert.cert)];
    let key: PrivateKeyDer<'static> = key.into();
    let server = TlsConfig::builder()
        .cert(certs.clone(), key)
        .build()
        .unwrap();
    let (runtime, handles) = RinglineBuilder::new(config(4096))
        .bind_tls("127.0.0.1:0".parse().unwrap(), server)
        .launch::<SendAfterFin<SPANS_SLOTS>>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let mut peers: Vec<_> = (0..CONNS)
        .map(|_| {
            let name: ServerName<'_> = "localhost".try_into().unwrap();
            let mut tls = rustls::ClientConnection::new(client.clone(), name).unwrap();
            let mut tcp = connect(addr);
            while tls.is_handshaking() {
                tls.complete_io(&mut tcp).expect("handshake");
            }
            tls.writer().write_all(b"go").unwrap();
            tls.complete_io(&mut tcp).expect("write");
            tcp.shutdown(Shutdown::Write).unwrap();
            (tls, tcp)
        })
        .collect();
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(DONE.load(Ordering::SeqCst), 0, "no send may have finished");
    assert_eq!(iou_threads(), 0, "a stalled send holds a worker thread");

    for (tls, tcp) in &mut peers {
        read_payload(&mut rustls::Stream::new(tls, tcp), len, "TLS peer");
    }
    wait_for_done(CONNS);
    drop(peers);
    stop(&runtime, handles);
}

/// A zero-copy send, small enough to fit under `RLIMIT_MEMLOCK`, stalls on a
/// half-closed peer and arrives intact. The limit is CI's 64 MiB: a process
/// under a smaller limit shares it with every ring and test running, so only
/// the delivery is checked there.
#[test]
fn a_zero_copy_send_waits_for_room() {
    use ringline::metrics::{POOL, pool};
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let len = 4 << 20;
    reset(len);
    let enomem = || POOL.value(pool::SEND_ZC_ENOMEM).unwrap_or(0);
    let before = enomem();
    let (runtime, handles) = RinglineBuilder::new(config(64))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SendAfterFin<GUARD>>()
        .expect("launch");
    let mut peer = connect(runtime.bound_addr().expect("bound address"));
    peer.write_all(b"go").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    read_payload(&mut peer, len, "zero-copy send");
    wait_for_done(1);

    let mut memlock = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `memlock` outlives the call.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut memlock) },
        0
    );
    if memlock.rlim_cur >= 64 << 20 {
        assert_eq!(enomem() - before, 0, "the send was not zero-copy");
    }
    drop(peer);
    stop(&runtime, handles);
}

/// A peer that reads paces a large send, half-closed (`fin`) or not. It stops
/// and starts the poll hundreds of times. The time limit fails a transfer that
/// is held to the 1 s backstop.
fn paced_send_arrives_intact<H: AsyncEventHandler>(fin: bool) {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let len = 64 << 20;
    reset(len);
    let (runtime, handles) = RinglineBuilder::new(config(64))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch");
    let mut peer = connect(runtime.bound_addr().expect("bound address"));
    small_rcvbuf(&peer);
    peer.write_all(b"go").unwrap();
    if fin {
        peer.shutdown(Shutdown::Write).unwrap();
    }

    let start = Instant::now();
    let mut head = vec![0u8; len / 2];
    peer.read_exact(&mut head).expect("first half delivered");
    // Before the send finishes: below Linux 6.13 a close's lead runs on an io-wq
    // worker.
    assert_eq!(
        DONE.load(Ordering::SeqCst),
        0,
        "the send must still be going"
    );
    assert_eq!(iou_threads(), 0, "the send took a worker thread");
    let mut tail = vec![0u8; len - len / 2];
    peer.read_exact(&mut tail).expect("second half delivered");
    let took = start.elapsed();
    wait_for_done(1);
    head.extend_from_slice(&tail);
    if let Some(i) = (0..len).find(|&i| head[i] != pattern(i)) {
        panic!("paced peer: payload differs at byte {i}");
    }
    assert!(
        took < Duration::from_secs(10),
        "held to the backstop: {took:?}"
    );
    drop(peer);
    stop(&runtime, handles);
}

#[test]
fn a_half_closed_reader_is_not_held_to_the_backstop() {
    paced_send_arrives_intact::<SendAfterFin<GUARD>>(true);
}

#[test]
fn a_paced_send_arrives_intact_without_a_fin() {
    paced_send_arrives_intact::<SendOnByte<GUARD>>(false);
}

/// The socket closes once the send that waited on a multishot poll finishes:
/// the poll does not hold it open.
#[test]
fn a_connection_with_a_multishot_poll_closes() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let len = 8 << 20;
    reset(len);
    let (runtime, handles) = RinglineBuilder::new(config(64))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SendAfterFin<GUARD>>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let mut peer = connect(addr);
    peer.write_all(b"go").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(DONE.load(Ordering::SeqCst), 0, "the send must have stalled");

    read_payload(&mut peer, len, "half-closed peer");
    let mut rest = Vec::new();
    peer.read_to_end(&mut rest).expect("the peer sees EOF");
    assert!(rest.is_empty());
    drop(peer);

    // The port in hex, as a local address in `/proc/net/tcp`, on a socket that
    // is not the listener (state 0A).
    let local = format!(":{:04X} ", addr.port());
    let open = || {
        std::fs::read_to_string("/proc/self/net/tcp")
            .unwrap()
            .lines()
            .filter(|l| {
                let mut fields = l.split_whitespace();
                let local_addr = fields.nth(1).unwrap_or("");
                let state = fields.nth(1).unwrap_or("");
                format!("{local_addr} ").contains(&local) && state != "0A"
            })
            .count()
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while open() > 0 {
        assert!(Instant::now() < deadline, "the socket stayed open");
        std::thread::sleep(Duration::from_millis(10));
    }
    stop(&runtime, handles);
}

/// A poll does not report a Unix peer's `SHUT_RD`, where a send fails `EPIPE`.
/// The backstop finds it.
#[test]
fn a_unix_peers_shut_rd_fails_the_send() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset(8 << 20);
    let dir = std::env::temp_dir().join(format!("ringline-605-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sock");
    let (runtime, handles) = RinglineBuilder::new(config(64))
        .bind_unix(&path)
        .launch::<SendOnByte<SINGLE_SLOT>>()
        .expect("launch");
    let mut peer = UnixStream::connect(&path).expect("connect");
    peer.write_all(b"go").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(DONE.load(Ordering::SeqCst), 0, "the send must have stalled");

    peer.shutdown(Shutdown::Read).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while SEND_ERRNO.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "the send did not fail");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(SEND_ERRNO.load(Ordering::SeqCst), libc::EPIPE);
    drop(peer);
    stop(&runtime, handles);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Once a byte arrives, sends chains of copied parts until one fails. Each
/// chain is long enough to fill a socket with no room left.
struct ChainOnByte;

impl AsyncEventHandler for ChainOnByte {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            let data = payload(0, CHUNK);
            for _ in 0..4096 {
                let Ok(fut) = conn.send_chain(|mut c| {
                    for _ in 0..CHAIN_PARTS {
                        c = c.copy(&data);
                    }
                    c.finish()
                }) else {
                    break;
                };
                if fut.await.is_err() {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ChainOnByte
    }
}

/// The control: a chain's parts keep `MSG_WAITALL`, because a short part would
/// break their order (#734). One on a full socket holds a thread, which is the
/// cost the sends above no longer pay, and shows `iou_threads` counts them.
#[test]
fn a_chain_on_a_half_closed_peer_holds_a_thread() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset(0);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(1024)
        .max_connections(64)
        .send_pool(1024, SLOT)
        .max_chain_length(CHAIN_PARTS as u16)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ChainOnByte>()
        .expect("launch");
    let mut peer = connect(runtime.bound_addr().expect("bound address"));
    peer.write_all(b"go").unwrap();
    std::thread::sleep(Duration::from_millis(500));
    peer.shutdown(Shutdown::Write).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(iou_threads() >= 1, "the chain should hold a worker thread");
    drop(peer);
    stop(&runtime, handles);
}
