//! `Runtime::stop_accepting`: it waits until the connections already accepted
//! have reached their worker, the workers keep serving afterwards, new
//! connections wait in the backlog of a listener from `bind_fd`, and it
//! returns at once when repeated, after shutdown, or on a worker thread.
//!
//! Each handler keeps its own statics: the tests in this file run in parallel
//! in one process.

#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

fn config() -> ringline::Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .build()
        .expect("valid config")
}

type Handles = Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>;

fn join(runtime: &ringline::Runtime, handles: Handles) {
    runtime.shutdown();
    common::join_workers(runtime, handles);
}

/// Echo what `conn` receives until the peer closes.
async fn echo_loop(conn: Connection) {
    let (mut tx, mut rx) = conn.split();
    loop {
        let n = rx
            .with_data(|data| {
                let _ = tx.send(data);
                ParseResult::Consumed(data.len())
            })
            .await;
        if n == 0 {
            break;
        }
    }
}

/// Write `msg` and read it back.
fn echo(stream: &mut TcpStream, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    stream.write_all(msg)?;
    let mut got = vec![0u8; msg.len()];
    stream.read_exact(&mut got)?;
    Ok(got)
}

fn connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
}

/// Wait up to 5 s for `count` to reach `n`.
fn wait_for(count: &AtomicUsize, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while count.load(Ordering::SeqCst) < n {
        assert!(Instant::now() < deadline, "count stayed below {n}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

struct Echo;

impl AsyncEventHandler for Echo {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        echo_loop(conn)
    }

    fn create_for_worker(_id: usize) -> Self {
        Echo
    }
}

/// How long [`Stall`]'s first connection blocks the worker thread.
const STALL: Duration = Duration::from_secs(1);
static STALL_ACCEPTED: AtomicUsize = AtomicUsize::new(0);

/// Counts each `on_accept` call. The task of the first connection blocks the
/// worker thread for [`STALL`], so connections accepted meanwhile stay in the
/// worker's accept channel.
struct Stall;

impl AsyncEventHandler for Stall {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        let n = STALL_ACCEPTED.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                std::thread::sleep(STALL);
            }
            echo_loop(conn).await;
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Stall
    }
}

/// Connections placed in a worker's channel while the worker is blocked have
/// reached `on_accept` when `stop_accepting` returns, and the worker serves
/// them afterwards.
#[test]
fn stop_accepting_waits_for_the_connections_in_a_workers_channel() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Stall>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("address");

    let _first = connect(addr);
    wait_for(&STALL_ACCEPTED, 1);
    // The first task now blocks the worker. These two are accepted and
    // placed in its channel.
    let mut second = connect(addr);
    let _third = connect(addr);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        STALL_ACCEPTED.load(Ordering::SeqCst),
        1,
        "the worker was not blocked: the test checks nothing"
    );

    runtime
        .stop_accepting(Duration::from_secs(5))
        .expect("stop accepting");
    assert_eq!(
        STALL_ACCEPTED.load(Ordering::SeqCst),
        3,
        "stop_accepting returned before the queued connections reached on_accept"
    );
    assert_eq!(echo(&mut second, b"served").expect("echo"), b"served");
    join(&runtime, handles);
}

static BLOCK_ACCEPTED: AtomicUsize = AtomicUsize::new(0);

/// As [`Stall`], with its own count.
struct Block;

impl AsyncEventHandler for Block {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        let n = BLOCK_ACCEPTED.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                std::thread::sleep(STALL);
            }
            echo_loop(conn).await;
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Block
    }
}

/// A worker that does not take what is in its channel within the timeout
/// makes `stop_accepting` return `TimedOut` at the timeout.
#[test]
fn stop_accepting_times_out_on_a_blocked_worker() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Block>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("address");

    let _first = connect(addr);
    wait_for(&BLOCK_ACCEPTED, 1);
    let _second = connect(addr);
    std::thread::sleep(Duration::from_millis(50));

    let start = Instant::now();
    let err = runtime
        .stop_accepting(Duration::from_millis(100))
        .expect_err("stop_accepting returned while the worker was blocked");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(
        start.elapsed() < STALL / 2,
        "returned after {:?}, not at the timeout",
        start.elapsed()
    );
    join(&runtime, handles);
}

/// A listening loopback TCP socket, and a second fd for the same socket that
/// the test keeps, as systemd keeps its copy in the fd store.
fn listening_pair() -> (OwnedFd, TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let kept = listener.try_clone().expect("dup");
    (listener.into(), kept, addr)
}

/// Accept from `listener` within 5 s, as a blocking stream with a 5 s read
/// timeout. The runtime's acceptor set `O_NONBLOCK` on the shared socket, so
/// `accept` returns `WouldBlock` until a connection is queued.
fn accept_within(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "no connection to accept");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("accept: {e}"),
        }
    };
    stream.set_nonblocking(false).expect("blocking");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
}

/// After `stop_accepting`, a listener from `bind_fd` keeps listening: a new
/// connection completes its handshake and waits in the backlog, unserved,
/// until the copy the test kept accepts it. The connection made before is
/// still served.
#[test]
fn after_stop_accepting_new_connections_wait_in_the_backlog() {
    let (fd, kept, addr) = listening_pair();
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind_fd(fd)
        .launch::<Echo>()
        .expect("launch");

    let mut before = connect(addr);
    assert_eq!(echo(&mut before, b"before").expect("echo"), b"before");

    runtime
        .stop_accepting(Duration::from_secs(5))
        .expect("stop accepting");

    let mut late = connect(addr);
    late.write_all(b"late").expect("write");
    late.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("read timeout");
    let mut got = [0u8; 4];
    let read = late.read(&mut got);
    assert!(
        matches!(&read, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
        "served after stop_accepting: {read:?}"
    );

    let mut accepted = accept_within(&kept);
    accepted.read_exact(&mut got).expect("read");
    assert_eq!(&got, b"late");

    assert_eq!(echo(&mut before, b"still").expect("echo"), b"still");
    join(&runtime, handles);
}

static HOLD_ACCEPTED: AtomicUsize = AtomicUsize::new(0);

/// As [`Stall`], with its own count.
struct Hold;

impl AsyncEventHandler for Hold {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        let n = HOLD_ACCEPTED.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                std::thread::sleep(STALL);
            }
            echo_loop(conn).await;
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Hold
    }
}

/// An acceptor holding a connection when `stop_accepting` begins places it
/// once the worker has room, and accepts no other: a connection queued in the
/// backlog behind it stays there.
///
/// With a channel of one and the worker blocked, the second connection fills
/// the channel, the acceptor holds the third, and the fourth waits in the
/// backlog.
#[test]
fn an_acceptor_holding_a_connection_places_it_and_accepts_no_more() {
    let (fd, kept, addr) = listening_pair();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .accept_queue_capacity(1)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind_fd(fd)
        .launch::<Hold>()
        .expect("launch");

    let _first = connect(addr);
    wait_for(&HOLD_ACCEPTED, 1);
    let _second = connect(addr);
    let mut third = connect(addr);
    std::thread::sleep(Duration::from_millis(50));
    let mut fourth = connect(addr);
    fourth.write_all(b"four").expect("write");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        HOLD_ACCEPTED.load(Ordering::SeqCst),
        1,
        "the worker was not blocked: the test checks nothing"
    );

    runtime
        .stop_accepting(Duration::from_secs(5))
        .expect("stop accepting");
    assert_eq!(
        HOLD_ACCEPTED.load(Ordering::SeqCst),
        3,
        "the held connection did not reach on_accept"
    );
    assert_eq!(echo(&mut third, b"held").expect("echo"), b"held");

    // The fourth is still in the backlog.
    let mut accepted = accept_within(&kept);
    let mut got = [0u8; 4];
    accepted.read_exact(&mut got).expect("read");
    assert_eq!(&got, b"four");
    join(&runtime, handles);
}

/// After `stop_accepting`, a listener from `bind` is shut down: on Linux a
/// new connection is refused. macOS keeps a listener listening after
/// `SHUT_RD`.
#[cfg(target_os = "linux")]
#[test]
fn after_stop_accepting_a_bound_listener_refuses() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Echo>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("address");
    let mut before = connect(addr);
    assert_eq!(echo(&mut before, b"before").expect("echo"), b"before");

    runtime
        .stop_accepting(Duration::from_secs(5))
        .expect("stop accepting");
    let err = TcpStream::connect(addr).expect_err("connected after stop_accepting");
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused, "{err}");
    assert_eq!(echo(&mut before, b"still").expect("echo"), b"still");
    join(&runtime, handles);
}

/// A second call returns at once, and the listen handle reports an error
/// from the first call on.
#[test]
fn a_second_stop_accepting_returns_at_once() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .defer_listen()
        .launch::<Echo>()
        .expect("launch");
    runtime
        .stop_accepting(Duration::from_secs(5))
        .expect("first call");
    let start = Instant::now();
    runtime
        .stop_accepting(Duration::from_secs(5))
        .expect("second call");
    assert!(start.elapsed() < Duration::from_millis(500));
    assert!(
        runtime.listen_handle().begin_listening_all().is_err(),
        "a gate opened after stop_accepting"
    );
    join(&runtime, handles);
}

/// `Duration::MAX` waits without a deadline instead of overflowing.
#[test]
fn stop_accepting_with_the_longest_timeout_returns() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Echo>()
        .expect("launch");
    runtime
        .stop_accepting(Duration::MAX)
        .expect("stop accepting");
    join(&runtime, handles);
}

static ENDS_ACCEPTED: AtomicUsize = AtomicUsize::new(0);

/// The first connection's task asks its worker to stop, then blocks the
/// worker thread for [`STALL`], so a connection accepted meanwhile is left in
/// the channel of a worker that ends without draining it.
struct EndsWorker;

impl AsyncEventHandler for EndsWorker {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        let n = ENDS_ACCEPTED.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                ringline::request_shutdown().expect("request shutdown");
                std::thread::sleep(STALL);
            }
            drop(conn);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        EndsWorker
    }
}

/// A worker that ended on its own, with a connection left in its channel,
/// does not hold `stop_accepting` until the timeout.
///
/// On io_uring the worker takes the second connection in the iteration that
/// sees its shutdown request, so the channel is empty when it ends and the
/// test passes either way; on mio the connection is left in the channel.
#[test]
fn stop_accepting_does_not_wait_for_a_worker_that_ended() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<EndsWorker>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("address");
    let _first = connect(addr);
    wait_for(&ENDS_ACCEPTED, 1);
    let _second = connect(addr);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !handles.iter().all(|h| h.is_finished()) {
        assert!(Instant::now() < deadline, "the worker did not end");
        std::thread::sleep(Duration::from_millis(5));
    }

    let start = Instant::now();
    runtime
        .stop_accepting(Duration::from_secs(2))
        .expect("stop accepting");
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "waited {:?} for a worker that had ended",
        start.elapsed()
    );
    join(&runtime, handles);
}

/// After `shutdown`, `stop_accepting` returns `Ok` at once.
#[test]
fn stop_accepting_after_shutdown_returns_at_once() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Echo>()
        .expect("launch");
    runtime.shutdown();
    let start = Instant::now();
    runtime
        .stop_accepting(Duration::from_secs(5))
        .expect("after shutdown");
    assert!(start.elapsed() < Duration::from_millis(500));
    join(&runtime, handles);
}

static WORKER_RUNTIME: Mutex<Option<Arc<ringline::Runtime>>> = Mutex::new(None);
static WORKER_RESULT: Mutex<Option<(std::io::ErrorKind, Duration)>> = Mutex::new(None);

/// Calls `stop_accepting` from its `on_accept`, on the worker thread, and
/// records the result.
struct CallsStop;

impl AsyncEventHandler for CallsStop {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let runtime = WORKER_RUNTIME.lock().unwrap().clone();
            if let Some(runtime) = runtime {
                let start = Instant::now();
                let result = runtime.stop_accepting(Duration::from_secs(5));
                let elapsed = start.elapsed();
                // Before the result is stored: the test takes the runtime
                // back once it sees the result.
                drop(runtime);
                let kind = match result {
                    Ok(()) => std::io::ErrorKind::Other,
                    Err(e) => e.kind(),
                };
                *WORKER_RESULT.lock().unwrap() = Some((kind, elapsed));
            }
            drop(conn);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        CallsStop
    }
}

/// On a worker thread, `stop_accepting` returns `Deadlock` at once.
#[test]
fn stop_accepting_on_a_worker_thread_is_an_error() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<CallsStop>()
        .expect("launch");
    let runtime = Arc::new(runtime);
    *WORKER_RUNTIME.lock().unwrap() = Some(Arc::clone(&runtime));
    let _client = connect(runtime.bound_addr().expect("address"));

    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        if let Some(result) = *WORKER_RESULT.lock().unwrap() {
            break result;
        }
        assert!(Instant::now() < deadline, "on_accept did not run");
        std::thread::sleep(Duration::from_millis(2));
    };
    WORKER_RUNTIME.lock().unwrap().take();
    assert_eq!(result.0, std::io::ErrorKind::Deadlock);
    assert!(result.1 < Duration::from_millis(500), "took {:?}", result.1);
    let runtime = Arc::into_inner(runtime).expect("the only runtime handle");
    join(&runtime, handles);
}

/// In merged accept mode, `stop_accepting` shuts the workers' listeners down
/// without counting a stopped acceptor, and a new connection is refused.
#[cfg(all(feature = "unstable-accept", has_io_uring))]
#[test]
fn stop_accepting_in_merged_mode_counts_no_stopped_acceptor() {
    let stopped = || {
        ringline::metrics::CONNECTIONS
            .value(ringline::metrics::conn::ACCEPTOR_STOPPED)
            .unwrap_or(0)
    };
    let config = ConfigBuilder::new()
        .workers(2)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .accept_mode(ringline::AcceptMode::Merged)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Echo>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("address");
    let mut before = connect(addr);
    assert_eq!(echo(&mut before, b"before").expect("echo"), b"before");
    let before_count = stopped();

    runtime
        .stop_accepting(Duration::from_secs(5))
        .expect("stop accepting");
    let err = TcpStream::connect(addr).expect_err("connected after stop_accepting");
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused, "{err}");
    assert_eq!(echo(&mut before, b"still").expect("echo"), b"still");
    // The workers handle the multishot accepts' final completions in their
    // next iteration; the echo above ran one on the connection's worker.
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        stopped(),
        before_count,
        "stop_accepting counted a stopped acceptor"
    );
    join(&runtime, handles);
}
