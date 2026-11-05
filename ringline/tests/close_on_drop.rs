#![allow(clippy::manual_async_fn)]
//! Dropping the last half of a connection closes it.
//!
//! Its own test binary: each test launches a runtime whose `on_start` or
//! `on_accept` reads the statics below.

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder,
};

/// Tests share the statics below, so they run one at a time under `cargo test`.
static SERIAL: Mutex<()> = Mutex::new(());
static PEER: Mutex<Option<SocketAddr>> = Mutex::new(None);
static LAST_HALF_DROPPED: AtomicBool = AtomicBool::new(false);

fn config() -> Config {
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

fn peer_addr() -> SocketAddr {
    PEER.lock().unwrap().expect("peer address set")
}

fn listen() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *PEER.lock().unwrap() = Some(listener.local_addr().unwrap());
    listener
}

/// Reads until the connection ends, and panics if it does not within 5 s. A close
/// with unread bytes in its receive buffer ends in a reset, not a FIN.
fn expect_eof(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = [0u8; 256];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return,
            Err(e) => panic!("no EOF: {e}"),
        }
    }
}

// ── An outbound connection ──────────────────────────────────────────

/// Connects, holds the connection briefly, and drops it.
struct DropsOutbound;

impl AsyncEventHandler for DropsOutbound {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let conn = ringline::connect(peer_addr()).await.expect("connect");
            ringline::sleep(Duration::from_millis(50)).await;
            drop(conn);
            // Shutdown closes every connection, so it must not come first.
            ringline::sleep(Duration::from_secs(60)).await;
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        DropsOutbound
    }
}

#[test]
fn dropping_an_outbound_connection_closes_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let listener = listen();
    let (runtime, handles) = RinglineBuilder::new(config())
        .launch::<DropsOutbound>()
        .expect("launch");
    let (mut peer, _) = listener.accept().unwrap();
    expect_eof(&mut peer);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// Unread bytes from the peer do not hold the connection open.
#[test]
fn dropping_an_outbound_connection_with_unread_bytes_closes_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let listener = listen();
    let (runtime, handles) = RinglineBuilder::new(config())
        .launch::<DropsOutbound>()
        .expect("launch");
    let (mut peer, _) = listener.accept().unwrap();
    peer.write_all(&[7u8; 100]).unwrap();
    expect_eof(&mut peer);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

// ── One half at a time ──────────────────────────────────────────────

struct DropsHalves;

impl AsyncEventHandler for DropsHalves {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let conn = ringline::connect(peer_addr()).await.expect("connect");
            let (tx, rx) = conn.split();
            drop(tx);
            ringline::sleep(Duration::from_millis(200)).await;
            LAST_HALF_DROPPED.store(true, Ordering::SeqCst);
            drop(rx);
            ringline::sleep(Duration::from_secs(60)).await;
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        DropsHalves
    }
}

#[test]
fn the_connection_stays_open_until_the_last_half_drops() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    LAST_HALF_DROPPED.store(false, Ordering::SeqCst);
    let listener = listen();
    let (runtime, handles) = RinglineBuilder::new(config())
        .launch::<DropsHalves>()
        .expect("launch");
    let (mut peer, _) = listener.accept().unwrap();
    expect_eof(&mut peer);
    assert!(
        LAST_HALF_DROPPED.load(Ordering::SeqCst),
        "the connection closed with a half still alive"
    );
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

// ── An unused `on_accept` parameter ─────────────────────────────────

struct IgnoresConn;

impl AsyncEventHandler for IgnoresConn {
    /// `async move` does not capture `_conn`, so it drops when this returns.
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            ringline::sleep(Duration::from_secs(60)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        IgnoresConn
    }
}

#[test]
fn a_connection_the_handler_drops_closes_while_its_task_runs() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<IgnoresConn>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let mut client = TcpStream::connect(addr).unwrap();
    expect_eof(&mut client);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

// ── A half dropped at another connection's teardown ─────────────────

struct HoldsBackend;

impl AsyncEventHandler for HoldsBackend {
    /// Parks holding both connections. The client's close drops this task
    /// outside any task poll, with the backend's halves in it.
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let _conn = conn;
            let _backend = ringline::connect(peer_addr()).await.expect("connect");
            ringline::sleep(Duration::from_secs(60)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        HoldsBackend
    }
}

#[test]
fn a_task_dropped_at_teardown_closes_the_connections_it_held() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let listener = listen();
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<HoldsBackend>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let client = TcpStream::connect(addr).unwrap();
    let (mut backend, _) = listener.accept().unwrap();
    let started = Instant::now();
    drop(client);
    expect_eof(&mut backend);
    assert!(started.elapsed() < Duration::from_secs(5));
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

// ── Queued sends ────────────────────────────────────────────────────

/// Fewer than the 16 send-pool slots in `config`.
const QUEUED_SENDS: usize = 12;

struct DropsWithSendsQueued;

impl AsyncEventHandler for DropsWithSendsQueued {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let mut conn = ringline::connect(peer_addr()).await.expect("connect");
            for i in 0..QUEUED_SENDS {
                conn.send_nowait(&[i as u8; 4096]).expect("send");
            }
            drop(conn);
            ringline::sleep(Duration::from_secs(60)).await;
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        DropsWithSendsQueued
    }
}

#[test]
fn sends_queued_before_the_drop_arrive_ahead_of_the_close() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let listener = listen();
    let (runtime, handles) = RinglineBuilder::new(config())
        .launch::<DropsWithSendsQueued>()
        .expect("launch");
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut received = Vec::new();
    peer.read_to_end(&mut received)
        .expect("EOF after the sends");
    assert_eq!(received.len(), QUEUED_SENDS * 4096);
    for (i, block) in received.chunks(4096).enumerate() {
        assert!(
            block.iter().all(|&b| b == i as u8),
            "block {i} out of order"
        );
    }
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

// ── A half dropped inside another connection's read ─────────────────

struct DropsBackendInRead;

impl AsyncEventHandler for DropsBackendInRead {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut backend = Some(ringline::connect(peer_addr()).await.expect("connect"));
            conn.with_data(|data| {
                backend.take();
                ParseResult::Consumed(data.len())
            })
            .await;
            ringline::sleep(Duration::from_secs(60)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        DropsBackendInRead
    }
}

#[test]
fn a_connection_dropped_inside_a_read_closure_closes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let listener = listen();
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<DropsBackendInRead>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let mut client = TcpStream::connect(addr).unwrap();
    let (mut backend, _) = listener.accept().unwrap();
    client.write_all(b"x").unwrap();
    expect_eof(&mut backend);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

// ── A cancelled task ────────────────────────────────────────────────

struct CancelsHolder;

impl AsyncEventHandler for CancelsHolder {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let holder = ringline::spawn(async {
                let _conn = ringline::connect(peer_addr()).await.expect("connect");
                ringline::sleep(Duration::from_secs(60)).await;
            })
            .expect("spawn");
            ringline::sleep(Duration::from_millis(50)).await;
            holder.cancel();
            ringline::sleep(Duration::from_secs(60)).await;
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        CancelsHolder
    }
}

#[test]
fn cancelling_the_task_that_holds_a_connection_closes_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let listener = listen();
    let (runtime, handles) = RinglineBuilder::new(config())
        .launch::<CancelsHolder>()
        .expect("launch");
    let (mut peer, _) = listener.accept().unwrap();
    expect_eof(&mut peer);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

// ── A close from the orphan drain, with no tick to wake the worker ──

#[cfg(has_io_uring)]
struct StuckCloseHoldsBackend;

#[cfg(has_io_uring)]
impl AsyncEventHandler for StuckCloseHoldsBackend {
    /// `pending()` arms no timer, so this task's teardown leaves no completion
    /// behind that would wake the worker.
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let _backend = ringline::connect(peer_addr()).await.expect("connect");
            let block = [0u8; 16384];
            while conn.send_nowait(&block).is_ok() {}
            conn.close();
            std::future::pending::<()>().await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        StuckCloseHoldsBackend
    }
}

/// A half queued at teardown closes its connection from the orphan drain. The
/// worker must not block before the end-of-iteration drain submits that Close:
/// with no tick timeout, nothing else would wake it.
#[cfg(has_io_uring)]
#[test]
fn a_close_from_the_orphan_drain_is_submitted_without_a_tick() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let listener = listen();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(1024, 16384)
        .tick_timeout_us(0)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<StuckCloseHoldsBackend>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let mut client = TcpStream::connect(addr).unwrap();
    let (mut backend, _) = listener.accept().unwrap();
    std::thread::sleep(Duration::from_millis(100));

    expect_eof(&mut client);
    expect_eof(&mut backend);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}
