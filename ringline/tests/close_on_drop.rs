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

use ringline::{AsyncEventHandler, Config, ConfigBuilder, Connection, RinglineBuilder};

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

/// Connects, holds the connection for `hold`, and drops it.
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
            ringline::sleep(Duration::from_millis(50)).await;
            ringline::request_shutdown().ok();
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
            ringline::sleep(Duration::from_millis(50)).await;
            ringline::request_shutdown().ok();
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
