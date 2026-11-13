#![allow(clippy::manual_async_fn)]
//! A connect timeout fires at its deadline with no tick (#838).
//!
//! The peer is a loopback listener whose accept queue is full: Linux drops
//! a SYN to such a listener, so the connect neither completes nor fails and
//! only its timeout can end it. With `tick_timeout_us(0)` nothing else ends
//! the worker's wait, so the connect resolves only if its deadline bounds
//! that wait. Linux only: other kernels treat a full accept queue
//! differently.
#![cfg(target_os = "linux")]

mod common;

use std::future::Future;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

const TIMEOUT: Duration = Duration::from_millis(300);

static ADDR: Mutex<Option<SocketAddr>> = Mutex::new(None);
/// The connect's result and how long it took.
static OUTCOME: Mutex<Option<(io::Result<()>, Duration)>> = Mutex::new(None);
static FINISHED: AtomicBool = AtomicBool::new(false);

struct Connector;

impl AsyncEventHandler for Connector {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let addr = ADDR.lock().unwrap().expect("address set before launch");
        Some(Box::pin(async move {
            let start = Instant::now();
            let result = ringline::connect(addr).timeout(TIMEOUT).await.map(drop);
            *OUTCOME.lock().unwrap() = Some((result, start.elapsed()));
            FINISHED.store(true, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        Connector
    }
}

/// A listener with a backlog of 0 that already holds one connection it has
/// not accepted, so its accept queue is full; and that connection.
fn full_listener() -> (TcpListener, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // Safety: the fd is open; a second `listen` changes the backlog.
    assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
    let held = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    (listener, held)
}

#[test]
fn a_connect_timeout_fires_without_a_tick() {
    let (listener, _held) = full_listener();
    // Control: a second connect to the full listener does not complete.
    let probe = listener.local_addr().unwrap();
    assert!(
        TcpStream::connect_timeout(&probe, Duration::from_millis(200)).is_err(),
        "the listener's accept queue is not full"
    );

    *ADDR.lock().unwrap() = Some(probe);
    FINISHED.store(false, Ordering::SeqCst);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .tick_timeout_us(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Connector>()
        .expect("launch");
    let start = Instant::now();
    while !FINISHED.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(5));
    }
    if FINISHED.load(Ordering::SeqCst) {
        common::join_workers(&runtime, handles);
    } else {
        // Shutdown wakes the worker, so a timeout that never fired does not
        // keep it from exiting.
        runtime.shutdown();
        for h in handles {
            let _ = h.join();
        }
        panic!("the connect did not resolve within 5 s with a {TIMEOUT:?} timeout");
    }
    let (result, took) = OUTCOME.lock().unwrap().take().expect("an outcome");
    assert_eq!(
        result.as_ref().err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut),
        "{result:?}"
    );
    assert!(took >= TIMEOUT, "resolved early: {took:?}");
    assert!(took < Duration::from_secs(2), "resolved late: {took:?}");
}
