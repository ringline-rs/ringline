//! Connections accepted but still queued for a worker when the runtime shuts
//! down must be closed.
//!
//! The acceptor thread accepts a connection and queues it on a worker's
//! channel. A worker that exits without draining the channel leaves the
//! connections there. This test blocks the only worker in `on_start` so it
//! cannot drain, connects several clients, shuts down, and requires every fd
//! `launch()` opened, the accepted sockets included, to be closed afterwards.
//!
//! Two more cases: on io_uring, connections queued after the worker's last
//! drain (the worker is held in `on_notify`, which runs after the drain); and
//! a worker that exits while the acceptor keeps running, whose queued
//! connections must close then rather than at runtime shutdown.
//!
//! Its own test binary, because it counts the process's open fds; the tests
//! take a lock so they do not disturb each other. Linux only.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

use std::collections::HashSet;
use std::future::Future;
use std::io::Read;
use std::net::TcpStream;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ListenerId, RinglineBuilder};

static WORKER_PARKED: AtomicBool = AtomicBool::new(false);

const CLIENTS: usize = 8;

/// Serialises the tests, which count process-wide fds.
static FD_LOCK: Mutex<()> = Mutex::new(());

fn test_config(workers: usize) -> ringline::Config {
    ConfigBuilder::new()
        .workers(workers)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(16, 1024)
        .max_connections(64)
        .send_pool(16, 16384)
        // No pools: their threads would also hold fds open past shutdown.
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .disk_io_threads(0)
        .build()
        .expect("valid config")
}

/// Wait up to 5 s for every fd opened since `baseline` to close, then assert.
fn assert_no_fds_left(baseline: &HashSet<RawFd>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut leaked: Vec<RawFd> = open_fds().difference(baseline).copied().collect();
    while !leaked.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        leaked = open_fds().difference(baseline).copied().collect();
    }
    let targets: Vec<String> = leaked
        .iter()
        .filter_map(|fd| std::fs::read_link(format!("/proc/self/fd/{fd}")).ok())
        .map(|t| t.display().to_string())
        .collect();
    assert!(
        leaked.is_empty(),
        "fds opened by launch() still open 5s after shutdown: {leaked:?} -> {targets:?}"
    );
}

fn wait_for_acceptor_exit() {
    let deadline = Instant::now() + Duration::from_secs(5);
    while thread_alive("ringline-accept") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !thread_alive("ringline-accept"),
        "acceptor thread never exited"
    );
}

/// Blocks the worker thread in `on_start` so it cannot drain its accept
/// channel before shutdown.
struct SlowWorker;

impl AsyncEventHandler for SlowWorker {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            WORKER_PARKED.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_millis(300));
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        SlowWorker
    }
}

/// The process's open fds, excluding the directory handle used to list them.
fn open_fds() -> HashSet<RawFd> {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(|e| {
            let e = e.ok()?;
            let target = std::fs::read_link(e.path()).ok()?;
            if target.starts_with("/proc") {
                return None;
            }
            e.file_name().to_str()?.parse().ok()
        })
        .collect()
}

fn thread_alive(prefix: &str) -> bool {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok())
        .any(|name| name.trim_end().starts_with(prefix))
}

#[test]
fn queued_connections_are_closed_at_shutdown() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let baseline = open_fds();
    let (runtime, handles) = RinglineBuilder::new(test_config(1))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SlowWorker>()
        .expect("launch");
    let addr = runtime
        .bound_addr_of(ListenerId::from_index(0))
        .expect("bound address");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !WORKER_PARKED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        WORKER_PARKED.load(Ordering::Acquire),
        "worker never ran on_start"
    );

    // The kernel completes the handshakes and the acceptor queues each
    // connection for the blocked worker.
    let clients: Vec<TcpStream> = (0..CLIENTS)
        .map(|_| TcpStream::connect(addr).expect("connect"))
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    drop(clients);

    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    drop(runtime);
    wait_for_acceptor_exit();
    assert_no_fds_left(&baseline);
}

#[cfg(has_io_uring)]
static NOTIFY_ARMED: AtomicBool = AtomicBool::new(false);
#[cfg(has_io_uring)]
static NOTIFY_BLOCKED: AtomicBool = AtomicBool::new(false);

/// Blocks the worker in `on_notify` once armed. On io_uring `on_notify` runs
/// after the accept drain and before the eventfd read is re-armed, so
/// connections queued meanwhile are never drained.
#[cfg(has_io_uring)]
struct NotifyBlocker;

#[cfg(has_io_uring)]
impl AsyncEventHandler for NotifyBlocker {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_notify(&mut self, _ctx: &mut ringline::DriverCtx<'_>) {
        if NOTIFY_ARMED.swap(false, Ordering::AcqRel) {
            NOTIFY_BLOCKED.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_millis(400));
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        NotifyBlocker
    }
}

/// io_uring drains the accept channel before checking for shutdown, so the
/// first test cannot reach its race there. Connections queued while the
/// worker is held in `on_notify` are queued after its last drain.
#[cfg(has_io_uring)]
#[test]
fn connections_queued_after_the_last_drain_are_closed() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let baseline = open_fds();
    let (runtime, handles) = RinglineBuilder::new(test_config(1))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<NotifyBlocker>()
        .expect("launch");
    let addr = runtime
        .bound_addr_of(ListenerId::from_index(0))
        .expect("bound address");

    NOTIFY_ARMED.store(true, Ordering::Release);
    runtime.worker_wake_handle(0).expect("wake handle").wake();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !NOTIFY_BLOCKED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        NOTIFY_BLOCKED.load(Ordering::Acquire),
        "worker never ran on_notify"
    );

    let clients: Vec<TcpStream> = (0..CLIENTS)
        .map(|_| TcpStream::connect(addr).expect("connect"))
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    drop(runtime);
    wait_for_acceptor_exit();

    for mut client in clients {
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let mut buf = [0u8; 8];
        assert_eq!(
            client.read(&mut buf).expect("read"),
            0,
            "a queued connection was not closed"
        );
    }
    assert_no_fds_left(&baseline);
}

static EXITING_WORKER_STARTED: AtomicBool = AtomicBool::new(false);

/// Worker 0 blocks in `on_start` and then exits through `request_shutdown`;
/// worker 1 keeps running, and so does the acceptor.
struct ExitingWorker {
    id: usize,
}

impl AsyncEventHandler for ExitingWorker {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        // Hold a served connection open, so only an unserved one reads EOF.
        async {
            std::future::pending::<()>().await;
        }
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        if self.id != 0 {
            return None;
        }
        Some(Box::pin(async {
            EXITING_WORKER_STARTED.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_millis(300));
            ringline::request_shutdown().expect("request_shutdown");
        }))
    }

    fn create_for_worker(id: usize) -> Self {
        ExitingWorker { id }
    }
}

/// Connections queued for a worker that exits while the runtime keeps running
/// are closed when that worker exits, not when the runtime shuts down. The
/// acceptor still holds a sender, so the channel is not freed until then.
#[test]
fn a_worker_that_exits_closes_its_queued_connections() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (runtime, mut handles) = RinglineBuilder::new(test_config(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ExitingWorker>()
        .expect("launch");
    let addr = runtime
        .bound_addr_of(ListenerId::from_index(0))
        .expect("bound address");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !EXITING_WORKER_STARTED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        EXITING_WORKER_STARTED.load(Ordering::Acquire),
        "worker 0 never started"
    );

    // Round robin: half go to the blocked worker 0, half to worker 1.
    let clients: Vec<TcpStream> = (0..CLIENTS)
        .map(|_| TcpStream::connect(addr).expect("connect"))
        .collect();
    handles
        .remove(0)
        .join()
        .expect("worker 0 panicked")
        .expect("worker 0 error");

    // The runtime is still running: worker 1 and the acceptor are alive.
    let mut closed = vec![false; clients.len()];
    let deadline = Instant::now() + Duration::from_secs(2);
    while closed.iter().filter(|c| **c).count() < CLIENTS / 2 && Instant::now() < deadline {
        for (i, mut client) in clients.iter().enumerate() {
            if closed[i] {
                continue;
            }
            client
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("set timeout");
            let mut buf = [0u8; 8];
            if let Ok(0) = client.read(&mut buf) {
                closed[i] = true;
            }
        }
    }
    let closed_count = closed.iter().filter(|c| **c).count();
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    assert_eq!(
        closed_count,
        CLIENTS / 2,
        "worker 0's queued connections should close when it exits, with the runtime \
         still running; closed: {closed:?}"
    );
}
