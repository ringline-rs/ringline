//! A disk-I/O future dropped before it resolves must not leave a result that
//! a later operation with the same key takes as its own completion (#574).
//!
//! On io_uring the key is a subsystem tag, a 14-bit sequence and the slab
//! index. The sequence repeats every 16,384 operations; with one operation
//! in flight each reuses the same slab slot, so the key repeats exactly. A
//! stale result under a read's key made the read's dropped future free its
//! buffer at once, while the kernel could still write into it.
//!
//! Its own test binary: it installs a global allocator that counts frees of
//! one distinctive allocation size. io_uring only: mio's sequence is 32-bit.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::BytesMut;
use ringline::fs::{FsConfig, OpenFlags};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

/// The capacity of the pending read's buffer. Nothing else in the process
/// allocates exactly this many bytes.
const BUF_SIZE: usize = 777_787;

/// How often the io_uring disk-I/O key's sequence repeats.
const KEY_PERIOD: usize = 1 << 14;

static BUF_FREES: AtomicUsize = AtomicUsize::new(0);

struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == BUF_SIZE {
            BUF_FREES.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

static DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
/// The tests share `DIR`, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());
static OUTCOME: Mutex<Option<Result<usize, String>>> = Mutex::new(None);

struct StaleKey;

impl AsyncEventHandler for StaleKey {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let outcome = drop_a_read_on_a_reused_key().await;
            *OUTCOME.lock().unwrap() = Some(outcome);
            ringline::request_shutdown().ok();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        StaleKey
    }
}

/// Returns how many times the read's buffer was freed right after the read's
/// future was dropped, while the read was still pending in the kernel.
async fn drop_a_read_on_a_reused_key() -> Result<usize, String> {
    let dir = DIR.lock().unwrap().clone().unwrap();
    let path = dir.join("file");
    // Read-write, so the open does not wait for a writer and a read waits
    // for data that never comes. Opened before the key cycle starts.
    let fifo = ringline::fs::open(dir.join("fifo"), OpenFlags::READ_WRITE, 0)
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;

    // A stat dropped before it resolves. Its result arrives with nothing to
    // take it. Yield so it completes, and frees its slab slot, before the
    // next operation: every later operation is then alone in flight and
    // reuses that slot.
    drop(ringline::fs::stat(&path).map_err(|e| e.to_string())?);
    ringline::sleep(Duration::from_millis(10)).await;

    // Bring the key round to the dropped stat's.
    for _ in 1..KEY_PERIOD {
        ringline::fs::stat(&path)
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;
    }

    // This read takes the dropped stat's key. It waits on the FIFO, so
    // dropping it must park the buffer, not free it.
    let before = BUF_FREES.load(Ordering::SeqCst);
    drop(
        ringline::fs::read_into(fifo, 0, BytesMut::with_capacity(BUF_SIZE))
            .map_err(|e| e.to_string())?,
    );
    Ok(BUF_FREES.load(Ordering::SeqCst) - before)
}

#[test]
fn a_stale_result_does_not_free_a_pending_reads_buffer() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("ringline-stale-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("file"), b"x").unwrap();
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    *DIR.lock().unwrap() = Some(dir.clone());

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .fs(FsConfig::default().max_files(4).max_commands_in_flight(64))
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<StaleKey>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_dir_all(&dir);
    let frees = OUTCOME
        .lock()
        .unwrap()
        .take()
        .expect("on_start did not finish")
        .unwrap();
    assert_eq!(
        frees, 0,
        "a stale result freed the pending read's buffer while the kernel could still write into it"
    );
}

static REUSE_OUTCOME: Mutex<Option<Result<(), String>>> = Mutex::new(None);

struct ResolvedKeyReused;

impl AsyncEventHandler for ResolvedKeyReused {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let outcome = reuse_a_resolved_key().await;
            *REUSE_OUTCOME.lock().unwrap() = Some(outcome);
            ringline::request_shutdown().ok();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        ResolvedKeyReused
    }
}

/// A stat that resolved is kept alive while the key comes round, and dropped
/// only after a new stat has taken its key and is waiting on it. The new stat
/// must still resolve.
async fn reuse_a_resolved_key() -> Result<(), String> {
    let path = DIR.lock().unwrap().clone().unwrap().join("file");
    let mut first = ringline::fs::stat(&path).map_err(|e| e.to_string())?;
    (&mut first).await.map_err(|e| e.to_string())?;
    for _ in 1..KEY_PERIOD {
        ringline::fs::stat(&path)
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;
    }
    // Takes `first`'s key, and is waiting on it.
    let mut reuser = ringline::fs::stat(&path).map_err(|e| e.to_string())?;
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut reuser).poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(first);
    // Let the reuser's result arrive before it is polled again.
    ringline::sleep(Duration::from_millis(20)).await;
    match ringline::timeout(Duration::from_secs(5), reuser).await {
        Ok(result) => result.map(|_| ()).map_err(|e| e.to_string()),
        Err(_) => Err("a stat on a reused key never resolved".into()),
    }
}

/// A future dropped after it resolved does not affect the operation that
/// has since taken its key.
#[test]
fn a_resolved_futures_key_can_be_reused() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("ringline-reused-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("file"), b"x").unwrap();
    *DIR.lock().unwrap() = Some(dir.clone());

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<ResolvedKeyReused>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_dir_all(&dir);
    REUSE_OUTCOME
        .lock()
        .unwrap()
        .take()
        .expect("on_start did not finish")
        .unwrap();
}

// ── An operation submitted without a future ─────────────────────────────

// ── A future dropped with its connection ───────────────────────────────

static TD_FIFO_FILE: Mutex<Option<ringline::fs::File>> = Mutex::new(None);
static TD_DROPPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static TD_GO: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static TD_OUTCOME: Mutex<Option<Result<usize, String>>> = Mutex::new(None);

/// Records that the connection's task, which owns it, was dropped.
struct OnDrop;

impl Drop for OnDrop {
    fn drop(&mut self) {
        TD_DROPPED.store(true, Ordering::SeqCst);
    }
}

struct StatDroppedWithConnection;

impl AsyncEventHandler for StatDroppedWithConnection {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        let (mut tx, _rx) = conn.split();
        async move {
            let _guard = OnDrop;
            let dir = DIR.lock().unwrap().clone().unwrap();
            let fifo = ringline::fs::open(dir.join("fifo"), OpenFlags::READ_WRITE, 0)
                .unwrap()
                .await
                .unwrap();
            *TD_FIFO_FILE.lock().unwrap() = Some(fifo);
            // Held unpolled; its result arrives with nothing to take it.
            let _stat = ringline::fs::stat(dir.join("file")).unwrap();
            // Close this connection: the task, and the stat with it, is
            // dropped outside any task poll.
            ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(50)).await;
                tx.close();
            })
            .unwrap();
            std::future::pending::<()>().await;
        }
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            while !TD_GO.load(Ordering::SeqCst) {
                ringline::sleep(Duration::from_millis(5)).await;
            }
            let outcome = cycle_then_drop_a_read().await;
            *TD_OUTCOME.lock().unwrap() = Some(outcome);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        StatDroppedWithConnection
    }
}

/// Bring the key round to the dropped stat's, then drop a pending FIFO read
/// on it. Returns how many times the read's buffer was freed right away.
async fn cycle_then_drop_a_read() -> Result<usize, String> {
    let path = DIR.lock().unwrap().clone().unwrap().join("file");
    for _ in 1..KEY_PERIOD {
        ringline::fs::stat(&path)
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;
    }
    let fifo = TD_FIFO_FILE.lock().unwrap().take().expect("fifo opened");
    let before = BUF_FREES.load(Ordering::SeqCst);
    drop(
        ringline::fs::read_into(fifo, 0, BytesMut::with_capacity(BUF_SIZE))
            .map_err(|e| e.to_string())?,
    );
    Ok(BUF_FREES.load(Ordering::SeqCst) - before)
}

/// A stat dropped with its connection's task leaves no result for a later
/// operation to take. (That its key is then released, rather than held for
/// the life of the worker, is checked by
/// `a_key_abandoned_outside_the_executor_is_released` in the io_uring event
/// loop's unit tests.)
#[test]
fn a_future_dropped_with_its_connection_leaves_no_result() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("ringline-td-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("file"), b"x").unwrap();
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    *DIR.lock().unwrap() = Some(dir.clone());

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .fs(FsConfig::default().max_files(4).max_commands_in_flight(64))
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<StatDroppedWithConnection>()
        .expect("launch");
    let _client = std::net::TcpStream::connect(runtime.bound_addr().unwrap()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !TD_DROPPED.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        TD_DROPPED.load(Ordering::SeqCst),
        "the connection's task was not dropped"
    );
    // Let the event loop release the queued key.
    std::thread::sleep(Duration::from_millis(50));
    TD_GO.store(true, Ordering::SeqCst);
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_dir_all(&dir);
    let frees = TD_OUTCOME
        .lock()
        .unwrap()
        .take()
        .expect("on_start did not finish")
        .unwrap();
    assert_eq!(
        frees, 0,
        "a result left by a future dropped at teardown freed the pending read's buffer"
    );
}

// ── A future that holds its result while its key comes round ───────────

static HELD_OUTCOME: Mutex<Option<String>> = Mutex::new(None);

struct HeldResult;

impl AsyncEventHandler for HeldResult {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let outcome = hold_a_result_while_the_key_comes_round().await;
            *HELD_OUTCOME.lock().unwrap() = Some(outcome);
            ringline::request_shutdown().ok();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        HeldResult
    }
}

/// A stat is created and kept unpolled (a prefetch) while its result
/// arrives and the sequence comes round. A read on an empty FIFO that would
/// take the stat's key must stay pending, and the stat must still resolve.
async fn hold_a_result_while_the_key_comes_round() -> String {
    let dir = DIR.lock().unwrap().clone().unwrap();
    let path = dir.join("file");
    let fifo = ringline::fs::open(dir.join("fifo"), OpenFlags::READ_WRITE, 0)
        .unwrap()
        .await
        .unwrap();
    let held = ringline::fs::stat(&path).unwrap();
    // The stat completes; its result waits for `held` to be polled.
    ringline::sleep(Duration::from_millis(10)).await;
    for _ in 1..KEY_PERIOD {
        ringline::fs::stat(&path).unwrap().await.unwrap();
    }
    let read = ringline::fs::read_into(fifo, 0, BytesMut::with_capacity(4096)).unwrap();
    let read = match ringline::timeout(Duration::from_millis(200), read).await {
        Ok((result, _buf)) => {
            format!("the read resolved with {result:?} while the kernel read was pending")
        }
        Err(_) => "read pending".to_string(),
    };
    let held = match ringline::timeout(Duration::from_millis(500), held).await {
        Ok(result) => format!("stat resolved: {}", result.is_ok()),
        Err(_) => "the held stat never resolved".to_string(),
    };
    format!("{read}; {held}")
}

/// A key a future still holds, with its result not yet taken, is not given
/// to a later operation.
#[test]
fn a_held_key_is_not_reused() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("ringline-held-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("file"), b"x").unwrap();
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    *DIR.lock().unwrap() = Some(dir.clone());

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .fs(FsConfig::default().max_files(4).max_commands_in_flight(64))
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<HeldResult>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_dir_all(&dir);
    let outcome = HELD_OUTCOME
        .lock()
        .unwrap()
        .take()
        .expect("on_start did not finish");
    assert_eq!(outcome, "read pending; stat resolved: true");
}
