#![allow(clippy::manual_async_fn)]
//! Integration tests: `ringline::direct_io`.
//!
//! On Linux the files are opened with `O_DIRECT`: io_uring
//! `IORING_OP_OPENAT`, `READ` and `WRITE` on a fixed file, or `open`, `pread`
//! and `pwrite` on the mio backend's pool. On macOS (mio) the open sets
//! `F_NOCACHE`.
//!
//! Linux needs a filesystem that accepts `O_DIRECT`; the files are in the
//! working directory rather than the temp dir, which may be tmpfs.

mod common;

use std::future::Future;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use ringline::direct_io::{DirectIoConfig, DirectIoFile, DirectIoOpenOptions};
use ringline::fs::FsConfig;
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

// ── Helpers ─────────────────────────────────────────────────────────

fn direct_test_config_builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .direct_io(
            DirectIoConfig::default()
                .max_files(4)
                .max_commands_in_flight(32),
        )
}

/// A path in the working directory, which is not tmpfs.
fn temp_file_path(name: &str) -> PathBuf {
    std::env::current_dir().unwrap().join(name)
}

/// Whether this filesystem accepts `O_DIRECT`.
#[cfg(target_os = "linux")]
fn o_direct_supported() -> bool {
    let path = temp_file_path(".krio_direct_io_probe");
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_DIRECT,
            0o644,
        )
    };
    if fd >= 0 {
        unsafe {
            libc::close(fd);
            libc::unlink(c_path.as_ptr());
        }
        true
    } else {
        let _ = std::fs::remove_file(&path);
        false
    }
}

/// On macOS the open sets `F_NOCACHE`, which every filesystem accepts.
#[cfg(not(target_os = "linux"))]
fn o_direct_supported() -> bool {
    true
}

/// Open `path` for direct I/O with `options`. A slot is free once the close
/// of its previous file has completed (on io_uring, an `IORING_OP_CLOSE`), so
/// an open that finds the table full yields and tries again, at most 1000
/// times.
async fn open_direct(path: &str, options: DirectIoOpenOptions) -> Result<DirectIoFile, String> {
    for _ in 0..1000 {
        match ringline::direct_io::open_with(path, options) {
            Ok(open) => return open.await.map_err(|e| format!("open: {e}")),
            Err(e) if e.to_string() == "direct I/O file table full" => {
                ringline::yield_now().await;
            }
            Err(e) => return Err(format!("open: {e}")),
        }
    }
    Err("open: the table stayed full for 1000 yields".to_string())
}

/// The length of one `O_DIRECT` block in these tests.
const BLOCK: usize = 4096;

/// One block of `byte`, aligned for `O_DIRECT`.
fn filled_block(byte: u8) -> ringline::buf::AlignedBuf {
    let mut buf = ringline::buf::AlignedBuf::zeroed(BLOCK, BLOCK);
    buf.fill(byte);
    buf
}

// ── O_DSYNC open, write, fsync, read back ───────────────────────────

static DSYNC_OUTCOME: std::sync::Mutex<Option<Result<(), String>>> = std::sync::Mutex::new(None);

async fn dsync_write_fsync_read(path: &str) -> Result<(), String> {
    let file = open_direct(path, DirectIoOpenOptions::new().dsync(true)).await?;
    let (n, out) = ringline::direct_io::write_from(file, 0, filled_block(0xa5)).await;
    let n = n.map_err(|e| format!("write: {e}"))?;
    if n != BLOCK {
        return Err(format!("wrote {n} bytes"));
    }
    let synced = ringline::direct_io::fsync(file)
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| format!("fsync: {e}"))?;
    if synced != 0 {
        return Err(format!("fsync resolved to {synced}"));
    }
    let back = ringline::buf::AlignedBuf::with_capacity(BLOCK, BLOCK);
    let (n, back) = ringline::direct_io::read_into(file, 0, back).await;
    let n = n.map_err(|e| format!("read: {e}"))?;
    if n != BLOCK || back[..] != out[..] {
        return Err(format!("read {n} bytes that differ from the write"));
    }
    ringline::direct_io::close(file).map_err(|e| format!("close: {e}"))
}

struct DsyncHandler;

impl AsyncEventHandler for DsyncHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = temp_file_path(".krio_direct_io_dsync");
            let outcome = dsync_write_fsync_read(path.to_str().unwrap()).await;
            *DSYNC_OUTCOME.lock().unwrap() = Some(outcome);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        DsyncHandler
    }
}

/// A file opened with `dsync` takes aligned writes and reads, and its fsync
/// future resolves to `Ok(0)`.
#[test]
fn a_direct_dsync_file_round_trips_and_its_fsync_future_resolves() {
    if !o_direct_supported() {
        eprintln!("SKIP: O_DIRECT not supported on this filesystem");
        return;
    }
    let path = temp_file_path(".krio_direct_io_dsync");
    std::fs::write(&path, [0u8; BLOCK]).unwrap();

    let config = direct_test_config_builder().build().expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .launch::<DsyncHandler>()
        .expect("launch failed");
    common::join_workers(&shutdown, handles);
    let _ = std::fs::remove_file(&path);

    DSYNC_OUTCOME
        .lock()
        .unwrap()
        .take()
        .expect("on_start did not finish")
        .unwrap();
}

// ── Closing a file with an operation queued ─────────────────────────

static QUEUED_DONE: AtomicBool = AtomicBool::new(false);
static QUEUED_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

fn queued_paths() -> (PathBuf, PathBuf) {
    let pid = std::process::id();
    (
        temp_file_path(&format!(".krio_direct_io_queued_a_{pid}")),
        temp_file_path(&format!(".krio_direct_io_queued_b_{pid}")),
    )
}

/// A write queued before a close lands in the closed file, the handle goes
/// stale at once, and the next file opened gets none of it.
async fn write_close_open(first: &str, second: &str) -> Result<(), String> {
    let a = open_direct(first, DirectIoOpenOptions::new()).await?;
    let write = ringline::direct_io::write_from(a, 0, filled_block(0xab));
    let closed = ringline::direct_io::close(a).map_err(|e| e.to_string());
    let stale = ringline::direct_io::close(a).is_err();
    let b = open_direct(second, DirectIoOpenOptions::new()).await;
    let written = write.await.0.map_err(|e| e.to_string())?;
    closed?;
    ringline::direct_io::close(b?).map_err(|e| e.to_string())?;
    if !stale {
        return Err("a second close of the handle succeeded".to_string());
    }
    if written != BLOCK {
        return Err(format!("write returned {written}"));
    }
    Ok(())
}

/// Every deferred close releases its slot: with more rounds than slots, an open
/// fails once a slot leaks.
async fn deferred_closes_release_their_slots(path: &str) -> Result<(), String> {
    for round in 0..16 {
        let file = open_direct(path, DirectIoOpenOptions::new())
            .await
            .map_err(|e| format!("round {round}: {e}"))?;
        let submit = |e: std::io::Error| format!("round {round}: submit: {e}");
        let op: std::pin::Pin<Box<dyn Future<Output = std::io::Result<usize>>>> = match round % 3 {
            0 => {
                let write = ringline::direct_io::write_from(file, 0, filled_block(0));
                Box::pin(async move { write.await.0 })
            }
            1 => {
                let buf = ringline::buf::AlignedBuf::with_capacity(BLOCK, BLOCK);
                let read = ringline::direct_io::read_into(file, 0, buf);
                Box::pin(async move { read.await.0 })
            }
            _ => {
                let fsync = ringline::direct_io::fsync(file).map_err(submit)?;
                Box::pin(async move { fsync.await.map(|n| n as usize) })
            }
        };
        let closed = ringline::direct_io::close(file);
        op.await.map_err(|e| format!("round {round}: op: {e}"))?;
        closed.map_err(|e| format!("round {round}: close: {e}"))?;
    }
    Ok(())
}

struct QueuedWriteHandler;

impl AsyncEventHandler for QueuedWriteHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let (first, second) = queued_paths();
            let (first, second) = (first.to_str().unwrap(), second.to_str().unwrap());
            let mut result = write_close_open(first, second).await;
            if result.is_ok() {
                result = deferred_closes_release_their_slots(second).await;
            }
            let _ = QUEUED_RESULT.set(result);
            QUEUED_DONE.store(true, Ordering::Release);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        QueuedWriteHandler
    }
}

#[test]
fn a_close_with_an_operation_queued_finishes_it_on_the_closed_file() {
    if !o_direct_supported() {
        eprintln!("skipping: O_DIRECT is not supported here");
        return;
    }
    let (first, second) = queued_paths();
    std::fs::write(&first, [0u8; BLOCK]).unwrap();
    std::fs::write(&second, [0u8; BLOCK]).unwrap();

    let config = direct_test_config_builder()
        .direct_io(
            DirectIoConfig::default()
                .max_files(2)
                .max_commands_in_flight(32),
        )
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<QueuedWriteHandler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);

    let a = std::fs::read(&first).unwrap();
    let _ = std::fs::remove_file(&first);
    let _ = std::fs::remove_file(&second);
    assert!(
        QUEUED_DONE.load(Ordering::Acquire),
        "the task did not finish"
    );
    QUEUED_RESULT.get().unwrap().clone().unwrap();
    assert!(a.iter().all(|&x| x == 0xab), "the write missed its file");
}

// ── An open whose future is dropped frees its slot ──────────────────

static ABANDONED_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

fn abandoned_path() -> PathBuf {
    temp_file_path(&format!(".krio_direct_io_abandoned_{}", std::process::id()))
}

/// With `max_files(2)`: two opens dropped before the event loop sees their
/// completions, then one dropped after its completion but before it is
/// polled. Each leaves its slot free, so two opens succeed after each.
async fn abandoned_direct_io_opens(path: &str) -> Result<(), String> {
    let open = || ringline::direct_io::open(path).map_err(|e| e.to_string());
    drop(open()?);
    drop(open()?);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let a = match open() {
            Ok(f) => f.await.map_err(|e| e.to_string()),
            Err(e) => Err(e),
        };
        let b = match open() {
            Ok(f) => f.await.map_err(|e| e.to_string()),
            Err(e) => Err(e),
        };
        let both = a.is_ok() && b.is_ok();
        for file in [a.as_ref(), b.as_ref()].into_iter().flatten() {
            ringline::direct_io::close(*file).map_err(|e| e.to_string())?;
        }
        if both {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "the abandoned opens' slots were not freed: {:?} {:?}",
                a.err(),
                b.err()
            ));
        }
        ringline::sleep(std::time::Duration::from_millis(10)).await;
    }

    let pending = open()?;
    ringline::sleep(std::time::Duration::from_millis(100)).await;
    drop(pending);
    // The event loop frees the slot on its next iteration, and on io_uring
    // after the file's close completes.
    let a = open_direct(path, DirectIoOpenOptions::new()).await?;
    let b = open_direct(path, DirectIoOpenOptions::new())
        .await
        .map_err(|e| format!("a completed, unpolled open kept its slot: {e}"))?;
    ringline::direct_io::close(a).map_err(|e| e.to_string())?;
    ringline::direct_io::close(b).map_err(|e| e.to_string())
}

struct AbandonedOpenHandler;

impl AsyncEventHandler for AbandonedOpenHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = abandoned_path();
            let result = abandoned_direct_io_opens(path.to_str().unwrap()).await;
            let _ = ABANDONED_RESULT.set(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        AbandonedOpenHandler
    }
}

/// fs is on as well, so a dropped direct I/O open released through fs's
/// table would leave the direct I/O slot taken.
#[test]
fn a_dropped_direct_io_open_frees_its_slot() {
    if !o_direct_supported() {
        eprintln!("skipping: O_DIRECT is not supported here");
        return;
    }
    let path = abandoned_path();
    std::fs::write(&path, [0u8; BLOCK]).unwrap();
    let config = direct_test_config_builder()
        .direct_io(
            DirectIoConfig::default()
                .max_files(2)
                .max_commands_in_flight(32),
        )
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<AbandonedOpenHandler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&path);
    ABANDONED_RESULT
        .get()
        .expect("the task finished")
        .clone()
        .unwrap();
}

// ── fs and direct I/O have separate tables ──────────────────────────

static SEPARATE_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

fn separate_path() -> PathBuf {
    temp_file_path(&format!(".krio_direct_io_separate_{}", std::process::id()))
}

/// With one slot in each table: an fs file and a direct I/O file are open at
/// once, a second of either fails with its own table's error, and each
/// handle reads its own file.
async fn tables_are_separate(path: &str) -> Result<(), String> {
    let fs_file = ringline::fs::open(path, ringline::fs::OpenFlags::READ, 0)
        .map_err(|e| format!("fs open: {e}"))?
        .await
        .map_err(|e| format!("fs open: {e}"))?;
    let direct = open_direct(path, DirectIoOpenOptions::new())
        .await
        .map_err(|e| format!("direct open with an fs file open: {e}"))?;
    match ringline::direct_io::open(path) {
        Err(e) if e.to_string() == "direct I/O file table full" => {}
        Err(e) => return Err(format!("second direct open: {e}")),
        Ok(_) => return Err("a second direct open found a free slot".to_string()),
    }
    match ringline::fs::open(path, ringline::fs::OpenFlags::READ, 0) {
        Err(e) if e.to_string() == "filesystem file table full" => {}
        Err(e) => return Err(format!("second fs open: {e}")),
        Ok(_) => return Err("a second fs open found a free slot".to_string()),
    }
    let (n, buf) = ringline::direct_io::read_into(
        direct,
        0,
        ringline::buf::AlignedBuf::with_capacity(BLOCK, BLOCK),
    )
    .await;
    let n = n.map_err(|e| format!("direct read: {e}"))?;
    if n != BLOCK || buf.iter().any(|&b| b != 0x5a) {
        return Err(format!("the direct read returned {n} bytes of other data"));
    }
    let (n, _) = ringline::fs::read_into(fs_file, 0, Vec::with_capacity(BLOCK)).await;
    if n.map_err(|e| format!("fs read: {e}"))? != BLOCK {
        return Err("the fs read was short".to_string());
    }
    ringline::direct_io::close(direct).map_err(|e| format!("direct close: {e}"))?;
    ringline::fs::close(fs_file).map_err(|e| format!("fs close: {e}"))
}

struct SeparateHandler;

impl AsyncEventHandler for SeparateHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = separate_path();
            let result = tables_are_separate(path.to_str().unwrap()).await;
            let _ = SEPARATE_RESULT.set(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        SeparateHandler
    }
}

#[test]
fn fs_and_direct_io_files_take_slots_from_separate_tables() {
    if !o_direct_supported() {
        eprintln!("skipping: O_DIRECT is not supported here");
        return;
    }
    let path = separate_path();
    std::fs::write(&path, [0x5au8; BLOCK]).unwrap();
    let config = direct_test_config_builder()
        .fs(FsConfig::default().max_files(1).max_commands_in_flight(8))
        .direct_io(
            DirectIoConfig::default()
                .max_files(1)
                .max_commands_in_flight(8),
        )
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<SeparateHandler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&path);
    SEPARATE_RESULT
        .get()
        .expect("the task finished")
        .clone()
        .unwrap();
}

// ── Closing an NVMe handle ──────────────────────────────────────────

#[cfg(has_io_uring)]
static NVME_CLOSE_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[cfg(has_io_uring)]
fn nvme_close_path() -> PathBuf {
    temp_file_path(&format!(".krio_nvme_close_{}", std::process::id()))
}

/// With a flush in flight the handle goes stale at once, and the completion
/// releases the slot: with `max_devices(2)`, the third open fails otherwise. A
/// regular file stands in for a device: opening registers the fd, and the flush
/// completes with an error, which is all this needs.
#[cfg(has_io_uring)]
async fn nvme_closes_release_their_slots(path: &str) -> Result<(), String> {
    for round in 0..12 {
        let device =
            ringline::open_nvme_device(path, 1).map_err(|e| format!("round {round}: open: {e}"))?;
        let flush =
            ringline::nvme_flush(device).map_err(|e| format!("round {round}: flush: {e}"))?;
        ringline::close_nvme_device(device).map_err(|e| format!("round {round}: close: {e}"))?;
        let stale = ringline::close_nvme_device(device).is_err();
        let _ = flush.await;
        if !stale {
            return Err(format!("round {round}: a second close succeeded"));
        }
    }
    Ok(())
}

#[cfg(has_io_uring)]
struct NvmeCloseHandler;

#[cfg(has_io_uring)]
impl AsyncEventHandler for NvmeCloseHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = nvme_close_path();
            let result = nvme_closes_release_their_slots(path.to_str().unwrap()).await;
            let _ = NVME_CLOSE_RESULT.set(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        NvmeCloseHandler
    }
}

#[cfg(has_io_uring)]
#[test]
fn closing_an_nvme_handle_with_a_command_in_flight_releases_it() {
    let path = nvme_close_path();
    std::fs::write(&path, [0u8; 4096]).unwrap();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .nvme(ringline::NvmeConfig::default().max_devices(2))
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<NvmeCloseHandler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&path);
    NVME_CLOSE_RESULT
        .get()
        .expect("the task finished")
        .clone()
        .unwrap();
}
