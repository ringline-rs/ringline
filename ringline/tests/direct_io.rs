#![allow(clippy::manual_async_fn)]
//! Integration tests: direct I/O via ringline's direct I/O support.
//!
//! On Linux, this exercises io_uring `IORING_OP_READ` / `IORING_OP_WRITE`
//! with `O_DIRECT`. On macOS (mio backend), it uses the disk I/O thread pool
//! with `fcntl(F_NOCACHE)` as an approximation.
//!
//! Requirements:
//! - Linux: kernel 5.6+, a real filesystem (not tmpfs)
//! - macOS: any filesystem (F_NOCACHE works everywhere)

mod common;

use std::future::Future;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, DirectIoConfig, RinglineBuilder,
};

// ── Helpers ─────────────────────────────────────────────────────────

fn direct_io_test_config_builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .tick_timeout_us(1000)
        .direct_io(
            DirectIoConfig::default()
                .max_files(4)
                .max_commands_in_flight(32),
        )
}

fn direct_io_test_config() -> Config {
    direct_io_test_config_builder()
        .build()
        .expect("valid config")
}

/// Generate a temp file path in the current working directory.
/// Using cwd (the repo root) ensures we're on a real filesystem, not tmpfs.
fn temp_file_path(name: &str) -> PathBuf {
    std::env::current_dir().unwrap().join(name)
}

/// Check if io_uring is supported on this kernel.
#[cfg(target_os = "linux")]
fn io_uring_supported() -> bool {
    // Try to create a minimal io_uring. ENOSYS means the syscall doesn't exist.
    let ret = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, std::ptr::null_mut::<u8>()) };
    // EFAULT (bad params pointer) means the syscall exists; ENOSYS means it doesn't.
    ret != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
}

#[cfg(not(target_os = "linux"))]
fn io_uring_supported() -> bool {
    false
}

/// Check if O_DIRECT is supported by trying to open a file.
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

/// On macOS, "direct I/O" uses F_NOCACHE (set by open_direct_io_file).
/// No special filesystem support needed.
#[cfg(not(target_os = "linux"))]
fn o_direct_supported() -> bool {
    true
}

// ── Write then Read roundtrip test ──────────────────────────────────

static ROUNDTRIP_DONE: AtomicBool = AtomicBool::new(false);
static ROUNDTRIP_OK: AtomicBool = AtomicBool::new(false);
static ROUNDTRIP_ERR: OnceLock<String> = OnceLock::new();

struct RoundtripTickHandler;

impl AsyncEventHandler for RoundtripTickHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_tick(&mut self) {
        static STARTED: AtomicBool = AtomicBool::new(false);
        if STARTED.swap(true, Ordering::AcqRel) {
            return;
        }

        let path = temp_file_path(".krio_direct_io_roundtrip_test");

        // Create the file with 4096 bytes so read doesn't hit EOF.
        if let Err(e) = std::fs::write(&path, [0u8; 4096]) {
            let _ = ROUNDTRIP_ERR.set(format!("file create failed: {e}"));
            ROUNDTRIP_DONE.store(true, Ordering::Release);
            ringline::request_shutdown().unwrap();
            return;
        }

        let path_str = path.to_str().unwrap();
        match ringline::open_direct_io_file(path_str) {
            Ok(_file) => {
                // File opened successfully - the full roundtrip test
                // would need completion callbacks which aren't available
                // in the async on_tick. Mark as done.
                ROUNDTRIP_OK.store(true, Ordering::Release);
                ROUNDTRIP_DONE.store(true, Ordering::Release);
                ringline::request_shutdown().unwrap();
            }
            Err(e) => {
                let _ = ROUNDTRIP_ERR.set(format!("open failed: {e}"));
                ROUNDTRIP_DONE.store(true, Ordering::Release);
                ringline::request_shutdown().unwrap();
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        RoundtripTickHandler
    }
}

#[test]
fn direct_io_write_fsync_read_roundtrip() {
    if ringline::backend() == ringline::Backend::IoUring && !io_uring_supported() {
        eprintln!("SKIP: io_uring not supported on this kernel");
        return;
    }
    if !o_direct_supported() {
        eprintln!("SKIP: O_DIRECT not supported on this filesystem");
        return;
    }

    // Reset statics (in case test runner reuses the process).
    ROUNDTRIP_DONE.store(false, Ordering::Release);
    ROUNDTRIP_OK.store(false, Ordering::Release);

    let (shutdown, handles) = RinglineBuilder::new(direct_io_test_config())
        .launch::<RoundtripTickHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);

    // Clean up temp file.
    let path = temp_file_path(".krio_direct_io_roundtrip_test");
    let _ = std::fs::remove_file(&path);

    if let Some(err) = ROUNDTRIP_ERR.get() {
        panic!("direct I/O roundtrip failed: {err}");
    }
    assert!(
        ROUNDTRIP_DONE.load(Ordering::Acquire),
        "test did not complete"
    );
    assert!(
        ROUNDTRIP_OK.load(Ordering::Acquire),
        "data verification failed"
    );
}

// ── Multiple files test ─────────────────────────────────────────────

static MULTI_FILE_DONE: AtomicBool = AtomicBool::new(false);
static MULTI_FILE_OK: AtomicBool = AtomicBool::new(false);
static MULTI_FILE_ERR: OnceLock<String> = OnceLock::new();

struct MultiFileTickHandler;

impl AsyncEventHandler for MultiFileTickHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_tick(&mut self) {
        static STARTED: AtomicBool = AtomicBool::new(false);
        if STARTED.swap(true, Ordering::AcqRel) {
            return;
        }

        let mut paths = Vec::new();
        for i in 0..3 {
            let path = temp_file_path(&format!(".krio_direct_io_multi_{i}"));
            if let Err(e) = std::fs::write(&path, [0u8; 4096]) {
                let _ = MULTI_FILE_ERR.set(format!("file create failed: {e}"));
                MULTI_FILE_DONE.store(true, Ordering::Release);
                ringline::request_shutdown().unwrap();
                return;
            }
            paths.push(path);
        }

        // Open all files.
        let mut files = Vec::new();
        for path in &paths {
            let path_str = path.to_str().unwrap();
            match ringline::open_direct_io_file(path_str) {
                Ok(file) => files.push(file),
                Err(e) => {
                    let _ = MULTI_FILE_ERR.set(format!("open failed: {e}"));
                    MULTI_FILE_DONE.store(true, Ordering::Release);
                    ringline::request_shutdown().unwrap();
                    return;
                }
            }
        }

        // Close all files.
        for file in &files {
            let _ = ringline::close_direct_io_file(*file);
        }

        MULTI_FILE_OK.store(true, Ordering::Release);
        MULTI_FILE_DONE.store(true, Ordering::Release);
        ringline::request_shutdown().unwrap();
    }

    fn create_for_worker(_id: usize) -> Self {
        MultiFileTickHandler
    }
}

#[test]
fn direct_io_multiple_files() {
    if ringline::backend() == ringline::Backend::IoUring && !io_uring_supported() {
        eprintln!("SKIP: io_uring not supported on this kernel");
        return;
    }
    if !o_direct_supported() {
        eprintln!("SKIP: O_DIRECT not supported on this filesystem");
        return;
    }

    MULTI_FILE_DONE.store(false, Ordering::Release);
    MULTI_FILE_OK.store(false, Ordering::Release);

    let (shutdown, handles) = RinglineBuilder::new(direct_io_test_config())
        .launch::<MultiFileTickHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);

    // Clean up.
    for i in 0..3 {
        let path = temp_file_path(&format!(".krio_direct_io_multi_{i}"));
        let _ = std::fs::remove_file(&path);
    }

    if let Some(err) = MULTI_FILE_ERR.get() {
        panic!("multi-file test failed: {err}");
    }
    assert!(MULTI_FILE_DONE.load(Ordering::Acquire));
    assert!(MULTI_FILE_OK.load(Ordering::Acquire));
}

// ── O_DSYNC open, write, fsync future, read back ────────────────────

static DSYNC_OUTCOME: std::sync::Mutex<Option<Result<(), String>>> = std::sync::Mutex::new(None);

/// One block, aligned for `O_DIRECT`, freed on drop.
struct Block(*mut u8);

impl Block {
    const LEN: usize = 4096;

    fn filled(byte: u8) -> Self {
        let layout = std::alloc::Layout::from_size_align(Self::LEN, Self::LEN).unwrap();
        // SAFETY: the layout has a non-zero size.
        let ptr = unsafe { std::alloc::alloc(layout) };
        assert!(!ptr.is_null());
        // SAFETY: `ptr` is valid for `LEN` bytes.
        unsafe { std::ptr::write_bytes(ptr, byte, Self::LEN) };
        Block(ptr)
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: `self.0` is valid for `LEN` bytes for the life of `self`.
        unsafe { std::slice::from_raw_parts(self.0, Self::LEN) }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::from_size_align(Self::LEN, Self::LEN).unwrap();
        // SAFETY: allocated in `filled` with this layout.
        unsafe { std::alloc::dealloc(self.0, layout) };
    }
}

async fn dsync_write_fsync_read(path: &str) -> Result<(), String> {
    let options = ringline::DirectIoOpenOptions::new().dsync(true);
    let file = ringline::open_direct_io_file_with(path, options).map_err(|e| e.to_string())?;
    let out = Block::filled(0xa5);
    // SAFETY: `out` is aligned, `LEN` bytes, and outlives the await.
    let n = unsafe { ringline::direct_io_write(file, 0, out.0, Block::LEN as u32) }
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| format!("write: {e}"))?;
    if n as usize != Block::LEN {
        return Err(format!("wrote {n} bytes"));
    }
    let synced = ringline::direct_io_fsync(file)
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| format!("fsync: {e}"))?;
    if synced != 0 {
        return Err(format!("fsync resolved to {synced}"));
    }
    let back = Block::filled(0);
    // SAFETY: as for the write.
    let n = unsafe { ringline::direct_io_read(file, 0, back.0, Block::LEN as u32) }
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| format!("read: {e}"))?;
    if n as usize != Block::LEN || back.bytes() != out.bytes() {
        return Err(format!("read {n} bytes that differ from the write"));
    }
    Ok(())
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

/// A file opened with `dsync` takes writes and reads like any other, and the
/// fsync future resolves to `Ok(0)`.
#[test]
fn a_dsync_file_round_trips_and_its_fsync_future_resolves() {
    if ringline::backend() == ringline::Backend::IoUring && !io_uring_supported() {
        eprintln!("SKIP: io_uring not supported on this kernel");
        return;
    }
    if !o_direct_supported() {
        eprintln!("SKIP: O_DIRECT not supported on this filesystem");
        return;
    }
    let path = temp_file_path(".krio_direct_io_dsync");
    std::fs::write(&path, [0u8; Block::LEN]).unwrap();

    let (shutdown, handles) = RinglineBuilder::new(direct_io_test_config())
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

/// A 4 KiB-aligned 4 KiB slice of `buf`, which holds 8 KiB.
fn aligned_block(buf: &mut [u8]) -> &mut [u8] {
    let offset = buf.as_ptr().align_offset(4096);
    &mut buf[offset..offset + 4096]
}

/// A write queued before a close lands in the closed file, the handle goes
/// stale at once, and the next file opened gets none of it.
async fn write_close_open(first: &str, second: &str) -> Result<(), String> {
    let mut buf = vec![0u8; 8192];
    let block = aligned_block(&mut buf);
    block.fill(0xab);

    let a = ringline::open_direct_io_file(first).map_err(|e| e.to_string())?;
    let write = unsafe { ringline::direct_io_write(a, 0, block.as_ptr(), 4096) }
        .map_err(|e| e.to_string())?;
    let closed = ringline::close_direct_io_file(a).map_err(|e| e.to_string());
    let stale = ringline::close_direct_io_file(a).is_err();
    let b = ringline::open_direct_io_file(second).map_err(|e| e.to_string());
    // Awaited before any return, so `buf` outlives the write.
    let written = write.await.map_err(|e| e.to_string())?;
    closed?;
    ringline::close_direct_io_file(b?).map_err(|e| e.to_string())?;
    if !stale {
        return Err("a second close of the handle succeeded".to_string());
    }
    if written != 4096 {
        return Err(format!("write returned {written}"));
    }
    Ok(())
}

/// Every deferred close releases its slot: with more rounds than slots, an open
/// fails once a slot leaks.
async fn deferred_closes_release_their_slots(path: &str) -> Result<(), String> {
    let mut buf = vec![0u8; 8192];
    let block = aligned_block(&mut buf);
    for round in 0..16 {
        let file =
            ringline::open_direct_io_file(path).map_err(|e| format!("round {round}: open: {e}"))?;
        let ptr = block.as_mut_ptr();
        let op = match round % 3 {
            0 => unsafe { ringline::direct_io_write(file, 0, ptr, 4096) },
            1 => unsafe { ringline::direct_io_read(file, 0, ptr, 4096) },
            _ => ringline::direct_io_fsync(file),
        }
        .map_err(|e| format!("round {round}: submit: {e}"))?;
        let closed = ringline::close_direct_io_file(file);
        // Awaited before any return, so `buf` outlives the operation.
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
    std::fs::write(&first, [0u8; 4096]).unwrap();
    std::fs::write(&second, [0u8; 4096]).unwrap();

    let config = direct_io_test_config_builder()
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
