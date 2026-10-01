//! A background thread that wakes a worker after the `Runtime` has dropped
//! must not write into whatever file now holds the wake fd's number.
//!
//! A blocking task still running at shutdown finishes on its pool thread and
//! then wakes the worker that requested it. This test drops the `Runtime` and
//! joins the workers while such a task runs, refills every fd number the
//! shutdown freed with the write end of an unrelated pipe, and checks that no
//! pipe receives the wake, then that every fd `launch()` opened is closed once
//! the task has finished.
//!
//! A second test covers the worker's own hold: with no pool, a worker still
//! running after the `Runtime` drops must keep every fd `launch()` opened.
//!
//! Its own test binary, because it reads `/proc/self/fd` and claims freed fd
//! numbers, which other tests in the same process would disturb; the two tests
//! here take a lock so they do not disturb each other. Linux only.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

use std::collections::HashSet;
use std::future::Future;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

static BLOCKING_STARTED: AtomicBool = AtomicBool::new(false);
static BLOCKING_FINISHED: AtomicBool = AtomicBool::new(false);

const BLOCKING_TASK: Duration = Duration::from_millis(300);

/// Serialises the tests, which both read and claim process-wide fd numbers.
static FD_LOCK: Mutex<()> = Mutex::new(());

/// Starts one blocking task on worker 0 that outlives the runtime.
struct SlowBlocking;

impl AsyncEventHandler for SlowBlocking {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let task = ringline::spawn_blocking(|| {
                BLOCKING_STARTED.store(true, Ordering::Release);
                std::thread::sleep(BLOCKING_TASK);
                BLOCKING_FINISHED.store(true, Ordering::Release);
            })
            .expect("spawn_blocking");
            let _ = task.await;
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        SlowBlocking
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

/// Whether a thread whose name starts with `prefix` is alive. The kernel
/// truncates thread names to 15 bytes.
fn thread_alive(prefix: &str) -> bool {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok())
        .any(|name| name.trim_end().starts_with(prefix))
}

/// Whether `fd` is open, checked without opening anything.
fn is_open(fd: RawFd) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

#[test]
fn a_late_wake_does_not_write_into_a_reused_fd() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(16, 1024)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(1)
        .build()
        .expect("valid config");
    let baseline = open_fds();
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<SlowBlocking>()
        .expect("launch");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !BLOCKING_STARTED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        BLOCKING_STARTED.load(Ordering::Acquire),
        "blocking task never started"
    );

    let before = open_fds();
    drop(runtime);
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    assert!(
        !BLOCKING_FINISHED.load(Ordering::Acquire),
        "the blocking task finished before shutdown completed; the test proves nothing"
    );
    let freed: Vec<RawFd> = before.iter().copied().filter(|&fd| !is_open(fd)).collect();
    assert!(!freed.is_empty(), "shutdown freed no fd numbers");

    // Put an unrelated pipe's write end on every freed number, so a write to a
    // stale wake fd lands in a pipe this test can read.
    let mut claimed: Vec<(RawFd, RawFd)> = Vec::new();
    for &target in &freed {
        let mut fds = [0 as RawFd; 2];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
            0
        );
        // `pipe2` takes the lowest free numbers, which are the freed ones, so
        // move both ends out of the way before placing the write end.
        let read = unsafe { libc::fcntl(fds[0], libc::F_DUPFD_CLOEXEC, 512) };
        let write = unsafe { libc::fcntl(fds[1], libc::F_DUPFD_CLOEXEC, 512) };
        assert!(read >= 512 && write >= 512);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert_eq!(
            unsafe { libc::dup3(write, target, libc::O_CLOEXEC) },
            target
        );
        unsafe { libc::close(write) };
        claimed.push((read, target));
    }

    let deadline = Instant::now() + BLOCKING_TASK * 3;
    while !BLOCKING_FINISHED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        BLOCKING_FINISHED.load(Ordering::Acquire),
        "blocking task never finished"
    );
    // The pool thread wakes the worker after the task returns and exits after
    // that, since its request channel has closed.
    let deadline = Instant::now() + Duration::from_secs(5);
    while thread_alive("ringline-blocki") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !thread_alive("ringline-blocki"),
        "blocking pool thread never exited"
    );

    let mut stray = Vec::new();
    for &(read, write) in &claimed {
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(read, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            stray.push((write, n));
        }
        unsafe {
            libc::close(read);
            libc::close(write);
        }
    }
    assert!(
        stray.is_empty(),
        "a wake after Runtime drop wrote into an unrelated pipe: (fd, bytes) = {stray:?}, \
         freed fds {freed:?}"
    );

    // Holding the wake fds open past shutdown must not leak them: once the
    // last thread that could wake a worker exits, every fd `launch()` opened
    // is closed.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut leaked: Vec<RawFd> = open_fds().difference(&baseline).copied().collect();
    while !leaked.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        leaked = open_fds().difference(&baseline).copied().collect();
    }
    assert!(
        leaked.is_empty(),
        "fds opened by launch() still open 5s after shutdown: {leaked:?}"
    );
}

static WORKER_PARKED: AtomicBool = AtomicBool::new(false);

/// Blocks the worker thread in `on_start` so it outlives the `Runtime`.
struct SlowWorker;

impl AsyncEventHandler for SlowWorker {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            WORKER_PARKED.store(true, Ordering::Release);
            std::thread::sleep(BLOCKING_TASK);
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        SlowWorker
    }
}

/// With no pool threads, a worker still running after the `Runtime` drops is
/// the only holder; every fd `launch()` opened stays open until it exits.
#[test]
fn a_running_worker_keeps_its_wake_fd_open() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(16, 1024)
        .max_connections(16)
        .send_pool(16, 16384)
        // No pools: their threads would also hold the fds open. The disk-I/O
        // pool runs on mio only.
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .disk_io_threads(0)
        .build()
        .expect("valid config");
    let baseline = open_fds();
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<SlowWorker>()
        .expect("launch");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !WORKER_PARKED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        WORKER_PARKED.load(Ordering::Acquire),
        "worker never ran on_start"
    );

    let launched: Vec<RawFd> = open_fds().difference(&baseline).copied().collect();
    drop(runtime);
    assert!(
        !handles.iter().all(|h| h.is_finished()),
        "the worker exited before the check; the test proves nothing"
    );
    let closed: Vec<RawFd> = launched
        .iter()
        .copied()
        .filter(|&fd| !is_open(fd))
        .collect();
    assert!(
        closed.is_empty(),
        "Runtime drop closed fds {closed:?} while a worker that uses them is still running"
    );

    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut leaked: Vec<RawFd> = launched.iter().copied().filter(|&fd| is_open(fd)).collect();
    while !leaked.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        leaked = launched.iter().copied().filter(|&fd| is_open(fd)).collect();
    }
    assert!(
        leaked.is_empty(),
        "fds opened by launch() still open 5s after the worker exited: {leaked:?}"
    );
}

#[cfg(not(has_io_uring))]
static DISK_OPEN_ISSUED: AtomicBool = AtomicBool::new(false);
#[cfg(not(has_io_uring))]
static FIFO_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Opens a FIFO for reading on the disk-I/O pool. The open blocks until a
/// writer appears, so the pool thread outlives the worker.
#[cfg(not(has_io_uring))]
struct FifoOpen;

#[cfg(not(has_io_uring))]
impl AsyncEventHandler for FifoOpen {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = FIFO_PATH.get().expect("fifo path").clone();
            let open =
                ringline::fs::open(path, ringline::fs::OpenFlags::READ, 0).expect("fs::open");
            DISK_OPEN_ISSUED.store(true, Ordering::Release);
            let _ = open.await;
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        FifoOpen
    }
}

/// The mio disk-I/O pool's hold: an fs operation that completes after the
/// worker has exited must not wake into a reused fd. The disk-I/O pool runs
/// on mio only.
#[cfg(not(has_io_uring))]
#[test]
fn a_late_disk_io_wake_does_not_write_into_a_reused_fd() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("ringline-wake-fifo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let fifo = dir.join("fifo");
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0, "mkfifo");
    FIFO_PATH.set(fifo.clone()).expect("fifo path set once");

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(16, 1024)
        .max_connections(16)
        .send_pool(16, 16384)
        // Only the disk-I/O pool, so its hold is the one under test.
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .disk_io_threads(1)
        .build()
        .expect("valid config");
    let baseline = open_fds();
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<FifoOpen>()
        .expect("launch");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !DISK_OPEN_ISSUED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        DISK_OPEN_ISSUED.load(Ordering::Acquire),
        "fs::open never issued"
    );
    // The disk-I/O thread picks the request up and blocks in open(2).
    std::thread::sleep(Duration::from_millis(50));

    let before = open_fds();
    drop(runtime);
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    assert!(
        thread_alive("ringline-disk-i"),
        "the disk-I/O thread exited before the open completed; the test proves nothing"
    );
    let freed: Vec<RawFd> = before.iter().copied().filter(|&fd| !is_open(fd)).collect();

    let mut claimed: Vec<(RawFd, RawFd)> = Vec::new();
    for &target in &freed {
        let mut fds = [0 as RawFd; 2];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
            0
        );
        let read = unsafe { libc::fcntl(fds[0], libc::F_DUPFD_CLOEXEC, 512) };
        let write = unsafe { libc::fcntl(fds[1], libc::F_DUPFD_CLOEXEC, 512) };
        assert!(read >= 512 && write >= 512);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert_eq!(
            unsafe { libc::dup3(write, target, libc::O_CLOEXEC) },
            target
        );
        unsafe { libc::close(write) };
        claimed.push((read, target));
    }

    // Opening the writer completes the pool thread's open(2); it then wakes
    // the worker and, its request channel closed, exits.
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(&fifo)
        .expect("open fifo writer");
    let deadline = Instant::now() + Duration::from_secs(5);
    while thread_alive("ringline-disk-i") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !thread_alive("ringline-disk-i"),
        "disk-I/O thread never exited"
    );
    drop(writer);

    let mut stray = Vec::new();
    for &(read, write) in &claimed {
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(read, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            stray.push((write, n));
        }
        unsafe {
            libc::close(read);
            libc::close(write);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        stray.is_empty(),
        "a disk-I/O wake after Runtime drop wrote into an unrelated pipe: \
         (fd, bytes) = {stray:?}, freed fds {freed:?}"
    );

    // The open's own result is not a wake fd. Its response reaches no worker
    // and is dropped without closing the file, a separate leak, so it is
    // excluded here.
    let opened_by_launch = || -> Vec<RawFd> {
        open_fds()
            .difference(&baseline)
            .copied()
            .filter(|fd| {
                std::fs::read_link(format!("/proc/self/fd/{fd}"))
                    .map(|t| !t.starts_with(&dir))
                    .unwrap_or(true)
            })
            .collect()
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut leaked = opened_by_launch();
    while !leaked.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        leaked = opened_by_launch();
    }
    assert!(
        leaked.is_empty(),
        "fds opened by launch() still open 5s after shutdown: {leaked:?}"
    );
}
