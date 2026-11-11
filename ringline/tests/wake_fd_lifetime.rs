//! A background thread that wakes a worker after the `Runtime` has dropped
//! must not write into whatever file now holds the wake fd's number.
//!
//! A blocking task still running at shutdown finishes on its pool thread and
//! then wakes the worker that requested it. This test drops the `Runtime` and
//! joins the workers while such a task runs, refills every fd number the
//! shutdown freed with the write end of an unrelated pipe, releases the task,
//! and checks that no pipe receives the wake, then that every fd `launch()`
//! opened is closed once the task has finished.
//!
//! A second test covers the worker's own hold: with no pool, a worker still
//! running after the `Runtime` drops must keep every fd `launch()` opened.
//!
//! A third test, on mio only, covers the disk-I/O pool's hold: an `fs::open`
//! of a FIFO with no writer completes after the worker has exited, and its
//! wake must not write into a reused fd.
//!
//! Its own test binary, because it reads `/proc/self/fd` and claims freed fd
//! numbers, which other tests in the same process would disturb; the tests
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
static BLOCKING_RELEASED: AtomicBool = AtomicBool::new(false);
static BLOCKING_FINISHED: AtomicBool = AtomicBool::new(false);

/// How long a test waits for a thread that may be starved: the blocking pool
/// runs at `SCHED_IDLE`, so on a loaded host it can wait seconds for a CPU.
const STARVED: Duration = Duration::from_secs(30);

/// How long a held task or worker waits for the test to release it before it
/// returns anyway, so a failed test does not leave a thread blocked forever.
const HOLD_LIMIT: Duration = Duration::from_secs(60);

/// Sets its flag when dropped, so a test that fails before releasing a held
/// thread still lets that thread return.
struct ReleaseOnDrop(&'static AtomicBool);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Waits until `flag` is set or `limit` has passed.
fn wait_for(flag: &AtomicBool, limit: Duration) {
    let deadline = Instant::now() + limit;
    while !flag.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Serialises the tests, which both read and claim process-wide fd numbers.
static FD_LOCK: Mutex<()> = Mutex::new(());

/// Starts one blocking task on worker 0 that waits for `BLOCKING_RELEASED`,
/// so it outlives the runtime.
struct SlowBlocking;

impl AsyncEventHandler for SlowBlocking {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let task = ringline::spawn_blocking(|| {
                BLOCKING_STARTED.store(true, Ordering::Release);
                wait_for(&BLOCKING_RELEASED, HOLD_LIMIT);
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

/// Whether a thread whose name starts with `prefix` is alive.
fn thread_alive(prefix: &str) -> bool {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok())
        .any(|name| name.trim_end().starts_with(prefix))
}

/// Waits until a thread whose name starts with `prefix` is inside open(2), or
/// `limit` has passed. A FIFO open with no writer does not return, so once the
/// thread is inside the call it stays there until the test opens the writer.
/// On timeout, returns what the last poll read from each matching thread's
/// `/proc/self/task/<tid>/syscall`.
#[cfg(not(has_io_uring))]
fn wait_in_open(prefix: &str, limit: Duration) -> Result<(), String> {
    // musl's open() makes the open syscall on archs that have it, of which
    // only x86_64 is built here; glibc's makes openat.
    #[cfg(target_arch = "x86_64")]
    let open_calls = [libc::SYS_openat, libc::SYS_open];
    #[cfg(not(target_arch = "x86_64"))]
    let open_calls = [libc::SYS_openat];
    let deadline = Instant::now() + limit;
    loop {
        let reads: Vec<std::io::Result<String>> = std::fs::read_dir("/proc/self/task")
            .expect("read /proc/self/task")
            .filter_map(|t| t.ok())
            .filter(|t| {
                std::fs::read_to_string(t.path().join("comm"))
                    .is_ok_and(|name| name.trim_end().starts_with(prefix))
            })
            .map(|t| std::fs::read_to_string(t.path().join("syscall")))
            .collect();
        // While the thread is blocked in a syscall the first field is its
        // number; blocked outside one, `-1`; on a CPU, the file reads
        // `running`.
        let in_open = reads.iter().any(|read| {
            read.as_ref().is_ok_and(|s| {
                s.split_whitespace()
                    .next()
                    .and_then(|nr| nr.parse::<libc::c_long>().ok())
                    .is_some_and(|nr| open_calls.contains(&nr))
            })
        });
        if in_open {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("{reads:?}"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Whether `fd` is open, checked without opening anything.
fn is_open(fd: RawFd) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

#[test]
fn a_late_wake_does_not_write_into_a_reused_fd() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _release = ReleaseOnDrop(&BLOCKING_RELEASED);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(1)
        .build()
        .expect("valid config");
    let baseline = open_fds();
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<SlowBlocking>()
        .expect("launch");

    wait_for(&BLOCKING_STARTED, STARVED);
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

    BLOCKING_RELEASED.store(true, Ordering::Release);
    wait_for(&BLOCKING_FINISHED, STARVED);
    assert!(
        BLOCKING_FINISHED.load(Ordering::Acquire),
        "blocking task never finished"
    );
    // The pool thread wakes the worker after the task returns and exits after
    // that, since its request channel has closed.
    let deadline = Instant::now() + STARVED;
    while thread_alive("rl-blok-") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !thread_alive("rl-blok-"),
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
static WORKER_RELEASED: AtomicBool = AtomicBool::new(false);

/// Blocks the worker thread in `on_start` until the test sets
/// `WORKER_RELEASED`, so it outlives the `Runtime`.
struct SlowWorker;

impl AsyncEventHandler for SlowWorker {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            WORKER_PARKED.store(true, Ordering::Release);
            wait_for(&WORKER_RELEASED, HOLD_LIMIT);
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
    let _release = ReleaseOnDrop(&WORKER_RELEASED);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        // No pools: their threads would also hold the fds open. The disk-I/O
        // pool runs on mio only.
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .disk_io_threads(0)
        .no_fs()
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
    WORKER_RELEASED.store(true, Ordering::Release);

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
    if let Err(last) = wait_in_open("rl-disk-", Duration::from_secs(30)) {
        panic!("the disk-I/O thread never blocked in open(2); last syscall reads: {last}");
    }

    let before = open_fds();
    drop(runtime);
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    assert!(
        thread_alive("rl-disk-"),
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
    while thread_alive("rl-disk-") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!thread_alive("rl-disk-"), "disk-I/O thread never exited");
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
