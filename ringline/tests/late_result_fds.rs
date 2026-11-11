//! A pool result that reaches no worker, or no future, must not leak the fd it
//! carries.
//!
//! - On mio, `fs::open` runs on the disk-I/O pool. Opening a FIFO for reading
//!   blocks until a writer appears, so the open can complete after the worker
//!   that asked for it has exited; the fd it opened must be closed.
//! - A spawn result carries the child's pidfd. Results that arrive after the
//!   worker has exited, and results whose future was dropped before or after
//!   delivery, must close it exactly once.
//!
//! Its own test binary, because it counts the process's open fds; the tests
//! take a lock so they do not disturb each other. Linux only.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

#[cfg(not(has_io_uring))]
use std::collections::HashSet;
use std::future::Future;
#[cfg(not(has_io_uring))]
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Mutex;
#[cfg(not(has_io_uring))]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

/// Serialises the tests, which count process-wide fds.
static FD_LOCK: Mutex<()> = Mutex::new(());

#[cfg(not(has_io_uring))]
static OPEN_ISSUED: AtomicBool = AtomicBool::new(false);
#[cfg(not(has_io_uring))]
static FIFO_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Opens a FIFO for reading on the disk-I/O pool from `on_start`.
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
            OPEN_ISSUED.store(true, Ordering::Release);
            let _ = open.await;
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        FifoOpen
    }
}

/// The process's open fds, excluding the directory handle used to list them.
#[cfg(not(has_io_uring))]
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

/// The disk-I/O pool runs on mio only.
#[cfg(not(has_io_uring))]
#[test]
fn a_late_disk_io_open_does_not_leak_its_fd() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("ringline-late-open-{}", std::process::id()));
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
    while !OPEN_ISSUED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(OPEN_ISSUED.load(Ordering::Acquire), "fs::open never issued");
    if let Err(last) = wait_in_open("rl-disk-", Duration::from_secs(30)) {
        panic!("the disk-I/O thread never blocked in open(2); last syscall reads: {last}");
    }

    drop(runtime);
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    assert!(
        thread_alive("rl-disk-"),
        "the disk-I/O thread exited before the open completed; the test proves nothing"
    );

    // Opening the writer completes the pool thread's open(2). Its response
    // reaches no worker.
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

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut leaked: Vec<RawFd> = open_fds().difference(&baseline).copied().collect();
    while !leaked.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        leaked = open_fds().difference(&baseline).copied().collect();
    }
    let targets: Vec<String> = leaked
        .iter()
        .filter_map(|fd| std::fs::read_link(format!("/proc/self/fd/{fd}")).ok())
        .map(|t| t.display().to_string())
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        leaked.is_empty(),
        "fds still open 5s after the late open completed: {leaked:?} -> {targets:?}"
    );
}

/// The process's open pidfds.
fn open_pidfds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter(|t| t.to_string_lossy().contains("pidfd"))
        .count()
}

fn spawn_config() -> ringline::Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(1)
        .disk_io_threads(0)
        .no_fs()
        .build()
        .expect("valid config")
}

const LATE_SPAWNS: usize = 300;
static LATE_SPAWNS_ISSUED: AtomicBool = AtomicBool::new(false);

/// Issues many spawns and keeps their futures pending, so the results still
/// queued on the single spawner thread arrive after the worker has exited.
struct SpawnMany;

impl AsyncEventHandler for SpawnMany {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let mut pending = Vec::new();
            for _ in 0..LATE_SPAWNS {
                pending.push(
                    ringline::process::Command::new("true")
                        .spawn()
                        .expect("spawn"),
                );
            }
            LATE_SPAWNS_ISSUED.store(true, Ordering::Release);
            // Hold the futures; worker exit drops them.
            loop {
                let _ = ringline::sleep(Duration::from_secs(1)).await;
                let _ = pending.len();
            }
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        SpawnMany
    }
}

/// Spawn results that reach no worker close their pidfds.
#[test]
fn late_spawn_results_close_their_pidfds() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (runtime, handles) = RinglineBuilder::new(spawn_config())
        .launch::<SpawnMany>()
        .expect("launch");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !LATE_SPAWNS_ISSUED.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        LATE_SPAWNS_ISSUED.load(Ordering::Acquire),
        "spawns never issued"
    );
    drop(runtime);
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }

    let deadline = Instant::now() + Duration::from_secs(20);
    while thread_alive("rl-spwn-") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!thread_alive("rl-spwn-"), "spawner thread never exited");
    let deadline = Instant::now() + Duration::from_secs(5);
    while open_pidfds() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(open_pidfds(), 0, "pidfds of late spawn results leaked");
}

static DROPPED_SPAWNS_DONE: AtomicBool = AtomicBool::new(false);

/// Drops spawn futures before delivery, after delivery without polling, and
/// after awaiting (dropping the `Child`), with the worker still running.
struct SpawnDrop;

impl AsyncEventHandler for SpawnDrop {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            // Dropped before delivery.
            for _ in 0..50 {
                drop(
                    ringline::process::Command::new("true")
                        .spawn()
                        .expect("spawn"),
                );
            }
            // Delivered, never polled, then dropped.
            let mut held = Vec::new();
            for _ in 0..50 {
                held.push(
                    ringline::process::Command::new("true")
                        .spawn()
                        .expect("spawn"),
                );
            }
            let _ = ringline::sleep(Duration::from_millis(500)).await;
            drop(held);
            // Delivered and awaited; the `Child` is dropped.
            for _ in 0..20 {
                let child = ringline::process::Command::new("true")
                    .spawn()
                    .expect("spawn")
                    .await
                    .expect("child");
                drop(child);
            }
            DROPPED_SPAWNS_DONE.store(true, Ordering::Release);
            loop {
                let _ = ringline::sleep(Duration::from_millis(50)).await;
            }
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        SpawnDrop
    }
}

/// Spawn futures dropped at each stage close their pidfds while the worker
/// runs.
#[test]
fn dropped_spawn_futures_close_their_pidfds() {
    let _lock = FD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (runtime, handles) = RinglineBuilder::new(spawn_config())
        .launch::<SpawnDrop>()
        .expect("launch");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !DROPPED_SPAWNS_DONE.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        DROPPED_SPAWNS_DONE.load(Ordering::Acquire),
        "spawns never finished"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while open_pidfds() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let live = open_pidfds();
    drop(runtime);
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    assert_eq!(live, 0, "pidfds leaked with the worker still running");
}
