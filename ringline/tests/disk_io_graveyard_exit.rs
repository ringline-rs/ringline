//! A buffer whose read was abandoned and is still queued when its worker exits
//! stays allocated: `Executor::drop` leaks the graveyard. The disk-I/O pool
//! then answers the queued read without running it (checked by
//! `worker::disk_exit_tests`, not here).
//!
//! Its own test binary: it installs a global allocator that counts frees of
//! one distinctive allocation size. mio only: the read is queued on the
//! disk-I/O pool behind an open that is held until after the worker joins.
//! Linux only: it uses `mkfifo`.

#![cfg(all(target_os = "linux", not(has_io_uring)))]
#![allow(clippy::manual_async_fn)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use ringline::fs::{FsConfig, OpenFlags};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

/// The capacity of the abandoned read's buffer. Nothing else in the process
/// allocates exactly this many bytes.
const BUF_SIZE: usize = 777_777;

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
static OUTCOME: Mutex<Option<Result<(), String>>> = Mutex::new(None);
/// Set by the test once the pool thread is inside the FIFO's open, so the
/// worker does not exit before the pool has started it.
static RELEASE: AtomicBool = AtomicBool::new(false);

struct AbandonsRead;

impl AsyncEventHandler for AbandonsRead {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let outcome = abandon_a_queued_read().await;
            *OUTCOME.lock().unwrap() = Some(outcome);
            while !RELEASE.load(Ordering::SeqCst) {
                ringline::sleep(Duration::from_millis(1)).await;
            }
            ringline::request_shutdown().ok();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        AbandonsRead
    }
}

async fn abandon_a_queued_read() -> Result<(), String> {
    let dir = DIR.lock().unwrap().clone().unwrap();
    let file = ringline::fs::open(dir.join("data"), OpenFlags::READ, 0)
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    // Park the pool's only thread in an open that waits for a writer, which
    // the test opens after the worker has exited.
    drop(ringline::fs::open(dir.join("fifo"), OpenFlags::READ, 0).map_err(|e| e.to_string())?);
    // Queued behind it. Dropping the future parks the buffer until the read
    // completes.
    let read = ringline::fs::read_into(file, 0, BytesMut::with_capacity(BUF_SIZE))
        .map_err(|e| e.to_string())?;
    drop(read);
    Ok(())
}

/// Waits until a thread whose name starts with `prefix` is inside open(2), or
/// `limit` has passed. A FIFO open with no writer does not return, so once the
/// thread is inside the call it stays there until the test opens the writer.
/// On timeout, returns what the last poll read from each matching thread's
/// `/proc/self/task/<tid>/syscall`.
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

#[test]
fn an_abandoned_reads_buffer_outlives_its_worker() {
    let dir = std::env::temp_dir().join(format!("ringline-graveyard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("data"), vec![7u8; 4096]).unwrap();
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
        .disk_io_threads(1)
        .fs(FsConfig::default().max_files(4).max_commands_in_flight(64))
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<AbandonsRead>()
        .expect("launch");
    if let Err(last) = wait_in_open("ringline-disk-i", Duration::from_secs(30)) {
        panic!("the disk-I/O thread never blocked in open(2); last syscall reads: {last}");
    }
    RELEASE.store(true, Ordering::SeqCst);
    common::join_workers(&runtime, handles);
    drop(runtime);
    OUTCOME
        .lock()
        .unwrap()
        .take()
        .expect("on_start did not finish")
        .unwrap();
    // The read is still queued behind the parked open.
    let frees = BUF_FREES.load(Ordering::SeqCst);

    // Let the pool finish the open; the read queued behind it is then answered
    // without running, since its worker has exited. Read-write, so this open
    // does not wait for a reader.
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fifo)
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    drop(writer);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        frees, 0,
        "the buffer was freed while its read was still queued"
    );
}
