//! Worker exit waits for the fs, direct I/O and NVMe commands still in flight,
//! and leaks its event loop, tasks included, when one outlasts the drain's
//! bound (#824). The kernel can write a command's buffer until it completes,
//! so freeing the task that owns the buffer before then would let the kernel
//! write into memory the allocator has handed out again.
//!
//! The command is a read from a FIFO opened read-write: it waits in the kernel
//! until the test writes to the FIFO, or forever. Linux only.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use ringline::fs::{FsConfig, OpenFlags};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

static FIFO: Mutex<Option<PathBuf>> = Mutex::new(None);
static READ_QUEUED: AtomicBool = AtomicBool::new(false);
static TASK_DROPPED: AtomicBool = AtomicBool::new(false);
/// The read's result, if it resolved.
static READ_RESULT: Mutex<Option<String>> = Mutex::new(None);
/// `cargo test` runs this binary's tests on parallel threads, and they share
/// the statics above.
static SERIAL: Mutex<()> = Mutex::new(());

type Launched = (
    PathBuf,
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
    std::net::TcpStream,
);

/// Records that the connection's task, which owns it, was dropped.
struct OnDrop;

impl Drop for OnDrop {
    fn drop(&mut self) {
        TASK_DROPPED.store(true, Ordering::SeqCst);
    }
}

struct ReadsFromFifo;

impl AsyncEventHandler for ReadsFromFifo {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Held for the task's life: dropping the connection closes it,
            // and closing it drops this task.
            let _conn = conn;
            let _guard = OnDrop;
            let fifo = FIFO.lock().unwrap().clone().unwrap();
            // Read-write, so the open does not wait for a writer and the
            // read waits for data.
            let file = ringline::fs::open(&fifo, OpenFlags::READ_WRITE, 0)
                .unwrap()
                .await
                .unwrap();
            let read = ringline::fs::read_into(file, 0, BytesMut::with_capacity(4096)).unwrap();
            READ_QUEUED.store(true, Ordering::SeqCst);
            let (result, _buf) = read.await;
            *READ_RESULT.lock().unwrap() = Some(format!("{result:?}"));
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ReadsFromFifo
    }
}

/// Starts a runtime whose one connection's task has a FIFO read in flight,
/// and returns the FIFO's path with the runtime.
fn launch_with_read_in_flight(name: &str) -> Launched {
    READ_QUEUED.store(false, Ordering::SeqCst);
    TASK_DROPPED.store(false, Ordering::SeqCst);
    *READ_RESULT.lock().unwrap() = None;
    let dir = std::env::temp_dir().join(format!("ringline-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    *FIFO.lock().unwrap() = Some(fifo.clone());

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
        .launch::<ReadsFromFifo>()
        .expect("launch");
    let client = std::net::TcpStream::connect(runtime.bound_addr().unwrap()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while !READ_QUEUED.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "the read was never queued");
        std::thread::sleep(Duration::from_millis(10));
    }
    // The read's SQE is submitted at the loop's next flush.
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        *READ_RESULT.lock().unwrap(),
        None,
        "the read resolved before shutdown"
    );
    assert!(
        !TASK_DROPPED.load(Ordering::SeqCst),
        "the task ended before shutdown"
    );
    (fifo, runtime, handles, client)
}

/// Opens the FIFO for writing without waiting (the worker's open is a
/// reader) and writes to it, which completes the read. Best effort: once the
/// worker has closed its end the open fails with `ENXIO`, and the caller's
/// assertions report what happened.
fn complete_the_read(fifo: &PathBuf) {
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut w) = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(fifo)
    {
        let _ = w.write_all(b"done");
    }
}

/// A read that completes during the drain is waited for, and the worker then
/// drops its tasks as usual.
#[test]
fn worker_exit_waits_for_a_disk_read_in_flight() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (fifo, runtime, handles, _client) = launch_with_read_in_flight("exit-waits");

    const DELAY: Duration = Duration::from_millis(500);
    let writer = {
        let fifo = fifo.clone();
        std::thread::spawn(move || {
            std::thread::sleep(DELAY);
            complete_the_read(&fifo);
        })
    };
    let start = Instant::now();
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    let waited = start.elapsed();
    writer.join().unwrap();
    let _ = std::fs::remove_dir_all(fifo.parent().unwrap());

    assert!(
        waited >= DELAY,
        "the worker exited after {waited:?}, before the read completed at {DELAY:?}"
    );
    assert!(
        waited < Duration::from_secs(5),
        "the worker took {waited:?}: the read's completion did not end the wait"
    );
    assert!(
        TASK_DROPPED.load(Ordering::SeqCst),
        "the worker leaked its tasks although the read completed"
    );
}

/// A read still in flight at the drain's 10 s bound leaves the task that owns
/// its buffer alive: the worker leaks its event loop.
#[test]
fn worker_exit_leaks_its_tasks_when_a_disk_read_outlasts_the_drain() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (fifo, runtime, handles, _client) = launch_with_read_in_flight("exit-leaks");

    let start = Instant::now();
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    let waited = start.elapsed();
    let dropped = TASK_DROPPED.load(Ordering::SeqCst);
    // Let the leaked read finish.
    complete_the_read(&fifo);
    let _ = std::fs::remove_dir_all(fifo.parent().unwrap());

    assert!(
        waited >= Duration::from_secs(9),
        "the worker exited after {waited:?} with a read in flight"
    );
    assert!(
        !dropped,
        "the task owning the in-flight read's buffer was dropped"
    );
}
