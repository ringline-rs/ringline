//! A read whose connection closes while it is in flight in the kernel frees
//! its buffer once the read completes, while the worker keeps running
//! (#568). io_uring counterpart of `disk_io_teardown_buffers.rs`.
//!
//! Its own test binary: it installs a global allocator that counts frees of
//! one distinctive allocation size. The read is from a FIFO opened read-write,
//! so it waits in the kernel until the runtime cancels it. Linux only.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use ringline::fs::{FsConfig, OpenFlags};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

/// The capacity of the abandoned read's buffer. Nothing else in the process
/// allocates exactly this many bytes.
const BUF_SIZE: usize = 777_781;

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

static FIFO: Mutex<Option<PathBuf>> = Mutex::new(None);
static READ_QUEUED: AtomicBool = AtomicBool::new(false);
static READ_RESOLVED: AtomicBool = AtomicBool::new(false);
static TASK_DROPPED: AtomicBool = AtomicBool::new(false);

/// Records that the connection's task, which owns it, was dropped.
struct OnDrop;

impl Drop for OnDrop {
    fn drop(&mut self) {
        TASK_DROPPED.store(true, Ordering::SeqCst);
    }
}

struct ReadsInConnection;

impl AsyncEventHandler for ReadsInConnection {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        let (mut tx, _rx) = conn.split();
        async move {
            let _guard = OnDrop;
            let fifo = FIFO.lock().unwrap().clone().unwrap();
            // Read-write, so the open does not wait for a writer and the
            // read waits for data that never comes.
            let file = ringline::fs::open(&fifo, OpenFlags::READ_WRITE, 0)
                .unwrap()
                .await
                .unwrap();
            let read = ringline::fs::read_into(file, 0, BytesMut::with_capacity(BUF_SIZE)).unwrap();
            // Close this connection while the read waits: the task, and the
            // read's future with it, is dropped outside any task poll.
            ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(100)).await;
                tx.close();
            })
            .unwrap();
            READ_QUEUED.store(true, Ordering::SeqCst);
            let _ = read.await;
            READ_RESOLVED.store(true, Ordering::SeqCst);
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ReadsInConnection
    }
}

#[test]
fn a_read_dropped_with_its_connection_frees_its_buffer() {
    let dir = std::env::temp_dir().join(format!(
        "ringline-teardown-buf-uring-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    *FIFO.lock().unwrap() = Some(fifo);

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
        .launch::<ReadsInConnection>()
        .expect("launch");
    let _client = std::net::TcpStream::connect(runtime.bound_addr().unwrap()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while !TASK_DROPPED.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    // The release parks the buffer and cancels the read; the cancelled read's
    // completion frees it.
    let deadline = Instant::now() + Duration::from_secs(5);
    while BUF_FREES.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let frees = BUF_FREES.load(Ordering::SeqCst);

    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        READ_QUEUED.load(Ordering::SeqCst),
        "the read was never queued"
    );
    assert!(
        TASK_DROPPED.load(Ordering::SeqCst),
        "the connection's task was not dropped"
    );
    assert!(
        !READ_RESOLVED.load(Ordering::SeqCst),
        "the read resolved before its task was dropped"
    );
    assert_eq!(
        frees, 1,
        "the buffer was not freed after its read completed"
    );
}
