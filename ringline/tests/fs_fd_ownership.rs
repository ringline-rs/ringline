//! Who owns a filesystem file's fd: abandoned opens, files left open at
//! worker exit, and a close while operations on the file are still queued.
//!
//! Its own test binary, because it inspects the process's open fds. Linux
//! only: it reads `/proc/self/fd`.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use ringline::fs::{FsConfig, OpenFlags};
use ringline::{AsyncEventHandler, Config, ConfigBuilder, Connection, RinglineBuilder};

/// What a test's `on_start` found, read by the test after the worker joins.
static OUTCOME: Mutex<Option<Result<(), String>>> = Mutex::new(None);
/// The tests share `OUTCOME` and count fds, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn config(max_files: u16, disk_io_threads: usize) -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .disk_io_threads(disk_io_threads)
        .fs(FsConfig::default()
            .max_files(max_files)
            .max_commands_in_flight(64))
        .build()
        .expect("valid config")
}

/// Launch one worker, wait for it to exit, and return what `on_start` set.
fn run<H: AsyncEventHandler>(config: Config) -> Result<(), String> {
    *OUTCOME.lock().unwrap() = None;
    let (runtime, handles) = RinglineBuilder::new(config).launch::<H>().expect("launch");
    common::join_workers(&runtime, handles);
    OUTCOME
        .lock()
        .unwrap()
        .take()
        .unwrap_or_else(|| Err("on_start did not finish".into()))
}

fn finish(outcome: Result<(), String>) {
    *OUTCOME.lock().unwrap() = Some(outcome);
    ringline::request_shutdown().ok();
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ringline-fs-fd-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn mkfifo(path: &Path) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
}

/// How many of this process's fds refer to `path`.
fn fds_on(path: &Path) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter(|target| target == path)
        .count()
}

// ── An open whose future is dropped frees its slot and fd ───────────

struct AbandonedOpens;

impl AsyncEventHandler for AbandonedOpens {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            finish(abandoned_opens().await);
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        AbandonedOpens
    }
}

async fn abandoned_opens() -> Result<(), String> {
    let dir = temp_dir("abandoned");
    let path = dir.join("file");
    std::fs::write(&path, b"x").map_err(|e| e.to_string())?;
    let open = || ringline::fs::open(&path, OpenFlags::READ, 0).map_err(|e| e.to_string());

    // Both slots of the table, each taken by an open whose future is dropped
    // before the event loop has seen its completion.
    drop(open()?);
    drop(open()?);

    // Both slots come back once the abandoned opens complete.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
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
            ringline::fs::close(*file).map_err(|e| e.to_string())?;
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
        ringline::sleep(Duration::from_millis(10)).await;
    }

    // An open that completed but whose future was dropped before it was
    // polled: the result is waiting, and no `File` was ever handed out.
    let pending = open()?;
    ringline::sleep(Duration::from_millis(100)).await;
    drop(pending);
    // The event loop frees the slot on its next iteration.
    ringline::sleep(Duration::from_millis(10)).await;
    let a = open()?.await.map_err(|e| e.to_string())?;
    let b = open()?
        .await
        .map_err(|e| format!("a completed, unpolled open kept its slot: {e}"))?;
    ringline::fs::close(a).map_err(|e| e.to_string())?;
    ringline::fs::close(b).map_err(|e| e.to_string())?;

    // Every handle is closed, so no fd may remain. (On io_uring files live in
    // the ring's fixed-file table and are never in `/proc/self/fd`.)
    if fds_on(&path) != 0 {
        return Err(format!("{} fds still open on the file", fds_on(&path)));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn abandoned_opens_free_their_slot_and_fd() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    run::<AbandonedOpens>(config(2, 2)).unwrap();
}

// ── io_uring: an abandoned open's file leaves the fixed-file table ──

/// Tests of io_uring's fixed-file table, which `/proc/self/fd` cannot see.
#[cfg(has_io_uring)]
mod uring {
    use super::*;

    struct AbandonedFifoOpen;

    impl AsyncEventHandler for AbandonedFifoOpen {
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async {
                finish(abandoned_fifo_open().await);
            }))
        }
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            async {}
        }
        fn create_for_worker(_id: usize) -> Self {
            AbandonedFifoOpen
        }
    }

    /// io_uring opens a FIFO's read end without waiting for a writer. Once the
    /// abandoned open is released, no reader is left, so a non-blocking open of
    /// the write end fails with `ENXIO`. A file left in the fixed-file table would
    /// still be a reader.
    async fn abandoned_fifo_open() -> Result<(), String> {
        let dir = temp_dir("abandoned-fifo");
        let fifo = dir.join("fifo");
        mkfifo(&fifo);
        drop(ringline::fs::open(&fifo, OpenFlags::READ, 0).map_err(|e| e.to_string())?);

        // Wait for the table's only slot to come back. The probe opens a path
        // that does not exist, so it never puts a file in the slot, which would
        // replace whatever is registered there.
        let missing = dir.join("missing");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match ringline::fs::open(&missing, OpenFlags::READ, 0) {
                Ok(probe) => {
                    let _ = probe.await;
                    break;
                }
                Err(e) if std::time::Instant::now() >= deadline => {
                    return Err(format!("the abandoned open's slot was not freed: {e}"));
                }
                Err(_) => ringline::sleep(Duration::from_millis(10)).await,
            }
        }

        // The FIFO's read end closes with the file's last reference. Linux 6.1
        // drops that about 1.1 s after the slot is freed.
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_millis(2500);
        let (fd, err) = loop {
            let fd = unsafe {
                libc::open(
                    c.as_ptr(),
                    libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            let err = std::io::Error::last_os_error();
            if fd < 0 || std::time::Instant::now() >= deadline {
                break (fd, err);
            }
            unsafe { libc::close(fd) };
            ringline::sleep(Duration::from_millis(20)).await;
        };
        let _ = std::fs::remove_dir_all(&dir);
        if fd >= 0 {
            unsafe { libc::close(fd) };
            return Err("the abandoned open's FIFO is still open for reading".into());
        }
        if err.raw_os_error() != Some(libc::ENXIO) {
            return Err(format!("opening the FIFO's write end: {err}"));
        }
        Ok(())
    }

    #[test]
    fn an_abandoned_open_leaves_the_fixed_file_table() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        run::<AbandonedFifoOpen>(config(1, 2)).unwrap();
    }
}

/// Tests of the mio backend's fd tables. On io_uring files live in the ring's
/// fixed-file table, which closes with the ring, and never appear in
/// `/proc/self/fd`.
#[cfg(not(has_io_uring))]
mod mio {
    use super::*;

    /// Open the FIFO's write end on another thread, which completes every
    /// open of its read end that is waiting, and hold it briefly.
    fn release_fifo_readers(path: PathBuf) {
        std::thread::spawn(move || {
            let writer = std::fs::OpenOptions::new().write(true).open(&path);
            std::thread::sleep(Duration::from_millis(200));
            drop(writer);
        });
    }

    // ── A file left open closes when its worker exits (mio) ─────────────

    static LEFT_OPEN: Mutex<Option<PathBuf>> = Mutex::new(None);

    struct LeavesFileOpen;

    impl AsyncEventHandler for LeavesFileOpen {
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async {
                let path = temp_dir("left-open").join("file");
                *LEFT_OPEN.lock().unwrap() = Some(path.clone());
                let outcome = async {
                    let file = ringline::fs::create(&path)?.await?;
                    let data = bytes::Bytes::from_static(b"left open");
                    ringline::fs::write_from(file, 0, data).await.0?;
                    Ok::<_, std::io::Error>(())
                }
                .await
                .map_err(|e| e.to_string());
                finish(outcome);
            }))
        }
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            async {}
        }
        fn create_for_worker(_id: usize) -> Self {
            LeavesFileOpen
        }
    }

    #[test]
    fn a_file_left_open_closes_when_its_worker_exits() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        run::<LeavesFileOpen>(config(4, 2)).unwrap();
        let path = LEFT_OPEN.lock().unwrap().take().expect("path");
        assert_eq!(fds_on(&path), 0, "the file outlived its worker");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    // ── A close while a write is queued: the write lands in its file (mio) ──

    static RACE_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

    struct CloseWithQueuedWrite;

    impl AsyncEventHandler for CloseWithQueuedWrite {
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async {
                finish(close_with_queued_write().await);
            }))
        }
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            async {}
        }
        fn create_for_worker(_id: usize) -> Self {
            CloseWithQueuedWrite
        }
    }

    static DATA: &[u8] = b"belongs to a";

    async fn close_with_queued_write() -> Result<(), String> {
        let dir = temp_dir("queued-write");
        *RACE_DIR.lock().unwrap() = Some(dir.clone());
        let fifo = dir.join("fifo");
        mkfifo(&fifo);

        let a = ringline::fs::create(dir.join("a"))
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;

        // Park the pool's only thread in an open that waits for a writer, so the
        // write below queues behind it.
        let blocker = ringline::fs::open(&fifo, OpenFlags::READ, 0).map_err(|e| e.to_string())?;
        let write = ringline::fs::write_from(a, 0, bytes::Bytes::from_static(DATA));
        ringline::fs::close(a).map_err(|e| e.to_string())?;

        // A new file takes the lowest free fd number, which is `a`'s if the close
        // released it.
        let c = std::fs::File::create(dir.join("c")).map_err(|e| e.to_string())?;

        release_fifo_readers(fifo.clone());
        let fifo_file = blocker.await.map_err(|e| e.to_string())?;
        ringline::fs::close(fifo_file).map_err(|e| e.to_string())?;
        write.await.0.map_err(|e| e.to_string())?;
        drop(c);
        Ok(())
    }

    #[test]
    fn a_queued_write_lands_in_its_file_after_close() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        run::<CloseWithQueuedWrite>(config(4, 1)).unwrap();
        let dir = RACE_DIR.lock().unwrap().take().expect("dir");
        let a = std::fs::read(dir.join("a")).expect("read a");
        let c = std::fs::read(dir.join("c")).expect("read c");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            c, b"",
            "the write landed in the file that reused a's fd number"
        );
        assert_eq!(a, DATA, "the write did not reach a");
    }

    // ── A connection task dropped while its open waits ──────────────────

    static TEARDOWN_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
    static OPEN_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static OPEN_RESOLVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static PROBE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    struct OpenInConnection;

    impl AsyncEventHandler for OpenInConnection {
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async {
                use std::sync::atomic::Ordering;
                while !PROBE.load(Ordering::SeqCst) {
                    ringline::sleep(Duration::from_millis(10)).await;
                }
                let dir = TEARDOWN_DIR.lock().unwrap().clone().unwrap();
                let regular = dir.join("regular");
                // The table's only slot comes back once the abandoned open's
                // completion has been handled.
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let outcome = loop {
                    match ringline::fs::open(&regular, OpenFlags::READ, 0) {
                        Ok(open) => match open.await {
                            Ok(file) => break ringline::fs::close(file).map_err(|e| e.to_string()),
                            Err(e) => break Err(e.to_string()),
                        },
                        Err(e) if std::time::Instant::now() >= deadline => {
                            break Err(format!("the abandoned open's slot was not freed: {e}"));
                        }
                        Err(_) => ringline::sleep(Duration::from_millis(10)).await,
                    }
                };
                finish(outcome);
            }))
        }

        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            use std::sync::atomic::Ordering;
            let (mut tx, _rx) = conn.split();
            async move {
                // Close this connection while the open below is waiting, which
                // drops this task, and the open's future with it, outside any
                // task poll.
                ringline::spawn(async move {
                    ringline::sleep(Duration::from_millis(100)).await;
                    tx.close();
                })
                .unwrap();
                let fifo = TEARDOWN_DIR.lock().unwrap().clone().unwrap().join("fifo");
                OPEN_STARTED.store(true, Ordering::SeqCst);
                let _ = ringline::fs::open(&fifo, OpenFlags::READ, 0).unwrap().await;
                OPEN_RESOLVED.store(true, Ordering::SeqCst);
            }
        }

        fn create_for_worker(_id: usize) -> Self {
            OpenInConnection
        }
    }

    #[test]
    fn an_open_dropped_with_its_connection_closes() {
        use std::sync::atomic::Ordering;
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        *OUTCOME.lock().unwrap() = None;
        let dir = temp_dir("teardown");
        std::fs::write(dir.join("regular"), b"x").unwrap();
        let fifo = dir.join("fifo");
        mkfifo(&fifo);
        *TEARDOWN_DIR.lock().unwrap() = Some(dir.clone());

        let (runtime, handles) = RinglineBuilder::new(config(1, 2))
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<OpenInConnection>()
            .expect("launch");
        let _client = std::net::TcpStream::connect(runtime.bound_addr().unwrap()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !OPEN_STARTED.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        // Let the connection close and its task go.
        std::thread::sleep(Duration::from_millis(400));

        // Complete the open, which no future is waiting for any more.
        let writer = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(writer);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while fds_on(&fifo) != 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let fifo_fds = fds_on(&fifo);

        PROBE.store(true, Ordering::SeqCst);
        common::join_workers(&runtime, handles);
        drop(runtime);
        let outcome = OUTCOME.lock().unwrap().take();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !OPEN_RESOLVED.load(Ordering::SeqCst),
            "the connection's task was not dropped before its open completed"
        );
        assert_eq!(fifo_fds, 0, "the abandoned open left the FIFO open");
        assert_eq!(outcome, Some(Ok(())));
    }
}
