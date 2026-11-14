#![allow(clippy::manual_async_fn)]
//! The owned-buffer disk API over `buf::IoBuf` and `buf::IoBufMut` (#825):
//! every buffer type ringline implements the traits for round-trips through
//! `fs::write_from` and `fs::read_into`, and a buffer type of the caller's own
//! is kept after its future is dropped until the read completes, then dropped.

mod common;

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use ringline::buf::{AlignedBuf, IoBuf, IoBufMut};
use ringline::fs::OpenFlags;
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

static SERIAL: Mutex<()> = Mutex::new(());
static DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static OUTCOME: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// Run `H` on one worker with a fresh directory, which `prepare` fills
/// first, and return what its task recorded.
fn run<H: AsyncEventHandler>(
    name: &str,
    prepare: impl FnOnce(&std::path::Path),
) -> Result<(), String> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("ringline-owned-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    prepare(&dir);
    *DIR.lock().unwrap() = Some(dir.clone());
    *OUTCOME.lock().unwrap() = None;
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .send_pool(16, 4096)
        .resolver_threads(0)
        .disk_io_threads(1)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config).launch::<H>().expect("launch");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_dir_all(&dir);
    OUTCOME
        .lock()
        .unwrap()
        .take()
        .expect("the task did not finish")
}

fn finish(outcome: Result<(), String>) {
    *OUTCOME.lock().unwrap() = Some(outcome);
    ringline::request_shutdown().ok();
}

fn dir() -> PathBuf {
    DIR.lock().unwrap().clone().unwrap()
}

// ── Every buffer type round-trips ───────────────────────────────────

struct RoundTrip;

impl AsyncEventHandler for RoundTrip {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async { finish(round_trip().await) }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        RoundTrip
    }
}

async fn write_at<B: IoBuf>(file: ringline::fs::File, offset: u64, buf: B) -> Result<B, String> {
    let len = buf.bytes_init();
    let (n, buf) = ringline::fs::write_from(file, offset, buf).await;
    match n {
        Ok(n) if n == len => Ok(buf),
        other => Err(format!("write at {offset}: {other:?}")),
    }
}

async fn read_all<B: IoBufMut>(file: ringline::fs::File, buf: B) -> Result<B, String> {
    let (n, buf) = ringline::fs::read_into(file, 0, buf).await;
    n.map_err(|e| format!("read: {e}"))?;
    Ok(buf)
}

async fn round_trip() -> Result<(), String> {
    let path = dir().join("file");
    let file = ringline::fs::open(&path, OpenFlags::READ_WRITE | OpenFlags::CREATE, 0o600)
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;

    let kept = Bytes::from_static(b"abcd");
    let returned = write_at(file, 0, kept.clone()).await?;
    if returned != kept {
        return Err("the Bytes came back changed".into());
    }
    write_at(file, 4, b"efgh".to_vec()).await?;
    write_at(file, 8, BytesMut::from(&b"ijkl"[..])).await?;
    let mut aligned = AlignedBuf::with_capacity(4, 512);
    aligned.extend_from_slice(b"mnop");
    write_at(file, 12, aligned).await?;
    let mut frozen = AlignedBuf::with_capacity(4, 512);
    frozen.extend_from_slice(b"qrst");
    write_at(file, 16, frozen.freeze()).await?;
    const ALL: &[u8] = b"abcdefghijklmnopqrst";

    let vec = read_all(file, Vec::with_capacity(ALL.len())).await?;
    if vec != ALL {
        return Err(format!("Vec read {vec:?}"));
    }
    let bytes = read_all(file, BytesMut::with_capacity(ALL.len())).await?;
    if bytes[..] != *ALL {
        return Err(format!("BytesMut read {bytes:?}"));
    }
    // A read appends after the initialized bytes.
    let mut aligned = AlignedBuf::with_capacity(64, 4096);
    aligned.extend_from_slice(b"__");
    let aligned = read_all(file, aligned).await?;
    if aligned[..2] != *b"__" || aligned[2..] != *ALL {
        return Err(format!("AlignedBuf read {:?}", &aligned[..]));
    }
    if !(aligned.stable_ptr() as usize).is_multiple_of(4096) {
        return Err("the AlignedBuf came back unaligned".into());
    }

    // A buffer with no spare capacity is refused before anything is
    // submitted.
    let full = AlignedBuf::zeroed(8, 8);
    match ringline::fs::read_into(file, 0, full).await {
        (Err(e), buf) if e.kind() == std::io::ErrorKind::InvalidInput => {
            if buf.len() != 8 {
                return Err("the refused buffer came back changed".into());
            }
        }
        (Err(e), _) => return Err(format!("full buffer: {e}")),
        (Ok(_), _) => return Err("a full buffer was accepted".into()),
    }
    ringline::fs::close(file).map_err(|e| e.to_string())
}

#[test]
fn every_buffer_type_round_trips() {
    run::<RoundTrip>("round-trip", |_| {}).unwrap();
}

// ── A caller's buffer type outlives its dropped read ────────────────

static TRACKED_DROPPED: AtomicBool = AtomicBool::new(false);

/// A buffer of the caller's own type, which records its drop.
struct Tracked(Vec<u8>);

impl Drop for Tracked {
    fn drop(&mut self) {
        TRACKED_DROPPED.store(true, Ordering::SeqCst);
    }
}

// Safety: delegates to the `Vec`, whose heap memory does not move with the
// value.
unsafe impl IoBuf for Tracked {
    fn stable_ptr(&self) -> *const u8 {
        self.0.stable_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.0.bytes_init()
    }
}

// Safety: as above.
unsafe impl IoBufMut for Tracked {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.0.stable_mut_ptr()
    }
    fn bytes_total(&self) -> usize {
        self.0.bytes_total()
    }
    unsafe fn set_init(&mut self, pos: usize) {
        unsafe { self.0.set_init(pos) }
    }
}

struct DroppedRead;

impl AsyncEventHandler for DroppedRead {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async { finish(dropped_read().await) }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        DroppedRead
    }
}

/// Whether the buffer was dropped while its read was in flight.
fn dropped_early() -> Result<(), String> {
    if TRACKED_DROPPED.load(Ordering::SeqCst) {
        return Err("the buffer was dropped while its read was in flight".into());
    }
    Ok(())
}

/// Wait up to 5 s for the buffer's drop.
async fn wait_for_drop() -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !TRACKED_DROPPED.load(Ordering::SeqCst) {
        if Instant::now() > deadline {
            return Err("the buffer was not dropped after its read completed".into());
        }
        ringline::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

/// io_uring: a read of an empty FIFO waits in the kernel. The FIFO is opened
/// read-write, so the open does not wait for a writer.
#[cfg(has_io_uring)]
async fn dropped_read() -> Result<(), String> {
    let fifo_path = dir().join("fifo");
    let fifo = ringline::fs::open(&fifo_path, OpenFlags::READ_WRITE, 0)
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    TRACKED_DROPPED.store(false, Ordering::SeqCst);
    let read = ringline::fs::read_into(fifo, 0, Tracked(Vec::with_capacity(64)));
    ringline::sleep(Duration::from_millis(20)).await;
    drop(read);
    dropped_early()?;
    // End the read if the drop's cancel has not: the FIFO has a reader, so
    // this write does not block.
    {
        use std::io::Write;
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .map_err(|e| e.to_string())?;
        writer.write_all(b"done").map_err(|e| e.to_string())?;
    }
    wait_for_drop().await?;
    ringline::fs::close(fifo).map_err(|e| e.to_string())
}

/// mio: `pread` of a FIFO fails at once, so the read is of a regular file,
/// queued behind an open of the FIFO that holds the pool's one thread until a
/// writer opens the FIFO.
#[cfg(not(has_io_uring))]
async fn dropped_read() -> Result<(), String> {
    let dir = dir();
    let fifo_path = dir.join("fifo");
    let file = ringline::fs::open(dir.join("file"), OpenFlags::READ, 0)
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    let blocker = ringline::fs::open(&fifo_path, OpenFlags::READ, 0).map_err(|e| e.to_string())?;
    TRACKED_DROPPED.store(false, Ordering::SeqCst);
    let read = ringline::fs::read_into(file, 0, Tracked(Vec::with_capacity(64)));
    ringline::sleep(Duration::from_millis(20)).await;
    drop(read);
    dropped_early()?;
    // A writer's open completes the blocker's open, and the pool then runs
    // the read.
    let writer =
        std::thread::spawn(move || std::fs::OpenOptions::new().write(true).open(fifo_path));
    let fifo = blocker.await.map_err(|e| e.to_string())?;
    let writer = writer.join().unwrap().map_err(|e| e.to_string())?;
    wait_for_drop().await?;
    drop(writer);
    ringline::fs::close(fifo).map_err(|e| e.to_string())?;
    ringline::fs::close(file).map_err(|e| e.to_string())
}

#[test]
fn a_dropped_read_keeps_its_buffer_until_the_read_completes() {
    run::<DroppedRead>("dropped-read", |dir| {
        let fifo = std::ffi::CString::new(dir.join("fifo").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0, "mkfifo");
        std::fs::write(dir.join("file"), b"data").unwrap();
    })
    .unwrap();
}
