#![allow(clippy::manual_async_fn)]
//! `max_commands_in_flight` bounds fs operations on both backends: with a
//! bound of 4, a fifth operation submitted in the same poll fails, and one
//! submitted after the four complete succeeds (#864). Reads and fsyncs are
//! both checked.

mod common;

use std::future::Future;
use std::path::PathBuf;
use std::sync::OnceLock;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder, fs::FsConfig};

static RESULT: OnceLock<Result<(), String>> = OnceLock::new();

const BOUND: u16 = 4;

/// A file in the working directory, so that it is not under the temp dir.
fn file_path(name: &str) -> PathBuf {
    std::env::current_dir()
        .unwrap()
        .join(format!(".krio_in_flight_{name}_{}", std::process::id()))
}

async fn fs_reads_past_the_bound(path: &std::path::Path) -> Result<(), String> {
    let file = ringline::fs::open(path, ringline::fs::OpenFlags::READ, 0)
        .map_err(|e| format!("open submit: {e}"))?
        .await
        .map_err(|e| format!("open: {e}"))?;
    let mut reads = Vec::new();
    for _ in 0..BOUND {
        let read = ringline::fs::read_into(file, 0, bytes::BytesMut::with_capacity(64));
        reads.push(read);
    }
    // Refused at submission: the future resolves at once with the error and
    // the buffer.
    let mut extra = bytes::BytesMut::with_capacity(64);
    extra.extend_from_slice(b"kept");
    match ringline::fs::read_into(file, 0, extra).await {
        (Ok(_), _) => return Err("fs read past the bound was accepted".to_string()),
        (Err(e), buf)
            if e.kind() == std::io::ErrorKind::WouldBlock
                && e.to_string() == "filesystem command slab exhausted" =>
        {
            if &buf[..] != b"kept" {
                return Err(format!("the refused read's buffer came back as {buf:?}"));
            }
        }
        (Err(e), _) => return Err(format!("fs read past the bound: unexpected error: {e}")),
    }
    for read in reads {
        read.await.0.map_err(|e| format!("fs read: {e}"))?;
    }
    let (n, _) = ringline::fs::read_into(file, 0, bytes::BytesMut::with_capacity(64)).await;
    n.map_err(|e| format!("fs read after the four completed: {e}"))?;
    ringline::fs::close(file).map_err(|e| format!("fs close: {e}"))
}

async fn fs_fsyncs_past_the_bound(path: &std::path::Path) -> Result<(), String> {
    let file = ringline::fs::open(path, ringline::fs::OpenFlags::READ, 0)
        .map_err(|e| format!("open submit: {e}"))?
        .await
        .map_err(|e| format!("open: {e}"))?;
    let mut fsyncs = Vec::new();
    for i in 0..BOUND {
        let fsync = ringline::fs::fsync(file)
            .map_err(|e| format!("fsync {i} refused under the bound: {e}"))?;
        fsyncs.push(fsync);
    }
    match ringline::fs::fsync(file) {
        Ok(_) => return Err("fsync past the bound was accepted".to_string()),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                && e.to_string() == "filesystem command slab exhausted" => {}
        Err(e) => return Err(format!("fsync past the bound: unexpected error: {e}")),
    }
    for fsync in fsyncs {
        fsync.await.map_err(|e| format!("fsync: {e}"))?;
    }
    ringline::fs::fsync(file)
        .map_err(|e| format!("fsync after the four completed: {e}"))?
        .await
        .map_err(|e| format!("fsync after the four completed: {e}"))?;
    ringline::fs::close(file).map_err(|e| format!("close: {e}"))
}

struct Handler;

impl AsyncEventHandler for Handler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = file_path("fs");
            let mut result = fs_reads_past_the_bound(&path).await;
            if result.is_ok() {
                result = fs_fsyncs_past_the_bound(&path).await;
            }
            let _ = RESULT.set(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        Handler
    }
}

#[test]
fn operations_past_max_commands_in_flight_are_refused() {
    let fs_path = file_path("fs");
    std::fs::write(&fs_path, [7u8; 64]).unwrap();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .fs(FsConfig::default()
            .max_files(4)
            .max_commands_in_flight(BOUND))
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Handler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&fs_path);
    RESULT.get().expect("the task finished").clone().unwrap();
}

static NO_FS_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

/// With fs off, an fs operation fails as it does on io_uring: fs is not
/// configured, and on mio no disk-I/O pool runs.
struct NoFsHandler;

impl AsyncEventHandler for NoFsHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let result = match ringline::fs::stat(std::env::current_dir().unwrap()) {
                Ok(_) => Err("fs::stat was accepted with fs off".to_string()),
                Err(e) if e.to_string() == "filesystem I/O not configured" => Ok(()),
                Err(e) => Err(format!("fs::stat with fs off: unexpected error: {e}")),
            };
            let _ = NO_FS_RESULT.set(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        NoFsHandler
    }
}

#[test]
fn an_fs_operation_with_fs_off_reports_it_is_not_configured() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .no_fs()
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<NoFsHandler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    NO_FS_RESULT
        .get()
        .expect("the task finished")
        .clone()
        .unwrap();
}
