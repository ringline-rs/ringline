#![allow(clippy::manual_async_fn)]
//! `max_commands_in_flight` bounds fs and direct I/O operations on both
//! backends: with a bound of 4, a fifth operation submitted in the same poll
//! fails, and one submitted after the four complete succeeds (#864).

mod common;

use std::future::Future;
use std::path::PathBuf;
use std::sync::OnceLock;

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, DirectIoConfig, RinglineBuilder, fs::FsConfig,
};

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
    for i in 0..BOUND {
        let read = ringline::fs::read_into(file, 0, bytes::BytesMut::with_capacity(64))
            .map_err(|e| format!("fs read {i} refused under the bound: {e}"))?;
        reads.push(read);
    }
    match ringline::fs::read_into(file, 0, bytes::BytesMut::with_capacity(64)) {
        Ok(_) => return Err("fs read past the bound was accepted".to_string()),
        Err(e) if e.to_string() == "filesystem command slab exhausted" => {}
        Err(e) => return Err(format!("fs read past the bound: unexpected error: {e}")),
    }
    for read in reads {
        read.await.0.map_err(|e| format!("fs read: {e}"))?;
    }
    let (n, _) = ringline::fs::read_into(file, 0, bytes::BytesMut::with_capacity(64))
        .map_err(|e| format!("fs read after the four completed: {e}"))?
        .await;
    n.map_err(|e| format!("fs read after the four completed: {e}"))?;
    ringline::fs::close(file).map_err(|e| format!("fs close: {e}"))
}

async fn direct_io_fsyncs_past_the_bound(path: &str) -> Result<(), String> {
    let file = ringline::open_direct_io_file(path).map_err(|e| format!("direct open: {e}"))?;
    let mut fsyncs = Vec::new();
    for i in 0..BOUND {
        let fsync = ringline::direct_io_fsync(file)
            .map_err(|e| format!("direct fsync {i} refused under the bound: {e}"))?;
        fsyncs.push(fsync);
    }
    match ringline::direct_io_fsync(file) {
        Ok(_) => return Err("direct fsync past the bound was accepted".to_string()),
        Err(e) if e.to_string() == "direct I/O command slab exhausted" => {}
        Err(e) => {
            return Err(format!(
                "direct fsync past the bound: unexpected error: {e}"
            ));
        }
    }
    for fsync in fsyncs {
        fsync.await.map_err(|e| format!("direct fsync: {e}"))?;
    }
    ringline::direct_io_fsync(file)
        .map_err(|e| format!("direct fsync after the four completed: {e}"))?
        .await
        .map_err(|e| format!("direct fsync after the four completed: {e}"))?;
    ringline::close_direct_io_file(file).map_err(|e| format!("direct close: {e}"))
}

struct Handler;

impl AsyncEventHandler for Handler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let fs_path = file_path("fs");
            let direct_path = file_path("direct");
            let mut result = fs_reads_past_the_bound(&fs_path).await;
            if result.is_ok() {
                result = direct_io_fsyncs_past_the_bound(direct_path.to_str().unwrap()).await;
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
    let direct_path = file_path("direct");
    std::fs::write(&fs_path, [7u8; 64]).unwrap();
    std::fs::write(&direct_path, [0u8; 4096]).unwrap();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .fs(FsConfig::default()
            .max_files(4)
            .max_commands_in_flight(BOUND))
        .direct_io(
            DirectIoConfig::default()
                .max_files(2)
                .max_commands_in_flight(BOUND),
        )
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Handler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&fs_path);
    let _ = std::fs::remove_file(&direct_path);
    let result = RESULT.get().expect("the task finished").clone();
    if let Err(e) = &result
        && e.starts_with("direct open")
        && e.contains("Invalid argument")
    {
        eprintln!("skipping the direct I/O half: O_DIRECT is not supported here ({e})");
        return;
    }
    result.unwrap();
}

/// One result per test: `cargo test` runs both in one process.
static NO_FS_RESULT: [OnceLock<Result<(), String>>; 2] = [OnceLock::new(), OnceLock::new()];

/// With fs off, an fs operation fails as it does on io_uring: fs is not
/// configured. With direct I/O on, mio still starts a disk-I/O pool; with it
/// off, there is none.
struct NoFsHandler<const N: usize>;

impl<const N: usize> AsyncEventHandler for NoFsHandler<N> {
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
            let _ = NO_FS_RESULT[N].set(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        NoFsHandler
    }
}

fn run_no_fs<const N: usize>(builder: ConfigBuilder) {
    let config = builder
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .no_fs()
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<NoFsHandler<N>>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    NO_FS_RESULT[N]
        .get()
        .expect("the task finished")
        .clone()
        .unwrap();
}

#[test]
fn an_fs_operation_with_fs_off_and_direct_io_on_reports_it_is_not_configured() {
    run_no_fs::<0>(ConfigBuilder::new().direct_io(DirectIoConfig::default()));
}

#[test]
fn an_fs_operation_with_fs_and_direct_io_off_reports_it_is_not_configured() {
    run_no_fs::<1>(ConfigBuilder::new());
}
