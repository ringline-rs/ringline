#![allow(clippy::manual_async_fn)]
//! An fs handle kept across 65,536 opens and closes of its slot stays stale:
//! closing it fails and leaves the slot's new file open (#862).

mod common;

use std::future::Future;
use std::path::PathBuf;
use std::sync::OnceLock;

use ringline::fs::{File, FsConfig, OpenFlags};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

static RESULT: OnceLock<Result<(), String>> = OnceLock::new();

/// A file in the working directory, so that it is not under the temp dir.
fn file_path() -> PathBuf {
    std::env::current_dir()
        .unwrap()
        .join(format!(".krio_handle_generation_{}", std::process::id()))
}

/// Open `path`. With one slot, the previous file's slot is free once its
/// close has completed (on io_uring, an `IORING_OP_CLOSE`), so an open that
/// finds the table full yields to let the close complete and tries again.
async fn open(path: &str, what: &str) -> Result<File, String> {
    for _ in 0..1000 {
        match ringline::fs::open(path, OpenFlags::READ, 0) {
            Ok(open) => return open.await.map_err(|e| format!("{what}: {e}")),
            Err(e) if e.to_string() == "filesystem file table full" => {
                ringline::yield_now().await;
            }
            Err(e) => return Err(format!("{what}: {e}")),
        }
    }
    Err(format!("{what}: the slot was not freed after 1000 yields"))
}

async fn stale_after_wrap(path: &str) -> Result<(), String> {
    let first = open(path, "first open").await?;
    ringline::fs::close(first).map_err(|e| format!("first close: {e}"))?;
    for cycle in 1..65_536 {
        let file = open(path, "open")
            .await
            .map_err(|e| format!("cycle {cycle}: {e}"))?;
        ringline::fs::close(file).map_err(|e| format!("cycle {cycle}: close: {e}"))?;
    }
    let current = open(path, "last open").await?;
    if current.index() != first.index() {
        return Err("the last open did not reuse the first slot".to_string());
    }
    if ringline::fs::close(first).is_ok() {
        return Err("the stale handle closed the slot's new file".to_string());
    }
    ringline::fs::close(current).map_err(|e| format!("last close: {e}"))
}

struct Handler;

impl AsyncEventHandler for Handler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = file_path();
            let result = stale_after_wrap(path.to_str().unwrap()).await;
            let _ = RESULT.set(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        Handler
    }
}

#[test]
fn a_stale_fs_handle_stays_stale_after_65536_reuses() {
    let path = file_path();
    std::fs::write(&path, [0u8; 4096]).unwrap();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .fs(FsConfig::default().max_files(1).max_commands_in_flight(8))
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Handler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&path);
    RESULT.get().expect("the task finished").clone().unwrap();
}
