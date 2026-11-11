#![allow(clippy::manual_async_fn)]
//! A direct I/O handle kept across 65,536 opens and closes of its slot stays
//! stale: closing it fails and leaves the slot's new file open (#862).

mod common;

use std::future::Future;
use std::path::PathBuf;
use std::sync::OnceLock;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, DirectIoConfig, RinglineBuilder};

static RESULT: OnceLock<Result<(), String>> = OnceLock::new();

/// A file in the working directory, so that it is not under the temp dir.
fn file_path() -> PathBuf {
    std::env::current_dir()
        .unwrap()
        .join(format!(".krio_handle_generation_{}", std::process::id()))
}

async fn stale_after_wrap(path: &str) -> Result<(), String> {
    let first = ringline::open_direct_io_file(path).map_err(|e| format!("first open: {e}"))?;
    ringline::close_direct_io_file(first).map_err(|e| format!("first close: {e}"))?;
    for cycle in 1..65_536 {
        let file =
            ringline::open_direct_io_file(path).map_err(|e| format!("cycle {cycle}: open: {e}"))?;
        ringline::close_direct_io_file(file).map_err(|e| format!("cycle {cycle}: close: {e}"))?;
    }
    let current = ringline::open_direct_io_file(path).map_err(|e| format!("last open: {e}"))?;
    if current.index() != first.index() {
        return Err("the last open did not reuse the first slot".to_string());
    }
    if ringline::close_direct_io_file(first).is_ok() {
        return Err("the stale handle closed the slot's new file".to_string());
    }
    ringline::close_direct_io_file(current).map_err(|e| format!("last close: {e}"))
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
fn a_stale_direct_io_handle_stays_stale_after_65536_reuses() {
    let path = file_path();
    std::fs::write(&path, [0u8; 4096]).unwrap();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .direct_io(
            DirectIoConfig::default()
                .max_files(1)
                .max_commands_in_flight(8),
        )
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Handler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&path);
    let result = RESULT.get().expect("the task finished").clone();
    if let Err(e) = &result
        && e.starts_with("first open")
        && e.contains("Invalid argument")
    {
        eprintln!("skipping: O_DIRECT is not supported here ({e})");
        return;
    }
    result.unwrap();
}
