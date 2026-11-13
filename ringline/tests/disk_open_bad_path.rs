#![allow(clippy::manual_async_fn)]
//! An open that fails on a path with an interior NUL leaves the file table as
//! it was: with two slots, three failed opens are followed by two that succeed.

mod common;

use std::future::Future;
use std::path::PathBuf;
use std::sync::OnceLock;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, DirectIoConfig, RinglineBuilder};

static DIRECT_IO_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

/// A file in the working directory, so that it is not under the temp dir.
fn file_path(name: &str) -> PathBuf {
    std::env::current_dir()
        .unwrap()
        .join(format!(".krio_{name}_{}", std::process::id()))
}

fn config_builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
}

async fn direct_io_bad_paths(path: &str) -> Result<(), String> {
    for round in 0..3 {
        match ringline::open_direct_io_file("a\0b") {
            Ok(_) => return Err(format!("round {round}: a NUL path opened")),
            Err(e) if e.to_string() == "invalid file path" => {}
            Err(e) => return Err(format!("round {round}: unexpected error: {e}")),
        }
    }
    let a = ringline::open_direct_io_file(path).map_err(|e| format!("first open: {e}"))?;
    let b = ringline::open_direct_io_file(path).map_err(|e| format!("second open: {e}"))?;
    ringline::close_direct_io_file(a).map_err(|e| format!("close a: {e}"))?;
    ringline::close_direct_io_file(b).map_err(|e| format!("close b: {e}"))?;
    Ok(())
}

struct DirectIoHandler;

impl AsyncEventHandler for DirectIoHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = file_path("bad_path_direct_io");
            let result = direct_io_bad_paths(path.to_str().unwrap()).await;
            let _ = DIRECT_IO_RESULT.set(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        DirectIoHandler
    }
}

#[test]
fn a_nul_path_does_not_leak_a_direct_io_slot() {
    let path = file_path("bad_path_direct_io");
    std::fs::write(&path, [0u8; 4096]).unwrap();
    let config = config_builder()
        .direct_io(
            DirectIoConfig::default()
                .max_files(2)
                .max_commands_in_flight(8),
        )
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<DirectIoHandler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&path);
    let result = DIRECT_IO_RESULT.get().expect("the task finished").clone();
    if let Err(e) = &result
        && e.contains("Invalid argument")
    {
        eprintln!("skipping: O_DIRECT is not supported here ({e})");
        return;
    }
    result.unwrap();
}

#[cfg(has_io_uring)]
static NVME_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

/// A regular file stands in for a device: opening registers the fd and does
/// not check what it is.
#[cfg(has_io_uring)]
async fn nvme_bad_paths(path: &str) -> Result<(), String> {
    for round in 0..3 {
        match ringline::open_nvme_device("a\0b", 1) {
            Ok(_) => return Err(format!("round {round}: a NUL path opened")),
            Err(e) if e.to_string() == "invalid device path" => {}
            Err(e) => return Err(format!("round {round}: unexpected error: {e}")),
        }
    }
    let a = ringline::open_nvme_device(path, 1).map_err(|e| format!("first open: {e}"))?;
    let b = ringline::open_nvme_device(path, 1).map_err(|e| format!("second open: {e}"))?;
    ringline::close_nvme_device(a).map_err(|e| format!("close a: {e}"))?;
    ringline::close_nvme_device(b).map_err(|e| format!("close b: {e}"))?;
    Ok(())
}

#[cfg(has_io_uring)]
struct NvmeHandler;

#[cfg(has_io_uring)]
impl AsyncEventHandler for NvmeHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = file_path("bad_path_nvme");
            let result = nvme_bad_paths(path.to_str().unwrap()).await;
            let _ = NVME_RESULT.set(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        NvmeHandler
    }
}

#[cfg(has_io_uring)]
#[test]
fn a_nul_path_does_not_leak_an_nvme_slot() {
    let path = file_path("bad_path_nvme");
    std::fs::write(&path, [0u8; 4096]).unwrap();
    let config = config_builder()
        .nvme(ringline::NvmeConfig::default().max_devices(2))
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<NvmeHandler>()
        .expect("launch failed");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&path);
    NVME_RESULT
        .get()
        .expect("the task finished")
        .clone()
        .unwrap();
}
