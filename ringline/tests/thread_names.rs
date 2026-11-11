//! Every thread a runtime starts has the name the docs give it, and Linux
//! reports the whole name. Linux keeps 15 bytes of a thread name.
//!
//! Other tests find a pool's threads by these names and wait for them to
//! exit, and a wrong name would pass those waits without a thread to wait
//! for. This test fails instead.
//!
//! This is its own test binary because it lists every thread in the process,
//! and runtimes started by any other test would be listed too.
//!
//! Linux only: it reads `/proc/self/task`.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {}
    }

    fn create_for_worker(_worker_id: usize) -> Self {
        Idle
    }
}

/// The sorted names of this process's threads that start with `rl-`. A
/// duplicate name appears twice.
fn rl_threads() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
        .map(|name| name.trim_end().to_string())
        .filter(|name| name.starts_with("rl-"))
        .collect();
    names.sort();
    names
}

#[test]
fn every_thread_has_its_documented_name() {
    let config = ConfigBuilder::new()
        .workers(2)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .resolver_threads(2)
        .spawner_threads(1)
        .blocking_threads(2)
        .disk_io_threads(2)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Idle>()
        .expect("launch");

    // Only the mio backend runs fs on a disk-I/O pool, one per worker.
    let disk: &[&str] = if cfg!(has_io_uring) {
        &[]
    } else {
        &["rl-disk-0-0", "rl-disk-0-1", "rl-disk-1-0", "rl-disk-1-1"]
    };
    let mut expected: Vec<String> = [
        "rl-work-0",
        "rl-work-1",
        "rl-acpt-0",
        "rl-rslv-0",
        "rl-rslv-1",
        "rl-spwn-0",
        "rl-blok-0",
        "rl-blok-1",
    ]
    .iter()
    .chain(disk)
    .map(|name| name.to_string())
    .collect();
    expected.sort();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut names = rl_threads();
    while names != expected && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
        names = rl_threads();
    }

    runtime.shutdown();
    common::join_workers(&runtime, handles);
    assert_eq!(names, expected, "the runtime's rl- threads");
}
