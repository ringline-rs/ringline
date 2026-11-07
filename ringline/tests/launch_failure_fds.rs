//! A `launch()` that fails in merged accept mode closes the sockets it bound.
//!
//! Merged mode binds every listener's `SO_REUSEPORT` sockets before the
//! workers start. A task panic under `TaskPanicPolicy::Shutdown` during the
//! listener setup fails the launch; the sockets of listeners not yet set up
//! must be closed, not leaked.
//!
//! Its own test binary, because it counts the process's open fds. io_uring
//! only: merged accept mode is.

#![cfg(all(target_os = "linux", has_io_uring, feature = "unstable-accept"))]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::pin::Pin;

use ringline::{
    AcceptMode, AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder, TaskPanicPolicy,
};

struct OnStartCallPanics;

impl AsyncEventHandler for OnStartCallPanics {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        panic!("boom in on_start call")
    }

    fn create_for_worker(_id: usize) -> Self {
        OnStartCallPanics
    }
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .count()
}

/// Launches that fail on a task panic do not accumulate fds.
#[test]
fn failed_merged_launches_do_not_leak_sockets() {
    let launch = || {
        let config = ConfigBuilder::new()
            .workers(2)
            .pin_to_core(false)
            .sq_entries(64)
            .max_connections(16)
            .send_pool(16, 16384)
            .blocking_threads(0)
            .resolver_threads(0)
            .spawner_threads(0)
            .accept_mode(AcceptMode::Merged)
            .task_panic_policy(TaskPanicPolicy::Shutdown)
            .build()
            .expect("valid config");
        let launched = RinglineBuilder::new(config)
            .bind("127.0.0.1:0".parse().unwrap())
            .bind("127.0.0.1:0".parse().unwrap())
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<OnStartCallPanics>();
        if let Ok((runtime, handles)) = launched {
            drop(runtime);
            for h in handles {
                let _ = h.join();
            }
        }
    };
    // Warm up anything the first launch allocates for the process.
    launch();
    let before = open_fd_count();
    for _ in 0..30 {
        launch();
    }
    let after = open_fd_count();
    assert!(
        after <= before + 2,
        "fds grew from {before} to {after} over 30 failed launches"
    );
}
