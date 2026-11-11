//! A `launch()` that fails after a deferred listener's acceptor has started
//! must release that acceptor.
//!
//! This is its own test binary because it counts the process's threads whose
//! name starts with `rl-acpt-`, and acceptors started by any other test
//! in the same process would be counted too.
//!
//! It fails the second bind, so it covers the bind-failure rollback. The
//! register and acceptor-spawn failure paths shut the runtime down the same
//! way and have no test of their own.
//!
//! Linux only: it reads `/proc/self/task`.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::net::TcpListener;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, Config, ConfigBuilder, Connection, RinglineBuilder};

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
        .expect("valid config")
}

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {}
    }

    fn create_for_worker(_worker_id: usize) -> Self {
        Idle
    }
}

/// The number of live acceptor threads in this process.
fn acceptor_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
        .filter(|name| name.trim_end().starts_with("rl-acpt-"))
        .count()
}

/// The first listener is deferred, so its acceptor parks on the gate. The
/// second bind fails, and the rollback must shut the gates as well as shut
/// the listeners down and join the workers.
#[test]
fn a_failed_launch_releases_a_parked_acceptor() {
    let taken = TcpListener::bind("127.0.0.1:0").expect("bind");
    let taken_addr = taken.local_addr().expect("local_addr");

    let result = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .defer_listen()
        .bind(taken_addr)
        .launch::<Idle>();
    assert!(result.is_err(), "the second bind must fail");

    let deadline = Instant::now() + Duration::from_secs(5);
    while acceptor_threads() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        acceptor_threads(),
        0,
        "an acceptor thread outlived the failed launch"
    );
    drop(taken);
}
