//! Repeated launch and shutdown of a runtime with a UDP socket closes every fd
//! each launch opened.
//!
//! Its own test binary, because it counts the process's open fds and waits
//! for the threads launched since the test started to exit, which other tests
//! in the same process would disturb. Linux only.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder, UdpSocket};

static STARTED: AtomicBool = AtomicBool::new(false);

/// Receives on its UDP socket until the runtime shuts down.
struct UdpRecv;

impl AsyncEventHandler for UdpRecv {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_udp_bind(
        &self,
        mut udp: UdpSocket,
    ) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async move {
            STARTED.store(true, Ordering::Release);
            loop {
                let _ = udp.recv_from().await;
            }
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        UdpRecv
    }
}

/// Launches a runtime with one UDP socket, waits for its handler to start,
/// shuts it down and joins the workers.
fn launch_and_shut_down() {
    STARTED.store(false, Ordering::Release);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(64, 16384)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind_udp("127.0.0.1:0".parse().unwrap())
        .launch::<UdpRecv>()
        .expect("launch");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !STARTED.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "UDP handler did not start");
        std::thread::sleep(Duration::from_millis(5));
    }
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .count()
}

/// What each open fd refers to, for a failure message.
fn open_fd_targets() -> Vec<String> {
    let mut targets: Vec<String> = std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .map(|t| t.display().to_string())
        .collect();
    targets.sort();
    targets
}

/// The ids of this process's threads.
fn thread_ids() -> BTreeSet<OsString> {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|t| Some(t.ok()?.file_name()))
        .collect()
}

/// Waits up to 30 s until the only threads left are those in `before`. Every
/// pool thread holds each worker's wake fd until it exits. Blocking-pool
/// threads run at `SCHED_IDLE`; on a busy host they can exit seconds after the
/// workers join.
fn wait_for_runtime_threads_to_exit(before: &BTreeSet<OsString>) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let extra: Vec<OsString> = thread_ids().difference(before).cloned().collect();
        if extra.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} runtime threads still running 30 s after the workers joined",
            extra.len()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn udp_repeated_launch_does_not_leak_fds() {
    let before = thread_ids();
    // Launch twice first, in case a launch opens an fd once per process that
    // stays open.
    for _ in 0..2 {
        launch_and_shut_down();
    }
    wait_for_runtime_threads_to_exit(&before);
    let baseline = open_fd_count();
    let baseline_targets = open_fd_targets();

    for _ in 0..6 {
        launch_and_shut_down();
    }
    // Every thread a launch started has exited, so every fd a launch opened
    // is closed.
    wait_for_runtime_threads_to_exit(&before);
    let after = open_fd_count();
    assert_eq!(
        after,
        baseline,
        "open fd count changed after 6 launch+shutdown cycles; open fds before: \
         {baseline_targets:?}, after: {:?}",
        open_fd_targets()
    );
}
