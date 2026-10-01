//! A wake after a worker has exited must not raise SIGPIPE.
//!
//! The Rust runtime sets SIGPIPE to ignored before `main`; a process that resets
//! it to `SIG_DFL`, or a C program embedding ringline, is killed by one. On mio a
//! worker's wake fd is a pipe, so a write after the read end has closed raises
//! it. This binary restores the default disposition, so a regression kills the
//! test process (signal 13) instead of passing.
//!
//! Its own test binary, because signal disposition is process-wide. Linux only.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, Config, ConfigBuilder, Connection, RinglineBuilder};

static BLOCKING_STARTED: AtomicBool = AtomicBool::new(false);
static BLOCKING_FINISHED: AtomicBool = AtomicBool::new(false);

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(16, 1024)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(1)
        .build()
        .expect("valid config")
}

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn create_for_worker(_id: usize) -> Self {
        Idle
    }
}

/// Starts one blocking task that finishes after the worker has exited.
struct SlowBlocking;

impl AsyncEventHandler for SlowBlocking {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let task = ringline::spawn_blocking(|| {
                BLOCKING_STARTED.store(true, Ordering::Release);
                std::thread::sleep(Duration::from_millis(300));
                BLOCKING_FINISHED.store(true, Ordering::Release);
            })
            .expect("spawn_blocking");
            let _ = task.await;
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        SlowBlocking
    }
}

/// Whether a blocking-pool thread is alive. The kernel truncates thread names
/// to 15 bytes, so `ringline-blocking-0` reads back as `ringline-blocki`.
fn blocking_thread_alive() -> bool {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok())
        .any(|name| name.trim_end().starts_with("ringline-blocki"))
}

fn wait_for(flag: &AtomicBool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !flag.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(flag.load(Ordering::Acquire), "{what}");
}

#[test]
fn late_wakes_do_not_raise_sigpipe() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    // `Runtime`'s drop wakes every worker, after they have exited.
    let (runtime, handles) = RinglineBuilder::new(test_config())
        .launch::<Idle>()
        .expect("launch");
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    drop(runtime);

    // A blocking task wakes its worker after the worker has exited and the
    // `Runtime` has dropped.
    let (runtime, handles) = RinglineBuilder::new(test_config())
        .launch::<SlowBlocking>()
        .expect("launch");
    wait_for(&BLOCKING_STARTED, "blocking task never started");
    drop(runtime);
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    wait_for(&BLOCKING_FINISHED, "blocking task never finished");
    // The pool thread wakes the worker after the task returns and exits after
    // that, since its request channel has closed.
    let deadline = Instant::now() + Duration::from_secs(5);
    while blocking_thread_alive() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !blocking_thread_alive(),
        "blocking pool thread never exited"
    );
}
