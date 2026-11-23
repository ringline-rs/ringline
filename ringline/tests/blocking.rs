#![allow(clippy::manual_async_fn)]
//! Integration tests for spawn_blocking.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, Config, ConfigBuilder, Connection, RinglineBuilder};

fn test_config_builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(64, 16384)
        .resolver_threads(0)
        .spawner_threads(0)
}

fn test_config() -> Config {
    test_config_builder().build().expect("valid config")
}

// ── Basic: returns a value ──────────────────────────────────────────

static BLOCKING_RESULT: AtomicU32 = AtomicU32::new(0);

struct BlockingBasicHandler;

impl AsyncEventHandler for BlockingBasicHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let val = ringline::spawn_blocking(|| 42u32)
                .unwrap()
                .await
                .expect("closure returned");
            BLOCKING_RESULT.store(val, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingBasicHandler
    }
}

#[test]
fn spawn_blocking_returns_value() {
    BLOCKING_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<BlockingBasicHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
    assert_eq!(BLOCKING_RESULT.load(Ordering::SeqCst), 42);
}

// ── Blocking work doesn't stall the worker ──────────────────────────

static BLOCKING_CONCURRENT: AtomicU32 = AtomicU32::new(0);

struct BlockingConcurrentHandler;

impl AsyncEventHandler for BlockingConcurrentHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            // Spawn a blocking task that sleeps.
            let handle = ringline::spawn_blocking(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                10u32
            })
            .unwrap();

            // Meanwhile, do async work (a timer) — this should not be blocked.
            ringline::sleep(std::time::Duration::from_millis(10)).await;

            // Now await the blocking result.
            let val = handle.await.expect("closure returned");
            BLOCKING_CONCURRENT.store(val, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingConcurrentHandler
    }
}

#[test]
fn spawn_blocking_doesnt_stall_worker() {
    BLOCKING_CONCURRENT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<BlockingConcurrentHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
    assert_eq!(BLOCKING_CONCURRENT.load(Ordering::SeqCst), 10);
}

// ── Multiple concurrent blocking tasks ──────────────────────────────

static BLOCKING_MULTI: AtomicU32 = AtomicU32::new(0);

struct BlockingMultiHandler;

impl AsyncEventHandler for BlockingMultiHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let h1 = ringline::spawn_blocking(|| 10u32).unwrap();
            let h2 = ringline::spawn_blocking(|| 20u32).unwrap();
            let h3 = ringline::spawn_blocking(|| 30u32).unwrap();

            let (a, b) = ringline::join(h1, h2).await;
            let (a, b) = (a.expect("closure returned"), b.expect("closure returned"));
            let c = h3.await.expect("closure returned");
            BLOCKING_MULTI.store(a + b + c, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingMultiHandler
    }
}

#[test]
fn spawn_blocking_multiple_concurrent() {
    BLOCKING_MULTI.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<BlockingMultiHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
    assert_eq!(BLOCKING_MULTI.load(Ordering::SeqCst), 60);
}

// ── Pool disabled ───────────────────────────────────────────────────

static BLOCKING_DISABLED: AtomicU32 = AtomicU32::new(0);

struct BlockingDisabledHandler;

impl AsyncEventHandler for BlockingDisabledHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            match ringline::spawn_blocking(|| 42u32) {
                Err(_) => BLOCKING_DISABLED.store(1, Ordering::SeqCst),
                Ok(_) => BLOCKING_DISABLED.store(99, Ordering::SeqCst),
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingDisabledHandler
    }
}

#[test]
fn spawn_blocking_disabled() {
    BLOCKING_DISABLED.store(0, Ordering::SeqCst);

    let config = test_config_builder()
        .blocking_threads(0)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .launch::<BlockingDisabledHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
    assert_eq!(BLOCKING_DISABLED.load(Ordering::SeqCst), 1);
}

// ── String return type (non-Copy) ───────────────────────────────────

static BLOCKING_STRING: AtomicU32 = AtomicU32::new(0);

struct BlockingStringHandler;

impl AsyncEventHandler for BlockingStringHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let val = ringline::spawn_blocking(|| "hello blocking".to_string())
                .unwrap()
                .await
                .expect("closure returned");
            if val == "hello blocking" {
                BLOCKING_STRING.store(1, Ordering::SeqCst);
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingStringHandler
    }
}

#[test]
fn spawn_blocking_non_copy_type() {
    BLOCKING_STRING.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<BlockingStringHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
    assert_eq!(BLOCKING_STRING.load(Ordering::SeqCst), 1);
}

// ── A dropped handle releases the result ────────────────────────────

static RESULTS_DROPPED: AtomicUsize = AtomicUsize::new(0);
/// Set by `MarkHandleDropped`: after the `timeout` statement, or when the
/// `on_start` future is dropped.
static HANDLE_DROPPED: AtomicBool = AtomicBool::new(false);
/// Whether the `timeout` around the blocking handle expired. Checked by the
/// test, since a panic inside the task would be contained.
static HANDLE_TIMED_OUT: AtomicBool = AtomicBool::new(false);

/// Sets `HANDLE_DROPPED` when dropped. Declared before the handle, so it drops
/// after it on every path, including a future dropped at shutdown.
struct MarkHandleDropped;

impl Drop for MarkHandleDropped {
    fn drop(&mut self) {
        HANDLE_DROPPED.store(true, Ordering::Release);
    }
}

/// A closure result that counts its own drop.
struct CountedResult;

impl Drop for CountedResult {
    fn drop(&mut self) {
        RESULTS_DROPPED.fetch_add(1, Ordering::SeqCst);
    }
}

/// Starts a closure that finishes only after its handle has been dropped, by
/// the `timeout` around it expiring at 20 ms. The closure gives up waiting
/// after 60 s, so a failed test does not leave the pool thread blocked.
struct DropsHandleEarly;

impl AsyncEventHandler for DropsHandleEarly {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let mark = MarkHandleDropped;
            let handle = ringline::spawn_blocking(|| {
                let deadline = Instant::now() + Duration::from_secs(60);
                while !HANDLE_DROPPED.load(Ordering::Acquire) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
                CountedResult
            })
            .unwrap();
            let timed_out = ringline::timeout(Duration::from_millis(20), handle)
                .await
                .is_err();
            // The `timeout` future, which owned the handle, was dropped at the
            // end of the previous statement.
            drop(mark);
            HANDLE_TIMED_OUT.store(timed_out, Ordering::Release);
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        DropsHandleEarly
    }
}

/// A result that arrives after its handle was dropped is dropped on arrival,
/// not held by the worker until it exits (#582).
#[test]
fn a_result_whose_handle_was_dropped_is_dropped_on_arrival() {
    RESULTS_DROPPED.store(0, Ordering::SeqCst);
    HANDLE_DROPPED.store(false, Ordering::Release);
    HANDLE_TIMED_OUT.store(false, Ordering::Release);
    let (runtime, handles) = RinglineBuilder::new(test_config())
        .launch::<DropsHandleEarly>()
        .expect("launch failed");

    // On a loaded host the blocking pool's result can take seconds to arrive.
    let deadline = Instant::now() + Duration::from_secs(30);
    while RESULTS_DROPPED.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let dropped = RESULTS_DROPPED.load(Ordering::SeqCst);
    runtime.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert!(
        HANDLE_TIMED_OUT.load(Ordering::Acquire),
        "the closure finished before the timeout"
    );
    assert_eq!(dropped, 1, "the worker held the result of a dropped handle");
}

// ── Scheduling policy of the pool's threads ─────────────────────────

/// The policy `sched_getscheduler` reported on a pool thread; -2 until then.
#[cfg(target_os = "linux")]
static POOL_POLICY: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-2);

#[cfg(target_os = "linux")]
struct PoolPolicyHandler;

#[cfg(target_os = "linux")]
impl AsyncEventHandler for PoolPolicyHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            // SAFETY: reads the calling thread's policy.
            let policy = ringline::spawn_blocking(|| unsafe { libc::sched_getscheduler(0) })
                .unwrap()
                .await
                .expect("closure returned");
            POOL_POLICY.store(policy, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        PoolPolicyHandler
    }
}

/// A blocking-pool thread runs at `SCHED_BATCH`, not `SCHED_IDLE`, which gets
/// almost no CPU on a busy host and which a thread cannot leave at the default
/// `RLIMIT_NICE`.
#[cfg(target_os = "linux")]
#[test]
fn a_blocking_pool_thread_runs_at_sched_batch() {
    // SAFETY: reads the calling thread's policy.
    if unsafe { libc::sched_getscheduler(0) } == libc::SCHED_IDLE {
        // Started under `chrt -i`: the pool threads inherit SCHED_IDLE and
        // cannot leave it, so the policy under test cannot be set.
        eprintln!("skipped: the test process runs at SCHED_IDLE");
        return;
    }
    POOL_POLICY.store(-2, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<PoolPolicyHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
    assert_eq!(POOL_POLICY.load(Ordering::SeqCst), libc::SCHED_BATCH);
}
