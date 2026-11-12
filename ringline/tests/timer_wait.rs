#![allow(clippy::manual_async_fn)]
//! Timers end the worker's wait for I/O (#838).
//!
//! On io_uring each wait is bounded by the earliest of the next tick, the
//! earliest timer and the earliest handshake or close deadline. A timer
//! therefore fires at its deadline whatever the tick, and with no tick at all.
//! The main thread waits for each worker task with its own deadline, so a
//! timer that never fires fails the test instead of hanging it.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

/// One handler type reads these, so the tests run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());
static FINISHED: AtomicBool = AtomicBool::new(false);
/// What `on_start` runs: `(sleep, count)`.
static SLEEPS: Mutex<(Duration, usize)> = Mutex::new((Duration::ZERO, 0));
/// Each sleep's measured duration, in nanoseconds, in the order taken.
static TAKEN: Mutex<Vec<u64>> = Mutex::new(Vec::new());
/// Set by `on_start` before its first sleep is polled.
static ARMING: AtomicBool = AtomicBool::new(false);
/// `on_tick` calls: one per loop iteration.
static TICKS: AtomicU64 = AtomicU64::new(0);

struct Sleeper;

impl AsyncEventHandler for Sleeper {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let (sleep, count) = *SLEEPS.lock().unwrap();
        Some(Box::pin(async move {
            ARMING.store(true, Ordering::SeqCst);
            for _ in 0..count {
                let start = Instant::now();
                ringline::sleep(sleep).await;
                TAKEN
                    .lock()
                    .unwrap()
                    .push(start.elapsed().as_nanos() as u64);
            }
            FINISHED.store(true, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        }))
    }

    fn on_tick(&mut self) {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }

    fn create_for_worker(_id: usize) -> Self {
        Sleeper
    }
}

/// Run `count` sequential sleeps of `sleep` on one worker with the given
/// tick, and return each one's duration. Fails if they have not all
/// completed within `limit`.
fn sleeps(tick_us: u64, sleep: Duration, count: usize, limit: Duration) -> Vec<Duration> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    FINISHED.store(false, Ordering::SeqCst);
    TAKEN.lock().unwrap().clear();
    *SLEEPS.lock().unwrap() = (sleep, count);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .tick_timeout_us(tick_us)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Sleeper>()
        .expect("launch");
    let start = Instant::now();
    while !FINISHED.load(Ordering::SeqCst) && start.elapsed() < limit {
        std::thread::sleep(Duration::from_millis(1));
    }
    let finished = FINISHED.load(Ordering::SeqCst);
    let taken = TAKEN.lock().unwrap().len();
    if finished {
        common::join_workers(&runtime, handles);
    } else {
        // Shutdown wakes the worker, so a sleep that never fired does not
        // keep it from exiting.
        runtime.shutdown();
        for h in handles {
            let _ = h.join();
        }
    }
    assert!(
        finished,
        "{taken} of {count} sleeps of {sleep:?} completed within {limit:?} \
         with tick_timeout_us = {tick_us}"
    );
    TAKEN
        .lock()
        .unwrap()
        .iter()
        .map(|&ns| Duration::from_nanos(ns))
        .collect()
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

/// With no tick and nothing else to wake the worker, a sleep fires: the
/// sleep's deadline bounds the wait.
#[test]
fn a_sleep_fires_with_no_tick() {
    let taken = sleeps(0, Duration::from_millis(50), 3, Duration::from_secs(5));
    for t in &taken {
        assert!(*t >= Duration::from_millis(50), "fired early: {t:?}");
        assert!(*t < Duration::from_secs(1), "fired late: {t:?}");
    }
}

/// A sleep much shorter than the tick completes near its own deadline, not
/// at the next tick. With a 20 ms tick, sleeps that fired only when the tick
/// ended the wait would each take about 20 ms; 1 ms sleeps take a median of
/// about 1 ms. The median under 10 ms leaves room for a loaded host.
#[test]
fn a_sleep_shorter_than_the_tick_fires_at_its_deadline() {
    let taken = sleeps(
        20_000,
        Duration::from_millis(1),
        20,
        Duration::from_secs(10),
    );
    let min = *taken.iter().min().unwrap();
    assert!(min >= Duration::from_millis(1), "fired early: {min:?}");
    let median = median(taken);
    assert!(
        median < Duration::from_millis(10),
        "median sleep of 1 ms took {median:?} with a 20 ms tick"
    );
}

/// A pending sleep far past the engine's one-hour cap on a timed wait does
/// not spin the worker. `on_tick` runs once per loop iteration, so it counts
/// them: with no tick and nothing else pending an io_uring worker iterates
/// about once per hour-long wait, and a mio worker about every 10 ms. A
/// worker whose wait returned at once would iterate thousands of times in
/// 300 ms.
#[test]
fn a_far_sleep_does_not_spin_the_worker() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    FINISHED.store(false, Ordering::SeqCst);
    ARMING.store(false, Ordering::SeqCst);
    // 2^30 s is far past the one-hour cap and fits in an `Instant` on
    // every platform the tests run on.
    *SLEEPS.lock().unwrap() = (Duration::from_secs(1 << 30), 1);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .tick_timeout_us(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Sleeper>()
        .expect("launch");
    let start = Instant::now();
    while !ARMING.load(Ordering::SeqCst) {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "on_start never ran"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // Let the sleep be polled and the worker reach its wait.
    std::thread::sleep(Duration::from_millis(100));
    let before = TICKS.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(300));
    let iterations = TICKS.load(Ordering::Relaxed) - before;
    let finished = FINISHED.load(Ordering::SeqCst);
    runtime.shutdown();
    for h in handles {
        let _ = h.join();
    }
    assert!(!finished, "a sleep of 2^30 s completed");
    assert!(
        iterations < 1_000,
        "the worker ran {iterations} loop iterations in 300 ms with one far sleep pending"
    );
}
