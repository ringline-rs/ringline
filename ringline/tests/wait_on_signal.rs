//! `Runtime::wait_on_signal` with two runtimes in one process.
//!
//! A signal wakes every waiter, and only one of them reads the signal byte.
//! The other must keep watching its own runtime and still return
//! `Signal::TaskPanic` when a task panics there under
//! `TaskPanicPolicy::Shutdown`.
//!
//! Its own test binary, because it sends real `SIGINT`s to the process and
//! installs ringline's signal handlers. Linux only.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ringline::signal::Signal;
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder, TaskPanicPolicy};

static PANIC_A: AtomicBool = AtomicBool::new(false);
static PANIC_B: AtomicBool = AtomicBool::new(false);

/// Panics in `on_tick` once its flag is set.
struct PanicA;
struct PanicB;

impl AsyncEventHandler for PanicA {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn on_tick(&mut self) {
        if PANIC_A.swap(false, Ordering::SeqCst) {
            panic!("boom in A");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        PanicA
    }
}

impl AsyncEventHandler for PanicB {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn on_tick(&mut self) {
        if PANIC_B.swap(false, Ordering::SeqCst) {
            panic!("boom in B");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        PanicB
    }
}

fn config() -> ringline::Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .task_panic_policy(TaskPanicPolicy::Shutdown)
        .build()
        .expect("valid config")
}

/// After a `SIGINT` that the other runtime's waiter consumed, a waiter still
/// sees its own runtime's task panic.
#[test]
fn a_waiter_that_lost_the_signal_still_sees_its_panic() {
    for round in 0..40 {
        PANIC_A.store(false, Ordering::SeqCst);
        PANIC_B.store(false, Ordering::SeqCst);
        let (runtime_a, handles_a) = RinglineBuilder::new(config())
            .launch::<PanicA>()
            .expect("launch A");
        let (runtime_b, handles_b) = RinglineBuilder::new(config())
            .launch::<PanicB>()
            .expect("launch B");

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|s| {
            let (tx_a, tx_b) = (tx.clone(), tx.clone());
            let (a, b) = (&runtime_a, &runtime_b);
            s.spawn(move || {
                let _ = tx_a.send(('A', a.wait_on_signal()));
            });
            s.spawn(move || {
                let _ = tx_b.send(('B', b.wait_on_signal()));
            });
            std::thread::sleep(Duration::from_millis(50));
            unsafe { libc::kill(libc::getpid(), libc::SIGINT) };
            let (first, signal) = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("no waiter saw the SIGINT");
            assert_eq!(signal, Signal::Interrupt, "round {round}");

            // Panic in the runtime whose waiter did not get the signal.
            let other = if first == 'A' { 'B' } else { 'A' };
            if other == 'A' {
                PANIC_A.store(true, Ordering::SeqCst);
            } else {
                PANIC_B.store(true, Ordering::SeqCst);
            }
            let second = rx.recv_timeout(Duration::from_secs(3));
            if second.is_err() {
                // Free the stuck waiter before failing, so the scope ends.
                unsafe { libc::kill(libc::getpid(), libc::SIGINT) };
            }
            assert_eq!(
                second.ok(),
                Some((other, Signal::TaskPanic)),
                "round {round}: {other}'s waiter missed its own runtime's panic"
            );
        });
        drop(runtime_a);
        drop(runtime_b);
        for h in handles_a.into_iter().chain(handles_b) {
            let _ = h.join();
        }
    }
}
