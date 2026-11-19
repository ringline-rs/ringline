//! `Runtime::next_signal` and `signal::install`: a `SIGTERM` sent after
//! `install()` and before any wait is kept and returned, without shutting the
//! runtime down, and a task panic is returned once.
//!
//! Its own test binary, because it sends real `SIGTERM`s to the process and
//! installs ringline's signal handlers. One test, so no other waiter in the
//! process can take a signal byte.

#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use ringline::signal::Signal;
use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, TaskPanicPolicy,
};

static PANIC: AtomicBool = AtomicBool::new(false);

/// Echoes, and panics in `on_tick` once [`PANIC`] is set.
struct Echo;

impl AsyncEventHandler for Echo {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }

    fn on_tick(&mut self) {
        if PANIC.swap(false, Ordering::SeqCst) {
            panic!("injected task panic");
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Echo
    }
}

fn config(policy: TaskPanicPolicy) -> ringline::Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .task_panic_policy(policy)
        .build()
        .expect("valid config")
}

/// `runtime.next_signal()` on another thread, or `None` after 5 s.
fn next_within(runtime: &Arc<ringline::Runtime>) -> Option<Signal> {
    let waiter = Arc::clone(runtime);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(waiter.next_signal());
    });
    rx.recv_timeout(Duration::from_secs(5)).ok()
}

fn sigterm() {
    assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGTERM) }, 0);
}

#[test]
fn next_signal_returns_signals_and_a_task_panic_once() {
    // Without the handlers installed, this SIGTERM ends the test process.
    ringline::signal::install();
    sigterm();

    let (runtime, handles) = RinglineBuilder::new(config(TaskPanicPolicy::Contain))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Echo>()
        .expect("launch");
    let runtime = Arc::new(runtime);
    assert_eq!(next_within(&runtime), Some(Signal::Terminate));

    // Not shut down: a new connection is served.
    let mut client = TcpStream::connect(runtime.bound_addr().unwrap()).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    client.write_all(b"ping").expect("write");
    let mut got = [0u8; 4];
    client
        .read_exact(&mut got)
        .expect("served after next_signal");
    assert_eq!(&got, b"ping");
    drop(client);
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }

    let (runtime, handles) = RinglineBuilder::new(config(TaskPanicPolicy::Shutdown))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Echo>()
        .expect("launch");
    let runtime = Arc::new(runtime);
    PANIC.store(true, Ordering::SeqCst);
    assert_eq!(next_within(&runtime), Some(Signal::TaskPanic));
    // The panic is not returned again: the next call returns the SIGTERM.
    sigterm();
    assert_eq!(next_within(&runtime), Some(Signal::Terminate));
    for h in handles {
        let _ = h.join().expect("worker panicked");
    }
}
