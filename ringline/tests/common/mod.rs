//! Helpers shared by this crate's integration tests.

#![allow(dead_code)]

use std::net::TcpStream;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A loopback port that refuses connections, held by the client end of an
/// established loopback connection. Nothing listens on it, so a connect to it
/// fails with `ConnectionRefused` on Linux and macOS, and the port stays in
/// use until the returned streams are dropped, so a port-0 bind is never
/// given it.
///
/// A bound socket that never listens does not work here: macOS drops a SYN
/// to it instead of refusing, so the connect times out.
pub fn refusing_port() -> ((TcpStream, TcpStream), u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let port = client.local_addr().unwrap().port();
    ((client, server), port)
}

/// How long [`join_workers`] waits for the workers to exit before it shuts
/// the runtime down and fails the test.
pub const WORKER_EXIT_DEADLINE: Duration = Duration::from_secs(30);

/// Join the workers of a runtime whose handler requests its own shutdown.
///
/// If the workers have not all exited within [`WORKER_EXIT_DEADLINE`] of the
/// call, this shuts the runtime down, waits up to 5 s for them, and fails the
/// test. A handler that never requests shutdown fails the test instead of
/// hanging it.
///
/// Panics as soon as a worker panics or returns an error.
#[track_caller]
pub fn join_workers(
    runtime: &ringline::Runtime,
    handles: Vec<JoinHandle<Result<(), ringline::Error>>>,
) {
    join_workers_within(runtime, handles, WORKER_EXIT_DEADLINE);
}

/// [`join_workers`] with a deadline other than [`WORKER_EXIT_DEADLINE`].
#[track_caller]
pub fn join_workers_within(
    runtime: &ringline::Runtime,
    handles: Vec<JoinHandle<Result<(), ringline::Error>>>,
    limit: Duration,
) {
    let deadline = Instant::now() + limit;
    let mut running = handles;
    while !running.is_empty() {
        // Check each worker as it exits, so an error surfaces at once rather
        // than after the others.
        let (finished, still): (Vec<_>, Vec<_>) =
            running.into_iter().partition(|h| h.is_finished());
        for h in finished {
            h.join().expect("worker panicked").expect("worker failed");
        }
        running = still;
        if running.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            runtime.shutdown();
            let grace = Instant::now() + Duration::from_secs(5);
            while !running.iter().all(|h| h.is_finished()) && Instant::now() < grace {
                std::thread::sleep(Duration::from_millis(10));
            }
            let exited = running.iter().all(|h| h.is_finished());
            panic!(
                "the workers did not exit within {limit:?}; after Runtime::shutdown they {}",
                if exited {
                    "exited, so shutdown was never requested"
                } else {
                    "were still running 5 s later"
                }
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
