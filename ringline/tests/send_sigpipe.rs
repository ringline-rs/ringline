//! A send after `shutdown_write` must fail with an error, not raise SIGPIPE.
//!
//! The Rust runtime sets SIGPIPE to ignored before `main`; a process that resets
//! it to `SIG_DFL`, or a C program embedding ringline, is killed by one. This
//! binary restores the default disposition, so a regression kills the test
//! process (signal 13) instead of passing.
//!
//! Its own test binary, because signal disposition is process-wide.

#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::Read;
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, Config, ConfigBuilder, Connection, RinglineBuilder};

/// The result of the handler's last send, as an `io::ErrorKind` name, or
/// `"ok"`.
static OUTCOME: Mutex<Option<String>> = Mutex::new(None);

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

fn record(result: std::io::Result<u32>) {
    let outcome = match result {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("{:?}", e.kind()),
    };
    *OUTCOME.lock().unwrap() = Some(outcome);
}

/// Shuts its write side down, then sends.
struct SendAfterShutdownWrite;

impl AsyncEventHandler for SendAfterShutdownWrite {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.shutdown_write();
            // Let the shutdown reach the socket before the send is queued.
            ringline::sleep(Duration::from_millis(50)).await;
            let result = match conn.send(b"x") {
                Ok(done) => done.await,
                Err(e) => Err(e),
            };
            record(result);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        SendAfterShutdownWrite
    }
}

fn wait_for_outcome() -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(o) = OUTCOME.lock().unwrap().take() {
            return o;
        }
        assert!(
            Instant::now() < deadline,
            "the handler never recorded a result"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn run<H: AsyncEventHandler>(client: impl FnOnce(TcpStream)) -> String {
    let (runtime, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    client(TcpStream::connect(addr).expect("connect"));
    let outcome = wait_for_outcome();
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    outcome
}

#[test]
fn a_send_after_shutdown_write_fails_without_sigpipe() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    let outcome = run::<SendAfterShutdownWrite>(|mut client| {
        // Hold the connection open until the server's FIN arrives.
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 16];
        let _ = client.read(&mut buf);
        std::thread::sleep(Duration::from_millis(200));
    });
    assert_eq!(outcome, "BrokenPipe", "a send after shutdown_write");
}
