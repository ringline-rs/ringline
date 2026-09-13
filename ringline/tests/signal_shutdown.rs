#![allow(clippy::manual_async_fn)]
//! `wait_on_signal`, in a test binary of its own.
//!
//! This test sends **SIGTERM to its own process**. A signal is delivered to
//! the process, not to a thread, so every ringline server alive anywhere in
//! that process is torn down — including servers belonging to other tests
//! that `cargo test` is running in parallel threads of the same binary.
//! Whichever of those is mid-round-trip when the signal lands sees
//! `ECONNRESET`, which is how this test used to make *other* tests in
//! `echo.rs` fail intermittently on the `Test (mio)` CI job
//! (ringline-rs/ringline#386).
//!
//! Cargo runs each integration-test binary as its own process, so giving
//! this test a file to itself contains the blast radius by construction.
//! **Keep it alone here**: any test added to this file is a test that can be
//! killed mid-flight by the signal below.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ringline::{AsyncEventHandler, Config, ConfigBuilder, ConnCtx, ParseResult, RinglineBuilder};

struct AsyncEcho;

impl AsyncEventHandler for AsyncEcho {
    fn on_accept(&self, conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| {
                        let owned = data.to_vec();
                        let _ = conn.send_nowait(&owned);
                        ParseResult::Consumed(owned.len())
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        AsyncEcho
    }
}

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(64, 4096)
        .max_connections(64)
        .send_pool(64, 16384)
        .build()
        .expect("valid config")
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

/// `wait_on_signal` shuts down workers when SIGTERM is sent to self.
#[test]
fn signal_wait_on_signal_shutdown() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

    wait_for_server(&addr);

    // Verify the server is running.
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"hi").unwrap();
    let mut got = [0u8; 2];
    stream.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"hi");
    drop(stream);

    // Send SIGTERM to self from a background thread after a short delay.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(100));
        unsafe {
            libc::kill(libc::getpid(), libc::SIGTERM);
        }
    });

    let sig = shutdown.wait_on_signal();
    assert_eq!(sig, ringline::Signal::Terminate);

    for h in handles {
        h.join().unwrap().unwrap();
    }
}
