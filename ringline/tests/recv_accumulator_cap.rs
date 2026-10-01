#![allow(clippy::manual_async_fn)]
//! Integration test: a peer that streams past `recv_accumulator_max` without
//! ever completing a message gets its connection closed — on both backends —
//! rather than growing the accumulator or (the pre-fix mio failure mode)
//! spinning in a read-and-discard loop with the connection held open forever.

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// A handler whose parser never completes: every poll reports `NeedMore`, so
/// the accumulator grows with every arriving byte until the cap is hit.
struct NeverSatisfied;

impl AsyncEventHandler for NeverSatisfied {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn.with_data(|_| ParseResult::NeedMore).await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        NeverSatisfied
    }
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

#[test]
fn overflow_closes_connection_instead_of_hanging() {
    const CAP: usize = 16 * 1024;

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(64, 4096)
        .max_connections(64)
        .send_pool(64, 16384)
        .recv_accumulator_max(CAP)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<NeverSatisfied>()
        .expect("launch failed");
    let addr = shutdown
        .bound_addr()
        .expect("bound_addr after TCP bind")
        .to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Stream 8x the cap in chunks. Writes may start failing once the server
    // closes (EPIPE/ECONNRESET) — that is the expected outcome, not an error.
    let chunk = vec![0xABu8; 4096];
    let mut write_err = false;
    for _ in 0..(CAP * 8 / chunk.len()) {
        match stream.write_all(&chunk) {
            Ok(()) => {}
            Err(_) => {
                write_err = true;
                break;
            }
        }
    }

    // The server must observe the overflow and close: the client sees EOF or
    // a reset. A read timeout here means the connection was left open with
    // the handler parked — the pre-fix mio failure mode.
    if !write_err {
        let mut buf = [0u8; 16];
        match stream.read(&mut buf) {
            Ok(0) => {}                                                // clean FIN
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {} // RST
            Ok(n) => panic!("server sent {n} unexpected bytes"),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                panic!("connection not closed on accumulator overflow (handler hang)")
            }
            Err(e) => panic!("unexpected read error: {e}"),
        }
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
