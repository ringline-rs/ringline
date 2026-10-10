//! The lend cap of `ConfigBuilder::recv_incremental` on the recv-forward and
//! direct-echo paths (#622). In its own test binary because
//! `tests/recv_incremental.rs` counts the process-wide `ringline/recv_ring`
//! selections, which these launches would also move.
#![cfg(has_io_uring)]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

/// Echo through the recv-forward path: held receive buffers are sent back
/// with one gathered write.
struct RecvForwardEcho;

impl AsyncEventHandler for RecvForwardEcho {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.enable_recv_forward();
            loop {
                conn.recv_ready().await;
                let n = match conn.forward_held() {
                    Ok(f) => f.await.unwrap_or(0),
                    Err(_) => break,
                };
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        RecvForwardEcho
    }
}

/// Echo through the direct-echo path, sent from the completion handler.
struct DirectEcho;

impl AsyncEventHandler for DirectEcho {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let _ = conn.run_direct_echo().await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        DirectEcho
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

fn echo_round_trip(addr: &str, msg: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(msg).unwrap();
    let mut buf = vec![0u8; msg.len()];
    let mut total = 0;
    while total < msg.len() {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }
    buf.truncate(total);
    buf
}

/// Whether the running kernel is at least `major.minor`.
fn kernel_at_least(major: u32, minor: u32) -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let mut next = || {
        parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0)
    };
    (next(), next()) >= (major, minor)
}

/// Echo `total` bytes through a 16 × 1 KiB incremental ring, whose lend cap
/// is 8 buffers, with handler `H` and unlimited multishot arms, and check
/// the bytes and that the cap refused lends (so owned copies carried part
/// of the stream).
fn echo_over_the_lend_cap<H: AsyncEventHandler>(total: usize) {
    use ringline::metrics::{RECV_RING, recv_ring};
    let refused = || RECV_RING.value(recv_ring::LEND_REFUSED).unwrap_or(0);
    let before = refused();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        .max_connections(64)
        .send_pool(128, 16384)
        .recv_incremental(true)
        // A limited arm holds one connection under the lend cap, so the
        // cap would refuse nothing (`tests/recv_limit.rs`).
        .recv_multishot_limit(false)
        .recv_buffer(16, 1024)
        .build()
        .expect("config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);
    let msg: Vec<u8> = (0..total).map(|k| (k % 251) as u8).collect();
    assert_eq!(echo_round_trip(&addr, &msg), msg);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    if kernel_at_least(6, 12) {
        assert!(refused() > before, "the lend cap refused no lend");
    }
}

#[test]
fn recv_forward_echoes_over_the_lend_cap() {
    echo_over_the_lend_cap::<RecvForwardEcho>(320 << 10);
}

#[test]
fn direct_echo_echoes_over_the_lend_cap() {
    echo_over_the_lend_cap::<DirectEcho>(320 << 10);
}

/// A client that writes without reading the echo is stopped by TCP
/// backpressure: above the lend cap, owned copies stop at one ring's worth,
/// then the ring drains and its receive stops. Without that bound the server
/// would buffer everything the client sends.
fn writes_stall_without_reads<H: AsyncEventHandler>() {
    const LIMIT: u64 = 64 << 20;
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(64)
        .recv_incremental(true)
        .recv_buffer(16, 64 << 10)
        .build()
        .expect("config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);
    let mut client = TcpStream::connect(&addr).unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let chunk = vec![7u8; 1 << 20];
    let mut sent = 0u64;
    while sent < LIMIT {
        match client.write(&chunk) {
            Ok(n) => sent += n as u64,
            Err(_) => break,
        }
    }
    drop(client);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert!(
        sent < LIMIT,
        "the server accepted {sent} bytes without a read"
    );
}

#[test]
fn recv_forward_writes_stall_without_reads() {
    writes_stall_without_reads::<RecvForwardEcho>();
}

#[test]
fn direct_echo_writes_stall_without_reads() {
    writes_stall_without_reads::<DirectEcho>();
}
