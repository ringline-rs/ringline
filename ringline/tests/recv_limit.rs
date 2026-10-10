//! `ConfigBuilder::recv_multishot_limit` end to end: data received through
//! limited multishot arms on an incremental ring arrives intact on each
//! receive path, and the arms end at their limit. In its own test binary
//! because it reads the process-wide `ringline/recv_ring` counters, which
//! every other launch in the same process would also move; for the same
//! reason all launches run in one test, one after another.
#![cfg(has_io_uring)]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ringline::metrics::{RECV_RING, recv_ring};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// Echo through the accumulator (`with_data`).
struct AsyncEcho;

impl AsyncEventHandler for AsyncEcho {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
                        ParseResult::Consumed(data.len())
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

/// Echo through the recv-forward path.
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

/// Echo through the direct-echo path.
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

/// Write `msg` from one thread and read the echo on this one, so a large
/// message cannot fill both directions' socket buffers and stall.
fn echo_round_trip(addr: &str, msg: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let out = msg.to_vec();
    let w = std::thread::spawn(move || writer.write_all(&out).unwrap());
    let mut buf = vec![0u8; msg.len()];
    let mut total = 0;
    while total < msg.len() {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error after {total} bytes: {e}"),
        }
    }
    w.join().unwrap();
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

/// `(workers that selected limited arms, arms that reached their limit)`.
fn counts() -> (u64, u64) {
    (
        RECV_RING.value(recv_ring::LIMITED).unwrap_or(0),
        RECV_RING.value(recv_ring::LIMIT_REACHED).unwrap_or(0),
    )
}

const TOTAL: usize = 1 << 20;

/// Echo `TOTAL` bytes through a 16 × 1 KiB incremental ring with handler
/// `H`, and return how the counters moved. The ring's quarter cap is 4
/// buffers, so an arm on a connection with nothing held is limited to
/// 4 KiB, and `TOTAL` takes at least 1 MiB / 5 KiB, about 200, arms.
fn echo<H: AsyncEventHandler>(limit: bool) -> (u64, u64) {
    let before = counts();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        .max_connections(64)
        .send_pool(128, 16384)
        .recv_incremental(true)
        .recv_multishot_limit(limit)
        .recv_buffer(16, 1024)
        .build()
        .expect("config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);
    let msg: Vec<u8> = (0..TOTAL).map(|k| (k % 251) as u8).collect();
    let got = echo_round_trip(&addr, &msg);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(got.len(), msg.len(), "echoed length");
    assert!(got == msg, "echoed bytes differ");
    let after = counts();
    (after.0 - before.0, after.1 - before.1)
}

#[test]
fn limited_arms_deliver_intact_on_every_receive_path() {
    let limited = kernel_at_least(6, 17);
    for (path, moved) in [
        ("accumulator", echo::<AsyncEcho>(true)),
        ("recv-forward", echo::<RecvForwardEcho>(true)),
        ("direct echo", echo::<DirectEcho>(true)),
    ] {
        eprintln!(
            "{path}: limited workers +{}, limits reached +{}",
            moved.0, moved.1
        );
        if limited {
            assert_eq!(moved.0, 1, "{path}: the worker did not select limited arms");
            assert!(
                moved.1 >= 100,
                "{path}: only {} arms reached their limit",
                moved.1
            );
        }
    }
    // With the setting off, no worker selects limited arms.
    let moved = echo::<AsyncEcho>(false);
    assert_eq!(moved, (0, 0), "recv_multishot_limit(false) armed limits");
}
