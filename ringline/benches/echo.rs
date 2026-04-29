//! Echo round-trip benchmarks against a ringline server.
//!
//! All benches share a single in-process ringline echo server (started
//! once via `OnceLock` and leaked for the lifetime of the process) and
//! reuse a long-lived TCP client connection for measurement. This
//! isolates per-message cost from `connect()` overhead and avoids
//! TIME_WAIT exhaustion at high iteration counts.

#![allow(clippy::manual_async_fn)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::OnceLock;

struct EchoHandler;

impl AsyncEventHandler for EchoHandler {
    fn on_accept(&self, conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| {
                        let _ = conn.send_nowait(data);
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
        EchoHandler
    }
}

fn echo_server_addr() -> SocketAddr {
    static ADDR: OnceLock<SocketAddr> = OnceLock::new();
    *ADDR.get_or_init(|| {
        let mut config = Config::default();
        config.worker.threads = 1;
        config.worker.pin_to_core = false;
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (shutdown, handles) = RinglineBuilder::new(config)
            .bind(bind)
            .launch::<EchoHandler>()
            .expect("failed to launch ringline echo server");
        let bound = shutdown
            .bound_addr()
            .expect("server should have a bound address");
        // Keep the server alive for the entire bench process. Workers
        // never join — the OS reaps them at process exit.
        std::mem::forget(shutdown);
        std::mem::forget(handles);
        bound
    })
}

fn open_client(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).expect("connect to echo server");
    stream.set_nodelay(true).ok();
    // Single round-trip handshake to make sure the server is echoing.
    let mut s = &stream;
    s.write_all(b"x").unwrap();
    let mut buf = [0u8; 1];
    s.read_exact(&mut buf).unwrap();
    stream
}

/// Round-trip latency for a single message at varying payload sizes.
fn bench_echo_roundtrip(c: &mut Criterion) {
    let addr = echo_server_addr();
    let mut group = c.benchmark_group("echo_roundtrip");
    for &size in &[64usize, 256, 1024, 4096, 16384] {
        let stream = open_client(addr);
        let payload = vec![0xAB_u8; size];
        let mut buf = vec![0u8; size];
        // Throughput is request + response bytes.
        group.throughput(Throughput::Bytes((size as u64) * 2));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let mut s = &stream;
                s.write_all(&payload).unwrap();
                s.read_exact(&mut buf).unwrap();
                black_box(buf[0]);
            });
        });
    }
    group.finish();
}

/// Pipelined throughput: send N requests back-to-back, then read N
/// responses. Measures the runtime's ability to amortize syscall cost
/// across multiple in-flight messages.
fn bench_echo_pipeline(c: &mut Criterion) {
    let addr = echo_server_addr();
    let mut group = c.benchmark_group("echo_pipeline");
    let payload_size = 64usize;
    for &depth in &[1usize, 4, 16, 64, 256] {
        let stream = open_client(addr);
        let payload = vec![0xAB_u8; payload_size];
        let mut buf = vec![0u8; payload_size];
        group.throughput(Throughput::Elements(depth as u64));
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &n| {
            b.iter(|| {
                let mut s = &stream;
                for _ in 0..n {
                    s.write_all(&payload).unwrap();
                }
                for _ in 0..n {
                    s.read_exact(&mut buf).unwrap();
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_echo_roundtrip, bench_echo_pipeline);
criterion_main!(benches);
