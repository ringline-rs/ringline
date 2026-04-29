//! TCP connect benchmarks against a ringline acceptor.
//!
//! Measures how fast ringline's centralized acceptor + worker handoff
//! can absorb fresh inbound connections, both serial and concurrent.

#![allow(clippy::manual_async_fn)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder};
use std::net::{SocketAddr, TcpStream};
use std::sync::OnceLock;
use std::thread;

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

fn server_addr() -> SocketAddr {
    static ADDR: OnceLock<SocketAddr> = OnceLock::new();
    *ADDR.get_or_init(|| {
        let mut config = Config::default();
        config.worker.threads = 1;
        config.worker.pin_to_core = false;
        config.max_connections = 8192;
        config.backlog = 4096;
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (shutdown, handles) = RinglineBuilder::new(config)
            .bind(bind)
            .launch::<EchoHandler>()
            .expect("failed to launch ringline server");
        let bound = shutdown.bound_addr().expect("bound");
        std::mem::forget(shutdown);
        std::mem::forget(handles);
        bound
    })
}

fn bench_connect_serial(c: &mut Criterion) {
    let addr = server_addr();
    c.bench_function("connect_serial", |b| {
        b.iter(|| {
            let _stream = TcpStream::connect(addr).expect("connect");
        });
    });
}

fn bench_connect_concurrent(c: &mut Criterion) {
    let addr = server_addr();
    let mut group = c.benchmark_group("connect_concurrent");
    for &fanout in &[1usize, 4, 16, 64] {
        group.throughput(Throughput::Elements(fanout as u64));
        group.bench_with_input(BenchmarkId::from_parameter(fanout), &fanout, |b, &n| {
            b.iter(|| {
                let mut handles = Vec::with_capacity(n);
                for _ in 0..n {
                    handles.push(thread::spawn(move || {
                        let _ = TcpStream::connect(addr).expect("connect");
                    }));
                }
                for h in handles {
                    h.join().ok();
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_connect_serial, bench_connect_concurrent);
criterion_main!(benches);
