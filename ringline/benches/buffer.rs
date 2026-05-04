use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

// ── Echo server handler ──────────────────────────────────────────────

#[allow(clippy::manual_async_fn)]
struct EchoHandler;

#[allow(clippy::manual_async_fn)]
impl AsyncEventHandler for EchoHandler {
    fn on_accept(&self, conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| {
                        conn.send_nowait(data).ok();
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

// ── Buffer size benchmarks ───────────────────────────────────────────

fn bench_ringline_buffer_sizes(c: &mut Criterion) {
    // Use a unique port range for buffer benchmarks
    let base_port = 32000;
    let sizes = [64, 256, 1024, 4096, 16384, 65536];

    for size in sizes {
        let data = vec![0u8; size];
        let port = base_port + size as u16;
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        // ── Ringline server benchmark ──────────────────────────────
        let config = Config::default();
        let (shutdown, handles) = RinglineBuilder::new(config)
            .bind(addr)
            .launch::<EchoHandler>()
            .unwrap_or_else(|_| panic!("Failed to start server on {}", addr));

        // Give server time to start
        thread::sleep(Duration::from_millis(500));

        // Warmup
        for _ in 0..100 {
            let mut stream = std::net::TcpStream::connect(addr)
                .unwrap_or_else(|_| panic!("Failed to connect to {}", addr));
            stream
                .write_all(&data)
                .unwrap_or_else(|_| panic!("Failed to write to {}", addr));
            let mut buf = vec![0u8; size];
            stream
                .read_exact(&mut buf)
                .unwrap_or_else(|_| panic!("Failed to read from {}", addr));
        }

        let mut group = c.benchmark_group(format!("ringline_buffer_{}", size));
        group.bench_function(BenchmarkId::from_parameter("ringline_server"), |b| {
            b.iter(|| {
                let mut stream = std::net::TcpStream::connect(addr)
                    .unwrap_or_else(|_| panic!("Failed to connect to {}", addr));
                stream
                    .write_all(&data)
                    .unwrap_or_else(|_| panic!("Failed to write to {}", addr));
                let mut buf = vec![0u8; size];
                stream
                    .read_exact(&mut buf)
                    .unwrap_or_else(|_| panic!("Failed to read from {}", addr));
                black_box(buf);
            });
        });
        group.finish();

        // Give server time to shut down
        drop(shutdown);
        for h in handles {
            h.join().ok();
        }
        thread::sleep(Duration::from_millis(500));
    }
}

criterion_group!(benches, bench_ringline_buffer_sizes);
criterion_main!(benches);
