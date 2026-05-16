use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::bench::{BenchmarkCombination, BenchmarkDefinition, Transport, TlsConfig};
use crate::port_manager::PortManager;
use crate::stats::{BenchResult, LatencyHistogram, LatencyStats, process_cpu_time_ns};
use crate::output::{ConfigResult, BenchReport};

/// Manages the lifecycle of a benchmark server.
pub struct BenchmarkServer {
    pub addr: SocketAddr,
    pub stop: Arc<AtomicBool>,
    pub thread: Option<std::thread::JoinHandle<()>>,
}

impl BenchmarkServer {
    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.thread {
            h.join().ok();
        }
    }
}

/// Start a TCP echo server for benchmarking.
pub fn start_tcp_echo_server(
    port_manager: &PortManager,
    workers: usize,
    msg_size: usize,
) -> Result<BenchmarkServer, String> {
    let addr = port_manager.next_addr();
    let stop = Arc::new(AtomicBool::new(false));

    let rt = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        rt.block_on(async move {
            let socket = tokio::net::TcpSocket::new_v4().expect("failed to create socket");
            socket.set_reuseaddr(true).expect("failed to set reuseaddr");
            socket.bind(addr).expect("failed to bind");
            let listener = socket.listen(1024).expect("failed to listen");

            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => continue,
                };
                stream.set_nodelay(true).ok();

                tokio::spawn(async move {
                    let (mut rd, mut wr) = stream.into_split();
                    tokio::io::copy(&mut rd, &mut wr).await.ok();
                });
            }
        });
    });

    std::thread::sleep(Duration::from_millis(100));

    Ok(BenchmarkServer {
        addr,
        stop,
        thread: Some(rt),
    })
}

/// Run a benchmark for a single configuration.
pub fn run_bench(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    client_runtime: crate::bench::ClientRuntime,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));

    wait_for_server(addr);

    if client_runtime == crate::bench::ClientRuntime::Tokio {
        run_bench_tokio(addr, num_clients, msg_size, warmup, duration, stop.clone(), ops.clone())
    } else {
        run_bench_ringline(addr, num_clients, msg_size, warmup, duration, stop.clone(), ops.clone())
    }
}

fn wait_for_server(addr: &str) {
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("  server did not start on {addr}");
}

// ── tokio client ─────────────────────────────────────────────────

async fn run_tokio_client(
    addr: String,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
) -> LatencyHistogram {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let msg = vec![0xABu8; msg_size];
    let mut recv_buf = vec![0u8; msg_size];
    let mut histogram = LatencyHistogram::new();

    let mut stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  client connect failed: {e}");
            return histogram;
        }
    };
    stream.set_nodelay(true).ok();

    let mut local_ops: u64 = 0;

    while !stop.load(Ordering::Relaxed) {
        let t0 = Instant::now();

        if stream.write_all(&msg).await.is_err() {
            break;
        }

        let mut total_read = 0;
        while total_read < msg_size {
            match stream.read(&mut recv_buf[total_read..]).await {
                Ok(0) => return histogram,
                Ok(n) => total_read += n,
                Err(_) => return histogram,
            }
        }

        let elapsed_ns = t0.elapsed().as_nanos() as u64;
        histogram.record(elapsed_ns);

        local_ops += 1;
        if local_ops & 0xFF == 0 {
            ops_counter.fetch_add(256, Ordering::Relaxed);
        }
    }

    ops_counter.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
    histogram
}

// ── ringline client ────────────────────────────────────────────────

fn run_bench_tokio(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
) -> BenchResult {
    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to build client runtime");

    let mut task_handles = Vec::with_capacity(num_clients);
    for _ in 0..num_clients {
        let addr = addr.to_string();
        let stop = stop.clone();
        let ops = ops.clone();
        task_handles.push(client_rt.spawn(run_tokio_client(addr, msg_size, stop, ops)));
    }

    std::thread::sleep(warmup);
    ops.store(0, Ordering::Relaxed);

    let cpu_before = process_cpu_time_ns();
    let start = Instant::now();
    std::thread::sleep(duration);
    let elapsed = start.elapsed();
    let cpu_after = process_cpu_time_ns();
    stop.store(true, Ordering::Relaxed);

    let mut merged = LatencyHistogram::new();
    client_rt.block_on(async {
        for handle in task_handles {
            match tokio::time::timeout(Duration::from_secs(2), handle).await {
                Ok(Ok(histogram)) => {
                    for &sample in histogram.samples() {
                        merged.record(sample);
                    }
                }
                Ok(Err(_join_err)) => {}
                Err(_timeout) => {}
            }
        }
    });

    client_rt.shutdown_timeout(Duration::from_secs(1));

    let total_ops = ops.load(Ordering::Relaxed);
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

    BenchResult {
        ops_per_sec,
        latency: merged.finalize(),
        cpu_ns: cpu_after.saturating_sub(cpu_before),
    }
}

fn run_bench_ringline(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
) -> BenchResult {
    // For now, fall back to tokio client for ringline client benchmarks
    // This will be replaced with actual ringline client implementation
    run_bench_tokio(addr, num_clients, msg_size, warmup, duration, stop, ops)
}

/// Run a full benchmark matrix for a single transport/protocol combination.
pub fn run_benchmark_matrix(
    port_manager: &PortManager,
    workers: usize,
    definition: &BenchmarkDefinition,
) -> Vec<ConfigResult> {
    let mut results: Vec<ConfigResult> = Vec::new();
    let mut port: u16 = 19400;

    let combinations = definition.combinations();

    for combo in &combinations {
        // Find a free port for this server
        let mut server_addr = None;
        for attempt in 0..100 {
            let try_port = port_manager.next_port();
            let try_addr: SocketAddr = format!("127.0.0.1:{}", try_port).parse().unwrap();
            if std::net::TcpStream::connect(&try_addr).is_err() {
                server_addr = Some(try_addr);
                break;
            }
            if attempt == 99 {
                eprintln!("  no free port found after 100 attempts");
                break;
            }
        }

        let server_addr = match server_addr {
            Some(a) => a,
            None => continue,
        };

        let addr_str = server_addr.to_string();

        // Start the server
        match start_tcp_echo_server(port_manager, workers, combo.size) {
            Ok(server) => {
                let client_label = match definition.client_runtime {
                    crate::bench::ClientRuntime::Ringline => "ringline",
                    crate::bench::ClientRuntime::Tokio => "tokio",
                };

                let server_label = match definition.server_runtime {
                    crate::bench::ServerRuntime::Ringline => "ringline",
                    crate::bench::ServerRuntime::Tokio => "tokio",
                };

                eprint!(
                    "  {:>8} -> {:<8}  {:>4}c x {:>5}: ",
                    client_label,
                    server_label,
                    combo.concurrency,
                    crate::stats::format_size(combo.size),
                );

                let tokio_ringline = run_bench(
                    &addr_str,
                    combo.concurrency,
                    combo.size,
                    definition.warmup,
                    definition.duration,
                    crate::bench::ClientRuntime::Tokio,
                );
                eprintln!(
                    "{:>9.0} ops/s  p50: {}  p99: {}",
                    tokio_ringline.ops_per_sec,
                    crate::stats::format_ns(tokio_ringline.latency.p50_ns),
                    crate::stats::format_ns(tokio_ringline.latency.p99_ns),
                );

                let ringline_ringline = run_bench(
                    &addr_str,
                    combo.concurrency,
                    combo.size,
                    definition.warmup,
                    definition.duration,
                    crate::bench::ClientRuntime::Ringline,
                );

                server.stop();
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("  server start failed: {}", e);
                continue;
            }
        }
    }

    results
}
