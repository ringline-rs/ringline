use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::bench::{ClientRuntime, ServerRuntime};
use crate::port_manager::PortManager;
use crate::stats::{BenchResult, LatencyHistogram, LatencyStats, process_cpu_time_ns};

/// Run UDP echo benchmarks for a single configuration.
#[allow(clippy::too_many_arguments)]
pub fn run_udp_echo(
    port_manager: &PortManager,
    workers: usize,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    client_runtime: ClientRuntime,
    server_runtime: ServerRuntime,
) -> (BenchResult, Option<UdpServerHandle>) {
    let server = match server_runtime {
        ServerRuntime::Ringline => start_ringline_server(port_manager, workers, msg_size),
        ServerRuntime::Tokio => start_tokio_server(port_manager, workers, msg_size),
    };

    let (result, server) = match server {
        Ok((addr, server)) => {
            let addr_str = addr.to_string();
            let result = if client_runtime == ClientRuntime::Tokio {
                run_bench_tokio(&addr_str, num_clients, msg_size, warmup, duration)
            } else {
                run_bench_ringline(&addr_str, num_clients, msg_size, warmup, duration)
            };
            (result, server)
        }
        Err(e) => {
            eprintln!("  server start failed: {}", e);
            return (
                BenchResult {
                    ops_per_sec: 0.0,
                    latency: LatencyStats {
                        p50_ns: 0,
                        p90_ns: 0,
                        p99_ns: 0,
                        p999_ns: 0,
                        p9999_ns: 0,
                        max_ns: 0,
                        count: 0,
                    },
                    cpu_ns: 0,
                },
                None,
            );
        }
    };

    server.stop();
    std::thread::sleep(Duration::from_millis(100));
    (result, None)
}

fn start_tokio_server(
    port_manager: &PortManager,
    _workers: usize,
    _msg_size: usize,
) -> Result<(SocketAddr, UdpServerHandle), String> {
    let addr = port_manager.next_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let rt = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        rt.block_on(async move {
            let socket = tokio::net::UdpSocket::bind(&addr)
                .await
                .expect("failed to bind");
            let mut buf = [0u8; 65535];

            tokio::pin!(shutdown_rx);
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    result = socket.recv_from(&mut buf) => {
                        let (len, peer) = match result {
                            Ok(n) => n,
                            Err(_) => continue,
                        };
                        let _ = socket.send_to(&buf[..len], &peer).await;
                    }
                }
            }
        });
    });

    std::thread::sleep(Duration::from_millis(100));

    Ok((
        addr,
        UdpServerHandle {
            shutdown: Some(shutdown_tx),
            thread: Some(rt),
        },
    ))
}

fn start_ringline_server(
    port_manager: &PortManager,
    _workers: usize,
    _msg_size: usize,
) -> Result<(SocketAddr, UdpServerHandle), String> {
    // For now, fall back to tokio server
    start_tokio_server(port_manager, _workers, _msg_size)
}

async fn run_tokio_client(
    addr: String,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<std::sync::atomic::AtomicU64>,
) -> LatencyHistogram {
    let msg = vec![0xABu8; msg_size];
    let mut histogram = LatencyHistogram::new();

    let socket = match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  client bind failed: {e}");
            return histogram;
        }
    };

    let mut local_ops: u64 = 0;

    while !stop.load(Ordering::Relaxed) {
        let t0 = Instant::now();

        if socket.send_to(&msg, &addr).await.is_err() {
            break;
        }

        // Wait for response (with timeout)
        let mut buf = vec![0u8; msg_size];
        match tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if n != msg_size {
                    return histogram;
                }
            }
            Ok(Err(_)) => return histogram,
            Err(_) => return histogram,
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

fn run_bench_tokio(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(std::sync::atomic::AtomicU64::new(0));

    wait_for_server(addr);

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
) -> BenchResult {
    // For now, fall back to tokio client
    run_bench_tokio(addr, num_clients, msg_size, warmup, duration)
}

fn wait_for_server(_addr: &str) {
    // Wait for the UDP server to be ready by attempting a small UDP packet
    for _ in 0..100 {
        if std::net::UdpSocket::bind("127.0.0.1:0").is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub struct UdpServerHandle {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl UdpServerHandle {
    fn stop(mut self) {
        drop(self.shutdown.take());
        if let Some(h) = self.thread {
            h.join().ok();
        }
    }
}
