use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bench::{ClientRuntime, ServerRuntime};
use crate::port_manager::PortManager;
use crate::stats::{BenchResult, LatencyHistogram, LatencyStats, process_cpu_time_ns};

/// Run TCP echo benchmarks for a single configuration.
#[allow(clippy::too_many_arguments)]
pub fn run_tcp_echo(
    port_manager: &PortManager,
    workers: usize,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    client_runtime: ClientRuntime,
    server_runtime: ServerRuntime,
) -> (BenchResult, Option<BenchmarkServer>) {
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
) -> Result<(SocketAddr, BenchmarkServer), String> {
    let addr = port_manager.next_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

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

            tokio::pin!(shutdown_rx);
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    result = listener.accept() => {
                        let (stream, _) = match result {
                            Ok(conn) => conn,
                            Err(_) => continue,
                        };
                        stream.set_nodelay(true).ok();
                        tokio::spawn(async move {
                            let (mut rd, mut wr) = stream.into_split();
                            tokio::io::copy(&mut rd, &mut wr).await.ok();
                        });
                    }
                }
            }
        });
    });

    std::thread::sleep(Duration::from_millis(100));

    Ok((
        addr,
        BenchmarkServer::Tokio {
            shutdown: Some(shutdown_tx),
            thread: Some(rt),
        },
    ))
}

/// Native ringline TCP echo server. Echoes via `forward_recv_buf` — the
/// provided recv buffer is handed straight back to a send without an
/// accumulator copy. This is the same echo path the standalone `bench-server`
/// runs (its `#[cfg(has_io_uring)]` direct-echo branch is never enabled in a
/// downstream crate, since that cfg is set only inside the `ringline` crate's
/// own build, so both reduce to this loop).
struct RinglineEchoHandler;

impl ringline::AsyncEventHandler for RinglineEchoHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(
        &self,
        conn: ringline::ConnCtx,
    ) -> impl std::future::Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| {
                        if conn.forward_recv_buf(data).is_err() {
                            return ringline::ParseResult::NeedMore;
                        }
                        ringline::ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        RinglineEchoHandler
    }
}

fn start_ringline_server(
    port_manager: &PortManager,
    _workers: usize,
    msg_size: usize,
) -> Result<(SocketAddr, BenchmarkServer), String> {
    let addr = port_manager.next_addr();

    // Single worker to match the single-machine methodology (1 ringline worker
    // vs 1 tokio current_thread). Mirrors the standalone bench-server config.
    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 256;
    config.recv_buffer.ring_size = 256;
    config.recv_buffer.buffer_size = msg_size.next_power_of_two().max(4096) as u32;
    config.max_connections = 16384;
    config.send_copy_count = 512;
    config.send_copy_slot_size = msg_size.next_power_of_two().max(4096) as u32;

    let (shutdown, handles) = ringline::RinglineBuilder::new(config)
        .bind(addr)
        .launch::<RinglineEchoHandler>()
        .map_err(|e| format!("ringline TCP server launch failed: {e}"))?;

    std::thread::sleep(Duration::from_millis(100));

    Ok((
        addr,
        BenchmarkServer::Ringline {
            shutdown: Some(shutdown),
            handles,
        },
    ))
}

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

fn run_bench_tokio(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));

    wait_for_server(addr);

    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
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

// ── Ringline client ─────────────────────────────────────────────────

struct RinglineClientState {
    addr: SocketAddr,
    msg_size: usize,
    num_clients: usize,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
}

static RINGLINE_CLIENT_CFG: Mutex<Option<Arc<RinglineClientState>>> = Mutex::new(None);

struct RinglineTcpBench;

impl ringline::AsyncEventHandler for RinglineTcpBench {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(
        &self,
        _conn: ringline::ConnCtx,
    ) -> impl std::future::Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(
        &self,
    ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>> {
        let state = RINGLINE_CLIENT_CFG.lock().ok()?.as_ref()?.clone();
        Some(Box::pin(async move {
            for _i in 0..state.num_clients {
                let stop = state.stop.clone();
                let ops = state.ops.clone();
                let sample_tx = state.sample_tx.clone();
                let addr = state.addr;
                let msg_size = state.msg_size;

                // Each client task calls connect() itself so that owner_task[conn_index]
                // is set to this spawned task's ID — not the on_start task's ID.
                // wake_recv() resolves through owner_task, so the correct task is woken
                // when echo data arrives.
                ringline::spawn(async move {
                    let conn = match ringline::connect(addr) {
                        Ok(f) => match f.await {
                            Ok(c) => c,
                            Err(_) => return,
                        },
                        Err(_) => return,
                    };

                    let msg = vec![0xABu8; msg_size];
                    let mut local_ops: u64 = 0;

                    loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }

                        let t0 = Instant::now();

                        if conn.send_nowait(&msg).is_err() {
                            break;
                        }

                        let n = conn
                            .with_data(|data| {
                                if data.len() >= msg_size {
                                    ringline::ParseResult::Consumed(msg_size)
                                } else {
                                    ringline::ParseResult::NeedMore
                                }
                            })
                            .await;

                        if n == 0 {
                            break;
                        }

                        let elapsed_ns = t0.elapsed().as_nanos() as u64;
                        sample_tx.try_send(elapsed_ns).ok();

                        local_ops += 1;
                        if local_ops & 0xFF == 0 {
                            ops.fetch_add(256, Ordering::Relaxed);
                        }
                    }

                    ops.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
                })
                .ok();
            }
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        RinglineTcpBench
    }
}

fn make_ringline_client_config(num_clients: usize, msg_size: usize) -> ringline::Config {
    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    // Each connection needs a send SQE + a recv SQE; add headroom.
    config.sq_entries = (num_clients * 4).next_power_of_two().max(256) as u32;
    // One provided recv buffer in flight per connection.
    config.recv_buffer.ring_size = (num_clients * 2).next_power_of_two().max(64) as u16;
    config.recv_buffer.buffer_size = msg_size.next_power_of_two().max(4096) as u32;
    config.send_copy_slot_size = msg_size.next_power_of_two().max(4096) as u32;
    // One standalone task per connection, plus the on_start task.
    config.standalone_task_capacity = (num_clients + 1).next_power_of_two().max(64) as u32;
    config
}

fn run_bench_ringline(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));
    let (sample_tx, sample_rx) = crossbeam_channel::unbounded::<u64>();

    {
        let mut guard = RINGLINE_CLIENT_CFG.lock().unwrap();
        *guard = Some(Arc::new(RinglineClientState {
            addr: addr.parse().expect("invalid server addr"),
            msg_size,
            num_clients,
            stop: stop.clone(),
            ops: ops.clone(),
            sample_tx,
        }));
    }

    wait_for_server(addr);

    let config = make_ringline_client_config(num_clients, msg_size);
    let (shutdown, handles) =
        match ringline::RinglineBuilder::new(config).launch::<RinglineTcpBench>() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  ringline client launch failed: {e}");
                RINGLINE_CLIENT_CFG.lock().unwrap().take();
                return BenchResult {
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
                };
            }
        };

    std::thread::sleep(warmup);
    ops.store(0, Ordering::Relaxed);

    let cpu_before = process_cpu_time_ns();
    let start = Instant::now();
    std::thread::sleep(duration);
    let elapsed = start.elapsed();
    let cpu_after = process_cpu_time_ns();

    stop.store(true, Ordering::Relaxed);
    shutdown.shutdown();
    for h in handles {
        h.join().ok();
    }

    RINGLINE_CLIENT_CFG.lock().unwrap().take();

    let total_ops = ops.load(Ordering::Relaxed);
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

    let mut histogram = LatencyHistogram::new();
    while let Ok(sample) = sample_rx.try_recv() {
        histogram.record(sample);
    }

    BenchResult {
        ops_per_sec,
        latency: histogram.finalize(),
        cpu_ns: cpu_after.saturating_sub(cpu_before),
    }
}

fn wait_for_server(addr: &str) {
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub enum BenchmarkServer {
    Tokio {
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    },
    Ringline {
        shutdown: Option<ringline::ShutdownHandle>,
        handles: Vec<std::thread::JoinHandle<Result<(), ringline::error::Error>>>,
    },
}

impl BenchmarkServer {
    fn stop(self) {
        match self {
            BenchmarkServer::Tokio {
                mut shutdown,
                mut thread,
            } => {
                drop(shutdown.take());
                if let Some(h) = thread.take() {
                    h.join().ok();
                }
            }
            BenchmarkServer::Ringline {
                mut shutdown,
                handles,
            } => {
                if let Some(s) = shutdown.take() {
                    s.shutdown();
                }
                for h in handles {
                    h.join().ok();
                }
            }
        }
    }
}
