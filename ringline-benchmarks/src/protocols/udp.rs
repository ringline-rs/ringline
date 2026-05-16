use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
                run_bench_tokio(
                    port_manager,
                    &addr_str,
                    num_clients,
                    msg_size,
                    warmup,
                    duration,
                )
            } else {
                run_bench_ringline(
                    port_manager,
                    &addr_str,
                    num_clients,
                    msg_size,
                    warmup,
                    duration,
                )
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

// ── Tokio server ────────────────────────────────────────────────────

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
        UdpServerHandle::Tokio {
            shutdown: Some(shutdown_tx),
            thread: Some(rt),
        },
    ))
}

// ── Ringline server ─────────────────────────────────────────────────

struct RinglineUdpEchoHandler;

impl ringline::AsyncEventHandler for RinglineUdpEchoHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(
        &self,
        _conn: ringline::ConnCtx,
    ) -> impl std::future::Future<Output = ()> + 'static {
        async {}
    }

    fn create_for_worker(_id: usize) -> Self {
        RinglineUdpEchoHandler
    }

    fn on_udp_bind(
        &self,
        udp: ringline::UdpCtx,
    ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>> {
        Some(Box::pin(async move {
            loop {
                let (data, peer) = udp.recv_from().await;
                loop {
                    match udp.send_to(peer, &data) {
                        Ok(()) => break,
                        Err(ringline::UdpSendError::PoolExhausted)
                        | Err(ringline::UdpSendError::SubmissionQueueFull) => {
                            udp.send_ready().await;
                        }
                        Err(_) => break,
                    }
                }
            }
        }))
    }
}

fn start_ringline_server(
    port_manager: &PortManager,
    _workers: usize,
    msg_size: usize,
) -> Result<(SocketAddr, UdpServerHandle), String> {
    let addr = port_manager.next_addr();

    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 1024;
    config.udp_recv_buffer.ring_size = 256;
    // Each buffer holds the recvmsg header (~160 bytes) plus the payload.
    config.udp_recv_buffer.buffer_size = (msg_size + 4096).min(65535) as u32;
    config.udp_send_slots = 256;
    config.udp_recv_queue_capacity = 4096;
    // Send copy pool slot must fit the largest datagram the server echoes.
    config.send_copy_slot_size = msg_size.next_power_of_two().max(16384) as u32;
    config.standalone_task_capacity = 64;

    let (shutdown, handles) = ringline::RinglineBuilder::new(config)
        .bind_udp(addr)
        .launch::<RinglineUdpEchoHandler>()
        .map_err(|e| format!("ringline UDP server launch failed: {e}"))?;

    std::thread::sleep(Duration::from_millis(100));

    Ok((
        addr,
        UdpServerHandle::Ringline {
            shutdown: Some(shutdown),
            handles,
        },
    ))
}

// ── Tokio client ────────────────────────────────────────────────────

async fn run_tokio_client(
    addr: String,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
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
    _port_manager: &PortManager,
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));

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

struct RinglineUdpClientState {
    server_addr: SocketAddr,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
}

static RINGLINE_UDP_CLIENT_CFG: Mutex<Option<Arc<RinglineUdpClientState>>> = Mutex::new(None);

struct RinglineUdpClient;

impl ringline::AsyncEventHandler for RinglineUdpClient {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(
        &self,
        _conn: ringline::ConnCtx,
    ) -> impl std::future::Future<Output = ()> + 'static {
        async {}
    }

    fn create_for_worker(_id: usize) -> Self {
        RinglineUdpClient
    }

    fn on_udp_bind(
        &self,
        udp: ringline::UdpCtx,
    ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>> {
        let state = RINGLINE_UDP_CLIENT_CFG.lock().ok()?.as_ref()?.clone();
        Some(Box::pin(async move {
            let msg = vec![0xABu8; state.msg_size];
            let mut local_ops: u64 = 0;
            let expected_len = state.msg_size;

            while !state.stop.load(Ordering::Relaxed) {
                let t0 = Instant::now();

                // Send_to with the connected peer hits the lighter
                // `IORING_OP_SEND` path inside ringline; no per-send msghdr
                // setup, no kernel copy_from_user of msghdr/iovec/sockaddr.
                loop {
                    match udp.send_to(state.server_addr, &msg) {
                        Ok(()) => break,
                        Err(ringline::UdpSendError::PoolExhausted)
                        | Err(ringline::UdpSendError::SubmissionQueueFull) => {
                            udp.send_ready().await;
                        }
                        Err(_) => {
                            state.ops.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
                            return;
                        }
                    }
                }

                // with_datagram() runs the callback over the kernel-provided
                // buffer directly — no Vec allocation per RTT.
                let ok = udp
                    .with_datagram(|data, _peer| data.len() == expected_len)
                    .await;
                if !ok {
                    state.ops.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
                    return;
                }

                let elapsed_ns = t0.elapsed().as_nanos() as u64;
                state.sample_tx.try_send(elapsed_ns).ok();

                local_ops += 1;
                if local_ops & 0xFF == 0 {
                    state.ops.fetch_add(256, Ordering::Relaxed);
                }
            }

            state.ops.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
        }))
    }
}

fn run_bench_ringline(
    port_manager: &PortManager,
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
        let mut guard = RINGLINE_UDP_CLIENT_CFG.lock().unwrap();
        *guard = Some(Arc::new(RinglineUdpClientState {
            server_addr: addr.parse().expect("invalid server addr"),
            msg_size,
            stop: stop.clone(),
            ops: ops.clone(),
            sample_tx,
        }));
    }

    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = (num_clients * 4).next_power_of_two().max(256) as u32;
    config.udp_recv_buffer.ring_size = (num_clients * 2).next_power_of_two().max(64) as u16;
    // Each buffer holds the recvmsg header (~160 bytes) plus the payload.
    config.udp_recv_buffer.buffer_size = (msg_size + 4096).min(65535) as u32;
    config.udp_send_slots = (num_clients * 2).next_power_of_two().max(64) as u16;
    config.udp_recv_queue_capacity = 4096;
    // Send copy pool slot must fit the largest datagram a client transmits.
    config.send_copy_slot_size = msg_size.next_power_of_two().max(16384) as u32;
    config.standalone_task_capacity = (num_clients + 4).next_power_of_two().max(64) as u32;

    let server_addr: SocketAddr = addr.parse().expect("invalid server addr");
    let mut builder = ringline::RinglineBuilder::new(config);
    for _ in 0..num_clients {
        // Each client binds an ephemeral local port and `connect()`s to the
        // server. Connected sockets get the lighter RecvUdp/SendUdp opcode
        // path inside the runtime.
        builder = builder.bind_udp_connected(port_manager.next_addr(), server_addr);
    }

    let (shutdown, handles) = match builder.launch::<RinglineUdpClient>() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  ringline UDP client launch failed: {e}");
            RINGLINE_UDP_CLIENT_CFG.lock().unwrap().take();
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

    RINGLINE_UDP_CLIENT_CFG.lock().unwrap().take();

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

// ── Server handle ───────────────────────────────────────────────────

pub enum UdpServerHandle {
    Tokio {
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    },
    Ringline {
        shutdown: Option<ringline::ShutdownHandle>,
        handles: Vec<std::thread::JoinHandle<Result<(), ringline::error::Error>>>,
    },
}

impl UdpServerHandle {
    fn stop(self) {
        match self {
            UdpServerHandle::Tokio {
                mut shutdown,
                mut thread,
            } => {
                drop(shutdown.take());
                if let Some(h) = thread.take() {
                    h.join().ok();
                }
            }
            UdpServerHandle::Ringline {
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
