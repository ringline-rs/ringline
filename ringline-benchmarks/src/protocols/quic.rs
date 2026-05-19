use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::bench::{ClientRuntime, ServerRuntime};
use crate::port_manager::PortManager;
use crate::stats::{BenchResult, LatencyHistogram, LatencyStats, process_cpu_time_ns};

/// Run a QUIC benchmark for one configuration.
///
/// Workload: a single QUIC connection multiplexes up to `num_clients`
/// concurrent bidirectional streams. Each stream writes `msg_size`
/// bytes + FIN, then reads the echoed `msg_size` bytes back. As soon
/// as one stream completes the driver opens a replacement, so there
/// are always `num_clients` in-flight at steady state.
///
/// The bench server is a ringline `AsyncEventHandler` that drives
/// `ringline_quic::QuicEndpoint` from `on_udp_bind` — same pattern as
/// `ringline-quic/tests/echo.rs`. The tokio reference client is
/// built on `quinn`, the de-facto tokio QUIC stack. Both sides do a
/// real QUIC handshake (TLS 1.3 + ALPN) against the same
/// self-signed cert.
#[allow(clippy::too_many_arguments)]
pub fn run_quic(
    port_manager: &PortManager,
    _workers: usize,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    client_runtime: ClientRuntime,
    _server_runtime: ServerRuntime,
) -> BenchResult {
    let (certs, key) = generate_self_signed();
    let server_addr = port_manager.next_addr();

    let server = match start_quic_server(server_addr, certs.clone(), key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  quic server start failed: {}", e);
            return empty_result();
        }
    };

    let result = match client_runtime {
        ClientRuntime::Tokio => {
            run_bench_tokio(server_addr, &certs, num_clients, msg_size, warmup, duration)
        }
        _ => run_bench_ringline(server_addr, certs, num_clients, msg_size, warmup, duration),
    };

    server.stop();
    std::thread::sleep(Duration::from_millis(100));
    result
}

fn empty_result() -> BenchResult {
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
    }
}

// ── TLS / QUIC config helpers ───────────────────────────────────────

fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert");
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![CertificateDer::from(cert.cert)], key.into())
}

fn quinn_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Arc<quinn_proto::ServerConfig> {
    let mut sc = quinn_proto::ServerConfig::with_single_cert(certs, key).expect("server config");
    let transport = Arc::get_mut(&mut sc.transport).unwrap();
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.max_concurrent_uni_streams(1024u32.into());
    Arc::new(sc)
}

fn quinn_client_config(certs: &[CertificateDer<'static>]) -> quinn_proto::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert.clone()).expect("add cert");
    }
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    quinn_proto::ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("quic client config"),
    ))
}

// ── Server (ringline + QuicEndpoint) ────────────────────────────────

struct BenchmarkServer {
    shutdown: Option<ringline::ShutdownHandle>,
    handles: Vec<std::thread::JoinHandle<Result<(), ringline::error::Error>>>,
}

impl BenchmarkServer {
    fn stop(mut self) {
        if let Some(sh) = self.shutdown.take() {
            sh.shutdown();
        }
        for h in self.handles.drain(..) {
            h.join().ok();
        }
    }
}

static SERVER_CFG: Mutex<Option<ringline_quic::QuicConfig>> = Mutex::new(None);

struct QuicEchoHandler;

impl ringline::AsyncEventHandler for QuicEchoHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(
        &self,
        _conn: ringline::ConnCtx,
    ) -> impl std::future::Future<Output = ()> + 'static {
        async {}
    }

    fn on_udp_bind(
        &self,
        udp: ringline::UdpCtx,
    ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>> {
        let config = SERVER_CFG.lock().ok()?.take()?;
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut quic = ringline_quic::QuicEndpoint::new(config, local_addr);
        let mut read_buf = vec![0u8; 65536];

        Some(Box::pin(async move {
            loop {
                // Drain up to 8 queued datagrams per wake to amortise
                // executor overhead at high pps without delaying ACK /
                // MAX_STREAM_DATA emission long enough to stall the
                // peer's congestion window.
                // `recv_batch_timed` passes the driver-captured rx
                // timestamp through so quinn-proto's RTT samples are
                // taken at actual arrival, not at user-space dispatch
                // — eliminates the executor wake + task poll latency
                // from CC's view of RTT.
                let recv_fut = udp.recv_batch_timed(8, |data, peer, recv_at| {
                    quic.handle_datagram(recv_at, data, peer);
                });
                ringline::select(recv_fut, ringline::sleep(Duration::from_millis(10))).await;
                quic.drive_timers(Instant::now());

                while let Some(event) = quic.poll_event() {
                    if let ringline_quic::QuicEvent::StreamReadable { conn, stream } = event {
                        loop {
                            let (n, fin) = match quic.stream_recv(conn, stream, &mut read_buf) {
                                Ok(r) => r,
                                Err(_) => break,
                            };
                            if n > 0 {
                                let _ = quic.stream_send(conn, stream, &read_buf[..n]);
                            }
                            if fin {
                                let _ = quic.stream_finish(conn, stream);
                                break;
                            }
                            if n == 0 {
                                break;
                            }
                        }
                    }
                }

                while let Some(pkt) = quic.poll_send() {
                    match pkt.segment_size {
                        Some(seg) => {
                            let _ = udp.send_to_gso(pkt.destination, &pkt.data, seg);
                        }
                        None => {
                            let _ = udp.send_to(pkt.destination, &pkt.data);
                        }
                    }
                }
            }
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        QuicEchoHandler
    }
}

fn start_quic_server(
    addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<BenchmarkServer, String> {
    let server_config = quinn_server_config(certs, key);
    let quic_config = ringline_quic::QuicConfig::server(server_config);

    {
        let mut guard = SERVER_CFG.lock().unwrap();
        *guard = Some(quic_config);
    }

    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 1024;
    config.udp_recv_buffer.ring_size = 512;
    config.udp_recv_buffer.buffer_size = 4096;
    config.udp_send_slots = 256;
    config.udp_recv_queue_capacity = 4096;
    config.send_copy_count = 1024;
    config.send_copy_slot_size = 65536;
    config.standalone_task_capacity = 64;

    let (shutdown, handles) = ringline::RinglineBuilder::new(config)
        .bind_udp(addr)
        .launch::<QuicEchoHandler>()
        .map_err(|e| format!("ringline quic server launch failed: {e}"))?;

    std::thread::sleep(Duration::from_millis(200));

    Ok(BenchmarkServer {
        shutdown: Some(shutdown),
        handles,
    })
}

// ── Ringline QUIC client ────────────────────────────────────────────

struct RinglineQuicState {
    server_addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    num_clients: usize,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
}

static RINGLINE_QUIC_CFG: Mutex<Option<Arc<RinglineQuicState>>> = Mutex::new(None);

struct RinglineQuicBench;

/// Per-in-flight-stream state for the client driver.
#[derive(Clone, Copy)]
enum StreamPhase {
    /// We've written the request and are awaiting the echoed response.
    AwaitingResponse { start: Instant, bytes_read: usize },
}

impl ringline::AsyncEventHandler for RinglineQuicBench {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(
        &self,
        _conn: ringline::ConnCtx,
    ) -> impl std::future::Future<Output = ()> + 'static {
        async {}
    }

    fn on_udp_bind(
        &self,
        udp: ringline::UdpCtx,
    ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>> {
        let state = RINGLINE_QUIC_CFG.lock().ok()?.as_ref()?.clone();
        let client_config = quinn_client_config(&state.certs);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        Some(Box::pin(async move {
            let quic_config = ringline_quic::QuicConfig::client(client_config);
            let mut quic = ringline_quic::QuicEndpoint::new(quic_config, local_addr);

            // Kick off the connection. The handshake is driven by the
            // recv/poll loop below.
            let conn_id = match quic.connect(Instant::now(), state.server_addr, "localhost") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("  ringline-quic connect failed: {e:?}");
                    return;
                }
            };

            let mut read_buf = vec![0u8; 65536];
            let payload: Vec<u8> = vec![0xCDu8; state.msg_size];
            let mut in_flight: HashMap<quinn_proto::StreamId, StreamPhase> = HashMap::new();
            let mut connected = false;
            let mut local_ops: u64 = 0;

            loop {
                if state.stop.load(Ordering::Relaxed) {
                    break;
                }

                // Same batched-drain rationale as the QUIC server above.
                // `recv_batch_timed` passes the driver-captured rx
                // timestamp through so quinn-proto's RTT samples are
                // taken at actual arrival, not at user-space dispatch
                // — eliminates the executor wake + task poll latency
                // from CC's view of RTT.
                let recv_fut = udp.recv_batch_timed(8, |data, peer, recv_at| {
                    quic.handle_datagram(recv_at, data, peer);
                });
                ringline::select(recv_fut, ringline::sleep(Duration::from_millis(1))).await;
                quic.drive_timers(Instant::now());

                while let Some(event) = quic.poll_event() {
                    match event {
                        ringline_quic::QuicEvent::Connected(_) => {
                            connected = true;
                        }
                        ringline_quic::QuicEvent::StreamReadable { conn, stream } => {
                            if let Some(phase) = in_flight.get_mut(&stream) {
                                let StreamPhase::AwaitingResponse { start, bytes_read } = phase;
                                loop {
                                    let (n, fin) =
                                        match quic.stream_recv(conn, stream, &mut read_buf) {
                                            Ok(r) => r,
                                            Err(_) => {
                                                in_flight.remove(&stream);
                                                break;
                                            }
                                        };
                                    if n > 0 {
                                        *bytes_read += n;
                                    }
                                    if fin || (n == 0 && *bytes_read >= state.msg_size) {
                                        let elapsed_ns = start.elapsed().as_nanos() as u64;
                                        state.sample_tx.try_send(elapsed_ns).ok();
                                        local_ops += 1;
                                        if local_ops & 0xFF == 0 {
                                            state.ops.fetch_add(256, Ordering::Relaxed);
                                        }
                                        in_flight.remove(&stream);
                                        break;
                                    }
                                    if n == 0 {
                                        break;
                                    }
                                }
                            } else {
                                // Drain unknown stream to keep flow control happy.
                                let _ = quic.stream_recv(conn, stream, &mut read_buf);
                            }
                        }
                        ringline_quic::QuicEvent::StreamWritable { .. }
                        | ringline_quic::QuicEvent::StreamFinished { .. }
                        | ringline_quic::QuicEvent::StreamStopped { .. }
                        | ringline_quic::QuicEvent::StreamOpened { .. }
                        | ringline_quic::QuicEvent::StreamsAvailable { .. }
                        | ringline_quic::QuicEvent::DatagramReceived { .. }
                        | ringline_quic::QuicEvent::DatagramsUnblocked { .. }
                        | ringline_quic::QuicEvent::HandshakeDataReady { .. }
                        | ringline_quic::QuicEvent::PeerAddressChanged { .. }
                        | ringline_quic::QuicEvent::ZeroRttRejected { .. }
                        | ringline_quic::QuicEvent::NewConnection(_) => {}
                        ringline_quic::QuicEvent::ConnectionClosed { .. } => {
                            return;
                        }
                        _ => {}
                    }
                }

                // Top up to `num_clients` in-flight streams. The
                // `batch()` scope suppresses ringline-quic's per-op
                // `drain_transmits` calls so quinn-proto can coalesce
                // the resulting open / send / finish packets into one
                // GSO segment, which we then hand to the kernel in
                // one syscall via `send_to_gso`. Without batching,
                // each of the three operations per stream emits its
                // own single-datagram poll_transmit, defeating GSO
                // and turning N streams into ~3 N small `sendmsg`
                // calls.
                if connected && in_flight.len() < state.num_clients {
                    // Same payload-size-aware topup cap as the H3
                    // bench. At large payloads (32 KiB) opening 50
                    // streams in one tick floods quinn-proto's send
                    // buffer before recv drains the ACKs that grow
                    // CWND. With small payloads the cost is trivial
                    // and batching helps GSO coalescing.
                    let default_cap = (32 * 1024 / state.msg_size.max(1)).max(1);
                    let topup_cap = std::env::var("RINGLINE_BENCH_TOPUP_CAP")
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(default_cap);
                    let mut opened_this_tick = 0usize;
                    let mut batch = quic.batch();
                    while in_flight.len() < state.num_clients {
                        if opened_this_tick >= topup_cap {
                            break;
                        }
                        match batch.open_bi(conn_id) {
                            Ok(Some(stream)) => {
                                let now = Instant::now();
                                if let Err(_e) = batch.stream_send(conn_id, stream, &payload) {
                                    let _ = batch.reset_stream(
                                        conn_id,
                                        stream,
                                        quinn_proto::VarInt::from_u32(0),
                                    );
                                    break;
                                }
                                let _ = batch.stream_finish(conn_id, stream);
                                opened_this_tick += 1;
                                in_flight.insert(
                                    stream,
                                    StreamPhase::AwaitingResponse {
                                        start: now,
                                        bytes_read: 0,
                                    },
                                );
                            }
                            Ok(None) => break, // out of stream credit
                            Err(_) => break,
                        }
                    }
                    // `batch` dropped here flushes deferred transmits
                    // — quinn-proto now sees all N opens/sends/fins
                    // at once and can emit them as a GSO segment.
                }

                // Flush packets.
                while let Some(pkt) = quic.poll_send() {
                    match pkt.segment_size {
                        Some(seg) => {
                            let _ = udp.send_to_gso(pkt.destination, &pkt.data, seg);
                        }
                        None => {
                            let _ = udp.send_to(pkt.destination, &pkt.data);
                        }
                    }
                }
            }

            state.ops.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        RinglineQuicBench
    }
}

fn run_bench_ringline(
    server_addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));
    let (sample_tx, sample_rx) = crossbeam_channel::unbounded::<u64>();

    {
        let mut guard = RINGLINE_QUIC_CFG.lock().unwrap();
        *guard = Some(Arc::new(RinglineQuicState {
            server_addr,
            certs,
            num_clients,
            msg_size,
            stop: stop.clone(),
            ops: ops.clone(),
            sample_tx,
        }));
    }

    let client_bind: SocketAddr = "0.0.0.0:0".parse().unwrap();

    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 1024;
    config.udp_recv_buffer.ring_size = 512;
    config.udp_recv_buffer.buffer_size = 4096;
    config.udp_send_slots = 256;
    config.udp_recv_queue_capacity = 4096;
    config.send_copy_count = 1024;
    config.send_copy_slot_size = 65536;
    config.standalone_task_capacity = 64;

    let (shutdown, handles) = match ringline::RinglineBuilder::new(config)
        .bind_udp(client_bind)
        .launch::<RinglineQuicBench>()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  ringline quic client launch failed: {e}");
            RINGLINE_QUIC_CFG.lock().unwrap().take();
            return empty_result();
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

    RINGLINE_QUIC_CFG.lock().unwrap().take();

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

// ── Tokio reference client (quinn) ──────────────────────────────────

async fn run_quinn_stream_loop(
    conn: quinn::Connection,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
) {
    let payload: Vec<u8> = vec![0xCDu8; msg_size];
    let mut local_ops: u64 = 0;
    let mut recv_buf = vec![0u8; msg_size + 64];

    while !stop.load(Ordering::Relaxed) {
        let t0 = Instant::now();
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };
        if send.write_all(&payload).await.is_err() {
            break;
        }
        if send.finish().is_err() {
            break;
        }

        let mut total = 0;
        loop {
            match recv.read(&mut recv_buf[..]).await {
                Ok(None) => break,
                Ok(Some(n)) => total += n,
                Err(_) => return,
            }
            if total >= msg_size {
                break;
            }
        }
        let elapsed_ns = t0.elapsed().as_nanos() as u64;
        sample_tx.try_send(elapsed_ns).ok();

        local_ops += 1;
        if local_ops & 0xFF == 0 {
            ops_counter.fetch_add(256, Ordering::Relaxed);
        }
    }
    ops_counter.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
}

fn run_bench_tokio(
    server_addr: SocketAddr,
    certs: &[CertificateDer<'static>],
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));
    let (sample_tx, sample_rx) = crossbeam_channel::unbounded::<u64>();

    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("failed to build client runtime");

    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert.clone()).expect("add cert");
    }
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("quic client config"),
    ));
    let mut tp = quinn_proto::TransportConfig::default();
    tp.max_concurrent_bidi_streams(1024u32.into());
    tp.max_concurrent_uni_streams(1024u32.into());
    client_cfg.transport_config(Arc::new(tp));

    let conn = client_rt.block_on(async {
        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("quinn endpoint");
        endpoint.set_default_client_config(client_cfg);
        endpoint
            .connect(server_addr, "localhost")
            .expect("connect submit")
            .await
            .expect("connect await")
    });

    let mut task_handles = Vec::with_capacity(num_clients);
    for _ in 0..num_clients {
        let conn = conn.clone();
        let stop = stop.clone();
        let ops = ops.clone();
        let sample_tx = sample_tx.clone();
        task_handles
            .push(client_rt.spawn(run_quinn_stream_loop(conn, msg_size, stop, ops, sample_tx)));
    }

    std::thread::sleep(warmup);
    ops.store(0, Ordering::Relaxed);

    let cpu_before = process_cpu_time_ns();
    let start = Instant::now();
    std::thread::sleep(duration);
    let elapsed = start.elapsed();
    let cpu_after = process_cpu_time_ns();
    stop.store(true, Ordering::Relaxed);

    client_rt.block_on(async {
        for handle in task_handles {
            if let Ok(Ok(())) = tokio::time::timeout(Duration::from_secs(2), handle).await {
                // collected via sample_tx
            }
        }
    });

    client_rt.shutdown_timeout(Duration::from_secs(1));

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
