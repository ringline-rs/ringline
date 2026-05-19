use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::bench::{ClientRuntime, ServerRuntime};
use crate::port_manager::PortManager;
use crate::stats::{BenchResult, LatencyHistogram, LatencyStats, process_cpu_time_ns};

/// Run an HTTP/3 benchmark for one configuration.
///
/// Workload: one QUIC connection, up to `num_clients` concurrent
/// bidirectional H3 request streams. Each stream sends a POST with an
/// `msg_size`-byte body, server echoes the body back in a DATA frame
/// with FIN. As soon as a stream completes the client opens a
/// replacement so the in-flight count stays at `num_clients`.
///
/// Both sides drive `ringline_h3::H3Connection` on top of
/// `ringline_quic::QuicEndpoint` from a `ringline` worker task.
/// There is no tokio reference cell here: HTTP/3 client crates that
/// fit the tokio model (`h3` + `h3-quinn`) are heavyweight extra
/// dependencies and the QUIC bench already covers the quinn path.
#[allow(clippy::too_many_arguments)]
pub fn run_http3(
    port_manager: &PortManager,
    _workers: usize,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    _client_runtime: ClientRuntime,
    _server_runtime: ServerRuntime,
) -> BenchResult {
    let (certs, key) = generate_self_signed();
    let server_addr = port_manager.next_addr();

    let server = match start_h3_server(server_addr, certs.clone(), key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  h3 server start failed: {}", e);
            return empty_result();
        }
    };

    let result = run_bench_ringline(server_addr, certs, num_clients, msg_size, warmup, duration);

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
    let mut cc = quinn_proto::ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("quic client config"),
    ));
    let mut tp = quinn_proto::TransportConfig::default();
    tp.max_concurrent_bidi_streams(1024u32.into());
    tp.max_concurrent_uni_streams(1024u32.into());
    cc.transport_config(Arc::new(tp));
    cc
}

// ── Server (ringline + QuicEndpoint + H3Connection) ─────────────────

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

struct H3EchoHandler;

impl ringline::AsyncEventHandler for H3EchoHandler {
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
        let mut h3 = ringline_h3::H3Connection::new(ringline_h3::Settings::default());
        // 64 MiB ceiling: enough for many concurrent in-flight streams at the
        // bench's largest msg_size; protects against runaway memory if a
        // remote peer stalls.
        h3.set_max_pending_bytes(64 * 1024 * 1024);

        // Per-stream body accumulator so we can echo back the full body
        // once we see end_stream.
        let mut bodies: HashMap<u64, Vec<u8>> = HashMap::new();

        Some(Box::pin(async move {
            loop {
                match ringline::select(udp.recv_from(), ringline::sleep(Duration::from_millis(1)))
                    .await
                {
                    ringline::Either::Left((data, peer)) => {
                        quic.handle_datagram(Instant::now(), &data, peer);
                    }
                    ringline::Either::Right(()) => {}
                }
                quic.drive_timers(Instant::now());

                while let Some(event) = quic.poll_event() {
                    let _ = h3.handle_quic_event(&mut quic, &event);
                }

                while let Some(event) = h3.poll_event() {
                    match event {
                        ringline_h3::H3Event::Request {
                            stream_id,
                            end_stream,
                            ..
                        } => {
                            if end_stream {
                                // GET-style: empty body, reply with empty body.
                                let resp = vec![ringline_h3::HeaderField::new(b":status", b"200")];
                                let _ = h3.send_response(&mut quic, stream_id, &resp, false);
                                let _ = h3.send_data(&mut quic, stream_id, b"", true);
                            } else {
                                bodies.insert(u64::from(stream_id), Vec::new());
                            }
                        }
                        ringline_h3::H3Event::Data {
                            stream_id,
                            data,
                            end_stream,
                        } => {
                            let key = u64::from(stream_id);
                            let entry = bodies.entry(key).or_default();
                            entry.extend_from_slice(&data);
                            if end_stream {
                                let body = bodies.remove(&key).unwrap_or_default();
                                let resp = vec![ringline_h3::HeaderField::new(b":status", b"200")];
                                let _ = h3.send_response(&mut quic, stream_id, &resp, false);
                                let _ = h3.send_data(&mut quic, stream_id, &body, true);
                            }
                        }
                        ringline_h3::H3Event::StreamReset { stream_id, .. } => {
                            bodies.remove(&u64::from(stream_id));
                        }
                        _ => {}
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
        H3EchoHandler
    }
}

fn start_h3_server(
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
        .launch::<H3EchoHandler>()
        .map_err(|e| format!("ringline h3 server launch failed: {e}"))?;

    std::thread::sleep(Duration::from_millis(200));

    Ok(BenchmarkServer {
        shutdown: Some(shutdown),
        handles,
    })
}

// ── Ringline H3 client ──────────────────────────────────────────────

struct RinglineH3State {
    server_addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    num_clients: usize,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
}

static RINGLINE_H3_CFG: Mutex<Option<Arc<RinglineH3State>>> = Mutex::new(None);

struct RinglineH3Bench;

struct PendingReq {
    start: Instant,
    bytes_read: usize,
    got_response_headers: bool,
}

impl ringline::AsyncEventHandler for RinglineH3Bench {
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
        let state = RINGLINE_H3_CFG.lock().ok()?.as_ref()?.clone();
        let client_config = quinn_client_config(&state.certs);
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        Some(Box::pin(async move {
            let quic_config = ringline_quic::QuicConfig::client(client_config);
            let mut quic = ringline_quic::QuicEndpoint::new(quic_config, local_addr);
            let mut h3 = ringline_h3::H3Connection::new(ringline_h3::Settings::default());
            h3.set_max_pending_bytes(64 * 1024 * 1024);

            if let Err(e) = quic.connect(Instant::now(), state.server_addr, "localhost") {
                eprintln!("  ringline-h3 connect failed: {e:?}");
                return;
            }

            let mut in_flight: HashMap<u64, PendingReq> = HashMap::new();
            let payload: Vec<u8> = vec![0xCDu8; state.msg_size];
            let mut local_ops: u64 = 0;
            let mut connected = false;

            loop {
                if state.stop.load(Ordering::Relaxed) {
                    break;
                }

                match ringline::select(udp.recv_from(), ringline::sleep(Duration::from_millis(1)))
                    .await
                {
                    ringline::Either::Left((data, peer)) => {
                        quic.handle_datagram(Instant::now(), &data, peer);
                    }
                    ringline::Either::Right(()) => {}
                }
                quic.drive_timers(Instant::now());

                while let Some(event) = quic.poll_event() {
                    if let ringline_quic::QuicEvent::Connected(_) = event {
                        connected = true;
                    }
                    let _ = h3.handle_quic_event(&mut quic, &event);
                }

                while let Some(event) = h3.poll_event() {
                    match event {
                        ringline_h3::H3Event::Response {
                            stream_id,
                            end_stream,
                            ..
                        } => {
                            let key = u64::from(stream_id);
                            if let Some(req) = in_flight.get_mut(&key) {
                                req.got_response_headers = true;
                                if end_stream {
                                    let elapsed_ns = req.start.elapsed().as_nanos() as u64;
                                    state.sample_tx.try_send(elapsed_ns).ok();
                                    local_ops += 1;
                                    if local_ops & 0xFF == 0 {
                                        state.ops.fetch_add(256, Ordering::Relaxed);
                                    }
                                    in_flight.remove(&key);
                                }
                            }
                        }
                        ringline_h3::H3Event::Data {
                            stream_id,
                            data,
                            end_stream,
                        } => {
                            let key = u64::from(stream_id);
                            if let Some(req) = in_flight.get_mut(&key) {
                                req.bytes_read += data.len();
                                if end_stream {
                                    let elapsed_ns = req.start.elapsed().as_nanos() as u64;
                                    state.sample_tx.try_send(elapsed_ns).ok();
                                    local_ops += 1;
                                    if local_ops & 0xFF == 0 {
                                        state.ops.fetch_add(256, Ordering::Relaxed);
                                    }
                                    in_flight.remove(&key);
                                }
                            }
                        }
                        ringline_h3::H3Event::StreamReset { stream_id, .. } => {
                            in_flight.remove(&u64::from(stream_id));
                        }
                        ringline_h3::H3Event::GoAway { .. } | ringline_h3::H3Event::Error(_) => {
                            return;
                        }
                        _ => {}
                    }
                }

                // Top up to num_clients in-flight requests. Wrap the
                // open + send_request + send_data sequence in a
                // ringline-quic batch so quinn-proto can coalesce all
                // of them into a single GSO segment instead of one
                // sendmsg per call. Same trick as the QUIC bench.
                if connected && in_flight.len() < state.num_clients {
                    let request_headers = [
                        ringline_h3::HeaderField::new(b":method", b"POST"),
                        ringline_h3::HeaderField::new(b":path", b"/echo"),
                        ringline_h3::HeaderField::new(b":scheme", b"https"),
                        ringline_h3::HeaderField::new(b":authority", b"localhost"),
                    ];

                    let mut batch = quic.batch();
                    while in_flight.len() < state.num_clients {
                        let now = Instant::now();
                        let stream = match h3.send_request(&mut batch, &request_headers, false) {
                            Ok(s) => s,
                            Err(_) => break,
                        };
                        // Send body + FIN. If this fails the stream is
                        // already registered with h3 — best-effort
                        // skip and try again next tick.
                        if h3.send_data(&mut batch, stream, &payload, true).is_err() {
                            break;
                        }
                        in_flight.insert(
                            u64::from(stream),
                            PendingReq {
                                start: now,
                                bytes_read: 0,
                                got_response_headers: false,
                            },
                        );
                    }
                    // drop(batch) flushes deferred QUIC transmits.
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

            state.ops.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
            let _ = connected;
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        RinglineH3Bench
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
        let mut guard = RINGLINE_H3_CFG.lock().unwrap();
        *guard = Some(Arc::new(RinglineH3State {
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
        .launch::<RinglineH3Bench>()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  ringline h3 client launch failed: {e}");
            RINGLINE_H3_CFG.lock().unwrap().take();
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

    RINGLINE_H3_CFG.lock().unwrap().take();

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
