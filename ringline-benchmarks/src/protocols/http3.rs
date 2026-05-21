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
/// The server is a `ringline` `AsyncEventHandler` driving
/// `ringline_h3::H3Connection` on top of `ringline_quic::QuicEndpoint`.
/// The ringline client uses the same stack from another worker task;
/// the tokio reference client is `h3` + `h3-quinn` — the canonical
/// tokio HTTP/3 stack — running on quinn for the transport. Both
/// sides do a real TLS 1.3 + ALPN (`h3`) handshake against the same
/// self-signed cert.
#[allow(clippy::too_many_arguments)]
pub fn run_http3(
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

    // Publish the body size so the echo server can size its
    // per-iteration response cap to match the workload.
    SERVER_MSG_SIZE.store(msg_size as u64, Ordering::Relaxed);

    let server = match start_h3_server(server_addr, certs.clone(), key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  h3 server start failed: {}", e);
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

/// Drain completed H3 responses on the client, recording latency samples
/// and op counts. Returns true if the loop should stop (GoAway / Error).
fn drain_client_h3_events(
    h3: &mut ringline_h3::H3Connection,
    in_flight: &mut HashMap<u64, PendingReq>,
    local_ops: &mut u64,
    state: &RinglineH3State,
) -> bool {
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
                        *local_ops += 1;
                        if *local_ops & 0xFF == 0 {
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
                        *local_ops += 1;
                        if *local_ops & 0xFF == 0 {
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
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Open replacement request streams up to `num_clients` in flight. Send
/// generation goes through `quic` — a `BatchGuard` via deref coercion, so
/// the resulting transmits are deferred to the batch's flush.
#[allow(clippy::too_many_arguments)]
fn topup_requests(
    h3: &mut ringline_h3::H3Connection,
    quic: &mut ringline_quic::QuicEndpoint,
    in_flight: &mut HashMap<u64, PendingReq>,
    payload: &bytes::Bytes,
    num_clients: usize,
    msg_size: usize,
    connected: bool,
) {
    if !connected || in_flight.len() >= num_clients {
        return;
    }
    let request_headers = [
        ringline_h3::HeaderField::new(b":method", b"POST"),
        ringline_h3::HeaderField::new(b":path", b"/echo"),
        ringline_h3::HeaderField::new(b":scheme", b"https"),
        ringline_h3::HeaderField::new(b":authority", b"localhost"),
    ];
    let default_cap = (32 * 1024 / msg_size.max(1)).max(1);
    let topup_cap = std::env::var("RINGLINE_BENCH_TOPUP_CAP")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default_cap);
    let mut opened_this_tick = 0usize;
    while in_flight.len() < num_clients {
        if topup_cap > 0 && opened_this_tick >= topup_cap {
            break;
        }
        let now = Instant::now();
        let stream = match h3.send_request(quic, &request_headers, false) {
            Ok(s) => s,
            Err(_) => break,
        };
        if h3
            .send_data_bytes(quic, stream, payload.clone(), true)
            .is_err()
        {
            break;
        }
        opened_this_tick += 1;
        in_flight.insert(
            u64::from(stream),
            PendingReq {
                start: now,
                bytes_read: 0,
                got_response_headers: false,
            },
        );
    }
}

/// Echo completed H3 request bodies back to the client, up to `resp_cap`
/// responses per call. Send generation goes through `quic` (a
/// `BatchGuard` via deref coercion).
fn echo_responses(
    h3: &mut ringline_h3::H3Connection,
    quic: &mut ringline_quic::QuicEndpoint,
    bodies: &mut HashMap<u64, Vec<u8>>,
    resp_cap: usize,
) {
    let mut responded = 0usize;
    while responded < resp_cap
        && let Some(event) = h3.poll_event()
    {
        match event {
            ringline_h3::H3Event::Request {
                stream_id,
                end_stream,
                ..
            } => {
                if end_stream {
                    let resp = vec![ringline_h3::HeaderField::new(b":status", b"200")];
                    let _ = h3.send_response(quic, stream_id, &resp, false);
                    let _ = h3.send_data_bytes(quic, stream_id, bytes::Bytes::new(), true);
                    responded += 1;
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
                    let _ = h3.send_response(quic, stream_id, &resp, false);
                    // `Bytes::from(Vec<u8>)` is O(1) — takes ownership of
                    // the Vec's buffer without copying the body bytes.
                    let _ = h3.send_data_bytes(quic, stream_id, bytes::Bytes::from(body), true);
                    responded += 1;
                }
            }
            ringline_h3::H3Event::StreamReset { stream_id, .. } => {
                bodies.remove(&u64::from(stream_id));
            }
            _ => {}
        }
    }
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

const H3_ALPN: &[u8] = b"h3";

fn quinn_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Arc<quinn_proto::ServerConfig> {
    // Build a rustls ServerConfig directly so we can advertise the
    // `h3` ALPN. `h3-quinn` (the tokio reference) requires this for
    // the handshake to complete.
    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server cert");
    tls_cfg.alpn_protocols = vec![H3_ALPN.to_vec()];
    let qsc =
        quinn_proto::crypto::rustls::QuicServerConfig::try_from(tls_cfg).expect("quic server tls");
    let mut sc = quinn_proto::ServerConfig::with_crypto(Arc::new(qsc));
    let transport = Arc::get_mut(&mut sc.transport).unwrap();
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.max_concurrent_uni_streams(1024u32.into());
    // Default 333 ms initial RTT comes from RFC 9002. On localhost
    // it makes the pacer wildly over-conservative during the
    // pre-first-ACK phase. 1 ms is closer to reality and lets the
    // first burst of packets actually use the available bandwidth
    // instead of being throttled.
    transport.initial_rtt(Duration::from_millis(1));
    Arc::new(sc)
}

fn quinn_client_config(certs: &[CertificateDer<'static>]) -> quinn_proto::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert.clone()).expect("add cert");
    }
    let mut tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![H3_ALPN.to_vec()];
    let qcc =
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(tls_cfg).expect("quic client tls");
    let mut cc = quinn_proto::ClientConfig::new(Arc::new(qcc));
    let mut tp = quinn_proto::TransportConfig::default();
    tp.max_concurrent_bidi_streams(1024u32.into());
    tp.max_concurrent_uni_streams(1024u32.into());
    tp.initial_rtt(Duration::from_millis(1));
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
/// Body size for the current bench config, published so the echo
/// server can size its per-iteration response cap (same payload-aware
/// heuristic as the client's topup cap).
static SERVER_MSG_SIZE: AtomicU64 = AtomicU64::new(0);

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
                // Cap responses generated per loop iteration. At 32 KiB,
                // echoing 50 responses in one drain dumps 1.6 MiB into
                // quinn-proto's send buffer and stalls recv (so the ACKs
                // growing the server's CWND don't get processed). Leave
                // un-responded events queued in H3Connection for the next
                // iteration. Override via RINGLINE_BENCH_RESP_CAP.
                let resp_cap = std::env::var("RINGLINE_BENCH_RESP_CAP")
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or_else(|| {
                        let msg = SERVER_MSG_SIZE.load(Ordering::Relaxed).max(1) as usize;
                        (32 * 1024 / msg).max(1)
                    });

                // Hold one `quic.batch()` across the whole recv → process
                // → echo phase. This defers quinn-proto's `poll_transmit`
                // to a single pass at batch-drop time — coalescing the
                // iteration's entire send backlog into max-size GSO
                // super-packets — instead of running it once per received
                // datagram inside `handle_datagram` (which, with only an
                // ACK or two queued each time, produced 3-4-segment GSO
                // buffers and ~10× the `sendmsg` syscalls). At 32 KiB the
                // per-datagram drain spent ~20% of CPU in `io_sendmsg`.
                // The recv callback reaches `handle_datagram` through the
                // guard's `DerefMut`, so the batch stays open across recv.
                {
                    let mut batch = quic.batch();
                    let recv_fut = udp.recv_batch_timed(8, |data, peer, recv_at| {
                        batch.handle_datagram(recv_at, data, peer);
                    });
                    ringline::select(recv_fut, ringline::sleep(Duration::from_millis(1))).await;
                    batch.drive_timers(Instant::now());

                    while let Some(event) = batch.poll_event() {
                        let _ = h3.handle_quic_event(&mut batch, &event);
                    }

                    echo_responses(&mut h3, &mut batch, &mut bodies, resp_cap);
                    // drop(batch) flushes deferred transmits as GSO.
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
            // Cache the payload as a refcounted `Bytes` once.
            // `send_data_bytes` clones the refcount (O(1)) instead of
            // copying msg_size bytes per call like `send_data` would
            // — critical at 32 KiB × hundreds of in-flight streams.
            let payload = bytes::Bytes::from(vec![0xCDu8; state.msg_size]);
            let mut local_ops: u64 = 0;
            let mut connected = false;

            loop {
                if state.stop.load(Ordering::Relaxed) {
                    break;
                }

                // Hold a single `quic.batch()` across the whole recv →
                // process → topup phase so quinn-proto's `poll_transmit`
                // runs once per loop iteration (coalescing the iteration's
                // entire send backlog into max-size GSO super-packets)
                // instead of once per received datagram inside
                // `handle_datagram` — which, with only an ACK or two queued
                // each time, produced 3-4-segment GSO buffers and ~10× the
                // `sendmsg` syscalls (~20% of CPU in `io_sendmsg` at
                // 32 KiB). The recv callback reaches `handle_datagram`
                // through the guard's `DerefMut`. See the H3 server above
                // for the matching change; both ends needed it.
                let mut stop = false;
                {
                    let mut batch = quic.batch();
                    let recv_fut = udp.recv_batch_timed(8, |data, peer, recv_at| {
                        batch.handle_datagram(recv_at, data, peer);
                    });
                    ringline::select(recv_fut, ringline::sleep(Duration::from_millis(1))).await;
                    batch.drive_timers(Instant::now());

                    while let Some(event) = batch.poll_event() {
                        if let ringline_quic::QuicEvent::Connected(_) = event {
                            connected = true;
                        }
                        let _ = h3.handle_quic_event(&mut batch, &event);
                    }

                    if drain_client_h3_events(&mut h3, &mut in_flight, &mut local_ops, &state) {
                        stop = true;
                    } else {
                        topup_requests(
                            &mut h3,
                            &mut batch,
                            &mut in_flight,
                            &payload,
                            state.num_clients,
                            state.msg_size,
                            connected,
                        );
                    }
                    // drop(batch) flushes deferred QUIC transmits as GSO.
                }
                if stop {
                    break;
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

// ── Tokio reference client (h3 + h3-quinn) ──────────────────────────

async fn run_h3_request_loop(
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
) {
    let payload = bytes::Bytes::from(vec![0xCDu8; msg_size]);
    let mut local_ops: u64 = 0;
    let mut send_request = send_request;

    while !stop.load(Ordering::Relaxed) {
        let req = match http::Request::builder()
            .method("POST")
            .uri("https://localhost/echo")
            .body(())
        {
            Ok(r) => r,
            Err(_) => break,
        };

        let t0 = Instant::now();
        let mut stream = match send_request.send_request(req).await {
            Ok(s) => s,
            Err(_) => break,
        };
        if stream.send_data(payload.clone()).await.is_err() {
            break;
        }
        if stream.finish().await.is_err() {
            break;
        }
        if stream.recv_response().await.is_err() {
            break;
        }
        loop {
            match stream.recv_data().await {
                Ok(Some(_chunk)) => {}
                Ok(None) => break,
                Err(_) => return,
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
    let mut tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![H3_ALPN.to_vec()];
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(tls_cfg).expect("quic tls"),
    ));
    let mut tp = quinn_proto::TransportConfig::default();
    tp.max_concurrent_bidi_streams(1024u32.into());
    tp.max_concurrent_uni_streams(1024u32.into());
    client_cfg.transport_config(Arc::new(tp));

    // Set up quinn endpoint + connect, then layer h3 on top.
    let (driver_handle, send_request) = client_rt.block_on(async {
        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("quinn endpoint");
        endpoint.set_default_client_config(client_cfg);
        let conn = endpoint
            .connect(server_addr, "localhost")
            .expect("connect submit")
            .await
            .expect("connect await");
        let quinn_conn = h3_quinn::Connection::new(conn);
        let (mut driver, send_request) = h3::client::new(quinn_conn).await.expect("h3 client");
        // The driver future drains the H3 connection until close; spawn
        // and ignore — same pattern as the official h3 example.
        let driver_handle = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        (driver_handle, send_request)
    });

    let mut task_handles = Vec::with_capacity(num_clients);
    for _ in 0..num_clients {
        // h3's SendRequest is Clone; each cloned handle issues
        // requests on its own bidirectional stream multiplexed over
        // the shared QUIC connection.
        let sr = send_request.clone();
        let stop = stop.clone();
        let ops = ops.clone();
        let sample_tx = sample_tx.clone();
        task_handles.push(client_rt.spawn(run_h3_request_loop(sr, msg_size, stop, ops, sample_tx)));
    }
    // The driver only closes once every SendRequest is dropped — drop
    // our copy now so it dies cleanly with the spawned workers.
    drop(send_request);

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
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), driver_handle).await;
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
