use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::bench::{ClientRuntime, ServerRuntime};
use crate::port_manager::PortManager;
use crate::stats::{BenchResult, LatencyHistogram, LatencyStats, process_cpu_time_ns};

/// Run an HTTP/2 benchmark for one configuration.
///
/// Workload: each client repeatedly issues `GET /` over a single
/// kept-alive HTTP/2 connection. The bench server is a hyper HTTP/2
/// listener wrapped in tokio-rustls; it serves a fixed `200 OK` plus
/// a `msg_size`-byte body. HTTP/2 *requires* TLS as far as
/// `ringline-http` is concerned (no h2c support), so the cert is a
/// self-signed one generated at server startup and shared with both
/// clients — same approach as `ringline-h2/tests/round_trip.rs`.
#[allow(clippy::too_many_arguments)]
pub fn run_http2(
    port_manager: &PortManager,
    _workers: usize,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    client_runtime: ClientRuntime,
    _server_runtime: ServerRuntime,
) -> BenchResult {
    let server = match start_http2_server(port_manager, msg_size) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  http2 server start failed: {}", e);
            return empty_result();
        }
    };
    let addr = server.addr;
    let cert = server.cert.clone();

    let result = match client_runtime {
        ClientRuntime::Tokio => run_bench_tokio(addr, cert, num_clients, warmup, duration),
        _ => run_bench_ringline(addr, cert, num_clients, msg_size, warmup, duration),
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

// ── HTTP/2 bench server (hyper + tokio-rustls) ─────────────────────

struct BenchmarkServer {
    addr: SocketAddr,
    cert: Arc<CertificateDer<'static>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl BenchmarkServer {
    fn stop(mut self) {
        drop(self.shutdown.take());
        if let Some(h) = self.thread.take() {
            h.join().ok();
        }
    }
}

fn make_self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert");
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (CertificateDer::from(cert.cert), key.into())
}

fn server_tls_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server tls config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

fn start_http2_server(
    port_manager: &PortManager,
    msg_size: usize,
) -> Result<BenchmarkServer, String> {
    let addr = port_manager.next_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let (cert, key) = make_self_signed();
    let server_cert = Arc::new(cert.clone());
    let tls_config = server_tls_config(cert, key);

    // Pre-encode the body once.
    let body_bytes: Arc<Vec<u8>> = Arc::new(vec![0xCDu8; msg_size]);

    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        rt.block_on(async move {
            let socket = tokio::net::TcpSocket::new_v4().expect("failed to create socket");
            socket.set_reuseaddr(true).ok();
            socket.bind(addr).expect("failed to bind");
            let listener = socket.listen(1024).expect("failed to listen");
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

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
                        let acceptor = acceptor.clone();
                        let body = body_bytes.clone();
                        tokio::spawn(serve_h2(acceptor, stream, body));
                    }
                }
            }
        });
    });

    std::thread::sleep(Duration::from_millis(100));

    Ok(BenchmarkServer {
        addr,
        cert: server_cert,
        shutdown: Some(shutdown_tx),
        thread: Some(thread),
    })
}

async fn serve_h2(
    acceptor: tokio_rustls::TlsAcceptor,
    stream: tokio::net::TcpStream,
    body: Arc<Vec<u8>>,
) {
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;

    let tls = match acceptor.accept(stream).await {
        Ok(t) => t,
        Err(_) => return,
    };

    let io = hyper_util::rt::TokioIo::new(tls);
    let body_for_service = body.clone();
    let service = service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
        let body = body_for_service.clone();
        async move {
            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                Bytes::copy_from_slice(&body),
            )))
        }
    });

    let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await;
}

// ── Ringline HTTP/2 client ──────────────────────────────────────────

struct RinglineHttp2State {
    addr: SocketAddr,
    num_clients: usize,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
}

static RINGLINE_HTTP2_CFG: Mutex<Option<Arc<RinglineHttp2State>>> = Mutex::new(None);

struct RinglineHttp2Bench;

impl ringline::AsyncEventHandler for RinglineHttp2Bench {
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
        let state = RINGLINE_HTTP2_CFG.lock().ok()?.as_ref()?.clone();
        Some(Box::pin(async move {
            for _i in 0..state.num_clients {
                let stop = state.stop.clone();
                let ops = state.ops.clone();
                let sample_tx = state.sample_tx.clone();
                let addr = state.addr;

                ringline::spawn(async move {
                    let mut client =
                        match ringline_http::HttpClient::connect_h2(addr, "localhost").await {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("  ringline http2 connect failed: {e}");
                                return;
                            }
                        };

                    let mut local_ops: u64 = 0;

                    while !stop.load(Ordering::Relaxed) {
                        let t0 = Instant::now();
                        match client.get("/").send().await {
                            Ok(_) => {}
                            Err(_) => break,
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
        RinglineHttp2Bench
    }
}

fn make_ringline_client_tls(cert: &CertificateDer<'static>) -> ringline::TlsClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("add cert to roots");
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    ringline::TlsClientConfig {
        client_config: Arc::new(client_config),
    }
}

fn make_ringline_client_config(
    num_clients: usize,
    _msg_size: usize,
    cert: &CertificateDer<'static>,
) -> ringline::Config {
    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = (num_clients * 8).next_power_of_two().max(512) as u32;
    config.recv_buffer.ring_size = (num_clients * 4).next_power_of_two().max(256) as u16;
    // HTTP/2 default `max_frame_size` is 16 KiB and TLS records can
    // be up to 16 KiB on top of that, so the recv buffer must be
    // comfortably larger than the body to keep one full HTTP/2 DATA
    // frame inside a single provided buffer. ringline caps
    // `recv_buffer.buffer_size` at 65535 (the user_data encoding
    // reserves 16 bits for the remaining-len field), so use that
    // ceiling — comfortably above the bench's worst case.
    config.recv_buffer.buffer_size = 65535;
    // Default send_copy_slot_size is 16384; keep it. ringline-http
    // can flush a request's HEADERS + DATA + WINDOW_UPDATE into one
    // send_nowait call, so the slot must accommodate the worst-case
    // batch size we expect to send in a single iteration.
    config.send_copy_slot_size = 16384;
    config.standalone_task_capacity = (num_clients + 1).next_power_of_two().max(64) as u32;
    config.tls_client = Some(make_ringline_client_tls(cert));
    config
}

fn run_bench_ringline(
    addr: SocketAddr,
    cert: Arc<CertificateDer<'static>>,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));
    let (sample_tx, sample_rx) = crossbeam_channel::unbounded::<u64>();

    {
        let mut guard = RINGLINE_HTTP2_CFG.lock().unwrap();
        *guard = Some(Arc::new(RinglineHttp2State {
            addr,
            num_clients,
            stop: stop.clone(),
            ops: ops.clone(),
            sample_tx,
        }));
    }

    wait_for_server(addr);

    let config = make_ringline_client_config(num_clients, msg_size, &cert);
    let (shutdown, handles) =
        match ringline::RinglineBuilder::new(config).launch::<RinglineHttp2Bench>() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  ringline http2 client launch failed: {e}");
                RINGLINE_HTTP2_CFG.lock().unwrap().take();
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

    RINGLINE_HTTP2_CFG.lock().unwrap().take();

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

// ── Tokio reference client (reqwest) ────────────────────────────────

async fn run_tokio_client(
    url: String,
    cert_pem: reqwest::Certificate,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
) -> LatencyHistogram {
    let mut histogram = LatencyHistogram::new();

    let client = match reqwest::Client::builder()
        .add_root_certificate(cert_pem)
        // Force ALPN to negotiate h2 with the server.
        .http2_prior_knowledge()
        .tcp_nodelay(true)
        .pool_max_idle_per_host(1)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  reqwest http2 client build failed: {e}");
            return histogram;
        }
    };

    let mut local_ops: u64 = 0;

    while !stop.load(Ordering::Relaxed) {
        let t0 = Instant::now();
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => break,
        };
        if resp.bytes().await.is_err() {
            break;
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
    addr: SocketAddr,
    cert: Arc<CertificateDer<'static>>,
    num_clients: usize,
    warmup: Duration,
    duration: Duration,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));

    wait_for_server(addr);

    let reqwest_cert = match reqwest::Certificate::from_der(cert.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  reqwest cert parse failed: {e}");
            return empty_result();
        }
    };

    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("failed to build client runtime");

    // reqwest needs a hostname that matches the cert's SAN
    // (`localhost`), not the literal `addr` (which includes the
    // ephemeral port host). Resolve hostname → port manually.
    let url = format!("https://localhost:{}/", addr.port());

    let mut task_handles = Vec::with_capacity(num_clients);
    for _ in 0..num_clients {
        let stop = stop.clone();
        let ops = ops.clone();
        let url = url.clone();
        let cert = reqwest_cert.clone();
        task_handles.push(client_rt.spawn(run_tokio_client(url, cert, stop, ops)));
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
            if let Ok(Ok(histogram)) = tokio::time::timeout(Duration::from_secs(2), handle).await {
                for &sample in histogram.samples() {
                    merged.record(sample);
                }
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

fn wait_for_server(addr: SocketAddr) {
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
