use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bench::{ClientRuntime, ServerRuntime};
use crate::port_manager::PortManager;
use crate::stats::{BenchResult, LatencyHistogram, LatencyStats, process_cpu_time_ns};

/// Run an HTTP/1.1 benchmark for one configuration.
///
/// Workload: each client repeatedly issues `GET /` over a single
/// keep-alive connection and waits for the reply. The bench server
/// is a minimal HTTP/1.1 tokio TCP listener — it understands enough
/// of the protocol to recognise the end of a request line + headers
/// (`\r\n\r\n`) and emit a pre-computed
/// `200 OK\r\nContent-Length: <msg_size>\r\n...` reply with a
/// `msg_size`-byte body. Both ringline and tokio clients hit the
/// same server.
#[allow(clippy::too_many_arguments)]
pub fn run_http1(
    port_manager: &PortManager,
    _workers: usize,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    client_runtime: ClientRuntime,
    _server_runtime: ServerRuntime,
) -> BenchResult {
    let server = match start_http1_server(port_manager, msg_size) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  http1 server start failed: {}", e);
            return empty_result();
        }
    };
    let addr = server.addr;

    let result = match client_runtime {
        ClientRuntime::Tokio => run_bench_tokio(addr, num_clients, msg_size, warmup, duration),
        _ => run_bench_ringline(addr, num_clients, msg_size, warmup, duration),
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

// ── HTTP/1 bench server ─────────────────────────────────────────────

struct BenchmarkServer {
    addr: SocketAddr,
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

fn start_http1_server(
    port_manager: &PortManager,
    msg_size: usize,
) -> Result<BenchmarkServer, String> {
    let addr = port_manager.next_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let response = Arc::new(encode_http1_response(msg_size));

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
                        let response = response.clone();
                        tokio::spawn(handle_http1_connection(stream, response));
                    }
                }
            }
        });
    });

    std::thread::sleep(Duration::from_millis(100));

    Ok(BenchmarkServer {
        addr,
        shutdown: Some(shutdown_tx),
        thread: Some(thread),
    })
}

async fn handle_http1_connection(mut stream: tokio::net::TcpStream, response: Arc<Vec<u8>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 8 * 1024];
    let mut filled = 0usize;
    let mut out = Vec::with_capacity(64 * 1024);

    loop {
        let n = match stream.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        filled += n;

        out.clear();
        let mut consumed = 0;
        // Drain as many full request heads (`\r\n\r\n`) as we have. The
        // bench client only sends header-only GETs, so we don't need to
        // honour Content-Length on the request side.
        while let Some(head_end) = find_double_crlf(&buf[consumed..filled]) {
            consumed += head_end + 4;
            out.extend_from_slice(&response);
        }

        if !out.is_empty() && stream.write_all(&out).await.is_err() {
            break;
        }

        if consumed > 0 {
            buf.copy_within(consumed..filled, 0);
            filled -= consumed;
        }
        // Grow if a single header set somehow exceeds the buffer (we
        // never expect this from our own clients but keep the server
        // forgiving).
        if filled == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
    }
}

/// Find `\r\n\r\n` in `buf`, returning the offset of the `\r` of the
/// first `\r\n` (so `head_end + 4` consumes the terminator).
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 3 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn encode_http1_response(msg_size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96 + msg_size);
    buf.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
    buf.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
    buf.extend_from_slice(b"Content-Length: ");
    buf.extend_from_slice(msg_size.to_string().as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(b"Connection: keep-alive\r\n");
    buf.extend_from_slice(b"\r\n");
    buf.resize(buf.len() + msg_size, 0xCD);
    buf
}

// ── Ringline HTTP/1 client ──────────────────────────────────────────

struct RinglineHttp1State {
    addr: SocketAddr,
    num_clients: usize,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
}

static RINGLINE_HTTP1_CFG: Mutex<Option<Arc<RinglineHttp1State>>> = Mutex::new(None);

struct RinglineHttp1Bench;

impl ringline::AsyncEventHandler for RinglineHttp1Bench {
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
        let state = RINGLINE_HTTP1_CFG.lock().ok()?.as_ref()?.clone();
        Some(Box::pin(async move {
            for _i in 0..state.num_clients {
                let stop = state.stop.clone();
                let ops = state.ops.clone();
                let sample_tx = state.sample_tx.clone();
                let addr = state.addr;

                ringline::spawn(async move {
                    let mut client =
                        match ringline_http::HttpClient::connect_h1_plain(addr, "bench").await {
                            Ok(c) => c,
                            Err(_) => return,
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
        RinglineHttp1Bench
    }
}

fn make_ringline_client_config(num_clients: usize, msg_size: usize) -> ringline::Config {
    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = (num_clients * 4).next_power_of_two().max(256) as u32;
    config.recv_buffer.ring_size = (num_clients * 2).next_power_of_two().max(64) as u16;
    // Response = status line + headers (~96 B) + body. Round up.
    config.recv_buffer.buffer_size = (msg_size + 256).next_power_of_two().max(4096) as u32;
    config.send_copy_slot_size = 512;
    config.standalone_task_capacity = (num_clients + 1).next_power_of_two().max(64) as u32;
    config
}

fn run_bench_ringline(
    addr: SocketAddr,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));
    let (sample_tx, sample_rx) = crossbeam_channel::unbounded::<u64>();

    {
        let mut guard = RINGLINE_HTTP1_CFG.lock().unwrap();
        *guard = Some(Arc::new(RinglineHttp1State {
            addr,
            num_clients,
            stop: stop.clone(),
            ops: ops.clone(),
            sample_tx,
        }));
    }

    wait_for_server(addr);

    let config = make_ringline_client_config(num_clients, msg_size);
    let (shutdown, handles) =
        match ringline::RinglineBuilder::new(config).launch::<RinglineHttp1Bench>() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  ringline http1 client launch failed: {e}");
                RINGLINE_HTTP1_CFG.lock().unwrap().take();
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

    RINGLINE_HTTP1_CFG.lock().unwrap().take();

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

// ── Tokio reference client ──────────────────────────────────────────

async fn run_tokio_client(
    addr: SocketAddr,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
) -> LatencyHistogram {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut histogram = LatencyHistogram::new();

    let mut stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  client connect failed: {e}");
            return histogram;
        }
    };
    stream.set_nodelay(true).ok();

    // Fixed `GET / HTTP/1.1` request — keep-alive is the HTTP/1.1
    // default, but state it explicitly so the server keeps the conn
    // open even on older implementations.
    let request: &[u8] = b"GET / HTTP/1.1\r\nHost: bench\r\nConnection: keep-alive\r\n\r\n";

    // Pre-compute the exact response size so we know when one reply
    // ends. Response: status line + headers + msg_size body.
    let len_str = msg_size.to_string();
    let expected_len = b"HTTP/1.1 200 OK\r\n".len()
        + b"Content-Type: application/octet-stream\r\n".len()
        + b"Content-Length: ".len()
        + len_str.len()
        + 2
        + b"Connection: keep-alive\r\n".len()
        + 2
        + msg_size;
    let mut recv_buf = vec![0u8; expected_len];
    let mut local_ops: u64 = 0;

    while !stop.load(Ordering::Relaxed) {
        let t0 = Instant::now();
        if stream.write_all(request).await.is_err() {
            break;
        }
        let mut read = 0;
        while read < expected_len {
            match stream.read(&mut recv_buf[read..]).await {
                Ok(0) => return histogram,
                Ok(n) => read += n,
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
    addr: SocketAddr,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_double_crlf_matches_simple_get() {
        let req = b"GET / HTTP/1.1\r\nHost: bench\r\n\r\n";
        let off = find_double_crlf(req).expect("find");
        assert_eq!(&req[..off + 4], req);
    }

    #[test]
    fn find_double_crlf_none_when_only_one_crlf() {
        let req = b"GET / HTTP/1.1\r\nHost: bench\r\n";
        assert!(find_double_crlf(req).is_none());
    }

    #[test]
    fn find_double_crlf_handles_two_headers() {
        let req = b"GET / HTTP/1.1\r\nHost: bench\r\nUser-Agent: test\r\n\r\n";
        let off = find_double_crlf(req).expect("find");
        assert_eq!(&req[off..off + 4], b"\r\n\r\n");
        assert_eq!(off + 4, req.len());
    }

    #[test]
    fn encode_response_shape() {
        let r = encode_http1_response(4);
        assert!(r.starts_with(b"HTTP/1.1 200 OK\r\n"));
        // ends with 4 body bytes
        assert_eq!(&r[r.len() - 4..], &[0xCD, 0xCD, 0xCD, 0xCD]);
        // Total len should be headers + 4 body bytes; verify a known
        // suffix is exactly the body.
        assert!(r.windows(4).any(|w| w == b"\r\n\r\n"));
    }
}
