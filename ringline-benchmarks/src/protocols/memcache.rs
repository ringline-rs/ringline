use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bench::{ClientRuntime, ServerRuntime};
use crate::port_manager::PortManager;
use crate::stats::{BenchResult, LatencyHistogram, LatencyStats, process_cpu_time_ns};

/// Run a Memcache benchmark for one configuration.
///
/// Workload: each client repeatedly issues `get k` and waits for the
/// reply. The bench server is a minimal text-protocol tokio TCP
/// listener — it understands enough memcache to respond to `get`
/// (with a `VALUE k 0 <msg_size>\r\n<bytes>\r\nEND\r\n` payload),
/// `set`, and `delete`. Tokio server/client paths are wired and
/// dispatched from `main.rs`.
#[allow(clippy::too_many_arguments)]
pub fn run_memcache(
    port_manager: &PortManager,
    _workers: usize,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    client_runtime: ClientRuntime,
    _server_runtime: ServerRuntime,
) -> BenchResult {
    let server = match start_memcache_server(port_manager, msg_size) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  memcache server start failed: {}", e);
            return empty_result();
        }
    };
    let addr_str = server.addr.to_string();

    let result = match client_runtime {
        ClientRuntime::Tokio => run_bench_tokio(&addr_str, num_clients, msg_size, warmup, duration),
        _ => run_bench_ringline(&addr_str, num_clients, msg_size, warmup, duration),
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

// ── Memcache text-protocol bench server ─────────────────────────────

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

fn start_memcache_server(
    port_manager: &PortManager,
    msg_size: usize,
) -> Result<BenchmarkServer, String> {
    let addr = port_manager.next_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Pre-build the GET response once: `VALUE k 0 <msg_size>\r\n<bytes>\r\nEND\r\n`
    let get_response = Arc::new(encode_get_response(b"k", msg_size));

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
                        let get_response = get_response.clone();
                        tokio::spawn(handle_memcache_connection(stream, get_response));
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

async fn handle_memcache_connection(mut stream: tokio::net::TcpStream, get_response: Arc<Vec<u8>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 64 * 1024];
    let mut filled = 0usize;
    let mut out = Vec::with_capacity(4096);

    loop {
        let n = match stream.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        filled += n;

        out.clear();
        let mut consumed = 0;
        while let Some(frame_len) =
            parse_memcache_command(&buf[consumed..filled], &mut out, &get_response)
        {
            consumed += frame_len;
        }

        if !out.is_empty() && stream.write_all(&out).await.is_err() {
            break;
        }

        if consumed > 0 {
            buf.copy_within(consumed..filled, 0);
            filled -= consumed;
        }
        // Grow buffer for unusually large in-flight `set` payloads.
        if filled == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
    }
}

/// Parse one memcache command and append the response to `out`.
/// Returns the number of bytes consumed from `buf`, or `None` if the
/// buffer doesn't yet contain a full frame.
fn parse_memcache_command(buf: &[u8], out: &mut Vec<u8>, get_response: &[u8]) -> Option<usize> {
    // Find `\r\n` ending the command line.
    let line_end = find_crlf(buf, 0)?;
    let line = &buf[..line_end];

    // Dispatch by the first token.
    if line.starts_with(b"get ") || line.starts_with(b"gets ") {
        out.extend_from_slice(get_response);
        Some(line_end + 2)
    } else if line.starts_with(b"set ") {
        // `set <key> <flags> <exptime> <bytes>\r\n<data>\r\n` — parse
        // the trailing `bytes` count to know how much body to consume.
        let bytes = parse_set_bytes(&line[4..])?;
        // Need command line + `bytes` data + trailing `\r\n`.
        let total = line_end + 2 + bytes + 2;
        if buf.len() < total {
            return None;
        }
        out.extend_from_slice(b"STORED\r\n");
        Some(total)
    } else if line.starts_with(b"delete ") {
        out.extend_from_slice(b"DELETED\r\n");
        Some(line_end + 2)
    } else if line == b"version" {
        out.extend_from_slice(b"VERSION 0.0.0-bench\r\n");
        Some(line_end + 2)
    } else if line == b"quit" {
        // Caller closes the connection; just consume the line.
        Some(line_end + 2)
    } else {
        // Unknown — respond ERROR and consume the line.
        out.extend_from_slice(b"ERROR\r\n");
        Some(line_end + 2)
    }
}

/// Parse the final `<bytes>` count from a `set <key> <flags> <exptime> <bytes>` line.
fn parse_set_bytes(rest: &[u8]) -> Option<usize> {
    let last_space = rest.iter().rposition(|&b| b == b' ')?;
    let bytes_str = &rest[last_space + 1..];
    std::str::from_utf8(bytes_str).ok()?.parse().ok()
}

fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn encode_get_response(key: &[u8], msg_size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + key.len() + msg_size);
    buf.extend_from_slice(b"VALUE ");
    buf.extend_from_slice(key);
    buf.extend_from_slice(b" 0 ");
    buf.extend_from_slice(msg_size.to_string().as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.resize(buf.len() + msg_size, 0xCD);
    buf.extend_from_slice(b"\r\nEND\r\n");
    buf
}

// ── Ringline-memcache client ────────────────────────────────────────

struct RinglineMemcacheState {
    addr: SocketAddr,
    num_clients: usize,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
}

static RINGLINE_MEMCACHE_CFG: Mutex<Option<Arc<RinglineMemcacheState>>> = Mutex::new(None);

struct RinglineMemcacheBench;

impl ringline::AsyncEventHandler for RinglineMemcacheBench {
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
        let state = RINGLINE_MEMCACHE_CFG.lock().ok()?.as_ref()?.clone();
        Some(Box::pin(async move {
            for _i in 0..state.num_clients {
                let stop = state.stop.clone();
                let ops = state.ops.clone();
                let sample_tx = state.sample_tx.clone();
                let addr = state.addr;

                ringline::spawn(async move {
                    let conn = match ringline::connect(addr) {
                        Ok(f) => match f.await {
                            Ok(c) => c,
                            Err(_) => return,
                        },
                        Err(_) => return,
                    };
                    let mut client = ringline_memcache::Client::new(conn);

                    let key: &[u8] = b"k";
                    let mut local_ops: u64 = 0;

                    while !stop.load(Ordering::Relaxed) {
                        let t0 = Instant::now();
                        match client.get(key).await {
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
        RinglineMemcacheBench
    }
}

fn make_ringline_client_config(num_clients: usize, msg_size: usize) -> ringline::Config {
    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = (num_clients * 4).next_power_of_two().max(256) as u32;
    config.recv_buffer.ring_size = (num_clients * 2).next_power_of_two().max(64) as u16;
    // Response includes value bytes + ~32 B of framing overhead
    // (`VALUE k 0 <bytes>\r\n` + `\r\nEND\r\n`).
    config.recv_buffer.buffer_size = (msg_size + 64).next_power_of_two().max(4096) as u32;
    config.send_copy_slot_size = 512;
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
        let mut guard = RINGLINE_MEMCACHE_CFG.lock().unwrap();
        *guard = Some(Arc::new(RinglineMemcacheState {
            addr: addr.parse().expect("invalid server addr"),
            num_clients,
            stop: stop.clone(),
            ops: ops.clone(),
            sample_tx,
        }));
    }

    wait_for_server(addr);

    let config = make_ringline_client_config(num_clients, msg_size);
    let (shutdown, handles) =
        match ringline::RinglineBuilder::new(config).launch::<RinglineMemcacheBench>() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  ringline memcache client launch failed: {e}");
                RINGLINE_MEMCACHE_CFG.lock().unwrap().take();
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

    RINGLINE_MEMCACHE_CFG.lock().unwrap().take();

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
    addr: String,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
) -> LatencyHistogram {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut histogram = LatencyHistogram::new();

    let mut stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  client connect failed: {e}");
            return histogram;
        }
    };
    stream.set_nodelay(true).ok();

    // `get k\r\n` request — fixed.
    let request: &[u8] = b"get k\r\n";
    // Response shape: `VALUE k 0 <msg_size>\r\n<msg_size B>\r\nEND\r\n`.
    let len_str = msg_size.to_string();
    let expected_len = b"VALUE k 0 ".len() + len_str.len() + 2 + msg_size + 2 + 5;
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

fn wait_for_server(addr: &str) {
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
    fn parse_get_consumes_one_line() {
        let mut out = Vec::new();
        let response = encode_get_response(b"k", 4);
        let consumed = parse_memcache_command(b"get k\r\n", &mut out, &response).expect("parse");
        assert_eq!(consumed, b"get k\r\n".len());
        assert_eq!(out, response);
    }

    #[test]
    fn parse_set_needs_full_body() {
        let mut out = Vec::new();
        let dummy = Vec::new();
        let buf = b"set k 0 0 4\r\nab";
        assert!(parse_memcache_command(buf, &mut out, &dummy).is_none());
    }

    #[test]
    fn parse_set_consumes_full_frame() {
        let mut out = Vec::new();
        let dummy = Vec::new();
        let buf = b"set k 0 0 4\r\nabcd\r\n";
        let consumed = parse_memcache_command(buf, &mut out, &dummy).expect("parse");
        assert_eq!(consumed, buf.len());
        assert_eq!(out, b"STORED\r\n");
    }

    #[test]
    fn parse_delete_returns_deleted() {
        let mut out = Vec::new();
        let dummy = Vec::new();
        let buf = b"delete k\r\n";
        let consumed = parse_memcache_command(buf, &mut out, &dummy).expect("parse");
        assert_eq!(consumed, buf.len());
        assert_eq!(out, b"DELETED\r\n");
    }

    #[test]
    fn pipelined_get_then_delete_drained_one_at_a_time() {
        let mut out = Vec::new();
        let response = encode_get_response(b"k", 4);
        let buf = b"get k\r\ndelete k\r\n";
        let n1 = parse_memcache_command(buf, &mut out, &response).expect("first");
        assert_eq!(&buf[..n1], b"get k\r\n");
        let n2 = parse_memcache_command(&buf[n1..], &mut out, &response).expect("second");
        assert_eq!(n1 + n2, buf.len());
        assert!(out.ends_with(b"DELETED\r\n"));
    }

    #[test]
    fn encode_get_response_shape() {
        let resp = encode_get_response(b"k", 4);
        // "VALUE k 0 4\r\n" (13) + 4 data + "\r\nEND\r\n" (7) = 24
        assert_eq!(resp.len(), 24);
        assert!(resp.starts_with(b"VALUE k 0 4\r\n"));
        assert!(resp.ends_with(b"\r\nEND\r\n"));
    }
}
