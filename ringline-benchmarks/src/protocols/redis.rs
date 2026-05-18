use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bench::{ClientRuntime, ServerRuntime};
use crate::port_manager::PortManager;
use crate::stats::{BenchResult, LatencyHistogram, LatencyStats, process_cpu_time_ns};

/// Run a Redis benchmark for one configuration.
///
/// Workload: each client repeatedly issues `GET k` and waits for the
/// reply. The bench server is a minimal RESP-speaking tokio TCP
/// listener — it understands enough of the protocol to respond to
/// `GET` (with a `$msg_size`-byte payload), `SET`, `PING`, and `DEL`.
/// Tokio client / server paths are wired but unused; today `main.rs`
/// only exercises the ringline-on-both-sides combo.
#[allow(clippy::too_many_arguments)]
pub fn run_redis(
    port_manager: &PortManager,
    _workers: usize,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    client_runtime: ClientRuntime,
    _server_runtime: ServerRuntime,
) -> BenchResult {
    let server = match start_resp_server(port_manager, msg_size) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  redis server start failed: {}", e);
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

// ── RESP bench server ───────────────────────────────────────────────

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

fn start_resp_server(
    port_manager: &PortManager,
    msg_size: usize,
) -> Result<BenchmarkServer, String> {
    let addr = port_manager.next_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Pre-build the GET response once: `$<msg_size>\r\n<msg_size B>\r\n`
    // — cloned per connection so the per-iter hot path is just write_all.
    let get_response = Arc::new(encode_bulk_string(msg_size));

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
                        tokio::spawn(handle_resp_connection(stream, get_response));
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

async fn handle_resp_connection(mut stream: tokio::net::TcpStream, get_response: Arc<Vec<u8>>) {
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

        // Drain as many complete RESP commands as we have.
        out.clear();
        let mut consumed = 0;
        while let Some((cmd_offset, frame_len)) = parse_resp_command(&buf[consumed..filled]) {
            let cmd_start = consumed + cmd_offset;
            // Compare just the command keyword. ringline-redis always
            // upper-cases its command tokens, but tolerate lower-case
            // too in case some other client points at us.
            let cmd = &buf[cmd_start..cmd_start + 8.min(filled - cmd_start)];
            if cmd.starts_with(b"GET") || cmd.starts_with(b"get") {
                out.extend_from_slice(&get_response);
            } else if cmd.starts_with(b"SET") || cmd.starts_with(b"set") {
                out.extend_from_slice(b"+OK\r\n");
            } else if cmd.starts_with(b"PING") || cmd.starts_with(b"ping") {
                out.extend_from_slice(b"+PONG\r\n");
            } else if cmd.starts_with(b"DEL") || cmd.starts_with(b"del") {
                out.extend_from_slice(b":0\r\n");
            } else {
                // Unknown command — close the connection.
                return;
            }
            consumed += frame_len;
        }

        if !out.is_empty() && stream.write_all(&out).await.is_err() {
            break;
        }

        if consumed > 0 {
            buf.copy_within(consumed..filled, 0);
            filled -= consumed;
        }
        // If the buffer is full of a partial frame we'd never make
        // progress; grow it. Realistically the warmup buffer is plenty
        // for our 1 KiB-ish RESP frames.
        if filled == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
    }
}

/// Parse one RESP array command out of `buf`. Returns
/// `(offset_of_first_command_token, total_frame_len)` or `None` if the
/// buffer doesn't yet contain a full frame.
fn parse_resp_command(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.is_empty() || buf[0] != b'*' {
        return None;
    }
    let crlf = find_crlf(buf, 1)?;
    let n: usize = std::str::from_utf8(&buf[1..crlf]).ok()?.parse().ok()?;
    if n == 0 {
        return Some((crlf + 2, crlf + 2));
    }
    let mut pos = crlf + 2;
    let mut first_token_offset = 0;
    for i in 0..n {
        if pos >= buf.len() || buf[pos] != b'$' {
            return None;
        }
        let header_crlf = find_crlf(buf, pos + 1)?;
        let len: usize = std::str::from_utf8(&buf[pos + 1..header_crlf])
            .ok()?
            .parse()
            .ok()?;
        let data_start = header_crlf + 2;
        let data_end = data_start + len;
        if buf.len() < data_end + 2 {
            return None;
        }
        if i == 0 {
            first_token_offset = data_start;
        }
        pos = data_end + 2;
    }
    Some((first_token_offset, pos))
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

fn encode_bulk_string(len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + len);
    buf.extend_from_slice(b"$");
    buf.extend_from_slice(len.to_string().as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.resize(buf.len() + len, 0xCD);
    buf.extend_from_slice(b"\r\n");
    buf
}

// ── Ringline-redis client ───────────────────────────────────────────

struct RinglineRedisState {
    addr: SocketAddr,
    num_clients: usize,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    sample_tx: crossbeam_channel::Sender<u64>,
}

static RINGLINE_REDIS_CFG: Mutex<Option<Arc<RinglineRedisState>>> = Mutex::new(None);

struct RinglineRedisBench;

impl ringline::AsyncEventHandler for RinglineRedisBench {
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
        let state = RINGLINE_REDIS_CFG.lock().ok()?.as_ref()?.clone();
        Some(Box::pin(async move {
            for _i in 0..state.num_clients {
                let stop = state.stop.clone();
                let ops = state.ops.clone();
                let sample_tx = state.sample_tx.clone();
                let addr = state.addr;

                // Each client task connects so owner_task is set to the
                // spawned task. Same pattern as tcp.rs.
                ringline::spawn(async move {
                    let conn = match ringline::connect(addr) {
                        Ok(f) => match f.await {
                            Ok(c) => c,
                            Err(_) => return,
                        },
                        Err(_) => return,
                    };
                    let mut client = ringline_redis::Client::new(conn);

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
        RinglineRedisBench
    }
}

fn make_ringline_client_config(num_clients: usize, msg_size: usize) -> ringline::Config {
    let mut config = ringline::Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = (num_clients * 4).next_power_of_two().max(256) as u32;
    config.recv_buffer.ring_size = (num_clients * 2).next_power_of_two().max(64) as u16;
    // Response is `$<len>\r\n<msg_size>\r\n` — a few extra bytes for the
    // length prefix, plus comfortable headroom.
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
        let mut guard = RINGLINE_REDIS_CFG.lock().unwrap();
        *guard = Some(Arc::new(RinglineRedisState {
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
        match ringline::RinglineBuilder::new(config).launch::<RinglineRedisBench>() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  ringline redis client launch failed: {e}");
                RINGLINE_REDIS_CFG.lock().unwrap().take();
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

    RINGLINE_REDIS_CFG.lock().unwrap().take();

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

// ── Tokio client (currently unused — main.rs only runs ringline) ────

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

    // `GET k` request — fixed.
    let request: &[u8] = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n";
    // Response shape: `$<msg_size>\r\n<msg_size B>\r\n`. Compute the
    // fixed-size suffix length so we know when one frame is done.
    let len_str = msg_size.to_string();
    let expected_len = 1 + len_str.len() + 2 + msg_size + 2;
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
    fn parse_get_command() {
        let buf = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n";
        let (offset, total) = parse_resp_command(buf).expect("parse");
        assert_eq!(&buf[offset..offset + 3], b"GET");
        assert_eq!(total, buf.len());
    }

    #[test]
    fn parse_set_command() {
        let buf = b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$5\r\nhello\r\n";
        let (offset, total) = parse_resp_command(buf).expect("parse");
        assert_eq!(&buf[offset..offset + 3], b"SET");
        assert_eq!(total, buf.len());
    }

    #[test]
    fn parse_incomplete_returns_none() {
        // Header says 2 elements but only one is present.
        let buf = b"*2\r\n$3\r\nGET\r\n";
        assert!(parse_resp_command(buf).is_none());
    }

    #[test]
    fn parse_pipelined_consumes_one_frame() {
        let buf = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n*1\r\n$4\r\nPING\r\n";
        let (offset, total) = parse_resp_command(buf).expect("parse");
        assert_eq!(&buf[offset..offset + 3], b"GET");
        // The second frame starts right after the first.
        let (offset2, total2) = parse_resp_command(&buf[total..]).expect("parse 2nd");
        assert_eq!(&buf[total + offset2..total + offset2 + 4], b"PING");
        assert_eq!(total + total2, buf.len());
    }

    #[test]
    fn encode_bulk_string_shape() {
        let buf = encode_bulk_string(4);
        // `$4\r\n____\r\n` = 4 + 4 + 2 = wait, "$4\r\n" is 4 bytes,
        // then 4 data bytes, then \r\n. Total 10.
        assert_eq!(buf.len(), 10);
        assert!(buf.starts_with(b"$4\r\n"));
        assert!(buf.ends_with(b"\r\n"));
    }
}
