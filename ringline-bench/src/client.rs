use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::stats::{BenchResult, LatencyHistogram, process_cpu_time_ns};

// ── Async (tokio) client ───────────────────────────────────────────

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

// ── Async (ringline) client ────────────────────────────────────────

mod ringline_client {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Instant;

    use ringline::{
        AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder, ShutdownHandle, connect,
        spawn,
    };

    /// Shared state passed into ringline worker tasks.
    pub struct ClientState {
        pub target: std::net::SocketAddr,
        pub msg_size: usize,
        pub clients_per_worker: usize,
        pub stop: Arc<AtomicBool>,
        pub ops: Arc<AtomicU64>,
        pub histograms: Arc<Mutex<Vec<Vec<u64>>>>,
    }

    struct ClientHandler {
        state: Arc<ClientState>,
    }

    #[allow(clippy::manual_async_fn)]
    impl AsyncEventHandler for ClientHandler {
        fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
            async {}
        }

        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            let state = self.state.clone();
            Some(Box::pin(async move {
                for _ in 0..state.clients_per_worker {
                    let s = state.clone();
                    spawn(async move {
                        run_ringline_client(s).await;
                    })
                    .ok();
                }
            }))
        }

        fn create_for_worker(_worker_id: usize) -> Self {
            let state = GLOBAL_STATE
                .lock()
                .unwrap()
                .as_ref()
                .expect("client state not set")
                .clone();
            ClientHandler { state }
        }
    }

    static GLOBAL_STATE: Mutex<Option<Arc<ClientState>>> = Mutex::new(None);

    async fn run_ringline_client(state: Arc<ClientState>) {
        let msg = vec![0xABu8; state.msg_size];
        let msg_size = state.msg_size;

        let connect_future = match connect(state.target) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  ringline client connect setup failed: {e}");
                return;
            }
        };

        let conn = match connect_future.await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ringline client connect failed: {e}");
                return;
            }
        };

        let mut local_ops: u64 = 0;
        let mut samples: Vec<u64> = Vec::with_capacity(1_000_000);

        while !state.stop.load(Ordering::Relaxed) {
            let t0 = Instant::now();

            if conn.send_nowait(&msg).is_err() {
                break;
            }

            // Read exactly msg_size bytes.
            let mut remaining = msg_size;
            while remaining > 0 {
                let consumed = conn
                    .with_data(|data| {
                        let take = data.len().min(remaining);
                        ParseResult::Consumed(take)
                    })
                    .await;
                if consumed == 0 {
                    state
                        .histograms
                        .lock()
                        .unwrap()
                        .push(std::mem::take(&mut samples));
                    state.ops.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
                    return;
                }
                remaining -= consumed;
            }

            let elapsed_ns = t0.elapsed().as_nanos() as u64;
            samples.push(elapsed_ns);

            local_ops += 1;
            if local_ops & 0xFF == 0 {
                state.ops.fetch_add(256, Ordering::Relaxed);
            }
        }

        state.ops.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
        state
            .histograms
            .lock()
            .unwrap()
            .push(std::mem::take(&mut samples));
    }

    pub struct RinglineClientRuntime {
        pub shutdown: ShutdownHandle,
        pub handles: Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
    }

    impl RinglineClientRuntime {
        pub fn start(state: Arc<ClientState>, workers: usize) -> Result<Self, ringline::Error> {
            let msg_size = state.msg_size;

            *GLOBAL_STATE.lock().unwrap() = Some(state);

            let mut config = Config::default();
            config.worker.threads = workers;
            config.worker.pin_to_core = false;
            config.sq_entries = 256;
            config.recv_buffer.ring_size = 256;
            config.recv_buffer.buffer_size = msg_size.next_power_of_two().max(4096) as u32;
            config.max_connections = 4096;
            config.send_copy_count = 512;
            config.send_copy_slot_size = msg_size.next_power_of_two().max(4096) as u32;

            // Client-only mode: no bind address.
            let (shutdown, handles) = RinglineBuilder::new(config).launch::<ClientHandler>()?;

            Ok(RinglineClientRuntime { shutdown, handles })
        }

        pub fn stop(self) {
            self.shutdown.shutdown();
            for h in self.handles {
                h.join().ok();
            }
        }
    }
}

// ── Shared ─────────────────────────────────────────────────────────

fn wait_for_server(addr: &str) {
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not start on {addr}");
}

/// Run a benchmark against a server already listening on `addr`.
pub fn run_bench(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    ringline_client: bool,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));

    wait_for_server(addr);

    if ringline_client {
        run_bench_ringline(addr, num_clients, msg_size, warmup, duration, stop, ops)
    } else {
        run_bench_tokio(addr, num_clients, msg_size, warmup, duration, stop, ops)
    }
}

fn run_bench_tokio(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
) -> BenchResult {
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
            if let Ok(histogram) = handle.await {
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

fn run_bench_ringline(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
) -> BenchResult {
    let histograms = Arc::new(Mutex::new(Vec::new()));

    let state = Arc::new(ringline_client::ClientState {
        target: addr.parse().expect("invalid addr for ringline client"),
        msg_size,
        clients_per_worker: num_clients,
        stop: stop.clone(),
        ops: ops.clone(),
        histograms: histograms.clone(),
    });

    let client_rt = match ringline_client::RinglineClientRuntime::start(state, 1) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("  ringline client failed to start: {e}");
            return BenchResult {
                ops_per_sec: 0.0,
                latency: LatencyHistogram::new().finalize(),
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

    // Give tasks a moment to finish and push their histograms.
    std::thread::sleep(Duration::from_millis(200));
    client_rt.stop();

    let mut merged = LatencyHistogram::new();
    let collected = histograms.lock().unwrap();
    for samples in collected.iter() {
        for &sample in samples {
            merged.record(sample);
        }
    }

    let total_ops = ops.load(Ordering::Relaxed);
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

    BenchResult {
        ops_per_sec,
        latency: merged.finalize(),
        cpu_ns: cpu_after.saturating_sub(cpu_before),
    }
}
