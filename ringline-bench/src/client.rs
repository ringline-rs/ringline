use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::stats::{BenchResult, LatencyHistogram, process_cpu_time_ns};

/// Open-loop load configuration.
///
/// `rate` is the aggregate offered requests/sec across all connections (split
/// evenly per connection). `max_inflight` bounds outstanding requests per
/// connection: when it is reached the sender stalls and falls behind its fixed
/// schedule, so overload manifests as climbing latency — measured from the
/// *scheduled* send time (coordinated-omission-free) — rather than a hang.
#[derive(Clone, Copy)]
pub struct OpenLoop {
    pub rate: u64,
    pub max_inflight: usize,
}

// ── Async (tokio) client — closed loop ──────────────────────────────

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

// ── Async (tokio) client — open loop ────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run_tokio_open_client(
    addr: String,
    msg_size: usize,
    per_conn_rate: f64,
    max_inflight: usize,
    measure: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
) -> LatencyHistogram {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  client connect failed: {e}");
            return LatencyHistogram::new();
        }
    };
    stream.set_nodelay(true).ok();
    let (mut rd, mut wr) = stream.into_split();

    let interval = 1.0 / per_conn_rate; // seconds between sends on this connection
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Instant>();
    let received = Arc::new(AtomicU64::new(0));

    // Reader task: drains responses, matches each to its scheduled send time
    // (FIFO), and records coordinated-omission-free latency while measuring.
    let reader = {
        let measure = measure.clone();
        let ops_counter = ops_counter.clone();
        let received = received.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut histogram = LatencyHistogram::new();
            let mut buf = vec![0u8; msg_size];
            let mut local_ops: u64 = 0;
            loop {
                // Read one full response, but bail promptly once stop is set
                // (the measurement window has ended; no need to drain in-flight).
                let read_one = async {
                    let mut total_read = 0;
                    while total_read < msg_size {
                        match rd.read(&mut buf[total_read..]).await {
                            Ok(0) => return false,
                            Ok(n) => total_read += n,
                            Err(_) => return false,
                        }
                    }
                    true
                };
                tokio::select! {
                    biased;
                    ok = read_one => { if !ok { break; } }
                    _ = async {
                        while !stop.load(Ordering::Relaxed) {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    } => { break; }
                }
                let sched = match rx.recv().await {
                    Some(s) => s,
                    None => break,
                };
                received.fetch_add(1, Ordering::Relaxed);
                if measure.load(Ordering::Relaxed) {
                    histogram.record(sched.elapsed().as_nanos() as u64);
                    local_ops += 1;
                    if local_ops & 0xFF == 0 {
                        ops_counter.fetch_add(256, Ordering::Relaxed);
                    }
                }
            }
            histogram
        })
    };

    // Sender: pace to each request's scheduled time, coalescing all currently-due
    // requests into ONE write to match ringline's send coalescing (so the two
    // clients are syscall-for-syscall comparable). When keeping up we sleep until
    // the next request is due; when behind we send a full batch to catch up,
    // bounded by in-flight (overload → fall behind → climbing
    // coordinated-omission-free latency). Messages are a constant byte, so one
    // preallocated buffer serves any batch.
    const TOKIO_SEND_BATCH: usize = 32;
    let batch_buf = vec![0xABu8; msg_size * TOKIO_SEND_BATCH];
    let start = Instant::now();
    let mut sent: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let elapsed = start.elapsed().as_secs_f64();
        let due = (elapsed / interval) as u64;
        let inflight = sent.saturating_sub(received.load(Ordering::Relaxed));
        let room = max_inflight.saturating_sub(inflight as usize) as u64;
        let want = due.saturating_sub(sent).min(room).min(TOKIO_SEND_BATCH as u64) as usize;
        if want == 0 {
            if (inflight as usize) >= max_inflight {
                tokio::time::sleep(Duration::from_micros(50)).await; // in-flight full
            } else {
                let target = start + Duration::from_secs_f64(interval * sent as f64);
                let now = Instant::now();
                if now < target {
                    tokio::time::sleep(target - now).await;
                } else {
                    tokio::time::sleep(Duration::from_micros(10)).await; // spin guard
                }
            }
            continue;
        }
        if wr.write_all(&batch_buf[..want * msg_size]).await.is_err() {
            stop.store(true, Ordering::Relaxed);
            break;
        }
        let mut failed = false;
        for k in 0..want as u64 {
            let sched = start + Duration::from_secs_f64(interval * (sent + k) as f64);
            if tx.send(sched).is_err() {
                stop.store(true, Ordering::Relaxed);
                failed = true;
                break;
            }
        }
        if failed {
            break;
        }
        sent += want as u64;
    }
    drop(tx);
    reader.await.unwrap_or_else(|_| LatencyHistogram::new())
}

// ── Async (ringline) client ─────────────────────────────────────────

mod ringline_client {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use ringline::{
        AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder, ShutdownHandle, connect,
        sleep, spawn,
    };

    use super::OpenLoop;

    /// Shared state passed into ringline worker tasks.
    pub struct ClientState {
        pub target: std::net::SocketAddr,
        pub msg_size: usize,
        /// Total client connections (used to split the aggregate open-loop rate).
        pub num_clients: usize,
        /// Total connections still to be opened. Each worker's `on_start`
        /// drains this counter, so connections are distributed across workers
        /// and the total is exactly the requested client count.
        pub remaining: Arc<AtomicUsize>,
        pub stop: Arc<AtomicBool>,
        /// Set true once warmup ends; open-loop latency/ops are only recorded
        /// while this is true.
        pub measure: Arc<AtomicBool>,
        pub ops: Arc<AtomicU64>,
        pub histograms: Arc<Mutex<Vec<Vec<u64>>>>,
        /// `Some` => open-loop (rate-controlled); `None` => closed-loop.
        pub open: Option<OpenLoop>,
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
                // Claim connection slots from the shared counter until drained.
                loop {
                    let prev = state.remaining.load(Ordering::Relaxed);
                    if prev == 0 {
                        break;
                    }
                    if state
                        .remaining
                        .compare_exchange_weak(prev, prev - 1, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        let s = state.clone();
                        match s.open {
                            Some(ol) => {
                                spawn(async move {
                                    run_ringline_open_client(s, ol).await;
                                })
                                .ok();
                            }
                            None => {
                                spawn(async move {
                                    run_ringline_client(s).await;
                                })
                                .ok();
                            }
                        }
                    }
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

    /// Open-loop ringline client. The connecting task is the *reader* (recv
    /// wake targets the owning task), and a separate spawned task is the
    /// *sender* (fire-and-forget `send_nowait`, never awaits recv).
    async fn run_ringline_open_client(state: Arc<ClientState>, ol: OpenLoop) {
        let conn = match connect(state.target) {
            Ok(f) => match f.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("  ringline client connect failed: {e}");
                    return;
                }
            },
            Err(e) => {
                eprintln!("  ringline client connect setup failed: {e}");
                return;
            }
        };

        let msg_size = state.msg_size;
        let msg = vec![0xABu8; msg_size];
        let per_conn_rate = (ol.rate as f64 / state.num_clients.max(1) as f64).max(1.0);
        let interval = 1.0 / per_conn_rate;

        // Single interleaved task: send a bounded burst of due requests, then do
        // one recv (the await is the yield point that lets other connections on
        // this single-threaded worker run). A separate sender task would starve
        // the reader on the same worker, so we keep both in one task. `fifo`
        // holds scheduled send-instants for in-flight requests (FIFO = echo
        // response order).
        const SEND_BURST: usize = 256;
        let start = Instant::now();
        let mut sent: u64 = 0;
        let mut fifo: VecDeque<Instant> = VecDeque::new();
        let mut samples: Vec<u64> = Vec::with_capacity(1_000_000);
        let mut local_ops: u64 = 0;
        // Bytes received toward the next not-yet-complete response, carried
        // across recv wakes (responses are a fixed msg_size byte stream).
        let mut partial: usize = 0;

        'outer: loop {
            // Exit promptly once stopped — the measurement window is over, so
            // there's no value in draining in-flight responses, and waiting to
            // drain risks the task being force-dropped at shutdown before it can
            // flush its recorded samples.
            if state.stop.load(Ordering::Relaxed) {
                break;
            }

            // Send all currently-due requests, bounded by in-flight and a burst
            // cap so we return to recv frequently.
            let mut burst = 0;
            let mut pool_full = false;
            while fifo.len() < ol.max_inflight && burst < SEND_BURST {
                let target = start + Duration::from_secs_f64(interval * sent as f64);
                if Instant::now() < target {
                    break; // next request not due yet
                }
                if conn.send_nowait(&msg).is_err() {
                    pool_full = true;
                    break; // send pool full; drain responses first
                }
                fifo.push_back(target);
                sent += 1;
                burst += 1;
            }

            if fifo.is_empty() {
                if pool_full {
                    // Behind but the send pool is exhausted with nothing of ours
                    // in flight to recv. Yield so in-flight sends (other conns)
                    // complete and free the pool — without this the loop
                    // busy-spins on failed sends and starves completion
                    // processing, so the pool never drains (overload collapse).
                    sleep(Duration::from_micros(50)).await;
                } else {
                    // Caught up: sleep until the next request is due.
                    let target = start + Duration::from_secs_f64(interval * sent as f64);
                    let now = Instant::now();
                    if now < target {
                        sleep(target - now).await;
                    } else {
                        sleep(Duration::from_micros(10)).await; // spin guard
                    }
                }
                continue;
            }

            // Drain every complete response available in one wake (blocks for at
            // least one byte; the await is this task's yield point). Consuming
            // the whole accumulator per wake — instead of one response per loop
            // iteration — is what lets the generator keep up at high rates. With
            // a fixed msg_size, the number of newly-complete responses is
            // (partial + consumed) / msg_size; the leftover is carried in
            // `partial`.
            let consumed = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if consumed == 0 {
                break 'outer; // EOF
            }
            partial += consumed;
            let completed = partial / msg_size;
            partial -= completed * msg_size;
            let measuring = state.measure.load(Ordering::Relaxed);
            for _ in 0..completed {
                if let Some(sched) = fifo.pop_front()
                    && measuring
                {
                    samples.push(sched.elapsed().as_nanos() as u64);
                    local_ops += 1;
                    if local_ops & 0xFF == 0 {
                        state.ops.fetch_add(256, Ordering::Relaxed);
                    }
                }
            }
        }
        state.ops.fetch_add(local_ops & 0xFF, Ordering::Relaxed);
        state.histograms.lock().unwrap().push(samples);
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
            config.sq_entries = 4096;
            config.recv_buffer.ring_size = 4096;
            config.recv_buffer.buffer_size = msg_size.next_power_of_two().max(4096) as u32;
            config.max_connections = 4096;
            // The send-copy pool is the open-loop in-flight ceiling: it must
            // comfortably exceed max_inflight * (conns per worker), or sends fail
            // below capacity. Keep a generous slot count; don't reserve 4 KiB per
            // slot for tiny messages.
            config.send_copy_count = 32768;
            config.send_copy_slot_size = msg_size.next_power_of_two().max(256) as u32;

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
///
/// `open` selects open-loop (rate-controlled) mode; `None` is the closed-loop
/// request/response loop.
#[allow(clippy::too_many_arguments)]
pub fn run_bench(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    ringline_client: bool,
    workers: usize,
    open: Option<OpenLoop>,
) -> BenchResult {
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));

    wait_for_server(addr);

    if ringline_client {
        run_bench_ringline(
            addr,
            num_clients,
            msg_size,
            warmup,
            duration,
            stop,
            ops,
            workers,
            open,
        )
    } else {
        run_bench_tokio(
            addr,
            num_clients,
            msg_size,
            warmup,
            duration,
            stop,
            ops,
            workers,
            open,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn run_bench_tokio(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    workers: usize,
    open: Option<OpenLoop>,
) -> BenchResult {
    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers.max(1))
        .enable_all()
        .build()
        .expect("failed to build client runtime");

    let measure = Arc::new(AtomicBool::new(false));
    let per_conn_rate = open.map(|o| o.rate as f64 / num_clients.max(1) as f64);

    let mut task_handles = Vec::with_capacity(num_clients);
    for _ in 0..num_clients {
        let addr = addr.to_string();
        let stop = stop.clone();
        let ops = ops.clone();
        if let Some(o) = open {
            let measure = measure.clone();
            let rate = per_conn_rate.unwrap().max(1.0);
            task_handles.push(client_rt.spawn(run_tokio_open_client(
                addr,
                msg_size,
                rate,
                o.max_inflight,
                measure,
                stop,
                ops,
            )));
        } else {
            task_handles.push(client_rt.spawn(run_tokio_client(addr, msg_size, stop, ops)));
        }
    }

    std::thread::sleep(warmup);
    ops.store(0, Ordering::Relaxed);
    measure.store(true, Ordering::Relaxed);

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

    // For open-loop, achieved throughput = measured responses; derive it from
    // the sample count so it stays consistent with the latency histogram.
    let total_ops = if open.is_some() {
        merged.samples().len() as u64
    } else {
        ops.load(Ordering::Relaxed)
    };
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

    BenchResult {
        ops_per_sec,
        total_ops,
        latency: merged.finalize(),
        cpu_ns: cpu_after.saturating_sub(cpu_before),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_bench_ringline(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    stop: Arc<AtomicBool>,
    ops: Arc<AtomicU64>,
    workers: usize,
    open: Option<OpenLoop>,
) -> BenchResult {
    let histograms = Arc::new(Mutex::new(Vec::new()));
    let measure = Arc::new(AtomicBool::new(false));

    let state = Arc::new(ringline_client::ClientState {
        target: addr.parse().expect("invalid addr for ringline client"),
        msg_size,
        num_clients,
        // Total connections to open, distributed across workers (each worker's
        // on_start drains this counter, so the total is exact).
        remaining: Arc::new(std::sync::atomic::AtomicUsize::new(num_clients)),
        stop: stop.clone(),
        measure: measure.clone(),
        ops: ops.clone(),
        histograms: histograms.clone(),
        open,
    });

    let client_rt = match ringline_client::RinglineClientRuntime::start(state, workers.max(1)) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("  ringline client failed to start: {e}");
            return BenchResult {
                ops_per_sec: 0.0,
                total_ops: 0,
                latency: LatencyHistogram::new().finalize(),
                cpu_ns: 0,
            };
        }
    };

    std::thread::sleep(warmup);
    ops.store(0, Ordering::Relaxed);
    measure.store(true, Ordering::Relaxed);

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

    // For open-loop, achieved throughput = measured responses; derive it from
    // the sample count so it stays consistent with the latency histogram.
    let total_ops = if open.is_some() {
        merged.samples().len() as u64
    } else {
        ops.load(Ordering::Relaxed)
    };
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

    BenchResult {
        ops_per_sec,
        total_ops,
        latency: merged.finalize(),
        cpu_ns: cpu_after.saturating_sub(cpu_before),
    }
}
