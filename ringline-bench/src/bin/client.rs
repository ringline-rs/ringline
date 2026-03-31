//! Standalone echo client for distributed benchmarking.
//!
//! Drives load against a server, measures latency and throughput,
//! and outputs JSON results to stdout.
//!
//! Usage:
//!   bench-client --addr 10.0.1.5:7878 --clients 100 --msg-size 64 --duration 10
//!   bench-client --addr 10.0.1.5:7878 --clients 1000 --msg-size 4096 --duration 30 --warmup 5

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Parser)]
#[command(
    name = "bench-client",
    about = "Echo client for distributed benchmarking"
)]
struct Args {
    /// Server address
    #[arg(long)]
    addr: String,

    /// Number of concurrent client connections
    #[arg(long, default_value_t = 1)]
    clients: usize,

    /// Message size in bytes
    #[arg(long, default_value_t = 64)]
    msg_size: usize,

    /// Test duration in seconds
    #[arg(long, default_value_t = 10)]
    duration: u64,

    /// Warmup duration in seconds
    #[arg(long, default_value_t = 3)]
    warmup: u64,

    /// Number of tokio worker threads for load generation
    #[arg(long, default_value_t = 4)]
    threads: usize,
}

#[derive(Serialize)]
struct ClientReport {
    addr: String,
    clients: usize,
    msg_size: usize,
    duration_secs: u64,
    ops_per_sec: f64,
    total_ops: u64,
    p50_ns: u64,
    p90_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    p9999_ns: u64,
    max_ns: u64,
    sample_count: u64,
}

struct LatencyHistogram {
    samples: Vec<u64>,
}

impl LatencyHistogram {
    fn new() -> Self {
        LatencyHistogram {
            samples: Vec::with_capacity(1_000_000),
        }
    }

    fn record(&mut self, ns: u64) {
        self.samples.push(ns);
    }

    fn samples(&self) -> &[u64] {
        &self.samples
    }
}

async fn run_client(
    addr: String,
    msg_size: usize,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
) -> LatencyHistogram {
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

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64) * p / 100.0) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn main() {
    let args = Args::parse();

    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.threads)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    eprintln!(
        "bench-client: {} clients, {}B messages, {}s warmup + {}s test -> {}",
        args.clients, args.msg_size, args.warmup, args.duration, args.addr,
    );

    // Wait for server to be reachable.
    for _ in 0..100 {
        if std::net::TcpStream::connect(&args.addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Spawn client tasks.
    let mut task_handles = Vec::with_capacity(args.clients);
    for _ in 0..args.clients {
        let addr = args.addr.clone();
        let stop = stop.clone();
        let ops = ops.clone();
        let msg_size = args.msg_size;
        task_handles.push(rt.spawn(run_client(addr, msg_size, stop, ops)));
    }

    // Warmup.
    eprintln!("bench-client: warming up for {}s", args.warmup);
    std::thread::sleep(Duration::from_secs(args.warmup));
    ops.store(0, Ordering::Relaxed);

    // Measurement.
    eprintln!("bench-client: measuring for {}s", args.duration);
    let start = Instant::now();
    std::thread::sleep(Duration::from_secs(args.duration));
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Relaxed);

    // Collect — give tasks a grace period, then abort stragglers stuck in I/O.
    let mut all_samples: Vec<u64> = Vec::new();
    rt.block_on(async {
        for handle in task_handles {
            match tokio::time::timeout(Duration::from_secs(2), handle).await {
                Ok(Ok(histogram)) => all_samples.extend_from_slice(histogram.samples()),
                Ok(Err(_join_err)) => {}
                Err(_timeout) => {
                    // Task stuck in I/O after stop was signaled — samples already
                    // recorded up to the last completed op, just move on.
                }
            }
        }
    });

    rt.shutdown_timeout(Duration::from_secs(1));

    all_samples.sort_unstable();

    let total_ops = ops.load(Ordering::Relaxed);
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

    let report = ClientReport {
        addr: args.addr,
        clients: args.clients,
        msg_size: args.msg_size,
        duration_secs: args.duration,
        ops_per_sec,
        total_ops,
        p50_ns: percentile(&all_samples, 50.0),
        p90_ns: percentile(&all_samples, 90.0),
        p99_ns: percentile(&all_samples, 99.0),
        p999_ns: percentile(&all_samples, 99.9),
        p9999_ns: percentile(&all_samples, 99.99),
        max_ns: all_samples.last().copied().unwrap_or(0),
        sample_count: all_samples.len() as u64,
    };

    // JSON to stdout for machine consumption.
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    // Human-readable summary to stderr.
    eprintln!(
        "bench-client: {:.0} ops/s, p50={:.1}us p99={:.1}us p999={:.1}us ({} samples)",
        report.ops_per_sec,
        report.p50_ns as f64 / 1000.0,
        report.p99_ns as f64 / 1000.0,
        report.p999_ns as f64 / 1000.0,
        report.sample_count,
    );
}
