//! Standalone echo client for distributed benchmarking.
//!
//! Drives load against a server, measures latency and throughput,
//! and outputs JSON results to stdout. The `--runtime` flag selects the
//! load-generator runtime (ringline or tokio), mirroring `bench-server`.
//!
//! Usage:
//!   bench-client --runtime tokio    --addr 10.0.1.5:7878 --clients 100  --msg-size 64   --duration 10
//!   bench-client --runtime ringline --addr 10.0.1.5:7878 --clients 1000 --msg-size 4096 --duration 30 --warmup 5

use std::time::Duration;

use clap::Parser;
use serde::Serialize;

use ringline_bench::client::run_bench;

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Runtime {
    Ringline,
    Tokio,
}

#[derive(Parser)]
#[command(
    name = "bench-client",
    about = "Echo client for distributed benchmarking"
)]
struct Args {
    /// Load-generator runtime
    #[arg(long)]
    runtime: Runtime,

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

    /// Number of load-generation worker threads (applies to both runtimes;
    /// connections are distributed across them)
    #[arg(long, default_value_t = 8)]
    threads: usize,
}

#[derive(Serialize)]
struct ClientReport {
    addr: String,
    runtime: String,
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

fn main() {
    let args = Args::parse();

    let runtime_name = match args.runtime {
        Runtime::Ringline => "ringline",
        Runtime::Tokio => "tokio",
    };

    eprintln!(
        "bench-client: {} runtime, {} clients, {}B messages, {}s warmup + {}s test -> {}",
        runtime_name, args.clients, args.msg_size, args.warmup, args.duration, args.addr,
    );

    let result = run_bench(
        &args.addr,
        args.clients,
        args.msg_size,
        Duration::from_secs(args.warmup),
        Duration::from_secs(args.duration),
        args.runtime == Runtime::Ringline,
        args.threads,
    );

    let report = ClientReport {
        addr: args.addr,
        runtime: runtime_name.to_string(),
        clients: args.clients,
        msg_size: args.msg_size,
        duration_secs: args.duration,
        ops_per_sec: result.ops_per_sec,
        total_ops: result.total_ops,
        p50_ns: result.latency.p50_ns,
        p90_ns: result.latency.p90_ns,
        p99_ns: result.latency.p99_ns,
        p999_ns: result.latency.p999_ns,
        p9999_ns: result.latency.p9999_ns,
        max_ns: result.latency.max_ns,
        sample_count: result.latency.count,
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
