mod client;
mod output;
mod servers;
mod stats;

use std::time::Duration;

use clap::Parser;

use crate::output::{BenchReport, ConfigResult};
use crate::stats::format_size;

#[derive(Parser)]
#[command(
    name = "ringline-bench",
    about = "Echo server benchmark: ringline vs tokio (2x2 matrix)"
)]
struct Args {
    /// Test duration per configuration (seconds)
    #[arg(long, default_value_t = 5)]
    duration: u64,

    /// Warmup duration (seconds)
    #[arg(long, default_value_t = 2)]
    warmup: u64,

    /// Number of server worker threads (0 = available parallelism)
    #[arg(long, default_value_t = 0)]
    workers: usize,

    /// Comma-separated client counts
    #[arg(long, default_value = "1,10,50,200,1000", value_delimiter = ',')]
    clients: Vec<usize>,

    /// Comma-separated message sizes in bytes
    #[arg(long, default_value = "64,512,4096,32768", value_delimiter = ',')]
    sizes: Vec<usize>,

    /// Write JSON results to file
    #[arg(long)]
    json: Option<String>,

    /// Run a single quick config (4 clients, 64B)
    #[arg(long)]
    quick: bool,

    /// Skip tokio server
    #[arg(long)]
    ringline_only: bool,

    /// Skip ringline server (e.g. on non-Linux)
    #[arg(long)]
    tokio_only: bool,
}

fn run_server_bench(
    addr: &str,
    num_clients: usize,
    msg_size: usize,
    warmup: Duration,
    duration: Duration,
    server_label: &str,
    ringline_client: bool,
) -> stats::BenchResult {
    let client_label = if ringline_client { "ringline" } else { "tokio" };
    eprint!(
        "  {:>8} -> {:<8}  {:>4}c x {:>5}: ",
        client_label,
        server_label,
        num_clients,
        format_size(msg_size),
    );

    let r = client::run_bench(
        addr,
        num_clients,
        msg_size,
        warmup,
        duration,
        ringline_client,
    );

    eprintln!(
        "{:>9.0} ops/s  p50: {}  p99: {}  p999: {}",
        r.ops_per_sec,
        stats::format_ns(r.latency.p50_ns),
        stats::format_ns(r.latency.p99_ns),
        stats::format_ns(r.latency.p999_ns),
    );

    r
}

fn main() {
    let mut args = Args::parse();

    if args.quick {
        args.clients = vec![4];
        args.sizes = vec![64];
    }

    let workers = if args.workers == 0 {
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1)
    } else {
        args.workers
    };

    let duration = Duration::from_secs(args.duration);
    let warmup = Duration::from_secs(args.warmup);

    let worker_counts: Vec<usize> = if args.workers != 0 {
        vec![workers]
    } else {
        let mut v = vec![1];
        if workers > 1 {
            v.push(workers);
        }
        v
    };

    eprintln!(
        "Echo benchmark: worker counts {:?}, {}s warmup + {}s per config",
        worker_counts, args.warmup, args.duration,
    );
    eprintln!("  clients: {:?}", args.clients);
    eprintln!(
        "  sizes:   {:?}",
        args.sizes
            .iter()
            .map(|s| format_size(*s))
            .collect::<Vec<_>>()
    );
    eprintln!("  matrix:  {{tokio, ringline}} client x {{ringline, tokio}} server");
    eprintln!();

    let mut results: Vec<ConfigResult> = Vec::new();
    let mut port: u16 = 19400;
    let mut ringline_available = !args.tokio_only;

    for &w in &worker_counts {
        for &num_clients in &args.clients {
            for &msg_size in &args.sizes {
                let mut config = ConfigResult {
                    workers: w,
                    clients: num_clients,
                    msg_size,
                    tokio_ringline: None,
                    tokio_tokio: None,
                    ringline_ringline: None,
                    ringline_tokio: None,
                };

                // ── ringline server ────────────────────────────────
                if ringline_available {
                    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
                    port += 1;

                    match servers::ringline_echo::RinglineServer::start(addr, w, msg_size) {
                        Ok(server) => {
                            let addr_str = addr.to_string();

                            config.tokio_ringline = Some(run_server_bench(
                                &addr_str,
                                num_clients,
                                msg_size,
                                warmup,
                                duration,
                                "ringline",
                                false,
                            ));
                            config.ringline_ringline = Some(run_server_bench(
                                &addr_str,
                                num_clients,
                                msg_size,
                                warmup,
                                duration,
                                "ringline",
                                true,
                            ));

                            server.stop();
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(e) => {
                            eprintln!("  ringline server: skipped ({})", e);
                            ringline_available = false;
                        }
                    }
                }

                // ── tokio server ───────────────────────────────────
                if !args.ringline_only {
                    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
                    port += 1;

                    let server = servers::tokio_echo::TokioServer::start(addr, w);
                    let addr_str = addr.to_string();

                    config.tokio_tokio = Some(run_server_bench(
                        &addr_str,
                        num_clients,
                        msg_size,
                        warmup,
                        duration,
                        "tokio",
                        false,
                    ));
                    config.ringline_tokio = Some(run_server_bench(
                        &addr_str,
                        num_clients,
                        msg_size,
                        warmup,
                        duration,
                        "tokio",
                        true,
                    ));

                    server.stop();
                    std::thread::sleep(Duration::from_millis(100));
                }

                eprintln!();
                results.push(config);
            }
        }
    }

    // ── Summary tables ─────────────────────────────────────────────
    for &w in &worker_counts {
        output::print_table(w, &results);
    }

    // ── JSON output ────────────────────────────────────────────────
    if let Some(ref path) = args.json {
        let report = BenchReport {
            timestamp: output::timestamp(),
            git_commit: output::git_commit(),
            configs: results,
        };
        output::write_json(path, &report);
    }
}
