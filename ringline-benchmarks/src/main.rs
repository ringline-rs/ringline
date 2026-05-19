use clap::Parser;
use std::time::Duration;

use ringline_benchmarks::bench::{ClientRuntime, ServerRuntime};
use ringline_benchmarks::output::{BenchReport, ConfigResult, git_commit, timestamp, write_json};
use ringline_benchmarks::port_manager::PortManager;
use ringline_benchmarks::protocols::http1;
use ringline_benchmarks::protocols::http2;
use ringline_benchmarks::protocols::http3;
use ringline_benchmarks::protocols::memcache;
use ringline_benchmarks::protocols::quic;
use ringline_benchmarks::protocols::redis;
use ringline_benchmarks::protocols::tcp;
use ringline_benchmarks::protocols::udp;
use ringline_benchmarks::stats::format_ns;
use std::sync::Arc;

#[derive(clap::Parser)]
#[command(
    name = "ringline-benchmarks",
    about = "Comprehensive performance benchmarking for ringline"
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
    #[arg(long, default_value = "1,10,50,200", value_delimiter = ',')]
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

    /// Skip ringline server (e.g. on non-Linux)
    #[arg(long)]
    tokio_only: bool,

    /// Skip tokio server
    #[arg(long)]
    ringline_only: bool,

    /// Run only specific benchmark categories (comma-separated: tcp,udp,quic,http1,http2,http3,redis,memcache,all)
    #[arg(long)]
    only: Option<String>,
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

    eprintln!(
        "Benchmarks: worker counts {:?}, {}s warmup + {}s per config",
        if args.workers == 0 {
            vec![1]
        } else {
            vec![workers]
        },
        args.warmup,
        args.duration,
    );
    eprintln!("  clients: {:?}", args.clients);
    eprintln!("  sizes:   {:?}", args.sizes);
    eprintln!();

    // Determine which benchmarks to run
    let (do_tcp, do_udp, do_quic, do_http1, do_http2, do_http3, do_redis, do_memcache, do_all) =
        match &args.only {
            None => (true, true, true, true, true, true, true, true, true),
            Some(only) => {
                let parts: Vec<&str> = only.split(',').collect();
                (
                    parts.contains(&"tcp"),
                    parts.contains(&"udp"),
                    parts.contains(&"quic"),
                    parts.contains(&"http1"),
                    parts.contains(&"http2"),
                    parts.contains(&"http3"),
                    parts.contains(&"redis"),
                    parts.contains(&"memcache"),
                    parts.contains(&"all"),
                )
            }
        };

    let port_manager = Arc::new(PortManager::new(19400));
    let mut all_results: Vec<ConfigResult> = Vec::new();

    // ── TCP echo benchmarks ───────────────────────────────────────
    if do_tcp || do_all {
        eprintln!("=== TCP Echo Benchmarks ===\n");

        let port_manager = port_manager.clone();
        for &num_clients in &args.clients {
            for &msg_size in &args.sizes {
                let combos: &[(&str, ClientRuntime, &str, ServerRuntime)] = &[
                    (
                        "ringline",
                        ClientRuntime::Ringline,
                        "ringline",
                        ServerRuntime::Ringline,
                    ),
                    (
                        "ringline",
                        ClientRuntime::Ringline,
                        "tokio",
                        ServerRuntime::Tokio,
                    ),
                    (
                        "tokio",
                        ClientRuntime::Tokio,
                        "ringline",
                        ServerRuntime::Ringline,
                    ),
                    ("tokio", ClientRuntime::Tokio, "tokio", ServerRuntime::Tokio),
                ];

                for &(client_name, client_rt, server_name, server_rt) in combos {
                    if args.tokio_only && server_rt == ServerRuntime::Ringline {
                        continue;
                    }
                    if args.ringline_only && server_rt == ServerRuntime::Tokio {
                        continue;
                    }

                    let (result, _) = tcp::run_tcp_echo(
                        &port_manager,
                        workers,
                        num_clients,
                        msg_size,
                        warmup,
                        duration,
                        client_rt,
                        server_rt,
                    );

                    eprintln!(
                        "  {:>8} -> {:<8}  {:>4}c x {:>5}: {:>9.0} ops/s  p50: {}  p99: {}",
                        client_name,
                        server_name,
                        num_clients,
                        format_size(msg_size),
                        result.ops_per_sec,
                        format_ns(result.latency.p50_ns),
                        format_ns(result.latency.p99_ns),
                    );

                    let (tokio_ringline, tokio_tokio, ringline_ringline, ringline_tokio) =
                        match (client_name, server_name) {
                            ("ringline", "ringline") => (None, None, Some(result), None),
                            ("ringline", "tokio") => (None, None, None, Some(result)),
                            ("tokio", "ringline") => (Some(result), None, None, None),
                            _ => (None, Some(result), None, None),
                        };

                    all_results.push(ConfigResult {
                        workers,
                        clients: num_clients,
                        msg_size,
                        client_runtime: client_name.to_string(),
                        server_runtime: server_name.to_string(),
                        transport: "tcp".to_string(),
                        protocol: "echo".to_string(),
                        tls: "none".to_string(),
                        tokio_ringline,
                        tokio_tokio,
                        ringline_ringline,
                        ringline_tokio,
                    });
                }

                eprintln!();
            }
        }
    }

    // ── UDP echo benchmarks ───────────────────────────────────────
    if do_udp || do_all {
        eprintln!("\n=== UDP Echo Benchmarks ===\n");

        let port_manager = port_manager.clone();
        for &num_clients in &args.clients {
            for &msg_size in &args.sizes {
                let combos: &[(&str, ClientRuntime, &str, ServerRuntime)] = &[
                    (
                        "ringline",
                        ClientRuntime::Ringline,
                        "ringline",
                        ServerRuntime::Ringline,
                    ),
                    (
                        "ringline",
                        ClientRuntime::Ringline,
                        "tokio",
                        ServerRuntime::Tokio,
                    ),
                    (
                        "tokio",
                        ClientRuntime::Tokio,
                        "ringline",
                        ServerRuntime::Ringline,
                    ),
                    ("tokio", ClientRuntime::Tokio, "tokio", ServerRuntime::Tokio),
                ];

                for &(client_name, client_rt, server_name, server_rt) in combos {
                    if args.tokio_only && server_rt == ServerRuntime::Ringline {
                        continue;
                    }
                    if args.ringline_only && server_rt == ServerRuntime::Tokio {
                        continue;
                    }

                    let (result, _) = udp::run_udp_echo(
                        &port_manager,
                        workers,
                        num_clients,
                        msg_size,
                        warmup,
                        duration,
                        client_rt,
                        server_rt,
                    );

                    eprintln!(
                        "  {:>8} -> {:<8}  {:>4}c x {:>5}: {:>9.0} ops/s  p50: {}  p99: {}",
                        client_name,
                        server_name,
                        num_clients,
                        format_size(msg_size),
                        result.ops_per_sec,
                        format_ns(result.latency.p50_ns),
                        format_ns(result.latency.p99_ns),
                    );

                    let (tokio_ringline, tokio_tokio, ringline_ringline, ringline_tokio) =
                        match (client_name, server_name) {
                            ("ringline", "ringline") => (None, None, Some(result), None),
                            ("ringline", "tokio") => (None, None, None, Some(result)),
                            ("tokio", "ringline") => (Some(result), None, None, None),
                            _ => (None, Some(result), None, None),
                        };

                    all_results.push(ConfigResult {
                        workers,
                        clients: num_clients,
                        msg_size,
                        client_runtime: client_name.to_string(),
                        server_runtime: server_name.to_string(),
                        transport: "udp".to_string(),
                        protocol: "echo".to_string(),
                        tls: "none".to_string(),
                        tokio_ringline,
                        tokio_tokio,
                        ringline_ringline,
                        ringline_tokio,
                    });
                }

                eprintln!();
            }
        }
    }

    // ── QUIC echo benchmarks ──────────────────────────────────────
    if do_quic || do_all {
        eprintln!("\n=== QUIC Echo Benchmarks ===\n");

        let port_manager = port_manager.clone();
        for &num_clients in &args.clients {
            for &msg_size in &args.sizes {
                let result = quic::run_quic(
                    &port_manager,
                    workers,
                    num_clients,
                    msg_size,
                    warmup,
                    duration,
                    ClientRuntime::Ringline,
                    ServerRuntime::Ringline,
                );

                eprint!(
                    "  {:>8} -> {:<8}  {:>4}c x {:>5}: ",
                    "ringline",
                    "ringline",
                    num_clients,
                    format_size(msg_size),
                );

                eprintln!(
                    "{:>9.0} ops/s  p50: {}  p99: {}",
                    result.ops_per_sec,
                    format_ns(result.latency.p50_ns),
                    format_ns(result.latency.p99_ns),
                );

                all_results.push(ConfigResult {
                    workers,
                    clients: num_clients,
                    msg_size,
                    client_runtime: "ringline".to_string(),
                    server_runtime: "ringline".to_string(),
                    transport: "quic".to_string(),
                    protocol: "echo".to_string(),
                    tls: "none".to_string(),
                    tokio_ringline: None,
                    tokio_tokio: None,
                    ringline_ringline: Some(result),
                    ringline_tokio: None,
                });

                eprintln!();
            }
        }
    }

    // ── HTTP/1.1 benchmarks ───────────────────────────────────────
    //
    // Same shape as Redis / Memcache: a single tokio server is the
    // target; we drive it with both a `ringline-http` HTTP/1.1
    // client and a hand-rolled keep-alive tokio TCP client so the
    // per-cell row pair shows which client runtime wins on the same
    // wire format.
    if do_http1 || do_all {
        eprintln!("\n=== HTTP/1.1 Benchmarks ===\n");

        let port_manager = port_manager.clone();
        for &num_clients in &args.clients {
            for &msg_size in &args.sizes {
                let combos: &[(&str, ClientRuntime)] = &[
                    ("ringline", ClientRuntime::Ringline),
                    ("tokio", ClientRuntime::Tokio),
                ];

                for &(client_name, client_rt) in combos {
                    let result = http1::run_http1(
                        &port_manager,
                        workers,
                        num_clients,
                        msg_size,
                        warmup,
                        duration,
                        client_rt,
                        ServerRuntime::Ringline,
                    );

                    eprintln!(
                        "  {:>8} -> {:<8}  {:>4}c x {:>5}: {:>9.0} ops/s  p50: {}  p99: {}",
                        client_name,
                        "tokio",
                        num_clients,
                        format_size(msg_size),
                        result.ops_per_sec,
                        format_ns(result.latency.p50_ns),
                        format_ns(result.latency.p99_ns),
                    );

                    let (ringline_tokio, tokio_tokio) = match client_name {
                        "ringline" => (Some(result), None),
                        _ => (None, Some(result)),
                    };

                    all_results.push(ConfigResult {
                        workers,
                        clients: num_clients,
                        msg_size,
                        client_runtime: client_name.to_string(),
                        server_runtime: "tokio".to_string(),
                        transport: "http1".to_string(),
                        protocol: "get".to_string(),
                        tls: "none".to_string(),
                        tokio_ringline: None,
                        tokio_tokio,
                        ringline_ringline: None,
                        ringline_tokio,
                    });
                }

                eprintln!();
            }
        }
    }

    // ── HTTP/2 benchmarks ─────────────────────────────────────────
    //
    // Same shape as HTTP/1.1, but the bench server is hyper-over-TLS
    // (HTTP/2 requires TLS as far as ringline-http is concerned —
    // there is no h2c path). Self-signed cert at startup, both
    // clients trust it explicitly. Reqwest is the reference; same
    // builder + structured response as ringline-http.
    if do_http2 || do_all {
        eprintln!("\n=== HTTP/2 Benchmarks ===\n");

        let port_manager = port_manager.clone();
        for &num_clients in &args.clients {
            for &msg_size in &args.sizes {
                let combos: &[(&str, ClientRuntime)] = &[
                    ("ringline", ClientRuntime::Ringline),
                    ("tokio", ClientRuntime::Tokio),
                ];

                for &(client_name, client_rt) in combos {
                    let result = http2::run_http2(
                        &port_manager,
                        workers,
                        num_clients,
                        msg_size,
                        warmup,
                        duration,
                        client_rt,
                        ServerRuntime::Ringline,
                    );

                    eprintln!(
                        "  {:>8} -> {:<8}  {:>4}c x {:>5}: {:>9.0} ops/s  p50: {}  p99: {}",
                        client_name,
                        "tokio",
                        num_clients,
                        format_size(msg_size),
                        result.ops_per_sec,
                        format_ns(result.latency.p50_ns),
                        format_ns(result.latency.p99_ns),
                    );

                    let (ringline_tokio, tokio_tokio) = match client_name {
                        "ringline" => (Some(result), None),
                        _ => (None, Some(result)),
                    };

                    all_results.push(ConfigResult {
                        workers,
                        clients: num_clients,
                        msg_size,
                        client_runtime: client_name.to_string(),
                        server_runtime: "tokio".to_string(),
                        transport: "http2".to_string(),
                        protocol: "get".to_string(),
                        tls: "rustls".to_string(),
                        tokio_ringline: None,
                        tokio_tokio,
                        ringline_ringline: None,
                        ringline_tokio,
                    });
                }

                eprintln!();
            }
        }
    }

    // ── HTTP/3 benchmarks ─────────────────────────────────────────
    if do_http3 || do_all {
        eprintln!("\n=== HTTP/3 Benchmarks ===\n");

        let port_manager = port_manager.clone();
        for &num_clients in &args.clients {
            for &msg_size in &args.sizes {
                let result = http3::run_http3(
                    &port_manager,
                    workers,
                    num_clients,
                    msg_size,
                    warmup,
                    duration,
                    ClientRuntime::Ringline,
                    ServerRuntime::Ringline,
                );

                eprint!(
                    "  {:>8} -> {:<8}  {:>4}c x {:>5}: ",
                    "ringline",
                    "ringline",
                    num_clients,
                    format_size(msg_size),
                );

                eprintln!(
                    "{:>9.0} ops/s  p50: {}  p99: {}",
                    result.ops_per_sec,
                    format_ns(result.latency.p50_ns),
                    format_ns(result.latency.p99_ns),
                );

                all_results.push(ConfigResult {
                    workers,
                    clients: num_clients,
                    msg_size,
                    client_runtime: "ringline".to_string(),
                    server_runtime: "ringline".to_string(),
                    transport: "http3".to_string(),
                    protocol: "echo".to_string(),
                    tls: "none".to_string(),
                    tokio_ringline: None,
                    tokio_tokio: None,
                    ringline_ringline: Some(result),
                    ringline_tokio: None,
                });

                eprintln!();
            }
        }
    }

    // ── Redis benchmarks ───────────────────────────────────────────
    //
    // The redis bench has a single server implementation (a tokio
    // RESP responder in `redis::run_redis`), so the meaningful axis
    // is *client* runtime: ringline-redis::Client vs a hand-rolled
    // tokio RESP client. Both go over the same wire format against
    // the same server.
    if do_redis || do_all {
        eprintln!("\n=== Redis Benchmarks ===\n");

        let port_manager = port_manager.clone();
        for &num_clients in &args.clients {
            for &msg_size in &args.sizes {
                let combos: &[(&str, ClientRuntime)] = &[
                    ("ringline", ClientRuntime::Ringline),
                    ("tokio", ClientRuntime::Tokio),
                ];

                for &(client_name, client_rt) in combos {
                    let result = redis::run_redis(
                        &port_manager,
                        workers,
                        num_clients,
                        msg_size,
                        warmup,
                        duration,
                        client_rt,
                        ServerRuntime::Ringline,
                    );

                    eprintln!(
                        "  {:>8} -> {:<8}  {:>4}c x {:>5}: {:>9.0} ops/s  p50: {}  p99: {}",
                        client_name,
                        "tokio",
                        num_clients,
                        format_size(msg_size),
                        result.ops_per_sec,
                        format_ns(result.latency.p50_ns),
                        format_ns(result.latency.p99_ns),
                    );

                    let (ringline_tokio, tokio_tokio) = match client_name {
                        "ringline" => (Some(result), None),
                        _ => (None, Some(result)),
                    };

                    all_results.push(ConfigResult {
                        workers,
                        clients: num_clients,
                        msg_size,
                        client_runtime: client_name.to_string(),
                        server_runtime: "tokio".to_string(),
                        transport: "redis".to_string(),
                        protocol: "get".to_string(),
                        tls: "none".to_string(),
                        tokio_ringline: None,
                        tokio_tokio,
                        ringline_ringline: None,
                        ringline_tokio,
                    });
                }

                eprintln!();
            }
        }
    }

    // ── Memcache benchmarks ────────────────────────────────────────
    //
    // Same shape as the Redis bench: a single tokio server is the
    // target; we drive it with both a ringline-memcache client and a
    // hand-rolled tokio TCP client so the per-cell row pair shows
    // which client runtime wins on the same wire format.
    if do_memcache || do_all {
        eprintln!("\n=== Memcache Benchmarks ===\n");

        let port_manager = port_manager.clone();
        for &num_clients in &args.clients {
            for &msg_size in &args.sizes {
                let combos: &[(&str, ClientRuntime)] = &[
                    ("ringline", ClientRuntime::Ringline),
                    ("tokio", ClientRuntime::Tokio),
                ];

                for &(client_name, client_rt) in combos {
                    let result = memcache::run_memcache(
                        &port_manager,
                        workers,
                        num_clients,
                        msg_size,
                        warmup,
                        duration,
                        client_rt,
                        ServerRuntime::Ringline,
                    );

                    eprintln!(
                        "  {:>8} -> {:<8}  {:>4}c x {:>5}: {:>9.0} ops/s  p50: {}  p99: {}",
                        client_name,
                        "tokio",
                        num_clients,
                        format_size(msg_size),
                        result.ops_per_sec,
                        format_ns(result.latency.p50_ns),
                        format_ns(result.latency.p99_ns),
                    );

                    let (ringline_tokio, tokio_tokio) = match client_name {
                        "ringline" => (Some(result), None),
                        _ => (None, Some(result)),
                    };

                    all_results.push(ConfigResult {
                        workers,
                        clients: num_clients,
                        msg_size,
                        client_runtime: client_name.to_string(),
                        server_runtime: "tokio".to_string(),
                        transport: "memcache".to_string(),
                        protocol: "get".to_string(),
                        tls: "none".to_string(),
                        tokio_ringline: None,
                        tokio_tokio,
                        ringline_ringline: None,
                        ringline_tokio,
                    });
                }

                eprintln!();
            }
        }
    }

    // ── JSON output ───────────────────────────────────────────────
    if let Some(ref path) = args.json {
        let report = BenchReport {
            timestamp: timestamp(),
            git_commit: git_commit(),
            configs: all_results,
        };
        write_json(path, &report);
    }
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}B", bytes)
    }
}
