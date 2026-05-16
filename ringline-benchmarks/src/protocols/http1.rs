use crate::stats::{BenchResult, LatencyStats};

/// Run HTTP/1.1 benchmarks for a single configuration.
#[allow(clippy::too_many_arguments)]
pub fn run_http1(
    _port_manager: &crate::port_manager::PortManager,
    _workers: usize,
    _num_clients: usize,
    _msg_size: usize,
    _warmup: std::time::Duration,
    _duration: std::time::Duration,
    _client_runtime: crate::bench::ClientRuntime,
    _server_runtime: crate::bench::ServerRuntime,
) -> BenchResult {
    // TODO: HTTP/1.1 implementation
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
