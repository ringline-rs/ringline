use serde::Serialize;
use std::time::Instant;

use crate::stats::{BenchResult, format_ns};

#[derive(Serialize)]
pub struct ConfigResult {
    pub workers: usize,
    pub clients: usize,
    pub msg_size: usize,
    pub client_runtime: String,
    pub server_runtime: String,
    pub transport: String,
    pub protocol: String,
    pub tls: String,
    pub tokio_ringline: Option<BenchResult>,
    pub tokio_tokio: Option<BenchResult>,
    pub ringline_ringline: Option<BenchResult>,
    pub ringline_tokio: Option<BenchResult>,
}

#[derive(Serialize)]
pub struct BenchReport {
    pub timestamp: String,
    pub git_commit: String,
    pub configs: Vec<ConfigResult>,
}

pub fn timestamp() -> String {
    let now = Instant::now();
    let duration = now.elapsed();
    let (hours, minutes, seconds) = (
        duration.as_secs() / 3600,
        (duration.as_secs() % 3600) / 60,
        duration.as_secs() % 60,
    );
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

pub fn git_commit() -> String {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8(o.stdout).unwrap_or_default(),
        _ => "unknown".to_string(),
    }
}

pub fn print_table(results: &[ConfigResult]) {
    // Summary row
    let total_configs = results.len();
    eprintln!("\n=== Summary: {} configurations ===\n", total_configs);

    for r in results {
        eprintln!(
            "  {}x{}  {} -> {}  {}",
            r.clients, r.msg_size, r.transport, r.protocol, r.tls,
        );

        if let Some(ringline_ringline) = &r.ringline_ringline {
            eprintln!(
                "    ringline -> ringline:  {:>9.0} ops/s  p50: {}  p99: {}",
                ringline_ringline.ops_per_sec,
                format_ns(ringline_ringline.latency.p50_ns),
                format_ns(ringline_ringline.latency.p99_ns),
            );
        }

        if let Some(tokio_tokio) = &r.tokio_tokio {
            eprintln!(
                "    tokio -> tokio:        {:>9.0} ops/s  p50: {}  p99: {}",
                tokio_tokio.ops_per_sec,
                format_ns(tokio_tokio.latency.p50_ns),
                format_ns(tokio_tokio.latency.p99_ns),
            );
        }
    }
}

pub fn write_json(path: &str, report: &BenchReport) {
    let content = serde_json::to_string_pretty(report).unwrap();
    std::fs::write(path, content).expect("failed to write JSON output");
}
