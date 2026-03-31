use serde::Serialize;

use crate::stats::{BenchResult, format_ns, format_size};

#[derive(Serialize)]
pub struct BenchReport {
    pub timestamp: String,
    pub git_commit: String,
    pub configs: Vec<ConfigResult>,
}

#[derive(Serialize)]
pub struct ConfigResult {
    pub workers: usize,
    pub clients: usize,
    pub msg_size: usize,
    /// tokio client → ringline server
    pub tokio_ringline: Option<BenchResult>,
    /// tokio client → tokio server
    pub tokio_tokio: Option<BenchResult>,
    /// ringline client → ringline server
    pub ringline_ringline: Option<BenchResult>,
    /// ringline client → tokio server
    pub ringline_tokio: Option<BenchResult>,
}

pub fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn timestamp() -> String {
    std::process::Command::new("date")
        .arg("--iso-8601=seconds")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Print a comparison table for a given worker count.
pub fn print_table(workers: usize, rows: &[ConfigResult]) {
    eprintln!();
    eprintln!("## Echo Benchmark — {} worker(s)", workers);
    eprintln!();
    eprintln!(
        "| Clients | MsgSize | Client   | Server   | ops/s      | p50        | p90        | p99        | p999       | p9999      | max        |"
    );
    eprintln!(
        "|---------|---------|----------|----------|------------|------------|------------|------------|------------|------------|------------|"
    );

    for row in rows {
        if row.workers != workers {
            continue;
        }
        let size = format_size(row.msg_size);

        let pairs: &[(&str, &str, &Option<BenchResult>)] = &[
            ("tokio   ", "ringline", &row.tokio_ringline),
            ("tokio   ", "tokio   ", &row.tokio_tokio),
            ("ringline", "ringline", &row.ringline_ringline),
            ("ringline", "tokio   ", &row.ringline_tokio),
        ];

        for &(client, server, result) in pairs {
            if let Some(r) = result {
                eprintln!(
                    "| {:>7} | {:>7} | {} | {} | {:>10.0} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} |",
                    row.clients,
                    size,
                    client,
                    server,
                    r.ops_per_sec,
                    format_ns(r.latency.p50_ns),
                    format_ns(r.latency.p90_ns),
                    format_ns(r.latency.p99_ns),
                    format_ns(r.latency.p999_ns),
                    format_ns(r.latency.p9999_ns),
                    format_ns(r.latency.max_ns),
                );
            }
        }

        // Delta rows: ringline server vs tokio server, per client type.
        print_delta_row(
            row,
            "tokio",
            row.tokio_ringline.as_ref(),
            row.tokio_tokio.as_ref(),
        );
        print_delta_row(
            row,
            "ringline",
            row.ringline_ringline.as_ref(),
            row.ringline_tokio.as_ref(),
        );
    }
}

fn print_delta_row(
    row: &ConfigResult,
    client_label: &str,
    ringline: Option<&BenchResult>,
    tokio: Option<&BenchResult>,
) {
    if let (Some(r), Some(t)) = (ringline, tokio) {
        let size = format_size(row.msg_size);
        let ops_delta = (r.ops_per_sec - t.ops_per_sec) / t.ops_per_sec * 100.0;
        let p50_delta = delta_pct(r.latency.p50_ns, t.latency.p50_ns);
        let p99_delta = delta_pct(r.latency.p99_ns, t.latency.p99_ns);
        let p999_delta = delta_pct(r.latency.p999_ns, t.latency.p999_ns);
        let p9999_delta = delta_pct(r.latency.p9999_ns, t.latency.p9999_ns);

        eprintln!(
            "| {:>7} | {:>7} | {:<8} | **delta**| {:>+9.1}% | {:>+9.1}% |            | {:>+9.1}% | {:>+9.1}% | {:>+9.1}% |            |",
            row.clients,
            size,
            client_label,
            ops_delta,
            p50_delta,
            p99_delta,
            p999_delta,
            p9999_delta,
        );
    }
}

/// Percentage change in latency (negative = ringline is lower/better).
fn delta_pct(ringline_ns: u64, tokio_ns: u64) -> f64 {
    if tokio_ns == 0 {
        return 0.0;
    }
    (ringline_ns as f64 - tokio_ns as f64) / tokio_ns as f64 * 100.0
}

pub fn write_json(path: &str, report: &BenchReport) {
    let json = serde_json::to_string_pretty(report).expect("failed to serialize");
    std::fs::write(path, json).expect("failed to write JSON");
    eprintln!();
    eprintln!("JSON results written to {path}");
}
