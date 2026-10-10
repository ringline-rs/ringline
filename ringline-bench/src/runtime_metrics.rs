//! Dump ringline's runtime counters at shutdown.
//!
//! The runtime counts the things that explain a benchmark result rather than
//! merely state it — `buffer_ring_empty`, `recv_parked`, `recv_fallback`,
//! `forward_throttled`, `recv_arm_failures` — but nothing in the workspace read
//! them back out, so a sweep could report that an arm was slower without being
//! able to say whether it starved its provided ring, degraded to the fallback
//! recv, or did neither.
//!
//! This walks the metriken registry and writes it as JSON. It is a
//! whole-process snapshot: ringline's counters are sharded per thread and
//! summed on read, so the numbers cover every worker, and they are cumulative
//! since start (take the difference across a warmup if an arm needs only its
//! measured window).

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use metriken::Value;

/// One counter: its full name, the `op` label if the group gave it one, and
/// its value.
#[derive(serde::Serialize)]
struct Entry {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    op: Option<String>,
    value: i128,
}

/// Collect every registered metric into a stable, diffable order.
fn collect() -> Vec<Entry> {
    let mut out: BTreeMap<(String, Option<String>), i128> = BTreeMap::new();

    for metric in metriken::metrics().iter() {
        let name = metric.name().to_string();
        match metric.value() {
            Some(Value::Counter(v)) => {
                out.insert((name, None), v as i128);
            }
            Some(Value::Gauge(v)) => {
                out.insert((name, None), v as i128);
            }
            Some(Value::CounterGroup(group)) => {
                // Sparse metadata: a group entry without an `op` label is
                // still reported, keyed by index, so a counter someone forgot
                // to label does not vanish from the dump.
                let meta: BTreeMap<usize, _> = group.metadata_snapshot().into_iter().collect();
                for idx in 0..group.entries() {
                    // A counter nobody has incremented reads back as `None`,
                    // not `Some(0)`. Reporting it as 0 is what makes the dump
                    // trustworthy: "this arm starved its ring zero times" and
                    // "this dump never found the counter" have to look
                    // different, or a healthy arm and a broken harness are
                    // the same empty file.
                    let v = group.counter_value(idx).unwrap_or(0);
                    let op = meta
                        .get(&idx)
                        .and_then(|m| m.get("op").cloned())
                        .unwrap_or_else(|| format!("idx{idx}"));
                    out.insert((name.clone(), Some(op)), v as i128);
                }
            }
            // Gauge groups and histograms: no ringline counter uses them today.
            // Skipped rather than guessed at, so the dump never invents a shape.
            _ => {}
        }
    }

    out.into_iter()
        .map(|((name, op), value)| Entry { name, op, value })
        .collect()
}

/// Write the registry to `path` as JSON.
///
/// Errors are the caller's to report: a benchmark that cannot write its
/// counters has lost the evidence for its own result, so this is worth a loud
/// message rather than a silent skip.
pub fn dump_to(path: &Path) -> io::Result<()> {
    let entries = collect();
    let json = serde_json::to_string_pretty(&entries)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Print the counters that usually explain a result, one line each, to stderr.
///
/// The JSON file is for the harness; this is for a human reading a job log and
/// wondering why an arm was slow.
pub fn print_summary() {
    let entries = collect();
    let interesting = [
        "buffer_ring_empty",
        "recv_parked",
        "recv_fallback",
        "forward_throttled",
        "recv_arm_failures",
        "send_eagain",
        "send_zc_enomem",
        "send_exhausted",
        "fallback_received",
    ];
    let mut shown = false;
    for e in &entries {
        let Some(op) = e.op.as_deref() else { continue };
        if interesting.contains(&op) && e.value != 0 {
            eprintln!("bench-server: {}/{} = {}", e.name, op, e.value);
            shown = true;
        }
    }
    if !shown {
        eprintln!("bench-server: no ring starvation or pool exhaustion counted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dump has to find ringline's counters and their `op` labels. A dump
    /// that silently returns an empty list would make every sweep arm look
    /// equally healthy — which is exactly the failure this module exists to
    /// prevent, so assert on a named counter rather than on a non-empty list.
    #[test]
    fn collects_ringline_pool_counters_by_label() {
        ringline::metrics::init_metadata();
        let entries = collect();
        let pool_ops: Vec<&str> = entries
            .iter()
            .filter(|e| e.name == "ringline/pool")
            .filter_map(|e| e.op.as_deref())
            .collect();
        for want in ["buffer_ring_empty", "recv_parked", "recv_fallback"] {
            assert!(
                pool_ops.contains(&want),
                "ringline/pool is missing `{want}`; found {pool_ops:?}"
            );
        }
    }

    #[test]
    fn dump_writes_parsable_json() {
        ringline::metrics::init_metadata();
        let dir =
            std::env::temp_dir().join(format!("ringline-bench-metrics-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("metrics.json");
        dump_to(&path).expect("dump");
        let text = std::fs::read_to_string(&path).expect("read back");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert!(parsed.as_array().is_some_and(|a| !a.is_empty()));
        std::fs::remove_dir_all(&dir).ok();
    }
}
