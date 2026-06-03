/// Returns the number of physical CPU cores available to this process.
///
/// On Linux, reads `/sys/devices/system/cpu/cpu*/topology/physical_package_id`
/// and `core_id` to count unique (socket, core) pairs, correctly ignoring
/// hyperthreading siblings. Falls back to the logical CPU count on any read
/// error or on non-Linux platforms.
///
/// # Why physical cores for thread-per-core
///
/// Ringline's event loop is io_uring–driven: each worker continuously submits
/// SQEs and drains CQEs in a tight CPU-bound loop. Two hyperthreads on the
/// same physical core share execution units, L1, and L2 — spawning a worker
/// per logical CPU doubles the thread count without doubling the hardware
/// resources, causing cache thrashing and SMT contention on the submission
/// path. One worker per physical core saturates the available execution
/// resources without that overhead.
///
/// Benchmarks confirm: the optimal connection assignment is
/// `conn_chunk_size = connections / physical_core_count()`, which naturally
/// equals `connections / worker_count` when workers default to physical cores.
///
/// # Example
///
/// ```rust
/// use ringline::physical_core_count;
/// println!("physical cores: {}", physical_core_count());
/// ```
pub fn physical_core_count() -> usize {
    #[cfg(target_os = "linux")]
    if let Some(n) = linux_physical_cores() {
        return n;
    }
    // Fallback: logical CPU count (sysconf).
    let ret = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if ret < 1 { 1 } else { ret as usize }
}

/// Parse unique (physical_package_id, core_id) pairs from sysfs.
/// Returns `None` if sysfs is unavailable or yields zero entries.
#[cfg(target_os = "linux")]
fn linux_physical_cores() -> Option<usize> {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut cpu = 0usize;
    while let Ok(pkg_raw) = std::fs::read_to_string(format!(
        "/sys/devices/system/cpu/cpu{cpu}/topology/physical_package_id"
    )) {
        let pkg = pkg_raw.trim().to_owned();
        let core = match std::fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/core_id"
        )) {
            Ok(s) => s.trim().to_owned(),
            Err(_) => break,
        };
        seen.insert((pkg, core));
        cpu += 1;
    }
    if seen.is_empty() {
        None
    } else {
        Some(seen.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_core_count_is_positive() {
        assert!(physical_core_count() >= 1);
    }

    #[test]
    fn physical_core_count_does_not_exceed_logical() {
        let logical = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as usize;
        assert!(physical_core_count() <= logical);
    }
}
