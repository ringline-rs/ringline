/// Returns the number of physical CPU cores available to this process.
///
/// On Linux, reads `/sys/devices/system/cpu/cpu*/topology/physical_package_id`
/// and `core_id` for each CPU in `/sys/devices/system/cpu/online` to count
/// unique (socket, core) pairs, counting hyperthreading siblings once.
/// Falls back to the logical CPU count when no CPU's topology can be read,
/// and on non-Linux platforms.
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

/// Logical CPU ids of the first SMT sibling of each physical core, in
/// ascending logical-CPU order.
///
/// Used for SMT-aware worker pinning: indexing this list by a physical
/// core number yields a logical CPU on a distinct physical core
/// regardless of how the machine enumerates hyperthread siblings
/// (grouped `0..N` physical then `N..2N` siblings, or adjacent
/// `0/1 = one core`). Returns `None` when sysfs topology is unavailable
/// (non-Linux, or exotic sysfs layouts).
pub(crate) fn physical_core_first_cpus() -> Option<Vec<usize>> {
    #[cfg(target_os = "linux")]
    {
        linux_first_siblings()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Walk sysfs recording the first logical CPU seen for each unique
/// (physical_package_id, core_id) pair.
#[cfg(target_os = "linux")]
fn linux_first_siblings() -> Option<Vec<usize>> {
    first_siblings_in(std::path::Path::new("/sys/devices/system/cpu"))
}

/// The first logical CPU of each unique (physical_package_id, core_id) pair
/// under `root` (`/sys/devices/system/cpu` on Linux), in ascending CPU order.
///
/// Visits the CPUs in `root/online` and skips any whose topology cannot be
/// read. An offline CPU has a `cpuN` directory and no `topology/`, so a walk
/// that stopped there would miss every CPU above it, as under `nosmt`, where
/// every odd CPU is offline. Without a readable `online` list it counts up
/// from cpu0 and stops at the first CPU without topology. `None` when no CPU
/// has readable topology.
#[cfg(any(target_os = "linux", test))]
fn first_siblings_in(root: &std::path::Path) -> Option<Vec<usize>> {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut firsts: Vec<usize> = Vec::new();
    // False when `cpu` has no readable topology.
    let mut visit = |cpu: usize| -> bool {
        let read = |file: &str| {
            std::fs::read_to_string(root.join(format!("cpu{cpu}/topology/{file}")))
                .map(|s| s.trim().to_owned())
        };
        let (Ok(pkg), Ok(core)) = (read("physical_package_id"), read("core_id")) else {
            return false;
        };
        if seen.insert((pkg, core)) {
            firsts.push(cpu);
        }
        true
    };
    let online = std::fs::read_to_string(root.join("online"))
        .ok()
        .and_then(|s| parse_cpu_list(s.trim()));
    match online {
        Some(cpus) => {
            for cpu in cpus {
                visit(cpu);
            }
        }
        None => {
            let mut cpu = 0;
            while visit(cpu) {
                cpu += 1;
            }
        }
    }
    if firsts.is_empty() {
        None
    } else {
        Some(firsts)
    }
}

/// Parse a kernel CPU list such as `0,2-5,8` into ascending CPU ids. `None`
/// for an empty or malformed list.
#[cfg(any(target_os = "linux", test))]
fn parse_cpu_list(list: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for part in list.split(',') {
        match part.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi): (usize, usize) = (lo.parse().ok()?, hi.parse().ok()?);
                if lo > hi {
                    return None;
                }
                cpus.extend(lo..=hi);
            }
            None => cpus.push(part.parse().ok()?),
        }
    }
    Some(cpus)
}

/// Parse unique (physical_package_id, core_id) pairs from sysfs.
/// Returns `None` if sysfs is unavailable or yields zero entries.
#[cfg(target_os = "linux")]
fn linux_physical_cores() -> Option<usize> {
    linux_first_siblings().map(|v| v.len())
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

    #[test]
    fn first_siblings_are_distinct_ascending_and_agree_with_count() {
        if let Some(cpus) = physical_core_first_cpus() {
            assert_eq!(cpus.len(), physical_core_count());
            // Strictly ascending (walk order) implies all-distinct.
            assert!(cpus.windows(2).all(|w| w[0] < w[1]));
            // Ids, not a count: with a CPU offline below the highest online
            // one, ids reach past the online count.
            let configured = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) } as usize;
            assert!(cpus.iter().all(|&c| c < configured));
        }
    }

    /// A fake `/sys/devices/system/cpu` under a fresh temp directory. Each
    /// `(cpu, Some((package, core)))` gets a `topology/` directory; `None`
    /// gets a bare `cpuN` directory, as an offline CPU has.
    fn fake_sysfs(
        name: &str,
        online: Option<&str>,
        cpus: &[(usize, Option<(u32, u32)>)],
    ) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("ringline-topology-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        if let Some(online) = online {
            std::fs::write(root.join("online"), format!("{online}\n")).unwrap();
        }
        for &(cpu, topo) in cpus {
            let dir = root.join(format!("cpu{cpu}"));
            std::fs::create_dir_all(&dir).unwrap();
            if let Some((pkg, core)) = topo {
                std::fs::create_dir_all(dir.join("topology")).unwrap();
                std::fs::write(dir.join("topology/physical_package_id"), format!("{pkg}\n"))
                    .unwrap();
                std::fs::write(dir.join("topology/core_id"), format!("{core}\n")).unwrap();
            }
        }
        root
    }

    #[test]
    fn an_offline_cpu_below_the_online_ones_does_not_end_the_walk() {
        // `nosmt`: every odd CPU offline.
        let root = fake_sysfs(
            "nosmt",
            Some("0,2,4"),
            &[
                (0, Some((0, 0))),
                (1, None),
                (2, Some((0, 1))),
                (3, None),
                (4, Some((0, 2))),
            ],
        );
        assert_eq!(first_siblings_in(&root), Some(vec![0, 2, 4]));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn smt_siblings_count_once() {
        // Siblings adjacent (cpu0/cpu1 one core), over two packages.
        let root = fake_sysfs(
            "smt",
            Some("0-3,4-7"),
            &[
                (0, Some((0, 0))),
                (1, Some((0, 0))),
                (2, Some((0, 1))),
                (3, Some((0, 1))),
                (4, Some((1, 0))),
                (5, Some((1, 0))),
                (6, Some((1, 1))),
                (7, Some((1, 1))),
            ],
        );
        assert_eq!(first_siblings_in(&root), Some(vec![0, 2, 4, 6]));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn without_an_online_list_the_walk_counts_up_from_zero() {
        let root = fake_sysfs(
            "no-online",
            None,
            &[(0, Some((0, 0))), (1, Some((0, 1))), (3, Some((0, 3)))],
        );
        assert_eq!(first_siblings_in(&root), Some(vec![0, 1]));
        std::fs::remove_dir_all(&root).unwrap();
        let root = fake_sysfs("empty", None, &[]);
        assert_eq!(first_siblings_in(&root), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cpu_lists_parse_as_the_kernel_writes_them() {
        assert_eq!(parse_cpu_list("0"), Some(vec![0]));
        assert_eq!(parse_cpu_list("0,2,4"), Some(vec![0, 2, 4]));
        assert_eq!(
            parse_cpu_list("0-3,8,10-11"),
            Some(vec![0, 1, 2, 3, 8, 10, 11])
        );
        assert_eq!(parse_cpu_list(""), None);
        assert_eq!(parse_cpu_list("3-1"), None);
        assert_eq!(parse_cpu_list("0,x"), None);
        assert_eq!(parse_cpu_list("0,"), None);
    }
}
