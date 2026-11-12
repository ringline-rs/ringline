//! What io_uring charges against `RLIMIT_MEMLOCK`, so `launch` can check the
//! limit before any worker exists and an `ENOMEM` can name the cause.
//!
//! Registered (fixed) buffers are charged on every kernel. From Linux 6.14
//! the rings are charged too: the SQ/CQ ring region, the SQE array and each
//! provided buffer ring are allocated with `io_create_region`
//! (`io_uring/memmap.c`), which charges their pages. Before 6.14 they are not
//! charged.
//!
//! Each ring's charge is added separately; rings do not share one. The kernel
//! adds every charge to what the same user has charged in any process, and
//! compares the total with the `RLIMIT_MEMLOCK` soft limit of the process
//! making the charge. A process with `CAP_IPC_LOCK` in the initial user
//! namespace is not charged; the capability inside a container's own user
//! namespace does not exempt it.
//!
//! A zero-copy send from memory that is not a registered buffer is charged
//! too, `len / page + 2` pages while the send is in flight
//! (`IORING_OP_SENDMSG_ZC` from Linux 6.15). The preflight cannot count that,
//! so the limit needs room above what it computes.

/// A kernel's major and minor version, from `uname -r`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct KernelVersion {
    pub(crate) major: u32,
    pub(crate) minor: u32,
}

impl KernelVersion {
    /// Parse the leading `major.minor` of a kernel release string such as
    /// `6.17.0-1022-azure`.
    pub(crate) fn parse(release: &str) -> Option<Self> {
        let mut parts = release.split(|c: char| !c.is_ascii_digit());
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some(Self { major, minor })
    }

    /// The running kernel's version, or `None` if `uname` fails or its
    /// release string does not parse.
    #[cfg(has_io_uring)]
    pub(crate) fn current() -> Option<Self> {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } != 0 {
            return None;
        }
        let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
        Self::parse(release.to_str().ok()?)
    }
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The first kernel that charges io_uring rings against `RLIMIT_MEMLOCK`.
pub(crate) const RINGS_CHARGED_SINCE: KernelVersion = KernelVersion {
    major: 6,
    minor: 14,
};

/// Whether `kernel` charges rings and provided buffer rings against
/// `RLIMIT_MEMLOCK`. An unknown kernel is assumed to.
pub(crate) fn charges_rings(kernel: Option<KernelVersion>) -> bool {
    kernel.is_none_or(|k| k >= RINGS_CHARGED_SINCE)
}

fn page_align(bytes: u64, page: u64) -> u64 {
    bytes.div_ceil(page) * page
}

/// The bytes the kernel charges for one ring set up the way
/// `backend::uring::engine::uring::UringEngine::setup` does it: 128-byte SQEs, 32-byte CQEs,
/// a CQ of `cq_entries`, and an SQ index array.
///
/// The kernel rounds both entry counts up to a power of two, then charges two
/// regions, each rounded up to whole pages:
///
/// - the ring region: the 64-byte `struct io_rings` header plus the CQEs,
///   doubled for 32-byte CQEs and aligned to a 64-byte cache line, followed by
///   a 4-byte index per SQ entry (`rings_size` in `io_uring/io_uring.c`);
/// - the SQE array: 128 bytes per SQ entry.
pub(crate) fn ring_bytes(sq_entries: u32, cq_entries: u32, page: u64) -> u64 {
    let sq = u64::from(sq_entries.max(1).next_power_of_two());
    let cq = u64::from(cq_entries).max(sq).next_power_of_two();
    let rings = ((64 + cq * 16) * 2).next_multiple_of(64) + sq * 4;
    page_align(rings, page) + page_align(sq * 128, page)
}

/// The bytes the kernel charges for a provided buffer ring of `entries`
/// 16-byte entries. The buffers the entries point at are not charged.
pub(crate) fn provided_ring_bytes(entries: u16, page: u64) -> u64 {
    page_align(u64::from(entries) * 16, page)
}

/// Whether this process holds `CAP_IPC_LOCK` in the initial user namespace,
/// which exempts it from io_uring's memlock charge. `false` when either part
/// cannot be read.
#[cfg(has_io_uring)]
pub(crate) fn has_cap_ipc_lock() -> bool {
    let initial_ns =
        std::fs::read_to_string("/proc/self/uid_map").is_ok_and(|map| is_initial_uid_map(&map));
    initial_ns
        && std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| cap_eff_has_ipc_lock(&status))
            .unwrap_or(false)
}

/// Whether `/proc/self/uid_map` is the initial user namespace's identity
/// map. io_uring honours `CAP_IPC_LOCK` only there
/// (`ns_capable_noaudit(&init_user_ns, CAP_IPC_LOCK)`).
pub(crate) fn is_initial_uid_map(map: &str) -> bool {
    map.split_whitespace().eq(["0", "0", "4294967295"])
}

/// Read bit `CAP_IPC_LOCK` (14) of the `CapEff:` line of `/proc/self/status`.
pub(crate) fn cap_eff_has_ipc_lock(status: &str) -> Option<bool> {
    const CAP_IPC_LOCK: u32 = 14;
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))?
        .trim();
    let caps = u64::from_str_radix(hex, 16).ok()?;
    Some(caps & (1 << CAP_IPC_LOCK) != 0)
}

/// A worker's connection table and ring queue sizes.
#[cfg(any(has_io_uring, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RingSizes {
    pub(crate) max_connections: u32,
    pub(crate) sq_entries: u32,
    pub(crate) cq_entries: u32,
}

/// The smallest CQ [`fit_ring_sizes`] tries.
#[cfg(any(has_io_uring, test))]
pub(crate) const FIT_MIN_CQ_ENTRIES: u32 = 1024;

/// Why [`fit_ring_sizes`] found no sizes that fit.
#[cfg(any(has_io_uring, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FitStop {
    /// The caller set `cq_entries`, which is not lowered.
    CqSet,
    /// The caller set `max_connections`, which needs a CQ of at least
    /// `needs_cq` entries in the defaults' proportion (at most the
    /// configured CQ), and no CQ that large fits.
    MaxConnections { max_connections: u32, needs_cq: u32 },
    /// The caller set `sq_entries`, and no CQ at least that large fits.
    SqEntries { sq_entries: u32 },
    /// Not even a CQ of [`FIT_MIN_CQ_ENTRIES`] fits.
    Floor,
}

/// The largest sizes, at most `current`, for which `fits` holds.
///
/// Only a CQ left at its default is lowered: it is halved from `current`
/// down to [`FIT_MIN_CQ_ENTRIES`]. An SQ left at its default goes with it as
/// `cq / 16`, and a `max_connections` left at its default as
/// `cq * 16000 / 65536`, the proportions of the defaults; the CQ is sized
/// for the connections' armed requests, so a smaller CQ takes fewer
/// connections. An SQ set by the caller that exceeds a candidate CQ, or a
/// `max_connections` set by the caller above a candidate's proportion, ends
/// the search. The error says which rule ended it.
#[cfg(any(has_io_uring, test))]
pub(crate) fn fit_ring_sizes(
    current: RingSizes,
    set: crate::config::SizesSet,
    fits: impl Fn(RingSizes) -> bool,
) -> Result<RingSizes, FitStop> {
    use crate::config::{DEFAULT_MAX_CONNECTIONS, MAX_CQ_ENTRIES};

    if fits(current) {
        return Ok(current);
    }
    if set.cq_entries {
        return Err(FitStop::CqSet);
    }
    let connections_for = |cq: u32| {
        (u64::from(cq) * u64::from(DEFAULT_MAX_CONNECTIONS) / u64::from(MAX_CQ_ENTRIES)) as u32
    };
    // A smaller CQ only tightens both rules below, so the first candidate
    // that breaks one ends the search.
    let mut cq = current.cq_entries / 2;
    while cq >= FIT_MIN_CQ_ENTRIES {
        let connections = connections_for(cq);
        let max_connections = if set.max_connections {
            if current.max_connections > connections {
                // The smallest CQ in the search whose proportion covers the
                // connections: the configured CQ itself when none below it
                // does.
                let needs_cq = (u64::from(current.max_connections) * u64::from(MAX_CQ_ENTRIES))
                    .div_ceil(u64::from(DEFAULT_MAX_CONNECTIONS))
                    .next_power_of_two()
                    .min(u64::from(current.cq_entries)) as u32;
                return Err(FitStop::MaxConnections {
                    max_connections: current.max_connections,
                    needs_cq,
                });
            }
            current.max_connections
        } else {
            current.max_connections.min(connections)
        };
        let sq_entries = if set.sq_entries {
            current.sq_entries
        } else {
            current.sq_entries.min(cq / 16)
        };
        if sq_entries > cq {
            return Err(FitStop::SqEntries { sq_entries });
        }
        let candidate = RingSizes {
            max_connections,
            sq_entries,
            cq_entries: cq,
        };
        if fits(candidate) {
            return Ok(candidate);
        }
        cq /= 2;
    }
    Err(FitStop::Floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;

    #[test]
    fn kernel_version_parses_distro_releases() {
        let v = |major, minor| Some(KernelVersion { major, minor });
        assert_eq!(KernelVersion::parse("6.17.0-1022-azure"), v(6, 17));
        assert_eq!(KernelVersion::parse("6.12.72-linuxkit"), v(6, 12));
        assert_eq!(KernelVersion::parse("6.1.0"), v(6, 1));
        assert_eq!(KernelVersion::parse("5.15.0-generic"), v(5, 15));
        assert_eq!(KernelVersion::parse("6"), None);
        assert_eq!(KernelVersion::parse("linux"), None);
    }

    #[test]
    fn rings_are_charged_from_6_14() {
        let k = |major, minor| Some(KernelVersion { major, minor });
        assert!(!charges_rings(k(6, 12)));
        assert!(!charges_rings(k(6, 13)));
        assert!(charges_rings(k(6, 14)));
        assert!(charges_rings(k(6, 17)));
        assert!(charges_rings(k(7, 0)));
        assert!(charges_rings(None));
    }

    /// Worked through `rings_size` and `io_allocate_scq_urings` by hand. The
    /// `memlock_rings` integration test checks the same numbers against a
    /// running 6.14+ kernel.
    #[test]
    fn ring_bytes_matches_the_kernel_layout() {
        // sq 64, cq 256: (64 + 256*16)*2 = 8320, +64*4 = 8576 -> 3 pages;
        // SQEs 64*128 = 8192 -> 2 pages.
        assert_eq!(ring_bytes(64, 256, PAGE), 5 * PAGE);
        // sq 256, cq 1024: (64 + 16384)*2 = 32896, +1024 = 33920 -> 9 pages;
        // SQEs 32768 -> 8 pages.
        assert_eq!(ring_bytes(256, 1024, PAGE), 17 * PAGE);
        // sq 1, cq 4: 260 bytes -> 1 page; one 128-byte SQE -> 1 page.
        assert_eq!(ring_bytes(1, 4, PAGE), 2 * PAGE);
        // The defaults, sq 4096 and cq 65536: (64 + 65536*16)*2 = 2097280,
        // +4096*4 = 2113664 -> 517 pages; SQEs 524288 -> 128 pages.
        assert_eq!(ring_bytes(4096, 65536, PAGE), 645 * PAGE);
        // The kernel rounds sq up to a power of two: 100 is charged as 128.
        assert_eq!(ring_bytes(100, 512, PAGE), ring_bytes(128, 512, PAGE));
    }

    #[test]
    fn provided_ring_bytes_is_sixteen_bytes_an_entry_in_whole_pages() {
        assert_eq!(provided_ring_bytes(16, PAGE), PAGE);
        assert_eq!(provided_ring_bytes(256, PAGE), PAGE);
        assert_eq!(provided_ring_bytes(512, PAGE), 2 * PAGE);
    }

    #[test]
    fn only_the_identity_uid_map_is_the_initial_namespace() {
        assert!(is_initial_uid_map("         0          0 4294967295\n"));
        // Root inside `unshare -Ur`, rootless podman, docker --userns-remap.
        assert!(!is_initial_uid_map("         0       1000          1\n"));
        assert!(!is_initial_uid_map("0 100000 65536\n"));
        assert!(!is_initial_uid_map(""));
    }

    #[test]
    fn cap_ipc_lock_is_bit_14_of_cap_eff() {
        let status = |eff: &str| format!("Name:\tx\nCapPrm:\t0\nCapEff:\t{eff}\nCapBnd:\t0\n");
        assert_eq!(
            cap_eff_has_ipc_lock(&status("000001ffffffffff")),
            Some(true)
        );
        assert_eq!(
            cap_eff_has_ipc_lock(&status("0000000000004000")),
            Some(true)
        );
        assert_eq!(
            cap_eff_has_ipc_lock(&status("0000000000003fff")),
            Some(false)
        );
        assert_eq!(
            cap_eff_has_ipc_lock(&status("0000000000000000")),
            Some(false)
        );
        assert_eq!(cap_eff_has_ipc_lock("Name:\tx\n"), None);
    }

    /// `fits` for `workers` workers' rings under `limit` bytes, at 4 KiB pages.
    fn under(limit: u64, workers: u64) -> impl Fn(RingSizes) -> bool {
        move |s: RingSizes| ring_bytes(s.sq_entries, s.cq_entries, PAGE) * workers <= limit
    }

    fn defaults() -> RingSizes {
        RingSizes {
            max_connections: 16000,
            sq_entries: 4096,
            cq_entries: 65536,
        }
    }

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn sizes_that_fit_are_kept() {
        let set = crate::config::SizesSet::default();
        assert_eq!(fit_ring_sizes(defaults(), set, |_| true), Ok(defaults()));
    }

    #[test]
    fn default_sizes_are_halved_in_proportion_until_they_fit() {
        let set = crate::config::SizesSet::default();
        // 8 MiB over 8 workers: 16384 CQ entries is the largest that fits.
        assert_eq!(
            fit_ring_sizes(defaults(), set, under(8 * MIB, 8)),
            Ok(RingSizes {
                max_connections: 4000,
                sq_entries: 1024,
                cq_entries: 16384,
            })
        );
        // 8 MiB over 4 workers: 32768.
        assert_eq!(
            fit_ring_sizes(defaults(), set, under(8 * MIB, 4)),
            Ok(RingSizes {
                max_connections: 8000,
                sq_entries: 2048,
                cq_entries: 32768,
            })
        );
    }

    #[test]
    fn the_smallest_cq_tried_is_1024() {
        let set = crate::config::SizesSet::default();
        let at_floor = ring_bytes(64, 1024, PAGE);
        assert_eq!(
            fit_ring_sizes(defaults(), set, under(at_floor, 1)),
            Ok(RingSizes {
                max_connections: 250,
                sq_entries: 64,
                cq_entries: 1024,
            })
        );
        assert_eq!(
            fit_ring_sizes(defaults(), set, under(at_floor - 1, 1)),
            Err(FitStop::Floor)
        );
    }

    #[test]
    fn a_cq_the_caller_set_is_not_lowered() {
        let set = crate::config::SizesSet {
            cq_entries: true,
            ..Default::default()
        };
        assert_eq!(
            fit_ring_sizes(defaults(), set, under(8 * MIB, 8)),
            Err(FitStop::CqSet)
        );
    }

    #[test]
    fn a_max_connections_the_caller_set_is_kept_or_ends_the_fit() {
        // 1000 connections need a CQ of at least 4096 in the defaults'
        // proportion; 8 MiB over 8 workers fits 16384, so it is kept.
        let set = crate::config::SizesSet {
            max_connections: true,
            ..Default::default()
        };
        let current = RingSizes {
            max_connections: 1000,
            ..defaults()
        };
        assert_eq!(
            fit_ring_sizes(current, set, under(8 * MIB, 8)),
            Ok(RingSizes {
                max_connections: 1000,
                sq_entries: 1024,
                cq_entries: 16384,
            })
        );
        // 16000 connections need the full 65536, which does not fit.
        assert_eq!(
            fit_ring_sizes(defaults(), set, under(8 * MIB, 8)),
            Err(FitStop::MaxConnections {
                max_connections: 16000,
                needs_cq: 65536
            })
        );
        // 16384, as the benchmark servers set, also needs 65536.
        let bench = RingSizes {
            max_connections: 16384,
            ..defaults()
        };
        assert_eq!(
            fit_ring_sizes(bench, set, under(8 * MIB, 8)),
            Err(FitStop::MaxConnections {
                max_connections: 16384,
                needs_cq: 65536
            })
        );
    }

    #[test]
    fn an_sq_the_caller_set_is_kept_or_ends_the_fit() {
        let set = crate::config::SizesSet {
            sq_entries: true,
            ..Default::default()
        };
        // The SQ stays at 4096; with it, 8 MiB over 8 workers fits a CQ of
        // 8192.
        let fitted = fit_ring_sizes(defaults(), set, under(8 * MIB, 8)).unwrap();
        assert_eq!((fitted.sq_entries, fitted.cq_entries), (4096, 8192));
        // A CQ of 4096 is the smallest an SQ of 4096 allows: one byte short of
        // it, the next candidate (2048) is below the SQ.
        let at_4096 = ring_bytes(4096, 4096, PAGE);
        assert_eq!(
            fit_ring_sizes(defaults(), set, under(at_4096, 1)).map(|s| s.cq_entries),
            Ok(4096)
        );
        assert_eq!(
            fit_ring_sizes(defaults(), set, under(at_4096 - 1, 1)),
            Err(FitStop::SqEntries { sq_entries: 4096 })
        );
    }
}
