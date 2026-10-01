//! What io_uring charges against `RLIMIT_MEMLOCK`, so `launch` can check the
//! limit before any worker exists and an `ENOMEM` can name the cause.
//!
//! Registered (fixed) buffers are charged on every kernel. From Linux 6.14
//! the rings are charged too: the SQ/CQ ring region, the SQE array and each
//! provided buffer ring are allocated with `io_create_region`
//! (`io_uring/memmap.c`), which charges their pages. Before 6.14 they are not
//! charged. Each ring is charged separately, against the `RLIMIT_MEMLOCK` of
//! the process creating it, and the kernel adds the charge to everything the
//! same user already has charged in any process. A process with
//! `CAP_IPC_LOCK` is not charged.

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
/// `backend::uring::ring::Ring::setup` does it: 128-byte SQEs, 32-byte CQEs,
/// a CQ four times the SQ, and an SQ index array.
///
/// The kernel rounds both entry counts up to a power of two, then charges two
/// regions, each rounded up to whole pages:
///
/// - the ring region: the 64-byte `struct io_rings` header plus the CQEs,
///   doubled for 32-byte CQEs and aligned to a 64-byte cache line, followed by
///   a 4-byte index per SQ entry (`rings_size` in `io_uring/io_uring.c`);
/// - the SQE array: 128 bytes per SQ entry.
pub(crate) fn ring_bytes(sq_entries: u32, page: u64) -> u64 {
    let sq = u64::from(sq_entries.max(1).next_power_of_two());
    let cq = (sq * 4).next_power_of_two();
    let rings = ((64 + cq * 16) * 2).next_multiple_of(64) + sq * 4;
    page_align(rings, page) + page_align(sq * 128, page)
}

/// The bytes the kernel charges for a provided buffer ring of `entries`
/// 16-byte entries. The buffers the entries point at are not charged.
pub(crate) fn provided_ring_bytes(entries: u16, page: u64) -> u64 {
    page_align(u64::from(entries) * 16, page)
}

/// Whether this process holds `CAP_IPC_LOCK` in its effective set, which
/// exempts it from io_uring's memlock charge. `false` when it cannot be read.
#[cfg(has_io_uring)]
pub(crate) fn has_cap_ipc_lock() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| cap_eff_has_ipc_lock(&status))
        .unwrap_or(false)
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
        assert_eq!(ring_bytes(64, PAGE), 5 * PAGE);
        // sq 256, cq 1024: (64 + 16384)*2 = 32896, +1024 = 33920 -> 9 pages;
        // SQEs 32768 -> 8 pages.
        assert_eq!(ring_bytes(256, PAGE), 17 * PAGE);
        // sq 1, cq 4: 260 bytes -> 1 page; one 128-byte SQE -> 1 page.
        assert_eq!(ring_bytes(1, PAGE), 2 * PAGE);
        // The kernel rounds sq up to a power of two: 100 is charged as 128.
        assert_eq!(ring_bytes(100, PAGE), ring_bytes(128, PAGE));
    }

    #[test]
    fn provided_ring_bytes_is_sixteen_bytes_an_entry_in_whole_pages() {
        assert_eq!(provided_ring_bytes(16, PAGE), PAGE);
        assert_eq!(provided_ring_bytes(256, PAGE), PAGE);
        assert_eq!(provided_ring_bytes(512, PAGE), 2 * PAGE);
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
}
