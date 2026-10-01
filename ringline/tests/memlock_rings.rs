//! What io_uring charges to `RLIMIT_MEMLOCK` for the rings themselves, checked
//! against the running kernel, and that `launch` counts it.
//!
//! From Linux 6.14 each ring (its SQ/CQ ring region and SQE array) and each
//! provided buffer ring is charged; before 6.14 neither is. The byte counts
//! below are the ones `ringline::memlock`'s unit tests derive from the kernel
//! source. Here the kernel itself must refuse one page below each and accept
//! each exactly.
//!
//! One test, sequential: the hard limit is lowered only for the last two
//! steps, because lowering it is irreversible for the process. The kernel compares the limit
//! with what every process of this user has charged, so this test must not
//! share the machine with other io_uring tests; `.config/nextest.toml` runs it
//! alone.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io;
use std::time::{Duration, Instant};

use io_uring::{IoUring, cqueue, squeue};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, Error, RinglineBuilder};

const PAGE: u64 = 4096;
/// One ring set up as ringline sets it up (128-byte SQEs, 32-byte CQEs, a CQ
/// four times the SQ) with 64 SQ entries: a 3-page ring region and a 2-page
/// SQE array.
const RING_64: u64 = 5 * PAGE;
/// The same with 256 SQ entries: 9 pages and 8 pages.
const RING_256: u64 = 17 * PAGE;
/// A provided buffer ring of 512 16-byte entries.
const PBUF_512: u64 = 2 * PAGE;
/// A provided buffer ring of 16 entries, the size `builder()` configures.
const PBUF_16: u64 = PAGE;

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        Idle
    }
}

fn builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(16, 1024)
        .max_connections(16)
        .send_pool(16, 16384)
}

fn kernel() -> (u32, u32) {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let mut parts = release.trim().split(|c: char| !c.is_ascii_digit());
    let major = parts.next().unwrap().parse().unwrap();
    let minor = parts.next().unwrap().parse().unwrap();
    (major, minor)
}

fn has_cap_ipc_lock() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .unwrap()
        .trim();
    u64::from_str_radix(hex, 16).unwrap() & (1 << 14) != 0
}

fn set_memlock(soft: u64, hard: u64) {
    let r = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &r) },
        0,
        "setrlimit: {}",
        io::Error::last_os_error()
    );
}

fn hard_limit() -> u64 {
    let mut r: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r) }, 0);
    r.rlim_max
}

/// A ring set up as `Ring::setup` sets it up, for the sizes that matter here.
fn ring(sq_entries: u32) -> io::Result<IoUring<squeue::Entry128, cqueue::Entry32>> {
    IoUring::<squeue::Entry128, cqueue::Entry32>::builder()
        .setup_cqsize(sq_entries * 4)
        .build(sq_entries)
}

/// Register a provided buffer ring of `entries` as group `bgid` on `ring`,
/// from memory this function maps and leaks.
fn register_pbuf(
    ring: &IoUring<squeue::Entry128, cqueue::Entry32>,
    entries: u16,
    bgid: u16,
) -> io::Result<()> {
    let len = usize::from(entries) * 16;
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            -1,
            0,
        )
    };
    assert_ne!(addr, libc::MAP_FAILED, "mmap");
    unsafe {
        ring.submitter()
            .register_buf_ring_with_flags(addr as u64, entries, bgid, 0)
    }
}

/// Retry `f` while it fails with `ENOMEM`, for up to 2 s. A ring that was just
/// dropped, in this process or another, is uncharged asynchronously, so a
/// limit that fits exactly can be briefly short.
fn within_limit<T>(what: &str, mut f: impl FnMut() -> io::Result<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match f() {
            Ok(v) => return v,
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("{what} must fit its computed charge exactly: {e}"),
        }
    }
}

fn expect_enomem<T>(what: &str, r: io::Result<T>) {
    match r {
        Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {}
        Err(e) => panic!("{what}: expected ENOMEM one page under its charge, got {e}"),
        Ok(_) => panic!("{what}: fit one page under its computed charge"),
    }
}

fn launch_and_stop() -> Result<(), Error> {
    let (runtime, handles) = RinglineBuilder::new(builder().build().unwrap()).launch::<Idle>()?;
    runtime.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    Ok(())
}

#[test]
fn ring_memory_charged_to_memlock_matches_the_kernel() {
    // A root or CAP_IPC_LOCK process is not charged; the assertions below
    // would then be testing nothing.
    assert!(
        unsafe { libc::geteuid() } != 0 && !has_cap_ipc_lock(),
        "run this test unprivileged"
    );
    assert_eq!(
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64,
        PAGE,
        "the byte counts here assume 4 KiB pages"
    );
    let hard = hard_limit();
    let kernel = kernel();

    if kernel < (6, 14) {
        // Not charged: a ring and a launch both fit under a one-page limit,
        // and the preflight must not refuse what the kernel would accept.
        set_memlock(PAGE, PAGE);
        drop(ring(256).expect("a ring is not charged before 6.14"));
        launch_and_stop().expect("launch is not charged before 6.14");
        return;
    }

    // Each ENOMEM check runs while holding something that fit the limit
    // exactly, so nothing else is charged to this user at that moment: a ring
    // dropped earlier, here or in another process, could otherwise still be
    // charged and make ENOMEM come early, which would hide an overcount.
    for (sq, bytes) in [(64, RING_64), (256, RING_256)] {
        let what = format!("ring with {sq} SQ entries");
        set_memlock(bytes, hard);
        let held = within_limit(&what, || ring(sq));
        set_memlock(2 * bytes - PAGE, hard);
        expect_enomem(&what, ring(sq));
        drop(held);
    }

    set_memlock(RING_64 + PBUF_512, hard);
    let held = within_limit("ring and provided buffer ring of 512", || {
        let r = ring(64)?;
        register_pbuf(&r, 512, 0)?;
        Ok(r)
    });
    set_memlock(RING_64 + 2 * PBUF_512 - PAGE, hard);
    expect_enomem(
        "a second provided buffer ring of 512",
        register_pbuf(&held, 512, 1),
    );
    drop(held);

    // A whole worker: its ring and its recv provided buffer ring, which is
    // what the preflight computes for `builder()`.
    // Soft and hard both at the figure, so a preflight that overcounted by a
    // page would have no room to raise into and would refuse.
    let worker = RING_64 + PBUF_16;
    set_memlock(worker, worker);
    within_limit("a one-worker launch", || {
        launch_and_stop().map_err(|e| match e {
            Error::RingSetup(ref text) | Error::BufferRegistration(ref text)
                if text.contains("ENOMEM") =>
            {
                io::Error::from_raw_os_error(libc::ENOMEM)
            }
            other => io::Error::other(other.to_string()),
        })
    });

    // One page short, with no hard headroom to raise into: the preflight
    // refuses before any ring exists and names what the rings need.
    set_memlock(worker - PAGE, worker - PAGE);
    let err = launch_and_stop().expect_err("launch must refuse a memlock limit below its rings");
    assert!(
        matches!(err, Error::ResourceLimit(_)),
        "expected the preflight's ResourceLimit, got {err:?}"
    );
    let text = err.to_string();
    assert!(
        text.contains(&format!("need {} KiB", worker / 1024)),
        "{text}"
    );
    assert!(text.contains("io_uring rings"), "{text}");
    assert!(
        text.contains("everything else the same user has charged"),
        "{text}"
    );
}
