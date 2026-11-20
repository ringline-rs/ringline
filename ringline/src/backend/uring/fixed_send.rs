//! Whether guard-only sends from a registered region go out as `SENDMSG_ZC`
//! with `IORING_RECVSEND_FIXED_BUF`, decided once per process by a probe of
//! the running kernel.
//!
//! The kernel must accept the flag on `SENDMSG_ZC` (Linux 6.15), and must
//! charge a send from a registered buffer to the socket's send buffer the
//! same as a send of the same bytes from plain iovecs. From Linux 6.3, a
//! registered buffer that lies in a large folio is coalesced into one bvec per
//! folio, and `io_sg_from_iter` charges a send from it by its offset in the
//! folio: a 4 KiB send near the end of a 2 MiB page is charged about 2 MiB.
//! The socket then runs out of send buffer after a few sends: over 10 GbE,
//! 16 KiB sends from a THP-backed registered region ran at 1.9 Gb/s instead
//! of 9.4 (report:
//! <https://lore.kernel.org/io-uring/CAC+fX10wVVSqGnfCg+aazorsCxB34sUDV-XJiBPd6R3Kuqc-7Q@mail.gmail.com/>).
//! The fix charges the send's own pages
//! (<https://lore.kernel.org/io-uring/20261119232935.1708458-1-thiery.louis@gmail.com/>).
//! Distribution kernels can carry it, or not, under any version number, so
//! the probe measures the charge instead of reading the version.
//!
//! The probe sends 4 KiB from the last page of a registered 2 MiB transparent
//! huge page, once with the flag and once from plain iovecs, each on a fresh
//! loopback connection whose receiver does not read, and compares the change
//! in `SK_MEMINFO_WMEM_QUEUED` across the send. The kernel's fault in the
//! charge raises the fixed send's charge by about 2 MiB.
//!
//! The probe usually takes a few milliseconds. Its waits on the sockets and
//! the ring are bounded: 1 s for each connection's setup and prefill, and 5 s
//! for each completion, about 22 s for one measurement and 66 s for the three
//! it makes at most. Two steps are not bounded: the huge
//! page is allocated with `MADV_HUGEPAGE` and `MADV_COLLAPSE`, which can wait
//! for memory compaction, and the check that it is one huge page reads
//! `/proc/self/smaps`, which takes longer the more the process has mapped.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::abi::cqueue;
use super::engine::{ActiveEngine, Engine};
use super::sqe::{Fd, Op, Sqe};
use crate::buffer::fixed::{FixedBufferRegistry, FixedBufferSends, MemoryRegion};

/// The size of a PMD-mapped transparent huge page on x86-64 and on arm64
/// with 4 KiB pages.
const HUGE: usize = 2 << 20;
/// The probe's send: one page, page-aligned.
const LEN: usize = 4096;
/// Bytes the fixed send's charge may exceed the plain send's and still pass.
/// A kernel with the fault charges the probe's send about `HUGE` more.
const TOLERANCE: i64 = LEN as i64;
/// Bytes over the plain send's charge that identify the fault.
const OVERCHARGE: i64 = (HUGE / 2) as i64;
/// How long the probe waits for each completion.
const WAIT: Duration = Duration::from_secs(5);
/// How long the probe waits for each connection's setup and prefill.
const SETUP: Duration = Duration::from_secs(1);
/// How many times the probe measures before it reports `Inconclusive`.
const ATTEMPTS: usize = 3;
/// The probe ring's sizes.
const PROBE_SQ: u32 = 8;
const PROBE_CQ: u32 = 16;
/// `MADV_COLLAPSE` (Linux 6.1). libc defines it for glibc targets only.
const MADV_COLLAPSE: libc::c_int = 25;
/// `SK_MEMINFO_VARS`: the length of the `SO_MEMINFO` array in Linux 4.18 and
/// later. libc does not define it.
const SK_MEMINFO_VARS: usize = 9;
/// `SIOCOUTQNSD`: bytes in a TCP socket's write queue not yet sent.
const SIOCOUTQNSD: libc::c_ulong = 0x894B;

static RESULT: OnceLock<FixedBufferSends> = OnceLock::new();
static ENABLED: AtomicBool = AtomicBool::new(false);
/// Why the probe must not run, set at launch when `RLIMIT_MEMLOCK` has no room
/// for its charge ([`refuse`]) and cleared by a later launch that made room
/// ([`allow`]).
static REFUSED: Mutex<Option<String>> = Mutex::new(None);

/// Whether the probe has run and passed. Workers read it on the send path.
///
/// [`probe_once`] stores `ENABLED` before its caller spawns the workers or
/// sends a worker the message that registers a region. A worker checks a
/// guard's region against its own table, which it updates on that message,
/// so a worker that can find the region loads after the store.
pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// The `RLIMIT_MEMLOCK` charge the probe makes while it runs: its buffer, and
/// its ring on a kernel that charges rings.
pub(crate) fn memlock_charge(charges_rings: bool, page: u64) -> u64 {
    let ring = if charges_rings {
        crate::memlock::ring_bytes(PROBE_SQ, PROBE_CQ, page)
    } else {
        0
    };
    HUGE as u64 + ring
}

/// Keep the probe from running until a later [`allow`]: if it runs
/// meanwhile, it returns `Inconclusive(why)`. The most recent launch decides,
/// and it counts only its own workers, not those of other runtimes in the
/// process.
pub(crate) fn refuse(why: String) {
    *REFUSED.lock().unwrap_or_else(|e| e.into_inner()) = Some(why);
}

/// Let the probe run: the launch calling this made room for it.
pub(crate) fn allow() {
    *REFUSED.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Whether the probe has run in this process.
pub(crate) fn probed() -> bool {
    RESULT.get().is_some()
}

/// The probe's result, running it on the first call. The calling thread
/// blocks while the probe runs.
pub(crate) fn probe_once() -> FixedBufferSends {
    RESULT
        .get_or_init(|| {
            let result = probe();
            if result == FixedBufferSends::Enabled {
                ENABLED.store(true, Ordering::Relaxed);
            }
            result
        })
        .clone()
}

fn probe() -> FixedBufferSends {
    if let Some(why) = REFUSED.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return FixedBufferSends::Inconclusive(why);
    }
    let buf = match HugeBuffer::new() {
        Ok(buf) => buf,
        Err(why) => return FixedBufferSends::Inconclusive(why),
    };
    let config = crate::config::Config {
        sq_entries: PROBE_SQ,
        cq_entries: PROBE_CQ,
        sqpoll: false,
        iowq_max_workers: 0,
        ..crate::config::Config::default()
    };
    let mut engine = match ActiveEngine::setup(&config) {
        Ok(engine) => engine,
        Err(e) => return FixedBufferSends::Inconclusive(format!("io_uring setup: {e}")),
    };
    // SAFETY: `buf` is mapped for `HUGE` bytes and outlives the engine, which
    // is dropped first (declared after it).
    let region = unsafe { MemoryRegion::new(buf.ptr, HUGE) };
    if let Err(e) = engine.register_buffers(&FixedBufferRegistry::new(&[region], 1)) {
        return FixedBufferSends::Inconclusive(format!("registering the probe buffer: {e}"));
    }
    // A measurement can fail for a passing reason (a connection slow to set
    // up, an ACK inside the measurement), so it is tried up to `ATTEMPTS`
    // times. A `Leak` ends the probe at once.
    let mut result = measure(&mut engine, &buf);
    for _ in 1..ATTEMPTS {
        if !matches!(result, Err(Failure::Other(_))) {
            break;
        }
        result = measure(&mut engine, &buf);
    }
    if let Err(Failure::Leak(_)) = result {
        // The kernel may still read the buffer, so neither it nor the ring
        // that registered it is released.
        let _ = std::mem::ManuallyDrop::new(engine);
        let _ = std::mem::ManuallyDrop::new(buf);
    } else {
        // Clearing the slot returns the buffer's `RLIMIT_MEMLOCK` charge now;
        // dropping the ring returns it later, from the kernel's ring exit work.
        let empty = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        // SAFETY: nothing using the slot is in flight: every send has
        // completed and posted its notification.
        let _ = unsafe { engine.register_buffers_update_one(0, empty) };
    }
    match result {
        Ok(result) => result,
        Err(Failure::Leak(why) | Failure::Other(why)) => FixedBufferSends::Inconclusive(why),
    }
}

/// Check that the registered buffer is one huge page, then compare the fixed
/// and plain sends' charges.
fn measure(engine: &mut ActiveEngine, buf: &HugeBuffer) -> Result<FixedBufferSends, Failure> {
    // Checked after registering: the registration pins the folio, so it is
    // still one huge page when the sends run. A folio split before the pin
    // reads as 0 here and makes the probe inconclusive, not wrong.
    if buf.anon_huge_kib() < HUGE / 1024 {
        return Err(Failure::Other(
            "no transparent huge page for the probe buffer \
             (/sys/kernel/mm/transparent_hugepage/enabled)"
                .into(),
        ));
    }
    // The last page of the huge page: the fault charges it about `HUGE`.
    let at = buf.ptr.wrapping_add(HUGE - LEN);
    let mut ready = Vec::new();
    let fixed = match charge(engine, &mut ready, at, Some(0))? {
        Charge::Sent(bytes) => bytes,
        Charge::Refused => return Ok(FixedBufferSends::Unsupported),
    };
    let plain = match charge(engine, &mut ready, at, None)? {
        Charge::Sent(bytes) => bytes,
        Charge::Refused => {
            return Err(Failure::Other("a plain SENDMSG_ZC was refused".into()));
        }
    };
    Ok(verdict(fixed, plain))
}

/// The result from the fixed and plain sends' charges, in bytes.
fn verdict(fixed: i64, plain: i64) -> FixedBufferSends {
    if fixed - plain <= TOLERANCE {
        FixedBufferSends::Enabled
    } else if fixed - plain >= OVERCHARGE {
        FixedBufferSends::Overcharged
    } else {
        FixedBufferSends::Inconclusive(format!(
            "a {LEN}-byte send from a registered buffer was charged {fixed} bytes, \
             and from plain iovecs {plain}"
        ))
    }
}

enum Charge {
    /// The send was taken; the change in the write queue's charge, in bytes.
    Sent(i64),
    /// `EINVAL`: the kernel does not take `IORING_RECVSEND_FIXED_BUF` on
    /// `SENDMSG_ZC`.
    Refused,
}

enum Failure {
    /// A send was pushed and its completion or notification did not arrive,
    /// so the kernel may still read the probe buffer: the buffer and the ring
    /// must not be released.
    Leak(String),
    /// Nothing the kernel holds refers to the buffer.
    Other(String),
}

impl From<String> for Failure {
    fn from(why: String) -> Self {
        Failure::Other(why)
    }
}

/// Send `LEN` bytes at `at` with `SENDMSG_ZC`, from registered buffer
/// `buf_index` or, with `None`, from plain iovecs, on a connection whose
/// write queue holds unsent data, and return the change in the queue's
/// charge. Waits for the send's completion and notification before
/// returning, and returns `Leak` when either does not arrive. `ready` holds
/// completions reaped and not yet consumed.
fn charge(
    engine: &mut ActiveEngine,
    ready: &mut Vec<(u64, i32, u32)>,
    at: *mut u8,
    buf_index: Option<u16>,
) -> Result<Charge, Failure> {
    let (client, peer) = stuck_connection()?;
    let fd = client.as_raw_fd();
    let before = wmem_queued(fd)?;
    let unsent_before = unsent(fd)?;
    let queued_before = queued(fd)?;

    let mut iov = libc::iovec {
        iov_base: at.cast(),
        iov_len: LEN,
    };
    // SAFETY: all-zero is a valid `msghdr`.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    let flags = libc::MSG_DONTWAIT as u32;
    let op = match buf_index {
        Some(buf_index) => Op::SendMsgZcFixed {
            fd: Fd::Raw(fd),
            msg: &msg,
            flags,
            buf_index,
        },
        None => Op::SendMsgZc {
            fd: Fd::Raw(fd),
            msg: &msg,
            flags,
        },
    };
    // SAFETY: `msg`, `iov` and the bytes at `at` stay valid until the send's
    // completion and notification have been reaped below, or, when the
    // notification does not arrive, are leaked by the caller.
    unsafe { engine.push(&Sqe::new(op, 1)) }.map_err(|e| format!("pushing the send: {e}"))?;
    // From here every failure is `Leak` until the notification is reaped.
    let (result, cqe_flags) = next_completion(engine, ready).map_err(Failure::Leak)?;
    let more = cqueue::more(cqe_flags);

    let outcome = if result == -libc::EINVAL && buf_index.is_some() {
        Ok(Charge::Refused)
    } else if result != LEN as i32 {
        Err(format!("the probe's send returned {result}, not {LEN}"))
    } else {
        // The charge is measured over exactly the probe's send: the queue
        // grew by `LEN` (an ACK would have shrunk it and lowered the charge),
        // and none of it was transmitted.
        match (wmem_queued(fd), unsent(fd), queued(fd)) {
            (Ok(after), Ok(left), Ok(held))
                if left - unsent_before == LEN as i64 && held - queued_before == LEN as i64 =>
            {
                Ok(Charge::Sent(after - before))
            }
            (Ok(_), Ok(_), Ok(_)) => Err(
                "the write queue changed by more than the probe's send while it was measured"
                    .into(),
            ),
            (Err(why), _, _) | (_, Err(why), _) | (_, _, Err(why)) => Err(why),
        }
    };

    // Discard the queued data, so the kernel releases the send's pages and
    // posts its notification.
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `linger` is a valid `SO_LINGER` value.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        );
    }
    drop(client);
    drop(peer);
    if more {
        match next_completion(engine, ready) {
            Ok((_, f)) if cqueue::notif(f) => {}
            Ok((r, f)) => {
                return Err(Failure::Leak(format!(
                    "expected the send's notification, got result {r} flags {f:#x}"
                )));
            }
            Err(why) => return Err(Failure::Leak(why)),
        }
    }
    outcome.map_err(Failure::Other)
}

/// The next completion's result and flags, waiting up to `WAIT`. `ready`
/// holds completions reaped and not yet consumed, oldest first.
fn next_completion(
    engine: &mut ActiveEngine,
    ready: &mut Vec<(u64, i32, u32)>,
) -> Result<(i32, u32), String> {
    let deadline = Instant::now() + WAIT;
    loop {
        engine.reap(ready);
        if !ready.is_empty() {
            let (_, result, flags) = ready.remove(0);
            return Ok((result, flags));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!(
                "no completion from the probe's send within {WAIT:?}"
            ));
        }
        engine
            .submit_and_wait_timeout(1, left)
            .map_err(|e| format!("waiting for the probe's send: {e}"))?;
    }
}

/// A loopback connection whose receiver does not read, with at least 32 KiB
/// queued and unsent, so a send that follows stays in the write queue.
/// Returns the sending socket and the receiving one.
///
/// The receive buffer is 64 KiB: TCP sizes skbs from the peer's window, and a
/// much smaller one would split the probe's 4 KiB send into several skbs.
fn stuck_connection() -> Result<(OwnedFd, OwnedFd), String> {
    let err = |what: &str| {
        format!(
            "probe connection: {what}: {}",
            std::io::Error::last_os_error()
        )
    };
    // Non-blocking, so the connect and accept below wait at most `SETUP`.
    let socket = || {
        // SAFETY: plain socket creation; the result is checked.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            Err(err("socket"))
        } else {
            // SAFETY: `fd` is a new descriptor this function owns.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    };
    let set = |fd: RawFd, level, name, value: libc::c_int| {
        // SAFETY: `value` is a valid `int` option value.
        let r = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&raw const value).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            Err(err("setsockopt"))
        } else {
            Ok(())
        }
    };

    let listener = socket()?;
    set(
        listener.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        64 << 10,
    )?;
    // SAFETY: all-zero is a valid `sockaddr_in`.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `addr` and `len` describe a valid `sockaddr_in`.
    unsafe {
        let a = (&raw mut addr).cast::<libc::sockaddr>();
        if libc::bind(listener.as_raw_fd(), a, len) != 0
            || libc::listen(listener.as_raw_fd(), 1) != 0
            || libc::getsockname(listener.as_raw_fd(), a, &mut len) != 0
        {
            return Err(err("listen"));
        }
    }
    let client = socket()?;
    set(
        client.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        1 << 20,
    )?;
    set(client.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)?;
    let deadline = Instant::now() + SETUP;
    // SAFETY: as for `bind`.
    if unsafe { libc::connect(client.as_raw_fd(), (&raw const addr).cast(), len) } != 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(err("connect"));
        }
        wait_for(client.as_raw_fd(), libc::POLLOUT, deadline)?;
        let mut so_error: libc::c_int = 0;
        let mut so_len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `so_error` and `so_len` describe a writable `int`.
        let r = unsafe {
            libc::getsockopt(
                client.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut so_error).cast(),
                &mut so_len,
            )
        };
        if r != 0 || so_error != 0 {
            return Err(format!(
                "probe connection: connect: {}",
                std::io::Error::from_raw_os_error(so_error)
            ));
        }
    }
    wait_for(listener.as_raw_fd(), libc::POLLIN, deadline)?;
    // SAFETY: plain accept; the result is checked.
    let peer = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if peer < 0 {
        return Err(err("accept"));
    }
    // SAFETY: `peer` is a new descriptor this function owns.
    let peer = unsafe { OwnedFd::from_raw_fd(peer) };

    // `MSG_EOR` keeps the probe's send out of the prefill's last skb.
    let fill = vec![0u8; 192 << 10];
    // SAFETY: `fill` is valid for its length.
    let sent = unsafe {
        libc::send(
            client.as_raw_fd(),
            fill.as_ptr().cast(),
            fill.len(),
            libc::MSG_DONTWAIT | libc::MSG_EOR,
        )
    };
    if sent < 0 {
        return Err(err("prefill"));
    }
    if sent != fill.len() as isize {
        return Err(format!(
            "probe connection: the prefill sent {sent} of {} bytes (the send \
             buffer, 2 x net.core.wmem_max, or net.ipv4.tcp_notsent_lowat is too small)",
            fill.len()
        ));
    }
    // The receiver's window closes within microseconds on loopback.
    while unsent(client.as_raw_fd())? < 32 << 10 {
        if Instant::now() >= deadline {
            return Err("probe connection: the prefill did not stay unsent".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok((client, peer))
}

/// Wait until `fd` reports `events`, or fail at `deadline`.
fn wait_for(fd: RawFd, events: libc::c_short, deadline: Instant) -> Result<(), String> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("probe connection: not ready within {SETUP:?}"));
        }
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ms = left.as_millis().clamp(1, 1000) as libc::c_int;
        // SAFETY: one valid `pollfd`.
        let r = unsafe { libc::poll(&mut pfd, 1, ms) };
        if r > 0 {
            return Ok(());
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(format!(
                "probe connection: poll: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
}

/// `SK_MEMINFO_WMEM_QUEUED`: bytes charged to the socket's write queue.
fn wmem_queued(fd: RawFd) -> Result<i64, String> {
    let mut info = [0u32; SK_MEMINFO_VARS];
    let mut len = size_of_val(&info) as libc::socklen_t;
    // SAFETY: `info` and `len` describe a writable buffer.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MEMINFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(format!("SO_MEMINFO: {}", std::io::Error::last_os_error()));
    }
    Ok(i64::from(info[libc::SK_MEMINFO_WMEM_QUEUED as usize]))
}

/// Bytes in the socket's write queue not yet acknowledged (`SIOCOUTQ`).
fn queued(fd: RawFd) -> Result<i64, String> {
    let mut n: libc::c_int = 0;
    // SAFETY: `SIOCOUTQ` writes one `int`.
    if unsafe { libc::ioctl(fd, libc::TIOCOUTQ as _, &mut n) } != 0 {
        return Err(format!("SIOCOUTQ: {}", std::io::Error::last_os_error()));
    }
    Ok(i64::from(n))
}

/// Bytes in the socket's write queue not yet sent.
fn unsent(fd: RawFd) -> Result<i64, String> {
    let mut n: libc::c_int = 0;
    // SAFETY: `SIOCOUTQNSD` writes one `int`.
    if unsafe { libc::ioctl(fd, SIOCOUTQNSD as _, &mut n) } != 0 {
        return Err(format!("SIOCOUTQNSD: {}", std::io::Error::last_os_error()));
    }
    Ok(i64::from(n))
}

/// A 2 MiB-aligned anonymous mapping of `HUGE` bytes, advised and collapsed
/// into a transparent huge page, inside a larger mapping, so its VMA has
/// neighbours of its own and `/proc/self/smaps` reports it alone.
struct HugeBuffer {
    raw: *mut libc::c_void,
    raw_len: usize,
    ptr: *mut u8,
}

impl HugeBuffer {
    fn new() -> Result<Self, String> {
        let raw_len = 3 * HUGE;
        // SAFETY: a new private anonymous mapping; the result is checked.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                raw_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(format!(
                "probe buffer: mmap: {}",
                std::io::Error::last_os_error()
            ));
        }
        // Strictly above `raw`, so a page of the mapping lies on each side.
        let ptr = ((raw as usize + 1).next_multiple_of(HUGE)) as *mut u8;
        let buf = HugeBuffer { raw, raw_len, ptr };
        // SAFETY: `ptr..ptr + HUGE` lies inside the mapping.
        // Collapsing is best effort; `measure` checks the result.
        unsafe {
            libc::madvise(buf.ptr.cast(), HUGE, libc::MADV_HUGEPAGE);
            std::ptr::write_bytes(buf.ptr, 1, HUGE);
            libc::madvise(buf.ptr.cast(), HUGE, MADV_COLLAPSE);
        }
        Ok(buf)
    }

    /// `AnonHugePages` of the VMA that starts at `ptr`, in KiB; 0 when it is
    /// not found.
    fn anon_huge_kib(&self) -> usize {
        let Ok(smaps) = std::fs::read_to_string("/proc/self/smaps") else {
            return 0;
        };
        let header = format!("{:x}-", self.ptr as usize);
        let mut lines = smaps.lines().skip_while(|l| !l.starts_with(&header));
        lines.next();
        lines
            // Field lines start with an upper-case name; the next VMA's
            // header starts with a hex address.
            .take_while(|l| l.starts_with(|c: char| c.is_ascii_uppercase()))
            .find_map(|l| l.strip_prefix("AnonHugePages:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .unwrap_or(0)
    }
}

impl Drop for HugeBuffer {
    fn drop(&mut self) {
        // SAFETY: the mapping this value created.
        unsafe { libc::munmap(self.raw, self.raw_len) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_passes_equal_charges_and_names_the_fault() {
        assert_eq!(verdict(4352, 4352), FixedBufferSends::Enabled);
        assert_eq!(verdict(4352 + 4096, 4352), FixedBufferSends::Enabled);
        assert_eq!(verdict(2 << 20, 4352), FixedBufferSends::Overcharged);
        assert!(matches!(
            verdict(64 << 10, 4352),
            FixedBufferSends::Inconclusive(_)
        ));
    }

    /// The probe returns a result that matches the running kernel's version
    /// where the version decides it: before 6.15 the kernel refuses the flag
    /// on `SENDMSG_ZC`. From 6.15 the result depends on whether the kernel
    /// carries the charge fix, which its version does not say; the test
    /// prints it.
    #[test]
    fn the_probe_agrees_with_the_kernel_version() {
        let result = probe_once();
        eprintln!("fixed-buffer send probe: {result:?}");
        let kernel = crate::memlock::KernelVersion::current().expect("kernel version");
        if (kernel.major, kernel.minor) < (6, 15) {
            assert!(
                matches!(
                    result,
                    FixedBufferSends::Unsupported | FixedBufferSends::Inconclusive(_)
                ),
                "{kernel}: {result:?}"
            );
        }
        assert_eq!(enabled(), result == FixedBufferSends::Enabled);
    }
}
