//! Whether guard-only sends from a registered region name the region's buffer
//! (`IORING_RECVSEND_FIXED_BUF`), decided once per process by a probe of the
//! running kernel, for a region in base pages only and for any other. A send
//! of one guard goes out as `SEND_ZC` (the flag is Linux 6.0), and a send of
//! several as `SENDMSG_ZC` (the flag is Linux 6.15).
//!
//! `docs/fixed-buffer-sends.md` describes the kernel behaviour this decides
//! on, the settings involved, and the send shapes that benefit.
//!
//! The kernel must accept the flag, and must charge a send from a registered
//! buffer to the socket's send buffer the same as a send of the same bytes
//! from plain iovecs. From Linux 6.3, a
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
//! The fault comes from coalescing, which base pages do not get, so a send
//! from a region in base pages only is charged correctly on every kernel
//! that takes the flag. The probe has a result for each kind.
//!
//! The probe sends 4 KiB from plain iovecs, then from the last page of each
//! of two registered buffers, four base pages advised `MADV_NOHUGEPAGE` and a
//! 2 MiB transparent huge page: as a fixed `SEND_ZC`, and, when that passes,
//! as a fixed `SENDMSG_ZC`. Each send is on a fresh loopback connection whose
//! receiver does not read, and the probe compares the change in
//! `SK_MEMINFO_WMEM_QUEUED` across each fixed send with the plain one's. The
//! kernel's fault in the charge raises a fixed send from the huge page by
//! about 2 MiB.
//!
//! The probe's duration has not been measured. Its waits on the sockets and
//! the ring are bounded: 1 s for each connection's setup and prefill, and 5 s
//! for each completion, about 11 s per send. It makes at most fifteen sends
//! (up to three tries at the plain one, and for each buffer up to three at
//! the `SEND_ZC` and three at the `SENDMSG_ZC`), so its waits are bounded at
//! about 165 s.
//!
//! Two steps are not bounded. The huge page is allocated with `MADV_HUGEPAGE`
//! and `MADV_COLLAPSE`, which can wait for memory compaction, and the check
//! that it is one huge page reads `/proc/self/smaps`, which takes longer the
//! more the process has mapped.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::abi::cqueue;
use super::engine::{ActiveEngine, Engine};
use super::sqe::{Fd, Op, Sqe};
use crate::buffer::fixed::{FixedBufferRegistry, FixedBufferSends, MemoryRegion};
use crate::smaps;

/// The size of a PMD-mapped transparent huge page on x86-64 and on arm64
/// with 4 KiB pages.
const HUGE: usize = 2 << 20;
/// The probe's send: one page, page-aligned.
const LEN: usize = 4096;
/// The base-page probe buffer's length, in base pages.
const BASE_PAGES: usize = 4;
/// Bytes the fixed send's charge may exceed the plain send's and still pass.
/// A kernel with the fault charges the probe's send about `HUGE` more.
const TOLERANCE: i64 = LEN as i64;
/// Bytes over the plain send's charge that identify the fault.
const OVERCHARGE: i64 = (HUGE / 2) as i64;
/// How long the probe waits for each completion.
const WAIT: Duration = Duration::from_secs(5);
/// How long the probe waits for each connection's setup and prefill.
const SETUP: Duration = Duration::from_secs(1);
/// How many times the probe tries each send (the plain one, and each
/// buffer's `SEND_ZC` and `SENDMSG_ZC`) while it fails transiently or
/// measures unclear.
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

static RESULT: OnceLock<Results> = OnceLock::new();
static HUGE_SINGLE: AtomicBool = AtomicBool::new(false);
static HUGE_MULTI: AtomicBool = AtomicBool::new(false);
static BASE_SINGLE: AtomicBool = AtomicBool::new(false);
static BASE_MULTI: AtomicBool = AtomicBool::new(false);

/// Which guard-only sends name their region's buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Modes {
    /// A send of one guard, as `SEND_ZC`.
    pub(crate) single: bool,
    /// A send of several guards, as `SENDMSG_ZC`.
    pub(crate) multi: bool,
}

/// Which guard-only sends name their region's buffer, for each kind of
/// region.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Allowed {
    /// A region whose registration did not show it to be in base pages.
    pub(crate) huge: Modes,
    /// A region in base pages only (`MemoryRegion::base_pages`).
    pub(crate) base: Modes,
}

impl Allowed {
    /// The modes for a region, by whether it is in base pages only.
    pub(crate) fn for_region(&self, base_pages: bool) -> Modes {
        if base_pages { self.base } else { self.huge }
    }
}

/// The probe's results: for a region that may lie in huge pages, and for one
/// in base pages only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Results {
    pub(crate) huge: FixedBufferSends,
    pub(crate) base: FixedBufferSends,
}

impl Results {
    /// The result for a region, by whether it is in base pages only.
    pub(crate) fn for_region(&self, base_pages: bool) -> FixedBufferSends {
        if base_pages {
            self.base.clone()
        } else {
            self.huge.clone()
        }
    }
}

/// Why the probe must not run, set at launch when `RLIMIT_MEMLOCK` has no room
/// for its charge ([`refuse`]) and cleared by a later launch that made room
/// ([`allow`]).
static REFUSED: Mutex<Option<String>> = Mutex::new(None);

/// Which sends the probe passed; none until it has run. Workers read it on
/// the send path.
///
/// [`probe_once`] stores the flags before its caller spawns the workers or
/// sends a worker the message that registers a region. A worker checks a
/// guard's region against its own table, which it updates on that message,
/// so a worker that can find the region loads after the stores.
pub(crate) fn allowed() -> Allowed {
    Allowed {
        huge: Modes {
            single: HUGE_SINGLE.load(Ordering::Relaxed),
            multi: HUGE_MULTI.load(Ordering::Relaxed),
        },
        base: Modes {
            single: BASE_SINGLE.load(Ordering::Relaxed),
            multi: BASE_MULTI.load(Ordering::Relaxed),
        },
    }
}

/// The `RLIMIT_MEMLOCK` charge the probe makes while it runs: its two
/// buffers, and its ring on a kernel that charges rings.
pub(crate) fn memlock_charge(charges_rings: bool, page: u64) -> u64 {
    let ring = if charges_rings {
        crate::memlock::ring_bytes(PROBE_SQ, PROBE_CQ, page)
    } else {
        0
    };
    HUGE as u64 + BASE_PAGES as u64 * page + ring
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

/// The probe's results, running it on the first call. The calling thread
/// blocks while the probe runs. The results are logged once at `debug`, and
/// set in the `ringline/ring/fixed_buffer_sends` and
/// `ringline/ring/fixed_buffer_sends_base_pages` gauges, so a kernel upgrade
/// that turns fixed-buffer sends on or off shows in the application's metrics.
/// `Runtime::register_region` logs, for each region, whether its sends use
/// its buffer.
pub(crate) fn probe_once() -> Results {
    RESULT
        .get_or_init(|| {
            let results = probe();
            let level = |result: &FixedBufferSends, single: &AtomicBool, multi: &AtomicBool| {
                let FixedBufferSends::Enabled { multi_guard } = *result else {
                    return 0;
                };
                multi.store(multi_guard, Ordering::Relaxed);
                single.store(true, Ordering::Relaxed);
                if multi_guard { 2 } else { 1 }
            };
            crate::metrics::FIXED_BUFFER_SENDS.set(level(&results.huge, &HUGE_SINGLE, &HUGE_MULTI));
            crate::metrics::FIXED_BUFFER_SENDS_BASE_PAGES.set(level(
                &results.base,
                &BASE_SINGLE,
                &BASE_MULTI,
            ));
            log::debug!(
                "fixed-buffer send probe: regions in base pages: {}; other regions: {}",
                describe(&results.base),
                describe(&results.huge)
            );
            results
        })
        .clone()
}

/// Whether `region` is in base pages only, by `/proc/self/smaps`
/// (`smaps::base_pages_in`); `false` when smaps cannot be read.
pub(crate) fn in_base_pages(region: &MemoryRegion) -> bool {
    std::fs::read_to_string("/proc/self/smaps").is_ok_and(|smaps| in_base_pages_by(&smaps, region))
}

/// As [`in_base_pages`], from `smaps` already read, for several regions at
/// once. Also `false` while a size of multi-page folios smaller than a PMD
/// is faulted in without `MADV_HUGEPAGE` (`smaps::small_folios_always`):
/// memory touched before it was advised `MADV_NOHUGEPAGE` may hold such
/// folios, and smaps does not show them.
pub(crate) fn in_base_pages_by(smaps: &str, region: &MemoryRegion) -> bool {
    !smaps::small_folios_always()
        && smaps::base_pages_in(
            smaps,
            region.ptr() as usize,
            region.len(),
            smaps::thp_configured(),
        )
}

/// Whether a region of each kind (not in base pages, in base pages) has been
/// logged at `warn`.
static WARNED: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];

/// Log whether sends from the region registered as `id` use its buffer: at
/// `debug` when they do, and when they do not at `warn` for the first region
/// of its kind in the process and at `debug` after that.
pub(crate) fn log_region(
    id: crate::buffer::fixed::RegionId,
    len: usize,
    base_pages: bool,
    result: &FixedBufferSends,
) {
    let pages = if base_pages {
        "in base pages"
    } else {
        "not shown to be in base pages"
    };
    let line = format!(
        "region {} ({len} bytes, {pages}): {}",
        id.0,
        describe(result)
    );
    let enabled = matches!(result, FixedBufferSends::Enabled { .. });
    if enabled || WARNED[usize::from(base_pages)].swap(true, Ordering::Relaxed) {
        log::debug!("{line}");
    } else {
        log::warn!("{line}");
    }
}

/// The probe's result in words, for the line `probe_once` logs.
fn describe(result: &FixedBufferSends) -> String {
    const DOC: &str =
        "https://github.com/ringline-rs/ringline/blob/main/docs/fixed-buffer-sends.md";
    const SAME: &str = "sends use plain iovecs as before";
    match result {
        FixedBufferSends::Enabled { multi_guard: true } => {
            "fixed-buffer sends on, for sends of one guard and of several".into()
        }
        FixedBufferSends::Enabled { multi_guard: false } => format!(
            "fixed-buffer sends on for sends of one guard, not of several: the \
             kernel refused them (it does before Linux 6.15) or the probe could not \
             measure them; those {SAME}. See {DOC}"
        ),
        FixedBufferSends::Overcharged => format!(
            "fixed-buffer sends off: this kernel does not have the fix to how they \
             are charged to the socket (Overcharged); {SAME}. See {DOC}"
        ),
        FixedBufferSends::Unsupported => {
            format!(
                "fixed-buffer sends off: the kernel refuses them (Unsupported); {SAME}. See {DOC}"
            )
        }
        FixedBufferSends::Inconclusive(why) => {
            format!("fixed-buffer sends off: the probe could not decide ({why}); {SAME}. See {DOC}")
        }
        FixedBufferSends::Disabled => {
            "fixed-buffer sends off: ConfigBuilder::fixed_buffer_sends is false".into()
        }
    }
}

fn probe() -> Results {
    let both = |result: FixedBufferSends| Results {
        huge: result.clone(),
        base: result,
    };
    if let Some(why) = REFUSED.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return both(FixedBufferSends::Inconclusive(why));
    }
    let base = match BaseBuffer::new() {
        Ok(buf) => buf,
        Err(why) => return both(FixedBufferSends::Inconclusive(why)),
    };
    // Without a huge page the base-page result is still measured.
    let huge = HugeBuffer::new();
    let config = crate::config::Config {
        sq_entries: PROBE_SQ,
        cq_entries: PROBE_CQ,
        sqpoll: false,
        iowq_max_workers: 0,
        ..crate::config::Config::default()
    };
    let mut engine = match ActiveEngine::setup(&config) {
        Ok(engine) => engine,
        Err(e) => {
            return both(FixedBufferSends::Inconclusive(format!(
                "io_uring setup: {e}"
            )));
        }
    };
    // SAFETY: both buffers are mapped for the lengths given and outlive the
    // engine, which is dropped first (declared after them).
    let mut regions = vec![unsafe { MemoryRegion::new(base.ptr, base.len) }];
    if let Ok(huge) = &huge {
        regions.push(unsafe { MemoryRegion::new(huge.ptr, HUGE) });
    }
    if let Err(e) = engine.register_buffers(&FixedBufferRegistry::new(&regions, 2)) {
        return both(FixedBufferSends::Inconclusive(format!(
            "registering the probe buffers: {e}"
        )));
    }
    // Checked after registering: the registration pins the folios, so they
    // are still what was checked when the sends run. A huge page split before
    // the pin reads as no huge page here and makes the huge-page result
    // inconclusive, not wrong.
    let huge_page = match &huge {
        Ok(buf) if buf.anon_huge_kib() >= HUGE / 1024 => Ok(buf.ptr),
        Ok(_) => Err("no transparent huge page for the probe buffer \
                      (/sys/kernel/mm/transparent_hugepage/enabled)"
            .to_string()),
        Err(why) => Err(why.clone()),
    };
    let in_base_pages = smaps::base_pages_in(
        &std::fs::read_to_string("/proc/self/smaps").unwrap_or_default(),
        base.ptr as usize,
        base.len,
        smaps::thp_configured(),
    );
    let result = measure(&mut engine, &base, in_base_pages, huge_page);
    if let Err(Failure::Leak(_)) = result {
        // The kernel may still read the buffers, so neither they nor the
        // ring that registered them are released.
        let _ = std::mem::ManuallyDrop::new(engine);
        let _ = std::mem::ManuallyDrop::new(base);
        let _ = std::mem::ManuallyDrop::new(huge);
    } else {
        // Clearing the slots returns the buffers' `RLIMIT_MEMLOCK` charge
        // now; dropping the ring returns it later, from the kernel's ring
        // exit work.
        let empty = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        for slot in 0..regions.len() as u16 {
            // SAFETY: nothing using the slot is in flight: every send has
            // completed and posted its notification.
            let _ = unsafe { engine.register_buffers_update_one(slot, empty) };
        }
    }
    match result {
        Ok(results) => results,
        Err(Failure::Leak(why) | Failure::Fixed(why) | Failure::Transient(why)) => {
            both(FixedBufferSends::Inconclusive(why))
        }
    }
}

/// The registered buffer index of the base-page probe buffer.
const BASE_INDEX: u16 = 0;
/// The registered buffer index of the huge page.
const HUGE_INDEX: u16 = 1;

/// Measure a plain send, then each probe buffer's fixed sends against it.
/// The base buffer is measured when `in_base_pages`, and the huge page when
/// there is one; otherwise that buffer's result is `Inconclusive`. A failure
/// on one buffer leaves the other's result. Only a `Leak`, or a plain send
/// that cannot be measured, ends the probe.
fn measure(
    engine: &mut ActiveEngine,
    base: &BaseBuffer,
    in_base_pages: bool,
    huge: Result<*mut u8, String>,
) -> Result<Results, Failure> {
    // The last page of the base buffer, so the send's registration spans
    // several pages, as a real region's does.
    let base_at = base.ptr.wrapping_add(base.len - LEN);
    let mut ready = Vec::new();
    let mut plain = Err(Failure::Transient(String::new()));
    for _ in 0..ATTEMPTS {
        plain = match charge(engine, &mut ready, base_at, Kind::Plain) {
            Ok(Charge::Sent(bytes)) => Ok(bytes),
            Ok(Charge::Refused) => Err(Failure::Fixed("a plain SENDMSG_ZC was refused".into())),
            Err(failure) => Err(failure),
        };
        if !matches!(plain, Err(Failure::Transient(_))) {
            break;
        }
    }
    let plain = plain?;
    let base_result = if in_base_pages {
        buffer(engine, &mut ready, base_at, BASE_INDEX, plain)?
    } else {
        FixedBufferSends::Inconclusive("the base-page probe buffer is not in base pages".into())
    };
    let huge_result = match huge {
        Err(why) => FixedBufferSends::Inconclusive(why),
        // The last page of the huge page: the fault charges it about `HUGE`.
        Ok(ptr) => buffer(
            engine,
            &mut ready,
            ptr.wrapping_add(HUGE - LEN),
            HUGE_INDEX,
            plain,
        )?,
    };
    Ok(Results {
        huge: huge_result,
        base: base_result,
    })
}

/// One buffer's result: a fixed `SEND_ZC` from `at` in buffer `index`
/// against the plain send's charge, tried up to `ATTEMPTS` times while it
/// fails transiently or measures unclear, and when it passes, the multi-guard
/// send. Only a `Leak` is an error.
fn buffer(
    engine: &mut ActiveEngine,
    ready: &mut Vec<(u64, i32, u32)>,
    at: *mut u8,
    index: u16,
    plain: i64,
) -> Result<FixedBufferSends, Failure> {
    let mut why = String::new();
    for _ in 0..ATTEMPTS {
        match charge(engine, ready, at, Kind::Single(index)) {
            Ok(Charge::Refused) => return Ok(FixedBufferSends::Unsupported),
            Ok(Charge::Sent(bytes)) => match verdict(bytes, plain) {
                Verdict::Pass => {
                    return Ok(FixedBufferSends::Enabled {
                        multi_guard: multi(engine, ready, at, index, plain)?,
                    });
                }
                Verdict::Overcharged => return Ok(FixedBufferSends::Overcharged),
                Verdict::Unclear(unclear) => why = unclear,
            },
            Err(Failure::Transient(transient) | Failure::Fixed(transient)) => why = transient,
            Err(leak @ Failure::Leak(_)) => return Err(leak),
        }
    }
    Ok(FixedBufferSends::Inconclusive(why))
}

/// Whether a fixed `SENDMSG_ZC` from `at` in buffer `index` is charged as the
/// plain send was, measured up to `ATTEMPTS` times. One that is refused or
/// overcharged, or that fails transiently or measures unclear on every try,
/// leaves sends of several guards on plain iovecs. Only a `Leak` ends the
/// probe.
fn multi(
    engine: &mut ActiveEngine,
    ready: &mut Vec<(u64, i32, u32)>,
    at: *mut u8,
    index: u16,
    plain: i64,
) -> Result<bool, Failure> {
    for _ in 0..ATTEMPTS {
        match charge(engine, ready, at, Kind::Multi(index)) {
            Ok(Charge::Sent(bytes)) => match verdict(bytes, plain) {
                Verdict::Pass => return Ok(true),
                Verdict::Overcharged => break,
                Verdict::Unclear(_) => {}
            },
            Ok(Charge::Refused) => break,
            Err(Failure::Transient(_) | Failure::Fixed(_)) => {}
            Err(leak @ Failure::Leak(_)) => return Err(leak),
        }
    }
    Ok(false)
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The fixed send was charged the same as the plain one.
    Pass,
    /// The fixed send was charged the kernel's fault.
    Overcharged,
    /// Neither, for the reason given.
    Unclear(String),
}

/// The verdict from a fixed and a plain send's charges, in bytes.
fn verdict(fixed: i64, plain: i64) -> Verdict {
    if fixed - plain <= TOLERANCE {
        Verdict::Pass
    } else if fixed - plain >= OVERCHARGE {
        Verdict::Overcharged
    } else {
        Verdict::Unclear(format!(
            "a {LEN}-byte send from a registered buffer was charged {fixed} bytes, \
             and from plain iovecs {plain}"
        ))
    }
}

/// Which send [`charge`] makes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `SENDMSG_ZC` from plain iovecs.
    Plain,
    /// `SEND_ZC` from the registered buffer at this index.
    Single(u16),
    /// `SENDMSG_ZC` from the registered buffer at this index.
    Multi(u16),
}

enum Charge {
    /// The send was taken; the change in the write queue's charge, in bytes.
    Sent(i64),
    /// `EINVAL`. On a fixed send, the kernel does not take
    /// `IORING_RECVSEND_FIXED_BUF` on its opcode; on a plain send, `measure`
    /// treats it as a failure that measuring again would repeat.
    Refused,
}

enum Failure {
    /// A send was pushed and its completion or notification did not arrive,
    /// so the kernel may still read the probe buffer: the buffer and the ring
    /// must not be released.
    Leak(String),
    /// Nothing the kernel holds refers to the buffer, and measuring again
    /// may succeed.
    Transient(String),
    /// Nothing the kernel holds refers to the buffer, and measuring again
    /// would fail the same way.
    Fixed(String),
}

impl From<String> for Failure {
    fn from(why: String) -> Self {
        Failure::Transient(why)
    }
}

/// Send `LEN` bytes at `at` as `kind` says, on a connection whose write
/// queue holds unsent data, and return the change in the queue's charge.
/// Waits for the send's completion and notification before returning, and
/// returns `Leak` when either does not arrive. `ready` holds
/// completions reaped and not yet consumed.
fn charge(
    engine: &mut ActiveEngine,
    ready: &mut Vec<(u64, i32, u32)>,
    at: *mut u8,
    kind: Kind,
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
    let op = match kind {
        Kind::Plain => Op::SendMsgZc {
            fd: Fd::Raw(fd),
            msg: &msg,
            flags,
        },
        Kind::Single(buf_index) => Op::SendZcFixed {
            fd: Fd::Raw(fd),
            buf: at,
            len: LEN as u32,
            flags: libc::MSG_DONTWAIT,
            buf_index,
        },
        Kind::Multi(buf_index) => Op::SendMsgZcFixed {
            fd: Fd::Raw(fd),
            msg: &msg,
            flags,
            buf_index,
        },
    };
    // SAFETY: `msg`, `iov` and the bytes at `at` stay valid until the send's
    // completion and notification have been reaped below, or, when the
    // notification does not arrive, are leaked by the caller.
    unsafe { engine.push(&Sqe::new(op, 1)) }.map_err(|e| format!("pushing the send: {e}"))?;
    // From here every failure is `Leak` until the notification is reaped.
    let (result, cqe_flags) = next_completion(engine, ready).map_err(Failure::Leak)?;
    // A notification here would be an earlier send's, posted without
    // `F_MORE` on its completion; this send's completion is then still to
    // come, and the completions after it would be misattributed.
    if cqueue::notif(cqe_flags) {
        return Err(Failure::Leak(
            "the probe's send was answered by a zero-copy notification".into(),
        ));
    }
    let more = cqueue::more(cqe_flags);

    let outcome = if result == -libc::EINVAL {
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
    outcome.map_err(Failure::Transient)
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

/// Private anonymous memory advised `MADV_NOHUGEPAGE` before it is touched,
/// so it is in base pages.
struct BaseBuffer {
    ptr: *mut u8,
    len: usize,
}

impl BaseBuffer {
    fn new() -> Result<Self, String> {
        // SAFETY: `sysconf` has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as usize;
        let len = BASE_PAGES * page;
        // SAFETY: a new private anonymous mapping; the result is checked.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(format!(
                "base-page probe buffer: mmap: {}",
                std::io::Error::last_os_error()
            ));
        }
        let buf = BaseBuffer {
            ptr: ptr.cast(),
            len,
        };
        // SAFETY: the mapping above.
        unsafe {
            libc::madvise(ptr, len, libc::MADV_NOHUGEPAGE);
            std::ptr::write_bytes(buf.ptr, 1, len);
        }
        Ok(buf)
    }
}

impl Drop for BaseBuffer {
    fn drop(&mut self) {
        // SAFETY: the mapping this value created.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
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

    /// The line names the outcome in words and ends with the result's name
    /// where fixed sends are off.
    #[test]
    fn the_probe_line_says_on_or_off() {
        assert!(describe(&FixedBufferSends::Enabled { multi_guard: true }).contains("sends on"));
        let single = describe(&FixedBufferSends::Enabled { multi_guard: false });
        assert!(single.contains("one guard, not of several"), "{single}");
        let over = describe(&FixedBufferSends::Overcharged);
        assert!(
            over.contains("sends off") && over.contains("(Overcharged)"),
            "{over}"
        );
        assert!(over.contains("https://"), "{over}");
        let why = describe(&FixedBufferSends::Inconclusive("no huge page".into()));
        assert!(why.contains("could not decide (no huge page)"), "{why}");
        assert!(why.contains("as before"), "{why}");
    }

    #[test]
    fn verdict_passes_equal_charges_and_names_the_fault() {
        assert_eq!(verdict(4352, 4352), Verdict::Pass);
        assert_eq!(verdict(4352 + 4096, 4352), Verdict::Pass);
        assert_eq!(verdict(2 << 20, 4352), Verdict::Overcharged);
        assert!(matches!(verdict(64 << 10, 4352), Verdict::Unclear(_)));
    }

    /// The probe's results agree with the running kernel's version where the
    /// version decides them: before 6.15 the kernel refuses the flag on
    /// `SENDMSG_ZC`, so several guards never name a buffer. Sends from base
    /// pages are charged by the pages they use on every kernel, so they are
    /// never `Overcharged`. Whether a kernel carries the charge
    /// fix its version does not say; `probe_once` logs the results, which
    /// show only under a logger. `allowed` and the gauges report what the
    /// results say.
    #[test]
    fn the_probe_agrees_with_the_kernel_version() {
        let results = probe_once();
        let kernel = crate::memlock::KernelVersion::current().expect("kernel version");
        for result in [&results.huge, &results.base] {
            if (kernel.major, kernel.minor) < (6, 15) {
                assert!(
                    !matches!(result, FixedBufferSends::Enabled { multi_guard: true }),
                    "{kernel}: {results:?}"
                );
            }
        }
        // `Inconclusive` is allowed: under one test process another test's
        // launch can refuse the probe, or its registration can meet the
        // user's `RLIMIT_MEMLOCK`. The integration test names the result it
        // expects on a known kernel.
        assert!(
            !matches!(results.base, FixedBufferSends::Overcharged),
            "{kernel}: {results:?}"
        );
        let want = |result: &FixedBufferSends| match result {
            FixedBufferSends::Enabled { multi_guard } => Modes {
                single: true,
                multi: *multi_guard,
            },
            _ => Modes::default(),
        };
        assert_eq!(
            allowed(),
            Allowed {
                huge: want(&results.huge),
                base: want(&results.base),
            }
        );
        let level = |m: Modes| i64::from(m.single) + i64::from(m.multi);
        assert_eq!(
            crate::metrics::FIXED_BUFFER_SENDS.value(),
            level(want(&results.huge))
        );
        assert_eq!(
            crate::metrics::FIXED_BUFFER_SENDS_BASE_PAGES.value(),
            level(want(&results.base))
        );
    }
}
