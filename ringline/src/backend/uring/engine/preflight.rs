//! Behaviour preflights for the receive ring: incremental provided-buffer
//! rings (#622), and multishot receives with a total byte limit.
//!
//! The 6.12.y incremental-buffer fixes ran through at least 6.12.81, so no
//! kernel version marks a kernel that behaves as the receive driver relies
//! on (`docs/recv-incremental-ring-design.md`, "Selecting the ring kind").
//! The byte limit first shipped in Linux 6.17. Before a worker registers its
//! TCP ring as incremental, and again before it arms limited receives, it
//! checks the behaviour on the running kernel with a one-entry incremental
//! ring and an `AF_UNIX` stream socketpair, which needs no network
//! configuration. Each runs on the worker's ring before anything else is
//! armed, since it reaps every completion the ring holds.

use std::io::Write;
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::{Engine, RingKind};
use crate::backend::ProvidedBufRing;
use crate::backend::uring::abi::cqueue;
use crate::backend::uring::sqe::{Fd, Op, Sqe};
use crate::error::Error;
use crate::metrics::recv_preflight as step;

/// The group the preflight registers, which `Config` reserves.
const BGID: u16 = u16::MAX;
/// The preflight buffer's size.
const SIZE: u32 = 64;
/// The preflight receive's user_data.
const USER_DATA: u64 = u64::MAX - 1;
/// The user_data of the cancel that tears a live preflight receive down.
const CANCEL_USER_DATA: u64 = u64::MAX - 2;
/// How long the preflight waits for one completion.
const WAIT: Duration = Duration::from_secs(1);

/// The byte limit the limit preflight arms with.
const LIMIT: u32 = 24;

/// What a preflight found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Preflight {
    /// The kernel behaves as the receive driver relies on.
    Passed,
    /// The kernel refuses the feature.
    Unsupported,
    /// The step that did not behave as relied on: a
    /// `metrics::recv_preflight` slot.
    Failed(usize),
}

/// The `metrics::recv_preflight` slots a preflight reports a setup failure,
/// an I/O error or a timeout in.
struct Slots {
    socketpair: usize,
    io_error: usize,
    timeout: usize,
}

/// Check the incremental-ring behaviour the receive driver relies on.
///
/// `Err` is the `incremental_buffers` probe failing other than with
/// `EINVAL`, the preflight ring's registration failing, or a receive the
/// preflight could not cancel within 1 s; each fails the worker's startup.
/// A socketpair or I/O failure is reported as a failed step, which selects
/// plain rings.
pub(crate) fn inc_preflight<E: Engine>(engine: &mut E) -> Result<Preflight, Error> {
    if !engine.incremental_buffers().map_err(|e| {
        Error::BufferRegistration(format!(
            "incremental provided buffer ring probe (bgid {BGID}): {e}"
        ))
    })? {
        return Ok(Preflight::Unsupported);
    }
    let slots = Slots {
        socketpair: step::SOCKETPAIR,
        io_error: step::IO_ERROR,
        timeout: step::TIMEOUT,
    };
    preflight(engine, "incremental-ring", slots, run)
}

/// Check that a multishot receive with a total byte limit (`sqe->optlen`)
/// ends once it has received at least the limit, on an incremental ring.
/// Run only on a worker whose TCP ring is incremental.
///
/// `Unsupported` is the kernel failing the limited arm with `EINVAL`
/// (before Linux 6.17). `Err` is as for `inc_preflight`.
pub(crate) fn limit_preflight<E: Engine>(engine: &mut E) -> Result<Preflight, Error> {
    let slots = Slots {
        socketpair: step::LIMIT_SOCKETPAIR,
        io_error: step::LIMIT_IO_ERROR,
        timeout: step::LIMIT_TIMEOUT,
    };
    preflight(engine, "receive-limit", slots, run_limit)
}

/// Register a one-entry incremental ring, run `body` on a socketpair, then
/// cancel whatever receive is still armed and unregister the ring.
fn preflight<E: Engine>(
    engine: &mut E,
    name: &str,
    slots: Slots,
    body: fn(
        &mut E,
        &mut ProvidedBufRing,
        &mut UnixStream,
        &UnixStream,
        &mut Reaped,
        &mut bool,
    ) -> std::io::Result<Preflight>,
) -> Result<Preflight, Error> {
    let Ok((mut client, server)) = UnixStream::pair() else {
        return Ok(Preflight::Failed(slots.socketpair));
    };
    let mut ring = ProvidedBufRing::new(BGID, 1, SIZE).map_err(Error::Io)?;
    ring.set_incremental();
    engine.register_buf_ring(&ring, RingKind::Incremental)?;
    let mut armed = false;
    let mut reaped = Reaped::default();
    let result = match body(
        engine,
        &mut ring,
        &mut client,
        &server,
        &mut reaped,
        &mut armed,
    ) {
        Ok(found) => Ok(found),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(Preflight::Failed(slots.timeout)),
        Err(_) => Ok(Preflight::Failed(slots.io_error)),
    };
    // A completion that ends the arm may already be reaped and unconsumed.
    armed &= reaped.0.iter().all(|&(_, flags)| cqueue::more(flags));
    let disarmed = !armed || disarm(engine);
    let unregistered = engine.unregister_buf_ring(BGID).is_ok();
    if !disarmed || !unregistered {
        // The kernel may still reach the ring's entry, which points into the
        // ring's buffer; leak both rather than free memory it can write.
        std::mem::forget(ring);
    }
    if !disarmed {
        // Its last completion would otherwise reach the event loop.
        return Err(Error::RingSetup(format!(
            "the {name} preflight could not cancel its receive within 1 s"
        )));
    }
    result
}

// Test-only: make the preflight report `step` as failed when it reaches
// that step, with its receive still armed.
#[cfg(test)]
thread_local! {
    static FAIL_AT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Whether a test asked the preflight to fail at `at`.
fn injected(at: usize) -> bool {
    #[cfg(test)]
    {
        FAIL_AT.with(|f| f.get()) == Some(at)
    }
    #[cfg(not(test))]
    {
        let _ = at;
        false
    }
}

fn run<E: Engine>(
    e: &mut E,
    ring: &mut ProvidedBufRing,
    client: &mut UnixStream,
    server: &UnixStream,
    reaped: &mut Reaped,
    armed: &mut bool,
) -> std::io::Result<Preflight> {
    use Preflight::Failed;
    let base = ring.data_ptr(0, 0) as u64;

    // Write, reap, write, reap: the completions append at increasing
    // offsets, and the entry advances in place.
    arm(e, server)?;
    *armed = true;
    if injected(step::APPEND) {
        return Ok(Failed(step::APPEND));
    }
    client.write_all(b"abc")?;
    if !delivered(wait(e, reaped, armed)?, 3, true, true) {
        return Ok(Failed(step::APPEND));
    }
    ring.complete(0, 3, true);
    client.write_all(b"defg")?;
    if !delivered(wait(e, reaped, armed)?, 4, true, true) {
        return Ok(Failed(step::APPEND));
    }
    ring.complete(0, 4, true);
    // Safety: 7 bytes were received into buffer 0, which is not posted again
    // until it is released below.
    if unsafe { std::slice::from_raw_parts(ring.data_ptr(0, 0), 7) } != b"abcdefg" {
        return Ok(Failed(step::OFFSETS));
    }
    if ring.entry(0) != (base + 7, SIZE - 7, 0) {
        return Ok(Failed(step::OFFSETS));
    }

    // More than the space left: the completion delivers exactly the space
    // left with F_BUF_MORE clear, and the excess ends the arm with ENOBUFS.
    const EXCESS: u32 = 5;
    if injected(step::EXHAUSTION) {
        return Ok(Failed(step::EXHAUSTION));
    }
    client.write_all(&[b'x'; (SIZE - 7 + EXCESS) as usize])?;
    if !delivered(wait(e, reaped, armed)?, (SIZE - 7) as i32, false, true) {
        return Ok(Failed(step::EXHAUSTION));
    }
    ring.complete(0, SIZE - 7, false);
    let (res, flags) = wait(e, reaped, armed)?;
    if res != -libc::ENOBUFS || cqueue::more(flags) {
        return Ok(Failed(step::EXHAUSTION));
    }

    // Posted again and re-armed, the excess lands at offset 0, and a
    // half-close leaves the buffer posted at its used length.
    ring.release_batch(&[0, 0, 0]);
    arm(e, server)?;
    *armed = true;
    if injected(step::REPOST) {
        return Ok(Failed(step::REPOST));
    }
    if !delivered(wait(e, reaped, armed)?, EXCESS as i32, true, true) {
        return Ok(Failed(step::REPOST));
    }
    ring.complete(0, EXCESS, true);
    if injected(step::EOF) {
        return Ok(Failed(step::EOF));
    }
    client.shutdown(Shutdown::Write)?;
    let (res, flags) = wait(e, reaped, armed)?;
    if res != 0 || cqueue::buffer_select(flags).is_some() || cqueue::more(flags) {
        return Ok(Failed(step::EOF));
    }
    if ring.entry(0) != (base + EXCESS as u64, SIZE - EXCESS, 0) {
        return Ok(Failed(step::EOF));
    }
    ring.release_batch(&[0]);
    Ok(Preflight::Passed)
}

/// Arm with a limit of `LIMIT` bytes, then write below it and past it: the
/// first completion keeps the arm, and the one that reaches the limit ends
/// it with `F_MORE` clear. That completion may take all of the second write
/// or stop at the limit.
fn run_limit<E: Engine>(
    e: &mut E,
    ring: &mut ProvidedBufRing,
    client: &mut UnixStream,
    server: &UnixStream,
    reaped: &mut Reaped,
    armed: &mut bool,
) -> std::io::Result<Preflight> {
    use Preflight::Failed;
    const FIRST: u32 = 10;
    const SECOND: u32 = 20;
    const _: () = assert!(FIRST < LIMIT && FIRST + SECOND >= LIMIT && FIRST + SECOND <= SIZE);
    arm_with(e, server, LIMIT)?;
    *armed = true;
    if injected(step::LIMIT_BELOW) {
        return Ok(Failed(step::LIMIT_BELOW));
    }
    client.write_all(&[b'a'; FIRST as usize])?;
    let first = wait(e, reaped, armed)?;
    if first.0 == -libc::EINVAL && !cqueue::more(first.1) {
        return Ok(Preflight::Unsupported);
    }
    if !delivered(first, FIRST as i32, true, true) {
        return Ok(Failed(step::LIMIT_BELOW));
    }
    ring.complete(0, FIRST, true);
    if injected(step::LIMIT_END) {
        return Ok(Failed(step::LIMIT_END));
    }
    client.write_all(&[b'b'; SECOND as usize])?;
    let (res, flags) = wait(e, reaped, armed)?;
    let ended = (LIMIT - FIRST..=SECOND).contains(&u32::try_from(res).unwrap_or(0))
        && cqueue::buffer_select(flags) == Some(0)
        && cqueue::buf_more(flags)
        && !cqueue::more(flags);
    if !ended {
        return Ok(Failed(step::LIMIT_END));
    }
    ring.complete(0, res as u32, true);
    ring.release_batch(&[0]);
    Ok(Preflight::Passed)
}

/// Cancel a live preflight receive and reap its last completion and the
/// cancel's, so neither reaches the event loop. Returns whether both were
/// reaped within `WAIT`.
fn disarm<E: Engine>(e: &mut E) -> bool {
    let cancel = Sqe::new(Op::Cancel { target: USER_DATA }, CANCEL_USER_DATA);
    // Safety: a cancel references no caller memory.
    if unsafe { e.push(&cancel) }.is_err() {
        return false;
    }
    let deadline = Instant::now() + WAIT;
    let mut out = Vec::new();
    let (mut ended, mut cancelled) = (false, false);
    while !(ended && cancelled) && Instant::now() < deadline {
        if e.submit_and_get_events().is_err() {
            return false;
        }
        e.reap(&mut out);
        for &(ud, _, flags) in &out {
            ended |= ud == USER_DATA && !cqueue::more(flags);
            cancelled |= ud == CANCEL_USER_DATA;
        }
        out.clear();
        std::thread::yield_now();
    }
    ended && cancelled
}

/// Whether `(res, flags)` delivered `len` bytes into buffer 0 with the given
/// `F_BUF_MORE` and `F_MORE`.
fn delivered((res, flags): (i32, u32), len: i32, buf_more: bool, more: bool) -> bool {
    res == len
        && cqueue::buffer_select(flags) == Some(0)
        && cqueue::buf_more(flags) == buf_more
        && cqueue::more(flags) == more
}

fn arm<E: Engine>(e: &mut E, server: &UnixStream) -> std::io::Result<()> {
    arm_with(e, server, 0)
}

/// Arm the preflight receive with a total byte limit (0 for none).
fn arm_with<E: Engine>(e: &mut E, server: &UnixStream, limit: u32) -> std::io::Result<()> {
    let sqe = Sqe::new(
        Op::RecvMulti {
            fd: Fd::Raw(server.as_raw_fd()),
            buf_group: BGID,
            limit,
        },
        USER_DATA,
    );
    // Safety: a multishot recv references no caller memory.
    unsafe { e.push(&sqe) }
}

/// Completions reaped but not yet consumed: one reap can return several
/// of the preflight receive's completions.
#[derive(Default)]
struct Reaped(std::collections::VecDeque<(i32, u32)>);

/// The next completion of the preflight receive, in order, or `TimedOut`
/// after `WAIT`. Clears `armed` when the completion ends the arm.
fn wait<E: Engine>(
    e: &mut E,
    reaped: &mut Reaped,
    armed: &mut bool,
) -> std::io::Result<(i32, u32)> {
    let deadline = Instant::now() + WAIT;
    let mut out = Vec::new();
    loop {
        if let Some((res, flags)) = reaped.0.pop_front() {
            if !cqueue::more(flags) {
                *armed = false;
            }
            return Ok((res, flags));
        }
        e.submit_and_get_events()?;
        e.reap(&mut out);
        reaped.0.extend(
            out.drain(..)
                .filter(|c| c.0 == USER_DATA)
                .map(|(_, res, flags)| (res, flags)),
        );
        if reaped.0.is_empty() {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no preflight completion within 1 s",
                ));
            }
            std::thread::yield_now();
        }
    }
}

#[cfg(all(test, uring_engine))]
mod tests {
    use super::*;
    use crate::backend::uring::engine::ActiveEngine;
    use crate::backend::uring::ring::is_memlock_enomem;
    use crate::config::ConfigBuilder;

    fn engine() -> ActiveEngine {
        let config = ConfigBuilder::new().workers(1).build().expect("config");
        // Up to 5 s for earlier rings' memlock charge to be released (#589).
        for _ in 0..50 {
            match ActiveEngine::setup(&config) {
                Err(e) if is_memlock_enomem(&e) => std::thread::sleep(Duration::from_millis(100)),
                result => return result.expect("engine"),
            }
        }
        ActiveEngine::setup(&config).expect("engine")
    }

    /// A preflight that fails with its receive armed cancels it: nothing is
    /// left to reap, and the preflight group can be registered again.
    #[test]
    fn a_failed_step_leaves_nothing_behind() {
        for at in [step::APPEND, step::EXHAUSTION, step::REPOST, step::EOF] {
            let mut e = engine();
            if !e.incremental_buffers().expect("probe") {
                return;
            }
            FAIL_AT.with(|f| f.set(Some(at)));
            let found = inc_preflight(&mut e);
            FAIL_AT.with(|f| f.set(None));
            assert_eq!(found.expect("preflight"), Preflight::Failed(at));
            e.submit_and_get_events().expect("enter");
            let mut left = Vec::new();
            e.reap(&mut left);
            assert!(left.is_empty(), "step {at}: {left:?}");
            let again = ProvidedBufRing::new(BGID, 1, SIZE).expect("ring");
            e.register_buf_ring(&again, RingKind::Incremental)
                .unwrap_or_else(|err| panic!("step {at}: group still registered: {err}"));
            e.unregister_buf_ring(BGID).expect("unregister");
        }
    }

    /// The preflight passes on a kernel with incremental rings, reports
    /// `Unsupported` on one without, and leaves no completion behind.
    #[test]
    fn the_preflight_matches_the_kernel() {
        let mut e = engine();
        let inc = e.incremental_buffers().expect("probe");
        let start = Instant::now();
        let found = inc_preflight(&mut e).expect("preflight");
        eprintln!("preflight: {found:?} in {:?}", start.elapsed());
        let expected = if inc {
            Preflight::Passed
        } else {
            Preflight::Unsupported
        };
        assert_eq!(found, expected);
        e.submit_and_get_events().expect("enter");
        let mut left = Vec::new();
        e.reap(&mut left);
        assert!(left.is_empty(), "{left:?}");
    }

    /// Whether the running kernel is 6.17 or later, where multishot
    /// receives take a total byte limit.
    fn has_recv_limit() -> bool {
        use crate::memlock::KernelVersion;
        KernelVersion::current()
            >= Some(KernelVersion {
                major: 6,
                minor: 17,
            })
    }

    /// The limit preflight passes from Linux 6.17, reports `Unsupported`
    /// before it, and leaves no completion behind.
    #[test]
    fn the_limit_preflight_matches_the_kernel() {
        let mut e = engine();
        if !e.incremental_buffers().expect("probe") {
            return;
        }
        let found = limit_preflight(&mut e).expect("preflight");
        let expected = if has_recv_limit() {
            Preflight::Passed
        } else {
            Preflight::Unsupported
        };
        assert_eq!(found, expected);
        e.submit_and_get_events().expect("enter");
        let mut left = Vec::new();
        e.reap(&mut left);
        assert!(left.is_empty(), "{left:?}");
    }

    /// A limit preflight that fails with its receive armed cancels it, as
    /// `a_failed_step_leaves_nothing_behind` checks for the ring preflight.
    #[test]
    fn a_failed_limit_step_leaves_nothing_behind() {
        if !has_recv_limit() {
            return;
        }
        for at in [step::LIMIT_BELOW, step::LIMIT_END] {
            let mut e = engine();
            if !e.incremental_buffers().expect("probe") {
                return;
            }
            FAIL_AT.with(|f| f.set(Some(at)));
            let found = limit_preflight(&mut e);
            FAIL_AT.with(|f| f.set(None));
            assert_eq!(found.expect("preflight"), Preflight::Failed(at));
            e.submit_and_get_events().expect("enter");
            let mut left = Vec::new();
            e.reap(&mut left);
            assert!(left.is_empty(), "step {at}: {left:?}");
            let again = ProvidedBufRing::new(BGID, 1, SIZE).expect("ring");
            e.register_buf_ring(&again, RingKind::Incremental)
                .unwrap_or_else(|err| panic!("step {at}: group still registered: {err}"));
            e.unregister_buf_ring(BGID).expect("unregister");
        }
    }
}
