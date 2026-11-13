//! The kernel engine: an io_uring instance that executes each [`Sqe`]
//! the driver pushes and reports its completions.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use io_uring::squeue::{Entry, Entry128, Flags};
use io_uring::types::{self, CancelBuilder, DestinationSlot, Fixed};
use io_uring::{IoUring, cqueue, opcode, squeue};

use super::Engine;
use crate::backend::ProvidedBufRing;
use crate::backend::uring::ring::{CloseLead, close_lead_for};
use crate::backend::uring::sqe::{Fd, Link, Op, Sqe};
use crate::buffer::fixed::FixedBufferRegistry;
use crate::config::Config;
use crate::error::{Error, MemlockLimit, describe_buffer_registration_failure, errno_name};
use crate::memlock::KernelVersion;

/// Ubuntu's 6.8 kernels (from 6.8.0-139) invert the check on the reserved
/// words of `IORING_REGISTER_PBUF_RING`: a registration with them zeroed, as
/// upstream kernels require, fails with `EINVAL`, and one with `resv[0]` set
/// succeeds. The same is reported for `IORING_UNREGISTER_PBUF_RING` (#626).
pub(crate) const PBUF_RESV_INVERTED_ON: KernelVersion = KernelVersion { major: 6, minor: 8 };

/// Whether a provided-buffer-ring registration refused with `err` on
/// `kernel` is retried with `resv[0]` set: only an `EINVAL` on 6.8. On any
/// other kernel the `EINVAL` is returned unchanged.
pub(crate) fn retry_with_resv_set(err: &io::Error, kernel: Option<KernelVersion>) -> bool {
    err.raw_os_error() == Some(libc::EINVAL) && kernel == Some(PBUF_RESV_INVERTED_ON)
}

/// The longest timed wait [`UringEngine::submit_and_wait_timeout`] passes
/// to the kernel. A longer wait ends early and the caller waits again.
pub(crate) const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(3600);

/// `Error::RingSetup` for a failed `io_uring_setup(2)`.
///
/// An `EINVAL` on a ring whose SQPOLL thread was pinned to `sq_cpu` can come
/// from the CPU or from a setup flag, and only the kernel can say which: it
/// checks the CPU against its cpuset, which this thread's affinity (a pinned
/// worker's single core) does not show. So `retry_unpinned` sets the ring up
/// again with the same flags and no SQ CPU:
/// - it succeeds: the CPU was refused, and the message names it;
/// - it fails with `EINVAL`: a setup flag was refused, and the original error
///   gets the generic message;
/// - it fails otherwise: the original `EINVAL` gets the generic message and a
///   note that the SQ CPU may be the cause, and is not reported as a memlock
///   failure. On Linux 6.14+ the refused ring's memlock charge can still be
///   held when the retry runs, so `UringEngine::setup` makes a retry that `ENOMEM`
///   refused again at `probe_sizes`; this case is left for when that fails
///   too.
fn ring_setup_error<R>(
    err: io::Error,
    sq_cpu: Option<u32>,
    config: &Config,
    retry_unpinned: impl FnOnce() -> io::Result<R>,
) -> Error {
    let Some(cpu) = sq_cpu.filter(|_| err.raw_os_error() == Some(libc::EINVAL)) else {
        return Error::ring_setup(err);
    };
    let source = crate::error::sq_cpu_source(config.sqpoll_cpu.as_ref(), config.worker_index);
    match retry_unpinned() {
        Ok(probe) => {
            drop(probe);
            let reason = crate::error::sq_cpu_reason(cpu, &crate::error::SqCpuProbe::read());
            Error::RingSetup(crate::error::describe_sq_cpu_refused(
                &err,
                cpu,
                config.worker_index,
                &source,
                &reason,
            ))
        }
        Err(retry_err) if retry_err.raw_os_error() == Some(libc::EINVAL) => Error::ring_setup(err),
        Err(retry_err) => match Error::ring_setup(err) {
            Error::RingSetup(msg) => Error::RingSetup(format!(
                "{msg} {}",
                crate::error::describe_sq_cpu_unresolved(
                    cpu,
                    config.worker_index,
                    &source,
                    &retry_err
                )
            )),
            other => other,
        },
    }
}

/// SQ and CQ sizes for an unpinned retry that `ENOMEM` refused at the ring's
/// own sizes: both divided by the same power of two, until the CQ has at most
/// 16 entries, and at least 1 each. The kernel checks the sizes before it
/// charges the ring, so an `ENOMEM` at the ring's own sizes means they were
/// accepted; the retry at these only shows whether the ring can be set up
/// without the CPU.
fn probe_sizes(sq_entries: u32, cq_entries: u32) -> (u32, u32) {
    let mut shift = 0;
    while cq_entries >> shift > 16 {
        shift += 1;
    }
    ((sq_entries >> shift).max(1), (cq_entries >> shift).max(1))
}

/// Whether an `io_uring_enter` failure is temporary, so the caller carries on
/// and reaps. `EBUSY`: the CQ is backed up (overflow list non-empty), and
/// reaping frees it. `EAGAIN`: the kernel could not allocate a request for the
/// first SQE (`io_submit_sqes`), which stays queued for the next enter.
fn is_enter_backpressure(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EBUSY | libc::EAGAIN))
}

/// Whether an `io_uring_enter` failure reports dropped completions, counting
/// it when it does. `EBADR`: the kernel could not allocate an overflow entry
/// for a completion and dropped it, so the operation it belonged to never
/// completes. The kernel returns it from an enter that waits for completions,
/// submits nothing and finds the CQ empty, and clears it there. Nothing else
/// is wrong with the ring, so the worker carries on. The completion itself
/// cannot be recovered. Of the enters here only `submit_and_wait` with a
/// nonzero `min_complete` can see it; the others match it as well.
fn reports_dropped_completions(error: &io::Error) -> bool {
    let dropped = error.raw_os_error() == Some(libc::EBADR);
    if dropped {
        crate::metrics::RING.increment(crate::metrics::ring::CQE_DROPPED_REPORTED);
    }
    dropped
}

/// `struct io_uring_buf_reg`, which the `io-uring` crate fills with `resv`
/// zeroed and does not let the caller set.
#[repr(C)]
struct BufReg {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    resv: [u64; 3],
}

const _: () = assert!(std::mem::size_of::<BufReg>() == 40);

pub(crate) const IORING_REGISTER_PBUF_RING: libc::c_uint = 22;
pub(crate) const IORING_UNREGISTER_PBUF_RING: libc::c_uint = 23;

/// `io_uring_register(2)` for a provided buffer ring, with the given `flags`
/// and `resv[0]` set to `resv0`. Ringline passes 1 (see [`retry_with_resv_set`]); tests pass 0 to
/// check the call against a kernel that requires zeroed reserved words.
///
/// # Safety
///
/// `opcode` must be `IORING_REGISTER_PBUF_RING` or
/// `IORING_UNREGISTER_PBUF_RING`. For registration, `ring_addr` must point to
/// a buffer ring of `ring_entries` entries that stays mapped until the group
/// is unregistered or the io_uring instance is dropped.
pub(crate) unsafe fn pbuf_ring_register(
    fd: RawFd,
    opcode: libc::c_uint,
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    resv0: u64,
) -> io::Result<()> {
    let reg = BufReg {
        ring_addr,
        ring_entries,
        bgid,
        flags,
        resv: [resv0, 0, 0],
    };
    // Safety: `reg` is a valid `io_uring_buf_reg` for the duration of the
    // call; the caller upholds the contract on `ring_addr`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            fd,
            opcode,
            &reg as *const BufReg,
            1,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The error for a refused provided-buffer-ring registration.
pub(crate) fn provided_ring_failure(
    err: &io::Error,
    bgid: u16,
    entries: impl std::fmt::Display,
    probe: &crate::error::RingSetupProbe,
) -> Error {
    let name = errno_name(err)
        .map(|n| format!(" ({n})"))
        .unwrap_or_default();
    Error::BufferRegistration(format!(
        "provided buffer ring (bgid {bgid}, {entries} entries): {err}{name}. \
         EINVAL here usually means a kernel older than 5.19 or a \
         ring size that is not a power of two. {}",
        crate::error::provided_ring_enomem_hint(probe)
    ))
}

/// An io_uring instance with 128-byte SQEs and 32-byte CQEs
/// (`IoUring<Entry128, Entry32>`), which NVMe passthrough
/// (`IORING_OP_URING_CMD`) needs. [`Sqe::encode`] produces the 128-byte
/// entries; 64-byte opcodes are zero-padded.
///
/// Memory overhead of Big SQE/CQE: +32 KB per worker with default config
/// (256 SQ × 64B extra + 1024 CQ × 16B extra), negligible relative to the
/// ~20 MB of buffer pools allocated per worker.
pub(crate) struct UringEngine {
    ring: IoUring<squeue::Entry128, cqueue::Entry32>,
    /// Reusable Entry128 conversion scratch for chain pushes — avoids a
    /// heap allocation per chained send.
    chain_scratch: Vec<squeue::Entry128>,
    /// Whether the ring was set up with `IORING_SETUP_DEFER_TASKRUN`. When
    /// set, the kernel runs task_work — and so posts the CQEs it generates —
    /// only on an `io_uring_enter` carrying `IORING_ENTER_GETEVENTS`.
    defer_taskrun: bool,
    /// Whether the ring was set up with `IORING_SETUP_TASKRUN_FLAG`, so
    /// `IORING_SQ_TASKRUN` says whether task work is pending.
    taskrun_flag: bool,
    /// Whether the kernel supports `IORING_OP_FIXED_FD_INSTALL` (6.8+).
    ///
    /// Park (tier 3, #443) has to hand a real fd to another worker, but an
    /// established connection's fd lives only in this ring's fixed-file
    /// table — `install_accepted` closes the raw fd once it is registered.
    /// This opcode is the only way to get one back, so it decides whether
    /// park is available at all. See [`Engine::supports_park`].
    fixed_fd_install: bool,
    /// What goes ahead of a connection's `Close` on this kernel. See
    /// [`close_lead_for`].
    close_lead: CloseLead,
    /// The kernel's count of dropped completions when `reap` last read it.
    dropped_seen: u32,
    /// The kernel accepted a provided buffer ring only with `resv[0]` set,
    /// so later registrations use that form and unregistration tries it
    /// first. See [`retry_with_resv_set`].
    pbuf_resv_set: bool,
    /// Test-only: number of upcoming `push_sqe128`/`push_sqe_pair` calls that
    /// fail as if the SQ were still full after a submit. See
    /// [`Engine::force_push_failures`].
    #[cfg(test)]
    forced_push_failures: usize,
    /// Test-only: completions `inject` queued on a kernel without
    /// `IORING_NOP_INJECT_RESULT`, for `reap` to hand out.
    #[cfg(test)]
    injected: Vec<(u64, i32, u32)>,
    /// Test-only: the entry `inject` queued last failed and was linked.
    #[cfg(test)]
    injected_link_broken: bool,
}

impl UringEngine {
    /// After a failed enter: a submit that took no SQE returns before it runs
    /// `DEFER_TASKRUN` work, so `EAGAIN` needs a second enter for there to be
    /// completions to reap. The worker would otherwise spin without them.
    fn reap_after_backpressure(&self, error: &io::Error) {
        if error.raw_os_error() == Some(libc::EAGAIN) {
            // Safety: enters with no SQEs, no wait and no argument.
            let _ = unsafe { self.ring.submitter().enter::<()>(0, 0, 1, None) };
        }
    }

    /// # Safety
    ///
    /// As [`pbuf_ring_register`].
    unsafe fn register_pbuf_resv_set(&self, addr: u64, entries: u32, bgid: u16) -> io::Result<()> {
        unsafe {
            pbuf_ring_register(
                self.ring.as_raw_fd(),
                IORING_REGISTER_PBUF_RING,
                addr,
                entries,
                bgid,
                0,
                1,
            )
        }
    }

    /// Test-only: the ring's file descriptor, for raw registration calls.
    #[cfg(test)]
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.ring.as_raw_fd()
    }

    /// Test-only: whether registrations use the `resv[0]` form.
    #[cfg(test)]
    pub(crate) fn pbuf_resv_set(&self) -> bool {
        self.pbuf_resv_set
    }

    fn close_lead_from(config: &Config) -> CloseLead {
        #[cfg(test)]
        if let Some(lead) = config.close_lead_override {
            return lead;
        }
        let _ = config;
        close_lead_for(KernelVersion::current())
    }

    /// Re-probe an arbitrary opcode. Exists so tests can establish that the
    /// probe mechanism answers at all — a probe that silently reported
    /// everything unsupported would disable park permanently and look
    /// exactly like an old kernel.
    #[cfg(test)]
    pub(crate) fn probe_supported(&self, code: u8) -> bool {
        let mut probe = io_uring::Probe::new();
        match self.ring.submitter().register_probe(&mut probe) {
            Ok(()) => probe.is_supported(code),
            Err(_) => false,
        }
    }

    /// The calling thread's io-wq limits, `[bounded, unbounded]`. Passing 0
    /// for both changes nothing and returns the current values.
    #[cfg(test)]
    pub(crate) fn iowq_max_workers(&self) -> io::Result<[u32; 2]> {
        let mut limits = [0, 0];
        self.ring
            .submitter()
            .register_iowq_max_workers(&mut limits)?;
        Ok(limits)
    }

    /// Push a raw 64-byte entry: the test-only NOP injections, which set
    /// fields `Sqe` does not describe.
    #[cfg(test)]
    unsafe fn push_entry(&mut self, entry: &squeue::Entry) -> io::Result<()> {
        unsafe {
            self.push_sqe128(entry.clone().into())?;
        }
        Ok(())
    }

    /// Push a 128-byte entry to the submission queue.
    ///
    /// # Safety
    /// The entry must reference valid memory for the lifetime of the operation.
    unsafe fn push_sqe128(&mut self, entry: squeue::Entry128) -> io::Result<()> {
        #[cfg(test)]
        if self.forced_push_failures > 0 {
            self.forced_push_failures -= 1;
            crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
            return Err(io::Error::other("forced SQ push failure"));
        }

        // Try to push; if SQ is full, submit first to make room.
        unsafe {
            if self.ring.submission().push(&entry).is_err() {
                if let Err(e) = self.make_sq_room(1) {
                    crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
                    return Err(e);
                }
                if self.ring.submission().push(&entry).is_err() {
                    crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
                    return Err(io::Error::other("SQ still full after submit"));
                }
            }
        }
        Ok(())
    }

    /// Submit the queued SQEs to free room for `needed` more. Under SQPOLL,
    /// only the SQ thread frees entries and `submit` does not enter the
    /// kernel while that thread is awake, so this also waits
    /// (`IORING_ENTER_SQ_WAIT`, which returns once at least one entry is
    /// free) until `needed` are free or the SQ has drained. When fewer than
    /// `needed` but at least one entry is free, `IORING_ENTER_SQ_WAIT`
    /// returns at once, so this repeats the enter until the SQ thread frees
    /// the rest.
    fn make_sq_room(&mut self, needed: usize) -> io::Result<()> {
        match self.ring.submit() {
            Ok(_) => {}
            Err(e) if reports_dropped_completions(&e) => {}
            Err(e) => return Err(e),
        }
        if self.ring.params().is_setup_sqpoll() {
            loop {
                let sq = self.ring.submission();
                if sq.capacity() - sq.len() >= needed || sq.is_empty() {
                    break;
                }
                drop(sq);
                match self.ring.submitter().squeue_wait() {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Push two SQEs adjacently, so a linked pair is never split across
    /// submissions. Submits first if the SQ has room for fewer than two.
    ///
    /// # Safety
    /// Both SQEs must reference valid memory for the lifetime of the operation.
    unsafe fn push_sqe_pair(
        &mut self,
        first: squeue::Entry128,
        second: squeue::Entry128,
    ) -> io::Result<()> {
        #[cfg(test)]
        if self.forced_push_failures > 0 {
            self.forced_push_failures -= 1;
            crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
            return Err(io::Error::other("forced SQ push failure"));
        }

        let pair = [first, second];
        unsafe {
            if self.ring.submission().push_multiple(&pair).is_err() {
                if let Err(e) = self.make_sq_room(2) {
                    crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
                    return Err(e);
                }
                if self.ring.submission().push_multiple(&pair).is_err() {
                    crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
                    return Err(io::Error::other("SQ still full after submit"));
                }
            }
        }
        Ok(())
    }
}

impl Engine for UringEngine {
    /// Create and configure the io_uring instance.
    ///
    /// Returns [`Error::RingSetup`] rather than `Error::Io` so a refused
    /// `io_uring_setup(2)` names the subsystem and, for `EPERM`, the
    /// `kernel.io_uring_disabled` sysctl or seccomp profile behind it.
    fn setup(config: &Config) -> Result<Self, Error> {
        let build = |sq_cpu: Option<u32>, sq_entries: u32, cq_entries: u32| {
            let mut builder = IoUring::<squeue::Entry128, cqueue::Entry32>::builder();
            builder.setup_cqsize(cq_entries);
            builder.setup_single_issuer();

            if config.sqpoll {
                builder.setup_sqpoll(config.sqpoll_idle_ms);
                if let Some(cpu) = sq_cpu {
                    builder.setup_sqpoll_cpu(cpu);
                }
                // The kernel refuses COOP_TASKRUN, TASKRUN_FLAG and
                // DEFER_TASKRUN with SQPOLL (EINVAL). The SQ thread issues the
                // requests, so their task_work runs on it, not on this worker.
            } else {
                builder.setup_coop_taskrun();
                builder.setup_defer_taskrun();
                if config.defer_recv_arm {
                    builder.setup_taskrun_flag();
                }
            }
            builder.build(sq_entries)
        };

        // The unpinned retry first uses the ring's own sizes. On Linux 6.14+
        // the refused ring's memlock charge can still be held when it runs,
        // so under a limit with less than a ring of headroom it fails with
        // ENOMEM; it is then made again at `probe_sizes`, which needs two
        // pages of memlock.
        let unpinned = || match build(None, config.sq_entries, config.cq_entries) {
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => {
                let (sq, cq) = probe_sizes(config.sq_entries, config.cq_entries);
                build(None, sq, cq)
            }
            other => other,
        };
        let ring = build(config.sq_thread_cpu, config.sq_entries, config.cq_entries)
            .map_err(|e| ring_setup_error(e, config.sq_thread_cpu, config, unpinned))?;

        // Applies to the io-wq of the thread that issues requests: the
        // calling thread, which is why the ring is set up on its worker's
        // thread, or the SQ thread under SQPOLL. A zero slot leaves that limit
        // unchanged and reads back its current value, so the first call only
        // reads. The cap is an upper bound: registering it where the
        // kernel's own limit is lower would raise the limit instead.
        if config.iowq_max_workers > 0 {
            let refused = |e: io::Error| {
                Error::RingSetup(format!(
                    "io_uring refused an io-wq worker cap of {}: {e}",
                    config.iowq_max_workers
                ))
            };
            let mut current = [0, 0];
            ring.submitter()
                .register_iowq_max_workers(&mut current)
                .map_err(refused)?;
            if config.iowq_max_workers < current[0] {
                let mut limits = [config.iowq_max_workers, 0];
                ring.submitter()
                    .register_iowq_max_workers(&mut limits)
                    .map_err(refused)?;
            }
        }

        // Probed once here rather than per park: the answer cannot change for
        // the life of the ring, and a failed probe is not a setup failure —
        // it only means park is unavailable.
        let fixed_fd_install = {
            let mut probe = io_uring::Probe::new();
            match ring.submitter().register_probe(&mut probe) {
                Ok(()) => probe.is_supported(opcode::FixedFdInstall::CODE),
                // `IORING_REGISTER_PROBE` is 5.6 and the crate floor is 6.1,
                // so this should not happen — but a refused probe means
                // "assume not supported", never "fail to start".
                Err(_) => false,
            }
        };

        Ok(UringEngine {
            ring,
            chain_scratch: Vec::new(),
            defer_taskrun: !config.sqpoll,
            taskrun_flag: !config.sqpoll && config.defer_recv_arm,
            fixed_fd_install,
            close_lead: Self::close_lead_from(config),
            dropped_seen: 0,
            pbuf_resv_set: false,
            #[cfg(test)]
            forced_push_failures: 0,
            #[cfg(test)]
            injected: Vec::new(),
            #[cfg(test)]
            injected_link_broken: false,
        })
    }

    /// Whether this kernel can return a registered fd to the process table,
    /// and so whether park (tier 3, #443) is available.
    ///
    /// Requires Linux 6.8 for `IORING_OP_FIXED_FD_INSTALL`. The crate floor
    /// stays at 6.1: below 6.8 park is simply unavailable, and nothing else
    /// changes. That is a smaller loss than it sounds, because park exists
    /// only to repair the placement imbalance
    /// [`AcceptMode::Merged`](crate::AcceptMode::Merged) introduces — the
    /// default [`Pool`](crate::AcceptMode::Pool) mode places by round-robin
    /// and has nothing to rebalance. A pre-6.8 deployment that wants even
    /// placement stays on the default and loses nothing.
    fn supports_park(&self) -> bool {
        self.fixed_fd_install
    }

    /// What goes ahead of a connection's `Close` on the running kernel. See
    /// [`close_lead_for`].
    fn close_lead(&self) -> CloseLead {
        self.close_lead
    }

    /// Register a sparse fixed-buffer table sized to the registry, then
    /// fill in any occupied slots via `register_buffers_update`.
    ///
    /// The sparse path lets us add and remove regions dynamically after
    /// launch without re-registering the entire table.
    ///
    /// Failures come back as [`Error::BufferRegistration`]; for a buffer
    /// that failed to pin, its text names the causes of an `ENOMEM` or
    /// `EFAULT`.
    fn register_buffers(&self, registry: &FixedBufferRegistry) -> Result<(), Error> {
        let iovecs = registry.iovecs();
        if iovecs.is_empty() {
            return Ok(());
        }
        // The memlock charge is cumulative, so an `ENOMEM` is described
        // against the total; an `EFAULT` is about the one buffer.
        let total: u64 = iovecs.iter().map(|iov| iov.iov_len as u64).sum();
        let attribute = |e: io::Error, len: usize| {
            let bytes = if e.raw_os_error() == Some(libc::EFAULT) {
                len as u64
            } else {
                total
            };
            Error::buffer_registration(e, bytes, MemlockLimit::read().ok().as_ref())
        };
        let submitter = self.ring.submitter();
        // The sparse table pins no pages and is not charged to
        // RLIMIT_MEMLOCK, so the pin hints do not apply to its errors.
        submitter
            .register_buffers_sparse(iovecs.len() as u32)
            .map_err(|e| {
                let mut msg = format!(
                    "io_uring_register(2) of a sparse table of {} slots: {e}",
                    iovecs.len()
                );
                if let Some(name) = errno_name(&e) {
                    msg.push_str(&format!(" ({name})"));
                }
                Error::BufferRegistration(msg)
            })?;

        // Apply each occupied slot. Empty slots stay zeroed in the kernel.
        for (slot, iov) in iovecs.iter().enumerate() {
            if iov.iov_base.is_null() {
                continue;
            }
            // Safety: the iovec points at user memory documented to outlive
            // the runtime; tags are unused.
            unsafe {
                submitter
                    .register_buffers_update(slot as u32, std::slice::from_ref(iov), None)
                    .map_err(|e| attribute(e, iov.iov_len))?;
            }
        }
        Ok(())
    }

    /// Update a single fixed-buffer slot with a new iovec.
    ///
    /// `iov.iov_base.is_null()` clears the slot.
    ///
    /// # Safety
    ///
    /// The memory described by `iov` must remain valid until either the slot
    /// is cleared or the runtime shuts down. No SQE referencing the slot may
    /// be in flight when this is called.
    unsafe fn register_buffers_update_one(&self, slot: u16, iov: libc::iovec) -> io::Result<()> {
        unsafe {
            self.ring
                .submitter()
                .register_buffers_update(slot as u32, std::slice::from_ref(&iov), None)
                .map_err(|e| {
                    // Surfaces to the caller of `Runtime::register_region`
                    // as an `io::Error`; keep the kind and add the causes
                    // of an `ENOMEM` or `EFAULT` to the OS message.
                    let text = describe_buffer_registration_failure(
                        &e,
                        iov.iov_len as u64,
                        MemlockLimit::read().ok().as_ref(),
                    );
                    io::Error::new(e.kind(), text)
                })?;
        }
        Ok(())
    }

    /// Register a sparse file table for direct descriptors.
    ///
    /// The kernel sizes this table against `RLIMIT_NOFILE`, so `EMFILE`
    /// means the limit, not fd exhaustion, and is reported as such.
    fn register_files_sparse(&self, count: u32) -> Result<(), Error> {
        self.ring
            .submitter()
            .register_files_sparse(count)
            .map_err(|e| match e.raw_os_error() {
                Some(libc::EMFILE | libc::ENFILE) => Error::ResourceLimit(format!(
                    "RLIMIT_NOFILE too low for the fixed file table: io_uring refused \
                     {count} entries ({e}). Raise it with `ulimit -n` to at least \
                     {count} plus overhead, or lower ConfigBuilder::max_connections"
                )),
                _ => Error::Io(e),
            })?;
        Ok(())
    }

    /// Update registered file table at given offset.
    fn register_files_update(&self, offset: u32, fds: &[RawFd]) -> io::Result<()> {
        self.ring.submitter().register_files_update(offset, fds)?;
        Ok(())
    }

    /// Register the provided buffer ring with the kernel.
    ///
    /// On a 6.8 kernel that refuses the zeroed reserved words with `EINVAL`,
    /// retries once with `resv[0]` set; after that succeeds, later
    /// registrations use only that form (#626).
    fn register_buf_ring(&mut self, provided: &ProvidedBufRing) -> Result<(), Error> {
        let (addr, entries, bgid) = (
            provided.ring_addr(),
            provided.ring_entries(),
            provided.bgid(),
        );
        // Safety (every registration in this function): `addr` is
        // `provided`'s mmap'd ring, mapped at the call. The `io-uring`
        // crate's contract, which `pbuf_ring_register` repeats, asks for it
        // to stay mapped until the group is unregistered or the io_uring
        // instance is dropped. `Driver::run_shutdown` meets that. The path
        // after a failed unregister unmaps the ring while its group is still
        // registered. That frees no memory the kernel reads. Registration pins the ring's pages
        // (`io_pin_pages`, called from `io_uring/kbuf.c` or
        // `io_uring/memmap.c`), and the kernel reads entries through its own
        // mapping of those pages. The kernel unpins them only when the group
        // is unregistered or the io_uring instance is freed. The buffers the
        // entries point at (`ProvidedBufRing::mem`) are a separate, unpinned
        // allocation that the kernel writes through the user addresses in the
        // entries; this argument does not cover them.
        let first = if self.pbuf_resv_set {
            unsafe { self.register_pbuf_resv_set(addr, entries, bgid) }
        } else {
            unsafe {
                self.ring
                    .submitter()
                    .register_buf_ring_with_flags(addr, entries as u16, bgid, 0)
            }
        };
        let result = match first {
            Err(e) if !self.pbuf_resv_set && retry_with_resv_set(&e, KernelVersion::current()) => {
                match unsafe { self.register_pbuf_resv_set(addr, entries, bgid) } {
                    Ok(()) => {
                        self.pbuf_resv_set = true;
                        Ok(())
                    }
                    // Report the refusal of the standard form.
                    Err(_) => Err(e),
                }
            }
            other => other,
        };
        result.map_err(|e| {
            provided_ring_failure(&e, bgid, entries, &crate::error::RingSetupProbe::read())
        })
    }

    /// Unregister the provided buffer ring from the kernel.
    /// Call it before the ring memory is unmapped, as the `io-uring` crate's
    /// contract requires; the Safety comment in `register_buf_ring`
    /// says why the exits that skip it free no memory the kernel reads.
    ///
    /// After a registration needed `resv[0]` set, unregistration tries that
    /// form first and falls back to the standard one on `EINVAL`, since only
    /// the registration check is confirmed inverted (#626).
    fn unregister_buf_ring(&self, bgid: u16) -> io::Result<()> {
        if self.pbuf_resv_set {
            // Safety: unregistration reads no memory through `ring_addr`.
            let resv = unsafe {
                pbuf_ring_register(
                    self.ring.as_raw_fd(),
                    IORING_UNREGISTER_PBUF_RING,
                    0,
                    0,
                    bgid,
                    0,
                    1,
                )
            };
            match resv {
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {}
                other => return other,
            }
        }
        self.ring.submitter().unregister_buf_ring(bgid)?;
        Ok(())
    }

    /// Submit all pending SQEs and wait for at least `min_complete` CQEs.
    ///
    /// A bare `?` here would kill the worker thread (and every connection on
    /// it) on the first transient `io_uring_enter` failure:
    /// - `EINTR`: any signal delivered to the worker interrupts the wait
    ///   regardless of `SA_RESTART` — restart it.
    /// - `EBUSY`, `EAGAIN`: see [`is_enter_backpressure`].
    fn submit_and_wait(&self, min_complete: u32) -> io::Result<()> {
        // What `inject` queued needs no wait.
        #[cfg(test)]
        let min_complete = if self.injected.is_empty() {
            min_complete
        } else {
            0
        };
        loop {
            match self.ring.submitter().submit_and_wait(min_complete as usize) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if is_enter_backpressure(&e) => {
                    self.reap_after_backpressure(&e);
                    return Ok(());
                }
                Err(e) if reports_dropped_completions(&e) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Submit all pending SQEs and wait for at least `min_complete` CQEs or
    /// until `timeout` has passed, in one `io_uring_enter` with
    /// `IORING_ENTER_EXT_ARG` (Linux 5.11). The kernel applies no timer slack
    /// to the wait (`schedule_hrtimeout` with a delta of 0 through 6.10,
    /// `hrtimer_set_expires_range_ns(.., 0)` from 6.12).
    ///
    /// `timeout` is capped at [`MAX_WAIT`]. The kernel adds the timeout to
    /// the current time without saturating (`io_cqring_wait`:
    /// `ktime_add_ns(timespec64_to_ktime(ts), ktime_get_ns())` in 6.1,
    /// `ktime_add(iowq.timeout, start_time)` in 6.12), so a timeout of more
    /// than `KTIME_MAX` (about 9.2e9 s) less the uptime gives a negative
    /// expiry; one of `KTIME_SEC_MAX` seconds or more is first saturated to
    /// `KTIME_MAX` by `timespec64_to_ktime`, and wraps as well. `hrtimer_set_expires_range_ns` saturates the hard expiry to
    /// `KTIME_SEC_MAX` seconds (`ktime_add_safe`) but keeps the negative soft
    /// expiry, so the wait does not end at once, but can end at any hrtimer
    /// interrupt on the CPU that finds it first in its clock base.
    ///
    /// Errors as [`submit_and_wait`](Self::submit_and_wait), except:
    /// - `ETIME`: the timeout passed with fewer than `min_complete` CQEs
    ///   ready. That is the expected end of a timed wait, so it returns `Ok`.
    /// - `EINTR` returns `Ok` instead of restarting the wait: a restart
    ///   would wait the whole `timeout` again. The caller computes a new
    ///   timeout before it next waits.
    fn submit_and_wait_timeout(
        &self,
        min_complete: u32,
        timeout: std::time::Duration,
    ) -> io::Result<()> {
        // What `inject` queued needs no wait.
        #[cfg(test)]
        if !self.injected.is_empty() {
            return self.submit_and_wait(0);
        }
        let ts = types::Timespec::from(timeout.min(MAX_WAIT));
        let args = types::SubmitArgs::new().timespec(&ts);
        match self
            .ring
            .submitter()
            .submit_with_args(min_complete as usize, &args)
        {
            Ok(_) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ETIME) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
            Err(e) if is_enter_backpressure(&e) => {
                self.reap_after_backpressure(&e);
                Ok(())
            }
            Err(e) if reports_dropped_completions(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Submit pending SQEs and reap deferred completions **without blocking**.
    ///
    /// Use this instead of `submit_and_wait(0)` whenever the event loop
    /// declines to block because a task is runnable.
    ///
    /// `submit_and_wait(0)` does not set `IORING_ENTER_GETEVENTS` (the
    /// io-uring crate sets it only for `want > 0`), and under
    /// `IORING_SETUP_DEFER_TASKRUN` the kernel runs task_work only when that
    /// flag is present. A worker with a permanently runnable task therefore
    /// never blocks, never sets GETEVENTS, and — if the runnable task also
    /// queues no SQEs, so `flush()` takes its empty-SQ shortcut — never reaps
    /// a single completion: no accepts, no recvs, no send completions, and so
    /// no send-pool slots recycled, for as long as that task stays runnable.
    ///
    /// One `io_uring_enter`.
    /// Without DEFER_TASKRUN (SQPOLL rings, which cannot enable it) the kernel
    /// posts completions eagerly, so this delegates.
    fn submit_and_get_events(&self) -> io::Result<()> {
        if !self.defer_taskrun {
            return self.submit_and_wait(0);
        }
        loop {
            // Safety: as in `flush()` — a shared view of the SQ head/tail
            // atomics, read-only.
            let n = unsafe { self.ring.submission_shared().len() } as u32;
            match unsafe {
                self.ring
                    .submitter()
                    .enter::<()>(n, 0, 1 /* IORING_ENTER_GETEVENTS */, None)
            } {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if is_enter_backpressure(&e) => {
                    self.reap_after_backpressure(&e);
                    return Ok(());
                }
                Err(e) if reports_dropped_completions(&e) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Submit pending SQEs without waiting. Used for mid-iteration flush.
    ///
    /// Submits pending SQEs with `IORING_ENTER_GETEVENTS` and
    /// `min_complete=0` in one `io_uring_enter`. With
    /// `IORING_SETUP_DEFER_TASKRUN` the kernel only runs task_work (and posts
    /// deferred CQEs to the completion ring) when `IORING_ENTER_GETEVENTS` is
    /// set.  A plain `submit()` call does NOT set that flag, so send-completion
    /// CQEs for the SQEs we just submitted sit in kernel-internal task_work
    /// until the next `submit_and_wait(1)`, causing a "dead" event-loop
    /// iteration that wakes up only to process those CQEs.
    ///
    /// Setting the flag on the submitting enter
    /// we flush task_work inline — the send CQEs land in the CQ ring before
    /// `flush()` returns, so the `drain_completions()` call that follows in
    /// the event loop can consume them immediately.
    fn flush(&self) -> io::Result<()> {
        // `enter(sq_len, 0, GETEVENTS, None)`: this submits any pending SQEs AND triggers DEFER_TASKRUN task_work
        // delivery in a single syscall, saving one round-trip to the kernel
        // per flush() invocation (≈ once or twice per event-loop iteration).
        //
        // Safety: `submission_shared()` gives a shared view of the SQ head/tail
        // atomics.  We only read `.len()` (sq_tail − sq_head) and never push
        // new entries here, so there is no aliasing or mutation hazard.
        let n = unsafe { self.ring.submission_shared().len() } as u32;
        if n > 0 && self.ring.params().is_setup_sqpoll() {
            // The SQ thread submits. `submit` enters the kernel only to wake
            // that thread when it has gone idle, or to flush an overflowed
            // CQ; a raw enter here would cost a syscall on every flush and
            // would not wake it.
            match self.ring.submit() {
                Ok(_) => {}
                Err(e) if reports_dropped_completions(&e) => {}
                Err(e) => return Err(e),
            }
            return Ok(());
        }
        if n == 0 {
            // Nothing to submit. Pending DEFER_TASKRUN task_work and CQEs are
            // reaped by the event loop's next ring entry, which always carries
            // GETEVENTS — `submit_and_wait(1)` when it blocks, and
            // `submit_and_get_events()` when it declines to because a task is
            // runnable. Skipping the syscall here therefore defers completion
            // reaping by at most one loop iteration. (That second case is why
            // `submit_and_get_events` exists: a plain `submit_and_wait(0)` sets
            // no GETEVENTS, and combined with this shortcut it would strand
            // task_work indefinitely.)
            return Ok(());
        }
        match unsafe {
            self.ring
                .submitter()
                .enter::<()>(n, 0, 1 /* IORING_ENTER_GETEVENTS */, None)
        } {
            Ok(_) => Ok(()),
            Err(e) if reports_dropped_completions(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn completion_pending(&self) -> bool {
        if !self.taskrun_flag {
            return true;
        }
        // Safety: shared views of the ring's flags and head/tail atomics,
        // read-only.
        unsafe {
            self.ring.submission_shared().taskrun() || !self.ring.completion_shared().is_empty()
        }
    }

    /// Append every completion the ring holds to `out` as
    /// `(user_data, result, flags)`, consuming them.
    fn reap(&mut self, out: &mut Vec<(u64, i32, u32)>) {
        #[cfg(test)]
        out.append(&mut self.injected);
        let cq = self.ring.completion();
        // The kernel counts each completion it drops, cumulatively.
        let dropped = cq.overflow();
        out.extend(cq.map(|cqe| (cqe.user_data(), cqe.result(), cqe.flags())));
        if dropped != self.dropped_seen {
            crate::metrics::RING.add(
                crate::metrics::ring::CQE_DROPPED,
                u64::from(dropped.wrapping_sub(self.dropped_seen)),
            );
            self.dropped_seen = dropped;
        }
        // Completions that did not fit in the CQ wait in the kernel's overflow
        // list, which the next enter moves into the CQ.
        // Safety: a shared view of the ring's flags, read-only.
        if unsafe { self.ring.submission_shared().cq_overflow() } {
            crate::metrics::RING.increment(crate::metrics::ring::CQ_OVERFLOW);
        }
    }

    /// Test-only: make the next `count` `push_sqe`/`push_sqe128` calls fail.
    ///
    /// Each forced failure returns an error of the same kind (`Other`) as
    /// the real "SQ still full after submit" path, increments the same
    /// `SQE_SUBMIT_FAILURES` metric, and consumes one unit of `count`
    /// before the real submission queue is touched. `push`, `push_pair`
    /// and `inject` are covered; `push_chain` is not affected.
    #[cfg(test)]
    fn force_push_failures(&mut self, count: usize) {
        self.forced_push_failures = count;
    }

    unsafe fn push(&mut self, sqe: &Sqe) -> io::Result<()> {
        unsafe { self.push_sqe128(sqe.encode()) }
    }

    unsafe fn push_pair(&mut self, first: &Sqe, second: &Sqe) -> io::Result<()> {
        unsafe { self.push_sqe_pair(first.encode(), second.encode()) }
    }

    unsafe fn push_chain(&mut self, sqes: &[Sqe]) -> io::Result<()> {
        // Convert to Entry128 for the Big SQ ring, reusing the scratch to
        // avoid a per-chain heap allocation.
        let mut entries128 = std::mem::take(&mut self.chain_scratch);
        entries128.clear();
        entries128.extend(sqes.iter().map(Sqe::encode));

        // Ensure enough room in the SQ for the entire chain.
        {
            let sq = self.ring.submission();
            if sq.capacity() - sq.len() < entries128.len() {
                drop(sq);
                if let Err(e) = self.make_sq_room(entries128.len()) {
                    crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
                    entries128.clear();
                    self.chain_scratch = entries128;
                    return Err(e);
                }
                let sq = self.ring.submission();
                if sq.capacity() - sq.len() < entries128.len() {
                    drop(sq);
                    crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
                    entries128.clear();
                    self.chain_scratch = entries128;
                    return Err(io::Error::other("SQ too small for chain"));
                }
            }
        }

        // Atomic push of the entire chain.
        let pushed = unsafe {
            self.ring
                .submission()
                .push_multiple(&entries128)
                .map_err(|_| io::Error::other("SQ full after flush for chain"))
        };
        // Return the scratch for reuse regardless of outcome.
        entries128.clear();
        self.chain_scratch = entries128;
        if pushed.is_err() {
            crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
        }
        pushed?;
        Ok(())
    }

    /// Post a completion with `user_data` and `result` through the real
    /// ring, by submitting a NOP with `IORING_NOP_INJECT_RESULT` (Linux
    /// 6.10). With `linked`, the next entry pushed is linked to it.
    #[cfg(test)]
    fn inject(&mut self, user_data: u64, result: i32, linked: bool) -> io::Result<()> {
        // `IORING_NOP_INJECT_RESULT` is Linux 6.10. On an older kernel the
        // completion skips the ring and reaches `reap` directly.
        if KernelVersion::current() < Some(KernelVersion::parse("6.10").expect("a version")) {
            // As the kernel does for a link: a failed entry cancels the next.
            let result = if self.injected_link_broken {
                -libc::ECANCELED
            } else {
                result
            };
            self.injected_link_broken = linked && result < 0;
            self.injected.push((user_data, result, 0));
            return Ok(());
        }
        let mut entry = opcode::Nop::new().build().user_data(user_data);
        if linked {
            entry = entry.flags(squeue::Flags::IO_LINK);
        }
        // The high-level Entry doesn't expose nop_flags or len fields.
        // Use raw pointer arithmetic to patch the SQE in-place.
        // SQE layout (64 bytes): opcode(1) flags(1) ioprio(2) fd(4) off(8) addr(8)
        //                         len(4@24) rw_flags/nop_flags(4@28) user_data(8) ...
        let ptr = &mut entry as *mut squeue::Entry as *mut u8;
        unsafe {
            // len is at byte offset 24 in the SQE
            std::ptr::write_unaligned(ptr.add(24) as *mut u32, result as u32);
            // nop_flags (union with rw_flags) is at byte offset 28
            std::ptr::write_unaligned(ptr.add(28) as *mut u32, 1); // IORING_NOP_INJECT_RESULT
        }
        unsafe { self.push_entry(&entry) }
    }
}

impl Sqe {
    /// The 128-byte entry the ring's submission queue holds.
    pub(crate) fn encode(&self) -> Entry128 {
        let e: Entry128 = match self.op {
            Op::UringCmd80 { fd, cmd_op, cmd } => {
                let e = match fd {
                    Fd::Fixed(i) => opcode::UringCmd80::new(Fixed(i), cmd_op).cmd(cmd).build(),
                    Fd::Raw(f) => opcode::UringCmd80::new(types::Fd(f), cmd_op)
                        .cmd(cmd)
                        .build(),
                };
                e.user_data(self.user_data)
            }
            _ => self.encode64().into(),
        };
        match self.link {
            Link::None => e,
            Link::Soft => e.flags(Flags::IO_LINK),
            Link::Hard => e.flags(Flags::IO_HARDLINK),
        }
    }

    /// The 64-byte entry, without link flags. Panics on `UringCmd80`, which
    /// needs [`Sqe::encode`].
    pub(crate) fn encode64(&self) -> Entry {
        macro_rules! on {
            ($fd:expr, |$t:ident| $build:expr) => {
                match $fd {
                    Fd::Fixed(i) => {
                        let $t = Fixed(i);
                        $build
                    }
                    Fd::Raw(f) => {
                        let $t = types::Fd(f);
                        $build
                    }
                }
            };
        }
        let e = match self.op {
            Op::RecvMulti { fd, buf_group } => {
                on!(fd, |t| opcode::RecvMulti::new(t, buf_group).build())
            }
            Op::RecvMsgMulti { fd, msg, buf_group } => {
                on!(fd, |t| opcode::RecvMsgMulti::new(t, msg, buf_group).build())
            }
            Op::Recv {
                fd,
                buf,
                len,
                flags,
            } => on!(fd, |t| opcode::Recv::new(t, buf, len).flags(flags).build()),
            Op::AcceptMulti { fd, flags } => {
                on!(fd, |t| opcode::AcceptMulti::new(t).flags(flags).build())
            }
            Op::Send {
                fd,
                buf,
                len,
                flags,
            } => {
                on!(fd, |t| opcode::Send::new(t, buf, len).flags(flags).build())
            }
            Op::SendMsg { fd, msg, flags } => {
                on!(fd, |t| opcode::SendMsg::new(t, msg).flags(flags).build())
            }
            Op::SendMsgZc { fd, msg, flags } => {
                on!(fd, |t| opcode::SendMsgZc::new(t, msg).flags(flags).build())
            }
            Op::Read {
                fd,
                buf,
                len,
                offset,
            } => {
                on!(fd, |t| opcode::Read::new(t, buf, len)
                    .offset(offset)
                    .build())
            }
            Op::Write {
                fd,
                buf,
                len,
                offset,
            } => {
                on!(fd, |t| opcode::Write::new(t, buf, len)
                    .offset(offset)
                    .build())
            }
            Op::Fsync { fd } => on!(fd, |t| opcode::Fsync::new(t).build()),
            Op::Close { fd } => match fd {
                Fd::Fixed(i) => opcode::Close::new(Fixed(i)).build(),
                Fd::Raw(f) => opcode::Close::new(types::Fd(f)).build(),
            },
            Op::Shutdown { fd, how } => on!(fd, |t| opcode::Shutdown::new(t, how).build()),
            Op::CancelFdAll { fd } => match fd {
                Fd::Fixed(i) => {
                    opcode::AsyncCancel2::new(CancelBuilder::fd(Fixed(i)).all()).build()
                }
                Fd::Raw(f) => {
                    opcode::AsyncCancel2::new(CancelBuilder::fd(types::Fd(f)).all()).build()
                }
            },
            Op::SetSockOpt {
                fd,
                level,
                optname,
                optval,
                optlen,
            } => on!(fd, |t| opcode::SetSockOpt::new(
                t, level, optname, optval, optlen
            )
            .build()),
            Op::Cancel { target } => opcode::AsyncCancel::new(target).build(),
            Op::Connect { fd, addr, addrlen } => {
                on!(fd, |t| opcode::Connect::new(t, addr, addrlen).build())
            }
            Op::FixedFdInstall { index } => opcode::FixedFdInstall::new(Fixed(index), 0).build(),
            Op::PollAdd { fd, mask, multi } => {
                on!(fd, |t| opcode::PollAdd::new(t, mask).multi(multi).build())
            }
            Op::OpenAt {
                path,
                flags,
                mode,
                file_index,
            } => {
                let dest = DestinationSlot::try_from_slot_target(file_index)
                    .expect("file_index validated by the caller");
                opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), path)
                    .flags(flags)
                    .mode(mode)
                    .file_index(Some(dest))
                    .build()
            }
            Op::Statx {
                path,
                buf,
                nofollow,
            } => {
                let nofollow_flag = if nofollow {
                    libc::AT_SYMLINK_NOFOLLOW
                } else {
                    0
                };
                opcode::Statx::new(types::Fd(libc::AT_FDCWD), path, buf as *mut types::statx)
                    .flags(libc::AT_STATX_SYNC_AS_STAT | nofollow_flag)
                    .mask(0x7ff) // STATX_BASIC_STATS
                    .build()
            }
            Op::RenameAt { old, new } => opcode::RenameAt::new(
                types::Fd(libc::AT_FDCWD),
                old,
                types::Fd(libc::AT_FDCWD),
                new,
            )
            .build(),
            Op::UnlinkAt { path, flags } => opcode::UnlinkAt::new(types::Fd(libc::AT_FDCWD), path)
                .flags(flags)
                .build(),
            Op::MkDirAt { path, mode } => opcode::MkDirAt::new(types::Fd(libc::AT_FDCWD), path)
                .mode(mode)
                .build(),
            Op::UringCmd80 { .. } => unreachable!("URING_CMD needs a 128-byte entry; use encode"),
        };
        e.user_data(self.user_data)
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use crate::backend::uring::sqe::{Fd, Link, Op, Sqe};
    use io_uring::squeue::Flags;

    fn bytes(e: &Entry128) -> Vec<u8> {
        let n = std::mem::size_of::<Entry128>();
        unsafe { std::slice::from_raw_parts(e as *const Entry128 as *const u8, n).to_vec() }
    }

    /// Each operation encodes to the same bytes as the equivalent
    /// `io_uring::opcode` builder chain: opcode, fields, flags and
    /// user_data. Call sites' arguments are not covered here.
    #[test]
    fn every_op_encodes_like_its_opcode_builder() {
        let ud = 0x0123_4567_89ab_cdef;
        let p = 0x1000 as *mut u8;
        let msg = 0x2000 as *const libc::msghdr;
        let path = 0x3000 as *const libc::c_char;
        let path2 = 0x3100 as *const libc::c_char;
        let addr = 0x6000 as *const libc::sockaddr;
        let stx = 0x7000 as *mut libc::statx;
        let cmd = [7u8; 80];
        let fx = Fixed(9);
        let raw = types::Fd(11);
        let e = |x: Entry| -> Entry128 { x.user_data(ud).into() };
        let cases: Vec<(Sqe, Entry128)> = vec![
            (
                Sqe::new(
                    Op::RecvMulti {
                        fd: Fd::Fixed(9),
                        buf_group: 3,
                    },
                    ud,
                ),
                e(opcode::RecvMulti::new(fx, 3).build()),
            ),
            (
                Sqe::new(
                    Op::RecvMsgMulti {
                        fd: Fd::Fixed(9),
                        msg,
                        buf_group: 3,
                    },
                    ud,
                ),
                e(opcode::RecvMsgMulti::new(fx, msg, 3).build()),
            ),
            (
                Sqe::new(
                    Op::Recv {
                        fd: Fd::Fixed(9),
                        buf: p,
                        len: 77,
                        flags: libc::MSG_PEEK,
                    },
                    ud,
                ),
                e(opcode::Recv::new(fx, p, 77).flags(libc::MSG_PEEK).build()),
            ),
            (
                Sqe::new(
                    Op::AcceptMulti {
                        fd: Fd::Raw(11),
                        flags: libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    },
                    ud,
                ),
                e(opcode::AcceptMulti::new(raw)
                    .flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
                    .build()),
            ),
            (
                Sqe::stream_send(9, p, 77, ud),
                e(opcode::Send::new(fx, p, 77)
                    .flags(crate::completion::STREAM_SEND_FLAGS)
                    .build()),
            ),
            (
                Sqe::chain_send(9, p, 77, ud),
                e(opcode::Send::new(fx, p, 77)
                    .flags(crate::completion::CHAIN_SEND_FLAGS)
                    .build()),
            ),
            (
                Sqe::new(
                    Op::Send {
                        fd: Fd::Raw(11),
                        buf: p,
                        len: 77,
                        flags: 0,
                    },
                    ud,
                ),
                e(opcode::Send::new(raw, p, 77).build()),
            ),
            (
                Sqe::new(
                    Op::SendMsg {
                        fd: Fd::Raw(11),
                        msg,
                        flags: crate::completion::STREAM_SEND_FLAGS as u32,
                    },
                    ud,
                ),
                e(opcode::SendMsg::new(raw, msg)
                    .flags(crate::completion::STREAM_SEND_FLAGS as u32)
                    .build()),
            ),
            (
                Sqe::new(
                    Op::SendMsg {
                        fd: Fd::Fixed(9),
                        msg,
                        flags: 0,
                    },
                    ud,
                ),
                e(opcode::SendMsg::new(fx, msg).build()),
            ),
            (
                Sqe::send_msg_zc(9, msg, ud),
                e(opcode::SendMsgZc::new(fx, msg)
                    .flags(crate::completion::STREAM_SEND_FLAGS as u32)
                    .build()),
            ),
            (
                Sqe::send_msg(9, msg, ud),
                e(opcode::SendMsg::new(fx, msg)
                    .flags(crate::completion::STREAM_SEND_FLAGS as u32)
                    .build()),
            ),
            (
                Sqe::chain_send_msg(9, msg, ud),
                e(opcode::SendMsg::new(fx, msg)
                    .flags(crate::completion::CHAIN_SEND_FLAGS as u32)
                    .build()),
            ),
            (
                Sqe::chain_send_msg_zc(9, msg, ud),
                e(opcode::SendMsgZc::new(fx, msg)
                    .flags(crate::completion::CHAIN_SEND_FLAGS as u32)
                    .build()),
            ),
            (
                Sqe::new(
                    Op::Read {
                        fd: Fd::Raw(11),
                        buf: p,
                        len: 8,
                        offset: 0,
                    },
                    ud,
                ),
                e(opcode::Read::new(raw, p, 8).build()),
            ),
            (
                Sqe::new(
                    Op::Read {
                        fd: Fd::Fixed(9),
                        buf: p,
                        len: 4096,
                        offset: 8192,
                    },
                    ud,
                ),
                e(opcode::Read::new(fx, p, 4096).offset(8192).build()),
            ),
            (
                Sqe::new(
                    Op::Write {
                        fd: Fd::Fixed(9),
                        buf: p,
                        len: 4096,
                        offset: 8192,
                    },
                    ud,
                ),
                e(opcode::Write::new(fx, p, 4096).offset(8192).build()),
            ),
            (
                Sqe::new(Op::Fsync { fd: Fd::Fixed(9) }, ud),
                e(opcode::Fsync::new(fx).build()),
            ),
            (
                Sqe::new(Op::Close { fd: Fd::Fixed(9) }, ud),
                e(opcode::Close::new(fx).build()),
            ),
            (
                Sqe::new(
                    Op::Shutdown {
                        fd: Fd::Fixed(9),
                        how: libc::SHUT_RDWR,
                    },
                    ud,
                ),
                e(opcode::Shutdown::new(fx, libc::SHUT_RDWR).build()),
            ),
            (
                Sqe::new(Op::CancelFdAll { fd: Fd::Fixed(9) }, ud),
                e(opcode::AsyncCancel2::new(CancelBuilder::fd(fx).all()).build()),
            ),
            (
                Sqe::new(Op::Cancel { target: 42 }, ud),
                e(opcode::AsyncCancel::new(42).build()),
            ),
            (
                Sqe::new(
                    Op::Connect {
                        fd: Fd::Fixed(9),
                        addr,
                        addrlen: 16,
                    },
                    ud,
                ),
                e(opcode::Connect::new(fx, addr, 16).build()),
            ),
            (
                Sqe::new(Op::FixedFdInstall { index: 9 }, ud),
                e(opcode::FixedFdInstall::new(fx, 0).build()),
            ),
            (
                Sqe::new(
                    Op::PollAdd {
                        fd: Fd::Fixed(9),
                        mask: libc::POLLOUT as u32,
                        multi: false,
                    },
                    ud,
                ),
                e(opcode::PollAdd::new(fx, libc::POLLOUT as u32).build()),
            ),
            (
                Sqe::new(
                    Op::PollAdd {
                        fd: Fd::Fixed(9),
                        mask: libc::POLLOUT as u32,
                        multi: true,
                    },
                    ud,
                ),
                e(opcode::PollAdd::new(fx, libc::POLLOUT as u32)
                    .multi(true)
                    .build()),
            ),
            (
                Sqe::new(
                    Op::OpenAt {
                        path,
                        flags: libc::O_RDONLY,
                        mode: 0o644,
                        file_index: 5,
                    },
                    ud,
                ),
                e(opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), path)
                    .flags(libc::O_RDONLY)
                    .mode(0o644)
                    .file_index(Some(DestinationSlot::try_from_slot_target(5).unwrap()))
                    .build()),
            ),
            (
                Sqe::new(
                    Op::Statx {
                        path,
                        buf: stx,
                        nofollow: false,
                    },
                    ud,
                ),
                e(
                    opcode::Statx::new(types::Fd(libc::AT_FDCWD), path, stx as *mut types::statx)
                        .flags(libc::AT_STATX_SYNC_AS_STAT)
                        .mask(0x7ff)
                        .build(),
                ),
            ),
            (
                Sqe::new(
                    Op::Statx {
                        path,
                        buf: stx,
                        nofollow: true,
                    },
                    ud,
                ),
                e(
                    opcode::Statx::new(types::Fd(libc::AT_FDCWD), path, stx as *mut types::statx)
                        .flags(libc::AT_STATX_SYNC_AS_STAT | libc::AT_SYMLINK_NOFOLLOW)
                        .mask(0x7ff)
                        .build(),
                ),
            ),
            (
                Sqe::new(
                    Op::RenameAt {
                        old: path,
                        new: path2,
                    },
                    ud,
                ),
                e(opcode::RenameAt::new(
                    types::Fd(libc::AT_FDCWD),
                    path,
                    types::Fd(libc::AT_FDCWD),
                    path2,
                )
                .build()),
            ),
            (
                Sqe::new(
                    Op::UnlinkAt {
                        path,
                        flags: libc::AT_REMOVEDIR,
                    },
                    ud,
                ),
                e(opcode::UnlinkAt::new(types::Fd(libc::AT_FDCWD), path)
                    .flags(libc::AT_REMOVEDIR)
                    .build()),
            ),
            (
                Sqe::new(Op::MkDirAt { path, mode: 0o755 }, ud),
                e(opcode::MkDirAt::new(types::Fd(libc::AT_FDCWD), path)
                    .mode(0o755)
                    .build()),
            ),
            (
                Sqe::new(
                    Op::UringCmd80 {
                        fd: Fd::Fixed(9),
                        cmd_op: 0x42,
                        cmd,
                    },
                    ud,
                ),
                opcode::UringCmd80::new(fx, 0x42)
                    .cmd(cmd)
                    .build()
                    .user_data(ud),
            ),
        ];
        for (i, (sqe, want)) in cases.iter().enumerate() {
            assert_eq!(bytes(&sqe.encode()), bytes(want), "case {i}: {:?}", sqe.op);
        }
    }

    /// `MAX_FILE_INDEX` is the largest slot the crate's `DestinationSlot`
    /// accepts, which `encode` relies on after `submit_openat` checks it.
    #[test]
    fn max_file_index_is_the_largest_destination_slot() {
        use crate::backend::uring::sqe::MAX_FILE_INDEX;
        assert!(DestinationSlot::try_from_slot_target(MAX_FILE_INDEX).is_ok());
        assert!(DestinationSlot::try_from_slot_target(MAX_FILE_INDEX + 1).is_err());
    }

    #[test]
    fn links_set_the_link_flags() {
        let base = Sqe::new(Op::Cancel { target: 1 }, 2);
        let plain: Entry128 = opcode::AsyncCancel::new(1).build().user_data(2).into();
        let cases = [
            (Link::None, plain.clone()),
            (Link::Soft, plain.clone().flags(Flags::IO_LINK)),
            (Link::Hard, plain.flags(Flags::IO_HARDLINK)),
        ];
        for (link, want) in cases {
            assert_eq!(bytes(&base.link(link).encode()), bytes(&want), "{link:?}");
        }
    }
}

#[cfg(all(test, uring_engine))]
mod sq_room_tests {
    use super::*;
    use crate::backend::uring::ring::is_memlock_enomem;
    use crate::config::ConfigBuilder;
    use std::time::Duration;

    fn sqpoll_engine(sq_entries: u32) -> UringEngine {
        let config = ConfigBuilder::new()
            .workers(1)
            .sq_entries(sq_entries)
            .sqpoll(true)
            .sqpoll_idle_ms(1)
            .build()
            .expect("valid config");
        // Up to 5 s for earlier rings' memlock charge to be released (#589).
        for _ in 0..50 {
            match UringEngine::setup(&config) {
                Err(e) if is_memlock_enomem(&e) => std::thread::sleep(Duration::from_millis(100)),
                result => return result.expect("ring"),
            }
        }
        UringEngine::setup(&config).expect("ring")
    }

    /// Under SQPOLL, a pair pushed when the SQ has one free entry waits for
    /// the SQ thread to free a second instead of failing (#630). The SQ
    /// thread is left to go idle first, so the queued entries stay in the SQ
    /// until the push wakes it.
    #[test]
    fn a_pair_waits_for_the_sq_thread_to_free_two_entries() {
        let mut e = sqpoll_engine(4);
        let cap = e.ring.submission().capacity();
        let mut exercised = 0;
        for round in 0..20 {
            // `sqpoll_idle_ms(1)`: the SQ thread sleeps after 1 ms idle.
            std::thread::sleep(Duration::from_millis(20));
            let nop = || -> squeue::Entry128 { opcode::Nop::new().build().into() };
            for _ in 0..cap - 1 {
                unsafe { e.ring.submission().push(&nop()) }.expect("room");
            }
            if e.ring.submission().len() == cap - 1 {
                exercised += 1;
            }
            unsafe { e.push_sqe_pair(nop(), nop()) }
                .unwrap_or_else(|err| panic!("round {round}: {err}"));
            let mut reaped = 0;
            while reaped < cap + 1 {
                e.ring.submit_and_wait(1).expect("wait");
                reaped += e.ring.completion().count();
            }
        }
        assert!(
            exercised > 0,
            "the SQ thread consumed every round's NOPs before the pair push"
        );
    }
}

#[cfg(test)]
mod sq_cpu_refusal_tests {
    use super::*;
    use crate::config::{ConfigBuilder, SqpollCpus};

    fn einval() -> io::Error {
        io::Error::from_raw_os_error(libc::EINVAL)
    }

    /// `UringEngine::setup`, retried for up to 5 s while it fails for
    /// earlier rings' memlock charge (#589).
    fn setup_retrying_memlock(config: &Config) -> Result<UringEngine, Error> {
        for _ in 0..50 {
            match UringEngine::setup(config) {
                Err(e) if crate::backend::uring::ring::is_memlock_enomem(&e) => {
                    std::thread::sleep(std::time::Duration::from_millis(100))
                }
                result => return result,
            }
        }
        UringEngine::setup(config)
    }

    fn config() -> Config {
        let mut config = ConfigBuilder::new()
            .workers(1)
            .sqpoll(true)
            .sqpoll_cpu(5)
            .build()
            .unwrap();
        config.worker_index = 2;
        config
    }

    #[test]
    fn an_einval_that_an_unpinned_retry_avoids_names_the_cpu() {
        let err = ring_setup_error(einval(), Some(7), &config(), || Ok(()));
        let text = err.to_string();
        assert!(text.contains("worker 2's SQPOLL thread on CPU 7"), "{text}");
        assert!(text.contains("sqpoll_cpu 5 + worker 2"), "{text}");
    }

    #[test]
    fn a_retry_that_fails_with_einval_too_gets_the_generic_error() {
        let mut retried = false;
        let err = ring_setup_error(einval(), Some(7), &config(), || {
            retried = true;
            Err::<(), _>(einval())
        });
        assert!(retried);
        let text = err.to_string();
        assert!(!text.contains("CPU 7"), "{text}");
        assert!(text.contains("(EINVAL)"), "{text}");
    }

    #[test]
    fn a_retry_that_fails_with_enomem_keeps_the_einval_and_names_the_cpu() {
        let err = ring_setup_error(einval(), Some(7), &config(), || {
            Err::<(), _>(io::Error::from_raw_os_error(libc::ENOMEM))
        });
        let text = err.to_string();
        assert!(
            !crate::backend::uring::ring::is_memlock_enomem(&err),
            "{text}"
        );
        assert!(text.contains("(EINVAL)"), "{text}");
        assert!(text.contains("Worker 2's SQPOLL CPU 7"), "{text}");
        assert!(text.contains("sqpoll_cpu 5 + worker 2"), "{text}");
        assert!(text.contains("may be the cause"), "{text}");
    }

    #[test]
    fn probe_sizes_shrink_both_by_one_factor() {
        // The defaults: SQ 4096, CQ 65536.
        assert_eq!(probe_sizes(4096, 65536), (1, 16));
        assert_eq!(probe_sizes(64, 128), (8, 16));
        // A CQ smaller than the SQ stays smaller.
        assert_eq!(probe_sizes(64, 32), (32, 16));
        // Already small: unchanged.
        assert_eq!(probe_sizes(4, 8), (4, 8));
    }

    #[test]
    fn other_errors_and_unpinned_rings_are_not_retried() {
        let no_retry = || -> io::Result<()> { panic!("retried") };
        let err = ring_setup_error(
            io::Error::from_raw_os_error(libc::EPERM),
            Some(7),
            &config(),
            no_retry,
        );
        assert!(!err.to_string().contains("SQPOLL thread"), "{err}");
        let err = ring_setup_error(einval(), None, &config(), no_retry);
        assert!(!err.to_string().contains("SQPOLL thread"), "{err}");
    }

    /// On a real kernel: a CQ smaller than the SQ (which `build()` refuses,
    /// so it is set here directly) makes `io_uring_setup` fail with `EINVAL`
    /// whatever the SQ CPU, and the error must not blame the CPU.
    #[test]
    fn a_ring_the_kernel_refuses_for_another_reason_does_not_blame_the_cpu() {
        let mut config = config();
        config.sq_entries = 64;
        config.cq_entries = 32;
        config.sqpoll_cpu = Some(SqpollCpus::Base(0));
        config.sq_thread_cpu = Some(0);
        let err = setup_retrying_memlock(&config)
            .err()
            .expect("setup refused");
        let text = err.to_string();
        assert!(text.contains("EINVAL"), "{text}");
        assert!(!text.contains("SQPOLL thread"), "{text}");
    }

    /// On a real kernel, from a thread pinned to CPU 0: a CPU far beyond the
    /// machine is reported as the CPU, whatever this thread's affinity.
    #[test]
    fn a_refused_cpu_is_named_from_a_pinned_thread() {
        std::thread::spawn(|| {
            // Pin to the first CPU this thread may run on.
            unsafe {
                let size = std::mem::size_of::<libc::cpu_set_t>();
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                assert_eq!(libc::sched_getaffinity(0, size, &mut set), 0);
                let first = (0..8 * size)
                    .find(|&c| libc::CPU_ISSET(c, &set))
                    .expect("an allowed CPU");
                let mut one: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_SET(first, &mut one);
                assert_eq!(libc::sched_setaffinity(0, size, &one), 0);
            }
            let mut config = config();
            config.sq_entries = 64;
            config.cq_entries = 128;
            config.sq_thread_cpu = Some(1 << 20);
            let err = setup_retrying_memlock(&config)
                .err()
                .expect("setup refused");
            let text = err.to_string();
            assert!(text.contains("SQPOLL thread on CPU 1048576"), "{text}");
            assert!(text.contains("beyond"), "{text}");
        })
        .join()
        .unwrap();
    }
}

#[cfg(test)]
mod enter_error_tests {
    use super::*;

    #[test]
    fn a_temporary_enter_failure_is_backpressure_and_lost_completions_are_not() {
        for errno in [libc::EBUSY, libc::EAGAIN] {
            assert!(is_enter_backpressure(&io::Error::from_raw_os_error(errno)));
        }
        for errno in [libc::EBADR, libc::EBADF, libc::EINVAL] {
            assert!(!is_enter_backpressure(&io::Error::from_raw_os_error(errno)));
        }
    }

    /// Dropped completions are reported and counted, and the worker carries
    /// on; other errors still end it (#831).
    #[test]
    fn a_report_of_dropped_completions_is_counted_and_not_fatal() {
        use crate::metrics::{RING, ring};
        let before = RING.value(ring::CQE_DROPPED_REPORTED).unwrap_or(0);
        assert!(reports_dropped_completions(&io::Error::from_raw_os_error(
            libc::EBADR
        )));
        assert!(RING.value(ring::CQE_DROPPED_REPORTED).unwrap_or(0) > before);
        for errno in [libc::EBADF, libc::EINVAL, libc::EBUSY] {
            assert!(!reports_dropped_completions(&io::Error::from_raw_os_error(
                errno
            )));
        }
    }
}

#[cfg(test)]
mod completion_pending_tests {
    use super::*;
    use crate::backend::uring::ring::is_memlock_enomem;
    use crate::config::ConfigBuilder;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn engine(defer_recv_arm: bool) -> UringEngine {
        let config = ConfigBuilder::new()
            .workers(1)
            .defer_recv_arm(defer_recv_arm)
            .build()
            .expect("valid config");
        // Up to 5 s for earlier rings' memlock charge to be released (#589).
        for _ in 0..50 {
            match UringEngine::setup(&config) {
                Err(e) if is_memlock_enomem(&e) => std::thread::sleep(Duration::from_millis(100)),
                result => return result.expect("ring"),
            }
        }
        UringEngine::setup(&config).expect("ring")
    }

    /// Completions past a full CQ wait in the kernel's overflow list: a reap
    /// that finds them counts `cq_overflow`, and the next enter delivers them,
    /// none dropped (#831).
    #[test]
    fn completions_past_a_full_cq_are_counted_and_delivered() {
        use crate::metrics::{RING, ring};
        let config = ConfigBuilder::new()
            .workers(1)
            .sq_entries(4)
            .cq_entries(4)
            .build()
            .expect("valid config");
        let mut e = UringEngine::setup(&config).expect("ring");
        let nop = |ud: u64| -> squeue::Entry128 { opcode::Nop::new().build().user_data(ud).into() };
        let overflow_before = RING.value(ring::CQ_OVERFLOW).unwrap_or(0);
        let dropped_before = RING.value(ring::CQE_DROPPED).unwrap_or(0);
        // Eight completions into a four-entry CQ, none reaped in between.
        for batch in 0..2u64 {
            for i in 0..4 {
                unsafe { e.ring.submission().push(&nop(batch * 4 + i)) }.expect("room");
            }
            e.submit_and_get_events().expect("submit");
        }
        let mut out = Vec::new();
        e.reap(&mut out);
        assert_eq!(out.len(), 4, "the CQ holds four");
        assert!(
            RING.value(ring::CQ_OVERFLOW).unwrap_or(0) > overflow_before,
            "the reap did not count the overflow"
        );
        e.submit_and_get_events().expect("submit");
        e.reap(&mut out);
        let mut delivered: Vec<u64> = out.iter().map(|&(ud, _, _)| ud).collect();
        delivered.sort();
        assert_eq!(
            delivered,
            (0..8).collect::<Vec<_>>(),
            "an overflowed completion was lost"
        );
        assert_eq!(RING.value(ring::CQE_DROPPED).unwrap_or(0), dropped_before);
    }

    /// The ring's queues are the sizes the config asks for, the defaults
    /// included (#831).
    #[test]
    fn the_ring_has_the_configured_queue_sizes() {
        let defaults = engine(false);
        assert_eq!(defaults.ring.params().sq_entries(), 4096);
        assert_eq!(defaults.ring.params().cq_entries(), 65536);
        drop(defaults);
        let config = ConfigBuilder::new()
            .workers(1)
            .sq_entries(64)
            .cq_entries(128)
            .build()
            .expect("valid config");
        let small = UringEngine::setup(&config).expect("ring");
        assert_eq!(small.ring.params().sq_entries(), 64);
        assert_eq!(small.ring.params().cq_entries(), 128);
    }

    /// A receive that found its socket empty is completed from task work when
    /// bytes arrive. Under DEFER_TASKRUN that work waits for the next enter,
    /// and `completion_pending` reports it before that enter, and also
    /// reports a completion posted but not yet reaped.
    #[test]
    fn pending_task_work_and_unreaped_completions_are_reported() {
        let mut e = engine(true);
        let (a, mut b) = UnixStream::pair().expect("socketpair");
        let mut buf = [0u8; 16];
        let recv = opcode::Recv::new(types::Fd(a.as_raw_fd()), buf.as_mut_ptr(), buf.len() as u32)
            .build()
            .user_data(7);
        // Safety: `buf` and `a` outlive the receive, which is reaped below.
        unsafe { e.ring.submission().push(&recv.into()) }.expect("room");
        e.flush().expect("submit");
        assert!(
            e.ring.completion().is_empty(),
            "the receive completed without data"
        );
        assert!(
            !e.completion_pending(),
            "nothing is pending before the write"
        );

        b.write_all(b"hello").expect("write");
        assert!(
            e.ring.completion().is_empty(),
            "DEFER_TASKRUN posted without an enter"
        );
        assert!(
            e.completion_pending(),
            "the receive's task work is not reported"
        );

        e.submit_and_get_events().expect("enter");
        assert!(
            e.completion_pending(),
            "the posted completion is not reported"
        );
        let cqe = e
            .ring
            .completion()
            .next()
            .expect("the receive's completion");
        assert_eq!((cqe.user_data(), cqe.result()), (7, 5));
        assert!(
            !e.completion_pending(),
            "pending after the completion was reaped"
        );
    }

    /// Without `defer_recv_arm` the ring has no TASKRUN_FLAG and the engine
    /// cannot tell, so it reports work pending.
    #[test]
    fn without_the_taskrun_flag_work_is_always_reported_pending() {
        let mut e = engine(false);
        assert!(e.ring.completion().is_empty());
        assert!(e.completion_pending());
    }
}
