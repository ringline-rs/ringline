use std::io;

use thiserror::Error;

/// Errors returned by the ringline driver.
///
/// # Recovery Guidance
///
/// | Error | Cause | Recovery |
/// |-------|-------|----------|
/// | `Io` | System call failure | Check `io::ErrorKind`; transient network errors may be retryable |
/// | `RingSetup` | io_uring refused or unsupported | Read the message: it names the sysctl/seccomp/kernel cause; or build with the `force-mio` feature |
/// | `BufferRegistration` | io_uring refused to register memory | `ENOMEM` is `RLIMIT_MEMLOCK`: raise with `ulimit -l` / `LimitMEMLOCK=`, or grant `CAP_IPC_LOCK`; `EFAULT` is a bad region pointer |
/// | `ConnectionLimitReached` | All connection slots in use | Increase via `ConfigBuilder::max_connections(...)` or close idle connections |
/// | `InvalidConnection` | Stale token, connection closed | Re-establish connection; do not reuse the `ConnCtx` |
/// | `SendPoolExhausted` | All send buffer slots in use | Await pending sends to complete before sending more |
/// | `InvalidRegion` | Region ID not registered | Check `MemoryRegion` registration; ensure region outlives usage |
/// | `PointerOutOfRegion` | SendGuard pointer outside registered region | Verify pointer arithmetic; region boundaries are strict |
/// | `ResourceLimit` | `RLIMIT_NOFILE` or `RLIMIT_MEMLOCK` too low for the config | The message names the limit and the `ulimit` to run; checked before any worker starts |
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error from a system call.
    ///
    /// Check the underlying [`io::ErrorKind`] for transient vs permanent failures.
    /// Network-related errors (e.g., `ConnectionReset`, `BrokenPipe`) typically
    /// indicate the peer closed the connection.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// io_uring ring setup failed, or the configuration cannot be applied.
    ///
    /// When `io_uring_setup(2)` itself is refused the message names the
    /// errno and the likely cause:
    /// - `EPERM`: the `kernel.io_uring_disabled` sysctl (Linux 6.6+; `2`
    ///   refuses everyone including root, `1` refuses callers outside
    ///   `kernel.io_uring_group` without `CAP_SYS_ADMIN`), or a seccomp
    ///   profile (Docker/containerd default, gVisor, systemd
    ///   `SystemCallFilter=`). The message says which, based on the sysctl.
    /// - `ENOSYS`: kernel built without io_uring.
    /// - `EINVAL`: kernel older than 6.1 rejecting a required setup flag
    ///   (`DEFER_TASKRUN` and `SendMsgZc` are 6.1 features).
    ///
    /// The backend is chosen at build time by `build.rs` (Linux 6.1+ host
    /// gets io_uring); the only opt-out is the `force-mio` cargo feature,
    /// e.g. `cargo build --features ringline/force-mio` from a dependent
    /// crate. There is no runtime fallback.
    #[error("ring setup: {0}")]
    RingSetup(String),

    /// io_uring refused to register memory: fixed buffers
    /// ([`ConfigBuilder::registered_regions`](crate::ConfigBuilder::registered_regions))
    /// or a provided buffer ring.
    ///
    /// The message names the errno and the cause. `ENOMEM` on fixed buffers
    /// is the `RLIMIT_MEMLOCK` limit in practice: io_uring pins registered
    /// buffers and charges them to the caller's memlock limit unless the
    /// process holds `CAP_IPC_LOCK`, and distros default the limit to 8 MiB
    /// or 64 MiB. Raise it with `ulimit -l` (or `LimitMEMLOCK=` in a systemd
    /// unit) or grant the capability. Regions in the startup config are
    /// checked against the limit before any worker starts and reported as
    /// [`Error::ResourceLimit`]; regions added later through
    /// [`ShutdownHandle::register_region`](crate::ShutdownHandle::register_region)
    /// report the same guidance as an `io::Error`. `EFAULT` means the
    /// `MemoryRegion` pointer or length does not describe mapped memory.
    #[error("buffer registration: {0}")]
    BufferRegistration(String),

    /// Connection limit reached.
    ///
    /// The worker has no free slots for new connections. Either:
    /// - Increase via `ConfigBuilder::max_connections(...)` (default: 16000)
    /// - Close idle connections to free slots
    /// - Add more worker threads to distribute load
    #[error("connection limit reached")]
    ConnectionLimitReached,

    /// Invalid or stale connection token.
    ///
    /// This occurs when:
    /// - The connection was closed and the slot was reused
    /// - The `ConnCtx` was used after the peer disconnected
    /// - A `ConnToken` was incorrectly cached and reused
    ///
    /// Do not retry with the same token; establish a new connection.
    #[error("invalid connection")]
    InvalidConnection,

    /// Send pool exhausted.
    ///
    /// All send buffer slots are in flight. This is a backpressure signal:
    /// - Await pending `send()` futures before sending more
    /// - Use `send_nowait()` for fire-and-forget with explicit error handling
    /// - Increase via `ConfigBuilder::send_pool(count, slot_size)` (default count: 1024)
    #[error("send pool exhausted")]
    SendPoolExhausted,

    /// Invalid memory region ID.
    ///
    /// The `RegionId` passed to `SendGuard` does not correspond to a
    /// registered `MemoryRegion`. Ensure:
    /// - The region was registered via [`ConfigBuilder::registered_regions`](crate::ConfigBuilder::registered_regions)
    ///   or [`ShutdownHandle::register_region`](crate::ShutdownHandle::register_region)
    /// - The region is still valid (not dropped)
    #[error("invalid memory region ID")]
    InvalidRegion,

    /// Pointer not within the registered memory region.
    ///
    /// `SendGuard` requires the pointer to be strictly within the bounds
    /// of the registered region. This check prevents:
    /// - Use-after-free (pointer to freed memory)
    /// - Buffer overflows (pointer past region end)
    ///
    /// Debug by printing the pointer and region bounds when registering.
    #[error("pointer not within registered region")]
    PointerOutOfRegion,

    /// A process resource limit is too low for this configuration.
    ///
    /// Checked in `launch` before any worker thread exists, and the soft
    /// limit is raised automatically when the hard limit allows; this error
    /// means the hard limit itself is too low and names the `ulimit` to run.
    /// - `RLIMIT_NOFILE`: connections need file descriptors (or fixed-file
    ///   table entries on io_uring); the default 1024 is too low for
    ///   high-concurrency workloads. `ulimit -n 65536` or higher.
    /// - `RLIMIT_MEMLOCK` (io_uring): fixed buffers from
    ///   [`ConfigBuilder::registered_regions`](crate::ConfigBuilder::registered_regions)
    ///   are pinned against it. `ulimit -l <KiB>`, or `CAP_IPC_LOCK`.
    #[error("{0}")]
    ResourceLimit(String),
}

/// What the kernel's io_uring policy sysctls reported when ring setup failed.
///
/// `None` means the sysctl could not be read — either the kernel predates
/// it (`kernel.io_uring_disabled` arrived in 6.6) or `/proc/sys` is not
/// mounted. Both fields are read once, only on the failure path.
#[cfg(any(has_io_uring, test))]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RingSetupProbe {
    /// `kernel.io_uring_disabled`: 0 = allowed, 1 = restricted to
    /// `kernel.io_uring_group` members and `CAP_SYS_ADMIN`, 2 = refused for
    /// everyone including root.
    pub(crate) io_uring_disabled: Option<u32>,
    /// `kernel.io_uring_group`: the gid exempted when `io_uring_disabled`
    /// is 1, or `-1` when no group is configured.
    pub(crate) io_uring_group: Option<i64>,
}

#[cfg(has_io_uring)]
impl RingSetupProbe {
    /// Read the policy sysctls from `/proc/sys`. Every failure collapses to
    /// `None`; this runs only after `io_uring_setup(2)` has already failed,
    /// so nothing here may fail loudly.
    pub(crate) fn read() -> Self {
        fn read_sysctl<T: std::str::FromStr>(path: &str) -> Option<T> {
            std::fs::read_to_string(path).ok()?.trim().parse().ok()
        }
        Self {
            io_uring_disabled: read_sysctl("/proc/sys/kernel/io_uring_disabled"),
            io_uring_group: read_sysctl("/proc/sys/kernel/io_uring_group"),
        }
    }
}

#[cfg(any(has_io_uring, test))]
const MIO_HINT: &str = "or build with the `force-mio` cargo feature \
    (`--features ringline/force-mio`) to use the mio backend instead";

/// Name an errno the way strace and the man pages do, so the message can
/// be searched for. `None` for non-OS errors.
#[cfg(any(has_io_uring, test))]
pub(crate) fn errno_name(err: &io::Error) -> Option<&'static str> {
    Some(match err.raw_os_error()? {
        libc::EPERM => "EPERM",
        libc::ENOSYS => "ENOSYS",
        libc::EINVAL => "EINVAL",
        libc::ENOMEM => "ENOMEM",
        libc::EMFILE => "EMFILE",
        libc::ENFILE => "ENFILE",
        libc::EAGAIN => "EAGAIN",
        libc::EFAULT => "EFAULT",
        _ => return None,
    })
}

/// Turn a raw `io_uring_setup(2)` failure into a message that names the
/// cause and the fix.
///
/// `EPERM` is the case that matters: on modern kernels it is almost always
/// either the `kernel.io_uring_disabled` sysctl or a seccomp profile
/// (Docker/containerd default since 2023, gVisor, systemd
/// `SystemCallFilter=`), and the sysctl value distinguishes the two. The
/// bare OS error ("Operation not permitted") says none of that, and `sudo`
/// does not help when the sysctl is 2.
#[cfg(any(has_io_uring, test))]
pub(crate) fn describe_ring_setup_failure(err: &io::Error, probe: &RingSetupProbe) -> String {
    let mut msg = String::from("io_uring_setup(2): ");
    msg.push_str(&err.to_string());
    if let Some(name) = errno_name(err) {
        msg.push_str(" (");
        msg.push_str(name);
        msg.push(')');
    }
    msg.push_str(". ");

    match err.raw_os_error() {
        Some(libc::EPERM) => match probe.io_uring_disabled {
            Some(2) => {
                msg.push_str(
                    "kernel.io_uring_disabled is 2, which refuses io_uring for every \
                     process including root. Set `sysctl kernel.io_uring_disabled=0` \
                     (or =1 and add this user to the kernel.io_uring_group gid), ",
                );
            }
            Some(1) => {
                msg.push_str(
                    "kernel.io_uring_disabled is 1, which refuses io_uring to callers \
                     that lack CAP_SYS_ADMIN and are not in kernel.io_uring_group ",
                );
                match probe.io_uring_group {
                    Some(gid) if gid >= 0 => {
                        msg.push_str(&format!("(gid {gid}). Add this user to that group, "));
                    }
                    _ => msg.push_str("(no group is configured). Set `sysctl kernel.io_uring_group=<gid>` and add this user to it, "),
                }
                msg.push_str("set `sysctl kernel.io_uring_disabled=0`, ");
            }
            other => {
                match other {
                    Some(v) => msg.push_str(&format!("kernel.io_uring_disabled is {v}, so the sysctl is not the cause; ")),
                    None => msg.push_str("this kernel has no kernel.io_uring_disabled sysctl, so it is not the cause; "),
                }
                msg.push_str(
                    "io_uring_setup is most likely denied by a seccomp profile (the \
                     Docker/containerd default profile, gVisor, or a systemd \
                     SystemCallFilter=). Allow io_uring_setup, io_uring_enter and \
                     io_uring_register in that profile, ",
                );
            }
        },
        Some(libc::ENOSYS) => {
            msg.push_str("this kernel was built without io_uring. Use a kernel with CONFIG_IO_URING (6.1+), ");
        }
        Some(libc::EINVAL) => {
            msg.push_str(
                "the kernel rejected a setup flag ringline requires \
                 (IORING_SETUP_DEFER_TASKRUN and IORING_OP_SENDMSG_ZC need \
                 Linux 6.1+). Upgrade the kernel, ",
            );
        }
        _ => {
            msg.push_str("Fix the underlying error, ");
        }
    }
    msg.push_str(MIO_HINT);
    msg.push('.');
    msg
}

#[cfg(any(has_io_uring, test))]
impl Error {
    /// Wrap an `io_uring_setup(2)` failure as [`Error::RingSetup`] with the
    /// cause and fix spelled out. Probes the policy sysctls on the failure
    /// path only.
    #[cfg(has_io_uring)]
    pub(crate) fn ring_setup(err: io::Error) -> Self {
        Self::ring_setup_with_probe(err, &RingSetupProbe::read())
    }

    pub(crate) fn ring_setup_with_probe(err: io::Error, probe: &RingSetupProbe) -> Self {
        Error::RingSetup(describe_ring_setup_failure(&err, probe))
    }
}

/// The process's `RLIMIT_MEMLOCK`, in bytes. io_uring charges registered
/// (fixed) buffers against it unless the process holds `CAP_IPC_LOCK`, and
/// distros default it to 8 MiB or 64 MiB, so a large `registered_regions`
/// config is the usual way to hit it.
#[cfg(any(has_io_uring, test))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct MemlockLimit {
    pub(crate) soft: u64,
    pub(crate) hard: u64,
}

#[cfg(has_io_uring)]
impl MemlockLimit {
    pub(crate) fn read() -> io::Result<Self> {
        let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            soft: rlim.rlim_cur,
            hard: rlim.rlim_max,
        })
    }
}

/// What to do about `RLIMIT_MEMLOCK` before registering `required` bytes.
#[cfg(any(has_io_uring, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemlockPlan {
    Sufficient,
    /// The soft limit is short but the hard limit allows raising it to this.
    RaiseSoftTo(u64),
    HardTooLow,
}

#[cfg(any(has_io_uring, test))]
pub(crate) fn memlock_plan(required: u64, limit: &MemlockLimit) -> MemlockPlan {
    if required == 0 || limit.soft >= required {
        MemlockPlan::Sufficient
    } else if limit.hard == libc::RLIM_INFINITY || limit.hard >= required {
        MemlockPlan::RaiseSoftTo(required)
    } else {
        MemlockPlan::HardTooLow
    }
}

#[cfg(any(has_io_uring, test))]
fn kib_ceil(bytes: u64) -> u64 {
    bytes.div_ceil(1024)
}

#[cfg(any(has_io_uring, test))]
fn rlim_kib(v: u64) -> String {
    if v == libc::RLIM_INFINITY {
        "unlimited".to_string()
    } else {
        format!("{} KiB", kib_ceil(v))
    }
}

/// The shortfall message shared by the launch-time preflight and a failed
/// registration. `what` names the memory being pinned ("2 registered regions").
#[cfg(any(has_io_uring, test))]
pub(crate) fn describe_memlock_shortfall(
    required: u64,
    limit: &MemlockLimit,
    what: &str,
) -> String {
    format!(
        "RLIMIT_MEMLOCK too low: {what} need {} KiB of pinned memory but the \
         hard limit is {} (soft {}). Raise it with `ulimit -l {}` before \
         starting (or `LimitMEMLOCK=` in the systemd unit), or grant the \
         process CAP_IPC_LOCK, which exempts it from the limit.",
        kib_ceil(required),
        rlim_kib(limit.hard),
        rlim_kib(limit.soft),
        kib_ceil(required),
    )
}

/// Turn a failed `io_uring_register` of `bytes` of user memory into a message
/// that names the cause. `ENOMEM` here is the memlock limit in practice; the
/// kernel returns it rather than `EPERM` when the accounting fails.
#[cfg(any(has_io_uring, test))]
pub(crate) fn describe_buffer_registration_failure(
    err: &io::Error,
    bytes: u64,
    limit: Option<&MemlockLimit>,
) -> String {
    let mut msg = format!("io_uring_register(2) of {} KiB: {err}", kib_ceil(bytes));
    if let Some(name) = errno_name(err) {
        msg.push_str(&format!(" ({name})"));
    }
    msg.push_str(". ");
    match err.raw_os_error() {
        Some(libc::ENOMEM) => match limit {
            Some(limit) => msg.push_str(&describe_memlock_shortfall(
                bytes,
                limit,
                "the buffers being registered",
            )),
            None => msg.push_str(
                "The kernel refused to pin this much memory, which is the \
                 RLIMIT_MEMLOCK limit in practice. Raise it with `ulimit -l` \
                 (or `LimitMEMLOCK=` in the systemd unit), or grant the process \
                 CAP_IPC_LOCK.",
            ),
        },
        Some(libc::EFAULT) => msg.push_str(
            "The region is not mapped in this process: the pointer or length \
             passed to MemoryRegion::new is wrong, or the memory was freed.",
        ),
        _ => {}
    }
    msg
}

#[cfg(any(has_io_uring, test))]
impl Error {
    /// Wrap a failed buffer registration as [`Error::BufferRegistration`].
    pub(crate) fn buffer_registration(
        err: io::Error,
        bytes: u64,
        limit: Option<&MemlockLimit>,
    ) -> Self {
        Error::BufferRegistration(describe_buffer_registration_failure(&err, bytes, limit))
    }
}

/// Errors returned by UDP send operations.
///
/// UDP sends can fail due to resource exhaustion even though UDP is
/// connectionless. The ringline runtime maintains per-worker send pools
/// to bound memory usage.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UdpSendError {
    /// UDP send pool exhausted.
    ///
    /// No free send slot or copy-pool slot available. This is transient:
    /// await pending UDP receives/sends to complete, then retry.
    #[error("UDP send pool exhausted")]
    PoolExhausted,

    /// UDP submission queue full.
    ///
    /// The io_uring submission queue is full. This is rare and indicates
    /// the application is submitting faster than the kernel can process.
    /// Await pending operations before submitting more.
    #[error("UDP submission queue full")]
    SubmissionQueueFull,

    /// UDP I/O error.
    #[error("UDP I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Error returned by [`try_sleep`](crate::try_sleep) and
/// [`try_timeout`](crate::try_timeout) when the timer slot pool is full.
///
/// The timer pool is pre-allocated to avoid allocations during async
/// execution. When exhausted, use the infallible variants [`sleep()`]
/// and [`timeout()`] which will panic instead (preferred in most cases).
///
/// [`sleep()`]: crate::sleep
/// [`timeout()`]: crate::timeout
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("timer slot pool exhausted")]
pub struct TimerExhausted;

#[cfg(test)]
mod tests {
    use super::*;

    fn eperm() -> io::Error {
        io::Error::from_raw_os_error(libc::EPERM)
    }

    fn probe(disabled: Option<u32>, group: Option<i64>) -> RingSetupProbe {
        RingSetupProbe {
            io_uring_disabled: disabled,
            io_uring_group: group,
        }
    }

    #[test]
    fn ring_setup_error_lands_in_ring_setup_variant_not_io() {
        let err = Error::ring_setup_with_probe(eperm(), &probe(None, None));
        assert!(matches!(err, Error::RingSetup(_)), "got {err:?}");
        let text = err.to_string();
        assert!(
            text.starts_with("ring setup: io_uring_setup(2): "),
            "{text}"
        );
        assert!(text.contains("EPERM"), "{text}");
    }

    #[test]
    fn eperm_with_sysctl_2_names_the_sysctl_and_the_fix() {
        let text = describe_ring_setup_failure(&eperm(), &probe(Some(2), Some(-1)));
        assert!(text.contains("kernel.io_uring_disabled is 2"), "{text}");
        assert!(text.contains("including root"), "{text}");
        assert!(text.contains("sysctl kernel.io_uring_disabled=0"), "{text}");
        assert!(text.contains("force-mio"), "{text}");
        assert!(!text.contains("seccomp"), "{text}");
    }

    #[test]
    fn eperm_with_sysctl_1_points_at_group_and_cap_sys_admin() {
        let text = describe_ring_setup_failure(&eperm(), &probe(Some(1), Some(1234)));
        assert!(text.contains("kernel.io_uring_disabled is 1"), "{text}");
        assert!(text.contains("kernel.io_uring_group (gid 1234)"), "{text}");
        assert!(text.contains("CAP_SYS_ADMIN"), "{text}");
        assert!(text.contains("force-mio"), "{text}");
        assert!(!text.contains("seccomp"), "{text}");
    }

    #[test]
    fn eperm_with_sysctl_1_and_no_group_says_so() {
        let text = describe_ring_setup_failure(&eperm(), &probe(Some(1), Some(-1)));
        assert!(text.contains("no group is configured"), "{text}");
    }

    #[test]
    fn eperm_with_sysctl_0_blames_seccomp() {
        let text = describe_ring_setup_failure(&eperm(), &probe(Some(0), Some(-1)));
        assert!(text.contains("kernel.io_uring_disabled is 0"), "{text}");
        assert!(text.contains("seccomp"), "{text}");
        assert!(text.contains("force-mio"), "{text}");
    }

    #[test]
    fn eperm_without_sysctl_blames_seccomp() {
        let text = describe_ring_setup_failure(&eperm(), &probe(None, None));
        assert!(
            text.contains("no kernel.io_uring_disabled sysctl"),
            "{text}"
        );
        assert!(text.contains("seccomp"), "{text}");
        assert!(text.contains("force-mio"), "{text}");
    }

    #[test]
    fn enosys_says_kernel_lacks_io_uring() {
        let err = io::Error::from_raw_os_error(libc::ENOSYS);
        let text = describe_ring_setup_failure(&err, &probe(None, None));
        assert!(text.contains("ENOSYS"), "{text}");
        assert!(text.contains("without io_uring"), "{text}");
        assert!(text.contains("force-mio"), "{text}");
    }

    #[test]
    fn einval_points_at_kernel_version() {
        let err = io::Error::from_raw_os_error(libc::EINVAL);
        let text = describe_ring_setup_failure(&err, &probe(None, None));
        assert!(text.contains("EINVAL"), "{text}");
        assert!(text.contains("6.1"), "{text}");
        assert!(text.contains("force-mio"), "{text}");
    }

    #[test]
    fn other_errors_keep_the_os_message_and_mio_hint() {
        let err = io::Error::from_raw_os_error(libc::ENOMEM);
        let text = describe_ring_setup_failure(&err, &probe(None, None));
        assert!(text.starts_with("io_uring_setup(2): "), "{text}");
        assert!(text.contains("ENOMEM"), "{text}");
        assert!(text.contains("force-mio"), "{text}");
        assert!(!text.contains("seccomp"), "{text}");
    }

    #[test]
    fn non_os_error_has_no_errno_name() {
        let err = io::Error::other("boom");
        let text = describe_ring_setup_failure(&err, &probe(None, None));
        assert!(text.starts_with("io_uring_setup(2): boom"), "{text}");
        assert!(!text.contains("()"), "{text}");
    }

    const MIB: u64 = 1024 * 1024;

    fn limit(soft: u64, hard: u64) -> MemlockLimit {
        MemlockLimit { soft, hard }
    }

    #[test]
    fn memlock_plan_nothing_required_is_sufficient() {
        assert!(matches!(
            memlock_plan(0, &limit(0, 0)),
            MemlockPlan::Sufficient
        ));
    }

    #[test]
    fn memlock_plan_soft_covers_it() {
        assert!(matches!(
            memlock_plan(8 * MIB, &limit(8 * MIB, 8 * MIB)),
            MemlockPlan::Sufficient
        ));
    }

    #[test]
    fn memlock_plan_raises_soft_when_hard_allows() {
        assert!(matches!(
            memlock_plan(32 * MIB, &limit(8 * MIB, 64 * MIB)),
            MemlockPlan::RaiseSoftTo(v) if v == 32 * MIB
        ));
    }

    #[test]
    fn memlock_plan_raises_soft_under_infinite_hard() {
        assert!(matches!(
            memlock_plan(32 * MIB, &limit(8 * MIB, libc::RLIM_INFINITY)),
            MemlockPlan::RaiseSoftTo(v) if v == 32 * MIB
        ));
    }

    #[test]
    fn memlock_plan_hard_too_low() {
        assert!(matches!(
            memlock_plan(65 * MIB, &limit(8 * MIB, 64 * MIB)),
            MemlockPlan::HardTooLow
        ));
    }

    #[test]
    fn memlock_shortfall_names_limit_fix_and_exemption() {
        let text = describe_memlock_shortfall(
            5 * MIB + 1,
            &limit(8 * MIB, 8 * MIB),
            "2 registered regions",
        );
        assert!(text.contains("RLIMIT_MEMLOCK too low"), "{text}");
        assert!(text.contains("2 registered regions"), "{text}");
        // 5 MiB + 1 byte rounds up to 5121 KiB for `ulimit -l`.
        assert!(text.contains("ulimit -l 5121"), "{text}");
        assert!(text.contains("hard limit is 8192 KiB"), "{text}");
        assert!(text.contains("CAP_IPC_LOCK"), "{text}");
    }

    #[test]
    fn memlock_shortfall_prints_infinite_hard_as_unlimited() {
        let text =
            describe_memlock_shortfall(MIB, &limit(0, libc::RLIM_INFINITY), "1 registered region");
        assert!(text.contains("hard limit is unlimited"), "{text}");
    }

    #[test]
    fn enomem_on_buffer_registration_blames_memlock() {
        let err = io::Error::from_raw_os_error(libc::ENOMEM);
        let e = Error::buffer_registration(err, 4 * MIB, Some(&limit(64 * 1024, 64 * 1024)));
        assert!(matches!(e, Error::BufferRegistration(_)), "got {e:?}");
        let text = e.to_string();
        assert!(text.starts_with("buffer registration: "), "{text}");
        assert!(text.contains("ENOMEM"), "{text}");
        assert!(text.contains("RLIMIT_MEMLOCK"), "{text}");
        assert!(text.contains("4096 KiB"), "{text}");
        assert!(text.contains("ulimit -l"), "{text}");
        assert!(text.contains("CAP_IPC_LOCK"), "{text}");
    }

    #[test]
    fn enomem_without_a_readable_limit_still_blames_memlock() {
        let err = io::Error::from_raw_os_error(libc::ENOMEM);
        let text = describe_buffer_registration_failure(&err, 4 * MIB, None);
        assert!(text.contains("RLIMIT_MEMLOCK"), "{text}");
        assert!(text.contains("ulimit -l"), "{text}");
    }

    #[test]
    fn efault_on_buffer_registration_blames_the_pointer() {
        let err = io::Error::from_raw_os_error(libc::EFAULT);
        let text = describe_buffer_registration_failure(&err, 4096, None);
        assert!(text.contains("EFAULT"), "{text}");
        assert!(text.contains("not mapped"), "{text}");
        assert!(!text.contains("RLIMIT_MEMLOCK"), "{text}");
    }

    #[test]
    fn other_buffer_registration_errors_keep_the_os_message() {
        let err = io::Error::from_raw_os_error(libc::EINVAL);
        let text = describe_buffer_registration_failure(&err, 4096, None);
        assert!(text.contains("EINVAL"), "{text}");
        assert!(!text.contains("RLIMIT_MEMLOCK"), "{text}");
    }
}
