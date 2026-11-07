//! Async process spawning.
//!
//! Spawns child processes on a dedicated thread pool (via `posix_spawnp` +
//! `pidfd_open`) and uses io_uring `PollAdd` on the pidfd for async exit
//! notification.
//!
//! # Example
//!
//! ```rust,no_run
//! use ringline::process::Command;
//!
//! # async fn example() -> std::io::Result<()> {
//! let child = Command::new("echo")
//!     .arg("hello")
//!     .arg("world")
//!     .spawn()?
//!     .await?;
//! let status = child.wait()?.await?;
//! assert!(status.success());
//! # Ok(())
//! # }
//! ```

use std::ffi::CString;
use std::future::Future;
use std::io;
#[cfg(has_io_uring)]
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(has_io_uring)]
use crate::completion::{OpTag, UserData};
use crate::runtime::CURRENT_TASK_ID;
use crate::runtime::io::{try_with_state, with_state};
use crate::runtime::waker::pending;

/// A spawned child process.
///
/// Obtained by awaiting the future returned by [`Command::spawn()`]. The child's
/// pidfd is held open until the `Child` is dropped.
pub struct Child {
    pid: u32,
    /// `None` on targets without `pidfd_open` (non-Linux). Held to keep the
    /// pidfd open until the `Child` drops; only `wait` reads it, on io_uring.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pidfd: Option<OwnedFd>,
}

impl Child {
    /// Get the process ID.
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Wait for the child to exit.
    ///
    /// Submits an io_uring `PollAdd` on the child's pidfd and returns a future
    /// that resolves when the child exits.
    #[cfg(has_io_uring)]
    pub fn wait(&self) -> io::Result<WaitFuture> {
        with_state(|driver, executor| {
            let seq = executor.next_pidfd_seq;
            executor.next_pidfd_seq += 1;
            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            executor.pidfd_waiters.insert(seq, task_id);

            // Present on Linux, the only target with io_uring.
            let pidfd = self
                .pidfd
                .as_ref()
                .map(AsRawFd::as_raw_fd)
                .ok_or_else(|| io::Error::other("child has no pidfd"))?;
            let ud = UserData::encode(OpTag::PidfdPoll, 0, seq);
            driver
                .ring
                .submit_poll_add(pidfd, libc::POLLIN as u32, ud.raw())?;
            Ok(WaitFuture {
                seq,
                pid: self.pid,
                owner: crate::runtime::waker::current_worker(),
            })
        })
    }

    /// Wait for the child to exit (not yet implemented on mio backend).
    #[cfg(not(has_io_uring))]
    pub fn wait(&self) -> io::Result<WaitFuture> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process wait requires the io_uring backend",
        ))
    }

    /// Send `SIGKILL` to the child.
    pub fn kill(&self) -> io::Result<()> {
        let ret = unsafe { libc::kill(self.pid as i32, libc::SIGKILL) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Future that resolves when a child process exits.
///
/// Polled on another worker it stays pending until a task on the owning worker
/// drives it.
pub struct WaitFuture {
    seq: u32,
    pid: u32,
    /// The worker whose executor holds `seq`.
    owner: u32,
}

impl Drop for WaitFuture {
    fn drop(&mut self) {
        // Only the owning worker's executor holds the entry. Dropped
        // elsewhere (the future is `Send`), it stays there.
        if crate::runtime::waker::current_worker() != self.owner {
            return;
        }
        // Deregister so an abandoned wait (select/timeout loser) leaves no
        // waiter or result entry; a completion after this finds no waiter and
        // is not stored. Outside a task poll, the release is deferred and
        // removes both entries.
        let released = try_with_state(|_driver, executor| {
            executor.pidfd_waiters.remove(&self.seq);
            executor.pidfd_results.remove(&self.seq);
        });
        // Outside a task poll (a connection's task dropped at teardown).
        if released.is_none() {
            crate::runtime::defer_release(crate::runtime::Orphan::Wait(self.seq));
        }
    }
}

impl Future for WaitFuture {
    type Output = io::Result<ExitStatus>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|_driver, executor| {
            // On another worker `seq` names that worker's entry, and the
            // result is not there.
            if self.owner != crate::runtime::waker::current_worker() {
                return pending(cx);
            }
            if let Some(result) = executor.pidfd_results.remove(&self.seq) {
                // pidfd is readable -- child has exited.
                if result < 0 {
                    return Poll::Ready(Err(io::Error::from_raw_os_error(-result)));
                }
                // Call waitid to collect exit status. This returns immediately
                // because the pidfd poll already confirmed the child exited.
                let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let ret = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        self.pid as libc::id_t,
                        &mut siginfo,
                        libc::WEXITED,
                    )
                };
                if ret < 0 {
                    return Poll::Ready(Err(io::Error::last_os_error()));
                }
                // Extract exit code from siginfo.
                let code = unsafe { siginfo.si_status() };
                Poll::Ready(Ok(ExitStatus { code }))
            } else {
                // Not yet ready -- re-register waiter.
                let task_id = CURRENT_TASK_ID.with(|c| c.get());
                executor.pidfd_waiters.insert(self.seq, task_id);
                pending(cx)
            }
        })
    }
}

/// Exit status of a child process.
#[derive(Debug, Clone, Copy)]
pub struct ExitStatus {
    code: i32,
}

impl ExitStatus {
    /// Returns true if the process exited with code 0.
    pub fn success(&self) -> bool {
        self.code == 0
    }

    /// Returns the exit code.
    pub fn code(&self) -> i32 {
        self.code
    }
}

/// Builder for spawning a child process.
///
/// Mirrors [`std::process::Command`]. The program is searched on `PATH`
/// (via `posix_spawnp`). The child inherits the parent's environment.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> std::io::Result<()> {
/// let child = ringline::process::Command::new("grep")
///     .arg("-r")
///     .arg("pattern")
///     .arg("src/")
///     .spawn()?
///     .await?;
/// let status = child.wait()?.await?;
/// # Ok(())
/// # }
/// ```
pub struct Command {
    program: String,
    args: Vec<String>,
}

impl Command {
    /// Create a new command for the given program.
    pub fn new(program: impl Into<String>) -> Self {
        Command {
            program: program.into(),
            args: Vec::new(),
        }
    }

    /// Add an argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add multiple arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(args.into_iter().map(|a| a.into()));
        self
    }

    /// Spawn the command.
    ///
    /// Returns a future that resolves to a [`Child`] once the spawner pool
    /// has created the process and obtained its pidfd.
    pub fn spawn(self) -> io::Result<SpawnFuture> {
        let program =
            CString::new(self.program).map_err(|_| io::Error::other("invalid program name"))?;
        let args: Vec<CString> = self
            .args
            .iter()
            .map(|a| CString::new(a.as_str()).map_err(|_| io::Error::other("invalid argument")))
            .collect::<io::Result<_>>()?;

        try_with_state(|driver, executor| {
            let spawner = driver
                .spawner
                .as_ref()
                .ok_or_else(|| io::Error::other("spawner pool not configured"))?;
            let spawn_tx = driver
                .spawn_tx
                .as_ref()
                .ok_or_else(|| io::Error::other("spawner pool not configured"))?;

            let request_id = executor.next_spawn_id;
            executor.next_spawn_id += 1;

            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            executor.pending_spawns.insert(request_id, (task_id, None));

            spawner
                .request_tx
                .send(crate::spawner::SpawnRequest {
                    program,
                    args,
                    request_id,
                    response_tx: spawn_tx.clone(),
                    wake_handle: driver.wake_handle,
                })
                .map_err(|_| io::Error::other("spawner pool shut down"))?;

            Ok(SpawnFuture {
                request_id,
                owner: crate::runtime::waker::current_worker(),
            })
        })
        .unwrap_or_else(|| Err(io::Error::other("called outside executor")))
    }
}

/// Future returned by [`Command::spawn()`]. Resolves to a [`Child`].
///
/// Polled on another worker it stays pending until a task on the owning worker
/// drives it.
pub struct SpawnFuture {
    request_id: u64,
    /// The worker whose executor holds `request_id`.
    owner: u32,
}

impl Drop for SpawnFuture {
    fn drop(&mut self) {
        // Only the owning worker's executor holds the entry. Dropped
        // elsewhere (the future is `Send`), it stays there.
        if crate::runtime::waker::current_worker() != self.owner {
            return;
        }
        // A SpawnFuture abandoned before completion (select/timeout loser)
        // must not leak its map entry. Removing the entry drops a response
        // that already arrived, which closes its pidfd; one that arrives later
        // finds no entry and is dropped on delivery.
        let released = try_with_state(|_driver, executor| {
            executor.pending_spawns.remove(&self.request_id);
        });
        // Outside a task poll (a connection's task dropped at teardown).
        if released.is_none() {
            crate::runtime::defer_release(crate::runtime::Orphan::Spawn(self.request_id));
        }
    }
}

impl Future for SpawnFuture {
    type Output = io::Result<Child>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|_driver, executor| {
            // On another worker this id names that worker's entry, and the
            // result is not there.
            if self.owner != crate::runtime::waker::current_worker() {
                return pending(cx);
            }
            if let Some((_, slot)) = executor.pending_spawns.get_mut(&self.request_id)
                && let Some(result) = slot.take()
            {
                executor.pending_spawns.remove(&self.request_id);
                return Poll::Ready(result.map(|r| Child {
                    pid: r.pid,
                    pidfd: r.pidfd,
                }));
            }
            // A `Shared` can pass this future between tasks of a worker.
            if let Some((owner, _)) = executor.pending_spawns.get_mut(&self.request_id) {
                *owner = CURRENT_TASK_ID.with(|c| c.get());
            }
            pending(cx)
        })
    }
}
