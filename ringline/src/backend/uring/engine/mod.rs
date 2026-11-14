//! The engine executes the operations the driver submits and reports their
//! completions. `UringEngine` runs them on the kernel's io_uring. Building
//! with the environment variable `RINGLINE_STUB_ENGINE=1` selects
//! `StubEngine` instead, which compiles the driver without `UringEngine`
//! and fails at setup.

use std::io;
use std::os::fd::RawFd;

use super::ring::CloseLead;
use super::sqe::Sqe;
use crate::backend::ProvidedBufRing;
use crate::buffer::fixed::FixedBufferRegistry;
use crate::config::Config;
use crate::error::Error;

#[cfg(not(uring_engine))]
pub(crate) mod stub;
#[cfg(uring_engine)]
pub(crate) mod uring;

/// The engine this build uses.
#[cfg(not(uring_engine))]
pub(crate) type ActiveEngine = stub::StubEngine;
/// The engine this build uses.
#[cfg(uring_engine)]
pub(crate) type ActiveEngine = uring::UringEngine;

/// What the driver needs from an engine.
///
/// A completion is `(user_data, result, flags)`, with the meaning
/// io_uring gives each: `result` is the operation's return value or a
/// negated errno, and `flags` are `IORING_CQE_F_*` bits (read them with
/// [`abi::cqueue`](super::abi::cqueue)).
pub(crate) trait Engine: Sized {
    /// Create the engine for one worker, on that worker's thread.
    fn setup(config: &Config) -> Result<Self, Error>;

    /// Queue `sqe`. Fails when the queue is full and submitting to make room
    /// either fails or leaves it full.
    ///
    /// # Safety
    /// The operation's pointers must stay valid until its completion
    /// arrives, and for `SendMsgZc` until its notification.
    unsafe fn push(&mut self, sqe: &Sqe) -> io::Result<()>;

    /// Queue two operations next to each other, so a link from `first` to
    /// `second` is never split across submissions.
    ///
    /// # Safety
    /// As [`push`](Self::push), for both.
    unsafe fn push_pair(&mut self, first: &Sqe, second: &Sqe) -> io::Result<()>;

    /// Queue `sqes` contiguously, with the links they carry.
    ///
    /// # Safety
    /// As [`push`](Self::push), for each.
    unsafe fn push_chain(&mut self, sqes: &[Sqe]) -> io::Result<()>;

    /// Start queued operations and block until at least `min_complete`
    /// completions are ready. `EINTR` restarts; `EAGAIN` (no memory for a
    /// request) and `EBUSY` return `Ok` so the caller reaps (see
    /// `is_enter_backpressure` in `uring.rs`).
    fn submit_and_wait(&self, min_complete: u32) -> io::Result<()>;

    /// As [`submit_and_wait`](Self::submit_and_wait), but return once
    /// `timeout` has passed, whether or not `min_complete` completions are
    /// ready. Expiry returns `Ok`, and so does `EINTR`, without restarting
    /// the wait.
    fn submit_and_wait_timeout(
        &self,
        min_complete: u32,
        timeout: std::time::Duration,
    ) -> io::Result<()>;

    /// Start queued operations and make ready completions reapable, without
    /// blocking.
    fn submit_and_get_events(&self) -> io::Result<()>;

    /// Start queued operations, if any, and make the completions they
    /// produce at once reapable.
    fn flush(&self) -> io::Result<()>;

    /// Whether a completion is ready to reap or the kernel holds task work for
    /// the next enter to run. That task work may post no completion, so
    /// `true` does not mean a wait for one completion returns. `false` means a
    /// wait would block until new work arrives. `true` when the engine cannot
    /// tell.
    fn completion_pending(&self) -> bool;

    /// Whether the last submitting enter left SQEs queued: it failed with
    /// `EBUSY` or `EAGAIN`, or submitted only some of them (a request the
    /// kernel could not allocate, or one that failed its prep). The kernel returns such an enter
    /// before it waits, so the run loop bounds its next wait by the push
    /// retry backoff while this holds (`Driver::push_retries_pending`).
    fn submit_refused(&self) -> bool;

    /// Append every ready completion to `out`, consuming them.
    fn reap(&mut self, out: &mut Vec<(u64, i32, u32)>);

    /// Create a fixed-file table of `count` empty slots.
    fn register_files_sparse(&self, count: u32) -> Result<(), Error>;

    /// Install `fds` into the fixed-file table from slot `offset`; `-1`
    /// empties a slot. The engine keeps its own reference to each file.
    fn register_files_update(&self, offset: u32, fds: &[RawFd]) -> io::Result<()>;

    /// Register a provided-buffer ring under its group id.
    fn register_buf_ring(&mut self, provided: &ProvidedBufRing) -> Result<(), Error>;

    /// Unregister the provided-buffer ring with group id `bgid`. Must be
    /// called before the ring's memory is unmapped.
    fn unregister_buf_ring(&self, bgid: u16) -> io::Result<()>;

    /// Register the fixed-buffer table, sized to `registry`, with its
    /// occupied slots. An empty registry registers nothing.
    fn register_buffers(&self, registry: &FixedBufferRegistry) -> Result<(), Error>;

    /// Set fixed-buffer slot `slot` to `iov`; a null `iov_base` clears it.
    ///
    /// # Safety
    /// The memory `iov` describes must stay valid until the slot is cleared
    /// or the runtime shuts down, and no operation using the slot may be in
    /// flight.
    unsafe fn register_buffers_update_one(&self, slot: u16, iov: libc::iovec) -> io::Result<()>;

    /// What goes ahead of a connection's `Close`.
    fn close_lead(&self) -> CloseLead;

    /// Whether a registered file can be returned to the process's file
    /// table (`FIXED_FD_INSTALL`), and so whether park (#443) is available.
    fn supports_park(&self) -> bool;

    /// Test-only: post a completion with `user_data` and `result` as if an
    /// operation had completed. With `linked`, the next operation pushed is
    /// linked to it. Below Linux 6.10 only the next `inject` is, and a chain
    /// must end in an unlinked entry in the same submission.
    #[cfg(test)]
    fn inject(&mut self, user_data: u64, result: i32, linked: bool) -> io::Result<()>;

    /// Test-only: make the next `count` calls to `push`, `push_pair` or, from
    /// Linux 6.10, `inject` fail as if the queue were still full after a
    /// submit; `push_chain` is not affected.
    #[cfg(test)]
    fn force_push_failures(&mut self, count: usize);

    /// Test-only: make the next `count` enters that have SQEs to submit fail
    /// with `EAGAIN` and leave the SQEs queued, as the kernel does when it
    /// cannot allocate a request.
    #[cfg(test)]
    fn force_enter_eagain(&mut self, count: usize);
}
