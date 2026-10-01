//! Cross-platform worker wakeup mechanism.
//!
//! With io_uring: uses `eventfd(2)` — a single fd that the event loop polls via
//! `IORING_OP_READ`. Writing 8 bytes wakes the worker.
//!
//! Without io_uring (mio backend): uses a `pipe(2)` pair. The read end is
//! registered with `mio::Poll`; writing 1 byte wakes the worker.

use std::io;
use std::os::fd::RawFd;
use std::sync::Arc;

/// Internal fd carrier used on hot paths inside the runtime.
///
/// Cheap to copy; does not own the fd. The fd is owned by the
/// [`Arc<WakeFdInner>`] held inside [`WakeHandle`]. A `WakeFd` must not be
/// used after the last `WakeHandle` clone drops, so every thread `launch()`
/// starts that carries one also holds owning handles (a [`WakeKeepAlive`], or
/// the acceptor's per-worker `WakeHandle`s) for as long as it runs.
#[derive(Clone, Copy)]
pub(crate) struct WakeFd {
    fd: RawFd,
}

impl WakeFd {
    /// Wrap a raw file descriptor as a non-owning fd carrier. Only valid
    /// for fds that accept writes (io_uring's eventfd is bidirectional; the
    /// mio backend's pipe read end is NOT — its driver receives the write
    /// end explicitly).
    #[cfg(has_io_uring)]
    pub(crate) fn from_raw_fd(fd: RawFd) -> Self {
        WakeFd { fd }
    }

    /// Return the underlying file descriptor.
    #[allow(dead_code)]
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Wake the worker by writing to the underlying fd.
    pub(crate) fn wake(&self) {
        wake_fd(self.fd);
    }
}

/// Owns the wake fd; closes it on drop.
///
/// On mio it also owns the pipe's read end, which the worker polls but does
/// not close. A write to a pipe whose read end has closed raises SIGPIPE, which
/// kills a process whose SIGPIPE disposition is `SIG_DFL`. With both ends owned
/// here, a write after the worker has exited goes into the pipe buffer, or
/// fails with `EAGAIN` once the buffer is full.
struct WakeFdInner {
    fd: RawFd,
    #[cfg(not(has_io_uring))]
    read_fd: RawFd,
}

impl Drop for WakeFdInner {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
            #[cfg(not(has_io_uring))]
            libc::close(self.read_fd);
        }
    }
}

/// Refcounted handle for waking a worker thread from any thread.
///
/// Returned by [`crate::Runtime::worker_wake_handle`]. Cloning is cheap
/// (an atomic refcount bump) and the underlying fd stays open until the last
/// clone is dropped, so it is safe to keep clones around past
/// [`crate::Runtime`] drop — the writes simply land in an fd nobody is
/// reading anymore.
///
/// Typical use is to deliver a response on a crossbeam channel and then call
/// [`wake`](Self::wake) so the target worker observes the channel without
/// waiting on its idle timeout.
#[derive(Clone)]
pub struct WakeHandle {
    inner: Arc<WakeFdInner>,
}

impl WakeHandle {
    /// Wake the associated worker.
    ///
    /// Non-blocking and never reports an error. If the pipe or eventfd is full
    /// the write fails with `EAGAIN`, and a wake is already pending.
    pub fn wake(&self) {
        wake_fd(self.inner.fd);
    }

    /// Extract a non-owning [`WakeFd`] carrier for use on hot paths.
    pub(crate) fn as_wake_fd(&self) -> WakeFd {
        WakeFd { fd: self.inner.fd }
    }
}

fn wake_fd(fd: RawFd) {
    #[cfg(has_io_uring)]
    {
        // eventfd expects exactly 8 bytes (a u64).
        let val: u64 = 1;
        unsafe {
            libc::write(fd, &val as *const u64 as *const libc::c_void, 8);
        }
    }
    #[cfg(not(has_io_uring))]
    {
        // pipe expects any non-zero write; 1 byte suffices.
        let val: u8 = 1;
        unsafe {
            libc::write(fd, &val as *const u8 as *const libc::c_void, 1);
        }
    }
}

/// Create a per-worker wake fd.
///
/// With io_uring: creates an `eventfd(2)`.
/// Without io_uring: creates a `pipe(2)` and returns `(read_fd, WakeHandle)`;
/// `WakeHandle` writes to the write end and owns both ends.
#[cfg(has_io_uring)]
pub(crate) fn create_wake_fd() -> io::Result<(RawFd, WakeHandle)> {
    let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if efd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        efd,
        WakeHandle {
            inner: Arc::new(WakeFdInner { fd: efd }),
        },
    ))
}

/// Owning clones of every worker's wake handle, held by each pool and worker
/// thread.
///
/// A thread holding one keeps every worker's wake fd open, so the [`WakeFd`]s
/// it carries stay valid for as long as it runs, including after the
/// `Runtime` has dropped. Cloned when a thread starts, never per request.
pub(crate) type WakeKeepAlive = Arc<[WakeHandle]>;

/// Create a per-worker wake fd pair (pipe).
///
/// Returns `(read_fd, WakeHandle)`. `read_fd` is registered with the poller
/// and is not owned by the caller; `WakeHandle` writes to the write end and
/// owns both ends.
#[cfg(not(has_io_uring))]
pub(crate) fn create_wake_fd() -> io::Result<(RawFd, WakeHandle)> {
    let mut fds = [0i32; 2];
    // Both ends non-blocking and close-on-exec. On Linux `pipe2` sets the
    // flags atomically, so a child spawned on another thread cannot inherit
    // the pipe; elsewhere they are set after `pipe`.
    #[cfg(target_os = "linux")]
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(not(target_os = "linux"))]
    {
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        for fd in &fds {
            unsafe {
                let flags = libc::fcntl(*fd, libc::F_GETFL);
                libc::fcntl(*fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                let fd_flags = libc::fcntl(*fd, libc::F_GETFD);
                libc::fcntl(*fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC);
            }
        }
    }
    let read_fd = fds[0];
    let write_fd = fds[1];

    Ok((
        read_fd,
        WakeHandle {
            inner: Arc::new(WakeFdInner {
                fd: write_fd,
                read_fd,
            }),
        },
    ))
}
