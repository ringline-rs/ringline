//! Cross-platform worker wakeup mechanism.
//!
//! With io_uring: uses `eventfd(2)` — a single fd that the event loop polls via
//! `IORING_OP_READ`. Writing 8 bytes wakes the worker.
//!
//! Without io_uring (mio backend): uses a `pipe(2)` pair. The read end is
//! registered with `mio::Poll`; writing 1 byte wakes the worker.

use std::io;
use std::os::fd::RawFd;

/// A handle for waking a worker thread from another thread.
///
/// Created per-worker during startup. Cloned into the acceptor, resolver,
/// spawner, and blocking pool threads so they can wake the owning worker
/// after delivering a response on its crossbeam channel.
#[derive(Clone, Copy)]
pub(crate) struct WakeHandle {
    fd: RawFd,
}

impl WakeHandle {
    /// Wrap a raw file descriptor (eventfd or pipe write-end) as a wake handle.
    pub(crate) fn from_raw_fd(fd: RawFd) -> Self {
        WakeHandle { fd }
    }

    /// Return the underlying file descriptor.
    #[allow(dead_code)]
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Wake the worker by writing to the underlying fd.
    pub(crate) fn wake(&self) {
        #[cfg(has_io_uring)]
        {
            // eventfd expects exactly 8 bytes (a u64).
            let val: u64 = 1;
            unsafe {
                libc::write(self.fd, &val as *const u64 as *const libc::c_void, 8);
            }
        }
        #[cfg(not(has_io_uring))]
        {
            // pipe expects any non-zero write; 1 byte suffices.
            let val: u8 = 1;
            unsafe {
                libc::write(self.fd, &val as *const u8 as *const libc::c_void, 1);
            }
        }
    }
}

/// Create a per-worker wake fd.
///
/// With io_uring: creates an `eventfd(2)`.
/// Without io_uring: creates a `pipe(2)` and returns `(read_fd, WakeHandle)`.
#[cfg(has_io_uring)]
pub(crate) fn create_wake_fd() -> io::Result<(RawFd, WakeHandle)> {
    let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if efd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((efd, WakeHandle::from_raw_fd(efd)))
}

/// Create a per-worker wake fd pair (pipe).
///
/// Returns `(read_fd, WakeHandle)` where `read_fd` is registered with the
/// poller and `WakeHandle` wraps the write end for cross-thread waking.
#[cfg(not(has_io_uring))]
pub(crate) fn create_wake_fd() -> io::Result<(RawFd, WakeHandle)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let read_fd = fds[0];
    let write_fd = fds[1];

    // Set both ends non-blocking and close-on-exec.
    for fd in &fds {
        unsafe {
            let flags = libc::fcntl(*fd, libc::F_GETFL);
            libc::fcntl(*fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            let fd_flags = libc::fcntl(*fd, libc::F_GETFD);
            libc::fcntl(*fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC);
        }
    }

    Ok((read_fd, WakeHandle::from_raw_fd(write_fd)))
}
