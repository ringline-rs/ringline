//! Signal handling for graceful shutdown.
//!
//! Provides [`wait()`] to block the current thread until `SIGINT` or
//! `SIGTERM` is received. Typically used with
//! [`Runtime::wait_on_signal()`](crate::worker::Runtime::wait_on_signal)
//! for one-line graceful shutdown.
//!
//! # Implementation
//!
//! Uses the self-pipe trick: a `pipe2` fd pair is created once, and
//! `sigaction` handlers write the signal number to the pipe. [`wait()`]
//! does a blocking `read()` on the pipe read end.
//!
//! # Example
//!
//! ```rust,no_run
//! use ringline::{Config, RinglineBuilder};
//! # struct H;
//! # impl ringline::AsyncEventHandler for H {
//! #     fn on_accept(&self, _: ringline::Connection) -> impl std::future::Future<Output = ()> + 'static { async {} }
//! #     fn create_for_worker(_: usize) -> Self { H }
//! # }
//!
//! let (runtime, handles) = RinglineBuilder::new(Config::default())
//!     .bind("127.0.0.1:8080".parse().unwrap())
//!     .launch::<H>()
//!     .unwrap();
//!
//! // Block until Ctrl-C or kill, then shut down gracefully.
//! runtime.wait_on_signal();
//! for h in handles {
//!     h.join().unwrap().unwrap();
//! }
//! ```

use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};

/// Pipe file descriptors: (read_end, write_end).
static PIPE: OnceLock<(i32, i32)> = OnceLock::new();

/// Write end fd, also stored in an atomic for the signal handler
/// (OnceLock is not async-signal-safe, but AtomicI32 load is).
static PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

/// A caught signal, or the reason [`Runtime::wait_on_signal`](crate::Runtime::wait_on_signal)
/// returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signal {
    /// `SIGINT` — typically sent by Ctrl-C.
    Interrupt,
    /// `SIGTERM` — the default `kill` signal.
    Terminate,
    /// Not an OS signal: a task panicked under
    /// [`TaskPanicPolicy::Shutdown`](crate::TaskPanicPolicy::Shutdown) and shut
    /// the runtime down. Returned only by
    /// [`Runtime::wait_on_signal`](crate::Runtime::wait_on_signal).
    TaskPanic,
    /// Not an OS signal: a worker stopped because of a panic in the runtime or
    /// an error from its ring or poll, and its connections are closing. Returned
    /// only by [`Runtime::wait_on_signal`](crate::Runtime::wait_on_signal),
    /// which then shuts the runtime down, so a supervisor can restart the
    /// process.
    WorkerExited,
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signal::Interrupt => f.write_str("SIGINT"),
            Signal::Terminate => f.write_str("SIGTERM"),
            Signal::TaskPanic => f.write_str("task panic"),
            Signal::WorkerExited => f.write_str("worker exited"),
        }
    }
}

/// Install signal handlers and create the self-pipe. Idempotent.
fn setup() {
    PIPE.get_or_init(|| {
        let mut fds = [0i32; 2];

        // Create pipe with close-on-exec. Both ends are set non-blocking
        // below: the signal handler must never block on a write, and several
        // waiters may poll the read end, so the one that loses the race for a
        // byte must get EAGAIN rather than block in read(2).
        #[cfg(target_os = "linux")]
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        #[cfg(not(target_os = "linux"))]
        let ret = unsafe {
            let r = libc::pipe(fds.as_mut_ptr());
            if r == 0 {
                // Set close-on-exec on both ends.
                for fd in &fds {
                    let fd_flags = libc::fcntl(*fd, libc::F_GETFD);
                    libc::fcntl(*fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC);
                }
            }
            r
        };
        assert!(ret == 0, "pipe failed: {}", std::io::Error::last_os_error());

        for fd in fds {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }

        // Publish write fd for the signal handler.
        PIPE_WRITE_FD.store(fds[1], Ordering::Release);

        // Install sigaction for SIGINT and SIGTERM.
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = signal_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        unsafe { libc::sigemptyset(&mut sa.sa_mask) };

        unsafe {
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        }

        (fds[0], fds[1])
    });
}

/// Async-signal-safe handler: writes the signal number to the pipe.
extern "C" fn signal_handler(sig: libc::c_int) {
    let fd = PIPE_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = sig as u8;
        unsafe {
            libc::write(fd, &byte as *const u8 as *const libc::c_void, 1);
        }
    }
}

/// Block the current thread until `SIGINT` or `SIGTERM` is received.
///
/// Installs signal handlers on first call (idempotent). Returns which
/// signal was caught.
///
/// This is a blocking call intended for use on the main thread.
pub fn wait() -> Signal {
    loop {
        if let Some(signal) = wait_inner(None) {
            return signal;
        }
    }
}

/// Block until `SIGINT` or `SIGTERM` is received or one of the runtime's fds
/// becomes readable: `panic_fd` returns [`Signal::TaskPanic`], and `exit_fd`
/// returns [`Signal::WorkerExited`].
pub(crate) fn wait_or_ready(panic_fd: i32, exit_fd: i32) -> Signal {
    loop {
        if let Some(signal) = wait_inner(Some((panic_fd, exit_fd))) {
            return signal;
        }
    }
}

/// Poll the signal pipe, and the runtime's panic and worker-exit fds if given,
/// until one is readable. Returns `None` when another waiter took the signal
/// byte first.
fn wait_inner(runtime_fds: Option<(i32, i32)>) -> Option<Signal> {
    setup();

    let (read_fd, _) = *PIPE.get().unwrap();
    let mut fds = [
        libc::pollfd {
            fd: read_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: runtime_fds.map_or(-1, |(panic_fd, _)| panic_fd),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: runtime_fds.map_or(-1, |(_, exit_fd)| exit_fd),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let count = if runtime_fds.is_some() { 3 } else { 1 };
    // EINTR: interrupted by a signal we don't handle — poll again.
    while unsafe { libc::poll(fds.as_mut_ptr(), count, -1) } <= 0 {}
    if count == 3 && fds[1].revents != 0 {
        return Some(Signal::TaskPanic);
    }
    if count == 3 && fds[2].revents != 0 {
        return Some(Signal::WorkerExited);
    }
    // The pipe is process-global and never closed by ringline; an invalid or
    // broken read end would make every later poll return at once.
    assert!(
        fds[0].revents & (libc::POLLNVAL | libc::POLLERR) == 0,
        "ringline signal pipe is invalid (revents {:#x})",
        fds[0].revents
    );
    if fds[0].revents & libc::POLLIN != 0 {
        let mut buf = [0u8; 1];
        // Non-blocking: another waiter may have taken the byte (EAGAIN).
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        if n == 1 {
            return Some(match buf[0] as i32 {
                libc::SIGTERM => Signal::Terminate,
                _ => Signal::Interrupt,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_display() {
        assert_eq!(Signal::Interrupt.to_string(), "SIGINT");
        assert_eq!(Signal::Terminate.to_string(), "SIGTERM");
    }

    #[test]
    fn setup_is_idempotent() {
        setup();
        let pipe1 = *PIPE.get().unwrap();
        setup();
        let pipe2 = *PIPE.get().unwrap();
        assert_eq!(pipe1, pipe2);
    }

    #[test]
    fn manual_pipe_write_triggers_wait() {
        setup();
        let (_, write_fd) = *PIPE.get().unwrap();

        // Simulate a SIGTERM by writing directly to the pipe.
        let byte = libc::SIGTERM as u8;
        let n = unsafe { libc::write(write_fd, &byte as *const u8 as *const libc::c_void, 1) };
        assert_eq!(n, 1);

        let sig = wait();
        assert_eq!(sig, Signal::Terminate);
    }
}
