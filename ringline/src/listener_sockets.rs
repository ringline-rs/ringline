//! The sockets of one bound listener, shared by everything that uses them.
//!
//! `launch()` creates one [`ListenerSockets`] per `bind*()` call. Until
//! shutdown, `RuntimeShutdown` and the listen gates each hold an `Arc` of it;
//! the listener's acceptor thread (pool mode) or every worker (merged mode)
//! holds one until it exits. The `Runtime` holds a `Weak`. An fd number stays
//! valid for as long as anything that passes it to a syscall holds the `Arc`.
//!
//! Shutdown does not close the sockets. [`ListenerSockets::shut_down`] stops
//! them accepting (except a socket from `RinglineBuilder::bind_fd`, which
//! stays listening), `RuntimeShutdown` and the gates drop their `Arc`s, and
//! the sockets close when the threads accepting on them exit.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;

/// One listener's sockets: one in pool mode, one `SO_REUSEPORT` socket per
/// worker in merged mode, where the worker at index `i` accepts on socket `i`.
pub(crate) struct ListenerSockets {
    fds: Vec<OwnedFd>,
    /// The socket came from `RinglineBuilder::bind_fd`: other processes may
    /// hold it, so `shut_down` leaves it listening.
    from_fd: bool,
}

impl ListenerSockets {
    pub(crate) fn new(fds: Vec<OwnedFd>) -> Arc<Self> {
        Arc::new(ListenerSockets {
            fds,
            from_fd: false,
        })
    }

    /// The one socket of a listener from `RinglineBuilder::bind_fd`.
    pub(crate) fn from_fd(fd: OwnedFd) -> Arc<Self> {
        Arc::new(ListenerSockets {
            fds: vec![fd],
            from_fd: true,
        })
    }

    /// The fd of socket `i`. Valid for as long as `self` is.
    ///
    /// # Panics
    ///
    /// If `i` is out of range.
    pub(crate) fn fd(&self, i: usize) -> RawFd {
        self.fds[i].as_raw_fd()
    }

    /// Every socket's fd, in order.
    pub(crate) fn fds(&self) -> impl Iterator<Item = RawFd> + '_ {
        self.fds.iter().map(AsRawFd::as_raw_fd)
    }

    /// Stop every socket accepting connections, leaving the fds open, except a
    /// socket from `RinglineBuilder::bind_fd`, which is left listening.
    /// Idempotent.
    ///
    /// On Linux `shutdown(SHUT_RD)` on a listening socket fails a multishot
    /// accept armed on it and takes the socket out of the listening state.
    /// The acceptor thread does not depend on it: it waits in `poll` on the
    /// runtime's stop signal (`crate::acceptor::StopSignal`).
    ///
    /// `SO_REUSEADDR` is set first. `SHUT_RD` does nothing to a socket that
    /// never listened, such as a deferred listener that was never opened, so
    /// until its holders exit and it closes, a new socket can bind its port
    /// only if both have `SO_REUSEADDR` set. A listening socket already has
    /// it.
    ///
    /// Call it after [`ListenGates::shutdown`](crate::listen_gate::ListenGates::shutdown),
    /// which stops the gates calling `listen(2)`: a socket that starts
    /// listening after its `SHUT_RD` keeps accepting.
    ///
    /// Does nothing to a socket from `RinglineBuilder::bind_fd`. `SHUT_RD`
    /// would take it out of the listening state for every process holding
    /// it, such as systemd holding it in the fd store, and reset the
    /// connections in its backlog. Its acceptor exits on the runtime's stop
    /// signal instead.
    pub(crate) fn shut_down(&self) {
        if self.from_fd {
            return;
        }
        let reuse: libc::c_int = 1;
        for fd in self.fds() {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &reuse as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                libc::shutdown(fd, libc::SHUT_RD);
            }
        }
    }
}
