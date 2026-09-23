use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crossbeam_channel::Sender;

/// One accepted connection on its way to a worker.
///
/// A struct rather than a tuple: this grew from `(RawFd, SocketAddr)` to carry
/// a real `PeerAddr` (#445) and now a `ListenerId`, and positional fields stop
/// paying their way at three.
pub struct AcceptedConn {
    pub fd: RawFd,
    pub listener: crate::ListenerId,
    pub peer: crate::connection::PeerAddr,
}

/// Configuration for one acceptor thread.
pub struct AcceptorConfig {
    /// The listening socket fd.
    pub listen_fd: RawFd,
    /// Which listener this acceptor serves. Travels with every accepted fd so
    /// the handler can tell connections from different listeners apart.
    pub listener: crate::ListenerId,
    /// Per-worker channels to send accepted (fd, peer_addr) pairs.
    pub worker_channels: Vec<Sender<AcceptedConn>>,
    /// Per-worker wake handles to wake the event loop after sending a connection.
    pub worker_wake_handles: Vec<crate::wakeup::WakeFd>,
    /// Shared flag set by ShutdownHandle to signal the acceptor to stop.
    #[allow(dead_code)] // stored for future use; acceptor currently uses channel disconnect
    pub shutdown_flag: Arc<AtomicBool>,
    /// Whether to set TCP_NODELAY on accepted connections.
    pub tcp_nodelay: bool,
    /// Connections to assign to each worker before moving to the next.
    /// 1 = round-robin. See [`ConfigBuilder::conn_chunk_size`](crate::ConfigBuilder::conn_chunk_size).
    pub conn_chunk_size: usize,
    /// Whether to set SO_TIMESTAMPING on accepted connections.
    #[cfg(feature = "timestamps")]
    pub timestamps: bool,
}

/// Apply the per-connection socket options an accepted fd needs.
///
/// Shared by both accept paths. It used to live inline in the acceptor loop,
/// which meant merged accept mode — which has no acceptor thread — applied
/// none of them: `ConfigBuilder::tcp_nodelay(true)` was accepted, documented
/// and ignored there. Nagle on a TLS handshake's small writes then met the
/// client's 40 ms delayed ACK, and merged mode measured 29x slower than the
/// pool with its workers idle (#460).
///
/// One function, called from both paths, so the two cannot drift again.
pub(crate) fn apply_accepted_sockopts(
    fd: RawFd,
    nodelay: bool,
    #[cfg(feature = "timestamps")] timestamps: bool,
) {
    if nodelay {
        let optval: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    // Kernel-level RX timestamps (Linux only).
    #[cfg(all(target_os = "linux", feature = "timestamps"))]
    if timestamps {
        let flags: libc::c_int =
            (libc::SOF_TIMESTAMPING_SOFTWARE | libc::SOF_TIMESTAMPING_RX_SOFTWARE) as libc::c_int;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                &flags as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

/// Run one listener's acceptor loop. Terminates when all channels disconnect.
///
/// Accepts connections via blocking `accept4` and distributes raw fds
/// to workers round-robin, waking each worker via eventfd. One of these runs
/// per listener; they share the worker channels, so accepts from different
/// listeners interleave and each carries its own `ListenerId`.
pub fn run_acceptor(config: AcceptorConfig) {
    let num_workers = config.worker_channels.len();
    if num_workers == 0 {
        return;
    }

    let chunk_size = config.conn_chunk_size.max(1);
    let mut conn_count = 0usize; // successfully dispatched connections
    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut alive = vec![true; num_workers];
    let mut alive_count = num_workers;

    loop {
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let fd = accept_nonblock(config.listen_fd, &mut addr_storage, &mut addr_len);

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EMFILE) | Some(libc::ENFILE) => {
                    // Too many open files — back off briefly.
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Some(libc::ECONNABORTED) | Some(libc::ECONNRESET) | Some(libc::EPERM) => {
                    // Connection reset before accept completed, or blocked by
                    // firewall — retry immediately.
                    continue;
                }
                _ => {
                    // Fatal accept error or listen fd closed.
                    return;
                }
            }
        }

        let is_unix = addr_storage.ss_family == libc::AF_UNIX as libc::sa_family_t;
        apply_accepted_sockopts(
            fd,
            config.tcp_nodelay && !is_unix,
            #[cfg(feature = "timestamps")]
            config.timestamps,
        );

        // Parse peer address from the sockaddr_storage filled by accept4.
        // A Unix accept has no `SocketAddr` — its peer is normally unnamed, so
        // the kernel returns family-only and `sockaddr_to_peer_addr` yields
        // `Unix("")`. Substituting a `SocketAddr` here is how an accepted Unix
        // connection used to reach the handler as `Tcp(0.0.0.0:0)`.
        //
        // The fallback covers only address families the helper does not know;
        // AF_INET, AF_INET6 and AF_UNIX all resolve above.
        let peer_addr = crate::backend::sockaddr::sockaddr_to_peer_addr(&addr_storage, addr_len)
            .unwrap_or_else(|| {
                crate::connection::PeerAddr::Tcp(SocketAddr::from(([0, 0, 0, 0], 0)))
            });

        // Pick a target worker based on chunk assignment, then fall back to
        // adjacent workers if that worker's channel is full or it has exited.
        // `try_send` lets us distinguish a full queue (skip) from a
        // disconnected channel (mark dead). Closing the fd when all workers
        // are full or dead lets the kernel deliver a clean connection-refused
        // to the peer instead of growing an unbounded backlog in the channel.
        let primary = (conn_count / chunk_size) % num_workers;
        let mut sent = false;
        for i in 0..num_workers {
            let worker_idx = (primary + i) % num_workers;

            if !alive[worker_idx] {
                continue;
            }

            let accepted = AcceptedConn {
                fd,
                listener: config.listener,
                peer: peer_addr.clone(),
            };
            match config.worker_channels[worker_idx].try_send(accepted) {
                Ok(()) => {
                    config.worker_wake_handles[worker_idx].wake();
                    conn_count = conn_count.wrapping_add(1);
                    sent = true;
                    break;
                }
                Err(crossbeam_channel::TrySendError::Full(_)) => {
                    // Worker is backlogged — try the next one.
                    continue;
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                    // Worker has exited — mark dead.
                    alive[worker_idx] = false;
                    alive_count -= 1;
                    if alive_count == 0 {
                        unsafe {
                            libc::close(fd);
                        }
                        return;
                    }
                    continue;
                }
            }
        }

        if !sent {
            // Every live worker is backlogged. Drop the connection rather
            // than block the acceptor, and keep accepting — the backlog is
            // transient. (The all-workers-dead case returns above.)
            unsafe {
                libc::close(fd);
            }
            continue;
        }
    }
}

/// Accept a connection and set the **returned** fd to non-blocking +
/// close-on-exec. The call itself blocks on the listen socket until a
/// connection arrives — only the resulting accepted fd is non-blocking.
///
/// On Linux, uses `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)` for a single
/// syscall. On other platforms, falls back to `accept()` + `fcntl()`.
///
/// Because this blocks, the acceptor thread is unblocked at shutdown by
/// `shutdown(fd, SHUT_RD)` on the listen socket, which makes a blocked
/// (or subsequent) `accept4` fail with `EINVAL` on Linux. (Closing the fd
/// alone does NOT wake a blocked accept — the in-progress syscall holds a
/// file reference.) On non-Linux platforms the wake is best-effort; a
/// quiet listener's acceptor thread may persist until a peer connects.
fn accept_nonblock(
    listen_fd: libc::c_int,
    addr: &mut libc::sockaddr_storage,
    addr_len: &mut libc::socklen_t,
) -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            libc::accept4(
                listen_fd,
                addr as *mut _ as *mut libc::sockaddr,
                addr_len,
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let fd =
            unsafe { libc::accept(listen_fd, addr as *mut _ as *mut libc::sockaddr, addr_len) };
        if fd >= 0 {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                let fd_flags = libc::fcntl(fd, libc::F_GETFD);
                libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC);
            }
        }
        fd
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// The option is actually applied, not merely requested.
    ///
    /// This covers the helper, which is what both accept paths call. It does
    /// not prove the merged path calls it — the accepted fd is closed right
    /// after `register_files_update` hands it to io_uring's fixed-file table,
    /// so no test can read the option back off a live accepted connection.
    /// That half is covered by the connect-rate measurement on the rack
    /// (#460), where the symptom is a 29x throughput difference.
    #[test]
    fn nodelay_is_set_when_asked() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");

        // Start from the opposite state, so a no-op helper cannot pass.
        let off: libc::c_int = 0;
        unsafe {
            libc::setsockopt(
                accepted.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &off as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        assert_eq!(read_nodelay(accepted.as_raw_fd()), 0, "precondition");

        apply_accepted_sockopts(
            accepted.as_raw_fd(),
            true,
            #[cfg(feature = "timestamps")]
            false,
        );
        // Non-zero, not `== 1`: Linux reports 1, macOS reports the internal
        // TF_NODELAY flag bits (4). The contract is on-versus-off.
        assert_ne!(
            read_nodelay(accepted.as_raw_fd()),
            0,
            "TCP_NODELAY should be on"
        );
        drop(client);
    }

    #[test]
    fn nodelay_is_left_alone_when_not_asked() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");

        let off: libc::c_int = 0;
        unsafe {
            libc::setsockopt(
                accepted.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &off as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        apply_accepted_sockopts(
            accepted.as_raw_fd(),
            false,
            #[cfg(feature = "timestamps")]
            false,
        );
        assert_eq!(read_nodelay(accepted.as_raw_fd()), 0);
        drop(client);
    }

    /// Zero means off; any non-zero means on (the value differs by platform).
    fn read_nodelay(fd: RawFd) -> libc::c_int {
        let mut val: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt failed");
        val
    }
}
