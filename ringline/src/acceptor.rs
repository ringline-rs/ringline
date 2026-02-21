use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crossbeam_channel::Sender;

/// Configuration for the centralized acceptor thread.
#[allow(dead_code)]
pub struct AcceptorConfig {
    /// The listening socket fd.
    pub listen_fd: RawFd,
    /// Per-worker channels to send accepted (fd, peer_addr) pairs.
    pub worker_channels: Vec<Sender<(RawFd, SocketAddr)>>,
    /// Per-worker eventfds to wake io_uring.
    pub worker_eventfds: Vec<RawFd>,
    /// Shared flag set by ShutdownHandle to signal the acceptor to stop.
    pub shutdown_flag: Arc<AtomicBool>,
    /// Whether to set TCP_NODELAY on accepted connections.
    pub tcp_nodelay: bool,
    /// Whether to set SO_TIMESTAMPING on accepted connections.
    #[cfg(feature = "timestamps")]
    pub timestamps: bool,
}

/// Run the acceptor loop. Terminates when all channels disconnect.
///
/// Accepts connections via blocking `accept4` and distributes raw fds
/// to workers round-robin, waking each worker via eventfd.
pub fn run_acceptor(config: AcceptorConfig) {
    let num_workers = config.worker_channels.len();
    if num_workers == 0 {
        return;
    }

    let mut next_worker = 0usize;
    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut alive = vec![true; num_workers];
    let mut alive_count = num_workers;

    loop {
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let fd = unsafe {
            libc::accept4(
                config.listen_fd,
                &mut addr_storage as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EMFILE) | Some(libc::ENFILE) => {
                    // Too many open files — back off briefly.
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                _ => {
                    // Fatal accept error or listen fd closed.
                    return;
                }
            }
        }

        // Set TCP_NODELAY if configured.
        if config.tcp_nodelay {
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

        // Set SO_TIMESTAMPING for kernel-level RX timestamps.
        #[cfg(feature = "timestamps")]
        if config.timestamps {
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

        // Parse peer address from the sockaddr_storage filled by accept4.
        let peer_addr = sockaddr_to_socket_addr(&addr_storage)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

        // Round-robin pick a live worker. Try up to num_workers times.
        let mut sent = false;
        for _ in 0..num_workers {
            let worker_idx = next_worker % num_workers;
            next_worker = next_worker.wrapping_add(1);

            if !alive[worker_idx] {
                continue;
            }

            if config.worker_channels[worker_idx]
                .send((fd, peer_addr))
                .is_err()
            {
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

            // Wake the worker's io_uring via eventfd.
            let val: u64 = 1;
            unsafe {
                libc::write(
                    config.worker_eventfds[worker_idx],
                    &val as *const u64 as *const libc::c_void,
                    8,
                );
            }
            sent = true;
            break;
        }

        if !sent {
            // All workers dead.
            unsafe {
                libc::close(fd);
            }
            return;
        }
    }
}

/// Convert a `sockaddr_storage` (from accept4) to a Rust `SocketAddr`.
fn sockaddr_to_socket_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sa = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            Some(SocketAddr::from((ip, port)))
        }
        libc::AF_INET6 => {
            let sa = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            Some(SocketAddr::from((ip, port)))
        }
        _ => None,
    }
}
