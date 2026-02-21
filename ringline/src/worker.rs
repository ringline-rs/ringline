use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::acceptor::{AcceptorConfig, run_acceptor};
use crate::async_event_loop::AsyncEventLoop;
use crate::config::Config;
use crate::runtime::handler::AsyncEventHandler;

/// Result type for `launch` / `RinglineBuilder::launch` to avoid type-complexity warnings.
type LaunchResult = Result<
    (
        ShutdownHandle,
        Vec<thread::JoinHandle<Result<(), crate::error::Error>>>,
    ),
    crate::error::Error,
>;

/// Handle returned by `launch()` to trigger graceful shutdown of all workers.
pub struct ShutdownHandle {
    shutdown_flag: Arc<AtomicBool>,
    worker_eventfds: Vec<RawFd>,
    listen_fd: Option<RawFd>,
    listen_fd_closed: Option<Arc<AtomicBool>>,
}

impl ShutdownHandle {
    /// Returns the per-worker eventfd file descriptors.
    /// External threads can write to these to wake specific workers.
    pub fn worker_eventfds(&self) -> &[RawFd] {
        &self.worker_eventfds
    }

    /// Signal all workers to shut down gracefully.
    ///
    /// Workers will stop accepting new connections, close all active connections,
    /// drain remaining CQEs, and exit their event loops returning `Ok(())`.
    /// Also closes the listen fd to unblock the acceptor's `accept4`.
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
        // Close listen_fd to unblock the acceptor thread's accept4() call.
        if let (Some(fd), Some(closed)) = (self.listen_fd, &self.listen_fd_closed)
            && !closed.swap(true, Ordering::AcqRel)
        {
            unsafe {
                libc::close(fd);
            }
        }
        // Wake all workers so they see the flag even if blocked in submit_and_wait.
        for &efd in &self.worker_eventfds {
            let val: u64 = 1;
            unsafe {
                libc::write(efd, &val as *const u64 as *const libc::c_void, 8);
            }
        }
    }
}

/// Builder for launching ringline workers with optional listener/acceptor.
///
/// Create a builder with [`RinglineBuilder::new(config)`](Self::new), optionally
/// call [`.bind(addr)`](Self::bind) to listen for inbound connections, then
/// call [`.launch::<Handler>()`](Self::launch) to start the worker threads.
///
/// If no bind address is set, ringline runs in client-only mode: no TCP
/// listener or acceptor thread is created, and workers can initiate outbound
/// connections via [`AsyncEventHandler::on_start`].
pub struct RinglineBuilder {
    config: Config,
    bind_addr: Option<SocketAddr>,
}

impl RinglineBuilder {
    /// Create a new builder with the given config.
    pub fn new(config: Config) -> Self {
        RinglineBuilder {
            config,
            bind_addr: None,
        }
    }

    /// Set the bind address for the TCP listener. If not set, no listener
    /// or acceptor thread is created (client-only mode).
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Bind a UDP socket on each worker (with `SO_REUSEPORT`).
    ///
    /// Can be called multiple times to bind multiple UDP addresses.
    /// Each worker creates its own socket per address.
    pub fn bind_udp(mut self, addr: SocketAddr) -> Self {
        self.config.udp_bind.push(addr);
        self
    }

    /// Launch worker threads with the async `AsyncEventHandler`.
    ///
    /// Each accepted connection gets a long-lived async task. The executor
    /// polls futures on the same thread-per-core model.
    pub fn launch<A: AsyncEventHandler>(self) -> LaunchResult {
        self.launch_inner(|worker_id, config, accept_rx, eventfd, shutdown_flag| {
            let handler = A::create_for_worker(worker_id);
            let mut event_loop =
                AsyncEventLoop::new(&config, handler, accept_rx, eventfd, shutdown_flag)?;
            event_loop.run()?;
            Ok(())
        })
    }

    /// Common infrastructure setup for launch.
    #[allow(clippy::needless_range_loop)]
    fn launch_inner<F>(self, worker_fn: F) -> LaunchResult
    where
        F: Fn(
                usize,
                Config,
                Option<crossbeam_channel::Receiver<(RawFd, SocketAddr)>>,
                RawFd,
                Arc<AtomicBool>,
            ) -> Result<(), crate::error::Error>
            + Send
            + Clone
            + 'static,
    {
        let num_threads = if self.config.worker.threads == 0 {
            num_cpus()
        } else {
            self.config.worker.threads
        };

        ensure_nofile_limit(self.config.max_connections, num_threads)?;

        // Create per-worker channels and eventfds.
        let mut worker_txs = Vec::with_capacity(num_threads);
        let mut worker_rxs = Vec::with_capacity(num_threads);
        let mut worker_eventfds = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let (tx, rx) = crossbeam_channel::unbounded::<(RawFd, SocketAddr)>();
            let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
            if efd < 0 {
                for &fd in &worker_eventfds {
                    unsafe {
                        libc::close(fd);
                    }
                }
                return Err(crate::error::Error::Io(io::Error::last_os_error()));
            }
            worker_txs.push(tx);
            worker_rxs.push(rx);
            worker_eventfds.push(efd);
        }

        let shutdown_flag = Arc::new(AtomicBool::new(false));

        // Optionally create listener + acceptor.
        let (listen_fd, listen_fd_closed) = if let Some(addr) = self.bind_addr {
            let fd = create_listener(addr, self.config.backlog)?;
            let closed = Arc::new(AtomicBool::new(false));

            let acceptor_config = AcceptorConfig {
                listen_fd: fd,
                worker_channels: worker_txs,
                worker_eventfds: worker_eventfds.clone(),
                shutdown_flag: shutdown_flag.clone(),
                tcp_nodelay: self.config.tcp_nodelay,
                #[cfg(feature = "timestamps")]
                timestamps: self.config.timestamps,
            };

            let acceptor_closed = closed.clone();
            thread::Builder::new()
                .name("ringline-acceptor".to_string())
                .spawn(move || {
                    run_acceptor(acceptor_config);
                    if !acceptor_closed.swap(true, Ordering::AcqRel) {
                        unsafe {
                            libc::close(fd);
                        }
                    }
                })
                .map_err(crate::error::Error::Io)?;

            (Some(fd), Some(closed))
        } else {
            // Client-only mode — drop txs so workers don't expect accept data.
            drop(worker_txs);
            (None, None)
        };

        // Spawn worker threads.
        let mut handles = Vec::with_capacity(num_threads);
        let has_acceptor = self.bind_addr.is_some();

        for worker_id in 0..num_threads {
            let config = self.config.clone();
            let rx = worker_rxs.remove(0);
            let eventfd = worker_eventfds[worker_id];
            let shutdown_flag = shutdown_flag.clone();
            let worker_fn = worker_fn.clone();

            let handle = thread::Builder::new()
                .name(format!("ringline-worker-{worker_id}"))
                .spawn(move || {
                    if config.worker.pin_to_core {
                        let core = config.worker.core_offset + worker_id;
                        pin_to_core(core)?;
                    }

                    crate::counter::set_thread_shard(worker_id);

                    let accept_rx = if has_acceptor { Some(rx) } else { None };
                    worker_fn(worker_id, config, accept_rx, eventfd, shutdown_flag)
                })
                .map_err(crate::error::Error::Io)?;

            handles.push(handle);
        }

        let shutdown_handle = ShutdownHandle {
            shutdown_flag,
            worker_eventfds,
            listen_fd,
            listen_fd_closed,
        };

        Ok((shutdown_handle, handles))
    }
}

/// Ensure RLIMIT_NOFILE is high enough for the io_uring fixed file table.
///
/// Each worker calls `register_files_sparse(max_connections)`, and the kernel
/// checks `nr_args > rlimit(RLIMIT_NOFILE)` per call (not cumulative across
/// workers). Connections use the fixed file table — the original FD is closed
/// immediately after `register_files_update` — so they don't consume process
/// FD table entries. We only need headroom for ring fds, eventfds, the listen
/// socket, stdin/stdout/stderr, etc.
fn ensure_nofile_limit(
    max_connections: u32,
    num_workers: usize,
) -> Result<(), crate::error::Error> {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if ret != 0 {
        return Err(crate::error::Error::Io(io::Error::last_os_error()));
    }

    // register_files_sparse(max_connections) needs RLIMIT_NOFILE >= max_connections.
    // Add per-worker overhead (ring fd, eventfd, transient socket fds) and global
    // overhead (listen socket, stdio, misc).
    let per_worker_overhead: u64 = 8;
    let global_overhead: u64 = 64;
    let required =
        max_connections as u64 + per_worker_overhead * num_workers as u64 + global_overhead;

    let soft = rlim.rlim_cur;
    let hard = rlim.rlim_max;

    if soft >= required {
        return Ok(());
    }

    if hard >= required || hard == libc::RLIM_INFINITY {
        // Raise soft limit to required (or hard if hard is finite and smaller)
        let new_soft = if hard == libc::RLIM_INFINITY {
            required
        } else {
            std::cmp::min(required, hard)
        };
        rlim.rlim_cur = new_soft;
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) };
        if ret != 0 {
            return Err(crate::error::Error::Io(io::Error::last_os_error()));
        }
        Ok(())
    } else {
        Err(crate::error::Error::ResourceLimit(format!(
            "RLIMIT_NOFILE too low: need {} but hard limit is {} (soft: {}). \
             Raise it with: ulimit -n {}",
            required, hard, soft, required
        )))
    }
}

/// Pin the current thread to a specific CPU core.
fn pin_to_core(core: usize) -> Result<(), crate::error::Error> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core, &mut set);
        let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if ret != 0 {
            return Err(crate::error::Error::Io(io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Create a TCP listener without SO_REUSEPORT (just SO_REUSEADDR).
fn create_listener(addr: SocketAddr, backlog: i32) -> Result<RawFd, crate::error::Error> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };

    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(crate::error::Error::Io(io::Error::last_os_error()));
    }

    // Set SO_REUSEADDR only (no SO_REUSEPORT).
    let optval: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Bind — use the driver's sockaddr helper.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let addr_len = crate::driver::socket_addr_to_sockaddr(addr, &mut storage);

    let ret = unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, addr_len) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(crate::error::Error::Io(err));
    }

    // Switch to blocking mode for the acceptor thread's accept4 call.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }

    let ret = unsafe { libc::listen(fd, backlog) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(crate::error::Error::Io(err));
    }

    Ok(fd)
}

/// Get the number of available CPU cores.
fn num_cpus() -> usize {
    let ret = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if ret < 1 { 1 } else { ret as usize }
}
