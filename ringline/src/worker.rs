use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::acceptor::{AcceptorConfig, run_acceptor};
use crate::backend::AsyncEventLoop;
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
    worker_wake_handles: Vec<crate::wakeup::WakeHandle>,
    listen_fd: Option<RawFd>,
    listen_fd_closed: Option<Arc<AtomicBool>>,
}

impl ShutdownHandle {
    /// Block the calling thread until `SIGINT` or `SIGTERM` is received,
    /// then trigger graceful shutdown.
    ///
    /// Equivalent to calling [`signal::wait()`](crate::signal::wait) followed
    /// by [`shutdown()`](Self::shutdown).
    ///
    /// Returns which signal was caught.
    pub fn wait_on_signal(&self) -> crate::signal::Signal {
        let sig = crate::signal::wait();
        self.shutdown();
        sig
    }

    /// Signal all workers to shut down gracefully.
    ///
    /// Workers will stop accepting new connections, close all active connections,
    /// drain remaining completions, and exit their event loops returning `Ok(())`.
    /// Also closes the listen fd to unblock the acceptor's `accept()`.
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
        // Close listen_fd to unblock the acceptor thread's accept() call.
        if let (Some(fd), Some(closed)) = (self.listen_fd, &self.listen_fd_closed)
            && !closed.swap(true, Ordering::AcqRel)
        {
            unsafe {
                libc::close(fd);
            }
        }
        // Wake all workers so they see the flag even if blocked on I/O.
        for wh in &self.worker_wake_handles {
            wh.wake();
        }
    }
}

/// Internal enum for the bound listen address.
enum BindAddr {
    Tcp(SocketAddr),
    Unix(PathBuf),
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
    bind_addr: Option<BindAddr>,
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
        self.bind_addr = Some(BindAddr::Tcp(addr));
        self
    }

    /// Set the bind path for a Unix domain socket listener. If not set, no
    /// listener or acceptor thread is created (client-only mode).
    ///
    /// Any existing socket file at the given path is unlinked before binding.
    pub fn bind_unix(mut self, path: impl AsRef<Path>) -> Self {
        self.bind_addr = Some(BindAddr::Unix(path.as_ref().to_path_buf()));
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
        self.launch_inner(
            |worker_id,
             config,
             accept_rx,
             eventfd,
             shutdown_flag,
             resolve_rx,
             resolve_tx,
             resolver,
             spawn_rx,
             spawn_tx,
             spawner,
             blocking_rx,
             blocking_tx,
             blocking_pool| {
                let handler = A::create_for_worker(worker_id);
                let mut event_loop = AsyncEventLoop::new(
                    &config,
                    handler,
                    accept_rx,
                    eventfd,
                    shutdown_flag,
                    resolve_rx,
                    resolve_tx,
                    resolver,
                    spawn_rx,
                    spawn_tx,
                    spawner,
                    blocking_rx,
                    blocking_tx,
                    blocking_pool,
                )?;
                event_loop.run()?;
                Ok(())
            },
        )
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
                Option<crossbeam_channel::Receiver<crate::resolver::ResolveResponse>>,
                Option<crossbeam_channel::Sender<crate::resolver::ResolveResponse>>,
                Option<Arc<crate::resolver::ResolverPool>>,
                Option<crossbeam_channel::Receiver<crate::spawner::SpawnResponse>>,
                Option<crossbeam_channel::Sender<crate::spawner::SpawnResponse>>,
                Option<Arc<crate::spawner::SpawnerPool>>,
                Option<crossbeam_channel::Receiver<crate::blocking::BlockingResponse>>,
                Option<crossbeam_channel::Sender<crate::blocking::BlockingResponse>>,
                Option<Arc<crate::blocking::BlockingPool>>,
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

        // Create per-worker channels and wake fds.
        let mut worker_txs = Vec::with_capacity(num_threads);
        let mut worker_rxs = Vec::with_capacity(num_threads);
        let mut worker_eventfds = Vec::with_capacity(num_threads);
        let mut worker_wake_handles = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let (tx, rx) = crossbeam_channel::unbounded::<(RawFd, SocketAddr)>();
            let (read_fd, wake_handle) =
                crate::wakeup::create_wake_fd().map_err(crate::error::Error::Io)?;
            worker_txs.push(tx);
            worker_rxs.push(rx);
            worker_eventfds.push(read_fd);
            worker_wake_handles.push(wake_handle);
        }

        let shutdown_flag = Arc::new(AtomicBool::new(false));

        // Create resolver pool if configured.
        let (resolver_pool, resolve_rxs) = if self.config.resolver_threads > 0 {
            let pool = Arc::new(crate::resolver::ResolverPool::start(
                self.config.resolver_threads,
            ));
            let mut rxs = Vec::with_capacity(num_threads);
            for _ in 0..num_threads {
                let (tx, rx) = crossbeam_channel::unbounded::<crate::resolver::ResolveResponse>();
                rxs.push((tx, rx));
            }
            (Some(pool), Some(rxs))
        } else {
            (None, None)
        };

        // Create spawner pool if configured.
        let (spawner_pool, spawn_rxs) = if self.config.spawner_threads > 0 {
            let pool = Arc::new(crate::spawner::SpawnerPool::start(
                self.config.spawner_threads,
            ));
            let mut rxs = Vec::with_capacity(num_threads);
            for _ in 0..num_threads {
                let (tx, rx) = crossbeam_channel::unbounded::<crate::spawner::SpawnResponse>();
                rxs.push((tx, rx));
            }
            (Some(pool), Some(rxs))
        } else {
            (None, None)
        };

        // Create blocking pool if configured.
        let (blocking_pool, blocking_rxs) = if self.config.blocking_threads > 0 {
            let pool = Arc::new(crate::blocking::BlockingPool::start(
                self.config.blocking_threads,
            ));
            let mut rxs = Vec::with_capacity(num_threads);
            for _ in 0..num_threads {
                let (tx, rx) = crossbeam_channel::unbounded::<crate::blocking::BlockingResponse>();
                rxs.push((tx, rx));
            }
            (Some(pool), Some(rxs))
        } else {
            (None, None)
        };

        // Optionally create listener + acceptor.
        let (listen_fd, listen_fd_closed) = if let Some(bind_addr) = self.bind_addr {
            let (fd, is_unix) = match bind_addr {
                BindAddr::Tcp(addr) => (create_listener(addr, self.config.backlog)?, false),
                BindAddr::Unix(ref path) => {
                    (create_unix_listener(path, self.config.backlog)?, true)
                }
            };
            let closed = Arc::new(AtomicBool::new(false));

            let acceptor_config = AcceptorConfig {
                listen_fd: fd,
                worker_channels: worker_txs,
                worker_wake_handles: worker_wake_handles.clone(),
                shutdown_flag: shutdown_flag.clone(),
                tcp_nodelay: if is_unix {
                    false
                } else {
                    self.config.tcp_nodelay
                },
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
        let has_acceptor = listen_fd.is_some();

        for worker_id in 0..num_threads {
            let config = self.config.clone();
            let rx = worker_rxs.remove(0);
            let eventfd = worker_eventfds[worker_id];
            let shutdown_flag = shutdown_flag.clone();
            let worker_fn = worker_fn.clone();

            let (worker_resolve_rx, worker_resolve_tx, worker_resolver) =
                if let Some(ref rxs) = resolve_rxs {
                    let (ref tx, ref rx) = rxs[worker_id];
                    (Some(rx.clone()), Some(tx.clone()), resolver_pool.clone())
                } else {
                    (None, None, None)
                };

            let (worker_spawn_rx, worker_spawn_tx, worker_spawner) =
                if let Some(ref rxs) = spawn_rxs {
                    let (ref tx, ref rx) = rxs[worker_id];
                    (Some(rx.clone()), Some(tx.clone()), spawner_pool.clone())
                } else {
                    (None, None, None)
                };

            let (worker_blocking_rx, worker_blocking_tx, worker_blocking_pool) =
                if let Some(ref rxs) = blocking_rxs {
                    let (ref tx, ref rx) = rxs[worker_id];
                    (Some(rx.clone()), Some(tx.clone()), blocking_pool.clone())
                } else {
                    (None, None, None)
                };

            let handle = thread::Builder::new()
                .name(format!("ringline-worker-{worker_id}"))
                .spawn(move || {
                    if config.worker.pin_to_core {
                        let core = config.worker.core_offset + worker_id;
                        pin_to_core(core)?;
                    }

                    crate::counter::set_thread_shard(worker_id);

                    let accept_rx = if has_acceptor { Some(rx) } else { None };
                    worker_fn(
                        worker_id,
                        config,
                        accept_rx,
                        eventfd,
                        shutdown_flag,
                        worker_resolve_rx,
                        worker_resolve_tx,
                        worker_resolver,
                        worker_spawn_rx,
                        worker_spawn_tx,
                        worker_spawner,
                        worker_blocking_rx,
                        worker_blocking_tx,
                        worker_blocking_pool,
                    )
                })
                .map_err(crate::error::Error::Io)?;

            handles.push(handle);
        }

        let shutdown_handle = ShutdownHandle {
            shutdown_flag,
            worker_wake_handles,
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

    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
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
    let addr_len = crate::backend::socket_addr_to_sockaddr(addr, &mut storage);

    let ret = unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, addr_len) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(crate::error::Error::Io(err));
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

/// Create a Unix domain socket listener at the given path.
///
/// Unlinks any existing socket file before binding.
fn create_unix_listener(path: &Path, backlog: i32) -> Result<RawFd, crate::error::Error> {
    // Remove existing socket file if present (ignore errors — path may not exist).
    let _ = std::fs::remove_file(path);

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(crate::error::Error::Io(io::Error::last_os_error()));
    }

    // Bind using the driver's sockaddr helper.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let addr_len = crate::backend::unix_path_to_sockaddr(path, &mut storage);

    let ret = unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, addr_len) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(crate::error::Error::Io(err));
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
