use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
#[cfg(not(has_io_uring))]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
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
        Runtime,
        Vec<thread::JoinHandle<Result<(), crate::error::Error>>>,
    ),
    crate::error::Error,
>;
type WorkerHandle = thread::JoinHandle<Result<(), crate::error::Error>>;

/// What a worker thread reports to `launch()` once its fallible setup is
/// done: `Ok` after `prepare_run`, or the typed error it hit (`RingSetup`,
/// `ResourceLimit`, an `Io` from pinning or socket setup, or an `Io`
/// carrying a startup panic's payload). Typed rather than a message so the
/// actionable variants from #360/#361 reach the caller intact.
type StartupResult = Result<(), crate::error::Error>;

/// Returned from a worker thread after the real error was reported over the
/// startup channel; `rollback_workers` only reads it as a fallback.
fn startup_failure_placeholder() -> crate::error::Error {
    crate::error::Error::Io(io::Error::other(
        "worker startup failure reported to launch()",
    ))
}

/// Render a panic payload for the startup error without consuming it, so
/// the payload can still be re-raised. `panic!("..")` and `panic!("{x}")`
/// give `&'static str` and `String`; anything else is opaque.
fn panic_payload(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Close listeners already bound when a later bind or acceptor spawn fails.
///
/// Without this a failure on the second `bind()` would leave the first socket
/// listening with an acceptor thread feeding channels nobody drains — the
/// port stays taken and peers get accepted into a runtime that is being torn
/// down. `shutdown(SHUT_RD)` first for the same reason `Runtime` does
/// it: it wakes a thread parked in `accept4` and frees the port immediately.
fn close_listeners(listeners: &[ListenerHandle]) {
    for listener in listeners {
        if listener
            .closed
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            continue;
        }
        for &fd in &listener.fds {
            unsafe {
                libc::shutdown(fd, libc::SHUT_RD);
                libc::close(fd);
            }
        }
    }
}

fn rollback_workers(
    shutdown_flag: &Arc<AtomicBool>,
    worker_wake_fds: &[crate::wakeup::WakeFd],
    handles: Vec<WorkerHandle>,
) -> Option<crate::error::Error> {
    shutdown_flag.store(true, Ordering::SeqCst);
    for wake in worker_wake_fds {
        wake.wake();
    }

    let mut first_error = None;
    for handle in handles {
        if let Ok(Err(error)) = handle.join()
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error
}

/// Carries the worker wake read descriptor into its worker thread.
///
/// Mio has a distinct pipe read end, which this type owns until the driver is
/// constructed. On io_uring, [`crate::wakeup::WakeHandle`] owns the shared
/// eventfd and this type only carries its descriptor number.
struct WorkerReadFd {
    #[cfg(has_io_uring)]
    fd: RawFd,
    #[cfg(not(has_io_uring))]
    fd: Option<OwnedFd>,
}

impl WorkerReadFd {
    fn new(fd: RawFd) -> Self {
        #[cfg(has_io_uring)]
        {
            Self { fd }
        }
        #[cfg(not(has_io_uring))]
        Self {
            // SAFETY: create_wake_fd returns a fresh pipe read descriptor and
            // transfers its ownership to this constructor on the mio backend.
            fd: Some(unsafe { OwnedFd::from_raw_fd(fd) }),
        }
    }

    fn as_raw_fd(&self) -> RawFd {
        #[cfg(has_io_uring)]
        {
            self.fd
        }
        #[cfg(not(has_io_uring))]
        {
            self.fd
                .as_ref()
                .expect("worker read fd must not be transferred twice")
                .as_raw_fd()
        }
    }

    fn transfer_to_driver(&mut self) {
        #[cfg(not(has_io_uring))]
        {
            let owned = self
                .fd
                .take()
                .expect("worker read fd must not be transferred twice");
            let _ = owned.into_raw_fd();
        }
    }
}

/// Returned by `launch()` with the workers' join handles. Controls shutdown,
/// listener addresses, deferred listeners, accept steering and registered
/// regions.
///
/// Dropping it calls [`shutdown`](Self::shutdown); join the handles to wait
/// for the workers to exit. [`ListenHandle`](crate::ListenHandle) and
/// [`WakeHandle`](crate::WakeHandle) implement `Clone`, and dropping them does
/// not shut the workers down.
pub struct Runtime {
    shutdown_flag: Arc<AtomicBool>,
    worker_wake_handles: Vec<crate::wakeup::WakeHandle>,
    /// One entry per listener, in `bind()` call order — the same order that
    /// gives each its [`ListenerId`](crate::ListenerId).
    listeners: Vec<ListenerHandle>,
    /// Which workers are currently in the accept rotation, for merged-mode
    /// listeners. Index is the worker id; all true until something takes a
    /// worker out. Shared with the workers, whose accept-time placement must
    /// skip anyone steered out — otherwise the drop in that worker's load
    /// would make it the preferred handoff target and undo the steering.
    ///
    /// Only read by `set_worker_accepting`, which is Linux-only because
    /// reuseport steering is.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    accepting: Arc<Vec<std::sync::atomic::AtomicBool>>,
    /// Read on the io_uring backend by `register_region` /
    /// `unregister_region`; on the mio backend it sits unused but is kept
    /// so the field layout is identical across backends.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    region_registrar: Arc<crate::region_registry::RegionRegistrar>,
    /// The listen gates, so `shutdown()` can release an acceptor parked on a
    /// gate that was never opened. Closing the listen fd wakes a thread
    /// inside `accept4`; it does not wake one parked in
    /// `ListenGates::wait_open`.
    listen_gates: Arc<crate::listen_gate::ListenGates>,
    /// The address of each UDP bind, in `Config::udp_bind` order: `Some` with a
    /// zero port replaced by the port the kernel chose, `None` for a connected
    /// zero-port bind, whose workers each have their own port.
    udp_addrs: Vec<Option<SocketAddr>>,
}

impl Runtime {
    /// The actual TCP address of the **first** TCP listener, if any. Returns
    /// `Some` for a TCP `bind()` (the port may have been zero-resolved) and
    /// `None` for client-only mode or when every listener is a Unix socket.
    ///
    /// With more than one listener, prefer [`bound_addr_of`] or
    /// [`bound_addrs`]: this returns the first TCP bind and cannot express
    /// the rest.
    ///
    /// [`bound_addr_of`]: Runtime::bound_addr_of
    /// [`bound_addrs`]: Runtime::bound_addrs
    pub fn bound_addr(&self) -> Option<SocketAddr> {
        self.listeners.iter().find_map(|l| l.bound_addr)
    }

    /// The address a specific listener bound to, by the [`ListenerId`](crate::ListenerId) its
    /// `bind()` call order gives it. `None` for a Unix listener or an id
    /// past the end.
    pub fn bound_addr_of(&self, listener: crate::ListenerId) -> Option<SocketAddr> {
        self.listeners
            .get(listener.index() as usize)
            .and_then(|l| l.bound_addr)
    }

    /// Every listener's bound address, in `bind()` call order. Unix
    /// listeners contribute `None`, so the indices line up with
    /// [`ListenerId`](crate::ListenerId).
    pub fn bound_addrs(&self) -> Vec<Option<SocketAddr>> {
        self.listeners.iter().map(|l| l.bound_addr).collect()
    }

    /// The address of the first UDP bind. `None` if there is no UDP bind, or
    /// if the first one has no single address (see [`bound_udp_addrs`]).
    ///
    /// With more than one UDP bind, use [`bound_udp_addrs`].
    ///
    /// [`bound_udp_addrs`]: Runtime::bound_udp_addrs
    pub fn bound_udp_addr(&self) -> Option<SocketAddr> {
        self.udp_addrs.first().copied().flatten()
    }

    /// Every UDP bind's address, in the order [`UdpCtx::index`] uses:
    /// `ConfigBuilder::udp_bind` / `udp_bind_connected` addresses first, then
    /// `RinglineBuilder::bind_udp` / `bind_udp_connected`, each in call order.
    ///
    /// A zero port reports the port the kernel chose, which every worker's
    /// socket for that bind shares. A connected zero-port bind reports
    /// `None`. Each worker's socket has its own port and receives the replies
    /// to what it sent.
    ///
    /// [`UdpCtx::index`]: crate::UdpCtx::index
    pub fn bound_udp_addrs(&self) -> Vec<Option<SocketAddr>> {
        self.udp_addrs.clone()
    }

    /// A handle for opening deferred listeners from any thread.
    ///
    /// The returned [`ListenHandle`](crate::ListenHandle) can be cloned and
    /// moved to other threads, and dropping it does not shut the workers
    /// down. After [`shutdown`](Self::shutdown), the `ListenHandle`'s calls
    /// return an error.
    pub fn listen_handle(&self) -> crate::ListenHandle {
        crate::ListenHandle::new(Arc::clone(&self.listen_gates))
    }

    /// Take a worker out of the accept rotation, or put it back.
    ///
    /// Only affects listeners in [`AcceptMode::Merged`](crate::AcceptMode):
    /// each worker owns a socket in a `SO_REUSEPORT` group, and this re-steers
    /// the group so the kernel stops choosing that worker's socket. The socket
    /// stays open, which is the point — closing one **resets** whatever is
    /// already queued on it.
    ///
    /// Two things it does not do:
    ///
    /// - **It does not drain.** Connections already queued on that worker's
    ///   socket stay there and are still accepted. Exclusion stops new
    ///   arrivals; it does not empty the queue.
    /// - **It does not move live connections.** Everything a running
    ///   connection owns is thread-local, so a worker keeps serving what it
    ///   already has.
    ///
    /// Returns `InvalidInput` if this would leave no worker accepting — a
    /// group that can select nothing accepts nothing, which is worse than the
    /// imbalance it was meant to fix.
    ///
    /// No-op when no listener is steerable (pool mode, Unix listeners,
    /// client-only, or a non-Linux build).
    #[cfg(target_os = "linux")]
    pub fn set_worker_accepting(&self, worker: usize, accepting: bool) -> io::Result<()> {
        use std::sync::atomic::Ordering;
        if worker >= self.accepting.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker index out of range",
            ));
        }
        if self.accepting[worker].load(Ordering::Acquire) == accepting {
            return Ok(());
        }
        self.accepting[worker].store(accepting, Ordering::Release);

        let live: Vec<u32> = self
            .accepting
            .iter()
            .enumerate()
            .filter(|(_, f)| f.load(Ordering::Acquire))
            .map(|(i, _)| i as u32)
            .collect();
        if live.is_empty() {
            // Put it back before returning: the caller's view of the rotation
            // must match the kernel's.
            self.accepting[worker].store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to leave no worker accepting",
            ));
        }

        for listener in &self.listeners {
            if !listener.steerable {
                continue;
            }
            let Some(&fd) = listener.fds.first() else {
                continue;
            };
            // The program governs the whole group, so one member is enough.
            crate::reuseport_bpf::attach_live_set(fd, &live)?;
        }
        Ok(())
    }

    /// How many listeners this runtime bound. Zero in client-only mode.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Number of worker threads launched.
    pub fn worker_count(&self) -> usize {
        self.worker_wake_handles.len()
    }

    /// Refcounted wake handle for the given worker, or `None` if `idx` is
    /// out of range.
    ///
    /// The returned handle can be cloned and moved to other threads, and
    /// stays valid past [`Runtime`] drop — the underlying fd is
    /// reference-counted and closes only when the last clone is dropped.
    /// After workers join, calling [`wake`](crate::WakeHandle::wake) is a
    /// no-op write into an fd nobody is reading.
    pub fn worker_wake_handle(&self, idx: usize) -> Option<crate::wakeup::WakeHandle> {
        self.worker_wake_handles.get(idx).cloned()
    }

    /// Register a memory region with every worker's io_uring fixed-buffer
    /// table. Blocks until every worker has acknowledged the kernel-side
    /// update.
    ///
    /// The returned [`RegionId`](crate::RegionId) is valid for use in
    /// `SendGuard` on any worker.
    ///
    /// # Errors
    ///
    /// - `io::ErrorKind::Other` "registered-region table is full" if the
    ///   table has no free slots (size set by
    ///   [`ConfigBuilder::max_registered_regions`](crate::ConfigBuilder::max_registered_regions)).
    /// - The first kernel error reported by any worker if the underlying
    ///   `register_buffers_update` call fails.
    /// - On the mio backend (no io_uring): always returns
    ///   `io::ErrorKind::Unsupported`.
    ///
    /// # Caller contract
    ///
    /// The memory must outlive the registration: do not unmap or free
    /// `region` until [`unregister_region`](Self::unregister_region) has
    /// returned, or until the runtime has fully shut down.
    pub fn register_region(
        &self,
        region: crate::buffer::fixed::MemoryRegion,
    ) -> io::Result<crate::buffer::fixed::RegionId> {
        #[cfg(has_io_uring)]
        {
            self.region_registrar.register(region)
        }
        #[cfg(not(has_io_uring))]
        {
            let _ = region;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "register_region requires the io_uring backend",
            ))
        }
    }

    /// Unregister a previously registered region. Blocks until every worker
    /// has acknowledged. The slot is returned to the free list on success.
    ///
    /// # Caller contract
    ///
    /// No SQE referencing the slot may be in flight when this is called.
    /// After it returns, the underlying memory may be safely unmapped.
    ///
    /// On the mio backend, always returns `io::ErrorKind::Unsupported`.
    pub fn unregister_region(&self, id: crate::buffer::fixed::RegionId) -> io::Result<()> {
        #[cfg(has_io_uring)]
        {
            self.region_registrar.unregister(id)
        }
        #[cfg(not(has_io_uring))]
        {
            let _ = id;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unregister_region requires the io_uring backend",
            ))
        }
    }

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
        // Before the listen fds are closed: an acceptor parked on a gate that
        // was never opened is not inside `accept4`, so closing its fd does
        // not reach it. Releasing the gate first means it wakes, sees
        // shutdown, and leaves without touching the fd.
        self.listen_gates.shutdown();
        for listener in &self.listeners {
            if listener.closed.swap(true, Ordering::AcqRel) {
                continue;
            }
            for &fd in &listener.fds {
                // shutdown(SHUT_RD) first: on Linux this wakes a thread
                // blocked in accept4 (with EINVAL) and releases the bound
                // port immediately. close(2) alone does neither — the
                // in-progress syscall holds a file reference, so the
                // acceptor stayed parked and the socket stayed listening
                // until one more peer connected (EADDRINUSE on prompt
                // relaunch). The close below then runs after the acceptor
                // can no longer loop into a reused fd number.
                //
                // In merged mode there is no acceptor thread, but a worker
                // may be parked in the ring with a multishot accept armed on
                // this fd; the same shutdown-then-close wakes it.
                unsafe {
                    libc::shutdown(fd, libc::SHUT_RD);
                    libc::close(fd);
                }
            }
        }
        // Wake all workers so they see the flag even if blocked on I/O.
        for wh in &self.worker_wake_handles {
            wh.wake();
        }
    }
}

// `Drop` calls `shutdown()` so that `drop(runtime); for h in handles { h.join() }`
// returns. `shutdown()` is idempotent, so an earlier explicit call is harmless.
impl Drop for Runtime {
    fn drop(&mut self) {
        // `shutdown()` is idempotent:
        //   * `shutdown_flag.store(true)` is monotonic — a second store
        //     is a no-op.
        //   * The listen-fd close is gated by an `AtomicBool::swap`, so
        //     a double-close is impossible whether `Drop` runs before
        //     or after an explicit `shutdown()`.
        //   * `WakeHandle::wake` is documented as a no-op write into
        //     an fd nobody is reading once workers have joined; the
        //     write either delivers a real wake or returns harmlessly.
        // Calling it unconditionally here makes the RAII idiom work
        // while leaving the explicit `.shutdown()` path unchanged.
        self.shutdown();
    }
}

/// Internal enum for the bound listen address.
enum BindAddr {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl BindAddr {
    fn is_unix(&self) -> bool {
        matches!(self, BindAddr::Unix(_))
    }
}

/// What a `bind*()` call asked for, before anything is bound. One per call, in
/// call order, so its position becomes its
/// [`ListenerId`](crate::ListenerId).
struct ListenerSpec {
    addr: BindAddr,
    /// TLS for this listener only. `None` falls back to the process-wide
    /// `ConfigBuilder::tls()`, so single-listener setups are unchanged.
    tls: Option<crate::config::TlsConfig>,
    /// Bind this listener but do not listen on it until a handler calls
    /// [`begin_listening`](crate::begin_listening). `false`, the default,
    /// listens during `launch()`.
    defer_listen: bool,
}

/// A listener the runtime owns, after binding. One per `bind*()` call, in
/// call order, so its position is its [`ListenerId`](crate::ListenerId).
struct ListenerHandle {
    /// One fd in pool mode. In merged mode, one `SO_REUSEPORT` socket per
    /// worker, all bound to the same address — the worker at index `i` accepts
    /// on `fds[i]`.
    fds: Vec<RawFd>,
    /// Set once by whoever closes these fds — `shutdown()` or the acceptor
    /// thread on exit — so the close happens exactly once.
    closed: Arc<AtomicBool>,
    /// `Some` for a TCP listener (after zero-port resolution), `None` for Unix.
    bound_addr: Option<SocketAddr>,
    /// Whether `fds` form a `SO_REUSEPORT` group that can be steered — true
    /// only for a merged-mode TCP listener, where `fds[i]` belongs to worker
    /// `i`. A pool-mode listener has a single socket and no group to steer.
    ///
    /// Only read by `set_worker_accepting`, which is Linux-only because
    /// reuseport steering is.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    steerable: bool,
}

/// Resolve the actual bound address of a TCP listen fd via `getsockname(2)`.
/// Returns `None` if the fd is not an IPv4/IPv6 TCP socket or the syscall fails.
fn getsockname_v4_v6(fd: RawFd) -> Option<SocketAddr> {
    use std::mem::{MaybeUninit, size_of};

    let mut storage: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::zeroed();
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockname(
            fd,
            storage.as_mut_ptr() as *mut libc::sockaddr,
            &mut len as *mut _,
        )
    };
    if rc != 0 {
        return None;
    }
    let s = unsafe { storage.assume_init() };
    match s.ss_family as i32 {
        libc::AF_INET => {
            let addr_in: libc::sockaddr_in =
                unsafe { std::ptr::read(&s as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
            let port = u16::from_be(addr_in.sin_port);
            Some(SocketAddr::from((ip, port)))
        }
        libc::AF_INET6 => {
            let addr_in6: libc::sockaddr_in6 =
                unsafe { std::ptr::read(&s as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
            let port = u16::from_be(addr_in6.sin6_port);
            Some(SocketAddr::from((ip, port)))
        }
        _ => None,
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
///
/// # Example: Echo Server
///
/// ```no_run
/// use ringline::{AsyncEventHandler, Config, Connection, ParseResult, RinglineBuilder};
///
/// struct Echo;
///
/// impl AsyncEventHandler for Echo {
///     fn on_accept(&self, mut conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
///         async move {
///             let (mut tx, mut rx) = conn.split();
///             loop {
///                 let n = rx.with_data(|data| {
///                     tx.send_nowait(data).ok();
///                     ParseResult::Consumed(data.len())
///                 }).await;
///                 if n == 0 { break; }
///             }
///         }
///     }
///     fn create_for_worker(_id: usize) -> Self { Echo }
/// }
///
/// fn main() -> Result<(), ringline::Error> {
///     let config = Config::default();
///     let (runtime, handles) = RinglineBuilder::new(config)
///         .bind("0.0.0.0:7878".parse().unwrap())
///         .launch::<Echo>()?;
///
///     // Wait for shutdown signal
///     runtime.wait_on_signal();
///
///     // Join all worker threads
///     for h in handles {
///         h.join().unwrap()?;
///     }
///     Ok(())
/// }
/// ```
///
/// # Example: Client-Only Mode
///
/// ```no_run
/// use ringline::{AsyncEventHandler, Config, RinglineBuilder};
/// use std::pin::Pin;
/// use std::future::Future;
///
/// struct ClientHandler;
///
/// impl AsyncEventHandler for ClientHandler {
///     fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
///         Some(Box::pin(async {
///             // Connect to Redis on startup
///             match ringline::connect("127.0.0.1:6379".parse().unwrap()).await {
///                 Ok(_conn) => println!("Connected to Redis"),
///                 Err(e) => eprintln!("Failed to connect: {e}"),
///             }
///         }))
///     }
///     fn on_accept(&self, _conn: ringline::Connection) -> impl std::future::Future<Output = ()> + 'static {
///         async {} // No inbound connections in client-only mode
///     }
///     fn create_for_worker(_id: usize) -> Self { ClientHandler }
/// }
///
/// fn main() -> Result<(), ringline::Error> {
///     let config = Config::default();
///     let (runtime, handles) = RinglineBuilder::new(config)
///         // No .bind() call = client-only mode
///         .launch::<ClientHandler>()?;
///
///     runtime.wait_on_signal();
///     for h in handles { h.join().unwrap()?; }
///     Ok(())
/// }
/// ```
///
/// # Example: Unix Domain Socket
///
/// ```no_run
/// use ringline::{AsyncEventHandler, Config, Connection, ParseResult, RinglineBuilder};
///
/// struct Handler;
/// impl AsyncEventHandler for Handler {
///     fn on_accept(&self, mut conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
///         async move {
///             let (mut tx, mut rx) = conn.split();
///             loop {
///                 let n = rx.with_data(|_data| ParseResult::Consumed(0)).await;
///                 if n == 0 { break; }
///             }
///         }
///     }
///     fn create_for_worker(_id: usize) -> Self { Handler }
/// }
///
/// fn main() -> Result<(), ringline::Error> {
///     let config = Config::default();
///     let (runtime, handles) = RinglineBuilder::new(config)
///         .bind_unix("/tmp/app.sock")
///         .launch::<Handler>()?;
///
///     runtime.wait_on_signal();
///     for h in handles { h.join().unwrap()?; }
///     Ok(())
/// }
/// ```
pub struct RinglineBuilder {
    config: Config,
    listeners: Vec<ListenerSpec>,
    /// `defer_listen()` was called with no listener to apply it to. Reported
    /// by `launch()` rather than panicking at the call, so it reads like
    /// every other configuration error.
    defer_listen_without_bind: bool,
}

impl RinglineBuilder {
    /// Create a new builder with the given config.
    pub fn new(config: Config) -> Self {
        RinglineBuilder {
            config,
            listeners: Vec::new(),
            defer_listen_without_bind: false,
        }
    }

    /// Set the bind address for the TCP listener. If not set, no listener
    /// or acceptor thread is created (client-only mode).
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.listeners.push(ListenerSpec {
            addr: BindAddr::Tcp(addr),
            tls: None,
            defer_listen: false,
        });
        self
    }

    /// Set the bind path for a Unix domain socket listener. If not set, no
    /// listener or acceptor thread is created (client-only mode).
    ///
    /// Any existing socket file at the given path is unlinked before binding.
    pub fn bind_unix(mut self, path: impl AsRef<Path>) -> Self {
        self.listeners.push(ListenerSpec {
            addr: BindAddr::Unix(path.as_ref().to_path_buf()),
            tls: None,
            defer_listen: false,
        });
        self
    }

    /// Bind a TCP listener that terminates TLS with its own configuration.
    ///
    /// The config applies to this listener alone, so one process can serve
    /// plaintext on one port and TLS on another — or two ports with different
    /// certificates. Accumulates like [`bind`](Self::bind).
    ///
    /// A listener bound with plain `bind()` falls back to the process-wide
    /// [`ConfigBuilder::tls`](crate::ConfigBuilder::tls) if one is set, which
    /// is how single-listener TLS setups behaved before per-listener configs
    /// existed. To serve a plaintext listener alongside a TLS one, leave the
    /// process-wide config unset and use `bind_tls` for the TLS listener.
    pub fn bind_tls(mut self, addr: SocketAddr, tls: crate::config::TlsConfig) -> Self {
        self.listeners.push(ListenerSpec {
            addr: BindAddr::Tcp(addr),
            tls: Some(tls),
            defer_listen: false,
        });
        self
    }

    /// Bind the most recently added listener without listening on it.
    ///
    /// The port is reserved, and the kernel does not complete handshakes on
    /// it, so a TCP readiness probe fails while the server is not ready. On
    /// Linux the peer is refused with `ECONNREFUSED`; on macOS and the BSDs
    /// the SYN is dropped and the peer times out.
    ///
    /// Call [`begin_listening()`](crate::begin_listening) with this
    /// listener's [`ListenerId`](crate::ListenerId) once the server can
    /// serve. [`on_start`](crate::AsyncEventHandler::on_start) is the usual
    /// place, since work that needs the runtime (outbound connections,
    /// timers, fs) runs there. From a thread that is not a ringline worker,
    /// call [`ListenHandle::begin_listening`](crate::ListenHandle::begin_listening)
    /// on the handle from [`Runtime::listen_handle`] instead.
    ///
    /// The first `begin_listening` call opens the listener for every worker,
    /// and connections are then spread across all of them. `on_start` runs
    /// on each worker, so if each worker has its own warmup, count completions
    /// and call `begin_listening` from the last one to finish.
    ///
    /// `listen(2)` is not called on the socket until `begin_listening` is. A
    /// socket that listens but does not accept still completes handshakes, so
    /// a TCP check passes against it; a bound socket that does not listen does
    /// not.
    ///
    /// Applies to the listener added by the most recent
    /// [`bind`](Self::bind), [`bind_unix`](Self::bind_unix) or
    /// [`bind_tls`](Self::bind_tls) call, so it is written immediately after
    /// one. UDP binds are not listeners and are unaffected. Calling it before
    /// any of those three is a configuration error that `launch()` reports.
    ///
    /// Not supported with [`AcceptMode::Merged`](crate::config::AcceptMode)
    /// on the io_uring backend, where `launch()` refuses the combination.
    ///
    /// ```no_run
    /// # use ringline::{Config, RinglineBuilder};
    /// # fn example(config: Config) -> Result<(), ringline::Error> {
    /// let builder = RinglineBuilder::new(config)
    ///     .bind("0.0.0.0:8080".parse().unwrap())  // health, serving at once
    ///     .bind("0.0.0.0:9090".parse().unwrap())  // data, gated
    ///     .defer_listen();
    /// # let _ = builder;
    /// # Ok(())
    /// # }
    /// ```
    pub fn defer_listen(mut self) -> Self {
        match self.listeners.last_mut() {
            Some(spec) => spec.defer_listen = true,
            // Recorded rather than panicked: the builder reports every other
            // misconfiguration through `launch()`.
            None => self.defer_listen_without_bind = true,
        }
        self
    }

    /// Bind a UDP socket on each worker (with `SO_REUSEPORT`).
    ///
    /// Can be called multiple times to bind multiple UDP addresses.
    /// Each worker creates its own socket per address. With a zero port,
    /// `launch` chooses one port and every worker binds it. The kernel
    /// delivers each datagram to one worker, so with more than one worker a
    /// reply can arrive at a worker other than the one that sent the request.
    /// Read the port back with [`Runtime::bound_udp_addrs`].
    pub fn bind_udp(mut self, addr: SocketAddr) -> Self {
        self.config.udp_bind.push(addr);
        self.config.udp_connect_peers.push(None);
        self
    }

    /// Bind a UDP socket on each worker (with `SO_REUSEPORT`) and immediately
    /// `connect(2)` it to `peer`. The kernel then filters incoming datagrams
    /// to `peer` and the runtime uses the lighter `RecvUdp`/`SendUdp`
    /// opcodes instead of `RecvMsgUdp`/`SendMsgUdp`. Saves ~4 microseconds
    /// per round trip on single-shot client workloads.
    ///
    /// With a zero local port, each worker's socket gets its own port and
    /// receives the replies to what it sent. [`Runtime::bound_udp_addrs`]
    /// reports `None` for this bind.
    pub fn bind_udp_connected(mut self, local: SocketAddr, peer: SocketAddr) -> Self {
        self.config.udp_bind.push(local);
        self.config.udp_connect_peers.push(Some(peer));
        self
    }

    /// Check the listener configuration, before `launch_inner` builds
    /// anything.
    ///
    /// These depend only on the builder, so they run beside
    /// `Config::validate` rather than after the worker threads, channel pairs
    /// and thread pools exist.
    fn validate_listeners(&self) -> Result<(), crate::error::Error> {
        if self.defer_listen_without_bind {
            return Err(crate::error::Error::RingSetup(
                "defer_listen() was called before any bind(): it applies to the listener \
                 added by the preceding bind call, so it belongs immediately after one"
                    .into(),
            ));
        }
        // Merged mode arms accept on the worker rings rather than in an
        // acceptor thread, so a gate would have to reach `arm_merged_accepts`
        // per listener rather than the single process-wide `merged_accept_live`
        // flag it reads. Refused rather than ignored: a deferral that does not defer
        // would pass a readiness probe against a server that cannot serve.
        let merged =
            self.config.accept_mode == crate::config::AcceptMode::Merged && cfg!(has_io_uring);
        if merged && self.listeners.iter().any(|spec| spec.defer_listen) {
            return Err(crate::error::Error::RingSetup(
                "defer_listen() is not supported with AcceptMode::Merged; use the default \
                 AcceptMode::Pool, or bind that listener without deferring"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Launch worker threads with the async `AsyncEventHandler`.
    ///
    /// Each accepted connection gets a long-lived async task. The executor
    /// polls futures on the same thread-per-core model. `launch()` waits for
    /// each worker to construct and prepare its backend before creating the
    /// listener. Errors from the subsequent event-loop run can still surface
    /// through the returned worker handles after the listener is live.
    pub fn launch<A: AsyncEventHandler>(self) -> LaunchResult {
        self.launch_inner(
            |worker_id,
             config,
             accept_rx,
             mut eventfd,
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
             region_rx,
             startup_tx| {
                let handler = A::create_for_worker(worker_id);
                // The io_uring backend's `AsyncEventLoop::new` returns
                // `crate::error::Error`; the mio backend returns
                // `io::Error`. Normalise to `crate::error::Error` so
                // the rest of this closure is backend-agnostic.
                #[cfg(has_io_uring)]
                let new_result = AsyncEventLoop::new(
                    &config,
                    handler,
                    accept_rx,
                    eventfd.0.as_raw_fd(),
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
                    region_rx,
                );
                #[cfg(not(has_io_uring))]
                let new_result = {
                    drop(region_rx);
                    AsyncEventLoop::new(
                        &config,
                        handler,
                        accept_rx,
                        eventfd.0.as_raw_fd(),
                        eventfd.1,
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
                    )
                };
                #[cfg(has_io_uring)]
                let event_loop_result: Result<_, crate::error::Error> = new_result;
                #[cfg(not(has_io_uring))]
                let event_loop_result: Result<_, crate::error::Error> =
                    new_result.map_err(crate::error::Error::Io);

                let mut event_loop = match event_loop_result {
                    Ok(event_loop) => event_loop,
                    Err(e) => {
                        let _ = startup_tx.send(Err(e));
                        return Err(startup_failure_placeholder());
                    }
                };

                // Keep `event_loop` in this final local binding from
                // preparation through `run()`: the io_uring eventfd-read SQE
                // points into its inline driver storage, so moving the value
                // after `prepare_run()` would invalidate that pointer.
                eventfd.0.transfer_to_driver();
                if let Err(e) = event_loop.prepare_run() {
                    let _ = startup_tx.send(Err(e));
                    return Err(startup_failure_placeholder());
                }

                // Signal only after the backend preparation Ringline knows can
                // fail before `run()`. This lets `launch()` surface those
                // errors rather than burying them in an unjoined worker.
                let _ = startup_tx.send(Ok(()));
                drop(startup_tx);
                event_loop.run()?;
                Ok(())
            },
        )
    }

    /// Common infrastructure setup for launch.
    #[allow(clippy::needless_range_loop)]
    #[allow(clippy::type_complexity)]
    fn launch_inner<F>(mut self, worker_fn: F) -> LaunchResult
    where
        F: Fn(
                usize,
                Config,
                Option<crossbeam_channel::Receiver<crate::acceptor::AcceptedConn>>,
                (WorkerReadFd, crate::wakeup::WakeFd),
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
                crate::region_registry::RegionControlRx,
                crossbeam_channel::Sender<StartupResult>,
            ) -> Result<(), crate::error::Error>
            + Send
            + Clone
            + 'static,
    {
        // Re-validate: RinglineBuilder::bind_udp / bind_udp_connected mutate
        // udp_bind AFTER ConfigBuilder::build() ran validate(), and every
        // UDP check is gated on !udp_bind.is_empty() — so builder-bound UDP
        // sockets used to skip validation entirely (e.g. GRO with a
        // too-small buffer silently truncates datagrams).
        self.config.validate()?;
        self.validate_listeners()?;

        let num_threads = if self.config.worker.threads == 0 {
            crate::topology::physical_core_count()
        } else {
            self.config.worker.threads
        };

        // Each worker binds its own socket per UDP address, so an unresolved
        // zero port gives each worker its own ephemeral port. Resolve it here
        // for every bind that should share one port. The first worker to set
        // up the bind takes the reserving socket as its own, so every socket
        // on the port is read by a worker.
        let (udp_reserved, udp_addrs) =
            resolve_zero_port_udp_binds(&mut self.config.udp_bind, &self.config.udp_connect_peers)?;
        self.config.udp_reserved = udp_reserved
            .into_iter()
            .map(std::sync::Mutex::new)
            .collect::<Vec<_>>()
            .into();

        ensure_nofile_limit(self.config.max_connections, num_threads)?;
        #[cfg(has_io_uring)]
        ensure_memlock_limit(&self.config)?;

        crate::metrics::init_metadata();

        // Create per-worker channels and wake fds. `worker_wake_handles`
        // (Arc-based) is what `Runtime` keeps and what
        // `worker_wake_handle()` hands out to users; `worker_wake_fds`
        // (Copy) is what the acceptor and internal request structs use on
        // hot paths.
        let mut worker_txs = Vec::with_capacity(num_threads);
        let mut worker_rxs = Vec::with_capacity(num_threads);
        let mut worker_eventfds = Vec::with_capacity(num_threads);
        let mut worker_wake_fds = Vec::with_capacity(num_threads);
        let mut worker_wake_handles = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            // Bounded so a slow worker applies backpressure on the acceptor
            // rather than queuing fds indefinitely. On full, the acceptor
            // tries the next worker; if every worker is full, the incoming
            // fd is closed so the kernel can signal connection-refused to
            // the peer instead of letting the listen queue overflow.
            let (tx, rx) = crossbeam_channel::bounded::<crate::acceptor::AcceptedConn>(
                self.config.accept_queue_capacity,
            );
            let (read_fd, wake_handle) =
                crate::wakeup::create_wake_fd().map_err(crate::error::Error::Io)?;
            worker_txs.push(tx);
            worker_rxs.push(rx);
            worker_eventfds.push(WorkerReadFd::new(read_fd));
            worker_wake_fds.push(wake_handle.as_wake_fd());
            worker_wake_handles.push(wake_handle);
        }

        // Park channels (tier 3, #443): a sibling of the accept channels so
        // the mio backend, which has neither merged accept nor park, is not
        // made to carry a variant it can never receive. Bounded for the same
        // reason as the accept channels — a slow worker must apply
        // backpressure rather than queue connections without limit.
        //
        // Created only for merged accept mode. A bounded crossbeam channel
        // allocates its capacity upfront, so building these unconditionally
        // costs `workers * accept_queue_capacity * size_of::<ParkedFd>()` —
        // hundreds of KiB per runtime at the default 1024 — in pool mode,
        // which is the default and can never park.
        let park_enabled =
            self.config.accept_mode == crate::config::AcceptMode::Merged && cfg!(has_io_uring);
        let mut park_txs = Vec::new();
        let mut park_rxs = Vec::new();
        if park_enabled {
            park_txs.reserve(num_threads);
            park_rxs.reserve(num_threads);
            for _ in 0..num_threads {
                let (tx, rx) = crossbeam_channel::bounded::<crate::park::ParkedFd>(
                    self.config.accept_queue_capacity,
                );
                park_txs.push(tx);
                park_rxs.push(rx);
            }
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

        // Region-registry control channels (one per worker). Always built;
        // only the io_uring backend drains them and the public API is gated
        // behind `cfg(has_io_uring)`.
        let (region_txs, region_rxs) = crate::region_registry::build_worker_channels(num_threads);
        let mut region_rxs_iter: Vec<_> = region_rxs.into_iter().map(Some).collect();

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

        // Retain only bind intent and worker senders until every worker has
        // completed fallible setup. No socket is bound or listening yet.
        let pending_listeners = std::mem::take(&mut self.listeners);
        let has_acceptor = !pending_listeners.is_empty();
        // One gate per listener, whether or not it is deferred: an ungated
        // listener is one whose gate `launch()` opens itself, which keeps a
        // single path through `listen(2)`.
        let listen_gates =
            crate::listen_gate::ListenGates::new(pending_listeners.len(), self.config.backlog);
        // Hand the per-listener TLS configs to every worker: the driver's
        // `TlsTable` selects by `ListenerId` at accept time, so it needs the
        // whole list, indexed the same way.
        self.config.listener_tls = pending_listeners.iter().map(|l| l.tls.clone()).collect();
        // Keep a copy for merged mode's fd handoff: `worker_txs` itself is
        // moved into the acceptor config below, and in merged mode there is no
        // acceptor to move it to.
        let worker_txs_for_peers = worker_txs.clone();
        let pending_worker_txs = if has_acceptor {
            Some(worker_txs)
        } else {
            drop(worker_txs);
            None
        };

        // Spawn worker threads. Each worker reports its setup outcome
        // (Ok / Err) over `startup_rx` so we can surface bind / config
        // errors to the caller of `launch()` instead of silently
        // swallowing them inside a thread that never gets joined.
        let mut handles: Vec<WorkerHandle> = Vec::with_capacity(num_threads);
        let (startup_tx, startup_rx) = crossbeam_channel::bounded::<StartupResult>(num_threads);

        // SMT-aware pinning: when the requested worker range fits within
        // the machine's physical cores, treat `core_offset + worker_id`
        // as a physical-core index and pin to that core's first SMT
        // sibling. On machines that enumerate hyperthread siblings
        // adjacently (cpu0/cpu1 = one core), raw logical ids would stack
        // two workers on one core. Ranges that don't fit fall back to
        // raw logical ids so deliberate hyperthread layouts remain
        // expressible.
        let physical_cpus: Option<Vec<usize>> = if self.config.worker.pin_to_core {
            crate::topology::physical_core_first_cpus()
                .filter(|cpus| self.config.worker.core_offset + num_threads <= cpus.len())
        } else {
            None
        };

        // Merged accept mode: bind every worker's SO_REUSEPORT socket now, but
        // do not listen yet. Binding reserves the port (and resolves a port-0
        // bind once, so all workers share one port instead of scattering across
        // ephemeral ones); listening is what makes the runtime reachable, and
        // that waits until every worker has reported ready. "Listening" and
        // "ready to serve" stay the same instant, which is the guarantee the
        // pool mode gets from creating its listener after the startup barrier.
        //
        // TCP only: SO_REUSEPORT does not apply to Unix sockets, so a Unix
        // listener keeps its acceptor thread even in merged mode.
        let merged_mode =
            self.config.accept_mode == crate::config::AcceptMode::Merged && cfg!(has_io_uring);
        let mut merged_sockets: Vec<(u32, Vec<RawFd>, Option<SocketAddr>)> = Vec::new();
        if merged_mode {
            for (idx, spec) in pending_listeners.iter().enumerate() {
                let BindAddr::Tcp(addr) = &spec.addr else {
                    continue;
                };
                let mut fds: Vec<RawFd> = Vec::with_capacity(num_threads);
                let mut resolved: Option<SocketAddr> = None;
                let mut failure = None;
                for _ in 0..num_threads {
                    let target = resolved.unwrap_or(*addr);
                    match bind_reuseport_socket(target) {
                        Ok(fd) => {
                            if resolved.is_none() {
                                resolved = getsockname_v4_v6(fd);
                            }
                            fds.push(fd);
                        }
                        Err(e) => {
                            failure = Some(e);
                            break;
                        }
                    }
                }
                if let Some(e) = failure {
                    for fd in fds {
                        unsafe { libc::close(fd) };
                    }
                    for (_, fds, _) in &merged_sockets {
                        for &fd in fds {
                            unsafe { libc::close(fd) };
                        }
                    }
                    rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                    return Err(e);
                }
                merged_sockets.push((idx as u32, fds, resolved));
            }
        }
        let merged_live = if merged_sockets.is_empty() {
            None
        } else {
            Some(Arc::new(AtomicBool::new(false)))
        };
        // Live connection count per worker. Merged mode reads it when placing a
        // newly accepted connection; pool mode places in the acceptor thread and
        // never looks at it.
        let worker_loads: Option<Arc<Vec<std::sync::atomic::AtomicU32>>> =
            if merged_sockets.is_empty() {
                None
            } else {
                Some(Arc::new(
                    (0..num_threads)
                        .map(|_| std::sync::atomic::AtomicU32::new(0))
                        .collect(),
                ))
            };

        // Shared by `Runtime::set_worker_accepting` and every worker's
        // accept-time placement: one mask, so steering and placement cannot
        // disagree about who is in the rotation.
        let worker_accepting: Arc<Vec<std::sync::atomic::AtomicBool>> = Arc::new(
            (0..num_threads)
                .map(|_| std::sync::atomic::AtomicBool::new(true))
                .collect(),
        );

        for worker_id in 0..num_threads {
            let mut config = self.config.clone();
            config.merged_accept_fds = merged_sockets
                .iter()
                .map(|(idx, fds, _)| (*idx, fds[worker_id]))
                .collect();
            config.merged_accept_live = merged_live.clone();
            config.worker_index = worker_id;
            config.worker_loads = worker_loads.clone();
            config.worker_accepting = Some(worker_accepting.clone());
            if worker_loads.is_some() {
                // Merged mode has no acceptor thread, so these channels are
                // otherwise unused; they become the fd-handoff path for
                // accept-time placement.
                config.peer_accept = worker_txs_for_peers
                    .iter()
                    .cloned()
                    .zip(worker_wake_fds.iter().copied())
                    .collect();
            }
            if worker_loads.is_some() {
                config.peer_park = park_txs
                    .iter()
                    .cloned()
                    .zip(worker_wake_fds.iter().copied())
                    .collect();
            }
            config.park_rx = if park_enabled {
                Some(park_rxs.remove(0))
            } else {
                None
            };
            let rx = worker_rxs.remove(0);
            // (read end for polling, write end for cross-thread wakes —
            // on the mio backend these are the two ends of a pipe; the
            // disk-I/O pool must write the WRITE end. It used to be handed
            // the read end, so every fs completion wake was an EBADF no-op
            // and completions were only noticed at the poll timeout.)
            let eventfd = (worker_eventfds.remove(0), worker_wake_fds[worker_id]);
            let worker_shutdown_flag = shutdown_flag.clone();
            let worker_listen_gates = listen_gates.clone();
            let worker_fn = worker_fn.clone();
            let startup_tx = startup_tx.clone();

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

            let worker_region_rx = region_rxs_iter[worker_id]
                .take()
                .expect("region rx already consumed");

            let pin_cpu = {
                let raw = self.config.worker.core_offset + worker_id;
                physical_cpus.as_ref().map(|cpus| cpus[raw]).unwrap_or(raw)
            };

            let spawn_result = thread::Builder::new()
                .name(format!("ringline-worker-{worker_id}"))
                .spawn(move || {
                    if config.worker.pin_to_core {
                        let core = pin_cpu;
                        // Report the failure before bailing — otherwise
                        // the launching thread waits indefinitely for
                        // a startup signal that never arrives.
                        if let Err(e) = pin_to_core(core) {
                            // A bare EINVAL here is opaque — name the knob.
                            eprintln!(
                                "ringline: failed to pin worker {worker_id} to logical CPU {core} \
                                 (core_offset {} + worker id): {e} — check Config::core_offset \
                                 against the machine's CPU count",
                                config.worker.core_offset
                            );
                            let _ = startup_tx.send(Err(e));
                            return Err(startup_failure_placeholder());
                        }
                    }

                    metriken::set_thread_shard(worker_id);
                    // Makes `begin_listening()` reachable from any code on this
                    // worker thread.
                    crate::listen_gate::install(worker_listen_gates);

                    let accept_rx = if has_acceptor { Some(rx) } else { None };
                    // A panic before startup completed must reach `launch()`
                    // as an error naming the worker and the payload, not as
                    // a disconnected channel and a generic "worker setup
                    // failed". `panic_tx` is cloned first because
                    // `worker_fn` consumes `startup_tx`.
                    let panic_tx = startup_tx.clone();
                    match catch_unwind(AssertUnwindSafe(|| {
                        worker_fn(
                            worker_id,
                            config,
                            accept_rx,
                            eventfd,
                            worker_shutdown_flag,
                            worker_resolve_rx,
                            worker_resolve_tx,
                            worker_resolver,
                            worker_spawn_rx,
                            worker_spawn_tx,
                            worker_spawner,
                            worker_blocking_rx,
                            worker_blocking_tx,
                            worker_blocking_pool,
                            worker_region_rx,
                            startup_tx,
                        )
                    })) {
                        Ok(result) => result,
                        Err(payload) => {
                            let message = format!(
                                "ringline worker {worker_id} panicked: {}",
                                panic_payload(&*payload)
                            );
                            // `try_send`, never `send`: during rollback the
                            // launcher has stopped receiving but still holds
                            // the receiver, and a blocking send into a full
                            // channel would hang the join. `Full` means the
                            // launcher already has an error to return.
                            // `Disconnected` means `launch()` has returned:
                            // this is a steady-state panic, and the join
                            // result must stay `Err(payload)` as it always
                            // was — re-raise instead of converting.
                            match panic_tx.try_send(Err(crate::error::Error::Io(io::Error::other(
                                message.clone(),
                            )))) {
                                Ok(()) | Err(crossbeam_channel::TrySendError::Full(_)) => {
                                    Err(crate::error::Error::Io(io::Error::other(message)))
                                }
                                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                                    std::panic::resume_unwind(payload)
                                }
                            }
                        }
                    }
                });

            let handle = match spawn_result {
                Ok(handle) => handle,
                Err(error) => {
                    rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                    return Err(crate::error::Error::Io(error));
                }
            };

            handles.push(handle);
        }

        // Drop our copy so `recv()` on the receiver side terminates if
        // every worker happens to die before sending.
        drop(startup_tx);

        // Collect setup outcomes. If any worker failed setup, signal
        // shutdown to the rest, join everyone, and surface the first
        // setup error back to the caller of `launch()`.
        // `Some(Some(e))`: a worker reported `e`. `Some(None)`: the channel
        // disconnected with nothing reported (a worker died before its
        // first send); the joined thread's error is the fallback.
        let mut setup_failure: Option<Option<crate::error::Error>> = None;
        for _ in 0..num_threads {
            match startup_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    setup_failure = Some(Some(error));
                    break;
                }
                Err(_) => {
                    setup_failure = Some(None);
                    break;
                }
            }
        }

        if let Some(reported) = setup_failure {
            let joined = rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
            return Err(reported.or(joined).unwrap_or_else(|| {
                crate::error::Error::Io(io::Error::other("worker setup failed"))
            }));
        }

        // Commit the listeners only after every worker has completed fallible
        // initialization. Before this point clients cannot connect or enter a
        // kernel listen backlog.
        //
        // One acceptor thread per listener, each blocking in its own accept4
        // and feeding the same worker channels. Accepts from different
        // listeners interleave on those channels; each carries its own
        // `ListenerId` so the handler can tell them apart.
        let listeners: Vec<ListenerHandle> = if has_acceptor {
            let worker_txs = pending_worker_txs.expect("worker senders must exist");
            let mut listeners: Vec<ListenerHandle> = Vec::with_capacity(pending_listeners.len());

            for (idx, spec) in pending_listeners.iter().enumerate() {
                // Merged listeners were bound before the workers started; all
                // that is left is to listen, which is the moment the runtime
                // becomes reachable.
                let merged_entry = merged_sockets.iter().find(|(i, _, _)| *i == idx as u32);

                // Bind only. `listen(2)` happens when the gate opens, which
                // for an ungated listener is a few lines below and for a
                // deferred one is whenever the handler releases it. Both go
                // through `ListenGates::open`, so there is one `listen` call
                // site.
                //
                // `getsockname` reports the port of a bound socket, so a
                // zero-port bind still resolves here; merged mode relies on
                // the same.
                let created: Result<(Vec<RawFd>, Option<SocketAddr>), crate::error::Error> =
                    match (&spec.addr, merged_entry) {
                        (BindAddr::Tcp(_), Some((_, fds, resolved))) => {
                            Ok((fds.clone(), *resolved))
                        }
                        (BindAddr::Tcp(addr), None) => {
                            create_listener(*addr).map(|fd| (vec![fd], getsockname_v4_v6(fd)))
                        }
                        (BindAddr::Unix(path), _) => {
                            create_unix_listener(path).map(|fd| (vec![fd], None))
                        }
                    };
                let (fds, bound_addr) = match created {
                    Ok(created) => created,
                    Err(error) => {
                        // Roll back the listeners already bound, or their ports
                        // stay held and a listening socket keeps accepting into
                        // workers that are being joined. Shut the gates
                        // first, as `Runtime::shutdown` does: an acceptor
                        // parked on a deferred gate is not woken by closing its fd.
                        listen_gates.shutdown();
                        close_listeners(&listeners);
                        rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                        return Err(error);
                    }
                };

                let closed = Arc::new(AtomicBool::new(false));

                // The gate owns the `listen(2)` call for these sockets from
                // here on. `register` itself can listen: a handler whose
                // `on_start` released this gate before `launch()` got here
                // recorded the request, and `register` honours it.
                let registered = listen_gates.register(idx as u32, fds.clone());
                if let Err(error) = registered.and_then(|()| {
                    if spec.defer_listen {
                        Ok(())
                    } else {
                        listen_gates.open(idx as u32)
                    }
                }) {
                    listen_gates.shutdown();
                    close_listeners(&listeners);
                    for &fd in &fds {
                        unsafe { libc::close(fd) };
                    }
                    rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                    return Err(crate::error::Error::Io(error));
                }

                // Merged mode has no acceptor thread: the workers arm their own
                // multishot accept on these fds. Record the listener and move on.
                if merged_entry.is_some() {
                    listeners.push(ListenerHandle {
                        fds,
                        closed,
                        bound_addr,
                        steerable: true,
                    });
                    continue;
                }

                let listen_fd = fds[0];
                let acceptor_config = AcceptorConfig {
                    listen_fd,
                    listener: crate::ListenerId::from_index(idx as u32),
                    worker_channels: worker_txs.clone(),
                    worker_wake_handles: worker_wake_fds.clone(),
                    shutdown_flag: shutdown_flag.clone(),
                    listen_gates: listen_gates.clone(),
                    // A Unix listener has no TCP_NODELAY to set. This used to be
                    // a runtime `if is_unix` branch over one global flag; with a
                    // listener list each one simply answers for itself.
                    tcp_nodelay: !spec.addr.is_unix() && self.config.tcp_nodelay,
                    #[cfg(feature = "timestamps")]
                    timestamps: self.config.timestamps,
                    conn_chunk_size: self.config.conn_chunk_size,
                };

                let acceptor_closed = closed.clone();
                let spawn_result = thread::Builder::new()
                    .name(format!("ringline-acceptor-{idx}"))
                    .spawn(move || {
                        run_acceptor(acceptor_config);
                        if !acceptor_closed.swap(true, Ordering::AcqRel) {
                            unsafe {
                                libc::close(listen_fd);
                            }
                        }
                    });

                if let Err(error) = spawn_result {
                    if !closed.swap(true, Ordering::AcqRel) {
                        unsafe {
                            libc::close(listen_fd);
                        }
                    }
                    listen_gates.shutdown();
                    close_listeners(&listeners);
                    rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                    return Err(crate::error::Error::Io(error));
                }

                listeners.push(ListenerHandle {
                    fds,
                    closed,
                    bound_addr,
                    steerable: false,
                });
            }
            // Every merged socket is listening now, so the workers may arm.
            // Publishing the flag before the wake means a worker that checks on
            // its own schedule still sees it.
            if let Some(ref live) = merged_live {
                live.store(true, Ordering::Release);
                for wh in &worker_wake_fds {
                    wh.wake();
                }
            }

            listeners
        } else {
            Vec::new()
        };

        let region_registrar = Arc::new(crate::region_registry::RegionRegistrar::new(
            self.config.max_registered_regions,
            self.config.registered_regions.len() as u16,
            region_txs,
            worker_wake_handles.clone(),
        ));

        let runtime = Runtime {
            shutdown_flag,
            worker_wake_handles,
            accepting: worker_accepting,
            listeners,
            region_registrar,
            listen_gates,
            udp_addrs,
        };

        Ok((runtime, handles))
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

    // io_uring: register_files_sparse(max_connections) needs RLIMIT_NOFILE
    // >= max_connections (the kernel's check is per-ring; connections live
    // in fixed-file tables, not real fds). Add per-worker overhead (ring
    // fd, eventfd, transient socket fds) and global overhead (listen
    // socket, stdio, misc).
    //
    // mio: every connection holds a REAL fd and each worker has its own
    // max_connections-slot table, so the worst case scales with the worker
    // count — the io_uring formula under-provisioned and configs passed
    // the check only to fail with EMFILE under load.
    let per_worker_overhead: u64 = 8;
    let global_overhead: u64 = 64;
    #[cfg(has_io_uring)]
    let conn_fds = max_connections as u64;
    #[cfg(not(has_io_uring))]
    let conn_fds = max_connections as u64 * num_workers as u64;
    let required = conn_fds + per_worker_overhead * num_workers as u64 + global_overhead;

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

/// Make sure `RLIMIT_MEMLOCK` covers the fixed buffers `Driver::new` will
/// register, before any worker thread exists.
///
/// io_uring charges registered buffers against the memlock limit unless the
/// process holds `CAP_IPC_LOCK`; distros default it to 8 MiB or 64 MiB, and
/// the kernel reports the shortfall as a bare `ENOMEM`. Like the nofile
/// check, this raises the soft limit when the hard limit allows and otherwise
/// fails with the fix spelled out. Regions registered later through
/// `Runtime::register_region` are checked at that call instead.
#[cfg(has_io_uring)]
fn ensure_memlock_limit(config: &Config) -> Result<(), crate::error::Error> {
    use crate::error::{MemlockLimit, MemlockPlan, describe_memlock_shortfall, memlock_plan};

    if config.registered_regions.is_empty() {
        return Ok(());
    }
    // Pinning is per page, and a region that does not start on a page
    // boundary pins one more than its length suggests.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let required: u64 = config
        .registered_regions
        .iter()
        .map(|r| (r.len() as u64).div_ceil(page) * page + page)
        .sum();
    let limit = MemlockLimit::read().map_err(crate::error::Error::Io)?;
    match memlock_plan(required, &limit) {
        MemlockPlan::Sufficient => Ok(()),
        MemlockPlan::RaiseSoftTo(soft) => {
            let rlim = libc::rlimit {
                rlim_cur: soft,
                rlim_max: limit.hard,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
                return Err(crate::error::Error::Io(io::Error::last_os_error()));
            }
            Ok(())
        }
        MemlockPlan::HardTooLow => Err(crate::error::Error::ResourceLimit(
            describe_memlock_shortfall(
                required,
                &limit,
                &format!("{} registered region(s)", config.registered_regions.len()),
            ),
        )),
    }
}

/// Pin the current thread to a specific CPU core.
#[cfg(target_os = "linux")]
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

/// Pin the current thread to a specific CPU core (no-op on non-Linux).
#[cfg(not(target_os = "linux"))]
fn pin_to_core(_core: usize) -> Result<(), crate::error::Error> {
    // Thread pinning is not supported on this platform.
    Ok(())
}

/// Create a `SO_REUSEPORT` socket and bind it, without listening.
///
/// A bound-but-not-listening socket holds the port reservation but takes no
/// connections, which is how `launch()` resolves a port-0 bind for merged mode
/// without opening a listener before the workers are ready.
fn bind_reuseport_socket(addr: SocketAddr) -> Result<RawFd, crate::error::Error> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(crate::error::Error::Io(io::Error::last_os_error()));
    }
    let optval: libc::c_int = 1;
    for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(crate::error::Error::Io(err));
        }
    }

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let addr_len = crate::backend::socket_addr_to_sockaddr(addr, &mut storage);
    let ret = unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, addr_len) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(crate::error::Error::Io(err));
    }
    Ok(fd)
}

/// The sockets `launch` binds for zero-port UDP binds, parallel to
/// `Config::udp_bind`.
type ReservedUdpSockets = Vec<Option<std::os::fd::OwnedFd>>;

/// Resolve the zero ports in `udp_bind` that every worker should share, and
/// return the sockets reserving them, parallel to `udp_bind`, with each
/// bind's reported address.
///
/// A zero port on an unconnected bind is resolved, and the chosen port
/// written back into the address. A connected zero-port bind is left at
/// port 0, so each worker's socket gets its own port, and reports `None`.
fn resolve_zero_port_udp_binds(
    udp_bind: &mut [SocketAddr],
    connect_peers: &[Option<SocketAddr>],
) -> Result<(ReservedUdpSockets, Vec<Option<SocketAddr>>), crate::error::Error> {
    let mut held = Vec::with_capacity(udp_bind.len());
    let mut reported = Vec::with_capacity(udp_bind.len());
    for (i, addr) in udp_bind.iter_mut().enumerate() {
        let connected = connect_peers.get(i).is_some_and(Option::is_some);
        if addr.port() != 0 {
            held.push(None);
            reported.push(Some(*addr));
        } else if connected {
            held.push(None);
            reported.push(None);
        } else {
            let (fd, resolved) = reserve_udp_port(*addr).map_err(crate::error::Error::Io)?;
            *addr = resolved;
            held.push(Some(fd));
            reported.push(Some(resolved));
        }
    }
    Ok((held, reported))
}

/// A UDP socket bound to an unused port at `addr`, with `SO_REUSEPORT` set so
/// the other workers' sockets can join it, and the address it bound. One
/// worker takes it as its own socket for the bind.
///
/// `SO_REUSEPORT` is set after the bind. Set before it, Linux's search for a
/// free port can return a port another `SO_REUSEPORT` socket of the same user
/// already holds, and the reservation would share that socket's port. The
/// worker sockets leave `SO_REUSEPORT` off for a zero port for the same
/// reason.
fn reserve_udp_port(addr: SocketAddr) -> io::Result<(std::os::fd::OwnedFd, SocketAddr)> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    #[cfg(target_os = "linux")]
    let sock_type = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let sock_type = libc::SOCK_DGRAM;
    let raw = unsafe { libc::socket(domain, sock_type, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a socket this function just created and owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    #[cfg(not(target_os = "linux"))]
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFD);
        if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = crate::backend::socket_addr_to_sockaddr(addr, &mut storage);
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &storage as *const _ as *const libc::sockaddr,
            len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let optval: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let resolved = getsockname_v4_v6(fd.as_raw_fd())
        .ok_or_else(|| io::Error::other("getsockname on a bound UDP socket returned no address"))?;
    Ok((fd, resolved))
}

/// Create a bound TCP listener, without SO_REUSEPORT and without listening.
///
/// SO_REUSEADDR is set for the bind and cleared immediately after it, so the
/// port is not open to a second binder while the socket is not yet
/// listening. `ListenGates` sets it again just before `listen(2)`.
pub(crate) fn create_listener(addr: SocketAddr) -> Result<RawFd, crate::error::Error> {
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

    // Clear SO_REUSEADDR now that the bind has succeeded, so the port is
    // reserved against another process for as long as this socket holds it.
    //
    // Linux lets two sockets share an address while neither is listening, and
    // only if both have SO_REUSEADDR set. A listener therefore reserves its
    // port exclusively only once it listens, which with a deferred listen is
    // however long the handler takes. Clearing the flag closes that window.
    // `listen_all` sets it again immediately before `listen(2)`, which
    // re-checks the port with the current flag and would otherwise fail
    // EADDRINUSE on a TIME_WAIT connection left by a previous instance.
    //
    // No effect on a listener that is not deferred: a listening socket
    // conflicts with a later bind regardless of the flag.
    //
    // Measured on Linux 6.12 aarch64 with plain sockets: left set, a second
    // bind succeeds; cleared after bind, it fails EADDRINUSE. Darwin refuses
    // the second bind either way. If another process does bind in the
    // window it must also call `listen(2)`, after which this socket's
    // `listen` fails with EADDRINUSE and `begin_listening` reports it.
    //
    // Merged-mode sockets come from `bind_reuseport_socket`, not from here,
    // so SO_REUSEPORT sharing is unaffected.
    //
    // A failure to clear is not checked: the port is then shareable with
    // another SO_REUSEADDR socket until this one listens.
    let clear: libc::c_int = 0;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &clear as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    Ok(fd)
}

/// Create a Unix domain socket listener at the given path.
///
/// Unlinks any existing socket file before binding.
fn create_unix_listener(path: &Path) -> Result<RawFd, crate::error::Error> {
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

    Ok(fd)
}

#[cfg(test)]
mod startup_gate_tests {
    use super::*;
    use std::path::PathBuf;
    #[cfg(target_os = "linux")]
    use std::process::Command;
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    const FD_LEAK_CHILD: &str =
        "worker::startup_gate_tests::worker_startup_failure_closes_all_runtime_fds_child";

    fn unix_socket_path() -> PathBuf {
        std::env::temp_dir().join(format!("ringline-startup-gate-{}.sock", std::process::id()))
    }

    fn one_worker_config() -> Config {
        crate::ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .resolver_threads(0)
            .spawner_threads(0)
            .blocking_threads(0)
            .disk_io_threads(0)
            .build()
            .unwrap()
    }

    #[test]
    fn listener_is_not_created_before_worker_startup_succeeds() {
        let path = unix_socket_path();
        let _ = std::fs::remove_file(&path);
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
        let (inspect_tx, inspect_rx) = crossbeam_channel::bounded(1);
        let (observed_tx, observed_rx) = crossbeam_channel::bounded(1);
        let launch_path = path.clone();

        let launcher = thread::spawn(move || {
            RinglineBuilder::new(one_worker_config())
                .bind_unix(launch_path)
                .launch_inner(
                    move |_,
                          _,
                          accept_rx,
                          _eventfd,
                          _,
                          _,
                          _,
                          _,
                          _,
                          _,
                          _,
                          _,
                          _,
                          _,
                          _,
                          startup_tx| {
                        ready_tx.send(()).unwrap();
                        inspect_rx.recv().unwrap();
                        let accepted = accept_rx
                            .unwrap()
                            .recv_timeout(Duration::from_millis(250))
                            .ok();
                        observed_tx.send(accepted.is_some()).unwrap();
                        if let Some(accepted) = accepted {
                            unsafe { libc::close(accepted.fd) };
                        }
                        let _ = startup_tx.send(Err(crate::error::Error::Io(io::Error::other(
                            "injected worker startup failure",
                        ))));
                        Err(crate::error::Error::Io(io::Error::other(
                            "injected worker startup failure",
                        )))
                    },
                )
        });

        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let absent_before_worker_ready = !path.exists();
        inspect_tx.send(()).unwrap();

        assert!(!observed_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        assert!(launcher.join().unwrap().is_err());
        let absent_after_rollback = !path.exists();
        let _ = std::fs::remove_file(path);
        assert!(absent_before_worker_ready);
        assert!(absent_after_rollback);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn worker_startup_failure_closes_all_runtime_fds() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", FD_LEAK_CHILD])
            .env("RINGLINE_FD_LEAK_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "spawned by worker_startup_failure_closes_all_runtime_fds"]
    fn worker_startup_failure_closes_all_runtime_fds_child() {
        if std::env::var("RINGLINE_FD_LEAK_CHILD").as_deref() != Ok("1") {
            return;
        }

        fn fd_count() -> usize {
            std::fs::read_dir("/proc/self/fd").unwrap().count()
        }

        let before = fd_count();
        for _ in 0..4 {
            let result = RinglineBuilder::new(one_worker_config()).launch_inner(
                |_, _, _, _eventfd, _, _, _, _, _, _, _, _, _, _, _, startup_tx| {
                    let _ = startup_tx.send(Err(crate::error::Error::Io(io::Error::other(
                        "injected worker startup failure",
                    ))));
                    Err(crate::error::Error::Io(io::Error::other(
                        "injected worker startup failure",
                    )))
                },
            );
            assert!(result.is_err());
        }
        assert_eq!(fd_count(), before);
    }
    /// The error a worker *reports* must be the one `launch()` returns, not
    /// whatever the first joined thread happened to return.
    #[test]
    fn startup_returns_the_reported_error_after_rollback() {
        let result = RinglineBuilder::new(one_worker_config()).launch_inner(
            |_, _, _, _eventfd, _, _, _, _, _, _, _, _, _, _, _, startup_tx| {
                let _ = startup_tx.send(Err(crate::error::Error::Io(io::Error::other(
                    "reported setup failure",
                ))));
                Err(crate::error::Error::Io(io::Error::other(
                    "different joined-worker failure",
                )))
            },
        );
        let error = result
            .err()
            .expect("reported setup failure must fail launch");
        let text = error.to_string();
        assert!(text.contains("reported setup failure"), "{text}");
        assert!(!text.contains("different joined-worker failure"), "{text}");
    }

    /// A panic during worker startup used to surface as a disconnected
    /// channel and "worker setup failed"; the payload and the worker id must
    /// reach the caller.
    #[test]
    fn worker_startup_panic_payload_is_preserved() {
        let result = RinglineBuilder::new(one_worker_config()).launch_inner(
            |_, _, _, _eventfd, _, _, _, _, _, _, _, _, _, _, _, _| {
                panic!("injected bootstrap panic")
            },
        );
        let text = result
            .err()
            .expect("startup panic must fail launch")
            .to_string();
        assert!(text.contains("injected bootstrap panic"), "{text}");
        assert!(text.contains("worker 0 panicked"), "{text}");
    }

    /// A panic after `launch()` has returned is not a startup failure: the
    /// worker's `JoinHandle` must still resolve to `Err(payload)` exactly as
    /// before the startup channel learned to carry panics.
    #[test]
    fn post_startup_panic_keeps_the_join_panic_contract() {
        let (go_tx, go_rx) = crossbeam_channel::bounded::<()>(1);
        let launched = RinglineBuilder::new(one_worker_config())
            .launch_inner(
                move |_, _, _, _eventfd, _, _, _, _, _, _, _, _, _, _, _, startup_tx| {
                    let _ = startup_tx.send(Ok(()));
                    drop(startup_tx);
                    let _ = go_rx.recv();
                    panic!("injected steady-state panic")
                },
            )
            .expect("startup succeeds");
        let (shutdown, handles) = launched;
        // launch() has returned, so the startup receiver is gone; now panic.
        go_tx.send(()).unwrap();
        let mut saw_panic = false;
        for handle in handles {
            match handle.join() {
                Err(payload) => {
                    saw_panic = true;
                    assert_eq!(
                        super::panic_payload(&*payload),
                        "injected steady-state panic"
                    );
                }
                Ok(other) => panic!("join must surface the panic, got {other:?}"),
            }
        }
        assert!(saw_panic);
        drop(shutdown);
    }

    #[test]
    fn panic_payload_renders_common_payload_types() {
        let s: Box<dyn std::any::Any + Send> = Box::new(String::from("owned"));
        assert_eq!(super::panic_payload(&*s), "owned");
        let st: Box<dyn std::any::Any + Send> = Box::new("static");
        assert_eq!(super::panic_payload(&*st), "static");
        let other: Box<dyn std::any::Any + Send> = Box::new(42u32);
        assert_eq!(super::panic_payload(&*other), "non-string panic payload");
    }
}
