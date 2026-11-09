use std::any::Any;
use std::io;
#[cfg(target_os = "linux")]
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::acceptor::{AcceptorConfig, run_acceptor};
use crate::backend::AsyncEventLoop;
use crate::config::Config;
use crate::listener_sockets::ListenerSockets;
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

/// The error a failed `launch()` returns after rolling back the workers. A
/// task panic on a worker, under `TaskPanicPolicy::Shutdown`, is what made
/// the launch fail, so it wins over the error the launch saw.
fn launch_error(
    joined: Option<crate::error::Error>,
    error: crate::error::Error,
) -> crate::error::Error {
    match joined {
        Some(panicked @ crate::error::Error::TaskPanicked(_)) => panicked,
        _ => error,
    }
}

/// Returned by `launch()` with the workers' join handles. Controls shutdown,
/// listener addresses, deferred listeners and registered
/// regions.
///
/// Dropping it calls [`shutdown`](Self::shutdown); join the handles to wait
/// for the workers to exit. [`ListenHandle`](crate::ListenHandle) and
/// [`WakeHandle`](crate::WakeHandle) implement `Clone`, and dropping them does
/// not shut the workers down.
pub struct Runtime {
    /// Shared with the workers, so a task panic can shut the runtime down.
    shutdown: Arc<RuntimeShutdown>,
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
    #[cfg_attr(
        not(all(target_os = "linux", any(feature = "unstable-accept", test))),
        allow(dead_code)
    )]
    accepting: Arc<Vec<std::sync::atomic::AtomicBool>>,
    /// Read on the io_uring backend by `register_region` /
    /// `unregister_region`; on the mio backend it sits unused but is kept
    /// so the field layout is identical across backends.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    region_registrar: Arc<crate::region_registry::RegionRegistrar>,
    /// The listen gates, for [`listen_handle`](Self::listen_handle).
    /// `shutdown()` reaches them through `RuntimeShutdown`.
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

    /// Every UDP bind's address, in the order [`UdpSocket::index`] uses:
    /// `ConfigBuilder::udp_bind` / `udp_bind_connected` addresses first, then
    /// `RinglineBuilder::bind_udp` / `bind_udp_connected`, each in call order.
    ///
    /// A zero port reports the port the kernel chose, which every worker's
    /// socket for that bind shares. A connected zero-port bind reports
    /// `None`. Each worker's socket has its own port and receives the replies
    /// to what it sent.
    ///
    /// [`UdpSocket::index`]: crate::UdpSocket::index
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
    /// Only affects listeners in `AcceptMode::Merged`:
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
    /// imbalance it was meant to fix — or to put back a worker that has
    /// stopped.
    ///
    /// A worker taken out returns to the rotation by itself if every worker
    /// in it stops.
    ///
    /// Otherwise a no-op when no listener is steerable (pool mode, Unix
    /// listeners, client-only, or a non-Linux build).
    ///
    /// Requires the `unstable-accept` feature. Outside semver.
    #[cfg(all(target_os = "linux", any(feature = "unstable-accept", test)))]
    pub fn set_worker_accepting(&self, worker: usize, accepting: bool) -> io::Result<()> {
        use std::sync::atomic::Ordering;
        if worker >= self.accepting.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker index out of range",
            ));
        }
        let _steering = self
            .shutdown
            .steering
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if accepting && self.shutdown.has_exited(worker) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker has exited",
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
            // Gone once the workers have exited after a shutdown.
            let Some(sockets) = listener.sockets.upgrade() else {
                continue;
            };
            let Some(fd) = sockets.fds().next() else {
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
    ///   `register_buffers_update` call fails. The slot is then released on
    ///   every worker, and reused by a later registration if every release
    ///   succeeds.
    /// - `io::ErrorKind::Other` if a worker has exited. The slot is not
    ///   reused, so each such failure leaves one fewer free slot.
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

    /// Block the calling thread until `SIGINT` or `SIGTERM` is received, a
    /// task panic shuts the runtime down under
    /// [`TaskPanicPolicy::Shutdown`](crate::TaskPanicPolicy::Shutdown), or a
    /// worker stops, then trigger graceful shutdown.
    ///
    /// Returns which signal was caught,
    /// [`Signal::TaskPanic`](crate::signal::Signal::TaskPanic), or
    /// [`Signal::WorkerExited`](crate::signal::Signal::WorkerExited). After a
    /// task panic, the handle of each worker on which a task panicked returns
    /// [`Error::TaskPanicked`](crate::Error::TaskPanicked).
    ///
    /// A worker stops on a panic in the runtime or an error from its ring or
    /// poll, under either policy. Its handle returns the error or the panic,
    /// or [`Error::TaskPanicked`](crate::Error::TaskPanicked) if a task panicked
    /// on it first under `Shutdown`. Its connections close and the other
    /// workers keep serving until the runtime shuts down, so a process that
    /// does not call this method runs on with fewer workers, and
    /// [`register_region`](Self::register_region) and
    /// [`unregister_region`](Self::unregister_region) fail from then on.
    pub fn wait_on_signal(&self) -> crate::signal::Signal {
        let sig = crate::signal::wait_or_ready(self.shutdown.panic_fd(), self.shutdown.exit_fd());
        self.shutdown();
        sig
    }

    /// Signal all workers to shut down gracefully.
    ///
    /// Workers stop accepting new connections, close all active connections (on
    /// io_uring, cancelling each connection's operations in flight and waiting up
    /// to 10 s for the connections to close), and exit their event loops
    /// returning `Ok(())`, or [`Error::TaskPanicked`](crate::Error::TaskPanicked)
    /// under [`TaskPanicPolicy::Shutdown`](crate::TaskPanicPolicy::Shutdown) for
    /// a worker on which a task panicked.
    ///
    /// A worker checks for shutdown once per event-loop iteration. Once it sees
    /// the request it polls no task again and drops every task's future. The
    /// futures' `Drop` implementations run, and a task does not resume from the
    /// `.await` it is suspended at. A task woken after the worker's last poll
    /// pass is dropped even when what it awaited is ready. On both backends a
    /// task can be woken after the iteration's last poll pass, for example from
    /// `on_tick`, by a send result, by released send capacity or from another
    /// thread. On io_uring the check also comes after the completions its wait
    /// returned are drained, so a task woken by one of those completions is
    /// dropped too. Work that must finish before exit has to complete before
    /// shutdown is requested.
    ///
    /// The listeners stop accepting at once on Linux, and within about 100 ms
    /// elsewhere. A listener's sockets close, and its port is free, once the
    /// threads accepting on it have exited: its acceptor thread, or with the
    /// `unstable-accept` feature in merged accept mode the workers. An
    /// acceptor exits at once on Linux. On other
    /// platforms, or holding a connection no worker has room for, it exits
    /// within about 100 ms. This `Runtime` does not hold the sockets open.
    pub fn shutdown(&self) {
        self.shutdown.shutdown();
    }
}

/// Everything [`Runtime::shutdown`] acts on, shared with the workers so that a
/// task panic under [`TaskPanicPolicy::Shutdown`](crate::TaskPanicPolicy::Shutdown)
/// shuts the runtime down the same way.
pub(crate) struct RuntimeShutdown {
    flag: Arc<AtomicBool>,
    listen_gates: Arc<crate::listen_gate::ListenGates>,
    /// Each listener's sockets and whether it is merged, added as `launch()`
    /// creates the listeners and released by `shutdown()`.
    listeners: std::sync::Mutex<Vec<(Arc<ListenerSockets>, bool)>>,
    wake: crate::wakeup::WakeKeepAlive,
    /// Readable once a task panic has shut the runtime down;
    /// [`Runtime::wait_on_signal`] polls it alongside the signal pipe.
    panic_read: OwnedFd,
    panic_write: OwnedFd,
    panicked: AtomicBool,
    /// Readable once a worker has stopped abnormally.
    /// [`Runtime::wait_on_signal`] polls it alongside the signal pipe.
    exit_read: OwnedFd,
    exit_write: OwnedFd,
    /// The workers that stopped abnormally.
    exited: std::sync::Mutex<Vec<usize>>,
    /// The accept rotation, set by `launch()`. See `Runtime::accepting`.
    accepting: std::sync::OnceLock<Arc<Vec<AtomicBool>>>,
    /// Held from reading the rotation through attaching the program built from
    /// it, so two changes cannot attach out of order.
    #[cfg(target_os = "linux")]
    steering: std::sync::Mutex<()>,
}

/// Accept and close every connection queued on a listening socket.
#[cfg(target_os = "linux")]
fn close_queued(fd: RawFd) {
    let nonblocking: libc::c_int = 1;
    unsafe { libc::ioctl(fd, libc::FIONBIO, &nonblocking) };
    loop {
        let conn = unsafe {
            libc::accept4(
                fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if conn < 0 {
            return;
        }
        unsafe { libc::close(conn) };
    }
}

/// A non-blocking, close-on-exec pipe: `(read end, write end)`.
fn nonblocking_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    #[cfg(target_os = "linux")]
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(not(target_os = "linux"))]
    {
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        for fd in fds {
            unsafe {
                libc::fcntl(
                    fd,
                    libc::F_SETFL,
                    libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
                );
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
    }
    // SAFETY: `pipe` returned two fresh descriptors nothing else owns.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

impl RuntimeShutdown {
    fn new(
        flag: Arc<AtomicBool>,
        listen_gates: Arc<crate::listen_gate::ListenGates>,
        wake: crate::wakeup::WakeKeepAlive,
    ) -> io::Result<Self> {
        let (panic_read, panic_write) = nonblocking_pipe()?;
        let (exit_read, exit_write) = nonblocking_pipe()?;
        Ok(RuntimeShutdown {
            flag,
            listen_gates,
            listeners: std::sync::Mutex::new(Vec::new()),
            wake,
            panic_read,
            panic_write,
            panicked: AtomicBool::new(false),
            exit_read,
            exit_write,
            exited: std::sync::Mutex::new(Vec::new()),
            accepting: std::sync::OnceLock::new(),
            #[cfg(target_os = "linux")]
            steering: std::sync::Mutex::new(()),
        })
    }

    fn add_listener(&self, sockets: Arc<ListenerSockets>, merged: bool) {
        self.listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((sockets, merged));
        // A shutdown that ran before this listener was added did not shut it
        // down; run it again now that it is added. Idempotent.
        if self.flag.load(Ordering::Acquire) {
            self.shutdown();
        }
    }

    /// Set the shutdown flag, release the listen gates, shut the listener
    /// sockets down and wake every worker. Idempotent.
    ///
    /// Releases this struct's hold on the sockets, as `ListenGates::shutdown`
    /// releases the gates'. They close when the threads that accept on them,
    /// the acceptor or in merged mode the workers, have exited.
    pub(crate) fn shutdown(&self) {
        self.flag.store(true, Ordering::Release);
        // Before the sockets are shut down: an acceptor parked on a gate that
        // was never opened is not inside `accept4`, so `SHUT_RD` does not
        // reach it, and after this call no gate starts a socket listening.
        self.listen_gates.shutdown();
        let listeners =
            std::mem::take(&mut *self.listeners.lock().unwrap_or_else(|e| e.into_inner()));
        for (sockets, _) in listeners {
            // Wakes an acceptor blocked in `accept4`, and in merged mode ends
            // the multishot accept a worker has armed on each socket.
            sockets.shut_down();
        }
        // Wake all workers so they see the flag even if blocked on I/O.
        for wh in self.wake.iter() {
            wh.wake();
        }
    }

    /// Shut down after a task panic, and wake [`Runtime::wait_on_signal`].
    pub(crate) fn shutdown_for_panic(&self) {
        self.shutdown();
        if !self.panicked.swap(true, Ordering::AcqRel) {
            let byte = 1u8;
            unsafe {
                libc::write(self.panic_write.as_raw_fd(), (&byte as *const u8).cast(), 1);
            }
        }
    }

    fn panic_fd(&self) -> RawFd {
        self.panic_read.as_raw_fd()
    }

    fn exit_fd(&self) -> RawFd {
        self.exit_read.as_raw_fd()
    }

    /// Record that `worker` stopped abnormally: take it out of the accept
    /// rotation, wake [`Runtime::wait_on_signal`], and shut the runtime down if
    /// `shutdown` is set. Runs on that worker's thread, before it closes its
    /// connections.
    pub(crate) fn worker_exited(&self, worker: usize, shutdown: bool) {
        self.exited
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(worker);
        #[cfg(target_os = "linux")]
        self.stop_accepting(worker);
        let byte = 1u8;
        unsafe {
            libc::write(self.exit_write.as_raw_fd(), (&byte as *const u8).cast(), 1);
        }
        if shutdown {
            self.shutdown();
        }
    }

    #[cfg(all(target_os = "linux", any(feature = "unstable-accept", test)))]
    fn has_exited(&self, worker: usize) -> bool {
        self.exited
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&worker)
    }

    /// Steer the merged listeners away from `worker` and close what is queued
    /// on its sockets. The sockets stay bound until the runtime shuts down:
    /// closing one reorders its group, and a steering program selects by
    /// position in the group. With no worker left to accept, the listeners are
    /// shut down. If only workers taken out of the rotation are left, they go
    /// back in.
    #[cfg(target_os = "linux")]
    fn stop_accepting(&self, worker: usize) {
        let Some(accepting) = self.accepting.get() else {
            return;
        };
        let _steering = self.steering.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(flag) = accepting.get(worker) {
            flag.store(false, Ordering::Release);
        }
        let exited = self
            .exited
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let alive: Vec<u32> = (0..accepting.len() as u32)
            .filter(|i| !exited.contains(&(*i as usize)))
            .collect();
        let mut live: Vec<u32> = alive
            .iter()
            .copied()
            .filter(|i| accepting[*i as usize].load(Ordering::Acquire))
            .collect();
        if live.is_empty() && !alive.is_empty() {
            let _ = writeln!(
                io::stderr(),
                "ringline: worker {worker} exited; returning {alive:?} to the accept rotation"
            );
            for i in &alive {
                accepting[*i as usize].store(true, Ordering::Release);
            }
            live = alive;
        }
        let listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        for (sockets, _) in listeners.iter().filter(|(_, merged)| *merged) {
            if live.is_empty() {
                sockets.shut_down();
                continue;
            }
            if let Some(fd) = sockets.fds().next()
                && let Err(e) = crate::reuseport_bpf::attach_live_set(fd, &live)
            {
                let _ = writeln!(
                    io::stderr(),
                    "ringline: steering around worker {worker} failed: {e}"
                );
            }
            close_queued(sockets.fd(worker));
        }
    }

    /// Close what reached `worker`'s merged sockets while it drained: a
    /// handshake that began before the steering can finish after it.
    pub(crate) fn worker_drained(&self, worker: usize) {
        #[cfg(target_os = "linux")]
        for (sockets, merged) in self
            .listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            if *merged {
                close_queued(sockets.fd(worker));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = worker;
    }

    /// Apply earlier worker exits to listeners added since.
    fn reapply_exits(&self) {
        #[cfg(target_os = "linux")]
        {
            let exited = self
                .exited
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            for worker in exited {
                self.stop_accepting(worker);
            }
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
        //   * `ListenerSockets::shut_down` only sets a socket option and
        //     calls `shutdown(SHUT_RD)`, both of which can repeat.
        //   * `WakeHandle::wake` after the workers have joined writes
        //     into a wake fd that is still open but unread; it never
        //     errors.
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
    /// One socket in pool mode. In merged mode, one `SO_REUSEPORT` socket per
    /// worker, all bound to the same address. Weak, so the sockets close once
    /// the threads accepting on them exit after a shutdown, while the
    /// `Runtime` is still alive.
    #[cfg_attr(
        not(all(target_os = "linux", any(feature = "unstable-accept", test))),
        allow(dead_code)
    )]
    sockets: std::sync::Weak<ListenerSockets>,
    /// `Some` for a TCP listener (after zero-port resolution), `None` for Unix.
    bound_addr: Option<SocketAddr>,
    /// Whether `sockets` form a `SO_REUSEPORT` group that can be steered —
    /// true only for a merged-mode TCP listener, where socket `i` belongs to
    /// worker `i`. A pool-mode listener has a single socket and no group to steer.
    ///
    /// Only read by `set_worker_accepting`, which is Linux-only because
    /// reuseport steering is.
    #[cfg_attr(
        not(all(target_os = "linux", any(feature = "unstable-accept", test))),
        allow(dead_code)
    )]
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
    /// The port is reserved against sockets that do not set `SO_REUSEADDR`.
    /// On Linux below 6.8, and on 7.4 or any stable kernel with upstream commit
    /// 947ccedf683e, a socket that sets it can also bind the port, but cannot
    /// listen on it while the port is held. The kernel does not complete
    /// handshakes on this listener, so a TCP readiness probe fails while the
    /// server is not ready. On Linux the peer is refused with `ECONNREFUSED`;
    /// on macOS and the BSDs the SYN is dropped and the peer times out.
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
    /// With the `unstable-accept` feature, not supported with
    /// `AcceptMode::Merged` on the io_uring backend, where `launch()` refuses
    /// the combination.
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
    /// to `peer`, on both backends. On io_uring the runtime also uses the
    /// lighter `RecvUdp`/`SendUdp` opcodes instead of
    /// `RecvMsgUdp`/`SendMsgUdp`, which saves ~4 microseconds per round trip
    /// on single-shot client workloads.
    ///
    /// `launch` returns an error if `connect(2)` fails, for example when
    /// `peer` is in a different address family from `local`. A `send_to` an
    /// address other than `peer` is sent on Linux; on macOS it fails with
    /// `EISCONN`.
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
            self.config.accept_mode == crate::accept::AcceptMode::Merged && cfg!(has_io_uring);
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
             park_rx,
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
                    park_rx,
                    eventfd.0,
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
                    drop(park_rx);
                    AsyncEventLoop::new(
                        &config,
                        handler,
                        accept_rx,
                        eventfd.0,
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
                if let Err(e) = event_loop.prepare_run() {
                    let _ = startup_tx.send(Err(e));
                    return Err(startup_failure_placeholder());
                }

                // Signal only after the backend preparation Ringline knows can
                // fail before `run()`. This lets `launch()` surface those
                // errors rather than burying them in an unjoined worker.
                let _ = startup_tx.send(Ok(()));
                drop(startup_tx);
                // An unwind out of here would free memory the kernel can
                // still use and skip the close of every connection, so a
                // panic in the runtime is caught where `event_loop` outlives
                // it.
                let run_result = catch_unwind(AssertUnwindSafe(|| event_loop.run()));
                let cause = match &run_result {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(e.to_string()),
                    Err(payload) => Some(format!("panic: {}", panic_payload(&**payload))),
                };
                if let Some(cause) = cause {
                    event_loop.report_worker_exit(worker_id, &cause);
                    let drained =
                        catch_unwind(AssertUnwindSafe(|| event_loop.drain_after_failure()));
                    event_loop.report_worker_drained(worker_id);
                    if drained.is_err() {
                        let task_panic = event_loop.take_task_panic();
                        // Safety: `event_loop` is leaked on the next line, so
                        // nothing uses the ring again.
                        unsafe { event_loop.close_ring() };
                        std::mem::forget(event_loop);
                        return match (task_panic, run_result) {
                            (Some(panic), _) => Err(crate::error::Error::TaskPanicked(panic)),
                            (None, Ok(result)) => result,
                            (None, Err(payload)) => std::panic::resume_unwind(payload),
                        };
                    }
                }
                event_loop.drop_tasks();
                // Under `TaskPanicPolicy::Shutdown`, a panic on this worker
                // shut the runtime down; report it as this worker's result,
                // ahead of any error from the drain that followed.
                let task_panic = event_loop.take_task_panic();
                // A `Drop` that panics here must not replace the panic below.
                if run_result.is_err() {
                    let _ = crate::task_panic::drop_caught(event_loop);
                } else {
                    drop(event_loop);
                }
                match (task_panic, run_result) {
                    (Some(panic), _) => Err(crate::error::Error::TaskPanicked(panic)),
                    (None, Ok(result)) => result,
                    (None, Err(payload)) => std::panic::resume_unwind(payload),
                }
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
                Option<crate::handoff::Receiver<crate::acceptor::AcceptedConn>>,
                Option<crate::handoff::Receiver<crate::park::ParkedFd>>,
                (RawFd, crate::wakeup::WakeFd),
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
        // too-small buffer silently truncates datagrams). `bind_tls` adds TLS
        // the same way, so the per-listener configs are filled in first for
        // the TLS slot-size check.
        self.config.listener_tls = self.listeners.iter().map(|l| l.tls.clone()).collect();
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
        ensure_memlock_limit(&self.config, num_threads)?;

        crate::metrics::init_metadata();

        // Create per-worker channels and wake fds. `worker_wake_handles`
        // (Arc-based) is what `Runtime` keeps and what
        // `worker_wake_handle()` hands out to users; `worker_wake_fds`
        // (Copy) is what internal request structs and peer handoff use on hot
        // paths; the acceptor takes owning `WakeHandle`s.
        let mut worker_txs = Vec::with_capacity(num_threads);
        let mut worker_rxs = Vec::with_capacity(num_threads);
        let mut worker_eventfds = Vec::with_capacity(num_threads);
        let mut worker_wake_fds = Vec::with_capacity(num_threads);
        let mut worker_wake_handles = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            // Bounded so a slow worker applies backpressure on the acceptor
            // rather than queuing fds indefinitely. On full, the acceptor
            // tries the next worker; if every worker is full, it stops
            // accepting until one has room, which leaves connections in the
            // kernel's listen queue.
            let (tx, rx) = crate::handoff::bounded::<crate::acceptor::AcceptedConn>(
                self.config.accept_queue_capacity,
            );
            let (read_fd, wake_handle) =
                crate::wakeup::create_wake_fd().map_err(crate::error::Error::Io)?;
            worker_txs.push(tx);
            worker_rxs.push(rx);
            // Not owning: `wake_handle` owns the read side (the eventfd on
            // io_uring, the pipe's read end on mio) and closes it.
            worker_eventfds.push(read_fd);
            worker_wake_fds.push(wake_handle.as_wake_fd());
            worker_wake_handles.push(wake_handle);
        }
        // The pool threads and the workers each hold a clone of this for as
        // long as they run; each acceptor holds its own `WakeHandle` clones.
        // The `WakeFd`s those threads carry do not own the fds. This keeps the
        // fds open after `Runtime` drops, until the last such thread exits, so
        // a late wake cannot write into a reused fd number.
        let wake_keep_alive: crate::wakeup::WakeKeepAlive =
            worker_wake_handles.iter().cloned().collect();

        // Park channels (tier 3, #443): a sibling of the accept channels so
        // the mio backend, which has neither merged accept nor park, is not
        // made to carry a variant it can never receive. Bounded for the same
        // reason as the accept channels — a slow worker must apply
        // backpressure rather than queue connections without limit.
        //
        // Created only for merged accept mode. A bounded channel allocates
        // its capacity upfront, so building these unconditionally
        // costs `workers * accept_queue_capacity * size_of::<ParkedFd>()` —
        // hundreds of KiB per runtime at the default 1024 — in pool mode,
        // which is the default and can never park.
        let park_enabled =
            self.config.accept_mode == crate::accept::AcceptMode::Merged && cfg!(has_io_uring);
        let mut park_txs = Vec::new();
        let mut park_rxs = Vec::new();
        if park_enabled {
            park_txs.reserve(num_threads);
            park_rxs.reserve(num_threads);
            for _ in 0..num_threads {
                let (tx, rx) = crate::handoff::bounded::<crate::park::ParkedFd>(
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
                wake_keep_alive.clone(),
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
                wake_keep_alive.clone(),
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
                wake_keep_alive.clone(),
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
        let runtime_shutdown = Arc::new(
            RuntimeShutdown::new(
                shutdown_flag.clone(),
                listen_gates.clone(),
                wake_keep_alive.clone(),
            )
            .map_err(crate::error::Error::Io)?,
        );
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
            self.config.accept_mode == crate::accept::AcceptMode::Merged && cfg!(has_io_uring);
        let mut merged_sockets: Vec<(u32, Arc<ListenerSockets>, Option<SocketAddr>)> = Vec::new();
        if merged_mode {
            for (idx, spec) in pending_listeners.iter().enumerate() {
                let BindAddr::Tcp(addr) = &spec.addr else {
                    continue;
                };
                let mut fds: Vec<OwnedFd> = Vec::with_capacity(num_threads);
                let mut resolved: Option<SocketAddr> = None;
                let mut failure = None;
                for _ in 0..num_threads {
                    let target = resolved.unwrap_or(*addr);
                    match bind_reuseport_socket(target) {
                        Ok(fd) => {
                            if resolved.is_none() {
                                resolved = getsockname_v4_v6(fd.as_raw_fd());
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
                    let joined = rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                    return Err(launch_error(joined, e));
                }
                merged_sockets.push((idx as u32, ListenerSockets::new(fds), resolved));
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
        let worker_accepting: Arc<Vec<AtomicBool>> = Arc::new(
            (0..num_threads)
                .map(|_| std::sync::atomic::AtomicBool::new(true))
                .collect(),
        );
        let _ = runtime_shutdown.accepting.set(worker_accepting.clone());

        for worker_id in 0..num_threads {
            let mut config = self.config.clone();
            // The worker holds every merged listener's sockets until it exits,
            // so they stay open while it can arm an accept on its own one.
            config.merged_listeners = merged_sockets
                .iter()
                .map(|(idx, sockets, _)| (*idx, Arc::clone(sockets)))
                .collect();
            config.merged_accept_live = merged_live.clone();
            // The worker's hold on every wake fd: `config` lives in the worker
            // thread until it exits. Its event loop reads its own wake fd by
            // number (the eventfd on io_uring, the pipe's read end on mio), and
            // in merged accept mode (io_uring) it wakes peers.
            config.wake_keep_alive = Some(wake_keep_alive.clone());
            config.runtime_shutdown = Some(runtime_shutdown.clone());
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
            let park_rx = if park_enabled {
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
                            park_rx,
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
                    let joined = rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                    return Err(launch_error(joined, crate::error::Error::Io(error)));
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
                let created: Result<
                    (Arc<ListenerSockets>, Option<SocketAddr>),
                    crate::error::Error,
                > = match (&spec.addr, merged_entry) {
                    (BindAddr::Tcp(_), Some((_, sockets, resolved))) => {
                        Ok((Arc::clone(sockets), *resolved))
                    }
                    (BindAddr::Tcp(addr), None) => create_listener(*addr).map(|fd| {
                        let bound = getsockname_v4_v6(fd.as_raw_fd());
                        (ListenerSockets::new(vec![fd]), bound)
                    }),
                    (BindAddr::Unix(path), _) => {
                        create_unix_listener(path).map(|fd| (ListenerSockets::new(vec![fd]), None))
                    }
                };
                let (sockets, bound_addr) = match created {
                    Ok(created) => created,
                    Err(error) => {
                        // Shut down the listeners already bound, or a
                        // listening socket keeps accepting into workers that
                        // are being joined. Their sockets close as the
                        // acceptors exit and `launch()` returns.
                        runtime_shutdown.shutdown();
                        let joined = rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                        return Err(launch_error(joined, error));
                    }
                };

                // The gate owns the `listen(2)` call for these sockets from
                // here on. `register` itself can listen: a handler whose
                // `on_start` released this gate before `launch()` got here
                // recorded the request, and `register` honours it.
                let registered = listen_gates.register(idx as u32, Arc::clone(&sockets));
                if let Err(error) = registered.and_then(|()| {
                    if spec.defer_listen {
                        Ok(())
                    } else {
                        listen_gates.open(idx as u32)
                    }
                }) {
                    runtime_shutdown.shutdown();
                    // Not yet added to `runtime_shutdown`, and `register` may
                    // have started it listening.
                    sockets.shut_down();
                    let joined = rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                    return Err(launch_error(joined, crate::error::Error::Io(error)));
                }

                // Merged mode has no acceptor thread: the workers arm their own
                // multishot accept on these sockets. Record the listener and
                // move on.
                runtime_shutdown.add_listener(Arc::clone(&sockets), merged_entry.is_some());
                if merged_entry.is_some() {
                    listeners.push(ListenerHandle {
                        sockets: Arc::downgrade(&sockets),
                        bound_addr,
                        steerable: true,
                    });
                    continue;
                }

                let acceptor_sockets = Arc::clone(&sockets);
                let spawn_result = {
                    let acceptor_config = AcceptorConfig {
                        sockets: Arc::clone(&sockets),
                        listener: crate::ListenerId::from_index(idx as u32),
                        worker_channels: worker_txs.clone(),
                        worker_wake_handles: worker_wake_handles.clone(),
                        shutdown_flag: shutdown_flag.clone(),
                        listen_gates: listen_gates.clone(),
                        // A Unix listener has no TCP_NODELAY to set.
                        tcp_nodelay: !spec.addr.is_unix() && self.config.tcp_nodelay,
                        conn_chunk_size: self.config.conn_chunk_size,
                    };
                    thread::Builder::new()
                        .name(format!("ringline-acceptor-{idx}"))
                        .spawn(move || {
                            run_acceptor(acceptor_config);
                            // An acceptor that stops on its own, because every
                            // worker has exited, must not leave the socket
                            // listening with nothing accepting.
                            acceptor_sockets.shut_down();
                        })
                };

                if let Err(error) = spawn_result {
                    runtime_shutdown.shutdown();
                    let joined = rollback_workers(&shutdown_flag, &worker_wake_fds, handles);
                    return Err(launch_error(joined, crate::error::Error::Io(error)));
                }

                listeners.push(ListenerHandle {
                    sockets: Arc::downgrade(&sockets),
                    bound_addr,
                    steerable: false,
                });
            }
            // Every merged socket is listening now, so the workers may arm.
            // Publishing the flag before the wake means a worker that checks on
            // its own schedule still sees it.
            // A task panic during launch shut the runtime down: leave the
            // workers unarmed.
            runtime_shutdown.reapply_exits();
            if let Some(ref live) = merged_live
                && !shutdown_flag.load(Ordering::Acquire)
            {
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
            shutdown: runtime_shutdown,
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

/// Make sure `RLIMIT_MEMLOCK` covers what the workers' rings will charge to it,
/// before any worker thread exists.
///
/// Every worker registers the configured regions as fixed buffers, and on
/// Linux 6.14+ each worker's ring and its UDP provided buffer rings are charged too
/// (see [`crate::memlock`]). The kernel's default limit is 8 MiB (64 KiB
/// before Linux 5.16), and it reports a shortfall as a bare `ENOMEM`. When
/// the hard limit covers the need, this raises the soft limit to the hard
/// limit, which leaves room for the charges it cannot count. Otherwise it
/// fails with the fix spelled out.
///
/// The kernel compares the limit with everything the same user has charged in
/// any process, which this cannot see, so passing here does not rule out an
/// `ENOMEM` at setup; the setup error names the limit in that case. A region
/// added later through `Runtime::register_region` is not counted here; if that
/// call fails with `ENOMEM`, its error names the limit.
#[cfg(has_io_uring)]
fn ensure_memlock_limit(config: &Config, workers: usize) -> Result<(), crate::error::Error> {
    use crate::error::{MemlockLimit, MemlockPlan, describe_memlock_shortfall, memlock_plan};
    use crate::memlock::{KernelVersion, charges_rings, has_cap_ipc_lock};

    if has_cap_ipc_lock() {
        return Ok(());
    }
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let kernel = KernelVersion::current();
    let required = memlock_required(config, workers, charges_rings(kernel), page);
    if required == 0 {
        return Ok(());
    }
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
        MemlockPlan::HardTooLow => {
            let mut what = format!("{workers} worker(s)");
            if charges_rings(kernel) {
                what.push_str(&match kernel {
                    Some(k) => format!(", whose io_uring rings Linux {k} charges to the limit,"),
                    None => ", whose io_uring rings this kernel may charge to the limit,".into(),
                });
            }
            if !config.registered_regions.is_empty() {
                what.push_str(&format!(
                    " each registering {} region(s)",
                    config.registered_regions.len()
                ));
            }
            Err(crate::error::Error::ResourceLimit(
                describe_memlock_shortfall(required, &limit, &what),
            ))
        }
    }
}

/// The bytes `workers` workers charge to `RLIMIT_MEMLOCK` when they start:
/// each worker's registered regions, plus its ring and one provided buffer
/// ring per UDP socket when the kernel charges those (`charges_rings`).
#[cfg(any(has_io_uring, test))]
fn memlock_required(config: &Config, workers: usize, charges_rings: bool, page: u64) -> u64 {
    use crate::memlock::{provided_ring_bytes, ring_bytes};

    // The kernel pins every page the region touches. This assumes base pages:
    // a region backed by huge pages is charged in whole huge pages.
    let regions: u64 = config
        .registered_regions
        .iter()
        .map(|r| {
            let start = r.ptr() as u64;
            ((start + r.len() as u64).div_ceil(page) - start / page) * page
        })
        .sum();
    let rings = if charges_rings {
        let mut bytes = ring_bytes(config.sq_entries, page);
        bytes += config.udp_bind.len() as u64
            * provided_ring_bytes(config.udp_recv_buffer.ring_size, page);
        bytes
    } else {
        0
    };
    (regions + rings) * workers as u64
}

/// Pin the current thread to a specific CPU core.
///
/// A `core` that `cpu_set_t` cannot hold is an `InvalidInput` error.
/// `libc::CPU_SET` panics on it, and the panic cannot unwind, so the process
/// aborts.
#[cfg(target_os = "linux")]
fn pin_to_core(core: usize) -> Result<(), crate::error::Error> {
    let capacity = 8 * std::mem::size_of::<libc::cpu_set_t>();
    if core >= capacity {
        return Err(crate::error::Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("CPU {core} is beyond the {capacity} CPUs an affinity mask can name"),
        )));
    }
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
fn bind_reuseport_socket(addr: SocketAddr) -> Result<OwnedFd, crate::error::Error> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let owned = stream_socket(domain).map_err(crate::error::Error::Io)?;
    let fd = owned.as_raw_fd();
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
            return Err(crate::error::Error::Io(io::Error::last_os_error()));
        }
    }

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let addr_len = crate::backend::socket_addr_to_sockaddr(addr, &mut storage);
    let ret = unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, addr_len) };
    if ret < 0 {
        return Err(crate::error::Error::Io(io::Error::last_os_error()));
    }
    Ok(owned)
}

/// A new close-on-exec stream socket in `domain`.
///
/// Close-on-exec, so a process spawned while the runtime runs does not inherit
/// a listener and hold its port open after the runtime has shut it down.
fn stream_socket(domain: libc::c_int) -> io::Result<OwnedFd> {
    #[cfg(target_os = "linux")]
    let sock_type = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let sock_type = libc::SOCK_STREAM;
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
/// SO_REUSEADDR is set for the bind and cleared immediately after it, so a
/// second socket cannot listen on the port, and on Linux 6.8 to 7.3 without
/// 947ccedf683e cannot bind it, while this socket is not yet listening. `ListenGates` sets it again just
/// before `listen(2)`.
pub(crate) fn create_listener(addr: SocketAddr) -> Result<OwnedFd, crate::error::Error> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };

    let owned = stream_socket(domain).map_err(crate::error::Error::Io)?;
    let fd = owned.as_raw_fd();

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
        return Err(crate::error::Error::Io(io::Error::last_os_error()));
    }

    // Clear SO_REUSEADDR now that the bind has succeeded, to reserve the port
    // against another process for as long as this socket holds it.
    //
    // Linux lets a second socket bind an address the first holds, while neither
    // is listening, if both have SO_REUSEADDR set. A listener therefore reserves
    // its port exclusively only once it listens, which with a deferred listen is
    // however long the handler takes. Clearing the flag refuses that bind when
    // the kernel runs the conflict check. The check is skipped when
    // `tb->fastreuse` is 1 and the second socket sets the flag, and the first
    // bind sets it to 1 below Linux 6.8 and on kernels with 947ccedf683e. On
    // those kernels the second socket binds, but its `listen(2)` fails with
    // EADDRINUSE while this socket has the flag cleared.
    // `listen_all` sets it again immediately before `listen(2)`, which
    // re-checks the port with the current flag and would otherwise fail
    // EADDRINUSE on a TIME_WAIT connection left by a previous instance.
    //
    // No effect on a listener that is not deferred: a listening socket
    // conflicts with a later bind regardless of the flag.
    //
    // Measured on Linux 6.12 aarch64 with plain sockets: left set, a second
    // bind succeeds; cleared after bind, it fails EADDRINUSE. Darwin refuses
    // the second bind either way. If another process binds in the window,
    // its `listen(2)` fails with EADDRINUSE until `listen_all` sets the flag
    // again. Only in the gap between that and this socket's `listen(2)` can it
    // listen first; this socket's `listen` then fails and `begin_listening`
    // reports it.
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

    Ok(owned)
}

/// Create a Unix domain socket listener at the given path.
///
/// Unlinks any existing socket file before binding.
fn create_unix_listener(path: &Path) -> Result<OwnedFd, crate::error::Error> {
    // Remove existing socket file if present (ignore errors — path may not exist).
    let _ = std::fs::remove_file(path);

    let fd = stream_socket(libc::AF_UNIX).map_err(crate::error::Error::Io)?;

    // Bind using the driver's sockaddr helper.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let addr_len = crate::backend::unix_path_to_sockaddr(path, &mut storage);

    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &storage as *const _ as *const libc::sockaddr,
            addr_len,
        )
    };
    if ret < 0 {
        return Err(crate::error::Error::Io(io::Error::last_os_error()));
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
                          _,
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
                        // Dropping `accepted` closes the connection.
                        drop(accepted);
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
                |_, _, _, _, _eventfd, _, _, _, _, _, _, _, _, _, _, _, startup_tx| {
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
            |_, _, _, _, _eventfd, _, _, _, _, _, _, _, _, _, _, _, startup_tx| {
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
            |_, _, _, _, _eventfd, _, _, _, _, _, _, _, _, _, _, _, _| {
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
                move |_, _, _, _, _eventfd, _, _, _, _, _, _, _, _, _, _, _, startup_tx| {
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

#[cfg(test)]
mod memlock_required_tests {
    use super::memlock_required;
    use crate::buffer::fixed::MemoryRegion;
    use crate::config::ConfigBuilder;

    const PAGE: u64 = 4096;

    fn builder() -> ConfigBuilder {
        ConfigBuilder::new().sq_entries(64)
    }

    #[test]
    fn rings_count_per_worker_only_when_the_kernel_charges_them() {
        let config = builder().build().unwrap();
        // The ring is 5 pages.
        assert_eq!(memlock_required(&config, 1, true, PAGE), 5 * PAGE);
        assert_eq!(memlock_required(&config, 4, true, PAGE), 20 * PAGE);
        assert_eq!(memlock_required(&config, 4, false, PAGE), 0);
    }

    #[test]
    fn the_udp_provided_ring_counts_only_with_a_udp_bind() {
        let without = builder().udp_recv_buffer(512, 2048).build().unwrap();
        assert_eq!(memlock_required(&without, 1, true, PAGE), 5 * PAGE);
        let mut with = without.clone();
        with.udp_bind.push("127.0.0.1:0".parse().unwrap());
        with.udp_connect_peers.push(None);
        // + 512 entries * 16 bytes = 2 pages.
        assert_eq!(memlock_required(&with, 1, true, PAGE), 7 * PAGE);
        // Each socket has its own ring.
        with.udp_bind.push("127.0.0.1:0".parse().unwrap());
        with.udp_connect_peers.push(None);
        assert_eq!(memlock_required(&with, 1, true, PAGE), 9 * PAGE);
    }

    /// A region at `addr`, for counting only: `memlock_required` reads its
    /// address and length and never touches the memory.
    fn region(addr: u64, len: u64) -> MemoryRegion {
        // SAFETY: the region is never registered or dereferenced.
        unsafe { MemoryRegion::new(addr as *mut u8, len as usize) }
    }

    #[test]
    fn a_region_costs_the_pages_it_touches() {
        let aligned = builder().registered_regions(vec![region(16 * PAGE, 3 * PAGE)]);
        assert_eq!(
            memlock_required(&aligned.build().unwrap(), 1, false, PAGE),
            3 * PAGE
        );
        let offset = builder().registered_regions(vec![region(16 * PAGE + 16, 3 * PAGE)]);
        assert_eq!(
            memlock_required(&offset.build().unwrap(), 1, false, PAGE),
            4 * PAGE
        );
    }

    #[test]
    fn every_worker_registers_every_region() {
        let config = builder()
            .registered_regions(vec![region(16 * PAGE, 3 * PAGE)])
            .build()
            .unwrap();
        assert_eq!(memlock_required(&config, 3, false, PAGE), 9 * PAGE);
        assert_eq!(memlock_required(&config, 3, true, PAGE), 3 * (3 + 5) * PAGE);
    }
}

/// A worker that stops because of a failure in the runtime: reported, steered
/// around, and its connections closed.
#[cfg(test)]
mod worker_exit_tests {
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    #[cfg(has_io_uring)]
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use crate::config::{ConfigBuilder, TestFault};
    use crate::error::Error;
    use crate::signal::Signal;
    use crate::{AcceptMode, AsyncEventHandler, Connection, ParseResult, RinglineBuilder};
    use crate::{Runtime, TaskPanicPolicy};

    /// A message that blocks the worker's thread for [`STALL_FOR`], so that
    /// connections and completions pile up behind it.
    const STALL: &[u8] = b"stall";
    const STALL_FOR: Duration = Duration::from_millis(300);

    struct Echo;

    impl AsyncEventHandler for Echo {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                loop {
                    let mut got = Vec::new();
                    let n = conn
                        .with_data(|d| {
                            got.extend_from_slice(d);
                            ParseResult::Consumed(d.len())
                        })
                        .await;
                    if got == STALL {
                        std::thread::sleep(STALL_FOR);
                    }
                    if n == 0 || conn.send_nowait(&got).is_err() {
                        return;
                    }
                }
            }
        }

        fn create_for_worker(_id: usize) -> Self {
            Echo
        }
    }

    type Handles = Vec<JoinHandle<Result<(), Error>>>;

    fn launch(
        workers: usize,
        mode: AcceptMode,
        policy: TaskPanicPolicy,
    ) -> (Arc<Runtime>, Handles, Arc<TestFault>) {
        let mut config = ConfigBuilder::new()
            .workers(workers)
            .pin_to_core(false)
            .sq_entries(64)
            .max_connections(64)
            .send_pool(32, 16384)
            .blocking_threads(1)
            .resolver_threads(0)
            .spawner_threads(0)
            .task_panic_policy(policy)
            .accept_mode(mode)
            .build()
            .expect("valid config");
        let fault = Arc::new(TestFault::default());
        config.test_fault = Some(fault.clone());
        let (runtime, handles) = RinglineBuilder::new(config)
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<Echo>()
            .expect("launch");
        (Arc::new(runtime), handles, fault)
    }

    fn wake_all(runtime: &Runtime, workers: usize) {
        for i in 0..workers {
            runtime.worker_wake_handle(i).unwrap().wake();
        }
    }

    /// What became of a connection when a byte was echoed through it.
    #[derive(Debug, PartialEq)]
    enum Echoed {
        Yes,
        Closed,
        Hung,
    }

    fn echo(stream: &mut TcpStream) -> Echoed {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        if stream.write_all(b"x").is_err() {
            return Echoed::Closed;
        }
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(1) => Echoed::Yes,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Echoed::Hung
            }
            _ => Echoed::Closed,
        }
    }

    /// Wait for `wait_on_signal` to return, for at most `within`.
    fn signal_within(runtime: &Arc<Runtime>, within: Duration) -> Option<Signal> {
        let waiter = runtime.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(waiter.wait_on_signal());
        });
        rx.recv_timeout(within).ok()
    }

    fn wait_for_exit(handles: &Handles, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while handles.iter().filter(|h| h.is_finished()).count() < count {
            assert!(Instant::now() < deadline, "no worker exited");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn connect_all(addr: std::net::SocketAddr, count: usize) -> Vec<TcpStream> {
        let mut streams: Vec<TcpStream> = (0..count)
            .map(|_| TcpStream::connect(addr).unwrap())
            .collect();
        for stream in &mut streams {
            assert_eq!(echo(stream), Echoed::Yes);
        }
        streams
    }

    /// The dead worker's connections close, the others keep working, and new
    /// connections are served.
    fn check_service_after_exit(runtime: &Runtime, streams: &mut [TcpStream], workers: usize) {
        let results: Vec<Echoed> = streams.iter_mut().map(echo).collect();
        let closed = results.iter().filter(|r| **r == Echoed::Closed).count();
        let served = results.iter().filter(|r| **r == Echoed::Yes).count();
        assert_eq!(
            closed + served,
            results.len(),
            "a connection hung: {results:?}"
        );
        assert!(closed > 0, "no connection closed: {results:?}");
        assert!(served > 0, "no connection survived: {results:?}");
        let addr = runtime.bound_addr().unwrap();
        for _ in 0..workers * 6 {
            let mut fresh = TcpStream::connect(addr).unwrap();
            assert_eq!(echo(&mut fresh), Echoed::Yes);
        }
    }

    #[test]
    fn a_panic_in_the_event_loop_leaves_the_other_workers_serving() {
        let (runtime, handles, fault) = launch(2, AcceptMode::Pool, TaskPanicPolicy::Contain);
        let mut streams = connect_all(runtime.bound_addr().unwrap(), 8);

        fault.panic.store(true, Ordering::Release);
        wake_all(&runtime, 2);

        wait_for_exit(&handles, 1);
        check_service_after_exit(&runtime, &mut streams, 2);

        runtime.shutdown();
        let panicked = handles
            .into_iter()
            .map(|h| h.join())
            .filter(Result::is_err)
            .count();
        assert_eq!(panicked, 1, "the join keeps the panic");
    }

    #[test]
    fn an_error_from_the_event_loop_leaves_the_other_workers_serving() {
        let (runtime, handles, fault) = launch(2, AcceptMode::Pool, TaskPanicPolicy::Contain);
        let mut streams = connect_all(runtime.bound_addr().unwrap(), 8);

        fault.error.store(true, Ordering::Release);
        wake_all(&runtime, 2);

        wait_for_exit(&handles, 1);
        check_service_after_exit(&runtime, &mut streams, 2);

        runtime.shutdown();
        let errors = handles
            .into_iter()
            .map(|h| h.join().expect("no panic"))
            .filter(Result::is_err)
            .count();
        assert_eq!(errors, 1);
    }

    /// `wait_on_signal` returns for a stopped worker, and shuts the runtime
    /// down so a supervisor can restart the process.
    #[test]
    fn wait_on_signal_reports_a_worker_exit_and_shuts_down() {
        for fail in [
            (|fault: &TestFault| fault.panic.store(true, Ordering::Release)) as fn(&TestFault),
            |fault| fault.error.store(true, Ordering::Release),
        ] {
            let (runtime, handles, fault) = launch(2, AcceptMode::Pool, TaskPanicPolicy::Contain);
            fail(&fault);
            wake_all(&runtime, 2);
            assert_eq!(
                signal_within(&runtime, Duration::from_secs(5)),
                Some(Signal::WorkerExited)
            );
            wait_for_exit(&handles, 2);
        }
    }

    /// With nobody in `wait_on_signal`, the `Shutdown` policy stops the runtime.
    #[test]
    fn a_worker_exit_shuts_the_runtime_down_under_the_shutdown_policy() {
        let (runtime, handles, fault) = launch(2, AcceptMode::Pool, TaskPanicPolicy::Shutdown);
        fault.panic.store(true, Ordering::Release);
        wake_all(&runtime, 2);
        wait_for_exit(&handles, 2);
        drop(runtime);
    }

    /// In merged mode the dead worker's socket stays in the `SO_REUSEPORT`
    /// group, so without steering a quarter of these would connect and hang.
    #[cfg(has_io_uring)]
    #[test]
    fn a_merged_listener_stops_choosing_a_dead_worker() {
        const WORKERS: usize = 4;
        let (runtime, handles, fault) =
            launch(WORKERS, AcceptMode::Merged, TaskPanicPolicy::Contain);
        let addr = runtime.bound_addr().unwrap();
        let mut streams = connect_all(addr, 16);

        fault.error.store(true, Ordering::Release);
        wake_all(&runtime, WORKERS);
        wait_for_exit(&handles, 1);
        check_service_after_exit(&runtime, &mut streams, WORKERS);

        let dead = handles.iter().position(|h| h.is_finished()).unwrap();
        assert!(runtime.set_worker_accepting(dead, true).is_err());
        runtime.shutdown();
        for handle in handles {
            let _ = handle.join();
        }
    }

    #[cfg(has_io_uring)]
    static GUARD_DROPPED: AtomicBool = AtomicBool::new(false);
    #[cfg(has_io_uring)]
    static GUARD_SENT: AtomicBool = AtomicBool::new(false);

    #[cfg(has_io_uring)]
    struct FlaggedGuard(Vec<u8>);

    #[cfg(has_io_uring)]
    impl crate::SendGuard for FlaggedGuard {
        fn as_ptr_len(&self) -> (*const u8, u32) {
            (self.0.as_ptr(), self.0.len() as u32)
        }
        fn region(&self) -> crate::RegionId {
            crate::RegionId::UNREGISTERED
        }
    }

    #[cfg(has_io_uring)]
    impl Drop for FlaggedGuard {
        fn drop(&mut self) {
            GUARD_DROPPED.store(true, Ordering::SeqCst);
        }
    }

    /// Sends a guarded body larger than the loopback socket buffers hold, and
    /// keeps the connection open.
    #[cfg(has_io_uring)]
    struct GuardSender;

    #[cfg(has_io_uring)]
    impl AsyncEventHandler for GuardSender {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                conn.with_data(|d| ParseResult::Consumed(d.len())).await;
                let guard = crate::GuardBox::new(FlaggedGuard(vec![7; 4 << 20]));
                conn.send_parts()
                    .build(|b| b.guard(guard).submit())
                    .expect("guard send accepted");
                GUARD_SENT.store(true, Ordering::SeqCst);
                while conn.with_data(|d| ParseResult::Consumed(d.len())).await > 0 {}
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            GuardSender
        }
    }

    /// A stopped worker runs the normal drain, so a zero-copy guard outlives
    /// the kernel's use of it. Dropping the event loop at once would free
    /// memory the kernel still holds.
    #[cfg(has_io_uring)]
    #[test]
    fn a_stopped_worker_holds_a_guard_the_kernel_still_uses() {
        let mut config = ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .sq_entries(64)
            .max_connections(16)
            .send_pool(16, 16384)
            .build()
            .expect("valid config");
        let fault = Arc::new(TestFault::default());
        config.test_fault = Some(fault.clone());
        let enomem = || {
            crate::metrics::POOL
                .value(crate::metrics::pool::SEND_ZC_ENOMEM)
                .unwrap_or(0)
        };
        let before = enomem();
        let (runtime, handles) = RinglineBuilder::new(config)
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<GuardSender>()
            .expect("launch");
        let mut peer = TcpStream::connect(runtime.bound_addr().unwrap()).unwrap();
        peer.write_all(b"x").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !GUARD_SENT.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "the send never started");
            std::thread::sleep(Duration::from_millis(1));
        }
        // Bytes on the socket: the send reached the kernel, and a `-ENOMEM` has
        // been handled, so the count below is settled.
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.peek(&mut [0u8; 1]).expect("the send's first bytes");

        fault.error.store(true, Ordering::Release);
        wake_all(&runtime, 1);
        std::thread::sleep(Duration::from_millis(300));
        // Over `RLIMIT_MEMLOCK` the send falls back to plain sends (#642), which
        // owe no notification, so the drain frees the guard.
        if enomem() == before {
            assert!(
                !GUARD_DROPPED.load(Ordering::SeqCst),
                "the guard was freed while its data was queued"
            );
        }
        drop(peer);
        runtime.shutdown();
        for handle in handles {
            let _ = handle.join();
        }
    }

    /// With no worker left, the listeners stop taking connections.
    #[cfg(has_io_uring)]
    fn check_refused_or_closed(runtime: &Runtime) {
        let addr = runtime.bound_addr().unwrap();
        for _ in 0..8 {
            if let Ok(mut fresh) = TcpStream::connect(addr) {
                assert_eq!(echo(&mut fresh), Echoed::Closed);
            }
        }
    }

    #[cfg(has_io_uring)]
    #[test]
    fn a_merged_listener_with_one_worker_stops_taking_connections() {
        let (runtime, handles, fault) = launch(1, AcceptMode::Merged, TaskPanicPolicy::Contain);
        fault.error.store(true, Ordering::Release);
        wake_all(&runtime, 1);
        wait_for_exit(&handles, 1);
        check_refused_or_closed(&runtime);
    }

    #[cfg(has_io_uring)]
    #[test]
    fn a_merged_listener_stops_taking_connections_when_every_worker_stops() {
        let (runtime, handles, fault) = launch(2, AcceptMode::Merged, TaskPanicPolicy::Contain);
        for stopped in 1..=2 {
            fault.error.store(true, Ordering::Release);
            wake_all(&runtime, 2);
            wait_for_exit(&handles, stopped);
        }
        check_refused_or_closed(&runtime);
    }

    /// The last worker in the rotation stops while another was taken out: the
    /// live one goes back in.
    #[cfg(has_io_uring)]
    #[test]
    fn a_worker_out_of_the_rotation_returns_when_the_others_stop() {
        let (runtime, handles, fault) = launch(2, AcceptMode::Merged, TaskPanicPolicy::Contain);
        runtime.set_worker_accepting(0, false).unwrap();
        fault.error_on_worker.store(2, Ordering::Release);
        wake_all(&runtime, 2);
        wait_for_exit(&handles, 1);
        assert!(handles[1].is_finished());
        let addr = runtime.bound_addr().unwrap();
        for _ in 0..8 {
            let mut fresh = TcpStream::connect(addr).unwrap();
            assert_eq!(echo(&mut fresh), Echoed::Yes);
        }
        runtime.shutdown();
        for handle in handles {
            let _ = handle.join();
        }
    }

    /// Connections in a batch of completions when a handler panics are closed,
    /// not lost with the rest of the batch.
    #[cfg(has_io_uring)]
    #[test]
    fn accepted_connections_behind_a_panic_are_closed() {
        let (runtime, handles, fault) = launch(1, AcceptMode::Merged, TaskPanicPolicy::Contain);
        let addr = runtime.bound_addr().unwrap();
        let mut staller = connect_all(addr, 1).pop().unwrap();
        fault.panic_on_accept.store(3, Ordering::Release);
        staller.write_all(STALL).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let mut streams: Vec<TcpStream> =
            (0..8).map(|_| TcpStream::connect(addr).unwrap()).collect();
        wait_for_exit(&handles, 1);
        for stream in &mut streams {
            assert_eq!(echo(stream), Echoed::Closed);
        }
    }

    /// `launch()` returns when a worker stops while `launch()` runs, before or
    /// after it listens, and once the worker has stopped every connection
    /// reaches the other one.
    #[cfg(has_io_uring)]
    #[test]
    fn a_worker_stopping_during_launch_does_not_hang_it() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut config = ConfigBuilder::new()
                .workers(2)
                .pin_to_core(false)
                .sq_entries(64)
                .max_connections(64)
                .send_pool(32, 16384)
                .accept_mode(AcceptMode::Merged)
                .build()
                .expect("valid config");
            let fault = Arc::new(TestFault::default());
            fault.error.store(true, Ordering::Release);
            config.test_fault = Some(fault);
            let (runtime, handles) = RinglineBuilder::new(config)
                .bind("127.0.0.1:0".parse().unwrap())
                .launch::<Echo>()
                .expect("launch");
            // The worker stops on its first loop iteration, before or after
            // `launch()` listens: nothing orders the two. Once it has
            // stopped, its socket is out of the steering and what the
            // socket queued is closed, so every later connection reaches
            // the other worker. A connection made before that can hash to
            // the stopping worker's socket, or be handed to it by placement,
            // and be closed (#783).
            wait_for_exit(&handles, 1);
            let addr = runtime.bound_addr().unwrap();
            let results: Vec<Echoed> = (0..16)
                .map(|_| echo(&mut TcpStream::connect(addr).unwrap()))
                .collect();
            drop(runtime);
            for handle in handles {
                let _ = handle.join();
            }
            let _ = tx.send(results);
        });
        let results = rx
            .recv_timeout(Duration::from_secs(90))
            .expect("launch hung");
        assert!(results.iter().all(|r| *r == Echoed::Yes), "{results:?}");
    }

    /// What is queued on a stopped worker's merged socket closes, both when it
    /// leaves the rotation and after its drain.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_stopped_worker_closes_what_is_queued_on_its_socket() {
        use std::os::fd::OwnedFd;
        let listeners: Vec<std::net::TcpListener> = (0..2)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let addr = listeners[1].local_addr().unwrap();
        let fds: Vec<OwnedFd> = listeners.into_iter().map(OwnedFd::from).collect();
        let sockets = super::ListenerSockets::new(fds);
        let shutdown = super::RuntimeShutdown::new(
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            crate::listen_gate::ListenGates::new(0, 128),
            Arc::from(Vec::new()),
        )
        .unwrap();
        let accepting = (0..2)
            .map(|_| std::sync::atomic::AtomicBool::new(true))
            .collect();
        let _ = shutdown.accepting.set(Arc::new(accepting));
        shutdown.add_listener(sockets, true);

        let mut at_exit = TcpStream::connect(addr).unwrap();
        shutdown.worker_exited(1, false);
        assert_eq!(echo(&mut at_exit), Echoed::Closed);

        let mut after_drain = TcpStream::connect(addr).unwrap();
        shutdown.worker_drained(1);
        assert_eq!(echo(&mut after_drain), Echoed::Closed);
    }

    /// A connection arriving as the worker stops does not hang.
    #[cfg(has_io_uring)]
    #[test]
    fn connections_arriving_as_a_worker_stops_do_not_hang() {
        const WORKERS: usize = 2;
        let (runtime, handles, fault) =
            launch(WORKERS, AcceptMode::Merged, TaskPanicPolicy::Contain);
        let addr = runtime.bound_addr().unwrap();
        let mut held = connect_all(addr, 16);
        // An armed accept empties the kernel's queue during the iteration, so
        // these reach the worker's ring or the steering, not `close_queued`.
        for stream in &mut held {
            stream.write_all(STALL).unwrap();
        }
        std::thread::sleep(Duration::from_millis(50));
        fault.panic_in_drain.store(true, Ordering::Release);
        fault.error.store(true, Ordering::Release);
        let mut streams: Vec<TcpStream> =
            (0..16).map(|_| TcpStream::connect(addr).unwrap()).collect();
        wake_all(&runtime, WORKERS);
        wait_for_exit(&handles, 1);
        for stream in &mut streams {
            let result = echo(stream);
            assert_ne!(result, Echoed::Hung);
        }
        runtime.shutdown();
        for handle in handles {
            let _ = handle.join();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn close_queued_closes_what_a_listening_socket_holds() {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut queued = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        super::close_queued(listener.as_raw_fd());
        assert_eq!(echo(&mut queued), Echoed::Closed);
    }

    /// A task panic under `Shutdown` is the worker's result on a failed drain
    /// too.
    #[cfg(has_io_uring)]
    #[test]
    fn a_failed_drain_keeps_the_task_panic() {
        struct Panicker;
        static FAULT: std::sync::OnceLock<Arc<TestFault>> = std::sync::OnceLock::new();
        impl AsyncEventHandler for Panicker {
            fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
                std::future::ready(())
            }
            fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
                Some(Box::pin(async {
                    let fault = FAULT.get().unwrap();
                    fault.panic_in_drain.store(true, Ordering::Release);
                    fault.panic.store(true, Ordering::Release);
                    panic!("boom in task");
                }))
            }
            fn create_for_worker(_id: usize) -> Self {
                Panicker
            }
        }
        let mut config = ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .sq_entries(64)
            .max_connections(16)
            .send_pool(16, 16384)
            .task_panic_policy(TaskPanicPolicy::Shutdown)
            .build()
            .expect("valid config");
        let fault = Arc::new(TestFault::default());
        let _ = FAULT.set(fault.clone());
        config.test_fault = Some(fault);
        let (runtime, mut handles) = RinglineBuilder::new(config)
            .launch::<Panicker>()
            .expect("launch");
        wait_for_exit(&handles, 1);
        drop(runtime);
        let result = handles
            .remove(0)
            .join()
            .expect("no panic out of the worker");
        assert!(
            matches!(&result, Err(Error::TaskPanicked(e)) if e.panic_message() == Some("boom in task")),
            "{result:?}"
        );
    }

    /// A blocking result that cannot reach its stopped worker drops on the pool
    /// thread, and a panic in its `Drop` leaves the pool working.
    #[cfg(has_io_uring)]
    #[test]
    fn a_result_for_a_stopped_worker_leaves_the_blocking_pool_working() {
        struct PanicsWhenDropped;
        impl Drop for PanicsWhenDropped {
            fn drop(&mut self) {
                panic!("boom in result drop");
            }
        }
        static POOL_SERVED: AtomicBool = AtomicBool::new(false);
        struct Blocks(usize);
        impl AsyncEventHandler for Blocks {
            fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
                std::future::ready(())
            }
            fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
                let id = self.0;
                Some(Box::pin(async move {
                    if id == 0 {
                        let held = crate::spawn_blocking(|| {
                            std::thread::sleep(Duration::from_millis(200));
                            PanicsWhenDropped
                        })
                        .expect("spawn_blocking");
                        crate::sleep(Duration::from_secs(3600)).await;
                        drop(held);
                    } else {
                        crate::sleep(Duration::from_millis(500)).await;
                        let served = crate::spawn_blocking(|| ())
                            .expect("spawn_blocking")
                            .await
                            .is_ok();
                        POOL_SERVED.store(served, Ordering::SeqCst);
                    }
                }))
            }
            fn create_for_worker(id: usize) -> Self {
                Blocks(id)
            }
        }
        let mut config = ConfigBuilder::new()
            .workers(2)
            .pin_to_core(false)
            .sq_entries(64)
            .max_connections(16)
            .send_pool(16, 16384)
            .blocking_threads(1)
            .build()
            .expect("valid config");
        let fault = Arc::new(TestFault::default());
        config.test_fault = Some(fault.clone());
        let (runtime, handles) = RinglineBuilder::new(config)
            .launch::<Blocks>()
            .expect("launch");
        std::thread::sleep(Duration::from_millis(50));
        fault.error_on_worker.store(1, Ordering::Release);
        wake_all(&runtime, 2);
        wait_for_exit(&handles, 1);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !POOL_SERVED.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(POOL_SERVED.load(Ordering::SeqCst), "the pool thread died");
        drop(runtime);
        for handle in handles {
            let _ = handle.join();
        }
    }

    /// After a failed drain nothing waits on the stopped worker.
    #[cfg(has_io_uring)]
    #[test]
    fn a_failed_drain_does_not_block_a_region_update() {
        let (runtime, handles, fault) = launch(2, AcceptMode::Pool, TaskPanicPolicy::Contain);
        fault.panic_in_drain.store(true, Ordering::Release);
        fault.panic.store(true, Ordering::Release);
        wake_all(&runtime, 2);
        wait_for_exit(&handles, 1);

        let mut backing = vec![0u8; 4096];
        let region = unsafe { crate::MemoryRegion::new(backing.as_mut_ptr(), 4096) };
        let registrar = runtime.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(registrar.register_region(region).is_err());
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(true));
        runtime.shutdown();
        for handle in handles {
            let _ = handle.join();
        }
        drop(backing);
    }

    /// A drain that panics leaves the ring to the kernel: its connections close
    /// and the process carries on.
    #[cfg(has_io_uring)]
    #[test]
    fn a_failed_drain_still_closes_the_connections() {
        let (runtime, handles, fault) = launch(2, AcceptMode::Pool, TaskPanicPolicy::Contain);
        let mut streams = connect_all(runtime.bound_addr().unwrap(), 8);

        fault.panic_in_drain.store(true, Ordering::Release);
        fault.panic.store(true, Ordering::Release);
        wake_all(&runtime, 2);
        wait_for_exit(&handles, 1);
        check_service_after_exit(&runtime, &mut streams, 2);

        runtime.shutdown();
        for handle in handles {
            let _ = handle.join();
        }
    }
}
