//! Per-listener listen gates.
//!
//! A listener is bound when the runtime launches, which reserves its port, and
//! begins listening when its gate opens. Between the two the kernel does not
//! complete handshakes, so a readiness probe fails while the server is not
//! ready instead of passing against a socket nothing will service.
//!
//! What the peer sees in that window is platform-specific: Linux answers the
//! SYN with RST, so the connect is refused immediately, while macOS and the
//! BSDs drop it and the peer times out. Both fail a probe; only the first
//! fails it quickly.
//!
//! Gates are open by default: [`RinglineBuilder::defer_listen`] closes a gate
//! and [`begin_listening`] opens it. A listener that is not deferred is
//! listening before `launch()` returns.
//!
//! The gate defers `listen(2)`, not `accept(2)`. A socket that is listening
//! but not accepting still completes handshakes, so a TCP readiness probe
//! against it passes.
//!
//! [`RinglineBuilder::defer_listen`]: crate::RinglineBuilder::defer_listen

use std::cell::RefCell;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::handler::ListenerId;
use crate::listener_sockets::ListenerSockets;

/// The listen gates for one runtime, one entry per `bind*()` call.
pub(crate) struct ListenGates {
    /// Whether each listener has begun listening. Published separately from
    /// `inner` so `wait_open` can check it without the lock.
    open: Vec<AtomicBool>,
    inner: Mutex<GateInner>,
    /// Signalled when a gate opens and when the runtime shuts down. Pool-mode
    /// acceptor threads park here.
    cv: Condvar,
}

struct GateInner {
    /// The sockets to `listen(2)` when a gate opens. `None` for a listener
    /// until `launch()` has bound it, and for every listener after shutdown.
    sockets: Vec<Option<Arc<ListenerSockets>>>,
    /// Whether a handler asked for this listener before it was registered.
    /// `register` performs the listen for anything marked here.
    requested: Vec<bool>,
    /// Whether `listen(2)` has been called. `open` returns early when it is
    /// set. Distinct from `open`, which is the published view.
    listened: Vec<bool>,
    backlog: i32,
    shutdown: bool,
}

impl ListenGates {
    pub(crate) fn new(listeners: usize, backlog: i32) -> Arc<Self> {
        Arc::new(ListenGates {
            open: (0..listeners).map(|_| AtomicBool::new(false)).collect(),
            inner: Mutex::new(GateInner {
                sockets: vec![None; listeners],
                requested: vec![false; listeners],
                listened: vec![false; listeners],
                backlog,
                shutdown: false,
            }),
            cv: Condvar::new(),
        })
    }

    /// Record the bound sockets for a listener.
    ///
    /// If a handler already called [`open`](Self::open) for this listener,
    /// that call recorded its intent and this one performs the `listen(2)`,
    /// so the error surfaces to `launch()`.
    pub(crate) fn register(&self, listener: u32, sockets: Arc<ListenerSockets>) -> io::Result<()> {
        let idx = listener as usize;
        {
            let mut inner = self.lock();
            if inner.shutdown {
                return Ok(());
            }
            inner.sockets[idx] = Some(Arc::clone(&sockets));
            if inner.listened[idx] || !inner.requested[idx] {
                return Ok(());
            }
            listen_all(&sockets, inner.backlog)?;
            inner.listened[idx] = true;
        }
        self.publish(idx);
        Ok(())
    }

    /// Publish a gate and wake everything waiting on it. Called after the
    /// lock is released, so a waiter that checks on its own schedule still
    /// sees the flag.
    fn publish(&self, idx: usize) {
        self.open[idx].store(true, Ordering::Release);
        self.cv.notify_all();
    }

    /// Begin listening on a listener's sockets and publish the gate.
    ///
    /// A second call is a no-op. Returns the `listen(2)` error if the syscall
    /// fails, in which case the gate stays closed and the call can be
    /// retried.
    pub(crate) fn open(&self, listener: u32) -> io::Result<()> {
        let idx = listener as usize;
        {
            let mut inner = self.lock();
            if idx >= inner.listened.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("no listener with index {listener}"),
                ));
            }
            if inner.shutdown {
                return Err(io::Error::other("runtime is shutting down"));
            }
            if inner.listened[idx] {
                return Ok(());
            }
            let Some(sockets) = inner.sockets[idx].clone() else {
                // `launch()` has not bound this listener yet. A worker signals
                // startup and then enters its event loop, which polls
                // `on_start` on the first iteration, so a handler that
                // releases immediately gets here before `launch()` reaches the
                // listener loop. Recording the request and letting `register`
                // perform the listen keeps that ordering from mattering.
                // Publishing here instead would listen on nothing and leave
                // the acceptor to fail `accept4` with EINVAL and exit.
                inner.requested[idx] = true;
                return Ok(());
            };
            listen_all(&sockets, inner.backlog)?;
            inner.listened[idx] = true;
        }
        self.publish(idx);
        Ok(())
    }

    /// Open every gate in index order, stopping at the first failure: gates
    /// before it stay open, later ones are not attempted.
    pub(crate) fn open_all(&self) -> io::Result<()> {
        for listener in 0..self.open.len() as u32 {
            self.open(listener)?;
        }
        Ok(())
    }

    /// Whether this listener has begun listening. One atomic load.
    pub(crate) fn is_open(&self, listener: u32) -> bool {
        self.open
            .get(listener as usize)
            .map(|f| f.load(Ordering::Acquire))
            .unwrap_or(false)
    }

    /// Block until this listener's gate opens, or the runtime shuts down.
    ///
    /// Returns `true` if the gate opened. A `false` return means shutdown, and
    /// the listener's sockets may never have listened.
    pub(crate) fn wait_open(&self, listener: u32) -> bool {
        let idx = listener as usize;
        // The common case is a gate that was opened during `launch()`, which
        // costs one atomic load and no lock.
        if self.is_open(listener) {
            return true;
        }
        let mut inner = self.lock();
        loop {
            if inner.shutdown {
                return false;
            }
            if inner.listened.get(idx).copied().unwrap_or(false) {
                return true;
            }
            inner = match self.cv.wait(inner) {
                Ok(guard) => guard,
                // A poisoned mutex means a gate operation panicked. Waiting
                // forever would hang shutdown, so treat it as shutdown.
                Err(_) => return false,
            };
        }
    }

    /// Release every waiter.
    ///
    /// Called by `Runtime::shutdown` before it shuts the listener sockets
    /// down. [`ListenerSockets::shut_down`] wakes a thread inside `accept4`;
    /// it does not wake a thread waiting in `wait_open`. After this call no
    /// gate calls `listen(2)`.
    pub(crate) fn shutdown(&self) {
        let released = {
            let mut inner = self.lock();
            inner.shutdown = true;
            // Release the gates' hold on the sockets, so a `ListenHandle`
            // that outlives the runtime does not keep them open.
            inner
                .sockets
                .iter_mut()
                .map(Option::take)
                .collect::<Vec<_>>()
        };
        drop(released);
        self.cv.notify_all();
    }

    /// The lock, recovered from poisoning. A panic inside a gate operation
    /// must not make later calls panic; the shutdown path in particular must
    /// still run.
    fn lock(&self) -> std::sync::MutexGuard<'_, GateInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `listen(2)` every socket of one listener.
///
/// The caller marks the listener listened only if this returns `Ok`. On a
/// failure the sockets before it stay listening and the gate stays closed; a
/// retry calls `listen(2)` on all of them again, which Linux accepts on a
/// socket that is already listening.
fn listen_all(sockets: &ListenerSockets, backlog: i32) -> io::Result<()> {
    for fd in sockets.fds() {
        // `create_listener` clears SO_REUSEADDR after bind so a held port is
        // reserved. It must be set again here: Linux re-runs the port conflict
        // check in `listen(2)` with the socket's current flag, and without it
        // a TIME_WAIT connection left by a previous instance on this port
        // fails the listen with EADDRINUSE. Between this call and `listen(2)`
        // another SO_REUSEADDR socket can bind the port. Whichever of the two
        // calls `listen(2)` first listens; the other's `listen(2)` fails with
        // EADDRINUSE. No effect on Unix sockets, and merged-mode sockets
        // already have it set. A failure here is not checked: the `listen(2)`
        // below reports any consequence.
        let reuse: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &reuse as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        if unsafe { libc::listen(fd, backlog) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Opens deferred listeners from any thread.
///
/// Obtained from
/// [`Runtime::listen_handle`](crate::Runtime::listen_handle).
/// For readiness decided outside a ringline worker: a management thread, a
/// thread that waits on each worker's warmup, or another runtime. Clones share
/// one runtime's listeners, and dropping one does not affect the runtime.
///
/// The handle exists only after `launch()` has bound every listener, so unlike
/// the free [`begin_listening`] it never records a request for later.
#[derive(Clone)]
pub struct ListenHandle {
    gates: Arc<ListenGates>,
}

impl ListenHandle {
    pub(crate) fn new(gates: Arc<ListenGates>) -> Self {
        Self { gates }
    }

    /// Begin listening on a deferred listener. The listener opens for every
    /// worker.
    ///
    /// Calling it for a listener that is already listening returns `Ok(())`
    /// and does nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if `listener` names no listener, if
    /// [`Runtime::shutdown`](crate::Runtime::shutdown) has been
    /// called, or if `listen(2)` fails. A `listen(2)` failure leaves the
    /// listener bound and not listening, so the call can be retried.
    pub fn begin_listening(&self, listener: ListenerId) -> io::Result<()> {
        self.gates.open(listener.index())
    }

    /// Applies [`begin_listening`](Self::begin_listening) to each listener in
    /// index order and stops at the first failure: listeners before it stay
    /// listening, later ones are not attempted.
    ///
    /// # Errors
    ///
    /// As [`begin_listening`](Self::begin_listening).
    pub fn begin_listening_all(&self) -> io::Result<()> {
        self.gates.open_all()
    }
}

thread_local! {
    /// The gates for the runtime this thread belongs to. Installed by each
    /// worker at startup; `None` on any other thread, which
    /// [`begin_listening`] reports as an error.
    static GATES: RefCell<Option<Arc<ListenGates>>> = const { RefCell::new(None) };
}

/// Make the gates reachable from any code on this worker thread.
pub(crate) fn install(gates: Arc<ListenGates>) {
    GATES.with(|g| *g.borrow_mut() = Some(gates));
}

fn with_gates<R>(f: impl FnOnce(&ListenGates) -> R) -> Option<R> {
    GATES.with(|g| g.borrow().as_ref().map(|gates| f(gates)))
}

/// Begin listening on a deferred listener.
///
/// Call this once the server can serve. Until it is called the listener's port
/// is bound but not listening, so a TCP readiness probe fails: on Linux the
/// peer is refused, on macOS and the BSDs it times out.
///
/// The first call opens the listener for every worker, whichever worker makes
/// it. To wait for warmup on every worker, count completions and
/// call this from the last worker to finish.
///
/// Calling it for a listener that is already listening returns `Ok(())` and
/// does nothing. A listener that was never deferred is already listening, so
/// passing the wrong index returns `Ok(())` and leaves the deferred listener
/// closed.
///
/// # Errors
///
/// Returns an error if called from a thread that is not a ringline worker
/// (use [`ListenHandle::begin_listening`] from other threads), if `listener` names no listener, if
/// [`Runtime::shutdown`](crate::Runtime::shutdown) has been
/// called or `launch()` has failed, or if `listen(2)` fails. A `listen(2)`
/// failure leaves the listener bound and not listening, so the call can be
/// retried.
///
/// If called before `launch()` has bound the listener, which is possible from
/// `on_start`, the call records the request and returns `Ok(())`; `launch()`
/// then calls `listen(2)` and, if it fails, returns that error.
///
/// ```no_run
/// # use std::future::Future;
/// # use std::pin::Pin;
/// # use ringline::{AsyncEventHandler, Connection, ListenerId};
/// # struct Handler;
/// impl AsyncEventHandler for Handler {
///     # fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
///     #     async {}
///     # }
///     fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
///         Some(Box::pin(async {
///             // warm caches, connect to backends, load config
///             if let Err(e) = ringline::begin_listening(ListenerId::from_index(0)) {
///                 // also returned when the runtime is shutting down
///                 eprintln!("begin_listening: {e}");
///             }
///         }))
///     }
///     # fn create_for_worker(_id: usize) -> Self {
///     #     Handler
///     # }
/// }
/// ```
pub fn begin_listening(listener: ListenerId) -> io::Result<()> {
    with_gates(|gates| gates.open(listener.index()))
        .unwrap_or_else(|| Err(io::Error::other("called outside a ringline worker")))
}

/// Begin listening on every deferred listener.
///
/// Applies [`begin_listening`] to each listener in index order and stops at the
/// first failure: listeners before it stay listening, later ones are not
/// attempted.
///
/// # Errors
///
/// As [`begin_listening`].
pub fn begin_listening_all() -> io::Result<()> {
    with_gates(|gates| gates.open_all())
        .unwrap_or_else(|| Err(io::Error::other("called outside a ringline worker")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A socketpair end stands in for a listener: `listen(2)` fails on it, so
    /// the bookkeeping tests can check that the gate does not publish when the
    /// syscall fails.
    fn unlistenable() -> Arc<ListenerSockets> {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        ListenerSockets::new(vec![a.into()])
    }

    fn listenable() -> Arc<ListenerSockets> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        ListenerSockets::new(vec![listener.into()])
    }

    /// Gates with every listener registered on a listenable socket, as
    /// `launch()` leaves them. `open` does not publish an unregistered gate,
    /// so tests of the open path start here. The gates own the sockets.
    fn registered_gates(listeners: usize) -> Arc<ListenGates> {
        let gates = ListenGates::new(listeners, 128);
        for id in 0..listeners as u32 {
            gates.register(id, listenable()).expect("register");
        }
        gates
    }

    /// Run `wait_open` on another thread and fail rather than hang if it does
    /// not return. A gate that never publishes blocks `wait_open` forever.
    fn wait_open_within(gates: &Arc<ListenGates>, listener: u32) -> bool {
        let waiter = Arc::clone(gates);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(waiter.wait_open(listener));
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("wait_open did not return within 5s")
    }

    #[test]
    fn opening_one_gate_publishes_it_and_no_other() {
        let gates = registered_gates(2);
        assert!(!gates.is_open(0));
        gates.open(0).expect("open");
        assert!(gates.is_open(0));
        assert!(!gates.is_open(1), "opening one gate must not open another");
    }

    #[test]
    fn opening_twice_is_a_no_op() {
        let gates = ListenGates::new(1, 128);
        gates.register(0, listenable()).expect("register");
        gates.open(0).expect("first open");
        // The second call must not reach `listen(2)` again — on Linux a second
        // listen on a listening socket succeeds, so the assertion that matters
        // is that the gate stays open and no error is produced.
        gates.open(0).expect("second open");
        assert!(gates.is_open(0));
    }

    #[test]
    fn a_failed_listen_leaves_the_gate_closed() {
        let gates = ListenGates::new(1, 128);
        gates.register(0, unlistenable()).expect("register");
        assert!(gates.open(0).is_err(), "listen on a socketpair must fail");
        assert!(
            !gates.is_open(0),
            "a gate must not publish when listen failed"
        );
        // Retryable: the bookkeeping did not record a listen that never happened.
        assert!(gates.open(0).is_err());
    }

    #[test]
    fn an_unknown_listener_is_an_error_not_a_panic() {
        let gates = ListenGates::new(1, 128);
        assert!(gates.open(7).is_err());
        assert!(!gates.is_open(7));
    }

    #[test]
    fn wait_returns_immediately_for_an_already_open_gate() {
        let gates = registered_gates(1);
        gates.open(0).expect("open");
        assert!(wait_open_within(&gates, 0));
    }

    #[test]
    fn wait_wakes_when_the_gate_opens() {
        let gates = registered_gates(1);
        let opener = Arc::clone(&gates);
        let handle = std::thread::spawn(move || {
            // Not a synchronisation point; it makes the wait usually start
            // first. The test is correct either way: `wait_open` rechecks
            // the predicate before parking.
            std::thread::sleep(std::time::Duration::from_millis(20));
            opener.open(0)
        });
        assert!(wait_open_within(&gates, 0));
        handle.join().expect("opener panicked").expect("open");
    }

    #[test]
    fn shutdown_releases_a_waiter_on_a_gate_that_never_opens() {
        let gates = ListenGates::new(1, 128);
        let waiter = Arc::clone(&gates);
        let handle = std::thread::spawn(move || waiter.wait_open(0));
        std::thread::sleep(std::time::Duration::from_millis(20));
        gates.shutdown();
        assert!(
            !handle.join().expect("waiter panicked"),
            "a waiter released by shutdown must report the gate as not open"
        );
    }

    #[test]
    fn opening_after_shutdown_is_refused() {
        let gates = ListenGates::new(1, 128);
        gates.shutdown();
        assert!(gates.open(0).is_err());
    }

    #[test]
    fn open_all_opens_every_gate() {
        let gates = registered_gates(3);
        gates.open_all().expect("open_all");
        for id in 0..3 {
            assert!(gates.is_open(id));
        }
    }

    /// A handler can release a gate before `launch()` has bound the listener:
    /// a worker signals startup and then polls `on_start` on its first event
    /// loop iteration, while `launch()` is still on its way to `register`.
    ///
    /// Publishing there would listen on nothing, and the acceptor would fail
    /// `accept4` with EINVAL and exit, leaving the port bound and dead with
    /// `begin_listening` having returned `Ok`.
    #[test]
    fn a_gate_released_before_registration_listens_when_it_registers() {
        let gates = ListenGates::new(1, 128);

        gates.open(0).expect("release before register");
        assert!(
            !gates.is_open(0),
            "a gate with no sockets yet must not publish"
        );

        gates.register(0, listenable()).expect("register");
        assert!(
            gates.is_open(0),
            "register must honour a release that arrived first"
        );
    }

    /// The same path, for a listener nobody asked for: registering must not
    /// open it.
    #[test]
    fn registering_does_not_open_a_gate_nobody_released() {
        let gates = ListenGates::new(1, 128);
        gates.register(0, listenable()).expect("register");
        assert!(
            !gates.is_open(0),
            "register must not open an unreleased gate"
        );
    }

    /// Leave a TIME_WAIT connection on a loopback port and return the port.
    /// The side that closes first enters TIME_WAIT, so the accepted
    /// connection closes before the client.
    fn port_with_time_wait() -> u16 {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");
        drop(accepted);
        let _ = client.read(&mut [0u8; 1]);
        drop(client);
        drop(listener);
        #[cfg(target_os = "linux")]
        assert!(
            has_time_wait(port),
            "no TIME_WAIT connection formed on port {port}"
        );
        port
    }

    /// Whether `/proc/net/tcp` lists a TIME_WAIT (state `06`) socket whose
    /// local port is `port`.
    #[cfg(target_os = "linux")]
    fn has_time_wait(port: u16) -> bool {
        let table = std::fs::read_to_string("/proc/net/tcp").expect("read /proc/net/tcp");
        let local = format!(":{port:04X}");
        table.lines().skip(1).any(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.len() > 3 && fields[1].ends_with(&local) && fields[3] == "06"
        })
    }

    /// A restart on a port that still has TIME_WAIT connections from the
    /// previous instance must listen. `create_listener` clears SO_REUSEADDR
    /// after bind, and Linux re-checks the port in `listen(2)` with the
    /// current flag, so the gate has to set it again first.
    #[test]
    fn a_listener_listens_over_a_time_wait_connection() {
        let port = port_with_time_wait();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let fd = crate::worker::create_listener(addr).expect("create_listener");
        let gates = ListenGates::new(1, 128);
        gates
            .register(0, ListenerSockets::new(vec![fd]))
            .expect("register");
        gates
            .open(0)
            .expect("listen must succeed over a TIME_WAIT connection");
        assert!(gates.is_open(0));
    }

    /// While a deferred listener is held, a socket that does not set
    /// `SO_REUSEADDR` cannot bind its port. One that sets it can on some
    /// kernels: see `create_listener`.
    #[test]
    fn a_held_listener_reserves_its_port() {
        let fd = crate::worker::create_listener("127.0.0.1:0".parse().unwrap())
            .expect("create_listener");
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockname(
                    std::os::fd::AsRawFd::as_raw_fd(&fd),
                    &mut storage as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            },
            0
        );
        let mut reuse: libc::c_int = 1;
        let mut reuse_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    std::os::fd::AsRawFd::as_raw_fd(&fd),
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &mut reuse as *mut _ as *mut libc::c_void,
                    &mut reuse_len,
                )
            },
            0
        );
        assert_eq!(reuse, 0, "a held listener must not keep SO_REUSEADDR set");
        let other = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(other >= 0);
        let ret = unsafe { libc::bind(other, &storage as *const _ as *const libc::sockaddr, len) };
        let err = io::Error::last_os_error();
        unsafe { libc::close(other) };
        drop(fd);
        assert!(ret < 0, "a second bind succeeded on a held listener's port");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EADDRINUSE),
            "the second bind failed for a reason other than the port being held: {err}"
        );
    }

    #[test]
    fn begin_listening_outside_a_worker_is_an_error() {
        // No `install` on this thread.
        assert!(begin_listening(ListenerId::from_index(0)).is_err());
        assert!(begin_listening_all().is_err());
    }
}
