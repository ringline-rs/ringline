use std::net::SocketAddr;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::handoff::{Sender, TrySendError};

/// One accepted connection on its way to a worker.
///
/// Owns the socket. A worker drops its channel's receiver when it exits, which
/// closes a connection still queued for it (`crate::handoff`).
pub struct AcceptedConn {
    pub fd: OwnedFd,
    pub listener: crate::ListenerId,
    pub peer: crate::connection::PeerAddr,
}

/// Configuration for one acceptor thread.
pub struct AcceptorConfig {
    /// The listener's socket. The acceptor's hold keeps it open while the
    /// acceptor runs. On Linux, shutdown wakes it from `accept4` with
    /// [`ListenerSockets::shut_down`](crate::listener_sockets::ListenerSockets::shut_down).
    pub sockets: Arc<crate::listener_sockets::ListenerSockets>,
    /// Which listener this acceptor serves. Travels with every accepted fd so
    /// the handler can tell connections from different listeners apart.
    pub listener: crate::ListenerId,
    /// Per-worker channels that carry each `AcceptedConn`.
    pub worker_channels: Vec<Sender<AcceptedConn>>,
    /// Per-worker wake handles to wake the event loop after sending a
    /// connection. Owning, so a worker's wake fd stays open while this
    /// acceptor can still write to it.
    pub worker_wake_handles: Vec<crate::wakeup::WakeHandle>,
    /// Shared flag set by `Runtime::shutdown` to signal the acceptor to stop.
    pub shutdown_flag: Arc<AtomicBool>,
    /// The runtime's listen gates. This acceptor waits on its gate before
    /// accepting. `ListenGates::open` calls `listen(2)`; until it runs, the
    /// socket is bound and not listening.
    pub listen_gates: Arc<crate::listen_gate::ListenGates>,
    /// Whether to set TCP_NODELAY on accepted connections.
    pub tcp_nodelay: bool,
    /// Connections to assign to each worker before moving to the next.
    /// 1 = round-robin. See [`ConfigBuilder::conn_chunk_size`](crate::ConfigBuilder::conn_chunk_size).
    pub conn_chunk_size: usize,
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
pub(crate) fn apply_accepted_sockopts(fd: RawFd, nodelay: bool) {
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
}

/// Run one listener's acceptor loop, until shutdown, a fatal accept error, or
/// every worker has exited.
///
/// Accepts connections with `accept_nonblock` and distributes them to
/// workers round-robin, waking each worker via eventfd. One of these runs
/// per listener; they share the worker channels, so accepts from different
/// listeners interleave and each carries its own `ListenerId`.
pub fn run_acceptor(config: AcceptorConfig) {
    let num_workers = config.worker_channels.len();
    if num_workers == 0 {
        return;
    }

    // Wait for this listener's gate. It is already open unless the caller
    // asked for a deferred listen, in which case the socket is bound and not
    // listening, and `accept4` on it would fail with EINVAL, which ends the
    // acceptor loop.
    //
    // A `false` return is shutdown, and the socket may never have listened.
    if !config.listen_gates.wait_open(config.listener.index()) {
        return;
    }

    // `SHUT_RD` does not wake a blocked `accept` here, so the loop waits in
    // `wait_for_connection`, and an `accept` that finds the connection gone
    // must not block.
    #[cfg(not(target_os = "linux"))]
    unsafe {
        let listen_fd = config.sockets.fd(0);
        let flags = libc::fcntl(listen_fd, libc::F_GETFL);
        libc::fcntl(listen_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let chunk_size = config.conn_chunk_size.max(1);
    let mut conn_count = 0usize; // successfully dispatched connections
    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut alive = vec![true; num_workers];

    loop {
        let mut addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        #[cfg(not(target_os = "linux"))]
        if !wait_for_connection(config.sockets.fd(0), &config.shutdown_flag) {
            return;
        }

        let fd = accept_nonblock(config.sockets.fd(0), &mut addr_storage, &mut addr_len);

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            // Shutdown makes `accept4` fail (`EINVAL` after `SHUT_RD`), and a
            // retry would only fail again.
            if config.shutdown_flag.load(Ordering::Acquire) {
                return;
            }
            match classify_accept_error(errno) {
                AcceptErrorAction::Retry => {}
                AcceptErrorAction::Backoff => {
                    crate::metrics::CONNECTIONS
                        .increment(crate::metrics::conn::ACCEPT_ERROR_BACKOFF);
                    std::thread::sleep(ACCEPT_ERROR_BACKOFF);
                }
                AcceptErrorAction::Stop => {
                    crate::metrics::CONNECTIONS.increment(crate::metrics::conn::ACCEPTOR_STOPPED);
                    // Not `eprintln!`, which panics if stderr fails.
                    let _ = std::io::Write::write_fmt(
                        &mut std::io::stderr(),
                        format_args!(
                            "ringline: acceptor for listener {} stopped: {err}\n",
                            config.listener.index()
                        ),
                    );
                    return;
                }
            }
            continue;
        }

        let is_unix = addr_storage.ss_family == libc::AF_UNIX as libc::sa_family_t;
        apply_accepted_sockopts(fd, config.tcp_nodelay && !is_unix);

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
        // disconnected channel (mark dead).
        let primary = (conn_count / chunk_size) % num_workers;
        // SAFETY: `accept4` returned a fresh descriptor that nothing else owns.
        let mut pending = Some(AcceptedConn {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            listener: config.listener,
            peer: peer_addr,
        });
        for i in 0..num_workers {
            let worker_idx = (primary + i) % num_workers;

            if !alive[worker_idx] {
                continue;
            }

            let accepted = pending.take().expect("connection not yet sent");
            match config.worker_channels[worker_idx].try_send(accepted) {
                Ok(()) => {
                    config.worker_wake_handles[worker_idx].wake();
                    conn_count = conn_count.wrapping_add(1);
                    break;
                }
                Err(TrySendError::Full(accepted)) => {
                    // Worker is backlogged — try the next one.
                    pending = Some(accepted);
                    continue;
                }
                Err(TrySendError::Disconnected(accepted)) => {
                    // Worker has exited — mark dead. With none left, dropping
                    // the connection closes it.
                    alive[worker_idx] = false;
                    if !alive.contains(&true) {
                        return;
                    }
                    pending = Some(accepted);
                    continue;
                }
            }
        }

        // Every live worker is backlogged. Hold this connection until one has
        // room: not calling `accept4` leaves the rest in the kernel's listen
        // queue, whose overflow the peer's TCP retries.
        if let Some(accepted) = pending {
            crate::metrics::CONNECTIONS.increment(crate::metrics::conn::ACCEPT_QUEUE_FULL);
            if !send_when_room(&config, &mut alive, accepted) {
                return;
            }
            conn_count = conn_count.wrapping_add(1);
        }
    }
}

/// What the acceptor does after `accept` fails with an errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptErrorAction {
    /// Call `accept` again at once.
    Retry,
    /// Wait [`ACCEPT_ERROR_BACKOFF`], then call `accept` again.
    Backoff,
    /// The listener cannot accept again: end the acceptor.
    Stop,
}

/// How long the acceptor waits after an error that a retry at once would
/// likely meet again: a full fd table, or no memory for the new socket.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

/// Classify an `accept` errno. Only an error that means the listening socket
/// is unusable stops the acceptor, since a stopped acceptor leaves its
/// listener accepting nothing while the workers run. An errno not listed here
/// backs off and is counted, rather than stopping.
fn classify_accept_error(errno: i32) -> AcceptErrorAction {
    match errno {
        // Not a socket, or not listening (also what `SHUT_RD` gives).
        libc::EBADF | libc::ENOTSOCK | libc::EINVAL => AcceptErrorAction::Stop,
        // EINTR: a signal. EAGAIN: on a platform with a non-blocking listener,
        // the connection `poll` saw has gone. ECONNABORTED, ECONNRESET and
        // EPERM end one pending connection. EPROTO, ENETDOWN, ENETUNREACH,
        // EHOSTDOWN, EHOSTUNREACH, ENONET, EOPNOTSUPP and ENOPROTOOPT are the
        // errors accept(2) says Linux passes through from the new socket, to
        // be retried like EAGAIN; ETIMEDOUT is one it says some kernels
        // return. EOPNOTSUPP also means a listener that is not SOCK_STREAM,
        // which cannot occur here: ringline creates every listener itself.
        libc::EINTR
        | libc::EAGAIN
        | libc::ECONNABORTED
        | libc::ECONNRESET
        | libc::EPERM
        | libc::EPROTO
        | libc::ENETDOWN
        | libc::ENETUNREACH
        | libc::EHOSTDOWN
        | libc::EHOSTUNREACH
        | libc::EOPNOTSUPP
        | libc::ENOPROTOOPT
        | libc::ETIMEDOUT => AcceptErrorAction::Retry,
        #[cfg(target_os = "linux")]
        libc::ENONET => AcceptErrorAction::Retry,
        // EMFILE, ENFILE, ENOBUFS and ENOMEM clear only when something else
        // frees an fd or memory, and an errno not listed above is treated the
        // same way.
        _ => AcceptErrorAction::Backoff,
    }
}

/// How often an acceptor waiting for a connection checks for shutdown, and
/// how often one waiting for queue room counts the wait.
const SHUTDOWN_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// How often an acceptor holding a connection retries the full queues.
const ROOM_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1);

/// Block until a live worker's queue takes `accepted`. Returns false, closing
/// the connection, when the runtime is shutting down or every worker has
/// exited.
///
/// Retries every live queue, [`ROOM_POLL_INTERVAL`] apart: `std::sync::mpsc`
/// has no wait on several senders at once. The acceptor is here only while
/// every worker's queue is full, so the interval adds about a millisecond
/// to a connection already waiting behind `accept_queue_capacity` others.
fn send_when_room(config: &AcceptorConfig, alive: &mut [bool], accepted: AcceptedConn) -> bool {
    let mut accepted = accepted;
    let mut counted = std::time::Instant::now();
    loop {
        for (worker_idx, tx) in config.worker_channels.iter().enumerate() {
            if !alive[worker_idx] {
                continue;
            }
            match tx.try_send(accepted) {
                Ok(()) => {
                    config.worker_wake_handles[worker_idx].wake();
                    return true;
                }
                Err(TrySendError::Full(returned)) => accepted = returned,
                // That worker has exited.
                Err(TrySendError::Disconnected(returned)) => {
                    alive[worker_idx] = false;
                    accepted = returned;
                }
            }
        }
        if !alive.contains(&true) || config.shutdown_flag.load(Ordering::Acquire) {
            return false;
        }
        if counted.elapsed() >= SHUTDOWN_CHECK_INTERVAL {
            crate::metrics::CONNECTIONS.increment(crate::metrics::conn::ACCEPT_QUEUE_FULL);
            counted = std::time::Instant::now();
        }
        std::thread::sleep(ROOM_POLL_INTERVAL);
    }
}

/// Block until `listen_fd` has a connection to accept. Returns false when
/// `shutdown_flag` is set.
#[cfg_attr(all(target_os = "linux", not(test)), allow(dead_code))]
fn wait_for_connection(listen_fd: RawFd, shutdown_flag: &AtomicBool) -> bool {
    loop {
        if shutdown_flag.load(Ordering::Acquire) {
            return false;
        }
        let mut pollfd = libc::pollfd {
            fd: listen_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = SHUTDOWN_CHECK_INTERVAL.as_millis() as libc::c_int;
        match unsafe { libc::poll(&mut pollfd, 1, timeout) } {
            0 => {}
            -1 if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) => {}
            // Ready, or an error `accept` reports.
            _ => return true,
        }
    }
}

/// Accept a connection and set the **returned** fd to non-blocking +
/// close-on-exec.
///
/// On Linux, uses a blocking `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)` for a
/// single syscall. `shutdown(fd, SHUT_RD)` on the listen socket makes a blocked
/// or later `accept4` fail with `EINVAL`, which ends the acceptor at shutdown.
/// Closing the fd does not wake a blocked accept, because the syscall holds a
/// file reference.
///
/// On other platforms, `SHUT_RD` does not wake a blocked `accept`, so the
/// listener is non-blocking and the acceptor waits in
/// [`wait_for_connection`] before calling `accept()` and `fcntl()`.
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

    /// An acceptor parked on a gate that never opens must still exit when the
    /// runtime shuts down.
    ///
    /// This is the mechanism `Runtime::shutdown` relies on. It cannot
    /// be tested through the public API: the acceptor thread is detached, so a
    /// parked one does not hold up `join()` on the worker handles, and the
    /// listener is shut down by `shutdown` whether the thread woke or not. The
    /// leak is a stranded thread, which no observable API state reflects.
    #[test]
    fn a_gated_acceptor_exits_on_shutdown() {
        use std::sync::atomic::AtomicBool;

        let gates = crate::listen_gate::ListenGates::new(1, 128);
        // `TcpListener::bind` listens, so an acceptor that skipped the gate
        // would block in `accept4` rather than exit. The assertions below
        // separate the two: a gated acceptor exits on `gates.shutdown()`, one
        // blocked in `accept4` does not.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let (tx, _rx) = crate::handoff::bounded::<AcceptedConn>(1);

        let config = AcceptorConfig {
            sockets: crate::listener_sockets::ListenerSockets::new(vec![listener.into()]),
            listener: crate::ListenerId::from_index(0),
            worker_channels: vec![tx],
            worker_wake_handles: Vec::new(),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            listen_gates: Arc::clone(&gates),
            tcp_nodelay: false,
            conn_chunk_size: 1,
        };

        let handle = std::thread::spawn(move || run_acceptor(config));
        // Give the thread time to enter `wait_open`. The assertion holds
        // either way: `wait_open` rechecks the predicate before it sleeps.
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(
            !handle.is_finished(),
            "the acceptor exited before the gate opened or shut"
        );

        gates.shutdown();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            handle.is_finished(),
            "shutdown did not release the acceptor parked on an unopened gate"
        );
        handle.join().expect("acceptor panicked");
    }

    /// The listener, gates and acceptor config for one worker, whose queue
    /// holds one connection and is already full.
    fn acceptor_with_a_full_queue(
        wake: crate::wakeup::WakeHandle,
    ) -> (
        std::net::SocketAddr,
        Arc<crate::listener_sockets::ListenerSockets>,
        Arc<crate::listen_gate::ListenGates>,
        crate::handoff::Receiver<AcceptedConn>,
        AcceptorConfig,
    ) {
        use std::sync::atomic::AtomicBool;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("listener address");
        let sockets = crate::listener_sockets::ListenerSockets::new(vec![listener.into()]);
        let gates = crate::listen_gate::ListenGates::new(1, 128);
        gates.register(0, Arc::clone(&sockets)).expect("register");
        gates.open(0).expect("open");

        let (tx, rx) = crate::handoff::bounded::<AcceptedConn>(1);
        let filler = std::net::UdpSocket::bind("127.0.0.1:0").expect("filler socket");
        tx.send(AcceptedConn {
            fd: filler.into(),
            listener: crate::ListenerId::from_index(0),
            peer: crate::connection::PeerAddr::Tcp(addr),
        })
        .expect("fill the queue");
        let config = AcceptorConfig {
            sockets: Arc::clone(&sockets),
            listener: crate::ListenerId::from_index(0),
            worker_channels: vec![tx],
            worker_wake_handles: vec![wake],
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            listen_gates: Arc::clone(&gates),
            tcp_nodelay: false,
            conn_chunk_size: 1,
        };
        (addr, sockets, gates, rx, config)
    }

    /// Only an error that leaves the listening socket unusable stops the
    /// acceptor; one that ends a single pending connection, or that clears
    /// when the process frees an fd or memory, does not (#828).
    #[test]
    fn only_a_dead_listener_stops_the_acceptor() {
        use AcceptErrorAction::{Backoff, Retry, Stop};
        for errno in [libc::EBADF, libc::ENOTSOCK, libc::EINVAL] {
            assert_eq!(classify_accept_error(errno), Stop, "errno {errno}");
        }
        for errno in [
            libc::EINTR,
            libc::EAGAIN,
            libc::ECONNABORTED,
            libc::ECONNRESET,
            libc::EPERM,
            libc::EPROTO,
            libc::ENETDOWN,
            libc::ENETUNREACH,
            libc::EHOSTDOWN,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
            libc::ENOPROTOOPT,
            libc::ETIMEDOUT,
        ] {
            assert_eq!(classify_accept_error(errno), Retry, "errno {errno}");
        }
        #[cfg(target_os = "linux")]
        assert_eq!(classify_accept_error(libc::ENONET), Retry);
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(classify_accept_error(errno), Backoff, "errno {errno}");
        }
        // An errno with no case of its own backs off rather than stopping.
        assert_eq!(classify_accept_error(libc::EIO), Backoff);
        assert_eq!(classify_accept_error(0), Backoff);
    }

    /// An acceptor whose listener stops accepting while the runtime is not
    /// shutting down exits and counts it, instead of exiting unseen.
    ///
    /// Linux only: `SHUT_RD` makes `accept4` fail with `EINVAL` there; other
    /// platforms do not wake a blocked `accept` that way.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_acceptor_whose_listener_dies_stops_and_counts_it() {
        let stopped = || {
            crate::metrics::CONNECTIONS
                .value(crate::metrics::conn::ACCEPTOR_STOPPED)
                .unwrap_or(0)
        };
        let before = stopped();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let sockets = crate::listener_sockets::ListenerSockets::new(vec![listener.into()]);
        let gates = crate::listen_gate::ListenGates::new(1, 128);
        gates.register(0, Arc::clone(&sockets)).expect("register");
        gates.open(0).expect("open");
        let (tx, _rx) = crate::handoff::bounded::<AcceptedConn>(1);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let config = AcceptorConfig {
            sockets: Arc::clone(&sockets),
            listener: crate::ListenerId::from_index(0),
            worker_channels: vec![tx],
            worker_wake_handles: Vec::new(),
            shutdown_flag: Arc::clone(&shutdown_flag),
            listen_gates: Arc::clone(&gates),
            tcp_nodelay: false,
            conn_chunk_size: 1,
        };
        let handle = std::thread::spawn(move || run_acceptor(config));
        std::thread::sleep(std::time::Duration::from_millis(30));

        // The listener fails every `accept` from here on; the flag stays false.
        sockets.shut_down();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(handle.is_finished(), "the acceptor did not stop");
        handle.join().expect("acceptor panicked");
        assert!(!shutdown_flag.load(Ordering::Acquire));
        assert!(
            stopped() > before,
            "the acceptor stopped without counting it"
        );
    }

    fn queue_full_count() -> u64 {
        crate::metrics::CONNECTIONS
            .value(crate::metrics::conn::ACCEPT_QUEUE_FULL)
            .unwrap_or(0)
    }

    /// A connection no worker has room for is held until one does, rather than
    /// closed (#658), and the worker is woken for it.
    ///
    /// Linux only: the test ends the acceptor by shutting its sockets down,
    /// and other platforms see shutdown through the flag.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_connection_every_worker_is_too_busy_for_waits_for_room() {
        use std::io::{Read, Write};
        use std::time::Duration;

        let (read_fd, wake) = crate::wakeup::create_wake_fd().expect("wake fd");
        let (addr, sockets, gates, rx, config) = acceptor_with_a_full_queue(wake);
        let shutdown_flag = Arc::clone(&config.shutdown_flag);
        let before = queue_full_count();
        let handle = std::thread::spawn(move || run_acceptor(config));

        let mut client = std::net::TcpStream::connect(addr).expect("connect");
        client.write_all(b"go").expect("write");
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("read timeout");
        let mut b = [0u8; 1];
        let read = client.read(&mut b);
        assert!(
            matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "the connection was closed while the queue was full: {read:?}"
        );
        assert!(queue_full_count() > before, "the wait was not counted");

        // Room appears: the held connection takes it, and the worker is woken.
        drop(rx.recv().expect("the filler"));
        let accepted = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the held connection reached the queue");
        // The fd is non-blocking and the `WakeHandle` owns it. The wake
        // follows the send, so it may land just after the receive above.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut counter = [0u8; 8];
        while unsafe { libc::read(read_fd, counter.as_mut_ptr().cast(), counter.len()) } <= 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the worker was not woken"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut served = std::net::TcpStream::from(accepted.fd);
        let mut request = [0u8; 2];
        served.read_exact(&mut request).expect("read the request");
        assert_eq!(&request, b"go");

        // As `RuntimeShutdown::shutdown` does: the flag first, so the
        // acceptor reads the `EINVAL` that `SHUT_RD` causes as shutdown.
        shutdown_flag.store(true, Ordering::Release);
        gates.shutdown();
        sockets.shut_down();
        handle.join().expect("acceptor panicked");
    }

    /// An acceptor holding a connection does not wait for the workers to exit
    /// at shutdown, as a blocked `accept4` does not.
    #[test]
    fn shutdown_ends_an_acceptor_waiting_for_room() {
        use std::time::Duration;

        let (_read_fd, wake) = crate::wakeup::create_wake_fd().expect("wake fd");
        let (addr, sockets, gates, _rx, config) = acceptor_with_a_full_queue(wake);
        let flag = Arc::clone(&config.shutdown_flag);
        let before = queue_full_count();
        let handle = std::thread::spawn(move || run_acceptor(config));

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while queue_full_count() == before && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!handle.is_finished(), "the acceptor exited before shutdown");

        flag.store(true, Ordering::Release);
        gates.shutdown();
        sockets.shut_down();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(handle.is_finished(), "shutdown did not end the acceptor");
        handle.join().expect("acceptor panicked");
        drop(client);
    }

    /// The last worker exiting ends an acceptor holding a connection.
    #[test]
    fn the_last_worker_exiting_ends_an_acceptor_waiting_for_room() {
        use std::time::Duration;

        let (_read_fd, wake) = crate::wakeup::create_wake_fd().expect("wake fd");
        let (addr, sockets, gates, rx, config) = acceptor_with_a_full_queue(wake);
        let before = queue_full_count();
        let handle = std::thread::spawn(move || run_acceptor(config));

        let client = std::net::TcpStream::connect(addr).expect("connect");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while queue_full_count() == before && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }

        drop(rx);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            handle.is_finished(),
            "the worker's exit did not end the acceptor"
        );
        handle.join().expect("acceptor panicked");
        gates.shutdown();
        sockets.shut_down();
        drop(client);
    }

    #[test]
    fn wait_for_connection_returns_when_a_peer_connects() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("listener address");
        let _client = std::net::TcpStream::connect(addr).expect("connect");
        let flag = AtomicBool::new(false);
        assert!(wait_for_connection(
            std::os::fd::AsRawFd::as_raw_fd(&listener),
            &flag
        ));
    }

    #[test]
    fn wait_for_connection_returns_false_on_shutdown() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let listen_fd = std::os::fd::AsRawFd::as_raw_fd(&listener);
        let flag = Arc::new(AtomicBool::new(false));
        let setter = Arc::clone(&flag);
        let waiter = std::thread::spawn(move || wait_for_connection(listen_fd, &setter));
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(!waiter.is_finished(), "returned with nothing to accept");
        flag.store(true, Ordering::Release);
        assert!(!waiter.join().expect("waiter panicked"));
    }

    /// An idle acceptor exits at shutdown with no peer connecting, on every
    /// platform (#560).
    #[test]
    fn shutdown_ends_an_idle_acceptor() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let sockets = crate::listener_sockets::ListenerSockets::new(vec![listener.into()]);
        let gates = crate::listen_gate::ListenGates::new(1, 128);
        gates.register(0, Arc::clone(&sockets)).expect("register");
        gates.open(0).expect("open");

        let (tx, _rx) = crate::handoff::bounded::<AcceptedConn>(8);
        let flag = Arc::new(AtomicBool::new(false));
        let config = AcceptorConfig {
            sockets: Arc::clone(&sockets),
            listener: crate::ListenerId::from_index(0),
            worker_channels: vec![tx],
            worker_wake_handles: Vec::new(),
            shutdown_flag: Arc::clone(&flag),
            listen_gates: Arc::clone(&gates),
            tcp_nodelay: false,
            conn_chunk_size: 1,
        };
        let handle = std::thread::spawn(move || run_acceptor(config));
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(!handle.is_finished(), "the acceptor exited before shutdown");

        flag.store(true, Ordering::Release);
        gates.shutdown();
        sockets.shut_down();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(handle.is_finished(), "shutdown did not end the acceptor");
        handle.join().expect("acceptor panicked");
    }

    /// `Runtime::shutdown` wakes an acceptor blocked in `accept4` by shutting
    /// its listener's sockets down, and leaves the fd open for the acceptor to
    /// drop.
    ///
    /// Linux only: other platforms see shutdown through the flag.
    #[cfg(target_os = "linux")]
    #[test]
    fn shutting_the_sockets_down_ends_a_blocked_acceptor() {
        use std::sync::atomic::AtomicBool;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let sockets = crate::listener_sockets::ListenerSockets::new(vec![listener.into()]);
        let gates = crate::listen_gate::ListenGates::new(1, 128);
        gates.register(0, Arc::clone(&sockets)).expect("register");
        gates.open(0).expect("open");

        let (tx, _rx) = crate::handoff::bounded::<AcceptedConn>(8);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let config = AcceptorConfig {
            sockets: Arc::clone(&sockets),
            listener: crate::ListenerId::from_index(0),
            worker_channels: vec![tx],
            worker_wake_handles: Vec::new(),
            shutdown_flag: Arc::clone(&shutdown_flag),
            listen_gates: Arc::clone(&gates),
            tcp_nodelay: false,
            conn_chunk_size: 1,
        };
        let handle = std::thread::spawn(move || run_acceptor(config));
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(!handle.is_finished(), "the acceptor exited before shutdown");

        // As `RuntimeShutdown::shutdown` does: the flag first.
        shutdown_flag.store(true, Ordering::Release);
        gates.shutdown();
        sockets.shut_down();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(handle.is_finished(), "shut_down did not wake the acceptor");
        handle.join().expect("acceptor panicked");

        assert!(
            unsafe { libc::fcntl(sockets.fd(0), libc::F_GETFD) } >= 0,
            "shut_down closed the socket"
        );
        assert_eq!(
            Arc::strong_count(&sockets),
            1,
            "the acceptor or the gates kept a hold after shutdown"
        );
    }

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

        apply_accepted_sockopts(accepted.as_raw_fd(), true);
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
        apply_accepted_sockopts(accepted.as_raw_fd(), false);
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
