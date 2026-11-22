//! Helpers shared by this crate's integration tests.

#![allow(dead_code)]

use std::net::TcpStream;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A loopback port that refuses connections, held by the client end of an
/// established loopback connection. Nothing listens on it, so a connect to it
/// fails with `ConnectionRefused` on Linux and macOS, and the port stays in
/// use until the returned streams are dropped, so a port-0 bind is never
/// given it.
///
/// A bound socket that never listens does not work here: macOS drops a SYN
/// to it instead of refusing, so the connect times out.
///
/// The client end is bound to `127.0.0.1:0` before it connects. Linux lets a
/// later `connect` take a port that an earlier `connect` chose as its own
/// source port when the two 4-tuples differ (`__inet_hash_connect` skips only
/// ports a `bind` took). A connect to this port could then choose the port
/// itself as its source and connect to itself, so the connect succeeds instead
/// of being refused.
pub fn refusing_port() -> ((TcpStream, TcpStream), u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = bound_connect(listener.local_addr().unwrap());
    let (server, _) = listener.accept().unwrap();
    let port = client.local_addr().unwrap().port();
    ((client, server), port)
}

/// A blocking TCP connection to `to` from a socket bound to `127.0.0.1:0`
/// first.
fn bound_connect(to: std::net::SocketAddr) -> TcpStream {
    use std::os::fd::FromRawFd;

    let std::net::SocketAddr::V4(to) = to else {
        panic!("bound_connect takes an IPv4 address");
    };
    let sockaddr = |ip: std::net::Ipv4Addr, port: u16| {
        // SAFETY: all-zero is a valid `sockaddr_in`.
        let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        {
            a.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        a.sin_family = libc::AF_INET as libc::sa_family_t;
        a.sin_port = port.to_be();
        a.sin_addr.s_addr = u32::from(ip).to_be();
        a
    };
    let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    #[cfg(target_os = "linux")]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let kind = libc::SOCK_STREAM;
    // SAFETY: a new socket this function owns until it is wrapped below.
    let fd = unsafe { libc::socket(libc::AF_INET, kind, 0) };
    assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
    // SAFETY: `fd` is the new socket, and `stream` owns it from here.
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    let local = sockaddr(std::net::Ipv4Addr::LOCALHOST, 0);
    let remote = sockaddr(*to.ip(), to.port());
    // SAFETY: both addresses are valid `sockaddr_in`s of length `len`.
    unsafe {
        assert_eq!(
            libc::bind(fd, (&raw const local).cast(), len),
            0,
            "bind: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            libc::connect(fd, (&raw const remote).cast(), len),
            0,
            "connect: {}",
            std::io::Error::last_os_error()
        );
    }
    stream
}

/// How long [`join_workers`] waits for the workers to exit before it shuts
/// the runtime down and fails the test.
pub const WORKER_EXIT_DEADLINE: Duration = Duration::from_secs(30);

/// Join the workers of a runtime whose handler requests its own shutdown.
///
/// If the workers have not all exited within [`WORKER_EXIT_DEADLINE`] of the
/// call, this shuts the runtime down, waits up to 5 s for them, and fails the
/// test. A handler that never requests shutdown fails the test instead of
/// hanging it.
///
/// Panics as soon as a worker panics or returns an error.
#[track_caller]
pub fn join_workers(
    runtime: &ringline::Runtime,
    handles: Vec<JoinHandle<Result<(), ringline::Error>>>,
) {
    join_workers_within(runtime, handles, WORKER_EXIT_DEADLINE);
}

/// [`join_workers`] with a deadline other than [`WORKER_EXIT_DEADLINE`].
#[track_caller]
pub fn join_workers_within(
    runtime: &ringline::Runtime,
    handles: Vec<JoinHandle<Result<(), ringline::Error>>>,
    limit: Duration,
) {
    let deadline = Instant::now() + limit;
    let mut running = handles;
    while !running.is_empty() {
        // Check each worker as it exits, so an error surfaces at once rather
        // than after the others.
        let (finished, still): (Vec<_>, Vec<_>) =
            running.into_iter().partition(|h| h.is_finished());
        for h in finished {
            h.join().expect("worker panicked").expect("worker failed");
        }
        running = still;
        if running.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            runtime.shutdown();
            let grace = Instant::now() + Duration::from_secs(5);
            while !running.iter().all(|h| h.is_finished()) && Instant::now() < grace {
                std::thread::sleep(Duration::from_millis(10));
            }
            let exited = running.iter().all(|h| h.is_finished());
            panic!(
                "the workers did not exit within {limit:?}; after Runtime::shutdown they {}",
                if exited {
                    "exited, so shutdown was never requested"
                } else {
                    "were still running 5 s later"
                }
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
