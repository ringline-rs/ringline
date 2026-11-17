//! A listener from `RinglineBuilder::bind_fd`: it serves like any listener,
//! keeps listening after the runtime shuts down so another holder of the
//! socket can accept from its backlog, honours `defer_listen` on a socket that
//! is already listening, and `launch()` refuses a socket it cannot use.

#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

struct Echo;

impl AsyncEventHandler for Echo {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Echo
    }
}

fn config() -> ringline::Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .build()
        .expect("valid config")
}

type Handles = Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>;

fn join(runtime: &ringline::Runtime, handles: Handles) {
    runtime.shutdown();
    common::join_workers(runtime, handles);
}

/// Write `msg` and read it back within 5 s.
fn echo<S: Read + Write>(stream: &mut S, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    stream.write_all(msg)?;
    let mut got = vec![0u8; msg.len()];
    stream.read_exact(&mut got)?;
    Ok(got)
}

/// A listening loopback TCP socket, and a second fd for the same socket that
/// the test keeps, as systemd keeps its copy in the fd store.
fn listening_pair() -> (OwnedFd, TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let kept = listener.try_clone().expect("dup");
    (listener.into(), kept, addr)
}

/// Accept from `listener` within 5 s. The runtime's acceptor set
/// `O_NONBLOCK` on the shared open file description, so `accept` returns
/// `WouldBlock` until a connection is queued.
fn accept_within(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "no connection to accept");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

/// The listener serves, and after the runtime has shut down and been dropped
/// the socket is still listening: a new connection completes its handshake
/// and the copy the test kept accepts it. On Linux, `SHUT_RD` would take the
/// socket out of the listening state and the connect would be refused. macOS
/// keeps a listener listening after `SHUT_RD`, so there this test passes
/// either way (`experiments/bind-fd-verify.toml` checks it on Linux).
#[test]
fn a_listener_from_an_fd_keeps_listening_after_shutdown() {
    let (fd, kept, addr) = listening_pair();
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind_fd(fd)
        .launch::<Echo>()
        .expect("launch");
    assert_eq!(runtime.bound_addr(), Some(addr));

    let mut client = TcpStream::connect(addr).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    assert_eq!(echo(&mut client, b"ping").expect("echo"), b"ping");
    drop(client);

    join(&runtime, handles);
    drop(runtime);

    let mut late = TcpStream::connect(addr).expect("connect after shutdown");
    late.write_all(b"late").expect("write");
    let mut accepted = accept_within(&kept);
    accepted
        .set_nonblocking(false)
        .expect("blocking accepted socket");
    accepted
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut got = [0u8; 4];
    accepted.read_exact(&mut got).expect("read");
    assert_eq!(&got, b"late");
}

/// With `defer_listen()`, a socket that is already listening queues
/// connections but serves none until its gate opens; then it serves the
/// connection made before.
#[test]
fn a_deferred_listener_from_a_listening_fd_serves_once_its_gate_opens() {
    let (fd, _kept, addr) = listening_pair();
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind_fd(fd)
        .defer_listen()
        .launch::<Echo>()
        .expect("launch");

    // The kernel completes the handshake: the socket is listening.
    let mut client = TcpStream::connect(addr).expect("connect while gated");
    client.write_all(b"early").expect("write");
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("read timeout");
    let mut got = [0u8; 5];
    let read = client.read(&mut got);
    assert!(
        matches!(&read, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
        "served before the gate opened: {read:?}"
    );

    runtime
        .listen_handle()
        .begin_listening_all()
        .expect("open the gate");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    client
        .read_exact(&mut got)
        .expect("served after the gate opened");
    assert_eq!(&got, b"early");
    drop(client);
    join(&runtime, handles);
}

/// A Unix-domain socket from an fd serves, and its path is left in place.
#[test]
fn a_unix_listener_from_an_fd_serves() {
    let dir = std::env::temp_dir().join(format!("ringline-bind-fd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("s");
    let _ = std::fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind unix");
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind_fd(listener.into())
        .launch::<Echo>()
        .expect("launch");
    assert_eq!(runtime.bound_addr(), None);

    let mut client = std::os::unix::net::UnixStream::connect(&path).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    assert_eq!(echo(&mut client, b"unix").expect("echo"), b"unix");
    drop(client);
    join(&runtime, handles);
    drop(runtime);
    assert!(path.exists(), "the runtime removed the socket's path");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The runtime sets close-on-exec on a socket it is given.
#[test]
fn a_listener_from_an_fd_is_close_on_exec() {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(raw >= 0, "socket: {}", std::io::Error::last_os_error());
    // SAFETY: `socket` returned a fresh descriptor this test owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    }
    let rc = unsafe {
        libc::bind(
            raw,
            &sin as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind: {}", std::io::Error::last_os_error());
    assert_eq!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );

    let (runtime, handles) = RinglineBuilder::new(config())
        .bind_fd(fd)
        .launch::<Echo>()
        .expect("launch");
    assert_ne!(
        unsafe { libc::fcntl(raw, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0,
        "the listener is inherited across exec"
    );
    join(&runtime, handles);
}

fn refused(fd: OwnedFd) -> String {
    match RinglineBuilder::new(config()).bind_fd(fd).launch::<Echo>() {
        Ok(_) => panic!("launch accepted the fd"),
        Err(ringline::Error::RingSetup(msg)) => msg,
        Err(e) => panic!("unexpected error: {e}"),
    }
}

/// `launch()` refuses a datagram socket.
#[test]
fn a_datagram_socket_is_refused() {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp");
    let msg = refused(udp.into());
    assert!(msg.contains("SOCK_STREAM"), "{msg}");
}

/// `launch()` refuses a TCP socket that was never bound.
#[test]
fn an_unbound_socket_is_refused() {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(raw >= 0, "socket: {}", std::io::Error::last_os_error());
    // SAFETY: `socket` returned a fresh descriptor this test owns.
    let msg = refused(unsafe { OwnedFd::from_raw_fd(raw) });
    assert!(msg.contains("not bound"), "{msg}");
}

/// `launch()` refuses a Unix-domain socket that was never bound.
#[test]
fn an_unbound_unix_socket_is_refused() {
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(raw >= 0, "socket: {}", std::io::Error::last_os_error());
    // SAFETY: `socket` returned a fresh descriptor this test owns.
    let msg = refused(unsafe { OwnedFd::from_raw_fd(raw) });
    assert!(msg.contains("not bound"), "{msg}");
}

/// `launch()` refuses a connected stream socket, which cannot listen.
#[test]
fn a_connected_socket_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let client = TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
    let msg = refused(client.into());
    assert!(msg.contains("connected"), "{msg}");
}

/// `launch()` refuses a listener from an fd in merged accept mode.
#[cfg(all(feature = "unstable-accept", has_io_uring))]
#[test]
fn a_listener_from_an_fd_is_refused_in_merged_mode() {
    let (fd, _kept, _addr) = listening_pair();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .accept_mode(ringline::AcceptMode::Merged)
        .build()
        .expect("valid config");
    match RinglineBuilder::new(config).bind_fd(fd).launch::<Echo>() {
        Ok(_) => panic!("launch accepted bind_fd in merged mode"),
        Err(ringline::Error::RingSetup(msg)) => assert!(msg.contains("Merged"), "{msg}"),
        Err(e) => panic!("unexpected error: {e}"),
    }
}
