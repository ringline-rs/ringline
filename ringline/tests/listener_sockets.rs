//! Listener sockets after shutdown: the port is free while the `Runtime` is
//! still alive, the sockets close once every holder has gone, and no socket
//! the runtime opens is inherited across `exec`.
//!
//! Its own test binary, because it counts the process's open fds. Linux only:
//! it reads `/proc/self/fd`, and on macOS a shut-down listener keeps its port
//! until its acceptor exits, within about 100 ms.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

/// The tests count fds, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn create_for_worker(_id: usize) -> Self {
        Idle
    }
}

#[cfg(feature = "unstable-accept")]
use ringline::AcceptMode;

/// The only mode without the `unstable-accept` feature.
#[cfg(not(feature = "unstable-accept"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptMode {
    Pool,
}

fn config(mode: AcceptMode) -> ringline::Config {
    let builder = ConfigBuilder::new()
        .workers(2)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0);
    #[cfg(feature = "unstable-accept")]
    let builder = builder.accept_mode(mode);
    #[cfg(not(feature = "unstable-accept"))]
    let _ = mode;
    builder.build().expect("valid config")
}

/// The `(accept mode, defer)` pairs `launch()` accepts. Merged mode needs
/// io_uring, and elsewhere `launch()` serves it from the pool; it does not
/// take a deferred listener.
fn cases() -> Vec<(AcceptMode, bool)> {
    vec![
        (AcceptMode::Pool, false),
        (AcceptMode::Pool, true),
        #[cfg(feature = "unstable-accept")]
        (AcceptMode::Merged, false),
    ]
}

type Handles = Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>;

fn launch(
    mode: AcceptMode,
    addr: SocketAddr,
    defer: bool,
) -> Result<(ringline::Runtime, Handles), ringline::Error> {
    let builder = RinglineBuilder::new(config(mode)).bind(addr);
    let builder = if defer {
        builder.defer_listen()
    } else {
        builder
    };
    builder.launch::<Idle>()
}

fn join(handles: Handles) {
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
}

/// A loopback port held by a socket that never listens and has
/// `SO_REUSEADDR` and `SO_REUSEPORT` set, so a runtime can bind it explicitly.
/// Drop the socket once the runtime holds the port: the runtime's sockets are
/// then the only ones bound to it, and no other process can take it between
/// the reservation and the launch.
fn reserve_port() -> (OwnedFd, SocketAddr) {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
    // SAFETY: `socket` returned a fresh descriptor this function owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        set_flag(fd.as_raw_fd(), opt);
    }
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let sa = &mut sin as *mut libc::sockaddr_in as *mut libc::sockaddr;
    assert_eq!(unsafe { libc::bind(fd.as_raw_fd(), sa, len) }, 0, "bind");
    assert_eq!(
        unsafe { libc::getsockname(fd.as_raw_fd(), sa, &mut len) },
        0,
        "getsockname"
    );
    let port = u16::from_be(sin.sin_port);
    (fd, SocketAddr::from(([127, 0, 0, 1], port)))
}

fn set_flag(fd: i32, opt: libc::c_int) {
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt");
}

/// Launch on an explicit port that only the runtime holds once this returns.
fn launch_on_reserved_port(
    mode: AcceptMode,
    defer: bool,
) -> (ringline::Runtime, Handles, SocketAddr) {
    let (reservation, addr) = reserve_port();
    let (runtime, handles) = launch(mode, addr, defer)
        .unwrap_or_else(|e| panic!("{mode:?} defer={defer}: launch on {addr}: {e}"));
    drop(reservation);
    (runtime, handles, addr)
}

/// Whether a plain socket, with neither `SO_REUSEADDR` nor `SO_REUSEPORT`, can
/// bind `addr`.
fn plain_bind(addr: SocketAddr) -> std::io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0);
    // SAFETY: `socket` returned a fresh descriptor this function owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let SocketAddr::V4(v4) = addr else {
        unreachable!("tests bind IPv4")
    };
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
    sin.sin_port = v4.port().to_be();
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sin as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .count()
}

/// After `shutdown()`, a new runtime binds and serves the same port while the
/// old `Runtime` and its workers are still alive.
#[test]
fn a_shut_down_runtime_frees_its_port() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // A deferred listener that never opened has never listened, so `SHUT_RD`
    // does nothing to it; the port is freed by the socket option `shut_down`
    // sets.
    for (mode, defer) in cases() {
        {
            let (old, old_handles, addr) = launch_on_reserved_port(mode, defer);
            old.shutdown();

            let (new, new_handles) = launch(mode, addr, false).unwrap_or_else(|e| {
                panic!(
                    "{mode:?} defer={defer}: relaunch on {addr} while the old runtime lives: {e}"
                )
            });
            TcpStream::connect(addr).unwrap_or_else(|e| {
                panic!("{mode:?} defer={defer}: connect to the new runtime: {e}")
            });

            drop(new);
            join(new_handles);
            drop(old);
            join(old_handles);
        }
    }
}

/// After `shutdown()`, once the threads accepting on a listener have exited,
/// its sockets are closed and a socket without `SO_REUSEADDR` can bind the
/// port, while the `Runtime` and a `ListenHandle` are still alive.
#[test]
fn shutdown_releases_the_port_while_the_runtime_lives() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for (mode, defer) in cases() {
        let (runtime, handles, addr) = launch_on_reserved_port(mode, defer);
        let listen_handle = runtime.listen_handle();
        runtime.shutdown();

        let deadline = Instant::now() + Duration::from_secs(5);
        let result = loop {
            let result = plain_bind(addr);
            if result.is_ok() || Instant::now() >= deadline {
                break result;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        drop(listen_handle);
        drop(runtime);
        join(handles);
        result.unwrap_or_else(|e| panic!("{mode:?} defer={defer}: plain bind on {addr}: {e}"));
    }
}

/// Every listener socket closes once the `Runtime` is dropped and its threads
/// have exited. The pool-mode acceptor is detached, so its exit is waited for.
#[test]
fn listener_sockets_close_after_shutdown() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for (mode, defer) in cases() {
        {
            let cycle = || {
                let (runtime, handles) =
                    launch(mode, "127.0.0.1:0".parse().unwrap(), defer).expect("launch");
                if !defer {
                    TcpStream::connect(runtime.bound_addr().unwrap()).expect("connect");
                }
                drop(runtime);
                join(handles);
            };
            // Warm up anything the first launch allocates for the process.
            cycle();
            let before = open_fds();
            for _ in 0..20 {
                cycle();
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while open_fds() > before && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let after = open_fds();
            assert!(
                after <= before,
                "{mode:?} defer={defer}: fds grew from {before} to {after} over 20 launches"
            );
        }
    }
}

/// The socket fds open in this process: `(fd, close-on-exec)`.
fn sockets() -> Vec<(i32, bool)> {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let target = std::fs::read_link(entry.path()).ok()?;
            if !target.to_string_lossy().starts_with("socket:") {
                return None;
            }
            let fd: i32 = entry.file_name().to_str()?.parse().ok()?;
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            Some((fd, flags >= 0 && flags & libc::FD_CLOEXEC != 0))
        })
        .collect()
}

/// A process the application spawns does not inherit a listener, which would
/// hold the port after the runtime shut down.
#[test]
fn listener_sockets_are_close_on_exec() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // Sockets the test process started with, such as a socket on stdin.
    let preexisting = sockets();
    for (mode, _) in cases() {
        let (runtime, handles) =
            launch(mode, "127.0.0.1:0".parse().unwrap(), false).expect("launch");
        let inherited: Vec<i32> = sockets()
            .into_iter()
            .filter(|s| !preexisting.contains(s))
            .filter(|&(_, cloexec)| !cloexec)
            .map(|(fd, _)| fd)
            .collect();
        drop(runtime);
        join(handles);
        assert!(
            inherited.is_empty(),
            "{mode:?}: sockets without close-on-exec: {inherited:?}"
        );
    }
}
