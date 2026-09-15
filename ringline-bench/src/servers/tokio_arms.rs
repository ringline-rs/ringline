//! Tokio server arms for the fair-comparison sweep.
//!
//! The default `bench-server --runtime tokio` path is a multi-threaded
//! work-stealing runtime running the canonical tokio echo loop (one reused
//! buffer, `read` into it, `write_all` out of it). Measured against ringline it
//! trails by ~50% at 64 connections, and the gap is *latency*, not syscalls —
//! tokio issues ~2.1 syscalls per operation against ringline's mio backend at
//! ~3.0, and still loses. Two structural differences could account for that,
//! and the default arm confounds them:
//!
//! - **scheduler shape.** ringline is thread-per-core with no work stealing and
//!   no cross-thread wakeups; tokio's default runtime is neither.
//! - **copies.** tokio's API copies kernel→user on `read` and user→kernel on
//!   `write`. ringline's forward paths do one copy or none.
//!
//! [`TokioScheduler::PerCore`] isolates the first: one `current_thread` runtime
//! per core, each with its own `SO_REUSEPORT` listener, which is as close to
//! ringline's structure as tokio gets. [`TokioEcho::Splice`] isolates the
//! second: `splice(2)` through a pipe moves the bytes without them ever
//! entering user memory, which is the honest counterpart to ringline's
//! `recv_forward`/`forward_held` byte pipe.
//!
//! Neither is a strawman-removal exercise. Both exist so that a published
//! "ringline is N% faster than tokio" survives the obvious objection that it
//! was comparing a specialised path against a general one.

use std::net::SocketAddr;

/// How the tokio arm schedules work across cores.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokioScheduler {
    /// One work-stealing multi-thread runtime (tokio's default, and the shape
    /// every published tokio benchmark uses).
    MultiThread,
    /// One `current_thread` runtime per core, each with its own
    /// `SO_REUSEPORT` listener. Matches ringline's thread-per-core structure.
    PerCore,
}

/// How the tokio arm moves the bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokioEcho {
    /// `read` into a reused buffer, `write_all` back out of it. Two copies.
    Copy,
    /// `splice(2)` socket → pipe → socket. Zero copies, Linux only.
    Splice,
}

/// Run the tokio echo server until the process is signalled.
pub fn run(
    addr: SocketAddr,
    workers: usize,
    msg_size: usize,
    scheduler: TokioScheduler,
    echo: TokioEcho,
    pin_to_core: bool,
) {
    if echo == TokioEcho::Splice && !cfg!(target_os = "linux") {
        eprintln!("bench-server: --tokio-echo splice requires Linux");
        std::process::exit(2);
    }
    match scheduler {
        TokioScheduler::MultiThread => run_multi_thread(addr, workers, msg_size, echo),
        TokioScheduler::PerCore => run_per_core(addr, workers, msg_size, echo, pin_to_core),
    }
}

fn run_multi_thread(addr: SocketAddr, workers: usize, msg_size: usize, echo: TokioEcho) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    rt.block_on(async move {
        let listener = bind_listener(addr, false).expect("failed to bind");
        eprintln!("bench-server: ready (tokio multi-thread, echo={echo:?})");
        accept_loop(listener, msg_size, echo).await;
    });
}

fn run_per_core(
    addr: SocketAddr,
    workers: usize,
    msg_size: usize,
    echo: TokioEcho,
    pin_to_core: bool,
) {
    // Report ready only once every listener is bound: the client connects as
    // soon as it sees the line, and a premature one races the bind.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let mut handles = Vec::with_capacity(workers);
    for core in 0..workers {
        let ready_tx = ready_tx.clone();
        handles.push(std::thread::spawn(move || {
            if pin_to_core {
                pin_current_thread(core);
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");
            rt.block_on(async move {
                // Every worker binds its own listener. The kernel hashes
                // incoming connections across them, which is how ringline's
                // acceptor spreads them too -- without this, one accept queue
                // would feed N runtimes and re-introduce the cross-thread
                // handoff the arm exists to remove.
                let listener = bind_listener(addr, true).expect("failed to bind");
                ready_tx.send(()).ok();
                accept_loop(listener, msg_size, echo).await;
            });
        }));
    }
    for _ in 0..workers {
        ready_rx
            .recv()
            .expect("a per-core worker died before binding");
    }
    eprintln!("bench-server: ready (tokio per-core x{workers}, echo={echo:?})");
    for h in handles {
        h.join().ok();
    }
}

/// A plain `std` listener with `SO_REUSEPORT` set, for runtimes that take one
/// by `from_std` (the `tokio-uring` arm). Gated on that arm's cfg: its only
/// caller is compiled out otherwise, and `-D dead-code` is a CI failure.
///
/// Built from raw syscalls rather than `tokio::net::TcpSocket`, because
/// `TcpSocket::listen` constructs a `tokio::net::TcpListener` and panics with
/// "there is no reactor running" — the tokio-uring arm's threads run a
/// tokio-uring runtime, not a tokio one.
#[cfg(all(target_os = "linux", feature = "tokio-uring-arm"))]
pub(crate) fn reuseport_std_listener(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    use std::os::fd::FromRawFd;

    let SocketAddr::V4(v4) = addr else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tokio-uring arm supports IPv4 only",
        ));
    };

    let err = || std::io::Error::last_os_error();
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(err());
        }
        // Owns the fd from here, so every early return closes it.
        let listener = std::net::TcpListener::from_raw_fd(fd);
        let on: libc::c_int = 1;
        let optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &on as *const _ as *const libc::c_void,
                optlen,
            ) != 0
            {
                return Err(err());
            }
        }
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: v4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        if libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            return Err(err());
        }
        if libc::listen(fd, 1024) != 0 {
            return Err(err());
        }
        Ok(listener)
    }
}

fn bind_listener(addr: SocketAddr, reuseport: bool) -> std::io::Result<tokio::net::TcpListener> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    if reuseport {
        socket.set_reuseport(true)?;
    }
    socket.bind(addr)?;
    socket.listen(1024)
}

async fn accept_loop(listener: tokio::net::TcpListener, msg_size: usize, echo: TokioEcho) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => continue,
        };
        stream.set_nodelay(true).ok();
        match echo {
            TokioEcho::Copy => {
                tokio::spawn(copy_echo(stream, msg_size));
            }
            TokioEcho::Splice => {
                #[cfg(target_os = "linux")]
                tokio::spawn(async move {
                    let _ = splice_echo(stream).await;
                });
                #[cfg(not(target_os = "linux"))]
                let _ = stream;
            }
        }
    }
}

/// The canonical tokio echo: one reused buffer, read into it, write back out.
async fn copy_echo(mut stream: tokio::net::TcpStream, msg_size: usize) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Matches ringline's per-buffer recv size so neither side gets a
    // structurally larger read quantum.
    let mut buf = vec![0u8; msg_size.next_power_of_two().max(4096)];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if stream.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
}

/// Zero-copy echo: `splice(2)` socket → pipe → socket. The bytes never enter
/// user memory, which is what ringline's `forward_held` achieves by holding
/// the kernel's own recv buffers.
#[cfg(target_os = "linux")]
async fn splice_echo(stream: tokio::net::TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    struct Pipe(libc::c_int, libc::c_int);
    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
                libc::close(self.1);
            }
        }
    }

    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let pipe = Pipe(fds[0], fds[1]);
    let (pipe_r, pipe_w) = (pipe.0, pipe.1);
    let sock = stream.as_raw_fd();

    // One splice chunk. Larger than the pipe's default 64 KiB capacity buys
    // nothing, since splice stops at capacity.
    const CHUNK: usize = 64 * 1024;
    const FLAGS: libc::c_uint = (libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK) as libc::c_uint;

    let do_splice = |from: libc::c_int, to: libc::c_int, len: usize| -> std::io::Result<usize> {
        let n = unsafe {
            libc::splice(
                from,
                std::ptr::null_mut(),
                to,
                std::ptr::null_mut(),
                len,
                FLAGS,
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    };

    loop {
        stream.readable().await?;
        let n = match stream.try_io(Interest::READABLE, || do_splice(sock, pipe_w, CHUNK)) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };
        // splice returns 0 at EOF, exactly like read.
        if n == 0 {
            return Ok(());
        }
        let mut left = n;
        while left > 0 {
            stream.writable().await?;
            match stream.try_io(Interest::WRITABLE, || do_splice(pipe_r, sock, left)) {
                Ok(0) => return Ok(()),
                Ok(w) => left -= w,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Pin the calling thread to one logical CPU, so the per-core arm has the same
/// placement discipline as ringline's workers. Linux only; elsewhere the arm
/// still runs, just unpinned.
#[cfg(target_os = "linux")]
pub(crate) fn pin_current_thread(core: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn pin_current_thread(_core: usize) {}
