//! tokio on `tokio-uring`: the interface axis of the comparison.
//!
//! The other two tokio arms vary the scheduler shape and the copy count while
//! holding epoll fixed. This one varies the I/O interface instead: same
//! futures, same task model, but submission/completion through io_uring rather
//! than readiness through epoll.
//!
//! `tokio-uring`'s runtime is single-threaded by construction, so this is
//! necessarily one runtime per core with its own `SO_REUSEPORT` listener --
//! which happens to make it directly comparable to
//! [`TokioScheduler::PerCore`](super::tokio_arms::TokioScheduler::PerCore)
//! rather than to the default multi-thread arm. Read the pair together: the
//! per-core epoll arm and this one differ only in the interface.
//!
//! Its API is owned-buffer (`read(buf) -> (Result<usize>, buf)`), so the
//! buffer moves into each call and back out, and the echo cannot borrow the
//! read buffer for the write the way the epoll arms do.

use std::net::SocketAddr;

// `slice` on an owned buffer comes from this trait, not from Vec.
use tokio_uring::buf::BoundedBuf;

/// Run one `tokio-uring` runtime per worker, each with its own listener.
pub fn run(addr: SocketAddr, workers: usize, msg_size: usize, pin_to_core: bool) {
    // Same readiness discipline as the epoll per-core arm: the "ready" line
    // must mean the listeners exist, not that the threads were spawned.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let mut handles = Vec::with_capacity(workers);
    for core in 0..workers {
        let ready_tx = ready_tx.clone();
        handles.push(std::thread::spawn(move || {
            if pin_to_core {
                super::tokio_arms::pin_current_thread(core);
            }
            // Each runtime binds its own SO_REUSEPORT listener: tokio-uring
            // runtimes do not share, and one shared accept queue would put a
            // cross-thread handoff back in the path.
            let std_listener = super::tokio_arms::reuseport_std_listener(addr)
                .expect("failed to bind SO_REUSEPORT listener");
            tokio_uring::start(async move {
                let listener = tokio_uring::net::TcpListener::from_std(std_listener);
                ready_tx.send(()).ok();
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    // The epoll arms get this from tokio's set_nodelay. Without
                    // it this arm measured 219 ops/s against the others' ~130k
                    // -- about 36ms per operation, which is the delayed-ACK
                    // timer, not the runtime.
                    set_nodelay(&stream);
                    tokio_uring::spawn(echo(stream, msg_size));
                }
            });
        }));
    }
    for _ in 0..workers {
        ready_rx
            .recv()
            .expect("a tokio-uring worker died before binding");
    }
    eprintln!("bench-server: ready (tokio-uring per-core x{workers})");
    for h in handles {
        h.join().ok();
    }
}

/// `TCP_NODELAY` on an accepted stream, by raw fd: `tokio-uring`'s `TcpStream`
/// does not expose a setter for it.
fn set_nodelay(stream: &tokio_uring::net::TcpStream) {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Owned-buffer echo: the buffer moves into `read`, comes back with the data,
/// moves into `write_all`, and comes back for reuse.
async fn echo(stream: tokio_uring::net::TcpStream, msg_size: usize) {
    let mut buf = vec![0u8; msg_size.next_power_of_two().max(4096)];
    loop {
        let (res, b) = stream.read(buf).await;
        buf = b;
        let n = match res {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let (res, b) = stream.write_all(buf.slice(..n)).await;
        buf = b.into_inner();
        if res.is_err() {
            break;
        }
    }
}
