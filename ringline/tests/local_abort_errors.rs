//! A connection the runtime aborts on its own account — a write that failed,
//! a receive that ran past `recv_accumulator_max` — reports the abort to a
//! reader parked on `with_data_result`, as a socket read error does. Only a
//! peer that closed cleanly resolves `Ok(0)`.

mod common;

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// What the handler's `with_data_result` resolved to, by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Ok(usize),
    Err(io::ErrorKind),
}

/// Tests share the statics below, so they run one at a time under `cargo test`.
static SERIAL: Mutex<()> = Mutex::new(());
static OUTCOME: Mutex<Option<Outcome>> = Mutex::new(None);
static DONE: AtomicBool = AtomicBool::new(false);

fn record(result: io::Result<usize>) {
    *OUTCOME.lock().unwrap() = Some(match result {
        Ok(n) => Outcome::Ok(n),
        Err(e) => Outcome::Err(e.kind()),
    });
    DONE.store(true, Ordering::SeqCst);
}

fn reset() {
    *OUTCOME.lock().unwrap() = None;
    DONE.store(false, Ordering::SeqCst);
}

/// Wait for the handler to record its outcome; fail the test if it does not.
fn outcome() -> Outcome {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !DONE.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline,
            "handler did not resolve its read"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    OUTCOME.lock().unwrap().clone().expect("recorded")
}

fn config() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .send_pool(1024, 16448)
        .no_fs()
}

fn launch<H: AsyncEventHandler>(
    config: ConfigBuilder,
) -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
    SocketAddr,
) {
    let (rt, handles) = RinglineBuilder::new(config.build().expect("config"))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch");
    let addr = rt.bound_addr().expect("bound address");
    (rt, handles, addr)
}

fn stop(rt: ringline::Runtime, handles: Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>) {
    rt.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
}

#[cfg(not(has_io_uring))]
fn set_linger_zero(stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: a valid fd and a correctly sized, initialised `linger`.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_LINGER)");
}

/// Reads one request, queues a response far larger than the socket buffers
/// without awaiting it, then parks on `with_data_result`.
#[cfg(not(has_io_uring))]
struct RespondThenRead;

#[cfg(not(has_io_uring))]
const RESPONSE: usize = 8 * 1024 * 1024;

#[cfg(not(has_io_uring))]
impl AsyncEventHandler for RespondThenRead {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let _ = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
            conn.send_nowait(&vec![b'x'; RESPONSE])
                .expect("queue the response");
            record(
                conn.with_data_result(|d| ParseResult::Consumed(d.len()))
                    .await,
            );
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        RespondThenRead
    }
}

/// The peer resets the connection while the response is still draining, so
/// the runtime's next write fails. The parked read reports that failure, not
/// a clean close.
///
/// mio only: there the write error is what closes the connection. On io_uring
/// a failed send does not close the connection, and whichever of the send and
/// the receive the kernel completes first takes the socket's pending error:
/// when the send takes it, the receive then reports a plain EOF and the read
/// resolves `Ok(0)` (audit finding F13), so the outcome there is not fixed.
#[cfg(not(has_io_uring))]
#[test]
fn write_error_teardown_is_reported_to_the_reader() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (rt, handles, addr) = launch::<RespondThenRead>(config());

    let mut peer = TcpStream::connect(addr).expect("connect");
    peer.write_all(b"req").expect("request");
    // Read one byte of the response: the server has queued it and is
    // writing, so the reset below lands on a write in progress.
    let mut first = [0u8; 1];
    peer.read_exact(&mut first).expect("first response byte");
    set_linger_zero(&peer);
    drop(peer);

    let got = outcome();
    stop(rt, handles);
    assert!(
        matches!(
            got,
            Outcome::Err(io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset)
        ),
        "a write error must reach the reader as an error, got {got:?}"
    );
}

/// Never finishes a message, so every byte accumulates until the cap.
struct NeverSatisfied;

impl AsyncEventHandler for NeverSatisfied {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            record(conn.with_data_result(|_| ParseResult::NeedMore).await);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        NeverSatisfied
    }
}

/// A message that runs past `recv_accumulator_max` on a plaintext connection
/// closes it; the reader is told why.
#[test]
fn accumulator_cap_exceeded_is_reported_to_the_reader() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    const CAP: usize = 16 * 1024;
    let (rt, handles, addr) = launch::<NeverSatisfied>(config().recv_accumulator_max(CAP));

    let mut peer = TcpStream::connect(addr).expect("connect");
    let chunk = vec![0xABu8; 4096];
    // Well past the cap; writes fail once the server has closed, which is
    // the expected end.
    for _ in 0..(CAP * 8 / chunk.len()) {
        if peer.write_all(&chunk).is_err() {
            break;
        }
    }

    let got = outcome();
    stop(rt, handles);
    assert_eq!(
        got,
        Outcome::Err(io::ErrorKind::QuotaExceeded),
        "exceeding recv_accumulator_max must reach the reader as an error"
    );
}

/// Consumes whatever arrives until the read resolves.
struct ReadToEnd;

impl AsyncEventHandler for ReadToEnd {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                match conn
                    .with_data_result(|d| ParseResult::Consumed(d.len()))
                    .await
                {
                    Ok(n) if n > 0 => continue,
                    other => {
                        record(other);
                        return;
                    }
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        ReadToEnd
    }
}

/// Control: a peer that closes cleanly still resolves `Ok(0)`.
#[test]
fn clean_peer_close_still_resolves_ok_zero() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (rt, handles, addr) = launch::<ReadToEnd>(config());

    let mut peer = TcpStream::connect(addr).expect("connect");
    peer.write_all(b"hello").expect("request");
    drop(peer);

    let got = outcome();
    stop(rt, handles);
    assert_eq!(got, Outcome::Ok(0));
}
