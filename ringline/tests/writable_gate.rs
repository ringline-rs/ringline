//! `SendHalf::writable`, the wait for room in a socket that a server awaits
//! before each piece of a large reply, so that a piece takes send-pool slots
//! only once its socket has room, and `SendCompletion::waited_for_room`, on
//! whichever backend the build has.
//!
//! Each test opens one connection to a one-worker server. The first byte the
//! client writes picks what the server does. Most cases fill the server's
//! socket first: the server sends 16 KiB at a time, eight sends a
//! millisecond, to a client that does not read, until the last send reads
//! `waited_for_room` before it has settled. The unit tests in the io_uring
//! event loop cover the multishot poll and its probe with injected
//! completions.
//!
//! The client leaves its receive buffer to the kernel. On Linux, a
//! `SO_RCVBUF` cut to 4096 after the connect keeps the client's window below
//! the server's MSS, which the kernel caps at half the largest window the
//! client has advertised (about 64 KiB at the handshake). The server then
//! sends only when its zero-window persist timer fires, a few KiB each
//! time, so the full socket takes minutes to drain and reports no `POLLOUT`
//! within the tests' bounds. `loopback_drain_with_a_receive_buffer_shrunk_after_connect`
//! measures this with plain sockets.
//!
//! The tests share the statics below, and `cargo test` runs them in one
//! process.

#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the server saw, for the test thread to check.
#[derive(Debug, Default)]
struct Seen {
    /// `waited_for_room` of a 5-byte send to an empty socket, once settled.
    first_waited: Option<bool>,
    /// Whether the gate was still pending 200 ms after the socket filled.
    pending_while_full: Option<bool>,
    /// The gate's result: `Ok`, the error's kind, or `TimedOut` if the
    /// server's bound on it elapsed.
    gate: Option<Result<(), io::ErrorKind>>,
    /// When the server told the client to drain or reset (or, for an empty
    /// socket, began the gate), and when the gate resolved.
    filled_at: Option<Instant>,
    resolved_at: Option<Instant>,
    /// `send_buffer_size`, and the server socket's `sk_sndbuf` read through
    /// netlink just before and just after it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    send_buffer: Option<(usize, u32, u32)>,
    /// Whether each of two sends made before the gate had settled when it
    /// resolved.
    queued_settled: Option<(bool, bool)>,
    /// Whether a send of the second fill, which should go in whole, waited.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    refill_waited: Option<bool>,
    /// The server socket's (`sk_wmem_queued`, `sk_sndbuf`) when the gate
    /// started, after the second fill.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    skmem_at_gate: Option<(u32, u32)>,
    /// The same, read just after the gate resolved, if it resolved early.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    skmem_at_early: Option<(u32, u32)>,
    /// The refills the second fill took: one, and one more each time the
    /// socket became writable while the gate waited.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    refill_attempts: Option<u32>,
    /// Why the server gave up before the gate.
    note: Option<String>,
}

static SEEN: Mutex<Option<Seen>> = Mutex::new(None);
/// The server has filled the socket and its gate waits.
static FILLED: AtomicBool = AtomicBool::new(false);
/// The bytes the server sent in its first fill.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
static TOTAL: AtomicUsize = AtomicUsize::new(0);
/// The client has read the first fill in full.
static READ_ALL: AtomicBool = AtomicBool::new(false);
/// The server has filled the socket a second time, with whole sends.
static REFILLED: AtomicBool = AtomicBool::new(false);
/// The listener's port and the client's, for reading the server socket's
/// memory through `NETLINK_SOCK_DIAG`; 0 until the test thread sets them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
static SERVER_PORT: AtomicU16 = AtomicU16::new(0);
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
static CLIENT_PORT: AtomicU16 = AtomicU16::new(0);

const CHUNK_LEN: usize = 16 * 1024;
const SLOT: u32 = 16 * 1024;
const SLOTS: u16 = 64;
/// At most 128 MiB: loopback buffers take a few MiB.
const MAX_ROUNDS: usize = 1024;

fn record(f: impl FnOnce(&mut Seen)) {
    let mut seen = SEEN.lock().unwrap();
    f(seen.get_or_insert_with(Seen::default));
}

fn gate_result(r: Result<io::Result<()>, ringline::Elapsed>) -> Result<(), io::ErrorKind> {
    match r {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.kind()),
        Err(_elapsed) => Err(io::ErrorKind::TimedOut),
    }
}

/// Send until the socket is full: 16 KiB a send, eight sends a millisecond,
/// until the last one reads `waited_for_room` before it settles. Panics if
/// that does not happen within `MAX_ROUNDS`.
///
/// The completions are dropped, so no send's completion wakes the task: a
/// gate the task then awaits ends its wait only through its own wakes.
async fn fill(conn: &mut Connection) {
    static CHUNK: [u8; CHUNK_LEN] = [7; CHUNK_LEN];
    for _ in 0..MAX_ROUNDS {
        let mut last = None;
        for _ in 0..8 {
            last = Some(conn.send(&CHUNK).expect("send"));
        }
        ringline::sleep(Duration::from_millis(1)).await;
        if last.expect("eight sends").waited_for_room() {
            return;
        }
    }
    panic!("no send waited for room after {MAX_ROUNDS} rounds");
}

/// `fill`, keeping the last send's completion and counting the bytes sent:
/// before the round whose last send waited for room, and in all.
async fn fill_keeping(conn: &mut Connection) -> (usize, usize, ringline::SendCompletion) {
    static CHUNK: [u8; CHUNK_LEN] = [7; CHUNK_LEN];
    let mut sent = 0;
    for _ in 0..MAX_ROUNDS {
        let before = sent;
        let mut last = None;
        for _ in 0..8 {
            last = Some(conn.send(&CHUNK).expect("send"));
            sent += CHUNK_LEN;
        }
        ringline::sleep(Duration::from_millis(1)).await;
        let last = last.expect("eight sends");
        if last.waited_for_room() {
            return (before, sent, last);
        }
    }
    panic!("no send waited for room after {MAX_ROUNDS} rounds");
}

/// Whether `sent` has settled, from one poll. Poll each completion once.
async fn settled(sent: &mut ringline::SendCompletion) -> bool {
    std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *sent).poll(cx).is_ready())).await
}

/// A 5-byte send to an empty socket settles without waiting for room.
async fn first_send(conn: &mut Connection) {
    let mut first = conn.send(b"first").expect("send");
    let settled = ringline::timeout(Duration::from_secs(5), &mut first).await;
    assert!(matches!(settled, Ok(Ok(5))), "{settled:?}");
    let waited = first.waited_for_room();
    record(|s| s.first_waited = Some(waited));
}

struct Gate;

impl AsyncEventHandler for Gate {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut cmd = 0u8;
            let n = conn
                .with_data(|data| {
                    cmd = data[0];
                    ParseResult::Consumed(1)
                })
                .await;
            if n == 0 {
                return;
            }
            match cmd {
                b'w' => {
                    // Before any write, so that no writable event from the
                    // peer's acknowledgement can wake a gate that did not look
                    // at the socket on its first poll.
                    let began = Instant::now();
                    let gate = ringline::timeout(Duration::from_secs(1), conn.writable()).await;
                    let gate = gate_result(gate);
                    record(|s| {
                        s.gate = Some(gate);
                        s.filled_at = Some(began);
                        s.resolved_at = Some(Instant::now());
                    });
                    first_send(&mut conn).await;
                }
                b'd' => full_then_drain(&mut conn).await,
                b'r' => {
                    fill(&mut conn).await;
                    FILLED.store(true, Ordering::SeqCst);
                    let gate = ringline::timeout(Duration::from_secs(10), conn.writable()).await;
                    let gate = gate_result(gate);
                    record(|s| {
                        s.gate = Some(gate);
                        s.resolved_at = Some(Instant::now());
                    });
                }
                b'q' => queued_bytes_come_first(&mut conn).await,
                b'p' => probe_on_a_drained_multishot_connection(&mut conn).await,
                #[cfg(target_os = "linux")]
                b'f' => whole_sends_fill(&mut conn).await,
                #[cfg(target_os = "linux")]
                b'b' => {
                    let ports = (
                        SERVER_PORT.load(Ordering::SeqCst),
                        CLIENT_PORT.load(Ordering::SeqCst),
                    );
                    let before = server_skmem(ports.0, ports.1);
                    let size = conn.send_buffer_size().await;
                    let after = server_skmem(ports.0, ports.1);
                    match (before, size, after) {
                        (Ok(Some(b)), Ok(size), Ok(Some(a))) => {
                            record(|s| s.send_buffer = Some((size, b.1, a.1)))
                        }
                        other => record(|s| s.note = Some(format!("{other:?}"))),
                    }
                }
                _ => {}
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Gate
    }
}

/// Fill the socket, check that the gate waits, then let the client drain
/// and check that it resolves.
async fn full_then_drain(conn: &mut Connection) {
    first_send(conn).await;
    // On macOS, a full socket toward a peer that does not read can report
    // room again about 100 ms later, most often when the peer has
    // half-closed (#1002). The kernel takes the queued bytes, so the fill's
    // last send settles. When the gate resolves early and that send has
    // settled, fill again and look again, up to four fills, on every
    // backend. An early `Ok` with the send unsettled, an error, or a gate
    // that resolves after every fill fails.
    const REFILL_ATTEMPTS: u32 = 4;
    let mut attempts = 0;
    let (early, gate) = loop {
        attempts += 1;
        let (_, _, mut last) = fill_keeping(conn).await;
        let mut gate = Box::pin(conn.writable());
        let early = ringline::timeout(Duration::from_millis(200), gate.as_mut()).await;
        if !matches!(early, Ok(Ok(()))) || attempts == REFILL_ATTEMPTS {
            break (early, gate);
        }
        // The completion reaches the task an iteration after the gate on
        // the mio backend, so one poll is not enough.
        let settled = ringline::timeout(Duration::from_millis(50), &mut last).await;
        if !matches!(settled, Ok(Ok(_))) {
            record(|s| {
                s.note = Some(format!(
                    "the gate resolved with the fill's last send unsettled: {settled:?}"
                ))
            });
            break (early, gate);
        }
    };
    if attempts > 1 {
        eprintln!("full_then_drain: {attempts} fills");
    }
    record(|s| {
        s.pending_while_full = Some(early.is_err());
        s.filled_at = Some(Instant::now());
    });
    FILLED.store(true, Ordering::SeqCst);
    let gate = ringline::timeout(Duration::from_secs(10), gate).await;
    let gate = gate_result(gate);
    record(|s| {
        s.gate = Some(gate);
        s.resolved_at = Some(Instant::now());
    });
}

/// Two 64 KiB sends, then the gate, in one poll: the gate resolves only
/// once both are written and the socket has room.
async fn queued_bytes_come_first(conn: &mut Connection) {
    static PART: [u8; 4 * CHUNK_LEN] = [3; 4 * CHUNK_LEN];
    let mut a = conn.send(&PART).expect("send");
    let mut b = conn.send(&PART).expect("send");
    let gate = ringline::timeout(Duration::from_secs(5), conn.writable()).await;
    let settled_a = settled(&mut a).await;
    let settled_b = settled(&mut b).await;
    record(|s| {
        s.gate = Some(gate_result(gate));
        s.queued_settled = Some((settled_a, settled_b));
    });
}

/// Fill the socket of a peer that has half-closed and reads, wait for the
/// last send to settle and the socket to drain, then wait on the gate. On
/// io_uring the connection's poll is multishot by then and its POLLOUT
/// changes have been reported, so only the probe reports the room.
async fn probe_on_a_drained_multishot_connection(conn: &mut Connection) {
    let (_, _, last) = fill_keeping(conn).await;
    let settled = ringline::timeout(Duration::from_secs(10), last).await;
    if !matches!(settled, Ok(Ok(_))) {
        record(|s| s.note = Some(format!("the fill did not settle: {settled:?}")));
        return;
    }
    ringline::sleep(Duration::from_millis(100)).await;
    let began = Instant::now();
    let gate = ringline::timeout(Duration::from_secs(1), conn.writable()).await;
    let gate = gate_result(gate);
    record(|s| {
        s.gate = Some(gate);
        s.filled_at = Some(began);
        s.resolved_at = Some(Instant::now());
    });
}

/// Linux: with the peer half-closed, fill the socket until a send waits,
/// which leaves the connection's poll multishot; let the client read it all,
/// so the poll reports POLLOUT; then fill it again with whole sends until
/// the kernel's figures say the socket is not writable (`sk_wmem_queued`
/// above two thirds of `sk_sndbuf`), with no send waiting. The gate must
/// wait until the client reads again. If the gate resolves and the socket
/// has become writable meanwhile, as when the autotuner grows `sk_sndbuf`,
/// it fills again and looks again: the second fill and up to three more.
#[cfg(target_os = "linux")]
async fn whole_sends_fill(conn: &mut Connection) {
    static CHUNK: [u8; CHUNK_LEN] = [7; CHUNK_LEN];
    let (capacity, total, last) = fill_keeping(conn).await;
    TOTAL.store(total, Ordering::SeqCst);
    FILLED.store(true, Ordering::SeqCst);
    let settled = ringline::timeout(Duration::from_secs(15), last).await;
    if !matches!(settled, Ok(Ok(_))) {
        record(|s| s.note = Some(format!("the first fill did not settle: {settled:?}")));
        return;
    }
    while !READ_ALL.load(Ordering::SeqCst) {
        ringline::sleep(Duration::from_millis(1)).await;
    }
    // One send at a time, each awaited until it settles, so that the
    // socket fills and the send pool, a few hundred KiB here, does not: a
    // queued copy send holds its pool slots until its bytes are in the
    // socket, and the socket can take several MiB. The kernel's figures
    // decide when to stop: the first fill's size counts the client's
    // receive buffer as well, and `sk_sndbuf` autotunes between the fills.
    let ports = (
        SERVER_PORT.load(Ordering::SeqCst),
        CLIENT_PORT.load(Ordering::SeqCst),
    );
    // The autotuner can grow `sk_sndbuf`, up to tcp_wmem's maximum, while
    // the gate waits, which makes the socket writable again: that says
    // nothing of the gate, so fill again and look again, a few times.
    const REFILL_ATTEMPTS: u32 = 4;
    let limit = 4 * capacity / CHUNK_LEN + 64;
    let mut sends = 0;
    let mut waited = false;
    let mut attempts = 0;
    let (at_gate, at_early, gate, early) = loop {
        attempts += 1;
        let at_gate = loop {
            let mem = match server_skmem(ports.0, ports.1) {
                Ok(Some(mem)) => mem,
                other => {
                    record(|s| {
                        s.note = Some(format!(
                            "no memory figures for the server socket {ports:?}: {other:?}"
                        ))
                    });
                    return;
                }
            };
            if !kernel_writable(mem) {
                break mem;
            }
            if sends == limit {
                record(|s| {
                    s.note = Some(format!(
                        "{sends} whole sends left the socket writable: (wmem_queued, sndbuf) {mem:?}"
                    ))
                });
                return;
            }
            // Each send settles before the next, so the fill holds at most
            // one send's pool slots and fills the socket, not the pool.
            let mut sent = conn.send(&CHUNK).expect("send");
            let done = ringline::timeout(Duration::from_secs(5), &mut sent).await;
            if !matches!(done, Ok(Ok(_))) {
                record(|s| {
                    s.note = Some(format!(
                        "a send of the second fill did not settle: {done:?}"
                    ))
                });
                return;
            }
            waited |= sent.waited_for_room();
            sends += 1;
        };
        eprintln!(
            "whole sends: the first fill held {capacity} B before a send waited; \
             after {sends} sends of {CHUNK_LEN} B in the second (attempt {attempts}), \
             (wmem_queued, sndbuf) {at_gate:?}"
        );
        let mut gate = Box::pin(conn.writable());
        let early = ringline::timeout(Duration::from_millis(300), gate.as_mut()).await;
        if early.is_err() {
            break (at_gate, None, gate, early);
        }
        let at_early = server_skmem(ports.0, ports.1).ok().flatten();
        if at_early.is_some_and(kernel_writable) && attempts < REFILL_ATTEMPTS {
            eprintln!(
                "whole sends: the gate resolved and the socket became writable, \
                 {at_gate:?} -> {at_early:?}: filling again"
            );
            continue;
        }
        break (at_gate, at_early, gate, early);
    };
    record(|s| {
        s.refill_waited = Some(waited);
        s.refill_attempts = Some(attempts);
        s.skmem_at_gate = Some(at_gate);
        s.skmem_at_early = at_early;
        s.pending_while_full = Some(early.is_err());
        s.filled_at = Some(Instant::now());
    });
    REFILLED.store(true, Ordering::SeqCst);
    let gate = if early.is_ok() {
        early
    } else {
        ringline::timeout(Duration::from_secs(10), gate).await
    };
    let gate = gate_result(gate);
    record(|s| {
        s.gate = Some(gate);
        s.resolved_at = Some(Instant::now());
    });
}

fn launch() -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
) {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(SLOTS, SLOT)
        .build()
        .expect("valid config");
    RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Gate>()
        .expect("launch")
}

#[cfg(target_os = "linux")]
fn set_rcvbuf(s: &TcpStream, size: i32) {
    // SAFETY: a live socket, and `size` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&size as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_RCVBUF) failed");
}

/// Close `client` with a reset: `SO_LINGER` with a zero timeout.
fn reset(client: TcpStream) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: a live socket, and `linger` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            client.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_LINGER) failed");
    drop(client);
}

/// A connection to a fresh server that does not read, with the first byte
/// written.
fn start(
    cmd: u8,
) -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
    TcpStream,
) {
    *SEEN.lock().unwrap() = None;
    FILLED.store(false, Ordering::SeqCst);
    READ_ALL.store(false, Ordering::SeqCst);
    REFILLED.store(false, Ordering::SeqCst);
    let (runtime, handles) = launch();
    let addr = runtime.bound_addr().expect("bound");
    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(&[cmd]).unwrap();
    (runtime, handles, client)
}

/// Wait until `done` holds for what the server saw, for at most 15 s.
fn wait_for(what: &str, done: impl Fn(&Seen) -> bool) -> Seen {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        {
            let mut seen = SEEN.lock().unwrap();
            if seen.as_ref().is_some_and(&done) {
                return seen.take().unwrap();
            }
        }
        assert!(Instant::now() < deadline, "the server never {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_filled() {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !FILLED.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline,
            "the server never filled the socket"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Read until the server closes, for at most 15 s.
fn drain(client: &mut TcpStream) {
    client
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let began = Instant::now();
    let mut buf = vec![0u8; 1 << 16];
    let mut read = 0usize;
    let mut first_mib = None;
    loop {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                read += n;
                if read >= 1 << 20 && first_mib.is_none() {
                    first_mib = Some(began.elapsed());
                }
            }
            Err(e) => panic!("drain: {e} after {read} bytes in {:?}", began.elapsed()),
        }
    }
    eprintln!(
        "drain: {read} bytes in {:?}, the first MiB in {first_mib:?}",
        began.elapsed()
    );
}

/// The gate resolved within 5 s of the client starting to drain, well inside
/// the server's 10 s bound. A `timeout` polls its future once more when its
/// bound elapses, so a gate that nothing woke would still resolve `Ok` then.
fn assert_resolved_promptly(seen: &Seen) {
    let took = seen.resolved_at.unwrap() - seen.filled_at.unwrap();
    assert!(
        took < Duration::from_secs(5),
        "resolved {took:?} after the drain began"
    );
}

/// A fresh socket is writable: the gate resolves at once, and a send that
/// went in whole did not wait for room.
#[test]
fn an_empty_socket_is_writable() {
    let _serial = serial();
    let (runtime, handles, _client) = start(b'w');
    let seen = wait_for("sent the first send", |s| s.first_waited.is_some());
    assert_eq!(seen.first_waited, Some(false));
    assert_eq!(seen.gate, Some(Ok(())));
    // Well inside the 1 s bound, whose expiry polls the gate once more.
    let took = seen.resolved_at.unwrap() - seen.filled_at.unwrap();
    assert!(took < Duration::from_millis(500), "resolved after {took:?}");
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// The gate waits while the socket is full and the peer does not read, and
/// resolves once the peer drains it.
#[test]
fn a_full_socket_that_drains() {
    let _serial = serial();
    let (runtime, handles, mut client) = start(b'd');
    wait_filled();
    drain(&mut client);
    let seen = wait_for("resolved the gate", |s| s.gate.is_some());
    assert_eq!(seen.first_waited, Some(false));
    assert_eq!(
        seen.pending_while_full,
        Some(true),
        "it resolved on a full socket: {:?}",
        seen.note
    );
    assert_eq!(seen.gate, Some(Ok(())));
    assert_resolved_promptly(&seen);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// As above with a peer that has half-closed: on io_uring the connection's
/// poll is multishot by the time the gate waits.
#[test]
fn a_half_closed_peer_with_a_full_socket() {
    let _serial = serial();
    let (runtime, handles, mut client) = start(b'd');
    client.shutdown(Shutdown::Write).unwrap();
    wait_filled();
    drain(&mut client);
    let seen = wait_for("resolved the gate", |s| s.gate.is_some());
    assert_eq!(
        seen.pending_while_full,
        Some(true),
        "it resolved on a full socket: {:?}",
        seen.note
    );
    assert_eq!(seen.gate, Some(Ok(())));
    assert_resolved_promptly(&seen);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// A peer that resets while the gate waits fails it with the error the
/// connection recorded: `ConnectionReset` from a receive or the poll, or
/// `BrokenPipe` where a write after the reset recorded `EPIPE` first, as mio's
/// flush does on macOS.
#[test]
fn a_peer_reset_while_waiting() {
    let _serial = serial();
    let (runtime, handles, client) = start(b'r');
    wait_filled();
    std::thread::sleep(Duration::from_millis(100));
    let reset_at = Instant::now();
    reset(client);
    let seen = wait_for("resolved the gate", |s| s.gate.is_some());
    eprintln!("reset: the gate resolved {:?}", seen.gate);
    assert!(
        matches!(
            seen.gate,
            Some(Err(
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ))
        ),
        "{:?}",
        seen.gate
    );
    let took = seen.resolved_at.unwrap() - reset_at;
    assert!(
        took < Duration::from_secs(5),
        "resolved {took:?} after the reset"
    );
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// Not part of the suite: a check, with plain sockets and no ringline, of why
/// the client above leaves its receive buffer to the kernel. A server socket
/// filled to `WouldBlock` towards a client that does not read reports
/// `POLLOUT` within 1 s of the client starting to read when the client keeps
/// the kernel's buffer, and not within 2 s when the client cut its
/// `SO_RCVBUF` to 4096 after the connect. Run on a Linux host with
/// `cargo test -p ringline --test writable_gate loopback_drain -- --ignored --nocapture`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "a check of the kernel for a Linux host; run with --ignored"]
fn loopback_drain_with_a_receive_buffer_shrunk_after_connect() {
    let kernel = time_to_pollout(None);
    let shrunk = time_to_pollout(Some(4096));
    eprintln!(
        "POLLOUT after the client began to read: kernel buffer {kernel:?}, 4096 after the connect {shrunk:?}"
    );
    assert!(
        kernel.is_some_and(|t| t < Duration::from_secs(1)),
        "with the kernel's buffer: {kernel:?}"
    );
    assert!(
        shrunk.is_none_or(|t| t > Duration::from_secs(2)),
        "with 4096 set after the connect: {shrunk:?}"
    );
}

/// Fill a loopback server socket to `WouldBlock` towards a client that does
/// not read, with the client's `SO_RCVBUF` set to `rcvbuf` after the connect;
/// wait 200 ms and fill it again, as the tests above do; then let the client
/// read, and return how long the server's socket took to report `POLLOUT`,
/// or `None` if it did not within 10 s.
#[cfg(target_os = "linux")]
fn time_to_pollout(rcvbuf: Option<i32>) -> Option<Duration> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server.set_nodelay(true).unwrap();
    if let Some(size) = rcvbuf {
        set_rcvbuf(&client, size);
    }
    server.set_nonblocking(true).unwrap();
    let chunk = [7u8; CHUNK_LEN];
    let fill = |server: &mut TcpStream| loop {
        match server.write(&chunk) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("fill: {e}"),
        }
    };
    fill(&mut server);
    std::thread::sleep(Duration::from_millis(200));
    fill(&mut server);
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let reader = {
        let stop = stop.clone();
        let mut client = client;
        std::thread::spawn(move || {
            client
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut buf = vec![0u8; 1 << 16];
            while !stop.load(Ordering::SeqCst) {
                match client.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => break,
                }
            }
        })
    };
    let began = Instant::now();
    let mut pfd = libc::pollfd {
        fd: server.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: one valid `pollfd` for the call.
    let n = unsafe { libc::poll(&mut pfd, 1, 10_000) };
    let took = (n > 0 && pfd.revents & libc::POLLOUT != 0).then(|| began.elapsed());
    stop.store(true, Ordering::SeqCst);
    reader.join().unwrap();
    took
}

/// Two sends made just before the gate, in the same poll, are written
/// before it resolves.
#[test]
fn sends_queued_before_the_gate_are_written_first() {
    let _serial = serial();
    let (runtime, handles, _client) = start(b'q');
    let seen = wait_for("resolved the gate", |s| s.gate.is_some());
    assert_eq!(seen.gate, Some(Ok(())));
    assert_eq!(
        seen.queued_settled,
        Some((true, true)),
        "the gate resolved before the sends"
    );
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// After the peer half-closes and the socket drains, the gate resolves at
/// once: on io_uring the multishot poll reports no change, and the probe
/// reports the room.
#[test]
fn a_drained_socket_after_a_half_close_is_writable() {
    let _serial = serial();
    let (runtime, handles, mut client) = start(b'p');
    client.shutdown(Shutdown::Write).unwrap();
    // Read at about 32 MiB/s, slower than the server fills, until the end.
    let reader = std::thread::spawn(move || {
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let mut buf = vec![0u8; 1 << 16];
        while let Ok(n) = client.read(&mut buf) {
            if n == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    let seen = wait_for("resolved the gate", |s| {
        s.gate.is_some() || s.note.is_some()
    });
    assert_eq!(seen.note, None);
    assert_eq!(seen.gate, Some(Ok(())));
    let took = seen.resolved_at.unwrap() - seen.filled_at.unwrap();
    assert!(took < Duration::from_millis(200), "resolved after {took:?}");
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    reader.join().unwrap();
}

/// Linux: a socket refilled by whole sends, with no send waiting and the
/// connection's poll multishot after a POLLOUT, is not writable until the
/// peer reads again. A gate that resolved on the poll's earlier POLLOUT
/// would let a piece into the full socket.
#[cfg(target_os = "linux")]
#[test]
fn a_socket_filled_by_whole_sends_is_not_writable() {
    let _serial = serial();
    *SEEN.lock().unwrap() = None;
    FILLED.store(false, Ordering::SeqCst);
    READ_ALL.store(false, Ordering::SeqCst);
    REFILLED.store(false, Ordering::SeqCst);
    let (runtime, handles) = launch();
    let addr = runtime.bound_addr().expect("bound");
    // Set before the connect, so the window and the server's MSS agree.
    let mut client = connect_with_rcvbuf(addr, 256 << 10);
    SERVER_PORT.store(addr.port(), Ordering::SeqCst);
    CLIENT_PORT.store(client.local_addr().unwrap().port(), Ordering::SeqCst);
    client.write_all(b"f").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    wait_filled();
    client
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut left = TOTAL.load(Ordering::SeqCst);
    let mut buf = vec![0u8; 1 << 16];
    while left > 0 {
        let n = client
            .read(&mut buf[..left.min(1 << 16)])
            .expect("read the first fill");
        assert!(n > 0, "the server closed early");
        left -= n;
    }
    READ_ALL.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !REFILLED.load(Ordering::SeqCst) {
        if SEEN
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|s| s.note.is_some())
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the server never refilled the socket"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    drain(&mut client);
    let seen = wait_for("resolved the gate", |s| {
        s.gate.is_some() || s.note.is_some()
    });
    assert_eq!(seen.note, None);
    assert_eq!(
        seen.refill_waited,
        Some(false),
        "precondition: a send of the second fill waited for room"
    );
    let at_gate = seen.skmem_at_gate.expect("recorded with the refill");
    assert!(
        !kernel_writable(at_gate),
        "precondition: the socket was writable when the gate started"
    );
    if seen.pending_while_full != Some(true) {
        let attempts = seen.refill_attempts.unwrap_or(0);
        let verdict = match seen.skmem_at_early {
            Some(mem) if kernel_writable(mem) => format!(
                "the kernel reported it writable by then, as in each of {attempts} refills: \
                 inconclusive, the socket changed, not the gate"
            ),
            Some(_) => {
                "the kernel still reported it not writable: the gate resolved on a full socket"
                    .to_string()
            }
            None => "its figures could not be read then".to_string(),
        };
        panic!(
            "the gate resolved within 300 ms of starting on a socket the kernel reported \
             not writable, (wmem_queued, sndbuf) {at_gate:?}; when it resolved, {:?}: {verdict}",
            seen.skmem_at_early
        );
    }
    assert_eq!(seen.gate, Some(Ok(())));
    assert_resolved_promptly(&seen);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// `send_buffer_size` reads the socket's `sk_sndbuf`, as the kernel reports
/// it through netlink just before or just after.
#[cfg(target_os = "linux")]
#[test]
fn send_buffer_size_is_the_kernel_s_sndbuf() {
    let _serial = serial();
    *SEEN.lock().unwrap() = None;
    let (runtime, handles) = launch();
    let addr = runtime.bound_addr().expect("bound");
    let mut client = TcpStream::connect(addr).expect("connect");
    SERVER_PORT.store(addr.port(), Ordering::SeqCst);
    CLIENT_PORT.store(client.local_addr().unwrap().port(), Ordering::SeqCst);
    client.write_all(b"b").unwrap();
    let seen = wait_for("read the send buffer", |s| {
        s.send_buffer.is_some() || s.note.is_some()
    });
    assert_eq!(seen.note, None);
    let (size, before, after) = seen.send_buffer.expect("recorded");
    assert!(
        size == before as usize || size == after as usize,
        "send_buffer_size {size}, sk_sndbuf {before} before and {after} after"
    );
    drop(client);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// Whether the kernel reports `POLLOUT` for a TCP socket with
/// (`sk_wmem_queued`, `sk_sndbuf`) `mem`: `__sk_stream_is_writeable`, free
/// space at least half of what is queued (`tcp_notsent_lowat` at its
/// default, which never binds).
#[cfg(target_os = "linux")]
fn kernel_writable((queued, sndbuf): (u32, u32)) -> bool {
    i64::from(sndbuf) - i64::from(queued) >= i64::from(queued >> 1)
}

/// The (`sk_wmem_queued`, `sk_sndbuf`) of the IPv4 TCP socket from local
/// port `local` to remote port `remote`, read as `ss -tmi` reads them: an
/// `inet_diag` dump over `NETLINK_SOCK_DIAG` with `INET_DIAG_SKMEMINFO`. On
/// io_uring the runtime's sockets are fixed files, with no fd to read
/// `SO_MEMINFO` from. `None` if there is no such socket.
#[cfg(target_os = "linux")]
fn server_skmem(local: u16, remote: u16) -> io::Result<Option<(u32, u32)>> {
    use std::os::fd::{FromRawFd, OwnedFd};
    const AF_NETLINK: i32 = 16;
    const SOCK_CLOEXEC: i32 = 0o2000000;
    const NETLINK_SOCK_DIAG: i32 = 4;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const INET_DIAG_SKMEMINFO: u16 = 7;
    const SK_MEMINFO_SNDBUF: usize = 3;
    const SK_MEMINFO_WMEM_QUEUED: usize = 5;
    /// The size of `struct nlmsghdr`.
    const NLMSG_HDRLEN: usize = 16;
    /// The size of `struct inet_diag_req_v2`.
    const REQ_LEN: usize = 56;
    /// The size of `struct inet_diag_msg`.
    const DIAG_MSG_LEN: usize = 72;
    /// `struct sockaddr_nl`.
    #[repr(C)]
    struct SockaddrNl {
        family: u16,
        pad: u16,
        pid: u32,
        groups: u32,
    }
    fn word(b: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
    }
    fn half(b: &[u8], at: usize) -> u16 {
        u16::from_ne_bytes(b[at..at + 2].try_into().unwrap())
    }

    // SAFETY: socket(2) takes no pointers.
    let fd = unsafe {
        libc::socket(
            AF_NETLINK,
            libc::SOCK_DGRAM | SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a socket this function owns; dropping it closes it.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // nlmsghdr, then inet_diag_req_v2: family, protocol, the extensions
    // wanted, a pad byte, the states (all), and a zero inet_diag_sockid (48
    // bytes), which a dump does not use.
    let mut req = Vec::with_capacity(NLMSG_HDRLEN + REQ_LEN);
    req.extend_from_slice(&((NLMSG_HDRLEN + REQ_LEN) as u32).to_ne_bytes());
    req.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req.extend_from_slice(&1u32.to_ne_bytes());
    req.extend_from_slice(&0u32.to_ne_bytes());
    req.extend_from_slice(&[
        libc::AF_INET as u8,
        libc::IPPROTO_TCP as u8,
        1 << (INET_DIAG_SKMEMINFO - 1),
        0,
    ]);
    req.extend_from_slice(&u32::MAX.to_ne_bytes());
    req.extend_from_slice(&[0u8; 48]);
    assert_eq!(req.len(), NLMSG_HDRLEN + REQ_LEN);
    let kernel = SockaddrNl {
        family: AF_NETLINK as u16,
        pad: 0,
        pid: 0,
        groups: 0,
    };
    // SAFETY: `req` and `kernel` are live for the call, with their lengths.
    let sent = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            req.as_ptr().cast(),
            req.len(),
            0,
            (&kernel as *const SockaddrNl).cast(),
            std::mem::size_of::<SockaddrNl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; 1 << 16];
    let mut found = None;
    loop {
        // SAFETY: `buf` is live and writable for its length.
        let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        let mut at = 0;
        while at + NLMSG_HDRLEN <= n {
            let len = word(&buf, at) as usize;
            if len < NLMSG_HDRLEN || at + len > n {
                return Err(io::Error::other("a truncated netlink message"));
            }
            match half(&buf, at + 4) {
                NLMSG_DONE => return Ok(found),
                NLMSG_ERROR => {
                    let errno = word(&buf, at + NLMSG_HDRLEN) as i32;
                    return Err(io::Error::from_raw_os_error(-errno));
                }
                SOCK_DIAG_BY_FAMILY if len >= NLMSG_HDRLEN + DIAG_MSG_LEN => {
                    let msg = &buf[at + NLMSG_HDRLEN..at + len];
                    // inet_diag_msg: family, state, timer, retrans, then the
                    // sockid, whose ports are in network order.
                    let sport = u16::from_be_bytes([msg[4], msg[5]]);
                    let dport = u16::from_be_bytes([msg[6], msg[7]]);
                    if sport == local && dport == remote {
                        let mut a = DIAG_MSG_LEN;
                        while a + 4 <= msg.len() {
                            let alen = half(msg, a) as usize;
                            if alen < 4 || a + alen > msg.len() {
                                break;
                            }
                            if half(msg, a + 2) == INET_DIAG_SKMEMINFO
                                && alen >= 4 + 4 * (SK_MEMINFO_WMEM_QUEUED + 1)
                            {
                                found = Some((
                                    word(msg, a + 4 + 4 * SK_MEMINFO_WMEM_QUEUED),
                                    word(msg, a + 4 + 4 * SK_MEMINFO_SNDBUF),
                                ));
                            }
                            a += (alen + 3) & !3;
                        }
                    }
                }
                _ => {}
            }
            at += (len + 3) & !3;
        }
    }
}

/// Connect to `addr` with `SO_RCVBUF` set to `size` before the connect.
#[cfg(target_os = "linux")]
fn connect_with_rcvbuf(addr: std::net::SocketAddr, size: i32) -> TcpStream {
    use std::os::fd::FromRawFd;
    let std::net::SocketAddr::V4(v4) = addr else {
        panic!("the test binds IPv4 loopback");
    };
    // SAFETY: socket(2) takes no pointers.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
    // SAFETY: `fd` is a socket this function owns; the stream closes it.
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    set_rcvbuf(&stream, size);
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: v4.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(v4.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `sin` is a valid IPv4 address and outlives the call.
    let rc = unsafe {
        libc::connect(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "connect: {}", io::Error::last_os_error());
    stream
}
