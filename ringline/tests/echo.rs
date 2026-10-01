#![allow(clippy::manual_async_fn)]
//! Integration tests: echo server using real TCP connections.
//!
//! Each test launches a ringline server, connects via std TCP, sends data,
//! and verifies the echoed response.

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::time::Duration;

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder,
};
use std::sync::atomic::{AtomicU32, Ordering};

// ── Async echo handler ─────────────────────────────────────────────

struct AsyncEcho;

impl AsyncEventHandler for AsyncEcho {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
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
        AsyncEcho
    }
}

// ── Burst sender (exercises the coalesced send path) ───────────────

const BURST_N: u32 = 100;
const BURST_MSG: usize = 64;

/// On accept, fires `BURST_N` distinct small messages back-to-back without
/// awaiting between them, so they queue on the connection and drain through the
/// coalesced `sendmsg` path. Message `i` is `BURST_MSG` bytes all set to
/// `(i % 251)`, so the client can verify order and detect any reordering or
/// truncation.
struct BurstSender;

impl AsyncEventHandler for BurstSender {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            for i in 0..BURST_N {
                let msg = [(i % 251) as u8; BURST_MSG];
                // Retry only if the copy pool is transiently exhausted.
                while conn.send_nowait(&msg).is_err() {
                    ringline::sleep(Duration::from_micros(50)).await;
                }
            }
            // Keep the connection open until the client finishes reading.
            loop {
                let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        BurstSender
    }
}

// ── Split-halves echo handler ──────────────────────

/// Echoes through `ConnCtx::split()`.
///
/// The send happens *inside* the `with_data` closure, while the read side is
/// mutably borrowed by the in-flight recv future. That is the whole point of
/// the split: a `SendHalf` that borrowed the `RecvHalf` would not compile here,
/// and an echo is the most ordinary thing a connection does.
struct SplitEcho;

impl AsyncEventHandler for SplitEcho {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
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
        SplitEcho
    }
}

// ── Zero-copy recv-forward echo handler ────────────────────────────

/// Echo via the multi-buffer zero-copy recv-forward path: held provided recv
/// buffers are scatter-gathered back in one `sendmsg`, no accumulator copy.
struct RecvForwardEcho;

impl AsyncEventHandler for RecvForwardEcho {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.enable_recv_forward();
            loop {
                conn.recv_ready().await;
                let n = match conn.forward_held() {
                    Ok(f) => f.await.unwrap_or(0),
                    Err(_) => break,
                };
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        RecvForwardEcho
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn test_config_builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(64, 4096)
        .max_connections(64)
        .send_pool(64, 16384)
}

fn test_config() -> Config {
    test_config_builder().build().expect("valid config")
}

/// A loopback TCP port that refuses connections, and the socket that holds it.
/// The socket is bound and never listens, so a connect to the port fails with
/// `ConnectionRefused`. No other socket can bind the port until the returned
/// fd is dropped.
fn refusing_port() -> (std::os::fd::OwnedFd, u16) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(raw >= 0, "socket: {}", io::Error::last_os_error());
    // SAFETY: `raw` is a socket created above and owned by nothing else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    }
    let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sin as *const _ as *const libc::sockaddr,
            len,
        )
    };
    assert_eq!(rc, 0, "bind: {}", io::Error::last_os_error());

    let mut bound: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut blen = len;
    let rc = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut blen,
        )
    };
    assert_eq!(rc, 0, "getsockname: {}", io::Error::last_os_error());
    (fd, u16::from_be(bound.sin_port))
}

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

/// Wait for the server *and* hand back the connection that proved it was up.
///
/// [`wait_for_server`] proves readiness by connecting and discarding the
/// stream, and the server accepts that probe like any other client: it becomes
/// a connection whose peer has already closed before its handler runs. For the
/// reactive tests that is harmless — the probe sends nothing, so an echo
/// handler never sends and simply parks until teardown. For a handler that
/// sends *unprompted* on accept it is not harmless, and it is the whole of
/// #518: the probe was connection 0, its handler pushed 4 KiB chunks at a
/// closed peer, the FIN-driven close was finalized between two of them, and
/// the parked send resolved `NotConnected("connection closing")` — which the
/// handler turned into a panic. The test's own readiness check supplied the
/// failure it then reported as data loss.
///
/// Every connection this returns has a live peer, so use it instead of
/// `wait_for_server` + `TcpStream::connect` whenever the handler sends first.
fn connect_retry(addr: &str) -> TcpStream {
    for _ in 0..200 {
        if let Ok(stream) = TcpStream::connect(addr) {
            return stream;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

fn echo_round_trip(addr: &str, msg: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(msg).unwrap();
    stream.flush().unwrap();

    let mut buf = vec![0u8; msg.len()];
    let mut total = 0;
    while total < msg.len() {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }
    buf.truncate(total);
    buf
}

// ── Tests ───────────────────────────────────────────────────────────

#[test]
fn coalesced_sends_preserve_order() {
    // Many small sends queued on one connection drain through the coalesced
    // sendmsg path; verify they arrive in order, byte-for-byte, none dropped.
    let config = test_config_builder()
        .send_pool(512, 16384)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<BurstSender>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let total = BURST_N as usize * BURST_MSG;
    let mut buf = vec![0u8; total];
    let mut read = 0;
    while read < total {
        match stream.read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }
    assert_eq!(read, total, "received {read} of {total} bytes");
    for i in 0..BURST_N {
        let off = i as usize * BURST_MSG;
        let expected = (i % 251) as u8;
        for (j, &b) in buf[off..off + BURST_MSG].iter().enumerate() {
            assert_eq!(
                b, expected,
                "message {i} byte {j}: got {b}, expected {expected} (reordering or corruption)"
            );
        }
    }

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn recv_forward_echo_preserves_order_across_buffers() {
    // Drive the zero-copy recv-forward path with many distinct messages, each
    // larger than one provided recv buffer (so a message spans buffers and
    // multiple buffers are held), and verify the echo is byte-for-byte in order.
    let config = test_config_builder()
        .recv_buffer(256, 4096)
        .sq_entries(256)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<RecvForwardEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    const N: usize = 20;
    const MSG: usize = 16384;
    let mut payload = Vec::with_capacity(N * MSG);
    for i in 0..N {
        payload.extend(std::iter::repeat_n((i % 251) as u8, MSG));
    }
    stream.write_all(&payload).unwrap();
    stream.flush().unwrap();

    let total = N * MSG;
    let mut buf = vec![0u8; total];
    let mut read = 0;
    while read < total {
        match stream.read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }
    assert_eq!(read, total, "received {read} of {total} bytes");
    assert!(
        buf == payload,
        "echoed bytes differ (reordering or corruption)"
    );

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn runtime_reports_bound_addr() {
    // Bind to :0 so the kernel picks a port, and verify Runtime
    // surfaces the resolved address (not the wildcard the user passed in).
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

    let bound = shutdown
        .bound_addr()
        .expect("bound_addr should be Some after a TCP bind");
    assert_eq!(bound.ip().to_string(), "127.0.0.1");
    assert_ne!(bound.port(), 0, "kernel-assigned port must be non-zero");

    // Sanity: the reported port actually accepts connections.
    wait_for_server(&bound.to_string());

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn echo_small_message() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let msg = b"Hello, ringline!";
    let response = echo_round_trip(&addr, msg);
    assert_eq!(response, msg);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn echo_large_message() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // 8KB message — larger than typical TCP segment
    let msg: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    let response = echo_round_trip(&addr, &msg);
    assert_eq!(response, msg);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn echo_multiple_connections() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut join_handles = Vec::new();
    for i in 0..4 {
        let addr = addr.clone();
        join_handles.push(std::thread::spawn(move || {
            let msg = format!("connection {i}");
            let response = echo_round_trip(&addr, msg.as_bytes());
            assert_eq!(response, msg.as_bytes());
        }));
    }
    for h in join_handles {
        h.join().unwrap();
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn echo_sequential_sends() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    for i in 0..10 {
        let msg = format!("msg-{i}\n");
        stream.write_all(msg.as_bytes()).unwrap();
        stream.flush().unwrap();

        let mut buf = vec![0u8; msg.len()];
        let mut total = 0;
        while total < msg.len() {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("read error: {e}"),
            }
        }
        assert_eq!(&buf[..total], msg.as_bytes(), "mismatch on send {i}");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn async_echo_small_message() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let msg = b"Hello, async ringline!";
    let response = echo_round_trip(&addr, msg);
    assert_eq!(response, msg);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn async_echo_large_message() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let msg: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    let response = echo_round_trip(&addr, &msg);
    assert_eq!(response, msg);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn async_echo_multiple_connections() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut join_handles = Vec::new();
    for i in 0..4 {
        let addr = addr.clone();
        join_handles.push(std::thread::spawn(move || {
            let msg = format!("async conn {i}");
            let response = echo_round_trip(&addr, msg.as_bytes());
            assert_eq!(response, msg.as_bytes());
        }));
    }
    for h in join_handles {
        h.join().unwrap();
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn connection_close_on_client_disconnect() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Open and immediately close 10 connections.
    for _ in 0..10 {
        let stream = TcpStream::connect(&addr).unwrap();
        drop(stream);
    }

    // Give the server time to process the closes.
    std::thread::sleep(Duration::from_millis(200));

    // Verify the server is still alive by connecting again.
    let msg = b"still alive";
    let response = echo_round_trip(&addr, msg);
    assert_eq!(response, msg);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn graceful_shutdown() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Open a connection, send data, verify echo.
    let msg = b"pre-shutdown";
    let response = echo_round_trip(&addr, msg);
    assert_eq!(response, msg);

    // Trigger shutdown.
    shutdown.shutdown();

    // Workers should exit cleanly.
    for h in handles {
        let result = h.join().expect("worker panicked");
        result.expect("worker returned error");
    }
}

// ── Shutdown-write test ─────────────────────────────────────────────

/// Handler that echoes back data then half-closes the write side.
struct ShutdownWriteEcho;

impl AsyncEventHandler for ShutdownWriteEcho {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            let n = rx
                .with_data(|data| {
                    let _ = tx.send_nowait(data);
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n > 0 {
                tx.shutdown_write();
            }
            // Keep the task alive to receive more (should get EOF).
            let _ = rx.with_data(|_data| ParseResult::Consumed(0)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ShutdownWriteEcho
    }
}

#[test]
fn async_shutdown_write_triggers_eof() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ShutdownWriteEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Send data.
    let msg = b"shutdown test";
    stream.write_all(msg).unwrap();
    stream.flush().unwrap();

    // Read the echo.
    let mut buf = vec![0u8; msg.len()];
    let mut total = 0;
    while total < msg.len() {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }
    assert_eq!(&buf[..total], msg);

    // After echo, server does shutdown_write — we should get EOF.
    let mut extra = [0u8; 1];
    match stream.read(&mut extra) {
        Ok(0) => {} // EOF — correct!
        Ok(_) => panic!("expected EOF after shutdown_write"),
        Err(e) => panic!("unexpected error: {e}"),
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Request-shutdown test ───────────────────────────────────────────

/// Handler that shuts down the worker after receiving any data.
struct RequestShutdownHandler;

impl AsyncEventHandler for RequestShutdownHandler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            rx.with_data(|data| {
                // Echo back, then request shutdown.
                let _ = tx.send_nowait(data);
                tx.request_shutdown();
                ParseResult::Consumed(data.len())
            })
            .await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        RequestShutdownHandler
    }
}

#[test]
fn async_request_shutdown_exits_cleanly() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<RequestShutdownHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Send a message — the handler will request shutdown after echoing.
    // The response may arrive or the connection may reset (race between
    // the queued send and shutdown closing the socket), so tolerate both.
    {
        let mut stream = TcpStream::connect(&addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = stream.write_all(b"trigger-shutdown");
        let _ = stream.flush();
        let mut buf = [0u8; 64];
        let _ = stream.read(&mut buf);
    }

    // Workers should exit on their own (request_shutdown triggers it).
    for h in handles {
        let result = h.join().expect("worker panicked");
        result.expect("worker returned error");
    }

    // The workers have exited; dropping `shutdown` calls `shutdown()` again,
    // which is a no-op.
    drop(shutdown);
}

// ── Spawn standalone task test ──────────────────────────────────────

static SPAWN_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Handler that spawns a standalone task from on_accept.
struct SpawnTestHandler;

impl AsyncEventHandler for SpawnTestHandler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            // Spawn a standalone task that increments the counter.
            ringline::spawn(async {
                SPAWN_COUNTER.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();

            // Echo one message to signal readiness.
            rx.with_data(|data| {
                let _ = tx.send_nowait(data);
                ParseResult::Consumed(data.len())
            })
            .await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SpawnTestHandler
    }
}

#[test]
fn async_spawn_standalone_task() {
    // Reset counter.
    SPAWN_COUNTER.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SpawnTestHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Connect 3 times — each accept spawns a standalone task.
    for _ in 0..3 {
        echo_round_trip(&addr, b"spawn-test");
    }

    // Give standalone tasks time to run.
    std::thread::sleep(Duration::from_millis(100));

    // Verify the standalone tasks ran.
    let count = SPAWN_COUNTER.load(Ordering::SeqCst);
    assert!(count >= 3, "expected at least 3, got {count}");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Sleep test ──────────────────────────────────────────────────────

/// Handler that sleeps before echoing back.
struct SleepEchoHandler;

impl AsyncEventHandler for SleepEchoHandler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();

            // Several producers feeding one connection is an explicit queue
            // drained by the task that owns the write half — the documented
            // alternative to a shared send handle, and now the only one: the
            // send half is not `Clone`, and `ConnCtx` no longer carries the
            // capability. See `docs/connection-handle-ownership-design.md`.
            let (outbox, drain) = ringline::mpsc::channel::<Vec<u8>>(8);
            ringline::spawn(async move {
                while let Some(msg) = drain.recv().await {
                    let _ = tx.send_nowait(&msg);
                }
            })
            .unwrap();

            loop {
                let n = rx
                    .with_data(|data| {
                        let len = data.len();
                        // Sleep 50ms then echo.
                        let data_copy = data.to_vec();
                        let producer = outbox.clone();
                        ringline::spawn(async move {
                            ringline::sleep(Duration::from_millis(50)).await;
                            let _ = producer.send(data_copy).await;
                        })
                        .unwrap();
                        ParseResult::Consumed(len)
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SleepEchoHandler
    }
}

#[test]
fn async_sleep_completes() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SleepEchoHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let start = std::time::Instant::now();
    let response = echo_round_trip(&addr, b"hello sleep");
    let elapsed = start.elapsed();

    assert_eq!(response, b"hello sleep");
    // Should take at least ~50ms due to sleep.
    assert!(
        elapsed >= Duration::from_millis(30),
        "elapsed only {elapsed:?}, expected at least 30ms"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Timeout test ────────────────────────────────────────────────────

/// Handler that tests timeout — a fast operation should succeed,
/// then the handler echoes a response indicating success.
struct TimeoutTestHandler;

impl AsyncEventHandler for TimeoutTestHandler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();

            // Same fan-in shape as `SleepEchoHandler`: the spawned tasks are
            // producers, and the half stays with the one task that drains.
            let (outbox, drain) = ringline::mpsc::channel::<&'static [u8]>(4);
            ringline::spawn(async move {
                while let Some(msg) = drain.recv().await {
                    let _ = tx.send_nowait(msg);
                }
            })
            .unwrap();

            rx.with_data(|data| -> ParseResult {
                let msg = std::str::from_utf8(data).unwrap_or("");
                if msg == "test-timeout-ok" {
                    // Timeout wrapping an immediate future should succeed.
                    let producer = outbox.clone();
                    ringline::spawn(async move {
                        let result =
                            ringline::timeout(Duration::from_secs(10), async { 42u32 }).await;
                        match result {
                            Ok(42) => {
                                let _ = producer.send(b"OK").await;
                            }
                            _ => {
                                let _ = producer.send(b"FAIL").await;
                            }
                        }
                    })
                    .unwrap();
                } else if msg == "test-timeout-expire" {
                    // Timeout wrapping a long sleep should expire.
                    let producer = outbox.clone();
                    ringline::spawn(async move {
                        let result = ringline::timeout(
                            Duration::from_millis(20),
                            ringline::sleep(Duration::from_secs(10)),
                        )
                        .await;
                        match result {
                            Err(_elapsed) => {
                                let _ = producer.send(b"ELAPSED").await;
                            }
                            Ok(()) => {
                                let _ = producer.send(b"FAIL").await;
                            }
                        }
                    })
                    .unwrap();
                }
                ParseResult::Consumed(data.len())
            })
            .await;
            // Keep the task alive so the spawned tasks can send.
            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        TimeoutTestHandler
    }
}

#[test]
fn async_timeout_ok() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TimeoutTestHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Test: timeout wrapping an immediate future should return Ok.
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"test-timeout-ok").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 16];
    let mut total = 0;
    while total < 2 {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("read error: {e}"),
        }
    }
    assert_eq!(&buf[..total], b"OK");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn async_timeout_expires() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TimeoutTestHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Test: timeout wrapping a long sleep should return Err(Elapsed).
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"test-timeout-expire").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 16];
    let mut total = 0;
    while total < 7 {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("read error: {e}"),
        }
    }
    assert_eq!(&buf[..total], b"ELAPSED");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Cross-connection I/O tests ──────────────────────────────────────

/// Forwarder handler: on accept, connects to a backend, forwards data
/// through it (echo), and sends the response back to the client.
/// This exercises the owner_task wakeup chain: client task at index N
/// owns backend connection at index M, and with_data/send on the backend
/// connection must correctly wake the client task.
struct ForwarderHandler {
    backend_addr: SocketAddr,
}

use std::net::SocketAddr;

static FORWARDER_BACKEND_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for ForwarderHandler {
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        let backend_addr = self.backend_addr;
        async move {
            // Connect to the backend echo server.
            let backend = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    let _ = client.send_nowait(format!("-ERR connect: {e}\r\n").as_bytes());
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            let (mut backend_tx, mut backend_rx) = backend.split();

            // Forward loop: read from client, send to backend, read echo, send back.
            loop {
                let mut data_copy = Vec::new();
                let n = client
                    .with_data(|data| {
                        data_copy = data.to_vec();
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    break;
                }

                // Forward to backend.
                if backend_tx.send_nowait(&data_copy).is_err() {
                    break;
                }

                // Read echo from backend.
                let mut echo = Vec::new();
                let target_len = data_copy.len();
                while echo.len() < target_len {
                    let remaining = target_len - echo.len();
                    let got = backend_rx
                        .with_data(|data| {
                            let take = data.len().min(remaining);
                            echo.extend_from_slice(&data[..take]);
                            ParseResult::Consumed(take)
                        })
                        .await;
                    if got == 0 {
                        break;
                    }
                }

                // Send back to client.
                if client.send_nowait(&echo).is_err() {
                    break;
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        let addr = *FORWARDER_BACKEND_ADDR.get().expect("backend addr not set");
        ForwarderHandler { backend_addr: addr }
    }
}

#[test]
fn async_outbound_connect_and_echo() {
    // 1. Start a backend echo server.

    let (backend_shutdown, backend_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    let backend_addr = backend_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();

    wait_for_server(&backend_addr);

    // 2. Start the forwarder server.
    FORWARDER_BACKEND_ADDR
        .set(backend_addr.parse().unwrap())
        .ok();

    let (fwd_shutdown, fwd_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ForwarderHandler>()
        .expect("forwarder launch failed");
    let forwarder_addr = fwd_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();

    wait_for_server(&forwarder_addr);

    // 3. Connect to the forwarder, send data, verify echo.
    let msg = b"cross-connection echo test!";
    let response = echo_round_trip(&forwarder_addr, msg);
    assert_eq!(response, msg, "forwarder did not echo correctly");

    // Larger message.
    let large_msg: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let response = echo_round_trip(&forwarder_addr, &large_msg);
    assert_eq!(response, large_msg, "forwarder did not echo large message");

    fwd_shutdown.shutdown();
    for h in fwd_handles {
        h.join().unwrap().unwrap();
    }

    backend_shutdown.shutdown();
    for h in backend_handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that tries to connect to a non-listening address.
struct ConnectRefusedHandler;

static CONNECT_REFUSED_PORT: AtomicU32 = AtomicU32::new(0);

impl AsyncEventHandler for ConnectRefusedHandler {
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Wait for trigger byte from client before connecting.
            client
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;

            let port = CONNECT_REFUSED_PORT.load(Ordering::SeqCst);
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

            let result = match ringline::connect(addr).await {
                Ok(_) => "CONNECTED".to_string(),
                Err(e) => format!("ERR:{}", e.kind()),
            };

            let _ = client.send_nowait(result.as_bytes());
            // Keep connection alive so the send completes.
            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ConnectRefusedHandler
    }
}

#[test]
fn async_outbound_connect_refused() {
    // A port held by a socket that never listens, so a connect is refused and
    // nothing else can take the port while the test runs.
    let (_dead_guard, dead_port) = refusing_port();

    CONNECT_REFUSED_PORT.store(dead_port as u32, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ConnectRefusedHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // Trigger the handler.
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 128];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                // Check if we have a complete response.
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s.starts_with("ERR:")
                    || s.starts_with("CONNECTED")
                    || s.starts_with("SUBMIT_ERR:")
                {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let response = std::str::from_utf8(&buf[..total]).unwrap();
    assert!(
        response.starts_with("ERR:"),
        "expected connect error, got: {response}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that opens multiple outbound connections from a single task.
struct MultiOutboundHandler;

static MULTI_OUTBOUND_BACKEND_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for MultiOutboundHandler {
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        let backend_addr = *MULTI_OUTBOUND_BACKEND_ADDR
            .get()
            .expect("backend addr not set");
        async move {
            // Open two backend connections from the same client task.
            let backend1 = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR1:{e}").as_bytes());
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            let (mut backend1_tx, mut backend1_rx) = backend1.split();

            let backend2 = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR2:{e}").as_bytes());
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            let (mut backend2_tx, mut backend2_rx) = backend2.split();

            // Send "AA" through backend1, "BB" through backend2.
            if backend1_tx.send_nowait(b"AA").is_err() {
                let _ = client.send_nowait(b"SEND_ERR1");
                return;
            }
            let mut echo1 = Vec::new();
            while echo1.len() < 2 {
                let remaining = 2 - echo1.len();
                let got = backend1_rx
                    .with_data(|data| {
                        let take = data.len().min(remaining);
                        echo1.extend_from_slice(&data[..take]);
                        ParseResult::Consumed(take)
                    })
                    .await;
                if got == 0 {
                    break;
                }
            }

            if backend2_tx.send_nowait(b"BB").is_err() {
                let _ = client.send_nowait(b"SEND_ERR2");
                return;
            }
            let mut echo2 = Vec::new();
            while echo2.len() < 2 {
                let remaining = 2 - echo2.len();
                let got = backend2_rx
                    .with_data(|data| {
                        let take = data.len().min(remaining);
                        echo2.extend_from_slice(&data[..take]);
                        ParseResult::Consumed(take)
                    })
                    .await;
                if got == 0 {
                    break;
                }
            }

            // Combine and send back.
            let mut result = echo1;
            result.extend_from_slice(&echo2);
            let _ = client.send_nowait(&result);
            // Keep connection alive so the send completes.
            ringline::sleep(Duration::from_secs(5)).await;
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        MultiOutboundHandler
    }
}

#[test]
fn async_multiple_outbound_from_one_task() {
    // Start backend echo server.

    let (backend_shutdown, backend_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    let backend_addr = backend_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();

    wait_for_server(&backend_addr);

    MULTI_OUTBOUND_BACKEND_ADDR
        .set(backend_addr.parse().unwrap())
        .ok();

    // Start the multi-outbound server.

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<MultiOutboundHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Connect and trigger the handler.
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // The handler fires on accept; we just need to read the result.
    // But the handler awaits with_data from client first — send a trigger byte.
    // Actually, looking at the handler, it connects on accept, no trigger needed.
    // But it does need to use with_data — wait, no it doesn't. Let me re-check...
    // The handler connects immediately on accept and doesn't read from client first.

    let mut buf = [0u8; 64];
    let mut total = 0;
    while total < 4 {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert_eq!(result, "AABB", "expected AABB, got: {result}");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }

    backend_shutdown.shutdown();
    for h in backend_handles {
        h.join().unwrap().unwrap();
    }
}

// ── Select tests ────────────────────────────────────────────────────

/// Handler that uses select to monitor two backend connections.
/// Connects to two backend echo servers, sends data to one, and uses
/// select to determine which responds first.
struct SelectTwoHandler;

static SELECT_BACKEND1_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
static SELECT_BACKEND2_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for SelectTwoHandler {
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        let addr1 = *SELECT_BACKEND1_ADDR.get().expect("backend1 addr not set");
        let addr2 = *SELECT_BACKEND2_ADDR.get().expect("backend2 addr not set");
        async move {
            // Connect to both backends.
            let backend1 = match ringline::connect(addr1).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR1:{e}").as_bytes());
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            let (mut backend1_tx, mut backend1_rx) = backend1.split();
            let backend2 = match ringline::connect(addr2).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR2:{e}").as_bytes());
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            // A `Connection` already owns both halves; this test only writes
            // through the other one.
            let (_unused_tx, mut backend2_rx) = backend2.split();

            // Send data to backend1 only.
            if backend1_tx.send_nowait(b"HELLO").is_err() {
                let _ = client.send_nowait(b"SEND_ERR");
                return;
            }

            // Select on both — backend1 should win since we sent data there.
            // Use separate buffers since each closure needs its own &mut.
            let mut buf1 = Vec::new();
            let mut buf2 = Vec::new();
            match ringline::select(
                backend1_rx.with_data(|data| {
                    buf1.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                }),
                backend2_rx.with_data(|data| {
                    buf2.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                }),
            )
            .await
            {
                ringline::Either::Left(_) => {
                    let _ = client.send_nowait(b"LEFT:");
                    let _ = client.send_nowait(&buf1);
                }
                ringline::Either::Right(_) => {
                    let _ = client.send_nowait(b"RIGHT:");
                    let _ = client.send_nowait(&buf2);
                }
            }

            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SelectTwoHandler
    }
}

#[test]
fn async_select_two_connections() {
    // Start two backend echo servers.
    let (b1_shutdown, b1_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend1 launch failed");
    let backend1_addr = b1_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&backend1_addr);

    let (b2_shutdown, b2_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend2 launch failed");
    let backend2_addr = b2_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&backend2_addr);

    SELECT_BACKEND1_ADDR
        .set(backend1_addr.parse().unwrap())
        .ok();
    SELECT_BACKEND2_ADDR
        .set(backend2_addr.parse().unwrap())
        .ok();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SelectTwoHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut buf = [0u8; 64];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s.starts_with("LEFT:") || s.starts_with("RIGHT:") || s.starts_with("ERR") {
                    // Wait for the full response.
                    if s.len() >= 10 || s.starts_with("ERR") {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert!(
        result.starts_with("LEFT:HELLO"),
        "expected LEFT:HELLO, got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    b1_shutdown.shutdown();
    for h in b1_handles {
        h.join().unwrap().unwrap();
    }
    b2_shutdown.shutdown();
    for h in b2_handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that uses select to show the second branch can win.
/// Sends data to backend2 (not backend1), so Right should win.
struct SelectSecondWinsHandler;

static SELECT2_BACKEND1_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
static SELECT2_BACKEND2_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for SelectSecondWinsHandler {
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        let addr1 = *SELECT2_BACKEND1_ADDR.get().expect("backend1 addr not set");
        let addr2 = *SELECT2_BACKEND2_ADDR.get().expect("backend2 addr not set");
        async move {
            let backend1 = match ringline::connect(addr1).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR:{e}").as_bytes());
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            // A `Connection` already owns both halves; this test only writes
            // through the other one.
            let (_unused_tx, mut backend1_rx) = backend1.split();
            let backend2 = match ringline::connect(addr2).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR:{e}").as_bytes());
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            let (mut backend2_tx, mut backend2_rx) = backend2.split();

            // Send data to backend2 only.
            if backend2_tx.send_nowait(b"WORLD").is_err() {
                let _ = client.send_nowait(b"SEND_ERR");
                return;
            }

            let mut buf1 = Vec::new();
            let mut buf2 = Vec::new();
            match ringline::select(
                backend1_rx.with_data(|data| {
                    buf1.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                }),
                backend2_rx.with_data(|data| {
                    buf2.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                }),
            )
            .await
            {
                ringline::Either::Left(_) => {
                    let _ = client.send_nowait(b"LEFT:");
                    let _ = client.send_nowait(&buf1);
                }
                ringline::Either::Right(_) => {
                    let _ = client.send_nowait(b"RIGHT:");
                    let _ = client.send_nowait(&buf2);
                }
            }

            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SelectSecondWinsHandler
    }
}

#[test]
fn async_select_second_wins() {
    let (b1_shutdown, b1_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend1 launch failed");
    let b1_addr = b1_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&b1_addr);

    let (b2_shutdown, b2_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend2 launch failed");
    let b2_addr = b2_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&b2_addr);

    SELECT2_BACKEND1_ADDR.set(b1_addr.parse().unwrap()).ok();
    SELECT2_BACKEND2_ADDR.set(b2_addr.parse().unwrap()).ok();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SelectSecondWinsHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut buf = [0u8; 64];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if (s.starts_with("LEFT:") || s.starts_with("RIGHT:")) && s.len() >= 11 {
                    break;
                }
                if s.starts_with("ERR") || s.starts_with("SEND_ERR") {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert!(
        result.starts_with("RIGHT:WORLD"),
        "expected RIGHT:WORLD, got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    b1_shutdown.shutdown();
    for h in b1_handles {
        h.join().unwrap().unwrap();
    }
    b2_shutdown.shutdown();
    for h in b2_handles {
        h.join().unwrap().unwrap();
    }
}

// ── Select with sleep test (timer slot leak check) ──────────────────

/// Handler that uses select(with_data, sleep) as a manual timeout.
/// Runs many iterations to confirm no timer slot leaks from dropped SleepFutures.
struct SelectSleepHandler;

impl AsyncEventHandler for SelectSleepHandler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            // Run 300 iterations of select(with_data, sleep).
            // Each iteration where data arrives drops the SleepFuture,
            // which must correctly cancel the io_uring timeout and release
            // the timer slot. If slots leak, we'll exhaust the pool and panic.
            for _ in 0..300 {
                match ringline::select(
                    rx.with_data(|data| {
                        let _ = tx.send_nowait(data);
                        ParseResult::Consumed(data.len())
                    }),
                    ringline::sleep(Duration::from_secs(60)),
                )
                .await
                {
                    ringline::Either::Left(0) => break,
                    ringline::Either::Left(_) => {} // got data, sleep was dropped
                    ringline::Either::Right(()) => {
                        // Timeout — shouldn't happen with 60s timeout.
                        let _ = tx.send_nowait(b"TIMEOUT");
                        break;
                    }
                }
            }
            let _ = tx.send_nowait(b"DONE");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SelectSleepHandler
    }
}

#[test]
fn async_select_with_sleep() {
    // Use a config with limited timer slots to make leaks detectable.
    let config = test_config_builder()
        .timer_slots(16)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SelectSleepHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Send 300 messages — each triggers a select(with_data, sleep) where
    // data wins and the SleepFuture is dropped.
    for i in 0..300 {
        let msg = format!("msg-{i}\n");
        stream.write_all(msg.as_bytes()).unwrap();
        stream.flush().unwrap();

        // Read the echo.
        let mut buf = vec![0u8; msg.len()];
        let mut total = 0;
        while total < msg.len() {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("read error on iteration {i}: {e}"),
            }
        }
        assert_eq!(
            &buf[..total],
            msg.as_bytes(),
            "echo mismatch on iteration {i}"
        );
    }

    // Close the connection — handler should send "DONE".
    drop(stream);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── select3 test ────────────────────────────────────────────────────

/// Handler that uses select3 with two data sources + sleep.
struct Select3Handler;

static SELECT3_BACKEND_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for Select3Handler {
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        let backend_addr = *SELECT3_BACKEND_ADDR.get().expect("backend addr not set");
        async move {
            let backend = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR:{e}").as_bytes());
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            let (mut backend_tx, mut backend_rx) = backend.split();

            // Send data to backend so it echoes.
            if backend_tx.send_nowait(b"ECHO3").is_err() {
                let _ = client.send_nowait(b"SEND_ERR");
                return;
            }

            // select3: client data (none sent), backend echo, long sleep.
            // Backend should win since we sent data there.
            let mut client_buf = Vec::new();
            let mut backend_buf = Vec::new();
            match ringline::select3(
                client.with_data(|data| {
                    client_buf.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                }),
                backend_rx.with_data(|data| {
                    backend_buf.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                }),
                ringline::sleep(Duration::from_secs(60)),
            )
            .await
            {
                ringline::Either3::First(_) => {
                    let _ = client.send_nowait(b"FIRST");
                }
                ringline::Either3::Second(_) => {
                    let _ = client.send_nowait(b"SECOND:");
                    let _ = client.send_nowait(&backend_buf);
                }
                ringline::Either3::Third(()) => {
                    let _ = client.send_nowait(b"THIRD");
                }
            }

            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Select3Handler
    }
}

#[test]
fn async_select3_basic() {
    let (b_shutdown, b_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    let b_addr = b_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&b_addr);

    SELECT3_BACKEND_ADDR.set(b_addr.parse().unwrap()).ok();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Select3Handler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut buf = [0u8; 64];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s.starts_with("SECOND:") && s.len() >= 12 {
                    break;
                }
                if s.starts_with("FIRST") || s.starts_with("THIRD") || s.starts_with("ERR") {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert!(
        result.starts_with("SECOND:ECHO3"),
        "expected SECOND:ECHO3, got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    b_shutdown.shutdown();
    for h in b_handles {
        h.join().unwrap().unwrap();
    }
}

// ── spawn / cancel tests ────────────────────────────────────────

/// Handler that tests spawn exhaustion.
struct TrySpawnHandler;

impl AsyncEventHandler for TrySpawnHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return; // probe connection from wait_for_server
            }

            // First spawn should succeed.
            let result1 = ringline::spawn(async {
                ringline::sleep(Duration::from_secs(60)).await;
            });

            // Slab capacity is 1, so second spawn should fail.
            let result2 = ringline::spawn(async {
                ringline::sleep(Duration::from_secs(60)).await;
            });

            match (result1, result2) {
                (Ok(task_id), Err(_)) => {
                    let _ = conn.send_nowait(b"OK");
                    // Clean up: cancel the first task.
                    task_id.cancel();
                }
                (Ok(_), Ok(_)) => {
                    let _ = conn.send_nowait(b"BOTH_OK");
                }
                _ => {
                    let _ = conn.send_nowait(b"FAIL");
                }
            }

            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        TrySpawnHandler
    }
}

#[test]
fn async_spawn_exhaustion() {
    let config = test_config_builder()
        .standalone_task_capacity(1)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TrySpawnHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 32];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s == "OK" || s == "BOTH_OK" || s == "FAIL" {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert_eq!(result, "OK", "expected OK, got: {result}");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that tests cancelling a running task.
struct CancelTaskHandler;

impl AsyncEventHandler for CancelTaskHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return; // probe connection from wait_for_server
            }

            // Spawn a long-running task.
            let task_id = ringline::spawn(async {
                ringline::sleep(Duration::from_secs(60)).await;
            })
            .unwrap();

            // Cancel it immediately.
            task_id.cancel();

            // The slot should be free — spawn a replacement.
            let result = ringline::spawn(async {
                // Quick task — completes immediately.
            });

            match result {
                Ok(_) => {
                    let _ = conn.send_nowait(b"OK");
                }
                Err(_) => {
                    let _ = conn.send_nowait(b"FAIL");
                }
            }

            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        CancelTaskHandler
    }
}

#[test]
fn async_cancel_running_task() {
    let config = test_config_builder()
        .standalone_task_capacity(1)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<CancelTaskHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 32];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s == "OK" || s == "FAIL" {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert_eq!(
        result, "OK",
        "expected OK (slot freed after cancel), got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that tests cancelling an already-completed task (should be a no-op).
struct CancelCompletedHandler;

impl AsyncEventHandler for CancelCompletedHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return; // probe connection from wait_for_server
            }

            // Spawn a task that completes immediately.
            let task_id = ringline::spawn(async {}).unwrap();

            // Give it a chance to complete.
            ringline::sleep(Duration::from_millis(50)).await;

            // Cancel after completion — should not panic.
            task_id.cancel();

            let _ = conn.send_nowait(b"OK");
            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        CancelCompletedHandler
    }
}

#[test]
fn async_cancel_completed_task() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<CancelCompletedHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 32];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s == "OK" {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert_eq!(
        result, "OK",
        "expected OK (cancel completed task is no-op), got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Multi-worker tests ──────────────────────────────────────────────

fn multi_worker_config(threads: usize) -> Config {
    test_config_builder()
        .workers(threads)
        .build()
        .expect("valid config")
}

#[test]
fn multi_worker_echo() {
    let (shutdown, handles) = RinglineBuilder::new(multi_worker_config(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Connect 4 clients sequentially — acceptor round-robins across 2 workers.
    for i in 0..4 {
        let msg = format!("multi-worker-{i}");
        let response = echo_round_trip(&addr, msg.as_bytes());
        assert_eq!(response, msg.as_bytes(), "mismatch on connection {i}");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn multi_worker_async_echo() {
    let (shutdown, handles) = RinglineBuilder::new(multi_worker_config(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Connect 4 clients sequentially — acceptor round-robins across 2 workers.
    for i in 0..4 {
        let msg = format!("multi-worker-async-{i}");
        let response = echo_round_trip(&addr, msg.as_bytes());
        assert_eq!(response, msg.as_bytes(), "mismatch on connection {i}");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn multi_worker_graceful_shutdown() {
    let (shutdown, handles) = RinglineBuilder::new(multi_worker_config(4))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Open a few connections to exercise the workers.
    for i in 0..4 {
        let msg = format!("shutdown-{i}");
        let response = echo_round_trip(&addr, msg.as_bytes());
        assert_eq!(response, msg.as_bytes());
    }

    // Trigger shutdown — all 4 worker threads must join cleanly.
    shutdown.shutdown();
    for (i, h) in handles.into_iter().enumerate() {
        let result = h.join().unwrap_or_else(|_| panic!("worker {i} panicked"));
        result.unwrap_or_else(|e| panic!("worker {i} returned error: {e}"));
    }
}

// ── Awaitable send tests ────────────────────────────────────────────

/// Handler that tests send_await: sends a known payload via send_await
/// and reports the byte count from the SendFuture.
struct SendAwaitHandler;

impl AsyncEventHandler for SendAwaitHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let payload = b"SEND_AWAIT_OK";
            match conn.send(payload) {
                Ok(fut) => match fut.await {
                    Ok(bytes) => {
                        let msg = format!("OK:{bytes}");
                        let _ = conn.send_nowait(msg.as_bytes());
                    }
                    Err(e) => {
                        let _ = conn.send_nowait(format!("ERR:{e}").as_bytes());
                    }
                },
                Err(e) => {
                    let _ = conn.send_nowait(format!("SUBMIT_ERR:{e}").as_bytes());
                }
            }
            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SendAwaitHandler
    }
}

#[test]
fn async_send_await_basic() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SendAwaitHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // Trigger the handler.
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    // Read "SEND_AWAIT_OK" followed by "OK:13".
    let mut buf = [0u8; 128];
    let mut total = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s.contains("OK:") && s.len() >= 16 {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert!(
        result.starts_with("SEND_AWAIT_OK"),
        "expected SEND_AWAIT_OK prefix, got: {result}"
    );
    assert!(
        result.contains("OK:13"),
        "expected OK:13 (send_await byte count), got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[cfg(has_io_uring)]
/// Handler that tests send_chain_await.
struct SendChainAwaitHandler;

#[cfg(has_io_uring)]
impl AsyncEventHandler for SendChainAwaitHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            // Build a chained send with two copy parts and await completion.
            let part1 = b"HELLO";
            let part2 = b"WORLD";
            match conn.send_chain(|b| b.copy(part1).copy(part2).finish()) {
                Ok(fut) => match fut.await {
                    Ok(bytes) => {
                        let msg = format!("OK:{bytes}");
                        let _ = conn.send_nowait(msg.as_bytes());
                    }
                    Err(e) => {
                        let _ = conn.send_nowait(format!("ERR:{e}").as_bytes());
                    }
                },
                Err(e) => {
                    let _ = conn.send_nowait(format!("SUBMIT_ERR:{e}").as_bytes());
                }
            }
            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SendChainAwaitHandler
    }
}

#[test]
#[cfg(has_io_uring)]
fn async_send_chain_await_basic() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SendChainAwaitHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    // Read "HELLOWORLD" followed by "OK:<bytes>".
    let mut buf = [0u8; 128];
    let mut total = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s.contains("OK:") && s.len() >= 13 {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert!(
        result.starts_with("HELLOWORLD"),
        "expected HELLOWORLD prefix, got: {result}"
    );
    assert!(
        result.contains("OK:10"),
        "expected OK:10 (5+5 bytes chain send), got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── try_sleep / try_timeout exhaustion tests ────────────────────────

/// Handler that tests try_sleep exhaustion.
struct TrySleepHandler;

impl AsyncEventHandler for TrySleepHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let exhausted = {
                // Allocate all timer slots (config has timer_slots = 2).
                let _s1 = ringline::try_sleep(Duration::from_secs(60));
                let _s2 = ringline::try_sleep(Duration::from_secs(60));

                // Third attempt should fail with TimerExhausted.
                ringline::try_sleep(Duration::from_secs(60)).is_err()
                // _s1, _s2 dropped here — slots released.
            };

            if exhausted {
                let _ = conn.send_nowait(b"EXHAUSTED");
            } else {
                let _ = conn.send_nowait(b"NOT_EXHAUSTED");
            }

            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        TrySleepHandler
    }
}

#[test]
fn async_try_sleep_exhaustion() {
    let config = test_config_builder()
        .timer_slots(2)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TrySleepHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 32];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s == "EXHAUSTED" || s == "NOT_EXHAUSTED" {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert_eq!(
        result, "EXHAUSTED",
        "expected EXHAUSTED (timer pool full), got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that tests try_timeout exhaustion.
struct TryTimeoutHandler;

impl AsyncEventHandler for TryTimeoutHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let exhausted = {
                // Allocate all timer slots (config has timer_slots = 2).
                let _t1 =
                    ringline::try_timeout(Duration::from_secs(60), std::future::pending::<()>());
                let _t2 =
                    ringline::try_timeout(Duration::from_secs(60), std::future::pending::<()>());

                // Third attempt should fail with TimerExhausted.
                ringline::try_timeout(Duration::from_secs(60), std::future::pending::<()>())
                    .is_err()
                // _t1, _t2 dropped here — timer slots released.
            };

            if exhausted {
                let _ = conn.send_nowait(b"EXHAUSTED");
            } else {
                let _ = conn.send_nowait(b"NOT_EXHAUSTED");
            }

            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        TryTimeoutHandler
    }
}

#[test]
fn async_try_timeout_exhaustion() {
    let config = test_config_builder()
        .timer_slots(2)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TryTimeoutHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 32];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s == "EXHAUSTED" || s == "NOT_EXHAUSTED" {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert_eq!(
        result, "EXHAUSTED",
        "expected EXHAUSTED (timer pool full), got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ═══════════════════════════════════════════════════════════════════
// Phase 5 tests: join, absolute timers, UDP
// ═══════════════════════════════════════════════════════════════════

// ── join / join3 ──────────────────────────────────────────────────

/// Handler that joins two send_await calls and reports byte counts.
struct JoinHandler;

impl AsyncEventHandler for JoinHandler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            let n = rx.with_data(|data| ParseResult::Consumed(data.len())).await;
            if n == 0 {
                return;
            }

            // Two sends in flight at once, from the one owned write half.
            //
            // `send` returns an owned `SendFuture`, so the `&mut tx` borrow
            // ends at the call — arming both and joining them needs no shared
            // handle. Single *ownership* was never the same thing as one
            // operation at a time; the per-connection send queue is what keeps
            // these two from interleaving on the wire.
            let fut_a = match tx.send(b"HELLO") {
                Ok(f) => f,
                Err(_) => return,
            };
            let fut_b = match tx.send(b"WORLD") {
                Ok(f) => f,
                Err(_) => return,
            };
            let (a, b) = ringline::join(fut_a, fut_b).await;
            let msg = format!("JOIN:{}:{}", a.unwrap_or(0), b.unwrap_or(0));
            let _ = tx.send_nowait(msg.as_bytes());

            // Wait for send to drain before closing.
            ringline::sleep(Duration::from_millis(20)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        JoinHandler
    }
}

#[test]
fn async_join_basic() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<JoinHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 128];
    let mut total = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s.contains("JOIN:") {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    // Both sends should report 5 bytes each: "HELLO" and "WORLD".
    assert!(
        result.contains("JOIN:5:5"),
        "expected JOIN:5:5, got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── send_backpressured (series PR 9) ────────────────────────────────

/// Sends a message far larger than the whole copy pool can hold at once, in
/// pieces that each fit, so every piece after the first has to wait for
/// capacity that only frees as earlier sends complete.
struct BackpressuredEchoHandler;

const BP_CHUNK: usize = 4096;
const BP_CHUNKS: usize = 8;

impl AsyncEventHandler for BackpressuredEchoHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let payload = vec![b'Z'; BP_CHUNK];
            for _ in 0..BP_CHUNKS {
                match conn.send_backpressured(&payload).await {
                    Ok(n) => assert_eq!(n as usize, BP_CHUNK, "resolved with the caller's length"),
                    Err(e) => panic!("backpressured send failed: {e}"),
                }
            }
            conn.shutdown_write();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        BackpressuredEchoHandler
    }
}

/// The core promise. One worker, a 32 KiB copy pool, and sixteen connections
/// each pushing 32 KiB at a client that is not reading yet: the sockets stall,
/// permits stay held, the pool runs dry, and every send after that has to take
/// its turn in the worker's admission FIFO. When the clients finally read,
/// every connection must receive all of its bytes, exactly once.
///
/// Concurrency across connections is what makes this a test of admission
/// rather than of the happy path. A single connection awaiting its sends one
/// at a time releases each permit before requesting the next, so the pool is
/// never under pressure and the queue never has a second entry — verified by
/// mutation: with one connection, submitting without waiting for a turn
/// passes.
#[test]
fn backpressured_send_waits_for_pool_capacity_without_duplication() {
    let config = test_config_builder()
        .workers(1)
        .send_pool(8, 4096)
        .build()
        .expect("valid config");

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<BackpressuredEchoHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    // `connect_retry`, not `wait_for_server` + `connect`: the discarded probe
    // would be accepted as connection 0, and this handler sends unprompted at a
    // peer that has already closed. See #518 and `connect_retry`'s comment.
    const CONNS: usize = 16;
    let mut streams = Vec::new();
    for _ in 0..CONNS {
        let stream = connect_retry(&addr);
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        streams.push(stream);
    }

    // Let every handler run ahead and exhaust the pool before anyone reads.
    std::thread::sleep(Duration::from_millis(300));

    let readers: Vec<_> = streams
        .into_iter()
        .map(|mut stream| {
            std::thread::spawn(move || {
                let mut got = Vec::new();
                stream.read_to_end(&mut got).expect("read to FIN");
                got
            })
        })
        .collect();

    for reader in readers {
        let got = reader.join().expect("reader thread");
        assert_eq!(
            got.len(),
            BP_CHUNK * BP_CHUNKS,
            "every byte arrives exactly once: no duplication, no loss"
        );
        assert!(
            got.iter().all(|&b| b == b'Z'),
            "the stream is not interleaved or corrupted"
        );
    }

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}

/// Polls `f` exactly once with the *current* task's context, then returns.
/// Used to park a `send_backpressured` future in one task before moving it to
/// another, which is the situation the queue's owner tracking exists for.
struct PollOnce<'f, F>(&'f mut F);

impl<F: Future + Unpin> Future for PollOnce<'_, F> {
    type Output = ();
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        // Assert rather than discard: a `Ready` swallowed here leaves the
        // inner future resolved, and the next poll of it panics inside a
        // spawned task where the panic is caught and the await hangs instead
        // of failing. Every use below depends on the inner future parking.
        assert!(
            std::pin::Pin::new(&mut *self.0).poll(cx).is_pending(),
            "PollOnce expects the inner future to park on its first poll"
        );
        std::task::Poll::Ready(())
    }
}

const MOVED_HOG: &[u8] = &[b'H'; 4096];
const MOVED_MSG: &[u8] = &[b'M'; 4096];

/// Parks a bounded send in the connection task, then moves it to a spawned
/// task and awaits it there.
///
/// The FIFO wakes owners by task id. If the future did not re-register its
/// owner on the poll after the move, the wake would go to the connection task
/// — which is no longer polling this future — and the send would hang
/// forever. The pool is one slot wide and a first send is holding it, so the
/// moved future is guaranteed to be parked at the moment it changes tasks.
struct OwnerMoveHandler;

impl AsyncEventHandler for OwnerMoveHandler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Occupies the only pool slot until the client starts reading.
            //
            // Both sends come from the one write half: `send_backpressured`
            // returns a future borrowing only the *data*, so the `&mut` on the
            // half ends at the call and the future can outlive it — which is
            // what lets the second one move to another task below.
            let (mut tx, _rx) = conn.split();
            let hog =
                ringline::spawn_with_handle(tx.send_backpressured(MOVED_HOG)).expect("spawn hog");

            // Park the second send in *this* task...
            let mut moved = tx.send_backpressured(MOVED_MSG);
            PollOnce(&mut moved).await;

            // ...then hand it to a different task to finish.
            let finisher = ringline::spawn_with_handle(moved).expect("spawn finisher");

            let _ = hog.await;
            let n = finisher.await.expect("the moved send resolved");
            assert_eq!(n as usize, MOVED_MSG.len());
            tx.shutdown_write();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        OwnerMoveHandler
    }
}

#[test]
fn backpressured_send_refreshes_owner_after_first_poll_move() {
    let config = test_config_builder()
        .workers(1)
        .send_pool(1, 4096)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<OwnerMoveHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    let mut stream = connect_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    // Let the hog take the slot and the second send park before draining.
    std::thread::sleep(Duration::from_millis(200));

    let mut got = Vec::new();
    stream.read_to_end(&mut got).expect("read to FIN");
    assert_eq!(
        got.len(),
        MOVED_HOG.len() + MOVED_MSG.len(),
        "both sends completed; the moved one was woken in its new task"
    );

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}

const FIRST_POLL_MSG: &[u8] = &[b'F'; 512];

/// Builds the future in the connection task, never polls it there, and polls
/// it for the first time in a spawned task. The queue entry must be owned by
/// the task that actually polls, not by whoever constructed the future — a
/// regression that captured the task id at construction would park forever.
struct FirstPollMoveHandler;

impl AsyncEventHandler for FirstPollMoveHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let unpolled = conn.send_backpressured(FIRST_POLL_MSG);
            let handle = ringline::spawn_with_handle(unpolled).expect("spawn");
            let n = handle.await.expect("resolved in the task that polled it");
            assert_eq!(n as usize, FIRST_POLL_MSG.len());
            conn.shutdown_write();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        FirstPollMoveHandler
    }
}

#[test]
fn backpressured_send_registers_the_first_polling_task_after_move() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<FirstPollMoveHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    let mut stream = connect_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut got = Vec::new();
    stream.read_to_end(&mut got).expect("read to FIN");
    assert_eq!(got.len(), FIRST_POLL_MSG.len());

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}

const CANCEL_A: &[u8] = &[b'A'; 1024];
const CANCEL_B: &[u8] = &[b'B'; 7];

/// Drops a send that has already been submitted, then issues another.
///
/// The abandoned operation's completion is still coming. It must settle the
/// entry it belongs to and nothing else: if results were taken positionally
/// rather than by id, the next send would resolve on the dropped one's
/// completion and report the wrong length — or resolve before its own bytes
/// were written.
struct CancelSubmittedHandler;

impl AsyncEventHandler for CancelSubmittedHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            {
                // One poll with a free pool submits it; then drop it.
                let mut submitted = conn.send_backpressured(CANCEL_A);
                PollOnce(&mut submitted).await;
            }
            let n = conn
                .send_backpressured(CANCEL_B)
                .await
                .expect("the next send resolves on its own completion");
            assert_eq!(
                n as usize,
                CANCEL_B.len(),
                "resolved with its own length, not the abandoned send's"
            );
            conn.shutdown_write();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        CancelSubmittedHandler
    }
}

#[test]
fn canceled_submitted_backpressured_send_cannot_complete_the_next_send() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<CancelSubmittedHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    let mut stream = connect_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut got = Vec::new();
    stream.read_to_end(&mut got).expect("read to FIN");

    // The abandoned send's bytes may or may not have reached the wire — that
    // is inherent to cancelling a submitted write, and is documented. What
    // must hold is that the second send's bytes are all there, at the end.
    assert!(
        got.ends_with(CANCEL_B),
        "the second send's bytes arrived intact; got {} bytes",
        got.len()
    );

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}

#[cfg(not(has_io_uring))]
const HALF_CLOSE_A: &[u8] = &[b'S'; 4096];
#[cfg(not(has_io_uring))]
const HALF_CLOSE_B: &[u8] = &[b'W'; 4096];

/// mio's half-close is deferred until queued sends drain, so the two kinds of
/// bounded send must be treated differently when the write half shuts:
/// one already submitted still has its bytes to deliver, while one merely
/// waiting for capacity can never use the turn it is waiting for.
///
/// The submitted send must complete `Ok`; the waiting one must fail
/// `BrokenPipe` rather than sit in the queue holding the head.
#[cfg(not(has_io_uring))]
struct MioHalfCloseHandler;

#[cfg(not(has_io_uring))]
impl AsyncEventHandler for MioHalfCloseHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Poll each exactly once, in order, so the states are not left to
            // scheduler timing: spawning the first and polling the second
            // immediately races — the spawned task has not run yet, the pool
            // is still free, and the "waiting" send submits instead.
            let mut submitted = conn.send_backpressured(HALF_CLOSE_A);
            PollOnce(&mut submitted).await; // takes the only slot
            let mut waiting = conn.send_backpressured(HALF_CLOSE_B);
            PollOnce(&mut waiting).await; // parks: the pool is now empty

            conn.shutdown_write();

            let waiting_err = waiting
                .await
                .expect_err("a parked send cannot survive a FIN");
            assert_eq!(
                waiting_err.kind(),
                std::io::ErrorKind::BrokenPipe,
                "{waiting_err}"
            );

            let n = submitted
                .await
                .expect("the already-submitted send still delivers its bytes");
            assert_eq!(n as usize, HALF_CLOSE_A.len());
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        MioHalfCloseHandler
    }
}

#[cfg(not(has_io_uring))]
#[test]
fn mio_half_close_resolves_every_bounded_send_without_hanging() {
    let config = test_config_builder()
        .workers(1)
        .send_pool(1, 4096)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<MioHalfCloseHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    let mut stream = connect_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    // Let both sends reach their states before draining.
    std::thread::sleep(Duration::from_millis(200));

    let mut got = Vec::new();
    stream.read_to_end(&mut got).expect("read to FIN");
    assert!(
        got.len() <= HALF_CLOSE_A.len(),
        "a send the half-close failed must not have put bytes on the wire; got {}",
        got.len()
    );

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}

/// Handler asserting the future is inert until polled: build one, drop it
/// without awaiting, then do a normal send. If construction had enqueued or
/// submitted anything, the queue would hold a phantom head and the send
/// below would stall.
struct LazyDropHandler;

impl AsyncEventHandler for LazyDropHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            for _ in 0..64 {
                let never_polled = conn.send_backpressured(b"dropped");
                drop(never_polled);
            }
            let _ = conn.send_backpressured(b"OK").await;
            conn.shutdown_write();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        LazyDropHandler
    }
}

#[test]
fn backpressured_send_construction_is_lazy_and_unpolled_drop_is_inert() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<LazyDropHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    let mut stream = connect_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut got = Vec::new();
    stream.read_to_end(&mut got).expect("read to FIN");
    assert_eq!(
        got, b"OK",
        "64 unpolled futures wrote nothing and blocked nothing"
    );

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}

/// A message larger than the entire pool can never be admitted, so it must be
/// refused rather than parked forever — and refused *before* anything is
/// written, so the peer sees nothing.
struct OversizeHandler;

impl AsyncEventHandler for OversizeHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Pool is 8 x 4096 = 32 KiB; ask for 64 KiB.
            let huge = vec![b'X'; 64 * 1024];
            let err = conn
                .send_backpressured(&huge)
                .await
                .expect_err("larger than the whole pool");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
            let _ = conn.send_backpressured(b"REFUSED").await;
            conn.shutdown_write();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        OversizeHandler
    }
}

#[test]
fn backpressured_send_rejects_oversize_before_writing() {
    let config = test_config_builder()
        .send_pool(8, 4096)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<OversizeHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    let mut stream = connect_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut got = Vec::new();
    stream.read_to_end(&mut got).expect("read to FIN");
    assert_eq!(
        got, b"REFUSED",
        "the oversize send put nothing on the wire, and the next send still works"
    );

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}

/// Half-close while a send is parked: the waiter must fail rather than hang.
/// The handler parks a send behind a pool it has deliberately exhausted, then
/// shuts the write half from a second task.
struct ShutdownWhileParkedHandler;

impl AsyncEventHandler for ShutdownWhileParkedHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Fill the one-slot pool, then park a second send behind it, so
            // there is a genuine waiting entry when the FIN is requested.
            // An earlier version shut the write half *first* and only
            // exercised the up-front refusal, leaving `shutdown_write`'s
            // `fail_waiting_bounded_sends` — the actual change — untested.
            // Two sends against a one-slot pool. Which of them ends up
            // submitted and which parked is deliberately NOT asserted: it
            // depends on how fast the socket drains, which differs between
            // platforms — an earlier version pinned it and passed on macOS
            // while failing on Linux. What must hold either way is that
            // shutting the write half resolves *both* rather than leaving
            // either to hang, and that any send it fails does so with
            // BrokenPipe.
            let mut first = conn.send_backpressured(SHUTDOWN_HOG);
            PollOnce(&mut first).await;
            let mut second = conn.send_backpressured(SHUTDOWN_PARKED);
            PollOnce(&mut second).await;

            conn.shutdown_write();

            for (label, outcome) in [("first", first.await), ("second", second.await)] {
                match outcome {
                    Ok(n) => assert_eq!(
                        n as usize,
                        SHUTDOWN_HOG.len(),
                        "{label}: a send that succeeded reports its own length"
                    ),
                    Err(e) => assert_eq!(
                        e.kind(),
                        std::io::ErrorKind::BrokenPipe,
                        "{label}: the only reason to fail here is the shut write half, got {e}"
                    ),
                }
            }

            // A send issued *after* the shutdown is refused up front, every
            // time — this part has no timing dependence.
            let late = conn
                .send_backpressured(b"after shutdown")
                .await
                .expect_err("write half is shut down");
            assert_eq!(late.kind(), std::io::ErrorKind::BrokenPipe, "{late}");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ShutdownWhileParkedHandler
    }
}

const SHUTDOWN_HOG: &[u8] = &[b'O'; 4096];
const SHUTDOWN_PARKED: &[u8] = &[b'P'; 4096];

#[test]
fn shutdown_drops_parked_backpressured_send_without_hanging() {
    let config = test_config_builder()
        .workers(1)
        .send_pool(1, 4096)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ShutdownWhileParkedHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    let mut stream = connect_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    // Let the pool fill and the second send park before draining.
    std::thread::sleep(Duration::from_millis(200));
    let mut got = Vec::new();
    // The FIN arrives; the parked send failed rather than hanging the task.
    stream.read_to_end(&mut got).expect("read to FIN");
    // At most one of the two sends can have been on the wire, and the task
    // reached its end rather than hanging — which is what this test is named
    // for.
    assert!(
        got.len() <= SHUTDOWN_HOG.len(),
        "a failed send must not have put bytes on the wire; got {}",
        got.len()
    );

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}

/// Handler that joins three futures: send_await + sleep + with_data.
struct Join3Handler;

impl AsyncEventHandler for Join3Handler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            let n = rx.with_data(|data| ParseResult::Consumed(data.len())).await;
            if n == 0 {
                return;
            }

            let fut_a = async {
                match tx.send(b"ABC") {
                    Ok(f) => f.await.unwrap_or(0),
                    Err(_) => 0,
                }
            };
            let fut_b = async {
                ringline::sleep(Duration::from_millis(20)).await;
                42u32
            };
            let fut_c = async {
                // This will wait for new data from the client.
                let n = rx.with_data(|data| ParseResult::Consumed(data.len())).await;
                n as u32
            };

            let (a, b, c) = ringline::join3(fut_a, fut_b, fut_c).await;
            let msg = format!("JOIN3:{a}:{b}:{c}");
            let _ = tx.send_nowait(msg.as_bytes());

            ringline::sleep(Duration::from_millis(20)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Join3Handler
    }
}

/// Counts accepts and send outcomes without ever panicking, so the probe's fate
/// is observable instead of fatal.
struct ProbeWitnessHandler;

static PROBE_ACCEPTED: AtomicU32 = AtomicU32::new(0);
static PROBE_SEND_OK: AtomicU32 = AtomicU32::new(0);

impl AsyncEventHandler for ProbeWitnessHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            PROBE_ACCEPTED.fetch_add(1, Ordering::SeqCst);
            let payload = vec![b'Z'; BP_CHUNK];
            for _ in 0..BP_CHUNKS {
                if conn.send_backpressured(&payload).await.is_err() {
                    return;
                }
                PROBE_SEND_OK.fetch_add(1, Ordering::SeqCst);
            }
            conn.shutdown_write();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ProbeWitnessHandler
    }
}

/// The premise #518 got wrong, pinned down so it cannot be re-litigated.
///
/// #518 read the failure as "a parked send resolved `connection closing` on a
/// connection the client had not closed". The client *had* closed it: that was
/// not one of the test's sixteen readers but [`wait_for_server`]'s readiness
/// probe, accepted as connection 0 with its peer already gone. This asserts
/// both halves of that — the probe reaches a handler, and a handler that sends
/// unprompted cannot complete its sends on it — which is why the
/// send-on-accept tests use [`connect_retry`] instead.
///
/// Deliberately asserts "did not finish all eight", not a specific error: the
/// handler either sees the failure (`EPIPE`, or `NotConnected` when the
/// FIN-driven close is finalized first) or is dropped mid-sequence when the
/// connection is torn down under it. Which one lands is a race, and the
/// hazard is the same either way.
#[test]
fn wait_for_server_probe_reaches_a_send_on_accept_handler() {
    let config = test_config_builder()
        .workers(1)
        .send_pool(8, 4096)
        .build()
        .expect("valid config");

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ProbeWitnessHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    // The probe, and nothing else: no real client connects in this test.
    wait_for_server(&addr);
    std::thread::sleep(Duration::from_millis(500));

    let accepted = PROBE_ACCEPTED.load(Ordering::SeqCst);
    let oks = PROBE_SEND_OK.load(Ordering::SeqCst);

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }

    assert!(
        accepted >= 1,
        "the readiness probe is accepted as a connection and runs a handler"
    );
    assert!(
        oks < BP_CHUNKS as u32,
        "a send-on-accept handler cannot complete its sends on the probe \
         connection: its peer closed before the handler ran (got {oks} of {BP_CHUNKS})"
    );
}

/// Instrumented reproducer for #518, run explicitly rather than in CI.
///
/// The control in #522 refuted the readiness-probe explanation: the failure is
/// `Broken pipe (os error 32)` on the *earliest* connection slots, whose peers
/// are live, and the probe only ever explained the `connection closing` string
/// that accompanied it. Deducing a mechanism from the panic text is what
/// produced the wrong answer, so this records what actually happened instead:
/// per connection, how many sends completed, the raw `errno` of the one that
/// failed, whether the handler reached `shutdown_write`, and what the client on
/// the other end saw.
///
/// Parameterized by environment so one build can sweep the conditions:
///
/// - `RL518_ITERS` (50) — rounds per process.
/// - `RL518_SLEEP_MS` (300) — the stall before any client reads. At 0 the
///   clients read immediately, which is the control: no stall means no
///   backpressure, so a failure there is not about the admission FIFO.
/// - `RL518_POOL_SLOTS` (8) — send-pool slots. At 64 the pool covers every
///   connection at once and nothing ever parks, the second control.
/// - `RL518_CONNS` (16) — connections per round.
///
/// Prints one line per anomalous round and a final tally; it asserts nothing,
/// because its job is to produce evidence rather than a verdict.
#[test]
#[ignore = "instrumentation for #518; run explicitly with RL518_* set"]
fn repro518_instrumented() {
    fn envn(key: &str, default: usize) -> usize {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    let iters = envn("RL518_ITERS", 50);
    let sleep_ms = envn("RL518_SLEEP_MS", 300);
    let pool_slots = envn("RL518_POOL_SLOTS", 8);
    let conns = envn("RL518_CONNS", 16);
    // `RL518_SHUTDOWN=0` makes the handler never call `shutdown_write()`, so no
    // `Shutdown` SQE is ever submitted. `submit_shutdown` targets the
    // registered-file slot `Fixed(conn_index)` with a `user_data` payload of 0
    // — no generation — so one that executes after its slot is recycled shuts
    // down whichever connection now holds the slot, and the completion cannot
    // tell. That is the shape of what the instrument measured: a clean FIN on a
    // live connection, then `EPIPE` on the next send. If the anomalies vanish
    // here, the shutdown path is implicated; if they persist, it is not.
    let want_shutdown = envn("RL518_SHUTDOWN", 1) != 0;
    R518_SHUTDOWN.store(want_shutdown, Ordering::SeqCst);
    eprintln!(
        "REPRO518 config iters={iters} sleep_ms={sleep_ms} pool_slots={pool_slots} conns={conns} shutdown={want_shutdown}"
    );

    let mut anomalous = 0usize;
    for round in 0..iters {
        let report = repro518_round(sleep_ms, pool_slots, conns);
        if report.is_anomalous() {
            anomalous += 1;
            eprintln!("REPRO518 round {round}: {}", report.describe());
        }
    }
    eprintln!(
        "REPRO518 RESULT anomalous={anomalous}/{iters} sleep_ms={sleep_ms} pool_slots={pool_slots} conns={conns} shutdown={want_shutdown}"
    );
}

/// One handler's fate: which accept it was, how many sends landed, and why it
/// stopped.
#[derive(Debug)]
struct SendFate {
    seq: u32,
    sends_ok: usize,
    err_os: Option<i32>,
    err_msg: String,
    reached_shutdown: bool,
}

/// One client's fate, so a server-side error can be read against what the peer
/// actually observed rather than against an assumption about it.
#[derive(Debug)]
struct ReadFate {
    bytes: usize,
    err: Option<String>,
}

struct Repro518Report {
    sends: Vec<SendFate>,
    reads: Vec<ReadFate>,
    expected_bytes: usize,
}

impl Repro518Report {
    fn is_anomalous(&self) -> bool {
        self.sends
            .iter()
            .any(|s| s.err_os.is_some() || !s.reached_shutdown)
            || self
                .reads
                .iter()
                .any(|r| r.err.is_some() || r.bytes != self.expected_bytes)
    }

    fn describe(&self) -> String {
        let mut out = String::new();
        for s in self
            .sends
            .iter()
            .filter(|s| s.err_os.is_some() || !s.reached_shutdown)
        {
            out.push_str(&format!(
                "[accept#{} sends_ok={} errno={:?} err={:?} shutdown={}] ",
                s.seq, s.sends_ok, s.err_os, s.err_msg, s.reached_shutdown
            ));
        }
        for (i, r) in self.reads.iter().enumerate() {
            if r.err.is_some() || r.bytes != self.expected_bytes {
                out.push_str(&format!("[reader{} bytes={} err={:?}] ", i, r.bytes, r.err));
            }
        }
        out
    }
}

static R518_SEQ: AtomicU32 = AtomicU32::new(0);
static R518_SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
static R518_FATES: std::sync::Mutex<Vec<SendFate>> = std::sync::Mutex::new(Vec::new());

struct Repro518Handler;

impl AsyncEventHandler for Repro518Handler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let seq = R518_SEQ.fetch_add(1, Ordering::SeqCst);
            let payload = vec![b'Z'; BP_CHUNK];
            let mut sends_ok = 0usize;
            let mut err_os = None;
            let mut err_msg = String::new();
            let mut reached_shutdown = false;
            for _ in 0..BP_CHUNKS {
                match conn.send_backpressured(&payload).await {
                    Ok(_) => sends_ok += 1,
                    Err(e) => {
                        err_os = Some(e.raw_os_error().unwrap_or(-1));
                        err_msg = format!("{e}");
                        break;
                    }
                }
            }
            if err_os.is_none() && R518_SHUTDOWN.load(Ordering::Relaxed) {
                conn.shutdown_write();
                reached_shutdown = true;
            } else if err_os.is_none() {
                // No FIN from us: the task ending closes the connection, which
                // FINs anyway, so the client still sees EOF. What disappears is
                // every `Shutdown` SQE.
                reached_shutdown = true;
            }
            if let Ok(mut g) = R518_FATES.lock() {
                g.push(SendFate {
                    seq,
                    sends_ok,
                    err_os,
                    err_msg,
                    reached_shutdown,
                });
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Repro518Handler
    }
}

fn repro518_round(sleep_ms: usize, pool_slots: usize, conns: usize) -> Repro518Report {
    R518_SEQ.store(0, Ordering::SeqCst);
    if let Ok(mut g) = R518_FATES.lock() {
        g.clear();
    }

    let config = test_config_builder()
        .workers(1)
        .send_pool(pool_slots as u16, 4096)
        .build()
        .expect("valid config");

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Repro518Handler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    let mut streams = Vec::new();
    for _ in 0..conns {
        let stream = connect_retry(&addr);
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        streams.push(stream);
    }

    if sleep_ms > 0 {
        std::thread::sleep(Duration::from_millis(sleep_ms as u64));
    }

    let readers: Vec<_> = streams
        .into_iter()
        .map(|mut stream| {
            std::thread::spawn(move || {
                let mut got = Vec::new();
                match stream.read_to_end(&mut got) {
                    Ok(_) => ReadFate {
                        bytes: got.len(),
                        err: None,
                    },
                    Err(e) => ReadFate {
                        bytes: got.len(),
                        err: Some(format!("{e}")),
                    },
                }
            })
        })
        .collect();

    let reads: Vec<ReadFate> = readers
        .into_iter()
        .map(|h| {
            h.join().unwrap_or(ReadFate {
                bytes: 0,
                err: Some("reader thread panicked".into()),
            })
        })
        .collect();

    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }

    let sends = R518_FATES
        .lock()
        .map(|mut g| std::mem::take(&mut *g))
        .unwrap_or_default();

    Repro518Report {
        sends,
        reads,
        expected_bytes: BP_CHUNK * BP_CHUNKS,
    }
}

#[test]
fn async_join3_mixed() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Join3Handler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Read until `buf[..total]` contains `needle`, or the deadline passes.
    // Returns whether it was found.
    fn read_until(stream: &mut TcpStream, buf: &mut [u8], total: &mut usize, needle: &str) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if std::str::from_utf8(&buf[..*total])
                .unwrap_or("")
                .contains(needle)
            {
                return true;
            }
            match stream.read(&mut buf[*total..]) {
                Ok(0) => break,
                Ok(n) => *total += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("read error: {e}"),
            }
        }
        std::str::from_utf8(&buf[..*total])
            .unwrap_or("")
            .contains(needle)
    }

    let mut buf = [0u8; 128];
    let mut total = 0;

    // First write triggers the handler; its initial `with_data` consumes
    // everything available at that moment.
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    // Wait for "ABC" before writing the second payload, rather than sleeping
    // and hoping. "ABC" is sent by `fut_a` *inside* the join3, so it cannot
    // appear until the initial `with_data` has already returned — which makes
    // it proof that the handler consumed "x" alone.
    //
    // The previous version slept 30ms instead. Under parallel suite load the
    // worker can take longer than that to get to this connection, in which
    // case one recv delivers "x" and "PAYLOAD" together, the initial
    // `with_data` consumes both, and the join3's own `with_data` waits for a
    // third write that never comes — the whole future stalls and the test
    // times out with only "ABC" in hand. Measured at ~3% on Linux under
    // `--features force-mio` (ringline-rs/ringline#386).
    assert!(
        read_until(&mut stream, &mut buf, &mut total, "ABC"),
        "handler did not reach the join3: {:?}",
        std::str::from_utf8(&buf[..total])
    );

    stream.write_all(b"PAYLOAD").unwrap();
    stream.flush().unwrap();

    read_until(&mut stream, &mut buf, &mut total, "JOIN3:");

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    // a=3 (send "ABC"), b=42 (sleep completed), c=7 (with_data received "PAYLOAD")
    // Note: "ABC" may appear before JOIN3 in the output since it's a real send.
    assert!(
        result.contains("JOIN3:3:42:7"),
        "expected JOIN3:3:42:7, got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Absolute timers ───────────────────────────────────────────────

/// Handler that uses sleep_until with a deadline.
struct SleepUntilHandler;

impl AsyncEventHandler for SleepUntilHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let before = std::time::Instant::now();
            let deadline = ringline::Deadline::after(Duration::from_millis(50));
            ringline::sleep_until(deadline).await;
            let elapsed = before.elapsed();

            let msg = if elapsed >= Duration::from_millis(30) {
                "SLEEP_UNTIL_OK"
            } else {
                "SLEEP_UNTIL_TOO_FAST"
            };
            let _ = conn.send_nowait(msg.as_bytes());
            ringline::sleep(Duration::from_millis(20)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SleepUntilHandler
    }
}

#[test]
fn async_sleep_until_basic() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SleepUntilHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 64];
    let mut total = 0;
    let deadline_t = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline_t {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s.contains("SLEEP_UNTIL") {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert_eq!(result, "SLEEP_UNTIL_OK", "got: {result}");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that uses timeout_at with a short deadline around a long sleep.
struct TimeoutAtHandler;

impl AsyncEventHandler for TimeoutAtHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let deadline = ringline::Deadline::after(Duration::from_millis(20));
            let result =
                ringline::timeout_at(deadline, ringline::sleep(Duration::from_secs(10))).await;

            let msg = match result {
                Err(_elapsed) => "TIMEOUT_AT_EXPIRED",
                Ok(()) => "TIMEOUT_AT_NOT_EXPIRED",
            };
            let _ = conn.send_nowait(msg.as_bytes());
            ringline::sleep(Duration::from_millis(20)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        TimeoutAtHandler
    }
}

#[test]
fn async_timeout_at_expires() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TimeoutAtHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 64];
    let mut total = 0;
    let deadline_t = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline_t {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s.contains("TIMEOUT_AT") {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert_eq!(result, "TIMEOUT_AT_EXPIRED", "got: {result}");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── UDP ───────────────────────────────────────────────────────────

/// Async handler that echoes UDP datagrams via UdpCtx.
struct UdpEchoAsync;

impl AsyncEventHandler for UdpEchoAsync {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| ParseResult::Consumed(data.len()))
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn on_udp_bind(
        &self,
        udp: ringline::UdpCtx,
    ) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async move {
            loop {
                let (data, peer) = udp.recv_from().await;
                let _ = udp.send_to(peer, &data);
            }
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        UdpEchoAsync
    }
}

#[test]
fn async_udp_echo() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .bind_udp("127.0.0.1:0".parse().unwrap())
        .launch::<UdpEchoAsync>()
        .expect("launch failed");
    let tcp_addr = shutdown.bound_addr().expect("bound address").to_string();
    let udp_addr = shutdown.bound_udp_addr().expect("bound UDP address");

    wait_for_server(&tcp_addr);
    std::thread::sleep(Duration::from_millis(50));

    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let msg = b"ASYNC_UDP_ECHO";
    client.send_to(msg, udp_addr).unwrap();

    let mut buf = [0u8; 64];
    let (n, _peer) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], msg, "async UDP echo mismatch");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ═══════════════════════════════════════════════════════════════════
// Free connect() + on_start() tests
// ═══════════════════════════════════════════════════════════════════

// ── Standalone task using free connect() ─────────────────────────

/// Handler where on_accept spawns a standalone task that uses the free
/// the free `ringline::connect()` to reach a backend echo server.
struct StandaloneConnectHandler;

static STANDALONE_CONNECT_BACKEND: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for StandaloneConnectHandler {
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        let backend_addr = *STANDALONE_CONNECT_BACKEND
            .get()
            .expect("backend addr not set");
        async move {
            // Wait for trigger from client.
            let n = client
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            // Spawn a standalone task that connects to the backend.
            // ConnCtx is Copy — standalone tasks can use it for send().
            ringline::spawn(async move {
                let backend = match ringline::connect(backend_addr).await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        let _ = client.send_nowait(format!("CONNECT_ERR:{e}").as_bytes());
                        return;
                    }
                };
                // Reading an outbound connection goes through its read half.
                let (mut backend_tx, mut backend_rx) = backend.split();

                // Send data to backend, read echo.
                if backend_tx.send_nowait(b"STANDALONE").is_err() {
                    return;
                }

                let mut echo = Vec::new();
                while echo.len() < 10 {
                    let remaining = 10 - echo.len();
                    let got = backend_rx
                        .with_data(|data| {
                            let take = data.len().min(remaining);
                            echo.extend_from_slice(&data[..take]);
                            ParseResult::Consumed(take)
                        })
                        .await;
                    if got == 0 {
                        break;
                    }
                }

                // Report to client.
                let _ = client.send_nowait(&echo);
            })
            .unwrap();

            // Keep connection alive so standalone task can send.
            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        StandaloneConnectHandler
    }
}

#[test]
fn async_standalone_connect() {
    // Start backend echo server.
    let (b_shutdown, b_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    let backend_addr = b_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&backend_addr);

    STANDALONE_CONNECT_BACKEND
        .set(backend_addr.parse().unwrap())
        .ok();

    // Start the handler server.
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<StandaloneConnectHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 64];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= 10 {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let result = std::str::from_utf8(&buf[..total]).unwrap();
    assert_eq!(
        result, "STANDALONE",
        "expected STANDALONE echo, got: {result}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    b_shutdown.shutdown();
    for h in b_handles {
        h.join().unwrap().unwrap();
    }
}

// ── Server-speaks-first greeting ─────────────────────────────────

/// Server that sends a greeting immediately on accept (MySQL/SMTP style),
/// before the client sends anything.
struct GreetingServer;

impl AsyncEventHandler for GreetingServer {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let _ = conn.send_nowait(b"WELCOME!");
            // Keep the connection open until the peer disconnects.
            loop {
                let n = conn
                    .with_data(|data| ParseResult::Consumed(data.len()))
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        GreetingServer
    }
}

static GREETING_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
static GREETING_RESULT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Client that connects and expects the server's greeting to arrive intact.
/// Regression: on the mio backend, greeting bytes delivered in the same
/// event batch as the connect-writable event were read into the accumulator
/// and then destroyed by the connect-success accumulator reset — and
/// edge-triggered mio never re-delivered them, so the client stalled.
struct GreetingClientHandler;

impl AsyncEventHandler for GreetingClientHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let addr = *GREETING_ADDR.get().expect("greeting addr not set");
        Some(Box::pin(async move {
            let conn = match ringline::connect(addr).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    GREETING_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            // A `Connection` already owns both halves; this test only writes
            // through the other one.
            let (_unused_tx, mut conn_rx) = conn.split();

            let mut greeting = Vec::new();
            while greeting.len() < 8 {
                let remaining = 8 - greeting.len();
                let got = conn_rx
                    .with_data(|data| {
                        let take = data.len().min(remaining);
                        greeting.extend_from_slice(&data[..take]);
                        ParseResult::Consumed(take)
                    })
                    .await;
                if got == 0 {
                    break;
                }
            }
            GREETING_RESULT
                .set(String::from_utf8_lossy(&greeting).to_string())
                .ok();
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        GreetingClientHandler
    }
}

#[test]
fn async_server_speaks_first_greeting() {
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<GreetingServer>()
        .expect("server launch failed");
    let addr = s_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    GREETING_ADDR.set(addr.parse().unwrap()).ok();

    let (_c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<GreetingClientHandler>()
        .expect("client launch failed");
    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    let result = GREETING_RESULT.get().expect("client did not set result");
    assert_eq!(result, "WELCOME!", "greeting lost or corrupted: {result}");

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}

// ── Client-only mode via on_start() ─────────────────────────────

/// Handler that uses on_start() for client-only mode: connects to a
/// backend, sends data, reads echo, then shuts down.
struct OnStartClientHandler;

static ON_START_BACKEND_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
static ON_START_RESULT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

impl AsyncEventHandler for OnStartClientHandler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        // No inbound connections expected in client-only mode.
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let backend_addr = *ON_START_BACKEND_ADDR.get().expect("backend addr not set");
        Some(Box::pin(async move {
            let backend = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    ON_START_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            let (mut backend_tx, mut backend_rx) = backend.split();

            if backend_tx.send_nowait(b"ON_START").is_err() {
                ON_START_RESULT.set("SEND_ERR".to_string()).ok();
                ringline::request_shutdown().ok();
                return;
            }

            let mut echo = Vec::new();
            while echo.len() < 8 {
                let remaining = 8 - echo.len();
                let got = backend_rx
                    .with_data(|data| {
                        let take = data.len().min(remaining);
                        echo.extend_from_slice(&data[..take]);
                        ParseResult::Consumed(take)
                    })
                    .await;
                if got == 0 {
                    break;
                }
            }

            ON_START_RESULT
                .set(String::from_utf8_lossy(&echo).to_string())
                .ok();
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        OnStartClientHandler
    }
}

#[test]
fn async_on_start_client_only() {
    // Start backend echo server.
    let (b_shutdown, b_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    let backend_addr = b_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&backend_addr);

    ON_START_BACKEND_ADDR
        .set(backend_addr.parse().unwrap())
        .ok();

    // Launch client-only (no .bind()).
    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<OnStartClientHandler>()
        .expect("launch failed");

    // Wait for the on_start task to complete and shut down the worker.
    for h in handles {
        h.join().unwrap().unwrap();
    }

    let result = ON_START_RESULT.get().expect("on_start did not set result");
    assert_eq!(result, "ON_START", "expected ON_START echo, got: {result}");

    b_shutdown.shutdown();
    for h in b_handles {
        h.join().unwrap().unwrap();
    }
}

// ── Free connect() to dead port returns error ────────────────────

/// Handler where on_accept spawns a standalone task that tries to
/// connect to a dead port via ringline::connect().
struct StandaloneConnectRefusedHandler;

static STANDALONE_REFUSED_PORT: AtomicU32 = AtomicU32::new(0);

impl AsyncEventHandler for StandaloneConnectRefusedHandler {
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = client
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let port = STANDALONE_REFUSED_PORT.load(Ordering::SeqCst);
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

            ringline::spawn(async move {
                let result = match ringline::connect(addr).await {
                    Ok(_) => "CONNECTED".to_string(),
                    Err(e) => format!("ERR:{}", e.kind()),
                };

                let _ = client.send_nowait(result.as_bytes());
            })
            .unwrap();

            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        StandaloneConnectRefusedHandler
    }
}

#[test]
fn async_standalone_connect_refused() {
    // A port held by a socket that never listens, so a connect is refused and
    // nothing else can take the port while the test runs.
    let (_dead_guard, dead_port) = refusing_port();

    STANDALONE_REFUSED_PORT.store(dead_port as u32, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<StandaloneConnectRefusedHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 128];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                if s.starts_with("ERR:")
                    || s.starts_with("CONNECTED")
                    || s.starts_with("SUBMIT_ERR:")
                {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }

    let response = std::str::from_utf8(&buf[..total]).unwrap();
    assert!(
        response.starts_with("ERR:"),
        "expected connect error, got: {response}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Peer close delivers EOF to accepted connection ──────────────────

/// Server that accepts a connection, reads one message, echoes it, then
/// waits for the client to disconnect. Verifies with_data returns 0 (EOF).
struct PeerCloseHandler;

static PEER_CLOSE_RESULT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

impl AsyncEventHandler for PeerCloseHandler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            // Read until EOF. Each chunk is echoed back.
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    // EOF — peer closed the connection. This is the success case.
                    PEER_CLOSE_RESULT.set("OK".to_string()).ok();
                    return;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        PeerCloseHandler
    }
}

#[test]
fn async_peer_close_delivers_eof() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<PeerCloseHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    // Connect with std TCP, send data, read echo, then close.
    {
        let mut stream = TcpStream::connect(&addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(b"hello").unwrap();
        stream.flush().unwrap();

        let mut buf = [0u8; 5];
        let mut total = 0;
        while total < 5 {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("read error: {e}"),
            }
        }
        assert_eq!(&buf[..total], b"hello");
        // stream drops here, closing the TCP connection
    }

    // Give the server time to process the close.
    std::thread::sleep(Duration::from_millis(200));

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }

    let result = PEER_CLOSE_RESULT.get().expect("handler did not set result");
    assert_eq!(result, "OK", "expected EOF after peer close, got: {result}");
}

// ── Send pool exhaustion ────────────────────────────────────────────

#[cfg(has_io_uring)]
/// Handler that fires many send_nowait calls to exhaust the send pool.
struct PoolExhaustionHandler;

#[cfg(has_io_uring)]
static POOL_EXHAUSTION_RESULT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[cfg(has_io_uring)]
impl AsyncEventHandler for PoolExhaustionHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Read one message to know the client is connected.
            conn.with_data(|data| ParseResult::Consumed(data.len()))
                .await;

            // Fire many send_nowait calls rapidly. With a tiny pool, this
            // should eventually return Err (pool exhausted).
            let mut got_error = false;
            let payload = [0xABu8; 512];
            for _ in 0..1000 {
                if let Err(_e) = conn.send_nowait(&payload) {
                    got_error = true;
                    break;
                }
            }

            if got_error {
                POOL_EXHAUSTION_RESULT.set("OK".to_string()).ok();
            } else {
                POOL_EXHAUSTION_RESULT.set("NO_ERROR".to_string()).ok();
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        PoolExhaustionHandler
    }
}

#[cfg(has_io_uring)]
#[test]
fn async_send_pool_exhaustion() {
    let config = test_config_builder()
        // Very small send pool to trigger exhaustion quickly.
        .send_pool(4, 16384)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<PoolExhaustionHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    // Connect and send a trigger message. Don't read — let the server's
    // sends queue up and exhaust the pool.
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"go").unwrap();
    stream.flush().unwrap();

    // Wait for the handler to complete.
    std::thread::sleep(Duration::from_millis(500));

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }

    let result = POOL_EXHAUSTION_RESULT
        .get()
        .expect("handler did not set result");
    assert_eq!(
        result, "OK",
        "expected pool exhaustion error, got: {result}"
    );
}

// ── Multi-slot send retry after pool pressure ──────────────────────

const MULTI_SLOT_FILLER_LEN: usize = 1024;
const MULTI_SLOT_FILLERS: usize = 3;
const MULTI_SLOT_PAYLOAD_LEN: usize = 3000;
const MULTI_SLOT_MAX_ATTEMPTS: u32 = 500;

/// How many `send_nowait` attempts `RetryAfterPoolPressure` needed for its
/// 3000-byte response, and the final outcome (`Err` if the fillers were
/// refused or the retry budget ran out).
static MULTI_SLOT_RETRY_ATTEMPTS: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
static MULTI_SLOT_RETRY_RESULT: std::sync::OnceLock<Result<(), String>> =
    std::sync::OnceLock::new();

/// With `send_pool(4, 1024)`: on the client's first byte, take three of the
/// four slots with 1024-byte fillers, then send a 3000-byte response that
/// needs three slots while only one is free. On io_uring the first attempt
/// is refused; the handler sleeps a tick (the fillers' CQEs release their
/// slots) and resends the same buffer. On mio sends are `Vec`-backed and
/// the first attempt succeeds.
struct RetryAfterPoolPressure;

impl AsyncEventHandler for RetryAfterPoolPressure {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| ParseResult::Consumed(data.len()))
                .await;

            let filler = [0xCDu8; MULTI_SLOT_FILLER_LEN];
            for _ in 0..MULTI_SLOT_FILLERS {
                if let Err(e) = conn.send_nowait(&filler) {
                    MULTI_SLOT_RETRY_ATTEMPTS.set(0).ok();
                    MULTI_SLOT_RETRY_RESULT
                        .set(Err(format!("one-slot filler send refused: {e}")))
                        .ok();
                    return;
                }
            }

            let payload = [0xABu8; MULTI_SLOT_PAYLOAD_LEN];
            let mut attempts = 0u32;
            let mut result: Result<(), String> = Err("retry budget exhausted".into());
            while attempts < MULTI_SLOT_MAX_ATTEMPTS {
                attempts += 1;
                match conn.send_nowait(&payload) {
                    Ok(()) => {
                        result = Ok(());
                        break;
                    }
                    Err(e) => {
                        // The contract under test: on `Err` nothing was
                        // queued, so waiting for in-flight sends to complete
                        // and resending the *same* buffer is safe.
                        result = Err(format!("attempt {attempts}: {e}"));
                        ringline::sleep(Duration::from_millis(1)).await;
                    }
                }
            }
            MULTI_SLOT_RETRY_ATTEMPTS.set(attempts).ok();
            MULTI_SLOT_RETRY_RESULT.set(result).ok();

            // Keep the connection open until the client hangs up, so its
            // "no extra bytes" read sees a timeout rather than a FIN.
            loop {
                let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        RetryAfterPoolPressure
    }
}

/// A multi-slot copied send refused for pool pressure must have committed
/// nothing, so resending the same buffer delivers it exactly once.
///
/// Why this could fail before the reservation (io_uring): the old
/// `DriverCtx::send` copied chunk by chunk, so with one free slot the first
/// attempt at the 3000-byte send queued its first 1024 bytes and then
/// returned `Err` on the second chunk. The retry then delivered all 3000, so
/// the client saw 3072 `0xCD` + 1024 `0xAB` + 3000 `0xAB`: the byte-pattern
/// checks below would pass, and the exactly-once check (nothing after the
/// expected total) would fail with 1024 surplus bytes. On mio the first
/// attempt succeeds and the test pins the contract without exercising it.
#[test]
fn multi_slot_send_retry_after_pool_pressure_delivers_exactly_once() {
    let config = test_config_builder()
        .send_pool(4, MULTI_SLOT_FILLER_LEN as u32)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<RetryAfterPoolPressure>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    let mut stream = connect_with_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stream.write_all(b"g").unwrap();
    stream.flush().unwrap();

    let expected = MULTI_SLOT_FILLERS * MULTI_SLOT_FILLER_LEN + MULTI_SLOT_PAYLOAD_LEN;
    let mut received = Vec::with_capacity(expected + 4096);
    let mut buf = [0u8; 4096];
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while received.len() < expected {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out with {} of {expected} bytes",
            received.len()
        );
        match stream.read(&mut buf) {
            Ok(0) => panic!("server closed after {} of {expected} bytes", received.len()),
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => panic!("read failed after {} bytes: {e}", received.len()),
        }
    }
    // A single read can overshoot `expected` only if more than one copy of
    // the response was sent.
    assert_eq!(
        received.len(),
        expected,
        "more than one copy of the response arrived"
    );
    let fillers_len = MULTI_SLOT_FILLERS * MULTI_SLOT_FILLER_LEN;
    assert!(
        received[..fillers_len].iter().all(|&b| b == 0xCD),
        "filler bytes corrupted"
    );
    assert!(
        received[fillers_len..].iter().all(|&b| b == 0xAB),
        "response bytes corrupted"
    );

    // Exactly once: nothing else may follow the response.
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    match stream.read(&mut buf) {
        Ok(0) => {}
        Ok(n) => {
            panic!("{n} surplus bytes after the response: the refused send had committed a prefix")
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Err(e) => panic!("unexpected read error after the response: {e}"),
    }

    let result = MULTI_SLOT_RETRY_RESULT
        .get()
        .expect("handler did not record a result");
    assert_eq!(result, &Ok(()), "response send did not succeed");
    let attempts = *MULTI_SLOT_RETRY_ATTEMPTS
        .get()
        .expect("handler did not record attempts");
    assert!(attempts >= 1);
    // On io_uring the pool really was three slots short at the first
    // attempt, so the retry path must have been exercised; on mio the
    // first attempt succeeds (Vec-backed sends, no pool admission).
    #[cfg(has_io_uring)]
    assert!(
        attempts > 1,
        "expected the first attempt to be refused for pool pressure, got {attempts} attempt(s)"
    );

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Scatter-gather send_parts test ──────────────────────────────────

#[cfg(has_io_uring)]
/// Handler that uses send_parts with multiple copy segments.
struct SendPartsHandler;

#[cfg(has_io_uring)]
impl AsyncEventHandler for SendPartsHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            // Build a scatter-gather send with 3 copy parts.
            let part1 = b"SCATTER";
            let part2 = b"-";
            let part3 = b"GATHER";
            match conn
                .send_parts()
                .build(|b| b.copy(part1).copy(part2).copy(part3).submit())
            {
                Ok(()) => {}
                Err(e) => {
                    let _ = conn.send_nowait(format!("ERR:{e}").as_bytes());
                }
            }
            ringline::sleep(Duration::from_secs(5)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SendPartsHandler
    }
}

#[cfg(has_io_uring)]
#[test]
fn async_send_parts_scatter_gather() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SendPartsHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    // Send trigger, then read the scatter-gather response.
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"go").unwrap();
    stream.flush().unwrap();

    let expected = b"SCATTER-GATHER";
    let mut buf = vec![0u8; expected.len()];
    let mut total = 0;
    while total < expected.len() {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("read error: {e}"),
        }
    }
    assert_eq!(
        &buf[..total],
        expected,
        "expected scatter-gather response, got: {}",
        String::from_utf8_lossy(&buf[..total])
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Outbound connect EOF delivery ───────────────────────────────────

static OUTBOUND_EOF_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
static OUTBOUND_EOF_RESULT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Client that connects outbound to a std TCP server, sends data, reads
/// echo, then waits for EOF. Exercises the outbound plaintext recv_mode fix.
struct OutboundEofClient;

impl AsyncEventHandler for OutboundEofClient {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *OUTBOUND_EOF_ADDR.get().expect("addr not set");
        Some(Box::pin(async move {
            let conn = match ringline::connect(server_addr).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    OUTBOUND_EOF_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            let (mut conn_tx, mut conn_rx) = conn.split();

            // Send data and read echo, with a timeout.
            let _ = conn_tx.send_nowait(b"hello");
            let mut echoed = Vec::new();
            let echo_fut = conn_rx.with_data(|data| {
                echoed.extend_from_slice(data);
                ParseResult::Consumed(data.len())
            });
            let n = match ringline::timeout(Duration::from_secs(5), echo_fut).await {
                Ok(n) => n,
                Err(_) => {
                    OUTBOUND_EOF_RESULT.set("ECHO_TIMEOUT".to_string()).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };
            if n == 0 || echoed != b"hello" {
                OUTBOUND_EOF_RESULT
                    .set(format!(
                        "ECHO_FAIL:n={n},data={}",
                        String::from_utf8_lossy(&echoed)
                    ))
                    .ok();
                ringline::request_shutdown().ok();
                return;
            }

            // Now wait for EOF — the std server thread closes after echoing.
            let eof_fut = conn_rx.with_data(|data| ParseResult::Consumed(data.len()));
            match ringline::timeout(Duration::from_secs(5), eof_fut).await {
                Ok(0) => {
                    OUTBOUND_EOF_RESULT.set("OK".to_string()).ok();
                }
                Ok(n) => {
                    OUTBOUND_EOF_RESULT.set(format!("UNEXPECTED:{n}")).ok();
                }
                Err(_) => {
                    OUTBOUND_EOF_RESULT.set("TIMEOUT".to_string()).ok();
                }
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        OutboundEofClient
    }
}

#[test]
fn async_outbound_connect_receives_eof() {
    // Start a simple std TCP echo-once server in a thread.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server_thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).unwrap();
        stream.write_all(&buf[..n]).unwrap();
        stream.flush().unwrap();
        // Close — this sends FIN to the client.
        drop(stream);
    });

    OUTBOUND_EOF_ADDR.set(addr).ok();

    let (_c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<OutboundEofClient>()
        .expect("client launch failed");

    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    server_thread.join().unwrap();

    let result = OUTBOUND_EOF_RESULT
        .get()
        .expect("on_start did not set result");
    assert_eq!(
        result, "OK",
        "expected EOF on outbound connect, got: {result}"
    );
}

// ── Buffer ring exhaustion stress test ──────────────────────────────

#[cfg(has_io_uring)]
#[test]
fn buffer_ring_exhaustion_recovers() {
    // Use a tiny buffer ring (4 buffers) to force ENOBUFS under
    // concurrent connection load, then verify all data echoes correctly.

    let config = test_config_builder()
        .recv_buffer(4, 4096)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    // Open 8 connections simultaneously and send data on all of them.
    let mut threads = Vec::new();
    for i in 0..8 {
        let addr = addr.clone();
        threads.push(std::thread::spawn(move || {
            let mut stream = TcpStream::connect(&addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            // Send a message identifying this connection.
            let msg = format!("connection-{i}-payload");
            stream.write_all(msg.as_bytes()).unwrap();
            stream.flush().unwrap();

            // Read back the echo.
            let mut buf = vec![0u8; msg.len()];
            let mut total = 0;
            while total < msg.len() {
                match stream.read(&mut buf[total..]) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => panic!("conn {i} read error: {e}"),
                }
            }
            assert_eq!(&buf[..total], msg.as_bytes(), "conn {i} echo mismatch");
        }));
    }

    for t in threads {
        t.join().expect("connection thread panicked");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Connect timeout test ────────────────────────────────────────────

static TIMEOUT_RESULT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

struct ConnectTimeoutClient;

impl AsyncEventHandler for ConnectTimeoutClient {
    fn on_accept(&self, _conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn std::future::Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            // Connect to a black-hole address with a 50ms timeout.
            // 192.0.2.1 is TEST-NET-1 (RFC 5737) — routable but unreachable.
            let addr: SocketAddr = "192.0.2.1:12345".parse().unwrap();
            // Submission and completion report through one error path (#528).
            match ringline::connect(addr)
                .timeout(std::time::Duration::from_millis(50))
                .await
            {
                Ok(_) => {
                    TIMEOUT_RESULT.set("UNEXPECTED_OK".into()).ok();
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::TimedOut {
                        TIMEOUT_RESULT.set("TIMED_OUT".into()).ok();
                    } else {
                        TIMEOUT_RESULT.set(format!("ERR:{e}")).ok();
                    }
                }
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        ConnectTimeoutClient
    }
}

#[test]
fn async_connect_timeout_fires() {
    let (_c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<ConnectTimeoutClient>()
        .expect("client launch failed");

    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    let result = TIMEOUT_RESULT.get().expect("on_start did not set result");
    // Accept either TimedOut or a connection error (some networks reject
    // immediately instead of black-holing).
    assert!(
        result == "TIMED_OUT" || result.starts_with("ERR:"),
        "expected timeout or connection error, got: {result}"
    );
}

// ── spawn_with_handle / JoinHandle tests ────────────────────────────

/// Send a trigger byte and read the full response (up to 256 bytes).
fn trigger_and_read(addr: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    let mut buf = vec![0u8; 256];
    let mut total = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }
    buf.truncate(total);
    buf
}

static JOIN_RESULT: AtomicU32 = AtomicU32::new(0);

/// Handler that uses spawn_with_handle to await a spawned task's result.
struct JoinHandleHandler;

impl AsyncEventHandler for JoinHandleHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            // Spawn a task that computes a value after a short sleep.
            let handle = ringline::spawn_with_handle(async {
                ringline::sleep(Duration::from_millis(10)).await;
                99u32
            })
            .unwrap();

            let value = handle.await;
            JOIN_RESULT.store(value, Ordering::SeqCst);
            let _ = conn.send_nowait(b"done");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        JoinHandleHandler
    }
}

#[test]
fn spawn_with_handle_awaits_result() {
    JOIN_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<JoinHandleHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"done");
    assert_eq!(JOIN_RESULT.load(Ordering::SeqCst), 99);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that spawns a task returning a value synchronously (no .await).
struct ImmediateJoinHandler;

static IMMEDIATE_RESULT: AtomicU32 = AtomicU32::new(0);

impl AsyncEventHandler for ImmediateJoinHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            // Task completes synchronously on first poll — result should
            // be available immediately when JoinHandle is next polled.
            let handle = ringline::spawn_with_handle(async { 42u32 }).unwrap();
            // Yield once so the child gets polled.
            ringline::sleep(Duration::from_millis(1)).await;
            let value = handle.await;
            IMMEDIATE_RESULT.store(value, Ordering::SeqCst);
            let _ = conn.send_nowait(b"ok");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ImmediateJoinHandler
    }
}

#[test]
fn spawn_with_handle_immediate_completion() {
    IMMEDIATE_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ImmediateJoinHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"ok");
    assert_eq!(IMMEDIATE_RESULT.load(Ordering::SeqCst), 42);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that drops the JoinHandle without awaiting — task should still run.
struct DetachHandler;

static DETACH_RAN: AtomicU32 = AtomicU32::new(0);

impl AsyncEventHandler for DetachHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            {
                let _handle = ringline::spawn_with_handle(async {
                    DETACH_RAN.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
                // _handle dropped here without await
            }

            // Give the detached task a tick to run.
            ringline::sleep(Duration::from_millis(20)).await;
            let _ = conn.send_nowait(b"ok");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        DetachHandler
    }
}

#[test]
fn spawn_with_handle_detach_on_drop() {
    DETACH_RAN.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<DetachHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"ok");
    assert!(DETACH_RAN.load(Ordering::SeqCst) >= 1);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that spawns a long-sleeping task and aborts it.
struct AbortHandler;

impl AsyncEventHandler for AbortHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let handle = ringline::spawn_with_handle(async {
                ringline::sleep(Duration::from_secs(60)).await;
                42u32
            })
            .unwrap();

            handle.abort();

            // Verify we can spawn another task (slot was freed).
            let ok = ringline::spawn(async {}).is_ok();
            let _ = conn.send_nowait(if ok { b"ok" as &[u8] } else { b"fail" });
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        AbortHandler
    }
}

#[test]
fn spawn_with_handle_abort() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AbortHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"ok");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Handler that spawns multiple tasks and awaits all of them.
struct MultiJoinHandler;

static MULTI_SUM: AtomicU32 = AtomicU32::new(0);

impl AsyncEventHandler for MultiJoinHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let h1 = ringline::spawn_with_handle(async { 10u32 }).unwrap();
            let h2 = ringline::spawn_with_handle(async { 20u32 }).unwrap();
            let h3 = ringline::spawn_with_handle(async { 30u32 }).unwrap();

            let (a, b) = ringline::join(h1, h2).await;
            let c = h3.await;
            MULTI_SUM.store(a + b + c, Ordering::SeqCst);
            let _ = conn.send_nowait(b"ok");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        MultiJoinHandler
    }
}

#[test]
fn spawn_with_handle_multiple_join() {
    MULTI_SUM.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<MultiJoinHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"ok");
    assert_eq!(MULTI_SUM.load(Ordering::SeqCst), 60);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── oneshot channel tests ───────────────────────────────────────────

static ONESHOT_RESULT: AtomicU32 = AtomicU32::new(0);

/// Spawn a task that sends a value on a oneshot, await it from the connection task.
struct OneshotHandler;

impl AsyncEventHandler for OneshotHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let (tx, rx) = ringline::oneshot::channel::<u32>();
            ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(10)).await;
                let _ = tx.send(77);
            })
            .unwrap();

            match rx.await {
                Ok(val) => ONESHOT_RESULT.store(val, Ordering::SeqCst),
                Err(_) => ONESHOT_RESULT.store(999, Ordering::SeqCst),
            }
            let _ = conn.send_nowait(b"done");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        OneshotHandler
    }
}

#[test]
fn oneshot_channel_async_wakeup() {
    ONESHOT_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<OneshotHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"done");
    assert_eq!(ONESHOT_RESULT.load(Ordering::SeqCst), 77);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Sender dropped without sending — receiver gets RecvError.
static ONESHOT_CLOSED: AtomicU32 = AtomicU32::new(0);

struct OneshotClosedHandler;

impl AsyncEventHandler for OneshotClosedHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let (tx, rx) = ringline::oneshot::channel::<u32>();
            ringline::spawn(async move {
                drop(tx); // Drop without sending.
            })
            .unwrap();

            // Give the spawned task a tick to run.
            ringline::sleep(Duration::from_millis(10)).await;
            match rx.await {
                Ok(_) => ONESHOT_CLOSED.store(0, Ordering::SeqCst),
                Err(_) => ONESHOT_CLOSED.store(1, Ordering::SeqCst),
            }
            let _ = conn.send_nowait(b"done");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        OneshotClosedHandler
    }
}

#[test]
fn oneshot_channel_sender_dropped() {
    ONESHOT_CLOSED.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<OneshotClosedHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"done");
    assert_eq!(ONESHOT_CLOSED.load(Ordering::SeqCst), 1);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── mpsc channel tests ──────────────────────────────────────────────

static MPSC_SUM: AtomicU32 = AtomicU32::new(0);

/// Multiple senders, single receiver via mpsc.
struct MpscHandler;

impl AsyncEventHandler for MpscHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let (tx, rx) = ringline::mpsc::channel::<u32>(16);

            // Spawn 3 senders.
            for i in 0..3 {
                let tx = tx.clone();
                ringline::spawn(async move {
                    ringline::sleep(Duration::from_millis(5)).await;
                    let _ = tx.try_send(10 * (i + 1));
                })
                .unwrap();
            }
            // Drop original sender so only the clones remain.
            drop(tx);

            // Receive until channel closes.
            let mut sum = 0u32;
            while let Some(val) = rx.recv().await {
                sum += val;
            }
            MPSC_SUM.store(sum, Ordering::SeqCst);
            let _ = conn.send_nowait(b"done");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        MpscHandler
    }
}

#[test]
fn mpsc_channel_multiple_senders() {
    MPSC_SUM.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<MpscHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"done");
    // 10 + 20 + 30 = 60
    assert_eq!(MPSC_SUM.load(Ordering::SeqCst), 60);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// async send with backpressure — channel capacity 1, multiple sends.
static MPSC_BACKPRESSURE: AtomicU32 = AtomicU32::new(0);

struct MpscBackpressureHandler;

impl AsyncEventHandler for MpscBackpressureHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let (tx, rx) = ringline::mpsc::channel::<u32>(1);

            // Sender task: send 5 values through a capacity-1 channel.
            ringline::spawn(async move {
                for i in 1..=5 {
                    tx.send(i).await.unwrap();
                }
            })
            .unwrap();

            // Receiver: drain all values.
            let mut sum = 0u32;
            while let Some(val) = rx.recv().await {
                sum += val;
            }
            MPSC_BACKPRESSURE.store(sum, Ordering::SeqCst);
            let _ = conn.send_nowait(b"done");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        MpscBackpressureHandler
    }
}

#[test]
fn mpsc_channel_backpressure() {
    MPSC_BACKPRESSURE.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<MpscBackpressureHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"done");
    // 1 + 2 + 3 + 4 + 5 = 15
    assert_eq!(MPSC_BACKPRESSURE.load(Ordering::SeqCst), 15);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── DNS resolver tests ──────────────────────────────────────────────

static RESOLVE_RESULT: AtomicU32 = AtomicU32::new(0);

/// Handler that resolves "localhost" and verifies the result.
struct ResolveHandler;

impl AsyncEventHandler for ResolveHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            match ringline::resolve("localhost", 80) {
                Ok(fut) => match fut.await {
                    Ok(addr) => {
                        if addr.ip().is_loopback() && addr.port() == 80 {
                            RESOLVE_RESULT.store(1, Ordering::SeqCst);
                        }
                        let _ = conn.send_nowait(b"ok");
                    }
                    Err(_) => {
                        let _ = conn.send_nowait(b"err");
                    }
                },
                Err(_) => {
                    let _ = conn.send_nowait(b"no-resolver");
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ResolveHandler
    }
}

#[test]
fn resolve_localhost() {
    RESOLVE_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ResolveHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"ok");
    assert_eq!(RESOLVE_RESULT.load(Ordering::SeqCst), 1);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Resolve an invalid hostname — should return an error.
static RESOLVE_ERR: AtomicU32 = AtomicU32::new(0);

struct ResolveErrorHandler;

impl AsyncEventHandler for ResolveErrorHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            match ringline::resolve("nonexistent.invalid", 80) {
                Ok(fut) => match fut.await {
                    Ok(_) => {
                        let _ = conn.send_nowait(b"unexpected-ok");
                    }
                    Err(_) => {
                        RESOLVE_ERR.store(1, Ordering::SeqCst);
                        let _ = conn.send_nowait(b"ok");
                    }
                },
                Err(_) => {
                    let _ = conn.send_nowait(b"no-resolver");
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ResolveErrorHandler
    }
}

#[test]
fn resolve_invalid_hostname() {
    // GitHub Actions macOS runners resolve `.invalid` hostnames: their
    // resolver returns an address for an RFC 6761 name that must never
    // resolve, so `resolve("nonexistent.invalid")` succeeds and the handler
    // replies "unexpected-ok" instead of taking the error path this test
    // asserts on. Skip only in that specific environment — the test still
    // runs on Linux CI (where `.invalid` correctly fails) and on local
    // macOS (normal resolvers return NXDOMAIN).
    if cfg!(target_os = "macos") && std::env::var_os("GITHUB_ACTIONS").is_some() {
        eprintln!(
            "skipping resolve_invalid_hostname: GitHub Actions macOS DNS \
             resolves .invalid hostnames"
        );
        return;
    }

    RESOLVE_ERR.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ResolveErrorHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"ok");
    assert_eq!(RESOLVE_ERR.load(Ordering::SeqCst), 1);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Resolver disabled (0 threads) — resolve() returns error.
struct ResolveDisabledHandler;

impl AsyncEventHandler for ResolveDisabledHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            match ringline::resolve("localhost", 80) {
                Ok(_) => {
                    let _ = conn.send_nowait(b"unexpected");
                }
                Err(_) => {
                    let _ = conn.send_nowait(b"ok");
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ResolveDisabledHandler
    }
}

#[test]
fn resolve_disabled_returns_error() {
    let config = test_config_builder()
        .resolver_threads(0)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ResolveDisabledHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"ok");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Unix domain socket tests ────────────────────────────────────────

/// Taking a worker out of the accept rotation actually stops it accepting.
///
/// io_uring only: steering applies to merged mode's `SO_REUSEPORT` group.
///
/// The unit tests in `reuseport_bpf` cover the instruction encoding; only a
/// real kernel can say whether the attached program does what it encodes.
#[cfg(has_io_uring)]
#[test]
fn an_excluded_worker_stops_receiving_connections() {
    use std::sync::Mutex;

    static SEEN: std::sync::OnceLock<Mutex<Vec<usize>>> = std::sync::OnceLock::new();

    const WORKERS: usize = 4;
    const EXCLUDED: usize = 2;
    const CONNS: usize = 40;

    struct Reporter {
        worker: usize,
    }
    impl AsyncEventHandler for Reporter {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            let worker = self.worker;
            async move {
                let (mut tx, mut rx) = conn.split();
                let _ = rx
                    .with_data(|data| {
                        if !data.is_empty() {
                            SEEN.get_or_init(Default::default)
                                .lock()
                                .unwrap()
                                .push(worker);
                        }
                        let _ = tx.send_nowait(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
            }
        }
        fn create_for_worker(id: usize) -> Self {
            Reporter { worker: id }
        }
    }

    let config = test_config_builder()
        .workers(WORKERS)
        .accept_mode(ringline::AcceptMode::Merged)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Reporter>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    shutdown
        .set_worker_accepting(EXCLUDED, false)
        .expect("steering should attach");

    // Only count connections made *after* the exclusion.
    SEEN.get_or_init(Default::default).lock().unwrap().clear();

    let mut held = Vec::with_capacity(CONNS);
    for i in 0..CONNS {
        let mut c = TcpStream::connect(&addr).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let payload = format!("excl-{i:02}");
        c.write_all(payload.as_bytes()).unwrap();
        c.flush().unwrap();
        let mut buf = vec![0u8; payload.len()];
        c.read_exact(&mut buf).unwrap();
        held.push(c);
    }

    let seen = SEEN.get().unwrap().lock().unwrap().clone();
    assert_eq!(seen.len(), CONNS, "every connection must still be served");

    // Zero, not merely "below its share". The kernel stops choosing the
    // excluded socket, and accept-time placement skips it too — without that
    // second half, taking a worker out of rotation drops its load and makes it
    // the *most* attractive handoff target, so tier 1 would put back exactly
    // what tier 2 took out.
    let on_excluded = seen.iter().filter(|&&w| w == EXCLUDED).count();
    assert_eq!(
        on_excluded, 0,
        "excluded worker {EXCLUDED} served {on_excluded} of {CONNS}; counts {seen:?}"
    );

    // And the rest actually carried the load, so this is not passing because
    // nothing was served at all.
    let others: std::collections::HashSet<usize> =
        seen.iter().copied().filter(|&w| w != EXCLUDED).collect();
    assert!(
        others.len() >= 2,
        "the remaining workers should share the load; saw {others:?}"
    );

    drop(held);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Merged accept mode actually accepts, on several workers, over one port.
///
/// io_uring only: merged mode needs multishot accept, which mio has no
/// equivalent for, so `AcceptMode::Merged` is ignored there.
///
/// Every other test runs the default `Pool` mode, so without this one the
/// whole merged path could be a no-op and the suite would not notice.
#[cfg(has_io_uring)]
#[test]
fn merged_accept_mode_serves_connections_across_workers() {
    static SERVED: AtomicU32 = AtomicU32::new(0);
    static SAW_PEER: AtomicU32 = AtomicU32::new(0);

    struct MergedEcho;
    impl AsyncEventHandler for MergedEcho {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                // Multishot accept carries no sockaddr; the runtime fills this
                // in with getpeername. If that were skipped the peer would come
                // back as the 0.0.0.0:0 placeholder.
                let real_peer = matches!(
                    conn.peer_addr(),
                    Some(ringline::PeerAddr::Tcp(a)) if a.port() != 0
                );
                let (mut tx, mut rx) = conn.split();
                let _ = rx
                    .with_data(|data| {
                        // Count only connections that carry data.
                        // `wait_for_server` connects and drops to probe
                        // reachability, and that probe is accepted like any
                        // other connection — counting it made this assert 17
                        // against 16 payloads.
                        if !data.is_empty() {
                            SERVED.fetch_add(1, Ordering::SeqCst);
                            if real_peer {
                                SAW_PEER.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        let _ = tx.send_nowait(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            MergedEcho
        }
    }

    SERVED.store(0, Ordering::SeqCst);
    SAW_PEER.store(0, Ordering::SeqCst);

    const CONNS: usize = 16;
    let config = test_config_builder()
        .workers(4)
        .accept_mode(ringline::AcceptMode::Merged)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<MergedEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    // Reachability is the real assertion here: in merged mode nothing listens
    // until every worker has reported ready and launch has called listen(2).
    wait_for_server(&addr);

    for i in 0..CONNS {
        let payload = format!("merged-{i:02}");
        let got = echo_round_trip(&addr, payload.as_bytes());
        assert_eq!(
            got,
            payload.as_bytes(),
            "connection {i} did not echo under merged accept"
        );
    }

    assert_eq!(
        SERVED.load(Ordering::SeqCst) as usize,
        CONNS,
        "every connection must reach a handler (0 = merged accept never armed)"
    );
    assert_eq!(
        SAW_PEER.load(Ordering::SeqCst) as usize,
        CONNS,
        "every connection must report a real peer port, not the placeholder"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// One process, a TCP listener and a Unix listener, one `on_accept`.
///
/// Before the listener list a runtime could bind exactly one socket —
/// `bind()` and `bind_unix()` overwrote each other — so this arrangement was
/// not expressible at all. Both halves matter: that each connection arrives
/// with the `ListenerId` of the listener that accepted it, and that ids follow
/// `bind()` call order.
#[test]
fn mixed_tcp_and_unix_listeners_are_distinguishable() {
    use std::os::unix::net::UnixStream;

    // Records the listener id each accepted connection reported, keyed by the
    // first byte the peer sends: 'T' from the TCP client, 'U' from the Unix one.
    static TCP_LISTENER: AtomicU32 = AtomicU32::new(u32::MAX);
    static UNIX_LISTENER: AtomicU32 = AtomicU32::new(u32::MAX);

    struct ListenerReporter;
    impl AsyncEventHandler for ListenerReporter {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let id = conn.listener().map(|l| l.index()).unwrap_or(u32::MAX);
                let (mut tx, mut rx) = conn.split();
                let _ = rx
                    .with_data(|data| {
                        match data.first() {
                            Some(b'T') => TCP_LISTENER.store(id, Ordering::SeqCst),
                            Some(b'U') => UNIX_LISTENER.store(id, Ordering::SeqCst),
                            _ => {}
                        }
                        let _ = tx.send_nowait(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            ListenerReporter
        }
    }

    TCP_LISTENER.store(u32::MAX, Ordering::SeqCst);
    UNIX_LISTENER.store(u32::MAX, Ordering::SeqCst);

    let sock_path =
        std::env::temp_dir().join(format!("ringline-mixed-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);

    // TCP binds first, so it is listener 0 and the Unix socket is listener 1.
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .bind_unix(&sock_path)
        .launch::<ListenerReporter>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    assert_eq!(
        shutdown.listener_count(),
        2,
        "both binds must produce listeners; one overwriting the other is the bug this fixes"
    );

    wait_for_server(&addr);
    for _ in 0..200 {
        if sock_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(sock_path.exists(), "unix socket file not created");

    let _ = echo_round_trip(&addr, b"T");

    let mut ustream = UnixStream::connect(&sock_path).unwrap();
    ustream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    ustream.write_all(b"U").unwrap();
    ustream.flush().unwrap();
    let mut buf = [0u8; 1];
    ustream.read_exact(&mut buf).unwrap();

    let tcp_id = TCP_LISTENER.load(Ordering::SeqCst);
    let unix_id = UNIX_LISTENER.load(Ordering::SeqCst);
    assert_eq!(
        tcp_id, 0,
        "TCP bound first, so it is listener 0 (u32::MAX = handler never ran)"
    );
    assert_eq!(
        unix_id, 1,
        "Unix bound second, so it is listener 1 (u32::MAX = handler never ran)"
    );

    // The whole point: the handler can tell them apart.
    assert_ne!(tcp_id, unix_id);

    // The ids index the right listeners: only the TCP one has an address, and
    // `bound_addrs()` keeps Unix listeners as `None` so positions stay aligned
    // with `ListenerId`.
    let addrs = shutdown.bound_addrs();
    assert_eq!(addrs.len(), 2);
    assert_eq!(
        addrs[tcp_id as usize].map(|a| a.to_string()),
        Some(addr.clone()),
        "the TCP listener's id should index its own bound address"
    );
    assert!(
        addrs[unix_id as usize].is_none(),
        "a Unix listener has no SocketAddr, but still holds its slot"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    let _ = std::fs::remove_file(&sock_path);
}

/// UDS echo server: bind_unix, connect via std UnixStream, echo round trip.
#[test]
fn unix_socket_echo() {
    use std::os::unix::net::UnixStream;

    let dir = std::env::temp_dir();
    let sock_path = dir.join(format!("ringline-test-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind_unix(&sock_path)
        .launch::<AsyncEcho>()
        .expect("launch failed");

    // Wait for the socket file to appear.
    for _ in 0..200 {
        if sock_path.exists() {
            std::thread::sleep(Duration::from_millis(10));
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(sock_path.exists(), "socket file not created");

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let msg = b"hello unix";
    stream.write_all(msg).unwrap();
    stream.flush().unwrap();

    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(buf, msg);

    // Multi-round trip.
    for i in 0..5 {
        let payload = format!("uds-msg-{i}");
        stream.write_all(payload.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, payload.as_bytes());
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    let _ = std::fs::remove_file(&sock_path);
}

/// peer_addr reports `Unix` for a connection accepted on a Unix listener.
///
/// Regression: the acceptor substituted a `SocketAddr` of `0.0.0.0:0` for
/// Unix accepts (`accept4` fills no usable one) and the accept path wrapped
/// whatever arrived in `PeerAddr::Tcp`, so an accepted UDS connection
/// reported `Tcp(0.0.0.0:0)`. `PeerAddr::Unix` was only ever produced for
/// *outbound* `connect_unix`.
#[test]
fn peer_addr_unix_regression() {
    use std::os::unix::net::UnixStream;

    // 0 = never ran, 1 = Unix (correct), 2 = anything else.
    static UNIX_PEER: AtomicU32 = AtomicU32::new(0);

    struct UnixPeerHandler;
    impl AsyncEventHandler for UnixPeerHandler {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let (mut tx, mut rx) = conn.split();
                match tx.peer_addr() {
                    Some(ringline::PeerAddr::Unix(_)) => UNIX_PEER.store(1, Ordering::SeqCst),
                    _ => UNIX_PEER.store(2, Ordering::SeqCst),
                }
                let _ = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            UnixPeerHandler
        }
    }

    UNIX_PEER.store(0, Ordering::SeqCst);
    let dir = std::env::temp_dir();
    let sock_path = dir.join(format!("ringline-peeraddr-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind_unix(&sock_path)
        .launch::<UnixPeerHandler>()
        .expect("launch failed");

    for _ in 0..200 {
        if sock_path.exists() {
            std::thread::sleep(Duration::from_millis(10));
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(sock_path.exists(), "socket file not created");

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).unwrap();

    assert_eq!(
        UNIX_PEER.load(Ordering::SeqCst),
        1,
        "accepted UDS connection did not report PeerAddr::Unix (0 = handler never ran)"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    let _ = std::fs::remove_file(&sock_path);
}

/// peer_addr returns PeerAddr::Tcp for TCP connections (regression).
#[test]
fn peer_addr_tcp_regression() {
    static TCP_PEER: AtomicU32 = AtomicU32::new(0);

    struct PeerAddrHandler;
    impl AsyncEventHandler for PeerAddrHandler {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let (mut tx, mut rx) = conn.split();
                if let Some(ringline::PeerAddr::Tcp(_)) = tx.peer_addr() {
                    TCP_PEER.store(1, Ordering::SeqCst);
                }
                let _ = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            PeerAddrHandler
        }
    }

    TCP_PEER.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<PeerAddrHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);
    let _ = echo_round_trip(&addr, b"x");
    assert_eq!(TCP_PEER.load(Ordering::SeqCst), 1);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── CancellationToken tests ─────────────────────────────────────────

static CANCEL_RESULT: AtomicU32 = AtomicU32::new(0);

/// Cancellation token interrupts a long-running task via select.
struct CancellationHandler;

impl AsyncEventHandler for CancellationHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let token = ringline::CancellationToken::new();
            let child = token.child_token();

            // Spawn a task that waits for cancellation.
            let handle = ringline::spawn_with_handle(async move {
                child.cancelled().await;
                42u32
            })
            .unwrap();

            // Cancel after a short delay.
            ringline::sleep(Duration::from_millis(10)).await;
            token.cancel();

            // The spawned task should now complete.
            let val = handle.await;
            CANCEL_RESULT.store(val, Ordering::SeqCst);
            let _ = conn.send_nowait(b"done");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        CancellationHandler
    }
}

#[test]
fn cancellation_token_wakes_task() {
    CANCEL_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<CancellationHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"done");
    assert_eq!(CANCEL_RESULT.load(Ordering::SeqCst), 42);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Select between data and cancellation — cancellation wins.
static SELECT_CANCEL: AtomicU32 = AtomicU32::new(0);

struct SelectCancelHandler;

impl AsyncEventHandler for SelectCancelHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let token = ringline::CancellationToken::new();

            // Cancel immediately — the select should pick cancellation
            // over a long sleep.
            token.cancel();

            let result =
                ringline::select(ringline::sleep(Duration::from_secs(60)), token.cancelled()).await;

            match result {
                ringline::Either::Right(()) => SELECT_CANCEL.store(1, Ordering::SeqCst),
                _ => SELECT_CANCEL.store(99, Ordering::SeqCst),
            }
            let _ = conn.send_nowait(b"done");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SelectCancelHandler
    }
}

#[test]
fn cancellation_token_with_select() {
    SELECT_CANCEL.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SelectCancelHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let got = trigger_and_read(&addr);
    assert_eq!(&got, b"done");
    assert_eq!(SELECT_CANCEL.load(Ordering::SeqCst), 1);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Zero-copy forward tests ────────────────────────────────────────
//
// These tests exercise the forward_recv_buf path, which sends directly
// from the kernel recv buffer without copying into the send pool.

struct ForwardEcho;

impl AsyncEventHandler for ForwardEcho {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        if let Err(e) = tx.forward_recv_buf(data) {
                            eprintln!("echo: forward_recv_buf failed: {e}");
                            return ParseResult::NeedMore;
                        }
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
        ForwardEcho
    }
}

#[test]
fn forward_echo_small_message() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ForwardEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let msg = b"Hello, zero-copy forward!";
    let response = echo_round_trip(&addr, msg);
    assert_eq!(response, msg);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn forward_echo_large_message() {
    let config = test_config_builder()
        .recv_buffer(64, 32768)
        .send_pool(64, 32768)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ForwardEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // 32KB — exercises the full zero-copy recv + forward path.
    let msg: Vec<u8> = (0..32768).map(|i| (i % 256) as u8).collect();
    let response = echo_round_trip(&addr, &msg);
    assert_eq!(response, msg);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn forward_echo_message_larger_than_buffer() {
    // Buffer is 4KB but message is 8KB — forces the accumulator path, where
    // forward_recv_buf detaches the accumulator and sends it under a guard
    // rather than copying it into the send pool (#397).
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ForwardEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let msg: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    let response = echo_round_trip(&addr, &msg);
    assert_eq!(response, msg);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn forward_echo_chunked_message_then_more_traffic() {
    // The accumulator-backed forward detaches the accumulator instead of
    // copying it (#397), so the delivery path must advance by what the closure
    // consumed *minus* what the forward already removed. Get that wrong in
    // either direction and this test fails rather than merely running slower:
    // over-advancing panics or drops bytes, under-advancing re-forwards them
    // and corrupts every message after the first.
    //
    // The first message is written in chunks with gaps so it lands across
    // several recv completions (the accumulator path). The two that follow
    // then have to arrive intact on the same connection.

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ForwardEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.set_nodelay(true).unwrap();

    let first: Vec<u8> = (0..24576).map(|i| (i % 251) as u8).collect();
    for chunk in first.chunks(3000) {
        stream.write_all(chunk).unwrap();
        stream.flush().unwrap();
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut echoed = vec![0u8; first.len()];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, first, "chunked message came back altered");

    // Anything still mis-accounted in the accumulator shows up here.
    for round in 0..2u8 {
        let msg: Vec<u8> = (0..4096)
            .map(|i| ((i + round as usize) % 251) as u8)
            .collect();
        stream.write_all(&msg).unwrap();
        stream.flush().unwrap();
        let mut back = vec![0u8; msg.len()];
        stream.read_exact(&mut back).unwrap();
        assert_eq!(
            back, msg,
            "message {round} after a chunked forward came back altered"
        );
    }

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn forward_echo_multiple_connections() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ForwardEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let mut join_handles = Vec::new();
    for conn_id in 0..10u8 {
        let addr = addr.clone();
        join_handles.push(std::thread::spawn(move || {
            let mut stream = TcpStream::connect(&addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.set_nodelay(true).unwrap();

            for round in 0..20u8 {
                let msg = vec![conn_id ^ round; 64];
                stream.write_all(&msg).unwrap();

                let mut buf = vec![0u8; 64];
                let mut total = 0;
                while total < 64 {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) => panic!("unexpected EOF"),
                        Ok(n) => total += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => panic!("read error: {e}"),
                    }
                }
                assert_eq!(buf, msg, "data mismatch conn={conn_id} round={round}");
            }
        }));
    }

    for h in join_handles {
        h.join().unwrap();
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn forward_echo_sequential_sends() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ForwardEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Many sequential round-trips on one connection to stress the
    // pending recv buf → replenish → reuse cycle.
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.set_nodelay(true).unwrap();

    for i in 0..500u16 {
        let msg = format!("msg-{i:04}");
        stream.write_all(msg.as_bytes()).unwrap();

        let mut buf = vec![0u8; msg.len()];
        let mut total = 0;
        while total < msg.len() {
            match stream.read(&mut buf[total..]) {
                Ok(0) => panic!("unexpected EOF at msg {i}"),
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("read error at msg {i}: {e}"),
            }
        }
        assert_eq!(buf, msg.as_bytes(), "data mismatch at msg {i}");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Connection-task panic recovery ─────────────────────────────────────

/// Handler that panics if any received data starts with `die`, otherwise
/// echoes. Lets one test run both paths against the same worker.
struct PanickingThenEcho;

#[allow(clippy::manual_async_fn)]
impl AsyncEventHandler for PanickingThenEcho {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        if data.starts_with(b"die") {
                            panic!("intentional panic in connection task");
                        }
                        let _ = tx.send_nowait(data);
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
        PanickingThenEcho
    }
}

#[test]
fn connection_task_panic_does_not_kill_worker() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<PanickingThenEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Connection 1: trigger panic. Connection should be torn down; we
    // expect the read side to see EOF.
    {
        let mut s = TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(b"die-now").unwrap();
        let mut buf = [0u8; 16];
        // The worker should close us; read returns 0 (EOF) or an error.
        let _ = s.read(&mut buf);
    }

    // Connection 2: must succeed — proves the worker is still alive.
    {
        let mut s = TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(b"hello").unwrap();
        let mut buf = vec![0u8; 5];
        let mut total = 0;
        while total < 5 {
            match s.read(&mut buf[total..]) {
                Ok(0) => panic!("worker died after panic — second connection got EOF"),
                Ok(n) => total += n,
                Err(e) => panic!("worker died after panic: {e}"),
            }
        }
        assert_eq!(&buf, b"hello");
    }

    shutdown.shutdown();
    for h in handles {
        // The worker should exit cleanly; the panic was caught.
        let _ = h.join();
    }
}

// ── with_data_result ──────────────────────────────────────────────

/// 0 = not yet observed; 1 = Err(ConnectionReset|ConnectionAborted);
/// 2 = Err(other); 3 = Ok(0).
static WITH_DATA_RESULT_OUTCOME: AtomicU32 = AtomicU32::new(0);

/// Incremented when `WithDataResultHandler::on_accept` starts, so a test can
/// wait for the server side to exist before doing anything to the socket.
static WITH_DATA_RESULT_ACCEPTED: AtomicU32 = AtomicU32::new(0);

struct WithDataResultHandler;

impl AsyncEventHandler for WithDataResultHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            WITH_DATA_RESULT_ACCEPTED.fetch_add(1, Ordering::AcqRel);
            loop {
                let outcome = match conn
                    .with_data_result(|data| ParseResult::Consumed(data.len()))
                    .await
                {
                    Ok(0) => 3,
                    Ok(_) => continue,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        1
                    }
                    Err(_) => 2,
                };
                WITH_DATA_RESULT_OUTCOME.store(outcome, Ordering::Release);
                break;
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        WithDataResultHandler
    }
}

fn wait_for_with_data_result_outcome() -> u32 {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while WITH_DATA_RESULT_OUTCOME.load(Ordering::Acquire) == 0
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    WITH_DATA_RESULT_OUTCOME.load(Ordering::Acquire)
}

fn wait_for_with_data_result_accept(expected: u32) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while WITH_DATA_RESULT_ACCEPTED.load(Ordering::Acquire) < expected
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        WITH_DATA_RESULT_ACCEPTED.load(Ordering::Acquire) >= expected,
        "server did not accept the connection"
    );
}

/// Connect with retry until the server is accepting. Used instead of
/// `wait_for_server`, whose probe connection would be accepted by the
/// handler and would store an outcome of its own, so a test using it could
/// pass without ever exercising the real connection.
fn connect_with_retry(addr: &str) -> TcpStream {
    (0..200)
        .find_map(|_| match TcpStream::connect(addr) {
            Ok(stream) => Some(stream),
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
                None
            }
        })
        .expect("server did not accept connection")
}

/// Serialises the `with_data_result` tests, which share the outcome cell.
static WITH_DATA_RESULT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn with_data_result_returns_ok_zero_on_clean_close() {
    let _guard = WITH_DATA_RESULT_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    WITH_DATA_RESULT_OUTCOME.store(0, Ordering::Release);
    WITH_DATA_RESULT_ACCEPTED.store(0, Ordering::Release);
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<WithDataResultHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    let mut stream = connect_with_retry(&addr);
    wait_for_with_data_result_accept(1);
    stream.write_all(b"hello").unwrap();
    drop(stream); // orderly FIN

    assert_eq!(
        wait_for_with_data_result_outcome(),
        3,
        "clean close must be Ok(0)"
    );

    shutdown.shutdown();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
}

#[test]
fn with_data_result_surfaces_tcp_reset() {
    use std::os::fd::AsRawFd;

    let _guard = WITH_DATA_RESULT_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    WITH_DATA_RESULT_OUTCOME.store(0, Ordering::Release);
    WITH_DATA_RESULT_ACCEPTED.store(0, Ordering::Release);
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<WithDataResultHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    let stream = connect_with_retry(&addr);
    wait_for_with_data_result_accept(1);

    // SO_LINGER with a zero timeout turns close() into an RST instead of a FIN.
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_LINGER) failed");
    drop(stream);

    assert_eq!(
        wait_for_with_data_result_outcome(),
        1,
        "an RST must surface as Err(ConnectionReset|ConnectionAborted)"
    );

    shutdown.shutdown();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
}

// ── Close lifecycle (#368) ────────────────────────────────────────

/// Echo handler that returns as soon as recv reports EOF or an error.
struct EchoUntilEof;

impl AsyncEventHandler for EchoUntilEof {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
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
        EchoUntilEof
    }
}

/// Like `EchoUntilEof`, but calls `conn.close()` after EOF before returning.
struct EchoThenClose;

impl AsyncEventHandler for EchoThenClose {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    tx.close();
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        EchoThenClose
    }
}

/// Two connection slots, one worker.
fn two_slot_config() -> Config {
    test_config_builder()
        .max_connections(2)
        .build()
        .expect("valid config")
}

/// How the client ends each connection in `assert_sequential_connections`.
#[derive(Clone, Copy)]
enum ClientClose {
    /// Orderly FIN: drop the stream.
    Fin,
    /// RST: set `SO_LINGER 0`, then drop.
    Reset,
}

fn set_linger_zero(stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_LINGER) failed");
}

/// Open `count` connections one after another against a two-slot server,
/// echo one message on each, and close from the client side. Every
/// connection must echo: a server that leaks the slot of a peer-closed
/// connection refuses the third one.
fn assert_sequential_connections<H: AsyncEventHandler>(count: usize, close: ClientClose) {
    let (shutdown, handles) = RinglineBuilder::new(two_slot_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    let mut echoed = 0;
    for i in 0..count {
        // Retry the whole connect+echo until the deadline: a slot released a
        // few milliseconds late is not a leak, a slot never released is.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut last_err = None;
        let stream: Option<TcpStream> = loop {
            let mut stream = connect_with_retry(&addr);
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            stream.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            match stream.read_exact(&mut buf) {
                Ok(()) => {
                    assert_eq!(&buf, b"ping");
                    echoed += 1;
                    break Some(stream);
                }
                Err(e) => {
                    last_err = Some(e);
                    drop(stream);
                    if std::time::Instant::now() >= deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        };
        match stream {
            Some(stream) => {
                if let ClientClose::Reset = close {
                    set_linger_zero(&stream);
                }
                drop(stream);
            }
            None => {
                eprintln!("connection {i}: echo never succeeded before the deadline: {last_err:?}")
            }
        }
        // Give the server an iteration to observe the close and tear down.
        std::thread::sleep(Duration::from_millis(20));
    }

    shutdown.shutdown();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    assert_eq!(
        echoed, count,
        "only {echoed} of {count} sequential connections echoed"
    );
}

#[test]
fn peer_fin_releases_the_slot() {
    assert_sequential_connections::<EchoUntilEof>(6, ClientClose::Fin);
}

#[test]
fn peer_reset_releases_the_slot() {
    assert_sequential_connections::<EchoUntilEof>(6, ClientClose::Reset);
}

#[test]
fn close_after_eof_releases_the_slot() {
    assert_sequential_connections::<EchoThenClose>(6, ClientClose::Fin);
}

/// Handler that reads until EOF, then sends a large response and returns.
struct RespondAfterEof;

const RESPONSE_AFTER_EOF_LEN: usize = 4 * 1024 * 1024;

/// Outcome of the post-EOF send in `RespondAfterEof`: 0 = not run,
/// 1 = `send()` accepted the buffer and the await completed, 2 = `send()`
/// refused it (e.g. copy pool exhausted), 3 = the await returned an error.
static RESPONSE_AFTER_EOF_SEND: AtomicU32 = AtomicU32::new(0);

/// `test_config()` with an 8 MiB copy pool: the io_uring `send()` takes one
/// pool slot per 16 KiB chunk synchronously, so a 4 MiB send needs 256 slots
/// up front (the default 64-slot test pool fails at chunk 65).
fn large_send_config() -> Config {
    test_config_builder()
        .send_pool(512, 16384)
        .build()
        .expect("valid config")
}

impl AsyncEventHandler for RespondAfterEof {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| ParseResult::Consumed(data.len()))
                    .await;
                if n == 0 {
                    break;
                }
            }
            let response = vec![0xA5u8; RESPONSE_AFTER_EOF_LEN];
            let outcome = match conn.send(&response) {
                Ok(fut) => match fut.await {
                    Ok(_) => 1,
                    Err(_) => 3,
                },
                Err(_) => 2,
            };
            RESPONSE_AFTER_EOF_SEND.store(outcome, Ordering::Release);
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        RespondAfterEof
    }
}

/// A response sent after the peer's FIN must still be delivered in full:
/// teardown waits for queued sends to drain (on mio, `finish_close` is
/// deferred; on io_uring the Close SQE already is).
#[test]
fn response_after_peer_fin_is_delivered() {
    RESPONSE_AFTER_EOF_SEND.store(0, Ordering::Release);
    let (shutdown, handles) = RinglineBuilder::new(large_send_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<RespondAfterEof>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    let mut stream = connect_with_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(b"request").unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();

    // Let the server's writev hit WouldBlock at least once so the retained
    // pending_closes path is exercised.
    std::thread::sleep(Duration::from_millis(100));

    let mut received = Vec::with_capacity(RESPONSE_AFTER_EOF_LEN);
    stream
        .read_to_end(&mut received)
        .expect("read response after half-close");
    assert_eq!(
        received.len(),
        RESPONSE_AFTER_EOF_LEN,
        "response truncated: teardown ran before the send drained"
    );
    assert!(received.iter().all(|&b| b == 0xA5));
    assert_eq!(
        RESPONSE_AFTER_EOF_SEND.load(Ordering::Acquire),
        1,
        "post-EOF send was refused or errored"
    );

    shutdown.shutdown();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
}

/// Counts `on_tick` calls, i.e. event-loop iterations, while a response
/// drains to a peer that half-closed and is slow to read. A loop that
/// re-reports the peer's EOF every iteration spins at hundreds of
/// thousands of iterations per second; a healthy loop blocks in poll and
/// ticks at most every few milliseconds.
static DRAIN_TICKS: AtomicU32 = AtomicU32::new(0);

struct RespondAfterEofCountingTicks;

impl AsyncEventHandler for RespondAfterEofCountingTicks {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| ParseResult::Consumed(data.len()))
                    .await;
                if n == 0 {
                    break;
                }
            }
            let response = vec![0x5Au8; RESPONSE_AFTER_EOF_LEN];
            if let Ok(fut) = conn.send(&response) {
                let _ = fut.await;
            }
        }
    }
    fn on_tick(&mut self, _ctx: &mut ringline::DriverCtx<'_>) {
        DRAIN_TICKS.fetch_add(1, Ordering::Relaxed);
    }
    fn create_for_worker(_id: usize) -> Self {
        RespondAfterEofCountingTicks
    }
}

#[test]
fn deferred_close_does_not_spin_on_half_closed_peer() {
    DRAIN_TICKS.store(0, Ordering::Relaxed);
    let (shutdown, handles) = RinglineBuilder::new(large_send_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<RespondAfterEofCountingTicks>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    let mut stream = connect_with_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Baseline: the loop's own cadence with this connection open and idle.
    // It is backend- and host-dependent (mio blocks in poll with a 10 ms cap:
    // tens of ticks; io_uring arms a tick timeout and ran ~5,300 ticks per
    // 500 ms on the validation host), so the spin check below is relative to
    // it rather than a fixed number.
    std::thread::sleep(Duration::from_millis(100));
    let base_before = DRAIN_TICKS.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(500));
    let baseline = DRAIN_TICKS.load(Ordering::Relaxed) - base_before;

    stream.write_all(b"request").unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();

    // Let the server queue the response and hit WouldBlock, then measure
    // the loop's cadence while the peer does not read.
    std::thread::sleep(Duration::from_millis(200));
    let before = DRAIN_TICKS.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(500));
    let ticks = DRAIN_TICKS.load(Ordering::Relaxed) - before;

    let mut received = Vec::with_capacity(RESPONSE_AFTER_EOF_LEN);
    stream
        .read_to_end(&mut received)
        .expect("read response after half-close");
    assert_eq!(received.len(), RESPONSE_AFTER_EOF_LEN);

    shutdown.shutdown();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    // A spinning loop re-reports the peer's EOF every iteration and did
    // ~270k ticks in 500 ms when this bug was live — over 500x the idle
    // cadence. A healthy loop with sends outstanding runs faster than idle
    // but nowhere near that: io_uring's send-completion and flush-deadline
    // traffic put it at ~11x idle on the validation host (473 idle vs 5,317
    // retained per 500 ms), mio stays at its 10 ms poll cap. Fifty times
    // idle separates the two by an order of magnitude either way; the floor
    // keeps a near-zero baseline from making the bound too tight.
    let bound = baseline.max(200) * 50;
    assert!(
        ticks < bound,
        "event loop spun while a close was deferred: {ticks} ticks in 500 ms \
         (idle baseline {baseline}, bound {bound})"
    );
}

// ── Write half (series PR 3) ─────────────────────────────────────

/// 0 = not started; 1 = response queued and shutdown_write called;
/// 2 = read after the half-close returned EOF (peer closed).
static HALF_CLOSE_PROGRESS: AtomicU32 = AtomicU32::new(0);

const HALF_CLOSE_RESPONSE_LEN: usize = 4 * 1024 * 1024;

/// Reads one request, queues a response larger than any socket buffer,
/// half-closes, then keeps reading until the peer closes.
struct RespondThenHalfClose;

impl AsyncEventHandler for RespondThenHalfClose {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }
            let response = vec![b'x'; HALF_CLOSE_RESPONSE_LEN];
            conn.send_nowait(&response).expect("queue response");
            conn.shutdown_write();
            HALF_CLOSE_PROGRESS.store(1, Ordering::Release);
            loop {
                let n = conn
                    .with_data(|data| ParseResult::Consumed(data.len()))
                    .await;
                if n == 0 {
                    break;
                }
            }
            HALF_CLOSE_PROGRESS.store(2, Ordering::Release);
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        RespondThenHalfClose
    }
}

/// `shutdown_write` with sends still queued must let them drain before the
/// FIN: the peer receives the whole response and only then sees EOF. mio
/// used to write what fit, drop the rest, and FIN immediately.
#[test]
fn half_close_waits_for_queued_sends_to_drain() {
    HALF_CLOSE_PROGRESS.store(0, Ordering::Release);
    let (shutdown, handles) = RinglineBuilder::new(large_send_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<RespondThenHalfClose>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    let mut stream = connect_with_retry(&addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(b"go").unwrap();

    // Do not read until the handler has queued the whole response and
    // called shutdown_write: with the reader racing the writer, a fast
    // loopback reader can keep the socket buffer from ever filling and the
    // old truncating drain would sometimes get away with it.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while HALF_CLOSE_PROGRESS.load(Ordering::Acquire) != 1 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        HALF_CLOSE_PROGRESS.load(Ordering::Acquire),
        1,
        "handler did not half-close"
    );

    let mut received = Vec::with_capacity(HALF_CLOSE_RESPONSE_LEN);
    stream
        .read_to_end(&mut received)
        .expect("read to the server's FIN");
    assert_eq!(
        received.len(),
        HALF_CLOSE_RESPONSE_LEN,
        "response truncated: FIN was sent before the queue drained"
    );
    assert!(received.iter().all(|&b| b == b'x'));
    assert_eq!(HALF_CLOSE_PROGRESS.load(Ordering::Acquire), 1);

    // Our FIN: the handler's post-half-close read must see EOF and finish.
    drop(stream);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while HALF_CLOSE_PROGRESS.load(Ordering::Acquire) != 2 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        HALF_CLOSE_PROGRESS.load(Ordering::Acquire),
        2,
        "handler did not see the peer's EOF after half-close"
    );

    shutdown.shutdown();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
}

// ── Cross-connection forward (proxy) ────────────────────────────────

/// A length-prefixed proxy built on `forward_to_conn`: read a 4-byte
/// big-endian length, hand exactly that many bytes to the backend without
/// copying them out of the runtime, then hand the backend's reply back the
/// same way.
///
/// The point of running it on both backends is that the same handler has to
/// behave identically on each — zero-copy through held provided buffers on
/// io_uring, a queued copy on mio. It also pins the case the API exists for:
/// the length comes from a header, so bytes of the body have already landed in
/// the accumulator by the time the forward starts, and they must come out
/// first.
struct ForwardToConnProxy {
    backend_addr: SocketAddr,
}

static PROXY_BACKEND_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for ForwardToConnProxy {
    fn on_accept(&self, client: Connection) -> impl Future<Output = ()> + 'static {
        let backend_addr = self.backend_addr;
        async move {
            // Each direction forwards into the *other* connection's write
            // half, borrowed for the duration. That borrow is what makes a
            // proxy safe to express: nothing else can send to a socket while a
            // forward is writing to it.
            let (mut client_tx, mut client_rx) = client.split();
            let backend = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(_) => return,
            };
            let (mut backend_tx, mut backend_rx) = backend.split();

            loop {
                let mut hdr = [0u8; 4];
                let n = client_rx
                    .with_data(|data| {
                        if data.len() < 4 {
                            return ParseResult::NeedMore;
                        }
                        hdr.copy_from_slice(&data[..4]);
                        ParseResult::Consumed(4)
                    })
                    .await;
                if n == 0 {
                    break;
                }
                let len = u32::from_be_bytes(hdr) as usize;

                match client_rx.forward_to_conn(&mut backend_tx, len).await {
                    Ok(f) if f == len => {}
                    other => {
                        eprintln!("proxy: client->backend forward {other:?}, wanted {len}");
                        break;
                    }
                }
                match backend_rx.forward_to_conn(&mut client_tx, len).await {
                    Ok(f) if f == len => {}
                    other => {
                        eprintln!("proxy: backend->client forward {other:?}, wanted {len}");
                        break;
                    }
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        ForwardToConnProxy {
            backend_addr: *PROXY_BACKEND_ADDR.get().expect("backend addr not set"),
        }
    }
}

/// Send one length-prefixed request and read exactly `payload.len()` bytes back.
///
/// `split` sends the header on its own and pauses before the body. That is the
/// case where the forward is already armed when the bytes arrive; sending the
/// whole request at once instead usually lands every byte in the accumulator
/// before the handler parses the header, which exercises the other route in.
/// Both have to work, so the test drives both.
fn proxy_round_trip(stream: &mut TcpStream, payload: &[u8], split: bool, case: &str) -> Vec<u8> {
    let header = (payload.len() as u32).to_be_bytes();
    if split {
        stream.write_all(&header).unwrap();
        stream.flush().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        stream.write_all(payload).unwrap();
    } else {
        let mut req = Vec::with_capacity(4 + payload.len());
        req.extend_from_slice(&header);
        req.extend_from_slice(payload);
        stream.write_all(&req).unwrap();
    }
    stream.flush().unwrap();

    let mut buf = vec![0u8; payload.len()];
    if let Err(e) = stream.read_exact(&mut buf) {
        panic!("no proxy reply for {case}: {e}");
    }
    buf
}

/// `forward_to_conn` in both directions, several sizes, on one connection.
///
/// Sizes straddle the interesting boundaries: under one read, over the 4 KiB
/// recv buffer, over the 16 KiB send-pool slot, and large enough (256 KiB) to
/// span many reads.
///
/// Run twice against the same backend. The second proxy sets
/// `forward_hold_cap(1)`, which is what actually exercises backpressure: on
/// mio the source stops reading after a single queued send and only resumes
/// when the sink drains, and on io_uring it holds one provided buffer at a
/// time. At the default cap a localhost sink never backs up, so the resume
/// path would go untested.
#[test]
fn forward_to_conn_proxies_both_directions() {
    let (backend_shutdown, backend_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    let backend_addr = backend_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();
    wait_for_server(&backend_addr);

    PROXY_BACKEND_ADDR
        .set(backend_addr.parse().unwrap())
        .expect("only one test may install the proxy backend address");

    for hold_cap in [64usize, 1] {
        let config = test_config_builder()
            .forward_hold_cap(hold_cap)
            .build()
            .expect("valid config");
        let (proxy_shutdown, proxy_handles) = RinglineBuilder::new(config)
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<ForwardToConnProxy>()
            .expect("proxy launch failed");
        let proxy_addr = proxy_shutdown
            .bound_addr()
            .expect("bound address")
            .to_string();
        wait_for_server(&proxy_addr);

        let mut stream = TcpStream::connect(&proxy_addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();

        for split in [false, true] {
            for (i, size) in [7usize, 1024, 8192, 65536, 262144].into_iter().enumerate() {
                let payload: Vec<u8> = (0..size).map(|b| (b.wrapping_mul(31) + i) as u8).collect();
                let case = format!("{size}B, cap {hold_cap}, split {split}");
                eprintln!("proxy case: {case}");
                let got = proxy_round_trip(&mut stream, &payload, split, &case);
                assert_eq!(
                    got.len(),
                    payload.len(),
                    "short reply at {size}B, cap {hold_cap}, split {split}"
                );
                assert_eq!(
                    got, payload,
                    "payload mismatch at {size}B, cap {hold_cap}, split {split}"
                );
            }
        }

        drop(stream);
        proxy_shutdown.shutdown();
        for h in proxy_handles {
            h.join().unwrap().unwrap();
        }
    }

    backend_shutdown.shutdown();
    for h in backend_handles {
        h.join().unwrap().unwrap();
    }
}

/// Dropping a `forward_to_conn` future stops the relay.
///
/// Both backends relay on their own once the forward is installed — mio from
/// its event loop, io_uring from the write-completion handler — so a dropped
/// future (a `select!` losing a race, a timeout) has to take the forward with
/// it. Otherwise bytes keep reaching the sink with nobody waiting on the
/// result, and the next forward on that connection starts behind.
///
/// This was mio-only until gathering moved io_uring's submission out of
/// `ForwardToFuture::poll` and into `handle_forward_write`. Before that, the
/// io_uring writes really were driven by polling and a drop stopped them by
/// itself; afterwards the driver owns the progress and keeps going. The test
/// covers both backends so that asymmetry cannot come back silently.
struct DroppedForwardProxy {
    backend_addr: SocketAddr,
}

static DROPPED_FORWARD_BACKEND: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for DroppedForwardProxy {
    fn on_accept(&self, client: Connection) -> impl Future<Output = ()> + 'static {
        let backend_addr = self.backend_addr;
        async move {
            let (mut tx, mut rx) = client.split();
            let backend = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(_) => return,
            };

            // A `Connection` already owns both halves; this test only reads
            // through the other one.
            let (mut backend_tx, _unused_rx) = backend.split();

            // Arm a forward for far more than the client will ever send, then
            // drop it without awaiting it to completion.
            {
                let _fut = rx.forward_to_conn(&mut backend_tx, 1 << 30);
            }

            // Everything the client sends must now come to *this* task, not to
            // the sink. Echo it back so the test can see where it went.
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
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
        DroppedForwardProxy {
            backend_addr: *DROPPED_FORWARD_BACKEND.get().expect("backend addr not set"),
        }
    }
}

#[test]
fn dropping_a_forward_to_conn_future_cancels_the_relay() {
    let (backend_shutdown, backend_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    let backend_addr = backend_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();
    wait_for_server(&backend_addr);
    DROPPED_FORWARD_BACKEND
        .set(backend_addr.parse().unwrap())
        .expect("backend addr set once");

    let (proxy_shutdown, proxy_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<DroppedForwardProxy>()
        .expect("proxy launch failed");
    let proxy_addr = proxy_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();
    wait_for_server(&proxy_addr);

    // Connect first and pause, so the handler has armed and dropped its
    // forward before any byte arrives. Bytes already buffered when a forward
    // is armed are part of that forward and are queued on the sink
    // immediately; the cancel can only stop what has not been read yet, which
    // is the case worth asserting.
    let mut stream = TcpStream::connect(&proxy_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // The handler echoes, so a reply proves the bytes reached the handler. If
    // the dropped forward were still installed they would have gone to the
    // backend instead and this read would time out.
    let msg = b"the forward was cancelled";
    stream.write_all(msg).unwrap();
    stream.flush().unwrap();
    let mut got = vec![0u8; msg.len()];
    stream
        .read_exact(&mut got)
        .expect("no echo: the bytes went to the sink instead of the handler");
    assert_eq!(got, msg);
    drop(stream);

    proxy_shutdown.shutdown();
    for h in proxy_handles {
        h.join().unwrap().unwrap();
    }
    backend_shutdown.shutdown();
    for h in backend_handles {
        h.join().unwrap().unwrap();
    }
}

// ── forward_to a file sink (io_uring Mode A, gathered writev) ───────────────

/// Forward a length-prefixed body straight to a file, then acknowledge the
/// byte count so the client knows the write is done.
///
/// The file path is the interesting part: a file sink uses `writev` at an
/// advancing offset, where a socket sink uses `sendmsg` and ignores offsets
/// entirely. Gathering made one write cover many held buffers, so the offset
/// now has to advance by the size of a *batch* and, after a short write, by a
/// partial batch. Nothing but a unit test covered that until this.
#[cfg(has_io_uring)]
struct FileForwarder;

#[cfg(has_io_uring)]
static FILE_SINK_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

#[cfg(has_io_uring)]
impl AsyncEventHandler for FileForwarder {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            use std::os::fd::AsFd;
            let mut hdr = [0u8; 4];
            let n = conn
                .with_data(|data| {
                    if data.len() < 4 {
                        return ParseResult::NeedMore;
                    }
                    hdr.copy_from_slice(&data[..4]);
                    ParseResult::Consumed(4)
                })
                .await;
            if n == 0 {
                return;
            }
            let len = u32::from_be_bytes(hdr) as usize;

            let path = FILE_SINK_PATH.get().expect("path set before launch");
            let file = match std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("file forwarder: open failed: {e}");
                    return;
                }
            };
            let sink = match ringline::SinkFd::file(file.as_fd()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("file forwarder: SinkFd::file failed: {e}");
                    return;
                }
            };
            let forwarded = conn.forward_to(&sink, len).await.unwrap_or(0);
            // `sink` borrows `file` immutably and `sync_all` takes `&self`, so
            // the two coexist — no drop needed to release anything.
            //
            // fsync before acking: the client reads the file as soon as it sees
            // the ack, and a buffered write need not be visible yet.
            let _ = file.sync_all();

            // Ack the count, then echo whatever arrived past `len` — which is
            // what `settle_forward_end` put back in the accumulator, and the
            // half of the split a gathered batch can get wrong.
            let _ = conn.send_nowait(&(forwarded as u32).to_be_bytes());
            let tail = conn
                .with_data(|data| {
                    if data.is_empty() {
                        return ParseResult::NeedMore;
                    }
                    ParseResult::Consumed(data.len())
                })
                .await;
            let _ = tail;
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        FileForwarder
    }
}

/// A body far larger than one provided buffer lands in the file byte-exact.
///
/// 1 MiB against a 4 KiB buffer ring is ~256 buffers, so the forward is many
/// gathered batches: this fails if a batch writes at the wrong offset, if
/// iovecs go out of order, or if a short write resubmits from the wrong place.
#[cfg(has_io_uring)]
#[test]
fn forward_to_file_writes_a_large_body_byte_exact() {
    let dir = std::env::temp_dir().join(format!("ringline-file-fwd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("sink.bin");
    FILE_SINK_PATH.set(path.clone()).expect("set once");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<FileForwarder>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let size = 1024 * 1024;
    // A position-dependent pattern: a misordered or misplaced batch changes
    // bytes rather than merely truncating, so the mismatch is visible.
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream.write_all(&(size as u32).to_be_bytes()).unwrap();
    stream.write_all(&payload).unwrap();
    stream.flush().unwrap();

    let mut ack = [0u8; 4];
    stream.read_exact(&mut ack).expect("ack");
    assert_eq!(
        u32::from_be_bytes(ack) as usize,
        size,
        "the forward should report every byte written"
    );

    let written = std::fs::read(&path).expect("read back the sink file");
    assert_eq!(written.len(), size, "file length");
    assert_eq!(written, payload, "file contents differ from what was sent");

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Bytes past `len` do not reach the file, and are still readable afterwards.
///
/// The overshoot split: a batch's last held buffer straddles the end of the
/// forward, so its prefix is written and its suffix goes back to the
/// accumulator. With gathering that split happens inside a multi-buffer batch,
/// which is a different code path from the single-buffer one it replaced.
#[cfg(has_io_uring)]
#[test]
fn forward_to_file_stops_at_len_and_leaves_the_tail_readable() {
    let dir = std::env::temp_dir().join(format!("ringline-file-tail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("sink.bin");
    // A second static: the two tests run in the same binary and must not share
    // a path.
    static TAIL_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    TAIL_PATH.set(path.clone()).expect("set once");

    struct TailForwarder;
    impl AsyncEventHandler for TailForwarder {
        fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                use std::os::fd::AsFd;
                let mut hdr = [0u8; 4];
                let n = conn
                    .with_data(|data| {
                        if data.len() < 4 {
                            return ParseResult::NeedMore;
                        }
                        hdr.copy_from_slice(&data[..4]);
                        ParseResult::Consumed(4)
                    })
                    .await;
                if n == 0 {
                    return;
                }
                let len = u32::from_be_bytes(hdr) as usize;
                let path = TAIL_PATH.get().expect("path set");
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)
                    .expect("open sink");
                let sink = ringline::SinkFd::file(file.as_fd()).expect("file sink");
                let forwarded = conn.forward_to(&sink, len).await.unwrap_or(0);
                let _ = file.sync_all();
                let _ = conn.send_nowait(&(forwarded as u32).to_be_bytes());

                // Echo the overshoot back, so the test can prove those bytes
                // survived the split rather than being written or dropped.
                let mut tail = Vec::new();
                while tail.len() < 64 {
                    let got = conn
                        .with_data(|data| {
                            tail.extend_from_slice(data);
                            ParseResult::Consumed(data.len())
                        })
                        .await;
                    if got == 0 {
                        break;
                    }
                }
                let _ = conn.send_nowait(&tail);
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            TailForwarder
        }
    }

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TailForwarder>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    // Forward 100_000 bytes, but send 64 more. With a 4 KiB ring the boundary
    // lands mid-buffer, inside a batch.
    let size = 100_000usize;
    let body: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let tail: Vec<u8> = (0..64u8).map(|i| i.wrapping_add(7)).collect();

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream.write_all(&(size as u32).to_be_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.write_all(&tail).unwrap();
    stream.flush().unwrap();

    let mut ack = [0u8; 4];
    stream.read_exact(&mut ack).expect("ack");
    assert_eq!(u32::from_be_bytes(ack) as usize, size);

    let mut echoed = vec![0u8; tail.len()];
    stream.read_exact(&mut echoed).expect("tail echo");
    assert_eq!(echoed, tail, "the overshoot must survive the split intact");

    let written = std::fs::read(&path).expect("read back");
    assert_eq!(
        written.len(),
        size,
        "the file must hold exactly `len` bytes — no overshoot written"
    );
    assert_eq!(written, body);

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Refusing a second forward on one connection (EBUSY, both backends) ──────

/// A forward already running must be refused, not silently replaced.
///
/// mio has always refused it; io_uring armed unconditionally, overwriting
/// `forward_progress` — which strands the running forward's held bids and
/// hands its caller a result belonging to a different forward. The contract
/// was stated only on the mio sibling's docs, so the two backends disagreed
/// behind one signature.
struct BusyForwardProxy {
    backend_addr: SocketAddr,
}

static BUSY_FORWARD_BACKEND: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
static BUSY_FORWARD_ERRNO: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

impl AsyncEventHandler for BusyForwardProxy {
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        let backend_addr = self.backend_addr;
        async move {
            let backend = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(_) => return,
            };

            // Hold one forward open (far more than the client will send), then
            // ask for a second on the same connection while the first is live.
            // Two forwards *in flight at once* is what this test is about, and
            // `&mut RecvHalf` makes that a compile error rather than the
            // runtime `EBUSY` being asserted here. Go through the `Copy`
            // handle so the refusal is still exercised.
            let client_ctx = client.as_conn();
            // Bound so the `ConnCtx` outlives both borrows.
            let backend_ctx = backend.as_conn();
            let first = client_ctx.forward_to_conn(&backend_ctx, 1 << 30);
            let second = client_ctx.forward_to_conn(&backend_ctx, 16);
            let errno = match second.await {
                Ok(_) => -1,
                Err(e) => e.raw_os_error().unwrap_or(-1),
            };
            let _ = BUSY_FORWARD_ERRNO.set(errno);
            // Report it on the wire so the test sees it without shared state
            // timing games.
            let _ = client.send_nowait(&errno.to_be_bytes());
            drop(first);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        BusyForwardProxy {
            backend_addr: *BUSY_FORWARD_BACKEND.get().expect("backend addr not set"),
        }
    }
}

#[test]
fn a_second_forward_on_one_connection_is_refused_with_ebusy() {
    let (backend_shutdown, backend_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    let backend_addr = backend_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();
    wait_for_server(&backend_addr);
    BUSY_FORWARD_BACKEND
        .set(backend_addr.parse().unwrap())
        .expect("backend addr set once");

    let (proxy_shutdown, proxy_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<BusyForwardProxy>()
        .expect("proxy launch failed");
    let proxy_addr = proxy_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();
    wait_for_server(&proxy_addr);

    let mut stream = TcpStream::connect(&proxy_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut got = [0u8; 4];
    stream
        .read_exact(&mut got)
        .expect("proxy never reported the second forward's result");
    assert_eq!(
        i32::from_be_bytes(got),
        libc::EBUSY,
        "a second forward while one is running must resolve EBUSY, not replace it"
    );
    drop(stream);

    proxy_shutdown.shutdown();
    for h in proxy_handles {
        h.join().unwrap().unwrap();
    }
    backend_shutdown.shutdown();
    for h in backend_handles {
        h.join().unwrap().unwrap();
    }
}

/// A connection driven entirely through the split halves round-trips, and does
/// so with the send issued while the read side is borrowed.
#[test]
fn split_halves_echo_round_trip() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SplitEcho>()
        .expect("launch failed");
    let addr = shutdown
        .bound_addr()
        .expect("bound_addr after a TCP bind")
        .to_string();

    wait_for_server(&addr);

    let msg = b"split halves echo";
    assert_eq!(echo_round_trip(&addr, msg), msg.to_vec());

    // A second message, over several reads: the halves survive across
    // iterations rather than being a one-shot.
    let big: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    assert_eq!(echo_round_trip(&addr, &big), big);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// The read side is exclusive on **both** backends: a second `split()` on a
/// connection whose half is still out must be refused with `EBUSY`.
///
/// The verdict travels over the wire because the mio event loop has no
/// in-process test harness for driver state — asserting through a real
/// connection is what works uniformly on both.
struct DoubleSplitReporter;

impl AsyncEventHandler for DoubleSplitReporter {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let ctx = conn.as_conn();
            let (mut tx, _rx) = conn.split();
            // `_rx` is still alive, so the read side is still claimed. The
            // handler was handed the only legitimate claim at accept time, so
            // this asks the underlying handle for a second one.
            let verdict = match ctx.take_recv() {
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => "EBUSY",
                Err(_) => "WRONG-ERRNO",
                Ok(_) => "HANDED-OUT-TWICE",
            };
            let _ = tx.send_nowait(verdict.as_bytes());
            // Hold the halves until the client has read the verdict.
            ringline::sleep(Duration::from_millis(200)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        DoubleSplitReporter
    }
}

#[test]
fn a_second_split_is_refused_on_both_backends() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<DoubleSplitReporter>()
        .expect("launch failed");
    let addr = shutdown
        .bound_addr()
        .expect("bound_addr after a TCP bind")
        .to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).expect("verdict from the handler");
    assert_eq!(
        &buf[..n],
        b"EBUSY",
        "a second split while the read half is live must be refused with EBUSY"
    );

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
