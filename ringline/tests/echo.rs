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

use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder};
use std::sync::atomic::{AtomicU32, Ordering};

// ── Async echo handler ─────────────────────────────────────────────

struct AsyncEcho;

impl AsyncEventHandler for AsyncEcho {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| {
                        let _ = conn.send_nowait(data);
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

// ── Helpers ─────────────────────────────────────────────────────────

fn test_config() -> Config {
    let mut config = Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 64;
    config.recv_buffer.ring_size = 64;
    config.recv_buffer.buffer_size = 4096;
    config.max_connections = 64;
    config.send_copy_count = 64;
    config
}

/// Find an available port by binding to :0.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
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
fn echo_small_message() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| {
                    let _ = conn.send_nowait(data);
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n > 0 {
                conn.shutdown_write();
            }
            // Keep the task alive to receive more (should get EOF).
            let _ = conn.with_data(|_data| ParseResult::Consumed(0)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ShutdownWriteEcho
    }
}

#[test]
fn async_shutdown_write_triggers_eof() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<ShutdownWriteEcho>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| {
                // Echo back, then request shutdown.
                let _ = conn.send_nowait(data);
                conn.request_shutdown();
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<RequestShutdownHandler>()
        .expect("launch failed");

    wait_for_server(&addr);

    // Send a message — the handler will request shutdown after echoing.
    let _response = echo_round_trip(&addr, b"trigger-shutdown");

    // Workers should exit on their own (request_shutdown triggers it).
    for h in handles {
        let result = h.join().expect("worker panicked");
        result.expect("worker returned error");
    }

    // ShutdownHandle is now redundant, but drop it cleanly.
    drop(shutdown);
}

// ── Spawn standalone task test ──────────────────────────────────────

static SPAWN_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Handler that spawns a standalone task from on_accept.
struct SpawnTestHandler;

impl AsyncEventHandler for SpawnTestHandler {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            // Spawn a standalone task that increments the counter.
            ringline::spawn(async {
                SPAWN_COUNTER.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();

            // Echo one message to signal readiness.
            conn.with_data(|data| {
                let _ = conn.send_nowait(data);
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

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<SpawnTestHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| {
                        let len = data.len();
                        // Sleep 50ms then echo.
                        let data_copy = data.to_vec();
                        let conn2 = conn;
                        ringline::spawn(async move {
                            ringline::sleep(Duration::from_millis(50)).await;
                            let _ = conn2.send_nowait(&data_copy);
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<SleepEchoHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| -> ParseResult {
                let msg = std::str::from_utf8(data).unwrap_or("");
                if msg == "test-timeout-ok" {
                    // Timeout wrapping an immediate future should succeed.
                    let conn2 = conn;
                    ringline::spawn(async move {
                        let result =
                            ringline::timeout(Duration::from_secs(10), async { 42u32 }).await;
                        match result {
                            Ok(42) => {
                                let _ = conn2.send_nowait(b"OK");
                            }
                            _ => {
                                let _ = conn2.send_nowait(b"FAIL");
                            }
                        }
                    })
                    .unwrap();
                } else if msg == "test-timeout-expire" {
                    // Timeout wrapping a long sleep should expire.
                    let conn2 = conn;
                    ringline::spawn(async move {
                        let result = ringline::timeout(
                            Duration::from_millis(20),
                            ringline::sleep(Duration::from_secs(10)),
                        )
                        .await;
                        match result {
                            Err(_elapsed) => {
                                let _ = conn2.send_nowait(b"ELAPSED");
                            }
                            Ok(()) => {
                                let _ = conn2.send_nowait(b"FAIL");
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<TimeoutTestHandler>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<TimeoutTestHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, client: ConnCtx) -> impl Future<Output = ()> + 'static {
        let backend_addr = self.backend_addr;
        async move {
            // Connect to the backend echo server.
            let backend = match client.connect(backend_addr) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        let _ = client.send_nowait(format!("-ERR connect: {e}\r\n").as_bytes());
                        return;
                    }
                },
                Err(e) => {
                    let _ = client.send_nowait(format!("-ERR connect: {e}\r\n").as_bytes());
                    return;
                }
            };

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
                if backend.send_nowait(&data_copy).is_err() {
                    break;
                }

                // Read echo from backend.
                let mut echo = Vec::new();
                let target_len = data_copy.len();
                while echo.len() < target_len {
                    let remaining = target_len - echo.len();
                    let got = backend
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
    let backend_port = free_port();
    let backend_addr = format!("127.0.0.1:{backend_port}");

    let (backend_shutdown, backend_handles) = RinglineBuilder::new(test_config())
        .bind(backend_addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");

    wait_for_server(&backend_addr);

    // 2. Start the forwarder server.
    FORWARDER_BACKEND_ADDR
        .set(backend_addr.parse().unwrap())
        .ok();

    let forwarder_port = free_port();
    let forwarder_addr = format!("127.0.0.1:{forwarder_port}");

    let (fwd_shutdown, fwd_handles) = RinglineBuilder::new(test_config())
        .bind(forwarder_addr.parse().unwrap())
        .launch::<ForwarderHandler>()
        .expect("forwarder launch failed");

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
    fn on_accept(&self, client: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            // Wait for trigger byte from client before connecting.
            client
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;

            let port = CONNECT_REFUSED_PORT.load(Ordering::SeqCst);
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

            let result = match client.connect(addr) {
                Ok(fut) => match fut.await {
                    Ok(_) => "CONNECTED".to_string(),
                    Err(e) => format!("ERR:{}", e.kind()),
                },
                Err(e) => format!("SUBMIT_ERR:{e}"),
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
    // Bind to a port, then drop the listener so nothing is listening.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = listener.local_addr().unwrap().port();
    drop(listener);

    CONNECT_REFUSED_PORT.store(dead_port as u32, Ordering::SeqCst);

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<ConnectRefusedHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, client: ConnCtx) -> impl Future<Output = ()> + 'static {
        let backend_addr = *MULTI_OUTBOUND_BACKEND_ADDR
            .get()
            .expect("backend addr not set");
        async move {
            // Open two backend connections from the same client task.
            let backend1 = match client.connect(backend_addr) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        let _ = client.send_nowait(format!("ERR1:{e}").as_bytes());
                        return;
                    }
                },
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR1:{e}").as_bytes());
                    return;
                }
            };

            let backend2 = match client.connect(backend_addr) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        let _ = client.send_nowait(format!("ERR2:{e}").as_bytes());
                        return;
                    }
                },
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR2:{e}").as_bytes());
                    return;
                }
            };

            // Send "AA" through backend1, "BB" through backend2.
            if backend1.send_nowait(b"AA").is_err() {
                let _ = client.send_nowait(b"SEND_ERR1");
                return;
            }
            let mut echo1 = Vec::new();
            while echo1.len() < 2 {
                let remaining = 2 - echo1.len();
                let got = backend1
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

            if backend2.send_nowait(b"BB").is_err() {
                let _ = client.send_nowait(b"SEND_ERR2");
                return;
            }
            let mut echo2 = Vec::new();
            while echo2.len() < 2 {
                let remaining = 2 - echo2.len();
                let got = backend2
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
    let backend_port = free_port();
    let backend_addr = format!("127.0.0.1:{backend_port}");

    let (backend_shutdown, backend_handles) = RinglineBuilder::new(test_config())
        .bind(backend_addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");

    wait_for_server(&backend_addr);

    MULTI_OUTBOUND_BACKEND_ADDR
        .set(backend_addr.parse().unwrap())
        .ok();

    // Start the multi-outbound server.
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<MultiOutboundHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, client: ConnCtx) -> impl Future<Output = ()> + 'static {
        let addr1 = *SELECT_BACKEND1_ADDR.get().expect("backend1 addr not set");
        let addr2 = *SELECT_BACKEND2_ADDR.get().expect("backend2 addr not set");
        async move {
            // Connect to both backends.
            let backend1 = match client.connect(addr1) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        let _ = client.send_nowait(format!("ERR1:{e}").as_bytes());
                        return;
                    }
                },
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR1:{e}").as_bytes());
                    return;
                }
            };
            let backend2 = match client.connect(addr2) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        let _ = client.send_nowait(format!("ERR2:{e}").as_bytes());
                        return;
                    }
                },
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR2:{e}").as_bytes());
                    return;
                }
            };

            // Send data to backend1 only.
            if backend1.send_nowait(b"HELLO").is_err() {
                let _ = client.send_nowait(b"SEND_ERR");
                return;
            }

            // Select on both — backend1 should win since we sent data there.
            // Use separate buffers since each closure needs its own &mut.
            let mut buf1 = Vec::new();
            let mut buf2 = Vec::new();
            match ringline::select(
                backend1.with_data(|data| {
                    buf1.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                }),
                backend2.with_data(|data| {
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
    let backend1_port = free_port();
    let backend1_addr = format!("127.0.0.1:{backend1_port}");
    let (b1_shutdown, b1_handles) = RinglineBuilder::new(test_config())
        .bind(backend1_addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend1 launch failed");
    wait_for_server(&backend1_addr);

    let backend2_port = free_port();
    let backend2_addr = format!("127.0.0.1:{backend2_port}");
    let (b2_shutdown, b2_handles) = RinglineBuilder::new(test_config())
        .bind(backend2_addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend2 launch failed");
    wait_for_server(&backend2_addr);

    SELECT_BACKEND1_ADDR
        .set(backend1_addr.parse().unwrap())
        .ok();
    SELECT_BACKEND2_ADDR
        .set(backend2_addr.parse().unwrap())
        .ok();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<SelectTwoHandler>()
        .expect("launch failed");
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
    fn on_accept(&self, client: ConnCtx) -> impl Future<Output = ()> + 'static {
        let addr1 = *SELECT2_BACKEND1_ADDR.get().expect("backend1 addr not set");
        let addr2 = *SELECT2_BACKEND2_ADDR.get().expect("backend2 addr not set");
        async move {
            let backend1 = match client.connect(addr1) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        let _ = client.send_nowait(format!("ERR:{e}").as_bytes());
                        return;
                    }
                },
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR:{e}").as_bytes());
                    return;
                }
            };
            let backend2 = match client.connect(addr2) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        let _ = client.send_nowait(format!("ERR:{e}").as_bytes());
                        return;
                    }
                },
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR:{e}").as_bytes());
                    return;
                }
            };

            // Send data to backend2 only.
            if backend2.send_nowait(b"WORLD").is_err() {
                let _ = client.send_nowait(b"SEND_ERR");
                return;
            }

            let mut buf1 = Vec::new();
            let mut buf2 = Vec::new();
            match ringline::select(
                backend1.with_data(|data| {
                    buf1.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                }),
                backend2.with_data(|data| {
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
    let b1_port = free_port();
    let b1_addr = format!("127.0.0.1:{b1_port}");
    let (b1_shutdown, b1_handles) = RinglineBuilder::new(test_config())
        .bind(b1_addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend1 launch failed");
    wait_for_server(&b1_addr);

    let b2_port = free_port();
    let b2_addr = format!("127.0.0.1:{b2_port}");
    let (b2_shutdown, b2_handles) = RinglineBuilder::new(test_config())
        .bind(b2_addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend2 launch failed");
    wait_for_server(&b2_addr);

    SELECT2_BACKEND1_ADDR.set(b1_addr.parse().unwrap()).ok();
    SELECT2_BACKEND2_ADDR.set(b2_addr.parse().unwrap()).ok();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<SelectSecondWinsHandler>()
        .expect("launch failed");
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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            // Run 300 iterations of select(with_data, sleep).
            // Each iteration where data arrives drops the SleepFuture,
            // which must correctly cancel the io_uring timeout and release
            // the timer slot. If slots leak, we'll exhaust the pool and panic.
            for _ in 0..300 {
                match ringline::select(
                    conn.with_data(|data| {
                        let _ = conn.send_nowait(data);
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
                        let _ = conn.send_nowait(b"TIMEOUT");
                        break;
                    }
                }
            }
            let _ = conn.send_nowait(b"DONE");
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SelectSleepHandler
    }
}

#[test]
fn async_select_with_sleep() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    // Use a config with limited timer slots to make leaks detectable.
    let mut config = test_config();
    config.timer_slots = 16;

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr.parse().unwrap())
        .launch::<SelectSleepHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, client: ConnCtx) -> impl Future<Output = ()> + 'static {
        let backend_addr = *SELECT3_BACKEND_ADDR.get().expect("backend addr not set");
        async move {
            let backend = match client.connect(backend_addr) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        let _ = client.send_nowait(format!("ERR:{e}").as_bytes());
                        return;
                    }
                },
                Err(e) => {
                    let _ = client.send_nowait(format!("ERR:{e}").as_bytes());
                    return;
                }
            };

            // Send data to backend so it echoes.
            if backend.send_nowait(b"ECHO3").is_err() {
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
                backend.with_data(|data| {
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
    let b_port = free_port();
    let b_addr = format!("127.0.0.1:{b_port}");
    let (b_shutdown, b_handles) = RinglineBuilder::new(test_config())
        .bind(b_addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    wait_for_server(&b_addr);

    SELECT3_BACKEND_ADDR.set(b_addr.parse().unwrap()).ok();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<Select3Handler>()
        .expect("launch failed");
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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let mut config = test_config();
    config.standalone_task_capacity = 1;

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr.parse().unwrap())
        .launch::<TrySpawnHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let mut config = test_config();
    config.standalone_task_capacity = 1;

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr.parse().unwrap())
        .launch::<CancelTaskHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<CancelCompletedHandler>()
        .expect("launch failed");

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
    let mut config = test_config();
    config.worker.threads = threads;
    config
}

#[test]
fn multi_worker_echo() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(multi_worker_config(2))
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(multi_worker_config(2))
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(multi_worker_config(4))
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<SendAwaitHandler>()
        .expect("launch failed");

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

/// Handler that tests send_chain_await.
struct SendChainAwaitHandler;

impl AsyncEventHandler for SendChainAwaitHandler {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
fn async_send_chain_await_basic() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<SendChainAwaitHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let mut config = test_config();
    config.timer_slots = 2;

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr.parse().unwrap())
        .launch::<TrySleepHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let mut config = test_config();
    config.timer_slots = 2;

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr.parse().unwrap())
        .launch::<TryTimeoutHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            // Join two send calls.
            let fut_a = async {
                match conn.send(b"HELLO") {
                    Ok(f) => f.await,
                    Err(e) => Err(e),
                }
            };
            let fut_b = async {
                match conn.send(b"WORLD") {
                    Ok(f) => f.await,
                    Err(e) => Err(e),
                }
            };
            let (a, b) = ringline::join(fut_a, fut_b).await;
            let msg = format!("JOIN:{}:{}", a.unwrap_or(0), b.unwrap_or(0));
            let _ = conn.send_nowait(msg.as_bytes());

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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<JoinHandler>()
        .expect("launch failed");

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

/// Handler that joins three futures: send_await + sleep + with_data.
struct Join3Handler;

impl AsyncEventHandler for Join3Handler {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let fut_a = async {
                match conn.send(b"ABC") {
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
                let n = conn
                    .with_data(|data| ParseResult::Consumed(data.len()))
                    .await;
                n as u32
            };

            let (a, b, c) = ringline::join3(fut_a, fut_b, fut_c).await;
            let msg = format!("JOIN3:{a}:{b}:{c}");
            let _ = conn.send_nowait(msg.as_bytes());

            ringline::sleep(Duration::from_millis(20)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Join3Handler
    }
}

#[test]
fn async_join3_mixed() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<Join3Handler>()
        .expect("launch failed");

    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // First write triggers the handler (consumed by initial with_data).
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();

    // Brief delay, then send second payload for the join3 with_data branch.
    std::thread::sleep(Duration::from_millis(30));
    stream.write_all(b"PAYLOAD").unwrap();
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
                if s.contains("JOIN3:") {
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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<SleepUntilHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<TimeoutAtHandler>()
        .expect("launch failed");

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
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
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
    let udp_port = free_port();
    let udp_addr: std::net::SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    let tcp_port = free_port();
    let tcp_addr = format!("127.0.0.1:{tcp_port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(tcp_addr.parse().unwrap())
        .bind_udp(udp_addr)
        .launch::<UdpEchoAsync>()
        .expect("launch failed");

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
/// ringline::connect() (not ConnCtx::connect) to reach a backend echo server.
struct StandaloneConnectHandler;

static STANDALONE_CONNECT_BACKEND: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for StandaloneConnectHandler {
    fn on_accept(&self, client: ConnCtx) -> impl Future<Output = ()> + 'static {
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
                let backend = match ringline::connect(backend_addr) {
                    Ok(fut) => match fut.await {
                        Ok(ctx) => ctx,
                        Err(e) => {
                            let _ = client.send_nowait(format!("CONNECT_ERR:{e}").as_bytes());
                            return;
                        }
                    },
                    Err(e) => {
                        let _ = client.send_nowait(format!("SUBMIT_ERR:{e}").as_bytes());
                        return;
                    }
                };

                // Send data to backend, read echo.
                if backend.send_nowait(b"STANDALONE").is_err() {
                    return;
                }

                let mut echo = Vec::new();
                while echo.len() < 10 {
                    let remaining = 10 - echo.len();
                    let got = backend
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
    let backend_port = free_port();
    let backend_addr = format!("127.0.0.1:{backend_port}");
    let (b_shutdown, b_handles) = RinglineBuilder::new(test_config())
        .bind(backend_addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
    wait_for_server(&backend_addr);

    STANDALONE_CONNECT_BACKEND
        .set(backend_addr.parse().unwrap())
        .ok();

    // Start the handler server.
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<StandaloneConnectHandler>()
        .expect("launch failed");
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

// ── Client-only mode via on_start() ─────────────────────────────

/// Handler that uses on_start() for client-only mode: connects to a
/// backend, sends data, reads echo, then shuts down.
struct OnStartClientHandler;

static ON_START_BACKEND_ADDR: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
static ON_START_RESULT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

impl AsyncEventHandler for OnStartClientHandler {
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        // No inbound connections expected in client-only mode.
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let backend_addr = *ON_START_BACKEND_ADDR.get().expect("backend addr not set");
        Some(Box::pin(async move {
            let backend = match ringline::connect(backend_addr) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        ON_START_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                        ringline::request_shutdown().ok();
                        return;
                    }
                },
                Err(e) => {
                    ON_START_RESULT.set(format!("SUBMIT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };

            if backend.send_nowait(b"ON_START").is_err() {
                ON_START_RESULT.set("SEND_ERR".to_string()).ok();
                ringline::request_shutdown().ok();
                return;
            }

            let mut echo = Vec::new();
            while echo.len() < 8 {
                let remaining = 8 - echo.len();
                let got = backend
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
    let backend_port = free_port();
    let backend_addr = format!("127.0.0.1:{backend_port}");
    let (b_shutdown, b_handles) = RinglineBuilder::new(test_config())
        .bind(backend_addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("backend launch failed");
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
    fn on_accept(&self, client: ConnCtx) -> impl Future<Output = ()> + 'static {
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
                let result = match ringline::connect(addr) {
                    Ok(fut) => match fut.await {
                        Ok(_) => "CONNECTED".to_string(),
                        Err(e) => format!("ERR:{}", e.kind()),
                    },
                    Err(e) => format!("SUBMIT_ERR:{e}"),
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
    // Bind to a port then drop it so nothing is listening.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = listener.local_addr().unwrap().port();
    drop(listener);

    STANDALONE_REFUSED_PORT.store(dead_port as u32, Ordering::SeqCst);

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<StandaloneConnectRefusedHandler>()
        .expect("launch failed");

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
