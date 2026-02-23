//! Round-trip integration tests for ringline-ping.
//!
//! Spins up a ringline server that speaks the ping protocol (responds
//! `PONG\r\n` to `PING\r\n`), then connects a ringline ping client
//! through `on_start` in client-only mode.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder};
use ringline_ping::{Pool, PoolConfig};

// ── Helpers ─────────────────────────────────────────────────────────────

static TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

// ── Ping Server Handler ─────────────────────────────────────────────────

/// Minimal server: parses `PING\r\n` and responds `PONG\r\n`.
struct PingServer;

impl AsyncEventHandler for PingServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| {
                        // Look for PING\r\n
                        if data.len() < 6 {
                            return ParseResult::NeedMore;
                        }
                        if data.starts_with(b"PING\r\n") {
                            let _ = conn.send_nowait(b"PONG\r\n");
                            ParseResult::Consumed(6)
                        } else {
                            let _ = conn.send_nowait(b"-ERR\r\n");
                            ParseResult::Consumed(data.len())
                        }
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        PingServer
    }
}

// ── Client-only handler for ping round-trip ─────────────────────────────

static PING_SERVER_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static PING_RESULT: OnceLock<String> = OnceLock::new();

struct PingClientHandler;

impl AsyncEventHandler for PingClientHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *PING_SERVER_ADDR.get().expect("server addr not set");
        Some(Box::pin(async move {
            let conn = match ringline::connect(server_addr) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        PING_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                        ringline::request_shutdown().ok();
                        return;
                    }
                },
                Err(e) => {
                    PING_RESULT.set(format!("SUBMIT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };

            let mut client = ringline_ping::Client::new(conn);
            match client.ping().await {
                Ok(()) => {
                    PING_RESULT.set("OK".to_string()).ok();
                }
                Err(e) => {
                    PING_RESULT.set(format!("PING_ERR:{e}")).ok();
                }
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        PingClientHandler
    }
}

#[test]
fn ping_round_trip() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    // Start ping server.
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<PingServer>()
        .expect("server launch failed");
    wait_for_server(&addr);

    PING_SERVER_ADDR.set(addr.parse().unwrap()).ok();

    // Launch client-only (no .bind()).
    let (_c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<PingClientHandler>()
        .expect("client launch failed");

    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    let result = PING_RESULT.get().expect("on_start did not set result");
    assert_eq!(result, "OK", "expected OK, got: {result}");

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}

// ── Pool round-trip ─────────────────────────────────────────────────────

static POOL_SERVER_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static POOL_RESULT: OnceLock<String> = OnceLock::new();

struct PingPoolClientHandler;

impl AsyncEventHandler for PingPoolClientHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *POOL_SERVER_ADDR.get().expect("server addr not set");
        Some(Box::pin(async move {
            let config = PoolConfig {
                addr: server_addr,
                pool_size: 2,
                connect_timeout_ms: 5000,
                tls_server_name: None,
            };
            let mut pool = Pool::new(config);

            if let Err(e) = pool.connect_all().await {
                POOL_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                ringline::request_shutdown().ok();
                return;
            }

            assert_eq!(pool.connected_count(), 2);
            assert_eq!(pool.pool_size(), 2);

            // Ping via pool.
            match pool.client().await {
                Ok(mut client) => match client.ping().await {
                    Ok(()) => {}
                    Err(e) => {
                        POOL_RESULT.set(format!("PING_ERR:{e}")).ok();
                        ringline::request_shutdown().ok();
                        return;
                    }
                },
                Err(e) => {
                    POOL_RESULT.set(format!("CLIENT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            }

            pool.close_all();
            assert_eq!(pool.connected_count(), 0);

            POOL_RESULT.set("OK".to_string()).ok();
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        PingPoolClientHandler
    }
}

#[test]
fn ping_pool() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    // Start ping server.
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<PingServer>()
        .expect("server launch failed");
    wait_for_server(&addr);

    POOL_SERVER_ADDR.set(addr.parse().unwrap()).ok();

    // Launch client-only.
    let (_c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<PingPoolClientHandler>()
        .expect("client launch failed");

    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    let result = POOL_RESULT.get().expect("on_start did not set result");
    assert_eq!(result, "OK", "expected OK, got: {result}");

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
