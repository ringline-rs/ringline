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

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder,
};
use ringline_ping::{Pool, PoolConfig};

// ── Helpers ─────────────────────────────────────────────────────────────

static TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        // Look for PING\r\n
                        if data.len() < 6 {
                            return ParseResult::NeedMore;
                        }
                        if data.starts_with(b"PING\r\n") {
                            let _ = tx.send_nowait(b"PONG\r\n");
                            ParseResult::Consumed(6)
                        } else {
                            let _ = tx.send_nowait(b"-ERR\r\n");
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
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *PING_SERVER_ADDR.get().expect("server addr not set");
        Some(Box::pin(async move {
            let conn = match ringline::connect(server_addr).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    PING_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
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
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<PingServer>()
        .expect("server launch failed");
    let addr = s_shutdown.bound_addr().expect("bound address").to_string();
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
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *POOL_SERVER_ADDR.get().expect("server addr not set");
        Some(Box::pin(async move {
            let config = PoolConfig::new(server_addr, 2).connect_timeout_ms(5000);
            let pool = Pool::new(config);

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
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<PingServer>()
        .expect("server launch failed");
    let addr = s_shutdown.bound_addr().expect("bound address").to_string();
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

// ── Parse error test ────────────────────────────────────────────────────

/// Server that responds with garbage instead of PONG\r\n.
struct BadPingServer;

impl AsyncEventHandler for BadPingServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            let n = rx
                .with_data(|data| {
                    if data.len() < 6 {
                        return ParseResult::NeedMore;
                    }
                    // Respond with malformed data instead of PONG\r\n.
                    let _ = tx.send_nowait(b"GARBAGE_NOT_A_PONG\r\n");
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n > 0 {
                // Keep connection open briefly so client can read the bad response.
                ringline::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        BadPingServer
    }
}

static BAD_SERVER_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static BAD_RESULT: OnceLock<String> = OnceLock::new();

struct BadPingClientHandler;

impl AsyncEventHandler for BadPingClientHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *BAD_SERVER_ADDR.get().expect("bad server addr not set");
        Some(Box::pin(async move {
            let conn = match ringline::connect(server_addr).await {
                Ok(ctx) => ctx,
                Err(e) => {
                    BAD_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };

            let mut client = ringline_ping::Client::new(conn);
            match client.ping().await {
                Ok(()) => {
                    BAD_RESULT.set("UNEXPECTED_OK".to_string()).ok();
                }
                Err(_e) => {
                    BAD_RESULT.set("ERROR".to_string()).ok();
                }
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        BadPingClientHandler
    }
}

#[test]
fn parse_error_returns_error_not_hang() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<BadPingServer>()
        .expect("server launch failed");
    let addr = s_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    BAD_SERVER_ADDR.set(addr.parse().unwrap()).ok();

    let (_c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<BadPingClientHandler>()
        .expect("client launch failed");

    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    let result = BAD_RESULT.get().expect("on_start did not set result");
    assert_eq!(result, "ERROR", "expected parse error, got: {result}");

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}

// ── Pool checkout semantics ─────────────────────────────────────────────

static SEMANTICS_SERVER_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static SEMANTICS_RESULT: OnceLock<String> = OnceLock::new();

struct PoolSemanticsHandler;

impl PoolSemanticsHandler {
    /// Exercises the checkout contract: several clients held at once, the
    /// exhausted case, the slot returning on drop, and `connect_all` leaving
    /// checked-out slots alone.
    async fn run(server_addr: SocketAddr) -> Result<(), String> {
        let config = PoolConfig::new(server_addr, 2).connect_timeout_ms(5000);
        let pool = Pool::new(config);
        pool.connect_all()
            .await
            .map_err(|e| format!("connect_all: {e}"))?;

        // Two clients out at the same time. This is the capability the guard
        // exists for: `PooledClient` owns its client and does not borrow the
        // pool.
        let mut a = pool
            .client()
            .await
            .map_err(|e| format!("checkout a: {e}"))?;
        let mut b = pool
            .client()
            .await
            .map_err(|e| format!("checkout b: {e}"))?;
        if pool.lent_count() != 2 || pool.connected_count() != 0 {
            return Err(format!(
                "with two out: lent={} connected={}",
                pool.lent_count(),
                pool.connected_count()
            ));
        }

        // Both are live and independent.
        a.ping().await.map_err(|e| format!("ping a: {e}"))?;
        b.ping().await.map_err(|e| format!("ping b: {e}"))?;
        if a.token() == b.token() {
            return Err("both guards hold the same connection".to_string());
        }

        // Every slot is out, so this is exhaustion, not a connect failure.
        match pool.client().await {
            Err(ringline_ping::Error::PoolExhausted) => {}
            Err(e) => return Err(format!("expected PoolExhausted, got {e}")),
            Ok(_) => return Err("expected PoolExhausted, got a client".to_string()),
        }

        // `connect_all` must leave a checked-out slot alone rather than
        // connecting over it.
        pool.connect_all()
            .await
            .map_err(|e| format!("connect_all while lent: {e}"))?;
        if pool.lent_count() != 2 || pool.connected_count() != 0 {
            return Err(format!(
                "connect_all disturbed lent slots: lent={} connected={}",
                pool.lent_count(),
                pool.connected_count()
            ));
        }
        a.ping()
            .await
            .map_err(|e| format!("ping a after connect_all: {e}"))?;

        // Dropping a guard returns its connection to the slot.
        let a_token = a.token();
        drop(a);
        if pool.lent_count() != 1 || pool.connected_count() != 1 {
            return Err(format!(
                "after drop: lent={} connected={}",
                pool.lent_count(),
                pool.connected_count()
            ));
        }

        // The returned connection is reused, not reconnected.
        let mut c = pool
            .client()
            .await
            .map_err(|e| format!("checkout c: {e}"))?;
        if c.token() != a_token {
            return Err("the returned slot was reconnected, not reused".to_string());
        }
        c.ping().await.map_err(|e| format!("ping c: {e}"))?;

        drop(b);
        drop(c);
        if pool.connected_count() != 2 || pool.lent_count() != 0 {
            return Err(format!(
                "after both drops: lent={} connected={}",
                pool.lent_count(),
                pool.connected_count()
            ));
        }

        pool.close_all();
        Ok(())
    }
}

impl AsyncEventHandler for PoolSemanticsHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *SEMANTICS_SERVER_ADDR.get().expect("server addr not set");
        Some(Box::pin(async move {
            let result = match Self::run(server_addr).await {
                Ok(()) => "OK".to_string(),
                Err(e) => e,
            };
            SEMANTICS_RESULT.set(result).ok();
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        PoolSemanticsHandler
    }
}

#[test]
fn pool_checkout_semantics() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<PingServer>()
        .expect("server launch failed");
    let addr = s_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    SEMANTICS_SERVER_ADDR.set(addr.parse().unwrap()).ok();

    let (_c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<PoolSemanticsHandler>()
        .expect("client launch failed");

    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    let result = SEMANTICS_RESULT.get().expect("on_start did not set result");
    assert_eq!(result, "OK", "expected OK, got: {result}");

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
