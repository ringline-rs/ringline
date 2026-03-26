//! Test that the redis client returns an error (not a hang) when the server
//! sends malformed RESP data. Exercises the `with_bytes` + `Consumed(len)`
//! error path fixed in PR #14.
//!
//! Uses a fake "bad redis" server that responds with garbage to any command.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder};
use ringline_redis::Client;

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

// ── Bad Redis Server ────────────────────────────────────────────────────

/// A server that accepts any data and responds with invalid RESP.
struct BadRedisServer;

impl AsyncEventHandler for BadRedisServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| {
                    if data.is_empty() {
                        return ParseResult::NeedMore;
                    }
                    // Respond with something that looks like RESP but isn't valid.
                    // A valid RESP value starts with +, -, :, $, or *.
                    // This starts with 'X' which is not a valid RESP type byte.
                    let _ = conn.send_nowait(b"XGARBAGE_NOT_RESP\r\n");
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n > 0 {
                // Keep connection open so client can read the bad response.
                ringline::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        BadRedisServer
    }
}

// ── Client Handler ──────────────────────────────────────────────────────

static BAD_REDIS_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static BAD_REDIS_RESULT: OnceLock<String> = OnceLock::new();

struct BadRedisClientHandler;

impl AsyncEventHandler for BadRedisClientHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *BAD_REDIS_ADDR.get().expect("bad redis addr not set");
        Some(Box::pin(async move {
            let conn = match ringline::connect(server_addr) {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        BAD_REDIS_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                        ringline::request_shutdown().ok();
                        return;
                    }
                },
                Err(e) => {
                    BAD_REDIS_RESULT.set(format!("SUBMIT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };

            let mut client = Client::new(conn);
            // GET will send *2\r\n$3\r\nGET\r\n$4\r\ntest\r\n
            // and the server will respond with garbage RESP.
            match client.get(b"test").await {
                Ok(val) => {
                    BAD_REDIS_RESULT.set(format!("UNEXPECTED_OK:{val:?}")).ok();
                }
                Err(_e) => {
                    // Any error is fine — the important thing is we didn't hang.
                    BAD_REDIS_RESULT.set("ERROR".to_string()).ok();
                }
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        BadRedisClientHandler
    }
}

// ── Test ────────────────────────────────────────────────────────────────

#[test]
fn malformed_resp_returns_error_not_hang() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<BadRedisServer>()
        .expect("server launch failed");
    wait_for_server(&addr);

    BAD_REDIS_ADDR.set(addr.parse().unwrap()).ok();

    let (_c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<BadRedisClientHandler>()
        .expect("client launch failed");

    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    let result = BAD_REDIS_RESULT.get().expect("on_start did not set result");
    assert_eq!(result, "ERROR", "expected parse error, got: {result}");

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
