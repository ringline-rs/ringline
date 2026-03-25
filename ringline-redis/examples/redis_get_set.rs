#![allow(clippy::manual_async_fn)]

//! Demonstrates basic Redis GET/SET using the ringline-redis client.
//!
//! Requires a running Redis server on localhost:6379 (or set REDIS_ADDR).
//!
//!   cargo run -p ringline-redis --example redis_get_set

use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;

use ringline::{AsyncEventHandler, Config, ConnCtx, RinglineBuilder};

static REDIS_ADDR: OnceLock<std::net::SocketAddr> = OnceLock::new();

struct RedisHandler;

impl AsyncEventHandler for RedisHandler {
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let addr = *REDIS_ADDR.get().unwrap();
        Some(Box::pin(async move {
            // Connect to Redis.
            let conn = match ringline::connect(addr) {
                Ok(f) => match f.await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("connect error: {e}");
                        ringline::request_shutdown().ok();
                        return;
                    }
                },
                Err(e) => {
                    eprintln!("submit error: {e}");
                    ringline::request_shutdown().ok();
                    return;
                }
            };

            let mut client = ringline_redis::Client::new(conn);

            // SET a key.
            match client.set(b"ringline:hello", b"world").await {
                Ok(()) => eprintln!("SET ringline:hello = world"),
                Err(e) => eprintln!("SET error: {e}"),
            }

            // GET it back.
            match client.get(b"ringline:hello").await {
                Ok(Some(value)) => {
                    eprintln!("GET ringline:hello = {}", String::from_utf8_lossy(&value));
                }
                Ok(None) => eprintln!("GET ringline:hello = (nil)"),
                Err(e) => eprintln!("GET error: {e}"),
            }

            // DEL cleanup.
            match client.del(b"ringline:hello").await {
                Ok(n) => eprintln!("DEL ringline:hello -> {n}"),
                Err(e) => eprintln!("DEL error: {e}"),
            }

            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        RedisHandler
    }
}

fn main() {
    let addr: std::net::SocketAddr = std::env::var("REDIS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:6379".to_string())
        .parse()
        .expect("invalid REDIS_ADDR");
    REDIS_ADDR.set(addr).unwrap();

    let mut config = Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;

    let (_shutdown, handles) = RinglineBuilder::new(config)
        .launch::<RedisHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
}
