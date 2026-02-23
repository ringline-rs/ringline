//! Integration tests for ringline-redis against a real Redis server.
//!
//! These tests are `#[ignore]` by default because they require a running
//! Redis instance on `127.0.0.1:6379`. Run them with:
//!
//!   cargo test -p ringline-redis --test integration -- --ignored --nocapture

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use ringline::{AsyncEventHandler, Config, ConnCtx, RinglineBuilder};
use ringline_redis::{Client, Pool, PoolConfig};

// ── Helpers ─────────────────────────────────────────────────────────────

static TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

const REDIS_ADDR: &str = "127.0.0.1:6379";

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

async fn connect_redis() -> Result<Client, String> {
    let addr: SocketAddr = REDIS_ADDR.parse().unwrap();
    let conn = ringline::connect(addr)
        .map_err(|e| format!("submit: {e}"))?
        .await
        .map_err(|e| format!("connect: {e}"))?;
    Ok(Client::new(conn))
}

/// Run a client-only test: launch a 1-worker ringline with `on_start`, wait
/// for it to finish, and check the stored result.
macro_rules! run_redis_test {
    ($result_static:ident, $test_fn:expr) => {{
        let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

        if std::net::TcpStream::connect_timeout(
            &REDIS_ADDR.parse().unwrap(),
            Duration::from_secs(2),
        )
        .is_err()
        {
            panic!("Redis not reachable at {REDIS_ADDR}");
        }

        struct Handler;

        impl AsyncEventHandler for Handler {
            #[allow(clippy::manual_async_fn)]
            fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
                async {}
            }

            fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
                Some(Box::pin(async move {
                    let result = async {
                        let mut client = connect_redis().await?;
                        let f: fn(
                            &mut Client,
                        )
                            -> Pin<Box<dyn Future<Output = Result<(), String>> + '_>> = $test_fn;
                        f(&mut client).await
                    }
                    .await;
                    $result_static.set(result).ok();
                    ringline::request_shutdown().ok();
                }))
            }

            fn create_for_worker(_id: usize) -> Self {
                Handler
            }
        }

        let (_shutdown, handles) = RinglineBuilder::new(test_config())
            .launch::<Handler>()
            .expect("launch failed");

        for h in handles {
            h.join().unwrap().unwrap();
        }

        let result = $result_static.get().expect("on_start did not set result");
        if let Err(e) = result {
            panic!("test failed: {e}");
        }
    }};
}

// ── Tests ───────────────────────────────────────────────────────────────

static PING_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn redis_ping() {
    run_redis_test!(PING_RESULT, |client| {
        Box::pin(async move { client.ping().await.map_err(|e| format!("ping: {e}")) })
    });
}

static SET_GET_DEL_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn redis_set_get_del() {
    run_redis_test!(SET_GET_DEL_RESULT, |client| {
        Box::pin(async move {
            client
                .set("ringline-test:key", "test-value")
                .await
                .map_err(|e| format!("set: {e}"))?;

            let val = client
                .get("ringline-test:key")
                .await
                .map_err(|e| format!("get: {e}"))?;
            let val = val.ok_or("get returned None")?;
            if val.as_ref() != b"test-value" {
                return Err(format!("get: expected test-value, got {:?}", val));
            }

            let deleted = client
                .del("ringline-test:key")
                .await
                .map_err(|e| format!("del: {e}"))?;
            if deleted != 1 {
                return Err(format!("del: expected 1, got {deleted}"));
            }

            let val = client
                .get("ringline-test:key")
                .await
                .map_err(|e| format!("get after del: {e}"))?;
            if val.is_some() {
                return Err("get after del: expected None".to_string());
            }

            Ok(())
        })
    });
}

static HASH_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn redis_hash_operations() {
    run_redis_test!(HASH_RESULT, |client| {
        Box::pin(async move {
            client.del("ringline-test:hash").await.ok();

            client
                .hset("ringline-test:hash", "field1", "value1")
                .await
                .map_err(|e| format!("hset: {e}"))?;
            client
                .hset("ringline-test:hash", "field2", "value2")
                .await
                .map_err(|e| format!("hset: {e}"))?;

            let val = client
                .hget("ringline-test:hash", "field1")
                .await
                .map_err(|e| format!("hget: {e}"))?;
            let val = val.ok_or("hget returned None")?;
            if val.as_ref() != b"value1" {
                return Err(format!("hget: expected value1, got {:?}", val));
            }

            let all = client
                .hgetall("ringline-test:hash")
                .await
                .map_err(|e| format!("hgetall: {e}"))?;
            if all.len() != 2 {
                return Err(format!("hgetall: expected 2 fields, got {}", all.len()));
            }

            let deleted = client
                .hdel("ringline-test:hash", &[b"field1", b"field2"])
                .await
                .map_err(|e| format!("hdel: {e}"))?;
            if deleted != 2 {
                return Err(format!("hdel: expected 2, got {deleted}"));
            }

            Ok(())
        })
    });
}

static LIST_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn redis_list_operations() {
    run_redis_test!(LIST_RESULT, |client| {
        Box::pin(async move {
            client.del("ringline-test:list").await.ok();

            client
                .lpush("ringline-test:list", &[b"a", b"b"])
                .await
                .map_err(|e| format!("lpush: {e}"))?;
            client
                .rpush("ringline-test:list", &[b"c"])
                .await
                .map_err(|e| format!("rpush: {e}"))?;

            let len = client
                .llen("ringline-test:list")
                .await
                .map_err(|e| format!("llen: {e}"))?;
            if len != 3 {
                return Err(format!("llen: expected 3, got {len}"));
            }

            let range = client
                .lrange("ringline-test:list", 0, -1)
                .await
                .map_err(|e| format!("lrange: {e}"))?;
            if range.len() != 3 {
                return Err(format!("lrange: expected 3 items, got {}", range.len()));
            }
            // lpush pushes left-to-right, so b is first, then a, then c (rpush).
            if range[0].as_ref() != b"b" {
                return Err(format!("lrange[0]: expected b, got {:?}", range[0]));
            }

            let popped = client
                .lpop("ringline-test:list")
                .await
                .map_err(|e| format!("lpop: {e}"))?;
            let popped = popped.ok_or("lpop returned None")?;
            if popped.as_ref() != b"b" {
                return Err(format!("lpop: expected b, got {:?}", popped));
            }

            client.del("ringline-test:list").await.ok();
            Ok(())
        })
    });
}

static SET_OPS_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn redis_set_operations() {
    run_redis_test!(SET_OPS_RESULT, |client| {
        Box::pin(async move {
            client.del("ringline-test:set").await.ok();

            client
                .sadd("ringline-test:set", &[b"a", b"b", b"c"])
                .await
                .map_err(|e| format!("sadd: {e}"))?;

            let card = client
                .scard("ringline-test:set")
                .await
                .map_err(|e| format!("scard: {e}"))?;
            if card != 3 {
                return Err(format!("scard: expected 3, got {card}"));
            }

            let members = client
                .smembers("ringline-test:set")
                .await
                .map_err(|e| format!("smembers: {e}"))?;
            if members.len() != 3 {
                return Err(format!(
                    "smembers: expected 3 members, got {}",
                    members.len()
                ));
            }

            let removed = client
                .srem("ringline-test:set", &[b"a"])
                .await
                .map_err(|e| format!("srem: {e}"))?;
            if removed != 1 {
                return Err(format!("srem: expected 1, got {removed}"));
            }

            client.del("ringline-test:set").await.ok();
            Ok(())
        })
    });
}

static INCR_DECR_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn redis_incr_decr() {
    run_redis_test!(INCR_DECR_RESULT, |client| {
        Box::pin(async move {
            client.del("ringline-test:counter").await.ok();

            client
                .set("ringline-test:counter", "10")
                .await
                .map_err(|e| format!("set: {e}"))?;

            let val = client
                .incr("ringline-test:counter")
                .await
                .map_err(|e| format!("incr: {e}"))?;
            if val != 11 {
                return Err(format!("incr: expected 11, got {val}"));
            }

            let val = client
                .decr("ringline-test:counter")
                .await
                .map_err(|e| format!("decr: {e}"))?;
            if val != 10 {
                return Err(format!("decr: expected 10, got {val}"));
            }

            let val = client
                .incrby("ringline-test:counter", 5)
                .await
                .map_err(|e| format!("incrby: {e}"))?;
            if val != 15 {
                return Err(format!("incrby: expected 15, got {val}"));
            }

            let val = client
                .decrby("ringline-test:counter", 3)
                .await
                .map_err(|e| format!("decrby: {e}"))?;
            if val != 12 {
                return Err(format!("decrby: expected 12, got {val}"));
            }

            client.del("ringline-test:counter").await.ok();
            Ok(())
        })
    });
}

static PIPELINE_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn redis_pipeline() {
    run_redis_test!(PIPELINE_RESULT, |client| {
        Box::pin(async move {
            client.del("ringline-test:pipe").await.ok();

            let results = client
                .pipeline()
                .set(b"ringline-test:pipe", b"pipe-value")
                .get(b"ringline-test:pipe")
                .del(b"ringline-test:pipe")
                .execute()
                .await
                .map_err(|e| format!("pipeline: {e}"))?;

            if results.len() != 3 {
                return Err(format!(
                    "pipeline: expected 3 results, got {}",
                    results.len()
                ));
            }

            Ok(())
        })
    });
}

// ── Pool test ───────────────────────────────────────────────────────────

static POOL_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn redis_pool() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    if std::net::TcpStream::connect_timeout(&REDIS_ADDR.parse().unwrap(), Duration::from_secs(2))
        .is_err()
    {
        panic!("Redis not reachable at {REDIS_ADDR}");
    }

    struct Handler;

    impl AsyncEventHandler for Handler {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
            async {}
        }

        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async move {
                let result = async {
                    let addr: SocketAddr = REDIS_ADDR.parse().unwrap();
                    let config = PoolConfig {
                        addr,
                        pool_size: 2,
                        connect_timeout_ms: 5000,
                        tls_server_name: None,
                        password: None,
                        username: None,
                    };
                    let mut pool = Pool::new(config);
                    pool.connect_all()
                        .await
                        .map_err(|e| format!("connect_all: {e}"))?;

                    if pool.connected_count() != 2 {
                        return Err(format!(
                            "connected_count: expected 2, got {}",
                            pool.connected_count()
                        ));
                    }

                    let mut client = pool.client().await.map_err(|e| format!("client: {e}"))?;
                    client
                        .set("ringline-test:pool", "pool-value")
                        .await
                        .map_err(|e| format!("set: {e}"))?;

                    let val = client
                        .get("ringline-test:pool")
                        .await
                        .map_err(|e| format!("get: {e}"))?;
                    let val = val.ok_or("get returned None")?;
                    if val.as_ref() != b"pool-value" {
                        return Err(format!("get: expected pool-value, got {:?}", val));
                    }

                    client
                        .del("ringline-test:pool")
                        .await
                        .map_err(|e| format!("del: {e}"))?;

                    pool.close_all();

                    if pool.connected_count() != 0 {
                        return Err(format!(
                            "connected_count after close: expected 0, got {}",
                            pool.connected_count()
                        ));
                    }

                    Ok(())
                }
                .await;
                POOL_RESULT.set(result).ok();
                ringline::request_shutdown().ok();
            }))
        }

        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<Handler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }

    let result = POOL_RESULT.get().expect("on_start did not set result");
    if let Err(e) = result {
        panic!("test failed: {e}");
    }
}
