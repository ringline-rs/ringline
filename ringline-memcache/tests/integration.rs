//! Integration tests for ringline-memcache against a real Memcached server.
//!
//! These tests are `#[ignore]` by default because they require a running
//! Memcached instance on `127.0.0.1:11211`. Run them with:
//!
//!   cargo test -p ringline-memcache --test integration -- --ignored --nocapture

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use ringline::{AsyncEventHandler, Config, ConnCtx, RinglineBuilder};
use ringline_memcache::{Client, Pool, PoolConfig};

// ── Helpers ─────────────────────────────────────────────────────────────

static TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

const MEMCACHE_ADDR: &str = "127.0.0.1:11211";

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

async fn connect_memcache() -> Result<Client, String> {
    let addr: SocketAddr = MEMCACHE_ADDR.parse().unwrap();
    let conn = ringline::connect(addr)
        .map_err(|e| format!("submit: {e}"))?
        .await
        .map_err(|e| format!("connect: {e}"))?;
    Ok(Client::new(conn))
}

macro_rules! run_memcache_test {
    ($result_static:ident, $test_fn:expr) => {{
        let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

        if std::net::TcpStream::connect_timeout(
            &MEMCACHE_ADDR.parse().unwrap(),
            Duration::from_secs(2),
        )
        .is_err()
        {
            panic!("Memcached not reachable at {MEMCACHE_ADDR}");
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
                        let mut client = connect_memcache().await?;
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

static VERSION_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn memcache_version() {
    run_memcache_test!(VERSION_RESULT, |client| {
        Box::pin(async move {
            let version = client
                .version()
                .await
                .map_err(|e| format!("version: {e}"))?;
            if version.is_empty() {
                return Err("version returned empty string".to_string());
            }
            println!("memcached version: {version}");
            Ok(())
        })
    });
}

static SET_GET_DEL_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn memcache_set_get_delete() {
    run_memcache_test!(SET_GET_DEL_RESULT, |client| {
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
            if val.data.as_ref() != b"test-value" {
                return Err(format!("get: expected test-value, got {:?}", val.data));
            }

            let deleted = client
                .delete("ringline-test:key")
                .await
                .map_err(|e| format!("delete: {e}"))?;
            if !deleted {
                return Err("delete returned false".to_string());
            }

            let val = client
                .get("ringline-test:key")
                .await
                .map_err(|e| format!("get after delete: {e}"))?;
            if val.is_some() {
                return Err("get after delete: expected None".to_string());
            }

            Ok(())
        })
    });
}

static ADD_REPLACE_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn memcache_add_replace() {
    run_memcache_test!(ADD_REPLACE_RESULT, |client| {
        Box::pin(async move {
            client.delete("ringline-test:add").await.ok();

            let added = client
                .add("ringline-test:add", "first")
                .await
                .map_err(|e| format!("add: {e}"))?;
            if !added {
                return Err("first add returned false".to_string());
            }

            let added_again = client
                .add("ringline-test:add", "second")
                .await
                .map_err(|e| format!("add again: {e}"))?;
            if added_again {
                return Err("second add returned true (expected false)".to_string());
            }

            let replaced = client
                .replace("ringline-test:add", "replaced")
                .await
                .map_err(|e| format!("replace: {e}"))?;
            if !replaced {
                return Err("replace returned false".to_string());
            }

            let val = client
                .get("ringline-test:add")
                .await
                .map_err(|e| format!("get: {e}"))?;
            let val = val.ok_or("get returned None")?;
            if val.data.as_ref() != b"replaced" {
                return Err(format!("get: expected replaced, got {:?}", val.data));
            }

            client.delete("ringline-test:add").await.ok();
            Ok(())
        })
    });
}

static INCR_DECR_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn memcache_incr_decr() {
    run_memcache_test!(INCR_DECR_RESULT, |client| {
        Box::pin(async move {
            client
                .set("ringline-test:num", "10")
                .await
                .map_err(|e| format!("set: {e}"))?;

            let val = client
                .incr("ringline-test:num", 5)
                .await
                .map_err(|e| format!("incr: {e}"))?;
            let val = val.ok_or("incr returned None")?;
            if val != 15 {
                return Err(format!("incr: expected 15, got {val}"));
            }

            let val = client
                .decr("ringline-test:num", 3)
                .await
                .map_err(|e| format!("decr: {e}"))?;
            let val = val.ok_or("decr returned None")?;
            if val != 12 {
                return Err(format!("decr: expected 12, got {val}"));
            }

            client.delete("ringline-test:num").await.ok();
            Ok(())
        })
    });
}

static APPEND_PREPEND_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn memcache_append_prepend() {
    run_memcache_test!(APPEND_PREPEND_RESULT, |client| {
        Box::pin(async move {
            client.delete("ringline-test:concat").await.ok();

            client
                .set("ringline-test:concat", "middle")
                .await
                .map_err(|e| format!("set: {e}"))?;

            let ok = client
                .append("ringline-test:concat", "-end")
                .await
                .map_err(|e| format!("append: {e}"))?;
            if !ok {
                return Err("append returned false".to_string());
            }

            let ok = client
                .prepend("ringline-test:concat", "start-")
                .await
                .map_err(|e| format!("prepend: {e}"))?;
            if !ok {
                return Err("prepend returned false".to_string());
            }

            let val = client
                .get("ringline-test:concat")
                .await
                .map_err(|e| format!("get: {e}"))?;
            let val = val.ok_or("get returned None")?;
            if val.data.as_ref() != b"start-middle-end" {
                return Err(format!(
                    "get: expected start-middle-end, got {:?}",
                    val.data
                ));
            }

            client.delete("ringline-test:concat").await.ok();
            Ok(())
        })
    });
}

static CAS_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn memcache_cas() {
    run_memcache_test!(CAS_RESULT, |client| {
        Box::pin(async move {
            client.delete("ringline-test:cas").await.ok();

            client
                .set("ringline-test:cas", "original")
                .await
                .map_err(|e| format!("set: {e}"))?;

            let values = client
                .gets(&[b"ringline-test:cas"])
                .await
                .map_err(|e| format!("gets: {e}"))?;
            if values.is_empty() {
                return Err("gets returned empty".to_string());
            }
            let cas_token = values[0].cas.ok_or("gets did not return CAS token")?;

            let ok = client
                .cas("ringline-test:cas", "updated", cas_token)
                .await
                .map_err(|e| format!("cas: {e}"))?;
            if !ok {
                return Err("cas returned false".to_string());
            }

            let val = client
                .get("ringline-test:cas")
                .await
                .map_err(|e| format!("get: {e}"))?;
            let val = val.ok_or("get returned None")?;
            if val.data.as_ref() != b"updated" {
                return Err(format!("get: expected updated, got {:?}", val.data));
            }

            client.delete("ringline-test:cas").await.ok();
            Ok(())
        })
    });
}

static FLUSH_ALL_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn memcache_flush_all() {
    run_memcache_test!(FLUSH_ALL_RESULT, |client| {
        Box::pin(async move {
            client
                .set("ringline-test:flush", "value")
                .await
                .map_err(|e| format!("set: {e}"))?;

            client
                .flush_all()
                .await
                .map_err(|e| format!("flush_all: {e}"))?;

            let val = client
                .get("ringline-test:flush")
                .await
                .map_err(|e| format!("get: {e}"))?;
            if val.is_some() {
                return Err("get after flush_all: expected None".to_string());
            }

            Ok(())
        })
    });
}

// ── Pool test ───────────────────────────────────────────────────────────

static POOL_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn memcache_pool() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    if std::net::TcpStream::connect_timeout(&MEMCACHE_ADDR.parse().unwrap(), Duration::from_secs(2))
        .is_err()
    {
        panic!("Memcached not reachable at {MEMCACHE_ADDR}");
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
                    let addr: SocketAddr = MEMCACHE_ADDR.parse().unwrap();
                    let config = PoolConfig {
                        addr,
                        pool_size: 2,
                        connect_timeout_ms: 5000,
                        tls_server_name: None,
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
                    if val.data.as_ref() != b"pool-value" {
                        return Err(format!("get: expected pool-value, got {:?}", val.data));
                    }

                    client
                        .delete("ringline-test:pool")
                        .await
                        .map_err(|e| format!("delete: {e}"))?;

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
