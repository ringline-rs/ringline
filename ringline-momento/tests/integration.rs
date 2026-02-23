//! Integration tests for ringline-momento against a real Momento cache.
//!
//! These tests are `#[ignore]` by default because they require:
//! - `MOMENTO_AUTH_TOKEN` (or `MOMENTO_API_KEY`) environment variable
//! - `MOMENTO_CACHE_NAME` environment variable (defaults to "test-cache")
//! - Network access to Momento servers
//!
//! Run them with:
//!
//!   cargo test -p ringline-momento --test integration -- --ignored --nocapture

use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::OnceLock;

use ringline::{AsyncEventHandler, Config, ConnCtx, RinglineBuilder};
use ringline_momento::{Client, Credential};

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

fn cache_name() -> String {
    std::env::var("MOMENTO_CACHE_NAME").unwrap_or_else(|_| "test-cache".to_string())
}

/// Pre-resolve DNS and build a credential with the resolved IP address.
/// DNS resolution uses blocking `getaddrinfo` which must happen outside
/// the io_uring event loop.
fn pre_resolve_credential() -> (Credential, SocketAddr) {
    let original = Credential::from_env().expect("failed to build credential from env");
    let host = original.host();
    let port = original.port();
    let addr_str = format!("{host}:{port}");
    let addr: SocketAddr = addr_str
        .to_socket_addrs()
        .unwrap_or_else(|e| panic!("failed to resolve {addr_str}: {e}"))
        .next()
        .unwrap_or_else(|| panic!("no addresses found for {addr_str}"));

    // Build a credential that uses the resolved IP so Client::connect
    // inside the runtime won't need DNS resolution. Set the original
    // hostname as the SNI host for TLS.
    let tls_host = original.tls_host().to_string();
    let resolved =
        Credential::with_endpoint(original.token(), format!("{addr}")).with_sni_host(tls_host);
    (resolved, addr)
}

/// Stored pre-resolved credential for use inside the runtime.
static RESOLVED_CREDENTIAL: OnceLock<Credential> = OnceLock::new();

/// Connect to Momento using a pre-resolved credential (no DNS inside the runtime).
async fn connect_momento() -> Result<Client, String> {
    let credential = RESOLVED_CREDENTIAL
        .get()
        .expect("credential not pre-resolved");
    Client::connect_with_timeout(credential, 10_000)
        .await
        .map_err(|e| format!("connect: {e}"))
}

macro_rules! run_momento_test {
    ($result_static:ident, $test_fn:expr) => {{
        let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

        if std::env::var("MOMENTO_API_KEY").is_err() && std::env::var("MOMENTO_AUTH_TOKEN").is_err()
        {
            panic!("MOMENTO_API_KEY or MOMENTO_AUTH_TOKEN must be set");
        }

        // Pre-resolve DNS on the main thread before entering the runtime.
        let (resolved, _addr) = pre_resolve_credential();
        RESOLVED_CREDENTIAL.set(resolved).ok();

        struct Handler;

        impl AsyncEventHandler for Handler {
            #[allow(clippy::manual_async_fn)]
            fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
                async {}
            }

            fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
                Some(Box::pin(async move {
                    let result = async {
                        let mut client = connect_momento().await?;
                        let cache = cache_name();
                        let f: for<'a> fn(
                            &'a mut Client,
                            &'a str,
                        ) -> Pin<
                            Box<dyn Future<Output = Result<(), String>> + 'a>,
                        > = $test_fn;
                        f(&mut client, &cache).await
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

static SET_GET_DEL_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn momento_set_get_delete() {
    run_momento_test!(SET_GET_DEL_RESULT, |client, cache| {
        Box::pin(async move {
            client
                .set(cache, b"ringline-test:key", b"test-value", 60_000)
                .await
                .map_err(|e| format!("set: {e}"))?;

            let val = client
                .get(cache, b"ringline-test:key")
                .await
                .map_err(|e| format!("get: {e}"))?;
            let val = val.ok_or("get returned None")?;
            if val.as_ref() != b"test-value" {
                return Err(format!("get: expected test-value, got {:?}", val));
            }

            client
                .delete(cache, b"ringline-test:key")
                .await
                .map_err(|e| format!("delete: {e}"))?;

            let val = client
                .get(cache, b"ringline-test:key")
                .await
                .map_err(|e| format!("get after delete: {e}"))?;
            if val.is_some() {
                return Err("get after delete: expected None".to_string());
            }

            Ok(())
        })
    });
}

static FIRE_RECV_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn momento_fire_recv() {
    run_momento_test!(FIRE_RECV_RESULT, |client, cache| {
        Box::pin(async move {
            let set_id = client
                .fire_set(cache, b"ringline-test:fire", b"fire-value", 60_000)
                .map_err(|e| format!("fire_set: {e}"))?;
            let get_id = client
                .fire_get(cache, b"ringline-test:fire")
                .map_err(|e| format!("fire_get: {e}"))?;

            let mut set_ok = false;
            let mut get_ok = false;

            for _ in 0..2 {
                let op = client.recv().await.map_err(|e| format!("recv: {e}"))?;
                match op {
                    ringline_momento::CompletedOp::Set { id, result, .. } => {
                        result.map_err(|e| format!("set result: {e}"))?;
                        if id.value() == set_id.value() {
                            set_ok = true;
                        }
                    }
                    ringline_momento::CompletedOp::Get { id, result, .. } => {
                        let _val = result.map_err(|e| format!("get result: {e}"))?;
                        if id.value() == get_id.value() {
                            get_ok = true;
                        }
                    }
                    _ => {}
                }
            }

            if !set_ok {
                return Err("did not receive set completion".to_string());
            }
            if !get_ok {
                return Err("did not receive get completion".to_string());
            }

            client
                .delete(cache, b"ringline-test:fire")
                .await
                .map_err(|e| format!("delete: {e}"))?;

            Ok(())
        })
    });
}

static GET_MISS_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

#[test]
#[ignore]
fn momento_get_miss() {
    run_momento_test!(GET_MISS_RESULT, |client, cache| {
        Box::pin(async move {
            let val = client
                .get(cache, b"ringline-test:nonexistent-key-12345")
                .await
                .map_err(|e| format!("get: {e}"))?;
            if val.is_some() {
                return Err("get of non-existent key: expected None".to_string());
            }
            Ok(())
        })
    });
}
