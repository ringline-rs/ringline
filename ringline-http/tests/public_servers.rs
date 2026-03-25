//! Integration tests against public HTTP servers.
//!
//! These tests are `#[ignore]` by default because they require network access
//! and a Linux kernel with io_uring support.
//!
//! Run them manually with:
//!
//!   cargo test -p ringline-http --test public_servers -- --ignored --nocapture

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use ringline::{AsyncEventHandler, Config, ConnCtx, TlsClientConfig};

// ── Helpers ─────────────────────────────────────────────────────────────

static TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn test_config(alpn: &[&[u8]]) -> Config {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if !alpn.is_empty() {
        tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    }

    let mut config = Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 64;
    config.recv_buffer.ring_size = 64;
    config.recv_buffer.buffer_size = 4096;
    config.max_connections = 64;
    config.send_copy_count = 64;
    config.tls_client = Some(TlsClientConfig {
        client_config: Arc::new(tls),
    });
    config
}

fn resolve(host: &str, port: u16) -> std::net::SocketAddr {
    use std::net::ToSocketAddrs;
    format!("{host}:{port}")
        .to_socket_addrs()
        .expect("DNS resolution failed")
        .next()
        .expect("no addresses found")
}

// ── HTTP/2 Tests ────────────────────────────────────────────────────────

static H2_GOOGLE_RESULT: OnceLock<String> = OnceLock::new();

#[test]
#[ignore]
fn h2_google() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let addr = resolve("www.google.com", 443);
    static ADDR: OnceLock<std::net::SocketAddr> = OnceLock::new();
    let _ = ADDR.set(addr);

    struct H2GoogleHandler;
    impl AsyncEventHandler for H2GoogleHandler {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
            async {}
        }

        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            let addr = *ADDR.get().unwrap();
            Some(Box::pin(async move {
                let result = async {
                    let mut client =
                        ringline_http::HttpClient::connect_h2(addr, "www.google.com").await?;

                    let resp = client
                        .get("/")
                        .header("user-agent", "ringline-http/0.1")
                        .send()
                        .await?;

                    let status = resp.status();
                    let body = resp.bytes();
                    Ok::<_, ringline_http::HttpError>((status, body.len()))
                }
                .await;

                match result {
                    Ok((status, body_len)) => {
                        println!("HTTP/2 google: status={status}, body={body_len} bytes");
                        if (status == 200 || status == 301 || status == 302) && body_len > 0 {
                            H2_GOOGLE_RESULT.set("OK".into()).ok();
                        } else {
                            H2_GOOGLE_RESULT
                                .set(format!("unexpected: status={status} body={body_len}"))
                                .ok();
                        }
                    }
                    Err(e) => {
                        H2_GOOGLE_RESULT.set(format!("ERR:{e}")).ok();
                    }
                }
                ringline::request_shutdown().ok();
            }))
        }

        fn create_for_worker(_id: usize) -> Self {
            H2GoogleHandler
        }
    }

    let (_shutdown, handles) = ringline::RinglineBuilder::new(test_config(&[b"h2"]))
        .launch::<H2GoogleHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }

    let r = H2_GOOGLE_RESULT.get().expect("test did not set result");
    assert_eq!(r, "OK", "h2_google: {r}");
}

static H2_CLOUDFLARE_RESULT: OnceLock<String> = OnceLock::new();

#[test]
#[ignore]
fn h2_cloudflare() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let addr = resolve("cloudflare.com", 443);
    static ADDR: OnceLock<std::net::SocketAddr> = OnceLock::new();
    let _ = ADDR.set(addr);

    struct H2CloudflareHandler;
    impl AsyncEventHandler for H2CloudflareHandler {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
            async {}
        }

        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            let addr = *ADDR.get().unwrap();
            Some(Box::pin(async move {
                let result = async {
                    let mut client =
                        ringline_http::HttpClient::connect_h2(addr, "cloudflare.com").await?;

                    let resp = client
                        .get("/")
                        .header("user-agent", "ringline-http/0.1")
                        .send()
                        .await?;

                    Ok::<_, ringline_http::HttpError>(resp.status())
                }
                .await;

                match result {
                    Ok(status) => {
                        println!("HTTP/2 cloudflare: status={status}");
                        if status == 200 || status == 301 || status == 302 || status == 403 {
                            H2_CLOUDFLARE_RESULT.set("OK".into()).ok();
                        } else {
                            H2_CLOUDFLARE_RESULT
                                .set(format!("unexpected status: {status}"))
                                .ok();
                        }
                    }
                    Err(e) => {
                        H2_CLOUDFLARE_RESULT.set(format!("ERR:{e}")).ok();
                    }
                }
                ringline::request_shutdown().ok();
            }))
        }

        fn create_for_worker(_id: usize) -> Self {
            H2CloudflareHandler
        }
    }

    let (_shutdown, handles) = ringline::RinglineBuilder::new(test_config(&[b"h2"]))
        .launch::<H2CloudflareHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }

    let r = H2_CLOUDFLARE_RESULT.get().expect("test did not set result");
    assert_eq!(r, "OK", "h2_cloudflare: {r}");
}

// ── HTTP/2 Multiplexed Test ─────────────────────────────────────────────

static H2_MULTIPLEX_RESULT: OnceLock<String> = OnceLock::new();

#[test]
#[ignore]
fn h2_multiplexed() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let addr = resolve("www.google.com", 443);
    static ADDR: OnceLock<std::net::SocketAddr> = OnceLock::new();
    let _ = ADDR.set(addr);

    struct H2MultiplexHandler;
    impl AsyncEventHandler for H2MultiplexHandler {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
            async {}
        }

        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            let addr = *ADDR.get().unwrap();
            Some(Box::pin(async move {
                let result = async {
                    let mut h2 =
                        ringline_http::H2AsyncConn::connect(addr, "www.google.com").await?;

                    // Fire two requests concurrently.
                    let s1 = h2.fire_request("GET", "/", "www.google.com", &[], None)?;
                    let s2 = h2.fire_request("GET", "/robots.txt", "www.google.com", &[], None)?;

                    // Recv both responses (in any order).
                    let (id1, r1) = h2.recv().await?;
                    let (id2, r2) = h2.recv().await?;

                    // Verify both stream IDs are accounted for.
                    let mut ids = vec![id1, id2];
                    ids.sort();
                    let mut expected = vec![s1, s2];
                    expected.sort();

                    if ids != expected {
                        return Err(ringline_http::HttpError::Protocol(format!(
                            "stream id mismatch: got {ids:?}, expected {expected:?}"
                        )));
                    }

                    Ok::<_, ringline_http::HttpError>((r1.status(), r2.status()))
                }
                .await;

                match result {
                    Ok((s1, s2)) => {
                        println!("HTTP/2 multiplexed: status1={s1}, status2={s2}");
                        if s1 > 0 && s2 > 0 {
                            H2_MULTIPLEX_RESULT.set("OK".into()).ok();
                        } else {
                            H2_MULTIPLEX_RESULT
                                .set(format!("bad statuses: {s1}, {s2}"))
                                .ok();
                        }
                    }
                    Err(e) => {
                        H2_MULTIPLEX_RESULT.set(format!("ERR:{e}")).ok();
                    }
                }
                ringline::request_shutdown().ok();
            }))
        }

        fn create_for_worker(_id: usize) -> Self {
            H2MultiplexHandler
        }
    }

    let (_shutdown, handles) = ringline::RinglineBuilder::new(test_config(&[b"h2"]))
        .launch::<H2MultiplexHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }

    let r = H2_MULTIPLEX_RESULT.get().expect("test did not set result");
    assert_eq!(r, "OK", "h2_multiplexed: {r}");
}

// ── HTTP/1.1 Test ───────────────────────────────────────────────────────

static H1_GOOGLE_RESULT: OnceLock<String> = OnceLock::new();

#[test]
#[ignore]
fn h1_google() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let addr = resolve("www.google.com", 443);
    static ADDR: OnceLock<std::net::SocketAddr> = OnceLock::new();
    let _ = ADDR.set(addr);

    struct H1GoogleHandler;
    impl AsyncEventHandler for H1GoogleHandler {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
            async {}
        }

        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            let addr = *ADDR.get().unwrap();
            Some(Box::pin(async move {
                let result = async {
                    let mut client =
                        ringline_http::HttpClient::connect_h1(addr, "www.google.com").await?;

                    let resp = client
                        .get("/")
                        .header("user-agent", "ringline-http/0.1")
                        .send()
                        .await?;

                    let status = resp.status();
                    let body = resp.bytes();
                    Ok::<_, ringline_http::HttpError>((status, body.len()))
                }
                .await;

                match result {
                    Ok((status, body_len)) => {
                        println!("HTTP/1.1 google: status={status}, body={body_len} bytes");
                        if (status == 200 || status == 301 || status == 302) && body_len > 0 {
                            H1_GOOGLE_RESULT.set("OK".into()).ok();
                        } else {
                            H1_GOOGLE_RESULT
                                .set(format!("unexpected: status={status} body={body_len}"))
                                .ok();
                        }
                    }
                    Err(e) => {
                        H1_GOOGLE_RESULT.set(format!("ERR:{e}")).ok();
                    }
                }
                ringline::request_shutdown().ok();
            }))
        }

        fn create_for_worker(_id: usize) -> Self {
            H1GoogleHandler
        }
    }

    let (_shutdown, handles) = ringline::RinglineBuilder::new(test_config(&[]))
        .launch::<H1GoogleHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }

    let r = H1_GOOGLE_RESULT.get().expect("test did not set result");
    assert_eq!(r, "OK", "h1_google: {r}");
}

// ── Streaming Test ──────────────────────────────────────────────────────

static H2_STREAMING_RESULT: OnceLock<String> = OnceLock::new();

#[test]
#[ignore]
fn h2_streaming() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let addr = resolve("www.google.com", 443);
    static ADDR: OnceLock<std::net::SocketAddr> = OnceLock::new();
    let _ = ADDR.set(addr);

    struct H2StreamingHandler;
    impl AsyncEventHandler for H2StreamingHandler {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
            async {}
        }

        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            let addr = *ADDR.get().unwrap();
            Some(Box::pin(async move {
                let result = async {
                    let mut client =
                        ringline_http::HttpClient::connect_h2(addr, "www.google.com").await?;

                    let mut stream = client
                        .get("/")
                        .header("user-agent", "ringline-http/0.1")
                        .send_streaming()
                        .await?;

                    let status = stream.status();
                    let mut total_bytes = 0usize;

                    while let Some(chunk) = stream.next_chunk().await? {
                        total_bytes += chunk.len();
                    }

                    Ok::<_, ringline_http::HttpError>((status, total_bytes))
                }
                .await;

                match result {
                    Ok((status, total)) => {
                        println!("HTTP/2 streaming: status={status}, body={total} bytes");
                        if (status == 200 || status == 301 || status == 302) && total > 0 {
                            H2_STREAMING_RESULT.set("OK".into()).ok();
                        } else {
                            H2_STREAMING_RESULT
                                .set(format!("unexpected: status={status} body={total}"))
                                .ok();
                        }
                    }
                    Err(e) => {
                        H2_STREAMING_RESULT.set(format!("ERR:{e}")).ok();
                    }
                }
                ringline::request_shutdown().ok();
            }))
        }

        fn create_for_worker(_id: usize) -> Self {
            H2StreamingHandler
        }
    }

    let (_shutdown, handles) = ringline::RinglineBuilder::new(test_config(&[b"h2"]))
        .launch::<H2StreamingHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }

    let r = H2_STREAMING_RESULT.get().expect("test did not set result");
    assert_eq!(r, "OK", "h2_streaming: {r}");
}
