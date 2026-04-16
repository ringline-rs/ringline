#![cfg(has_io_uring)]
//! End-to-end TLS echo tests.
//!
//! Tests the core TLS machinery: server-side TLS accept (handshake + data
//! exchange), and outbound `connect_tls` from one ringline worker to another.
//! Uses self-signed certificates generated at test time via `rcgen`.

use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder, TlsConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

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
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);
    (vec![cert_der], key.into())
}

fn server_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Arc<rustls::ServerConfig> {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    Arc::new(config)
}

fn client_tls_config(certs: &[CertificateDer<'static>]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert.clone()).unwrap();
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
        .into()
}

// ── TLS Echo Handler ────────────────────────────────────────────────────

struct TlsEchoHandler;

impl AsyncEventHandler for TlsEchoHandler {
    #[allow(clippy::manual_async_fn)]
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
        TlsEchoHandler
    }
}

// ── Test 1: External rustls client → ringline TLS server ────────────────

#[test]
fn tls_echo_with_external_client() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (certs, key) = generate_self_signed();
    let server_config = server_tls_config(certs.clone(), key);

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let mut config = test_config();
    config.tls = Some(TlsConfig { server_config });

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr.parse().unwrap())
        .launch::<TlsEchoHandler>()
        .expect("launch failed");

    wait_for_server(&addr);

    // Connect with a rustls client.
    let client_config = client_tls_config(&certs);
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);

    // Send and receive data over TLS.
    let msg = b"Hello, TLS ringline!";
    stream.write_all(msg).unwrap();
    stream.flush().unwrap();

    let mut buf = vec![0u8; msg.len()];
    let mut total = 0;
    while total < msg.len() {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("TLS read error: {e}"),
        }
    }
    assert_eq!(&buf[..total], msg, "echoed data mismatch");

    // Send a larger message to exercise multi-chunk TLS.
    let large_msg = vec![0xABu8; 8192];
    stream.write_all(&large_msg).unwrap();
    stream.flush().unwrap();

    let mut large_buf = vec![0u8; large_msg.len()];
    let mut total = 0;
    while total < large_msg.len() {
        match stream.read(&mut large_buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("TLS read error (large): {e}"),
        }
    }
    assert_eq!(&large_buf[..total], &large_msg[..], "large echo mismatch");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Test 2: Outbound connect_tls from ringline worker ───────────────────

static TLS_SERVER_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static TLS_CONNECT_RESULT: OnceLock<String> = OnceLock::new();

struct TlsClientHandler;

impl AsyncEventHandler for TlsClientHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *TLS_SERVER_ADDR.get().expect("server addr not set");
        Some(Box::pin(async move {
            let conn = match ringline::connect_tls(server_addr, "localhost") {
                Ok(fut) => match fut.await {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        TLS_CONNECT_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                        ringline::request_shutdown().ok();
                        return;
                    }
                },
                Err(e) => {
                    TLS_CONNECT_RESULT.set(format!("SUBMIT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };

            // Send data over TLS and read back.
            let msg = b"ringline-to-ringline TLS echo";
            if let Err(e) = conn.send(msg) {
                TLS_CONNECT_RESULT.set(format!("SEND_ERR:{e}")).ok();
                ringline::request_shutdown().ok();
                return;
            }

            let mut received = Vec::new();
            let n = conn
                .with_data(|data| {
                    received.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                })
                .await;

            if n == 0 {
                TLS_CONNECT_RESULT.set("EOF".to_string()).ok();
            } else if received == msg {
                TLS_CONNECT_RESULT.set("OK".to_string()).ok();
            } else {
                TLS_CONNECT_RESULT
                    .set(format!("MISMATCH:{}", String::from_utf8_lossy(&received)))
                    .ok();
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsClientHandler
    }
}

#[test]
fn tls_outbound_connect_and_echo() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (certs, key) = generate_self_signed();
    let server_config = server_tls_config(certs.clone(), key);

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    // Start TLS server.
    let mut srv_config = test_config();
    srv_config.tls = Some(TlsConfig { server_config });

    let (s_shutdown, s_handles) = RinglineBuilder::new(srv_config)
        .bind(addr.parse().unwrap())
        .launch::<TlsEchoHandler>()
        .expect("server launch failed");

    wait_for_server(&addr);
    TLS_SERVER_ADDR.set(addr.parse().unwrap()).ok();

    // Start client-only ringline with TLS client config.
    let client_tls = client_tls_config(&certs);
    let mut cli_config = test_config();
    cli_config.tls_client = Some(ringline::TlsClientConfig {
        client_config: client_tls,
    });

    let (_c_shutdown, c_handles) = RinglineBuilder::new(cli_config)
        .launch::<TlsClientHandler>()
        .expect("client launch failed");

    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    let result = TLS_CONNECT_RESULT
        .get()
        .expect("on_start did not set result");
    assert_eq!(result, "OK", "expected OK, got: {result}");

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
