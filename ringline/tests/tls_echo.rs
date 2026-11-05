//! End-to-end TLS echo tests.
//!
//! Tests the core TLS machinery: server-side TLS accept (handshake + data
//! exchange), and outbound `connect(addr).tls(..)` from one ringline worker to another.
//! Uses self-signed certificates generated at test time via `rcgen`.

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, TlsConfig, TlsInfo,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

// ── Helpers ─────────────────────────────────────────────────────────────

static TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Read until `buf` is full, **failing when progress stalls** rather than
/// retrying forever.
///
/// `TcpStream::set_read_timeout` surfaces a timed-out read as
/// `ErrorKind::WouldBlock`, which is indistinguishable from "no data yet". So
/// a `WouldBlock` arm that retries unconditionally makes the read timeout
/// **inert**: any stall becomes an unbounded hang instead of a failure. This
/// file already learned that once — see the `big_send` reader, whose comment
/// records a six-hour CI hang from the same shape — and this is that fix,
/// factored out so the remaining readers cannot regress to it.
///
/// The budget is *time without progress*, not total time, so a large transfer
/// on a slow link still succeeds while a genuine stall fails fast. Panics
/// report how far the read got, which is the number that localises the stall.
fn read_until_full_or_stalled(
    stream: &mut impl Read,
    buf: &mut [u8],
    stall_budget: Duration,
    what: &str,
) -> usize {
    let want = buf.len();
    let mut total = 0;
    let mut last_progress = Instant::now();
    while total < want {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                last_progress = Instant::now();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    last_progress.elapsed() < stall_budget,
                    "{what}: no progress for {stall_budget:?} at {total}/{want} bytes"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("{what}: read error at {total}/{want} bytes: {e}"),
        }
    }
    total
}

fn test_config_builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        // One whole TLS record per slot, which the unbuffered engine needs.
        .send_pool(64, 16448)
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

/// The server config ringline uses, built with ringline's builder.
fn ringline_server_tls(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> TlsConfig {
    TlsConfig::builder().cert(certs, key).build().unwrap()
}

/// The client config ringline uses, built with ringline's builder.
fn ringline_client_tls(certs: &[CertificateDer<'static>]) -> ringline::TlsClientConfig {
    ringline::TlsClientConfig::builder()
        .root_certificates(certs.iter().cloned())
        .build()
        .unwrap()
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
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
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
fn a_plaintext_and_a_tls_listener_coexist_in_one_process() {
    // The combination per-listener TLS exists for, and the one the process-wide
    // `ConfigBuilder::tls()` could never express: one runtime serving plaintext
    // on one port and TLS on another. With a single global config every
    // listener had to agree.
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (certs, key) = generate_self_signed();
    let server_config = ringline_server_tls(certs.clone(), key);

    // No process-wide `.tls()`: the TLS listener carries its own config, and
    // the plaintext one must stay plaintext.
    let config = test_config_builder().build().expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .bind_tls("127.0.0.1:0".parse().unwrap(), server_config)
        .launch::<TlsEchoHandler>()
        .expect("launch failed");

    assert_eq!(shutdown.listener_count(), 2);
    let bound = shutdown.bound_addrs();
    let plain_addr = bound[0].expect("plaintext listener address").to_string();
    let tls_addr = bound[1].expect("TLS listener address").to_string();

    wait_for_server(&plain_addr);
    wait_for_server(&tls_addr);

    // Plaintext listener: a bare TCP echo, no handshake.
    {
        let mut tcp = TcpStream::connect(&plain_addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.write_all(b"plain").unwrap();
        tcp.flush().unwrap();
        let mut buf = [0u8; 5];
        tcp.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"plain", "listener 0 must speak plaintext");
    }

    // TLS listener: a full rustls handshake on the other port.
    {
        let client_config = client_tls_config(&certs);
        let server_name: ServerName<'_> = "localhost".try_into().unwrap();
        let mut tls_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
        let mut tcp = TcpStream::connect(&tls_addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
        stream.write_all(b"secret").unwrap();
        stream.flush().unwrap();
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"secret", "listener 1 must terminate TLS");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn tls_echo_with_external_client() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (certs, key) = generate_self_signed();
    let server_config = ringline_server_tls(certs.clone(), key);

    let config = test_config_builder()
        .tls(server_config)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsEchoHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

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
    let total = read_until_full_or_stalled(
        &mut stream,
        &mut large_buf,
        Duration::from_secs(30),
        "large TLS echo",
    );
    assert_eq!(&large_buf[..total], &large_msg[..], "large echo mismatch");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Test 1b: Large multi-chunk payloads (BufRead fill_buf/consume loop) ──

/// Echo payloads larger than rustls's internal plaintext buffer (~16 KiB) so
/// the recv-side `fill_buf`/`consume` drain loop iterates across multiple
/// chunks and across multiple TLS records. This is the regression guard for
/// the zero-scratch drain: any off-by-one in the chunk advance would corrupt
/// the round-trip. A non-constant byte pattern makes mis-ordering detectable.
///
/// Runs on both backends. (It was briefly gated to io_uring while the mio
/// backend had a large-payload TLS busy-spin; that was fixed by the #241
/// TLS output-queueing parity work and the gate removed — both verified by
/// this test passing on mio.)
/// A handler that responds to the first received byte with one large
/// `send()` — larger than rustls's 64 KiB ciphertext buffer cap
/// (`DEFAULT_BUFFER_LIMIT`). Exercises the interleaved encrypt/drain loop:
/// a single oversized `writer().write_all()` used to fail with WriteZero
/// after the first 64 KiB was already encrypted and queued.
struct TlsBigSendHandler;

const BIG_SEND_SIZE: usize = 150 * 1024;

/// What `TlsBigSendHandler`'s awaited send resolved with.
static BIG_SEND_RESULT: std::sync::Mutex<Option<usize>> = std::sync::Mutex::new(None);

fn big_send_payload() -> Vec<u8> {
    (0..BIG_SEND_SIZE)
        .map(|i| (i as u32).wrapping_mul(2246822519) as u8)
        .collect()
}

impl AsyncEventHandler for TlsBigSendHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }
            let payload = big_send_payload();
            let sent = conn
                .send(&payload)
                .expect("large TLS send submit failed")
                .await
                .expect("large TLS send failed");
            *BIG_SEND_RESULT.lock().unwrap() = Some(sent as usize);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsBigSendHandler
    }
}

#[test]
fn tls_single_send_larger_than_rustls_buffer() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (certs, key) = generate_self_signed();
    let server_config = ringline_server_tls(certs.clone(), key);

    let config = test_config_builder()
        .tls(server_config)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsBigSendHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let client_config = client_tls_config(&certs);
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);

    stream.write_all(b"go").unwrap();
    stream.flush().unwrap();

    let expected = big_send_payload();
    let mut buf = vec![0u8; BIG_SEND_SIZE];
    let total = read_until_full_or_stalled(
        &mut stream,
        &mut buf,
        Duration::from_secs(30),
        "single send larger than the rustls buffer",
    );
    assert_eq!(total, BIG_SEND_SIZE, "short read");
    assert_eq!(buf, expected, "byte-exact mismatch — chunk reorder or loss");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    // The awaited send reports the plaintext it was handed, not the
    // ciphertext of its records.
    assert_eq!(
        BIG_SEND_RESULT.lock().unwrap().take(),
        Some(BIG_SEND_SIZE),
        "the TLS send resolved with a length other than the caller's"
    );
}

#[test]
fn tls_echo_large_multichunk() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (certs, key) = generate_self_signed();
    let server_config = ringline_server_tls(certs.clone(), key);

    // The 1 MiB payload needs > 64 in-flight echo chunks at peak (the
    // synchronous client writes the whole payload before reading, so echo
    // sends queue until it turns around). The default 64-slot test pool is
    // about 1 MiB — sitting on the exhaustion cliff, and TlsEchoHandler's
    // send_nowait errors are swallowed, which turned exhaustion into a
    // silent short echo. Give this test 4× headroom.
    let config = test_config_builder()
        .send_pool(256, 16448)
        .tls(server_config)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsEchoHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let client_config = client_tls_config(&certs);
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);

    // All sizes well past rustls's ~16 KiB plaintext buffer so the drain
    // loop must iterate over several chunks and several records; 1 MiB also
    // exceeds rustls's 64 KiB ciphertext buffer cap many times over on the
    // echo side.
    for &size in &[64 * 1024usize, 100 * 1024, 200 * 1024, 1024 * 1024] {
        // Distinctive, position-dependent pattern so any chunk reorder or
        // off-by-one in the advance is caught by the byte-exact comparison.
        let msg: Vec<u8> = (0..size)
            .map(|i| (i as u32).wrapping_mul(2654435761) as u8)
            .collect();

        stream.write_all(&msg).unwrap();
        stream.flush().unwrap();

        let mut buf = vec![0u8; size];
        let mut total = 0;
        // Time-bounded no-progress deadline: each WouldBlock here costs the
        // full 10s SO_RCVTIMEO, so an unbounded (or count-bounded) retry
        // loop turned a dropped echo chunk into a 6-hour CI hang
        // (run 33052650385) instead of a fast failure.
        let mut last_progress = std::time::Instant::now();
        while total < size {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    last_progress = std::time::Instant::now();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        last_progress.elapsed() < Duration::from_secs(30),
                        "no echo progress for 30s at {total}/{size} bytes"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("TLS read error ({size} bytes): {e}"),
            }
        }
        assert_eq!(total, size, "short read for {size}-byte payload");
        assert_eq!(buf, msg, "byte-exact mismatch for {size}-byte payload");
    }

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
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server_addr = *TLS_SERVER_ADDR.get().expect("server addr not set");
        Some(Box::pin(async move {
            let conn = match ringline::connect(server_addr).tls("localhost").await {
                Ok(ctx) => ctx,
                Err(e) => {
                    TLS_CONNECT_RESULT.set(format!("CONNECT_ERR:{e}")).ok();
                    ringline::request_shutdown().ok();
                    return;
                }
            };
            // Reading an outbound connection goes through its read half.
            let (mut conn_tx, mut conn_rx) = conn.split();

            // Send data over TLS and read back.
            let msg = b"ringline-to-ringline TLS echo";
            if let Err(e) = conn_tx.send(msg) {
                TLS_CONNECT_RESULT.set(format!("SEND_ERR:{e}")).ok();
                ringline::request_shutdown().ok();
                return;
            }

            let mut received = Vec::new();
            let n = conn_rx
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
    let server_config = ringline_server_tls(certs.clone(), key);

    // Start TLS server.
    let srv_config = test_config_builder()
        .tls(server_config)
        .build()
        .expect("valid config");

    let (s_shutdown, s_handles) = RinglineBuilder::new(srv_config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsEchoHandler>()
        .expect("server launch failed");
    let addr = s_shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);
    TLS_SERVER_ADDR.set(addr.parse().unwrap()).ok();

    // Start client-only ringline with TLS client config.
    let client_tls = ringline_client_tls(&certs);
    let cli_config = test_config_builder()
        .tls_client(client_tls)
        .build()
        .expect("valid config");

    let (c_shutdown, c_handles) = RinglineBuilder::new(cli_config)
        .launch::<TlsClientHandler>()
        .expect("client launch failed");

    common::join_workers(&c_shutdown, c_handles);

    let result = TLS_CONNECT_RESULT
        .get()
        .expect("on_start did not set result");
    assert_eq!(result, "OK", "expected OK, got: {result}");

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}

// ── Test 3: TlsInfo accessors ────────────────────────────────────────────

/// Snapshot of TlsInfo fields recorded by the handler on the first recv.
struct TlsInfoSnapshot {
    is_some: bool,
    protocol_version: Option<ringline::TlsVersion>,
    cipher_suite: Option<ringline::CipherSuite>,
    alpn_protocol: Option<Vec<u8>>,
    sni_hostname: Option<String>,
}

static TLS_INFO_SNAPSHOT: Mutex<Option<TlsInfoSnapshot>> = Mutex::new(None);

struct TlsInfoHandler;

impl AsyncEventHandler for TlsInfoHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            let mut recorded = false;
            loop {
                let n = rx
                    .with_data(|data| {
                        // Record TlsInfo on the first data arrival (handshake is
                        // already complete — data is decrypted plaintext).
                        if !recorded {
                            recorded = true;
                            let info: Option<TlsInfo> = tx.tls_info();
                            let snapshot = TlsInfoSnapshot {
                                is_some: info.is_some(),
                                protocol_version: info.as_ref().and_then(|i| i.protocol_version()),
                                cipher_suite: info.as_ref().and_then(|i| i.cipher_suite()),
                                alpn_protocol: info
                                    .as_ref()
                                    .and_then(|i| i.alpn_protocol())
                                    .map(|b| b.to_vec()),
                                sni_hostname: info
                                    .as_ref()
                                    .and_then(|i| i.sni_hostname())
                                    .map(|s| s.to_string()),
                            };
                            *TLS_INFO_SNAPSHOT.lock().unwrap() = Some(snapshot);
                        }
                        let _ = tx.send_nowait(data);
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
        TlsInfoHandler
    }
}

#[test]
fn tls_info_accessors() {
    tls_info_accessors_with(false);
}

/// The same with the TLS config given per listener (`bind_tls`) rather than
/// process-wide: the unbuffered engine wraps each listener's config to capture
/// the SNI hostname, as it wraps the process-wide one.
#[test]
fn tls_info_accessors_on_a_bind_tls_listener() {
    tls_info_accessors_with(true);
}

fn tls_info_accessors_with(per_listener: bool) {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    // Reset shared state from any prior test run.
    *TLS_INFO_SNAPSHOT.lock().unwrap() = None;

    let (certs, key) = generate_self_signed();
    let server_config = ringline_server_tls(certs.clone(), key);

    let (shutdown, handles) = if per_listener {
        let config = test_config_builder().build().expect("valid config");
        RinglineBuilder::new(config)
            .bind_tls("127.0.0.1:0".parse().unwrap(), server_config)
            .launch::<TlsInfoHandler>()
            .expect("launch failed")
    } else {
        let config = test_config_builder()
            .tls(server_config)
            .build()
            .expect("valid config");
        RinglineBuilder::new(config)
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<TlsInfoHandler>()
            .expect("launch failed")
    };
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    // Connect with a rustls client using SNI "localhost".
    let client_config = client_tls_config(&certs);
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);

    // One round-trip to trigger on_accept and populate TLS_INFO_SNAPSHOT.
    let msg = b"tls-info-probe";
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

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }

    // Assert all four TlsInfo accessors.
    let guard = TLS_INFO_SNAPSHOT.lock().unwrap();
    let snap = guard
        .as_ref()
        .expect("TlsInfo was never recorded — handler did not run");

    assert!(
        snap.is_some,
        "conn.tls_info() returned None after handshake"
    );
    // Both peers offer TLS 1.3, which rustls prefers.
    assert_eq!(
        snap.protocol_version,
        Some(ringline::TlsVersion::Tls13),
        "protocol_version() after a completed TLS handshake"
    );
    let suite = snap
        .cipher_suite
        .expect("cipher_suite() was None after completed TLS handshake");
    assert!(
        !matches!(suite, ringline::CipherSuite::Unknown(_)),
        "a ring TLS 1.3 suite is named: {suite:?}"
    );
    // No ALPN protocols are configured in server_tls_config, so the handshake
    // does not negotiate one.
    assert_eq!(
        snap.alpn_protocol, None,
        "expected alpn_protocol() == None (no ALPN configured)"
    );
    // The client above used "localhost" as its ServerName, so its ClientHello
    // carries that SNI. The buffered engine reads it from
    // `ServerConnection::server_name()`; the unbuffered engine captures it from
    // the ClientHello through the certificate resolver (`unbuffered::sni`).
    assert_eq!(
        snap.sni_hostname.as_deref(),
        Some("localhost"),
        "sni_hostname() should reflect the client's SNI value"
    );
}

/// A send-pool slot one byte smaller than one whole TLS record is refused at
/// launch when the only TLS is a per-listener config (`bind_tls`), as it is
/// for a process-wide one.
#[cfg(not(feature = "tls-buffered"))]
#[test]
fn a_bind_tls_listener_with_a_slot_too_small_for_tls_is_refused() {
    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .send_pool(64, 16412)
        .build()
        .expect("valid without TLS");
    let result = RinglineBuilder::new(config)
        .bind_tls(
            "127.0.0.1:0".parse().unwrap(),
            ringline_server_tls(certs, key),
        )
        .launch::<TlsInfoHandler>();
    let err = match result {
        Ok((shutdown, handles)) => {
            shutdown.shutdown();
            for h in handles {
                let _ = h.join();
            }
            panic!("launched with a 16412-byte send slot and a TLS listener");
        }
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("send_copy_slot_size"),
        "unexpected error: {err}"
    );
}

// ── Test 5: Server-initiated clean TLS close ────────────────────────────

/// Echo one message, then close the connection from the server side.
struct TlsCloseHandler;

impl AsyncEventHandler for TlsCloseHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            rx.with_data(|data| {
                let _ = tx.send_nowait(data);
                ParseResult::Consumed(data.len())
            })
            .await;
            tx.close();
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsCloseHandler
    }
}

/// A ringline TLS server closing a connection must emit a close_notify alert
/// before the FIN, so the peer can tell a clean shutdown from a truncation
/// attack. Both engines owe this; they produce the alert differently (the
/// buffered engine queues it with `send_close_notify`, the unbuffered one
/// encrypts it through `WriteTraffic::queue_close_notify`), so this is the
/// guard on the close path being engine-aware at all.
///
/// The assertion is `peer_has_closed()`, not "the read returned 0": a server
/// that sends only a FIN also ends the client's reads, and rustls reports that
/// as `UnexpectedEof` instead.
#[test]
fn tls_server_close_sends_close_notify() {
    server_close_sends_close_notify::<TlsCloseHandler>();
}

/// Echo one message, then return without closing: the runtime closes the
/// connection when its task finishes.
struct TlsReturnHandler;

impl AsyncEventHandler for TlsReturnHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            rx.with_data(|data| {
                let _ = tx.send_nowait(data);
                ParseResult::Consumed(data.len())
            })
            .await;
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsReturnHandler
    }
}

/// A handler that returns closes its connection with a close_notify too.
#[test]
fn tls_handler_return_sends_close_notify() {
    server_close_sends_close_notify::<TlsReturnHandler>();
}

/// Echo one message through a server running `H`, then check that the
/// server's close carried a close_notify.
fn server_close_sends_close_notify<H: AsyncEventHandler>() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (certs, key) = generate_self_signed();
    let server_config = ringline_server_tls(certs.clone(), key);

    let config = test_config_builder()
        .tls(server_config)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let client_config = client_tls_config(&certs);
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    {
        let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
        let msg = b"close me";
        stream.write_all(msg).unwrap();
        stream.flush().unwrap();
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, msg, "echo mismatch before close");
    }

    // Drain the rest of the connection by hand: `rustls::Stream` maps both a
    // clean close and a truncation to a read of 0, which is exactly the
    // distinction under test.
    //
    // Check before reading as well as after. The alert can arrive in the same
    // TCP segment as the echo, in which case `Stream::read_exact` above already
    // fed it to the deframer and there is nothing left on the socket — a loop
    // that only inspected the state after a fresh read would see the FIN and
    // wrongly report a truncation (this raced roughly one run in three).
    let mut peer_closed = tls_conn
        .process_new_packets()
        .expect("server sent a malformed record")
        .peer_has_closed();
    while !peer_closed {
        match tls_conn.read_tls(&mut tcp) {
            Ok(0) => break, // FIN
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("read_tls failed: {e}"),
        }
        peer_closed = tls_conn
            .process_new_packets()
            .expect("server sent a malformed record after echoing")
            .peer_has_closed();
    }

    assert!(
        peer_closed,
        "server closed without close_notify — the peer cannot distinguish a \
         clean shutdown from a truncated stream"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Read one byte, queue an 8 MiB reply, and return: the runtime closes the
/// connection gracefully while the reply is still draining.
#[cfg(has_io_uring)]
struct TlsBigReplyThenReturn;

#[cfg(has_io_uring)]
const BIG_REPLY: usize = 8 << 20;

#[cfg(has_io_uring)]
impl AsyncEventHandler for TlsBigReplyThenReturn {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(1)
                    }
                })
                .await;
            if n == 0 {
                return;
            }
            let chunk = vec![0x5au8; 64 * 1024];
            for _ in 0..BIG_REPLY / chunk.len() {
                conn.send_nowait(&chunk).expect("queue the reply");
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsBigReplyThenReturn
    }
}

/// A graceful close whose queued reply takes longer than
/// `close_notify_timeout_ms` to drain delivers the whole reply and then the
/// close_notify: the graceful close arms no deadline.
#[cfg(has_io_uring)]
#[test]
fn a_slow_reader_gets_the_whole_reply_before_close_notify() {
    use std::os::fd::AsRawFd;
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .send_pool(1024, 16448)
        .close_notify_timeout_ms(300)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsBigReplyThenReturn>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn =
        rustls::ClientConnection::new(client_tls_config(&certs), server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    // A small receive buffer keeps the server's sends waiting on the reads.
    let rcvbuf: libc::c_int = 64 * 1024;
    let rc = unsafe {
        libc::setsockopt(
            tcp.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_RCVBUF)");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    {
        let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
        stream.write_all(b"g").unwrap();
        stream.flush().unwrap();
    }

    // Sleep 5 ms after each `read_tls` (rustls reads at most a few KiB per
    // call): the drain takes about 3.5 s, well over the 300 ms
    // `close_notify_timeout_ms`.
    let started = Instant::now();
    let mut received = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    let peer_closed = loop {
        match tls_conn.read_tls(&mut tcp) {
            Ok(0) => break false,
            Ok(_) => {}
            Err(e) => panic!("read_tls failed after {received} bytes: {e}"),
        }
        let state = tls_conn
            .process_new_packets()
            .expect("server sent a malformed record");
        loop {
            match tls_conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => received += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("plaintext read failed: {e}"),
            }
        }
        if state.peer_has_closed() {
            break true;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    eprintln!("received {received} bytes in {:?}", started.elapsed());

    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert_eq!(received, BIG_REPLY, "the reply was cut short");
    assert!(peer_closed, "no close_notify after the reply");
}

/// Read one byte, queue an 8 MiB reply, shut the write side down while the
/// reply is still queued, and return.
#[cfg(has_io_uring)]
struct TlsBigReplyShutdownThenReturn;

#[cfg(has_io_uring)]
impl AsyncEventHandler for TlsBigReplyShutdownThenReturn {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(1)
                    }
                })
                .await;
            if n == 0 {
                return;
            }
            let chunk = vec![0x5au8; 64 * 1024];
            for _ in 0..BIG_REPLY / chunk.len() {
                conn.send_nowait(&chunk).expect("queue the reply");
            }
            conn.shutdown_write();
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsBigReplyShutdownThenReturn
    }
}

/// Connect to `addr` with a 64 KiB receive buffer, send one byte, wait
/// `delay`, then read until the server's close. Returns the plaintext and
/// whether a close_notify arrived.
#[cfg(has_io_uring)]
fn read_reply_until_close(
    addr: &str,
    certs: &[rustls::pki_types::CertificateDer<'static>],
    delay: Duration,
) -> (Vec<u8>, bool) {
    use std::os::fd::AsRawFd;
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn =
        rustls::ClientConnection::new(client_tls_config(certs), server_name).unwrap();
    let mut tcp = TcpStream::connect(addr).unwrap();
    let rcvbuf: libc::c_int = 64 * 1024;
    let rc = unsafe {
        libc::setsockopt(
            tcp.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_RCVBUF)");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    {
        let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
        stream.write_all(b"g").unwrap();
        stream.flush().unwrap();
    }
    std::thread::sleep(delay);
    let mut plaintext = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match tls_conn.read_tls(&mut tcp) {
            Ok(0) => return (plaintext, false),
            Ok(_) => {}
            Err(e) => panic!("read_tls failed after {} bytes: {e}", plaintext.len()),
        }
        let state = tls_conn
            .process_new_packets()
            .expect("server sent a malformed record");
        loop {
            match tls_conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => plaintext.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("plaintext read failed: {e}"),
            }
        }
        if state.peer_has_closed() {
            return (plaintext, true);
        }
    }
}

/// A handler that shuts its write side down while sends are still queued and
/// then returns sends no close_notify: the FIN is already ordered behind the
/// queue, and an alert after it would never be read.
#[cfg(has_io_uring)]
#[test]
fn no_close_notify_after_a_pending_write_shutdown() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .send_pool(1024, 16448)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsBigReplyShutdownThenReturn>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    // The client does not read for 300 ms, so the reply is still queued when
    // the handler shuts the write side down and returns.
    let (plaintext, peer_closed) =
        read_reply_until_close(&addr, &certs, Duration::from_millis(300));

    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert_eq!(plaintext.len(), BIG_REPLY, "the reply was cut short");
    assert!(!peer_closed, "a close_notify followed the write shutdown");
}

/// The result of the send a handler makes after `close()`.
#[cfg(has_io_uring)]
static TLS_SEND_AFTER_CLOSE: Mutex<Option<std::io::Result<()>>> = Mutex::new(None);

/// Read one byte, send "early", close, then try to send "late".
#[cfg(has_io_uring)]
struct TlsSendAfterClose;

#[cfg(has_io_uring)]
impl AsyncEventHandler for TlsSendAfterClose {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(1)
                    }
                })
                .await;
            if n == 0 {
                return;
            }
            conn.send_nowait(b"early").expect("send before close");
            conn.close();
            *TLS_SEND_AFTER_CLOSE.lock().unwrap() = Some(conn.send_nowait(b"late"));
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsSendAfterClose
    }
}

/// Read one byte, send "early", close, then try `send_backpressured("late")`.
#[cfg(has_io_uring)]
struct TlsBackpressuredSendAfterClose;

#[cfg(has_io_uring)]
impl AsyncEventHandler for TlsBackpressuredSendAfterClose {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(1)
                    }
                })
                .await;
            if n == 0 {
                return;
            }
            conn.send_nowait(b"early").expect("send before close");
            conn.close();
            let late = conn.send_backpressured(b"late").await.map(|_| ());
            *TLS_SEND_AFTER_CLOSE.lock().unwrap() = Some(late);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsBackpressuredSendAfterClose
    }
}

/// On io_uring a TLS `send_nowait` after `close()` is refused: its record
/// would follow the close_notify, and the peer discards records after the
/// alert.
#[cfg(has_io_uring)]
#[test]
fn a_tls_send_after_close_is_refused() {
    send_after_close_is_refused::<TlsSendAfterClose>();
}

/// The same for `send_backpressured`.
#[cfg(has_io_uring)]
#[test]
fn a_tls_backpressured_send_after_close_is_refused() {
    send_after_close_is_refused::<TlsBackpressuredSendAfterClose>();
}

/// Run `H`, which sends "early", closes, and records the result of a later
/// send in `TLS_SEND_AFTER_CLOSE`; check the client got "early" and the
/// alert, and the later send was refused.
#[cfg(has_io_uring)]
fn send_after_close_is_refused<H: AsyncEventHandler>() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    *TLS_SEND_AFTER_CLOSE.lock().unwrap() = None;
    let (certs, key) = generate_self_signed();
    // A slot that holds a whole record, which a bounded TLS send needs on the
    // unbuffered engine.
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .send_pool(256, 16448)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let (plaintext, peer_closed) = read_reply_until_close(&addr, &certs, Duration::ZERO);

    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert_eq!(plaintext, b"early");
    assert!(peer_closed, "no close_notify");
    let late = TLS_SEND_AFTER_CLOSE
        .lock()
        .unwrap()
        .take()
        .expect("handler ran");
    let err = late.expect_err("a send after close() was accepted");
    assert_eq!(err.kind(), std::io::ErrorKind::NotConnected);
}

/// Owns the heap bytes a chain's guard part sends.
#[cfg(has_io_uring)]
struct ChainGuard(Vec<u8>);

#[cfg(has_io_uring)]
impl ringline::SendGuard for ChainGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> ringline::RegionId {
        ringline::RegionId::UNREGISTERED
    }
}

/// Above `send_zc_threshold`, so on a plaintext connection the guard part
/// would go out zero-copy.
#[cfg(has_io_uring)]
const CHAIN_GUARD_LEN: usize = 8192;

/// The send before the chain spans several TLS records. It is in flight when
/// the chain is submitted whatever its size: the handler submits both in one
/// poll, and completions are processed only between polls.
#[cfg(has_io_uring)]
const CHAIN_BEFORE_LEN: usize = 100_000;

/// The results of `TlsSendChain`'s chain and empty chain.
#[cfg(has_io_uring)]
#[allow(clippy::type_complexity)]
static TLS_CHAIN_RESULTS: Mutex<Option<(std::io::Result<u32>, std::io::Result<u32>)>> =
    Mutex::new(None);

/// Read one byte, queue a large send, then without waiting send a `send_chain`
/// of a copy part, a scatter-gather part with a guard, and another copy part;
/// wait for it, send an empty chain, record both results, and close.
#[cfg(has_io_uring)]
struct TlsSendChain;

#[cfg(has_io_uring)]
impl AsyncEventHandler for TlsSendChain {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(1)
                    }
                })
                .await;
            if n == 0 {
                return;
            }
            // On TLS the chain queues behind this send rather than refusing,
            // so do not wait for it.
            let mut before = vec![b'x'; CHAIN_BEFORE_LEN];
            before.extend_from_slice(b"before-");
            conn.send_nowait(&before).expect("send before the chain");
            let guard = ringline::GuardBox::new(ChainGuard(vec![b'g'; CHAIN_GUARD_LEN]));
            let sent = conn
                .send_chain(|chain| {
                    chain
                        .copy(b"chain-a")
                        .parts()
                        .copy(b"-")
                        .guard(guard)
                        .copy(b"-")
                        .add()
                        .copy(b"-chain-b")
                        .finish()
                })
                .expect("submit the chain")
                .await;
            // An empty chain sends nothing and resolves to 0.
            let empty = conn
                .send_chain(|chain| chain.finish())
                .expect("submit the empty chain")
                .await;
            *TLS_CHAIN_RESULTS.lock().unwrap() = Some((sent, empty));
            conn.close();
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsSendChain
    }
}

/// A `send_chain` on a TLS connection, copy and guard parts alike, is
/// encrypted, queued behind a send still in flight rather than refused, and
/// resolves with its plaintext length.
#[cfg(has_io_uring)]
#[test]
fn a_tls_send_chain_is_encrypted() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    *TLS_CHAIN_RESULTS.lock().unwrap() = None;
    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsSendChain>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let (plaintext, peer_closed) = read_reply_until_close(&addr, &certs, Duration::ZERO);

    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    let (sent, empty) = TLS_CHAIN_RESULTS
        .lock()
        .unwrap()
        .take()
        .expect("handler ran");
    assert_eq!(
        sent.expect("chain completes"),
        (CHAIN_GUARD_LEN + 17) as u32,
        "the chain's bytes"
    );
    assert_eq!(empty.expect("empty chain completes"), 0);
    let mut expected = vec![b'x'; CHAIN_BEFORE_LEN];
    expected.extend_from_slice(b"before-chain-a-");
    expected.extend(std::iter::repeat_n(b'g', CHAIN_GUARD_LEN));
    expected.extend_from_slice(b"--chain-b");
    assert_eq!(plaintext, expected);
    assert!(peer_closed, "no close_notify after the chain");
}

// ── Test 6: Server-initiated clean TLS close from on_tick (io_uring) ─────

/// Where `on_accept` parks the connection's `ConnToken` for `on_tick` to close.
#[cfg(has_io_uring)]
static TLS_TICK_CLOSE_TOKEN: Mutex<Option<ringline::ConnToken>> = Mutex::new(None);

/// Echo one message, then hand the token to `on_tick`, which closes the
/// connection through `DriverCtx::close`.
///
/// The task deliberately does **not** call `ConnCtx::close()`. That is a
/// different path (`Driver::close_connection_graceful`), covered by
/// `tls_server_close_sends_close_notify`.
#[cfg(has_io_uring)]
struct TlsTickCloseHandler;

#[cfg(has_io_uring)]
impl AsyncEventHandler for TlsTickCloseHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            // Echo once so the connection reaches full TLS traffic state —
            // `WriteTraffic::queue_close_notify` is only reachable there, and a
            // handshaking connection would have no alert to produce.
            rx.with_data(|data| {
                let _ = tx.send_nowait(data);
                ParseResult::Consumed(data.len())
            })
            .await;
            *TLS_TICK_CLOSE_TOKEN.lock().unwrap() = Some(tx.token());
            // Park until the connection goes away rather than returning, which
            // would close it from the task side and race the tick-driven close
            // under test.
            loop {
                if rx.with_data(|d| ParseResult::Consumed(d.len())).await == 0 {
                    break;
                }
            }
        }
    }

    fn on_tick(&mut self, ctx: &mut ringline::DriverCtx<'_>) {
        if let Some(token) = TLS_TICK_CLOSE_TOKEN.lock().unwrap().take() {
            ctx.close(token);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsTickCloseHandler
    }
}

/// A ringline TLS server closing a connection from `on_tick` must emit a
/// close_notify alert before the FIN, so the peer can tell a clean shutdown
/// from a truncation attack. Both engines owe this and produce the alert
/// differently (the buffered engine queues it with `send_close_notify`, the
/// unbuffered one encrypts it through `WriteTraffic::queue_close_notify`), so
/// this is the guard on `TlsTable::send_close_notify_queued` dispatching by
/// engine at all — it must pass in the default build and under
/// `--features tls-buffered`.
///
/// **io_uring only, and `DriverCtx::close` specifically.** That is the
/// handler-facing close reachable from `on_tick`/`on_notify` against any live
/// connection. `ConnCtx::close()` and a handler return are covered by
/// `tls_server_close_sends_close_notify` and
/// `tls_handler_return_sends_close_notify`, on both backends.
///
/// The assertion is `peer_has_closed()`, not "the read returned 0": a server
/// that sends only a FIN also ends the client's reads, and rustls reports that
/// as `UnexpectedEof` instead.
#[cfg(has_io_uring)]
#[test]
fn tls_tick_close_sends_close_notify() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    *TLS_TICK_CLOSE_TOKEN.lock().unwrap() = None;

    let (certs, key) = generate_self_signed();
    let server_config = ringline_server_tls(certs.clone(), key);

    let config = test_config_builder()
        .tls(server_config)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsTickCloseHandler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();

    wait_for_server(&addr);

    let client_config = client_tls_config(&certs);
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    {
        let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
        let msg = b"close me";
        stream.write_all(msg).unwrap();
        stream.flush().unwrap();
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, msg, "echo mismatch before close");
    }

    // Drain the rest of the connection by hand: `rustls::Stream` maps both a
    // clean close and a truncation to a read of 0, which is exactly the
    // distinction under test.
    //
    // Check before reading as well as after. The alert can arrive in the same
    // TCP segment as the echo, in which case `Stream::read_exact` above already
    // fed it to the deframer and there is nothing left on the socket — a loop
    // that only inspected the state after a fresh read would see the FIN and
    // wrongly report a truncation (this raced roughly one run in three on the
    // mio sibling).
    let mut peer_closed = tls_conn
        .process_new_packets()
        .expect("server sent a malformed record")
        .peer_has_closed();
    while !peer_closed {
        match tls_conn.read_tls(&mut tcp) {
            Ok(0) => break, // FIN
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("read_tls failed: {e}"),
        }
        peer_closed = tls_conn
            .process_new_packets()
            .expect("server sent a malformed record after echoing")
            .peer_has_closed();
    }

    assert!(
        peer_closed,
        "server closed from on_tick without close_notify — the peer cannot \
         distinguish a clean shutdown from a truncated stream"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── TLS source for forward_to_conn ──────────────────────────────────────

/// A TLS-terminating proxy: decrypt the client's stream and forward the
/// plaintext body to a cleartext backend with `forward_to_conn`, then read the
/// backend's echo normally and send it back over TLS.
///
/// Only one direction can be a forward. The forward writes bytes onto the sink
/// as they are, with nothing on the path to encrypt them, so a TLS sink is
/// refused — the return leg uses an ordinary `send`.
struct TlsForwardProxy {
    backend_addr: SocketAddr,
}

static TLS_FORWARD_BACKEND: OnceLock<SocketAddr> = OnceLock::new();

impl AsyncEventHandler for TlsForwardProxy {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        let backend_addr = self.backend_addr;
        async move {
            let backend = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(_) => return,
            };
            // The backend is both read (for the return leg) and written (as
            // the forward sink), so take both halves.
            let (mut backend_tx, mut backend_rx) = backend.split();

            loop {
                let mut hdr = [0u8; 4];
                let n = client
                    .with_data(|data| {
                        if data.len() < 4 {
                            return ParseResult::NeedMore;
                        }
                        hdr.copy_from_slice(&data[..4]);
                        ParseResult::Consumed(4)
                    })
                    .await;
                if n == 0 {
                    break;
                }
                let len = u32::from_be_bytes(hdr) as usize;

                match client.forward_to_conn(&mut backend_tx, len).await {
                    Ok(f) if f == len => {}
                    other => {
                        eprintln!("tls proxy: forward {other:?}, wanted {len}");
                        break;
                    }
                }

                // Return leg: the client is a TLS connection, so it cannot be
                // a forward sink. Read the echo and send it encrypted.
                let mut echo = Vec::with_capacity(len);
                while echo.len() < len {
                    let remaining = len - echo.len();
                    let got = backend_rx
                        .with_data(|data| {
                            let take = data.len().min(remaining);
                            echo.extend_from_slice(&data[..take]);
                            ParseResult::Consumed(take)
                        })
                        .await;
                    if got == 0 {
                        return;
                    }
                }
                if client.send_nowait(&echo).is_err() {
                    break;
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsForwardProxy {
            backend_addr: *TLS_FORWARD_BACKEND.get().expect("backend addr not set"),
        }
    }
}

/// Plaintext echo backend for the TLS forward proxy.
struct PlainEcho;

impl AsyncEventHandler for PlainEcho {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        let _ = tx.send_nowait(data);
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
        PlainEcho
    }
}

/// `forward_to_conn` with a TLS source: the bytes come out of rustls, not off
/// the socket, so they reach the sink by a different route than the plaintext
/// path uses. Sizes span several TLS records and force the sink to back up.
#[test]
fn forward_to_conn_from_a_tls_source() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (backend_shutdown, backend_handles) =
        RinglineBuilder::new(test_config_builder().build().expect("valid config"))
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<PlainEcho>()
            .expect("backend launch failed");
    let backend_addr = backend_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();
    wait_for_server(&backend_addr);
    TLS_FORWARD_BACKEND
        .set(backend_addr.parse().unwrap())
        .expect("backend addr set once");

    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .forward_hold_cap(1)
        .build()
        .expect("valid config");
    let (proxy_shutdown, proxy_handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsForwardProxy>()
        .expect("proxy launch failed");
    let proxy_addr = proxy_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();
    wait_for_server(&proxy_addr);

    let client_config = client_tls_config(&certs);
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut tcp = TcpStream::connect(&proxy_addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);

    for (i, size) in [7usize, 1024, 20_000, 70_000].into_iter().enumerate() {
        let payload: Vec<u8> = (0..size).map(|b| (b.wrapping_mul(17) + i) as u8).collect();
        // Header alone first, then the body in pieces. If the whole request
        // arrives before the handler parses the header, every byte is already
        // in the accumulator when the forward starts and the path that routes
        // freshly decrypted plaintext into a *running* forward never runs.
        stream.write_all(&(size as u32).to_be_bytes()).unwrap();
        stream.flush().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        for chunk in payload.chunks(4096) {
            stream.write_all(chunk).unwrap();
            stream.flush().unwrap();
        }

        let mut got = vec![0u8; size];
        let total = read_until_full_or_stalled(
            &mut stream,
            &mut got,
            Duration::from_secs(30),
            "TLS-source forward echo",
        );
        assert_eq!(total, size, "proxy closed at {size}B after {total}B");
        assert_eq!(got, payload, "payload mismatch at {size}B");
    }

    // `stream` borrows `tcp`; ending the borrow is what lets the socket close.
    let _ = stream;
    drop(tcp);
    proxy_shutdown.shutdown();
    for h in proxy_handles {
        h.join().unwrap().unwrap();
    }
    backend_shutdown.shutdown();
    for h in backend_handles {
        h.join().unwrap().unwrap();
    }
}

/// Connect a TLS client to `addr`, send one byte, wait for the server's
/// one-byte ack, then flood from a thread until the sent count stops moving
/// with the write blocked (`stalled`) or reaches `limit`. Returns the bytes
/// sent and whether the flood stalled.
fn tls_flood_after_ack(addr: &str, certs: &[CertificateDer<'static>], limit: u64) -> (u64, bool) {
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn =
        rustls::ClientConnection::new(client_tls_config(certs), server_name).unwrap();
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
    stream.write_all(b"g").unwrap();
    stream.flush().unwrap();
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).expect("forward armed ack");
    let _ = stream;

    // Flood from a thread until the count stops moving (throttled) or
    // reaches the limit (not throttled), then shut the socket down to end a
    // write the throttle has stalled.
    let sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = Arc::clone(&sent);
    let control = tcp.try_clone().unwrap();
    let writer = std::thread::spawn(move || {
        let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
        let chunk = vec![7u8; 1 << 20];
        while counter.load(std::sync::atomic::Ordering::Relaxed) < limit {
            match stream.write(&chunk) {
                Ok(n) => {
                    counter.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
    });
    let started = Instant::now();
    let (mut last, mut still_since) = (0u64, Instant::now());
    let stalled = loop {
        std::thread::sleep(Duration::from_millis(250));
        let now = sent.load(std::sync::atomic::Ordering::Relaxed);
        if now >= limit || started.elapsed() > Duration::from_secs(30) {
            break false;
        }
        if now != last {
            (last, still_since) = (now, Instant::now());
        } else if still_since.elapsed() >= Duration::from_secs(1) {
            // A writer that stopped on an error (the server closed the
            // connection) also stops the count; only a blocked write is a stall.
            break !writer.is_finished();
        }
    };
    let sent = sent.load(std::sync::atomic::Ordering::Relaxed);
    let _ = control.shutdown(std::net::Shutdown::Both);
    writer.join().unwrap();
    (sent, stalled)
}

// ── TLS forward sources whose sink does not read ───────────────────────

/// Forwards everything the TLS client sends to a sink that never reads.
struct TlsForwardToStuckSink;

static TLS_STUCK_SINK: Mutex<Option<SocketAddr>> = Mutex::new(None);

impl AsyncEventHandler for TlsForwardToStuckSink {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let addr = TLS_STUCK_SINK.lock().unwrap().expect("sink addr not set");
            let Ok(sink) = ringline::connect(addr).await else {
                return;
            };
            let (mut sink_tx, _sink_rx) = sink.split();
            // Wait for the client's first byte, so its flood starts after the
            // forward is armed rather than landing in the accumulator first.
            let n = client
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(1)
                    }
                })
                .await;
            if n == 0 {
                return;
            }
            // The ack is queued before the forward is armed, but both happen
            // in this poll, before the ack's send is submitted, so the
            // client's flood arrives after the forward is armed.
            let _ = client.send_nowait(b"a");
            let _ = client.forward_to_conn(&mut sink_tx, 1 << 30).await;
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsForwardToStuckSink
    }
}

/// A TLS `forward_to_conn` source whose sink does not read stops receiving:
/// the direct forward has one send in flight and arms the next receive only
/// when the accumulator is empty, so its peer's writes stall.
#[test]
fn a_tls_forward_to_conn_source_with_a_stuck_sink_stops_its_peer() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    const LIMIT: u64 = 64 << 20;

    // Accepts the forward's sink connection and never reads from it.
    let sink = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    *TLS_STUCK_SINK.lock().unwrap() = Some(sink.local_addr().unwrap());
    let held = std::thread::spawn(move || sink.accept().map(|(s, _)| s));

    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .forward_hold_cap(8)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsForwardToStuckSink>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let (sent, stalled) = tls_flood_after_ack(&addr, &certs, LIMIT);
    eprintln!("sent {sent} bytes, stalled {stalled}");

    // Close the sink's peer first: the forward's send to it holds worker exit
    // until the kernel releases the data it queued.
    drop(held.join());
    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert!(
        stalled && sent > 0 && sent < LIMIT,
        "the TLS forward_to_conn source accepted {sent} bytes without stalling"
    );
}

// ── A TLS connection's receive follows its reads ───────────────────────

/// Reads the client's first byte, acks it, then never reads again.
#[cfg(has_io_uring)]
struct TlsIdleReader;

#[cfg(has_io_uring)]
impl AsyncEventHandler for TlsIdleReader {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(1)
                    }
                })
                .await;
            if n == 0 {
                return;
            }
            let _ = conn.send_nowait(b"a");
            loop {
                ringline::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsIdleReader
    }
}

/// A TLS connection whose task does not read stops receiving, so its peer's
/// writes stall instead of filling the accumulator up to
/// `recv_accumulator_max`. io_uring only: mio reads on readiness whether or
/// not the task reads.
#[cfg(has_io_uring)]
#[test]
fn a_tls_reader_that_does_not_read_stops_its_peer() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    const LIMIT: u64 = 64 << 20;
    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsIdleReader>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let (sent, stalled) = tls_flood_after_ack(&addr, &certs, LIMIT);
    eprintln!("idle TLS reader: sent {sent} bytes, stalled {stalled}");

    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert!(
        stalled && sent > 0 && sent < LIMIT,
        "an idle TLS reader accepted {sent} bytes without stalling"
    );
}

/// Acks the handshake with one byte, then watches `is_alive` without reading.
struct TlsCloseWatcher;

static TLS_CLOSE_SEEN: Mutex<Option<bool>> = Mutex::new(None);

/// Reports the close if the runtime drops the watcher's task when the
/// connection closes, before the watcher sees `is_alive` turn false.
struct ReportCloseOnDrop;

impl Drop for ReportCloseOnDrop {
    fn drop(&mut self) {
        let mut seen = TLS_CLOSE_SEEN.lock().unwrap();
        if seen.is_none() {
            *seen = Some(true);
        }
    }
}

impl AsyncEventHandler for TlsCloseWatcher {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let _report = ReportCloseOnDrop;
            let _ = conn.send_nowait(b"a");
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(5) {
                if !conn.is_alive() {
                    *TLS_CLOSE_SEEN.lock().unwrap() = Some(true);
                    return;
                }
                ringline::sleep(Duration::from_millis(10)).await;
            }
            *TLS_CLOSE_SEEN.lock().unwrap() = Some(false);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsCloseWatcher
    }
}

/// A TLS connection that nothing reads sees its peer's close_notify and FIN:
/// the hangup poll arms a receive, so `is_alive` turns false.
#[test]
fn a_tls_peer_close_is_seen_while_nothing_reads() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    *TLS_CLOSE_SEEN.lock().unwrap() = None;
    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsCloseWatcher>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn =
        rustls::ClientConnection::new(client_tls_config(&certs), server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    {
        let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
        let mut ack = [0u8; 1];
        stream.read_exact(&mut ack).expect("handshake ack");
    }
    tls_conn.send_close_notify();
    while tls_conn.wants_write() {
        tls_conn.write_tls(&mut tcp).unwrap();
    }
    drop(tcp);

    let deadline = Instant::now() + Duration::from_secs(10);
    let seen = loop {
        if let Some(seen) = *TLS_CLOSE_SEEN.lock().unwrap() {
            break seen;
        }
        assert!(Instant::now() < deadline, "the handler never reported");
        std::thread::sleep(Duration::from_millis(10));
    };
    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert!(seen, "the TLS connection did not see its peer close");
}

// ── A TLS connection may not be a forward sink (EPROTOTYPE, both backends) ──

/// Forwarding *into* a TLS connection must be refused.
///
/// A forward writes bytes to the sink as they are — `sendmsg` straight to the
/// sink's descriptor on io_uring, a queued send on mio — with nothing on the
/// path to encrypt them. So a TLS sink would put plaintext on a wire the peer
/// is decrypting, which is a confidentiality failure, not a protocol error.
///
/// mio refused this from the start. io_uring had no guard anywhere on the
/// forward path and would have written the plaintext; the invariant was only
/// ever honoured because `forward_to_conn_from_a_tls_source` above avoids the
/// return leg by hand ("the client is a TLS connection, so it cannot be a
/// forward sink").
struct TlsSinkRefusedProxy {
    backend_addr: SocketAddr,
}

static TLS_SINK_REFUSED_BACKEND: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

impl AsyncEventHandler for TlsSinkRefusedProxy {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut client: Connection) -> impl Future<Output = ()> + 'static {
        let backend_addr = self.backend_addr;
        async move {
            let mut backend = match ringline::connect(backend_addr).await {
                Ok(ctx) => ctx,
                Err(_) => return,
            };

            // `client` is the TLS connection. Forwarding backend -> client is
            // the case that must be refused.
            let errno = match backend.forward_to_conn(client.send_half(), 16).await {
                Ok(_) => -1,
                Err(e) => e.raw_os_error().unwrap_or(-1),
            };
            // Reported over TLS, so a plaintext leak could not masquerade as
            // the answer.
            let _ = client.send(&errno.to_be_bytes());
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsSinkRefusedProxy {
            backend_addr: *TLS_SINK_REFUSED_BACKEND
                .get()
                .expect("backend addr not set"),
        }
    }
}

#[test]
fn a_tls_connection_is_refused_as_a_forward_sink() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    let (backend_shutdown, backend_handles) =
        RinglineBuilder::new(test_config_builder().build().expect("valid config"))
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<PlainEcho>()
            .expect("backend launch failed");
    let backend_addr = backend_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();
    wait_for_server(&backend_addr);
    TLS_SINK_REFUSED_BACKEND
        .set(backend_addr.parse().unwrap())
        .expect("backend addr set once");

    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .build()
        .expect("valid config");
    let (proxy_shutdown, proxy_handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsSinkRefusedProxy>()
        .expect("proxy launch failed");
    let proxy_addr = proxy_shutdown
        .bound_addr()
        .expect("bound address")
        .to_string();
    wait_for_server(&proxy_addr);

    let client_config = client_tls_config(&certs);
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut tcp = TcpStream::connect(&proxy_addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);

    // Wake the handler so it reaches the forward attempt.
    stream.write_all(b"go").unwrap();
    stream.flush().unwrap();

    let mut got = [0u8; 4];
    let total = read_until_full_or_stalled(
        &mut stream,
        &mut got,
        Duration::from_secs(30),
        "forward-sink refusal report",
    );
    assert_eq!(
        total,
        got.len(),
        "proxy closed before reporting the refusal"
    );
    assert_eq!(
        i32::from_be_bytes(got),
        libc::EPROTOTYPE,
        "a TLS connection must be refused as a forward sink, not written in the clear"
    );

    let _ = stream;
    drop(tcp);
    proxy_shutdown.shutdown();
    for h in proxy_handles {
        h.join().unwrap().unwrap();
    }
    backend_shutdown.shutdown();
    for h in backend_handles {
        h.join().unwrap().unwrap();
    }
}

// ── A close_notify in the same segment as the handshake's last flight ────

static TLS_HS_CLOSE_INBOUND: Mutex<Option<(Vec<u8>, bool)>> = Mutex::new(None);

struct TlsReadToEof;

impl AsyncEventHandler for TlsReadToEof {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (_tx, mut rx) = conn.split();
            let mut got = Vec::new();
            loop {
                let n = rx
                    .with_data(|data| {
                        got.extend_from_slice(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
            *TLS_HS_CLOSE_INBOUND.lock().unwrap() = Some((got, rx.eof_truncated()));
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsReadToEof
    }
}

/// A client that sends its Finished, application data and close_notify in one
/// write, and keeps TCP open, is read to a clean EOF: the handshake completion
/// and the close arrive in one feed, and the server handles both.
#[test]
fn a_close_notify_with_the_clients_finished_is_read_to_eof() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    *TLS_HS_CLOSE_INBOUND.lock().unwrap() = None;
    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsReadToEof>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address");

    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls = rustls::ClientConnection::new(client_tls_config(&certs), server_name).unwrap();
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    while tls.wants_write() {
        tls.write_tls(&mut tcp).unwrap();
    }
    // Read the server's flight. The client's Finished is queued, not sent.
    while tls.is_handshaking() {
        let n = tls.read_tls(&mut tcp).expect("read the server's flight");
        assert!(n > 0, "the server closed during the handshake");
        tls.process_new_packets()
            .expect("process the server's flight");
    }
    tls.writer().write_all(b"hello").unwrap();
    tls.send_close_notify();
    let mut wire = Vec::new();
    while tls.wants_write() {
        tls.write_tls(&mut wire).unwrap();
    }
    tcp.write_all(&wire).unwrap();

    // The server reads to EOF, returns, and closes; TCP stays open on this
    // side until then.
    let mut buf = [0u8; 4096];
    let closed = loop {
        match tcp.read(&mut buf) {
            Ok(0) => break true,
            Ok(_) => continue,
            Err(_) => break false,
        }
    };
    let result = TLS_HS_CLOSE_INBOUND.lock().unwrap().take();
    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert!(closed, "the server did not close within 5 s");
    let (got, truncated) = result.expect("the handler did not read to EOF");
    assert_eq!(got, b"hello");
    assert!(!truncated, "a close_notify preceded the EOF");
}

static TLS_HS_CLOSE_SERVER: Mutex<Option<SocketAddr>> = Mutex::new(None);
static TLS_HS_CLOSE_OUTBOUND: Mutex<Option<String>> = Mutex::new(None);

struct TlsConnectReadToEof;

impl AsyncEventHandler for TlsConnectReadToEof {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let server = TLS_HS_CLOSE_SERVER.lock().unwrap().expect("server addr");
        Some(Box::pin(async move {
            let result = match ringline::connect(server).tls("localhost").await {
                Err(e) => format!("CONNECT_ERR:{e}"),
                Ok(conn) => {
                    let (_tx, mut rx) = conn.split();
                    let read = ringline::timeout(Duration::from_secs(5), async {
                        loop {
                            let n = rx.with_data(|data| ParseResult::Consumed(data.len())).await;
                            if n == 0 {
                                break;
                            }
                        }
                    })
                    .await;
                    match read {
                        Err(_) => "TIMEOUT".to_string(),
                        Ok(()) if rx.eof_truncated() => "EOF_TRUNCATED".to_string(),
                        Ok(()) => "EOF".to_string(),
                    }
                }
            };
            *TLS_HS_CLOSE_OUTBOUND.lock().unwrap() = Some(result);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsConnectReadToEof
    }
}

/// An outbound TLS connection whose server sends its flight and a close_notify
/// in one write, and keeps TCP open, is read to a clean EOF.
#[test]
fn a_close_notify_with_the_servers_flight_is_read_to_eof() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    *TLS_HS_CLOSE_OUTBOUND.lock().unwrap() = None;
    let (certs, key) = generate_self_signed();
    let server_config = server_tls_config(certs.clone(), key);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    *TLS_HS_CLOSE_SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut tls = rustls::ServerConnection::new(server_config).unwrap();
        while !tls.wants_write() {
            let n = tls.read_tls(&mut tcp).expect("read the ClientHello");
            assert!(n > 0, "the client closed before its ClientHello");
            tls.process_new_packets().expect("process the ClientHello");
        }
        tls.send_close_notify();
        let mut wire = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut wire).unwrap();
        }
        tcp.write_all(&wire).unwrap();
        // Hold TCP open until the client closes it or the timeout passes.
        let mut buf = [0u8; 4096];
        while matches!(tcp.read(&mut buf), Ok(n) if n > 0) {}
    });

    let config = test_config_builder()
        .tls_client(ringline_client_tls(&certs))
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .launch::<TlsConnectReadToEof>()
        .expect("launch failed");
    common::join_workers(&shutdown, handles);
    server.join().expect("server thread panicked");
    let result = TLS_HS_CLOSE_OUTBOUND.lock().unwrap().take();
    assert_eq!(result.as_deref(), Some("EOF"));
}

// ── Sends while a TLS receive is in flight ─────────────────────────────

static TLS_SEND_WHILE_RECV: Mutex<Option<Result<Vec<u8>, String>>> = Mutex::new(None);

/// Messages the server sends, and their size.
const SEND_WHILE_RECV_COUNT: usize = 64;
const SEND_WHILE_RECV_SIZE: usize = 1000;

fn send_while_recv_message(i: usize) -> Vec<u8> {
    (0..SEND_WHILE_RECV_SIZE)
        .map(|j| (i * 31 + j) as u8)
        .collect()
}

/// A task sends messages while the connection's task is parked in
/// `with_data`, so each send is encrypted while the receive is in flight,
/// then reads what the client sends back.
struct TlsSendWhileRecv;

impl AsyncEventHandler for TlsSendWhileRecv {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            let _ = ringline::spawn(async move {
                for i in 0..SEND_WHILE_RECV_COUNT {
                    let sent = match tx.send(&send_while_recv_message(i)) {
                        Ok(f) => f.await.map(|_| ()),
                        Err(e) => Err(e),
                    };
                    if sent.is_err() {
                        return;
                    }
                    ringline::sleep(Duration::from_millis(1)).await;
                }
                // Keep the write side open until the reader is done.
                ringline::sleep(Duration::from_secs(10)).await;
            });
            let mut got = Vec::new();
            while got.len() < 4 {
                let n = rx
                    .with_data(|data| {
                        got.extend_from_slice(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
            *TLS_SEND_WHILE_RECV.lock().unwrap() = Some(Ok(got));
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsSendWhileRecv
    }
}

/// Records sent while the server's receive is in flight reach the client in
/// order, and the bytes the client sends afterwards reach the server.
#[test]
fn tls_sends_while_a_receive_is_in_flight() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    *TLS_SEND_WHILE_RECV.lock().unwrap() = None;
    let (certs, key) = generate_self_signed();
    let config = test_config_builder()
        .tls(ringline_server_tls(certs.clone(), key))
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<TlsSendWhileRecv>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn =
        rustls::ClientConnection::new(client_tls_config(&certs), server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
    let mut got = vec![0u8; SEND_WHILE_RECV_COUNT * SEND_WHILE_RECV_SIZE];
    read_until_full_or_stalled(
        &mut stream,
        &mut got,
        Duration::from_secs(10),
        "messages sent while the receive was in flight",
    );
    let want: Vec<u8> = (0..SEND_WHILE_RECV_COUNT)
        .flat_map(send_while_recv_message)
        .collect();
    assert!(
        got == want,
        "the messages arrived out of order or corrupted"
    );
    stream.write_all(b"done").unwrap();
    stream.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let result = loop {
        if let Some(r) = TLS_SEND_WHILE_RECV.lock().unwrap().take() {
            break r;
        }
        assert!(Instant::now() < deadline, "the server never read the reply");
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = stream;
    drop(tcp);
    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert_eq!(result, Ok(b"done".to_vec()));
}

// ── A send or close during a read, with a partial handshake message ─────

static PARTIAL_TICKET_SERVER: Mutex<Option<SocketAddr>> = Mutex::new(None);
static PARTIAL_TICKET_SEND: Mutex<bool> = Mutex::new(true);

/// Splits whole TLS records.
fn split_tls_records(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        let len = u16::from_be_bytes([bytes[i + 3], bytes[i + 4]]) as usize;
        records.push(bytes[i..i + 5 + len].to_vec());
        i += 5 + len;
    }
    records
}

/// Connects with TLS, parks a read, and from another task sends `hello` or
/// closes while the read is parked.
struct PartialTicketClient;

impl AsyncEventHandler for PartialTicketClient {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let addr = PARTIAL_TICKET_SERVER.lock().unwrap().expect("server addr");
        let send = *PARTIAL_TICKET_SEND.lock().unwrap();
        Some(Box::pin(async move {
            let Ok(conn) = ringline::connect(addr).tls("localhost").await else {
                return;
            };
            let (mut tx, mut rx) = conn.split();
            let _ = ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(300)).await;
                if send {
                    if let Ok(f) = tx.send(b"hello") {
                        let _ = f.await;
                    }
                } else {
                    tx.close();
                }
            });
            let _ = ringline::timeout(
                Duration::from_secs(5),
                rx.with_data(|d| ParseResult::Consumed(d.len())),
            )
            .await;
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        PartialTicketClient
    }
}

/// The server fragments its NewSessionTicket into 32-byte records, sends the
/// first, and holds the rest while the ringline client, with a read parked,
/// sends or closes. Returns the plaintext the server read, and whether it
/// read a close_notify.
fn partial_ticket_exchange(send: bool) -> (Vec<u8>, bool) {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    *PARTIAL_TICKET_SEND.lock().unwrap() = send;
    let (certs, key) = generate_self_signed();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    *PARTIAL_TICKET_SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    let server_certs = certs.clone();
    let server = std::thread::spawn(move || {
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(server_certs, key)
            .unwrap();
        config.max_fragment_size = Some(32);
        let mut tls = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = vec![0u8; 65536];
        while tls.is_handshaking() {
            let mut out = Vec::new();
            while tls.wants_write() {
                tls.write_tls(&mut out).unwrap();
            }
            tcp.write_all(&out).unwrap();
            if !tls.is_handshaking() {
                break;
            }
            let n = tcp.read(&mut buf).expect("read the client's flight");
            assert!(n > 0, "the client closed during the handshake");
            tls.read_tls(&mut &buf[..n]).unwrap();
            tls.process_new_packets().unwrap();
        }
        let mut tickets = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut tickets).unwrap();
        }
        let records = split_tls_records(&tickets);
        assert!(
            records.len() >= 2,
            "the ticket spans {} records",
            records.len()
        );
        tcp.write_all(&records[0]).unwrap();
        // Read what the client sends while the rest of the ticket is held.
        let mut got = Vec::new();
        let mut closed = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !closed && got.len() < 5 {
            let n = match tcp.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            tls.read_tls(&mut &buf[..n]).unwrap();
            let state = tls.process_new_packets().expect("the client's records");
            let pending = state.plaintext_bytes_to_read();
            let mut plain = vec![0u8; pending];
            tls.reader().read_exact(&mut plain).unwrap();
            got.extend_from_slice(&plain);
            closed = state.peer_has_closed();
        }
        for record in &records[1..] {
            let _ = tcp.write_all(record);
        }
        (got, closed)
    });

    let config = test_config_builder()
        .tls_client(ringline_client_tls(&certs))
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .launch::<PartialTicketClient>()
        .expect("launch failed");
    let result = server.join().expect("server thread");
    shutdown.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    result
}

/// A send while a read is parked and rustls holds part of a handshake
/// message reaches the peer.
#[test]
fn a_send_during_a_read_with_a_partial_handshake_message() {
    let (got, _) = partial_ticket_exchange(true);
    assert_eq!(got, b"hello");
}

/// A close in the same state sends close_notify.
#[test]
fn a_close_during_a_read_with_a_partial_handshake_message() {
    let (_, closed) = partial_ticket_exchange(false);
    assert!(closed, "the server did not read a close_notify");
}
