//! A TLS handshake that does not complete within `tls_handshake_timeout`
//! closes the connection.
//!
//! Until the handshake completes no task holds the connection: an inbound
//! connection's `on_accept` task is spawned at completion, and an outbound
//! `connect(..).tls(..)` is still parked. A peer that connects and sends
//! nothing would hold the connection until the worker exits. Both backends.
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, TlsClientConfig,
    TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// The tests share `TARGET`, `CONNECT_RESULT` and the connection counters,
/// and `cargo test` runs them in one process.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

struct Echo;

impl AsyncEventHandler for Echo {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let mut echo = Vec::new();
                let n = conn
                    .with_data(|data| {
                        echo.extend_from_slice(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    return;
                }
                let _ = conn.send_nowait(&echo);
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Echo
    }
}

fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![CertificateDer::from(cert.cert)], key.into())
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

/// A TLS client connection to `addr` with 3 s socket timeouts.
fn tls_client(
    addr: SocketAddr,
    certs: &[CertificateDer<'static>],
) -> std::io::Result<(rustls::ClientConnection, TcpStream)> {
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let tls_conn = rustls::ClientConnection::new(client_tls_config(certs), server_name).unwrap();
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(3)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(3)))?;
    Ok((tls_conn, tcp))
}

/// Echo `msg` on an open TLS client connection.
fn echo(
    tls_conn: &mut rustls::ClientConnection,
    tcp: &mut TcpStream,
    msg: &[u8],
) -> std::io::Result<()> {
    let mut stream = rustls::Stream::new(tls_conn, tcp);
    stream.write_all(msg)?;
    stream.flush()?;
    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf)?;
    assert_eq!(buf, msg);
    Ok(())
}

/// Echo one message over a new TLS connection, then close it.
fn echo_once(addr: SocketAddr, certs: &[CertificateDer<'static>]) -> std::io::Result<()> {
    let (mut tls_conn, mut tcp) = tls_client(addr, certs)?;
    echo(&mut tls_conn, &mut tcp, b"hello")?;
    tls_conn.send_close_notify();
    let _ = tls_conn.complete_io(&mut tcp);
    Ok(())
}

/// A TLS echo server with one connection slot.
struct Server {
    runtime: ringline::Runtime,
    handles: Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
    addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
}

impl Server {
    fn start(timeout: Duration, tick_timeout_us: u64) -> Server {
        let (certs, key) = generate_self_signed();
        let config = ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .sq_entries(64)
            .max_connections(1)
            // One whole TLS record per slot, which the unbuffered engine needs.
            .send_pool(64, 16448)
            .tick_timeout_us(tick_timeout_us)
            .tls_handshake_timeout(timeout)
            .tls(
                TlsConfig::builder()
                    .cert(certs.clone(), key)
                    .build()
                    .unwrap(),
            )
            .build()
            .expect("valid config");
        let (runtime, handles) = RinglineBuilder::new(config)
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<Echo>()
            .expect("launch failed");
        let addr = runtime.bound_addr().expect("bound address");
        Server {
            runtime,
            handles,
            addr,
            certs,
        }
    }

    /// Whether an echo on a new connection succeeds within `within`. The
    /// echo is retried: while the one slot is held the server resets each
    /// new connection.
    fn echo_within(&self, within: Duration) -> std::io::Result<()> {
        let deadline = Instant::now() + within;
        loop {
            match echo_once(self.addr, &self.certs) {
                Ok(()) => return Ok(()),
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    fn stop(self) {
        self.runtime.shutdown();
        for h in self.handles {
            h.join().unwrap().unwrap();
        }
    }
}

/// Connect to `server` and send nothing, holding the socket open, then
/// return whether an echo on a second connection succeeds within `within`.
fn echo_beside_a_silent_peer(server: &Server, within: Duration) -> std::io::Result<()> {
    let silent = TcpStream::connect(server.addr).unwrap();
    // Let the server accept the silent connection into its one slot.
    std::thread::sleep(Duration::from_millis(100));
    let result = server.echo_within(within);
    drop(silent);
    result
}

/// A peer that connects to a TLS listener and sends nothing has its
/// connection closed once the handshake timeout elapses, so the next
/// connection is served.
#[test]
fn a_silent_peer_is_closed_after_the_handshake_timeout() {
    let _serial = serial();
    let server = Server::start(Duration::from_millis(300), 1000);
    let result = echo_beside_a_silent_peer(&server, Duration::from_secs(5));
    server.stop();
    result.expect("an echo after the silent peer's handshake timed out");
}

/// The `tls_handshake_timeout` connection counter.
fn handshake_timeouts() -> u64 {
    ringline::metrics::CONNECTIONS
        .value(ringline::metrics::conn::TLS_HANDSHAKE_TIMEOUT)
        .unwrap_or(0)
}

/// With no tick timeout and no traffic after the silent peer connects, on
/// io_uring nothing ends the worker's wait but the deadline's own timer. The
/// counter is read with no further connection, because each one would wake
/// the worker.
#[test]
fn a_silent_peer_is_closed_after_the_handshake_timeout_without_a_tick() {
    let _serial = serial();
    let server = Server::start(Duration::from_millis(300), 0);
    let before = handshake_timeouts();
    let silent = TcpStream::connect(server.addr).unwrap();
    std::thread::sleep(Duration::from_secs(1));
    let after = handshake_timeouts();
    drop(silent);
    server.stop();
    assert_eq!(after - before, 1, "handshake timeouts counted within 1 s");
}

/// A tick longer than the handshake timeout does not delay the close: with
/// a 3 s tick and no traffic, the 300 ms deadline is counted within 1 s.
#[test]
fn a_silent_peer_is_closed_after_the_handshake_timeout_with_a_long_tick() {
    let _serial = serial();
    let server = Server::start(Duration::from_millis(300), 3_000_000);
    let before = handshake_timeouts();
    let silent = TcpStream::connect(server.addr).unwrap();
    std::thread::sleep(Duration::from_secs(1));
    let after = handshake_timeouts();
    drop(silent);
    server.stop();
    assert_eq!(after - before, 1, "handshake timeouts counted within 1 s");
}

/// Control: within the handshake timeout the silent peer still holds the one
/// slot, so the test above would see the hold.
#[test]
fn a_silent_peer_holds_its_slot_until_the_handshake_timeout() {
    let _serial = serial();
    let server = Server::start(Duration::from_secs(60), 1000);
    let result = echo_beside_a_silent_peer(&server, Duration::from_secs(2));
    server.stop();
    assert!(result.is_err(), "the silent peer's slot was freed early");
}

/// The timeout applies to the handshake only: an established connection
/// left idle for longer than it stays open.
#[test]
fn an_established_connection_outlives_the_handshake_timeout() {
    let _serial = serial();
    let server = Server::start(Duration::from_millis(200), 1000);
    let result = (|| {
        let (mut tls_conn, mut tcp) = tls_client(server.addr, &server.certs)?;
        echo(&mut tls_conn, &mut tcp, b"first")?;
        std::thread::sleep(Duration::from_millis(600));
        echo(&mut tls_conn, &mut tcp, b"second")
    })();
    server.stop();
    result.expect("an echo after the connection idled past the handshake timeout");
}

/// Where `Dial` connects.
static TARGET: Mutex<Option<SocketAddr>> = Mutex::new(None);
/// What `Dial`'s connect resolved with: `Ok(())`, the error's kind, or
/// `None` inside if it had not resolved after 3 s.
static CONNECT_RESULT: Mutex<Option<Option<Result<(), ErrorKind>>>> = Mutex::new(None);

/// On each accepted connection, dials `TARGET` over TLS and records how the
/// connect resolved.
struct Dial;

impl AsyncEventHandler for Dial {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let _conn = conn;
            let target = TARGET.lock().unwrap().expect("target set");
            let resolved = ringline::timeout(Duration::from_secs(3), async move {
                ringline::connect(target).tls("localhost").await
            })
            .await;
            let recorded = match resolved {
                Err(_) => None,
                Ok(Ok(_)) => Some(Ok(())),
                Ok(Err(e)) => Some(Err(e.kind())),
            };
            *CONNECT_RESULT.lock().unwrap() = Some(recorded);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Dial
    }
}

/// An outbound TLS connect to a peer that reads the ClientHello and then
/// sends nothing, holding the socket open, resolves `TimedOut` once the
/// handshake timeout elapses.
#[test]
fn a_tls_connect_to_a_silent_peer_resolves_timed_out() {
    let _serial = serial();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *TARGET.lock().unwrap() = Some(listener.local_addr().unwrap());
    *CONNECT_RESULT.lock().unwrap() = None;
    let (release, released) = mpsc::channel::<()>();
    let peer = std::thread::spawn(move || {
        // A dial that fails before it connects leaves nothing to accept.
        // The test then drops `release`, and this thread returns.
        listener.set_nonblocking(true).unwrap();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if released.try_recv() == Err(mpsc::TryRecvError::Disconnected) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut hello = [0u8; 4096];
        let n = stream.read(&mut hello).expect("the ClientHello");
        assert!(n > 0, "the client closed before its ClientHello");
        // Hold the socket, sending nothing, until the connect has resolved.
        let _ = released.recv();
    });

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(64, 16448)
        .tls_handshake_timeout(Duration::from_millis(300))
        .tls_client(TlsClientConfig::builder().build().unwrap())
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Dial>()
        .expect("launch failed");
    let trigger = TcpStream::connect(runtime.bound_addr().expect("bound address"))
        .expect("the connection that starts the dial");

    let deadline = Instant::now() + Duration::from_secs(10);
    let recorded = loop {
        if let Some(recorded) = *CONNECT_RESULT.lock().unwrap() {
            break recorded;
        }
        assert!(Instant::now() < deadline, "the handler recorded nothing");
        std::thread::sleep(Duration::from_millis(5));
    };

    drop(trigger);
    drop(release);
    peer.join().unwrap();
    runtime.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(
        recorded,
        Some(Err(ErrorKind::TimedOut)),
        "how the connect resolved (None: not within 3 s)"
    );
}
