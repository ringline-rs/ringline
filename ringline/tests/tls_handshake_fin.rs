//! A peer's FIN before the TLS handshake completes fails the handshake.
//!
//! Until the handshake completes no task holds the connection: an inbound
//! connection's `on_accept` task is spawned at completion, and an outbound
//! `connect(..).tls(..)` is still parked. A FIN that only finished the read
//! half would leave the connection open with nothing to close it. So the
//! connection is closed, and an outbound connect resolves `UnexpectedEof`.
//! Both backends.
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, TlsClientConfig,
    TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

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

/// Echo one message over TLS, then close with a close_notify.
fn echo_once(addr: SocketAddr, certs: &[CertificateDer<'static>]) -> std::io::Result<()> {
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn =
        rustls::ClientConnection::new(client_tls_config(certs), server_name).unwrap();
    let mut tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(3)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
    stream.write_all(b"hello")?;
    stream.flush()?;
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf)?;
    assert_eq!(&buf, b"hello");
    tls_conn.send_close_notify();
    let _ = tls_conn.complete_io(&mut tcp);
    Ok(())
}

/// Start a TLS echo server with one connection slot, run `first` against
/// it, and return whether an echo on a second connection succeeds within
/// 5 s. The second echo is retried because the first connection's slot is
/// released some time after its peer closed; with the slot still held the
/// server resets the new connection.
fn echo_after(first: impl FnOnce(SocketAddr, &[CertificateDer<'static>])) -> std::io::Result<()> {
    let (certs, key) = generate_self_signed();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(1)
        // One whole TLS record per slot, which the unbuffered engine needs.
        .send_pool(64, 16448)
        .tls(
            TlsConfig::builder()
                .cert(certs.clone(), key)
                .build()
                .unwrap(),
        )
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Echo>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address");

    first(addr, &certs);
    let deadline = Instant::now() + Duration::from_secs(5);
    let second = loop {
        match echo_once(addr, &certs) {
            Ok(()) => break Ok(()),
            Err(e) if Instant::now() >= deadline => break Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    };

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    second
}

/// Control: an established TLS connection that the peer closes frees the
/// one slot, so a second connection is served.
#[test]
fn a_closed_established_connection_frees_its_slot() {
    echo_after(|addr, certs| echo_once(addr, certs).expect("first echo")).expect("second echo");
}

/// A peer that connects to a TLS listener and closes without sending a
/// ClientHello, as a TCP health check or a port scan does. The connection
/// is closed and its slot freed, so the next connection is served.
#[test]
fn a_fin_before_the_handshake_frees_the_connection_slot() {
    echo_after(|addr, _| drop(TcpStream::connect(addr).unwrap()))
        .expect("an echo after the peer that sent only a FIN");
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
/// half-closes resolves `UnexpectedEof`. The peer reads the ClientHello
/// first, so the FIN arrives after the client's first flight, then
/// half-closes with `shutdown(Write)` and holds the socket until the connect
/// has resolved.
#[test]
fn a_tls_connect_whose_peer_closes_before_the_handshake_resolves_unexpected_eof() {
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
        stream.shutdown(Shutdown::Write).expect("half-close");
        // Hold the socket until the connect has resolved.
        let _ = released.recv();
    });

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(64, 16448)
        .tls_client(TlsClientConfig::builder().build().unwrap())
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Dial>()
        .expect("launch failed");
    let trigger = TcpStream::connect(shutdown.bound_addr().expect("bound address"))
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
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(
        recorded,
        Some(Err(ErrorKind::UnexpectedEof)),
        "how the connect resolved (None: not within 3 s)"
    );
}
