//! `recv_ready` over real sockets, on both backends and over TLS.
//!
//! A server reads one line, then waits on `recv_ready` while the peer is
//! silent and again after the peer writes a second line. `recv_ready` must stay
//! pending while nothing has arrived and resolve once the second line has
//! arrived.

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, Either, ParseResult, RinglineBuilder,
    TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16448)
        .build()
        .expect("valid config")
}

fn stop(
    shutdown: ringline::Runtime,
    handles: Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
) {
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// How long the server checks that `recv_ready` stays pending after the first
/// line.
const QUIET: Duration = Duration::from_millis(100);

/// How long the peer waits after the first line before writing the second.
const GAP: Duration = Duration::from_millis(300);

/// What the server saw after reading the first line.
#[derive(Clone, Debug, PartialEq)]
enum Seen {
    /// `recv_ready` resolved while the peer was silent.
    Early,
    /// `recv_ready` did not resolve within 5 s of the quiet period.
    Hung,
    /// `recv_ready` resolved and the next read returned this line.
    Line(Vec<u8>),
    /// `recv_ready` resolved and the next read reported end of stream.
    Closed,
}

fn wait_for(seen: &Mutex<Vec<Seen>>) -> Seen {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(s) = seen.lock().unwrap().first() {
            return s.clone();
        }
        assert!(Instant::now() < deadline, "the server recorded nothing");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Read one line with `with_data`. `None` at end of stream.
async fn read_line(conn: &mut Connection) -> Option<Vec<u8>> {
    let mut line = None;
    let n = conn
        .with_data(|d| match d.iter().position(|&b| b == b'\n') {
            Some(i) => {
                line = Some(d[..=i].to_vec());
                ParseResult::Consumed(i + 1)
            }
            None => ParseResult::NeedMore,
        })
        .await;
    if n == 0 { None } else { line }
}

/// Read the first line and acknowledge it with one byte, check `recv_ready`
/// stays pending for `QUIET`, then wait for it and read what follows. The peer
/// starts `GAP` only after the acknowledgement, so the quiet period falls
/// inside it however long the server took to read the first line.
async fn wait_then_read(conn: &mut Connection) -> Seen {
    read_line(conn).await.expect("the first line");
    conn.send(b"+").expect("acknowledge");
    if let Either::Left(()) = ringline::select(conn.recv_ready(), ringline::sleep(QUIET)).await {
        return Seen::Early;
    }
    if ringline::timeout(Duration::from_secs(5), conn.recv_ready())
        .await
        .is_err()
    {
        return Seen::Hung;
    }
    match read_line(conn).await {
        Some(line) => Seen::Line(line),
        None => Seen::Closed,
    }
}

macro_rules! server {
    ($name:ident, $seen:ident) => {
        static $seen: Mutex<Vec<Seen>> = Mutex::new(Vec::new());

        struct $name;

        impl AsyncEventHandler for $name {
            #[allow(clippy::manual_async_fn)]
            fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
                async move {
                    let seen = wait_then_read(&mut conn).await;
                    $seen.lock().unwrap().push(seen);
                }
            }

            fn create_for_worker(_id: usize) -> Self {
                $name
            }
        }
    };
}

server!(Copy, COPY);
server!(PeerClose, PEER_CLOSE);
server!(Tls, TLS);

/// Wait for the server's acknowledgement of the first line.
fn await_ack(stream: &mut impl Read) {
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).expect("acknowledgement");
    assert_eq!(&ack, b"+");
}

fn plain_server<H: AsyncEventHandler>() -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
    TcpStream,
) {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address");
    let peer = TcpStream::connect(addr).expect("connect");
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    (shutdown, handles, peer)
}

/// The second line arrives with the accumulator empty. On io_uring the
/// completion lends the buffer instead of copying it.
#[test]
fn resolves_for_a_reply_on_an_empty_accumulator() {
    let (shutdown, handles, mut peer) = plain_server::<Copy>();
    peer.write_all(b"first\n").expect("write");
    await_ack(&mut peer);
    std::thread::sleep(GAP);
    peer.write_all(b"second\n").expect("write");
    assert_eq!(wait_for(&COPY), Seen::Line(b"second\n".to_vec()));
    drop(peer);
    stop(shutdown, handles);
}

#[test]
fn resolves_when_the_peer_closes() {
    let (shutdown, handles, mut peer) = plain_server::<PeerClose>();
    peer.write_all(b"first\n").expect("write");
    await_ack(&mut peer);
    std::thread::sleep(GAP);
    drop(peer);
    assert_eq!(wait_for(&PEER_CLOSE), Seen::Closed);
    stop(shutdown, handles);
}

fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![CertificateDer::from(cert.cert)], key.into())
}

/// Half of the second line's TLS record arrives during the quiet period and
/// the rest after it. `recv_ready` must not resolve on the partial record.
#[test]
fn tls_does_not_resolve_on_a_partial_record() {
    let (certs, key) = self_signed();
    let server = TlsConfig::builder()
        .cert(certs.clone(), key)
        .build()
        .unwrap();
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind_tls("127.0.0.1:0".parse().unwrap(), server)
        .launch::<Tls>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls = rustls::ClientConnection::new(Arc::new(client_config), name).unwrap();
    let mut tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    while tls.is_handshaking() {
        tls.complete_io(&mut tcp).expect("handshake");
    }

    let mut stream = rustls::Stream::new(&mut tls, &mut tcp);
    stream.write_all(b"first\n").expect("write");
    await_ack(&mut stream);
    tls.writer().write_all(b"second\n").expect("encrypt");
    let mut record = Vec::new();
    while tls.wants_write() {
        tls.write_tls(&mut record).expect("write_tls");
    }
    let half = record.len() / 2;
    // Inside the quiet period, which starts when the acknowledgement is sent.
    std::thread::sleep(QUIET / 4);
    tcp.write_all(&record[..half]).expect("write");
    std::thread::sleep(GAP);
    tcp.write_all(&record[half..]).expect("write");

    assert_eq!(wait_for(&TLS), Seen::Line(b"second\n".to_vec()));
    drop(tcp);
    stop(shutdown, handles);
}
