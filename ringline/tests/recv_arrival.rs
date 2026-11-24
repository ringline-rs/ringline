//! `Connection::recv_arrival` over real sockets, on both backends.
//!
//! A client writes lines with pauses between writes and records the instant
//! before each write. The server reads one line per `with_data` call and
//! records `recv_arrival`. A byte cannot arrive before it was sent, so every
//! line's first-byte time must be at or after the instant its first byte was
//! written. A reader that looked up the wrong offset would return the time of
//! an earlier write, which fails that check.

use std::future::Future;
use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder, TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// One line the server read: its bytes and `recv_arrival` after the read.
type Seen = (Vec<u8>, Option<(u64, u64)>);

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

/// Shut the server down and join its workers.
fn stop(
    shutdown: ringline::Runtime,
    handles: Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
) {
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Pause between client writes, so each write is read in its own batch.
const GAP: Duration = Duration::from_millis(30);

/// Read `\n`-terminated lines from `conn` until EOF, recording each.
async fn read_lines(conn: &mut Connection, seen: &Mutex<Vec<Seen>>) {
    loop {
        let mut line = Vec::new();
        let n = conn
            .with_data(|d| match d.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    line.extend_from_slice(&d[..=i]);
                    ParseResult::Consumed(i + 1)
                }
                None => ParseResult::NeedMore,
            })
            .await;
        if n == 0 {
            return;
        }
        let arrival = conn.recv_arrival().map(|a| (a.first_ns(), a.last_ns()));
        seen.lock().unwrap().push((line, arrival));
    }
}

/// Wait until the server has recorded `count` lines.
fn wait_for_lines(seen: &Mutex<Vec<Seen>>, count: usize) -> Vec<Seen> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = seen.lock().unwrap().clone();
        if got.len() >= count {
            return got;
        }
        assert!(
            Instant::now() < deadline,
            "server read {} of {count} lines",
            got.len()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Write each chunk, `GAP` apart, and return the `monotonic_ns` time before
/// each write.
fn write_chunks(stream: &mut impl Write, chunks: &[&[u8]]) -> Vec<u64> {
    let mut sent = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(GAP);
        }
        sent.push(ringline::monotonic_ns());
        stream.write_all(chunk).expect("client write");
        stream.flush().expect("client flush");
    }
    sent
}

/// The lines every test sends: a line, a line split over two writes, and
/// two pipelined lines in one write.
const CHUNKS: [&[u8]; 4] = [b"one\n", b"tw", b"o\n", b"three\nfour\n"];

/// Check the four lines of `CHUNKS` against the times their writes began.
fn check_lines(seen: &[Seen], sent: &[u64]) {
    let lines: Vec<&[u8]> = seen.iter().map(|(l, _)| l.as_slice()).collect();
    assert_eq!(lines, [&b"one\n"[..], b"two\n", b"three\n", b"four\n"]);
    let times: Vec<(u64, u64)> = seen
        .iter()
        .map(|(l, a)| a.unwrap_or_else(|| panic!("no arrival for {l:?}")))
        .collect();
    for (i, (first, last)) in times.iter().enumerate() {
        assert!(first <= last, "line {i}: first after last");
    }
    // A line's first byte was sent by the write that began at `sent[k]`.
    assert!(times[0].0 >= sent[0], "one: arrival before it was sent");
    assert!(times[1].0 >= sent[1], "two: arrival before it was sent");
    assert!(times[1].1 >= sent[2], "two: last byte before its write");
    assert!(times[2].0 >= sent[3], "three: arrival before it was sent");
    assert!(times[3].0 >= sent[3], "four: arrival before it was sent");
}

// ── Plaintext ───────────────────────────────────────────────────────────

static PLAIN: Mutex<Vec<Seen>> = Mutex::new(Vec::new());

struct PlainLines;

impl AsyncEventHandler for PlainLines {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move { read_lines(&mut conn, &PLAIN).await }
    }

    fn create_for_worker(_id: usize) -> Self {
        PlainLines
    }
}

#[test]
fn plaintext_lines_report_times_no_earlier_than_their_writes() {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<PlainLines>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address");

    let mut client = TcpStream::connect(addr).expect("connect");
    let sent = write_chunks(&mut client, &CHUNKS);
    let seen = wait_for_lines(&PLAIN, 4);
    check_lines(&seen, &sent);

    drop(client);
    stop(shutdown, handles);
}

// ── TLS ─────────────────────────────────────────────────────────────────

static TLS: Mutex<Vec<Seen>> = Mutex::new(Vec::new());

struct TlsLines;

impl AsyncEventHandler for TlsLines {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move { read_lines(&mut conn, &TLS).await }
    }

    fn create_for_worker(_id: usize) -> Self {
        TlsLines
    }
}

fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![CertificateDer::from(cert.cert)], key.into())
}

#[test]
fn tls_lines_report_times_no_earlier_than_their_writes() {
    let (certs, key) = self_signed();
    let server = TlsConfig::builder()
        .cert(certs.clone(), key)
        .build()
        .unwrap();
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind_tls("127.0.0.1:0".parse().unwrap(), server)
        .launch::<TlsLines>()
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
    // Finish the handshake before timing anything.
    while tls.is_handshaking() {
        tls.complete_io(&mut tcp).expect("handshake");
    }
    let mut stream = rustls::Stream::new(&mut tls, &mut tcp);
    let sent = write_chunks(&mut stream, &CHUNKS);
    let seen = wait_for_lines(&TLS, 4);
    check_lines(&seen, &sent);

    drop(tcp);
    stop(shutdown, handles);
}
