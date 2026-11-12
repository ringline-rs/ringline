//! A TLS connection closed before its handshake completes drains its queued
//! sends, so the peer receives the rest of the handshake flight and any
//! alert, but only until the close deadline (5 s): then it is torn down
//! without them.
//!
//! The server's handshake flight here is about 2 MB. On loopback, a peer that
//! sets a minimal receive buffer, sends a ClientHello and does not read leaves
//! part of a flight that size queued (a 0.5 MB flight is taken in full).
//! Both backends.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::FromRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder, TlsConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// The tests share the connection counters, and `cargo test` runs them in
/// one process.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// The close deadline, `CLOSE_NOTIFY_TIMEOUT`.
const CLOSE_DEADLINE: Duration = Duration::from_secs(5);

/// Copies of the certificate in a flight of about 2 MB.
const LARGE: usize = 40;

struct Idle;

impl AsyncEventHandler for Idle {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
        async move {}
    }

    fn create_for_worker(_id: usize) -> Self {
        Idle
    }
}

/// A certificate chain of `copies` copies of one self-signed certificate
/// with 2000 subject alternative names (about 50 KB each), and its key.
fn certificate_chain(copies: usize) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let names: Vec<String> = (0..2000)
        .map(|i| format!("host-{i:05}.example.test"))
        .collect();
    let cert = rcgen::generate_simple_self_signed(names).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let der = CertificateDer::from(cert.cert);
    (vec![der; copies], key.into())
}

/// A ClientHello for `localhost` offering only `versions`, as the bytes a
/// client writes first.
fn client_hello(versions: &[&'static rustls::SupportedProtocolVersion]) -> Vec<u8> {
    let config = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut hello = Vec::new();
    conn.write_tls(&mut hello).unwrap();
    hello
}

fn tls13_hello() -> Vec<u8> {
    client_hello(&[&rustls::version::TLS13])
}

/// A TCP connection to `addr` whose receive buffer is set to its minimum
/// before the connect, so the window it advertises stays small.
fn connect_with_small_window(addr: SocketAddr) -> TcpStream {
    let SocketAddr::V4(v4) = addr else {
        panic!("IPv4 address expected")
    };
    // SAFETY: plain socket calls on a descriptor this function owns until
    // `from_raw_fd` takes it.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
        let small: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&small as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: v4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            },
            ..std::mem::zeroed()
        };
        let rc = libc::connect(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        assert_eq!(rc, 0, "connect: {}", std::io::Error::last_os_error());
        TcpStream::from_raw_fd(fd)
    }
}

/// Whether one new connection to `addr` is served: it sends a ClientHello
/// and reads the first byte of the server's reply, a TLS handshake record
/// (0x16). While the server's one slot is held it resets the connection.
fn served_once(addr: SocketAddr) -> bool {
    let Ok(mut probe) = TcpStream::connect(addr) else {
        return false;
    };
    let _ = probe.set_read_timeout(Some(Duration::from_secs(2)));
    let mut first = [0u8; 1];
    probe.write_all(&tls13_hello()).is_ok()
        && probe.read_exact(&mut first).is_ok()
        && first[0] == 0x16
}

/// Whether a new connection to `addr` is served within `within`, retrying.
fn served_within(addr: SocketAddr, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if served_once(addr) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The `tls_handshake_timeout` connection counter.
fn handshake_timeouts() -> u64 {
    ringline::metrics::CONNECTIONS
        .value(ringline::metrics::conn::TLS_HANDSHAKE_TIMEOUT)
        .unwrap_or(0)
}

/// A one-slot TLS server whose handshake flight carries `copies` copies of
/// the certificate.
struct Server {
    runtime: ringline::Runtime,
    handles: Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
    addr: SocketAddr,
}

impl Server {
    fn start(copies: usize, handshake_timeout: Duration, tick_timeout_us: u64) -> Server {
        let (certs, key) = certificate_chain(copies);
        let config = ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .sq_entries(64)
            .max_connections(1)
            // Room for the whole flight, one TLS record per slot.
            .send_pool(1024, 16448)
            .tick_timeout_us(tick_timeout_us)
            .tls_handshake_timeout(handshake_timeout)
            .tls(TlsConfig::builder().cert(certs, key).build().unwrap())
            .build()
            .expect("valid config");
        let (runtime, handles) = RinglineBuilder::new(config)
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<Idle>()
            .expect("launch failed");
        let addr = runtime.bound_addr().expect("bound address");
        Server {
            runtime,
            handles,
            addr,
        }
    }

    fn stop(self) {
        self.runtime.shutdown();
        for h in self.handles {
            h.join().unwrap().unwrap();
        }
    }
}

/// What closes the stalled connection.
#[derive(Clone, Copy, PartialEq)]
enum Close {
    /// A 300 ms `tls_handshake_timeout`.
    Timeout,
    /// The peer's FIN after its ClientHello, under a 60 s timeout.
    Fin,
}

/// Have a peer send a ClientHello to a server with a flight of `copies`
/// certificates and stop reading, let `close` close the connection, and
/// report whether the slot is served again within the close deadline plus
/// 3 s.
fn slot_returns_after_a_stalled_handshake(copies: usize, close: Close) -> bool {
    let _serial = serial();
    let timeout = match close {
        Close::Timeout => Duration::from_millis(300),
        Close::Fin => Duration::from_secs(60),
    };
    let server = Server::start(copies, timeout, 1000);

    let before = handshake_timeouts();
    let mut stalled = connect_with_small_window(server.addr);
    stalled.write_all(&tls13_hello()).unwrap();
    if close == Close::Fin {
        stalled.shutdown(std::net::Shutdown::Write).unwrap();
    }
    // Past the handshake timeout, or the FIN's arrival.
    std::thread::sleep(Duration::from_millis(800));
    let expected = u64::from(close == Close::Timeout);
    assert_eq!(
        handshake_timeouts() - before,
        expected,
        "handshake timeouts counted"
    );
    let served = served_within(server.addr, CLOSE_DEADLINE + Duration::from_secs(3));

    drop(stalled);
    server.stop();
    served
}

/// Control: a flight of one certificate fits in the socket buffers, so the
/// close does not wait on it.
#[test]
fn the_slot_returns_after_a_handshake_timeout_with_a_small_flight() {
    assert!(slot_returns_after_a_stalled_handshake(1, Close::Timeout));
}

/// A flight of about 2 MB does not fit, and the peer never reads it.
#[test]
fn the_slot_returns_after_a_handshake_timeout_with_an_unsent_flight() {
    assert!(
        slot_returns_after_a_stalled_handshake(LARGE, Close::Timeout),
        "the slot was still held 3 s after the close deadline"
    );
}

/// The same flight, with the connection closed by the peer's FIN.
#[test]
fn the_slot_returns_after_a_fin_with_an_unsent_flight() {
    assert!(
        slot_returns_after_a_stalled_handshake(LARGE, Close::Fin),
        "the slot was still held 3 s after the close deadline"
    );
}

/// With `tick_timeout_us(0)` and no traffic after the close, the close
/// deadline is checked only when one of the worker's own timers ends its
/// wait. One probe made 2 s after the deadline is served only if the
/// connection was torn down by then: a probe that woke the worker would find
/// the slot still held. `close` is what closed it.
fn the_close_deadline_fires_without_a_tick(close: Close) -> bool {
    let _serial = serial();
    let timeout = match close {
        Close::Timeout => Duration::from_millis(300),
        Close::Fin => Duration::from_secs(60),
    };
    let server = Server::start(LARGE, timeout, 0);
    let mut stalled = connect_with_small_window(server.addr);
    stalled.write_all(&tls13_hello()).unwrap();
    if close == Close::Fin {
        stalled.shutdown(std::net::Shutdown::Write).unwrap();
    }
    // The close (up to about 1 s with a 2 MB flight to build), then the close
    // deadline, then 2 s.
    std::thread::sleep(Duration::from_secs(1) + CLOSE_DEADLINE + Duration::from_secs(2));
    let served = served_once(server.addr);
    drop(stalled);
    server.stop();
    served
}

/// After a handshake timeout the stalled send comes back short and waits for
/// room, so on io_uring the 1 s retry timer for such sends wakes the worker.
#[test]
fn the_close_deadline_fires_without_a_tick_after_a_handshake_timeout() {
    assert!(
        the_close_deadline_fires_without_a_tick(Close::Timeout),
        "the slot was still held 2 s after the close deadline"
    );
}

/// After the peer's FIN. The stalled flight still comes back short and waits
/// for room, so on io_uring the 1 s retry timer wakes the worker here too;
/// the worker's deadline timer is what wakes it only when that timer is
/// disabled.
#[test]
fn the_close_deadline_fires_without_a_tick_after_a_fin() {
    assert!(
        the_close_deadline_fires_without_a_tick(Close::Fin),
        "the slot was still held 2 s after the close deadline"
    );
}

/// The TLS records in `bytes`, as (content type, payload).
fn records(mut bytes: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while bytes.len() >= 5 {
        let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        if bytes.len() < 5 + len {
            break;
        }
        out.push((bytes[0], &bytes[5..5 + len]));
        bytes = &bytes[5 + len..];
    }
    out
}

/// A TLS error before the handshake completes queues a fatal alert behind
/// the rest of the flight. A peer that reads after the close, within the
/// close deadline, receives the whole flight and then the alert. TLS 1.2 is
/// used because its handshake records and this alert are not encrypted.
#[test]
fn a_peer_that_reads_after_the_close_receives_the_alert() {
    let _serial = serial();
    let server = Server::start(LARGE, Duration::from_secs(60), 1000);
    let mut peer = connect_with_small_window(server.addr);
    peer.write_all(&client_hello(&[&rustls::version::TLS12]))
        .unwrap();
    // An application-data record where the server expects the client's key
    // exchange: rustls fails the handshake with a fatal unexpected_message
    // alert, and the error closes the connection.
    peer.write_all(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00])
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));

    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut received = Vec::new();
    let end = peer.read_to_end(&mut received);
    drop(peer);
    server.stop();

    end.expect("the server closes after the alert");
    let records = records(&received);
    let flight: usize = records
        .iter()
        .filter(|(kind, _)| *kind == 0x16)
        .map(|(_, payload)| payload.len())
        .sum();
    assert!(flight > 1 << 20, "{flight} bytes of handshake records");
    let last = records.last().expect("records");
    assert_eq!(last.0, 0x15, "the last record is an alert");
    assert_eq!(last.1, &[2, 10], "fatal unexpected_message");
}
