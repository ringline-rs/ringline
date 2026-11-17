#![allow(clippy::manual_async_fn)]
//! `send_parts().build` and `forward_recv_buf` return a `SendCompletion` that
//! resolves with the length they sent, on plaintext and TLS connections, and
//! `build` refuses, with `InvalidInput` and nothing sent, a batch that carries
//! no bytes and a closure that returns without submitting.

use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};

/// What each `build` scenario returned, keyed by the trigger byte: the
/// awaited length, or the error kind of the refusal.
static BUILT: Mutex<Vec<(u8, Result<u32, ErrorKind>)>> = Mutex::new(Vec::new());

/// A forward's length and what its completion resolved with.
type Forward = (usize, Result<u32, String>);

/// The forwards, one list per `ForwardEcho` slot so that the plaintext and
/// TLS tests do not share one.
static FORWARDS: [Mutex<Vec<Forward>>; 2] = [Mutex::new(Vec::new()), Mutex::new(Vec::new())];

/// Two copy parts, awaited. A TLS client sends the scenario byte in upper
/// case, so that its result is told apart from a plaintext run's.
const TWO_PARTS: u8 = b'p';
/// `submit` on a builder with no parts.
const EMPTY: u8 = b'e';
/// A closure that adds a part and returns `Ok` without calling `submit`.
const NO_SUBMIT: u8 = b'n';

const FIRST: &[u8] = &[b'a'; 10];
const SECOND: &[u8] = &[b'b'; 20];
/// Sent after a refused `build`, so the client can tell the refusal sent
/// nothing: it is the only byte the client reads.
const MARKER: &[u8] = b"m";

/// Runs the `build` scenario the client's first byte names and records the
/// result, then stays open until the client closes.
struct BuildScenarios;

impl AsyncEventHandler for BuildScenarios {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut trigger = 0u8;
            let n = conn
                .with_data(|data| {
                    trigger = data[0];
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n == 0 {
                return;
            }
            let built = match trigger.to_ascii_lowercase() {
                TWO_PARTS => conn
                    .send_parts()
                    .build(|b| b.copy(FIRST).copy(SECOND).submit()),
                EMPTY => conn.send_parts().build(|b| b.submit()),
                NO_SUBMIT => conn.send_parts().build(|b| {
                    let _unsubmitted = b.copy(FIRST);
                    Ok(())
                }),
                other => panic!("unknown scenario {other}"),
            };
            let result = match built {
                Ok(sent) => sent.await.map_err(|e| e.kind()),
                Err(e) => {
                    conn.send(MARKER).expect("marker queued");
                    Err(e.kind())
                }
            };
            BUILT.lock().unwrap().push((trigger, result));
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        BuildScenarios
    }
}

/// Echoes with `forward_recv_buf`, awaiting each forward's completion before
/// the next read and recording its result in `FORWARDS[SLOT]`.
struct ForwardEcho<const SLOT: usize>;

impl<const SLOT: usize> AsyncEventHandler for ForwardEcho<SLOT> {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let mut forwarded = None;
                let n = rx
                    .with_data(|data| {
                        if data.is_empty() {
                            return ParseResult::Consumed(0);
                        }
                        forwarded = Some((data.len(), tx.forward_recv_buf(data)));
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if let Some((len, sent)) = forwarded {
                    let result = match sent {
                        Ok(sent) => sent.await,
                        Err(e) => Err(e),
                    };
                    FORWARDS[SLOT]
                        .lock()
                        .unwrap()
                        .push((len, result.map_err(|e| e.to_string())));
                }
                if n == 0 {
                    break;
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        ForwardEcho
    }
}

/// A server config with a self-signed certificate for `localhost`, and the
/// certificate for the client to trust.
fn tls_server() -> (TlsConfig, Vec<CertificateDer<'static>>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let certs = vec![CertificateDer::from(cert.cert)];
    let config = TlsConfig::builder()
        .cert(certs.clone(), key.into())
        .build()
        .unwrap();
    (config, certs)
}

/// The client end of a test connection, plaintext or TLS.
enum Client {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Client {
    /// Connect to `addr`, over TLS trusting `certs` when they are given.
    fn connect(addr: SocketAddr, certs: Option<&[CertificateDer<'static>]>) -> Self {
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let Some(certs) = certs else {
            return Client::Plain(tcp);
        };
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots.add(cert.clone()).unwrap();
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name: ServerName<'static> = "localhost".try_into().unwrap();
        let conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        Client::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
    }
}

impl Read for Client {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Client::Plain(s) => s.read(buf),
            Client::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Client {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Client::Plain(s) => s.write(buf),
            Client::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Client::Plain(s) => s.flush(),
            Client::Tls(s) => s.flush(),
        }
    }
}

fn launch<H: AsyncEventHandler + 'static>(
    tls: Option<TlsConfig>,
) -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
) {
    let mut config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        // One whole TLS record per slot, which the unbuffered engine needs.
        .send_pool(16, 16448);
    if let Some(tls) = tls {
        config = config.tls(tls);
    }
    RinglineBuilder::new(config.build().expect("valid config"))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch")
}

/// Runs `scenario`, over TLS when `tls` is set, reads `expected` from the
/// server, and returns what the `build` resolved or was refused with.
fn run_build(scenario: u8, expected: &[u8], tls: bool) -> Result<u32, ErrorKind> {
    let (server_tls, certs) = tls_server();
    let (runtime, handles) = launch::<BuildScenarios>(tls.then_some(server_tls));
    let addr = runtime.bound_addr().expect("bound address");
    let mut stream = Client::connect(addr, tls.then_some(&certs[..]));
    let scenario = if tls {
        scenario.to_ascii_uppercase()
    } else {
        scenario
    };
    stream.write_all(&[scenario]).unwrap();
    stream.flush().unwrap();

    let mut got = vec![0u8; expected.len()];
    stream.read_exact(&mut got).expect("the server's bytes");
    assert_eq!(got, expected, "the bytes the server sent");

    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        {
            let mut results = BUILT.lock().unwrap();
            if let Some(pos) = results.iter().position(|(s, _)| *s == scenario) {
                break results.remove(pos).1;
            }
        }
        assert!(Instant::now() < deadline, "the build never resolved");
        std::thread::sleep(Duration::from_millis(1));
    };
    drop(stream);
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    result
}

#[test]
fn build_resolves_with_the_length_of_its_parts() {
    let expected = [FIRST, SECOND].concat();
    assert_eq!(
        run_build(TWO_PARTS, &expected, false),
        Ok((FIRST.len() + SECOND.len()) as u32)
    );
}

/// On io_uring a TLS batch is encrypted as one send (`SendBuilder::submit_tls`),
/// which carries the batch's id on its last ciphertext send.
#[test]
fn build_over_tls_resolves_with_the_length_of_its_parts() {
    let expected = [FIRST, SECOND].concat();
    assert_eq!(
        run_build(TWO_PARTS, &expected, true),
        Ok((FIRST.len() + SECOND.len()) as u32)
    );
}

#[test]
fn build_refuses_an_empty_batch() {
    assert_eq!(
        run_build(EMPTY, MARKER, false),
        Err(ErrorKind::InvalidInput)
    );
}

/// Before 0.7 the mio backend sent the parts of a closure that never called
/// `submit`, and io_uring did not. Both now send nothing and refuse.
#[test]
fn build_refuses_a_closure_that_does_not_submit() {
    assert_eq!(
        run_build(NO_SUBMIT, MARKER, false),
        Err(ErrorKind::InvalidInput)
    );
}

#[test]
fn forward_recv_buf_resolves_with_the_forwarded_length() {
    run_forward::<0>(false);
}

/// On io_uring a TLS forward of the whole accumulator is encrypted from the
/// detached accumulator, and any other is a copy send; both carry the id on
/// their last ciphertext send.
#[test]
fn forward_recv_buf_over_tls_resolves_with_the_forwarded_length() {
    run_forward::<1>(true);
}

/// Echoes 64 KiB through `ForwardEcho<SLOT>`, over TLS when `tls` is set,
/// and checks that every forward's completion resolved with its length.
fn run_forward<const SLOT: usize>(tls: bool) {
    const LEN: usize = 64 * 1024;
    let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let (server_tls, certs) = tls_server();
    let (runtime, handles) = launch::<ForwardEcho<SLOT>>(tls.then_some(server_tls));
    let addr = runtime.bound_addr().expect("bound address");
    let mut stream = Client::connect(addr, tls.then_some(&certs[..]));
    stream.write_all(&payload).unwrap();
    stream.flush().unwrap();
    let mut got = vec![0u8; LEN];
    stream.read_exact(&mut got).expect("the echo");
    assert_eq!(got, payload, "the echoed bytes");

    let deadline = Instant::now() + Duration::from_secs(5);
    let forwards = loop {
        {
            let forwards = FORWARDS[SLOT].lock().unwrap();
            if forwards.iter().map(|(len, _)| len).sum::<usize>() == LEN {
                break forwards.clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "the forwards' completions never all resolved"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    for (len, result) in &forwards {
        assert_eq!(
            result.as_ref().map(|&n| n as usize),
            Ok(*len),
            "a forward's completion"
        );
    }

    drop(stream);
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
}
