#![allow(clippy::manual_async_fn)]
//! TLS output produced on the receive path waits for send-pool slots
//! (`docs/send-pool-partition-design.md`, section 2). One connection's peer
//! stops reading while its server sends until the pool has fewer free slots
//! than a second connection's handshake flight needs. That handshake waits,
//! and completes once the first peer reads and the slots come back.
//!
//! io_uring only: on mio TLS output holds no send-pool slots.
#![cfg(has_io_uring)]

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// One whole record per slot, which the unbuffered engine needs.
const SLOT: u32 = 16448;
const SLOTS: u16 = 64;
/// The plaintext of one TLS record.
const F: usize = 16384;
/// Subject alternative names on the server's certificate, enough that its
/// handshake flight is longer than one slot.
const NAMES: usize = 600;

/// The filling connection's sends hold all but at most one slot.
static FILLED: AtomicBool = AtomicBool::new(false);
/// `tls_output_waited` as the second connection's task saw it.
static WAITED: Mutex<Option<u64>> = Mutex::new(None);

struct Server;

impl AsyncEventHandler for Server {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // `f` fills the pool, `h` reports. `wait_for_server`'s probe
            // closes without a byte.
            let mut first = 0;
            let n = conn
                .with_data(|d| {
                    first = d[0];
                    ParseResult::Consumed(d.len())
                })
                .await;
            if n == 0 {
                return;
            }
            if first == b'h' {
                *WAITED.lock().unwrap() =
                    Some(ringline::send_admission_counters().tls_output_waited);
                conn.send(b"ok").expect("send").await.expect("sent");
                return;
            }
            // Send until a send is refused, and again after a pause in which
            // the held count did not fall: the peer has stopped reading and
            // the queued sends hold the slots. A refused send needs two
            // slots, so at most one is left.
            let record = vec![0x5au8; F];
            let mut held_at_refusal = None;
            loop {
                match conn.send(&record) {
                    Ok(_) => held_at_refusal = None,
                    Err(_) => {
                        let held = conn.send_pool_held();
                        if held_at_refusal == Some(held) {
                            break;
                        }
                        held_at_refusal = Some(held);
                        ringline::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            FILLED.store(true, Ordering::SeqCst);
            // Keep the connection until its peer goes.
            while conn.with_data(|d| ParseResult::Consumed(d.len())).await != 0 {}
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Server
    }
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
    let mut names = vec!["localhost".to_string()];
    names.extend((0..NAMES).map(|i| format!("name-{i:04}.sealed-output.test")));
    let cert = rcgen::generate_simple_self_signed(names).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![CertificateDer::from(cert.cert)], key.into())
}

fn client(certs: &[CertificateDer<'static>]) -> rustls::ClientConnection {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    rustls::ClientConnection::new(config, server_name).unwrap()
}

/// A handshake whose flight the send pool has no slots for waits, and
/// completes once slots come back: the client reads the server's reply over
/// it, and the server counted the output as waiting.
#[test]
fn a_handshake_flight_waits_for_send_pool_slots() {
    let (certs, key) = generate_self_signed();
    assert!(
        certs[0].len() > SLOT as usize,
        "the certificate ({} bytes) makes the flight longer than one slot",
        certs[0].len()
    );
    let server_tls = ringline::TlsConfig::builder()
        .cert(certs.clone(), key)
        .build()
        .unwrap();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        .max_connections(16)
        .send_pool(SLOTS, SLOT)
        .tls(server_tls)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Server>()
        .expect("launch failed");
    let addr = runtime.bound_addr().expect("bound_addr").to_string();
    wait_for_server(&addr);

    // The filling connection: handshake, ask for the fill, stop reading.
    let mut fill_tls = client(&certs);
    let mut fill_tcp = TcpStream::connect(&addr).unwrap();
    fill_tcp
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    {
        let mut stream = rustls::Stream::new(&mut fill_tls, &mut fill_tcp);
        stream.write_all(b"f").unwrap();
        stream.flush().unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while !FILLED.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "the pool never filled");
        std::thread::sleep(Duration::from_millis(10));
    }

    // The second connection's handshake waits for slots.
    let second = std::thread::spawn({
        let certs = certs.clone();
        let addr = addr.clone();
        move || {
            let mut tls = client(&certs);
            let mut tcp = TcpStream::connect(&addr).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            let mut stream = rustls::Stream::new(&mut tls, &mut tcp);
            stream.write_all(b"h").unwrap();
            stream.flush().unwrap();
            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply).map(|()| reply)
        }
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !second.is_finished(),
        "the handshake finished while the pool had no slots for its flight"
    );

    // The filling peer reads its ciphertext without decrypting it, and the
    // queued sends give their slots back.
    let drain = std::thread::spawn(move || {
        let mut buf = vec![0u8; 1 << 16];
        while let Ok(n) = fill_tcp.read(&mut buf) {
            if n == 0 {
                break;
            }
        }
    });
    let reply = second.join().unwrap().expect("the handshake completed");
    assert_eq!(&reply, b"ok");
    assert!(
        WAITED.lock().unwrap().is_some_and(|w| w >= 1),
        "the flight was counted as waiting: {:?}",
        WAITED.lock().unwrap()
    );

    runtime.shutdown();
    common::join_workers(&runtime, handles);
    let _ = drain.join();
}
