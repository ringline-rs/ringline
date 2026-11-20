#![allow(clippy::manual_async_fn)]
//! A TLS send on io_uring takes the slots of its ciphertext bound before
//! encrypting and returns the ones encryption did not use, so straight after
//! the send the connection holds the slots its ciphertext fills, not the
//! bound (`SendHalf::send_pool_held`).
//!
//! io_uring only: on mio a plain TLS send queues an owned buffer and holds no
//! send-pool slots.
#![cfg(has_io_uring)]

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// One whole record per slot, which the unbuffered engine needs.
const SLOT: u32 = 16448;
const SLOTS: u16 = 64;
/// The plaintext of one TLS record.
const F: usize = 16384;
/// Nine full records and a short tenth.
const LEN: usize = 9 * F + 100;
/// The ciphertext bound for `LEN`: `ceil(LEN / F) + 1` records, which is 11
/// slots on both engines at this slot size.
const BOUND: usize = 11;
/// The slots the ciphertext fills. The unbuffered engine writes whole
/// records into each slot, one record per slot here. The buffered engine
/// packs the 147,776 bytes of TLS 1.3 records (22 bytes of overhead each)
/// into slots back to back.
#[cfg(not(feature = "tls-buffered"))]
const USED: usize = 10;
#[cfg(feature = "tls-buffered")]
const USED: usize = 9;
const _: () = assert!(USED < BOUND);

/// What the handler saw: held straight after the send, and held after it
/// completed.
static SEEN: Mutex<Option<(usize, usize)>> = Mutex::new(None);

struct Sender;

impl AsyncEventHandler for Sender {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Wait for the client's go byte. `wait_for_server`'s probe
            // connection closes without one.
            let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
            if n == 0 {
                return;
            }
            // Session tickets sent after the handshake hold slots until their
            // sends complete.
            let start = Instant::now();
            while conn.send_pool_held() != 0 {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "handshake output still holds {} slots",
                    conn.send_pool_held()
                );
                ringline::sleep(Duration::from_millis(1)).await;
            }
            let data = vec![0x5au8; LEN];
            let done = conn.send(&data).expect("send");
            // `send` encrypts in the call and the task has not yielded since,
            // so no completion has been processed.
            let held = conn.send_pool_held();
            done.await.expect("send completed");
            let after = conn.send_pool_held();
            *SEEN.lock().unwrap() = Some((held, after));
            conn.close();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Sender
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
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![CertificateDer::from(cert.cert)], key.into())
}

#[test]
fn a_tls_send_holds_the_slots_its_ciphertext_fills() {
    let (certs, key) = generate_self_signed();
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
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Sender>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound_addr").to_string();
    wait_for_server(&addr);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut stream = rustls::Stream::new(&mut tls, &mut tcp);
    stream.write_all(b"g").unwrap();
    stream.flush().unwrap();
    let mut got = vec![0u8; LEN];
    stream.read_exact(&mut got).unwrap();
    assert!(got.iter().all(|&b| b == 0x5a));

    let (held, after) = SEEN.lock().unwrap().take().expect("handler finished");
    assert_eq!(
        held, USED,
        "held straight after the send: the slots the ciphertext fills, not the \
         {BOUND}-slot bound"
    );
    assert_eq!(after, 0, "held after the send completed");

    shutdown.shutdown();
    common::join_workers(&shutdown, handles);
}
