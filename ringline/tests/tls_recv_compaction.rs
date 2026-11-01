//! Bytes a TLS connection's accumulator copies when a `with_data` reader
//! receives pipelined messages larger than a TLS record, read from the
//! process-wide `ringline/recv_ring` counter. In its own test binary, with one
//! test, so no other runtime in the process adds to it.
//!
//! io_uring only: on mio some runs with `compact_at_message_start` move as
//! much as runs without it, so no bound separates the two. On both backends,
//! `tls_recv_compaction_rr` covers messages answered one at a time.
#![cfg(has_io_uring)]
#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ringline::metrics::{RECV_RING, recv_ring};
use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};

const FRAMES: usize = 200;
const PAYLOAD: usize = 64 * 1024;

static RECEIVED: AtomicUsize = AtomicUsize::new(0);

/// Reads `FRAMES` frames (a 4-byte length and a payload) with `with_data`,
/// one frame per call, returning `NeedMore` until a frame is complete.
struct Server;

impl AsyncEventHandler for Server {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            for _ in 0..FRAMES {
                let n = conn
                    .with_data(|d| {
                        if d.len() < 4 {
                            return ParseResult::NeedMore;
                        }
                        let n = u32::from_be_bytes(d[..4].try_into().unwrap()) as usize;
                        if d.len() < 4 + n {
                            ParseResult::NeedMore
                        } else {
                            ParseResult::Consumed(4 + n)
                        }
                    })
                    .await;
                if n == 0 {
                    break;
                }
                RECEIVED.fetch_add(1, Ordering::Relaxed);
            }
            let _ = ringline::request_shutdown();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Server
    }
}

#[test]
fn tls_with_data_moves_few_bytes_of_pipelined_large_messages() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let certs = vec![CertificateDer::from(cert.cert)];
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        // One whole TLS record per slot, which the unbuffered engine needs.
        .send_pool(64, 16448)
        .tls(
            TlsConfig::builder()
                .cert(certs.clone(), key.into())
                .build()
                .unwrap(),
        )
        .build()
        .expect("config");
    let before = RECV_RING.value(recv_ring::BYTES_COPIED).unwrap_or(0);
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Server>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");

    let client = std::thread::spawn(move || {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name: ServerName<'_> = "localhost".try_into().unwrap();
        let mut tls = rustls::ClientConnection::new(Arc::new(client_config), name).unwrap();
        let mut tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut stream = rustls::Stream::new(&mut tls, &mut tcp);
        let mut out = Vec::with_capacity(FRAMES * (PAYLOAD + 4));
        for _ in 0..FRAMES {
            out.extend_from_slice(&(PAYLOAD as u32).to_be_bytes());
            out.resize(out.len() + PAYLOAD, 0x5a);
        }
        stream.write_all(&out).unwrap();
        stream.flush().unwrap();
        // Hold the connection until the server closes it.
        let mut buf = [0u8; 64];
        let _ = stream.read(&mut buf);
    });

    common::join_workers(&runtime, handles);
    client.join().unwrap();
    assert_eq!(RECEIVED.load(Ordering::Relaxed), FRAMES, "frames received");
    let copied = RECV_RING.value(recv_ring::BYTES_COPIED).unwrap_or(0) - before;
    let plaintext = (FRAMES * (PAYLOAD + 4)) as u64;
    // `BYTES_COPIED` counts the copy of each decrypted record into the
    // accumulator, once per plaintext byte, and every move of bytes already in
    // it, so the rest is mostly moves. Plaintext stashed before a read parks
    // is counted when stashed and again when appended.
    let moved = copied.saturating_sub(plaintext);
    eprintln!(
        "{FRAMES} x {PAYLOAD} B over TLS: copied {copied}, moved {moved}, plaintext {plaintext}"
    );
    // 0.25 to 0.5 per plaintext byte with `compact_at_message_start`, 1.0
    // without the call at the incomplete parse.
    assert!(
        moved * 4 <= plaintext * 3,
        "{moved} bytes moved for {plaintext} bytes of plaintext"
    );
}
