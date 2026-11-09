//! A TLS record-layer error is reported to the reader as an error.
//!
//! A peer that sends a record the engine cannot decrypt ends the connection.
//! `with_data_result` resolves `Err(InvalidData)` for it, where a peer's
//! close_notify or FIN resolves `Ok(0)`; `with_data` keeps resolving `0` for
//! both. Both backends.

mod common;

use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// What the handler's last `with_data_result` resolved with: `Ok(0)` or the
/// error's kind.
static READ_END: Mutex<Option<Result<usize, ErrorKind>>> = Mutex::new(None);

/// Echoes each message, and records how its read ended.
struct RecordingEcho;

impl AsyncEventHandler for RecordingEcho {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let mut echo = Vec::new();
                let result = conn
                    .with_data_result(|data| {
                        echo.extend_from_slice(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                match result {
                    Ok(0) => {
                        *READ_END.lock().unwrap() = Some(Ok(0));
                        return;
                    }
                    Ok(_) => {
                        let _ = conn.send_nowait(&echo);
                    }
                    Err(e) => {
                        *READ_END.lock().unwrap() = Some(Err(e.kind()));
                        return;
                    }
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        RecordingEcho
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

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

/// Echo one message over TLS, so the connection is established and the
/// handler is reading, then write a record the server cannot decrypt on
/// the raw stream and read to the end.
#[test]
fn a_record_the_engine_cannot_decrypt_is_an_error_to_the_reader() {
    *READ_END.lock().unwrap() = None;
    let (certs, key) = generate_self_signed();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
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
        .launch::<RecordingEcho>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    let server_name: ServerName<'_> = "localhost".try_into().unwrap();
    let mut tls_conn =
        rustls::ClientConnection::new(client_tls_config(&certs), server_name).unwrap();
    let mut tcp = TcpStream::connect(&addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    {
        let mut stream = rustls::Stream::new(&mut tls_conn, &mut tcp);
        stream.write_all(b"hello").unwrap();
        stream.flush().unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).expect("the echo");
        assert_eq!(&buf, b"hello");
    }

    // An application-data record whose ciphertext the server's keys do not
    // authenticate: `bad_record_mac` at the server's record layer.
    let bogus = [0x17, 0x03, 0x03, 0x00, 0x20]
        .into_iter()
        .chain(std::iter::repeat_n(0xA5u8, 32))
        .collect::<Vec<u8>>();
    tcp.write_all(&bogus).unwrap();
    tcp.flush().unwrap();

    // The server sends an alert and closes; read the raw stream to its end.
    let mut sink = [0u8; 4096];
    loop {
        match tcp.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }

    // The handler records the end of its read before the worker releases
    // the connection; give it a bounded moment.
    let mut end = None;
    for _ in 0..200 {
        end = *READ_END.lock().unwrap();
        if end.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(
        end,
        Some(Err(ErrorKind::InvalidData)),
        "a record-layer error is reported to the reader as InvalidData"
    );
}
