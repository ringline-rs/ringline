//! Event-ordering tests for [`QuicEndpoint`].
//!
//! The regression of note: quinn-proto's `on_stream_frame` swallows the
//! `Readable` event when the frame both opens a new remotely-initiated stream
//! and carries data — it only sets the `Opened` flag. An application that
//! waits for `StreamReadable` before calling `stream_recv` would hang until
//! the next inbound STREAM frame, which may never arrive for short one-shot
//! messages. `QuicEndpoint` synthesises a `StreamReadable` alongside
//! `StreamOpened` so callers don't need to know this quirk.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use quinn_proto::{ClientConfig, ServerConfig};
use ringline_quic::{QuicConfig, QuicConnId, QuicEndpoint, QuicEvent};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![CertificateDer::from(cert.cert)], key.into())
}

fn server_config(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> QuicConfig {
    let mut sc = ServerConfig::with_single_cert(certs, key).unwrap();
    let transport = Arc::get_mut(&mut sc.transport).unwrap();
    transport.max_concurrent_bidi_streams(64u32.into());
    transport.max_concurrent_uni_streams(64u32.into());
    QuicConfig::server(Arc::new(sc))
}

fn client_config(certs: &[CertificateDer<'static>]) -> QuicConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert.clone()).unwrap();
    }
    let rustls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let cc = ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(rustls_cfg).unwrap(),
    ));
    QuicConfig::client(cc)
}

/// Ferry packets between two endpoints until neither has anything queued.
fn shuffle(
    client: &mut QuicEndpoint,
    server: &mut QuicEndpoint,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) {
    let now = Instant::now();
    for _ in 0..32 {
        let mut moved = false;
        while let Some(pkt) = client.poll_send() {
            for dgram in pkt.datagrams() {
                server.handle_datagram(now, dgram, client_addr);
            }
            moved = true;
        }
        while let Some(pkt) = server.poll_send() {
            for dgram in pkt.datagrams() {
                client.handle_datagram(now, dgram, server_addr);
            }
            moved = true;
        }
        client.drive_timers(now);
        server.drive_timers(now);
        if !moved {
            break;
        }
    }
}

/// Complete the handshake and return both connection ids.
fn handshake(
    client: &mut QuicEndpoint,
    server: &mut QuicEndpoint,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) -> (QuicConnId, QuicConnId) {
    let client_conn = client
        .connect(Instant::now(), server_addr, "localhost")
        .expect("connect");

    let mut server_conn = None;
    // Repeat handshake round trips until both sides are settled.
    for _ in 0..16 {
        shuffle(client, server, client_addr, server_addr);
        while let Some(ev) = server.poll_event() {
            if let QuicEvent::NewConnection(c) = ev {
                server_conn = Some(c);
            }
        }
        while let Some(_ev) = client.poll_event() {}
        if server_conn.is_some() {
            break;
        }
    }

    (
        client_conn,
        server_conn.expect("server never emitted NewConnection"),
    )
}

#[test]
fn stream_opened_with_data_in_opening_frame_fires_readable() {
    let (certs, key) = self_signed();
    let client_addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:40002".parse().unwrap();

    let mut client = QuicEndpoint::new(client_config(&certs), client_addr);
    let mut server = QuicEndpoint::new(server_config(certs, key), server_addr);

    let (client_conn, _server_conn) = handshake(&mut client, &mut server, client_addr, server_addr);
    assert_eq!(server.connection_count(), 1, "server handshake failed");

    // Open a bi-stream and write a tiny payload that fits in one STREAM frame.
    // Crucially, we do NOT call stream_finish — so no subsequent FIN frame
    // will arrive to unblock the else-if branch of quinn-proto's
    // `on_stream_frame`.
    let stream = client
        .open_bi(client_conn)
        .expect("open_bi ok")
        .expect("stream limit");
    client
        .stream_send(client_conn, stream, b"hi")
        .expect("stream_send");
    client.flush(Instant::now());

    shuffle(&mut client, &mut server, client_addr, server_addr);

    let mut saw_opened = false;
    let mut saw_readable = false;
    while let Some(ev) = server.poll_event() {
        match ev {
            QuicEvent::StreamOpened { stream: s, .. } if s == stream => saw_opened = true,
            QuicEvent::StreamReadable { stream: s, .. } if s == stream => saw_readable = true,
            _ => {}
        }
    }

    assert!(saw_opened, "server did not see StreamOpened");
    assert!(
        saw_readable,
        "server did not see StreamReadable for data that arrived with the opening frame \
         — an application waiting on StreamReadable before calling stream_recv would hang"
    );
}
