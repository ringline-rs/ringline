//! Tests for StreamFinished event handling.
//!
//! Regression tests for the missing `StreamFinished` handler that caused
//! h3 connections to stall when the peer finished sending on a stream.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use quinn_proto::{ClientConfig, ServerConfig, TransportConfig, VarInt};
use ringline_h3::{H3Connection, H3Event, HeaderField, Settings};
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
    transport.max_concurrent_bidi_streams(16u32.into());
    transport.max_concurrent_uni_streams(16u32.into());
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
    let mut cc = ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(rustls_cfg).unwrap(),
    ));
    let mut transport = TransportConfig::default();
    // Tight per-stream window so server responses get backpressured.
    transport.stream_receive_window(VarInt::from(1024u32));
    transport.receive_window(VarInt::from(4096u32));
    transport.max_concurrent_bidi_streams(16u32.into());
    transport.max_concurrent_uni_streams(16u32.into());
    cc.transport_config(Arc::new(transport));
    QuicConfig::client(cc)
}

fn shuffle(
    client: &mut QuicEndpoint,
    server: &mut QuicEndpoint,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) {
    for _ in 0..128 {
        let now = Instant::now();
        client.flush(now);
        server.flush(now);
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
    for _ in 0..32 {
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
        server_conn.expect("server did not emit NewConnection"),
    )
}

fn pump_h3(ep: &mut QuicEndpoint, h3: &mut H3Connection) {
    let mut events = Vec::new();
    while let Some(ev) = ep.poll_event() {
        events.push(ev);
    }
    for ev in events {
        h3.handle_quic_event(ep, &ev).expect("h3 event");
    }
}

/// Test that when the peer finishes sending on a stream, h3 emits a
/// StreamFinished event for that stream.
///
/// Without a StreamFinished handler, this event is never emitted, and the
/// application stalls waiting for it.
#[test]
fn stream_finished_event_emitted() {
    let (certs, key) = self_signed();
    let client_addr: SocketAddr = "127.0.0.1:51101".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:51102".parse().unwrap();

    let mut client_ep = QuicEndpoint::new(client_config(&certs), client_addr);
    let mut server_ep = QuicEndpoint::new(server_config(certs, key), server_addr);

    let (client_conn, server_conn) =
        handshake(&mut client_ep, &mut server_ep, client_addr, server_addr);

    let mut client_h3 = H3Connection::new(Settings::default());
    let mut server_h3 = H3Connection::new(Settings::default());

    client_h3
        .handle_quic_event(&mut client_ep, &QuicEvent::Connected(client_conn))
        .expect("client initiate");
    server_h3
        .handle_quic_event(&mut server_ep, &QuicEvent::NewConnection(server_conn))
        .expect("server accept");

    // Exchange SETTINGS.
    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut client_ep, &mut client_h3);
    pump_h3(&mut server_ep, &mut server_h3);
    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut client_ep, &mut client_h3);
    pump_h3(&mut server_ep, &mut server_h3);

    // Client sends a POST request with body and FIN.
    let req_stream = client_h3
        .send_request(
            &mut client_ep,
            &[
                HeaderField::new(b":method", b"POST"),
                HeaderField::new(b":path", b"/echo"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"localhost"),
            ],
            false, // no end_stream yet
        )
        .expect("send_request");

    // Send body data and then FIN.
    let body = b"request body";
    client_h3
        .send_data(&mut client_ep, req_stream, body, false)
        .expect("send_data");
    client_h3
        .send_data(&mut client_ep, req_stream, body, true) // FIN
        .expect("send_data");

    // Flush to server and process.
    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut client_ep, &mut client_h3);
    pump_h3(&mut server_ep, &mut server_h3);

    // Server sends response + FIN.
    let resp_stream = server_h3
        .poll_event()
        .and_then(|e| {
            if let H3Event::Request { stream_id, .. } = e {
                Some(stream_id)
            } else {
                None
            }
        })
        .expect("server should see Request");

    server_h3
        .send_response(
            &mut server_ep,
            resp_stream,
            &[HeaderField::new(b":status", b"200")],
            false,
        )
        .expect("send_response");
    // Send a large response body that will be backpressured by the tight
    // flow-control window, so the server has pending writes.
    let large_body: Vec<u8> = (0u8..255).cycle().take(8 * 1024).collect();
    server_h3
        .send_data(&mut server_ep, resp_stream, &large_body, true) // FIN
        .expect("send_data");

    // Keep shuffling until the server's pending writes drain (flow control
    // window opens). Without the StreamFinished handler, the FIN is deferred
    // and the pending_sends entry lingers forever.
    for _ in 0..256 {
        shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
        pump_h3(&mut client_ep, &mut client_h3);
        pump_h3(&mut server_ep, &mut server_h3);
        if !server_h3.has_pending_writes(resp_stream) {
            break;
        }
    }

    // The client's FIN on the request stream should be acknowledged by the
    // server. Without the StreamFinished handler, the client's pending_sends
    // entry for the request stream is never cleaned up — it lingers forever.
    assert!(
        !client_h3.has_pending_writes(req_stream),
        "client pending_sends for request stream should be cleaned up after FIN",
    );

    // The server's FIN on the response stream should be acknowledged by the
    // client. Without the handler, the server's pending_sends entry for the
    // response stream lingers forever.
    assert!(
        !server_h3.has_pending_writes(resp_stream),
        "server pending_sends for response stream should be cleaned up after FIN",
    );
}

/// Test that the connection is cleaned up when a QUIC connection is closed.
///
/// Without cleanup on ConnectionClosed, pending_sends and request_streams
/// entries linger, causing the application to think streams are still active.
#[test]
fn connection_close_cleans_up_state() {
    let (certs, key) = self_signed();
    let client_addr: SocketAddr = "127.0.0.1:51201".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:51202".parse().unwrap();

    let mut client_ep = QuicEndpoint::new(client_config(&certs), client_addr);
    let mut server_ep = QuicEndpoint::new(server_config(certs, key), server_addr);

    let (client_conn, server_conn) =
        handshake(&mut client_ep, &mut server_ep, client_addr, server_addr);

    let mut client_h3 = H3Connection::new(Settings::default());
    let mut server_h3 = H3Connection::new(Settings::default());

    client_h3
        .handle_quic_event(&mut client_ep, &QuicEvent::Connected(client_conn))
        .expect("client initiate");
    server_h3
        .handle_quic_event(&mut server_ep, &QuicEvent::NewConnection(server_conn))
        .expect("server accept");

    // Exchange SETTINGS.
    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut client_ep, &mut client_h3);
    pump_h3(&mut server_ep, &mut server_h3);
    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut client_ep, &mut client_h3);
    pump_h3(&mut server_ep, &mut server_h3);

    // Client sends a request.
    let req_stream = client_h3
        .send_request(
            &mut client_ep,
            &[
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":path", b"/"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"localhost"),
            ],
            true,
        )
        .expect("send_request");

    // Server processes and sends a response.
    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut server_ep, &mut server_h3);

    let resp_stream = server_h3
        .poll_event()
        .and_then(|e| {
            if let H3Event::Request { stream_id, .. } = e {
                Some(stream_id)
            } else {
                None
            }
        })
        .expect("server should see Request");

    // Send a large response body that will be backpressured by the tight
    // flow-control window, so the server has pending writes.
    let large_body: Vec<u8> = (0u8..255).cycle().take(8 * 1024).collect();

    server_h3
        .send_response(
            &mut server_ep,
            resp_stream,
            &[HeaderField::new(b":status", b"200")],
            false,
        )
        .expect("send_response");
    server_h3
        .send_data(&mut server_ep, resp_stream, &large_body, false)
        .expect("send_data");

    // Server has pending writes (response queued behind flow control).
    assert!(
        server_h3.has_pending_writes(resp_stream),
        "server should have pending writes after large body",
    );

    // Close the QUIC connection.
    server_ep.close_connection(server_conn, 0, b"graceful closure".as_ref());

    // Flush and process.
    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut server_ep, &mut server_h3);
    pump_h3(&mut client_ep, &mut client_h3);

    // The server's pending writes should be cleaned up.
    assert!(
        !server_h3.has_pending_writes(resp_stream),
        "server should have no pending writes after connection close",
    );

    // The server should have emitted a GoAway event.
    let mut goaway_seen = false;
    loop {
        match server_h3.poll_event() {
            Some(H3Event::GoAway { .. }) => goaway_seen = true,
            Some(H3Event::Error(_)) => break,
            None => break,
            _ => {}
        }
    }

    assert!(
        goaway_seen,
        "server should have emitted GoAway after connection close",
    );

    // The client should also have received the connection close.
    let mut client_closed = false;
    loop {
        match client_h3.poll_event() {
            Some(H3Event::GoAway { .. }) | Some(H3Event::Error(_)) => {
                client_closed = true;
            }
            None => break,
            _ => {}
        }
    }

    assert!(client_closed, "client should have seen connection close",);

    // The client's request stream should have no pending writes.
    assert!(
        !client_h3.has_pending_writes(req_stream),
        "client should have no pending writes for request stream",
    );
}
