//! Flow-control backpressure test for [`H3Connection::send_data`].
//!
//! Regression against the silent-data-loss bug where `send_data` ignored
//! partial writes from quinn-proto. We shrink the client's per-stream
//! receive window far below the response body size, force the server to
//! write in chunks across many `StreamWritable` events, and assert the
//! client ultimately receives every byte.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use quinn_proto::{ClientConfig, ServerConfig, TransportConfig};
use ringline_h3::{H3Connection, H3Event, HeaderField, Settings};
use ringline_quic::{QuicConfig, QuicConnId, QuicEndpoint, QuicEvent, StreamId};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![CertificateDer::from(cert.cert)], key.into())
}

/// Server with permissive receive windows — we're not testing client→server.
fn server_config(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> QuicConfig {
    let mut sc = ServerConfig::with_single_cert(certs, key).unwrap();
    let transport = Arc::get_mut(&mut sc.transport).unwrap();
    transport.max_concurrent_bidi_streams(16u32.into());
    transport.max_concurrent_uni_streams(16u32.into());
    QuicConfig::server(Arc::new(sc))
}

/// Client with a *tight* per-stream receive window. The server, when sending
/// a response body larger than this window, will hit `WriteError::Blocked`
/// and exercise the queue-and-drain path we're regression-testing.
fn client_config(certs: &[CertificateDer<'static>], stream_window: u64) -> QuicConfig {
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
    transport.stream_receive_window(stream_window.try_into().unwrap());
    transport.receive_window((stream_window * 4).try_into().unwrap());
    transport.max_concurrent_bidi_streams(16u32.into());
    transport.max_concurrent_uni_streams(16u32.into());
    cc.transport_config(Arc::new(transport));
    QuicConfig::client(cc)
}

/// Pump packets between two endpoints until neither has anything queued.
/// Repeatedly flushes, swaps datagrams, drives timers. Bounded so a bug that
/// loses progress hangs the test rather than the runner.
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
        while let Some((_, data)) = client.poll_send() {
            server.handle_datagram(now, &data, client_addr);
            moved = true;
        }
        while let Some((_, data)) = server.poll_send() {
            client.handle_datagram(now, &data, server_addr);
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

/// Feed every queued QUIC event on `ep` into `h3` and clear the QUIC event
/// queue. Pending H3 events stay on the H3 connection for the caller to
/// drain.
fn pump_h3(ep: &mut QuicEndpoint, h3: &mut H3Connection) {
    let mut events = Vec::new();
    while let Some(ev) = ep.poll_event() {
        events.push(ev);
    }
    for ev in events {
        h3.handle_quic_event(ep, &ev).expect("h3 event");
    }
}

#[test]
fn send_data_is_resilient_to_flow_control_backpressure() {
    let (certs, key) = self_signed();
    let client_addr: SocketAddr = "127.0.0.1:50001".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:50002".parse().unwrap();

    // Client's per-stream receive window — the ceiling the server must write
    // under. Deliberately far smaller than the response body so the server
    // blocks several times over.
    const STREAM_WINDOW: u64 = 4 * 1024;
    // Response body: large enough to guarantee multiple write/block cycles.
    const BODY_LEN: usize = 128 * 1024;

    let mut client_ep = QuicEndpoint::new(client_config(&certs, STREAM_WINDOW), client_addr);
    let mut server_ep = QuicEndpoint::new(server_config(certs, key), server_addr);

    let (client_conn, server_conn) =
        handshake(&mut client_ep, &mut server_ep, client_addr, server_addr);

    let mut client_h3 = H3Connection::new(Settings::default());
    let mut server_h3 = H3Connection::new(Settings::default());

    // Hand each H3 its QUIC connection by synthesising the handshake events
    // that `handshake()` already drained.
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
                HeaderField {
                    name: b":method".to_vec(),
                    value: b"GET".to_vec(),
                },
                HeaderField {
                    name: b":path".to_vec(),
                    value: b"/big".to_vec(),
                },
                HeaderField {
                    name: b":scheme".to_vec(),
                    value: b"https".to_vec(),
                },
                HeaderField {
                    name: b":authority".to_vec(),
                    value: b"localhost".to_vec(),
                },
            ],
            true,
        )
        .expect("send_request");
    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);

    // Server pumps events → observes the request → sends response + large body.
    pump_h3(&mut server_ep, &mut server_h3);
    let mut request_stream: Option<StreamId> = None;
    while let Some(ev) = server_h3.poll_event() {
        if let H3Event::Request { stream_id, .. } = ev {
            request_stream = Some(stream_id);
        }
    }
    let resp_stream = request_stream.expect("server never saw Request");
    assert_eq!(u64::from(resp_stream), u64::from(req_stream));

    server_h3
        .send_response(
            &mut server_ep,
            resp_stream,
            &[HeaderField {
                name: b":status".to_vec(),
                value: b"200".to_vec(),
            }],
            false,
        )
        .expect("send_response");

    let body: Vec<u8> = (0u8..=255).cycle().take(BODY_LEN).collect();
    server_h3
        .send_data(&mut server_ep, resp_stream, &body, true)
        .expect("send_data");

    // The first send couldn't possibly have flushed the whole 128 KB body
    // through a 4 KB window. If queue_send is working, this is true.
    assert!(
        server_h3.has_pending_writes(resp_stream),
        "expected backpressure on 128 KB body through 4 KB window",
    );

    // Drive the endpoints until the server's pending queue drains.
    let mut received = Vec::new();
    let mut response_seen = false;
    let mut end_stream_seen = false;
    for _ in 0..256 {
        shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
        pump_h3(&mut server_ep, &mut server_h3);
        pump_h3(&mut client_ep, &mut client_h3);
        while let Some(ev) = client_h3.poll_event() {
            match ev {
                H3Event::Response { .. } => response_seen = true,
                H3Event::Data {
                    data, end_stream, ..
                } => {
                    received.extend_from_slice(&data);
                    if end_stream {
                        end_stream_seen = true;
                    }
                }
                H3Event::Error(e) => panic!("client H3 error: {e:?}"),
                _ => {}
            }
        }
        if end_stream_seen && !server_h3.has_pending_writes(resp_stream) {
            break;
        }
    }

    assert!(response_seen, "client never saw response headers");
    assert!(end_stream_seen, "client never saw end-of-stream");
    assert!(
        !server_h3.has_pending_writes(resp_stream),
        "server still has pending writes after drain",
    );
    assert_eq!(received.len(), body.len(), "body length mismatch");
    assert_eq!(received, body, "body payload mismatch");
}
