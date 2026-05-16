//! Tests for per-stream state cleanup.
//!
//! Regression tests for state that lingered in `H3Connection.request_streams`
//! / `pending_sends` when a stream finished, was reset, or was stopped by the
//! peer. Before these fixes the maps grew without bound on long-lived
//! connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use quinn_proto::{ClientConfig, ServerConfig, TransportConfig, VarInt};
use ringline_h3::error::H3Error;
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

/// Drain anything h3 already has queued.
fn drain_h3(h3: &mut H3Connection) -> Vec<H3Event> {
    let mut events = Vec::new();
    while let Some(ev) = h3.poll_event() {
        events.push(ev);
    }
    events
}

/// Set up a connected pair (handshake done, SETTINGS exchanged).
fn connected_pair() -> (
    QuicEndpoint,
    QuicEndpoint,
    QuicConnId,
    QuicConnId,
    H3Connection,
    H3Connection,
    SocketAddr,
    SocketAddr,
    u16,
) {
    static PORT_OFFSET: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let port = 52000 + PORT_OFFSET.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    let (certs, key) = self_signed();
    let client_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let server_addr: SocketAddr = format!("127.0.0.1:{}", port + 1).parse().unwrap();

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
    for _ in 0..3 {
        shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
        pump_h3(&mut client_ep, &mut client_h3);
        pump_h3(&mut server_ep, &mut server_h3);
    }
    // Drop the SETTINGS events the application would otherwise see.
    drain_h3(&mut client_h3);
    drain_h3(&mut server_h3);

    (
        client_ep,
        server_ep,
        client_conn,
        server_conn,
        client_h3,
        server_h3,
        client_addr,
        server_addr,
        port,
    )
}

/// After a complete GET round trip (request + FIN, response + FIN), neither
/// side should be tracking per-stream state.
#[test]
fn request_streams_cleaned_up_after_round_trip() {
    let (
        mut client_ep,
        mut server_ep,
        _client_conn,
        _server_conn,
        mut client_h3,
        mut server_h3,
        client_addr,
        server_addr,
        _port,
    ) = connected_pair();

    let req_stream = client_h3
        .send_request(
            &mut client_ep,
            &[
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":path", b"/"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"localhost"),
            ],
            true, // end_stream
        )
        .expect("send_request");

    // Server picks up the request.
    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut server_ep, &mut server_h3);

    let resp_stream = drain_h3(&mut server_h3)
        .into_iter()
        .find_map(|e| match e {
            H3Event::Request { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .expect("server should see Request");

    server_h3
        .send_response(
            &mut server_ep,
            resp_stream,
            &[HeaderField::new(b":status", b"200")],
            true, // end_stream
        )
        .expect("send_response");

    // Drive both sides until everything quiesces.
    for _ in 0..32 {
        shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
        pump_h3(&mut client_ep, &mut client_h3);
        pump_h3(&mut server_ep, &mut server_h3);
        drain_h3(&mut client_h3);
        drain_h3(&mut server_h3);
        if !client_h3.has_request_stream(req_stream) && !server_h3.has_request_stream(resp_stream) {
            break;
        }
    }

    assert!(
        !client_h3.has_request_stream(req_stream),
        "client should drop request_streams entry after both directions FIN",
    );
    assert!(
        !server_h3.has_request_stream(resp_stream),
        "server should drop request_streams entry after both directions FIN",
    );
    assert_eq!(client_h3.tracked_stream_count(), 0);
    assert_eq!(server_h3.tracked_stream_count(), 0);
}

/// When the peer sends STOP_SENDING on a stream we have queued bytes for,
/// `pending_sends` and `request_streams` for that stream must drop and an
/// `H3Event::StreamReset` must surface.
#[test]
fn stop_sending_drops_pending_state_and_emits_event() {
    let (
        mut client_ep,
        mut server_ep,
        client_conn,
        _server_conn,
        mut client_h3,
        mut server_h3,
        client_addr,
        server_addr,
        _port,
    ) = connected_pair();

    // Client opens a request.
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

    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut server_ep, &mut server_h3);

    let resp_stream = drain_h3(&mut server_h3)
        .into_iter()
        .find_map(|e| match e {
            H3Event::Request { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .expect("server should see Request");

    // Server starts streaming a large body (no FIN yet) — backed up behind
    // the default flow-control window so some chunks sit in pending_sends.
    let body: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
    server_h3
        .send_response(
            &mut server_ep,
            resp_stream,
            &[HeaderField::new(b":status", b"200")],
            false,
        )
        .expect("send_response");
    server_h3
        .send_data(&mut server_ep, resp_stream, &body, false)
        .expect("send_data");

    assert!(
        server_h3.has_pending_writes(resp_stream) || server_h3.has_request_stream(resp_stream),
        "server should have either queued bytes or stream tracking",
    );
    assert!(
        server_h3.has_request_stream(resp_stream),
        "server should still be tracking the request",
    );

    // Client decides it doesn't want the response — STOP_SENDING on its
    // recv half tells the server-side send half to stop. The stream id is
    // the same on both sides (it's bidirectional).
    client_ep
        .stop_sending(client_conn, req_stream, VarInt::from_u32(0))
        .expect("stop_sending");

    // Pump until the server sees the STOP_SENDING event.
    let mut saw_reset = false;
    for _ in 0..32 {
        shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
        pump_h3(&mut server_ep, &mut server_h3);
        for ev in drain_h3(&mut server_h3) {
            if matches!(ev, H3Event::StreamReset { .. }) {
                saw_reset = true;
            }
        }
        pump_h3(&mut client_ep, &mut client_h3);
        drain_h3(&mut client_h3);
        if saw_reset && !server_h3.has_request_stream(resp_stream) {
            break;
        }
    }

    assert!(saw_reset, "server should emit H3Event::StreamReset");
    assert!(
        !server_h3.has_pending_writes(resp_stream),
        "server pending_sends should be dropped after STOP_SENDING",
    );
    assert!(
        !server_h3.has_request_stream(resp_stream),
        "server request_streams should be dropped after STOP_SENDING",
    );
}

/// When the peer resets a stream we're reading from, the application must
/// receive an `H3Event::StreamReset` and our per-stream state must drop.
#[test]
fn peer_reset_drops_stream_state_and_emits_event() {
    let (
        mut client_ep,
        mut server_ep,
        client_conn,
        _server_conn,
        mut client_h3,
        mut server_h3,
        client_addr,
        server_addr,
        _port,
    ) = connected_pair();

    // Client opens a POST with body (no FIN yet) and starts streaming.
    let req_stream = client_h3
        .send_request(
            &mut client_ep,
            &[
                HeaderField::new(b":method", b"POST"),
                HeaderField::new(b":path", b"/echo"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"localhost"),
            ],
            false,
        )
        .expect("send_request");

    client_h3
        .send_data(&mut client_ep, req_stream, b"some body bytes", false)
        .expect("send_data");

    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut server_ep, &mut server_h3);
    let _req_event = drain_h3(&mut server_h3);

    // Client decides to give up — resets the request stream.
    client_ep
        .reset_stream(client_conn, req_stream, VarInt::from_u32(42))
        .expect("reset_stream");

    // Pump until the server sees the RESET_STREAM event.
    let mut saw_reset_code = None;
    for _ in 0..32 {
        shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
        pump_h3(&mut server_ep, &mut server_h3);
        for ev in drain_h3(&mut server_h3) {
            if let H3Event::StreamReset { error_code, .. } = ev {
                saw_reset_code = Some(error_code);
            }
        }
        pump_h3(&mut client_ep, &mut client_h3);
        drain_h3(&mut client_h3);
        // Server's stream tracking should drop once it processes the reset.
        if saw_reset_code.is_some() {
            break;
        }
    }

    assert_eq!(
        saw_reset_code,
        Some(42),
        "server should emit H3Event::StreamReset with the peer's error code",
    );
    // After the reset the server's per-stream tracking should be back to zero.
    assert_eq!(
        server_h3.tracked_stream_count(),
        0,
        "server should drop request_streams entry after RESET_STREAM",
    );
}

/// After the connection enters Closing (peer GOAWAY) or Closed (we closed),
/// `send_request` must refuse new requests rather than opening a stream the
/// peer would just reset.
#[test]
fn send_request_after_goaway_errors() {
    let (
        mut client_ep,
        mut server_ep,
        _client_conn,
        server_conn,
        mut client_h3,
        mut server_h3,
        client_addr,
        server_addr,
        _port,
    ) = connected_pair();

    // Server sends GOAWAY (stream id 4 — the next-expected client stream).
    server_h3
        .send_goaway(&mut server_ep, 4)
        .expect("send_goaway");

    // Push the GOAWAY through and let the client process it.
    for _ in 0..8 {
        shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
        pump_h3(&mut client_ep, &mut client_h3);
    }
    // Drain the GoAway event so we can observe the state change cleanly.
    let saw_goaway = drain_h3(&mut client_h3)
        .into_iter()
        .any(|e| matches!(e, H3Event::GoAway { .. }));
    assert!(saw_goaway, "client should see GoAway from server");

    let err = client_h3
        .send_request(
            &mut client_ep,
            &[
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":path", b"/late"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"localhost"),
            ],
            true,
        )
        .expect_err("send_request after GOAWAY must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("shutting down"),
        "expected shutdown error, got {msg:?}",
    );

    // Reference unused server connection to silence warning.
    let _ = server_conn;
}

/// Feeding a synthetic `ZeroRttRejected` event must clear per-stream state
/// and produce an `H3Event::ZeroRttRejected` so the app knows to re-issue.
#[test]
fn zero_rtt_rejected_clears_state_and_emits_event() {
    let (
        mut client_ep,
        _server_ep,
        client_conn,
        _server_conn,
        mut client_h3,
        _server_h3,
        _client_addr,
        _server_addr,
        _port,
    ) = connected_pair();

    // Open a request stream so there is per-stream state to discard.
    let _req_stream = client_h3
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
    assert!(client_h3.tracked_stream_count() > 0);

    // Synthesise a ZeroRttRejected event. (The QUIC layer's real
    // emission path is exercised in zero_rtt_rejected_event_fires_when_*
    // in ringline-quic; here we only need to verify the H3 handler.)
    client_h3
        .handle_quic_event(
            &mut client_ep,
            &QuicEvent::ZeroRttRejected { conn: client_conn },
        )
        .expect("handle ZeroRttRejected");

    assert_eq!(
        client_h3.tracked_stream_count(),
        0,
        "request_streams should be cleared after ZeroRttRejected",
    );
    let saw_event = drain_h3(&mut client_h3)
        .into_iter()
        .any(|e| matches!(e, H3Event::ZeroRttRejected));
    assert!(saw_event, "client should emit H3Event::ZeroRttRejected");
}

/// `set_max_pending_bytes` should cause `send_data` to fail when the queued
/// bytes would otherwise grow without bound.
#[test]
fn pending_bytes_cap_returns_backpressure_exceeded() {
    let (
        mut client_ep,
        _server_ep,
        _client_conn,
        _server_conn,
        mut client_h3,
        _server_h3,
        _client_addr,
        _server_addr,
        _port,
    ) = connected_pair();

    // Cap the connection at 4 KiB of pending bytes.
    client_h3.set_max_pending_bytes(4 * 1024);

    let req_stream = client_h3
        .send_request(
            &mut client_ep,
            &[
                HeaderField::new(b":method", b"POST"),
                HeaderField::new(b":path", b"/upload"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"localhost"),
            ],
            false,
        )
        .expect("send_request");

    // Without ferrying bytes to the server, sending a 32 KiB body will
    // accumulate in `pending_sends` and immediately blow past the cap.
    let body = vec![0u8; 32 * 1024];
    let err = client_h3
        .send_data(&mut client_ep, req_stream, &body, false)
        .expect_err("send_data should fail past cap");
    assert!(
        matches!(err, H3Error::BackpressureExceeded),
        "expected BackpressureExceeded, got {err:?}",
    );

    // `pending_bytes` reports what's actually queued.
    assert!(client_h3.pending_bytes() <= 4 * 1024);
}

/// Trailers (HEADERS frame following an initial HEADERS + DATA) surface as
/// a distinct `H3Event::Trailers` event with the same `stream_id`.
#[test]
fn trailers_emit_trailers_event() {
    let (
        mut client_ep,
        mut server_ep,
        _client_conn,
        _server_conn,
        mut client_h3,
        mut server_h3,
        client_addr,
        server_addr,
        _port,
    ) = connected_pair();

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

    shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
    pump_h3(&mut server_ep, &mut server_h3);
    let resp_stream = drain_h3(&mut server_h3)
        .into_iter()
        .find_map(|e| match e {
            H3Event::Request { stream_id, .. } => Some(stream_id),
            _ => None,
        })
        .expect("server sees Request");

    // Server: initial response HEADERS, a small DATA, then trailers.
    server_h3
        .send_response(
            &mut server_ep,
            resp_stream,
            &[HeaderField::new(b":status", b"200")],
            false,
        )
        .expect("send_response");
    server_h3
        .send_data(&mut server_ep, resp_stream, b"body", false)
        .expect("send_data");
    server_h3
        .send_trailers(
            &mut server_ep,
            resp_stream,
            &[HeaderField::new(b"x-trailer", b"v")],
        )
        .expect("send_trailers");

    // Drive both sides until the client has seen the trailers.
    let mut saw_response = false;
    let mut saw_trailers = false;
    for _ in 0..32 {
        shuffle(&mut client_ep, &mut server_ep, client_addr, server_addr);
        pump_h3(&mut client_ep, &mut client_h3);
        pump_h3(&mut server_ep, &mut server_h3);
        for ev in drain_h3(&mut client_h3) {
            match ev {
                H3Event::Response { .. } => saw_response = true,
                H3Event::Trailers { stream_id, headers } => {
                    assert_eq!(stream_id, req_stream);
                    assert_eq!(headers.len(), 1);
                    assert_eq!(headers[0].name, b"x-trailer");
                    saw_trailers = true;
                }
                _ => {}
            }
        }
        if saw_trailers {
            break;
        }
    }
    assert!(saw_response, "client should see Response");
    assert!(saw_trailers, "client should see Trailers");
}

/// `send_request` rejects a header section larger than the peer's
/// advertised `SETTINGS_MAX_FIELD_SECTION_SIZE`.
#[test]
fn send_request_rejects_oversize_headers_per_peer_settings() {
    let (
        mut client_ep,
        mut server_ep,
        _client_conn,
        _server_conn,
        mut client_h3,
        mut server_h3,
        client_addr,
        server_addr,
        _port,
    ) = connected_pair();

    // Discover what the server advertised — `connected_pair` already pumped
    // SETTINGS across, so the client should know the server's value.
    // Default is 256 KiB. Construct headers larger than that.
    let huge_value = vec![b'a'; 300 * 1024];
    let headers = vec![
        HeaderField::new(b":method", b"GET"),
        HeaderField::new(b":path", b"/"),
        HeaderField::new(b":scheme", b"https"),
        HeaderField::new(b":authority", b"localhost"),
        HeaderField::new(b"x-huge", huge_value.as_slice()),
    ];

    let err = client_h3
        .send_request(&mut client_ep, &headers, true)
        .expect_err("expected ExcessiveSize from oversize headers");
    assert!(matches!(err, H3Error::ExcessiveSize));

    // Reference the server endpoint/h3 so they don't get warnings as unused.
    let _ = (&mut server_ep, &mut server_h3, client_addr, server_addr);
}
