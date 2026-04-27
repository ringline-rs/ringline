//! Peer-to-peer integration tests for `QuicEndpoint`.
//!
//! Drives two `QuicEndpoint`s in-process by ferrying packets between them
//! manually. No real UDP socket is involved — this isolates the
//! `QuicEndpoint` API from the runtime so we can hammer the state-machine
//! glue (event ordering, drain logic, close paths) without needing a
//! kernel socket or an async runtime.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn_proto::{ClientConfig, ServerConfig};
use ringline_quic::{QuicConfig, QuicConnId, QuicEndpoint, QuicEvent};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

// ── Common helpers ─────────────────────────────────────────────────────

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

/// Drive both endpoints to a stable state by ferrying any pending packets
/// across, draining timers, and emitting events. Loops until one full
/// pass produces no movement, or until `cap` iterations have run.
fn drain(client: &mut QuicEndpoint, server: &mut QuicEndpoint, ca: SocketAddr, sa: SocketAddr) {
    let now = Instant::now();
    for _ in 0..64 {
        let mut moved = false;
        while let Some((_dest, data)) = client.poll_send() {
            server.handle_datagram(now, &data, ca);
            moved = true;
        }
        while let Some((_dest, data)) = server.poll_send() {
            client.handle_datagram(now, &data, sa);
            moved = true;
        }
        client.drive_timers(now);
        server.drive_timers(now);
        if !moved {
            break;
        }
    }
}

/// Drive both endpoints until either `pred` reports done or we run out of
/// iterations. Useful when you need to wait for a specific event or for an
/// in-flight write to fully ACK.
fn drain_until(
    client: &mut QuicEndpoint,
    server: &mut QuicEndpoint,
    ca: SocketAddr,
    sa: SocketAddr,
    mut pred: impl FnMut(&mut QuicEndpoint, &mut QuicEndpoint) -> bool,
    max_iters: usize,
) -> bool {
    for _ in 0..max_iters {
        drain(client, server, ca, sa);
        if pred(client, server) {
            return true;
        }
        // Advance time slightly so timers can fire.
        std::thread::sleep(Duration::from_millis(2));
    }
    false
}

fn handshake(
    client: &mut QuicEndpoint,
    server: &mut QuicEndpoint,
    ca: SocketAddr,
    sa: SocketAddr,
) -> (QuicConnId, QuicConnId) {
    let client_conn = client
        .connect(Instant::now(), sa, "localhost")
        .expect("connect");

    let mut server_conn = None;
    let mut client_connected = false;
    drain_until(
        client,
        server,
        ca,
        sa,
        |c, s| {
            while let Some(ev) = s.poll_event() {
                if let QuicEvent::NewConnection(id) = ev {
                    server_conn = Some(id);
                }
            }
            while let Some(ev) = c.poll_event() {
                if let QuicEvent::Connected(_) = ev {
                    client_connected = true;
                }
            }
            server_conn.is_some() && client_connected
        },
        32,
    );

    (
        client_conn,
        server_conn.expect("server never emitted NewConnection"),
    )
}

fn make_pair() -> (
    QuicEndpoint,
    QuicEndpoint,
    SocketAddr,
    SocketAddr,
    Vec<CertificateDer<'static>>,
) {
    let (certs, key) = self_signed();
    let ca: SocketAddr = "127.0.0.1:50001".parse().unwrap();
    let sa: SocketAddr = "127.0.0.1:50002".parse().unwrap();
    let client = QuicEndpoint::new(client_config(&certs), ca);
    let server = QuicEndpoint::new(server_config(certs.clone(), key), sa);
    (client, server, ca, sa, certs)
}

/// Read every byte the peer is willing to send on `stream`, ferrying
/// packets back and forth until the FIN arrives or `cap` rounds elapse.
/// Returns the accumulated bytes plus whether FIN was observed.
fn read_until_fin(
    rx_endpoint: &mut QuicEndpoint,
    tx_endpoint: &mut QuicEndpoint,
    rx_addr: SocketAddr,
    tx_addr: SocketAddr,
    rx_conn: QuicConnId,
    stream: quinn_proto::StreamId,
    expected_len: usize,
) -> (Vec<u8>, bool) {
    let mut acc = Vec::with_capacity(expected_len);
    let mut buf = vec![0u8; 16 * 1024];
    let mut fin = false;
    for _ in 0..64 {
        // Process outstanding events from the rx side first so any
        // synthesised StreamReadable lands.
        while let Some(_ev) = rx_endpoint.poll_event() {}
        loop {
            match rx_endpoint.stream_recv(rx_conn, stream, &mut buf) {
                Ok((0, true)) => {
                    fin = true;
                    break;
                }
                Ok((0, false)) => break,
                Ok((n, more_fin)) => {
                    acc.extend_from_slice(&buf[..n]);
                    if more_fin {
                        fin = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if fin && acc.len() >= expected_len {
            break;
        }
        // Need more data — let the wire deliver it.
        rx_endpoint.flush(Instant::now());
        drain(tx_endpoint, rx_endpoint, tx_addr, rx_addr);
    }
    (acc, fin)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[test]
fn handshake_then_echo_one_message() {
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);
    assert_eq!(server.connection_count(), 1);
    assert_eq!(client.connection_count(), 1);

    let stream = client.open_bi(cc).unwrap().unwrap();
    let n = client.stream_send(cc, stream, b"ping").unwrap();
    assert_eq!(n, 4);
    client.flush(Instant::now());

    drain(&mut client, &mut server, ca, sa);

    // Server: drain events, find the new stream id (peer-initiated).
    let mut server_stream = None;
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::StreamOpened { stream, .. } = ev {
            server_stream = Some(stream);
        }
    }
    let server_stream = server_stream.expect("server didn't see StreamOpened");
    assert_eq!(
        server_stream, stream,
        "stream ids should match across peers"
    );

    let (data, _fin) = read_until_fin(&mut server, &mut client, sa, ca, sc, server_stream, 4);
    assert_eq!(&data, b"ping");

    // Echo back.
    server.stream_send(sc, server_stream, b"pong").unwrap();
    server.stream_finish(sc, server_stream).unwrap();
    server.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    let (resp, fin) = read_until_fin(&mut client, &mut server, ca, sa, cc, stream, 4);
    assert_eq!(&resp, b"pong");
    assert!(fin, "client should observe FIN");
}

#[test]
fn unidirectional_stream_round_trip() {
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    let stream = client
        .open_uni(cc)
        .expect("open_uni call ok")
        .expect("stream limit");
    client.stream_send(cc, stream, b"unidi").unwrap();
    client.stream_finish(cc, stream).unwrap();
    client.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    let mut server_stream = None;
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::StreamOpened { stream, bidi, .. } = ev {
            assert!(!bidi, "expected unidirectional");
            server_stream = Some(stream);
        }
    }
    let s = server_stream.expect("server did not observe StreamOpened");
    let (data, fin) = read_until_fin(&mut server, &mut client, sa, ca, sc, s, 5);
    assert_eq!(&data, b"unidi");
    assert!(fin, "server should observe FIN on unidirectional stream");
}

#[test]
fn close_connection_drains_close_packet_without_explicit_flush() {
    // `close_connection` should leave the CONNECTION_CLOSE packet ready in
    // the send queue without the caller having to call `flush` afterward —
    // otherwise it's a silent footgun where a user who forgets to flush
    // never tells the peer that the connection went away.
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (_cc, sc) = handshake(&mut client, &mut server, ca, sa);

    let pre = server.send_queue_len();
    server.close_connection(sc, 0x42, b"bye");
    let post = server.send_queue_len();
    assert!(
        post > pre,
        "close_connection must enqueue the CONNECTION_CLOSE packet \
         (pre={pre} post={post})"
    );
}

#[test]
fn close_connection_delivers_event_to_peer() {
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    server.close_connection(sc, 0x42, b"bye");
    server.flush(Instant::now());

    let mut client_close = None;
    drain_until(
        &mut client,
        &mut server,
        ca,
        sa,
        |c, _| {
            while let Some(ev) = c.poll_event() {
                if let QuicEvent::ConnectionClosed { .. } = ev {
                    client_close = Some(true);
                }
            }
            client_close.is_some()
        },
        32,
    );
    assert!(
        client_close.is_some(),
        "client should observe ConnectionClosed after server.close_connection"
    );

    // After the close round-trips, the client connection should eventually
    // disappear from the slab (drained).
    drain_until(
        &mut client,
        &mut server,
        ca,
        sa,
        |c, _| !c.remote_addr(cc).map(|_| true).unwrap_or(false),
        32,
    );
}

#[test]
fn stream_send_chunks_writes_all_bytes() {
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    let stream = client.open_bi(cc).unwrap().unwrap();

    let mut chunks = vec![
        Bytes::from_static(b"alpha"),
        Bytes::from_static(b"-"),
        Bytes::from_static(b"beta"),
    ];
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    let n = client.stream_send_chunks(cc, stream, &mut chunks).unwrap();
    assert_eq!(n, total);
    client.stream_finish(cc, stream).unwrap();
    client.flush(Instant::now());

    drain(&mut client, &mut server, ca, sa);
    let mut server_stream = None;
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::StreamOpened { stream, .. } = ev {
            server_stream = Some(stream);
        }
    }
    let s = server_stream.expect("server should see the stream");
    let (data, _fin) = read_until_fin(&mut server, &mut client, sa, ca, sc, s, total);
    assert_eq!(&data, b"alpha-beta");
}

#[test]
fn many_concurrent_bidi_streams_round_trip() {
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    // Open 16 bidirectional streams from the client. Each carries a
    // distinct payload that must round-trip independently.
    let mut client_streams: Vec<(quinn_proto::StreamId, Vec<u8>)> = Vec::new();
    for i in 0..16u8 {
        let stream = client
            .open_bi(cc)
            .expect("open_bi ok")
            .expect("stream limit");
        let payload = vec![i; 64];
        client.stream_send(cc, stream, &payload).unwrap();
        client.stream_finish(cc, stream).unwrap();
        client_streams.push((stream, payload));
    }
    client.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    // Server-side: collect all opened streams, read them, echo back.
    let mut server_streams = Vec::new();
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::StreamOpened { stream, .. } = ev {
            server_streams.push(stream);
        }
    }
    assert_eq!(
        server_streams.len(),
        client_streams.len(),
        "server should observe all StreamOpened events"
    );

    for s in &server_streams {
        let (data, fin) = read_until_fin(&mut server, &mut client, sa, ca, sc, *s, 64);
        assert_eq!(data.len(), 64);
        assert!(fin);
        // Echo the same payload back on the same bidi stream.
        server.stream_send(sc, *s, &data).unwrap();
        server.stream_finish(sc, *s).unwrap();
    }
    server.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    for (stream, expected) in &client_streams {
        let (data, fin) = read_until_fin(&mut client, &mut server, ca, sa, cc, *stream, 64);
        assert_eq!(&data, expected, "stream {stream} echo mismatch");
        assert!(fin);
    }
}

#[test]
fn closed_connection_id_returns_invalid() {
    // After a connection is fully drained from the slab, attempting to use
    // its `QuicConnId` should fail cleanly with `InvalidConnection` rather
    // than panic.
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    server.close_connection(sc, 0, b"goodbye");
    server.flush(Instant::now());

    // Drive until the client connection is purged from its slab.
    let mut purged = false;
    for _ in 0..32 {
        drain(&mut client, &mut server, ca, sa);
        while let Some(_ev) = client.poll_event() {}
        if client.remote_addr(cc).is_none() {
            purged = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(purged, "client connection should drain after close");

    // The conn id is now stale — operations must return InvalidConnection,
    // not panic. (`open_bi` is the most natural call to make on a stale id.)
    let err = client
        .open_bi(cc)
        .expect_err("stale conn id must be rejected");
    assert!(matches!(err, ringline_quic::Error::InvalidConnection));
}

#[test]
fn client_endpoint_without_client_config_cannot_connect() {
    let (certs, key) = self_signed();
    // Server-only config (no client_config set).
    let server_only = server_config(certs, key);
    let mut endpoint = QuicEndpoint::new(server_only, "127.0.0.1:60001".parse().unwrap());
    let res = endpoint.connect(
        Instant::now(),
        "127.0.0.1:60002".parse().unwrap(),
        "localhost",
    );
    assert!(
        res.is_err(),
        "connect on server-only endpoint must error, got {:?}",
        res.is_ok()
    );
}

#[test]
fn server_drops_incoming_when_no_server_config() {
    // Endpoint with neither client nor server config.
    let endpoint_cfg = QuicConfig {
        endpoint_config: Arc::new(quinn_proto::EndpointConfig::default()),
        server_config: None,
        client_config: None,
        send_queue_capacity: 4096,
        allow_mtud: false,
        rng_seed: None,
    };
    let mut server = QuicEndpoint::new(endpoint_cfg, "127.0.0.1:60100".parse().unwrap());

    // Build a separate client that *is* configured, and let it try to
    // initiate a handshake.
    let (certs, _key) = self_signed();
    let mut client = QuicEndpoint::new(client_config(&certs), "127.0.0.1:60101".parse().unwrap());
    let _ = client.connect(
        Instant::now(),
        "127.0.0.1:60100".parse().unwrap(),
        "localhost",
    );

    // Ferry the initial Initial packet to the server. Server has no
    // server_config so accept() fails — should not crash, should not yield
    // a NewConnection event.
    let now = Instant::now();
    while let Some((_dest, data)) = client.poll_send() {
        server.handle_datagram(now, &data, "127.0.0.1:60101".parse().unwrap());
    }

    // No NewConnection from server.
    let mut saw_new = false;
    while let Some(ev) = server.poll_event() {
        if matches!(ev, QuicEvent::NewConnection(_)) {
            saw_new = true;
        }
    }
    assert!(!saw_new, "server with no config must not accept");
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn idle_timeout_closes_connection() {
    // Configure short idle timeout via custom server transport.
    let (certs, key) = self_signed();
    let mut sc = ServerConfig::with_single_cert(certs.clone(), key).unwrap();
    let st = Arc::get_mut(&mut sc.transport).unwrap();
    st.max_concurrent_bidi_streams(64u32.into());
    st.max_idle_timeout(Some(Duration::from_millis(200).try_into().unwrap()));
    let mut server = QuicEndpoint::new(
        QuicConfig::server(Arc::new(sc)),
        "127.0.0.1:50901".parse().unwrap(),
    );

    let mut cc = ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from({
            let mut roots = rustls::RootCertStore::empty();
            for cert in &certs {
                roots.add(cert.clone()).unwrap();
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        })
        .unwrap(),
    ));
    let mut ct = quinn_proto::TransportConfig::default();
    ct.max_idle_timeout(Some(Duration::from_millis(200).try_into().unwrap()));
    cc.transport_config(Arc::new(ct));
    let mut client = QuicEndpoint::new(QuicConfig::client(cc), "127.0.0.1:50900".parse().unwrap());

    let ca: SocketAddr = "127.0.0.1:50900".parse().unwrap();
    let sa: SocketAddr = "127.0.0.1:50901".parse().unwrap();
    let (_cc_id, _sc_id) = handshake(&mut client, &mut server, ca, sa);
    assert_eq!(server.connection_count(), 1);

    // Don't ferry any packets for > idle timeout. Drive only timers.
    std::thread::sleep(Duration::from_millis(350));
    for _ in 0..16 {
        let now = Instant::now();
        client.drive_timers(now);
        server.drive_timers(now);
        std::thread::sleep(Duration::from_millis(20));
    }

    // At least one side should have produced a ConnectionClosed event and
    // pruned its connection slab.
    let mut closed = 0;
    while let Some(ev) = client.poll_event() {
        if let QuicEvent::ConnectionClosed { .. } = ev {
            closed += 1;
        }
    }
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::ConnectionClosed { .. } = ev {
            closed += 1;
        }
    }
    assert!(
        closed >= 1,
        "idle timeout should produce a ConnectionClosed event on at least one side"
    );
}

#[test]
fn large_payload_round_trip_via_endpoint_api() {
    // Pure-API stress test: 256 KiB through bidi stream, no socket.
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    let stream = client.open_bi(cc).unwrap().unwrap();
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i & 0xFF) as u8).collect();

    // Push in chunks, ferrying packets between writes so flow control opens.
    let mut written = 0;
    for _ in 0..1024 {
        let n = client.stream_send(cc, stream, &payload[written..]).unwrap();
        written += n;
        client.flush(Instant::now());
        drain(&mut client, &mut server, ca, sa);
        if written >= payload.len() {
            break;
        }
    }
    assert_eq!(written, payload.len(), "should have pushed full payload");
    client.stream_finish(cc, stream).unwrap();
    client.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    let mut server_stream = None;
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::StreamOpened { stream, .. } = ev {
            server_stream = Some(stream);
        }
    }
    let s = server_stream.expect("server should see StreamOpened");

    let (data, fin) = read_until_fin(&mut server, &mut client, sa, ca, sc, s, payload.len());
    assert!(fin, "server should observe FIN");
    assert_eq!(data.len(), payload.len(), "received length mismatch");
    assert_eq!(data, payload, "received payload mismatch");
}

#[test]
fn handshake_with_wrong_server_name_fails() {
    let (mut client, mut server, ca, sa, _) = make_pair();

    // Use a completely wrong server name. quinn will fail TLS server name
    // verification and the connection will close during handshake.
    let cc_id = client
        .connect(Instant::now(), sa, "not-the-cert.example")
        .expect("connect");

    let mut closed = false;
    drain_until(
        &mut client,
        &mut server,
        ca,
        sa,
        |c, _| {
            while let Some(ev) = c.poll_event() {
                if let QuicEvent::ConnectionClosed { .. } = ev {
                    closed = true;
                }
            }
            closed
        },
        16,
    );
    assert!(closed, "handshake with wrong SNI must close the connection");
    // Slab should have been freed.
    assert!(client.remote_addr(cc_id).is_none());
}

#[test]
fn flush_emits_packets_buffered_during_write() {
    // Regression-style test for `QuicEndpoint::flush`: data written via
    // stream_send should not stall in the connection until something else
    // (a timer firing, a peer datagram arriving) flushes it.
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    let stream = client.open_bi(cc).unwrap().unwrap();
    client.stream_send(cc, stream, b"flush-me").unwrap();

    // Without flush, poll_send may be empty even though we have data to
    // send. After flush(), at least one packet should be ready.
    let pre = client.send_queue_len();
    client.flush(Instant::now());
    let post = client.send_queue_len();
    assert!(
        post > pre,
        "flush should drain buffered transmits into the send queue (pre={pre} post={post})"
    );

    // Now ferry the packet to the server; server should see the stream and
    // the data without us having to advance time.
    drain(&mut client, &mut server, ca, sa);
    let mut server_stream = None;
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::StreamOpened { stream, .. } = ev {
            server_stream = Some(stream);
        }
    }
    let s = server_stream.expect("server should observe stream opened");
    let mut buf = [0u8; 32];
    let (n, _fin) = server.stream_recv(sc, s, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"flush-me");
}

// ── Stream stop / reset ────────────────────────────────────────────────

#[test]
fn peer_stop_sending_surfaces_streamstopped_event() {
    // Regression: previously `StreamEvent::Stopped` from quinn-proto was
    // swallowed inside `poll_connection`, so a sender whose peer issued
    // STOP_SENDING never got told. We now surface it as
    // `QuicEvent::StreamStopped`.
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    // Client opens a bidi stream and pushes one chunk.
    let stream = client.open_bi(cc).unwrap().unwrap();
    client.stream_send(cc, stream, b"hello").unwrap();
    client.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    // Server learns about the stream.
    let mut server_stream = None;
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::StreamOpened { stream, .. } = ev {
            server_stream = Some(stream);
        }
    }
    let s = server_stream.expect("server StreamOpened");

    // Server tells the client to stop sending.
    server
        .stop_sending(sc, s, quinn_proto::VarInt::from_u32(0x99))
        .unwrap();
    server.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    // Client should now see StreamStopped on `stream`.
    let mut got_stop = None;
    while let Some(ev) = client.poll_event() {
        if let QuicEvent::StreamStopped {
            stream: s2,
            error_code,
            ..
        } = ev
            && s2 == stream
        {
            got_stop = Some(error_code);
        }
    }
    let code = got_stop.expect(
        "client should receive StreamStopped after server's stop_sending — \
         silent loss here means the bug regressed",
    );
    assert_eq!(code, quinn_proto::VarInt::from_u32(0x99));
}

#[test]
fn reset_stream_surfaces_read_error_to_peer() {
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    let stream = client.open_bi(cc).unwrap().unwrap();
    client.stream_send(cc, stream, b"about-to-reset").unwrap();
    client.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    // Server learns about the stream and reads the data.
    let mut server_stream = None;
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::StreamOpened { stream, .. } = ev {
            server_stream = Some(stream);
        }
    }
    let s = server_stream.expect("server StreamOpened");
    let mut buf = [0u8; 64];
    let _ = server.stream_recv(sc, s, &mut buf).unwrap();

    // Client resets the send side.
    client
        .reset_stream(cc, stream, quinn_proto::VarInt::from_u32(0x42))
        .unwrap();
    client.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    // Server's next stream_recv on this stream must return an error
    // (specifically, a `ReadError::Reset`).
    match server.stream_recv(sc, s, &mut buf) {
        Ok(_) => panic!("expected an error after peer reset, got Ok"),
        Err(ringline_quic::Error::Read(quinn_proto::ReadError::Reset(code))) => {
            assert_eq!(code, quinn_proto::VarInt::from_u32(0x42));
        }
        Err(other) => panic!("expected ReadError::Reset, got {other:?}"),
    }
}

// ── send_queue_capacity drop behavior ─────────────────────────────────

#[test]
fn send_queue_capacity_caps_queued_packets() {
    // Configure a tiny send_queue_capacity so we can verify excess
    // outbound packets are dropped (quinn handles retransmission, so
    // dropping is acceptable — but the cap must actually be enforced
    // and the connection must not corrupt itself).
    let (certs, key) = self_signed();

    let mut client_cfg = client_config(&certs);
    client_cfg.send_queue_capacity = 4;
    let mut server_cfg = server_config(certs, key);
    server_cfg.send_queue_capacity = 4;

    let ca: SocketAddr = "127.0.0.1:51000".parse().unwrap();
    let sa: SocketAddr = "127.0.0.1:51001".parse().unwrap();
    let mut client = QuicEndpoint::new(client_cfg, ca);
    let mut server = QuicEndpoint::new(server_cfg, sa);

    let (cc, _sc) = handshake(&mut client, &mut server, ca, sa);

    // Push a lot of stream data without ferrying anything to the server.
    // The connection's outgoing transmits should grow into the queue
    // and be capped.
    let stream = client.open_bi(cc).unwrap().unwrap();
    let payload = vec![0u8; 16 * 1024];
    let _ = client.stream_send(cc, stream, &payload);
    client.flush(Instant::now());

    let qlen = client.send_queue_len();
    assert!(
        qlen <= 4,
        "send_queue must respect cap of 4; got {qlen} queued packets"
    );

    // Sanity: connection still works after dropping packets — drain
    // and ensure the next round of queueing still proceeds.
    let _ = client.send_queue_len();
    drain(&mut client, &mut server, ca, sa);
    // No assertion on bytes received: dropping is allowed under cap.
    // Just verify no panic, no inconsistent state.
}

// ── StreamsAvailable event ─────────────────────────────────────────────

fn server_config_with_stream_limits(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    bidi: u32,
    uni: u32,
) -> QuicConfig {
    let mut sc = ServerConfig::with_single_cert(certs, key).unwrap();
    let transport = Arc::get_mut(&mut sc.transport).unwrap();
    transport.max_concurrent_bidi_streams(bidi.into());
    transport.max_concurrent_uni_streams(uni.into());
    QuicConfig::server(Arc::new(sc))
}

#[test]
fn streams_available_fires_when_peer_raises_limit() {
    // Quinn fires `StreamEvent::Available` when the peer increases the
    // stream limit. We surface it as `QuicEvent::StreamsAvailable` so
    // applications that hit `Ok(None)` from `open_bi` can resume work
    // on an event instead of polling.
    let (certs, key) = self_signed();
    let ca: SocketAddr = "127.0.0.1:51200".parse().unwrap();
    let sa: SocketAddr = "127.0.0.1:51201".parse().unwrap();

    // Server allows 2 bidi streams initially; the client will see this
    // as its open_bi limit.
    let mut client = QuicEndpoint::new(client_config(&certs), ca);
    let mut server = QuicEndpoint::new(server_config_with_stream_limits(certs, key, 2, 64), sa);
    let (cc, sc) = handshake(&mut client, &mut server, ca, sa);

    // Open the two streams the server allows. Send a small payload on
    // each + finish so the streams reach the FullyClosed state once
    // the server peer-finishes; quinn won't increment the credit (and
    // therefore won't send MAX_STREAMS) for streams that never carried
    // application bytes.
    let s1 = client.open_bi(cc).unwrap().expect("first stream");
    let s2 = client.open_bi(cc).unwrap().expect("second stream");
    client.stream_send(cc, s1, b"a").unwrap();
    client.stream_send(cc, s2, b"b").unwrap();
    client.stream_finish(cc, s1).unwrap();
    client.stream_finish(cc, s2).unwrap();
    // Third must hit the limit.
    assert!(
        client.open_bi(cc).unwrap().is_none(),
        "expected to hit the stream limit at 2 concurrent bidi streams"
    );
    client.flush(Instant::now());
    drain(&mut client, &mut server, ca, sa);

    // Server: read both streams to FIN, then finish their send side.
    let mut server_streams = Vec::new();
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::StreamOpened { stream, .. } = ev {
            server_streams.push(stream);
        }
    }
    assert_eq!(
        server_streams.len(),
        2,
        "server should observe both streams"
    );
    let mut buf = [0u8; 16];
    for s in &server_streams {
        // Read until FIN; server.stream_recv returns (n, true) once the
        // FIN flag arrives.
        for _ in 0..8 {
            match server.stream_recv(sc, *s, &mut buf) {
                Ok((_, true)) => break,
                Ok((_, false)) => {
                    drain(&mut client, &mut server, ca, sa);
                }
                Err(_) => break,
            }
        }
        let _ = server.stream_finish(sc, *s);
    }
    server.flush(Instant::now());

    // Drive enough rounds for the FINs to ACK and the server to issue
    // MAX_STREAMS.
    let mut got_avail = false;
    for _ in 0..32 {
        drain(&mut client, &mut server, ca, sa);
        while let Some(ev) = client.poll_event() {
            if let QuicEvent::StreamsAvailable { dir, .. } = ev
                && dir == quinn_proto::Dir::Bi
            {
                got_avail = true;
            }
        }
        if got_avail {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        got_avail,
        "client should see StreamsAvailable(Bi) after server frees stream slots"
    );

    // Sanity: open should now succeed again.
    assert!(client.open_bi(cc).unwrap().is_some());
}

// ── Unreliable QUIC datagrams (RFC 9221) ───────────────────────────────

#[test]
fn datagram_round_trip() {
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, _sc) = handshake(&mut client, &mut server, ca, sa);

    // Both endpoints should advertise datagram support after the
    // handshake. The exact size depends on path MTU and peer params,
    // but should be at least a few hundred bytes.
    let max = client
        .max_datagram_size(cc)
        .expect("datagrams should be supported by default");
    assert!(max >= 256, "max_datagram_size suspiciously small: {max}");

    let payload = bytes::Bytes::from_static(b"unreliable hello");
    client.send_datagram(cc, payload.clone(), false).unwrap();
    drain(&mut client, &mut server, ca, sa);

    let mut got = None;
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::DatagramReceived { data, .. } = ev {
            got = Some(data);
        }
    }
    assert_eq!(
        got.as_ref(),
        Some(&payload),
        "datagram should round-trip verbatim"
    );
}

#[test]
fn datagram_send_too_large_errors() {
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, _sc) = handshake(&mut client, &mut server, ca, sa);

    let max = client.max_datagram_size(cc).unwrap();
    // 4 KiB is well above any sane datagram MTU on loopback after path
    // overhead — quinn-proto rejects it.
    let too_big = bytes::Bytes::from(vec![0xFFu8; (max + 1) * 4]);
    let res = client.send_datagram(cc, too_big, false);
    assert!(res.is_err(), "oversize datagram must fail to enqueue");
}

#[test]
fn datagram_drop_old_when_full_does_not_error() {
    let (mut client, mut server, ca, sa, _) = make_pair();
    let (cc, _sc) = handshake(&mut client, &mut server, ca, sa);

    // Burst many datagrams without ferrying so the local outgoing
    // buffer fills. With drop=true, sends never fail; older queued
    // datagrams are dropped to make room.
    let payload = bytes::Bytes::from(vec![0xCDu8; 1100]);
    for _ in 0..256 {
        client.send_datagram(cc, payload.clone(), true).unwrap();
    }

    // Now actually deliver. Server should receive *some* datagrams (we
    // don't pin a count — drop semantics are timing-dependent), but the
    // client must not have errored mid-burst.
    drain(&mut client, &mut server, ca, sa);
    let mut received = 0usize;
    while let Some(ev) = server.poll_event() {
        if let QuicEvent::DatagramReceived { .. } = ev {
            received += 1;
        }
    }
    // Even one delivery proves the path didn't poison itself; many is
    // also fine.
    assert!(
        received >= 1,
        "expected at least one datagram to round-trip after drop-on-full burst"
    );
}
