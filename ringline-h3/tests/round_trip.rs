//! Integration tests: HTTP/3 server using ringline + ringline-quic + ringline-h3.
//!
//! Each test launches a ringline server with an H3 AsyncEventHandler, connects a
//! QUIC client (driven by quinn-proto directly), sends HTTP/3 frames,
//! and verifies responses.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event,
    ServerConfig,
};
use ringline::{AsyncEventHandler, Config, ConnCtx, RinglineBuilder, UdpCtx, select, sleep};
use ringline_h3::{H3Connection, H3Event, HeaderField, Settings};
use ringline_quic::{QuicConfig, QuicEndpoint};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::future::Future;

// ── TLS cert generation ──────────────────────────────────────────────

fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);
    (vec![cert_der], key.into())
}

fn server_crypto(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    let mut sc = ServerConfig::with_single_cert(certs, key).unwrap();
    let transport = Arc::get_mut(&mut sc.transport).unwrap();
    transport.max_concurrent_bidi_streams(64u32.into());
    transport.max_concurrent_uni_streams(64u32.into());
    Arc::new(sc)
}

fn client_crypto(certs: &[CertificateDer<'static>]) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert.clone()).unwrap();
    }
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    ))
}

// ── Helpers ──────────────────────────────────────────────────────────

fn test_config() -> Config {
    let mut config = Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 64;
    config.recv_buffer.ring_size = 64;
    config.recv_buffer.buffer_size = 4096;
    config.max_connections = 64;
    config.send_copy_count = 64;
    config
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_server(addr: SocketAddr) {
    for _ in 0..200 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

static TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── H3 Echo Server (AsyncEventHandler) ──────────────────────────────

static SERVER_CONFIG: std::sync::OnceLock<std::sync::Mutex<Option<QuicConfig>>> =
    std::sync::OnceLock::new();

struct H3Server;

impl AsyncEventHandler for H3Server {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_udp_bind(&self, udp: UdpCtx) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let quic_config = SERVER_CONFIG
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap()
            .take();

        let quic_config = quic_config?;

        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut quic = QuicEndpoint::new(quic_config, local_addr);
        let mut h3 = H3Connection::new(Settings::default());

        Some(Box::pin(async move {
            loop {
                match select(udp.recv_from(), sleep(Duration::from_millis(10))).await {
                    ringline::Either::Left((data, peer)) => {
                        quic.handle_datagram(Instant::now(), &data, peer);
                    }
                    ringline::Either::Right(()) => {}
                }

                quic.drive_timers(Instant::now());

                // Feed QUIC events to H3.
                while let Some(event) = quic.poll_event() {
                    let _ = h3.handle_quic_event(&mut quic, &event);
                }

                // Process H3 events: echo back responses.
                while let Some(event) = h3.poll_event() {
                    match event {
                        H3Event::Request {
                            stream_id,
                            headers,
                            end_stream,
                        } => {
                            let method = headers.iter().find(|h| h.name == b":method");
                            let is_get = method.is_some_and(|m| m.value == b"GET");

                            if is_get || end_stream {
                                let response_headers = vec![HeaderField::new(b":status", b"200")];
                                let _ = h3.send_response(
                                    &mut quic,
                                    stream_id,
                                    &response_headers,
                                    false,
                                );
                                let _ = h3.send_data(&mut quic, stream_id, b"hello", true);
                            }
                        }
                        H3Event::Data {
                            stream_id,
                            data,
                            end_stream,
                        } => {
                            if end_stream {
                                let response_headers = vec![HeaderField::new(b":status", b"200")];
                                let _ = h3.send_response(
                                    &mut quic,
                                    stream_id,
                                    &response_headers,
                                    false,
                                );
                                let _ = h3.send_data(&mut quic, stream_id, &data, true);
                            }
                        }
                        H3Event::GoAway { .. } | H3Event::Error(_) => {}
                    }
                }

                // Flush outgoing QUIC packets.
                while let Some((dest, data)) = quic.poll_send() {
                    let _ = udp.send_to(dest, &data);
                }
            }
        }))
    }

    fn create_for_worker(_worker_id: usize) -> Self {
        H3Server
    }
}

// ── Test Client (drives quinn-proto + HTTP/3 frames) ────────────────

struct H3TestClient {
    endpoint: Endpoint,
    socket: UdpSocket,
    conn_handle: ConnectionHandle,
    conn: quinn_proto::Connection,
    buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

impl H3TestClient {
    fn connect(server_addr: SocketAddr, client_config: ClientConfig) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.set_nonblocking(false).unwrap();

        let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

        let (conn_handle, conn) = endpoint
            .connect(Instant::now(), client_config, server_addr, "localhost")
            .unwrap();

        let mut client = H3TestClient {
            endpoint,
            socket,
            conn_handle,
            conn,
            buf: Vec::with_capacity(1500),
            recv_buf: vec![0u8; 65536],
        };

        client.flush_transmits();
        client.drive_until_connected();

        // After connection established, open our control stream and send SETTINGS.
        client.send_control_settings();

        client
    }

    fn send_control_settings(&mut self) {
        let control_stream = self.conn.streams().open(Dir::Uni).expect("open uni");
        let mut buf = Vec::new();
        // Stream type: control (0x00)
        ringline_h3::frame::encode_varint(&mut buf, 0x00);
        // SETTINGS frame with defaults (empty payload).
        ringline_h3::Frame::Settings(Settings::default()).encode(&mut buf);
        self.conn.send_stream(control_stream).write(&buf).unwrap();
        // Do NOT finish the control stream — RFC 9114 requires it stays open.
        self.flush_transmits();
    }

    fn flush_transmits(&mut self) {
        loop {
            self.buf.clear();
            match self.conn.poll_transmit(Instant::now(), 1, &mut self.buf) {
                Some(t) => {
                    self.socket
                        .send_to(&self.buf[..t.size], t.destination)
                        .unwrap();
                }
                None => break,
            }
        }
    }

    fn process_endpoint_events(&mut self) {
        while let Some(event) = self.conn.poll_endpoint_events() {
            if let Some(conn_event) = self.endpoint.handle_event(self.conn_handle, event) {
                self.conn.handle_event(conn_event);
            }
        }
    }

    fn recv_and_process(&mut self) -> bool {
        match self.socket.recv_from(&mut self.recv_buf) {
            Ok((n, peer)) => {
                let now = Instant::now();
                let data = bytes::BytesMut::from(&self.recv_buf[..n]);
                let mut response_buf = Vec::new();
                if let Some(event) = self.endpoint.handle(
                    now,
                    peer,
                    Some(self.socket.local_addr().unwrap().ip()),
                    None,
                    data,
                    &mut response_buf,
                ) {
                    match event {
                        DatagramEvent::ConnectionEvent(_ch, event) => {
                            self.conn.handle_event(event);
                        }
                        DatagramEvent::NewConnection(_) => {}
                        DatagramEvent::Response(t) => {
                            self.socket
                                .send_to(&response_buf[..t.size], t.destination)
                                .unwrap();
                        }
                    }
                }
                self.process_endpoint_events();
                self.flush_transmits();
                true
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => false,
            Err(e) => panic!("recv error: {e}"),
        }
    }

    fn drive_until_connected(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "QUIC handshake timed out");

            if let Some(timeout) = self.conn.poll_timeout()
                && timeout <= Instant::now()
            {
                self.conn.handle_timeout(Instant::now());
                self.flush_transmits();
            }

            while let Some(event) = self.conn.poll() {
                if matches!(event, Event::Connected) {
                    return;
                }
            }

            self.recv_and_process();
        }
    }

    /// Send an HTTP/3 request (HEADERS frame + optional DATA + FIN).
    fn send_request(
        &mut self,
        headers: &[HeaderField],
        body: Option<&[u8]>,
    ) -> quinn_proto::StreamId {
        let stream = self.conn.streams().open(Dir::Bi).expect("stream limit");

        // Encode and send HEADERS frame.
        let mut frame_buf = Vec::new();
        let mut encoded_headers = Vec::new();
        ringline_h3::qpack::encode(headers, &mut encoded_headers);
        ringline_h3::Frame::Headers {
            encoded: encoded_headers,
        }
        .encode(&mut frame_buf);

        // Encode DATA frame if body present.
        if let Some(body) = body {
            ringline_h3::Frame::Data {
                payload: body.to_vec(),
            }
            .encode(&mut frame_buf);
        }

        self.conn.send_stream(stream).write(&frame_buf).unwrap();
        self.conn.send_stream(stream).finish().unwrap();
        self.flush_transmits();
        stream
    }

    /// Receive the HTTP/3 response (HEADERS + DATA) from a stream.
    fn recv_response(&mut self, stream: quinn_proto::StreamId) -> (Vec<HeaderField>, Vec<u8>) {
        let mut raw = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        // Read all data from the stream until FIN.
        loop {
            assert!(Instant::now() < deadline, "recv timed out");

            if let Some(timeout) = self.conn.poll_timeout()
                && timeout <= Instant::now()
            {
                self.conn.handle_timeout(Instant::now());
                self.flush_transmits();
            }

            let mut got_fin = false;
            match self.conn.recv_stream(stream).read(true) {
                Ok(mut chunks) => loop {
                    match chunks.next(65536) {
                        Ok(Some(chunk)) => raw.extend_from_slice(&chunk.bytes),
                        Ok(None) => {
                            let _ = chunks.finalize();
                            got_fin = true;
                            break;
                        }
                        Err(quinn_proto::ReadError::Blocked) => break,
                        Err(e) => panic!("read error: {e}"),
                    }
                },
                Err(quinn_proto::ReadableError::ClosedStream) => {}
                Err(e) => panic!("readable error: {e}"),
            }

            if got_fin {
                break;
            }

            self.flush_transmits();
            while let Some(_event) = self.conn.poll() {}
            self.recv_and_process();
        }

        // Parse HTTP/3 frames from the raw data.
        let mut headers = Vec::new();
        let mut body = Vec::new();
        let mut offset = 0;

        while offset < raw.len() {
            match ringline_h3::frame::decode_frame(&raw[offset..]).unwrap() {
                Some((frame, consumed)) => {
                    offset += consumed;
                    match frame {
                        ringline_h3::Frame::Headers { encoded } => {
                            headers = ringline_h3::qpack::decode(&encoded).unwrap();
                        }
                        ringline_h3::Frame::Data { payload } => {
                            body.extend_from_slice(&payload);
                        }
                        _ => {}
                    }
                }
                None => break,
            }
        }

        (headers, body)
    }

    fn close(mut self) {
        self.conn.close(
            Instant::now(),
            quinn_proto::VarInt::from_u32(0),
            b"done".as_ref().into(),
        );
        self.flush_transmits();
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[test]
fn h3_request_response() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let (certs, key) = generate_self_signed();
    let server_cfg = server_crypto(certs.clone(), key);
    let client_cfg = client_crypto(&certs);

    let quic_config = QuicConfig::server(server_cfg);
    SERVER_CONFIG
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap()
        .replace(quic_config);

    let udp_port = free_port();
    let udp_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let tcp_port = free_port();
    let tcp_addr: SocketAddr = format!("127.0.0.1:{tcp_port}").parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(tcp_addr)
        .bind_udp(udp_addr)
        .launch::<H3Server>()
        .expect("launch failed");

    wait_for_server(tcp_addr);
    std::thread::sleep(Duration::from_millis(50));

    let mut client = H3TestClient::connect(udp_addr, client_cfg);

    // Send GET request.
    let request_headers = vec![
        HeaderField::new(b":method", b"GET"),
        HeaderField::new(b":path", b"/"),
        HeaderField::new(b":scheme", b"https"),
        HeaderField::new(b":authority", b"localhost"),
    ];
    let stream = client.send_request(&request_headers, None);

    // Receive response.
    let (resp_headers, resp_body) = client.recv_response(stream);

    // Verify.
    let status = resp_headers
        .iter()
        .find(|h| h.name == b":status")
        .expect("no :status header");
    assert_eq!(status.value, b"200");
    assert_eq!(resp_body, b"hello");

    client.close();
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn h3_request_with_body() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let (certs, key) = generate_self_signed();
    let server_cfg = server_crypto(certs.clone(), key);
    let client_cfg = client_crypto(&certs);

    let quic_config = QuicConfig::server(server_cfg);
    SERVER_CONFIG
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap()
        .replace(quic_config);

    let udp_port = free_port();
    let udp_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let tcp_port = free_port();
    let tcp_addr: SocketAddr = format!("127.0.0.1:{tcp_port}").parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(tcp_addr)
        .bind_udp(udp_addr)
        .launch::<H3Server>()
        .expect("launch failed");

    wait_for_server(tcp_addr);
    std::thread::sleep(Duration::from_millis(50));

    let mut client = H3TestClient::connect(udp_addr, client_cfg);

    // Send POST request with body.
    let request_headers = vec![
        HeaderField::new(b":method", b"POST"),
        HeaderField::new(b":path", b"/echo"),
        HeaderField::new(b":scheme", b"https"),
        HeaderField::new(b":authority", b"localhost"),
    ];
    let stream = client.send_request(&request_headers, Some(b"request body"));

    let (resp_headers, resp_body) = client.recv_response(stream);

    let status = resp_headers
        .iter()
        .find(|h| h.name == b":status")
        .expect("no :status header");
    assert_eq!(status.value, b"200");
    assert_eq!(resp_body, b"request body");

    client.close();
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn h3_multiple_requests() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let (certs, key) = generate_self_signed();
    let server_cfg = server_crypto(certs.clone(), key);
    let client_cfg = client_crypto(&certs);

    let quic_config = QuicConfig::server(server_cfg);
    SERVER_CONFIG
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap()
        .replace(quic_config);

    let udp_port = free_port();
    let udp_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let tcp_port = free_port();
    let tcp_addr: SocketAddr = format!("127.0.0.1:{tcp_port}").parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(tcp_addr)
        .bind_udp(udp_addr)
        .launch::<H3Server>()
        .expect("launch failed");

    wait_for_server(tcp_addr);
    std::thread::sleep(Duration::from_millis(50));

    let mut client = H3TestClient::connect(udp_addr, client_cfg);

    // Send 3 GET requests on separate streams.
    let mut streams = Vec::new();
    for i in 0..3 {
        let request_headers = vec![
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(":path", format!("/{i}")),
            HeaderField::new(b":scheme", b"https"),
            HeaderField::new(b":authority", b"localhost"),
        ];
        let stream = client.send_request(&request_headers, None);
        streams.push(stream);
    }

    // Receive all responses.
    for stream in &streams {
        let (resp_headers, resp_body) = client.recv_response(*stream);
        let status = resp_headers
            .iter()
            .find(|h| h.name == b":status")
            .expect("no :status header");
        assert_eq!(status.value, b"200");
        assert_eq!(resp_body, b"hello");
    }

    client.close();
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
