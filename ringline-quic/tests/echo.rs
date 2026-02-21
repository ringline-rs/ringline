//! Integration tests: QUIC echo server using ringline's AsyncEventHandler + QuicEndpoint.
//!
//! Each test launches a ringline server with UDP, connects a QUIC client (driven
//! by quinn-proto directly), sends data, and verifies echoed responses.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event,
    ServerConfig,
};
use ringline::{
    AsyncEventHandler, Config, ConnCtx, RinglineBuilder, UdpCtx, select, sleep,
};
use ringline_quic::{QuicConfig, QuicEndpoint, QuicEvent};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

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
    // Allow enough concurrent streams for tests.
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

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

// Serialize tests — SERVER_CONFIG can only hold one test's state at a time.
static TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── QUIC Echo Server (AsyncEventHandler) ─────────────────────────────

/// Config sent to the server handler via OnceLock.
static SERVER_CONFIG: std::sync::OnceLock<std::sync::Mutex<Option<QuicConfig>>> =
    std::sync::OnceLock::new();

struct QuicEchoServer;

#[allow(clippy::manual_async_fn)]
impl AsyncEventHandler for QuicEchoServer {
    fn on_accept(&self, _conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
        async move {}
    }

    fn create_for_worker(_worker_id: usize) -> Self {
        QuicEchoServer
    }

    fn on_udp_bind(
        &self,
        udp: UdpCtx,
    ) -> Option<Pin<Box<dyn std::future::Future<Output = ()> + 'static>>> {
        let config = SERVER_CONFIG
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap()
            .take()?;

        // We don't know the local_addr at this point; use a placeholder.
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut quic = QuicEndpoint::new(config, local_addr);
        let mut read_buf = vec![0u8; 65536];

        Some(Box::pin(async move {
            loop {
                // Use select to drive both recv and a timer for QUIC timers.
                match select(udp.recv_from(), sleep(Duration::from_millis(10))).await {
                    ringline::Either::Left((data, peer)) => {
                        quic.handle_datagram(Instant::now(), &data, peer);
                    }
                    ringline::Either::Right(()) => {
                        // Timer expired — drive QUIC timers.
                    }
                }

                quic.drive_timers(Instant::now());

                // Process events.
                while let Some(event) = quic.poll_event() {
                    match event {
                        QuicEvent::StreamReadable { conn, stream } => loop {
                            let (n, fin) = match quic.stream_recv(conn, stream, &mut read_buf) {
                                Ok(r) => r,
                                Err(_) => break,
                            };
                            if n > 0 {
                                let _ = quic.stream_send(conn, stream, &read_buf[..n]);
                            }
                            if fin {
                                let _ = quic.stream_finish(conn, stream);
                                break;
                            }
                            if n == 0 {
                                break;
                            }
                        },
                        QuicEvent::NewConnection(_)
                        | QuicEvent::Connected(_)
                        | QuicEvent::StreamOpened { .. }
                        | QuicEvent::StreamWritable { .. }
                        | QuicEvent::StreamFinished { .. }
                        | QuicEvent::ConnectionClosed { .. } => {}
                    }
                }

                // Flush outgoing packets.
                while let Some((dest, data)) = quic.poll_send() {
                    let _ = udp.send_to(dest, &data);
                }
            }
        }))
    }
}

// ── Test Client ─────────────────────────────────────────────────────

/// A blocking QUIC test client that drives quinn-proto over a std UdpSocket.
struct QuicTestClient {
    endpoint: Endpoint,
    socket: UdpSocket,
    conn_handle: ConnectionHandle,
    conn: quinn_proto::Connection,
    buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

impl QuicTestClient {
    fn connect(server_addr: SocketAddr, client_config: ClientConfig) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.set_nonblocking(false).unwrap();

        let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

        // Initiate connection.
        let (conn_handle, conn) = endpoint
            .connect(Instant::now(), client_config, server_addr, "localhost")
            .unwrap();

        let mut client = QuicTestClient {
            endpoint,
            socket,
            conn_handle,
            conn,
            buf: Vec::with_capacity(1500),
            recv_buf: vec![0u8; 65536],
        };

        // Send initial handshake packets.
        client.flush_transmits();

        // Drive handshake to completion.
        client.drive_until_connected();

        client
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

            // Handle timeouts.
            if let Some(timeout) = self.conn.poll_timeout()
                && timeout <= Instant::now()
            {
                self.conn.handle_timeout(Instant::now());
                self.flush_transmits();
            }

            // Check for Connected event.
            while let Some(event) = self.conn.poll() {
                if matches!(event, Event::Connected) {
                    return;
                }
            }

            self.recv_and_process();
        }
    }

    fn open_bi(&mut self) -> quinn_proto::StreamId {
        self.conn
            .streams()
            .open(Dir::Bi)
            .expect("stream limit reached")
    }

    fn send_data(&mut self, stream: quinn_proto::StreamId, data: &[u8]) {
        let written = self.conn.send_stream(stream).write(data).unwrap();
        assert_eq!(written, data.len(), "partial write");
        self.flush_transmits();
    }

    fn finish_stream(&mut self, stream: quinn_proto::StreamId) {
        self.conn.send_stream(stream).finish().unwrap();
        self.flush_transmits();
    }

    fn recv_all(&mut self, stream: quinn_proto::StreamId, expected_len: usize) -> Vec<u8> {
        let mut result = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        while result.len() < expected_len {
            assert!(Instant::now() < deadline, "recv timed out");

            // Handle timeouts.
            if let Some(timeout) = self.conn.poll_timeout()
                && timeout <= Instant::now()
            {
                self.conn.handle_timeout(Instant::now());
                self.flush_transmits();
            }

            // Try reading.
            match self.conn.recv_stream(stream).read(true) {
                Ok(mut chunks) => {
                    loop {
                        match chunks.next(65536) {
                            Ok(Some(chunk)) => result.extend_from_slice(&chunk.bytes),
                            Ok(None) => {
                                let _ = chunks.finalize();
                                return result;
                            }
                            Err(quinn_proto::ReadError::Blocked) => break,
                            Err(e) => panic!("read error: {e}"),
                        }
                    }
                    let _ = chunks.finalize();
                }
                Err(quinn_proto::ReadableError::ClosedStream) => {
                    // Stream not ready yet; recv more data.
                }
                Err(e) => panic!("readable error: {e}"),
            }

            // Flush any pending transmits (ACKs, etc).
            self.flush_transmits();

            // Drain events.
            while let Some(_event) = self.conn.poll() {}

            // Recv more data from the server.
            self.recv_and_process();
        }

        result
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
fn quic_echo() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let (certs, key) = generate_self_signed();
    let server_cfg = server_crypto(certs.clone(), key);
    let client_cfg = client_crypto(&certs);

    let quic_config = QuicConfig::server(server_cfg);

    // Store config for server handler.
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
        .launch::<QuicEchoServer>()
        .expect("launch failed");

    wait_for_server(&tcp_addr.to_string());
    std::thread::sleep(Duration::from_millis(50));

    // Connect and echo.
    let mut client = QuicTestClient::connect(udp_addr, client_cfg);
    let stream = client.open_bi();
    client.send_data(stream, b"hello QUIC");
    client.finish_stream(stream);

    let response = client.recv_all(stream, 10);
    assert_eq!(&response, b"hello QUIC", "echo mismatch");

    client.close();
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn quic_multi_stream() {
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
        .launch::<QuicEchoServer>()
        .expect("launch failed");

    wait_for_server(&tcp_addr.to_string());
    std::thread::sleep(Duration::from_millis(50));

    let mut client = QuicTestClient::connect(udp_addr, client_cfg);

    let messages = [b"stream-one".as_ref(), b"stream-two", b"stream-three"];
    let mut streams = Vec::new();

    for msg in &messages {
        let stream = client.open_bi();
        client.send_data(stream, msg);
        client.finish_stream(stream);
        streams.push((stream, msg.len()));
    }

    for (i, (stream, len)) in streams.iter().enumerate() {
        let response = client.recv_all(*stream, *len);
        assert_eq!(&response, messages[i], "echo mismatch on stream {i}");
    }

    client.close();
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn quic_large_message() {
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
        .launch::<QuicEchoServer>()
        .expect("launch failed");

    wait_for_server(&tcp_addr.to_string());
    std::thread::sleep(Duration::from_millis(50));

    // 64KB payload.
    let payload: Vec<u8> = (0u8..=255).cycle().take(65536).collect();

    let mut client = QuicTestClient::connect(udp_addr, client_cfg);
    let stream = client.open_bi();

    // Send in chunks (quinn flow control may limit per-write).
    let mut offset = 0;
    while offset < payload.len() {
        let n = client
            .conn
            .send_stream(stream)
            .write(&payload[offset..])
            .unwrap();
        offset += n;
        client.flush_transmits();
        // Process any incoming ACKs to open flow control window.
        client.recv_and_process();
    }
    client.finish_stream(stream);

    let response = client.recv_all(stream, payload.len());
    assert_eq!(response.len(), payload.len(), "length mismatch");
    assert_eq!(response, payload, "data mismatch");

    client.close();
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
