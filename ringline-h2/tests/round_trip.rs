//! Integration tests: HTTP/2 server using ringline + ringline-h2 over TLS.
//!
//! Each test launches a ringline TLS server with an HTTP/2 handler, connects
//! a rustls client, performs the HTTP/2 handshake, and verifies request/response.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder, TlsConfig};
use ringline_h2::hpack::{Decoder, Encoder};
use ringline_h2::{Frame, H2Connection, H2Event, HeaderField, Settings};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::future::Future;

// -- TLS cert generation --

fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);
    (vec![cert_der], key.into())
}

fn server_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

fn client_tls_config(certs: &[CertificateDer<'static>]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert.clone()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

// -- Helpers --

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
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

static TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

// -- H2 Echo Server (AsyncEventHandler) --

struct H2Server;

impl AsyncEventHandler for H2Server {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            // Create server-side H2 connection (we handle the server role manually).
            let mut recv_buf = Vec::new();
            let mut encoder = Encoder::new(4096);
            let mut decoder = Decoder::new(4096);
            let mut settings_sent = false;
            let mut settings_acked = false;

            loop {
                let consumed = conn
                    .with_data(|data| {
                        recv_buf.extend_from_slice(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;

                if consumed == 0 {
                    break;
                }

                // If we haven't sent server preface yet, skip the client preface
                // (24-byte magic) first.
                if !settings_sent {
                    let magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                    if recv_buf.len() >= magic.len() && &recv_buf[..magic.len()] == magic {
                        recv_buf.drain(..magic.len());
                    }

                    // Send server SETTINGS.
                    let mut send_buf = Vec::new();
                    let settings_frame = Frame::Settings {
                        ack: false,
                        settings: Settings::default(),
                    };
                    settings_frame.encode(&mut send_buf);
                    let _ = conn.send_nowait(&send_buf);
                    settings_sent = true;
                }

                // Process frames from recv_buf.
                loop {
                    match ringline_h2::frame::decode_frame(&recv_buf, 16384) {
                        Ok(Some((frame, consumed))) => {
                            recv_buf.drain(..consumed);
                            match frame {
                                Frame::Settings { ack, .. } => {
                                    if !ack {
                                        // ACK client's SETTINGS.
                                        let mut buf = Vec::new();
                                        Frame::Settings {
                                            ack: true,
                                            settings: Settings::default(),
                                        }
                                        .encode(&mut buf);
                                        let _ = conn.send_nowait(&buf);
                                    } else {
                                        settings_acked = true;
                                    }
                                }
                                Frame::Headers {
                                    stream_id,
                                    encoded,
                                    end_stream,
                                    end_headers: true,
                                    ..
                                } => {
                                    let _ = settings_acked;
                                    let headers = decoder.decode(&encoded).unwrap_or_default();
                                    let method = headers
                                        .iter()
                                        .find(|h| h.name == b":method")
                                        .map(|h| h.value.clone());
                                    let is_get = method.as_deref() == Some(b"GET");

                                    if is_get || end_stream {
                                        // Send response: 200 OK + "hello".
                                        let mut send_buf = Vec::new();
                                        let mut encoded_resp = Vec::new();
                                        encoder.encode(
                                            &[HeaderField::new(b":status", b"200")],
                                            &mut encoded_resp,
                                        );
                                        Frame::Headers {
                                            stream_id,
                                            encoded: encoded_resp,
                                            end_stream: false,
                                            end_headers: true,
                                            priority: None,
                                        }
                                        .encode(&mut send_buf);
                                        Frame::Data {
                                            stream_id,
                                            payload: b"hello".to_vec(),
                                            end_stream: true,
                                        }
                                        .encode(&mut send_buf);
                                        let _ = conn.send_nowait(&send_buf);
                                    }
                                }
                                Frame::Data {
                                    stream_id,
                                    payload,
                                    end_stream: true,
                                } => {
                                    // Echo the body back.
                                    let mut send_buf = Vec::new();
                                    let mut encoded_resp = Vec::new();
                                    encoder.encode(
                                        &[HeaderField::new(b":status", b"200")],
                                        &mut encoded_resp,
                                    );
                                    Frame::Headers {
                                        stream_id,
                                        encoded: encoded_resp,
                                        end_stream: false,
                                        end_headers: true,
                                        priority: None,
                                    }
                                    .encode(&mut send_buf);
                                    Frame::Data {
                                        stream_id,
                                        payload,
                                        end_stream: true,
                                    }
                                    .encode(&mut send_buf);
                                    let _ = conn.send_nowait(&send_buf);
                                }
                                Frame::WindowUpdate { .. }
                                | Frame::Ping { .. }
                                | Frame::Priority { .. } => {
                                    // Ignore for test purposes (or respond to PING).
                                    if let Frame::Ping {
                                        ack: false,
                                        opaque_data,
                                    } = frame
                                    {
                                        let mut buf = Vec::new();
                                        Frame::Ping {
                                            ack: true,
                                            opaque_data,
                                        }
                                        .encode(&mut buf);
                                        let _ = conn.send_nowait(&buf);
                                    }
                                }
                                _ => {}
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
        }
    }

    fn create_for_worker(_worker_id: usize) -> Self {
        H2Server
    }
}

// -- Test Client (TLS + H2Connection) --

struct H2TestClient {
    tls_conn: rustls::ClientConnection,
    tcp: TcpStream,
    h2: H2Connection,
}

impl H2TestClient {
    fn connect(addr: SocketAddr, tls_config: Arc<rustls::ClientConfig>) -> Self {
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_nodelay(true).unwrap();

        let server_name = "localhost".try_into().unwrap();
        let tls_conn = rustls::ClientConnection::new(tls_config, server_name).unwrap();

        let h2 = H2Connection::new(Settings::client_default());

        let mut client = H2TestClient { tls_conn, tcp, h2 };

        // Complete TLS handshake.
        client.drive_tls();

        // Send HTTP/2 connection preface + SETTINGS.
        let preface = client.h2.take_pending_send();
        client.tls_write(&preface);
        client.flush_tls();

        // Read server SETTINGS and process.
        client.drive_until_ready();

        client
    }

    fn tls_write(&mut self, data: &[u8]) {
        self.tls_conn.writer().write_all(data).unwrap();
    }

    fn flush_tls(&mut self) {
        loop {
            let mut buf = Vec::new();
            match self.tls_conn.write_tls(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    self.tcp.write_all(&buf).unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("write_tls error: {e}"),
            }
        }
    }

    fn read_tls(&mut self) -> bool {
        let mut buf = [0u8; 8192];
        match self.tcp.read(&mut buf) {
            Ok(0) => false,
            Ok(n) => {
                self.tls_conn.read_tls(&mut &buf[..n]).unwrap();
                self.tls_conn.process_new_packets().unwrap();
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => false,
            Err(e) => panic!("tcp read error: {e}"),
        }
    }

    fn drive_tls(&mut self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "TLS handshake timed out"
            );

            self.flush_tls();

            if !self.tls_conn.is_handshaking() {
                break;
            }

            self.read_tls();
        }
    }

    fn drive_until_ready(&mut self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "waiting for server SETTINGS timed out"
            );

            self.read_tls();

            // Read decrypted data from TLS.
            let mut plaintext = vec![0u8; 65536];
            match self.tls_conn.reader().read(&mut plaintext) {
                Ok(0) => {}
                Ok(n) => {
                    self.h2.recv(&plaintext[..n]).unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("tls read error: {e}"),
            }

            // Send any H2 data (e.g., SETTINGS ACK).
            if self.h2.has_pending_send() {
                let data = self.h2.take_pending_send();
                self.tls_write(&data);
                self.flush_tls();
            }

            // Check for events.
            while let Some(event) = self.h2.poll_event() {
                match event {
                    H2Event::SettingsAcknowledged => return,
                    H2Event::Error(e) => panic!("H2 error during setup: {e}"),
                    _ => {}
                }
            }
        }
    }

    fn send_request(&mut self, headers: &[HeaderField], body: Option<&[u8]>) -> u32 {
        let end_stream = body.is_none();
        let stream_id = self.h2.send_request(headers, end_stream).unwrap();

        if let Some(body) = body {
            self.h2.send_data(stream_id, body, true).unwrap();
        }

        let data = self.h2.take_pending_send();
        self.tls_write(&data);
        self.flush_tls();
        stream_id
    }

    fn recv_response(&mut self, stream_id: u32) -> (Vec<HeaderField>, Vec<u8>) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut resp_headers = Vec::new();
        let mut resp_body = Vec::new();
        let mut got_end = false;

        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "recv response timed out"
            );

            self.read_tls();

            let mut plaintext = vec![0u8; 65536];
            match self.tls_conn.reader().read(&mut plaintext) {
                Ok(0) => {}
                Ok(n) => {
                    self.h2.recv(&plaintext[..n]).unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("tls read error: {e}"),
            }

            // Send any pending data (e.g., WINDOW_UPDATE).
            if self.h2.has_pending_send() {
                let data = self.h2.take_pending_send();
                self.tls_write(&data);
                self.flush_tls();
            }

            while let Some(event) = self.h2.poll_event() {
                match event {
                    H2Event::Response {
                        stream_id: sid,
                        headers,
                        end_stream,
                    } if sid == stream_id => {
                        resp_headers = headers;
                        if end_stream {
                            got_end = true;
                        }
                    }
                    H2Event::Data {
                        stream_id: sid,
                        data,
                        end_stream,
                    } if sid == stream_id => {
                        resp_body.extend_from_slice(&data);
                        if end_stream {
                            got_end = true;
                        }
                    }
                    _ => {}
                }
            }

            if got_end {
                break;
            }
        }

        (resp_headers, resp_body)
    }
}

// -- Tests --

#[test]
fn h2_request_response() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let (certs, key) = generate_self_signed();
    let server_tls = server_tls_config(certs.clone(), key);
    let client_tls = client_tls_config(&certs);

    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut config = test_config();
    config.tls = Some(TlsConfig {
        server_config: server_tls,
    });

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr)
        .launch::<H2Server>()
        .expect("launch failed");

    wait_for_server(addr);
    std::thread::sleep(Duration::from_millis(50));

    let mut client = H2TestClient::connect(addr, client_tls);

    // Send GET request.
    let request_headers = vec![
        HeaderField::new(b":method", b"GET"),
        HeaderField::new(b":path", b"/"),
        HeaderField::new(b":scheme", b"https"),
        HeaderField::new(b":authority", b"localhost"),
    ];
    let stream_id = client.send_request(&request_headers, None);

    // Receive response.
    let (resp_headers, resp_body) = client.recv_response(stream_id);

    // Verify.
    let status = resp_headers
        .iter()
        .find(|h| h.name == b":status")
        .expect("no :status header");
    assert_eq!(status.value, b"200");
    assert_eq!(resp_body, b"hello");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn h2_request_with_body() {
    let _guard = TEST_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let (certs, key) = generate_self_signed();
    let server_tls = server_tls_config(certs.clone(), key);
    let client_tls = client_tls_config(&certs);

    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut config = test_config();
    config.tls = Some(TlsConfig {
        server_config: server_tls,
    });

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr)
        .launch::<H2Server>()
        .expect("launch failed");

    wait_for_server(addr);
    std::thread::sleep(Duration::from_millis(50));

    let mut client = H2TestClient::connect(addr, client_tls);

    // Send POST request with body.
    let request_headers = vec![
        HeaderField::new(b":method", b"POST"),
        HeaderField::new(b":path", b"/echo"),
        HeaderField::new(b":scheme", b"https"),
        HeaderField::new(b":authority", b"localhost"),
    ];
    let stream_id = client.send_request(&request_headers, Some(b"request body"));

    let (resp_headers, resp_body) = client.recv_response(stream_id);

    let status = resp_headers
        .iter()
        .find(|h| h.name == b":status")
        .expect("no :status header");
    assert_eq!(status.value, b"200");
    assert_eq!(resp_body, b"request body");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
