//! Integration tests: gRPC client over TLS with a mock gRPC server.
//!
//! The mock server speaks just enough HTTP/2 + gRPC framing to echo back
//! request messages with a `grpc-status: 0` trailer.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder, TlsConfig};
use ringline_h2::frame::{self, Frame};
use ringline_h2::hpack::{Decoder, Encoder, HeaderField};
use ringline_h2::settings::Settings;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::future::Future;

use ringline_grpc::{GrpcConnection, GrpcEvent, GrpcStatus};

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

// -- Mock gRPC Server --

/// A minimal gRPC server that echoes request bodies back with grpc-status: 0 trailers.
struct GrpcEchoServer;

impl AsyncEventHandler for GrpcEchoServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let mut recv_buf = Vec::new();
            let mut encoder = Encoder::new(4096);
            let mut decoder = Decoder::new(4096);
            let mut settings_sent = false;

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

                if !settings_sent {
                    let magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                    if recv_buf.len() >= magic.len() && &recv_buf[..magic.len()] == magic {
                        recv_buf.drain(..magic.len());
                    }
                    let mut send_buf = Vec::new();
                    Frame::Settings {
                        ack: false,
                        settings: Settings::default(),
                    }
                    .encode(&mut send_buf);
                    let _ = conn.send_nowait(&send_buf);
                    settings_sent = true;
                }

                loop {
                    match frame::decode_frame(&recv_buf, 16384) {
                        Ok(Some((frame, consumed))) => {
                            recv_buf.drain(..consumed);
                            match frame {
                                Frame::Settings { ack, .. } => {
                                    if !ack {
                                        let mut buf = Vec::new();
                                        Frame::Settings {
                                            ack: true,
                                            settings: Settings::default(),
                                        }
                                        .encode(&mut buf);
                                        let _ = conn.send_nowait(&buf);
                                    }
                                }
                                Frame::Headers {
                                    stream_id: _,
                                    encoded,
                                    end_headers: true,
                                    ..
                                } => {
                                    // Decode headers to verify gRPC request.
                                    let _headers = decoder.decode(&encoded).unwrap_or_default();
                                }
                                Frame::Data {
                                    stream_id,
                                    payload,
                                    end_stream: true,
                                } => {
                                    // Extract the gRPC message from the length-prefixed frame.
                                    let grpc_payload = if payload.len() >= 5 {
                                        let len = u32::from_be_bytes([
                                            payload[1], payload[2], payload[3], payload[4],
                                        ])
                                            as usize;
                                        payload[5..5 + len].to_vec()
                                    } else {
                                        Vec::new()
                                    };

                                    let mut send_buf = Vec::new();

                                    // Response HEADERS.
                                    let mut encoded_resp = Vec::new();
                                    encoder.encode(
                                        &[
                                            HeaderField::new(b":status", b"200"),
                                            HeaderField::new(b"content-type", b"application/grpc"),
                                        ],
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

                                    // Echo the message back with gRPC framing.
                                    let mut grpc_framed = Vec::new();
                                    grpc_framed.push(0); // no compression
                                    grpc_framed.extend_from_slice(
                                        &(grpc_payload.len() as u32).to_be_bytes(),
                                    );
                                    grpc_framed.extend_from_slice(&grpc_payload);

                                    Frame::Data {
                                        stream_id,
                                        payload: grpc_framed,
                                        end_stream: false,
                                    }
                                    .encode(&mut send_buf);

                                    // Trailers with grpc-status: 0.
                                    let mut encoded_trailers = Vec::new();
                                    encoder.encode(
                                        &[HeaderField::new(b"grpc-status", b"0")],
                                        &mut encoded_trailers,
                                    );
                                    Frame::Headers {
                                        stream_id,
                                        encoded: encoded_trailers,
                                        end_stream: true,
                                        end_headers: true,
                                        priority: None,
                                    }
                                    .encode(&mut send_buf);

                                    let _ = conn.send_nowait(&send_buf);
                                }
                                Frame::WindowUpdate { .. } | Frame::Ping { .. } => {
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
        GrpcEchoServer
    }
}

// -- Test Client --

struct GrpcTestClient {
    tls_conn: rustls::ClientConnection,
    tcp: TcpStream,
    grpc: GrpcConnection,
}

impl GrpcTestClient {
    fn connect(addr: SocketAddr, tls_config: Arc<rustls::ClientConfig>) -> Self {
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_nodelay(true).unwrap();

        let server_name = "localhost".try_into().unwrap();
        let tls_conn = rustls::ClientConnection::new(tls_config, server_name).unwrap();

        let grpc = GrpcConnection::new(Settings::client_default());

        let mut client = GrpcTestClient {
            tls_conn,
            tcp,
            grpc,
        };

        // Complete TLS handshake.
        client.drive_tls();

        // Send HTTP/2 connection preface + SETTINGS.
        let preface = client.grpc.take_pending_send();
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
                "waiting for gRPC ready timed out"
            );

            self.read_tls();

            let mut plaintext = vec![0u8; 65536];
            match self.tls_conn.reader().read(&mut plaintext) {
                Ok(0) => {}
                Ok(n) => {
                    self.grpc.recv(&plaintext[..n]).unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("tls read error: {e}"),
            }

            if self.grpc.has_pending_send() {
                let data = self.grpc.take_pending_send();
                self.tls_write(&data);
                self.flush_tls();
            }

            while let Some(event) = self.grpc.poll_event() {
                match event {
                    GrpcEvent::Ready => return,
                    GrpcEvent::Error(e) => panic!("gRPC error during setup: {e}"),
                    _ => {}
                }
            }
        }
    }

    fn send_unary(&mut self, service: &str, method: &str, body: &[u8]) -> u32 {
        let stream_id = self.grpc.send_unary(service, method, body, &[]).unwrap();
        let data = self.grpc.take_pending_send();
        self.tls_write(&data);
        self.flush_tls();
        stream_id
    }

    fn recv_response(&mut self, stream_id: u32) -> (Vec<u8>, GrpcStatus, String) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut resp_data = Vec::new();
        let mut resp_status = None;
        let mut resp_message = String::new();

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
                    self.grpc.recv(&plaintext[..n]).unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("tls read error: {e}"),
            }

            if self.grpc.has_pending_send() {
                let data = self.grpc.take_pending_send();
                self.tls_write(&data);
                self.flush_tls();
            }

            while let Some(event) = self.grpc.poll_event() {
                match event {
                    GrpcEvent::Message {
                        stream_id: sid,
                        data,
                    } if sid == stream_id => {
                        resp_data.extend_from_slice(&data);
                    }
                    GrpcEvent::Status {
                        stream_id: sid,
                        status,
                        message,
                        ..
                    } if sid == stream_id => {
                        resp_status = Some(status);
                        resp_message = message;
                    }
                    _ => {}
                }
            }

            if let Some(status) = resp_status {
                return (resp_data, status, resp_message);
            }
        }
    }
}

// -- Tests --

#[test]
fn grpc_unary_echo() {
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
        .launch::<GrpcEchoServer>()
        .expect("launch failed");

    wait_for_server(addr);
    std::thread::sleep(Duration::from_millis(50));

    let mut client = GrpcTestClient::connect(addr, client_tls);

    // Send a unary gRPC request.
    let request_body = b"hello grpc";
    let stream_id = client.send_unary("test.EchoService", "Echo", request_body);

    // Receive the response.
    let (resp_data, status, message) = client.recv_response(stream_id);

    assert_eq!(resp_data, request_body);
    assert_eq!(status, GrpcStatus::Ok);
    assert!(message.is_empty());

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
