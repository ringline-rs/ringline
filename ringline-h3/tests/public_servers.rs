//! Integration tests against public HTTP/3 servers.
//!
//! These tests are `#[ignore]` by default because they require network access.
//! Run them manually with:
//!
//!   cargo test -p ringline-h3 --test public_servers -- --ignored --nocapture

use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event,
};

// ── QUIC client with real TLS ───────────────────────────────────────

fn h3_client_config() -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // HTTP/3 requires ALPN "h3".
    tls.alpn_protocols = vec![b"h3".to_vec()];

    ClientConfig::new(Arc::new(
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ))
}

struct QuicClient {
    endpoint: Endpoint,
    socket: UdpSocket,
    conn_handle: ConnectionHandle,
    conn: quinn_proto::Connection,
    buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

impl QuicClient {
    fn connect(server_addr: SocketAddr, server_name: &str) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.set_nonblocking(false).unwrap();

        let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
        let client_config = h3_client_config();

        let (conn_handle, conn) = endpoint
            .connect(Instant::now(), client_config, server_addr, server_name)
            .unwrap();

        let mut client = QuicClient {
            endpoint,
            socket,
            conn_handle,
            conn,
            buf: Vec::with_capacity(1500),
            recv_buf: vec![0u8; 65536],
        };

        client.flush_transmits();
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
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                Instant::now() < deadline,
                "QUIC handshake timed out — is the server reachable?"
            );

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

    /// Send our HTTP/3 control stream with SETTINGS.
    fn send_h3_settings(&mut self) {
        let control = self.conn.streams().open(Dir::Uni).expect("open uni");
        let mut buf = Vec::new();
        ringline_h3::frame::encode_varint(&mut buf, 0x00); // control stream type
        ringline_h3::Frame::Settings(ringline_h3::Settings::default()).encode(&mut buf);
        self.conn.send_stream(control).write(&buf).unwrap();
        self.flush_transmits();
    }

    /// Send an HTTP/3 GET request. Returns the bidi stream ID.
    fn send_get(&mut self, authority: &str, path: &str) -> quinn_proto::StreamId {
        let stream = self.conn.streams().open(Dir::Bi).expect("open bidi");

        let headers = vec![
            ringline_h3::HeaderField::new(b":method", b"GET"),
            ringline_h3::HeaderField::new(b":path", path.as_bytes()),
            ringline_h3::HeaderField::new(b":scheme", b"https"),
            ringline_h3::HeaderField::new(b":authority", authority.as_bytes()),
            ringline_h3::HeaderField::new(b"user-agent", b"ringline-h3/0.1"),
        ];

        let mut frame_buf = Vec::new();
        let mut encoded_headers = Vec::new();
        ringline_h3::qpack::encode(&headers, &mut encoded_headers);
        ringline_h3::Frame::Headers {
            encoded: encoded_headers,
        }
        .encode(&mut frame_buf);

        self.conn.send_stream(stream).write(&frame_buf).unwrap();
        self.conn.send_stream(stream).finish().unwrap();
        self.flush_transmits();
        stream
    }

    /// Receive the HTTP/3 response from a stream.
    /// Returns (status_code, response_headers, body).
    fn recv_response(
        &mut self,
        stream: quinn_proto::StreamId,
    ) -> (u16, Vec<ringline_h3::HeaderField>, Vec<u8>) {
        let mut raw = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);

        loop {
            assert!(
                Instant::now() < deadline,
                "recv timed out waiting for response"
            );

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

        // Parse HTTP/3 frames.
        let mut headers = Vec::new();
        let mut body = Vec::new();
        let mut offset = 0;
        println!("  Raw response: {} bytes total", raw.len());

        while offset < raw.len() {
            match ringline_h3::frame::decode_frame(&raw[offset..]) {
                Ok(Some((frame, consumed))) => {
                    offset += consumed;
                    match frame {
                        ringline_h3::Frame::Headers { encoded } => {
                            println!(
                                "  HEADERS frame: {} bytes, first bytes: {:02x?}",
                                encoded.len(),
                                &encoded[..encoded.len().min(32)]
                            );
                            match ringline_h3::qpack::decode(&encoded) {
                                Ok(h) => headers = h,
                                Err(e) => println!("  QPACK decode error: {e}"),
                            }
                        }
                        ringline_h3::Frame::Data { payload } => {
                            body.extend_from_slice(&payload);
                        }
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        // Extract status code.
        let status = headers
            .iter()
            .find(|h| h.name == b":status")
            .map(|h| {
                std::str::from_utf8(&h.value)
                    .unwrap()
                    .parse::<u16>()
                    .unwrap()
            })
            .unwrap_or(0);

        (status, headers, body)
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

// ── Helpers ─────────────────────────────────────────────────────────

fn resolve(host: &str, port: u16) -> SocketAddr {
    format!("{host}:{port}")
        .to_socket_addrs()
        .expect("DNS resolution failed")
        .next()
        .expect("no addresses found")
}

// ── Tests ───────────────────────────────────────────────────────────

#[test]
#[ignore]
fn h3_google() {
    let addr = resolve("www.google.com", 443);
    println!("Connecting to www.google.com ({addr}) ...");

    let mut client = QuicClient::connect(addr, "www.google.com");
    println!("QUIC handshake complete");

    client.send_h3_settings();
    let stream = client.send_get("www.google.com", "/");
    println!("Sent GET / request");

    let (status, headers, body) = client.recv_response(stream);
    println!("Response: HTTP/3 {status}");
    for h in &headers {
        println!(
            "  {}: {}",
            std::str::from_utf8(&h.name).unwrap_or("?"),
            std::str::from_utf8(&h.value).unwrap_or("?"),
        );
    }
    println!("Body: {} bytes", body.len());
    if body.len() < 500 {
        println!("{}", String::from_utf8_lossy(&body));
    }

    assert!(
        status == 200 || status == 301 || status == 302,
        "unexpected status {status}"
    );
    assert!(!body.is_empty(), "empty body");

    client.close();
    println!("Done!");
}

#[test]
#[ignore]
fn h3_cloudflare() {
    let addr = resolve("cloudflare-quic.com", 443);
    println!("Connecting to cloudflare-quic.com ({addr}) ...");

    let mut client = QuicClient::connect(addr, "cloudflare-quic.com");
    println!("QUIC handshake complete");

    client.send_h3_settings();
    let stream = client.send_get("cloudflare-quic.com", "/");
    println!("Sent GET / request");

    let (status, headers, body) = client.recv_response(stream);
    println!("Response: HTTP/3 {status}");
    for h in &headers {
        println!(
            "  {}: {}",
            std::str::from_utf8(&h.name).unwrap_or("?"),
            std::str::from_utf8(&h.value).unwrap_or("?"),
        );
    }
    println!("Body: {} bytes", body.len());

    assert!(
        status == 200 || status == 301 || status == 302 || status == 403,
        "unexpected status {status}"
    );

    client.close();
    println!("Done!");
}

#[test]
#[ignore]
fn h3_meta() {
    let addr = resolve("www.facebook.com", 443);
    println!("Connecting to www.facebook.com ({addr}) ...");

    let mut client = QuicClient::connect(addr, "www.facebook.com");
    println!("QUIC handshake complete");

    client.send_h3_settings();
    let stream = client.send_get("www.facebook.com", "/");
    println!("Sent GET / request");

    let (status, headers, body) = client.recv_response(stream);
    println!("Response: HTTP/3 {status}");
    for h in &headers {
        println!(
            "  {}: {}",
            std::str::from_utf8(&h.name).unwrap_or("?"),
            std::str::from_utf8(&h.value).unwrap_or("?"),
        );
    }
    println!("Body: {} bytes", body.len());

    assert!(status > 0, "no status received");

    client.close();
    println!("Done!");
}
