//! Integration tests against public HTTP/2 servers.
//!
//! These tests are `#[ignore]` by default because they require network access.
//! Run them manually with:
//!
//!   cargo test -p ringline-h2 --test public_servers -- --ignored --nocapture

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use ringline_h2::{H2Connection, H2Event, HeaderField, Settings};

// -- TLS client with real certs --

fn h2_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

struct H2Client {
    tls_conn: rustls::ClientConnection,
    tcp: TcpStream,
    h2: H2Connection,
}

impl H2Client {
    fn connect(addr: SocketAddr, server_name: &str) -> Self {
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        tcp.set_nodelay(true).unwrap();

        let tls_config = h2_client_config();
        let server_name = server_name.to_string().try_into().unwrap();
        let tls_conn = rustls::ClientConnection::new(tls_config, server_name).unwrap();
        let h2 = H2Connection::new(Settings::client_default());

        let mut client = H2Client { tls_conn, tcp, h2 };

        // TLS handshake.
        client.drive_tls();

        // Send HTTP/2 preface.
        let preface = client.h2.take_pending_send();
        client.tls_write(&preface);
        client.flush_tls();

        // Wait for server SETTINGS.
        client.drive_until_ready();

        client
    }

    fn tls_write(&mut self, data: &[u8]) {
        self.tls_conn.writer().write_all(data).unwrap();
    }

    fn flush_tls(&mut self) {
        while self.tls_conn.wants_write() {
            self.tls_conn.write_tls(&mut self.tcp).unwrap();
        }
    }

    fn read_tls(&mut self) -> bool {
        match self.tls_conn.read_tls(&mut self.tcp) {
            Ok(0) => return false,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return false,
            Err(e) => panic!("tcp read error: {e}"),
        }
        self.tls_conn.process_new_packets().unwrap();
        self.flush_tls();
        true
    }

    fn drive_tls(&mut self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
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
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "waiting for server SETTINGS timed out"
            );
            self.read_tls();
            let mut plaintext = vec![0u8; 65536];
            match self.tls_conn.reader().read(&mut plaintext) {
                Ok(n) if n > 0 => {
                    self.h2.recv(&plaintext[..n]).unwrap();
                }
                _ => {}
            }
            if self.h2.has_pending_send() {
                let data = self.h2.take_pending_send();
                self.tls_write(&data);
                self.flush_tls();
            }
            while let Some(event) = self.h2.poll_event() {
                if matches!(event, H2Event::SettingsAcknowledged) {
                    return;
                }
            }
        }
    }

    fn send_get(&mut self, authority: &str, path: &str) -> u32 {
        let headers = vec![
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(":path", path),
            HeaderField::new(b":scheme", b"https"),
            HeaderField::new(":authority", authority),
            HeaderField::new(b"user-agent", b"ringline-h2/0.1"),
            HeaderField::new(b"accept", b"*/*"),
        ];
        let stream_id = self.h2.send_request(&headers, true).unwrap();
        let data = self.h2.take_pending_send();
        self.tls_write(&data);
        self.flush_tls();
        stream_id
    }

    fn recv_response(&mut self, stream_id: u32) -> (u16, Vec<HeaderField>, Vec<u8>) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
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
                Ok(n) if n > 0 => {
                    self.h2.recv(&plaintext[..n]).unwrap();
                }
                _ => {}
            }
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

        let status = resp_headers
            .iter()
            .find(|h| h.name == b":status")
            .map(|h| {
                std::str::from_utf8(&h.value)
                    .unwrap()
                    .parse::<u16>()
                    .unwrap()
            })
            .unwrap_or(0);

        (status, resp_headers, resp_body)
    }
}

// -- Helpers --

fn resolve(host: &str, port: u16) -> SocketAddr {
    format!("{host}:{port}")
        .to_socket_addrs()
        .expect("DNS resolution failed")
        .next()
        .expect("no addresses found")
}

// -- Tests --

#[test]
#[ignore]
fn h2_google() {
    let addr = resolve("www.google.com", 443);
    println!("Connecting to www.google.com ({addr}) ...");

    let mut client = H2Client::connect(addr, "www.google.com");
    println!("TLS + HTTP/2 handshake complete");

    let stream = client.send_get("www.google.com", "/");
    println!("Sent GET / request");

    let (status, headers, body) = client.recv_response(stream);
    println!("Response: HTTP/2 {status}");
    for h in &headers {
        println!(
            "  {}: {}",
            std::str::from_utf8(&h.name).unwrap_or("?"),
            std::str::from_utf8(&h.value).unwrap_or("?"),
        );
    }
    println!("Body: {} bytes", body.len());

    assert!(
        status == 200 || status == 301 || status == 302,
        "unexpected status {status}"
    );
    assert!(!body.is_empty(), "empty body");
}

#[test]
#[ignore]
fn h2_cloudflare() {
    let addr = resolve("cloudflare.com", 443);
    println!("Connecting to cloudflare.com ({addr}) ...");

    let mut client = H2Client::connect(addr, "cloudflare.com");
    println!("TLS + HTTP/2 handshake complete");

    let stream = client.send_get("cloudflare.com", "/");
    println!("Sent GET / request");

    let (status, headers, body) = client.recv_response(stream);
    println!("Response: HTTP/2 {status}");
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
}
