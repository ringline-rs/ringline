#![allow(clippy::manual_async_fn)]
//! Integration tests for `ConnStream`: `AsyncRead`, `AsyncWrite`, `AsyncBufRead`.

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use ringline::{AsyncEventHandler, Config, ConnCtx, ConnStream, RinglineBuilder};

// ── Stream-based echo handler ────────────────────────────────────────

struct StreamEcho;

impl AsyncEventHandler for StreamEcho {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let mut stream = ConnStream::new(conn);
            loop {
                let data = match futures_util::AsyncBufReadExt::fill_buf(&mut stream).await {
                    Ok([]) => break, // EOF
                    Ok(buf) => buf.to_vec(),
                    Err(_) => break,
                };
                let n = data.len();
                if stream.write_all(&data).await.is_err() {
                    break;
                }
                futures_util::AsyncBufReadExt::consume_unpin(&mut stream, n);
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        StreamEcho
    }
}

// ── AsyncRead-based echo handler ─────────────────────────────────────

struct ReadEcho;

impl AsyncEventHandler for ReadEcho {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let mut stream = ConnStream::new(conn);
            let mut buf = [0u8; 4096];
            loop {
                let n = match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ReadEcho
    }
}

// ── Handler that counts EOF via poll_close ───────────────────────────

struct CloseCounter {
    closed: Arc<AtomicUsize>,
}

impl AsyncEventHandler for CloseCounter {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        let closed = self.closed.clone();
        async move {
            let mut stream = ConnStream::new(conn);
            // Echo once, then close.
            let mut buf = [0u8; 256];
            if let Ok(n) = stream.read(&mut buf).await
                && n > 0
            {
                let _ = stream.write_all(&buf[..n]).await;
            }
            // Explicitly close the stream.
            let _ = futures_util::AsyncWriteExt::close(&mut stream).await;
            closed.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        CloseCounter {
            closed: Arc::new(AtomicUsize::new(0)),
        }
    }
}

// ── Small-read handler (reads 1 byte at a time) ─────────────────────

struct TinyReadEcho;

impl AsyncEventHandler for TinyReadEcho {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let mut stream = ConnStream::new(conn);
            let mut byte = [0u8; 1];
            loop {
                match stream.read(&mut byte).await {
                    Ok(0) => break,
                    Ok(_) => {
                        if stream.write_all(&byte).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        TinyReadEcho
    }
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
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

fn echo_round_trip(addr: &str, msg: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(msg).unwrap();
    stream.flush().unwrap();

    let mut buf = vec![0u8; msg.len()];
    let mut total = 0;
    while total < msg.len() {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("read error: {e}"),
        }
    }
    buf.truncate(total);
    buf
}

// ── Tests ────────────────────────────────────────────────────────────

#[test]
fn stream_echo_bufread() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let bind: std::net::SocketAddr = addr.parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(bind)
        .launch::<StreamEcho>()
        .unwrap();

    wait_for_server(&addr);

    let msg = b"hello from ConnStream";
    let got = echo_round_trip(&addr, msg);
    assert_eq!(got, msg);

    // Multi-round trip.
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for i in 0..10 {
        let payload = format!("message {i}");
        stream.write_all(payload.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, payload.as_bytes());
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn stream_echo_async_read() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let bind: std::net::SocketAddr = addr.parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(bind)
        .launch::<ReadEcho>()
        .unwrap();

    wait_for_server(&addr);

    let msg = b"async read echo test";
    let got = echo_round_trip(&addr, msg);
    assert_eq!(got, msg);

    // Larger payload.
    let big = vec![0xABu8; 8192];
    let got = echo_round_trip(&addr, &big);
    assert_eq!(got, big);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// EOF: client disconnects cleanly, server sees Ok(0) from read.
#[test]
fn stream_eof_on_client_close() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let bind: std::net::SocketAddr = addr.parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(bind)
        .launch::<ReadEcho>()
        .unwrap();

    wait_for_server(&addr);

    // Connect, send nothing, close immediately.
    let stream = TcpStream::connect(&addr).unwrap();
    drop(stream);

    // Connect, send data, read echo, then close.
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"bye").unwrap();
    let mut buf = [0u8; 3];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"bye");
    drop(stream);

    // Small delay so server processes the close.
    std::thread::sleep(Duration::from_millis(50));

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// poll_close (shutdown_write) doesn't panic and the handler completes cleanly.
#[test]
fn stream_poll_close() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let bind: std::net::SocketAddr = addr.parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(bind)
        .launch::<CloseCounter>()
        .unwrap();

    wait_for_server(&addr);

    // Send data, get echo. The handler calls close() then returns.
    let msg = b"ping";
    let got = echo_round_trip(&addr, msg);
    assert_eq!(got, msg);

    // Do it a few times to exercise close on multiple connections.
    for _ in 0..5 {
        let got = echo_round_trip(&addr, b"test");
        assert_eq!(got, b"test");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Multiple concurrent connections on the same server.
#[test]
fn stream_concurrent_connections() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let bind: std::net::SocketAddr = addr.parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(bind)
        .launch::<StreamEcho>()
        .unwrap();

    wait_for_server(&addr);

    let threads: Vec<_> = (0..8)
        .map(|i| {
            let addr = addr.clone();
            std::thread::spawn(move || {
                let mut stream = TcpStream::connect(&addr).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                for j in 0..5 {
                    let msg = format!("conn{i}-msg{j}");
                    stream.write_all(msg.as_bytes()).unwrap();
                    stream.flush().unwrap();
                    let mut buf = vec![0u8; msg.len()];
                    stream.read_exact(&mut buf).unwrap();
                    assert_eq!(buf, msg.as_bytes());
                }
            })
        })
        .collect();

    for t in threads {
        t.join().unwrap();
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Small 1-byte reads exercise the accumulator drain path thoroughly.
#[test]
fn stream_tiny_reads() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let bind: std::net::SocketAddr = addr.parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(bind)
        .launch::<TinyReadEcho>()
        .unwrap();

    wait_for_server(&addr);

    let msg = b"abcdefghijklmnop";
    let got = echo_round_trip(&addr, msg);
    assert_eq!(got, msg);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Large payload that exceeds a single send pool slot (default 16384 bytes).
/// Exercises partial writes in poll_write.
#[test]
fn stream_large_payload() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let bind: std::net::SocketAddr = addr.parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind(bind)
        .launch::<ReadEcho>()
        .unwrap();

    wait_for_server(&addr);

    // 64 KiB — larger than the default 16 KiB slot size, so write_all will
    // need multiple poll_write calls internally.
    let big = vec![0x42u8; 65536];
    let got = echo_round_trip(&addr, &big);
    assert_eq!(got, big);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
