//! Streaming GET (`Client::get_stream` / `ValueStream`) integration tests.
//!
//! Mirrors the in-process stub-server pattern in `parse_error.rs` (no real Redis
//! needed): a `StreamStubServer` handler answers GETs with canned `$<len>\r\n…`
//! bulk replies, and a client handler drives `get_stream` against it over a real
//! loopback io_uring connection.
//!
//! The whole file is gated on `has_io_uring` — segmented recv (and therefore
//! `get_stream`) is an io_uring-only API. On the mio backend / macOS the file
//! compiles to nothing, matching the runtime.
#![cfg(has_io_uring)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use resp_proto::Value;
use ringline::{AsyncEventHandler, Config, ConfigBuilder, ConnCtx, ParseResult, RinglineBuilder};
use ringline_redis::Client;

// ── Config ───────────────────────────────────────────────────────────────

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        // Small provided buffers so a large value spans many recv segments
        // (exercises the multi-buffer path).
        .recv_buffer(128, 4096)
        .max_connections(64)
        // Large send-pool slot so the server can push a 100 KB value in one send.
        .send_pool(16, 131_072)
        .build()
        .expect("valid config")
}

// ── Canned values ────────────────────────────────────────────────────────

const SMALL: &[u8] = b"hello-streaming-world";
const LARGE_LEN: usize = 100_000;
const POISON_LEN: usize = 20_000;

fn large_value() -> Vec<u8> {
    (0..LARGE_LEN).map(|i| (i % 251) as u8).collect()
}
fn poison_value() -> Vec<u8> {
    (0..POISON_LEN).map(|i| (i % 241) as u8).collect()
}

/// Encode a RESP bulk-string reply `$<len>\r\n<value>\r\n`.
fn bulk_reply(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 16);
    out.extend_from_slice(format!("${}\r\n", value.len()).as_bytes());
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
    out
}

/// Reply bytes for a requested key.
fn decide(key: &[u8]) -> Vec<u8> {
    match key {
        b"stream:small" => bulk_reply(SMALL),
        b"stream:large" => bulk_reply(&large_value()),
        b"stream:poison" => bulk_reply(&poison_value()),
        _ => b"$-1\r\n".to_vec(),
    }
}

// ── Stub server ──────────────────────────────────────────────────────────

struct StreamStubServer;

impl AsyncEventHandler for StreamStubServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_bytes(|bytes| {
                        let len = bytes.len();
                        match Value::parse_bytes(bytes) {
                            Ok((val, consumed)) => {
                                if let Value::Array(items) = &val
                                    && let Some(Value::BulkString(key)) = items.get(1)
                                {
                                    let reply = decide(&key[..]);
                                    let _ = conn.send_nowait(&reply);
                                }
                                ParseResult::Consumed(consumed)
                            }
                            Err(e) if e.is_incomplete() => ParseResult::NeedMore,
                            Err(_) => ParseResult::Consumed(len),
                        }
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        StreamStubServer
    }
}

// ── Client driver ────────────────────────────────────────────────────────

static SERVER_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static RESULT: OnceLock<Result<(), String>> = OnceLock::new();

struct ClientHandler;

impl AsyncEventHandler for ClientHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let addr = *SERVER_ADDR.get().expect("server addr");
        Some(Box::pin(async move {
            RESULT.set(run_client(addr).await).ok();
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        ClientHandler
    }
}

async fn connect(addr: SocketAddr) -> Result<Client, String> {
    let conn = ringline::connect(addr)
        .map_err(|e| format!("submit: {e}"))?
        .await
        .map_err(|e| format!("connect: {e}"))?;
    Ok(Client::new(conn))
}

async fn run_client(addr: SocketAddr) -> Result<(), String> {
    // ── (a) small value: collect() == get() ──────────────────────────────
    let mut client = connect(addr).await?;
    {
        let stream = client
            .get_stream(b"stream:small")
            .await
            .map_err(|e| format!("small get_stream: {e}"))?
            .ok_or("small: unexpected None")?;
        if stream.len() != SMALL.len() {
            return Err(format!("small len: {} != {}", stream.len(), SMALL.len()));
        }
        let collected = stream
            .collect()
            .await
            .map_err(|e| format!("small collect: {e}"))?;
        if collected.as_ref() != SMALL {
            return Err(format!("small collect mismatch: {collected:?}"));
        }
    }
    // Same value via the materialized get() — connection still usable, results equal.
    let materialized = client
        .get(b"stream:small")
        .await
        .map_err(|e| format!("small get: {e}"))?
        .ok_or("small get: None")?;
    if materialized.as_ref() != SMALL {
        return Err("small get != get_stream".into());
    }

    // ── (b) large value: collect() reassembles across many buffers ────────
    let expected_large = large_value();
    {
        let stream = client
            .get_stream(b"stream:large")
            .await
            .map_err(|e| format!("large get_stream: {e}"))?
            .ok_or("large: None")?;
        if stream.len() != LARGE_LEN {
            return Err(format!("large len: {}", stream.len()));
        }
        let collected = stream
            .collect()
            .await
            .map_err(|e| format!("large collect: {e}"))?;
        if collected.len() != LARGE_LEN || collected.as_ref() != expected_large.as_slice() {
            return Err("large collect mismatch".into());
        }
    }

    // Large value via next_segment(): chunks must reassemble to the same bytes,
    // and no chunk may exceed the remaining value length (bounded to len).
    {
        let mut stream = client
            .get_stream(b"stream:large")
            .await
            .map_err(|e| format!("large2 get_stream: {e}"))?
            .ok_or("large2: None")?;
        let mut assembled = Vec::with_capacity(LARGE_LEN);
        while let Some(chunk) = stream
            .next_segment()
            .await
            .map_err(|e| format!("large2 next_segment: {e}"))?
        {
            assembled.extend_from_slice(&chunk);
            if assembled.len() > LARGE_LEN {
                return Err("next_segment over-read past len".into());
            }
        }
        if assembled != expected_large {
            return Err("large next_segment reassembly mismatch".into());
        }
    }

    // ── (b') discard() leaves the connection usable for the NEXT command ──
    {
        let stream = client
            .get_stream(b"stream:large")
            .await
            .map_err(|e| format!("discard get_stream: {e}"))?
            .ok_or("discard: None")?;
        stream
            .discard()
            .await
            .map_err(|e| format!("discard: {e}"))?;
    }
    // No desync: a plain command right after discard must succeed and be correct.
    let after_discard = client
        .get(b"stream:small")
        .await
        .map_err(|e| format!("get after discard: {e}"))?
        .ok_or("get after discard: None")?;
    if after_discard.as_ref() != SMALL {
        return Err("desync after discard".into());
    }

    // ── (c) nil → Ok(None) ────────────────────────────────────────────────
    // `.is_some()` consumes the Option immediately so the `&mut client` borrow
    // (held by the `ValueStream`'s Drop) is released before the next call.
    let nil_present = client
        .get_stream(b"stream:nil")
        .await
        .map_err(|e| format!("nil get_stream: {e}"))?
        .is_some();
    if nil_present {
        return Err("nil: expected None".into());
    }
    // Connection still usable after a nil stream.
    let after_nil = client
        .get(b"stream:small")
        .await
        .map_err(|e| format!("get after nil: {e}"))?
        .ok_or("get after nil: None")?;
    if after_nil.as_ref() != SMALL {
        return Err("desync after nil".into());
    }

    // NOTE: a short-FIN test (server claims N bytes, sends fewer, then closes)
    // is DEFERRED. `ValueStream::refill` maps a runtime `None` (EOF) to an error
    // — correct by construction — but the underlying runtime does not currently
    // surface EOF to a parked `recv_owned_segment` reader when the peer FINs on a
    // *segmented* connection (the FIN CQE is not observed on the segmented recv),
    // so the scenario hangs rather than erroring. This is a runtime segmented-recv
    // gap to fix separately, not a defect in this client code.

    // ── (d) undrained drop poisons the connection ────────────────────────
    {
        let mut pclient = connect(addr).await?;
        {
            let mut stream = pclient
                .get_stream(b"stream:poison")
                .await
                .map_err(|e| format!("poison get_stream: {e}"))?
                .ok_or("poison: None")?;
            // Pull one chunk (value not fully consumed), then drop mid-stream.
            let first = stream
                .next_segment()
                .await
                .map_err(|e| format!("poison next_segment: {e}"))?
                .ok_or("poison: first chunk None")?;
            if first.len() >= POISON_LEN {
                return Err("poison value did not span multiple buffers".into());
            }
            // `stream` dropped here undrained → connection poisoned (close()).
        }
        // The next op must error (stale slot after the poison close).
        match pclient.get(b"stream:small").await {
            Ok(_) => return Err("poison: next op unexpectedly succeeded".into()),
            Err(_) => { /* expected */ }
        }
    }

    Ok(())
}

// ── Test ─────────────────────────────────────────────────────────────────

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[test]
fn get_stream_end_to_end() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<StreamStubServer>()
        .expect("server launch failed");
    wait_for_server(&addr);

    SERVER_ADDR.set(addr.parse().unwrap()).ok();

    let (_c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<ClientHandler>()
        .expect("client launch failed");

    for h in c_handles {
        h.join().unwrap().unwrap();
    }

    let result = RESULT.get().expect("client did not set result");
    if let Err(e) = result {
        panic!("streaming test failed: {e}");
    }

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
