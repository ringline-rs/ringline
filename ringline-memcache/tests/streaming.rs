//! `gets`, a value cut short by the peer, pooled and sharded GETs, and
//! `set_stream` against an in-process stub server.
//!
//! Mirrors the stub-server pattern used by the redis crate
//! (`ringline-redis/tests/streaming.rs`), so no real Memcached is needed: a
//! `StreamStubServer` handler answers `get`, `gets` and `set` requests with
//! canned replies over a loopback connection.

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder,
};
use ringline_memcache::{Client, Error, SegmentSource};

// ── Config ───────────────────────────────────────────────────────────────

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        .max_connections(64)
        // Large send-pool slot so the server can push a 100 KB value in one send.
        .send_pool(16, 131_072)
        .build()
        .expect("valid config")
}

// ── Canned values ────────────────────────────────────────────────────────

const SMALL: &[u8] = b"hello-streaming-world";
const SMALL_FLAGS: u32 = 7;
const SMALL_CAS: u64 = 424_242;
const LARGE_LEN: usize = 100_000;
const LARGE_FLAGS: u32 = 0xABCD;
const LARGE_CAS: u64 = 9_876_543_210;

/// Streaming-SET value: a deterministic pattern of `SET_LEN` bytes the client
/// streams via `set_stream` and the stub server re-derives to verify it received
/// the exact bytes.
const SET_LEN: usize = 100_000;
const SET_FLAGS: u32 = 0x1234;
const SET_EXPTIME: u32 = 0;
fn set_value() -> Vec<u8> {
    (0..SET_LEN).map(|i| (i % 251) as u8).collect()
}

/// The `stream:short` reply CLAIMS this many value bytes in its `VALUE` header
/// but only sends `SHORT_SENT` of them before the peer FINs — exercising the
/// "peer closes mid-value" short-read path.
const SHORT_CLAIMED_LEN: usize = 1000;
const SHORT_SENT: &[u8] = b"0123456789";

fn large_value() -> Vec<u8> {
    (0..LARGE_LEN).map(|i| (i % 251) as u8).collect()
}

/// Encode a memcache GET hit reply: `VALUE <key> <flags> <bytes>\r\n<data>\r\nEND\r\n`.
fn value_reply(key: &[u8], value: &[u8], flags: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 64);
    out.extend_from_slice(b"VALUE ");
    out.extend_from_slice(key);
    out.extend_from_slice(format!(" {} {}\r\n", flags, value.len()).as_bytes());
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\nEND\r\n");
    out
}

/// Encode a memcache `gets` hit reply (5-token VALUE line, with the extra
/// `<cas>`): `VALUE <key> <flags> <bytes> <cas>\r\n<data>\r\nEND\r\n`.
fn cas_value_reply(key: &[u8], value: &[u8], flags: u32, cas: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 64);
    out.extend_from_slice(b"VALUE ");
    out.extend_from_slice(key);
    out.extend_from_slice(format!(" {} {} {}\r\n", flags, value.len(), cas).as_bytes());
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\nEND\r\n");
    out
}

/// Reply bytes for a `gets <key>` request (CAS-carrying), plus a close flag.
fn decide_cas(key: &[u8]) -> (Vec<u8>, bool) {
    match key {
        b"stream:small" => (cas_value_reply(key, SMALL, SMALL_FLAGS, SMALL_CAS), false),
        b"stream:large" => (
            cas_value_reply(key, &large_value(), LARGE_FLAGS, LARGE_CAS),
            false,
        ),
        // Cache miss: bare END.
        _ => (b"END\r\n".to_vec(), false),
    }
}

/// Reply bytes for a requested key, plus whether the server should CLOSE the
/// connection (send a FIN) right after this reply.
fn decide(key: &[u8]) -> (Vec<u8>, bool) {
    match key {
        b"stream:small" => (value_reply(key, SMALL, SMALL_FLAGS), false),
        b"stream:large" => (value_reply(key, &large_value(), LARGE_FLAGS), false),
        b"stream:short" => {
            // Claim SHORT_CLAIMED_LEN bytes but send only SHORT_SENT, then FIN.
            let mut out = Vec::new();
            out.extend_from_slice(b"VALUE ");
            out.extend_from_slice(key);
            out.extend_from_slice(format!(" 0 {SHORT_CLAIMED_LEN}\r\n").as_bytes());
            out.extend_from_slice(SHORT_SENT);
            (out, true)
        }
        // Cache miss: bare END.
        _ => (b"END\r\n".to_vec(), false),
    }
}

/// Position of the first `\r\n` in `buf` (the index of the `\r`), or `None`.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

// ── Stub server ──────────────────────────────────────────────────────────

struct StreamStubServer;

impl AsyncEventHandler for StreamStubServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_bytes(|bytes| {
                        // Parse one command line per call.
                        let Some(cr) = find_crlf(&bytes) else {
                            return ParseResult::NeedMore;
                        };
                        let line = &bytes[..cr];
                        let header_len = cr + 2;
                        if let Some(key) = line.strip_prefix(b"gets ") {
                            // `gets <key>` — CAS-carrying reply.
                            let (reply, should_close) = decide_cas(key);
                            let _ = tx.send(&reply);
                            if should_close {
                                tx.close();
                            }
                            ParseResult::Consumed(header_len)
                        } else if let Some(key) = line.strip_prefix(b"get ") {
                            let (reply, should_close) = decide(key);
                            let _ = tx.send(&reply);
                            if should_close {
                                // Send has been queued; closing the connection
                                // FINs after the queued bytes drain, giving the
                                // client a short reply followed by peer EOF.
                                tx.close();
                            }
                            ParseResult::Consumed(header_len)
                        } else if line.starts_with(b"set ") {
                            // `set <key> <flags> <exp> <len>\r\n<value>\r\n`.
                            // Wait for the whole command (header + value + CRLF)
                            // before replying, then verify the exact value bytes.
                            let mut fields = line.split(|&b| b == b' ').filter(|f| !f.is_empty());
                            let _set = fields.next();
                            let _key = fields.next();
                            let _flags = fields.next();
                            let _exp = fields.next();
                            let len: usize = fields
                                .next()
                                .and_then(|t| std::str::from_utf8(t).ok())
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            let total = header_len + len + 2; // value + trailing CRLF
                            if bytes.len() < total {
                                return ParseResult::NeedMore;
                            }
                            let value = &bytes[header_len..header_len + len];
                            let reply: &[u8] = if value == set_value().as_slice() {
                                b"STORED\r\n"
                            } else {
                                b"SERVER_ERROR value mismatch\r\n"
                            };
                            let _ = tx.send(reply);
                            ParseResult::Consumed(total)
                        } else {
                            // Unknown line — consume it.
                            ParseResult::Consumed(header_len)
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
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
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
        .await
        .map_err(|e| format!("connect: {e}"))?;
    Ok(Client::new(conn))
}

async fn run_client(addr: SocketAddr) -> Result<(), String> {
    run_gets(addr).await?;
    run_short_get(addr).await?;
    run_pool_get(addr).await?;
    run_sharded_get(addr).await?;
    run_set_stream(addr).await?;

    Ok(())
}

// ── gets (values with their CAS tokens) ─────────────────────────────────────

async fn run_gets(addr: SocketAddr) -> Result<(), String> {
    let mut client = connect(addr).await?;
    for (key, want, flags, cas) in [
        (&b"stream:small"[..], SMALL.to_vec(), SMALL_FLAGS, SMALL_CAS),
        (&b"stream:large"[..], large_value(), LARGE_FLAGS, LARGE_CAS),
    ] {
        let mut got = client
            .gets(&[key])
            .await
            .map_err(|e| format!("gets: {e}"))?;
        let v = got.pop().ok_or("gets: no value")?;
        if v.data.as_ref() != want.as_slice() || v.flags != flags || v.cas != Some(cas) {
            return Err(format!(
                "gets {}: {} bytes, flags {}, cas {:?}",
                String::from_utf8_lossy(key),
                v.data.len(),
                v.flags,
                v.cas
            ));
        }
    }
    let miss = client
        .gets(&[b"stream:absent"])
        .await
        .map_err(|e| format!("gets miss: {e}"))?;
    if !miss.is_empty() {
        return Err(format!("gets miss returned {} values", miss.len()));
    }
    Ok(())
}

// ── A peer that closes partway through a value ─────────────────────────────

async fn run_short_get(addr: SocketAddr) -> Result<(), String> {
    let mut client = connect(addr).await?;
    match client.get(b"stream:short").await {
        Err(Error::ConnectionClosed) => Ok(()),
        other => Err(format!("short get: {other:?}")),
    }
}

// ── Pool and sharded GETs ──────────────────────────────────────────────────

/// A sharded client reads a value larger than one receive buffer.
async fn run_sharded_get(addr: SocketAddr) -> Result<(), String> {
    use ringline_memcache::{ShardedClient, ShardedConfig};

    let mut sharded = ShardedClient::new(ShardedConfig::new(vec![addr]));
    sharded
        .connect_all()
        .await
        .map_err(|e| format!("sharded connect: {e}"))?;
    let large = sharded
        .get("stream:large")
        .await
        .map_err(|e| format!("sharded large get: {e}"))?
        .ok_or("sharded large: None")?;
    if large.data.as_ref() != large_value().as_slice() {
        return Err("sharded large mismatch".into());
    }
    sharded.close_all();
    Ok(())
}

/// A pooled client reads small and large values.
async fn run_pool_get(addr: SocketAddr) -> Result<(), String> {
    use ringline_memcache::{Pool, PoolConfig};

    let pool = Pool::new(PoolConfig::new(addr, 1));
    let mut client = pool
        .client()
        .await
        .map_err(|e| format!("pool client: {e}"))?;
    for (key, want) in [
        (&b"stream:small"[..], SMALL.to_vec()),
        (&b"stream:large"[..], large_value()),
    ] {
        let got = client
            .get(key)
            .await
            .map_err(|e| format!("pool get: {e}"))?
            .ok_or("pool get: None")?;
        if got.data.as_ref() != want.as_slice() {
            return Err("pool get mismatch".into());
        }
    }
    Ok(())
}

fn chunked(value: &[u8], chunk: usize) -> std::vec::IntoIter<Bytes> {
    value
        .chunks(chunk)
        .map(Bytes::copy_from_slice)
        .collect::<Vec<_>>()
        .into_iter()
}

async fn run_set_stream(addr: SocketAddr) -> Result<(), String> {
    let value = set_value();

    // (a) happy path: server verifies the exact streamed value → STORED.
    {
        let mut client = connect(addr).await?;
        client
            .set_stream(
                b"stream:setlarge",
                SET_FLAGS,
                SET_EXPTIME,
                SET_LEN,
                chunked(&value, 7000),
            )
            .await
            .map_err(|e| format!("set_stream: {e}"))?;
        // Connection still usable after a successful streaming set.
        let after = client
            .get(b"stream:small")
            .await
            .map_err(|e| format!("get after set_stream: {e}"))?
            .ok_or("get after set_stream: None")?;
        if after.data.as_ref() != SMALL {
            return Err("desync after set_stream".into());
        }
    }

    // (b) under-produce: source yields fewer than `len` bytes → LengthMismatch,
    // and the connection is poisoned (next op errors).
    {
        let mut client = connect(addr).await?;
        let short = value[..SET_LEN - 100].to_vec();
        match client
            .set_stream(
                b"stream:setlarge",
                SET_FLAGS,
                SET_EXPTIME,
                SET_LEN,
                chunked(&short, 7000),
            )
            .await
        {
            Err(Error::LengthMismatch) => { /* expected */ }
            Err(e) => return Err(format!("under-produce: wrong error {e}")),
            Ok(()) => return Err("under-produce: unexpectedly succeeded".into()),
        }
        match client.get(b"stream:small").await {
            Ok(_) => return Err("under-produce: next op unexpectedly succeeded".into()),
            Err(_) => { /* expected: poisoned */ }
        }
    }

    // (c) over-produce: source yields more than `len` bytes → LengthMismatch.
    {
        let mut client = connect(addr).await?;
        let mut over = value.clone();
        over.extend_from_slice(b"EXTRA-BYTES");
        match client
            .set_stream(
                b"stream:setlarge",
                SET_FLAGS,
                SET_EXPTIME,
                SET_LEN,
                chunked(&over, 7000),
            )
            .await
        {
            Err(Error::LengthMismatch) => { /* expected */ }
            Err(e) => return Err(format!("over-produce: wrong error {e}")),
            Ok(()) => return Err("over-produce: unexpectedly succeeded".into()),
        }
    }

    // (d) source error mid-stream: `next_chunk` returns an error after the value
    // header (and some value bytes) are already on the wire. The error must
    // propagate AND the connection must be poisoned (closed) — otherwise a pooled
    // reuse would feed the next caller's bytes into this half-written frame.
    // Regression for the set_stream no-poison bug.
    {
        /// Yields `ok_chunks` 1 KiB chunks, then errors — a value source that
        /// fails partway (I/O, decode, etc.).
        struct FailingSource {
            ok_chunks: usize,
        }
        impl SegmentSource for FailingSource {
            fn next_chunk(&mut self) -> Result<Option<Bytes>, Error> {
                if self.ok_chunks == 0 {
                    return Err(Error::Io(std::io::Error::other("source boom")));
                }
                self.ok_chunks -= 1;
                Ok(Some(Bytes::from_static(&[b'x'; 1000])))
            }
        }

        let mut client = connect(addr).await?;
        match client
            .set_stream(
                b"stream:setlarge",
                SET_FLAGS,
                SET_EXPTIME,
                SET_LEN,
                FailingSource { ok_chunks: 2 },
            )
            .await
        {
            Err(Error::Io(_)) => { /* expected: the source error propagated */ }
            Err(e) => return Err(format!("source-error: wrong error {e}")),
            Ok(()) => return Err("source-error: unexpectedly succeeded".into()),
        }
        // Poisoned: the next op on this connection must fail rather than run on a
        // desynced connection.
        match client.get(b"stream:small").await {
            Ok(_) => {
                return Err("source-error: next op succeeded — connection not poisoned".into());
            }
            Err(_) => { /* expected: poisoned */ }
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

#[test]
fn streaming_and_gets_end_to_end() {
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<StreamStubServer>()
        .expect("server launch failed");
    let addr = s_shutdown.bound_addr().expect("bound address").to_string();
    wait_for_server(&addr);

    SERVER_ADDR.set(addr.parse().unwrap()).ok();

    let (c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<ClientHandler>()
        .expect("client launch failed");

    common::join_workers(&c_shutdown, c_handles);

    let result = RESULT.get().expect("client did not set result");
    if let Err(e) = result {
        panic!("streaming test failed: {e}");
    }

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
