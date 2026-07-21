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

use bytes::Bytes;
use resp_proto::Value;
use ringline::{AsyncEventHandler, Config, ConfigBuilder, ConnCtx, ParseResult, RinglineBuilder};
use ringline_redis::{Client, Error, OpKind, SegmentSource};

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

/// Streaming-SET value: a deterministic pattern of `SET_LEN` bytes the client
/// streams via `set_stream` and the stub server re-derives to verify it received
/// the exact bytes.
const SET_LEN: usize = 100_000;
fn set_value() -> Vec<u8> {
    (0..SET_LEN).map(|i| (i % 251) as u8).collect()
}

/// The `stream:short` reply CLAIMS this many value bytes in its `$<len>\r\n`
/// header but only sends `SHORT_SENT` of them before the peer FINs — exercising
/// the "peer closes mid-value" short-read path.
const SHORT_CLAIMED_LEN: usize = 1000;
const SHORT_SENT: &[u8] = b"0123456789";

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

/// Reply bytes for a requested key, plus whether the server should CLOSE the
/// connection (send a FIN) right after this reply.
fn decide(key: &[u8]) -> (Vec<u8>, bool) {
    match key {
        b"stream:small" => (bulk_reply(SMALL), false),
        b"stream:large" => (bulk_reply(&large_value()), false),
        b"stream:poison" => (bulk_reply(&poison_value()), false),
        b"stream:short" => {
            // Claim SHORT_CLAIMED_LEN bytes but send only SHORT_SENT, then FIN.
            let mut out = format!("${SHORT_CLAIMED_LEN}\r\n").into_bytes();
            out.extend_from_slice(SHORT_SENT);
            (out, true)
        }
        b"borrow:unexpected" => {
            // A non-`$`/`-` reply type (RESP integer) to a GET. The borrow-GET's
            // byte-at-a-time header parse errors on the first byte, leaving
            // `5\r\n` on the wire → the connection is desynced and must poison.
            (b":5\r\n".to_vec(), false)
        }
        _ => (b"$-1\r\n".to_vec(), false),
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
                                let mut close_after = false;
                                if let Value::Array(items) = &val
                                    && let Some(Value::BulkString(verb)) = items.first()
                                {
                                    if verb.eq_ignore_ascii_case(b"SET") {
                                        // `SET <key> <value>` (streaming set): verify
                                        // the exact value bytes, reply +OK / -ERR.
                                        let reply: &[u8] = match items.get(2) {
                                            Some(Value::BulkString(v))
                                                if v[..] == set_value()[..] =>
                                            {
                                                b"+OK\r\n"
                                            }
                                            _ => b"-ERR value mismatch\r\n",
                                        };
                                        let _ = conn.send_nowait(reply);
                                    } else if verb.eq_ignore_ascii_case(b"DEL") {
                                        // `DEL <key>`: reply with the deleted-key
                                        // count (a RESP integer).
                                        let _ = conn.send_nowait(b":1\r\n");
                                    } else if let Some(Value::BulkString(key)) = items.get(1) {
                                        // `GET <key>`.
                                        let (reply, should_close) = decide(&key[..]);
                                        let _ = conn.send_nowait(&reply);
                                        close_after = should_close;
                                    }
                                }
                                if close_after {
                                    // Send has been queued; closing the connection
                                    // FINs after the queued bytes drain, giving the
                                    // client a short reply followed by peer EOF.
                                    conn.close();
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

    // ── (c') short FIN: server claims N bytes, sends fewer, then closes ───
    // The header parses fine and a `ValueStream` is created, but the value body
    // is truncated by a peer FIN mid-stream. `ValueStream::refill` maps the
    // runtime EOF (`recv_owned_segment() -> Ok(None)`) to a short-read error, so
    // `collect()` must ERROR (not hang, not return truncated bytes). Regression
    // for: a parked segmented reader must observe a peer FIN as EOF.
    {
        let stream = client
            .get_stream(b"stream:short")
            .await
            .map_err(|e| format!("short get_stream: {e}"))?
            .ok_or("short: unexpected None")?;
        // Header claimed SHORT_CLAIMED_LEN value bytes.
        if stream.len() != SHORT_CLAIMED_LEN {
            return Err(format!(
                "short len: {} != {SHORT_CLAIMED_LEN}",
                stream.len()
            ));
        }
        match stream.collect().await {
            Ok(v) => {
                return Err(format!(
                    "short: expected an error on truncated value, got {} bytes",
                    v.len()
                ));
            }
            Err(_) => { /* expected: peer FIN mid-value surfaces as an error */ }
        }
    }

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

    run_set_stream(addr).await?;
    run_pool_stream(addr).await?;
    run_borrow_get(addr).await?;
    run_recv_meta(addr).await?;

    Ok(())
}

// ── recv_meta (uniform zero-copy metadata for GET/SET/DEL) ─────────────────

async fn run_recv_meta(addr: SocketAddr) -> Result<(), String> {
    // (a) GET hit → kind Get, success, value_len Some(len), user_data preserved.
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"stream:small", 1)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client
            .recv_meta()
            .await
            .map_err(|e| format!("get hit recv_meta: {e}"))?;
        if m.kind != OpKind::Get
            || !m.success
            || m.value_len != Some(SMALL.len())
            || m.user_data != 1
        {
            return Err(format!("get hit meta wrong: {m:?}"));
        }
    }

    // (b) GET miss → success, value_len None.
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"stream:absent", 2)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client
            .recv_meta()
            .await
            .map_err(|e| format!("get miss recv_meta: {e}"))?;
        if !m.success || m.value_len.is_some() {
            return Err(format!("get miss meta wrong: {m:?}"));
        }
    }

    // (c) GET large spanning many provided buffers → value_len Some(large len).
    {
        let large = large_value();
        let mut client = connect(addr).await?;
        client
            .fire_get(b"stream:large", 3)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client
            .recv_meta()
            .await
            .map_err(|e| format!("get large recv_meta: {e}"))?;
        if m.value_len != Some(large.len()) {
            return Err(format!("get large meta wrong: {m:?}"));
        }
    }

    // (d) SET ok (stub verifies the exact value → +OK) → kind Set, success.
    {
        let mut client = connect(addr).await?;
        client
            .fire_set(b"k:set", &set_value(), 4)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client
            .recv_meta()
            .await
            .map_err(|e| format!("set recv_meta: {e}"))?;
        if m.kind != OpKind::Set || !m.success || m.value_len.is_some() {
            return Err(format!("set meta wrong: {m:?}"));
        }
    }

    // (e) DEL (stub replies `:1`) → kind Del, success, value_len None.
    {
        let mut client = connect(addr).await?;
        client
            .fire_del(b"k:del", 5)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client
            .recv_meta()
            .await
            .map_err(|e| format!("del recv_meta: {e}"))?;
        if m.kind != OpKind::Del || !m.success || m.value_len.is_some() {
            return Err(format!("del meta wrong: {m:?}"));
        }
    }

    // (f) unexpected reply type to a GET → Err(UnexpectedResponse) + poison
    // (next op on the connection fails).
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"borrow:unexpected", 6)
            .map_err(|e| format!("fire: {e}"))?;
        match client.recv_meta().await {
            Ok(m) => return Err(format!("unexpected reply should Err, got {m:?}")),
            Err(Error::UnexpectedResponse) => { /* expected */ }
            Err(e) => return Err(format!("unexpected reply wrong error: {e}")),
        }
        if client.get(b"stream:small").await.is_ok() {
            return Err("recv_meta unexpected: next op unexpectedly succeeded".into());
        }
    }

    // (g) mixed pipeline: GET, SET, DEL, GET — metadata returns in order with the
    // right kinds/user_data (no peek, one uniform call).
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"stream:small", 10)
            .map_err(|e| format!("fire: {e}"))?;
        client
            .fire_set(b"k:set", &set_value(), 11)
            .map_err(|e| format!("fire: {e}"))?;
        client
            .fire_del(b"k:del", 12)
            .map_err(|e| format!("fire: {e}"))?;
        client
            .fire_get(b"stream:absent", 13)
            .map_err(|e| format!("fire: {e}"))?;
        let m0 = client
            .recv_meta()
            .await
            .map_err(|e| format!("pipe0: {e}"))?;
        let m1 = client
            .recv_meta()
            .await
            .map_err(|e| format!("pipe1: {e}"))?;
        let m2 = client
            .recv_meta()
            .await
            .map_err(|e| format!("pipe2: {e}"))?;
        let m3 = client
            .recv_meta()
            .await
            .map_err(|e| format!("pipe3: {e}"))?;
        if m0.kind != OpKind::Get || m0.user_data != 10 || m0.value_len != Some(SMALL.len()) {
            return Err(format!("pipe0 (get) wrong: {m0:?}"));
        }
        if m1.kind != OpKind::Set || m1.user_data != 11 || !m1.success {
            return Err(format!("pipe1 (set) wrong: {m1:?}"));
        }
        if m2.kind != OpKind::Del || m2.user_data != 12 || !m2.success {
            return Err(format!("pipe2 (del) wrong: {m2:?}"));
        }
        if m3.kind != OpKind::Get || m3.user_data != 13 || m3.value_len.is_some() {
            return Err(format!("pipe3 (get miss) wrong: {m3:?}"));
        }
    }

    Ok(())
}

// ── Borrow GET (Mode-B recv_get_discard / recv_get_segments) ───────────────

async fn run_borrow_get(addr: SocketAddr) -> Result<(), String> {
    // (a) hit: recv_get_discard returns the value length (no copy).
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"stream:small", 1)
            .map_err(|e| format!("fire: {e}"))?;
        let meta = client
            .recv_get_discard()
            .await
            .map_err(|e| format!("recv_get_discard: {e}"))?;
        if meta.value_len != Some(SMALL.len()) {
            return Err(format!(
                "borrow hit len: got {:?}, want {}",
                meta.value_len,
                SMALL.len()
            ));
        }
        if meta.user_data != 1 {
            return Err("borrow user_data mismatch".into());
        }
    }

    // (b) miss: `$-1` → value_len None.
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"stream:absent", 2)
            .map_err(|e| format!("fire: {e}"))?;
        let meta = client
            .recv_get_discard()
            .await
            .map_err(|e| format!("recv miss: {e}"))?;
        if meta.value_len.is_some() {
            return Err(format!(
                "borrow miss should be None, got {:?}",
                meta.value_len
            ));
        }
    }

    // (c) recv_get_segments delivers the exact value bytes (zero-copy borrow),
    // reassembling a large value that spans many provided buffers.
    {
        let large = large_value();
        let mut client = connect(addr).await?;
        client
            .fire_get(b"stream:large", 3)
            .map_err(|e| format!("fire: {e}"))?;
        let mut collected = Vec::new();
        let meta = client
            .recv_get_segments(|seg| collected.extend_from_slice(seg))
            .await
            .map_err(|e| format!("recv_get_segments: {e}"))?;
        if meta.value_len != Some(large.len()) {
            return Err(format!(
                "borrow large len: got {:?}, want {}",
                meta.value_len,
                large.len()
            ));
        }
        if collected != large {
            return Err("borrow large value bytes mismatch".into());
        }
    }

    // (d) pipelined: fire several GETs, recv in order — exercises the inter-reply
    // boundary gathering (the only copy on the path).
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"stream:small", 10)
            .map_err(|e| format!("fire: {e}"))?;
        client
            .fire_get(b"stream:absent", 11)
            .map_err(|e| format!("fire: {e}"))?;
        client
            .fire_get(b"stream:small", 12)
            .map_err(|e| format!("fire: {e}"))?;
        let m0 = client
            .recv_get_discard()
            .await
            .map_err(|e| format!("pipe 0: {e}"))?;
        let m1 = client
            .recv_get_discard()
            .await
            .map_err(|e| format!("pipe 1: {e}"))?;
        let m2 = client
            .recv_get_discard()
            .await
            .map_err(|e| format!("pipe 2: {e}"))?;
        if m0.user_data != 10 || m0.value_len != Some(SMALL.len()) {
            return Err(format!("pipe 0 mismatch: {m0:?}"));
        }
        if m1.user_data != 11 || m1.value_len.is_some() {
            return Err(format!("pipe 1 (miss) mismatch: {m1:?}"));
        }
        if m2.user_data != 12 || m2.value_len != Some(SMALL.len()) {
            return Err(format!("pipe 2 mismatch: {m2:?}"));
        }
    }

    // (e) an unexpected reply type (`:`/`+`/`*`) to a borrow-GET is only
    // partially consumed by the header parse → the connection is desynced and
    // MUST be poisoned, so the next op on it fails rather than reading the stray
    // bytes as the head of a bogus reply. (A genuine `-ERR` stays reusable — see
    // the `get_header_poison_contract_tests` unit tests.)
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"borrow:unexpected", 20)
            .map_err(|e| format!("fire: {e}"))?;
        match client.recv_get_discard().await {
            Ok(m) => return Err(format!("unexpected-reply borrow should Err, got {m:?}")),
            Err(Error::UnexpectedResponse) => { /* expected */ }
            Err(e) => return Err(format!("unexpected-reply borrow wrong error: {e}")),
        }
        // Poisoned: the next op must fail (stale slot after the close()), not run
        // on the desynced connection.
        if client.get(b"stream:small").await.is_ok() {
            return Err("unexpected-reply borrow: next op unexpectedly succeeded".into());
        }
    }

    Ok(())
}

// ── Pooled streaming get_stream (poison-eviction) ──────────────────────────

async fn run_pool_stream(addr: SocketAddr) -> Result<(), String> {
    use ringline_redis::{Pool, PoolConfig};

    // `pool_size == 1` forces every checkout onto the SAME slot, so the poison
    // path below actually re-checks-out the poisoned connection (with 2+ slots
    // round-robin would dodge it, never exercising the eviction).
    let mut pool = Pool::new(PoolConfig {
        addr,
        pool_size: 1,
        connect_timeout_ms: 0,
        tls_server_name: None,
        password: None,
        username: None,
    });

    let expected_large = large_value();

    // (a) happy path: pooled streaming collect() reassembles the large value
    //     across many recv buffers, just like the single-connection Client.
    {
        let stream = pool
            .get_stream(b"stream:large")
            .await
            .map_err(|e| format!("pool large get_stream: {e}"))?
            .ok_or("pool large: None")?;
        if stream.len() != LARGE_LEN {
            return Err(format!("pool large len: {}", stream.len()));
        }
        let collected = stream
            .collect()
            .await
            .map_err(|e| format!("pool large collect: {e}"))?;
        if collected.as_ref() != expected_large.as_slice() {
            return Err("pool large collect mismatch".into());
        }
    }

    // A drained stream leaves the connection HEALTHY: the next pooled op reuses
    // the same slot (no reconnect) and returns correct results.
    {
        let small = pool
            .client()
            .await
            .map_err(|e| format!("pool client after healthy stream: {e}"))?
            .get(b"stream:small")
            .await
            .map_err(|e| format!("pool get after healthy stream: {e}"))?
            .ok_or("pool get after healthy stream: None")?;
        if small.as_ref() != SMALL {
            return Err("pool desync after healthy stream".into());
        }
    }

    // (b) undrained drop POISONS the pooled connection. The pool must evict the
    //     slot and lazily reconnect on the next checkout — never hand the
    //     desynced connection back out.
    {
        let mut stream = pool
            .get_stream(b"stream:poison")
            .await
            .map_err(|e| format!("pool poison get_stream: {e}"))?
            .ok_or("pool poison: None")?;
        let first = stream
            .next_segment()
            .await
            .map_err(|e| format!("pool poison next_segment: {e}"))?
            .ok_or("pool poison: first chunk None")?;
        if first.len() >= POISON_LEN {
            return Err("pool poison value did not span multiple buffers".into());
        }
        // `stream` dropped here undrained → pooled connection poisoned (close()).
    }

    // The NEXT pooled op must get a healthy, freshly reconnected connection with
    // CORRECT results — proving the abandoned inbound value bytes did not desync
    // a reused connection (the whole point of the eviction).
    let after_poison = pool
        .get_stream(b"stream:small")
        .await
        .map_err(|e| format!("pool get_stream after poison: {e}"))?
        .ok_or("pool after poison: None")?
        .collect()
        .await
        .map_err(|e| format!("pool collect after poison: {e}"))?;
    if after_poison.as_ref() != SMALL {
        return Err("pool desync after poison-evict-reconnect".into());
    }

    // A second op on the reconnected slot confirms steady-state reuse (a large
    // value, so any residual desync from the abandoned poison read would surface
    // as a mismatch).
    let again = pool
        .client()
        .await
        .map_err(|e| format!("pool client 2: {e}"))?
        .get(b"stream:large")
        .await
        .map_err(|e| format!("pool get large after poison: {e}"))?
        .ok_or("pool get large after poison: None")?;
    if again.as_ref() != expected_large.as_slice() {
        return Err("pool desync on reconnected slot".into());
    }

    Ok(())
}

// ── set_stream (streaming SET) ────────────────────────────────────────────

/// Split `value` into `chunk`-byte `Bytes` pieces (an `Iterator<Item = Bytes>`,
/// which is a `SegmentSource` via the blanket impl).
fn chunked(value: &[u8], chunk: usize) -> std::vec::IntoIter<Bytes> {
    value
        .chunks(chunk)
        .map(Bytes::copy_from_slice)
        .collect::<Vec<_>>()
        .into_iter()
}

async fn run_set_stream(addr: SocketAddr) -> Result<(), String> {
    let value = set_value();

    // (a) happy path: server verifies the exact streamed value → +OK.
    {
        let mut client = connect(addr).await?;
        client
            .set_stream(b"stream:setlarge", SET_LEN, chunked(&value, 7000))
            .await
            .map_err(|e| format!("set_stream: {e}"))?;
        // Connection still usable after a successful streaming set.
        let after = client
            .get(b"stream:small")
            .await
            .map_err(|e| format!("get after set_stream: {e}"))?
            .ok_or("get after set_stream: None")?;
        if after.as_ref() != SMALL {
            return Err("desync after set_stream".into());
        }
    }

    // (b) under-produce: source yields fewer than `len` bytes → LengthMismatch,
    // and the connection is poisoned (next op errors).
    {
        let mut client = connect(addr).await?;
        let short = value[..SET_LEN - 100].to_vec();
        match client
            .set_stream(b"stream:setlarge", SET_LEN, chunked(&short, 7000))
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
            .set_stream(b"stream:setlarge", SET_LEN, chunked(&over, 7000))
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
    // Regression for the set_stream no-poison bug (this path previously returned
    // the error without closing).
    {
        /// Yields `ok_chunks` 1 KiB chunks, then errors — simulating a value
        /// source that fails partway (I/O, decode, etc.).
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
        // 2 KiB of value then an error — well short of SET_LEN, so it fails
        // mid-stream (not via the over/under-produce length checks).
        match client
            .set_stream(b"stream:setlarge", SET_LEN, FailingSource { ok_chunks: 2 })
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
