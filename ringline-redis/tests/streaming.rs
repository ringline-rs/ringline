//! `set_stream`, pooled and sharded GETs, and `recv_meta` against an
//! in-process stub server.
//!
//! Mirrors the stub-server pattern in `parse_error.rs` (no real Redis needed):
//! a `StreamStubServer` handler answers commands with canned replies over a
//! loopback connection.

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use resp_proto::Value;
use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder,
};
use ringline_redis::{Client, Error, OpKind, SegmentSource};

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
const LARGE_LEN: usize = 100_000;

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
        b"stream:short" => {
            // Claim SHORT_CLAIMED_LEN bytes but send only SHORT_SENT, then FIN.
            let mut out = format!("${SHORT_CLAIMED_LEN}\r\n").into_bytes();
            out.extend_from_slice(SHORT_SENT);
            (out, true)
        }
        b"borrow:unexpected" => {
            // A non-`$`/`-` reply type (RESP integer) to a GET. `recv_meta`'s
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
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
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
                                        let _ = tx.send(reply);
                                    } else if verb.eq_ignore_ascii_case(b"DEL") {
                                        // `DEL <key>`: reply with the deleted-key
                                        // count (a RESP integer).
                                        let _ = tx.send(b":1\r\n");
                                    } else if let Some(Value::BulkString(key)) = items.get(1) {
                                        // `GET <key>`.
                                        let (reply, should_close) = decide(&key[..]);
                                        let _ = tx.send(&reply);
                                        close_after = should_close;
                                    }
                                }
                                if close_after {
                                    // Send has been queued; closing the connection
                                    // FINs after the queued bytes drain, giving the
                                    // client a short reply followed by peer EOF.
                                    tx.close();
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
    run_set_stream(addr).await?;
    run_pool_get(addr).await?;
    run_sharded_get(addr).await?;
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

    // (h) the peer closes partway through a GET value → `ConnectionClosed`.
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"stream:short", 20)
            .map_err(|e| format!("fire short: {e}"))?;
        match client.recv_meta().await {
            Err(Error::ConnectionClosed) => {}
            other => return Err(format!("short recv_meta: {other:?}")),
        }
    }

    Ok(())
}

// ── Pool and sharded GETs ──────────────────────────────────────────────────

/// A sharded client reads a value larger than one receive buffer.
async fn run_sharded_get(addr: SocketAddr) -> Result<(), String> {
    use ringline_redis::{ShardedClient, ShardedConfig};

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
    if large.as_ref() != large_value().as_slice() {
        return Err("sharded large mismatch".into());
    }
    sharded.close_all();
    Ok(())
}

/// A pooled client reads small and large values with `get` and `recv_meta`.
async fn run_pool_get(addr: SocketAddr) -> Result<(), String> {
    use ringline_redis::{Pool, PoolConfig};

    let pool = Pool::new(PoolConfig::new(addr, 1));
    let mut client = pool
        .client()
        .await
        .map_err(|e| format!("pool client: {e}"))?;
    let small = client
        .get(b"stream:small")
        .await
        .map_err(|e| format!("pool small get: {e}"))?
        .ok_or("pool small: None")?;
    if small.as_ref() != SMALL {
        return Err("pool small mismatch".into());
    }
    // Larger than the connection's receive buffer, so the parser's length
    // hint sizes the receive.
    let large = client
        .get(b"stream:large")
        .await
        .map_err(|e| format!("pool large get: {e}"))?
        .ok_or("pool large: None")?;
    if large.as_ref() != large_value().as_slice() {
        return Err("pool large mismatch".into());
    }
    // `recv_meta` drains a large GET reply without materializing it.
    client
        .fire_get(b"stream:large", 2)
        .map_err(|e| format!("pool fire large: {e}"))?;
    let m = client
        .recv_meta()
        .await
        .map_err(|e| format!("pool recv_meta: {e}"))?;
    if m.value_len != Some(large_value().len()) || m.user_data != 2 {
        return Err(format!("pool recv_meta: {m:?}"));
    }
    let small = client
        .get(b"stream:small")
        .await
        .map_err(|e| format!("pool get after recv_meta: {e}"))?
        .ok_or("pool get after recv_meta: None")?;
    if small.as_ref() != SMALL {
        return Err("pool get after recv_meta mismatch".into());
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

#[test]
fn streaming_and_metadata_end_to_end() {
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
