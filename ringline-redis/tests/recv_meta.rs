//! Backend-agnostic integration tests for `Client::recv_meta` — the uniform
//! zero-copy reply-metadata recv (GET/SET/DEL). Unlike `streaming.rs` (which is
//! `#![cfg(has_io_uring)]`), this file has NO backend gate: `recv_meta` works on
//! both the io_uring provided-buffer path AND the mio streaming-drain path, so
//! this runs under `cargo test` (io_uring) and `cargo test --features force-mio`
//! (mio), and on macOS. A large value forces the value body across many recv
//! bursts, exercising the mio `run_get_drain_mio` incremental drain.
//!
//! In-process stub-server pattern, mirroring `parse_error.rs` / `streaming.rs`.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use resp_proto::Value;
use ringline::{AsyncEventHandler, Config, ConfigBuilder, ConnCtx, ParseResult, RinglineBuilder};
use ringline_redis::{Client, Error, OpKind};

// ── Config / helpers ──────────────────────────────────────────────────────

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        // Small provided buffers so a large value spans many recv segments/bursts.
        .recv_buffer(128, 4096)
        .max_connections(64)
        // Large send-pool slot so the server can push the whole value in one send.
        .send_pool(16, 262_144)
        .build()
        .expect("valid config")
}

fn free_port() -> u16 {
    use std::sync::Mutex;
    static CLAIMED: Mutex<Option<std::collections::HashSet<u16>>> = Mutex::new(None);
    loop {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut guard = CLAIMED.lock().unwrap();
        if guard.get_or_insert_with(Default::default).insert(port) {
            return port;
        }
    }
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

const SMALL: &[u8] = b"hello-recv-meta-world";
const LARGE_LEN: usize = 200_000;
const SET_LEN: usize = 100_000;

fn large_value() -> Vec<u8> {
    (0..LARGE_LEN).map(|i| (i % 251) as u8).collect()
}
fn set_value() -> Vec<u8> {
    (0..SET_LEN).map(|i| (i % 251) as u8).collect()
}

fn bulk_reply(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 16);
    out.extend_from_slice(format!("${}\r\n", value.len()).as_bytes());
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
    out
}

/// Reply bytes for a GET of `key`.
fn reply_for_key(key: &[u8]) -> Vec<u8> {
    match key {
        b"meta:small" => bulk_reply(SMALL),
        b"meta:large" => bulk_reply(&large_value()),
        // A non-`$`/`-` reply type (RESP integer) to a GET: only partially
        // consumed by the header parse → desync → the client must poison.
        b"meta:unexpected" => b":5\r\n".to_vec(),
        _ => b"$-1\r\n".to_vec(), // miss
    }
}

// ── Stub server ───────────────────────────────────────────────────────────

struct MetaStubServer;

impl AsyncEventHandler for MetaStubServer {
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
                                    && let Some(Value::BulkString(verb)) = items.first()
                                {
                                    if verb.eq_ignore_ascii_case(b"SET") {
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
                                        let _ = conn.send_nowait(b":1\r\n");
                                    } else if let Some(Value::BulkString(key)) = items.get(1) {
                                        let _ = conn.send_nowait(&reply_for_key(&key[..]));
                                    }
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
        MetaStubServer
    }
}

// ── Client driver ─────────────────────────────────────────────────────────

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
            RESULT.set(run_recv_meta(addr).await).ok();
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

async fn run_recv_meta(addr: SocketAddr) -> Result<(), String> {
    // (a) GET hit → kind Get, success, value_len Some(len), user_data preserved.
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"meta:small", 1)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client
            .recv_meta()
            .await
            .map_err(|e| format!("get hit: {e}"))?;
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
            .fire_get(b"meta:absent", 2)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client
            .recv_meta()
            .await
            .map_err(|e| format!("get miss: {e}"))?;
        if !m.success || m.value_len.is_some() {
            return Err(format!("get miss meta wrong: {m:?}"));
        }
    }

    // (c) GET large — value body spans many recv bursts; the drain must stay
    // bounded and report the exact length (mio `run_get_drain_mio` path).
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"meta:large", 3)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client
            .recv_meta()
            .await
            .map_err(|e| format!("get large: {e}"))?;
        if m.value_len != Some(LARGE_LEN) {
            return Err(format!("get large meta wrong: {m:?}"));
        }
    }

    // (d) SET ok (stub verifies the exact value → +OK) → kind Set, success.
    {
        let mut client = connect(addr).await?;
        client
            .fire_set(b"k:set", &set_value(), 4)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client.recv_meta().await.map_err(|e| format!("set: {e}"))?;
        if m.kind != OpKind::Set || !m.success || m.value_len.is_some() {
            return Err(format!("set meta wrong: {m:?}"));
        }
    }

    // (e) DEL (stub replies `:1`) → kind Del, success.
    {
        let mut client = connect(addr).await?;
        client
            .fire_del(b"k:del", 5)
            .map_err(|e| format!("fire: {e}"))?;
        let m = client.recv_meta().await.map_err(|e| format!("del: {e}"))?;
        if m.kind != OpKind::Del || !m.success || m.value_len.is_some() {
            return Err(format!("del meta wrong: {m:?}"));
        }
    }

    // (f) unexpected reply type to a GET → Err(UnexpectedResponse) + poison
    // (next op on the connection fails).
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"meta:unexpected", 6)
            .map_err(|e| format!("fire: {e}"))?;
        match client.recv_meta().await {
            Ok(m) => return Err(format!("unexpected reply should Err, got {m:?}")),
            Err(Error::UnexpectedResponse) => { /* expected */ }
            Err(e) => return Err(format!("unexpected reply wrong error: {e}")),
        }
        if client.get(b"meta:small").await.is_ok() {
            return Err("recv_meta unexpected: next op unexpectedly succeeded".into());
        }
    }

    // (g) mixed pipeline: GET, SET, DEL, GET — metadata in order, right kinds.
    {
        let mut client = connect(addr).await?;
        client
            .fire_get(b"meta:small", 10)
            .map_err(|e| format!("fire: {e}"))?;
        client
            .fire_set(b"k:set", &set_value(), 11)
            .map_err(|e| format!("fire: {e}"))?;
        client
            .fire_del(b"k:del", 12)
            .map_err(|e| format!("fire: {e}"))?;
        client
            .fire_get(b"meta:absent", 13)
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

// ── Test ──────────────────────────────────────────────────────────────────

#[test]
fn recv_meta_end_to_end() {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind(addr.parse().unwrap())
        .launch::<MetaStubServer>()
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
        panic!("recv_meta test failed: {e}");
    }

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
