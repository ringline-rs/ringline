//! `CommandResult::ttfb_ns` and `ttlb_ns` on every instrumented path.
//!
//! Runs on both backends against an in-process stub server. Every recorded
//! result that read a reply must have both times, with
//! `ttfb_ns <= ttlb_ns <= latency_ns`. An error reply has both times. An
//! operation that fails at send reads nothing: `rx_bytes == 0` and no times.

mod common;

use std::cell::RefCell;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::Duration;

use resp_proto::Value;
use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RegionId, RinglineBuilder,
    SendGuard,
};
use ringline_redis::{Client, CommandResult, CommandType, Error};

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
        .expect("valid config")
}

/// Replies by verb and key: `k:err` gets an error reply.
fn reply(items: &[Value]) -> &'static [u8] {
    let verb = match items.first() {
        Some(Value::BulkString(v)) => v.to_ascii_uppercase(),
        _ => return b"-ERR no verb\r\n",
    };
    let key_is_err = matches!(items.get(1), Some(Value::BulkString(k)) if &k[..] == b"k:err");
    match (&verb[..], key_is_err) {
        (_, true) => b"-ERR boom\r\n",
        (b"GET", false) => b"$5\r\nhello\r\n",
        (b"SET", false) => b"+OK\r\n",
        (b"DEL", false) => b":1\r\n",
        (b"PING", false) => b"+PONG\r\n",
        _ => b"-ERR unknown\r\n",
    }
}

struct StubServer;

impl AsyncEventHandler for StubServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_bytes(|bytes| {
                        let len = bytes.len();
                        match Value::parse_bytes(bytes) {
                            Ok((Value::Array(items), consumed)) => {
                                let _ = tx.send(reply(&items));
                                ParseResult::Consumed(consumed)
                            }
                            Ok((_, consumed)) => ParseResult::Consumed(consumed),
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
        StubServer
    }
}

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

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
            RESULT.set(run(addr).await).ok();
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        ClientHandler
    }
}

/// A result that read a reply has both times, in order, within the latency.
fn check_read(what: &str, r: &CommandResult) -> Result<(), String> {
    match (r.ttfb_ns, r.ttlb_ns) {
        (Some(first), Some(last)) if first <= last && last <= r.latency_ns && r.rx_bytes > 0 => {
            Ok(())
        }
        _ => Err(format!("{what}: {r:?}")),
    }
}

/// A result that failed at send read nothing.
fn check_unsent(what: &str, r: &CommandResult) -> Result<(), String> {
    if r.ttfb_ns.is_none() && r.ttlb_ns.is_none() && r.rx_bytes == 0 && !r.success {
        Ok(())
    } else {
        Err(format!("{what}: {r:?}"))
    }
}

async fn run(addr: SocketAddr) -> Result<(), String> {
    let seen: Rc<RefCell<Vec<CommandResult>>> = Rc::default();
    let sink = seen.clone();
    let conn = ringline::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut client = Client::builder(conn)
        .on_result(move |r| sink.borrow_mut().push(r.clone()))
        .build();
    let last = |what: &str| -> Result<CommandResult, String> {
        seen.borrow()
            .last()
            .cloned()
            .ok_or_else(|| format!("{what}: nothing recorded"))
    };

    client.get(b"k").await.map_err(|e| format!("get: {e}"))?;
    check_read("get", &last("get")?)?;
    client
        .get(b"k:err")
        .await
        .err()
        .ok_or("get k:err succeeded")?;
    check_read("get error reply", &last("get error reply")?)?;
    client
        .set(b"k", b"v")
        .await
        .map_err(|e| format!("set: {e}"))?;
    check_read("set", &last("set")?)?;
    client
        .set_ex(b"k", b"v", 60)
        .await
        .map_err(|e| format!("set_ex: {e}"))?;
    check_read("set_ex", &last("set_ex")?)?;
    client
        .set_with_guard(b"k", VecGuard(vec![b'v'; 16]))
        .await
        .map_err(|e| format!("set_with_guard: {e}"))?;
    check_read("set_with_guard", &last("set_with_guard")?)?;
    client
        .set_with_guard(b"k:err", VecGuard(vec![b'v'; 16]))
        .await
        .err()
        .ok_or("set_with_guard k:err succeeded")?;
    let r = last("set_with_guard error reply")?;
    check_read("set_with_guard error reply", &r)?;
    if r.success || r.command != CommandType::Set {
        return Err(format!("set_with_guard error reply: {r:?}"));
    }
    client
        .set_ex_with_guard(b"k:err", VecGuard(vec![b'v'; 16]), 60)
        .await
        .err()
        .ok_or("set_ex_with_guard k:err succeeded")?;
    check_read("set_ex_with_guard error reply", &last("set_ex_with_guard")?)?;
    client.del(b"k").await.map_err(|e| format!("del: {e}"))?;
    check_read("del", &last("del")?)?;
    client.ping().await.map_err(|e| format!("ping: {e}"))?;
    check_read("ping", &last("ping")?)?;

    client
        .fire_get(b"k", 1)
        .map_err(|e| format!("fire_get: {e}"))?;
    client.recv().await.map_err(|e| format!("recv: {e}"))?;
    check_read("recv", &last("recv")?)?;
    client
        .fire_get(b"k", 2)
        .map_err(|e| format!("fire_get: {e}"))?;
    client
        .recv_meta()
        .await
        .map_err(|e| format!("recv_meta get: {e}"))?;
    check_read("recv_meta get", &last("recv_meta get")?)?;
    client
        .fire_set(b"k", b"v", 3)
        .map_err(|e| format!("fire_set: {e}"))?;
    client
        .recv_meta()
        .await
        .map_err(|e| format!("recv_meta set: {e}"))?;
    check_read("recv_meta set", &last("recv_meta set")?)?;

    // Once the close has been submitted, sends fail, and the results record
    // nothing read.
    client.close();
    ringline::sleep(Duration::from_millis(20)).await;
    let count = seen.borrow().len();
    match client.get(b"k").await {
        Err(Error::Io(_)) => {}
        other => return Err(format!("get after close: {other:?}")),
    }
    match client.set_with_guard(b"k", VecGuard(vec![b'v'; 16])).await {
        Err(Error::Io(_)) => {}
        other => return Err(format!("set_with_guard after close: {other:?}")),
    }
    let after: Vec<CommandResult> = seen.borrow()[count..].to_vec();
    if after.len() != 2 {
        return Err(format!("expected 2 results after close, got {after:?}"));
    }
    check_unsent("get after close", &after[0])?;
    check_unsent("set_with_guard after close", &after[1])?;
    Ok(())
}

#[test]
fn every_instrumented_path_reports_reply_arrival_times() {
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<StubServer>()
        .expect("server launch failed");
    SERVER_ADDR
        .set(s_shutdown.bound_addr().expect("bound address"))
        .ok();

    let (c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<ClientHandler>()
        .expect("client launch failed");
    common::join_workers(&c_shutdown, c_handles);

    if let Err(e) = RESULT.get().expect("client did not set result") {
        panic!("{e}");
    }
    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
