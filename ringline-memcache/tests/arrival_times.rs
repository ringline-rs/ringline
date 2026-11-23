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

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RegionId, RinglineBuilder,
    SendGuard,
};
use ringline_memcache::{Client, CommandResult, CommandType, Error};

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

/// The reply to one text-protocol request, and the request's length, or
/// `None` if the request is incomplete. Key `k:err` gets a server error.
fn handle(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let line_end = data.windows(2).position(|w| w == b"\r\n")?;
    let line = &data[..line_end];
    let parts: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
    let err = parts.get(1) == Some(&&b"k:err"[..]);
    let mut len = line_end + 2;
    let reply: &[u8] = match parts[0] {
        b"get" if err => b"SERVER_ERROR boom\r\n",
        b"get" => b"VALUE k 0 5\r\nhello\r\nEND\r\n",
        b"set" => {
            let bytes: usize = std::str::from_utf8(parts.get(4)?).ok()?.parse().ok()?;
            len += bytes + 2;
            if data.len() < len {
                return None;
            }
            if err {
                b"SERVER_ERROR no\r\n"
            } else {
                b"STORED\r\n"
            }
        }
        b"delete" => b"DELETED\r\n",
        _ => b"ERROR\r\n",
    };
    Some((reply.to_vec(), len))
}

struct StubServer;

impl AsyncEventHandler for StubServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| match handle(data) {
                        Some((reply, len)) => {
                            let _ = tx.send(&reply);
                            ParseResult::Consumed(len)
                        }
                        None => ParseResult::NeedMore,
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
    fn as_bytes(&self) -> &[u8] {
        &self.0
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
        .delete(b"k")
        .await
        .map_err(|e| format!("delete: {e}"))?;
    check_read("delete", &last("delete")?)?;
    client
        .set_with_guard(b"k", VecGuard(vec![b'v'; 16]), 0, 0)
        .await
        .map_err(|e| format!("set_with_guard: {e}"))?;
    check_read("set_with_guard", &last("set_with_guard")?)?;
    client
        .set_with_guard(b"k:err", VecGuard(vec![b'v'; 16]), 0, 0)
        .await
        .err()
        .ok_or("set_with_guard k:err succeeded")?;
    let r = last("set_with_guard error reply")?;
    check_read("set_with_guard error reply", &r)?;
    if r.success || r.command != CommandType::Set {
        return Err(format!("set_with_guard error reply: {r:?}"));
    }

    client
        .fire_get(b"k", 1)
        .map_err(|e| format!("fire_get: {e}"))?;
    client.recv().await.map_err(|e| format!("recv: {e}"))?;
    check_read("recv", &last("recv")?)?;

    // Once the close has been submitted, sends fail, and the results record
    // nothing read.
    client.close();
    ringline::sleep(Duration::from_millis(20)).await;
    let count = seen.borrow().len();
    match client.get(b"k").await {
        Err(Error::Io(_)) => {}
        other => return Err(format!("get after close: {other:?}")),
    }
    match client
        .set_with_guard(b"k", VecGuard(vec![b'v'; 16]), 0, 0)
        .await
    {
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
