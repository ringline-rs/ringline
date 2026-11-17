//! `CommandResult::ttfb_ns` and `ttlb_ns` for `ping`.
//!
//! Runs on both backends against an in-process server that answers `PING`
//! with `PONG`. A ping that read its reply has both times, with
//! `ttfb_ns <= ttlb_ns <= latency_ns`. A ping that fails at send reads
//! nothing: `rx_bytes == 0` and no times.

mod common;

use std::cell::RefCell;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::Duration;

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder,
};
use ringline_ping::{Client, CommandResult, Error};

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

struct PongServer;

impl AsyncEventHandler for PongServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| match data.windows(2).position(|w| w == b"\r\n") {
                        Some(end) => {
                            let _ = tx.send(b"PONG\r\n");
                            ParseResult::Consumed(end + 2)
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
        PongServer
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

async fn run(addr: SocketAddr) -> Result<(), String> {
    let seen: Rc<RefCell<Vec<CommandResult>>> = Rc::default();
    let sink = seen.clone();
    let conn = ringline::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut client = Client::builder(conn)
        .on_result(move |r| sink.borrow_mut().push(r.clone()))
        .build();

    client.ping().await.map_err(|e| format!("ping: {e}"))?;
    let r = seen
        .borrow()
        .last()
        .cloned()
        .ok_or("ping: nothing recorded")?;
    match (r.ttfb_ns, r.ttlb_ns) {
        (Some(first), Some(last)) if first <= last && last <= r.latency_ns && r.rx_bytes > 0 => {}
        _ => return Err(format!("ping: {r:?}")),
    }

    // Once the close has been submitted, the send fails and the result
    // records nothing read.
    client.close();
    ringline::sleep(Duration::from_millis(20)).await;
    match client.ping().await {
        Err(Error::Io(_)) => {}
        other => return Err(format!("ping after close: {other:?}")),
    }
    let r = seen.borrow().last().cloned().ok_or("nothing recorded")?;
    if r.ttfb_ns.is_some() || r.ttlb_ns.is_some() || r.rx_bytes != 0 || r.success {
        return Err(format!("ping after close: {r:?}"));
    }
    Ok(())
}

#[test]
fn ping_reports_reply_arrival_times() {
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<PongServer>()
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
