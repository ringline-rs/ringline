//! A client with metrics and no `on_result` callback times fire/recv ops.
//!
//! Runs on both backends against an in-process stub server that answers every
//! request line with a GET miss (`END\r\n`).
#![cfg(feature = "metrics")]

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder,
};
use ringline_memcache::{Client, CompletedOp};

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

struct MissServer;

impl AsyncEventHandler for MissServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| match data.windows(2).position(|w| w == b"\r\n") {
                        Some(end) => {
                            let _ = tx.send(b"END\r\n");
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
        MissServer
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
    let conn = ringline::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut client = Client::builder(conn).with_metrics().build();
    client
        .fire_get(b"absent", 1)
        .map_err(|e| format!("fire: {e}"))?;
    let op = client.recv().await.map_err(|e| format!("recv: {e}"))?;
    let CompletedOp::Get { latency_ns, .. } = op else {
        return Err("recv: not a Get".into());
    };
    if latency_ns == 0 {
        return Err("metrics-only client recorded latency 0".into());
    }
    let metrics = client.metrics().ok_or("metrics not enabled")?;
    if metrics.requests != 1 {
        return Err(format!("metrics requests = {}", metrics.requests));
    }
    Ok(())
}

#[test]
fn metrics_only_client_times_fire_recv() {
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<MissServer>()
        .expect("server launch failed");
    let addr = s_shutdown.bound_addr().expect("bound address");
    SERVER_ADDR.set(addr).ok();

    let (c_shutdown, c_handles) = RinglineBuilder::new(test_config())
        .launch::<ClientHandler>()
        .expect("client launch failed");
    common::join_workers(&c_shutdown, c_handles);

    let result = RESULT.get().expect("client did not set result");
    if let Err(e) = result {
        panic!("{e}");
    }

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
