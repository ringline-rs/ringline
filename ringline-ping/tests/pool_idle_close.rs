//! A pool reconnects a slot whose connection the server closed while it sat
//! idle, instead of handing out the closed connection.
//!
//! The stub server answers one PING on each connection and then closes it.

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder,
};
use ringline_ping::{Pool, PoolConfig};

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(64, 16384)
        .build()
        .expect("valid config")
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

const PING: &[u8] = b"PING\r\n";

/// Connections the stub server answered a PING on. `wait_for_server`'s probe
/// connections send nothing and are not counted.
static ANSWERED: AtomicUsize = AtomicUsize::new(0);

struct OneReplyServer;

impl AsyncEventHandler for OneReplyServer {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            let n = rx
                .with_data(|data| {
                    if data.len() < PING.len() {
                        return ParseResult::NeedMore;
                    }
                    let _ = tx.send(b"PONG\r\n");
                    ParseResult::Consumed(PING.len())
                })
                .await;
            if n > 0 {
                ANSWERED.fetch_add(1, Ordering::SeqCst);
                // Wait 50 ms before closing, so the client reads the reply and
                // returns the connection to the pool before the FIN arrives.
                ringline::sleep(Duration::from_millis(50)).await;
            }
            tx.close();
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        OneReplyServer
    }
}

static SERVER_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static RESULT: OnceLock<Result<(), String>> = OnceLock::new();

async fn run_client(addr: SocketAddr) -> Result<(), String> {
    let pool = Pool::new(PoolConfig::new(addr, 1));
    {
        let mut client = pool
            .client()
            .await
            .map_err(|e| format!("first client: {e}"))?;
        client
            .ping()
            .await
            .map_err(|e| format!("first ping: {e}"))?;
    }
    // The connection went back into the pool alive.
    if pool.connected_count() != 1 {
        return Err("the first client was not returned alive".into());
    }
    // The server closes the connection 50 ms after its reply. Give the
    // client's worker time to see the close while the client sits in the pool.
    ringline::sleep(Duration::from_millis(200)).await;
    let mut client = pool
        .client()
        .await
        .map_err(|e| format!("second client: {e}"))?;
    client
        .ping()
        .await
        .map_err(|e| format!("second ping on the pooled connection: {e}"))?;
    Ok(())
}

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

#[test]
fn a_connection_closed_while_idle_is_reconnected_at_checkout() {
    let (s_shutdown, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<OneReplyServer>()
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
        panic!("{e}");
    }
    assert_eq!(
        ANSWERED.load(Ordering::SeqCst),
        2,
        "the slot reconnected once"
    );

    s_shutdown.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }
}
