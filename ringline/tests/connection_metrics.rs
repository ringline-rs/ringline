//! `CONNECTIONS_ACTIVE` and `conn::CLOSED` follow `established` on both
//! backends, for accepted and outbound connections alike.
//!
//! The gauge is process-global, so each case takes `SERIALIZE` and measures
//! deltas against the value it read before launching anything. Under
//! cargo-nextest every test is its own process and the lock is idle.

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, Instant};

use ringline::metrics::{CONNECTIONS, CONNECTIONS_ACTIVE, conn};
use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

static SERIALIZE: Mutex<()> = Mutex::new(());

/// Shared with the client worker's `on_start`.
static SERVER_ADDR: Mutex<Option<SocketAddr>> = Mutex::new(None);
static USE_TLS: AtomicBool = AtomicBool::new(false);
static BASELINE: AtomicI64 = AtomicI64::new(0);
/// Gauge delta read once the server had accepted and the client's connect
/// had resolved.
static DELTA_OPEN: AtomicI64 = AtomicI64::new(i64::MIN);
/// Gauge delta read once both ends had torn down (or the wait gave up).
static DELTA_CLOSED: AtomicI64 = AtomicI64::new(i64::MIN);
static SERVER_ACCEPTED: AtomicBool = AtomicBool::new(false);
static OUTCOME: Mutex<String> = Mutex::new(String::new());

const WAIT: Duration = Duration::from_secs(5);

fn config() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .no_fs()
}

fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![CertificateDer::from(cert.cert)], key.into())
}

fn gauge_delta() -> i64 {
    CONNECTIONS_ACTIVE.value() - BASELINE.load(Ordering::SeqCst)
}

/// Poll `done` every 5 ms until it holds or `WAIT` passes. Returns whether it
/// held; the caller asserts on the state it then reads, not on the time.
async fn wait_until(done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + WAIT;
    while !done() {
        if Instant::now() >= deadline {
            return false;
        }
        ringline::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// Server: record the accept, read to EOF, return.
struct SinkHandler;

impl AsyncEventHandler for SinkHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        SERVER_ACCEPTED.store(true, Ordering::SeqCst);
        async move { while conn.with_data(|d| ParseResult::Consumed(d.len())).await != 0 {} }
    }

    fn create_for_worker(_id: usize) -> Self {
        SinkHandler
    }
}

/// Client: connect (TLS per `USE_TLS`), read the gauge once both sides are
/// up, close, read it again once both sides are down, then stop.
struct ClientHandler;

impl AsyncEventHandler for ClientHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let addr = SERVER_ADDR.lock().unwrap().expect("server address");
        let tls = USE_TLS.load(Ordering::SeqCst);
        Some(Box::pin(async move {
            let connected = if tls {
                ringline::connect(addr).tls("localhost").await
            } else {
                ringline::connect(addr).await
            };
            let mut conn = match connected {
                Ok(c) => c,
                Err(e) => {
                    *OUTCOME.lock().unwrap() = format!("connect failed: {e}");
                    ringline::request_shutdown().ok();
                    return;
                }
            };
            // Both ends counted in: the server's accept and this connect.
            let up =
                wait_until(|| SERVER_ACCEPTED.load(Ordering::SeqCst) && gauge_delta() >= 2).await;
            DELTA_OPEN.store(gauge_delta(), Ordering::SeqCst);
            conn.close();
            // Both ends counted out. The client slot's decrement has no
            // handler-visible signal, so the gauge itself is what is waited on.
            let down = wait_until(|| gauge_delta() <= 0).await;
            DELTA_CLOSED.store(gauge_delta(), Ordering::SeqCst);
            *OUTCOME.lock().unwrap() = format!("ok up={up} down={down}");
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        ClientHandler
    }
}

/// Launch a sink server and a one-connection client; return the gauge delta
/// while both ends were open and after both closed.
fn outbound_case(tls: bool) -> (i64, i64) {
    let _serial = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    DELTA_OPEN.store(i64::MIN, Ordering::SeqCst);
    DELTA_CLOSED.store(i64::MIN, Ordering::SeqCst);
    SERVER_ACCEPTED.store(false, Ordering::SeqCst);
    OUTCOME.lock().unwrap().clear();
    USE_TLS.store(tls, Ordering::SeqCst);
    BASELINE.store(CONNECTIONS_ACTIVE.value(), Ordering::SeqCst);

    let (certs, key) = generate_self_signed();

    let mut server = config();
    if tls {
        server = server.tls(
            TlsConfig::builder()
                .cert(certs.clone(), key)
                .build()
                .unwrap(),
        );
    }
    let (s_rt, s_handles) = RinglineBuilder::new(server.build().unwrap())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SinkHandler>()
        .expect("server launch");
    *SERVER_ADDR.lock().unwrap() = Some(s_rt.bound_addr().expect("bound address"));

    let mut client = config();
    if tls {
        let roots = ringline::TlsClientConfig::builder()
            .root_certificates(certs.iter().cloned())
            .build()
            .unwrap();
        client = client.tls_client(roots);
    }
    let (c_rt, c_handles) = RinglineBuilder::new(client.build().unwrap())
        .launch::<ClientHandler>()
        .expect("client launch");
    common::join_workers(&c_rt, c_handles);
    let outcome = OUTCOME.lock().unwrap().clone();
    assert!(outcome.starts_with("ok"), "client: {outcome}");

    s_rt.shutdown();
    for h in s_handles {
        h.join()
            .expect("server worker panicked")
            .expect("server worker failed");
    }
    (
        DELTA_OPEN.load(Ordering::SeqCst),
        DELTA_CLOSED.load(Ordering::SeqCst),
    )
}

/// Plaintext outbound: the server's accept and the client's connect both
/// count in, and both count out at close.
#[test]
fn outbound_plaintext_connection_balances_the_active_gauge() {
    let (open, closed) = outbound_case(false);
    assert_eq!(open, 2, "server accept + client connect while open");
    assert_eq!(closed, 0, "both counted out after close");
}

/// TLS outbound: the client counts in when its handshake completes, as the
/// server did at accept, and both count out at close.
#[test]
fn outbound_tls_connection_balances_the_active_gauge() {
    let (open, closed) = outbound_case(true);
    assert_eq!(open, 2, "server accept + client connect while open");
    assert_eq!(closed, 0, "both counted out after close");
}

static REFUSED_ADDR: Mutex<Option<SocketAddr>> = Mutex::new(None);

struct RefusedHandler;

impl AsyncEventHandler for RefusedHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let addr = REFUSED_ADDR.lock().unwrap().expect("refused address");
        Some(Box::pin(async move {
            *OUTCOME.lock().unwrap() = match ringline::connect(addr).await {
                Ok(_) => "connected".to_string(),
                Err(e) => format!("refused: {}", e.kind()),
            };
            // The failed slot is released by the loop's finalize: the same
            // iteration on mio, the Close CQE's iteration on io_uring. Yield
            // a few iterations so the counters the test reads are final.
            for _ in 0..8 {
                ringline::yield_now().await;
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        RefusedHandler
    }
}

/// A connect that is refused was never established, so it is neither an
/// active connection nor a close: the gauge and `conn::CLOSED` do not move,
/// on either backend.
#[test]
fn refused_connect_is_not_counted_as_a_close() {
    let _serial = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    OUTCOME.lock().unwrap().clear();
    let (_hold, port) = common::refusing_port();
    *REFUSED_ADDR.lock().unwrap() = Some(SocketAddr::from(([127, 0, 0, 1], port)));

    let closed_before = CONNECTIONS.value(conn::CLOSED).unwrap_or(0);
    let gauge_before = CONNECTIONS_ACTIVE.value();

    let (rt, handles) = RinglineBuilder::new(config().build().unwrap())
        .launch::<RefusedHandler>()
        .expect("launch");
    common::join_workers(&rt, handles);

    let outcome = OUTCOME.lock().unwrap().clone();
    assert!(outcome.starts_with("refused"), "connect outcome: {outcome}");
    assert_eq!(
        CONNECTIONS_ACTIVE.value() - gauge_before,
        0,
        "a connection never counted in must not count out"
    );
    assert_eq!(
        CONNECTIONS.value(conn::CLOSED).unwrap_or(0) - closed_before,
        0,
        "a connection never established is not a close"
    );
}

/// Worker exit counts every connection still open out, on both backends:
/// the gauge returns to its baseline and `CLOSED` grows by the number of
/// connections the worker closed.
#[test]
fn worker_exit_counts_open_connections_out() {
    let _serial = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    SERVER_ACCEPTED.store(false, Ordering::SeqCst);
    BASELINE.store(CONNECTIONS_ACTIVE.value(), Ordering::SeqCst);
    let closed_before = CONNECTIONS.value(conn::CLOSED).unwrap_or(0);

    let (rt, handles) = RinglineBuilder::new(config().build().unwrap())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SinkHandler>()
        .expect("server launch");
    let addr = rt.bound_addr().expect("bound address");
    let peers: Vec<std::net::TcpStream> = (0..3)
        .map(|_| std::net::TcpStream::connect(addr).expect("connect"))
        .collect();
    let deadline = Instant::now() + WAIT;
    while gauge_delta() < 3 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(gauge_delta(), 3, "three accepted connections counted in");

    // The peers stay open: the worker closes the connections on its way out.
    rt.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert_eq!(
        gauge_delta(),
        0,
        "worker exit counts its open connections out"
    );
    assert_eq!(
        CONNECTIONS.value(conn::CLOSED).unwrap_or(0) - closed_before,
        3,
        "each connection the worker closed counts as a close"
    );
    drop(peers);
}
