//! `connect_all` connects concurrently: the stub server answers no AUTH until
//! every connection has sent one, so a sequential `connect_all` waits forever
//! on its first connection (#532).

mod common;

use std::collections::VecDeque;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};
use ringline_redis::{Pool, PoolConfig, ShardedClient, ShardedConfig};

const CONNECTIONS: usize = 8;

/// Accept `CONNECTIONS`, read an AUTH from each, and only then answer them all.
fn answer_once_all_have_authenticated(listener: TcpListener) {
    let mut clients: VecDeque<TcpStream> = VecDeque::new();
    while clients.len() < CONNECTIONS {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut request = [0u8; 256];
        assert!(stream.read(&mut request).expect("read AUTH") > 0);
        clients.push_back(stream);
    }
    for stream in &mut clients {
        stream.write_all(b"+OK\r\n").expect("write");
    }
    // Held open, so the client's connections stay alive for the test to check.
    while !FINISHED.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(5));
    }
}

static POOL_ADDR: Mutex<Option<SocketAddr>> = Mutex::new(None);
static SHARDED_ADDR: Mutex<Option<SocketAddr>> = Mutex::new(None);
static FINISHED: AtomicBool = AtomicBool::new(false);

struct Handler;

impl AsyncEventHandler for Handler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = POOL_ADDR.lock().unwrap().expect("set before launch");
            let pool = Pool::new(PoolConfig::new(addr, CONNECTIONS).password("secret"));
            ringline::timeout(Duration::from_secs(5), pool.connect_all())
                .await
                .expect("the pool connected one at a time")
                .expect("connect_all");
            assert_eq!(pool.connected_count(), CONNECTIONS);

            let addr = SHARDED_ADDR.lock().unwrap().expect("set before launch");
            let config = ShardedConfig::new(vec![addr])
                .pool_size(CONNECTIONS)
                .password("secret");
            let mut sharded = ShardedClient::new(config);
            ringline::timeout(Duration::from_secs(5), sharded.connect_all())
                .await
                .expect("the sharded client connected one at a time")
                .expect("connect_all");
            // The stub accepts no more connections, so this finds a stored
            // connection or fails.
            for _ in 0..CONNECTIONS {
                ringline::timeout(Duration::from_secs(5), sharded.shard_client(0))
                    .await
                    .expect("no stored client")
                    .expect("a stored client");
            }

            FINISHED.store(true, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        Handler
    }
}

#[test]
fn connect_all_runs_its_connects_at_once() {
    let serve = |slot: &Mutex<Option<SocketAddr>>| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        *slot.lock().unwrap() = Some(listener.local_addr().expect("address"));
        std::thread::spawn(move || answer_once_all_have_authenticated(listener))
    };
    let pool_server = serve(&POOL_ADDR);
    let sharded_server = serve(&SHARDED_ADDR);

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        .max_connections(64)
        // Smaller than `CONNECTIONS`: AUTH waits for a slot.
        .send_pool(4, 16384)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Handler>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    assert!(
        FINISHED.load(Ordering::SeqCst),
        "connect_all did not finish"
    );
    pool_server.join().expect("pool server");
    sharded_server.join().expect("sharded server");
}
