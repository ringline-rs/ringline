//! `ClientBuilder::get_command` / `set_command` against an in-process stub
//! server that records the command name and argument count of every request.
//!
//! One client run covers the direct-send and coalesced `fire_*` paths, the
//! zero-copy guard path, the async methods, `Pipeline` and `set_stream`, and a
//! client built without the options. The stub answers a GET-shaped name
//! (ending in `GET`) with a bulk string for key `hit` and nil otherwise, and a
//! SET-shaped name with `+OK` once it has checked the value.
//!
//! No backend gate: runs on io_uring and on mio (guards are copied there).

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use resp_proto::Value;
use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RegionId, RinglineBuilder,
    SendGuard,
};
use ringline_redis::{Client, CompletedOp};

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        .recv_buffer(128, 16384)
        .max_connections(64)
        .send_pool(64, 65536)
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

/// A value above the client's default `zc_threshold` (4096), so
/// `fire_set_with_guard` and `set_with_guard` take the guard path.
const BIG_LEN: usize = 8192;
const STREAM_VALUE: &[u8] = b"streamed-value";

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

fn big_guard() -> VecGuard {
    VecGuard(vec![7u8; BIG_LEN])
}

/// `(command name, argument count including the name)` of every request the
/// stub has received, in arrival order.
static SEEN: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

/// The value a SET of `key` must carry; anything else is answered with an
/// error so a corrupted frame fails the client's assertions.
fn value_ok(key: &[u8], value: &[u8]) -> bool {
    match key {
        b"big" => value.len() == BIG_LEN && value.iter().all(|&b| b == 7),
        b"stream" => value == STREAM_VALUE,
        _ => value == b"v",
    }
}

fn reply(items: &[Value]) -> &'static [u8] {
    let (Some(Value::BulkString(name)), Some(Value::BulkString(key))) =
        (items.first(), items.get(1))
    else {
        return b"-ERR malformed\r\n";
    };
    let name = name.to_ascii_uppercase();
    if name.ends_with(b"GET") && items.len() == 2 {
        if &key[..] == b"hit" {
            b"$5\r\nhello\r\n"
        } else {
            b"$-1\r\n"
        }
    } else if name.ends_with(b"SET") {
        match items.get(2) {
            Some(Value::BulkString(v)) if value_ok(key, v) => b"+OK\r\n",
            _ => b"-ERR value mismatch\r\n",
        }
    } else {
        b"-ERR unknown command\r\n"
    }
}

struct RecordingServer;

impl AsyncEventHandler for RecordingServer {
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
                                let name = match items.first() {
                                    Some(Value::BulkString(b)) => {
                                        String::from_utf8_lossy(b).into_owned()
                                    }
                                    _ => String::from("<not a bulk string>"),
                                };
                                SEEN.lock().unwrap().push((name, items.len()));
                                let _ = tx.send_nowait(reply(&items));
                                ParseResult::Consumed(consumed)
                            }
                            Ok((_, consumed)) => {
                                SEEN.lock()
                                    .unwrap()
                                    .push((String::from("<not an array>"), 0));
                                let _ = tx.send_nowait(b"-ERR not an array\r\n");
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
        RecordingServer
    }
}

static SERVER_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static RESULT: OnceLock<Result<(), String>> = OnceLock::new();

/// `tx_bytes` of each command completed by the instrumented renamed client.
static TX_BYTES: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// Fire GET hit, GET miss, SET, guarded SET and SET EX, then receive and check
/// all five replies.
async fn fire_all(client: &mut Client) -> Result<(), String> {
    let e = |what: &str| {
        let what = what.to_string();
        move |err: ringline_redis::Error| format!("{what}: {err}")
    };
    client.fire_get(b"hit", 1).map_err(e("fire_get hit"))?;
    client.fire_get(b"miss", 2).map_err(e("fire_get miss"))?;
    client.fire_set(b"k", b"v", 3).map_err(e("fire_set"))?;
    client
        .fire_set_with_guard(b"big", big_guard(), 4)
        .map_err(e("fire_set_with_guard"))?;
    client
        .fire_set_ex(b"k", b"v", 60, 5)
        .map_err(e("fire_set_ex"))?;
    for want in 1..=5u64 {
        let op = client.recv().await.map_err(e("recv"))?;
        match (want, op) {
            (
                1,
                CompletedOp::Get {
                    result,
                    user_data: 1,
                    ..
                },
            ) => {
                let v = result.map_err(e("GET hit reply"))?;
                if v.as_deref() != Some(&b"hello"[..]) {
                    return Err(format!("GET hit returned {v:?}"));
                }
            }
            (
                2,
                CompletedOp::Get {
                    result,
                    user_data: 2,
                    ..
                },
            ) => {
                let v = result.map_err(e("GET miss reply"))?;
                if v.is_some() {
                    return Err(format!("GET miss returned {v:?}"));
                }
            }
            (
                3..=5,
                CompletedOp::Set {
                    result, user_data, ..
                },
            ) if user_data == want => {
                result.map_err(e("SET reply"))?;
            }
            (want, _) => return Err(format!("op {want}: unexpected reply kind or user_data")),
        }
    }
    Ok(())
}

async fn run(addr: SocketAddr) -> Result<(), String> {
    let e = |what: &str| {
        let what = what.to_string();
        move |err: ringline_redis::Error| format!("{what}: {err}")
    };
    let connect = || async {
        ringline::connect(addr)
            .await
            .map_err(|err| format!("connect: {err}"))
    };

    // Renamed, direct-send path (max_batch_size 1), plus the async methods.
    let mut client = Client::builder(connect().await?)
        .get_command("X.GET")
        .set_command("X.SET")
        .build();
    fire_all(&mut client).await?;
    let hit = client.get("hit").await.map_err(e("get"))?;
    if hit.as_deref() != Some(&b"hello"[..]) {
        return Err(format!("get hit returned {hit:?}"));
    }
    client.set("k", "v").await.map_err(e("set"))?;
    client.set_ex("k", "v", 60).await.map_err(e("set_ex"))?;
    client
        .set_with_guard(b"big", big_guard())
        .await
        .map_err(e("set_with_guard"))?;
    client
        .set_ex_with_guard(b"big", big_guard(), 60)
        .await
        .map_err(e("set_ex_with_guard"))?;
    let results = client
        .pipeline()
        .get(b"miss")
        .set(b"k", b"v")
        .execute()
        .await
        .map_err(e("pipeline"))?;
    if !matches!(results.as_slice(), [Value::Null, Value::SimpleString(_)]) {
        return Err(format!("pipeline returned {results:?}"));
    }
    client
        .set_stream(
            b"stream",
            STREAM_VALUE.len(),
            [
                Bytes::from_static(&STREAM_VALUE[..5]),
                Bytes::from_static(&STREAM_VALUE[5..]),
            ]
            .into_iter(),
        )
        .await
        .map_err(e("set_stream"))?;

    // Renamed, coalesced path, instrumented.
    let builder = Client::builder(connect().await?)
        .get_command("X.GET")
        .set_command("X.SET")
        .max_batch_size(4)
        .on_result(|_| {});
    #[cfg(feature = "metrics")]
    let builder = builder.with_metrics();
    let mut client = builder.build();
    fire_all(&mut client).await?;

    // Renamed and instrumented: the async SETs report the renamed request's
    // length in `tx_bytes`.
    let mut client = Client::builder(connect().await?)
        .set_command("X.SET")
        .on_result(|r| TX_BYTES.lock().unwrap().push(r.tx_bytes))
        .build();
    client.set("k", "v").await.map_err(e("instrumented set"))?;
    client
        .set_ex("k", "v", 60)
        .await
        .map_err(e("instrumented set_ex"))?;
    client
        .set_with_guard(b"big", big_guard())
        .await
        .map_err(e("instrumented set_with_guard"))?;
    client
        .set_ex_with_guard(b"big", big_guard(), 60)
        .await
        .map_err(e("instrumented set_ex_with_guard"))?;

    // Only SET renamed: GET stays GET.
    let mut client = Client::builder(connect().await?)
        .set_command("X.SET")
        .build();
    client.get("hit").await.map_err(e("set-only get"))?;
    client.set("k", "v").await.map_err(e("set-only set"))?;

    // No options: GET and SET.
    let mut client = Client::new(connect().await?);
    client.fire_get(b"hit", 1).map_err(e("default fire_get"))?;
    client.recv().await.map_err(e("default recv"))?;
    client.set("k", "v").await.map_err(e("default set"))?;
    client
        .set_with_guard(b"big", big_guard())
        .await
        .map_err(e("default set_with_guard"))?;
    Ok(())
}

struct ClientHandler;

impl AsyncEventHandler for ClientHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let addr = *SERVER_ADDR.get().expect("server addr not set");
        Some(Box::pin(async move {
            RESULT.set(run(addr).await).ok();
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        ClientHandler
    }
}

#[test]
fn custom_get_and_set_names_reach_the_wire() {
    let (s_runtime, s_handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<RecordingServer>()
        .expect("server launch failed");
    let addr = s_runtime.bound_addr().expect("bound address");
    wait_for_server(&addr.to_string());
    // wait_for_server's probe connections send nothing, so SEEN stays empty.
    SERVER_ADDR.set(addr).ok();

    let (c_runtime, c_handles) = RinglineBuilder::new(test_config())
        .launch::<ClientHandler>()
        .expect("client launch failed");
    common::join_workers(&c_runtime, c_handles);

    s_runtime.shutdown();
    for h in s_handles {
        h.join().unwrap().unwrap();
    }

    let result = RESULT.get().expect("client did not set a result");
    if let Err(e) = result {
        panic!("client failed: {e}");
    }

    let fired = |get: &str, set: &str| {
        vec![
            (get.to_string(), 2),
            (get.to_string(), 2),
            (set.to_string(), 3),
            (set.to_string(), 3),
            (set.to_string(), 5),
        ]
    };
    let mut want = fired("X.GET", "X.SET");
    want.extend([
        ("X.GET".to_string(), 2), // get
        ("X.SET".to_string(), 3), // set
        ("X.SET".to_string(), 5), // set_ex
        ("X.SET".to_string(), 3), // set_with_guard
        ("X.SET".to_string(), 5), // set_ex_with_guard
        ("X.GET".to_string(), 2), // pipeline get
        ("X.SET".to_string(), 3), // pipeline set
        ("X.SET".to_string(), 3), // set_stream
    ]);
    want.extend(fired("X.GET", "X.SET"));
    want.extend([
        ("X.SET".to_string(), 3),
        ("X.SET".to_string(), 5),
        ("X.SET".to_string(), 3),
        ("X.SET".to_string(), 5),
    ]);
    want.extend([("GET".to_string(), 2), ("X.SET".to_string(), 3)]);
    want.extend([
        ("GET".to_string(), 2),
        ("SET".to_string(), 3),
        ("SET".to_string(), 3),
    ]);
    let seen = SEEN.lock().unwrap().clone();
    assert_eq!(seen, want);

    // `*3\r\n$5\r\nX.SET\r\n$1\r\nk\r\n$1\r\nv\r\n` is 29 bytes; the EX form
    // adds `$2\r\nEX\r\n$2\r\n60\r\n` (16) and has a `*5` header. Under the name
    // `SET` they would be 27 and 43. The guarded SETs of the 8192-byte value
    // to `big` are a 31-byte prefix, the value, and `\r\n` (8225) or the
    // 18-byte EX suffix (8241).
    assert_eq!(*TX_BYTES.lock().unwrap(), vec![29, 45, 8225, 8241]);
}
