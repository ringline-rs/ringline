//! Regression test for the recv-side collection cap.
//!
//! `Client::cmd`/`Pipeline::execute` read replies via `read_value`, which must
//! not cap array replies so low that ordinary large replies (a big `LRANGE`,
//! `FT.SEARCH` with large `k`, an oversized `SCAN` batch) trip
//! `CollectionTooLarge` and close the connection. `#[ignore]` — needs a Redis
//! or Valkey server on 127.0.0.1:6379.
//!
//!   cargo test -p ringline-redis --test recv_cap -- --ignored --nocapture

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use resp_proto::{Request, Value};
use ringline::{AsyncEventHandler, ConfigBuilder, ConnCtx, RinglineBuilder};
use ringline_redis::Client;

const ADDR: &str = "127.0.0.1:6379";
static RESULT: OnceLock<Result<usize, String>> = OnceLock::new();

/// Number of list elements to round-trip (over resp-proto's default 1024 cap).
fn n_from_env() -> usize {
    std::env::var("N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000)
}

#[test]
#[ignore]
fn lrange_over_1024_elements_round_trips() {
    if std::net::TcpStream::connect_timeout(&ADDR.parse().unwrap(), Duration::from_secs(2)).is_err()
    {
        panic!("server not reachable at {ADDR}");
    }

    struct H;
    impl AsyncEventHandler for H {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _c: ConnCtx) -> impl Future<Output = ()> + 'static {
            async {}
        }
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async move {
                let r = async {
                    let addr: SocketAddr = ADDR.parse().unwrap();
                    let conn = ringline::connect(addr)
                        .map_err(|e| format!("submit: {e}"))?
                        .await
                        .map_err(|e| format!("connect: {e:?}"))?;
                    let mut client = Client::builder(conn).build();
                    let n = n_from_env();

                    client
                        .cmd(&Request::cmd(b"DEL").arg(b"ringline-test:biglist"))
                        .await
                        .map_err(|e| format!("del: {e}"))?;
                    // Build the list in chunks so the request side stays small.
                    let mut i = 0;
                    while i < n {
                        let end = (i + 200).min(n);
                        let vals: Vec<String> = (i..end).map(|x| x.to_string()).collect();
                        let mut req = Request::cmd(b"RPUSH").arg(b"ringline-test:biglist");
                        for v in &vals {
                            req = req.arg(v.as_bytes());
                        }
                        client.cmd(&req).await.map_err(|e| format!("rpush: {e}"))?;
                        i = end;
                    }

                    // The reply is an `n`-element array; n > 1024 must not be
                    // rejected as CollectionTooLarge.
                    let reply = client
                        .cmd(
                            &Request::cmd(b"LRANGE")
                                .arg(b"ringline-test:biglist")
                                .arg(b"0")
                                .arg(b"-1"),
                        )
                        .await
                        .map_err(|e| format!("lrange: {e}"))?;
                    client
                        .cmd(&Request::cmd(b"DEL").arg(b"ringline-test:biglist"))
                        .await
                        .ok();
                    match reply {
                        Value::Array(items) => Ok::<usize, String>(items.len()),
                        other => Err(format!("unexpected reply {other:?}")),
                    }
                }
                .await;
                RESULT.set(r).ok();
                ringline::request_shutdown().ok();
            }))
        }
        fn create_for_worker(_id: usize) -> Self {
            H
        }
    }

    let cfg = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .build()
        .expect("valid config");
    let (_s, handles) = RinglineBuilder::new(cfg).launch::<H>().expect("launch");
    for h in handles {
        h.join().unwrap().unwrap();
    }
    match RESULT.get().expect("on_start did not set result") {
        Ok(len) => {
            let n = n_from_env();
            assert_eq!(*len, n, "LRANGE returned {len} elements, expected {n}");
            println!("LRANGE round-tripped {len} elements");
        }
        Err(e) => panic!("FAILED: {e}"),
    }
}
