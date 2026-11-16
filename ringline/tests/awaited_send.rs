#![allow(clippy::manual_async_fn)]
//! An awaited send resolves with its own send's result, not with the
//! completion of an earlier or later send on the same connection whose
//! completion was dropped (#617).

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard, SendPart,
};

/// What each scenario's awaited send returned, keyed by the trigger byte.
static AWAITED: Mutex<Vec<(u8, Result<u32, String>)>> = Mutex::new(Vec::new());

/// What the first of `TWO_AWAITED`'s sends returned.
static FIRST_OF_TWO: Mutex<Option<Result<u32, String>>> = Mutex::new(None);

/// The unawaited send that goes first.
const FIRST: usize = 1000;
/// The awaited send's length in the copy scenarios.
const SECOND: usize = 10;
/// The guard's length in the zero-copy scenario, above the default
/// `send_zc_threshold` so the batch is sent with `SendMsgZc`.
const GUARDED: usize = 16384;

/// A `send` whose completion is dropped, then an awaited `send`.
const UNAWAITED_THEN_SEND: u8 = b'1';
/// A `send` whose completion is dropped, then an awaited copy-only
/// `submit_batch`.
const UNAWAITED_THEN_COPY_BATCH: u8 = b'2';
/// A `send` whose completion is dropped, then an awaited zero-copy
/// `submit_batch`.
const UNAWAITED_THEN_ZC_BATCH: u8 = b'3';
/// A `send_chain` whose completion is dropped, then an awaited `send`.
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const CHAIN_UNAWAITED_THEN_SEND: u8 = b'4';
/// An awaited `send`, then a `send` submitted before the await whose
/// completion is dropped.
const SEND_THEN_UNAWAITED: u8 = b'5';
/// Two awaited sends in flight at once, the second awaited first.
const TWO_AWAITED: u8 = b'6';
/// An awaited `send` of no bytes.
const EMPTY_SEND: u8 = b'7';
/// A `send_chain` whose closure submits nothing.
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const EMPTY_CHAIN: u8 = b'8';

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

/// Runs the scenario the client's first byte names, records the awaited
/// send's result, and stays open until the client closes.
struct Scenarios;

impl AsyncEventHandler for Scenarios {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut trigger = 0u8;
            let n = conn
                .with_data(|data| {
                    trigger = data[0];
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n == 0 {
                return;
            }
            let result = match trigger {
                UNAWAITED_THEN_SEND => {
                    conn.send(&[b'a'; FIRST]).expect("unawaited send");
                    match conn.send(&[b'b'; SECOND]) {
                        Ok(fut) => fut.await,
                        Err(e) => Err(e),
                    }
                }
                UNAWAITED_THEN_COPY_BATCH => {
                    conn.send(&[b'a'; FIRST]).expect("unawaited send");
                    match conn
                        .send_parts()
                        .submit_batch(vec![SendPart::Copy(&[b'b'; SECOND])])
                    {
                        Ok((_, fut)) => fut.await,
                        Err(e) => Err(e),
                    }
                }
                UNAWAITED_THEN_ZC_BATCH => {
                    conn.send(&[b'a'; FIRST]).expect("unawaited send");
                    let guard = GuardBox::new(VecGuard(vec![b'b'; GUARDED]));
                    match conn.send_parts().submit_batch(vec![SendPart::Guard(guard)]) {
                        Ok((_, fut)) => fut.await,
                        Err(e) => Err(e),
                    }
                }
                #[cfg(has_io_uring)]
                CHAIN_UNAWAITED_THEN_SEND => {
                    conn.send_chain(|chain| chain.copy(&[b'a'; FIRST]).finish())
                        .expect("unawaited chain");
                    match conn.send(&[b'b'; SECOND]) {
                        Ok(fut) => fut.await,
                        Err(e) => Err(e),
                    }
                }
                SEND_THEN_UNAWAITED => match conn.send(&[b'b'; SECOND]) {
                    Ok(fut) => {
                        conn.send(&[b'a'; FIRST]).expect("unawaited send");
                        fut.await
                    }
                    Err(e) => Err(e),
                },
                TWO_AWAITED => {
                    let first = conn.send(&[b'a'; FIRST]);
                    let second = conn.send(&[b'b'; SECOND]);
                    match (first, second) {
                        (Ok(first), Ok(second)) => {
                            let second = second.await;
                            *FIRST_OF_TWO.lock().unwrap() =
                                Some(first.await.map_err(|e| e.to_string()));
                            second
                        }
                        (Err(e), _) | (_, Err(e)) => Err(e),
                    }
                }
                EMPTY_SEND => {
                    // Something to read, so the client knows the send ran.
                    conn.send(&[b'a'; FIRST]).expect("unawaited send");
                    match conn.send(&[]) {
                        Ok(fut) => fut.await,
                        Err(e) => Err(e),
                    }
                }
                #[cfg(has_io_uring)]
                EMPTY_CHAIN => {
                    conn.send(&[b'a'; FIRST]).expect("unawaited send");
                    match conn.send_chain(|_chain| Ok(())) {
                        Ok(fut) => fut.await,
                        Err(e) => Err(e),
                    }
                }
                other => panic!("unknown scenario {other}"),
            };
            AWAITED
                .lock()
                .unwrap()
                .push((trigger, result.map_err(|e| e.to_string())));
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Scenarios
    }
}

/// Runs `scenario`, reads `expected_bytes` from the server, and returns what
/// the awaited send resolved with.
fn run(scenario: u8, expected_bytes: usize) -> Result<u32, String> {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Scenarios>()
        .expect("launch");
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&[scenario]).unwrap();

    let mut got = vec![0u8; expected_bytes];
    stream.read_exact(&mut got).expect("every send delivered");

    let deadline = Instant::now() + Duration::from_secs(5);
    let awaited = loop {
        {
            let mut results = AWAITED.lock().unwrap();
            if let Some(pos) = results.iter().position(|(s, _)| *s == scenario) {
                break results.remove(pos).1;
            }
        }
        assert!(Instant::now() < deadline, "the awaited send never resolved");
        std::thread::sleep(Duration::from_millis(1));
    };
    drop(stream);
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    awaited
}

#[test]
fn an_awaited_send_reports_its_own_length() {
    let n = run(UNAWAITED_THEN_SEND, FIRST + SECOND).expect("the awaited send failed");
    assert_eq!(
        n as usize, SECOND,
        "the awaited send resolved with another send's result"
    );
}

#[test]
fn an_awaited_copy_batch_reports_its_own_length() {
    let n = run(UNAWAITED_THEN_COPY_BATCH, FIRST + SECOND).expect("the awaited batch failed");
    assert_eq!(
        n as usize, SECOND,
        "the awaited batch resolved with another send's result"
    );
}

#[test]
fn an_awaited_zero_copy_batch_reports_its_own_length() {
    let n = run(UNAWAITED_THEN_ZC_BATCH, FIRST + GUARDED).expect("the awaited batch failed");
    assert_eq!(
        n as usize, GUARDED,
        "the awaited batch resolved with another send's result"
    );
}

#[cfg(has_io_uring)]
#[test]
fn a_send_after_an_unawaited_chain_reports_its_own_length() {
    let n = run(CHAIN_UNAWAITED_THEN_SEND, FIRST + SECOND).expect("the awaited send failed");
    assert_eq!(
        n as usize, SECOND,
        "the awaited send resolved with the chain's result"
    );
}

/// The ordering opposite to #617: the awaited send goes first, and the
/// unawaited send behind it must not settle it. This passed before #617 was
/// fixed too; it guards the fix against settling the last send queued
/// rather than the awaited one.
#[test]
fn a_send_followed_by_an_unawaited_one_reports_its_own_length() {
    let n = run(SEND_THEN_UNAWAITED, SECOND + FIRST).expect("the awaited send failed");
    assert_eq!(
        n as usize, SECOND,
        "the awaited send resolved with a later send's result"
    );
}

#[test]
fn two_awaited_sends_in_flight_each_report_their_own_length() {
    let second = run(TWO_AWAITED, FIRST + SECOND).expect("the second send failed");
    let first = FIRST_OF_TWO
        .lock()
        .unwrap()
        .take()
        .expect("the first send resolved")
        .expect("the first send failed");
    assert_eq!(first as usize, FIRST, "the first send's result");
    assert_eq!(second as usize, SECOND, "the second send's result");
}

#[test]
fn an_awaited_empty_send_resolves_with_zero() {
    assert_eq!(run(EMPTY_SEND, FIRST).expect("the empty send failed"), 0);
}

#[cfg(has_io_uring)]
#[test]
fn a_chain_that_submits_nothing_resolves_with_zero() {
    assert_eq!(run(EMPTY_CHAIN, FIRST).expect("the empty chain failed"), 0);
}
