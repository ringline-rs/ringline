#![allow(clippy::manual_async_fn)]
//! `send_parts().build` and `forward_recv_buf` return a `SendCompletion` that
//! resolves with the length they sent, and `build` refuses, with
//! `InvalidInput` and nothing sent, a batch that carries no bytes and a
//! closure that returns without submitting.

use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// What each `build` scenario returned, keyed by the trigger byte: the
/// awaited length, or the error kind of the refusal.
static BUILT: Mutex<Vec<(u8, Result<u32, ErrorKind>)>> = Mutex::new(Vec::new());

/// Each forward's length and what its completion resolved with.
static FORWARDS: Mutex<Vec<(usize, Result<u32, String>)>> = Mutex::new(Vec::new());

/// Two copy parts, awaited.
const TWO_PARTS: u8 = b'p';
/// `submit` on a builder with no parts.
const EMPTY: u8 = b'e';
/// A closure that adds a part and returns `Ok` without calling `submit`.
const NO_SUBMIT: u8 = b'n';

const FIRST: &[u8] = &[b'a'; 10];
const SECOND: &[u8] = &[b'b'; 20];
/// Sent after a refused `build`, so the client can tell the refusal sent
/// nothing: it is the only byte the client reads.
const MARKER: &[u8] = b"m";

/// Runs the `build` scenario the client's first byte names and records the
/// result, then stays open until the client closes.
struct BuildScenarios;

impl AsyncEventHandler for BuildScenarios {
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
            let built = match trigger {
                TWO_PARTS => conn
                    .send_parts()
                    .build(|b| b.copy(FIRST).copy(SECOND).submit()),
                EMPTY => conn.send_parts().build(|b| b.submit()),
                NO_SUBMIT => conn.send_parts().build(|b| {
                    let _unsubmitted = b.copy(FIRST);
                    Ok(())
                }),
                other => panic!("unknown scenario {other}"),
            };
            let result = match built {
                Ok(sent) => sent.await.map_err(|e| e.kind()),
                Err(e) => {
                    conn.send(MARKER).expect("marker queued");
                    Err(e.kind())
                }
            };
            BUILT.lock().unwrap().push((trigger, result));
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        BuildScenarios
    }
}

/// Echoes with `forward_recv_buf`, awaiting each forward's completion before
/// the next read and recording its result.
struct ForwardEcho;

impl AsyncEventHandler for ForwardEcho {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let mut forwarded = None;
                let n = rx
                    .with_data(|data| {
                        if data.is_empty() {
                            return ParseResult::Consumed(0);
                        }
                        forwarded = Some((data.len(), tx.forward_recv_buf(data)));
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if let Some((len, sent)) = forwarded {
                    let result = match sent {
                        Ok(sent) => sent.await,
                        Err(e) => Err(e),
                    };
                    FORWARDS
                        .lock()
                        .unwrap()
                        .push((len, result.map_err(|e| e.to_string())));
                }
                if n == 0 {
                    break;
                }
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        ForwardEcho
    }
}

fn launch<H: AsyncEventHandler + 'static>() -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
) {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
        .expect("valid config");
    RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch")
}

/// Runs `scenario`, reads `expected` from the server, and returns what the
/// `build` resolved or was refused with.
fn run_build(scenario: u8, expected: &[u8]) -> Result<u32, ErrorKind> {
    let (runtime, handles) = launch::<BuildScenarios>();
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&[scenario]).unwrap();

    let mut got = vec![0u8; expected.len()];
    stream.read_exact(&mut got).expect("the server's bytes");
    assert_eq!(got, expected, "the bytes the server sent");

    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        {
            let mut results = BUILT.lock().unwrap();
            if let Some(pos) = results.iter().position(|(s, _)| *s == scenario) {
                break results.remove(pos).1;
            }
        }
        assert!(Instant::now() < deadline, "the build never resolved");
        std::thread::sleep(Duration::from_millis(1));
    };
    drop(stream);
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    result
}

#[test]
fn build_resolves_with_the_length_of_its_parts() {
    let expected = [FIRST, SECOND].concat();
    assert_eq!(
        run_build(TWO_PARTS, &expected),
        Ok((FIRST.len() + SECOND.len()) as u32)
    );
}

#[test]
fn build_refuses_an_empty_batch() {
    assert_eq!(run_build(EMPTY, MARKER), Err(ErrorKind::InvalidInput));
}

/// Before 0.7 the mio backend sent the parts of a closure that never called
/// `submit`, and io_uring did not. Both now send nothing and refuse.
#[test]
fn build_refuses_a_closure_that_does_not_submit() {
    assert_eq!(run_build(NO_SUBMIT, MARKER), Err(ErrorKind::InvalidInput));
}

#[test]
fn forward_recv_buf_resolves_with_the_forwarded_length() {
    const LEN: usize = 64 * 1024;
    let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let (runtime, handles) = launch::<ForwardEcho>();
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&payload).unwrap();
    let mut got = vec![0u8; LEN];
    stream.read_exact(&mut got).expect("the echo");
    assert_eq!(got, payload, "the echoed bytes");

    let deadline = Instant::now() + Duration::from_secs(5);
    let forwards = loop {
        {
            let forwards = FORWARDS.lock().unwrap();
            if forwards.iter().map(|(len, _)| len).sum::<usize>() == LEN {
                break forwards.clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "the forwards' completions never all resolved"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    for (len, result) in &forwards {
        assert_eq!(
            result.as_ref().map(|&n| n as usize),
            Ok(*len),
            "a forward's completion"
        );
    }

    drop(stream);
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
}
