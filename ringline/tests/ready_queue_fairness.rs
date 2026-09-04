#![allow(clippy::manual_async_fn)]
//! Regression test: one task that repeatedly wakes itself must not starve the
//! rest of a worker.
//!
//! A task that self-wakes mid-poll has its slot read `Empty`, so the wake
//! cannot transition it; the event loop re-queues it via `woken_while_polling`
//! right after it parks. The ready-queue drain condition re-reads
//! `ready_queue.len()`, so without a budget that re-queued task is polled
//! again inside the same pass -- indefinitely, never returning to
//! `submit_and_wait` / `drain_completions`. Nothing else on the worker runs:
//! no new connection is accepted, no recv is processed, and no send completion
//! is reaped (so send-pool slots never recycle).
//!
//! This test pins the fairness property: a second connection is serviced
//! while a first connection's task is in an unbounded self-wake loop.

use ringline::ConfigBuilder;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConnCtx, ParseResult, RinglineBuilder};

/// Set by the test to release the spinning task so shutdown can complete.
static STOP: AtomicBool = AtomicBool::new(false);

/// Yield to the executor once: wake our own waker, then return `Pending`.
fn yield_once() -> impl Future<Output = ()> {
    let mut yielded = false;
    std::future::poll_fn(move |cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
}

/// `spin` → self-wake until released. `ping` → reply `pong`.
struct SpinOrPong;

impl AsyncEventHandler for SpinOrPong {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let mut spin = false;
            let n = conn
                .with_data(|data| {
                    spin = data.starts_with(b"spin");
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n == 0 {
                return;
            }

            if spin {
                // Belt-and-braces deadline so a regression cannot hang the
                // suite forever -- the assertion still fails first.
                let deadline = Instant::now() + Duration::from_secs(30);
                while !STOP.load(Ordering::Relaxed) && Instant::now() < deadline {
                    yield_once().await;
                }
                return;
            }

            let _ = conn.send_nowait(b"pong");

            loop {
                let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SpinOrPong
    }
}

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

/// A single worker, so both connections share one ready queue.
#[test]
fn self_waking_task_does_not_starve_the_worker() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(64, 4096)
        .max_connections(64)
        .send_pool(64, 16384)
        .build()
        .expect("valid config");

    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SpinOrPong>()
        .expect("launch failed");
    let addr = shutdown
        .bound_addr()
        .expect("bound_addr should be Some after a TCP bind")
        .to_string();
    wait_for_server(&addr);

    // Connection A: park the worker in a self-wake loop.
    let mut spinner = TcpStream::connect(&addr).unwrap();
    spinner.write_all(b"spin").unwrap();
    spinner.flush().unwrap();

    // Give the spinner time to be accepted and start looping.
    std::thread::sleep(Duration::from_millis(200));

    // Connection B: must still be serviced.
    let result = (|| -> io::Result<Vec<u8>> {
        let mut client = TcpStream::connect(&addr)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        client.write_all(b"ping")?;
        client.flush()?;
        let mut buf = vec![0u8; 4];
        let mut total = 0;
        while total < buf.len() {
            match client.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        buf.truncate(total);
        Ok(buf)
    })();

    // Release the spinner before asserting, so shutdown can join cleanly
    // even when the assertion below fails.
    STOP.store(true, Ordering::Relaxed);
    drop(spinner);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }

    match result {
        Ok(buf) => assert_eq!(
            buf, b"pong",
            "second connection was serviced but replied unexpectedly",
        ),
        Err(e) => panic!(
            "second connection was starved by a self-waking task ({e}) -- \
             the ready-queue drain re-polls a self-woken task within the same \
             pass, so the worker never returns to the event loop",
        ),
    }
}
