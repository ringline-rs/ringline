#![allow(clippy::manual_async_fn)]
//! Integration tests: `AsyncSendBuilder::submit_batch_await` delivers the
//! batch byte-exactly *and* resolves its `SendFuture`.
//!
//! The awaited variant exists so a caller can pace itself against send
//! completion instead of firing and forgetting. Yielding to the executor is
//! not a substitute: a self-wake is re-polled inside the same ready-queue
//! drain pass, before the event loop revisits the ring, so it never lets a
//! send CQE land. These tests pin the two properties a caller depends on:
//! the wire bytes are unchanged from `submit_batch`, and awaiting the future
//! actually returns (with the full byte count) rather than hanging.
//!
//! Both backends are covered: on io_uring the future is woken by the send
//! CQE, on the mio fallback by the event loop once the bytes reach the
//! socket.

use ringline::ConfigBuilder;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ringline::{
    AsyncEventHandler, Config, ConnCtx, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard, SendPart,
};

const PREFIX: &[u8] = b"PFX:";
const SUFFIX: &[u8] = b":SFX";
const VLEN: usize = 16384;

fn value_byte(i: usize) -> u8 {
    (i.wrapping_mul(7).wrapping_add(13) % 251) as u8
}

fn value_of_len(len: usize) -> Vec<u8> {
    (0..len).map(value_byte).collect()
}

fn expected_payload() -> Vec<u8> {
    let mut v = Vec::with_capacity(PREFIX.len() + VLEN + SUFFIX.len());
    v.extend_from_slice(PREFIX);
    v.extend(value_of_len(VLEN));
    v.extend_from_slice(SUFFIX);
    v
}

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// Sends copy(PREFIX) + guard(value) + copy(SUFFIX) as one awaited batch,
/// then reports the resolved byte count as a trailing `OK:<n>` line. The
/// trailer can only appear if the future resolved.
struct AwaitedBatchSender;

impl AsyncEventHandler for AwaitedBatchSender {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let guard = GuardBox::new(VecGuard(value_of_len(VLEN)));
            let parts = vec![
                SendPart::Copy(PREFIX),
                SendPart::Guard(guard),
                SendPart::Copy(SUFFIX),
            ];

            match conn.send_parts().submit_batch_await(parts) {
                Ok((count, fut)) => match fut.await {
                    Ok(sent) => {
                        let _ = conn.send_nowait(format!("OK:{count}:{sent}").as_bytes());
                    }
                    Err(e) => {
                        let _ = conn.send_nowait(format!("AWAIT_ERR:{e}").as_bytes());
                    }
                },
                Err(e) => {
                    let _ = conn.send_nowait(format!("ERR:{e}").as_bytes());
                }
            }

            loop {
                let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        AwaitedBatchSender
    }
}

/// Reports how an empty batch is rejected. A batch carrying no bytes
/// produces no completion, so returning a future that could never resolve
/// would hang the caller.
struct EmptyBatchSender;

impl AsyncEventHandler for EmptyBatchSender {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let reply = match conn.send_parts().submit_batch_await(Vec::new()) {
                Ok(_) => "UNEXPECTED_OK".to_string(),
                Err(e) => format!("KIND:{:?}", e.kind()),
            };
            let _ = conn.send_nowait(reply.as_bytes());

            loop {
                let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        EmptyBatchSender
    }
}

// ── Harness ─────────────────────────────────────────────────────────

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(64, 4096)
        .max_connections(64)
        .send_pool(64, 16384)
        .build()
        .expect("valid config")
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

/// Launch `H`, trigger one send, and read exactly `want` bytes.
fn run_case<H: AsyncEventHandler + 'static>(want: usize) -> Vec<u8> {
    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let bound = shutdown
        .bound_addr()
        .expect("bound_addr should be Some after a TCP bind");
    let addr = bound.to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"go").unwrap();
    stream.flush().unwrap();

    let mut buf = vec![0u8; want];
    let mut total = 0;
    while total < want {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                panic!("read timed out after 5s with {total}/{want} bytes")
            }
            Err(e) => panic!("read error: {e}"),
        }
    }
    buf.truncate(total);

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    buf
}

// ── Tests ───────────────────────────────────────────────────────────

/// The batch lands byte-exactly and the future resolves with the full
/// logical byte count -- not a short count from one chunk of a multi-chunk
/// send, and not never.
#[test]
fn submit_batch_await_delivers_and_resolves() {
    let payload = expected_payload();
    let trailer = format!("OK:3:{}", payload.len());
    let want = payload.len() + trailer.len();

    let buf = run_case::<AwaitedBatchSender>(want);

    assert_eq!(
        buf.len(),
        want,
        "short read -- future likely never resolved (got {} of {want} bytes: {:?})",
        buf.len(),
        String::from_utf8_lossy(&buf[payload.len().min(buf.len())..]),
    );
    assert_eq!(
        &buf[..payload.len()],
        &payload[..],
        "batch bytes differ from prefix ++ value ++ suffix",
    );
    assert_eq!(
        String::from_utf8_lossy(&buf[payload.len()..]),
        trailer,
        "future resolved with an unexpected byte count",
    );
}

/// An empty batch is rejected rather than handing back a future that can
/// never be woken.
#[test]
fn submit_batch_await_rejects_empty_batch() {
    let expected = format!("KIND:{:?}", io::ErrorKind::InvalidInput);
    let buf = run_case::<EmptyBatchSender>(expected.len());
    assert_eq!(String::from_utf8_lossy(&buf), expected);
}
