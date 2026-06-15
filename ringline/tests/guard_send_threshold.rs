#![allow(clippy::manual_async_fn)]
//! Integration tests: wire-format correctness of guard sends on both sides of
//! the `send_zc_threshold`.
//!
//! A `send_parts()` send built as copy(prefix) + guard(value) + copy(suffix)
//! must deliver exactly `prefix ++ value ++ suffix` regardless of which
//! internal path is taken:
//!
//! - total < threshold → small-gather: everything (guard memory included) is
//!   copied into one send-pool slot and submitted as a plain `Send`
//! - total >= threshold, or threshold == 0 (disabled) → SendMsgZc zero-copy
//!
//! The threshold branch only exists on the io_uring backend; on the mio
//! fallback all `send_parts()` sends degrade to a single copy send, so these
//! tests still pass there (and pin the same wire format), but only exercise
//! the small-gather/ZC branch selection on Linux with io_uring.

use ringline::ConfigBuilder;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ringline::{
    AsyncEventHandler, Config, ConnCtx, GuardBox, ParseResult, RegionId, RinglineBuilder, SendGuard,
};

const PREFIX: &[u8] = b"PFX:";
const SUFFIX: &[u8] = b":SFX";

/// Rolling (non-constant) value pattern so part-reordering bugs can't cancel
/// out against a uniform payload.
fn value_byte(i: usize) -> u8 {
    (i.wrapping_mul(7).wrapping_add(13) % 251) as u8
}

fn value_of_len(len: usize) -> Vec<u8> {
    (0..len).map(value_byte).collect()
}

fn expected_payload(value_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(PREFIX.len() + value_len + SUFFIX.len());
    v.extend_from_slice(PREFIX);
    v.extend(value_of_len(value_len));
    v.extend_from_slice(SUFFIX);
    v
}

// ── Guard over heap memory ──────────────────────────────────────────

/// Guard that owns its heap buffer. The Vec keeps the bytes alive until the
/// guard is dropped (after the ZC notification on the zero-copy path, or
/// immediately after the gather-copy on the small-gather path).
struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        // Unregistered memory: skips fixed-region pointer validation.
        RegionId::UNREGISTERED
    }
}

// ── Handler ─────────────────────────────────────────────────────────

/// On the first recv (trigger), sends copy(PREFIX) + guard(value of VLEN
/// rolling bytes) + copy(SUFFIX) via `send_parts()`, then keeps the
/// connection open (so any in-flight ZC guard stays valid) until the client
/// closes.
struct GuardPartsSender<const VLEN: usize>;

impl<const VLEN: usize> AsyncEventHandler for GuardPartsSender<VLEN> {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            if n == 0 {
                return;
            }

            let guard = GuardBox::new(VecGuard(value_of_len(VLEN)));
            let result = conn
                .send_parts()
                .build(|b| b.copy(PREFIX).guard(guard).copy(SUFFIX).submit());
            if let Err(e) = result {
                let _ = conn.send_nowait(format!("ERR:{e}").as_bytes());
            }

            // Keep the connection open until the client finishes reading.
            loop {
                let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        GuardPartsSender
    }
}

// ── Harness ─────────────────────────────────────────────────────────

fn test_config_builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(64, 4096)
        .max_connections(64)
        .send_pool(64, 16384)
}

fn test_config() -> Config {
    test_config_builder().build().expect("valid config")
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

/// Launch a `GuardPartsSender::<VLEN>` server with `config`, trigger one
/// guard send, and assert the byte-exact `PREFIX ++ value ++ SUFFIX` echo.
fn run_case<const VLEN: usize>(config: Config) {
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<GuardPartsSender<VLEN>>()
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

    let expected = expected_payload(VLEN);
    let mut buf = vec![0u8; expected.len()];
    let mut total = 0;
    let want = expected.len();
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
    assert_eq!(total, want, "received {total} bytes");
    assert!(
        !buf.starts_with(b"ERR:"),
        "server-side send_parts failed: {}",
        String::from_utf8_lossy(&buf)
    );
    assert!(
        buf == expected,
        "guard send bytes differ from prefix ++ value ++ suffix \
         (got prefix {:?} ... suffix {:?})",
        &buf[..PREFIX.len().min(total)],
        &buf[total.saturating_sub(SUFFIX.len())..total],
    );

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Tests ───────────────────────────────────────────────────────────

const SMALL_VALUE: usize = 64;
const LARGE_VALUE: usize = 16384;

/// Default threshold (4096): 4 + 64 + 4 = 72 bytes total, well under — takes
/// the small-gather copy path on io_uring.
#[test]
fn guard_send_below_threshold_small_gather() {
    let config = test_config();
    assert_eq!(
        config.send_zc_threshold(),
        4096,
        "default threshold changed"
    );
    run_case::<SMALL_VALUE>(config);
}

/// Threshold 1: the same 72-byte payload can't satisfy `total < threshold`,
/// so the small-gather branch can't fire — exercises the ZC path with the
/// identical payload and assertions.
#[test]
fn guard_send_above_threshold_zc() {
    let config = test_config_builder()
        .send_zc_threshold(1)
        .build()
        .expect("valid config");
    run_case::<SMALL_VALUE>(config);
}

/// Threshold 0 (disabled): small-gather is off entirely — ZC path, same
/// payload and assertions.
#[test]
fn guard_send_threshold_disabled_zc() {
    let config = test_config_builder()
        .send_zc_threshold(0)
        .build()
        .expect("valid config");
    run_case::<SMALL_VALUE>(config);
}

/// Default threshold with a 16 KiB guard value: the total gather exceeds the
/// 4096-byte threshold, so this is automatically the ZC path.
#[test]
fn guard_send_large_value_zc() {
    let config = test_config();
    run_case::<LARGE_VALUE>(config);
}
