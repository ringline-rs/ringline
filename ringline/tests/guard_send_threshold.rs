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
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, Config, Connection, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard,
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

// ── Server-side trace, for a client timeout (#513) ──────────────────

/// Handler steps as (client port, time, event), shared by every test in this
/// binary (#513).
///
/// Each handler records its steps under the client's ephemeral port. When the
/// client's read times out or ends short, it prints the steps recorded under
/// its own local port. The tests run in parallel and share this list; the port
/// separates their connections only while no two connections in the process
/// use the same port, which is likely but not guaranteed.
static TRACE: Mutex<Vec<(u16, Instant, String)>> = Mutex::new(Vec::new());

/// The client's ephemeral port, read once when the handler starts. `0` if the
/// connection has no TCP peer address.
fn client_port(conn: &Connection) -> u16 {
    match conn.peer_addr() {
        Some(ringline::PeerAddr::Tcp(a)) => a.port(),
        _ => 0,
    }
}

fn trace(port: u16, event: impl Into<String>) {
    let event = event.into();
    TRACE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((port, Instant::now(), event));
}

/// The server-side steps for the client on `port` since `t0`, one per line.
///
/// With `timed_out_at`, steps recorded after that offset are marked, so a
/// handler that ran late is distinguishable from one that never ran.
fn trace_for(port: u16, t0: Instant, timed_out_at: Option<Duration>) -> String {
    let trace = TRACE.lock().unwrap_or_else(|e| e.into_inner());
    let steps: Vec<String> = trace
        .iter()
        .filter(|(p, at, _)| *p == port && *at >= t0)
        .map(|(_, at, ev)| {
            let offset = at.duration_since(t0);
            let late = match timed_out_at {
                Some(limit) if offset > limit => " (after the timeout)",
                _ => "",
            };
            format!("  +{:.1}ms {ev}{late}", offset.as_secs_f64() * 1000.0)
        })
        .collect();
    if steps.is_empty() {
        format!(
            "  (none recorded by +{:.1}ms)",
            t0.elapsed().as_secs_f64() * 1000.0
        )
    } else {
        steps.join("\n")
    }
}

/// Opens a second connection to `addr`, sends the trigger, and reports what it
/// received and what the handler recorded for it.
///
/// After a timeout this separates a server that still serves connections from
/// one whose worker is stuck.
fn probe(addr: &str, want: usize) -> String {
    let t0 = Instant::now();
    let mut stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => return format!("probe: connect failed: {e}"),
    };
    let port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.write_all(b"go");
    let mut buf = vec![0u8; want];
    let mut total = 0;
    while total < want {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    format!(
        "probe (client port {port}): received {total}/{want} bytes in {:.1}ms\n{}",
        t0.elapsed().as_secs_f64() * 1000.0,
        trace_for(port, t0, None)
    )
}

// ── Handler ─────────────────────────────────────────────────────────

/// On the first recv (trigger), sends copy(PREFIX) + guard(value of VLEN
/// rolling bytes) + copy(SUFFIX) via `send_parts()`, then keeps the
/// connection open (so any in-flight ZC guard stays valid) until the client
/// closes.
struct GuardPartsSender<const VLEN: usize>;

impl<const VLEN: usize> AsyncEventHandler for GuardPartsSender<VLEN> {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let port = client_port(&conn);
            trace(port, "accepted");
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            trace(port, format!("trigger with_data -> {n} bytes"));
            if n == 0 {
                return;
            }

            let guard = GuardBox::new(VecGuard(value_of_len(VLEN)));
            let result = conn
                .send_parts()
                .build(|b| b.copy(PREFIX).guard(guard).copy(SUFFIX).submit());
            trace(port, format!("send_parts -> {result:?}"));
            if let Err(e) = result {
                let r = conn.send_nowait(format!("ERR:{e}").as_bytes());
                trace(port, format!("ERR send_nowait -> {r:?}"));
            }

            // Keep the connection open until the client finishes reading.
            loop {
                let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
                if n == 0 {
                    trace(port, "client closed");
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        GuardPartsSender
    }
}

#[cfg(has_io_uring)]
/// Chain variant: sends TWO scatter-gather SQEs (each copy(PREFIX) +
/// guard(value) + copy(SUFFIX)) linked in one chain via `send_chain`.
/// Exercises `ChainPartsBuilder::add`, whose sub-threshold guard fold is
/// separate from `SendBuilder::submit`'s.
struct ChainGuardPartsSender<const VLEN: usize>;

#[cfg(has_io_uring)]
impl<const VLEN: usize> AsyncEventHandler for ChainGuardPartsSender<VLEN> {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let port = client_port(&conn);
            trace(port, "accepted");
            let n = conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            trace(port, format!("trigger with_data -> {n} bytes"));
            if n == 0 {
                return;
            }

            let g1 = GuardBox::new(VecGuard(value_of_len(VLEN)));
            let g2 = GuardBox::new(VecGuard(value_of_len(VLEN)));
            let result = conn.send_chain_nowait(|c| {
                c.parts()
                    .copy(PREFIX)
                    .guard(g1)
                    .copy(SUFFIX)
                    .add()
                    .parts()
                    .copy(PREFIX)
                    .guard(g2)
                    .copy(SUFFIX)
                    .add()
                    .finish()
            });
            trace(port, format!("send_chain_nowait -> {result:?}"));
            if let Err(e) = result {
                let r = conn.send_nowait(format!("ERR:{e}").as_bytes());
                trace(port, format!("ERR send_nowait -> {r:?}"));
            }

            loop {
                let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
                if n == 0 {
                    trace(port, "client closed");
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ChainGuardPartsSender
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
    run_case_with::<GuardPartsSender<VLEN>, VLEN>(config, 1);
}

/// Chain variant: two linked part-groups → two copies of the payload.
/// The chain API (`send_chain_nowait`) only exists on the io_uring backend.
#[cfg(has_io_uring)]
fn run_case_chain<const VLEN: usize>(config: Config) {
    run_case_with::<ChainGuardPartsSender<VLEN>, VLEN>(config, 2);
}

/// Launch `H` with `config`, trigger one send, and assert `copies`
/// byte-exact repetitions of `PREFIX ++ value ++ SUFFIX`.
fn run_case_with<H: AsyncEventHandler + 'static, const VLEN: usize>(config: Config, copies: usize) {
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let bound = shutdown
        .bound_addr()
        .expect("bound_addr should be Some after a TCP bind");
    let addr = bound.to_string();
    wait_for_server(&addr);

    let t0 = Instant::now();
    let mut stream = TcpStream::connect(&addr).unwrap();
    let port = stream.local_addr().unwrap().port();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"go").unwrap();
    stream.flush().unwrap();

    let expected: Vec<u8> = expected_payload(VLEN).repeat(copies);
    let mut buf = vec![0u8; expected.len()];
    let mut total = 0;
    let want = expected.len();
    while total < want {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let timed_out_at = t0.elapsed();
                // Steps that land in this second show a late handler.
                std::thread::sleep(Duration::from_secs(1));
                let probe = probe(&addr, want);
                panic!(
                    "read timed out at +{:.1}ms with {total}/{want} bytes; server side \
                     (client port {port}):\n{}\n{probe}",
                    timed_out_at.as_secs_f64() * 1000.0,
                    trace_for(port, t0, Some(timed_out_at))
                )
            }
            Err(e) => panic!("read error: {e}"),
        }
    }
    assert_eq!(
        total,
        want,
        "received {total} bytes; server side (client port {port}):\n{}",
        trace_for(port, t0, None)
    );
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

#[cfg(has_io_uring)]
/// Chained sub-threshold guard sends take the small-gather fold in
/// `ChainPartsBuilder::add` (previously chain parts always paid the ZC
/// path regardless of size).
#[test]
fn chain_guard_send_below_threshold_small_gather() {
    let config = test_config();
    run_case_chain::<SMALL_VALUE>(config);
}

/// Threshold 1: the chain fold can't fire — same payload through the
/// chained ZC path.
#[cfg(has_io_uring)]
#[test]
fn chain_guard_send_above_threshold_zc() {
    let config = test_config_builder()
        .send_zc_threshold(1)
        .build()
        .expect("valid config");
    run_case_chain::<SMALL_VALUE>(config);
}

/// Chained large values exceed the threshold — ZC path, two linked SQEs.
#[cfg(has_io_uring)]
#[test]
fn chain_guard_send_large_value_zc() {
    let config = test_config();
    run_case_chain::<LARGE_VALUE>(config);
}
