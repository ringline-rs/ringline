#![allow(clippy::manual_async_fn)]
//! Sends that back up behind a peer that has half-closed and is not reading
//! must wait for room without spinning the event loop, and must deliver every
//! byte once the peer reads.
//!
//! On io_uring a `sendmsg` to such a peer returns `-EAGAIN`, and a `POLLOUT`
//! poll on it completes at once with `POLLRDHUP`, so a loop that retried the
//! `sendmsg` behind a poll spun at the ring's round-trip rate (#603). Each test
//! here drives one send path into that state. The `*_waits_and_delivers`
//! tests count event-loop iterations (`on_tick`) while the peer does not read
//! and compare the count with the loop's idle rate; the `shutdown_*` tests
//! check that a worker exits promptly while such a send waits. The spin check
//! for coalesced copy sends is `deferred_close_does_not_spin_on_half_closed_peer`
//! in `echo.rs`, and the coalesced send's drain is covered by
//! `coalesced_eagain_drains_with_a_plain_send` in the io_uring event loop's
//! unit tests.
//!
//! The tests share the tick counter, so they take a lock.

use std::future::Future;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId,
    RinglineBuilder, SendGuard,
};

/// Event-loop iterations of the runtime under test.
static TICKS: AtomicU32 = AtomicU32::new(0);

/// Serialises the tests, which share `TICKS`.
static LOCK: Mutex<()> = Mutex::new(());

/// More than loopback's socket buffers hold for a peer that does not read, so
/// the send backs up.
const LEN: usize = 8 * 1024 * 1024;

/// Byte `i` of every payload: a rolling pattern, so reordered or repeated
/// chunks fail the comparison.
fn pattern(i: usize) -> u8 {
    (i.wrapping_mul(7).wrapping_add(13) % 251) as u8
}

fn payload() -> Vec<u8> {
    (0..LEN).map(pattern).collect()
}

fn config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(64, 16384)
        .build()
        .expect("valid config")
}

/// Ticks counted over 500 ms.
fn ticks_over_500ms() -> u32 {
    let before = TICKS.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(500));
    TICKS.load(Ordering::Relaxed) - before
}

/// Checks the loop's rate once a send has backed up behind a half-closed peer
/// against its idle rate.
///
/// A healthy loop has nothing to complete while the peer does not read, so it
/// ticks at about its idle rate; the spin ran at more than 30 times idle. Four
/// times idle leaves room for scheduling noise, and the floor keeps a
/// near-zero baseline from making the bound too tight.
fn assert_no_spin(baseline: u32, ticks: u32) {
    let bound = baseline.max(200) * 4;
    assert!(
        ticks < bound,
        "event loop spun while a send waited on a half-closed peer: {ticks} ticks in \
         500 ms (idle baseline {baseline}, bound {bound})"
    );
}

/// Reads exactly `LEN` bytes and checks them against `pattern`.
fn read_payload(stream: &mut TcpStream, what: &str) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut got = vec![0u8; LEN];
    stream
        .read_exact(&mut got)
        .unwrap_or_else(|e| panic!("{what}: payload not delivered in full: {e}"));
    if let Some(i) = (0..LEN).find(|&i| got[i] != pattern(i)) {
        panic!("{what}: payload differs at byte {i}");
    }
}

fn connect(addr: std::net::SocketAddr) -> TcpStream {
    (0..200)
        .find_map(|_| match TcpStream::connect(addr) {
            Ok(s) => Some(s),
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
                None
            }
        })
        .expect("server did not accept the connection")
}

// ── Guard (zero-copy) send ──────────────────────────────────────────────

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

/// Reads until the peer's FIN, then sends `LEN` bytes from a guard. On
/// io_uring that is a `SendMsgZc`, which returned `-EAGAIN` once the socket
/// filled and failed the send.
struct GuardSendAfterFin;

impl AsyncEventHandler for GuardSendAfterFin {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
            let guard = GuardBox::new(VecGuard(payload()));
            conn.send_parts()
                .build(|b| b.guard(guard).submit())
                .expect("guard send accepted");
        }
    }
    fn on_tick(&mut self) {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
    fn create_for_worker(_id: usize) -> Self {
        GuardSendAfterFin
    }
}

#[test]
fn guard_send_to_a_half_closed_peer_waits_and_delivers() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<GuardSendAfterFin>()
        .expect("launch");
    let mut stream = connect(runtime.bound_addr().expect("bound address"));

    std::thread::sleep(Duration::from_millis(100));
    let baseline = ticks_over_500ms();

    stream.write_all(b"go").unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    // Let the send fill the socket and stall.
    std::thread::sleep(Duration::from_millis(200));
    let ticks = ticks_over_500ms();

    read_payload(&mut stream, "guard send");
    drop(stream);
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    assert_no_spin(baseline, ticks);
}

// ── Shutdown while a send waits ─────────────────────────────────────────

/// Reads until the peer's FIN, then sends 4 MiB as one copy send. On io_uring
/// it spans many send-pool slots and goes out as coalesced `sendmsg`s.
struct CopySendsAfterFin;

impl AsyncEventHandler for CopySendsAfterFin {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
            let data = vec![0x5Au8; 4 * 1024 * 1024];
            if let Ok(fut) = conn.send(&data) {
                let _ = fut.await;
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        CopySendsAfterFin
    }
}

/// Launches `H`, leaves a send waiting on a half-closed peer, then shuts the
/// runtime down and returns how long the workers took to exit.
fn shutdown_time_with_a_waiting_send<H: AsyncEventHandler>(config: Config) -> Duration {
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch");
    let mut stream = connect(runtime.bound_addr().expect("bound address"));
    stream.write_all(b"go").unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    // Let the send fill the socket and stall.
    std::thread::sleep(Duration::from_millis(300));

    let start = std::time::Instant::now();
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
    let took = start.elapsed();
    drop(stream);
    took
}

/// A worker exits promptly when a copy send is waiting for a peer that will
/// never read: shutdown cancels the send rather than waiting it out.
///
/// A zero-copy send in the same state is not covered: its guards stay in use
/// until the kernel's notification, which does not come while the data sits
/// in the socket, so shutdown waits out its bound for it (see
/// `run_shutdown`).
#[test]
fn shutdown_does_not_wait_out_copy_sends_to_a_half_closed_peer() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(512, 16384)
        .build()
        .expect("valid config");
    let took = shutdown_time_with_a_waiting_send::<CopySendsAfterFin>(config);
    assert!(
        took < Duration::from_secs(2),
        "worker took {took:?} to exit with copy sends waiting"
    );
}
