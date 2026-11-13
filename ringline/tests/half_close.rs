//! A peer's FIN finishes the read half and closes nothing: the task keeps the
//! connection, may keep sending, and the connection closes when the task
//! ends (`docs/half-close-design.md`).

#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// The tests share statics, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn config() -> ringline::Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(64, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .build()
        .expect("valid config")
}

fn connect(addr: std::net::SocketAddr) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                return s;
            }
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("connect: {e}"),
        }
    }
}

/// Counts tasks dropped before they returned.
struct DroppedBeforeReturn(bool);

impl Drop for DroppedBeforeReturn {
    fn drop(&mut self) {
        if !self.0 {
            DROPPED_EARLY.fetch_add(1, Ordering::SeqCst);
        }
    }
}

static DROPPED_EARLY: AtomicUsize = AtomicUsize::new(0);

// ── A reply after a timer, with the peer half-closed ───────────────────

/// `(peer_closed, is_alive)` after the timer, and the last read's result.
static AFTER_TIMER: Mutex<Option<(bool, bool, usize)>> = Mutex::new(None);

/// Reads the request, waits on a timer, then sends the reply, reads to the
/// end and returns. A proxy awaiting an upstream reply has this shape.
struct ReplyAfterTimer;

impl AsyncEventHandler for ReplyAfterTimer {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut guard = DroppedBeforeReturn(false);
            let n = conn
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(d.len())
                    }
                })
                .await;
            if n == 0 {
                guard.0 = true;
                return;
            }
            ringline::sleep(Duration::from_millis(300)).await;
            let flags = (conn.peer_closed(), conn.is_alive());
            if let Ok(fut) = conn.send(b"reply") {
                let _ = fut.await;
            }
            let last = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
            *AFTER_TIMER.lock().unwrap() = Some((flags.0, flags.1, last));
            guard.0 = true;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ReplyAfterTimer
    }
}

/// The peer half-closes after its request while the task waits on a timer.
/// The task is not dropped: it wakes, sees the peer's end on `peer_closed`
/// with the connection still alive, sends the reply, reads `0` and returns,
/// and the peer reads the reply and then the FIN.
#[test]
fn a_task_awaiting_a_timer_survives_the_peers_fin_and_replies() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    *AFTER_TIMER.lock().unwrap() = None;
    DROPPED_EARLY.store(0, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ReplyAfterTimer>()
        .expect("launch");
    let mut peer = connect(runtime.bound_addr().unwrap());
    peer.write_all(b"request").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();

    let mut got = Vec::new();
    peer.read_to_end(&mut got)
        .expect("read the reply and the FIN");

    runtime.shutdown();
    common::join_workers(&runtime, handles);
    assert_eq!(got, b"reply", "the reply was not delivered after the FIN");
    assert_eq!(
        *AFTER_TIMER.lock().unwrap(),
        Some((true, true, 0)),
        "(peer_closed, is_alive, last read) after the timer"
    );
    assert_eq!(
        DROPPED_EARLY.load(Ordering::SeqCst),
        0,
        "the task was dropped before it returned"
    );
}

// ── Sends to a peer that closed fully ──────────────────────────────────

/// The kind of the first send error, as `ErrorKind as i32 + 1`; 0 is none.
static SEND_ERROR: AtomicU32 = AtomicU32::new(0);
static SENDER_RETURNED: AtomicUsize = AtomicUsize::new(0);
/// Sends that completed before the task returned or was dropped.
static SENDS_COMPLETED: AtomicUsize = AtomicUsize::new(0);

/// Reads the request and then to the end of the stream, then sends until a
/// send fails.
struct SendsUntilError;

impl AsyncEventHandler for SendsUntilError {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut guard = DroppedBeforeReturn(false);
            let n = conn
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(d.len())
                    }
                })
                .await;
            if n == 0 {
                guard.0 = true;
                return;
            }
            // Read to the end of the stream before the first send. Data that
            // reaches the peer before its close makes that close a reset,
            // which the read side reports and the runtime aborts on, dropping
            // this task before any send fails (#819).
            while conn.with_data(|d| ParseResult::Consumed(d.len())).await != 0 {}
            let chunk = [0x5au8; 4096];
            for _ in 0..500 {
                let result = match conn.send(&chunk) {
                    Ok(fut) => fut.await,
                    Err(e) => Err(e),
                };
                if let Err(e) = result {
                    SEND_ERROR.store(e.kind() as u32 + 1, Ordering::SeqCst);
                    break;
                }
                SENDS_COMPLETED.fetch_add(1, Ordering::SeqCst);
                ringline::sleep(Duration::from_millis(5)).await;
            }
            guard.0 = true;
            SENDER_RETURNED.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        SendsUntilError
    }
}

/// A task that has read to the end of the stream and then only sends on a
/// connection its peer closed fully gets the send error (the peer answers the
/// data with a reset) and returns.
#[test]
fn a_send_to_a_peer_that_closed_fully_fails() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    SEND_ERROR.store(0, Ordering::SeqCst);
    SENDER_RETURNED.store(0, Ordering::SeqCst);
    SENDS_COMPLETED.store(0, Ordering::SeqCst);
    DROPPED_EARLY.store(0, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SendsUntilError>()
        .expect("launch");
    let mut peer = connect(runtime.bound_addr().unwrap());
    peer.write_all(b"go").unwrap();
    drop(peer);

    let deadline = Instant::now() + Duration::from_secs(10);
    while SENDER_RETURNED.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the sending task never returned: dropped before return {}, sends completed {}",
            DROPPED_EARLY.load(Ordering::SeqCst),
            SENDS_COMPLETED.load(Ordering::SeqCst)
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    let kind = SEND_ERROR.load(Ordering::SeqCst);
    assert_ne!(kind, 0, "no send failed in 500 sends to a closed peer");
}

// ── A half-open idle connection does not spin the loop ─────────────────

static TICKS: AtomicU32 = AtomicU32::new(0);

/// Reads the request, then sleeps with the connection half-open.
struct SleepsAfterRequest;

impl AsyncEventHandler for SleepsAfterRequest {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let n = conn
                .with_data(|d| {
                    if d.is_empty() {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(d.len())
                    }
                })
                .await;
            if n == 0 {
                return;
            }
            ringline::sleep(Duration::from_secs(2)).await;
        }
    }
    fn on_tick(&mut self) {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
    fn create_for_worker(_id: usize) -> Self {
        SleepsAfterRequest
    }
}

fn ticks_over_500ms() -> u32 {
    let before = TICKS.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(500));
    TICKS.load(Ordering::Relaxed) - before
}

/// A connection whose peer half-closed, with nothing queued and its task
/// asleep, costs no event-loop iterations: the FIN is reported once, and
/// nothing is armed on the socket afterwards. The loop ticks at its idle rate,
/// measured first with the connection open.
#[test]
fn a_half_open_idle_connection_does_not_spin_the_event_loop() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SleepsAfterRequest>()
        .expect("launch");
    let mut peer = connect(runtime.bound_addr().unwrap());
    std::thread::sleep(Duration::from_millis(100));
    let baseline = ticks_over_500ms();

    peer.write_all(b"request").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let ticks = ticks_over_500ms();

    let mut got = Vec::new();
    peer.read_to_end(&mut got).expect("read to the FIN");

    runtime.shutdown();
    common::join_workers(&runtime, handles);
    // Four times idle leaves room for scheduling noise; the floor keeps a
    // near-zero baseline from making the bound too tight.
    let bound = baseline.max(200) * 4;
    assert!(
        ticks < bound,
        "event loop spun with a half-open idle connection: {ticks} ticks in 500 ms \
         (idle baseline {baseline}, bound {bound})"
    );
}
