#![allow(clippy::manual_async_fn)]
//! `AsyncSendBuilder::submit_batch_admitted`: a refusal returns every part,
//! guards included, and a batch that waits for pool slots is admitted when
//! they return.

mod common;

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::task::Poll;
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard, SendPart,
};

/// The guard's length where a scenario needs a zero-copy-sized one.
const GUARD_LEN: usize = 16384;
/// Large enough for one whole TLS record on the unbuffered record layer.
const SLOT: u32 = 16448;
const SLOTS: u16 = 8;

/// A guard over heap memory, reporting `region`.
struct VecGuard {
    data: Vec<u8>,
    region: RegionId,
}

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.data.as_ptr(), self.data.len() as u32)
    }
    fn region(&self) -> RegionId {
        self.region
    }
}

fn guard(len: usize) -> GuardBox {
    GuardBox::new(VecGuard {
        data: (0..len).map(|i| (i % 251) as u8).collect(),
        region: RegionId::UNREGISTERED,
    })
}

/// What a scenario's batch resolved to.
#[derive(Debug, Clone, PartialEq)]
struct Outcome {
    /// `None` when the batch was admitted.
    refused: Option<io::ErrorKind>,
    /// Parts in the refusal.
    parts_back: usize,
    /// Byte lengths of the guards in the refusal, in order.
    guard_lens: Vec<u32>,
    /// Whether the batch's first poll was pending.
    waited: bool,
}

static OUTCOMES: Mutex<Vec<(u8, Outcome)>> = Mutex::new(Vec::new());
/// Bytes the waiting scenario queued before its batch.
static FILLED: AtomicUsize = AtomicUsize::new(0);
/// Set by the waiting scenario once its batch is pending.
static WAITING: AtomicBool = AtomicBool::new(false);
/// The registered region (base address, id) for the region scenario.
#[cfg(has_io_uring)]
static REGION: OnceLock<(usize, RegionId)> = OnceLock::new();
#[cfg(not(has_io_uring))]
#[allow(dead_code)]
static REGION: OnceLock<(usize, RegionId)> = OnceLock::new();

/// The tests share statics and run one runtime each; one at a time.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const EMPTY: u8 = b'e';
const ABORTED: u8 = b'a';
const SHUT: u8 = b's';
const TOO_LARGE: u8 = b'l';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const COPY_OVER_SLOT: u8 = b'c';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const TOO_MANY_PARTS: u8 = b'p';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const TOO_MANY_GUARDS: u8 = b'g';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const OUT_OF_REGION: u8 = b'r';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const SLAB_FULL: u8 = b'f';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const OVER_CAP: u8 = b'h';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const OVER_CAP_PLAIN: u8 = b'H';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const OVER_CAP_SMALL: u8 = b'm';
const WAITS: u8 = b'w';
const TIMED_OUT: u8 = b't';
const WAIT_SHUT: u8 = b'W';
const SENT: u8 = b'S';
const GUARDS_ONLY: u8 = b'o';
const PASS_PANIC: u8 = b'x';

/// The idle peer the passing scenario connects to; it reads everything.
static READER: Mutex<Option<std::net::SocketAddr>> = Mutex::new(None);
/// Calls of `PanicGuard::as_ptr_len`.
static PANIC_CALLS: AtomicUsize = AtomicUsize::new(0);
/// What the passing scenario saw: whether the batch's task panicked, and B
/// straight after a send admitted at the head once the panic was contained.
static PANIC_SEEN: Mutex<Option<(bool, u64)>> = Mutex::new(None);

/// A guard whose `as_ptr_len` panics from its third call on. Before the
/// admission decision a batch's first poll calls it once on mio
/// (`total_part_len`) and twice on io_uring (`total_part_len`, then
/// `batch_plain_slots`). The submit's first call is the second on mio (the
/// gather's `total_part_len`) and the third on io_uring
/// (`batch_plain_ready`), so the third call falls inside the submit of a
/// batch admitted past the head on both backends.
struct PanicGuard([u8; 64]);

impl SendGuard for PanicGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        if PANIC_CALLS.fetch_add(1, Ordering::SeqCst) >= 2 {
            panic!("guard code panicked");
        }
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

/// B on this worker now.
fn passing_held() -> u64 {
    ringline::send_admission_counters().passing_held
}

/// Poll `f` once from the current task.
async fn poll_once<F: Future + Unpin>(f: &mut F) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(std::pin::Pin::new(&mut *f).poll(cx))).await
}

/// More than the socket buffers take, on a connection whose peer does not
/// read: a zero-copy guard on io_uring, 16 MiB of plain sends (which take no
/// pool slot) on mio.
#[cfg(has_io_uring)]
fn fill_socket(conn: &mut Connection) {
    let big = vec![SendPart::Guard(guard(8 << 20))];
    conn.send_parts().submit_batch(big).expect("fill accepted");
}

#[cfg(not(has_io_uring))]
fn fill_socket(conn: &mut Connection) {
    for _ in 0..256 {
        conn.send(&[1; 1 << 16]).expect("queued");
    }
}

/// On `conn`, whose peer does not read: a full socket, four bounded sends
/// behind it holding four of the eight slots, and a head that needs six and
/// waits. A batch on an idle connection then passes the head, and its
/// guard panics in the submit. Once that task's panic is contained, a send
/// admitted at the head on another connection must not count as passing.
async fn pass_and_panic(conn: &mut Connection) {
    static QUEUED: [u8; SLOT as usize] = [1; SLOT as usize];
    static HEAD: [u8; 6 * SLOT as usize] = [2; 6 * SLOT as usize];
    static SMALL: [u8; 100] = [3; 100];
    let reader = READER.lock().unwrap().expect("reader");
    fill_socket(conn);
    let mut queued = Vec::new();
    for _ in 0..4 {
        queued.push(conn.send_admitted(&QUEUED).await.expect("admitted"));
    }
    let mut head = conn.send_admitted(&HEAD);
    assert!(poll_once(&mut head).await.is_pending(), "the head waits");

    let task = ringline::spawn_with_handle(async move {
        let mut idle = ringline::connect(reader).await.expect("connect the reader");
        let parts = vec![
            SendPart::Copy(b"h"),
            SendPart::Guard(GuardBox::new(PanicGuard([4; 64]))),
        ];
        let _ = idle.send_parts().submit_batch_admitted(parts).await;
    })
    .expect("spawn");
    let panicked = task.await.is_err();
    drop(head);

    let mut other = ringline::connect(reader).await.expect("connect the reader");
    let mut sent = other.send_admitted(&SMALL);
    let first = poll_once(&mut sent).await;
    let held = passing_held();
    assert!(matches!(first, Poll::Ready(Ok(_))), "admitted at the head");
    *PANIC_SEEN.lock().unwrap() = Some((panicked, held));
    conn.abort();
}

/// A send's error kind and message, or `None` if it was accepted.
type SendError = Option<(io::ErrorKind, String)>;

/// `zero_copy_capped` on the over-cap scenario's connection once it holds its
/// three entries.
#[cfg_attr(not(has_io_uring), allow(dead_code))]
static OVER_CAP_CAPPED: Mutex<Option<bool>> = Mutex::new(None);

/// The outcomes of the over-cap scenario's sends that are not a
/// `submit_batch_admitted`.
#[cfg_attr(not(has_io_uring), allow(dead_code))]
static OVER_CAP_ERRORS: Mutex<Vec<(u8, SendError)>> = Mutex::new(Vec::new());

/// Three zero-copy batches larger than the socket takes, to a client that
/// does not read, hold three of the slab's four entries. A zero-copy batch on
/// the same connection is then tried three ways: `submit_batch_admitted`
/// (recorded as `OVER_CAP`), `submit_batch` (`OVER_CAP_PLAIN`). Last, a
/// `submit_batch` below `send_zc_threshold`, which is gathered into one pool
/// slot (`OVER_CAP_SMALL`).
#[cfg(has_io_uring)]
async fn over_cap(conn: &mut Connection) {
    let mut held = Vec::new();
    for _ in 0..3 {
        let big = vec![SendPart::Guard(guard(8 << 20))];
        held.push(conn.send_parts().submit_batch(big).expect("held batch"));
    }
    *OVER_CAP_CAPPED.lock().unwrap() = Some(conn.zero_copy_capped());
    let outcome = match conn
        .send_parts()
        .submit_batch_admitted(parts_for(OVER_CAP))
        .await
    {
        Ok((n, _sent)) => Outcome {
            refused: None,
            parts_back: n,
            guard_lens: Vec::new(),
            waited: false,
        },
        Err(r) => refused_outcome(r, false),
    };
    record(OVER_CAP, outcome);
    let plain = conn
        .send_parts()
        .submit_batch(parts_for(OVER_CAP_PLAIN))
        .map(drop)
        .err()
        .map(|e| (e.kind(), e.to_string()));
    let small = conn
        .send_parts()
        .submit_batch(vec![SendPart::Copy(b"h"), SendPart::Guard(guard(1000))])
        .map(drop)
        .err()
        .map(|e| (e.kind(), e.to_string()));
    let mut errors = OVER_CAP_ERRORS.lock().unwrap();
    errors.push((OVER_CAP_PLAIN, plain));
    errors.push((OVER_CAP_SMALL, small));
    drop(errors);
    conn.abort();
}

#[cfg(not(has_io_uring))]
async fn over_cap(_conn: &mut Connection) {}

/// The batch the waiting scenario sends once admitted.
const HEADER: &[u8] = b"HDR:";

fn parts_for(scenario: u8) -> Vec<SendPart<'static>> {
    match scenario {
        EMPTY => vec![SendPart::Copy(b""), SendPart::Guard(guard(0))],
        ABORTED | SHUT => vec![SendPart::Copy(b"h"), SendPart::Guard(guard(GUARD_LEN))],
        // More than the whole pool, so it can never be admitted.
        TOO_LARGE => vec![
            SendPart::Copy(b"h"),
            SendPart::Guard(guard(SLOT as usize * SLOTS as usize + 1)),
        ],
        COPY_OVER_SLOT => vec![
            SendPart::Copy(&[b'c'; SLOT as usize + 1]),
            SendPart::Guard(guard(GUARD_LEN)),
        ],
        TOO_MANY_PARTS => {
            let mut parts: Vec<SendPart<'static>> = (0..32).map(|_| SendPart::Copy(b"x")).collect();
            parts.push(SendPart::Guard(guard(GUARD_LEN)));
            parts
        }
        TOO_MANY_GUARDS => (0..9).map(|_| SendPart::Guard(guard(GUARD_LEN))).collect(),
        OUT_OF_REGION => {
            let (_, id) = *REGION.get().expect("region registered");
            // Heap memory claiming the registered region.
            vec![SendPart::Guard(GuardBox::new(VecGuard {
                data: vec![b'r'; GUARD_LEN],
                region: id,
            }))]
        }
        SLAB_FULL | OVER_CAP | OVER_CAP_PLAIN => {
            vec![SendPart::Copy(b"h"), SendPart::Guard(guard(GUARD_LEN))]
        }
        WAITS | WAIT_SHUT | SENT => {
            vec![SendPart::Copy(HEADER), SendPart::Guard(guard(GUARD_LEN))]
        }
        GUARDS_ONLY => vec![SendPart::Guard(guard(GUARD_LEN))],
        other => panic!("unknown scenario {other}"),
    }
}

fn record(scenario: u8, outcome: Outcome) {
    OUTCOMES.lock().unwrap().push((scenario, outcome));
}

fn parts_outcome(refused: Option<io::ErrorKind>, parts: &[SendPart<'_>], waited: bool) -> Outcome {
    let guard_lens = parts
        .iter()
        .filter_map(|p| match p {
            SendPart::Guard(g) => Some(g.as_ptr_len().1),
            SendPart::Copy(_) => None,
        })
        .collect();
    Outcome {
        refused,
        parts_back: parts.len(),
        guard_lens,
        waited,
    }
}

fn refused_outcome(refused: ringline::BatchRefused<'_>, waited: bool) -> Outcome {
    parts_outcome(Some(refused.error.kind()), &refused.parts, waited)
}

/// Fill the send pool with bounded sends until one has to wait. The client
/// does not read until `WAITING` is set, so the socket fills and the sends
/// queued hold their slots. Returns the bytes queued.
async fn fill_pool(conn: &mut Connection) -> usize {
    let chunk = vec![b'f'; SLOT as usize];
    let mut queued = 0usize;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let admitted = {
            let mut send = pin!(conn.send_admitted(&chunk));
            std::future::poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx))).await
        };
        match admitted {
            Poll::Ready(Ok(_)) => queued += chunk.len(),
            Poll::Ready(Err(e)) => panic!("filling the pool: {e}"),
            Poll::Pending => return queued,
        }
        assert!(Instant::now() < deadline, "the pool never filled");
        ringline::sleep(Duration::from_millis(1)).await;
    }
}

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
            match trigger {
                ABORTED => conn.abort(),
                SHUT => conn.shutdown_write(),
                SLAB_FULL => {
                    // Holds the only slab entry: a zero-copy batch larger than
                    // the socket takes while the client does not read.
                    let big = vec![SendPart::Guard(guard(8 << 20))];
                    let _held = conn.send_parts().submit_batch(big).expect("first batch");
                    let outcome = match conn
                        .send_parts()
                        .submit_batch_admitted(parts_for(SLAB_FULL))
                        .await
                    {
                        Ok(_) => Outcome {
                            refused: None,
                            parts_back: 0,
                            guard_lens: Vec::new(),
                            waited: false,
                        },
                        Err(r) => refused_outcome(r, false),
                    };
                    record(SLAB_FULL, outcome);
                    return;
                }
                OVER_CAP => {
                    over_cap(&mut conn).await;
                    return;
                }
                WAITS => {
                    FILLED.store(fill_pool(&mut conn).await, Ordering::SeqCst);
                    let mut batch = pin!(conn.send_parts().submit_batch_admitted(parts_for(WAITS)));
                    let first =
                        std::future::poll_fn(|cx| Poll::Ready(batch.as_mut().poll(cx))).await;
                    let (waited, result) = match first {
                        Poll::Ready(r) => (false, r),
                        Poll::Pending => {
                            WAITING.store(true, Ordering::SeqCst);
                            (true, batch.await)
                        }
                    };
                    let outcome = match result {
                        Ok((n, sent)) => {
                            sent.await.expect("the admitted batch settles");
                            Outcome {
                                refused: None,
                                parts_back: n,
                                guard_lens: Vec::new(),
                                waited,
                            }
                        }
                        Err(r) => refused_outcome(r, waited),
                    };
                    record(WAITS, outcome);
                    while conn
                        .with_data(|data| ParseResult::Consumed(data.len()))
                        .await
                        > 0
                    {}
                    return;
                }
                WAIT_SHUT => {
                    fill_pool(&mut conn).await;
                    let mut batch = conn
                        .send_parts()
                        .submit_batch_admitted(parts_for(WAIT_SHUT));
                    let waited = poll_once(&mut batch).await.is_pending();
                    conn.shutdown_write();
                    let outcome = match batch.await {
                        Ok(_) => Outcome {
                            refused: None,
                            parts_back: 0,
                            guard_lens: Vec::new(),
                            waited,
                        },
                        Err(r) => refused_outcome(r, waited),
                    };
                    record(WAIT_SHUT, outcome);
                    conn.abort();
                    return;
                }
                SENT | GUARDS_ONLY => {
                    let outcome = match conn
                        .send_parts()
                        .submit_batch_admitted(parts_for(trigger))
                        .await
                    {
                        Ok((n, sent)) => {
                            sent.await.expect("the batch settles");
                            Outcome {
                                refused: None,
                                parts_back: n,
                                guard_lens: Vec::new(),
                                waited: false,
                            }
                        }
                        Err(r) => refused_outcome(r, false),
                    };
                    record(trigger, outcome);
                    while conn
                        .with_data(|data| ParseResult::Consumed(data.len()))
                        .await
                        > 0
                    {}
                    return;
                }
                TIMED_OUT => {
                    fill_pool(&mut conn).await;
                    let mut batch = conn.send_parts().submit_batch_admitted(parts_for(WAITS));
                    let outcome =
                        match ringline::timeout(Duration::from_millis(50), &mut batch).await {
                            Ok(Ok(_)) => Outcome {
                                refused: None,
                                parts_back: 0,
                                guard_lens: Vec::new(),
                                waited: false,
                            },
                            Ok(Err(r)) => refused_outcome(r, false),
                            Err(_elapsed) => {
                                let parts = batch.into_parts();
                                parts_outcome(Some(io::ErrorKind::TimedOut), &parts, true)
                            }
                        };
                    record(TIMED_OUT, outcome);
                    conn.abort();
                    return;
                }
                PASS_PANIC => {
                    pass_and_panic(&mut conn).await;
                    return;
                }
                _ => {}
            }
            let outcome = match conn
                .send_parts()
                .submit_batch_admitted(parts_for(trigger))
                .await
            {
                Ok((n, _sent)) => Outcome {
                    refused: None,
                    parts_back: n,
                    guard_lens: Vec::new(),
                    waited: false,
                },
                Err(r) => refused_outcome(r, false),
            };
            record(trigger, outcome);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Scenarios
    }
}

fn launch(
    slab_slots: u16,
    tls: Option<ringline::TlsConfig>,
) -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
) {
    launch_capped(slab_slots, 16, tls)
}

fn launch_capped(
    slab_slots: u16,
    zero_copy_hold_cap: usize,
    tls: Option<ringline::TlsConfig>,
) -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
) {
    let mut builder = ConfigBuilder::new()
        .zero_copy_hold_cap(zero_copy_hold_cap)
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(SLOTS, SLOT)
        .send_slab_slots(slab_slots)
        .max_registered_regions(4);
    if let Some(tls) = tls {
        builder = builder.tls(tls);
    }
    let config = builder.build().expect("valid config");
    RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Scenarios>()
        .expect("launch")
}

fn wait_outcome(scenario: u8) -> Outcome {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        {
            let mut outcomes = OUTCOMES.lock().unwrap();
            if let Some(pos) = outcomes.iter().position(|(s, _)| *s == scenario) {
                return outcomes.remove(pos).1;
            }
        }
        assert!(
            Instant::now() < deadline,
            "scenario {scenario} never resolved"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Runs a refusal scenario over plaintext and returns its outcome.
fn run(scenario: u8, slab_slots: u16) -> Outcome {
    let (runtime, handles) = launch(slab_slots, None);
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream.write_all(&[scenario]).unwrap();
    let outcome = wait_outcome(scenario);
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    outcome
}

fn assert_refused(outcome: &Outcome, kind: io::ErrorKind, parts: usize, guard_lens: &[u32]) {
    assert_eq!(outcome.refused, Some(kind), "{outcome:?}");
    assert_eq!(
        outcome.parts_back, parts,
        "every part comes back: {outcome:?}"
    );
    assert_eq!(
        outcome.guard_lens, guard_lens,
        "every guard comes back: {outcome:?}"
    );
}

#[test]
fn an_empty_batch_is_refused_with_its_parts() {
    let _serial = serial();
    let outcome = run(EMPTY, 64);
    assert_refused(&outcome, io::ErrorKind::InvalidInput, 2, &[0]);
}

#[test]
fn a_batch_after_abort_is_refused_with_its_parts() {
    let _serial = serial();
    let outcome = run(ABORTED, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::ConnectionAborted,
        2,
        &[GUARD_LEN as u32],
    );
}

#[test]
fn a_batch_after_shutdown_write_is_refused_with_its_parts() {
    let _serial = serial();
    let outcome = run(SHUT, 64);
    assert_refused(&outcome, io::ErrorKind::BrokenPipe, 2, &[GUARD_LEN as u32]);
}

/// On mio the whole batch is copied, so a batch longer than the pool can
/// never be admitted. On io_uring a plaintext batch's guards take no pool
/// slot, so the same batch is sent.
#[cfg(not(has_io_uring))]
#[test]
fn a_batch_longer_than_the_pool_is_refused_with_its_parts() {
    let _serial = serial();
    let outcome = run(TOO_LARGE, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        2,
        &[SLOT * SLOTS as u32 + 1],
    );
}

#[cfg(has_io_uring)]
#[test]
fn copy_parts_over_one_slot_are_refused_with_their_parts() {
    let _serial = serial();
    let outcome = run(COPY_OVER_SLOT, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        2,
        &[GUARD_LEN as u32],
    );
}

#[cfg(has_io_uring)]
#[test]
fn more_than_32_parts_are_refused_with_their_parts() {
    let _serial = serial();
    let outcome = run(TOO_MANY_PARTS, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        33,
        &[GUARD_LEN as u32],
    );
}

#[cfg(has_io_uring)]
#[test]
fn more_than_8_guards_are_refused_with_their_parts() {
    let _serial = serial();
    let outcome = run(TOO_MANY_GUARDS, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        9,
        &[GUARD_LEN as u32; 9],
    );
}

#[cfg(has_io_uring)]
#[test]
fn a_guard_outside_its_region_is_refused_with_its_parts() {
    use ringline::MemoryRegion;
    const REGION_LEN: usize = 1 << 16;
    let _serial = serial();
    let (runtime, handles) = launch(64, None);
    if REGION.get().is_none() {
        let backing: &'static mut [u8] = Box::leak(vec![0u8; REGION_LEN].into_boxed_slice());
        // SAFETY: leaked, so valid and unmoved for the life of the process.
        let region = unsafe { MemoryRegion::new(backing.as_mut_ptr(), REGION_LEN) };
        // As `disk_fixed_buffers.rs`: retry a transient ENOMEM or EFAULT.
        let deadline = Instant::now() + Duration::from_secs(5);
        let id = loop {
            match runtime.register_region(region.clone()) {
                Ok(id) => break id,
                Err(e) => {
                    let msg = e.to_string();
                    let transient = msg.contains("(ENOMEM)") || msg.contains("(EFAULT)");
                    assert!(
                        transient && Instant::now() < deadline,
                        "register_region: {e}"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        REGION.set((backing.as_mut_ptr() as usize, id)).unwrap();
    }
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream.write_all(&[OUT_OF_REGION]).unwrap();
    let outcome = wait_outcome(OUT_OF_REGION);
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        1,
        &[GUARD_LEN as u32],
    );
}

/// With one slab entry, held by a zero-copy send the client does not read, a
/// waiting batch with a guard is admitted for its slot and refused for the
/// slab.
#[cfg(has_io_uring)]
#[test]
fn a_full_slab_refuses_a_batch_with_its_parts() {
    let _serial = serial();
    let outcome = run(SLAB_FULL, 1);
    assert_refused(&outcome, io::ErrorKind::WouldBlock, 2, &[GUARD_LEN as u32]);
}

/// Runs the over-cap scenario with a four-entry slab and `cap`, and returns
/// the admitted batch's outcome and the plain batch's and the gathered
/// batch's errors.
#[cfg(has_io_uring)]
fn run_over_cap(cap: usize) -> (Outcome, SendError, SendError) {
    OVER_CAP_ERRORS.lock().unwrap().clear();
    *OVER_CAP_CAPPED.lock().unwrap() = None;
    let (runtime, handles) = launch_capped(4, cap, None);
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream.write_all(&[OVER_CAP]).unwrap();
    let outcome = wait_outcome(OVER_CAP);
    let deadline = Instant::now() + Duration::from_secs(10);
    while OVER_CAP_ERRORS.lock().unwrap().len() < 2 {
        assert!(Instant::now() < deadline, "the over-cap sends never ran");
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    let errors = std::mem::take(&mut *OVER_CAP_ERRORS.lock().unwrap());
    let find = |s: u8| errors.iter().find(|(k, _)| *k == s).unwrap().1.clone();
    (outcome, find(OVER_CAP_PLAIN), find(OVER_CAP_SMALL))
}

/// A connection holds three of four slab entries, so the slab is over half
/// used, and `zero_copy_hold_cap` is 2. A zero-copy batch on it is refused
/// although an entry is free: `submit_batch_admitted` returns its parts with
/// `WouldBlock`, and `submit_batch` fails with `Other`. A batch
/// small enough to be gathered into one pool slot takes no entry and is sent.
#[cfg(has_io_uring)]
#[test]
fn a_connection_at_the_zero_copy_cap_is_refused_with_a_free_entry() {
    let _serial = serial();
    let (outcome, plain, small) = run_over_cap(2);
    assert_eq!(*OVER_CAP_CAPPED.lock().unwrap(), Some(true));
    assert_refused(&outcome, io::ErrorKind::WouldBlock, 2, &[GUARD_LEN as u32]);
    let (kind, message) = plain.expect("submit_batch was accepted");
    assert_eq!(kind, io::ErrorKind::Other, "submit_batch: {message}");
    assert!(
        message.contains("zero_copy_hold_cap"),
        "submit_batch: {message}"
    );
    assert_eq!(small, None, "the gathered batch was refused");
}

/// The same connection with `zero_copy_hold_cap` 4: the batch takes the free
/// entry. The connection then holds four, so the plain batch after it is
/// refused at the cap.
#[cfg(has_io_uring)]
#[test]
fn a_connection_below_the_zero_copy_cap_takes_the_free_entry() {
    let _serial = serial();
    let (outcome, plain, _small) = run_over_cap(4);
    assert_eq!(*OVER_CAP_CAPPED.lock().unwrap(), Some(false));
    assert_eq!(outcome.refused, None, "{outcome:?}");
    let (kind, message) = plain.expect("the connection is at the cap");
    assert_eq!(kind, io::ErrorKind::Other, "{message}");
    assert!(message.contains("zero_copy_hold_cap"), "{message}");
}

/// The pool is full of sends to a client that does not read. The batch's
/// first poll is pending; once the client reads, the slots return and the
/// batch is admitted and delivered after the queued bytes.
#[test]
fn a_waiting_batch_is_admitted_when_slots_return() {
    let _serial = serial();
    WAITING.store(false, Ordering::SeqCst);
    let (runtime, handles) = launch(64, None);
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(&[WAITS]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !WAITING.load(Ordering::SeqCst) {
        if let Some((_, o)) = OUTCOMES.lock().unwrap().iter().find(|(s, _)| *s == WAITS) {
            panic!("the batch resolved without waiting: {o:?}");
        }
        assert!(Instant::now() < deadline, "the batch never waited");
        std::thread::sleep(Duration::from_millis(1));
    }
    let filled = FILLED.load(Ordering::SeqCst);
    let mut got = vec![0u8; filled + HEADER.len() + GUARD_LEN];
    stream.read_exact(&mut got).expect("every byte delivered");
    let outcome = wait_outcome(WAITS);
    assert_eq!(
        outcome,
        Outcome {
            refused: None,
            parts_back: 2,
            guard_lens: Vec::new(),
            waited: true,
        }
    );
    assert!(got[..filled].iter().all(|&b| b == b'f'));
    assert_eq!(&got[filled..filled + HEADER.len()], HEADER);
    let value: Vec<u8> = (0..GUARD_LEN).map(|i| (i % 251) as u8).collect();
    assert_eq!(&got[filled + HEADER.len()..], &value[..]);
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// A runtime with TLS and a client connected to it.
fn launch_tls() -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
    TlsStream,
) {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let tls = ringline::TlsConfig::builder()
        .cert(vec![der.clone()], key.into())
        .build()
        .expect("tls config");
    let (runtime, handles) = launch(64, Some(tls));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from("localhost").unwrap();
    let client = rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    let sock = TcpStream::connect(runtime.bound_addr().expect("bound")).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    (runtime, handles, rustls::StreamOwned::new(client, sock))
}

fn expected_value() -> Vec<u8> {
    (0..GUARD_LEN).map(|i| (i % 251) as u8).collect()
}

/// Over TLS every part is copied and the batch waits for the ciphertext
/// bound of its length, so one longer than the pool is refused, with its
/// parts.
#[test]
fn a_tls_batch_longer_than_the_pool_is_refused_with_its_parts() {
    let _serial = serial();
    let (runtime, handles, mut stream) = launch_tls();
    stream.write_all(&[TOO_LARGE]).expect("handshake and write");
    let outcome = wait_outcome(TOO_LARGE);
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        2,
        &[SLOT * SLOTS as u32 + 1],
    );
}

/// A TLS batch is admitted, encrypted and delivered in part order.
#[test]
fn a_tls_batch_is_delivered() {
    let _serial = serial();
    let (runtime, handles, mut stream) = launch_tls();
    stream.write_all(&[SENT]).expect("handshake and write");
    let mut got = vec![0u8; HEADER.len() + GUARD_LEN];
    stream.read_exact(&mut got).expect("the batch delivered");
    let outcome = wait_outcome(SENT);
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    assert_eq!(outcome.refused, None, "{outcome:?}");
    assert_eq!(outcome.parts_back, 2);
    assert_eq!(&got[..HEADER.len()], HEADER);
    assert_eq!(&got[HEADER.len()..], &expected_value()[..]);
}

/// A plaintext batch is delivered in part order, and a batch of guards
/// alone (which joins no FIFO on io_uring) is delivered too.
#[test]
fn plaintext_batches_are_delivered() {
    let _serial = serial();
    for (scenario, prefix) in [(SENT, HEADER), (GUARDS_ONLY, &b""[..])] {
        let (runtime, handles) = launch(64, None);
        let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(&[scenario]).unwrap();
        let mut got = vec![0u8; prefix.len() + GUARD_LEN];
        stream.read_exact(&mut got).expect("the batch delivered");
        let outcome = wait_outcome(scenario);
        drop(stream);
        runtime.shutdown();
        common::join_workers(&runtime, handles);
        assert_eq!(outcome.refused, None, "{outcome:?}");
        assert_eq!(&got[..prefix.len()], prefix);
        assert_eq!(&got[prefix.len()..], &expected_value()[..]);
    }
}

/// A batch waiting for slots when the write half is shut down is refused
/// with its parts.
#[test]
fn a_waiting_batch_refused_by_shutdown_write_returns_its_parts() {
    let _serial = serial();
    let outcome = run(WAIT_SHUT, 64);
    assert!(outcome.waited, "the batch waited first: {outcome:?}");
    assert_refused(&outcome, io::ErrorKind::BrokenPipe, 2, &[GUARD_LEN as u32]);
}

/// A waiting batch whose wait expires gives every part back through
/// `into_parts`.
#[test]
fn a_timed_out_batch_gives_its_parts_back() {
    let _serial = serial();
    let outcome = run(TIMED_OUT, 64);
    assert_refused(&outcome, io::ErrorKind::TimedOut, 2, &[GUARD_LEN as u32]);
}

/// A guard that panics in the submit of a batch admitted past the head
/// leaves the pool marking nothing as passing afterwards.
#[test]
fn a_guard_panic_while_passing_leaves_no_slot_marked() {
    let _serial = serial();
    PANIC_CALLS.store(0, Ordering::SeqCst);
    *PANIC_SEEN.lock().unwrap() = None;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the reader");
    *READER.lock().unwrap() = Some(listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            std::thread::spawn(move || {
                let mut sink = Vec::new();
                let _ = stream.expect("accept").read_to_end(&mut sink);
            });
        }
    });
    let (runtime, handles) = launch(64, None);
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream.write_all(&[PASS_PANIC]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let seen = loop {
        if let Some(seen) = *PANIC_SEEN.lock().unwrap() {
            break seen;
        }
        assert!(Instant::now() < deadline, "the scenario never finished");
        std::thread::sleep(Duration::from_millis(1));
    };
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    assert!(
        PANIC_CALLS.load(Ordering::SeqCst) >= 3,
        "the guard's third call ran"
    );
    assert_eq!(seen, (true, 0), "(the batch's task panicked, B after it)");
}
