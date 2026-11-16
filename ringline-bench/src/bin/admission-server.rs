//! Server for the contended cases of Experiments B and C
//! (`docs/send-admission-design.md`, section 4).
//!
//! # Requests
//!
//! A request is 24 bytes, each field little-endian: the reply length (`u32`),
//! a tag (`u32`), flags (`u32`), a reserved word (`u32`, 0), and the time the
//! client scheduled the request, in nanoseconds of `CLOCK_MONOTONIC` (`u64`).
//! A client on the same host reads the same clock. The reply is that many
//! bytes, at least 8, starting with the tag and the length.
//!
//! Flags:
//! - bit 0: the client reads this connection slowly. The server reads it only
//!   to split its statistics.
//! - bit 1: send the reply with `send` and drop its `SendCompletion`, outside
//!   the send-capacity FIFO. The reply is neither small nor large. A refusal
//!   is counted and the request dropped, the connection stays open, and
//!   nothing waits for the reply to settle.
//! - bit 2: the client scheduled the request inside its measurement window.
//!   The statistics below count only these, except the samples of held
//!   slots; the counters count every request.
//!
//! # Sending
//!
//! - A reply of at most `--small-max` bytes is small. It is sent with the call
//!   `--small-send` names: `send_admitted`, which waits in the FIFO (order O0
//!   in the design), or `send`, which takes no place in it (O1). A `send` the
//!   pool refuses aborts the connection.
//! - A larger reply is large, and is always sent with `send_admitted`.
//! - Every wait for admission is bounded by `--admit-limit-ms`. A connection
//!   whose reply is not admitted within it is aborted.
//!
//! # Settling, and `--pipeline`
//!
//! A reply settles when its `SendCompletion` resolves, once the kernel has
//! taken its last byte. Each connection keeps the replies it has admitted and
//! not yet seen settle, oldest first, as the cache server this design is for
//! does (`Unsettled`), and reads a request only while fewer than `--pipeline`
//! are unsettled:
//!
//! - each reply is timed from its admission or, if later, from when the reply
//!   before it on the connection settled;
//! - before each send, the settled replies at the front are dropped without
//!   waiting;
//! - the read of the next request, and every wait for admission, race a watch
//!   that resolves once the oldest reply has been unsettled for
//!   `--settle-limit-ms`; the connection is then aborted, and the abort is
//!   counted as a settle abort of that reply;
//! - with `--pipeline` replies unsettled, the connection waits for the oldest
//!   to settle, bounded the same way, before it reads again.
//!
//! With `--pipeline 1`, the default, a connection answers one request at a
//! time, as in Experiment B: it sends the reply, waits up to
//! `--settle-limit-ms` from admission for it to settle, then reads the next
//! request.
//!
//! # Measurements
//!
//! Replies fall in three classes: small replies to fast readers, small
//! replies to slow readers (flag bit 0), and large replies.
//!
//! - For each admitted reply, by class: the delay from the request's scheduled
//!   time to its admission, and the delay from just before the call that
//!   admits it to that call's result. Admission is the return of `send` for a
//!   small reply under `--small-send send`, and the result of `send_admitted`
//!   otherwise. The first delay includes the time the request waited unread
//!   behind the connection's earlier replies; the second does not.
//! - By class, the requests that were not admitted, by reason, and the
//!   admitted replies by how they ended.
//! - For each large reply: its tag, length and scheduled time, its two delays
//!   or the reason it was not admitted, how it ended once admitted, and the
//!   mean of each class's held slots (below) over the samples from its
//!   scheduled time to its admission or removal.
//! - Every 10 ms a standalone task samples the send-pool slots held by each
//!   class. A reply counts `ceil(len / --slot-size)` slots from its admission
//!   until its task sees it settle, its connection is aborted, or the task
//!   stops watching it. That over-counts: the runtime returns each slot of a
//!   reply as the kernel takes the slot's bytes, before the reply settles, and
//!   a settled reply is counted until its task is next polled. An aborted
//!   connection's replies stop counting at the abort, before the runtime gets
//!   back the slots of a send the kernel holds. Replies sent outside the FIFO
//!   are not counted.
//!
//! The statistics are kept in a `Mutex`: only the worker thread takes it until
//! the worker has exited and `main` reads it, and `thread_local!` storage
//! would be dropped with the worker thread. One worker, so every connection
//! shares one send pool and one FIFO. The counters and statistics are printed
//! as one JSON line on SIGINT or SIGTERM.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};
use std::task::Poll;
use std::time::{Duration, Instant};

use clap::Parser;
use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, Either, ParseResult, RinglineBuilder,
    SendCompletion, SendHalf,
};
use serde_json::{Value, json};

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SmallSend {
    Admitted,
    Send,
}

#[derive(Parser)]
#[command(
    name = "admission-server",
    about = "The contended-case server of Experiments B and C"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7979")]
    addr: SocketAddr,
    /// How replies of at most `--small-max` bytes are sent: `admitted` is
    /// order O0, `send` is O1. The other orders need a runtime option; a flag
    /// that selects one belongs beside this one, and `send_reply` is the one
    /// place that chooses the call.
    #[arg(long, value_enum)]
    small_send: SmallSend,
    #[arg(long, default_value_t = 4096)]
    small_max: u32,
    #[arg(long)]
    admit_limit_ms: u64,
    #[arg(long)]
    settle_limit_ms: u64,
    /// Replies a connection may have admitted and unsettled before it stops
    /// reading requests.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    pipeline: u32,
    /// Send-pool slots.
    #[arg(long, default_value_t = 512)]
    pool_slots: u16,
    /// Send-pool slot size in bytes.
    #[arg(long, default_value_t = 16384)]
    slot_size: u32,
    /// Pin the worker to this CPU.
    #[arg(long, default_value_t = 0)]
    cpu: usize,
}

struct Settings {
    use_send: bool,
    small_max: usize,
    admit_limit: Duration,
    settle_limit: Duration,
    pipeline: usize,
    slot_size: usize,
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();

fn settings() -> &'static Settings {
    SETTINGS.get().expect("settings are set before launch")
}

const REQUEST_LEN: usize = 24;
const FLAG_SLOW: u32 = 1;
const FLAG_OUTSIDE: u32 = 1 << 1;
const FLAG_WINDOW: u32 = 1 << 2;
const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);

/// Reply classes, the index of every per-class array.
const FAST: usize = 0;
const SLOW: usize = 1;
const LARGE: usize = 2;
const CLASS_NAMES: [&str; 3] = ["small_fast", "small_slow", "large"];

/// Per class, over every request. `replies`, `failed` and `settle_aborts`
/// count admitted replies by how they ended; `refused` and `admit_timeouts`
/// count replies never admitted; `discarded` counts admitted replies dropped
/// unsettled when their connection was aborted for another reply. A failure
/// before admission counts in `failed`. A reply whose wait for admission ends
/// because an earlier reply on its connection stalled is counted only in the
/// statistics (`Unadmitted::SettleAbort`).
struct Counters {
    replies: [AtomicU64; 3],
    refused: [AtomicU64; 3],
    admit_timeouts: [AtomicU64; 3],
    settle_aborts: [AtomicU64; 3],
    failed: [AtomicU64; 3],
    discarded: [AtomicU64; 3],
}

static COUNTERS: Counters = Counters {
    replies: [const { AtomicU64::new(0) }; 3],
    refused: [const { AtomicU64::new(0) }; 3],
    admit_timeouts: [const { AtomicU64::new(0) }; 3],
    settle_aborts: [const { AtomicU64::new(0) }; 3],
    failed: [const { AtomicU64::new(0) }; 3],
    discarded: [const { AtomicU64::new(0) }; 3],
};

/// Replies sent outside the FIFO (flag bit 1): sent, refused by the pool, and
/// failed otherwise.
static OUTSIDE: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Send-pool slots held by admitted replies that have not been seen to
/// settle, per class. See the module docs for what this over-counts.
static HELD: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

fn count(counter: &[AtomicU64; 3], class: usize) {
    counter[class].fetch_add(1, Relaxed);
}

fn mono_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid `timespec` for the call to write.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn micros(from_ns: u64, to_ns: u64) -> u32 {
    u32::try_from(to_ns.saturating_sub(from_ns) / 1000).unwrap_or(u32::MAX)
}

/// Why an in-window request's reply was not admitted.
#[derive(Clone, Copy)]
enum Unadmitted {
    AdmitTimeout,
    Refused,
    /// The connection was aborted while the reply waited, because an earlier
    /// reply on it had been unsettled for `--settle-limit-ms`.
    SettleAbort,
    Failed,
}

impl Unadmitted {
    fn name(self) -> &'static str {
        match self {
            Unadmitted::AdmitTimeout => "admit_timeout",
            Unadmitted::Refused => "refused",
            Unadmitted::SettleAbort => "settle_abort",
            Unadmitted::Failed => "failed",
        }
    }
}

/// How an admitted reply ended.
#[derive(Clone, Copy)]
enum Ended {
    Settled,
    Failed,
    SettleAbort,
    /// Dropped unsettled when its connection was aborted for another reply.
    Discarded,
}

impl Ended {
    fn name(self) -> &'static str {
        match self {
            Ended::Settled => "settled",
            Ended::Failed => "failed",
            Ended::SettleAbort => "settle_abort",
            Ended::Discarded => "discarded",
        }
    }
}

/// One large reply, in the order the server built them.
struct LargeRecord {
    tag: u32,
    len: usize,
    scheduled_ns: u64,
    /// When it was admitted, or when its wait ended without admission.
    end_ns: u64,
    /// Scheduled time to admission, and call to result, in microseconds.
    delays: Option<(u32, u32)>,
    unadmitted: Option<Unadmitted>,
    ended: Option<Ended>,
}

struct Sample {
    at_ns: u64,
    held: [u64; 3],
}

/// What `main` prints at shutdown, beyond the counters. Only requests with
/// flag bit 2 are recorded, except the samples.
struct Recorder {
    /// Per class, admitted replies' delays from scheduled time to admission,
    /// in microseconds.
    scheduled_us: [Vec<u32>; 3],
    /// Per class, admitted replies' delays from just before the admitting
    /// call to its result, in microseconds.
    wait_us: [Vec<u32>; 3],
    /// Per class, requests not admitted, indexed by `Unadmitted as usize`.
    unadmitted: [[u64; 4]; 3],
    /// Per class, admitted replies by how they ended, indexed by
    /// `Ended as usize`.
    ended: [[u64; 4]; 3],
    large: Vec<LargeRecord>,
    samples: Vec<Sample>,
    /// The earliest and latest scheduled time of a recorded request.
    window_ns: Option<(u64, u64)>,
}

static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
    scheduled_us: [Vec::new(), Vec::new(), Vec::new()],
    wait_us: [Vec::new(), Vec::new(), Vec::new()],
    unadmitted: [[0; 4]; 3],
    ended: [[0; 4]; 3],
    large: Vec::new(),
    samples: Vec::new(),
    window_ns: None,
});

fn recorder() -> std::sync::MutexGuard<'static, Recorder> {
    RECORDER.lock().unwrap_or_else(|e| e.into_inner())
}

struct Request {
    len: usize,
    tag: u32,
    flags: u32,
    scheduled_ns: u64,
}

impl Request {
    fn parse(data: &[u8]) -> Request {
        let word = |i: usize| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        Request {
            len: word(0).max(8) as usize,
            tag: word(4),
            flags: word(8),
            scheduled_ns: u64::from_le_bytes(data[16..24].try_into().unwrap()),
        }
    }

    fn recorded(&self) -> bool {
        self.flags & FLAG_WINDOW != 0
    }
}

/// One admitted reply that its connection has not seen settle.
struct Pending {
    sent: SendCompletion,
    /// When its settle clock started: its admission, or the settlement of the
    /// reply before it if that was later.
    since: Instant,
    class: usize,
    slots: u64,
    /// Whether its request was scheduled in the window.
    recorded: bool,
    /// Its index in `Recorder::large`.
    large: Option<usize>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        HELD[self.class].fetch_sub(self.slots, Relaxed);
    }
}

/// Record how an in-window reply ended.
fn record_end(p: &Pending, how: Ended) {
    if !p.recorded {
        return;
    }
    let mut r = recorder();
    r.ended[p.class][how as usize] += 1;
    if let Some(i) = p.large {
        r.large[i].ended = Some(how);
    }
}

enum Settle {
    Settled,
    Failed,
    Stalled,
}

/// One connection's admitted replies that have not been seen to settle,
/// oldest first. A connection's replies settle in the order they were
/// admitted, so the front is the reply that has waited longest for the
/// socket. Each reply is timed from its admission or, if later, from when the
/// reply before it settled: a reply admitted behind a backlog is not charged
/// for the time the backlog takes.
struct Unsettled {
    queue: VecDeque<Pending>,
    limit: Duration,
}

impl Unsettled {
    fn new(limit: Duration) -> Self {
        Unsettled {
            queue: VecDeque::new(),
            limit,
        }
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    /// Watch `sent`, a reply just admitted.
    fn push(
        &mut self,
        sent: SendCompletion,
        class: usize,
        slots: u64,
        recorded: bool,
        large: Option<usize>,
    ) {
        HELD[class].fetch_add(slots, Relaxed);
        self.queue.push_back(Pending {
            sent,
            since: Instant::now(),
            class,
            slots,
            recorded,
            large,
        });
    }

    /// Drop the settled replies at the front, without waiting.
    async fn prune(&mut self) {
        std::future::poll_fn(|cx| {
            while let Some(front) = self.queue.front_mut() {
                match Pin::new(&mut front.sent).poll(cx) {
                    Poll::Pending => break,
                    Poll::Ready(result) => self.pop(result.is_ok()),
                }
            }
            Poll::Ready(())
        })
        .await;
    }

    /// Wait for the oldest reply to settle, for what is left of its
    /// `--settle-limit-ms`. A reply that settles with an error is counted as
    /// failed and dropped.
    async fn settle_front(&mut self) -> Settle {
        let front = self.queue.front_mut().expect("a reply to settle");
        let left = self.limit.saturating_sub(front.since.elapsed());
        let result = ringline::timeout(left, &mut front.sent).await;
        match result {
            Ok(Ok(_)) => {
                self.pop(true);
                Settle::Settled
            }
            Ok(Err(_)) => {
                self.pop(false);
                Settle::Failed
            }
            Err(_elapsed) => Settle::Stalled,
        }
    }

    /// Resolve once the oldest reply has been unsettled for
    /// `--settle-limit-ms`. Never resolves once every reply has settled.
    async fn stalled(&mut self) {
        while !self.queue.is_empty() {
            if let Settle::Stalled = self.settle_front().await {
                return;
            }
        }
        std::future::pending::<()>().await;
    }

    /// Wait for every reply to settle. Abort the connection if one stalls.
    async fn finish(&mut self, tx: &mut SendHalf) {
        while !self.queue.is_empty() {
            if let Settle::Stalled = self.settle_front().await {
                self.abort_stalled(tx);
            }
        }
    }

    /// Count the front reply as settled or failed, drop it, and start the
    /// next one's clock now if it was admitted earlier.
    fn pop(&mut self, ok: bool) {
        let front = self.queue.pop_front().expect("a reply to pop");
        if ok {
            count(&COUNTERS.replies, front.class);
            record_end(&front, Ended::Settled);
        } else {
            count(&COUNTERS.failed, front.class);
            record_end(&front, Ended::Failed);
        }
        if let Some(next) = self.queue.front_mut() {
            next.since = next.since.max(Instant::now());
        }
    }

    /// Abort the connection because its oldest reply has been unsettled for
    /// `--settle-limit-ms`. The front counts as a settle abort, the rest as
    /// discarded.
    fn abort_stalled(&mut self, tx: &mut SendHalf) {
        tx.abort();
        if let Some(front) = self.queue.pop_front() {
            count(&COUNTERS.settle_aborts, front.class);
            record_end(&front, Ended::SettleAbort);
        }
        self.discard();
    }

    /// Forget every reply after an abort: they fail without reaching the
    /// peer.
    fn discard(&mut self) {
        for p in self.queue.drain(..) {
            count(&COUNTERS.discarded, p.class);
            record_end(&p, Ended::Discarded);
        }
    }
}

async fn serve(conn: Connection) {
    let s = settings();
    let (mut tx, mut rx) = conn.split();
    let mut unsettled = Unsettled::new(s.settle_limit);
    let mut reply = Vec::new();
    'conn: loop {
        while unsettled.len() >= s.pipeline {
            match unsettled.settle_front().await {
                Settle::Settled => {}
                Settle::Failed => break 'conn,
                Settle::Stalled => {
                    unsettled.abort_stalled(&mut tx);
                    break 'conn;
                }
            }
        }
        let mut request = None;
        let read = rx.with_data(|data| {
            if data.len() < REQUEST_LEN {
                return ParseResult::NeedMore;
            }
            request = Some(Request::parse(data));
            ParseResult::Consumed(REQUEST_LEN)
        });
        // While the task waits for a request, nothing else watches its
        // replies.
        let n = match ringline::select(read, unsettled.stalled()).await {
            Either::Left(n) => n,
            Either::Right(()) => {
                unsettled.abort_stalled(&mut tx);
                break 'conn;
            }
        };
        let Some(req) = request.filter(|_| n > 0) else {
            break;
        };
        reply.clear();
        reply.extend_from_slice(&req.tag.to_le_bytes());
        reply.extend_from_slice(&(req.len as u32).to_le_bytes());
        reply.resize(req.len, b'r');
        if req.flags & FLAG_OUTSIDE != 0 {
            match tx.send(&reply) {
                Ok(_) => count(&OUTSIDE, 0),
                Err(e) if e.kind() == std::io::ErrorKind::Other && tx.is_alive() => {
                    count(&OUTSIDE, 1);
                }
                Err(_) => {
                    count(&OUTSIDE, 2);
                    break;
                }
            }
            continue;
        }
        unsettled.prune().await;
        if !send_reply(&mut tx, &mut unsettled, &reply, &req).await {
            break;
        }
    }
    // Once the task returns, ringline's close drains the queued replies with
    // no time bound. Wait for them here, and abort if one stalls.
    unsettled.finish(&mut tx).await;
}

/// Send a small or large reply and watch it in `unsettled`. Returns false if
/// the connection should end.
///
/// This chooses the call for small and large replies, and so the admission
/// order (flag bit 1's replies are sent with `send` in `serve`):
/// `--small-send send` sends a small reply with `send`, and every other reply
/// waits in the FIFO in `send_admitted`. The wait for admission also watches
/// the connection's earlier replies, as the cache server's does: a reply
/// unsettled for `--settle-limit-ms` aborts the connection, which returns the
/// slots this reply and every other on the worker are waiting for.
async fn send_reply(
    tx: &mut SendHalf,
    unsettled: &mut Unsettled,
    reply: &[u8],
    req: &Request,
) -> bool {
    let s = settings();
    let class = if reply.len() > s.small_max {
        LARGE
    } else if req.flags & FLAG_SLOW != 0 {
        SLOW
    } else {
        FAST
    };
    let called_ns = mono_ns();
    let admitted = if class != LARGE && s.use_send {
        match tx.send(reply) {
            Ok(sent) => Ok(sent),
            Err(e) if e.kind() == std::io::ErrorKind::Other && tx.is_alive() => {
                Err(Unadmitted::Refused)
            }
            Err(_) => Err(Unadmitted::Failed),
        }
    } else {
        let wait = ringline::timeout(s.admit_limit, tx.send_admitted(reply));
        match ringline::select(wait, unsettled.stalled()).await {
            Either::Left(Ok(Ok(sent))) => Ok(sent),
            Either::Left(Ok(Err(_))) => Err(Unadmitted::Failed),
            Either::Left(Err(_elapsed)) => Err(Unadmitted::AdmitTimeout),
            Either::Right(()) => Err(Unadmitted::SettleAbort),
        }
    };
    let result_ns = mono_ns();
    let large = req
        .recorded()
        .then(|| record(req, class, called_ns, result_ns, admitted.as_ref().err()))
        .flatten();
    match admitted {
        Ok(sent) => {
            let slots = reply.len().div_ceil(s.slot_size) as u64;
            unsettled.push(sent, class, slots, req.recorded(), large);
            true
        }
        Err(Unadmitted::Refused) => {
            count(&COUNTERS.refused, class);
            tx.abort();
            unsettled.discard();
            false
        }
        Err(Unadmitted::AdmitTimeout) => {
            count(&COUNTERS.admit_timeouts, class);
            tx.abort();
            unsettled.discard();
            false
        }
        Err(Unadmitted::SettleAbort) => {
            unsettled.abort_stalled(tx);
            false
        }
        Err(Unadmitted::Failed) => {
            count(&COUNTERS.failed, class);
            false
        }
    }
}

/// Record an in-window request's delays, or why it was not admitted. Returns
/// the index of its large-reply record, if it is large.
fn record(
    req: &Request,
    class: usize,
    called_ns: u64,
    result_ns: u64,
    unadmitted: Option<&Unadmitted>,
) -> Option<usize> {
    let mut r = recorder();
    r.window_ns = Some(match r.window_ns {
        None => (req.scheduled_ns, req.scheduled_ns),
        Some((lo, hi)) => (lo.min(req.scheduled_ns), hi.max(req.scheduled_ns)),
    });
    let delays = (
        micros(req.scheduled_ns, result_ns),
        micros(called_ns, result_ns),
    );
    match unadmitted {
        None => {
            r.scheduled_us[class].push(delays.0);
            r.wait_us[class].push(delays.1);
        }
        Some(&u) => r.unadmitted[class][u as usize] += 1,
    }
    (class == LARGE).then(|| {
        r.large.push(LargeRecord {
            tag: req.tag,
            len: req.len,
            scheduled_ns: req.scheduled_ns,
            end_ns: result_ns,
            delays: unadmitted.is_none().then_some(delays),
            unadmitted: unadmitted.copied(),
            ended: None,
        });
        r.large.len() - 1
    })
}

/// Sample `HELD` every `SAMPLE_INTERVAL`, until the worker drops the task at
/// shutdown.
async fn sample_held() {
    let interval = SAMPLE_INTERVAL.as_nanos() as u64;
    let mut next = mono_ns();
    loop {
        next = (next + interval).max(mono_ns());
        ringline::sleep(Duration::from_nanos(next.saturating_sub(mono_ns()))).await;
        let sample = Sample {
            at_ns: mono_ns(),
            held: [
                HELD[FAST].load(Relaxed),
                HELD[SLOW].load(Relaxed),
                HELD[LARGE].load(Relaxed),
            ],
        };
        recorder().samples.push(sample);
    }
}

struct Handler;
impl AsyncEventHandler for Handler {
    fn on_accept(&self, conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
        serve(conn)
    }
    fn on_start(&self) -> Option<Pin<Box<dyn std::future::Future<Output = ()> + 'static>>> {
        Some(Box::pin(sample_held()))
    }
    fn create_for_worker(_id: usize) -> Self {
        Handler
    }
}

fn percentile(sorted: &[u32], p: f64) -> u32 {
    let i = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[i]
}

/// p50, p99, p999 and max of `v`, or nulls if it is empty.
fn spread(v: &mut [u32]) -> Value {
    if v.is_empty() {
        return json!({"p50": null, "p99": null, "p999": null, "max": null});
    }
    v.sort_unstable();
    json!({
        "p50": percentile(v, 0.50),
        "p99": percentile(v, 0.99),
        "p999": percentile(v, 0.999),
        "max": v[v.len() - 1],
    })
}

/// The mean of each class's held slots over the samples taken from `from_ns`
/// to `to_ns`, and how many there were.
fn held_mean(samples: &[Sample], from_ns: u64, to_ns: u64) -> Value {
    let mut sum = [0u64; 3];
    let mut n = 0u64;
    for s in samples
        .iter()
        .filter(|s| s.at_ns >= from_ns && s.at_ns <= to_ns)
    {
        for (total, held) in sum.iter_mut().zip(s.held) {
            *total += held;
        }
        n += 1;
    }
    let mean = |c: usize| (n > 0).then(|| sum[c] as f64 / n as f64);
    json!({
        "small_fast": mean(FAST),
        "small_slow": mean(SLOW),
        "large": mean(LARGE),
        "samples": n,
    })
}

fn statistics(r: &mut Recorder, admit_limit_ms: u64) -> Value {
    let limit_us = admit_limit_ms.saturating_mul(1000);
    let mut classes = serde_json::Map::new();
    for (c, name) in CLASS_NAMES.iter().enumerate() {
        let beyond = r.scheduled_us[c]
            .iter()
            .filter(|&&d| u64::from(d) > limit_us)
            .count();
        let not = &r.unadmitted[c];
        let ended = &r.ended[c];
        classes.insert(
            (*name).to_string(),
            json!({
                "count": r.scheduled_us[c].len(),
                "scheduled_us": spread(&mut r.scheduled_us[c]),
                "wait_us": spread(&mut r.wait_us[c]),
                "beyond_admit_limit": beyond,
                "not_admitted": {
                    "admit_timeout": not[Unadmitted::AdmitTimeout as usize],
                    "refused": not[Unadmitted::Refused as usize],
                    "settle_abort": not[Unadmitted::SettleAbort as usize],
                    "failed": not[Unadmitted::Failed as usize],
                },
                "ended": {
                    "settled": ended[Ended::Settled as usize],
                    "failed": ended[Ended::Failed as usize],
                    "settle_abort": ended[Ended::SettleAbort as usize],
                    "discarded": ended[Ended::Discarded as usize],
                },
            }),
        );
    }
    let large: Vec<Value> = r
        .large
        .iter()
        .map(|l| {
            json!({
                "tag": l.tag,
                "len": l.len,
                "scheduled_ns": l.scheduled_ns,
                "scheduled_us": l.delays.map(|d| d.0),
                "wait_us": l.delays.map(|d| d.1),
                "not_admitted": l.unadmitted.map(Unadmitted::name),
                "ended": l.ended.map(Ended::name),
                "held": held_mean(&r.samples, l.scheduled_ns, l.end_ns),
            })
        })
        .collect();
    let window = r
        .window_ns
        .map(|(lo, hi)| held_mean(&r.samples, lo, hi))
        .unwrap_or(Value::Null);
    json!({
        "classes": classes,
        "large_replies": large,
        "held_run": held_mean(&r.samples, 0, u64::MAX),
        "held_window": window,
        "window_ns": r.window_ns.map(|(lo, hi)| [lo, hi]),
    })
}

fn main() {
    let args = Args::parse();
    let settings = Settings {
        use_send: args.small_send == SmallSend::Send,
        small_max: args.small_max as usize,
        admit_limit: Duration::from_millis(args.admit_limit_ms),
        settle_limit: Duration::from_millis(args.settle_limit_ms),
        pipeline: args.pipeline as usize,
        slot_size: args.slot_size as usize,
    };
    // Set once, before any connection reads it.
    let _ = SETTINGS.set(settings);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(true)
        .core_offset(args.cpu)
        .max_connections(4096)
        .send_pool(args.pool_slots, args.slot_size)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind(args.addr)
        .launch::<Handler>()
        .expect("launch");
    let small_send = if args.small_send == SmallSend::Send {
        "send"
    } else {
        "admitted"
    };
    eprintln!(
        "admission-server: ready on {} (small_send={small_send}, admit={} ms, settle={} ms, pipeline={})",
        args.addr, args.admit_limit_ms, args.settle_limit_ms, args.pipeline
    );
    runtime.wait_on_signal();
    for h in handles {
        h.join().ok();
    }
    let c = &COUNTERS;
    let load = |a: &[AtomicU64; 3], i: usize| a[i].load(Relaxed);
    let pair = |a: &[AtomicU64; 3]| [load(a, FAST) + load(a, SLOW), load(a, LARGE)];
    let stats = statistics(&mut recorder(), args.admit_limit_ms);
    println!(
        "{}",
        json!({
            "replies": pair(&c.replies),
            "refused": pair(&c.refused),
            "admit_timeouts": pair(&c.admit_timeouts),
            "settle_aborts": pair(&c.settle_aborts),
            "failed": pair(&c.failed),
            "discarded": pair(&c.discarded),
            "slow_reader": {
                "replies": load(&c.replies, SLOW),
                "refused": load(&c.refused, SLOW),
                "admit_timeouts": load(&c.admit_timeouts, SLOW),
                "settle_aborts": load(&c.settle_aborts, SLOW),
                "failed": load(&c.failed, SLOW),
                "discarded": load(&c.discarded, SLOW),
            },
            "outside": {
                "sent": OUTSIDE[0].load(Relaxed),
                "refused": OUTSIDE[1].load(Relaxed),
                "failed": OUTSIDE[2].load(Relaxed),
            },
            "small_send": small_send,
            "admit_limit_ms": args.admit_limit_ms,
            "settle_limit_ms": args.settle_limit_ms,
            "pipeline": args.pipeline,
            "pool_slots": args.pool_slots,
            "slot_size": args.slot_size,
            "small_max": args.small_max,
            "statistics": stats,
        })
    );
}
