//! Server for the contended cases of Experiments B, C and D
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
//!   `--small-send` names: `send_admitted`, which waits in the FIFO, or
//!   `send`, which takes no place in it (order O1 in the design). A `send`
//!   the pool refuses aborts the connection.
//! - A larger reply is large, and is always sent with `send_admitted`.
//! - `--order` sets the runtime's `SendAdmissionOrder`, which decides what
//!   `send_admitted` does while the FIFO's head does not fit: `strict`
//!   (O0 with `--small-send admitted`) admits only the head; `budget` (O7w)
//!   also admits a waiter that fits ahead of the head, while the slots held
//!   by such passing sends stay within `--budget` slots and the waiter's
//!   connection has nothing queued and did not last wait for socket room.
//!   The default is `strict`, so a run that does not name an order measures
//!   O0 or O1 as before; the runtime's own default is `budget` with 32.
//! - Every wait for admission is bounded by `--admit-limit-ms`. A connection
//!   whose reply is not admitted within it is aborted.
//!
//! # TLS
//!
//! With `--tls` the listener serves TLS, with a certificate for `localhost`
//! generated at start, and `--tls-cert-out` writes that certificate as PEM
//! for `admission-load --tls-ca`. The record layer needs a send-pool slot
//! that holds one whole TLS record, at least 16,413 bytes (16,384 of
//! plaintext and 29 of record overhead), so `--slot-size` must be at least
//! that; the server refuses to start otherwise. Admission counts a TLS
//! reply's slots as one per record plus one, `ceil(len / 16384) + 1`, rather
//! than `ceil(len / --slot-size)`, and the held-slot samples below count it
//! the same way.
//!
//! # Pieces, and `--stream-piece`
//!
//! With `--stream-piece p`, a large reply of more than p bytes is sent as
//! `ceil(n / p)` pieces of p bytes but the last, which holds the rest (p
//! bytes when p divides n), one unsettled at a time. The first piece holds
//! the reply's tag and length. For each piece:
//!
//! - with `--stream-gate`, the task waits until the socket reports room
//!   (`SendHalf::writable`), bounded by `--settle-limit-ms`;
//! - it waits in `send_admitted` for the piece's slots, bounded by
//!   `--admit-limit-ms`;
//! - each piece but the last is then awaited until it settles, bounded by
//!   `--settle-limit-ms` from its admission. The last piece is watched in
//!   `Unsettled`, as a whole reply is.
//!
//! The pieces count as one reply against `--pipeline`. Every wait also races
//! the watch on the connection's earlier replies, as a whole reply's wait for
//! admission does. Any failure of a piece aborts the connection, the first
//! piece's included, as a whole reply's admission timeout does. The
//! connection reads no request while a reply's pieces go out, since the
//! serve loop reads only between replies.
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
//!   otherwise; for a reply in pieces, its first piece's. The first delay
//!   includes the time the request waited unread behind the connection's
//!   earlier replies; the second does not, but for a reply in pieces under
//!   `--stream-gate` it includes the first piece's wait for room.
//! - By class, the requests that were not admitted, by reason, and the
//!   admitted replies by how they ended.
//! - For each large reply: its tag, length and scheduled time, its two delays
//!   or the reason it was not admitted (for a reply in pieces, its first
//!   piece's, the second delay from before its first wait for room), how it
//!   ended once admitted, and the mean of each class's held
//!   slots (below) over the samples from its scheduled time to its admission
//!   or removal. Also its pieces (1 for a whole reply), those admitted, those
//!   whose `SendCompletion` read `waited_for_room` once the task was done
//!   with it, its outcome (completed; an admission, room-wait or settlement
//!   timeout; a peer reset, `ConnectionReset` or `BrokenPipe`; another send
//!   error; or discarded with its connection for an earlier reply), the time
//!   from its scheduled time to its last piece's settlement in microseconds
//!   (completed replies only; a settlement is seen when the task next polls
//!   the reply), the smallest free count of the pool's main region over the
//!   samples from its scheduled time to its end, and the smallest read just
//!   after each admission of the reply or of its pieces (a reply in gated
//!   pieces can take less time than a sample's 10 ms), and its pieces
//!   admitted past a waiting head.
//! - Per class, admitted sends the runtime admitted past a waiting head
//!   (`SendCompletion::passed_head`), and for those that settled, the time
//!   from admission to settlement. Each piece of a reply counts as a send.
//!   Always zero under `--order strict`.
//! - Connections aborted, by cause: admission timeout, a `send` the pool
//!   refused, room-wait timeout, settlement timeout (a piece's, or an
//!   unsettled reply's), peer reset, and other send errors.
//! - Every 10 ms a standalone task samples the send-pool slots held by each
//!   class, and B, the slots held by sends admitted past a head as the
//!   runtime counts them (`SendAdmissionCounters::passing_held`), and keeps
//!   the runtime's admission counters from the last sample. A reply counts
//!   `ceil(len / --slot-size)` slots (with `--tls`, as in TLS above) from its
//!   admission until its task sees it settle, its connection is aborted, or
//!   the task stops watching it. That over-counts: the runtime returns each slot of a
//!   reply as the kernel takes the slot's bytes, before the reply settles, and
//!   a settled reply is counted until its task is next polled. An aborted
//!   connection's replies stop counting at the abort, before the runtime gets
//!   back the slots of a send the kernel holds. Replies sent outside the FIFO
//!   are not counted. A piece counts its own slots from its admission until
//!   its task sees it settle. The same task records the free slots of the
//!   pool's main region (`SendAdmissionCounters::main_free`), every sample
//!   kept, with its time.
//!
//! The statistics are kept in a `Mutex`: only the worker thread takes it until
//! the worker has exited and `main` reads it, and `thread_local!` storage
//! would be dropped with the worker thread. One worker, so every connection
//! shares one send pool and one FIFO. The counters, the configuration
//! (order, budget, pool, pieces and gate) and the statistics are printed as
//! one JSON line on SIGINT or SIGTERM. With `--summary-file`, the same object
//! without the per-large-reply records and the free-slot samples, which run
//! to hundreds of KiB, is written to that file as well, for a log line.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
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

/// The runtime's admission order for `send_admitted`
/// (`ringline::SendAdmissionOrder`), with the design's name for each.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Order {
    /// O0 with `--small-send admitted`: only the FIFO's head is admitted.
    Strict,
    /// O7w: a waiter that fits may pass a head that does not, within
    /// `--budget` slots.
    Budget,
}

impl Order {
    fn runtime(self, budget: u16) -> ringline::SendAdmissionOrder {
        match self {
            Order::Strict => ringline::SendAdmissionOrder::Strict,
            Order::Budget => ringline::SendAdmissionOrder::Budget { slots: budget },
        }
    }

    fn name(self) -> &'static str {
        match self {
            Order::Strict => "strict",
            Order::Budget => "budget",
        }
    }
}

#[derive(Parser)]
#[command(
    name = "admission-server",
    about = "The contended-case server of Experiments B, C and D"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7979")]
    addr: SocketAddr,
    /// How replies of at most `--small-max` bytes are sent: `admitted` waits
    /// in the FIFO under `--order`, `send` is O1. `send_reply` chooses the
    /// call for small and large replies.
    #[arg(long, value_enum)]
    small_send: SmallSend,
    /// The order `send_admitted` admits under: `strict` (O0) or `budget`
    /// (O7w).
    #[arg(long, value_enum, default_value = "strict")]
    order: Order,
    /// The most slots sends admitted past a head may hold at once, for
    /// `--order budget`.
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..))]
    budget: u16,
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
    /// Send-pool slot size in bytes. With `--tls`, at least 16413: one whole
    /// TLS record.
    #[arg(long, default_value_t = 16384)]
    slot_size: u32,
    /// Pin the worker to this CPU.
    #[arg(long, default_value_t = 0)]
    cpu: usize,
    /// Serve TLS with a self-signed certificate for `localhost`, generated at
    /// start. Needs `--slot-size` of at least 16413.
    #[arg(long)]
    tls: bool,
    /// Write the `--tls` certificate here as PEM, before listening, for
    /// `admission-load --tls-ca`.
    #[arg(long, requires = "tls")]
    tls_cert_out: Option<PathBuf>,
    /// Send a large reply of more than this many bytes in pieces of this
    /// many bytes, one unsettled at a time; 0 sends every reply whole. At
    /// least 8, so that the first piece holds the reply's header.
    #[arg(long, default_value_t = 0)]
    stream_piece: u32,
    /// Before each piece, wait until the socket reports room
    /// (`SendHalf::writable`).
    #[arg(long)]
    stream_gate: bool,
    /// Also write the output, without the per-large-reply records and the
    /// free-slot samples, to this file.
    #[arg(long)]
    summary_file: Option<std::path::PathBuf>,
}

struct Settings {
    use_send: bool,
    small_max: usize,
    admit_limit: Duration,
    settle_limit: Duration,
    pipeline: usize,
    slot_size: usize,
    tls: bool,
    stream_piece: usize,
    stream_gate: bool,
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
/// Plaintext bytes in one TLS record at rustls' default fragment size.
const TLS_RECORD_PLAINTEXT: usize = 16384;

/// The send-pool slots admission counts for a reply of `len` bytes: one per
/// record plus one under TLS (ringline's bound for its unbuffered record
/// layer, which writes one record per slot), `ceil(len / --slot-size)`
/// otherwise.
fn reply_slots(len: usize) -> u64 {
    let s = settings();
    if s.tls {
        (len.div_ceil(TLS_RECORD_PLAINTEXT) + 1) as u64
    } else {
        len.div_ceil(s.slot_size) as u64
    }
}

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

/// Connections the server aborted, by cause, over every request, indexed by
/// `Abort as usize`.
static ABORTS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];

/// Why the server aborted a connection.
#[derive(Clone, Copy)]
enum Abort {
    /// A reply, or a piece, was not admitted within `--admit-limit-ms`.
    AdmitTimeout,
    /// The pool refused a small reply sent with `send`.
    Refused,
    /// The socket did not report room within `--settle-limit-ms` before a
    /// piece (`--stream-gate`).
    RoomWaitTimeout,
    /// A reply, or a piece, was unsettled for `--settle-limit-ms`.
    SettleTimeout,
    /// A piece's wait for room, admission or settlement failed with
    /// `ConnectionReset` or `BrokenPipe`.
    PeerReset,
    /// It failed with another error.
    SendError,
}

const ABORT_NAMES: [&str; 6] = [
    "admit_timeout",
    "refused",
    "room_wait_timeout",
    "settle_timeout",
    "peer_reset",
    "send_error",
];

fn count_abort(cause: Abort) {
    ABORTS[cause as usize].fetch_add(1, Relaxed);
}

/// A failed send's cause, by its error's kind.
fn error_cause(kind: std::io::ErrorKind) -> Abort {
    match kind {
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => Abort::PeerReset,
        _ => Abort::SendError,
    }
}

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
    /// Its first piece's wait for room timed out (`--stream-gate`).
    RoomWaitTimeout,
}

impl Unadmitted {
    fn name(self) -> &'static str {
        match self {
            Unadmitted::AdmitTimeout => "admit_timeout",
            Unadmitted::Refused => "refused",
            Unadmitted::SettleAbort => "settle_abort",
            Unadmitted::Failed => "failed",
            Unadmitted::RoomWaitTimeout => "room_wait_timeout",
        }
    }
}

/// How a large reply ended, whole or in pieces.
#[derive(Clone, Copy)]
enum Outcome {
    /// Its last piece, or the whole reply, settled.
    Completed,
    AdmitTimeout,
    RoomWaitTimeout,
    /// It, or a piece, was unsettled for `--settle-limit-ms`.
    SettleTimeout,
    /// A send of it failed with `ConnectionReset` or `BrokenPipe`.
    PeerReset,
    /// A send of it failed with another error.
    SendError,
    /// Its connection was aborted for an earlier reply on it.
    Discarded,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Outcome::Completed => "completed",
            Outcome::AdmitTimeout => "admit_timeout",
            Outcome::RoomWaitTimeout => "room_wait_timeout",
            Outcome::SettleTimeout => "settle_timeout",
            Outcome::PeerReset => "peer_reset",
            Outcome::SendError => "send_error",
            Outcome::Discarded => "discarded",
        }
    }

    fn of_error(kind: std::io::ErrorKind) -> Outcome {
        match error_cause(kind) {
            Abort::PeerReset => Outcome::PeerReset,
            _ => Outcome::SendError,
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
    /// When it, or its first piece, was admitted, or when its wait ended
    /// without admission.
    end_ns: u64,
    /// Scheduled time to admission, and call to result, in microseconds; for
    /// a reply in pieces, its first piece's.
    delays: Option<(u32, u32)>,
    unadmitted: Option<Unadmitted>,
    ended: Option<Ended>,
    /// The pieces it is sent in: 1 for a whole reply.
    pieces: u32,
    /// The pieces admitted.
    pieces_sent: u32,
    /// Of those, the pieces whose `SendCompletion` read `waited_for_room`
    /// when the reply was done with them.
    pieces_waited: u32,
    /// When it ended: its last piece settled, or it failed.
    done_ns: Option<u64>,
    outcome: Option<Outcome>,
    /// The fewest free main-region slots read just after an admission of it
    /// or of one of its pieces.
    admit_min_free: Option<u64>,
    /// Its pieces, or the whole reply, admitted past a waiting head.
    pieces_passed: u32,
}

impl LargeRecord {
    /// The reply ended now, as `outcome`. The first end recorded stands.
    fn finish(&mut self, outcome: Outcome) {
        if self.outcome.is_none() {
            self.outcome = Some(outcome);
            self.done_ns = Some(mono_ns());
        }
    }
}

struct Sample {
    at_ns: u64,
    held: [u64; 3],
    /// B: the slots held by sends admitted past a head, as the runtime
    /// counts them (`SendAdmissionCounters::passing_held`).
    passing_held: u64,
    /// Free slots of the pool's main region
    /// (`SendAdmissionCounters::main_free`).
    main_free: u64,
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
    unadmitted: [[u64; 5]; 3],
    /// Per class, admitted replies by how they ended, indexed by
    /// `Ended as usize`.
    ended: [[u64; 4]; 3],
    large: Vec<LargeRecord>,
    samples: Vec<Sample>,
    /// The earliest and latest scheduled time of a recorded request.
    window_ns: Option<(u64, u64)>,
    /// Per class, admitted sends (a whole reply or one piece) the runtime
    /// admitted past a head, and how long each held its slots: from
    /// admission until it settled, in microseconds (settled ones only).
    passed: [u64; 3],
    /// Per class, for those that settled, the time from admission to
    /// settlement, in microseconds.
    passing_hold_us: [Vec<u32>; 3],
    /// The runtime's admission counters at the last sample.
    counters: Option<ringline::SendAdmissionCounters>,
}

static RECORDER: Mutex<Recorder> = Mutex::new(Recorder {
    scheduled_us: [Vec::new(), Vec::new(), Vec::new()],
    wait_us: [Vec::new(), Vec::new(), Vec::new()],
    unadmitted: [[0; 5]; 3],
    ended: [[0; 4]; 3],
    large: Vec::new(),
    samples: Vec::new(),
    window_ns: None,
    passed: [0; 3],
    passing_hold_us: [Vec::new(), Vec::new(), Vec::new()],
    counters: None,
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
    /// Whether the runtime admitted it past a waiting head.
    passed: bool,
    /// When it was admitted.
    admitted: Instant,
}

impl Drop for Pending {
    fn drop(&mut self) {
        HELD[self.class].fetch_sub(self.slots, Relaxed);
    }
}

/// Record how an in-window reply ended. `error` is the kind of the error a
/// failed reply settled with.
fn record_end(p: &Pending, how: Ended, error: Option<std::io::ErrorKind>) {
    if !p.recorded {
        return;
    }
    let waited = p.sent.waited_for_room();
    let mut r = recorder();
    r.ended[p.class][how as usize] += 1;
    if let Some(i) = p.large {
        let l = &mut r.large[i];
        l.ended = Some(how);
        l.pieces_waited += u32::from(waited);
        l.finish(match how {
            Ended::Settled => Outcome::Completed,
            Ended::Failed => Outcome::of_error(error.unwrap_or(std::io::ErrorKind::Other)),
            Ended::SettleAbort => Outcome::SettleTimeout,
            Ended::Discarded => Outcome::Discarded,
        });
    }
}

/// Update the in-window large reply `large`, if any.
fn with_large(large: Option<usize>, f: impl FnOnce(&mut LargeRecord)) {
    if let Some(i) = large {
        f(&mut recorder().large[i]);
    }
}

/// Note in the record of `large` that `sent`, the whole reply or one of its
/// pieces, was just admitted: the free main-region slots now, and whether it
/// passed a waiting head.
fn note_admission(large: Option<usize>, sent: &SendCompletion) {
    if large.is_none() {
        return;
    }
    let free = ringline::send_admission_counters().main_free;
    let passed = sent.passed_head();
    with_large(large, |l| {
        l.pieces_sent += 1;
        l.pieces_passed += u32::from(passed);
        l.admit_min_free = Some(l.admit_min_free.map_or(free, |m| m.min(free)));
    });
}

enum Settle {
    Settled,
    Failed,
    Stalled,
}

/// Send-pool slots counted in `HELD` while a piece other than a reply's
/// last is admitted and unsettled.
struct Held {
    class: usize,
    slots: u64,
}

impl Held {
    fn new(class: usize, slots: u64) -> Held {
        HELD[class].fetch_add(slots, Relaxed);
        Held { class, slots }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        HELD[self.class].fetch_sub(self.slots, Relaxed);
    }
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
        let passed = sent.passed_head();
        if passed && recorded {
            recorder().passed[class] += 1;
        }
        let now = Instant::now();
        self.queue.push_back(Pending {
            sent,
            since: now,
            class,
            slots,
            recorded,
            large,
            passed,
            admitted: now,
        });
    }

    /// Drop the settled replies at the front, without waiting.
    async fn prune(&mut self) {
        std::future::poll_fn(|cx| {
            while let Some(front) = self.queue.front_mut() {
                match Pin::new(&mut front.sent).poll(cx) {
                    Poll::Pending => break,
                    Poll::Ready(result) => self.pop(result.map(drop).map_err(|e| e.kind())),
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
                self.pop(Ok(()));
                Settle::Settled
            }
            Ok(Err(e)) => {
                self.pop(Err(e.kind()));
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
    fn pop(&mut self, result: Result<(), std::io::ErrorKind>) {
        let front = self.queue.pop_front().expect("a reply to pop");
        match result {
            Ok(()) => {
                count(&COUNTERS.replies, front.class);
                record_end(&front, Ended::Settled, None);
                if front.passed && front.recorded {
                    let held =
                        u32::try_from(front.admitted.elapsed().as_micros()).unwrap_or(u32::MAX);
                    recorder().passing_hold_us[front.class].push(held);
                }
            }
            Err(kind) => {
                count(&COUNTERS.failed, front.class);
                record_end(&front, Ended::Failed, Some(kind));
            }
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
        count_abort(Abort::SettleTimeout);
        if let Some(front) = self.queue.pop_front() {
            count(&COUNTERS.settle_aborts, front.class);
            record_end(&front, Ended::SettleAbort, None);
        }
        self.discard();
    }

    /// Forget every reply after an abort: they fail without reaching the
    /// peer.
    fn discard(&mut self) {
        for p in self.queue.drain(..) {
            count(&COUNTERS.discarded, p.class);
            record_end(&p, Ended::Discarded, None);
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
        // Refilled only when the length changes: a 7 MiB fill per request
        // would count in every arm's worker CPU.
        if reply.len() != req.len {
            reply.clear();
            reply.resize(req.len, b'r');
        }
        reply[0..4].copy_from_slice(&req.tag.to_le_bytes());
        reply[4..8].copy_from_slice(&(req.len as u32).to_le_bytes());
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
    if class == LARGE && s.stream_piece > 0 && reply.len() > s.stream_piece {
        return send_pieces(tx, unsettled, reply, req).await;
    }
    let called_ns = mono_ns();
    let mut failed_kind = None;
    let admitted = if class != LARGE && s.use_send {
        match tx.send(reply) {
            Ok(sent) => Ok(sent),
            Err(e) if e.kind() == std::io::ErrorKind::Other && tx.is_alive() => {
                Err(Unadmitted::Refused)
            }
            Err(e) => {
                failed_kind = Some(e.kind());
                Err(Unadmitted::Failed)
            }
        }
    } else {
        let wait = ringline::timeout(s.admit_limit, tx.send_admitted(reply));
        match ringline::select(wait, unsettled.stalled()).await {
            Either::Left(Ok(Ok(sent))) => Ok(sent),
            Either::Left(Ok(Err(e))) => {
                failed_kind = Some(e.kind());
                Err(Unadmitted::Failed)
            }
            Either::Left(Err(_elapsed)) => Err(Unadmitted::AdmitTimeout),
            Either::Right(()) => Err(Unadmitted::SettleAbort),
        }
    };
    let result_ns = mono_ns();
    let large = begin_large(req, class, 1);
    if let Some(kind) = failed_kind {
        // Before `record_admission`, whose generic outcome would stand.
        with_large(large, |l| l.finish(Outcome::of_error(kind)));
    }
    if req.recorded() {
        record_admission(
            req,
            class,
            called_ns,
            result_ns,
            admitted.as_ref().err(),
            large,
        );
    }
    if let Ok(sent) = &admitted {
        note_admission(large, sent);
    }
    match admitted {
        Ok(sent) => {
            let slots = reply_slots(reply.len());
            unsettled.push(sent, class, slots, req.recorded(), large);
            true
        }
        Err(Unadmitted::Refused) => {
            count(&COUNTERS.refused, class);
            tx.abort();
            count_abort(Abort::Refused);
            unsettled.discard();
            false
        }
        Err(Unadmitted::AdmitTimeout) => {
            count(&COUNTERS.admit_timeouts, class);
            tx.abort();
            count_abort(Abort::AdmitTimeout);
            unsettled.discard();
            false
        }
        Err(Unadmitted::SettleAbort) => {
            unsettled.abort_stalled(tx);
            false
        }
        Err(Unadmitted::Failed | Unadmitted::RoomWaitTimeout) => {
            count(&COUNTERS.failed, class);
            false
        }
    }
}

/// The byte ranges of the pieces a reply of `len` bytes goes out in, in
/// order: `ceil(len / piece)` of them when `len` exceeds `piece`, otherwise
/// the whole reply. Each piece but the last has `piece` bytes, so with
/// `piece` at least 8 the first holds the reply's tag and length.
fn pieces(len: usize, piece: usize) -> impl Iterator<Item = std::ops::Range<usize>> {
    let step = if piece == 0 || len <= piece {
        len.max(1)
    } else {
        piece
    };
    (0..len.div_ceil(step)).map(move |i| i * step..((i + 1) * step).min(len))
}

/// Why a piece's wait failed.
#[derive(Clone, Copy)]
enum PieceFailure {
    /// The socket did not report room within `--settle-limit-ms`.
    RoomWait,
    AdmitTimeout,
    /// The piece was unsettled for `--settle-limit-ms` from its admission.
    SettleTimeout,
    /// The wait for room, the admission or the settlement failed.
    Error(std::io::ErrorKind),
    /// An earlier reply on the connection was unsettled for
    /// `--settle-limit-ms`.
    Stalled,
}

/// Send a large reply in `--stream-piece` pieces, one unsettled at a time,
/// and watch its last piece in `unsettled`. Returns false if the connection
/// should end; every failure aborts it.
///
/// With `--stream-gate`, each piece first waits for room in the socket,
/// bounded by `--settle-limit-ms`. Each piece then waits for admission,
/// bounded by `--admit-limit-ms`, and each piece but the last for its
/// settlement, bounded by `--settle-limit-ms` from its admission. Every
/// wait also watches the connection's earlier replies, as `send_reply`'s
/// wait for admission does.
async fn send_pieces(
    tx: &mut SendHalf,
    unsettled: &mut Unsettled,
    reply: &[u8],
    req: &Request,
) -> bool {
    let s = settings();
    let ranges: Vec<_> = pieces(reply.len(), s.stream_piece).collect();
    let n = ranges.len();
    let large = begin_large(req, LARGE, n as u32);
    let called_ns = mono_ns();
    let mut admitted = false;
    for (i, range) in ranges.into_iter().enumerate() {
        let piece = &reply[range];
        if s.stream_gate {
            let gate = ringline::timeout(s.settle_limit, tx.writable());
            let failure = match ringline::select(gate, unsettled.stalled()).await {
                Either::Left(Ok(Ok(()))) => None,
                Either::Left(Ok(Err(e))) => Some(PieceFailure::Error(e.kind())),
                Either::Left(Err(_elapsed)) => Some(PieceFailure::RoomWait),
                Either::Right(()) => Some(PieceFailure::Stalled),
            };
            if let Some(f) = failure {
                return piece_failed(tx, unsettled, req, large, called_ns, admitted, f);
            }
        }
        let wait = ringline::timeout(s.admit_limit, tx.send_admitted(piece));
        let mut sent = match ringline::select(wait, unsettled.stalled()).await {
            Either::Left(Ok(Ok(sent))) => sent,
            Either::Left(Ok(Err(e))) => {
                let f = PieceFailure::Error(e.kind());
                return piece_failed(tx, unsettled, req, large, called_ns, admitted, f);
            }
            Either::Left(Err(_elapsed)) => {
                let f = PieceFailure::AdmitTimeout;
                return piece_failed(tx, unsettled, req, large, called_ns, admitted, f);
            }
            Either::Right(()) => {
                let f = PieceFailure::Stalled;
                return piece_failed(tx, unsettled, req, large, called_ns, admitted, f);
            }
        };
        if !admitted {
            admitted = true;
            if req.recorded() {
                record_admission(req, LARGE, called_ns, mono_ns(), None, large);
            }
        }
        note_admission(large, &sent);
        let slots = reply_slots(piece.len());
        if i + 1 == n {
            unsettled.push(sent, LARGE, slots, req.recorded(), large);
            return true;
        }
        let admitted_at = Instant::now();
        let held = Held::new(LARGE, slots);
        let settle = ringline::timeout(s.settle_limit, &mut sent);
        let failure = match ringline::select(settle, unsettled.stalled()).await {
            Either::Left(Ok(Ok(_))) => None,
            Either::Left(Ok(Err(e))) => Some(PieceFailure::Error(e.kind())),
            Either::Left(Err(_elapsed)) => Some(PieceFailure::SettleTimeout),
            Either::Right(()) => Some(PieceFailure::Stalled),
        };
        let waited = sent.waited_for_room();
        with_large(large, |l| l.pieces_waited += u32::from(waited));
        drop(held);
        // A piece that passed a head counts as a passing send, as the last
        // piece does in `Unsettled::push` and `pop`.
        if sent.passed_head() && req.recorded() {
            let mut r = recorder();
            r.passed[LARGE] += 1;
            if failure.is_none() {
                let held_us = u32::try_from(admitted_at.elapsed().as_micros()).unwrap_or(u32::MAX);
                r.passing_hold_us[LARGE].push(held_us);
            }
        }
        if let Some(f) = failure {
            return piece_failed(tx, unsettled, req, large, called_ns, admitted, f);
        }
    }
    unreachable!("the last piece returns")
}

/// A piece of a large reply failed: abort the connection, and count and
/// record why. `admitted` says whether a piece of the reply was admitted.
fn piece_failed(
    tx: &mut SendHalf,
    unsettled: &mut Unsettled,
    req: &Request,
    large: Option<usize>,
    called_ns: u64,
    admitted: bool,
    failure: PieceFailure,
) -> bool {
    let (outcome, unadmitted) = match failure {
        PieceFailure::RoomWait => (Outcome::RoomWaitTimeout, Unadmitted::RoomWaitTimeout),
        PieceFailure::AdmitTimeout => (Outcome::AdmitTimeout, Unadmitted::AdmitTimeout),
        PieceFailure::SettleTimeout => (Outcome::SettleTimeout, Unadmitted::Failed),
        PieceFailure::Error(kind) => (Outcome::of_error(kind), Unadmitted::Failed),
        PieceFailure::Stalled => (Outcome::Discarded, Unadmitted::SettleAbort),
    };
    // Before `record_admission`, whose generic outcome for an unadmitted
    // reply would otherwise stand.
    with_large(large, |l| l.finish(outcome));
    if !admitted && req.recorded() {
        record_admission(req, LARGE, called_ns, mono_ns(), Some(&unadmitted), large);
    }
    if let PieceFailure::Stalled = failure {
        unsettled.abort_stalled(tx);
        return false;
    }
    tx.abort();
    count_abort(match failure {
        PieceFailure::RoomWait => Abort::RoomWaitTimeout,
        PieceFailure::AdmitTimeout => Abort::AdmitTimeout,
        PieceFailure::SettleTimeout => Abort::SettleTimeout,
        PieceFailure::Error(kind) => error_cause(kind),
        PieceFailure::Stalled => unreachable!("handled above"),
    });
    match (admitted, failure) {
        (false, PieceFailure::AdmitTimeout) => count(&COUNTERS.admit_timeouts, LARGE),
        (true, PieceFailure::SettleTimeout) => count(&COUNTERS.settle_aborts, LARGE),
        _ => count(&COUNTERS.failed, LARGE),
    }
    if admitted && req.recorded() {
        let how = match failure {
            PieceFailure::SettleTimeout => Ended::SettleAbort,
            _ => Ended::Failed,
        };
        recorder().ended[LARGE][how as usize] += 1;
        with_large(large, |l| l.ended = Some(how));
    }
    unsettled.discard();
    false
}

/// Start the record of an in-window large reply sent in `pieces` pieces, and
/// return its index; `None` for a small reply or one outside the window.
fn begin_large(req: &Request, class: usize, pieces: u32) -> Option<usize> {
    if class != LARGE || !req.recorded() {
        return None;
    }
    let mut r = recorder();
    r.large.push(LargeRecord {
        tag: req.tag,
        len: req.len,
        scheduled_ns: req.scheduled_ns,
        end_ns: req.scheduled_ns,
        delays: None,
        unadmitted: None,
        ended: None,
        pieces,
        pieces_sent: 0,
        pieces_waited: 0,
        done_ns: None,
        outcome: None,
        admit_min_free: None,
        pieces_passed: 0,
    });
    Some(r.large.len() - 1)
}

/// Record an in-window request's delays from its scheduled time and from
/// `called_ns` to its admission at `result_ns`, or why it was not admitted,
/// in its class and in its large-reply record `large`.
fn record_admission(
    req: &Request,
    class: usize,
    called_ns: u64,
    result_ns: u64,
    unadmitted: Option<&Unadmitted>,
    large: Option<usize>,
) {
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
    if let Some(i) = large {
        let l = &mut r.large[i];
        l.end_ns = result_ns;
        l.delays = unadmitted.is_none().then_some(delays);
        l.unadmitted = unadmitted.copied();
        if let Some(&u) = unadmitted {
            l.finish(match u {
                Unadmitted::AdmitTimeout => Outcome::AdmitTimeout,
                Unadmitted::RoomWaitTimeout => Outcome::RoomWaitTimeout,
                Unadmitted::SettleAbort => Outcome::Discarded,
                Unadmitted::Refused | Unadmitted::Failed => Outcome::SendError,
            });
        }
    }
}

/// Sample `HELD` every `SAMPLE_INTERVAL`, until the worker drops the task at
/// shutdown.
async fn sample_held() {
    let interval = SAMPLE_INTERVAL.as_nanos() as u64;
    let mut next = mono_ns();
    loop {
        next = (next + interval).max(mono_ns());
        ringline::sleep(Duration::from_nanos(next.saturating_sub(mono_ns()))).await;
        let counters = ringline::send_admission_counters();
        let sample = Sample {
            at_ns: mono_ns(),
            held: [
                HELD[FAST].load(Relaxed),
                HELD[SLOW].load(Relaxed),
                HELD[LARGE].load(Relaxed),
            ],
            passing_held: counters.passing_held,
            main_free: counters.main_free,
        };
        let mut r = recorder();
        r.samples.push(sample);
        r.counters = Some(counters);
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
    let mut passing = 0u64;
    let mut n = 0u64;
    for s in samples
        .iter()
        .filter(|s| s.at_ns >= from_ns && s.at_ns <= to_ns)
    {
        for (total, held) in sum.iter_mut().zip(s.held) {
            *total += held;
        }
        passing += s.passing_held;
        n += 1;
    }
    let mean = |c: usize| (n > 0).then(|| sum[c] as f64 / n as f64);
    json!({
        "small_fast": mean(FAST),
        "small_slow": mean(SLOW),
        "large": mean(LARGE),
        "passing_held": (n > 0).then(|| passing as f64 / n as f64),
        "samples": n,
    })
}

/// The smallest main-region free count over the samples taken from
/// `from_ns` to `to_ns`, or `None` if none was.
fn min_main_free(samples: &[Sample], from_ns: u64, to_ns: u64) -> Option<u64> {
    samples
        .iter()
        .filter(|s| s.at_ns >= from_ns && s.at_ns <= to_ns)
        .map(|s| s.main_free)
        .min()
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
                "passed": r.passed[c],
                "passing_hold_us": spread(&mut r.passing_hold_us[c]),
                "not_admitted": {
                    "admit_timeout": not[Unadmitted::AdmitTimeout as usize],
                    "refused": not[Unadmitted::Refused as usize],
                    "settle_abort": not[Unadmitted::SettleAbort as usize],
                    "failed": not[Unadmitted::Failed as usize],
                    "room_wait_timeout": not[Unadmitted::RoomWaitTimeout as usize],
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
            let completed = matches!(l.outcome, Some(Outcome::Completed));
            json!({
                "tag": l.tag,
                "len": l.len,
                "scheduled_ns": l.scheduled_ns,
                "scheduled_us": l.delays.map(|d| d.0),
                "wait_us": l.delays.map(|d| d.1),
                "not_admitted": l.unadmitted.map(Unadmitted::name),
                "ended": l.ended.map(Ended::name),
                "held": held_mean(&r.samples, l.scheduled_ns, l.end_ns),
                "pieces": l.pieces,
                "pieces_sent": l.pieces_sent,
                "pieces_waited": l.pieces_waited,
                "outcome": l.outcome.map(Outcome::name),
                "done_ns": l.done_ns,
                "server_us": l
                    .done_ns
                    .filter(|_| completed)
                    .map(|d| d.saturating_sub(l.scheduled_ns) / 1000),
                "min_main_free": min_main_free(
                    &r.samples,
                    l.scheduled_ns,
                    l.done_ns.unwrap_or(u64::MAX),
                ),
                "admit_min_free": l.admit_min_free,
                "pieces_passed": l.pieces_passed,
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
        "admission_counters": r.counters.map(|c| json!({
            "passing_admissions": c.passing_admissions,
            "passing_slots": c.passing_slots,
            "passing_held": c.passing_held,
            "passing_held_max": c.passing_held_max,
            "wake_scans": c.wake_scans,
            "scan_wakes": c.scan_wakes,
            "main_free": c.main_free,
        })),
        "held_window": window,
        "window_ns": r.window_ns.map(|(lo, hi)| [lo, hi]),
        // Every 10 ms sample of the main region's free slots, as
        // [CLOCK_MONOTONIC ms, free].
        "main_free_samples": r
            .samples
            .iter()
            .map(|s| [s.at_ns / 1_000_000, s.main_free])
            .collect::<Vec<_>>(),
    })
}

/// A TLS config with a self-signed certificate for `localhost`, written as
/// PEM to `cert_out` if given.
fn self_signed(cert_out: Option<&std::path::Path>) -> ringline::TlsConfig {
    use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed cert");
    if let Some(path) = cert_out {
        std::fs::write(path, cert.cert.pem()).unwrap_or_else(|e| {
            eprintln!("admission-server: write {}: {e}", path.display());
            std::process::exit(2);
        });
    }
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let chain = vec![CertificateDer::from(cert.cert)];
    ringline::TlsConfig::builder()
        .cert(chain, key.into())
        .build()
        .expect("valid server config")
}

fn main() {
    let args = Args::parse();
    if args.stream_piece != 0 && args.stream_piece < 8 {
        eprintln!("admission-server: --stream-piece must be 0 or at least 8, the reply header");
        std::process::exit(2);
    }
    if args.stream_gate && args.stream_piece == 0 {
        eprintln!("admission-server: --stream-gate needs --stream-piece");
        std::process::exit(2);
    }
    let settings = Settings {
        use_send: args.small_send == SmallSend::Send,
        small_max: args.small_max as usize,
        admit_limit: Duration::from_millis(args.admit_limit_ms),
        settle_limit: Duration::from_millis(args.settle_limit_ms),
        pipeline: args.pipeline as usize,
        slot_size: args.slot_size as usize,
        tls: args.tls,
        stream_piece: args.stream_piece as usize,
        stream_gate: args.stream_gate,
    };
    // Set once, before any connection reads it.
    let _ = SETTINGS.set(settings);
    let builder = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(true)
        .core_offset(args.cpu)
        .max_connections(4096)
        .send_pool(args.pool_slots, args.slot_size)
        // The default here is strict, not the runtime's default, so a run
        // that does not name an order measures O0 or O1.
        .send_admission_order(args.order.runtime(args.budget));
    let builder = if args.tls {
        builder.tls(self_signed(args.tls_cert_out.as_deref()))
    } else {
        builder
    };
    let config = builder.build().unwrap_or_else(|e| {
        eprintln!("admission-server: {e}");
        std::process::exit(2);
    });
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
        "admission-server: ready on {} (small_send={small_send}, order={}, budget={}, tls={}, admit={} ms, settle={} ms, pipeline={}, stream_piece={}, stream_gate={})",
        args.addr,
        args.order.name(),
        args.budget,
        args.tls,
        args.admit_limit_ms,
        args.settle_limit_ms,
        args.pipeline,
        args.stream_piece,
        args.stream_gate
    );
    runtime.wait_on_signal();
    for h in handles {
        h.join().ok();
    }
    let c = &COUNTERS;
    let load = |a: &[AtomicU64; 3], i: usize| a[i].load(Relaxed);
    let pair = |a: &[AtomicU64; 3]| [load(a, FAST) + load(a, SLOW), load(a, LARGE)];
    let stats = statistics(&mut recorder(), args.admit_limit_ms);
    let out = json!({
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
            "order": args.order.name(),
            "budget": args.budget,
            "tls": args.tls,
            "admit_limit_ms": args.admit_limit_ms,
            "settle_limit_ms": args.settle_limit_ms,
            "pipeline": args.pipeline,
            "pool_slots": args.pool_slots,
            "slot_size": args.slot_size,
            "small_max": args.small_max,
            "stream_piece": args.stream_piece,
            "stream_gate": args.stream_gate,
            "aborts": ABORT_NAMES
                .iter()
                .zip(ABORTS.iter())
                .map(|(name, n)| ((*name).to_string(), json!(n.load(Relaxed))))
                .collect::<serde_json::Map<_, _>>(),
            "statistics": stats,
    });
    println!("{out}");
    if let Some(path) = &args.summary_file {
        let mut summary = out.clone();
        if let Some(st) = summary["statistics"].as_object_mut() {
            let larges = st.remove("large_replies");
            st.remove("main_free_samples");
            st.insert(
                "large_replies_count".into(),
                json!(larges.and_then(|v| v.as_array().map(Vec::len))),
            );
        }
        if let Err(e) = std::fs::write(path, format!("{summary}\n")) {
            eprintln!("admission-server: --summary-file {}: {e}", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::pieces;

    #[test]
    fn a_reply_longer_than_a_piece_goes_in_ceil_n_over_p_pieces() {
        let ranges: Vec<_> = pieces(7 << 20, 128 << 10).collect();
        assert_eq!(ranges.len(), 56);
        assert!(ranges.iter().all(|r| r.len() == 128 << 10));
        let ranges: Vec<_> = pieces((3 << 20) + 1, 1 << 20).collect();
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[3], (3 << 20)..((3 << 20) + 1));
    }

    #[test]
    fn the_pieces_cover_the_reply_in_order_with_the_header_in_the_first() {
        let len = (3 << 20) + 12345;
        let ranges: Vec<_> = pieces(len, 64 << 10).collect();
        assert_eq!(ranges[0].start, 0);
        assert!(
            ranges[0].end >= 8,
            "the tag and the length are in the first piece"
        );
        for pair in ranges.windows(2) {
            assert_eq!(pair[0].end, pair[1].start);
        }
        assert_eq!(ranges.last().unwrap().end, len);
    }

    #[test]
    fn a_reply_no_longer_than_a_piece_goes_whole() {
        assert_eq!(pieces(1000, 0).collect::<Vec<_>>(), vec![0..1000]);
        assert_eq!(pieces(1000, 1000).collect::<Vec<_>>(), vec![0..1000]);
        assert_eq!(pieces(8, 4096).collect::<Vec<_>>(), vec![0..8]);
    }
}
