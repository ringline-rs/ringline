//! ringline-native RESP client for use inside the ringline async runtime.
//!
//! This client wraps a [`ringline::ConnCtx`] and provides typed Redis command
//! methods that use `with_bytes()` + `Value::parse_bytes()` for zero-copy
//! incremental RESP parsing. It is designed for single-threaded,
//! single-connection use within ringline's `AsyncEventHandler::on_start()` or
//! connection tasks.
//!
//! All key and value parameters accept `impl AsRef<[u8]>`, so you can pass
//! `&str`, `String`, `&[u8]`, `Vec<u8>`, `Bytes`, etc.
//!
//! # Sequential API (Simple)
//!
//! The basic API sends one command and awaits its response:
//!
//! ```no_run
//! use ringline::ConnCtx;
//! use ringline_redis::Client;
//!
//! async fn example(conn: ConnCtx) -> Result<(), ringline_redis::Error> {
//!     let mut client = Client::new(conn);
//!     client.set("hello", "world").await?;
//!     let val = client.get("hello").await?;
//!     assert_eq!(val.as_deref(), Some(&b"world"[..]));
//!     Ok(())
//! }
//! ```
//!
//! # Fire/Recv Pipelining API (High Throughput)
//!
//! For higher throughput, use the fire/recv pattern to pipeline multiple
//! commands without waiting for each response:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        Application                              │
//! │                                                                 │
//! │   client.fire_get("key1", 1)?;  ──┐                            │
//! │   client.fire_get("key2", 2)?;  ──┼───→ [single TCP send]      │
//! │   client.fire_get("key3", 3)?;  ──┘                            │
//! │                              │                                │
//! │                              ▼                                │
//! │                    [Redis processes]                          │
//! │                              │                                │
//! │                              ▼                                │
//! │   let r1 = client.recv().await?;  ←── [response 1, user_data=1]│
//! │   let r2 = client.recv().await?;  ←── [response 2, user_data=2]│
//! │   let r3 = client.recv().await?;  ←── [response 3, user_data=3]│
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ```no_run
//! use ringline::ConnCtx;
//! use ringline_redis::{Client, CompletedOp};
//!
//! async fn pipelined_example(conn: ConnCtx) -> Result<(), ringline_redis::Error> {
//!     let mut client = Client::new(conn);
//!
//!     // Fire multiple requests (synchronous, non-blocking)
//!     client.fire_get(b"session:abc", 1)?;
//!     client.fire_get(b"session:def", 2)?;
//!     client.fire_get(b"session:ghi", 3)?;
//!
//!     // Recv responses in order (async, blocks until each arrives)
//!     match client.recv().await? {
//!         CompletedOp::Get { result, user_data, latency_ns: _ } => {
//!             assert_eq!(user_data, 1);
//!             let value = result?; // Option<Bytes>
//!             println!("session:abc = {:?}", value);
//!         }
//!         _ => unreachable!(),
//!     }
//!
//!     match client.recv().await? {
//!         CompletedOp::Get { result, user_data, .. } => {
//!             assert_eq!(user_data, 2);
//!             let _value = result?;
//!         }
//!         _ => unreachable!(),
//!     }
//!
//!     match client.recv().await? {
//!         CompletedOp::Get { result, user_data, .. } => {
//!             assert_eq!(user_data, 3);
//!             let _value = result?;
//!         }
//!         _ => unreachable!(),
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Fire/Recv Benefits
//!
//! - **Overlaps network RTT**: All commands sent before any response received
//! - **Better TCP utilization**: Multiple commands coalesced into fewer segments
//! - **Correlation via `user_data`**: Attach opaque `u64` to each fire, returned on recv
//! - **Zero-copy values**: Responses are `Bytes::slice()` into the recv accumulator
//!
//! ## Available Fire Methods
//!
//! - [`Client::fire_get()`] — GET command
//! - [`Client::fire_set()`] — SET command
//! - [`Client::fire_set_with_guard()`] — SET with zero-copy value
//! - [`Client::fire_set_ex()`] — SETEX command
//! - [`Client::fire_del()`] — DEL command
//!
//! ## Important Notes
//!
//! - Responses must be consumed in FIFO order (protocol guarantee)
//! - `recv()` returns [`Error::NoPending`] if called with no in-flight requests
//! - Timing is zero-overhead when no callbacks/metrics are configured
//! - Distinct from [`Client::pipeline()`] which uses Redis's native PIPELINE protocol
//!
//! # Copy Semantics
//!
//! | Path | Copies | Mechanism |
//! |------|--------|-----------|
//! | **Recv (values)** | **0** | `with_bytes()` + `Value::parse_bytes()`. Bulk strings are `Bytes::slice()` references into the accumulator — zero allocation, O(1) refcount. |
//! | **Send (commands)** | 1 | `encode_request()` serializes RESP into `Vec<u8>`, then `conn.send()` copies into the send pool. |
//! | **Send (SET value, standard)** | 1 | All parts gathered into one send-pool slot via `send_parts().copy()`. |
//! | **Send (SET value, guard)** | 0 (value) | [`Client::set_with_guard`] / [`Client::set_ex_with_guard`]: RESP prefix+suffix copied to pool, value stays in-place via `SendGuard`. |
//! | **Pipeline** | 1 | All commands accumulated into one `Vec<u8>`, single `conn.send()` to pool. |
//!
//! TLS connections add encryption copies on the send path regardless of
//! `SendGuard` usage.

pub mod cluster;
pub mod pool;
pub mod sharded;
pub use cluster::{ClusterClient, ClusterConfig};
pub use pool::{Pool, PoolConfig};
pub use sharded::{ShardedClient, ShardedConfig};

use std::cell::Cell;
use std::collections::VecDeque;
use std::io;
use std::time::Instant;

use bytes::Bytes;
use resp_proto::{Request, Value};
use ringline::{ConnCtx, GuardBox, ParseResult, SendGuard};

/// Maximum guards per scatter-gather send (matches ringline core limit).
const MAX_FLUSH_GUARDS: usize = 8;
/// Maximum iovecs a full guard batch needs: each guard contributes an iovec
/// plus at most one copied-run iovec before it, plus one trailing copied run
/// (2g+1 = 17). Well under the ringline core limit of 32. Was incorrectly 8,
/// which made guard batches flush at 3 guards instead of MAX_FLUSH_GUARDS.
const MAX_FLUSH_IOVECS: usize = 2 * MAX_FLUSH_GUARDS + 1;
/// Default [`ClientBuilder::zc_threshold`]. Matches the runtime
/// `Config::send_zc_threshold` default so small guarded SETs fold into the
/// coalescing copy path by default.
const DEFAULT_ZC_THRESHOLD: u32 = 4096;

// ── Error ───────────────────────────────────────────────────────────────

/// Errors returned by the ringline RESP client.
///
/// Marked `#[non_exhaustive]` because the crate is still evolving and new
/// transport / protocol error kinds are expected. Downstream `match`
/// blocks must include a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The connection was closed before a response was received.
    #[error("connection closed")]
    ConnectionClosed,

    /// The server returned a Redis error response.
    #[error("redis error: {0}")]
    Redis(String),

    /// The response type did not match the expected type for the command.
    #[error("unexpected response")]
    UnexpectedResponse,

    /// RESP protocol parse error.
    #[error("protocol error: {0}")]
    Protocol(#[from] resp_proto::ParseError),

    /// I/O error during send.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// All connections in the pool are down and reconnection failed.
    #[error("all connections failed")]
    AllConnectionsFailed,

    /// Too many MOVED/ASK redirects for a single command.
    #[error("too many redirects")]
    TooManyRedirects,

    /// `recv()` called with no pending fire operations.
    #[error("no pending operations")]
    NoPending,

    /// The in-flight pending-op queue reached `max_in_flight`. Drain via
    /// `recv()` before issuing more `fire_*` calls. Configurable via
    /// [`ClientBuilder::max_in_flight`].
    #[error("too many in-flight operations")]
    TooManyInFlight,

    /// A streaming [`set_stream`](Client::set_stream) value source produced a
    /// different number of bytes than the declared length. Because the command
    /// framing (which declares the bulk length) is already on the wire, the
    /// framing is now irrecoverably desynced, so the connection is closed —
    /// matching the read-side poison rule.
    #[error("streaming value length mismatch")]
    LengthMismatch,
}

impl Error {
    /// `true` for transient server-side conditions where the same command
    /// is expected to succeed if retried after a short delay:
    ///
    /// - `LOADING` — node is starting up and loading its RDB/AOF file
    /// - `BUSY` — a `SCRIPT` is running and blocking the server
    /// - `TRYAGAIN` — cluster slot is migrating and the migrating node
    ///   wants the client to retry after the migration finishes
    ///
    /// `ClusterClient`'s routing uses this to retry on the same node a
    /// few times before giving up. Application code can also use it to
    /// build its own retry policy on a [`Client`] not going through
    /// cluster routing.
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Redis(msg) => {
                let bytes = msg.as_bytes();
                starts_with_token(bytes, b"LOADING")
                    || starts_with_token(bytes, b"BUSY")
                    || starts_with_token(bytes, b"TRYAGAIN")
            }
            _ => false,
        }
    }
}

/// `true` if `msg` starts with `prefix` and either ends there or is followed
/// by ASCII whitespace — matches the Redis convention of `-CODE message`.
fn starts_with_token(msg: &[u8], prefix: &[u8]) -> bool {
    msg.starts_with(prefix)
        && (msg.len() == prefix.len() || msg[prefix.len()].is_ascii_whitespace())
}

// ── Command types ───────────────────────────────────────────────────────

/// The type of Redis command that completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandType {
    Get,
    Set,
    Del,
    Ping,
    Other,
}

/// Result metadata for a completed command, passed to the `on_result` callback.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// The command type.
    pub command: CommandType,
    /// Latency in nanoseconds (send → response parsed).
    pub latency_ns: u64,
    /// For GET: `Some(true)` = hit, `Some(false)` = miss. `None` for others.
    pub hit: Option<bool>,
    /// Whether the command succeeded (no Redis error).
    pub success: bool,
    /// Time-to-first-byte in nanoseconds (not available in sequential mode).
    pub ttfb_ns: Option<u64>,
    /// Bytes transmitted for this command (RESP-encoded request size).
    pub tx_bytes: u32,
    /// Bytes received for this command (RESP-encoded response size).
    pub rx_bytes: u32,
}

// ── ClientMetrics ───────────────────────────────────────────────────────

/// Built-in histogram-based metrics, available when the `metrics` feature is
/// enabled. Not registered globally — the caller decides how to expose them.
#[cfg(feature = "metrics")]
pub struct ClientMetrics {
    /// Overall request latency histogram.
    pub latency: histogram::Histogram,
    /// GET latency histogram.
    pub get_latency: histogram::Histogram,
    /// SET latency histogram.
    pub set_latency: histogram::Histogram,
    /// DEL latency histogram.
    pub del_latency: histogram::Histogram,
    /// Total requests completed.
    pub requests: u64,
    /// Total errors.
    pub errors: u64,
    /// Total GET hits.
    pub hits: u64,
    /// Total GET misses.
    pub misses: u64,
}

#[cfg(feature = "metrics")]
impl ClientMetrics {
    fn new() -> Self {
        Self {
            latency: histogram::Histogram::new(7, 64).unwrap(),
            get_latency: histogram::Histogram::new(7, 64).unwrap(),
            set_latency: histogram::Histogram::new(7, 64).unwrap(),
            del_latency: histogram::Histogram::new(7, 64).unwrap(),
            requests: 0,
            errors: 0,
            hits: 0,
            misses: 0,
        }
    }

    fn record(&mut self, result: &CommandResult) {
        self.requests += 1;
        let _ = self.latency.increment(result.latency_ns);

        if !result.success {
            self.errors += 1;
        }

        match result.command {
            CommandType::Get => {
                let _ = self.get_latency.increment(result.latency_ns);
                match result.hit {
                    Some(true) => self.hits += 1,
                    Some(false) => self.misses += 1,
                    None => {}
                }
            }
            CommandType::Set => {
                let _ = self.set_latency.increment(result.latency_ns);
            }
            CommandType::Del => {
                let _ = self.del_latency.increment(result.latency_ns);
            }
            _ => {}
        }
    }
}

// ── Pending operation state ─────────────────────────────────────────────

enum PendingOpKind {
    Get,
    Set,
    Del,
}

struct PendingOp {
    kind: PendingOpKind,
    send_ts: u64,
    start: Option<Instant>,
    user_data: u64,
    tx_bytes: u32,
}

/// A completed fire/recv operation with its result.
#[non_exhaustive]
pub enum CompletedOp {
    /// GET completed.
    Get {
        result: Result<Option<Bytes>, Error>,
        user_data: u64,
        latency_ns: u64,
    },
    /// SET completed.
    Set {
        result: Result<(), Error>,
        user_data: u64,
        latency_ns: u64,
    },
    /// DEL completed.
    Del {
        result: Result<u64, Error>,
        user_data: u64,
        latency_ns: u64,
    },
}

/// Result metadata from a Mode-B borrow GET
/// ([`recv_get_discard`](Client::recv_get_discard) /
/// [`recv_get_segments`](Client::recv_get_segments)): the value length (`None`
/// for a miss) and the fired `user_data`. The value bytes are never retained —
/// they are parsed from borrowed, zero-copy segments and released.
#[cfg(has_io_uring)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetMeta {
    /// Value length in bytes, or `None` for a cache miss (`$-1`).
    pub value_len: Option<usize>,
    /// The `user_data` passed to the corresponding [`fire_get`](Client::fire_get).
    pub user_data: u64,
}

/// The kind of operation a reply corresponds to (a public mirror of the
/// internal `PendingOpKind`), surfaced on [`RespMeta`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    /// A `GET` reply.
    Get,
    /// A `SET` reply.
    Set,
    /// A `DEL` reply.
    Del,
}

/// Zero-copy metadata for a completed reply of any kind, from
/// [`recv_meta`](Client::recv_meta). The value body is drained (never
/// materialized); only its length and the control metadata are surfaced — all a
/// load generator needs. A server error reply is reported here (in `error`, with
/// `success = false`), not as a transport `Err`.
#[derive(Debug, Clone)]
pub struct RespMeta {
    /// What was fired — taken from the pending op, not inferred from the wire.
    pub kind: OpKind,
    /// The `user_data` passed to the corresponding `fire_*`.
    pub user_data: u64,
    /// GET hit → `Some(value byte length)`; GET miss / SET / DEL / error → `None`.
    pub value_len: Option<usize>,
    /// `true` unless the reply was a server error or an unexpected reply type.
    pub success: bool,
    /// Server error text (`-...`, including `MOVED`/`ASK`) when the reply was a
    /// server error; `None` on success or an unexpected-type failure.
    pub error: Option<String>,
    /// Measured request latency in nanoseconds (0 if this client was built
    /// without request timing). Also delivered to the `on_result` callback.
    pub latency_ns: u64,
}

// ── ClientBuilder ───────────────────────────────────────────────────────

type ResultCallback = Box<dyn Fn(&CommandResult)>;

/// Builder for creating a [`Client`] with per-request callbacks and metrics.
pub struct ClientBuilder {
    conn: ConnCtx,
    on_result: Option<ResultCallback>,
    max_batch_size: usize,
    max_in_flight: usize,
    zc_threshold: u32,
    #[cfg(feature = "timestamps")]
    use_kernel_ts: bool,
    #[cfg(feature = "metrics")]
    with_metrics: bool,
}

impl ClientBuilder {
    pub(crate) fn new(conn: ConnCtx) -> Self {
        Self {
            conn,
            on_result: None,
            max_batch_size: 1,
            max_in_flight: usize::MAX,
            zc_threshold: DEFAULT_ZC_THRESHOLD,
            #[cfg(feature = "timestamps")]
            use_kernel_ts: false,
            #[cfg(feature = "metrics")]
            with_metrics: false,
        }
    }

    /// Set the zero-copy guard threshold (in bytes). Guard values passed to
    /// [`fire_set_with_guard`](Client::fire_set_with_guard) /
    /// [`fire_set_ex_with_guard`](Client::fire_set_ex_with_guard) *smaller*
    /// than this are copied into the coalescing send buffer so they batch like
    /// plain SETs instead of taking the scatter-gather guard path (which
    /// flushes every few ops). `0` = always use the guard path.
    ///
    /// Defaults to 4096. Should generally match the runtime
    /// `Config::send_zc_threshold`.
    pub fn zc_threshold(mut self, bytes: u32) -> Self {
        self.zc_threshold = bytes;
        self
    }

    /// Configure the maximum number of in-flight `fire_*` operations
    /// (the depth of the pending queue) before the next `fire_*` call
    /// returns [`Error::TooManyInFlight`]. Defaults to `usize::MAX`
    /// (unbounded).
    ///
    /// A bounded value should be set for any server / loop that issues
    /// `fire_*` faster than `recv()` consumes — without a cap, a slow
    /// or stalled consumer grows the queue without limit and eventually
    /// OOMs the worker.
    pub fn max_in_flight(mut self, n: usize) -> Self {
        self.max_in_flight = n;
        self
    }

    /// Register a callback invoked after each command completes.
    pub fn on_result<F: Fn(&CommandResult) + 'static>(mut self, f: F) -> Self {
        self.on_result = Some(Box::new(f));
        self
    }

    /// Enable kernel SO_TIMESTAMPING for latency measurement (requires `timestamps` feature).
    #[cfg(feature = "timestamps")]
    pub fn kernel_timestamps(mut self, enabled: bool) -> Self {
        self.use_kernel_ts = enabled;
        self
    }

    /// Set the maximum number of `fire_*` commands to coalesce into a single
    /// send. Default is 1 (each `fire_*` sends immediately, matching
    /// pre-coalescing behavior). Set higher for pipelined workloads to batch
    /// multiple commands into fewer TCP segments.
    ///
    /// # Panics
    ///
    /// Panics if `n` is 0.
    pub fn max_batch_size(mut self, n: usize) -> Self {
        assert!(n > 0, "max_batch_size must be >= 1");
        self.max_batch_size = n;
        self
    }

    /// Enable built-in histogram tracking (requires `metrics` feature).
    #[cfg(feature = "metrics")]
    pub fn with_metrics(mut self) -> Self {
        self.with_metrics = true;
        self
    }

    /// Build the client.
    pub fn build(self) -> Client {
        Client {
            conn: self.conn,
            on_result: self.on_result,
            pending: VecDeque::with_capacity(16),
            last_rx_bytes: Cell::new(0),
            write_buf: Vec::new(),
            write_guards: Vec::new(),
            flushed_count: 0,
            max_batch_size: self.max_batch_size,
            max_in_flight: self.max_in_flight,
            zc_threshold: self.zc_threshold,
            buffered_ops: 0,
            encode_buf: Vec::new(),
            #[cfg(feature = "timestamps")]
            use_kernel_ts: self.use_kernel_ts,
            #[cfg(feature = "metrics")]
            metrics: if self.with_metrics {
                Some(ClientMetrics::new())
            } else {
                None
            },
        }
    }
}

// ── Client ──────────────────────────────────────────────────────────────

/// A ringline-native RESP client wrapping a single connection.
///
/// `Client::new(conn)` creates a zero-overhead client with no callbacks or
/// metrics. Use `Client::builder(conn)` to configure per-request callbacks,
/// kernel timestamps, and built-in histogram tracking.
pub struct Client {
    conn: ConnCtx,
    on_result: Option<ResultCallback>,
    pending: VecDeque<PendingOp>,
    last_rx_bytes: Cell<u32>,
    /// Write buffer for coalescing `fire_*` commands. Contains all copy data
    /// (command framing, prefixes, suffixes, non-guard values). Guard values
    /// are stored separately in `write_guards` with byte offsets into this buffer.
    write_buf: Vec<u8>,
    /// Zero-copy guards pending flush. Each entry is `(offset, guard)` where
    /// `offset` is the byte position in `write_buf` where the guard value
    /// should be inserted in the byte stream.
    write_guards: Vec<(usize, GuardBox)>,
    /// Number of pending ops whose send_ts has been finalized (at flush time).
    flushed_count: usize,
    /// Maximum `fire_*` commands to coalesce before flushing. 1 = send each
    /// command immediately (default, matching pre-coalescing behavior).
    max_batch_size: usize,
    /// Cap on `pending.len()`; `fire_*` returns `Error::TooManyInFlight`
    /// past it. `usize::MAX` (default) disables.
    max_in_flight: usize,
    /// Guard values smaller than this (bytes) are folded into the coalescing
    /// copy path by `fire_set_with_guard` / `fire_set_ex_with_guard` instead
    /// of taking the scatter-gather guard path. `0` disables the fold.
    zc_threshold: u32,
    /// Number of ops buffered in `write_buf` that have not yet been flushed.
    buffered_ops: usize,
    /// Reusable scratch buffer for encoding single requests (direct-send
    /// fast path and sequential commands). Cleared before each use; keeps
    /// its capacity across requests so steady-state encoding is
    /// allocation-free.
    encode_buf: Vec<u8>,
    #[cfg(feature = "timestamps")]
    use_kernel_ts: bool,
    #[cfg(feature = "metrics")]
    metrics: Option<ClientMetrics>,
}

impl Client {
    /// Create a new client wrapping an established connection.
    ///
    /// No callbacks, no metrics, no kernel timestamps — zero overhead.
    /// `max_batch_size` defaults to 1 (each `fire_*` sends immediately).
    pub fn new(conn: ConnCtx) -> Self {
        Self {
            conn,
            on_result: None,
            pending: VecDeque::new(),
            last_rx_bytes: Cell::new(0),
            write_buf: Vec::new(),
            write_guards: Vec::new(),
            flushed_count: 0,
            max_batch_size: 1,
            max_in_flight: usize::MAX,
            zc_threshold: DEFAULT_ZC_THRESHOLD,
            buffered_ops: 0,
            encode_buf: Vec::new(),
            #[cfg(feature = "timestamps")]
            use_kernel_ts: false,
            #[cfg(feature = "metrics")]
            metrics: None,
        }
    }

    /// Create a builder for a client with per-request callbacks.
    pub fn builder(conn: ConnCtx) -> ClientBuilder {
        ClientBuilder::new(conn)
    }

    /// Returns the underlying connection context.
    pub fn conn(&self) -> ConnCtx {
        self.conn
    }

    /// Returns a reference to the built-in metrics, if enabled.
    #[cfg(feature = "metrics")]
    pub fn metrics(&self) -> Option<&ClientMetrics> {
        self.metrics.as_ref()
    }

    /// Returns a mutable reference to the built-in metrics, if enabled.
    #[cfg(feature = "metrics")]
    pub fn metrics_mut(&mut self) -> Option<&mut ClientMetrics> {
        self.metrics.as_mut()
    }

    // ── Timing helpers (private) ────────────────────────────────────────

    #[inline]
    fn is_instrumented(&self) -> bool {
        if self.on_result.is_some() {
            return true;
        }
        #[cfg(feature = "metrics")]
        if self.metrics.is_some() {
            return true;
        }
        false
    }

    #[cfg(feature = "timestamps")]
    #[inline]
    fn send_timestamp(&self) -> u64 {
        if self.use_kernel_ts {
            now_realtime_ns()
        } else {
            0
        }
    }

    #[cfg(not(feature = "timestamps"))]
    #[inline]
    fn send_timestamp(&self) -> u64 {
        0
    }

    #[cfg(feature = "timestamps")]
    #[inline]
    fn finish_timing(&self, send_ts: u64, start: Instant) -> u64 {
        if self.use_kernel_ts {
            let recv_ts = self.conn.recv_timestamp();
            if recv_ts > 0 && recv_ts > send_ts {
                return recv_ts - send_ts;
            }
        }
        start.elapsed().as_nanos() as u64
    }

    #[cfg(not(feature = "timestamps"))]
    #[inline]
    fn finish_timing(&self, _send_ts: u64, start: Instant) -> u64 {
        start.elapsed().as_nanos() as u64
    }

    /// Record a command result: invoke callback and update metrics.
    #[inline]
    fn record(&mut self, result: &CommandResult) {
        if let Some(ref cb) = self.on_result {
            cb(result);
        }
        #[cfg(feature = "metrics")]
        if let Some(ref mut m) = self.metrics {
            m.record(result);
        }
    }

    // ── Fire/recv pipelining API ─────────────────────────────────────────

    #[inline]
    fn timing_start(&self) -> (u64, Option<Instant>) {
        #[cfg(feature = "timestamps")]
        {
            if self.is_instrumented() {
                (self.send_timestamp(), Some(Instant::now()))
            } else {
                (0, None)
            }
        }
        #[cfg(not(feature = "timestamps"))]
        {
            // When timestamps feature is disabled, only use Instant::now() if callbacks are registered
            if self.on_result.is_some() {
                (0, Some(Instant::now()))
            } else {
                (0, None)
            }
        }
    }

    /// `timing_start()` for `fire_*` call sites, evaluated *after* the op
    /// has been buffered/sent. When this op is buffered behind another op
    /// (`buffered_ops > 1`), `flush()` will unconditionally re-stamp
    /// `send_ts`/`start` for every op in the batch, so the fire-time clock
    /// read would be discarded — skip it. `buffered_ops` is monotonic
    /// between flushes, so if it is > 1 now, the rewriting branch in
    /// `flush()` (`buffered_ops > 1`) is guaranteed to run for this op.
    #[inline]
    fn timing_start_buffered(&self) -> (u64, Option<Instant>) {
        if self.buffered_ops >= 1 {
            (0, None)
        } else {
            self.timing_start()
        }
    }

    #[cfg(feature = "timestamps")]
    #[inline]
    fn compute_ttfb(&self, send_ts: u64) -> Option<u64> {
        if self.use_kernel_ts {
            let recv_ts = self.conn.recv_timestamp();
            if recv_ts > 0 && recv_ts > send_ts {
                return Some(recv_ts - send_ts);
            }
        }
        None
    }

    #[cfg(not(feature = "timestamps"))]
    #[inline]
    fn compute_ttfb(&self, _send_ts: u64) -> Option<u64> {
        None
    }

    /// Number of in-flight requests.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Flush before appending the next op if adding it would exceed
    /// guard/iovec limits for scatter-gather sends. Also enforces the
    /// `max_in_flight` cap so adversarial / stalled callers can't grow
    /// the pending queue without bound.
    fn pre_flush_if_needed(&mut self, has_guard: bool) -> Result<(), Error> {
        if self.pending.len() >= self.max_in_flight {
            return Err(Error::TooManyInFlight);
        }
        if self.buffered_ops == 0 {
            return Ok(());
        }
        let next_guards = self.write_guards.len() + usize::from(has_guard);
        let next_parts = 2 * next_guards + 1;
        if next_guards > MAX_FLUSH_GUARDS || next_parts > MAX_FLUSH_IOVECS {
            self.flush()?;
        }
        Ok(())
    }

    /// Flush after appending an op if we have reached `max_batch_size`.
    fn post_flush_if_needed(&mut self) -> Result<(), Error> {
        if self.buffered_ops >= self.max_batch_size {
            self.flush()?;
        }
        Ok(())
    }

    /// Fire a GET request without waiting for the response.
    /// Flush buffered `fire_*` commands as a single send.
    ///
    /// Called automatically by [`recv()`](Self::recv). Call explicitly if you
    /// need commands to hit the wire before reading responses (e.g., when
    /// interleaving fire/recv across multiple clients).
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.write_buf.is_empty() && self.write_guards.is_empty() {
            self.buffered_ops = 0;
            return Ok(());
        }

        // Send the batch. If the send itself errors (peer RST, kernel
        // ENOBUFS, etc.), discard the bytes-in-progress and the pending
        // ops we'd push_back'd for them. The previous behaviour returned
        // the error but left `write_buf` / `write_guards` / `pending` /
        // `flushed_count` inconsistent — the next `flush()` would re-send
        // the same buffer, and `recv()` would pop a `PendingOp` for a
        // request that was never on the wire and then hang forever
        // awaiting a response that will never come.
        let send_outcome: Result<(), Error> = if self.write_guards.is_empty() {
            self.conn
                .send_nowait(&self.write_buf)
                .map(|_| ())
                .map_err(Error::from)
        } else {
            use ringline::SendPart;
            let mut parts: Vec<SendPart<'_>> = Vec::with_capacity(2 * MAX_FLUSH_GUARDS + 1);
            let mut pos = 0;
            for (offset, guard) in self.write_guards.drain(..) {
                if offset > pos {
                    parts.push(SendPart::Copy(&self.write_buf[pos..offset]));
                }
                parts.push(SendPart::Guard(guard));
                pos = offset;
            }
            if pos < self.write_buf.len() {
                parts.push(SendPart::Copy(&self.write_buf[pos..]));
            }
            self.conn
                .send_parts()
                .submit_batch(parts)
                .map(|_| ())
                .map_err(Error::from)
        };

        if let Err(e) = send_outcome {
            // Discard everything that was buffered for this flush. The
            // pending ops that haven't been finalised yet (i.e., those
            // beyond `flushed_count`) correspond to commands that were
            // pushed onto `pending` but never reached the wire — drop
            // them so `recv()` doesn't try to read responses for them.
            self.write_buf.clear();
            self.write_guards.clear();
            self.buffered_ops = 0;
            self.pending.truncate(self.flushed_count);
            return Err(e);
        }

        // Only rewrite send timestamps when batching multiple ops —
        // for a single buffered op the timestamp captured at fire time
        // is already accurate.
        if self.buffered_ops >= 1 {
            let (send_ts, start) = self.timing_start();
            for pending in self.pending.iter_mut().skip(self.flushed_count) {
                pending.send_ts = send_ts;
                pending.start = start;
            }
        }
        self.flushed_count = self.pending.len();

        self.write_buf.clear();
        self.write_guards.clear();
        self.buffered_ops = 0;

        Ok(())
    }

    /// Fire a GET request without waiting for the response.
    pub fn fire_get(&mut self, key: &[u8], user_data: u64) -> Result<(), Error> {
        self.pre_flush_if_needed(false)?;
        let req = Request::get(key);
        let tx_bytes;
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            // Direct send — skip write_buf round-trip.
            self.encode_buf.clear();
            Self::encode_request_into(&req, &mut self.encode_buf);
            tx_bytes = self.encode_buf.len() as u32;
            self.conn.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            Self::encode_request_into(&req, &mut self.write_buf);
            tx_bytes = (self.write_buf.len() - before) as u32;
            self.buffered_ops += 1;
        }
        let (send_ts, start) = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Get,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
        // Direct sends are already on the wire: keep flushed_count in
        // sync so a later flush() failure only truncates pending ops
        // that were never sent. Without this, the error path dropped
        // an op whose response WILL arrive — permanently misattributing
        // every subsequent response.
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            self.flushed_count += 1;
        }
        self.post_flush_if_needed()?;
        Ok(())
    }

    /// Fire a SET request (with copy) without waiting for the response.
    pub fn fire_set(&mut self, key: &[u8], value: &[u8], user_data: u64) -> Result<(), Error> {
        self.pre_flush_if_needed(false)?;
        let set_req = Request::set(key, value);
        let tx_bytes;
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            // Direct send — skip write_buf round-trip.
            self.encode_buf.clear();
            Self::encode_set_request_into(&set_req, &mut self.encode_buf);
            tx_bytes = self.encode_buf.len() as u32;
            self.conn.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            Self::encode_set_request_into(&set_req, &mut self.write_buf);
            tx_bytes = (self.write_buf.len() - before) as u32;
            self.buffered_ops += 1;
        }
        let (send_ts, start) = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Set,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
        // Direct sends are already on the wire: keep flushed_count in
        // sync so a later flush() failure only truncates pending ops
        // that were never sent. Without this, the error path dropped
        // an op whose response WILL arrive — permanently misattributing
        // every subsequent response.
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            self.flushed_count += 1;
        }
        self.post_flush_if_needed()?;
        Ok(())
    }

    /// Fire a SET request with zero-copy value via SendGuard.
    ///
    /// The guard value is kept alive and sent zero-copy at flush time via
    /// scatter-gather I/O. The command prefix/suffix are buffered as copy data.
    pub fn fire_set_with_guard<G: SendGuard>(
        &mut self,
        key: &[u8],
        guard: G,
        user_data: u64,
    ) -> Result<(), Error> {
        let (ptr, value_len) = guard.as_ptr_len();
        // Small guard values: fold into the coalescing copy path so they
        // batch like plain SETs (up to `max_batch_size`) instead of taking
        // the scatter-gather guard path, which flushes every few ops.
        if self.zc_threshold != 0 && value_len < self.zc_threshold {
            // SAFETY: `guard` is owned and live for the duration of this
            // function, so `ptr`/`value_len` describe a valid byte range.
            // `fire_set` copies those bytes into `write_buf`/`encode_buf`
            // synchronously (no `.await` between this borrow and the copy),
            // after which the guard `G` is dropped at the end of this call.
            let value = unsafe { core::slice::from_raw_parts(ptr, value_len as usize) };
            return self.fire_set(key, value, user_data);
        }
        self.pre_flush_if_needed(true)?;
        // Append prefix, record guard insertion point, append suffix —
        // directly into write_buf, no intermediate allocation.
        let before = self.write_buf.len();
        append_set_guard_prefix(&mut self.write_buf, key, value_len as usize);
        self.write_guards
            .push((self.write_buf.len(), GuardBox::new(guard)));
        self.write_buf.extend_from_slice(b"\r\n");
        let tx_bytes = (self.write_buf.len() - before + value_len as usize) as u32;
        self.buffered_ops += 1;
        let (send_ts, start) = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Set,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
        self.post_flush_if_needed()?;
        Ok(())
    }

    /// Fire a SET EX request (with copy) without waiting for the response.
    pub fn fire_set_ex(
        &mut self,
        key: &[u8],
        value: &[u8],
        ttl_secs: u64,
        user_data: u64,
    ) -> Result<(), Error> {
        self.pre_flush_if_needed(false)?;
        let set_req = Request::set(key, value).ex(ttl_secs);
        let tx_bytes;
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            // Direct send — skip write_buf round-trip.
            self.encode_buf.clear();
            Self::encode_set_request_into(&set_req, &mut self.encode_buf);
            tx_bytes = self.encode_buf.len() as u32;
            self.conn.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            Self::encode_set_request_into(&set_req, &mut self.write_buf);
            tx_bytes = (self.write_buf.len() - before) as u32;
            self.buffered_ops += 1;
        }
        let (send_ts, start) = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Set,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
        // Direct sends are already on the wire: keep flushed_count in
        // sync so a later flush() failure only truncates pending ops
        // that were never sent. Without this, the error path dropped
        // an op whose response WILL arrive — permanently misattributing
        // every subsequent response.
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            self.flushed_count += 1;
        }
        self.post_flush_if_needed()?;
        Ok(())
    }

    /// Fire a SET EX request with zero-copy value via SendGuard.
    ///
    /// The guard value is kept alive and sent zero-copy at flush time via
    /// scatter-gather I/O. The command prefix/suffix are buffered as copy data.
    pub fn fire_set_ex_with_guard<G: SendGuard>(
        &mut self,
        key: &[u8],
        guard: G,
        ttl_secs: u64,
        user_data: u64,
    ) -> Result<(), Error> {
        let (ptr, value_len) = guard.as_ptr_len();
        // Small guard values: fold into the coalescing copy path (the EX
        // copy SET, `fire_set_ex`) so they batch like plain SETs instead of
        // taking the scatter-gather guard path.
        if self.zc_threshold != 0 && value_len < self.zc_threshold {
            // SAFETY: `guard` is owned and live for the duration of this
            // function, so `ptr`/`value_len` describe a valid byte range.
            // `fire_set_ex` copies those bytes synchronously (no `.await`
            // between this borrow and the copy), after which the guard `G`
            // is dropped at the end of this call.
            let value = unsafe { core::slice::from_raw_parts(ptr, value_len as usize) };
            return self.fire_set_ex(key, value, ttl_secs, user_data);
        }
        self.pre_flush_if_needed(true)?;
        // Append prefix, record guard insertion point, append suffix —
        // directly into write_buf, no intermediate allocations.
        let before = self.write_buf.len();
        append_set_guard_prefix_ex(&mut self.write_buf, key, value_len as usize);
        self.write_guards
            .push((self.write_buf.len(), GuardBox::new(guard)));
        append_set_guard_suffix_ex(&mut self.write_buf, ttl_secs);
        let tx_bytes = (self.write_buf.len() - before + value_len as usize) as u32;
        self.buffered_ops += 1;
        let (send_ts, start) = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Set,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
        self.post_flush_if_needed()?;
        Ok(())
    }

    /// Fire a DEL request without waiting for the response.
    pub fn fire_del(&mut self, key: &[u8], user_data: u64) -> Result<(), Error> {
        self.pre_flush_if_needed(false)?;
        let req = Request::del(key);
        let tx_bytes;
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            // Direct send — skip write_buf round-trip.
            self.encode_buf.clear();
            Self::encode_request_into(&req, &mut self.encode_buf);
            tx_bytes = self.encode_buf.len() as u32;
            self.conn.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            Self::encode_request_into(&req, &mut self.write_buf);
            tx_bytes = (self.write_buf.len() - before) as u32;
            self.buffered_ops += 1;
        }
        let (send_ts, start) = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Del,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
        // Direct sends are already on the wire: keep flushed_count in
        // sync so a later flush() failure only truncates pending ops
        // that were never sent. Without this, the error path dropped
        // an op whose response WILL arrive — permanently misattributing
        // every subsequent response.
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            self.flushed_count += 1;
        }
        self.post_flush_if_needed()?;
        Ok(())
    }

    /// Receive the next completed operation from the pipeline.
    ///
    /// Returns `Err(Error::NoPending)` if there are no in-flight requests.
    pub async fn recv(&mut self) -> Result<CompletedOp, Error> {
        // Flush any buffered fire_* commands before reading.
        self.flush()?;

        let pending = self.pending.pop_front().ok_or(Error::NoPending)?;
        self.flushed_count = self.flushed_count.saturating_sub(1);

        let resp = match self.read_value().await {
            Ok(v) => v,
            Err(e) => {
                // Connection is broken — clear remaining pending ops so
                // subsequent recv() calls return NoPending instead of
                // reading stale/misaligned responses. Reset
                // `flushed_count` too — otherwise a stale count > 0 makes
                // the next batched `flush()` skip the send_ts rewrite for
                // newly-buffered ops.
                self.pending.clear();
                self.flushed_count = 0;
                return Err(e);
            }
        };
        // TTFB from the kernel timestamp of the data that completed THIS
        // read. Sampling before the read used the PREVIOUS response's
        // arrival time for every op after the first in a pipelined batch.
        let ttfb_ns = self.compute_ttfb(pending.send_ts);
        let latency_ns = match pending.start {
            Some(start) => self.finish_timing(pending.send_ts, start),
            None => 0,
        };
        let rx_bytes = self.last_rx_bytes.get();
        let tx_bytes = pending.tx_bytes;

        let op = match pending.kind {
            PendingOpKind::Get => {
                let result = match resp {
                    Value::BulkString(data) => Ok(Some(data)),
                    Value::Null => Ok(None),
                    Value::Error(msg) => {
                        Err(Error::Redis(String::from_utf8_lossy(&msg).into_owned()))
                    }
                    _ => Err(Error::UnexpectedResponse),
                };
                let (success, hit) = match &result {
                    Ok(Some(_)) => (true, Some(true)),
                    Ok(None) => (true, Some(false)),
                    Err(_) => (false, None),
                };
                self.record(&CommandResult {
                    command: CommandType::Get,
                    latency_ns,
                    hit,
                    success,
                    ttfb_ns,
                    tx_bytes,
                    rx_bytes,
                });
                CompletedOp::Get {
                    result,
                    user_data: pending.user_data,
                    latency_ns,
                }
            }
            PendingOpKind::Set => {
                let result = match resp {
                    Value::SimpleString(_) | Value::Null => Ok(()),
                    Value::Error(msg) => {
                        Err(Error::Redis(String::from_utf8_lossy(&msg).into_owned()))
                    }
                    _ => Err(Error::UnexpectedResponse),
                };
                self.record(&CommandResult {
                    command: CommandType::Set,
                    latency_ns,
                    hit: None,
                    success: result.is_ok(),
                    ttfb_ns,
                    tx_bytes,
                    rx_bytes,
                });
                CompletedOp::Set {
                    result,
                    user_data: pending.user_data,
                    latency_ns,
                }
            }
            PendingOpKind::Del => {
                let result = match resp {
                    Value::Integer(n) => Ok(n as u64),
                    Value::Error(msg) => {
                        Err(Error::Redis(String::from_utf8_lossy(&msg).into_owned()))
                    }
                    _ => Err(Error::UnexpectedResponse),
                };
                self.record(&CommandResult {
                    command: CommandType::Del,
                    latency_ns,
                    hit: None,
                    success: result.is_ok(),
                    ttfb_ns,
                    tx_bytes,
                    rx_bytes,
                });
                CompletedOp::Del {
                    result,
                    user_data: pending.user_data,
                    latency_ns,
                }
            }
        };

        Ok(op)
    }

    /// Recv the next pending GET as a Mode-B **borrow-and-discard**: the value
    /// body is parsed from borrowed, zero-copy segments and released without ever
    /// being gathered into a contiguous buffer or [`Bytes`]. Returns the value
    /// length (`None` = miss) and the fired `user_data`.
    ///
    /// The next pending fire/recv op MUST be a GET (fired via
    /// [`fire_get`](Self::fire_get)); a non-GET pending op yields
    /// [`Error::UnexpectedResponse`].
    ///
    /// Zero value copy: under pipelining only the few-byte boundary remainder
    /// between this reply and the next is gathered. io_uring only (segmented recv).
    #[cfg(has_io_uring)]
    pub async fn recv_get_discard(&mut self) -> Result<GetMeta, Error> {
        self.recv_get_segments(|_| {}).await
    }

    /// Like [`recv_get_discard`](Self::recv_get_discard), but invokes `on_value`
    /// on each borrowed span of value bytes, in order — for a checksum or
    /// validator that must not retain the value. Still zero value copy.
    #[cfg(has_io_uring)]
    pub async fn recv_get_segments(
        &mut self,
        on_value: impl FnMut(&[u8]),
    ) -> Result<GetMeta, Error> {
        self.flush()?;
        let pending = self.pending.pop_front().ok_or(Error::NoPending)?;
        if !matches!(pending.kind, PendingOpKind::Get) {
            // This specialized recv only decodes a GET reply. A different pending
            // kind is caller misuse (mixed op kinds); surface it.
            return Err(Error::UnexpectedResponse);
        }
        self.flushed_count = self.flushed_count.saturating_sub(1);
        let (outcome, _consumed, _latency_ns) =
            self.run_get_state_machine(&pending, on_value).await?;
        match outcome {
            Ok(value_len) => Ok(GetMeta {
                value_len,
                user_data: pending.user_data,
            }),
            // A server error (`-ERR`/`-WRONGTYPE`) is wire-aligned; surface it as
            // `Err` so the connection stays usable. Desync/connection errors were
            // already turned into the OUTER `Err` (and poisoned) by the helper.
            Err(e) => Err(e),
        }
    }

    /// Runs the RESP GET reply state machine on an already-popped GET `pending`,
    /// draining the value via `on_value` (Mode-B borrow-and-discard). Shared by
    /// [`recv_get_segments`](Self::recv_get_segments) and
    /// [`recv_meta`](Self::recv_meta).
    ///
    /// Returns `(outcome, total_consumed)` where `outcome` is `Ok(Some(len))` =
    /// hit, `Ok(None)` = miss, or `Err(Error::Redis(_))` = a wire-aligned server
    /// error. Restores the default read path (`end_segments`) and records `GET`
    /// metrics. A desync (`Error::UnexpectedResponse` — only partially consumed,
    /// rest left on the wire) or a short FIN (`Error::ConnectionClosed`) is
    /// returned as the OUTER `Err`; the desync case also POISONS the connection
    /// (close + clear pipeline) so it is never reused.
    #[cfg(has_io_uring)]
    async fn run_get_state_machine(
        &mut self,
        pending: &PendingOp,
        mut on_value: impl FnMut(&[u8]),
    ) -> Result<(Result<Option<usize>, Error>, usize, u64), Error> {
        // RESP GET reply parse state, carried across `with_segments` calls. Each
        // call consumes every value byte it is shown (so nothing is re-gathered)
        // and stops only at the reply boundary, leaving the next reply's bytes to
        // be gathered — the only copy on the path.
        enum Phase {
            Header,
            Value,
            Trailing,
            Done,
        }
        let mut phase = Phase::Header;
        let mut header_buf: Vec<u8> = Vec::with_capacity(16);
        let mut value_remaining: usize = 0;
        let mut trailing_remaining: usize = 0;
        // Ok(Some(len)) = hit, Ok(None) = miss, Err = server error / unexpected.
        let mut outcome: Result<Option<usize>, Error> = Ok(None);
        let mut total_consumed: usize = 0;

        loop {
            let n = self
                .conn
                .with_segments(|chain| {
                    let mut consumed = 0usize;
                    'outer: for slice in chain.iter() {
                        let mut pos = 0usize;
                        while pos < slice.len() {
                            match phase {
                                Phase::Header => {
                                    header_buf.push(slice[pos]);
                                    pos += 1;
                                    consumed += 1;
                                    match parse_get_header(&header_buf) {
                                        Ok(None) => {} // need more header bytes
                                        Ok(Some(GetHeader::Nil)) => {
                                            outcome = Ok(None);
                                            phase = Phase::Done;
                                            break 'outer;
                                        }
                                        Ok(Some(GetHeader::Bulk { len, .. })) => {
                                            value_remaining = len;
                                            trailing_remaining = 2;
                                            outcome = Ok(Some(len));
                                            phase = Phase::Value;
                                        }
                                        Err(e) => {
                                            outcome = Err(e);
                                            phase = Phase::Done;
                                            break 'outer;
                                        }
                                    }
                                }
                                Phase::Value => {
                                    let take = value_remaining.min(slice.len() - pos);
                                    if take > 0 {
                                        on_value(&slice[pos..pos + take]);
                                    }
                                    value_remaining -= take;
                                    pos += take;
                                    consumed += take;
                                    if value_remaining == 0 {
                                        phase = Phase::Trailing;
                                    }
                                }
                                Phase::Trailing => {
                                    let take = trailing_remaining.min(slice.len() - pos);
                                    trailing_remaining -= take;
                                    pos += take;
                                    consumed += take;
                                    if trailing_remaining == 0 {
                                        phase = Phase::Done;
                                        break 'outer;
                                    }
                                }
                                Phase::Done => break 'outer,
                            }
                        }
                    }
                    ringline::SegConsumed(consumed)
                })
                .await?;
            total_consumed += n;
            if matches!(phase, Phase::Done) {
                break;
            }
            if n == 0 {
                // EOF before the reply completed (short FIN) — desynced.
                let _ = self.conn.end_segments();
                return Err(Error::ConnectionClosed);
            }
        }

        // Restore the default read path (the next reply's leftover bytes were
        // already gathered into the accumulator by the last `with_segments`
        // settle, and are presented to the following read).
        self.conn.end_segments()?;

        // Metrics, mirroring `recv()`.
        let ttfb_ns = self.compute_ttfb(pending.send_ts);
        let latency_ns = match pending.start {
            Some(start) => self.finish_timing(pending.send_ts, start),
            None => 0,
        };
        let (success, hit) = match &outcome {
            Ok(Some(_)) => (true, Some(true)),
            Ok(None) => (true, Some(false)),
            Err(_) => (false, None),
        };
        self.record(&CommandResult {
            command: CommandType::Get,
            latency_ns,
            hit,
            success,
            ttfb_ns,
            tx_bytes: pending.tx_bytes,
            rx_bytes: total_consumed as u32,
        });

        // A reply whose first byte is not `$`/`-` (`UnexpectedResponse`) is only
        // *partially* consumed by the byte-at-a-time header parse:
        // `parse_get_header`'s catch-all errors on the first byte, so the rest of
        // the reply is left on the wire. We cannot know how many bytes to skip for
        // an arbitrary reply type, so the connection is desynced and MUST NOT be
        // reused — poison it (close) and clear the pipeline, mirroring `recv()`'s
        // broken-read path. A genuine server error (`-ERR`/`-WRONGTYPE`,
        // `Error::Redis`) consumed its whole `\r\n`-terminated line via the `-`
        // arm, so the wire stays aligned and the connection stays valid — surface
        // it as the inner `outcome` `Err`, not the outer one.
        if let Err(Error::UnexpectedResponse) = &outcome {
            self.conn.close();
            self.pending.clear();
            self.flushed_count = 0;
            return Err(Error::UnexpectedResponse);
        }

        Ok((outcome, total_consumed, latency_ns))
    }

    /// Runs the RESP GET reply state machine on an already-popped GET `pending`
    /// over the mio accumulator (`with_bytes`): parses the header, then drains
    /// the value body incrementally so the accumulator stays bounded (~one
    /// kernel-drain burst), never materializing the value. The mio counterpart
    /// of [`run_get_state_machine`](Self::run_get_state_machine) — SAME parse and
    /// poison semantics, minus provided-buffer zero-copy (a `read()` copy per
    /// burst is unavoidable on mio). Intentionally duplicates the state machine
    /// (over `with_bytes` vs `with_segments`) to leave the reviewed io_uring path
    /// untouched.
    ///
    /// Returns `(outcome, total_consumed, latency_ns)`; a desync
    /// (`UnexpectedResponse`) poisons; a short FIN returns `ConnectionClosed`.
    #[cfg(not(has_io_uring))]
    async fn run_get_drain_mio(
        &mut self,
        pending: &PendingOp,
    ) -> Result<(Result<Option<usize>, Error>, usize, u64), Error> {
        enum Phase {
            Header,
            Value,
            Trailing,
            Done,
        }
        let mut phase = Phase::Header;
        let mut header_buf: Vec<u8> = Vec::with_capacity(16);
        let mut value_remaining: usize = 0;
        let mut trailing_remaining: usize = 0;
        let mut outcome: Result<Option<usize>, Error> = Ok(None);
        let mut total_consumed: usize = 0;

        loop {
            let n = self
                .conn
                .with_bytes(|bytes| {
                    let mut consumed = 0usize;
                    let mut pos = 0usize;
                    while pos < bytes.len() {
                        match phase {
                            Phase::Header => {
                                header_buf.push(bytes[pos]);
                                pos += 1;
                                consumed += 1;
                                match parse_get_header(&header_buf) {
                                    Ok(None) => {} // need more header bytes
                                    Ok(Some(GetHeader::Nil)) => {
                                        outcome = Ok(None);
                                        phase = Phase::Done;
                                        break;
                                    }
                                    Ok(Some(GetHeader::Bulk { len, .. })) => {
                                        value_remaining = len;
                                        trailing_remaining = 2;
                                        outcome = Ok(Some(len));
                                        phase = Phase::Value;
                                    }
                                    Err(e) => {
                                        outcome = Err(e);
                                        phase = Phase::Done;
                                        break;
                                    }
                                }
                            }
                            Phase::Value => {
                                // Drain what's present; the accumulator front is
                                // freed on `Consumed`, so a huge value never needs
                                // to be resident.
                                let take = value_remaining.min(bytes.len() - pos);
                                value_remaining -= take;
                                pos += take;
                                consumed += take;
                                if value_remaining == 0 {
                                    phase = Phase::Trailing;
                                }
                            }
                            Phase::Trailing => {
                                let take = trailing_remaining.min(bytes.len() - pos);
                                trailing_remaining -= take;
                                pos += take;
                                consumed += take;
                                if trailing_remaining == 0 {
                                    phase = Phase::Done;
                                    break;
                                }
                            }
                            Phase::Done => break,
                        }
                    }
                    if consumed == 0 {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(consumed)
                    }
                })
                .await;
            total_consumed += n;
            if matches!(phase, Phase::Done) {
                break;
            }
            if n == 0 {
                // EOF before the reply completed (short FIN) — desynced.
                return Err(Error::ConnectionClosed);
            }
        }

        // Metrics, mirroring `recv()` and the io_uring GET path.
        let ttfb_ns = self.compute_ttfb(pending.send_ts);
        let latency_ns = match pending.start {
            Some(start) => self.finish_timing(pending.send_ts, start),
            None => 0,
        };
        let (success, hit) = match &outcome {
            Ok(Some(_)) => (true, Some(true)),
            Ok(None) => (true, Some(false)),
            Err(_) => (false, None),
        };
        self.record(&CommandResult {
            command: CommandType::Get,
            latency_ns,
            hit,
            success,
            ttfb_ns,
            tx_bytes: pending.tx_bytes,
            rx_bytes: total_consumed as u32,
        });

        // Same poison discipline as the io_uring path: an unexpected reply type
        // (first byte not `$`/`-`) is only partially consumed (the header parse
        // stops on that byte), leaving the rest on the wire → desync, poison. A
        // server error (`-...`) consumed its whole line → wire aligned, surfaced
        // as the inner `outcome` Err.
        if let Err(Error::UnexpectedResponse) = &outcome {
            self.conn.close();
            self.pending.clear();
            self.flushed_count = 0;
            return Err(Error::UnexpectedResponse);
        }

        Ok((outcome, total_consumed, latency_ns))
    }

    /// Read the next pending reply as zero-copy metadata, for ANY op kind (GET /
    /// SET / DEL). GET drains the value body via the borrow-and-discard segmented
    /// path; SET/DEL read the small reply normally. The value bytes are never
    /// materialized — only the header / control metadata is surfaced
    /// ([`RespMeta`]), which is all a load generator needs.
    ///
    /// A server error reply (`-ERR`/`-MOVED`/`-ASK`) is reported as
    /// `Ok(RespMeta { success: false, error: Some(..) })` so the caller can
    /// inspect it (e.g. cluster redirects). `Err` is reserved for
    /// connection/desync failures — a GET desync poisons the connection.
    ///
    /// io_uring only (segmented recv).
    pub async fn recv_meta(&mut self) -> Result<RespMeta, Error> {
        self.flush()?;
        let pending = self.pending.pop_front().ok_or(Error::NoPending)?;
        self.flushed_count = self.flushed_count.saturating_sub(1);
        match pending.kind {
            PendingOpKind::Get => {
                // io_uring: zero-copy borrow-and-discard over provided buffers.
                // mio: header-parse + streaming drain over `with_bytes` — bounded
                // memory (never materializes the value), same `RespMeta` contract.
                #[cfg(has_io_uring)]
                let (outcome, _consumed, latency_ns) =
                    self.run_get_state_machine(&pending, |_| {}).await?;
                #[cfg(not(has_io_uring))]
                let (outcome, _consumed, latency_ns) = self.run_get_drain_mio(&pending).await?;
                let meta = match outcome {
                    Ok(value_len) => RespMeta {
                        kind: OpKind::Get,
                        user_data: pending.user_data,
                        value_len,
                        success: true,
                        error: None,
                        latency_ns,
                    },
                    Err(Error::Redis(msg)) => RespMeta {
                        kind: OpKind::Get,
                        user_data: pending.user_data,
                        value_len: None,
                        success: false,
                        error: Some(msg),
                        latency_ns,
                    },
                    // Only `Ok(..)` or `Err(Redis)` reach here; desync/connection
                    // errors were returned as the outer `Err` by the helper.
                    Err(e) => return Err(e),
                };
                Ok(meta)
            }
            PendingOpKind::Set => self.recv_meta_simple(&pending, OpKind::Set).await,
            PendingOpKind::Del => self.recv_meta_simple(&pending, OpKind::Del).await,
        }
    }

    /// Read a small SET/DEL reply and classify it into [`RespMeta`], mirroring
    /// `recv()`'s SET/DEL classification, without materializing anything the
    /// caller keeps. Unlike the GET segmented path, `read_value` consumes a
    /// *complete* RESP value, so an unexpected reply type is wire-aligned and is
    /// reported as `success = false` WITHOUT poisoning. A broken read clears the
    /// pipeline and returns `Err` (mirroring `recv()`).
    async fn recv_meta_simple(
        &mut self,
        pending: &PendingOp,
        kind: OpKind,
    ) -> Result<RespMeta, Error> {
        let resp = match self.read_value().await {
            Ok(v) => v,
            Err(e) => {
                self.pending.clear();
                self.flushed_count = 0;
                return Err(e);
            }
        };
        let ttfb_ns = self.compute_ttfb(pending.send_ts);
        let latency_ns = match pending.start {
            Some(start) => self.finish_timing(pending.send_ts, start),
            None => 0,
        };
        let rx_bytes = self.last_rx_bytes.get();
        let (success, error) = match resp {
            Value::Error(msg) => (false, Some(String::from_utf8_lossy(&msg).into_owned())),
            other => {
                // Wire-aligned (a full RESP value was consumed): an unexpected
                // type is a benign per-op failure, not a desync — do not poison.
                let ok = match kind {
                    OpKind::Set => matches!(other, Value::SimpleString(_) | Value::Null),
                    OpKind::Del => matches!(other, Value::Integer(_)),
                    OpKind::Get => false,
                };
                (ok, None)
            }
        };
        let command = match kind {
            OpKind::Set => CommandType::Set,
            OpKind::Del => CommandType::Del,
            OpKind::Get => CommandType::Get,
        };
        self.record(&CommandResult {
            command,
            latency_ns,
            hit: None,
            success,
            ttfb_ns,
            tx_bytes: pending.tx_bytes,
            rx_bytes,
        });
        Ok(RespMeta {
            kind,
            user_data: pending.user_data,
            value_len: None,
            success,
            error,
            latency_ns,
        })
    }

    // ── Internal protocol methods (pub(crate), &self) ───────────────────

    /// Read and parse a single RESP value from the connection.
    ///
    /// Uses zero-copy parsing via `with_bytes` + `Value::parse_bytes_with_options`:
    /// bulk string values are `Bytes::slice()` references into the
    /// accumulator's buffer rather than freshly allocated `Vec<u8>`.
    pub(crate) async fn read_value(&self) -> Result<Value, Error> {
        let mut result: Option<Result<Value, Error>> = None;
        // resp-proto's `parse_bytes` defaults to a 1 MiB bulk-string cap
        // (`DEFAULT_MAX_BULK_STRING_LEN`), which is far below what a real
        // Redis server can return (Redis 7's `proto-max-bulk-len` defaults to
        // 512 MiB). Hit the wall and the parser consumes the whole
        // accumulator, forcing a connection close for a value the server
        // happily produced. Use `usize::MAX` — the `RecvAccumulator`'s own
        // capacity is the genuine backstop — and let the server be the
        // authority on what's too large.
        // Also lift the collection caps well above resp-proto's 1024 defaults:
        // a real server returns arrays far larger than that (a big `LRANGE`,
        // `FT.SEARCH` with large `k`, an oversized `SCAN` batch), and hitting
        // the cap surfaces as a protocol error that closes the connection.
        // Unlike `max_bulk_string_len` (whose bytes must actually arrive, so the
        // accumulator is the real backstop), array parsing pre-allocates
        // `Vec::with_capacity(announced_len)`, so this stays a bounded ceiling
        // rather than `usize::MAX` to keep a hostile length from OOMing.
        const MAX_COLLECTION: usize = 1 << 20;
        let options = resp_proto::ParseOptions::new()
            .max_bulk_string_len(usize::MAX)
            .max_collection_elements(MAX_COLLECTION)
            .max_total_items(MAX_COLLECTION);
        let n = self
            .conn
            .with_bytes(|bytes| {
                let len = bytes.len();
                // Peek the bulk-string header before the parse takes
                // ownership: RESP announces payload length up front, so an
                // incomplete parse can tell the runtime exactly how much
                // more is coming and the recv accumulator reserves once
                // instead of doubling through a multi-MB value.
                let hint = bulk_remainder_hint(&bytes);
                match Value::parse_bytes_with_options(bytes, &options) {
                    Ok((value, consumed)) => {
                        result = Some(Ok(value));
                        ParseResult::Consumed(consumed)
                    }
                    Err(e) if e.is_incomplete() => match hint {
                        Some(additional) => ParseResult::NeedAtLeast(additional),
                        None => ParseResult::Consumed(0),
                    },
                    Err(e) => {
                        result = Some(Err(Error::Protocol(e)));
                        ParseResult::Consumed(len)
                    }
                }
            })
            .await;
        self.last_rx_bytes.set(n as u32);
        if n == 0 {
            return result.unwrap_or(Err(Error::ConnectionClosed));
        }
        let value = result.unwrap();
        // A protocol error means the RESP framing is irrecoverably
        // misaligned (the failed parse consumed the whole accumulator,
        // possibly swallowing the fronts of pipelined responses). Close the
        // connection so it can't serve stale responses to later commands —
        // matching the memcache and ping clients.
        if matches!(value, Err(Error::Protocol(_))) {
            self.conn.close();
        }
        value
    }

    /// Send a SET command via scatter-gather (prefix + value + suffix as
    /// separate iovecs) and read the response.
    async fn execute_set(
        &self,
        set_req: &resp_proto::SetRequest<'_>,
        value: &[u8],
    ) -> Result<Value, Error> {
        let (prefix, suffix) = set_req.encode_parts();
        self.conn
            .send_parts()
            .build(|b| b.copy(&prefix).copy(value).copy(&suffix).submit())?;
        let resp = self.read_value().await?;
        if let Value::Error(ref msg) = resp {
            return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
        }
        Ok(resp)
    }

    /// Send an encoded command and read the response, converting Redis
    /// error responses into `Error::Redis`.
    async fn execute(&self, encoded: &[u8]) -> Result<Value, Error> {
        self.conn.send(encoded)?;
        let value = self.read_value().await?;
        if let Value::Error(ref msg) = value {
            return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
        }
        Ok(value)
    }

    /// Execute a command and expect a SimpleString response (e.g. +OK).
    async fn execute_ok(&self, encoded: &[u8]) -> Result<(), Error> {
        let value = self.execute(encoded).await?;
        match value {
            Value::SimpleString(_) => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Execute a command and expect an Integer response.
    async fn execute_int(&self, encoded: &[u8]) -> Result<i64, Error> {
        let value = self.execute(encoded).await?;
        match value {
            Value::Integer(n) => Ok(n),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Execute a command and expect a BulkString or Null response.
    async fn execute_bulk(&self, encoded: &[u8]) -> Result<Option<Bytes>, Error> {
        let value = self.execute(encoded).await?;
        match value {
            Value::BulkString(data) => Ok(Some(data)),
            Value::Null => Ok(None),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Append the RESP encoding of a `Request` to `buf` (no allocation
    /// once `buf` has sufficient capacity).
    pub(crate) fn encode_request_into(req: &Request<'_>, buf: &mut Vec<u8>) {
        let len = req.encoded_len();
        let start = buf.len();
        buf.resize(start + len, 0);
        req.encode(&mut buf[start..]);
    }

    /// Append the RESP encoding of a `SetRequest` to `buf` (no allocation
    /// once `buf` has sufficient capacity).
    pub(crate) fn encode_set_request_into(req: &resp_proto::SetRequest<'_>, buf: &mut Vec<u8>) {
        let len = req.encoded_len();
        let start = buf.len();
        buf.resize(start + len, 0);
        req.encode(&mut buf[start..]);
    }

    /// Encode a `Request` into a `Vec<u8>`.
    pub(crate) fn encode_request(req: &Request<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        Self::encode_request_into(req, &mut buf);
        buf
    }

    /// Encode a `SetRequest` into a `Vec<u8>`. Test-only convenience; hot
    /// paths use [`Self::encode_set_request_into`] with a reused buffer.
    #[cfg(test)]
    pub(crate) fn encode_set_request(req: &resp_proto::SetRequest<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        Self::encode_set_request_into(req, &mut buf);
        buf
    }

    // ── Instrumented String commands ────────────────────────────────────

    /// Get the value of a key.
    pub async fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        self.encode_buf.clear();
        Self::encode_request_into(&Request::get(key), &mut self.encode_buf);
        if !self.is_instrumented() {
            return self.execute_bulk(&self.encode_buf).await;
        }
        let tx_bytes = self.encode_buf.len() as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self.execute_bulk(&self.encode_buf).await;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();
        let (success, hit) = match &result {
            Ok(Some(_)) => (true, Some(true)),
            Ok(None) => (true, Some(false)),
            Err(_) => (false, None),
        };
        self.record(&CommandResult {
            command: CommandType::Get,
            latency_ns,
            hit,
            success,
            ttfb_ns: None,
            tx_bytes,
            rx_bytes,
        });
        result
    }

    /// Set a key-value pair.
    pub async fn set(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let set_req = Request::set(key, value);
        if !self.is_instrumented() {
            let resp = self.execute_set(&set_req, value).await?;
            return match resp {
                Value::SimpleString(_) | Value::Null => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }
        let tx_bytes = set_req.encoded_len() as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self.execute_set(&set_req, value).await;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();
        let success = result.is_ok();
        let final_result = match result {
            Ok(Value::SimpleString(_) | Value::Null) => Ok(()),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Set,
            latency_ns,
            hit: None,
            success,
            ttfb_ns: None,
            tx_bytes,
            rx_bytes,
        });
        final_result
    }

    /// Set a key-value pair with TTL in seconds.
    pub async fn set_ex(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        ttl_secs: u64,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let set_req = Request::set(key, value).ex(ttl_secs);
        if !self.is_instrumented() {
            let resp = self.execute_set(&set_req, value).await?;
            return match resp {
                Value::SimpleString(_) => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }
        let tx_bytes = set_req.encoded_len() as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self.execute_set(&set_req, value).await;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();
        let success = result.is_ok();
        let final_result = match result {
            Ok(Value::SimpleString(_)) => Ok(()),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Set,
            latency_ns,
            hit: None,
            success,
            ttfb_ns: None,
            tx_bytes,
            rx_bytes,
        });
        final_result
    }

    /// Set a key-value pair with TTL in milliseconds.
    pub async fn set_px(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        ttl_ms: u64,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let resp = self
            .execute_set(&Request::set(key, value).px(ttl_ms), value)
            .await?;
        match resp {
            Value::SimpleString(_) => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Set a key only if it does not already exist. Returns true if the key was set.
    pub async fn set_nx(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let resp = self
            .execute_set(&Request::set(key, value).nx(), value)
            .await?;
        match resp {
            Value::SimpleString(_) => Ok(true),
            Value::Null => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Delete a key. Returns the number of keys deleted.
    pub async fn del(&mut self, key: impl AsRef<[u8]>) -> Result<u64, Error> {
        let key = key.as_ref();
        self.encode_buf.clear();
        Self::encode_request_into(&Request::del(key), &mut self.encode_buf);
        if !self.is_instrumented() {
            return self.execute_int(&self.encode_buf).await.map(|n| n as u64);
        }
        let tx_bytes = self.encode_buf.len() as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self.execute_int(&self.encode_buf).await.map(|n| n as u64);
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();
        self.record(&CommandResult {
            command: CommandType::Del,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
            tx_bytes,
            rx_bytes,
        });
        result
    }

    /// Get values for multiple keys.
    pub async fn mget(&mut self, keys: &[&[u8]]) -> Result<Vec<Option<Bytes>>, Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let value = self
            .execute(&Self::encode_request(&Request::mget(keys)))
            .await?;
        match value {
            Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::BulkString(data) => result.push(Some(data)),
                        Value::Null => result.push(None),
                        _ => return Err(Error::UnexpectedResponse),
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Increment the integer value of a key by 1.
    pub async fn incr(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"INCR").arg(key)))
            .await
    }

    /// Decrement the integer value of a key by 1.
    pub async fn decr(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"DECR").arg(key)))
            .await
    }

    /// Increment the integer value of a key by a given amount.
    pub async fn incrby(&mut self, key: impl AsRef<[u8]>, delta: i64) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut buf = itoa::Buffer::new();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"INCRBY")
                .arg(key)
                .arg(buf.format(delta).as_bytes()),
        ))
        .await
    }

    /// Decrement the integer value of a key by a given amount.
    pub async fn decrby(&mut self, key: impl AsRef<[u8]>, delta: i64) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut buf = itoa::Buffer::new();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"DECRBY")
                .arg(key)
                .arg(buf.format(delta).as_bytes()),
        ))
        .await
    }

    /// Append a value to a key. Returns the length of the string after the append.
    pub async fn append(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<i64, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"APPEND").arg(key).arg(value),
        ))
        .await
    }

    // ── Key commands ────────────────────────────────────────────────────

    /// Check if a key exists.
    pub async fn exists(&mut self, key: impl AsRef<[u8]>) -> Result<bool, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"EXISTS").arg(key)))
            .await
            .map(|n| n > 0)
    }

    /// Set a timeout on a key in seconds.
    pub async fn expire(&mut self, key: impl AsRef<[u8]>, seconds: u64) -> Result<bool, Error> {
        let key = key.as_ref();
        let mut buf = itoa::Buffer::new();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"EXPIRE")
                .arg(key)
                .arg(buf.format(seconds).as_bytes()),
        ))
        .await
        .map(|n| n == 1)
    }

    /// Get the TTL of a key in seconds.
    pub async fn ttl(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"TTL").arg(key)))
            .await
    }

    /// Get the TTL of a key in milliseconds.
    pub async fn pttl(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"PTTL").arg(key)))
            .await
    }

    /// Remove the existing timeout on a key.
    pub async fn persist(&mut self, key: impl AsRef<[u8]>) -> Result<bool, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"PERSIST").arg(key)))
            .await
            .map(|n| n == 1)
    }

    /// Get the type of a key.
    pub async fn key_type(&mut self, key: impl AsRef<[u8]>) -> Result<String, Error> {
        let key = key.as_ref();
        let value = self
            .execute(&Self::encode_request(&Request::cmd(b"TYPE").arg(key)))
            .await?;
        match value {
            Value::SimpleString(data) => Ok(String::from_utf8_lossy(&data).into_owned()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Rename a key.
    pub async fn rename(
        &mut self,
        key: impl AsRef<[u8]>,
        new_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let new_key = new_key.as_ref();
        self.execute_ok(&Self::encode_request(
            &Request::cmd(b"RENAME").arg(key).arg(new_key),
        ))
        .await
    }

    /// Delete keys without blocking. Returns the number of keys removed.
    pub async fn unlink(&mut self, key: impl AsRef<[u8]>) -> Result<u64, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"UNLINK").arg(key)))
            .await
            .map(|n| n as u64)
    }

    // ── Hash commands ───────────────────────────────────────────────────

    /// Set a field in a hash. Returns true if the field is new.
    pub async fn hset(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        let value = value.as_ref();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"HSET").arg(key).arg(field).arg(value),
        ))
        .await
        .map(|n| n > 0)
    }

    /// Get the value of a hash field.
    pub async fn hget(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
    ) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        self.execute_bulk(&Self::encode_request(
            &Request::cmd(b"HGET").arg(key).arg(field),
        ))
        .await
    }

    /// Get all fields and values in a hash.
    pub async fn hgetall(&mut self, key: impl AsRef<[u8]>) -> Result<Vec<(Bytes, Bytes)>, Error> {
        let key = key.as_ref();
        let value = self
            .execute(&Self::encode_request(&Request::cmd(b"HGETALL").arg(key)))
            .await?;
        match value {
            Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len() / 2);
                let mut iter = arr.into_iter();
                while let Some(field) = iter.next() {
                    let val = iter.next().ok_or(Error::UnexpectedResponse)?;
                    match (field, val) {
                        (Value::BulkString(f), Value::BulkString(v)) => {
                            result.push((f, v));
                        }
                        _ => return Err(Error::UnexpectedResponse),
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Get values for multiple hash fields.
    pub async fn hmget(
        &mut self,
        key: impl AsRef<[u8]>,
        fields: &[&[u8]],
    ) -> Result<Vec<Option<Bytes>>, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"HMGET").arg(key);
        for field in fields {
            req = req.arg(field);
        }
        let value = self.execute(&Self::encode_request(&req)).await?;
        match value {
            Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::BulkString(data) => result.push(Some(data)),
                        Value::Null => result.push(None),
                        _ => return Err(Error::UnexpectedResponse),
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Delete fields from a hash. Returns the number of fields removed.
    pub async fn hdel(&mut self, key: impl AsRef<[u8]>, fields: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"HDEL").arg(key);
        for field in fields {
            req = req.arg(field);
        }
        self.execute_int(&Self::encode_request(&req)).await
    }

    /// Check if a field exists in a hash.
    pub async fn hexists(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"HEXISTS").arg(key).arg(field),
        ))
        .await
        .map(|n| n == 1)
    }

    /// Get the number of fields in a hash.
    pub async fn hlen(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"HLEN").arg(key)))
            .await
    }

    /// Get all field names in a hash.
    pub async fn hkeys(&mut self, key: impl AsRef<[u8]>) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let value = self
            .execute(&Self::encode_request(&Request::cmd(b"HKEYS").arg(key)))
            .await?;
        parse_bytes_array(value)
    }

    /// Get all values in a hash.
    pub async fn hvals(&mut self, key: impl AsRef<[u8]>) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let value = self
            .execute(&Self::encode_request(&Request::cmd(b"HVALS").arg(key)))
            .await?;
        parse_bytes_array(value)
    }

    /// Increment the integer value of a hash field.
    pub async fn hincrby(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
        delta: i64,
    ) -> Result<i64, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        let mut buf = itoa::Buffer::new();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"HINCRBY")
                .arg(key)
                .arg(field)
                .arg(buf.format(delta).as_bytes()),
        ))
        .await
    }

    /// Set a hash field only if it does not exist.
    pub async fn hsetnx(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        let value = value.as_ref();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"HSETNX").arg(key).arg(field).arg(value),
        ))
        .await
        .map(|n| n == 1)
    }

    // ── List commands ───────────────────────────────────────────────────

    /// Push values to the head of a list. Returns the list length.
    pub async fn lpush(&mut self, key: impl AsRef<[u8]>, values: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"LPUSH").arg(key);
        for v in values {
            req = req.arg(v);
        }
        self.execute_int(&Self::encode_request(&req)).await
    }

    /// Push values to the tail of a list. Returns the list length.
    pub async fn rpush(&mut self, key: impl AsRef<[u8]>, values: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"RPUSH").arg(key);
        for v in values {
            req = req.arg(v);
        }
        self.execute_int(&Self::encode_request(&req)).await
    }

    /// Remove and return the first element of a list.
    pub async fn lpop(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        self.execute_bulk(&Self::encode_request(&Request::cmd(b"LPOP").arg(key)))
            .await
    }

    /// Remove and return the last element of a list.
    pub async fn rpop(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        self.execute_bulk(&Self::encode_request(&Request::cmd(b"RPOP").arg(key)))
            .await
    }

    /// Get the length of a list.
    pub async fn llen(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"LLEN").arg(key)))
            .await
    }

    /// Get an element from a list by index.
    pub async fn lindex(
        &mut self,
        key: impl AsRef<[u8]>,
        index: i64,
    ) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        let mut buf = itoa::Buffer::new();
        self.execute_bulk(&Self::encode_request(
            &Request::cmd(b"LINDEX")
                .arg(key)
                .arg(buf.format(index).as_bytes()),
        ))
        .await
    }

    /// Get a range of elements from a list.
    pub async fn lrange(
        &mut self,
        key: impl AsRef<[u8]>,
        start: i64,
        stop: i64,
    ) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let mut buf1 = itoa::Buffer::new();
        let mut buf2 = itoa::Buffer::new();
        let value = self
            .execute(&Self::encode_request(
                &Request::cmd(b"LRANGE")
                    .arg(key)
                    .arg(buf1.format(start).as_bytes())
                    .arg(buf2.format(stop).as_bytes()),
            ))
            .await?;
        parse_bytes_array(value)
    }

    /// Trim a list to a specified range.
    pub async fn ltrim(
        &mut self,
        key: impl AsRef<[u8]>,
        start: i64,
        stop: i64,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let mut buf1 = itoa::Buffer::new();
        let mut buf2 = itoa::Buffer::new();
        self.execute_ok(&Self::encode_request(
            &Request::cmd(b"LTRIM")
                .arg(key)
                .arg(buf1.format(start).as_bytes())
                .arg(buf2.format(stop).as_bytes()),
        ))
        .await
    }

    /// Set the value of an element by index.
    pub async fn lset(
        &mut self,
        key: impl AsRef<[u8]>,
        index: i64,
        value: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let mut buf = itoa::Buffer::new();
        self.execute_ok(&Self::encode_request(
            &Request::cmd(b"LSET")
                .arg(key)
                .arg(buf.format(index).as_bytes())
                .arg(value),
        ))
        .await
    }

    /// Push a value to the head of a list only if the list exists. Returns the list length.
    pub async fn lpushx(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<i64, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"LPUSHX").arg(key).arg(value),
        ))
        .await
    }

    /// Push a value to the tail of a list only if the list exists. Returns the list length.
    pub async fn rpushx(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<i64, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"RPUSHX").arg(key).arg(value),
        ))
        .await
    }

    // ── Set commands ────────────────────────────────────────────────────

    /// Add members to a set. Returns the number of members added.
    pub async fn sadd(&mut self, key: impl AsRef<[u8]>, members: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"SADD").arg(key);
        for m in members {
            req = req.arg(m);
        }
        self.execute_int(&Self::encode_request(&req)).await
    }

    /// Remove members from a set. Returns the number of members removed.
    pub async fn srem(&mut self, key: impl AsRef<[u8]>, members: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"SREM").arg(key);
        for m in members {
            req = req.arg(m);
        }
        self.execute_int(&Self::encode_request(&req)).await
    }

    /// Get all members of a set.
    pub async fn smembers(&mut self, key: impl AsRef<[u8]>) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let value = self
            .execute(&Self::encode_request(&Request::cmd(b"SMEMBERS").arg(key)))
            .await?;
        parse_bytes_array(value)
    }

    /// Get the number of members in a set.
    pub async fn scard(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.execute_int(&Self::encode_request(&Request::cmd(b"SCARD").arg(key)))
            .await
    }

    /// Check if a member exists in a set.
    pub async fn sismember(
        &mut self,
        key: impl AsRef<[u8]>,
        member: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let member = member.as_ref();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"SISMEMBER").arg(key).arg(member),
        ))
        .await
        .map(|n| n == 1)
    }

    /// Check if multiple members exist in a set.
    pub async fn smismember(
        &mut self,
        key: impl AsRef<[u8]>,
        members: &[&[u8]],
    ) -> Result<Vec<bool>, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"SMISMEMBER").arg(key);
        for m in members {
            req = req.arg(m);
        }
        let value = self.execute(&Self::encode_request(&req)).await?;
        match value {
            Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::Integer(n) => result.push(n == 1),
                        _ => return Err(Error::UnexpectedResponse),
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Remove and return a random member from a set.
    pub async fn spop(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        self.execute_bulk(&Self::encode_request(&Request::cmd(b"SPOP").arg(key)))
            .await
    }

    /// Get random members from a set.
    pub async fn srandmember(
        &mut self,
        key: impl AsRef<[u8]>,
        count: i64,
    ) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let mut buf = itoa::Buffer::new();
        let value = self
            .execute(&Self::encode_request(
                &Request::cmd(b"SRANDMEMBER")
                    .arg(key)
                    .arg(buf.format(count).as_bytes()),
            ))
            .await?;
        parse_bytes_array(value)
    }

    // ── Auth commands ────────────────────────────────────────────────────

    /// Authenticate with a password (`AUTH password`).
    pub async fn auth(&mut self, password: impl AsRef<[u8]>) -> Result<(), Error> {
        let password = password.as_ref();
        self.execute_ok(&Self::encode_request(&Request::cmd(b"AUTH").arg(password)))
            .await
    }

    /// Authenticate with a username and password (`AUTH username password`).
    ///
    /// Requires Redis 6.0+ with ACL support.
    pub async fn auth_username(
        &mut self,
        username: impl AsRef<[u8]>,
        password: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let username = username.as_ref();
        let password = password.as_ref();
        self.execute_ok(&Self::encode_request(
            &Request::cmd(b"AUTH").arg(username).arg(password),
        ))
        .await
    }

    /// Send AUTH if credentials are provided. Used internally after connect.
    pub(crate) async fn maybe_auth(
        &mut self,
        password: Option<&str>,
        username: Option<&str>,
    ) -> Result<(), Error> {
        if let Some(password) = password {
            match username {
                Some(username) => self.auth_username(username, password).await,
                None => self.auth(password).await,
            }
        } else {
            Ok(())
        }
    }

    // ── Server commands ─────────────────────────────────────────────────

    /// Ping the server.
    pub async fn ping(&mut self) -> Result<(), Error> {
        self.encode_buf.clear();
        Self::encode_request_into(&Request::ping(), &mut self.encode_buf);
        if !self.is_instrumented() {
            let value = self.execute(&self.encode_buf).await?;
            return match value {
                Value::SimpleString(_) => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }
        let tx_bytes = self.encode_buf.len() as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self.execute(&self.encode_buf).await;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();
        let success = result.is_ok();
        let final_result = match result {
            Ok(Value::SimpleString(_)) => Ok(()),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Ping,
            latency_ns,
            hit: None,
            success,
            ttfb_ns: None,
            tx_bytes,
            rx_bytes,
        });
        final_result
    }

    /// Delete all keys in the current database.
    pub async fn flushdb(&mut self) -> Result<(), Error> {
        self.execute_ok(&Self::encode_request(&Request::flushdb()))
            .await
    }

    /// Delete all keys in all databases.
    pub async fn flushall(&mut self) -> Result<(), Error> {
        self.execute_ok(&Self::encode_request(&Request::flushall()))
            .await
    }

    /// Get the number of keys in the current database.
    pub async fn dbsize(&mut self) -> Result<i64, Error> {
        self.execute_int(&Self::encode_request(&Request::cmd(b"DBSIZE")))
            .await
    }

    /// Get configuration parameter values.
    pub async fn config_get(
        &mut self,
        key: impl AsRef<[u8]>,
    ) -> Result<Vec<(Bytes, Bytes)>, Error> {
        let key = key.as_ref();
        let value = self
            .execute(&Self::encode_request(&Request::config_get(key)))
            .await?;
        match value {
            Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len() / 2);
                let mut iter = arr.into_iter();
                while let Some(k) = iter.next() {
                    let v = iter.next().ok_or(Error::UnexpectedResponse)?;
                    match (k, v) {
                        (Value::BulkString(kk), Value::BulkString(vv)) => {
                            result.push((kk, vv));
                        }
                        _ => return Err(Error::UnexpectedResponse),
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Set a configuration parameter.
    pub async fn config_set(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        self.execute_ok(&Self::encode_request(&Request::config_set(key, value)))
            .await
    }

    // ── Custom command ──────────────────────────────────────────────────

    /// Execute a custom command. Returns the raw RESP Value.
    pub async fn cmd(&mut self, request: &Request<'_>) -> Result<Value, Error> {
        self.execute(&Self::encode_request(request)).await
    }

    // ── Pipeline ────────────────────────────────────────────────────────

    /// Create a pipeline for batched command execution.
    pub fn pipeline(&self) -> Pipeline {
        Pipeline::new(self.conn)
    }

    // ── Zero-copy SET ───────────────────────────────────────────────────

    /// SET with zero-copy value via SendGuard. The guard pins value memory
    /// until the kernel completes the send.
    pub async fn set_with_guard<G: SendGuard>(
        &mut self,
        key: &[u8],
        guard: G,
    ) -> Result<(), Error> {
        if !self.is_instrumented() {
            let (_, value_len) = guard.as_ptr_len();
            self.encode_buf.clear();
            append_set_guard_prefix(&mut self.encode_buf, key, value_len as usize);
            let prefix: &[u8] = &self.encode_buf;
            self.conn.send_parts().build(move |b| {
                b.copy(prefix)
                    .guard(GuardBox::new(guard))
                    .copy(b"\r\n")
                    .submit()
            })?;
            let resp = self.read_value().await?;
            if let Value::Error(ref msg) = resp {
                return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
            }
            return match resp {
                Value::SimpleString(_) | Value::Null => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }
        let (_, value_len) = guard.as_ptr_len();
        self.encode_buf.clear();
        append_set_guard_prefix(&mut self.encode_buf, key, value_len as usize);
        let tx_bytes = (self.encode_buf.len() + value_len as usize + 2) as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let prefix: &[u8] = &self.encode_buf;
        self.conn.send_parts().build(move |b| {
            b.copy(prefix)
                .guard(GuardBox::new(guard))
                .copy(b"\r\n")
                .submit()
        })?;
        let resp = self.read_value().await?;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();
        let result = if let Value::Error(ref msg) = resp {
            Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()))
        } else {
            match resp {
                Value::SimpleString(_) | Value::Null => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            }
        };
        self.record(&CommandResult {
            command: CommandType::Set,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
            tx_bytes,
            rx_bytes,
        });
        result
    }

    /// SET with TTL (EX) and zero-copy value via SendGuard.
    pub async fn set_ex_with_guard<G: SendGuard>(
        &mut self,
        key: &[u8],
        guard: G,
        ttl_secs: u64,
    ) -> Result<(), Error> {
        if !self.is_instrumented() {
            let (_, value_len) = guard.as_ptr_len();
            self.encode_buf.clear();
            append_set_guard_prefix_ex(&mut self.encode_buf, key, value_len as usize);
            let split = self.encode_buf.len();
            append_set_guard_suffix_ex(&mut self.encode_buf, ttl_secs);
            let (prefix, suffix) = self.encode_buf.split_at(split);
            self.conn.send_parts().build(move |b| {
                b.copy(prefix)
                    .guard(GuardBox::new(guard))
                    .copy(suffix)
                    .submit()
            })?;
            let resp = self.read_value().await?;
            if let Value::Error(ref msg) = resp {
                return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
            }
            return match resp {
                Value::SimpleString(_) => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }
        let (_, value_len) = guard.as_ptr_len();
        self.encode_buf.clear();
        append_set_guard_prefix_ex(&mut self.encode_buf, key, value_len as usize);
        let split = self.encode_buf.len();
        append_set_guard_suffix_ex(&mut self.encode_buf, ttl_secs);
        let tx_bytes = (self.encode_buf.len() + value_len as usize) as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let (prefix, suffix) = self.encode_buf.split_at(split);
        self.conn.send_parts().build(move |b| {
            b.copy(prefix)
                .guard(GuardBox::new(guard))
                .copy(suffix)
                .submit()
        })?;
        let resp = self.read_value().await?;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();
        let result = if let Value::Error(ref msg) = resp {
            Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()))
        } else {
            match resp {
                Value::SimpleString(_) => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            }
        };
        self.record(&CommandResult {
            command: CommandType::Set,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
            tx_bytes,
            rx_bytes,
        });
        result
    }
}

// ── Streaming SET (send-side, single-connection Client only) ──────────────
//
// `set_stream` writes a large value from a caller-provided [`SegmentSource`]
// without gathering it into one contiguous buffer: the RESP command framing
// (which declares the value's bulk length) is sent, then value chunks are pulled
// from the source and streamed to the wire, then the trailing `\r\n`, then the
// `+OK` reply is read. Works on both backends (send works everywhere); v1 copies
// each chunk into the send pool (`send`) — zero-copy guarded streaming is a later
// optimization.

/// A source of exactly `len` value bytes for a streaming
/// [`set_stream`](Client::set_stream), yielded in chunks.
///
/// The client pulls chunks with [`next_chunk`](SegmentSource::next_chunk) until
/// it returns `Ok(None)` (exhausted), counting bytes as it goes. If the total
/// number of bytes yielded differs from the `len` passed to `set_stream`, the
/// send is a protocol desync and the connection is closed
/// ([`Error::LengthMismatch`]).
///
/// `next_chunk` is **synchronous** by design: it avoids the `async_fn_in_trait`
/// public-API lint and keeps v1 simple. A source backed by async I/O should
/// pre-buffer each chunk before yielding it. (An async pull is a documented
/// follow-up.)
pub trait SegmentSource {
    /// Yield the next chunk of value bytes, or `Ok(None)` once exhausted. An
    /// empty chunk is skipped (treated as "no bytes this call", not end).
    fn next_chunk(&mut self) -> Result<Option<Bytes>, Error>;
}

/// A [`SegmentSource`] that yields chunks from an in-memory iterator of
/// [`Bytes`]. Convenience for callers that already have their value in chunks
/// (or a single chunk); the streaming win is that ringline never gathers them
/// into one contiguous buffer.
impl<I: Iterator<Item = Bytes>> SegmentSource for I {
    fn next_chunk(&mut self) -> Result<Option<Bytes>, Error> {
        Ok(self.next())
    }
}

impl Client {
    /// Streaming SET (single-connection [`Client`] only).
    ///
    /// Sends the RESP `SET` command with the value bulk header declaring `len`
    /// (`*3\r\n$3\r\nSET\r\n$<klen>\r\n<key>\r\n$<len>\r\n`), then streams exactly
    /// `len` value bytes pulled from `src`, then the trailing `\r\n`, and reads
    /// the `+OK` reply. The value is never gathered into one contiguous buffer on
    /// the client side.
    ///
    /// # Length contract
    ///
    /// `len` is authoritative: it is written into the bulk-string header. The
    /// client counts the bytes pulled from `src` and returns
    /// [`Error::LengthMismatch`] (after closing the connection) if `src` yields
    /// fewer or more than `len` bytes — because a partial/oversized value frame
    /// is already on the wire and the connection is irrecoverably desynced (same
    /// discipline as the read-side poison rule).
    ///
    /// # Backends
    ///
    /// Works on both io_uring and mio. v1 copies each chunk into the send pool
    /// via [`ConnCtx::send`](ringline::ConnCtx::send) (awaited per chunk for
    /// backpressure). Zero-copy guarded streaming is a later optimization.
    pub async fn set_stream(
        &mut self,
        key: &[u8],
        len: usize,
        src: impl SegmentSource,
    ) -> Result<(), Error> {
        // Every failure between the first byte of the value frame reaching the
        // wire and a *complete* reply being read leaves a partial/desynced frame
        // the server is still parsing — a pooled connection reused after that
        // feeds the next caller's bytes into this frame's value. So poison (close)
        // the connection on any such error, matching the over/under-produce and
        // read-side poison discipline. A well-formed reply that merely *reports*
        // an error (a Redis error string, or an unexpected type) means the frame
        // was fully sent and the wire is synced — that path must NOT poison.
        match self.write_set_frame_and_read(key, len, src).await {
            Ok(Value::SimpleString(_)) | Ok(Value::Null) => Ok(()),
            Ok(Value::Error(msg)) => Err(Error::Redis(String::from_utf8_lossy(&msg).into_owned())),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => {
                self.conn.close();
                Err(e)
            }
        }
    }

    /// Write the streamed `SET` frame and read its reply. Every `?` here is a
    /// wire-desync condition ([`set_stream`](Self::set_stream) poisons on it);
    /// classifying the returned [`Value`] happens in the caller, after a complete
    /// reply has been read (so a server error reply does not poison).
    async fn write_set_frame_and_read(
        &mut self,
        key: &[u8],
        len: usize,
        mut src: impl SegmentSource,
    ) -> Result<Value, Error> {
        // Command framing with the value bulk header declaring `len`:
        // `*3\r\n$3\r\nSET\r\n$<klen>\r\n<key>\r\n$<len>\r\n`.
        self.encode_buf.clear();
        append_set_guard_prefix(&mut self.encode_buf, key, len);
        self.conn.send_nowait(&self.encode_buf)?;

        // Stream the value body, enforcing the length contract.
        let mut sent = 0usize;
        while let Some(chunk) = src.next_chunk()? {
            if chunk.is_empty() {
                continue;
            }
            sent += chunk.len();
            if sent > len {
                // Over-produce: the value frame is already too long → desync.
                return Err(Error::LengthMismatch);
            }
            // `send` copies into the pool synchronously and returns a future that
            // resolves when the bytes reach the socket — awaiting bounds in-flight
            // sends to one, so a large value can't exhaust the send pool.
            self.conn.send(&chunk)?.await?;
        }
        if sent != len {
            // Under-produce: header declared `len`, source gave fewer → desync.
            return Err(Error::LengthMismatch);
        }

        // Trailing `\r\n`, then the `+OK` reply.
        self.conn.send_nowait(b"\r\n")?;
        self.read_value().await
    }
}

// ── Streaming GET (segmented recv, single-connection Client only) ─────────
//
// `get_stream` returns a `ValueStream` instead of a materialized `Bytes`: the
// value body is delivered as segments over the runtime's segmented-recv API
// (`ConnCtx::recv_owned_segment`), so a consumer that discards or streams the
// value never forces the whole thing into one contiguous allocation. Only
// `collect()` materializes.
//
// io_uring only — segmented recv is backed by the provided-buffer ring, and the
// underlying `recv_owned_segment` / `end_segments` methods are `#[cfg(has_io_uring)]`.
// This crate's build.rs emits `has_io_uring` in lockstep with `ringline`.
//
// SCOPE (v1): redis `get_stream` on the single-connection `Client` (here) and on
// `Pool` (see `pool.rs`, which reuses this `ValueStream` machinery with
// poison-eviction). Deferred: `recv_streaming()` fire/recv integration, and
// `ShardedClient` streaming. `ClusterClient` streaming stays out of scope
// (MOVED/ASK re-read cannot be expressed by a length-bounded single-conn stream).

#[cfg(has_io_uring)]
impl Client {
    /// Streaming GET (single-connection [`Client`] only).
    ///
    /// Like [`get`](Self::get), but the value body is delivered as a
    /// [`ValueStream`] of segments rather than a single materialized [`Bytes`].
    /// A consumer that only needs to discard or checksum the value pays no
    /// gather copy; [`ValueStream::collect`] is the one materialization.
    ///
    /// Returns `Ok(None)` for a missing key (`$-1\r\n` nil reply).
    ///
    /// # Sequential use only
    ///
    /// The returned stream borrows `&mut self`, so a second concurrent stream (or
    /// any other client call) while it is alive is a compile error. `get_stream`
    /// must be called on an *idle* connection — not interleaved with pending
    /// `fire_*` operations or a half-read pipeline, whose responses would arrive
    /// ahead of the GET reply and desync the segmented read.
    ///
    /// # Dropping mid-stream poisons the connection
    ///
    /// If a [`ValueStream`] is dropped before its value (and the trailing
    /// delimiter) is fully consumed — via [`collect`](ValueStream::collect),
    /// [`discard`](ValueStream::discard), or reading
    /// [`next_segment`](ValueStream::next_segment) to the end — the undrained
    /// wire bytes cannot be drained synchronously in `Drop`, so the connection is
    /// **closed** (its slot generation bumped). The next operation on this client
    /// then fails, matching the "poison = close" recovery discipline.
    pub async fn get_stream(
        &mut self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<ValueStream<'_>>, Error> {
        let key = key.as_ref();
        // Fire the GET, then opt the connection into segmented delivery. The
        // reply body then arrives as held segments instead of being gathered
        // into the accumulator. `recv_owned_segment()` sets the domain
        // synchronously (before we await), so the reply can't be processed under
        // the default path first.
        self.encode_buf.clear();
        Self::encode_request_into(&Request::get(key), &mut self.encode_buf);
        self.conn.send_nowait(&self.encode_buf)?;

        // Read the tiny `$<len>\r\n` (or `$-1\r\n`) bulk-string header. It always
        // fits in the first received buffer; the rare split-across-buffers case is
        // handled by accumulating into `acc` and retrying.
        //
        // Demarcation is exact: `parse_get_header` measures only the header bytes
        // (`header_len`), never the value. Everything after `header_len` in the
        // buffer we already pulled is value-body bytes, handed to the stream as an
        // O(1) `Bytes::slice` — so no value byte is lost or double-read, and the
        // read cursor is a single monotonic position across header + body.
        let mut acc: Option<Vec<u8>> = None;
        loop {
            let seg = match self.conn.recv_owned_segment().await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    // Peer closed before any header arrived.
                    let _ = self.conn.end_segments();
                    return Err(Error::ConnectionClosed);
                }
                Err(e) => {
                    // Recv I/O error mid-header: the read is broken and the
                    // connection is still in the segmented domain. Poison it
                    // (close) so it is not reused stuck in that domain / desynced,
                    // rather than leaking the error while leaving the domain set.
                    self.conn.close();
                    return Err(e.into());
                }
            };
            let combined: Bytes = match acc.take() {
                None => seg,
                Some(mut a) => {
                    a.extend_from_slice(&seg);
                    Bytes::from(a)
                }
            };
            match parse_get_header(&combined) {
                Ok(Some(GetHeader::Nil)) => {
                    // Missing key. `$-1\r\n` carries no value/trailing; restore
                    // the default read path so the next command works.
                    self.conn.end_segments()?;
                    return Ok(None);
                }
                Ok(Some(GetHeader::Bulk { len, header_len })) => {
                    let leftover = combined.slice(header_len..);
                    return Ok(Some(ValueStream::new(self, len, leftover)));
                }
                Ok(None) => {
                    // Header not yet complete — stash and pull the next buffer.
                    acc = Some(combined.to_vec());
                }
                Err(e) => {
                    // Server error reply (e.g. `-WRONGTYPE`) or malformed header.
                    // In sequential use the whole reply line is in `combined`;
                    // restore the read path and surface the error.
                    let _ = self.conn.end_segments();
                    return Err(e);
                }
            }
        }
    }
}

/// Parsed shape of a GET reply header.
enum GetHeader {
    /// The key does not exist: RESP2 `$-1\r\n` or RESP3 `_\r\n`.
    Nil,
    /// `$<len>\r\n` — a bulk string of `len` value bytes follows (then a trailing
    /// CRLF). `header_len` is the byte length of the `$<len>\r\n` header itself.
    /// `header_len` is used only by the io_uring `get_stream` path; the mio GET
    /// drainer parses the header byte-at-a-time and ignores it.
    Bulk {
        len: usize,
        #[cfg_attr(not(has_io_uring), allow(dead_code))]
        header_len: usize,
    },
}

/// Position of the first `\r\n` in `buf` (the index of the `\r`), or `None`.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Parse a GET bulk-string reply header from the **front** of `buf`, measuring
/// only the header (`$<len>\r\n` / `$-1\r\n`) — the value body and trailing CRLF
/// are left for the caller to stream, so the header/value split loses no byte.
///
/// - `Ok(None)` — the header line is not yet fully buffered (need more bytes).
/// - `Ok(Some(..))` — a nil or bulk header.
/// - `Err(Error::Redis(_))` — a server error reply (`-...\r\n`).
/// - `Err(Error::UnexpectedResponse)` — a non-bulk, non-error reply, or a
///   malformed length.
fn parse_get_header(buf: &[u8]) -> Result<Option<GetHeader>, Error> {
    match buf.first() {
        None => Ok(None),
        Some(b'$') => {
            let Some(cr) = find_crlf(buf) else {
                return Ok(None);
            };
            let digits = &buf[1..cr];
            let header_len = cr + 2; // '$' .. through the "\r\n"
            if digits == b"-1" {
                return Ok(Some(GetHeader::Nil));
            }
            let s = std::str::from_utf8(digits).map_err(|_| Error::UnexpectedResponse)?;
            let len: usize = s.parse().map_err(|_| Error::UnexpectedResponse)?;
            Ok(Some(GetHeader::Bulk { len, header_len }))
        }
        Some(b'_') => {
            // RESP3 null (`_\r\n`) — a GET miss on a RESP3 (`HELLO 3`)
            // connection, where RESP2 would send `$-1\r\n`. Wait for the CRLF
            // so the drain consumes the full 3-byte frame, then report a miss.
            if find_crlf(buf).is_none() {
                return Ok(None);
            }
            Ok(Some(GetHeader::Nil))
        }
        Some(b'-') => {
            let Some(cr) = find_crlf(buf) else {
                return Ok(None);
            };
            Err(Error::Redis(
                String::from_utf8_lossy(&buf[1..cr]).into_owned(),
            ))
        }
        Some(_) => Err(Error::UnexpectedResponse),
    }
}

/// A streaming Redis GET value (see [`Client::get_stream`]).
///
/// Borrows the [`Client`] exclusively (`&mut`) and is bounded to the value length
/// parsed from the `$<len>\r\n` header, so it can neither over-read into a
/// following reply nor be used concurrently with another client operation.
///
/// The value body is delivered via the runtime's segmented-recv API. In v1 each
/// [`next_segment`](Self::next_segment) chunk (and the [`collect`](Self::collect)
/// gather) is an owned [`Bytes`] copied at delivery (Mode C). A zero-copy
/// [`discard`](Self::discard) over the borrowed `segments()` reader is a
/// documented follow-up; v1 `discard` still copies each chunk at delivery but
/// performs no *gather* copy.
#[cfg(has_io_uring)]
pub struct ValueStream<'a> {
    client: &'a mut Client,
    /// Full bulk-string length from the header.
    len: usize,
    /// Value bytes not yet handed to the caller.
    value_left: usize,
    /// Trailing CRLF bytes not yet consumed (starts at 2).
    trail_left: usize,
    /// Bytes pulled from the wire but not yet consumed (value + maybe trailing +,
    /// in non-sequential misuse, following-reply bytes which are discarded).
    buf: Bytes,
    /// Set once value + trailing CRLF are fully consumed and the recv domain has
    /// been restored. `false` at drop time ⇒ the stream was abandoned mid-value ⇒
    /// poison (close) the connection.
    finished: bool,
}

#[cfg(has_io_uring)]
impl<'a> ValueStream<'a> {
    fn new(client: &'a mut Client, len: usize, leftover: Bytes) -> Self {
        Self {
            client,
            len,
            value_left: len,
            trail_left: 2,
            buf: leftover,
            finished: false,
        }
    }

    /// The value length in bytes, from the `$<len>\r\n` header.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the value is zero-length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Pull the next non-empty received buffer into `self.buf`.
    ///
    /// A `None` from the runtime here means the peer closed (FIN) before the
    /// whole value + trailing CRLF arrived — a **short FIN**, surfaced as an
    /// error (never a truncated value), per the design's bounded-`len` contract.
    async fn refill(&mut self) -> Result<(), Error> {
        loop {
            match self.client.conn.recv_owned_segment().await {
                Ok(Some(b)) if !b.is_empty() => {
                    self.buf = b;
                    return Ok(());
                }
                Ok(Some(_)) => continue,
                Ok(None) => return Err(Error::ConnectionClosed),
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }

    /// The next chunk of the value body, or `Ok(None)` once the whole value has
    /// been delivered. Chunks are owned [`Bytes`] (Mode C copy-at-delivery); the
    /// caller may hold them freely.
    ///
    /// After the final chunk the trailing CRLF is consumed and the connection is
    /// restored for the next command, so a caller need not read past the last
    /// value byte — though calling again simply returns `Ok(None)`.
    pub async fn next_segment(&mut self) -> Result<Option<Bytes>, Error> {
        if self.value_left == 0 {
            self.finish().await?;
            return Ok(None);
        }
        if self.buf.is_empty() {
            self.refill().await?;
        }
        let take = self.value_left.min(self.buf.len());
        let chunk = self.buf.split_to(take);
        self.value_left -= take;
        if self.value_left == 0 {
            self.finish().await?;
        }
        Ok(Some(chunk))
    }

    /// Materialize the whole value into one contiguous [`Bytes`] (the copy).
    ///
    /// Single-buffer values return an O(1) `Bytes` slice with no extra gather;
    /// multi-buffer values are gathered into one allocation (still one logical
    /// copy of the value from the caller's perspective).
    pub async fn collect(mut self) -> Result<Bytes, Error> {
        // Fast path: the whole value is already contiguous in `buf`.
        if self.buf.len() >= self.value_left {
            let out = self.buf.split_to(self.value_left);
            self.value_left = 0;
            self.finish().await?;
            return Ok(out);
        }
        let mut out = bytes::BytesMut::with_capacity(self.len);
        while self.value_left > 0 {
            if self.buf.is_empty() {
                self.refill().await?;
            }
            let take = self.value_left.min(self.buf.len());
            out.extend_from_slice(&self.buf.split_to(take));
            self.value_left -= take;
        }
        self.finish().await?;
        Ok(out.freeze())
    }

    /// Consume and release the whole value without materializing it, leaving the
    /// connection usable for the next command. No gather copy.
    pub async fn discard(mut self) -> Result<(), Error> {
        while self.value_left > 0 {
            if self.buf.is_empty() {
                self.refill().await?;
            }
            let take = self.value_left.min(self.buf.len());
            let _ = self.buf.split_to(take);
            self.value_left -= take;
        }
        self.finish().await
    }

    /// Consume the trailing CRLF, restore the default `with_data`/`with_bytes`
    /// read path, and mark the stream finished so `Drop` does not poison the
    /// connection.
    async fn finish(&mut self) -> Result<(), Error> {
        if self.finished {
            return Ok(());
        }
        while self.trail_left > 0 {
            if self.buf.is_empty() {
                self.refill().await?;
            }
            let take = self.trail_left.min(self.buf.len());
            let _ = self.buf.split_to(take);
            self.trail_left -= take;
        }
        // Restore the default read path. Any bytes still in `self.buf` past the
        // trailing CRLF would belong to a *following* reply — none exist in the
        // documented sequential use; they are dropped rather than reinjected.
        self.client.conn.end_segments()?;
        self.finished = true;
        Ok(())
    }
}

#[cfg(has_io_uring)]
impl Drop for ValueStream<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Abandoned mid-value (or a short FIN left the stream broken):
            // undrained bytes remain inbound and the wire cannot be drained
            // synchronously here, so poison the connection. `close()` bumps the
            // slot generation, making the client's stored handle stale so the
            // next operation fails.
            self.client.conn.close();
        }
    }
}

// ── Timestamp helper ────────────────────────────────────────────────────

/// Get the current time as nanoseconds since epoch using CLOCK_REALTIME.
#[cfg(feature = "timestamps")]
fn now_realtime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

// ── Zero-copy SET encoding helpers ──────────────────────────────────────

/// Append a RESP bulk-string length header (`${n}\r\n`) to `buf`.
#[inline]
fn append_bulk_len(buf: &mut Vec<u8>, n: usize) {
    let mut itoa_buf = itoa::Buffer::new();
    buf.push(b'$');
    buf.extend_from_slice(itoa_buf.format(n).as_bytes());
    buf.extend_from_slice(b"\r\n");
}

/// Append the RESP SET prefix for guard-based sends to `buf`:
/// `*3\r\n$3\r\nSET\r\n${keylen}\r\n{key}\r\n${valuelen}\r\n`.
/// The caller must append value bytes (via guard) + `\r\n` suffix.
fn append_set_guard_prefix(buf: &mut Vec<u8>, key: &[u8], value_len: usize) {
    buf.extend_from_slice(b"*3\r\n$3\r\nSET\r\n");
    append_bulk_len(buf, key.len());
    buf.extend_from_slice(key);
    buf.extend_from_slice(b"\r\n");
    append_bulk_len(buf, value_len);
}

/// Append the RESP SET EX prefix for guard-based sends to `buf`:
/// `*5\r\n$3\r\nSET\r\n${keylen}\r\n{key}\r\n${valuelen}\r\n`.
/// The caller must append value bytes (via guard) followed by the
/// [`append_set_guard_suffix_ex`] suffix.
fn append_set_guard_prefix_ex(buf: &mut Vec<u8>, key: &[u8], value_len: usize) {
    buf.extend_from_slice(b"*5\r\n$3\r\nSET\r\n");
    append_bulk_len(buf, key.len());
    buf.extend_from_slice(key);
    buf.extend_from_slice(b"\r\n");
    append_bulk_len(buf, value_len);
}

/// Append the RESP SET EX suffix for guard-based sends to `buf`:
/// `\r\n$2\r\nEX\r\n${ttllen}\r\n{ttl}\r\n`.
fn append_set_guard_suffix_ex(buf: &mut Vec<u8>, ttl_secs: u64) {
    let mut itoa_buf = itoa::Buffer::new();
    let ttl_str = itoa_buf.format(ttl_secs);
    buf.extend_from_slice(b"\r\n$2\r\nEX\r\n");
    append_bulk_len(buf, ttl_str.len());
    buf.extend_from_slice(ttl_str.as_bytes());
    buf.extend_from_slice(b"\r\n");
}

// ── Pipeline ────────────────────────────────────────────────────────────

/// Accumulates commands into a single buffer and sends them as a batch.
///
/// All responses are read back in order after sending.
///
/// # Example
///
/// ```no_run
/// # use ringline::ConnCtx;
/// # use ringline_redis::Client;
/// # async fn example(conn: ConnCtx) -> Result<(), ringline_redis::Error> {
/// let mut client = Client::new(conn);
/// let results = client.pipeline()
///     .set(b"k1", b"v1")
///     .set(b"k2", b"v2")
///     .get(b"k1")
///     .execute().await?;
/// assert_eq!(results.len(), 3);
/// # Ok(())
/// # }
/// ```
pub struct Pipeline {
    conn: ConnCtx,
    buf: Vec<u8>,
    count: usize,
}

impl Pipeline {
    fn new(conn: ConnCtx) -> Self {
        Self {
            conn,
            buf: Vec::new(),
            count: 0,
        }
    }

    /// Add a custom command to the pipeline.
    pub fn cmd(mut self, request: &Request<'_>) -> Self {
        Client::encode_request_into(request, &mut self.buf);
        self.count += 1;
        self
    }

    /// Add a SET command to the pipeline.
    pub fn set(mut self, key: &[u8], value: &[u8]) -> Self {
        Client::encode_set_request_into(&Request::set(key, value), &mut self.buf);
        self.count += 1;
        self
    }

    /// Add a GET command to the pipeline.
    pub fn get(mut self, key: &[u8]) -> Self {
        Client::encode_request_into(&Request::get(key), &mut self.buf);
        self.count += 1;
        self
    }

    /// Add a DEL command to the pipeline.
    pub fn del(mut self, key: &[u8]) -> Self {
        Client::encode_request_into(&Request::del(key), &mut self.buf);
        self.count += 1;
        self
    }

    /// Add an INCR command to the pipeline.
    pub fn incr(mut self, key: &[u8]) -> Self {
        Client::encode_request_into(&Request::cmd(b"INCR").arg(key), &mut self.buf);
        self.count += 1;
        self
    }

    /// Execute all commands in the pipeline and return their results in order.
    ///
    /// On error mid-batch, the underlying connection is closed: pipeline
    /// responses are positional, and there's no safe way to skip
    /// remaining responses without parsing the full RESP value (which
    /// might itself fail). Closing the conn surfaces the desync as a
    /// `ConnectionClosed` to the next user instead of letting them read
    /// the tail of this pipeline's responses.
    pub async fn execute(self) -> Result<Vec<Value>, Error> {
        if self.count == 0 {
            return Ok(Vec::new());
        }
        self.conn.send(&self.buf)?;

        // Use a temporary Client to read values.
        let client = Client::new(self.conn);
        let mut results = Vec::with_capacity(self.count);
        for _ in 0..self.count {
            let value = match client.read_value().await {
                Ok(v) => v,
                Err(e) => {
                    self.conn.close();
                    return Err(e);
                }
            };
            if let Value::Error(ref msg) = value {
                // Drain any remaining responses we haven't read yet —
                // we can't return early here because Redis already sent
                // responses for every command we sent. A Value::Error
                // for one command doesn't desync the stream; we
                // continue reading the rest. (This matches the prior
                // behaviour and is correct for pipelined Redis.)
                let err = Error::Redis(String::from_utf8_lossy(msg).into_owned());
                for _ in (results.len() + 1)..self.count {
                    if client.read_value().await.is_err() {
                        // *Now* the stream is broken — close.
                        self.conn.close();
                        return Err(err);
                    }
                }
                return Err(err);
            }
            results.push(value);
        }
        Ok(results)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

pub(crate) fn parse_bytes_array(value: Value) -> Result<Vec<Bytes>, Error> {
    match value {
        Value::Array(arr) => {
            let mut result = Vec::with_capacity(arr.len());
            for v in arr {
                match v {
                    Value::BulkString(data) => result.push(data),
                    _ => return Err(Error::UnexpectedResponse),
                }
            }
            Ok(result)
        }
        _ => Err(Error::UnexpectedResponse),
    }
}

/// For an incomplete reply that starts with a bulk string (`$<len>\r\n…`),
/// compute how many more bytes complete the frame. Returns `None` when the
/// head isn't a bulk string, the length header is itself incomplete, the
/// length is negative (`$-1` null reply), or the frame is already fully
/// buffered (the parse was incomplete for some other reason).
///
/// The hint drives [`ParseResult::NeedAtLeast`]: the runtime reserves the
/// recv accumulator once at full size instead of doubling through a
/// multi-MB value arriving in chunks (~2× the payload in avoided memcpy).
fn bulk_remainder_hint(bytes: &[u8]) -> Option<usize> {
    let rest = bytes.strip_prefix(b"$")?;
    // Redis 7's proto-max-bulk-len ceiling is 512MB — 10 digits covers it;
    // scan a few extra so a corrupt header falls through to the parser's
    // own error handling rather than being mis-hinted.
    let digits_end = rest
        .iter()
        .take(16)
        .position(|&b| !b.is_ascii_digit())
        .unwrap_or(rest.len().min(16));
    if digits_end == 0 {
        return None; // "$-1" null reply or malformed — no hint
    }
    // Header must be complete: digits followed by CRLF.
    if rest.len() < digits_end + 2 || &rest[digits_end..digits_end + 2] != b"\r\n" {
        return None;
    }
    let len: usize = std::str::from_utf8(&rest[..digits_end])
        .ok()?
        .parse()
        .ok()?;
    // '$' + digits + CRLF + payload + trailing CRLF
    let total = 1 + digits_end + 2 + len.checked_add(2)?;
    total.checked_sub(bytes.len()).filter(|&a| a > 0)
}

#[cfg(test)]
mod bulk_hint_tests {
    use super::bulk_remainder_hint;

    #[test]
    fn partial_bulk_reports_remainder() {
        // $16\r\n + 4 of 16 payload bytes; missing 12 payload + CRLF = 14.
        let buf = b"$16\r\nabcd";
        assert_eq!(bulk_remainder_hint(buf), Some(14));
    }

    #[test]
    fn header_only_reports_full_payload() {
        assert_eq!(bulk_remainder_hint(b"$16777216\r\n"), Some(16_777_216 + 2));
    }

    #[test]
    fn incomplete_header_no_hint() {
        assert_eq!(bulk_remainder_hint(b"$167"), None);
        assert_eq!(bulk_remainder_hint(b"$16777216\r"), None);
        assert_eq!(bulk_remainder_hint(b"$"), None);
    }

    #[test]
    fn null_reply_no_hint() {
        assert_eq!(bulk_remainder_hint(b"$-1\r"), None);
    }

    #[test]
    fn non_bulk_no_hint() {
        assert_eq!(bulk_remainder_hint(b"+OK\r"), None);
        assert_eq!(bulk_remainder_hint(b"*2\r\n$3\r\nfo"), None);
        assert_eq!(bulk_remainder_hint(b""), None);
    }

    #[test]
    fn complete_frame_no_hint() {
        assert_eq!(bulk_remainder_hint(b"$4\r\nabcd\r\n"), None);
    }

    #[test]
    fn malformed_header_no_hint() {
        assert_eq!(bulk_remainder_hint(b"$12x4\r\nzz"), None);
        assert_eq!(bulk_remainder_hint(b"$99999999999999999999\r\nzz"), None);
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;

    // 14-byte key with digits — exercises two-digit bulk-string length
    // headers and digit/key-byte adjacency (itoa boundary cases).
    const KEY: &[u8] = b"user:123456789";

    #[test]
    fn golden_encode_request_get() {
        let encoded = Client::encode_request(&Request::get(KEY));
        assert_eq!(encoded, b"*2\r\n$3\r\nGET\r\n$14\r\nuser:123456789\r\n");
    }

    #[test]
    fn golden_encode_request_del() {
        let encoded = Client::encode_request(&Request::del(KEY));
        assert_eq!(encoded, b"*2\r\n$3\r\nDEL\r\n$14\r\nuser:123456789\r\n");
    }

    #[test]
    fn golden_encode_set_request() {
        let encoded = Client::encode_set_request(&Request::set(KEY, b"hello world value"));
        assert_eq!(
            encoded,
            &b"*3\r\n$3\r\nSET\r\n$14\r\nuser:123456789\r\n$17\r\nhello world value\r\n"[..]
        );
    }

    #[test]
    fn golden_encode_set_request_ex() {
        let encoded = Client::encode_set_request(&Request::set(KEY, b"v").ex(7200));
        assert_eq!(
            encoded,
            &b"*5\r\n$3\r\nSET\r\n$14\r\nuser:123456789\r\n$1\r\nv\r\n$2\r\nEX\r\n$4\r\n7200\r\n"[..]
        );
    }

    #[test]
    fn golden_set_guard_prefix() {
        let mut prefix = Vec::new();
        append_set_guard_prefix(&mut prefix, KEY, 1024);
        assert_eq!(
            prefix,
            &b"*3\r\n$3\r\nSET\r\n$14\r\nuser:123456789\r\n$1024\r\n"[..]
        );
    }

    #[test]
    fn golden_set_guard_prefix_ex() {
        let mut prefix = Vec::new();
        append_set_guard_prefix_ex(&mut prefix, KEY, 1024);
        let mut suffix = Vec::new();
        append_set_guard_suffix_ex(&mut suffix, 7200);
        assert_eq!(
            prefix,
            &b"*5\r\n$3\r\nSET\r\n$14\r\nuser:123456789\r\n$1024\r\n"[..]
        );
        assert_eq!(suffix, &b"\r\n$2\r\nEX\r\n$4\r\n7200\r\n"[..]);
    }

    #[test]
    fn encode_into_appends_without_clobbering() {
        // The `_into` helpers must append (coalescing path writes multiple
        // commands into one write_buf), never clear.
        let mut buf = b"EXISTING".to_vec();
        Client::encode_request_into(&Request::get(KEY), &mut buf);
        Client::encode_set_request_into(&Request::set(KEY, b"v"), &mut buf);
        assert_eq!(
            buf,
            &b"EXISTING*2\r\n$3\r\nGET\r\n$14\r\nuser:123456789\r\n\
               *3\r\n$3\r\nSET\r\n$14\r\nuser:123456789\r\n$1\r\nv\r\n"[..]
        );
    }

    // Key constants shared by the tx_bytes tests below.
    const VALUE: &[u8] = b"hello";
    const VALUE_LEN: usize = VALUE.len(); // 5
    const TTL: u64 = 7200;

    /// Pin the tx_bytes arithmetic for the non-EX guard SET path.
    ///
    /// The guard split is: `prefix || [value bytes supplied by caller] || "\r\n"`.
    /// So the full on-wire byte count is `prefix.len() + value_len + 2`.
    #[test]
    fn tx_bytes_guard_set_no_ex() {
        // Full wire bytes for SET key value (no EX), constructed explicitly.
        let full_wire: &[u8] = b"*3\r\n$3\r\nSET\r\n$14\r\nuser:123456789\r\n$5\r\nhello\r\n";

        let mut prefix = Vec::new();
        append_set_guard_prefix(&mut prefix, KEY, VALUE_LEN);

        // The caller sends: prefix || value_bytes || "\r\n".
        // So full wire length == prefix.len() + value_len + 2.
        assert_eq!(
            prefix.len() + VALUE_LEN + 2,
            full_wire.len(),
            "prefix.len()={} + value_len={} + 2 should equal full wire len={}",
            prefix.len(),
            VALUE_LEN,
            full_wire.len(),
        );
    }

    /// Pin the tx_bytes arithmetic for the EX guard SET path.
    ///
    /// The guard split is: `prefix || [value bytes supplied by caller] || suffix`.
    /// The suffix *starts* with "\r\n" (terminating the value bulk string),
    /// so the full on-wire byte count is `prefix.len() + value_len + suffix.len()`.
    #[test]
    fn tx_bytes_guard_set_ex() {
        // Full wire bytes for SET key value EX ttl, constructed explicitly.
        let full_wire: &[u8] =
            b"*5\r\n$3\r\nSET\r\n$14\r\nuser:123456789\r\n$5\r\nhello\r\n$2\r\nEX\r\n$4\r\n7200\r\n";

        let mut prefix = Vec::new();
        append_set_guard_prefix_ex(&mut prefix, KEY, VALUE_LEN);
        let mut suffix = Vec::new();
        append_set_guard_suffix_ex(&mut suffix, TTL);

        // The suffix starts with "\r\n" which closes the value bulk string —
        // no separate "\r\n" is needed between value and suffix.
        // So full wire length == prefix.len() + value_len + suffix.len().
        assert_eq!(
            prefix.len() + VALUE_LEN + suffix.len(),
            full_wire.len(),
            "prefix.len()={} + value_len={} + suffix.len()={} should equal full wire len={}",
            prefix.len(),
            VALUE_LEN,
            suffix.len(),
            full_wire.len(),
        );
    }
}

#[cfg(test)]
mod zc_threshold_tests {
    use super::*;
    use ringline::{ConnCtx, RegionId, SendGuard};

    const KEY: &[u8] = b"user:123456789";

    /// Heap-backed guard for tests. The `Vec` keeps bytes alive for the
    /// guard's lifetime.
    struct VecGuard(Vec<u8>);

    impl SendGuard for VecGuard {
        fn as_ptr_len(&self) -> (*const u8, u32) {
            (self.0.as_ptr(), self.0.len() as u32)
        }
        fn region(&self) -> RegionId {
            RegionId::UNREGISTERED
        }
    }

    /// A `Client` backed by a dangling `ConnCtx`. Only safe for tests that
    /// stay in the buffered path (no flush, no direct send, no recv).
    fn test_client(max_batch_size: usize, zc_threshold: u32) -> Client {
        let conn = ConnCtx::for_test(0, 0);
        let mut client = Client::builder(conn).max_batch_size(max_batch_size);
        client = client.zc_threshold(zc_threshold);
        client.build()
    }

    #[test]
    fn small_guard_set_is_byte_identical_to_plain_set() {
        // Small guarded SET must produce byte-identical write_buf to a plain
        // copy SET of the same key/value, because it routes through fire_set.
        let value = vec![0xABu8; 64];

        let mut guarded = test_client(4, 4096);
        guarded
            .fire_set_with_guard(KEY, VecGuard(value.clone()), 1)
            .unwrap();

        let mut plain = test_client(4, 4096);
        plain.fire_set(KEY, &value, 1).unwrap();

        assert_eq!(guarded.write_buf, plain.write_buf);
        assert!(guarded.write_guards.is_empty());
    }

    #[test]
    fn small_guard_set_ex_is_byte_identical_to_plain_set_ex() {
        let value = vec![0xCDu8; 64];

        let mut guarded = test_client(4, 4096);
        guarded
            .fire_set_ex_with_guard(KEY, VecGuard(value.clone()), 7200, 1)
            .unwrap();

        let mut plain = test_client(4, 4096);
        plain.fire_set_ex(KEY, &value, 7200, 1).unwrap();

        assert_eq!(guarded.write_buf, plain.write_buf);
        assert!(guarded.write_guards.is_empty());
    }

    #[test]
    fn small_value_takes_copy_path() {
        // 64B < 4096 → folds into copy path: write_guards empty, one buffered op.
        let mut client = test_client(4, 4096);
        client
            .fire_set_with_guard(KEY, VecGuard(vec![0u8; 64]), 1)
            .unwrap();
        assert!(client.write_guards.is_empty());
        assert_eq!(client.buffered_ops, 1);
        assert!(!client.write_buf.is_empty());
    }

    #[test]
    fn large_value_takes_guard_path() {
        // 8KB >= 4096 → guard path: write_guards non-empty.
        let mut client = test_client(4, 4096);
        client
            .fire_set_with_guard(KEY, VecGuard(vec![0u8; 8192]), 1)
            .unwrap();
        assert_eq!(client.write_guards.len(), 1);
    }

    #[test]
    fn large_value_set_ex_takes_guard_path() {
        let mut client = test_client(4, 4096);
        client
            .fire_set_ex_with_guard(KEY, VecGuard(vec![0u8; 8192]), 7200, 1)
            .unwrap();
        assert_eq!(client.write_guards.len(), 1);
    }

    #[test]
    fn threshold_zero_disables_fold() {
        // zc_threshold = 0 → always guard path, even for tiny values.
        let mut client = test_client(4, 0);
        client
            .fire_set_with_guard(KEY, VecGuard(vec![0u8; 64]), 1)
            .unwrap();
        assert_eq!(client.write_guards.len(), 1);

        let mut client_ex = test_client(4, 0);
        client_ex
            .fire_set_ex_with_guard(KEY, VecGuard(vec![0u8; 64]), 7200, 1)
            .unwrap();
        assert_eq!(client_ex.write_guards.len(), 1);
    }

    #[test]
    fn guard_batch_accumulates_max_flush_guards_before_flush() {
        // zc_threshold = 0 forces the guard path. MAX_FLUSH_GUARDS guards
        // must accumulate without triggering a pre-flush: g guards need
        // 2g+1 iovecs, within MAX_FLUSH_IOVECS. A stale iovec cap of 8
        // used to force a flush at the 4th guard (batching only 3).
        let mut client = test_client(16, 0);
        for i in 0..MAX_FLUSH_GUARDS {
            client
                .fire_set_with_guard(KEY, VecGuard(vec![0u8; 64]), i as u64)
                .unwrap();
        }
        assert_eq!(
            client.write_guards.len(),
            MAX_FLUSH_GUARDS,
            "a full guard batch must accumulate without a premature flush"
        );
    }

    #[test]
    fn batch_of_small_guard_sets_coalesces_to_one_flush() {
        // N small guarded SETs at max_batch_size = N: all fold into the copy
        // path (write_guards stays empty), so they batch into a single buffer
        // and exactly one flush is triggered by the Nth op (buffered_ops
        // resets to 0, write_buf cleared). With a guard path they'd flush
        // every MAX_FLUSH_GUARDS ops instead.
        const N: usize = 8;
        let mut client = test_client(N, 4096);
        // Pre-fill write_buf so we can detect the flush clearing it; but the
        // flush itself would hit the (dangling) conn, so instead assert the
        // pre-flush invariant: the first N-1 ops accumulate with no guards.
        for i in 0..N - 1 {
            client
                .fire_set_with_guard(KEY, VecGuard(vec![0u8; 64]), i as u64)
                .unwrap();
            assert!(
                client.write_guards.is_empty(),
                "op {i} must use the copy path, not the guard path"
            );
            assert_eq!(client.buffered_ops, i + 1);
        }
        // After N-1 small guarded SETs we have N-1 buffered copy ops and zero
        // guards — proving the whole batch coalesces (a guard path would have
        // flushed at op index 4 when next_guards exceeded MAX_FLUSH_GUARDS).
        assert_eq!(client.buffered_ops, N - 1);
        assert!(client.write_guards.is_empty());
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    #[test]
    fn is_transient_recognises_loading() {
        let e = Error::Redis("LOADING Redis is loading the dataset in memory".into());
        assert!(e.is_transient());
    }

    #[test]
    fn is_transient_recognises_busy() {
        let e = Error::Redis("BUSY Redis is busy running a script".into());
        assert!(e.is_transient());
    }

    #[test]
    fn is_transient_recognises_tryagain() {
        let e = Error::Redis("TRYAGAIN slot migration in progress".into());
        assert!(e.is_transient());
    }

    #[test]
    fn is_transient_does_not_match_loadinga() {
        // The whole-word check stops `LOADINGSOMETHING` from being treated
        // as `LOADING` followed by junk.
        let e = Error::Redis("LOADINGSOMETHING fake error".into());
        assert!(!e.is_transient());
    }

    #[test]
    fn is_transient_false_for_non_redis_errors() {
        assert!(!Error::ConnectionClosed.is_transient());
        assert!(!Error::UnexpectedResponse.is_transient());
        assert!(!Error::TooManyRedirects.is_transient());
    }

    #[test]
    fn is_transient_false_for_other_redis_errors() {
        assert!(!Error::Redis("ERR wrong number of arguments".into()).is_transient());
        assert!(!Error::Redis("MOVED 1234 127.0.0.1:7000".into()).is_transient());
        assert!(!Error::Redis("WRONGTYPE Operation against a key".into()).is_transient());
    }
}

/// Locks the `parse_get_header` contract that `recv_get_segments`'s poison
/// decision depends on. The Mode-B state machine feeds the header **one byte at
/// a time** and stops the instant `parse_get_header` returns non-`Ok(None)`, so:
///
/// - An unexpected reply type (`:`/`+`/`*`, …) errors on the **first byte** with
///   `UnexpectedResponse` — only 1 byte is consumed, the rest of the reply is
///   left on the wire, and we cannot know how many bytes to skip. The connection
///   is desynced, so `recv_get_segments` **must poison** it.
/// - A genuine server error (`-...\r\n`) errors only once the whole `\r\n`-
///   terminated line is buffered (`Error::Redis`), so the wire stays aligned and
///   the connection is **reusable** — it must NOT be poisoned.
///
/// If this contract ever flips, the poison logic silently evicts healthy
/// connections (a `-ERR` reported as `UnexpectedResponse`) or, far worse, returns
/// a desynced connection to the pool (a `:`/`+`/`*` reply reported as `Redis`).
#[cfg(test)]
mod get_header_resp3_tests {
    use super::*;

    #[test]
    fn resp3_null_header_is_a_miss() {
        // RESP3 GET miss is `_\r\n` (vs RESP2 `$-1\r\n`). It must classify as a
        // miss, not an `UnexpectedResponse`. `parse_get_header` feeds both the
        // io_uring and mio GET drains, so this is not io_uring-gated.
        assert!(matches!(
            parse_get_header(b"_\r\n"),
            Ok(Some(GetHeader::Nil))
        ));
        // The bare `_` (no CRLF yet) must report "need more bytes" so the drain
        // loops consume exactly the 3-byte frame — never over-reading into the
        // next pipelined reply.
        assert!(matches!(parse_get_header(b"_"), Ok(None)));
    }
}

#[cfg(all(test, has_io_uring))]
mod get_header_poison_contract_tests {
    use super::*;

    #[test]
    fn unexpected_reply_types_error_on_first_byte() {
        // Desync trigger: the catch-all fires before any CRLF, so only the
        // leading byte would be consumed. Both the 1-byte prefix and the full
        // reply must classify as `UnexpectedResponse` → poison.
        for reply in [
            &b":"[..],
            &b":5\r\n"[..],
            &b"+"[..],
            &b"+OK\r\n"[..],
            &b"*"[..],
            &b"*1\r\n"[..],
        ] {
            assert!(
                matches!(parse_get_header(reply), Err(Error::UnexpectedResponse)),
                "reply {reply:?} must be UnexpectedResponse (desync → poison)"
            );
        }
    }

    #[test]
    fn server_error_reply_is_redis_and_waits_for_full_line() {
        // The `-` arm returns `Ok(None)` until the whole line is buffered, so
        // the full error line is consumed (wire aligned) before it errors.
        assert!(matches!(parse_get_header(b"-WRONGTYPE"), Ok(None)));
        assert!(matches!(
            parse_get_header(b"-WRONGTYPE Operation\r\n"),
            Err(Error::Redis(_))
        ));
    }

    #[test]
    fn bulk_and_nil_headers_still_parse() {
        assert!(matches!(
            parse_get_header(b"$-1\r\n"),
            Ok(Some(GetHeader::Nil))
        ));
        assert!(matches!(
            parse_get_header(b"$3\r\n"),
            Ok(Some(GetHeader::Bulk { len: 3, .. }))
        ));
        // Header not yet complete → need more bytes (not an error).
        assert!(matches!(parse_get_header(b"$3"), Ok(None)));
    }

    #[test]
    fn malformed_bulk_length_is_unexpected_not_redis() {
        // A malformed `$` length is wire-aligned (full `$..\r\n` consumed) but
        // still classifies as `UnexpectedResponse`; poisoning it is acceptable
        // (a malformed server reply is exceptional), and it must never be a
        // reusable `Redis` error.
        assert!(matches!(
            parse_get_header(b"$abc\r\n"),
            Err(Error::UnexpectedResponse)
        ));
    }
}
