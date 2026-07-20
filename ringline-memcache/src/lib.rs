//! ringline-native Memcache client for use inside the ringline async runtime.
//!
//! This client wraps a [`ringline::ConnCtx`] and provides typed Memcache command
//! methods that use `with_bytes()` + `ResponseBytes::parse()` for zero-copy
//! incremental parsing. It is designed for single-threaded, single-connection
//! use within ringline's `AsyncEventHandler::on_start()` or connection tasks.
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
//! use ringline_memcache::Client;
//!
//! async fn example(conn: ConnCtx) -> Result<(), ringline_memcache::Error> {
//!     let mut client = Client::new(conn);
//!     client.set("hello", "world").await?;
//!     let val = client.get("hello").await?;
//!     assert_eq!(val.unwrap().data.as_ref(), b"world");
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
//! │                    [Memcache processes]                       │
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
//! use ringline_memcache::{Client, CompletedOp};
//!
//! async fn pipelined_example(conn: ConnCtx) -> Result<(), ringline_memcache::Error> {
//!     let mut client = Client::new(conn);
//!
//!     // Fire multiple requests (synchronous, non-blocking)
//!     client.fire_get(b"session:abc", 1)?;
//!     client.fire_get(b"session:def", 2)?;
//!     client.fire_get(b"session:ghi", 3)?;
//!
//!     // Recv responses in order (async, blocks until each arrives)
//!     match client.recv().await? {
//!         CompletedOp::Get { result, user_data, .. } => {
//!             assert_eq!(user_data, 1);
//!             let value = result?; // Option<Value>
//!             println!("session:abc = {:?}", value);
//!         }
//!         _ => unreachable!(),
//!     }
//!
//!     // Continue with remaining responses...
//!     match client.recv().await? {
//!         CompletedOp::Get { result: _, user_data, .. } => {
//!             assert_eq!(user_data, 2);
//!         }
//!         _ => unreachable!(),
//!     }
//!
//!     match client.recv().await? {
//!         CompletedOp::Get { result: _, user_data, .. } => {
//!             assert_eq!(user_data, 3);
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
//! - [`Client::fire_delete()`] — DELETE command
//!
//! ## Important Notes
//!
//! - Responses must be consumed in FIFO order (protocol guarantee)
//! - `recv()` returns [`Error::NoPending`] if called with no in-flight requests
//! - Timing is zero-overhead when no callbacks/metrics are configured
//!
//! # Copy Semantics
//!
//! | Path | Copies | Mechanism |
//! |------|--------|-----------|
//! | **Recv (values)** | **0** | `with_bytes()` + `ResponseBytes::parse()`. Keys and values are `Bytes::slice()` references into the accumulator — zero allocation, O(1) refcount. |
//! | **Send (commands)** | 1 | Requests are encoded into a reusable per-client buffer (no per-request allocation), then `conn.send()` copies into the send pool. |
//! | **Send (SET value, guard)** | 0 (value) | [`Client::set_with_guard`]: prefix+suffix copied to pool, value stays in-place via `SendGuard`. |
//!
//! TLS connections add encryption copies on the send path regardless of
//! `SendGuard` usage.

pub mod pool;
pub mod sharded;
pub use pool::{Pool, PoolConfig};
pub use sharded::{ShardedClient, ShardedConfig};

use std::cell::Cell;
use std::collections::VecDeque;
use std::io;
use std::time::Instant;

use bytes::Bytes;
use memcache_proto::{Request as McRequest, ResponseBytes as McResponseBytes};
use ringline::{ConnCtx, GuardBox, ParseResult, SendGuard};

/// Callback type invoked after each command completes.
type ResultCallback = Box<dyn Fn(&CommandResult)>;

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

// -- Error -------------------------------------------------------------------

/// Errors returned by the ringline Memcache client.
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

    /// The server returned an error response (ERROR, CLIENT_ERROR, SERVER_ERROR).
    #[error("memcache error: {0}")]
    Memcache(String),

    /// The response type did not match the expected type for the command.
    #[error("unexpected response")]
    UnexpectedResponse,

    /// Memcache protocol parse error.
    #[error("protocol error: {0}")]
    Protocol(#[from] memcache_proto::ParseError),

    /// I/O error during send.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// All connections in the pool are down and reconnection failed.
    #[error("all connections failed")]
    AllConnectionsFailed,

    /// `recv()` called with no pending fire operations.
    #[error("no pending operations")]
    NoPending,

    /// The in-flight pending-op queue reached `max_in_flight`. Drain via
    /// `recv()` before issuing more `fire_*` calls. Configurable via
    /// [`ClientBuilder::max_in_flight`].
    #[error("too many in-flight operations")]
    TooManyInFlight,

    /// Key exceeds memcache's 250-byte cap ([`MAX_KEY_LEN`]). The request
    /// is rejected client-side instead of being transmitted; otherwise the
    /// server would reply with `CLIENT_ERROR` after consuming pool /
    /// pending-queue capacity for a doomed command.
    #[error("key too long (max 250 bytes)")]
    KeyTooLong,

    /// A streaming [`set_stream`](Client::set_stream) value source produced a
    /// different number of bytes than the declared length. Because the command
    /// header (which declares the length) is already on the wire, the framing is
    /// now irrecoverably desynced, so the connection is closed — matching the
    /// read-side poison rule.
    #[error("streaming value length mismatch")]
    LengthMismatch,
}

/// Maximum key length per memcache text-protocol spec.
pub const MAX_KEY_LEN: usize = 250;

#[inline]
fn validate_key(key: &[u8]) -> Result<(), Error> {
    if key.len() > MAX_KEY_LEN {
        Err(Error::KeyTooLong)
    } else {
        Ok(())
    }
}

// -- Value types -------------------------------------------------------------

/// A value returned from a single-key GET command.
#[derive(Debug, Clone)]
pub struct Value {
    /// The cached data.
    pub data: Bytes,
    /// Flags stored with the item.
    pub flags: u32,
}

/// A value returned from a multi-key GET command, including the key.
#[derive(Debug, Clone)]
pub struct GetValue {
    /// The key for this value.
    pub key: Bytes,
    /// The cached data.
    pub data: Bytes,
    /// Flags stored with the item.
    pub flags: u32,
    /// CAS unique token (present when the server returns it via `gets`).
    pub cas: Option<u64>,
}

// ── Command types ───────────────────────────────────────────────────────

/// The type of Memcache command that completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandType {
    Get,
    Set,
    Delete,
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
    /// Whether the command succeeded (no error response).
    pub success: bool,
    /// Time-to-first-byte in nanoseconds (not available in sequential mode).
    pub ttfb_ns: Option<u64>,
    /// Bytes transmitted for this command (protocol-encoded request size).
    pub tx_bytes: u32,
    /// Bytes received for this command (protocol-encoded response size).
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
            CommandType::Delete => {
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
    Delete,
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
        result: Result<Option<Value>, Error>,
        user_data: u64,
        latency_ns: u64,
    },
    /// SET completed.
    Set {
        result: Result<(), Error>,
        user_data: u64,
        latency_ns: u64,
    },
    /// DELETE completed.
    Delete {
        result: Result<bool, Error>,
        user_data: u64,
        latency_ns: u64,
    },
}

// ── ClientBuilder ───────────────────────────────────────────────────────

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
    /// [`fire_set_with_guard`](Client::fire_set_with_guard) *smaller* than
    /// this are copied into the coalescing send buffer so they batch like
    /// plain SETs instead of taking the scatter-gather guard path (which
    /// flushes every few ops). `0` = always use the guard path.
    ///
    /// Defaults to 4096. Should generally match the runtime
    /// `Config::send_zc_threshold`.
    pub fn zc_threshold(mut self, bytes: u32) -> Self {
        self.zc_threshold = bytes;
        self
    }

    /// Configure the maximum number of in-flight `fire_*` operations.
    /// `fire_*` returns [`Error::TooManyInFlight`] past it. Defaults to
    /// `usize::MAX` (unbounded). Set a bounded value on any server that
    /// issues `fire_*` faster than `recv()` consumes.
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

// -- Client ------------------------------------------------------------------

/// A ringline-native Memcache client wrapping a single connection.
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
    /// copy path by `fire_set_with_guard` instead of taking the
    /// scatter-gather guard path. `0` disables the fold.
    zc_threshold: u32,
    /// Number of ops buffered in `write_buf` that have not yet been flushed.
    buffered_ops: usize,
    /// Reusable scratch buffer for encoding requests. Cleared before each
    /// use; keeps its capacity across requests so steady-state encoding is
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
        // ops we'd push_back'd for them. Otherwise the next `flush()` would
        // re-send the same buffer, and `recv()` would pop a `PendingOp` for
        // a request that was never on the wire and then hang forever
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
        let tx_bytes;
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            // Direct send — skip write_buf round-trip.
            self.encode_buf.clear();
            encode_request_into(&McRequest::get(key), &mut self.encode_buf)?;
            tx_bytes = self.encode_buf.len() as u32;
            self.conn.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            encode_request_into(&McRequest::get(key), &mut self.write_buf)?;
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
    pub fn fire_set(
        &mut self,
        key: &[u8],
        value: &[u8],
        flags: u32,
        exptime: u32,
        user_data: u64,
    ) -> Result<(), Error> {
        self.pre_flush_if_needed(false)?;
        let req = McRequest::Set {
            key,
            value,
            flags,
            exptime,
        };
        let tx_bytes;
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            // Direct send — skip write_buf round-trip.
            self.encode_buf.clear();
            encode_request_into(&req, &mut self.encode_buf)?;
            tx_bytes = self.encode_buf.len() as u32;
            self.conn.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            encode_request_into(&req, &mut self.write_buf)?;
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
        flags: u32,
        exptime: u32,
        user_data: u64,
    ) -> Result<(), Error> {
        let (ptr, value_len) = guard.as_ptr_len();
        // Small guard values: fold into the coalescing copy path (`fire_set`)
        // so they batch like plain SETs instead of taking the scatter-gather
        // guard path, which flushes every few ops.
        if self.zc_threshold != 0 && value_len < self.zc_threshold {
            // SAFETY: `guard` is owned and live for the duration of this
            // function, so `ptr`/`value_len` describe a valid byte range.
            // `fire_set` copies those bytes into `write_buf`/`encode_buf`
            // synchronously (no `.await` between this borrow and the copy),
            // after which the guard `G` is dropped at the end of this call.
            let value = unsafe { core::slice::from_raw_parts(ptr, value_len as usize) };
            return self.fire_set(key, value, flags, exptime, user_data);
        }
        self.pre_flush_if_needed(true)?;
        // Append prefix, record guard insertion point, append suffix —
        // directly into write_buf, no intermediate allocation.
        let before = self.write_buf.len();
        append_set_guard_prefix(&mut self.write_buf, key, value_len as usize, flags, exptime)?;
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

    /// Fire a DELETE request without waiting for the response.
    pub fn fire_delete(&mut self, key: &[u8], user_data: u64) -> Result<(), Error> {
        self.pre_flush_if_needed(false)?;
        let tx_bytes;
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            // Direct send — skip write_buf round-trip.
            self.encode_buf.clear();
            encode_request_into(&McRequest::delete(key), &mut self.encode_buf)?;
            tx_bytes = self.encode_buf.len() as u32;
            self.conn.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            encode_request_into(&McRequest::delete(key), &mut self.write_buf)?;
            tx_bytes = (self.write_buf.len() - before) as u32;
            self.buffered_ops += 1;
        }
        let (send_ts, start) = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Delete,
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

        let response = match self.read_response().await {
            Ok(v) => v,
            Err(e) => {
                // Connection is broken — clear remaining pending ops so
                // subsequent recv() calls return NoPending instead of
                // reading stale/misaligned responses. Reset `flushed_count`
                // too — otherwise a stale count > 0 makes the next batched
                // `flush()` skip the send_ts rewrite for newly-buffered ops.
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
                // Check for error responses first
                let result = match check_error_bytes(&response) {
                    Err(e) => Err(e),
                    Ok(()) => match response {
                        McResponseBytes::Values(mut values) => {
                            if values.is_empty() {
                                Ok(None)
                            } else {
                                let v = values.swap_remove(0);
                                Ok(Some(Value {
                                    data: v.data,
                                    flags: v.flags,
                                }))
                            }
                        }
                        _ => Err(Error::UnexpectedResponse),
                    },
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
                let result = match check_error_bytes(&response) {
                    Err(e) => Err(e),
                    Ok(()) => match response {
                        McResponseBytes::Stored => Ok(()),
                        _ => Err(Error::UnexpectedResponse),
                    },
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
            PendingOpKind::Delete => {
                let result = match check_error_bytes(&response) {
                    Err(e) => Err(e),
                    Ok(()) => match response {
                        McResponseBytes::Deleted => Ok(true),
                        McResponseBytes::NotFound => Ok(false),
                        _ => Err(Error::UnexpectedResponse),
                    },
                };
                self.record(&CommandResult {
                    command: CommandType::Delete,
                    latency_ns,
                    hit: None,
                    success: result.is_ok(),
                    ttfb_ns,
                    tx_bytes,
                    rx_bytes,
                });
                CompletedOp::Delete {
                    result,
                    user_data: pending.user_data,
                    latency_ns,
                }
            }
        };

        Ok(op)
    }

    // ── Internal I/O (unchanged) ────────────────────────────────────────

    /// Read and parse a single Memcache response from the connection.
    ///
    /// Uses zero-copy parsing via `with_bytes` + `ResponseBytes::parse`:
    /// value data are `Bytes::slice()` references into the accumulator's
    /// buffer rather than freshly allocated `Vec<u8>`.
    ///
    /// On `Error::Protocol` (parse failure) the underlying connection is
    /// closed: even though the parser advanced past the malformed bytes,
    /// the request/response framing is now irrecoverably misaligned and
    /// any further command would read garbage. Surfacing `Protocol` as a
    /// terminal error matches the recv() pending-queue clear and avoids
    /// silently desynced clients.
    pub(crate) async fn read_response(&self) -> Result<McResponseBytes, Error> {
        let mut result: Option<Result<McResponseBytes, Error>> = None;
        let n = self
            .conn
            .with_bytes(|bytes| {
                let len = bytes.len();
                match McResponseBytes::parse(bytes) {
                    Ok((response, consumed)) => {
                        result = Some(Ok(response));
                        ParseResult::Consumed(consumed)
                    }
                    Err(e) if e.is_incomplete() => ParseResult::Consumed(0),
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
        let r = result.unwrap();
        if matches!(r, Err(Error::Protocol(_))) {
            self.conn.close();
        }
        r
    }

    /// Send an encoded command and read the response, converting error
    /// responses into `Error::Memcache`.
    async fn execute(&self, encoded: &[u8]) -> Result<McResponseBytes, Error> {
        self.conn.send(encoded)?;
        let response = self.read_response().await?;
        check_error_bytes(&response)?;
        Ok(response)
    }

    // -- Commands (instrumented hot-path) ---------------------------------

    /// Get the value of a key. Returns `None` on cache miss.
    pub async fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Value>, Error> {
        let key = key.as_ref();
        self.encode_buf.clear();
        encode_request_into(&McRequest::get(key), &mut self.encode_buf)?;

        if !self.is_instrumented() {
            let response = self.execute(&self.encode_buf).await?;
            return match response {
                McResponseBytes::Values(mut values) => {
                    if values.is_empty() {
                        Ok(None)
                    } else {
                        let v = values.swap_remove(0);
                        Ok(Some(Value {
                            data: v.data,
                            flags: v.flags,
                        }))
                    }
                }
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let tx_bytes = self.encode_buf.len() as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let response = self.execute(&self.encode_buf).await;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();

        let result = match response {
            Ok(McResponseBytes::Values(mut values)) => {
                if values.is_empty() {
                    Ok(None)
                } else {
                    let v = values.swap_remove(0);
                    Ok(Some(Value {
                        data: v.data,
                        flags: v.flags,
                    }))
                }
            }
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
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
            ttfb_ns: None,
            tx_bytes,
            rx_bytes,
        });
        result
    }

    /// Get values for multiple keys. Returns only hits, each with its key and CAS token.
    pub async fn gets(&mut self, keys: &[&[u8]]) -> Result<Vec<GetValue>, Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let encoded = encode_request(&McRequest::gets(keys))?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Values(values) => Ok(values
                .into_iter()
                .map(|v| GetValue {
                    key: v.key,
                    data: v.data,
                    flags: v.flags,
                    cas: v.cas,
                })
                .collect()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Set a key-value pair with default flags (0) and no expiration.
    pub async fn set(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        self.set_with_options(key, value, 0, 0).await
    }

    /// Set a key-value pair with custom flags and expiration time.
    pub async fn set_with_options(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        flags: u32,
        exptime: u32,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        self.encode_buf.clear();
        encode_request_into(
            &McRequest::Set {
                key,
                value,
                flags,
                exptime,
            },
            &mut self.encode_buf,
        )?;

        if !self.is_instrumented() {
            let response = self.execute(&self.encode_buf).await?;
            return match response {
                McResponseBytes::Stored => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let tx_bytes = self.encode_buf.len() as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let response = self.execute(&self.encode_buf).await;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();

        let result = match response {
            Ok(McResponseBytes::Stored) => Ok(()),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
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

    /// Store a key only if it does not already exist (ADD command).
    /// Returns `true` if stored, `false` if the key already exists.
    pub async fn add(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_add(key, value)?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Stored => Ok(true),
            McResponseBytes::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Store a key only if it already exists (REPLACE command).
    /// Returns `true` if stored, `false` if the key does not exist.
    pub async fn replace(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::Replace {
            key,
            value,
            flags: 0,
            exptime: 0,
        })?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Stored => Ok(true),
            McResponseBytes::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Increment a numeric value by delta. Returns the new value after incrementing.
    /// Returns `None` if the key does not exist.
    pub async fn incr(&mut self, key: impl AsRef<[u8]>, delta: u64) -> Result<Option<u64>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::incr(key, delta))?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Numeric(val) => Ok(Some(val)),
            McResponseBytes::NotFound => Ok(None),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Decrement a numeric value by delta. Returns the new value after decrementing.
    /// Returns `None` if the key does not exist.
    pub async fn decr(&mut self, key: impl AsRef<[u8]>, delta: u64) -> Result<Option<u64>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::decr(key, delta))?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Numeric(val) => Ok(Some(val)),
            McResponseBytes::NotFound => Ok(None),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Append data to an existing item's value.
    /// Returns `true` if stored, `false` if the key does not exist.
    pub async fn append(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::append(key, value))?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Stored => Ok(true),
            McResponseBytes::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Prepend data to an existing item's value.
    /// Returns `true` if stored, `false` if the key does not exist.
    pub async fn prepend(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::prepend(key, value))?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Stored => Ok(true),
            McResponseBytes::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Compare-and-swap: store the value only if the CAS token matches.
    /// Returns `Ok(true)` if stored, `Ok(false)` if the CAS token didn't match (EXISTS),
    /// or `Err` if the key was not found or another error occurred.
    pub async fn cas(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        cas_unique: u64,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::cas(key, value, cas_unique))?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Stored => Ok(true),
            McResponseBytes::Exists => Ok(false),
            McResponseBytes::NotFound => Err(Error::Memcache("NOT_FOUND".into())),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Delete a key. Returns `true` if deleted, `false` if not found.
    pub async fn delete(&mut self, key: impl AsRef<[u8]>) -> Result<bool, Error> {
        let key = key.as_ref();
        self.encode_buf.clear();
        encode_request_into(&McRequest::delete(key), &mut self.encode_buf)?;

        if !self.is_instrumented() {
            let response = self.execute(&self.encode_buf).await?;
            return match response {
                McResponseBytes::Deleted => Ok(true),
                McResponseBytes::NotFound => Ok(false),
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let tx_bytes = self.encode_buf.len() as u32;
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let response = self.execute(&self.encode_buf).await;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();

        let result = match response {
            Ok(McResponseBytes::Deleted) => Ok(true),
            Ok(McResponseBytes::NotFound) => Ok(false),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Delete,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
            tx_bytes,
            rx_bytes,
        });
        result
    }

    /// Flush all items from the cache.
    pub async fn flush_all(&mut self) -> Result<(), Error> {
        let encoded = encode_request(&McRequest::flush_all())?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Get the server version string.
    pub async fn version(&mut self) -> Result<Box<str>, Error> {
        let encoded = encode_request(&McRequest::version())?;
        let response = self.execute(&encoded).await?;
        match response {
            McResponseBytes::Version(v) => Ok(Box::from(String::from_utf8_lossy(v.as_ref()))),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    // -- Zero-copy SET -------------------------------------------------------

    /// SET with zero-copy value via SendGuard. The guard pins value memory
    /// until the kernel completes the send.
    pub async fn set_with_guard<G: SendGuard>(
        &mut self,
        key: &[u8],
        guard: G,
        flags: u32,
        exptime: u32,
    ) -> Result<(), Error> {
        if !self.is_instrumented() {
            let (_, value_len) = guard.as_ptr_len();
            self.encode_buf.clear();
            append_set_guard_prefix(
                &mut self.encode_buf,
                key,
                value_len as usize,
                flags,
                exptime,
            )?;

            let prefix: &[u8] = &self.encode_buf;
            self.conn.send_parts().build(move |b| {
                b.copy(prefix)
                    .guard(GuardBox::new(guard))
                    .copy(b"\r\n")
                    .submit()
            })?;

            let response = self.read_response().await?;
            check_error_bytes(&response)?;
            return match response {
                McResponseBytes::Stored => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let (_, value_len) = guard.as_ptr_len();
        self.encode_buf.clear();
        append_set_guard_prefix(
            &mut self.encode_buf,
            key,
            value_len as usize,
            flags,
            exptime,
        )?;
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

        let response = self.read_response().await;
        let latency_ns = self.finish_timing(send_ts, start);
        let rx_bytes = self.last_rx_bytes.get();

        let result = match response {
            Ok(ref r) => {
                check_error_bytes(r)?;
                match r {
                    McResponseBytes::Stored => Ok(()),
                    _ => Err(Error::UnexpectedResponse),
                }
            }
            Err(e) => Err(e),
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
// without gathering it into one contiguous buffer: the command header (which
// declares the length) is sent, then value chunks are pulled from the source and
// streamed to the wire, then the trailing `\r\n`. Works on both backends (send
// works everywhere); v1 copies each chunk into the send pool (`send`) — zero-copy
// guarded streaming is a later optimization.

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
    /// Sends `set <key> <flags> <exptime> <len>\r\n`, then streams exactly `len`
    /// value bytes pulled from `src`, then the trailing `\r\n`, and reads the
    /// `STORED\r\n` reply. The value is never gathered into one contiguous buffer
    /// on the client side.
    ///
    /// # Length contract
    ///
    /// `len` is authoritative: it is written into the command header. The client
    /// counts the bytes pulled from `src` and returns [`Error::LengthMismatch`]
    /// (after closing the connection) if `src` yields fewer or more than `len`
    /// bytes — because a partial/oversized value frame is already on the wire and
    /// the connection is irrecoverably desynced (same discipline as the read-side
    /// poison rule).
    ///
    /// # Backends
    ///
    /// Works on both io_uring and mio. v1 copies each chunk into the send pool
    /// via [`ConnCtx::send`](ringline::ConnCtx::send) (awaited per chunk for
    /// backpressure). Zero-copy guarded streaming is a later optimization.
    pub async fn set_stream(
        &mut self,
        key: &[u8],
        flags: u32,
        exptime: u32,
        len: usize,
        src: impl SegmentSource,
    ) -> Result<(), Error> {
        // Header: `set <key> <flags> <exptime> <len>\r\n`. Build and validate it
        // first — an oversized key is rejected here, before any byte hits the
        // wire, so that error does NOT poison the connection.
        self.encode_buf.clear();
        append_set_guard_prefix(&mut self.encode_buf, key, len, flags, exptime)?;

        // From the first send onward a partial value frame can be on the wire;
        // any error before a *complete* reply is read leaves the connection
        // desynced — a pooled reuse would feed the next caller's bytes into this
        // frame's value. So poison (close) on any such error, matching the
        // over/under-produce and read-side poison discipline. A complete reply
        // (even a server error line, or an unexpected type) means the frame was
        // fully sent and the wire is synced — that path must NOT poison.
        match self.write_set_frame_and_read(len, src).await {
            Ok(response) => {
                check_error_bytes(&response)?;
                match response {
                    McResponseBytes::Stored => Ok(()),
                    _ => Err(Error::UnexpectedResponse),
                }
            }
            Err(e) => {
                self.conn.close();
                Err(e)
            }
        }
    }

    /// Write the streamed `set` frame (header already built in `encode_buf`) and
    /// read its reply. Every `?` here is a wire-desync condition
    /// ([`set_stream`](Self::set_stream) poisons on it); classifying the reply
    /// happens in the caller, after a complete reply has been read.
    async fn write_set_frame_and_read(
        &mut self,
        len: usize,
        mut src: impl SegmentSource,
    ) -> Result<McResponseBytes, Error> {
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

        // Trailing `\r\n`, then the `STORED\r\n` reply.
        self.conn.send_nowait(b"\r\n")?;
        self.read_response().await
    }
}

// ── Streaming GET (segmented recv, single-connection Client only) ─────────
//
// `get_stream` returns a `StreamValue` instead of a materialized `Value`: the
// value body is delivered as segments over the runtime's segmented-recv API
// (`ConnCtx::recv_owned_segment`), so a consumer that discards or streams the
// value never forces the whole thing into one contiguous allocation. Only
// `collect()` materializes.
//
// io_uring only — segmented recv is backed by the provided-buffer ring, and the
// underlying `recv_owned_segment` / `end_segments` methods are `#[cfg(has_io_uring)]`.
// This crate's build.rs emits `has_io_uring` in lockstep with `ringline`.
//
// SCOPE (v1): memcache `get_stream` on the single-connection `Client` only.
// Deferred (documented, not implemented here): `get_cas` streaming (the CAS
// variant), streaming `set`, and `recv_streaming()` fire/recv integration. The
// multi-key `gets(keys)` stays eager/materialized (one frame carries N values),
// and pooled / sharded clients intentionally keep the materialized `get`.

#[cfg(has_io_uring)]
impl Client {
    /// Streaming GET (single-connection [`Client`] only).
    ///
    /// Like [`get`](Self::get), but the value body is delivered as a
    /// [`StreamValue`] of segments rather than a single materialized [`Value`].
    /// A consumer that only needs to discard or checksum the value pays no
    /// gather copy; [`StreamValue::collect`] is the one materialization. The
    /// item flags are available via [`StreamValue::flags`].
    ///
    /// Returns `Ok(None)` for a missing key (bare `END\r\n` reply).
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
    /// If a [`StreamValue`] is dropped before its value (and the trailing
    /// `\r\nEND\r\n` delimiter) is fully consumed — via
    /// [`collect`](StreamValue::collect), [`discard`](StreamValue::discard), or
    /// reading [`next_segment`](StreamValue::next_segment) to the end — the
    /// undrained wire bytes cannot be drained synchronously in `Drop`, so the
    /// connection is **closed** (its slot generation bumped). The next operation
    /// on this client then fails, matching the "poison = close" recovery
    /// discipline.
    pub async fn get_stream(
        &mut self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<StreamValue<'_>>, Error> {
        let key = key.as_ref();
        // Fire the GET, then opt the connection into segmented delivery. The
        // reply body then arrives as held segments instead of being gathered
        // into the accumulator. `recv_owned_segment()` sets the domain
        // synchronously (before we await), so the reply can't be processed under
        // the default path first.
        self.encode_buf.clear();
        encode_request_into(&McRequest::get(key), &mut self.encode_buf)?;
        self.conn.send_nowait(&self.encode_buf)?;

        // Read the `VALUE <key> <flags> <bytes>\r\n` header line (or `END\r\n`).
        // It always fits in the first received buffer; the rare split-across-
        // buffers case is handled by accumulating into `acc` and retrying.
        //
        // Demarcation is exact: `parse_get_header` measures only the header line
        // (`header_len`, up to and including its `\r\n`), never the value.
        // Everything after `header_len` in the buffer we already pulled is
        // value-body bytes, handed to the stream as an O(1) `Bytes::slice` — so
        // no value byte is lost or double-read, and the read cursor is a single
        // monotonic position across header + body + trailing `\r\nEND\r\n`.
        let mut acc: Option<Vec<u8>> = None;
        loop {
            let seg = match self.conn.recv_owned_segment().await? {
                Some(b) => b,
                None => {
                    // Peer closed before any header arrived.
                    let _ = self.conn.end_segments();
                    return Err(Error::ConnectionClosed);
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
                Ok(Some(GetHeader::Miss)) => {
                    // Missing key. `END\r\n` carries no value/trailing; restore
                    // the default read path so the next command works.
                    self.conn.end_segments()?;
                    return Ok(None);
                }
                Ok(Some(GetHeader::Value {
                    flags,
                    len,
                    header_len,
                })) => {
                    let leftover = combined.slice(header_len..);
                    return Ok(Some(StreamValue::new(self, flags, len, leftover)));
                }
                Ok(None) => {
                    // Header line not yet complete — stash and pull the next buffer.
                    acc = Some(combined.to_vec());
                }
                Err(e) => {
                    // Server error line (`ERROR`, `SERVER_ERROR …`,
                    // `CLIENT_ERROR …`) or a malformed header. In sequential use
                    // the whole reply line is in `combined`; restore the read
                    // path and surface the error.
                    let _ = self.conn.end_segments();
                    return Err(e);
                }
            }
        }
    }
}

/// Parsed shape of a memcache GET reply header line.
#[cfg(has_io_uring)]
enum GetHeader {
    /// Bare `END\r\n` — the key does not exist.
    Miss,
    /// `VALUE <key> <flags> <bytes>\r\n` — `bytes` value bytes follow, then a
    /// trailing `\r\nEND\r\n`. `header_len` is the byte length of the header line
    /// itself (through its `\r\n`); `flags` is the stored item flags.
    Value {
        flags: u32,
        len: usize,
        header_len: usize,
    },
}

/// Position of the first `\r\n` in `buf` (the index of the `\r`), or `None`.
#[cfg(has_io_uring)]
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Parse a memcache GET reply header line from the **front** of `buf`, measuring
/// only the header line (`VALUE <key> <flags> <bytes>\r\n` / `END\r\n`) — the
/// value body and trailing `\r\nEND\r\n` are left for the caller to stream, so
/// the header/value split loses no byte.
///
/// - `Ok(None)` — the header line is not yet fully buffered (need more bytes).
/// - `Ok(Some(GetHeader::Miss))` — a bare `END` line (cache miss).
/// - `Ok(Some(GetHeader::Value { .. }))` — a `VALUE` header.
/// - `Err(Error::Memcache(_))` — a server error line (`ERROR` / `SERVER_ERROR …`
///   / `CLIENT_ERROR …`).
/// - `Err(Error::UnexpectedResponse)` — an unrecognized line or malformed
///   integer field.
#[cfg(has_io_uring)]
fn parse_get_header(buf: &[u8]) -> Result<Option<GetHeader>, Error> {
    // Every valid first line (VALUE / END / error) ends in `\r\n`; without one
    // the line is incomplete.
    let Some(cr) = find_crlf(buf) else {
        return Ok(None);
    };
    let line = &buf[..cr];
    let header_len = cr + 2; // line bytes + "\r\n"

    if line == b"END" {
        return Ok(Some(GetHeader::Miss));
    }
    if line.starts_with(b"VALUE ") {
        // VALUE <key> <flags> <bytes> [<cas>]
        let mut fields = line.split(|&b| b == b' ').filter(|f| !f.is_empty());
        let _value_kw = fields.next(); // "VALUE"
        let _key = fields.next().ok_or(Error::UnexpectedResponse)?;
        let flags_tok = fields.next().ok_or(Error::UnexpectedResponse)?;
        let bytes_tok = fields.next().ok_or(Error::UnexpectedResponse)?;
        let flags = parse_uint::<u32>(flags_tok)?;
        let len = parse_uint::<usize>(bytes_tok)?;
        return Ok(Some(GetHeader::Value {
            flags,
            len,
            header_len,
        }));
    }
    // Error lines. `ERROR` is a bare token; `SERVER_ERROR`/`CLIENT_ERROR` carry a
    // trailing message.
    if line == b"ERROR" || line.starts_with(b"CLIENT_ERROR") || line.starts_with(b"SERVER_ERROR") {
        return Err(Error::Memcache(String::from_utf8_lossy(line).into_owned()));
    }
    Err(Error::UnexpectedResponse)
}

/// Parse an ASCII unsigned integer field, mapping any malformation to
/// [`Error::UnexpectedResponse`].
#[cfg(has_io_uring)]
fn parse_uint<T: std::str::FromStr>(tok: &[u8]) -> Result<T, Error> {
    std::str::from_utf8(tok)
        .ok()
        .and_then(|s| s.parse::<T>().ok())
        .ok_or(Error::UnexpectedResponse)
}

/// A streaming memcache GET value (see [`Client::get_stream`]).
///
/// Borrows the [`Client`] exclusively (`&mut`) and is bounded to the value length
/// parsed from the `VALUE <key> <flags> <bytes>\r\n` header, so it can neither
/// over-read into a following reply nor be used concurrently with another client
/// operation.
///
/// The value body is delivered via the runtime's segmented-recv API. In v1 each
/// [`next_segment`](Self::next_segment) chunk (and the [`collect`](Self::collect)
/// gather) is an owned [`Bytes`] copied at delivery (Mode C). [`discard`](Self::discard)
/// consumes each chunk at delivery but performs no *gather* copy.
#[cfg(has_io_uring)]
pub struct StreamValue<'a> {
    client: &'a mut Client,
    /// Item flags from the `VALUE` header.
    flags: u32,
    /// Full value length from the header.
    len: usize,
    /// Value bytes not yet handed to the caller.
    value_left: usize,
    /// Trailing `\r\nEND\r\n` bytes not yet consumed (starts at 7).
    trail_left: usize,
    /// Bytes pulled from the wire but not yet consumed (value + maybe trailing).
    buf: Bytes,
    /// Set once value + trailing delimiter are fully consumed and the recv
    /// domain has been restored. `false` at drop time ⇒ the stream was abandoned
    /// mid-value ⇒ poison (close) the connection.
    finished: bool,
}

/// Length of the trailing `\r\nEND\r\n` after a memcache value body: the value's
/// own CRLF (2) plus the `END\r\n` terminator (5).
#[cfg(has_io_uring)]
const TRAILER_LEN: usize = 7;

#[cfg(has_io_uring)]
impl<'a> StreamValue<'a> {
    fn new(client: &'a mut Client, flags: u32, len: usize, leftover: Bytes) -> Self {
        Self {
            client,
            flags,
            len,
            value_left: len,
            trail_left: TRAILER_LEN,
            buf: leftover,
            finished: false,
        }
    }

    /// The item flags from the `VALUE` header.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// The value length in bytes, from the `VALUE <key> <flags> <bytes>` header.
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
    /// whole value + trailing delimiter arrived — a **short FIN**, surfaced as an
    /// error (never a truncated value), per the bounded-`len` contract.
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
    /// After the final chunk the trailing `\r\nEND\r\n` is consumed and the
    /// connection is restored for the next command, so a caller need not read
    /// past the last value byte — though calling again simply returns `Ok(None)`.
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

    /// Consume the trailing `\r\nEND\r\n`, restore the default
    /// `with_data`/`with_bytes` read path, and mark the stream finished so `Drop`
    /// does not poison the connection.
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
        // trailing delimiter would belong to a *following* reply — none exist in
        // the documented sequential use; they are dropped rather than reinjected.
        self.client.conn.end_segments()?;
        self.finished = true;
        Ok(())
    }
}

#[cfg(has_io_uring)]
impl Drop for StreamValue<'_> {
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

// ── Streaming get-with-CAS (segmented recv, single-connection Client only) ─
//
// `get_cas` is the CAS-carrying mirror of `get_stream`: it issues `gets <key>`
// instead of `get <key>`, so the hit reply is
// `VALUE <key> <flags> <bytes> <cas>\r\n<data>\r\nEND\r\n` (an extra `<cas>`
// token). The value body then streams exactly like `get_stream` — `get_cas`
// reuses `StreamValue` (bounded to `<bytes>`, `\r\nEND\r\n` trailer, short-FIN
// error, undrained-drop poison) and layers the parsed `cas` token on top.

#[cfg(has_io_uring)]
impl Client {
    /// Streaming get-with-CAS (single-connection [`Client`] only).
    ///
    /// Like [`get_stream`](Self::get_stream), but issues `gets <key>` so the
    /// reply header carries a CAS token (`VALUE <key> <flags> <bytes> <cas>`),
    /// exposed via [`CasStreamValue::cas`]. The value body is delivered as a
    /// [`CasStreamValue`] of segments; a consumer that only discards or checksums
    /// pays no gather copy, and [`CasStreamValue::collect`] is the one
    /// materialization.
    ///
    /// Returns `Ok(None)` for a missing key (bare `END\r\n` reply).
    ///
    /// The same sequential-use, short-FIN-error, and undrained-drop-poison
    /// contracts as [`get_stream`](Self::get_stream) apply.
    pub async fn get_cas(
        &mut self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<CasStreamValue<'_>>, Error> {
        let key = key.as_ref();
        // Fire `gets <key>\r\n`, then opt into segmented delivery (synchronous,
        // before the await) so the reply arrives as held segments.
        self.encode_buf.clear();
        encode_request_into(&McRequest::gets(&[key]), &mut self.encode_buf)?;
        self.conn.send_nowait(&self.encode_buf)?;

        // Read the `VALUE <key> <flags> <bytes> <cas>\r\n` header (or `END\r\n`).
        // Demarcation is exact — see `get_stream`.
        let mut acc: Option<Vec<u8>> = None;
        loop {
            let seg = match self.conn.recv_owned_segment().await? {
                Some(b) => b,
                None => {
                    let _ = self.conn.end_segments();
                    return Err(Error::ConnectionClosed);
                }
            };
            let combined: Bytes = match acc.take() {
                None => seg,
                Some(mut a) => {
                    a.extend_from_slice(&seg);
                    Bytes::from(a)
                }
            };
            match parse_gets_header(&combined) {
                Ok(Some(CasHeader::Miss)) => {
                    self.conn.end_segments()?;
                    return Ok(None);
                }
                Ok(Some(CasHeader::Value {
                    flags,
                    len,
                    cas,
                    header_len,
                })) => {
                    let leftover = combined.slice(header_len..);
                    let inner = StreamValue::new(self, flags, len, leftover);
                    return Ok(Some(CasStreamValue { inner, cas }));
                }
                Ok(None) => {
                    acc = Some(combined.to_vec());
                }
                Err(e) => {
                    let _ = self.conn.end_segments();
                    return Err(e);
                }
            }
        }
    }
}

/// Parsed shape of a memcache `gets` reply header line (like [`GetHeader`] but
/// carrying the extra CAS token).
#[cfg(has_io_uring)]
enum CasHeader {
    /// Bare `END\r\n` — the key does not exist.
    Miss,
    /// `VALUE <key> <flags> <bytes> <cas>\r\n`.
    Value {
        flags: u32,
        len: usize,
        cas: u64,
        header_len: usize,
    },
}

/// Parse a memcache `gets` reply header line from the **front** of `buf`,
/// measuring only the header line (5-token
/// `VALUE <key> <flags> <bytes> <cas>\r\n` / `END\r\n`). The value body and
/// trailing `\r\nEND\r\n` are left for the caller to stream.
///
/// Same return contract as [`parse_get_header`], with the additional `<cas>`
/// token extracted.
#[cfg(has_io_uring)]
fn parse_gets_header(buf: &[u8]) -> Result<Option<CasHeader>, Error> {
    let Some(cr) = find_crlf(buf) else {
        return Ok(None);
    };
    let line = &buf[..cr];
    let header_len = cr + 2; // line bytes + "\r\n"

    if line == b"END" {
        return Ok(Some(CasHeader::Miss));
    }
    if line.starts_with(b"VALUE ") {
        // VALUE <key> <flags> <bytes> <cas>
        let mut fields = line.split(|&b| b == b' ').filter(|f| !f.is_empty());
        let _value_kw = fields.next(); // "VALUE"
        let _key = fields.next().ok_or(Error::UnexpectedResponse)?;
        let flags_tok = fields.next().ok_or(Error::UnexpectedResponse)?;
        let bytes_tok = fields.next().ok_or(Error::UnexpectedResponse)?;
        let cas_tok = fields.next().ok_or(Error::UnexpectedResponse)?;
        let flags = parse_uint::<u32>(flags_tok)?;
        let len = parse_uint::<usize>(bytes_tok)?;
        let cas = parse_uint::<u64>(cas_tok)?;
        return Ok(Some(CasHeader::Value {
            flags,
            len,
            cas,
            header_len,
        }));
    }
    if line == b"ERROR" || line.starts_with(b"CLIENT_ERROR") || line.starts_with(b"SERVER_ERROR") {
        return Err(Error::Memcache(String::from_utf8_lossy(line).into_owned()));
    }
    Err(Error::UnexpectedResponse)
}

/// A streaming memcache get-with-CAS value (see [`Client::get_cas`]).
///
/// Wraps a [`StreamValue`] (the bounded value-body stream) with the CAS token
/// parsed from the `VALUE <key> <flags> <bytes> <cas>\r\n` header. All the
/// streaming semantics — bounded to the value length, short-FIN error,
/// undrained-drop poison — come from the inner [`StreamValue`].
#[cfg(has_io_uring)]
pub struct CasStreamValue<'a> {
    inner: StreamValue<'a>,
    cas: u64,
}

#[cfg(has_io_uring)]
impl CasStreamValue<'_> {
    /// The item flags from the `VALUE` header.
    pub fn flags(&self) -> u32 {
        self.inner.flags()
    }

    /// The CAS (compare-and-swap) unique token from the `VALUE` header.
    pub fn cas(&self) -> u64 {
        self.cas
    }

    /// The value length in bytes, from the `VALUE <key> <flags> <bytes> <cas>`
    /// header.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the value is zero-length.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The next chunk of the value body, or `Ok(None)` once the whole value has
    /// been delivered. See [`StreamValue::next_segment`].
    pub async fn next_segment(&mut self) -> Result<Option<Bytes>, Error> {
        self.inner.next_segment().await
    }

    /// Materialize the whole value into one contiguous [`Bytes`] (the copy).
    /// See [`StreamValue::collect`].
    pub async fn collect(self) -> Result<Bytes, Error> {
        self.inner.collect().await
    }

    /// Consume and release the whole value without materializing it, leaving the
    /// connection usable for the next command. See [`StreamValue::discard`].
    pub async fn discard(self) -> Result<(), Error> {
        self.inner.discard().await
    }
}

// -- Zero-copy SET encoding helpers ------------------------------------------

/// Append the memcache text SET prefix for guard-based sends to `buf`:
/// `set {key} {flags} {exptime} {valuelen}\r\n`.
/// The caller must append value bytes (via guard) + `\r\n` suffix.
///
/// Validates `key` (≤ [`MAX_KEY_LEN`]); returns [`Error::KeyTooLong`] if the
/// bound is exceeded so that no bytes hit the wire for a request the server
/// would misparse. Value length is not checked — see [`validate_request`].
/// On error nothing is appended to `buf`.
fn append_set_guard_prefix(
    buf: &mut Vec<u8>,
    key: &[u8],
    value_len: usize,
    flags: u32,
    exptime: u32,
) -> Result<(), Error> {
    validate_key(key)?;
    let mut itoa_buf = itoa::Buffer::new();
    buf.extend_from_slice(b"set ");
    buf.extend_from_slice(key);
    buf.push(b' ');
    buf.extend_from_slice(itoa_buf.format(flags).as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(itoa_buf.format(exptime).as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(itoa_buf.format(value_len).as_bytes());
    buf.extend_from_slice(b"\r\n");
    Ok(())
}

// -- Encoding helpers --------------------------------------------------------

/// Reject requests whose key exceeds the 250-byte protocol cap. Value
/// length is not checked here — memcached's `-I` item-size limit is a
/// server knob, so the client lets the server reject an oversized value
/// with a normal `SERVER_ERROR` reply rather than second-guessing it.
fn validate_request(req: &McRequest<'_>) -> Result<(), Error> {
    match req {
        McRequest::Get { key }
        | McRequest::Incr { key, .. }
        | McRequest::Decr { key, .. }
        | McRequest::Delete { key } => validate_key(key),
        McRequest::Gets { keys } => {
            for k in keys.iter() {
                validate_key(k)?;
            }
            Ok(())
        }
        McRequest::Set { key, .. }
        | McRequest::Add { key, .. }
        | McRequest::Replace { key, .. }
        | McRequest::Append { key, .. }
        | McRequest::Prepend { key, .. }
        | McRequest::Cas { key, .. } => validate_key(key),
        McRequest::FlushAll | McRequest::Version | McRequest::Quit => Ok(()),
    }
}

/// Append the encoding of a `McRequest` to `buf`, rejecting oversized keys
/// up-front (see [`validate_request`]). No allocation once `buf` has
/// sufficient capacity. On error nothing is appended to `buf`.
pub(crate) fn encode_request_into(req: &McRequest<'_>, buf: &mut Vec<u8>) -> Result<(), Error> {
    validate_request(req)?;
    let size = match req {
        McRequest::Get { key } => 6 + key.len(),
        McRequest::Gets { keys } => 6 + keys.iter().map(|k| 1 + k.len()).sum::<usize>(),
        McRequest::Set { key, value, .. } | McRequest::Add { key, value, .. } => {
            41 + key.len() + value.len()
        }
        McRequest::Replace { key, value, .. } => 45 + key.len() + value.len(),
        McRequest::Incr { key, .. } | McRequest::Decr { key, .. } => 27 + key.len(),
        McRequest::Append { key, value } => 44 + key.len() + value.len(),
        McRequest::Prepend { key, value } => 45 + key.len() + value.len(),
        McRequest::Cas { key, value, .. } => 61 + key.len() + value.len(),
        McRequest::Delete { key } => 9 + key.len(),
        McRequest::FlushAll => 11,
        McRequest::Version => 9,
        McRequest::Quit => 6,
    };
    let start = buf.len();
    buf.resize(start + size, 0);
    let len = req.encode(&mut buf[start..]);
    buf.truncate(start + len);
    Ok(())
}

/// Encode a `McRequest` into a freshly allocated `Vec<u8>`, rejecting
/// oversized keys up-front (see [`validate_request`]). Hot paths in
/// [`Client`] use [`encode_request_into`] with a reusable buffer instead.
pub(crate) fn encode_request(req: &McRequest<'_>) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    encode_request_into(req, &mut buf)?;
    Ok(buf)
}

/// Encode a SET command into a `Vec<u8>`. Test-only convenience; hot paths
/// use [`encode_request_into`] with a reused buffer.
#[cfg(test)]
pub(crate) fn encode_set(
    key: &[u8],
    value: &[u8],
    flags: u32,
    exptime: u32,
) -> Result<Vec<u8>, Error> {
    encode_request(&McRequest::Set {
        key,
        value,
        flags,
        exptime,
    })
}

/// Encode an ADD command into a `Vec<u8>`.
pub(crate) fn encode_add(key: &[u8], value: &[u8]) -> Result<Vec<u8>, Error> {
    encode_request(&McRequest::Add {
        key,
        value,
        flags: 0,
        exptime: 0,
    })
}

/// Check a `ResponseBytes` for error variants and return an appropriate `Error`.
pub(crate) fn check_error_bytes(response: &McResponseBytes) -> Result<(), Error> {
    match response {
        McResponseBytes::Error => Err(Error::Memcache("ERROR".into())),
        McResponseBytes::ClientError(msg) => Err(Error::Memcache(format!(
            "CLIENT_ERROR {}",
            String::from_utf8_lossy(msg)
        ))),
        McResponseBytes::ServerError(msg) => Err(Error::Memcache(format!(
            "SERVER_ERROR {}",
            String::from_utf8_lossy(msg)
        ))),
        _ => Ok(()),
    }
}

// ── Kernel timestamp helper ─────────────────────────────────────────────

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

#[cfg(test)]
mod encode_tests {
    use super::*;

    // 14-byte key with digits — exercises digit/key-byte adjacency and
    // multi-digit integer fields (itoa boundary cases).
    const KEY: &[u8] = b"user:123456789";

    #[test]
    fn golden_encode_request_get() {
        let encoded = encode_request(&McRequest::get(KEY)).unwrap();
        assert_eq!(encoded, b"get user:123456789\r\n");
    }

    #[test]
    fn golden_encode_request_delete() {
        let encoded = encode_request(&McRequest::delete(KEY)).unwrap();
        assert_eq!(encoded, b"delete user:123456789\r\n");
    }

    #[test]
    fn golden_encode_request_set() {
        let encoded = encode_set(KEY, b"hello world value", 42, 7200).unwrap();
        assert_eq!(
            encoded,
            &b"set user:123456789 42 7200 17\r\nhello world value\r\n"[..]
        );
    }

    #[test]
    fn golden_encode_request_set_zero_fields() {
        let encoded = encode_set(KEY, b"v", 0, 0).unwrap();
        assert_eq!(encoded, &b"set user:123456789 0 0 1\r\nv\r\n"[..]);
    }

    #[test]
    fn golden_set_guard_prefix() {
        // Non-trivial flags / exptime / value_len so every integer field
        // is pinned byte-exactly.
        let mut prefix = Vec::new();
        append_set_guard_prefix(&mut prefix, KEY, 1024, 42, 7200).unwrap();
        assert_eq!(prefix, &b"set user:123456789 42 7200 1024\r\n"[..]);
    }

    #[test]
    fn encode_into_appends_without_clobbering() {
        // The `_into` helper must append, never clear — clearing is the
        // caller's responsibility.
        let mut buf = b"EXISTING".to_vec();
        encode_request_into(&McRequest::get(KEY), &mut buf).unwrap();
        assert_eq!(buf, &b"EXISTINGget user:123456789\r\n"[..]);
    }

    #[test]
    fn encode_into_error_leaves_buf_untouched() {
        let mut buf = b"EXISTING".to_vec();
        let long_key = vec![b'k'; MAX_KEY_LEN + 1];
        assert!(encode_request_into(&McRequest::get(&long_key), &mut buf).is_err());
        assert_eq!(buf, b"EXISTING");
        assert!(append_set_guard_prefix(&mut buf, &long_key, 16, 0, 0).is_err());
        assert_eq!(buf, b"EXISTING");
    }

    // ── Coalescing byte-exactness ───────────────────────────────────────
    //
    // The write-coalescing layer (`max_batch_size > 1`) builds a single
    // `write_buf` by appending each `fire_*` command's encoding back-to-back,
    // then issues one send. The on-wire bytes for a coalesced batch must
    // therefore equal the exact concatenation of the N individual command
    // encodings. These tests pin that invariant without a live connection by
    // exercising the same `encode_request_into` append path `fire_*` uses.

    #[test]
    fn coalesced_buf_equals_concatenation_of_individual_encodings() {
        // Build the batch the way the coalescing path does: append each
        // command into one shared buffer.
        let mut coalesced = Vec::new();
        encode_request_into(&McRequest::get(b"key1"), &mut coalesced).unwrap();
        encode_request_into(
            &McRequest::Set {
                key: b"key2",
                value: b"val",
                flags: 0,
                exptime: 0,
            },
            &mut coalesced,
        )
        .unwrap();
        encode_request_into(&McRequest::delete(b"key3"), &mut coalesced).unwrap();

        // Build the reference: concatenate three independently-encoded
        // commands.
        let mut expected = Vec::new();
        expected.extend_from_slice(&encode_request(&McRequest::get(b"key1")).unwrap());
        expected.extend_from_slice(
            &encode_request(&McRequest::Set {
                key: b"key2",
                value: b"val",
                flags: 0,
                exptime: 0,
            })
            .unwrap(),
        );
        expected.extend_from_slice(&encode_request(&McRequest::delete(b"key3")).unwrap());

        assert_eq!(coalesced, expected);
        // And the literal on-wire bytes, to catch framing regressions.
        assert_eq!(
            coalesced,
            &b"get key1\r\nset key2 0 0 3\r\nval\r\ndelete key3\r\n"[..]
        );
    }

    #[test]
    fn coalesced_guard_set_byte_layout() {
        // Mirror the `fire_set_with_guard` buffer assembly: prefix into
        // write_buf, guard insertion point recorded, then "\r\n" suffix.
        // The flush scatter-gather then emits: prefix || value || "\r\n".
        let mut write_buf = Vec::new();
        let value: &[u8] = b"hello";
        append_set_guard_prefix(&mut write_buf, KEY, value.len(), 42, 7200).unwrap();
        let guard_offset = write_buf.len();
        write_buf.extend_from_slice(b"\r\n");

        // Reconstruct the on-wire stream the flush path produces:
        // Copy(write_buf[..guard_offset]) Guard(value) Copy(write_buf[guard_offset..]).
        let mut wire = Vec::new();
        wire.extend_from_slice(&write_buf[..guard_offset]);
        wire.extend_from_slice(value);
        wire.extend_from_slice(&write_buf[guard_offset..]);

        assert_eq!(
            wire,
            &b"set user:123456789 42 7200 5\r\nhello\r\n"[..],
            "coalesced guard SET must match a standard SET on the wire"
        );

        // tx_bytes accounting: write_buf bytes + value bytes (guard is not
        // in write_buf). `fire_set_with_guard` computes
        // (write_buf.len() - before + value_len).
        assert_eq!(write_buf.len() + value.len(), wire.len());
    }

    #[test]
    fn two_coalesced_guard_sets_interleave_correctly() {
        // Two guard SETs in one batch must produce
        // prefix1 value1 "\r\n" prefix2 value2 "\r\n" on the wire — this
        // pins the drain/interleave loop in `flush()`.
        let v1: &[u8] = b"aa";
        let v2: &[u8] = b"bbbb";

        let mut write_buf = Vec::new();
        let mut guards: Vec<usize> = Vec::new();

        append_set_guard_prefix(&mut write_buf, b"k1", v1.len(), 0, 0).unwrap();
        guards.push(write_buf.len());
        write_buf.extend_from_slice(b"\r\n");

        append_set_guard_prefix(&mut write_buf, b"k2", v2.len(), 0, 0).unwrap();
        guards.push(write_buf.len());
        write_buf.extend_from_slice(b"\r\n");

        // Replay the flush interleave loop.
        let values = [v1, v2];
        let mut wire = Vec::new();
        let mut pos = 0;
        for (i, &offset) in guards.iter().enumerate() {
            if offset > pos {
                wire.extend_from_slice(&write_buf[pos..offset]);
            }
            wire.extend_from_slice(values[i]);
            pos = offset;
        }
        if pos < write_buf.len() {
            wire.extend_from_slice(&write_buf[pos..]);
        }

        assert_eq!(wire, &b"set k1 0 0 2\r\naa\r\nset k2 0 0 4\r\nbbbb\r\n"[..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_key_accepts_max_len() {
        let key = vec![b'k'; MAX_KEY_LEN];
        assert!(validate_key(&key).is_ok());
    }

    #[test]
    fn validate_key_rejects_oversized() {
        let key = vec![b'k'; MAX_KEY_LEN + 1];
        assert!(matches!(validate_key(&key), Err(Error::KeyTooLong)));
    }

    #[test]
    fn encode_request_get_rejects_long_key() {
        let key = vec![b'k'; MAX_KEY_LEN + 1];
        let r = encode_request(&McRequest::get(&key));
        assert!(matches!(r, Err(Error::KeyTooLong)));
    }

    #[test]
    fn encode_request_set_passes_large_value() {
        // Value length is not checked client-side — memcached's `-I` item-size
        // limit is a server knob, so an oversized value is allowed onto the
        // wire and the server rejects it.
        let key = b"k";
        let value = vec![0u8; 2 * 1024 * 1024];
        let r = encode_request(&McRequest::Set {
            key,
            value: &value,
            flags: 0,
            exptime: 0,
        });
        assert!(r.is_ok());
        assert!(r.unwrap().starts_with(b"set "));
    }

    #[test]
    fn encode_request_gets_rejects_any_long_key() {
        let ok = vec![b'k'; MAX_KEY_LEN];
        let bad = vec![b'k'; MAX_KEY_LEN + 1];
        let keys: &[&[u8]] = &[&ok, &bad];
        let r = encode_request(&McRequest::gets(keys));
        assert!(matches!(r, Err(Error::KeyTooLong)));
    }

    #[test]
    fn set_guard_prefix_rejects_long_key() {
        let key = vec![b'k'; MAX_KEY_LEN + 1];
        let r = append_set_guard_prefix(&mut Vec::new(), &key, 16, 0, 0);
        assert!(matches!(r, Err(Error::KeyTooLong)));
    }

    #[test]
    fn set_guard_prefix_passes_large_value_len() {
        // Value length is not checked client-side (see `validate_request`).
        let r = append_set_guard_prefix(&mut Vec::new(), b"k", 2 * 1024 * 1024, 0, 0);
        assert!(r.is_ok());
    }

    #[test]
    fn encode_request_passes_through_at_key_cap() {
        let key = vec![b'k'; MAX_KEY_LEN];
        let value = vec![0u8; 1024];
        let r = encode_request(&McRequest::Set {
            key: &key,
            value: &value,
            flags: 0,
            exptime: 0,
        });
        assert!(r.is_ok());
        let buf = r.unwrap();
        // Sanity: encoded buffer starts with "set ".
        assert!(buf.starts_with(b"set "));
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
        Client::builder(conn)
            .max_batch_size(max_batch_size)
            .zc_threshold(zc_threshold)
            .build()
    }

    #[test]
    fn small_guard_set_is_byte_identical_to_plain_set() {
        // Small guarded SET must produce byte-identical write_buf to a plain
        // copy SET of the same key/value/flags/exptime via fire_set.
        let value = vec![0xABu8; 64];

        let mut guarded = test_client(4, 4096);
        guarded
            .fire_set_with_guard(KEY, VecGuard(value.clone()), 7, 42, 1)
            .unwrap();

        let mut plain = test_client(4, 4096);
        plain.fire_set(KEY, &value, 7, 42, 1).unwrap();

        assert_eq!(guarded.write_buf, plain.write_buf);
        assert!(guarded.write_guards.is_empty());
    }

    #[test]
    fn small_value_takes_copy_path() {
        // 64B < 4096 → folds into copy path: write_guards empty, one buffered op.
        let mut client = test_client(4, 4096);
        client
            .fire_set_with_guard(KEY, VecGuard(vec![0u8; 64]), 0, 0, 1)
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
            .fire_set_with_guard(KEY, VecGuard(vec![0u8; 8192]), 0, 0, 1)
            .unwrap();
        assert_eq!(client.write_guards.len(), 1);
    }

    #[test]
    fn threshold_zero_disables_fold() {
        // zc_threshold = 0 → always guard path, even for tiny values.
        let mut client = test_client(4, 0);
        client
            .fire_set_with_guard(KEY, VecGuard(vec![0u8; 64]), 0, 0, 1)
            .unwrap();
        assert_eq!(client.write_guards.len(), 1);
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
                .fire_set_with_guard(KEY, VecGuard(vec![0u8; 64]), 0, 0, i as u64)
                .unwrap();
        }
        assert_eq!(
            client.write_guards.len(),
            MAX_FLUSH_GUARDS,
            "a full guard batch must accumulate without a premature flush"
        );
    }

    #[test]
    fn batch_of_small_guard_sets_coalesces() {
        // N small guarded SETs at max_batch_size = N: all fold into the copy
        // path (write_guards stays empty), so they batch into a single buffer.
        // With a guard path they'd flush every MAX_FLUSH_GUARDS ops.
        const N: usize = 8;
        let mut client = test_client(N, 4096);
        for i in 0..N - 1 {
            client
                .fire_set_with_guard(KEY, VecGuard(vec![0u8; 64]), 0, 0, i as u64)
                .unwrap();
            assert!(
                client.write_guards.is_empty(),
                "op {i} must use the copy path, not the guard path"
            );
            assert_eq!(client.buffered_ops, i + 1);
        }
        assert_eq!(client.buffered_ops, N - 1);
        assert!(client.write_guards.is_empty());
    }
}
