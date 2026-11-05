//! ringline-native Memcache client for use inside the ringline async runtime.
//!
//! This client wraps a [`ringline::Connection`] and provides typed Memcache command
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
//! use ringline::Connection;
//! use ringline_memcache::Client;
//!
//! async fn example(conn: Connection) -> Result<(), ringline_memcache::Error> {
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
//! use ringline::Connection;
//! use ringline_memcache::{Client, CompletedOp};
//!
//! async fn pipelined_example(conn: Connection) -> Result<(), ringline_memcache::Error> {
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
pub use pool::{Pool, PoolConfig, PooledClient};
pub use sharded::{ShardedClient, ShardedConfig};

use std::collections::VecDeque;
use std::io;
use std::time::Instant;

use bytes::Bytes;
use memcache_proto::binary::BinaryRequest;
use memcache_proto::{Request as McRequest, ResponseBytes as McResponseBytes, ValueBytes};
use ringline::{
    Connection, GuardBox, ParseResult, RecvArrival, RecvHalf, RecvReadyFuture, SendGuard, SendHalf,
};

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
    /// Every pooled connection is currently checked out.
    ///
    /// Distinct from [`AllConnectionsFailed`](Self::AllConnectionsFailed):
    /// nothing failed and no connect was attempted. Drop a
    /// [`PooledClient`] or size the pool for the number of
    /// concurrent users.
    #[error("every pooled connection is checked out")]
    PoolExhausted,

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
#[non_exhaustive]
pub struct CommandResult {
    /// The command type.
    pub command: CommandType,
    /// Latency in nanoseconds (send → response parsed).
    pub latency_ns: u64,
    /// Nanoseconds from the start of `latency_ns` to the arrival of the
    /// response's first byte ([`RecvArrival::first`]). `None` if no byte was
    /// read, or if the byte arrived before the start.
    pub ttfb_ns: Option<u64>,
    /// Nanoseconds from the start of `latency_ns` to the arrival of the
    /// response's last byte ([`RecvArrival::last`]). `None` as for
    /// `ttfb_ns`.
    pub ttlb_ns: Option<u64>,
    /// For GET: `Some(true)` = hit, `Some(false)` = miss. `None` for others.
    pub hit: Option<bool>,
    /// Whether the command succeeded (no error response).
    pub success: bool,
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
    conn: Connection,
    on_result: Option<ResultCallback>,
    max_batch_size: usize,
    max_in_flight: usize,
    zc_threshold: u32,
    #[cfg(feature = "metrics")]
    with_metrics: bool,
}

impl ClientBuilder {
    pub(crate) fn new(conn: Connection) -> Self {
        Self {
            conn,
            on_result: None,
            max_batch_size: 1,
            max_in_flight: usize::MAX,
            zc_threshold: DEFAULT_ZC_THRESHOLD,
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

    /// Build a [`BinaryClient`] speaking the Memcache **binary** protocol.
    ///
    /// Requests are framed with the binary header (`BinaryRequest`) and
    /// responses parsed from the 24-byte binary header. Response/request
    /// correlation stays FIFO (opaque is set to 0), matching the ASCII path.
    /// Enables driving servers that only speak the binary protocol.
    ///
    /// The binary protocol implements the fire/recv pipelining API only, so
    /// this returns a [`BinaryClient`] rather than a [`Client`]: the ASCII
    /// request/response methods are simply absent from its surface instead of
    /// failing at runtime. Use [`build`](Self::build) for an ASCII [`Client`].
    ///
    /// Cannot fail; see [`Client::new`].
    pub fn build_binary(self) -> BinaryClient {
        let mut client = self.build();
        client.binary = true;
        BinaryClient { inner: client }
    }

    /// [`build_binary`](Self::build_binary) for the in-memory unit tests.
    #[cfg(test)]
    pub(crate) fn build_binary_for_test(self) -> BinaryClient {
        let mut client = self.build();
        client.binary = true;
        BinaryClient { inner: client }
    }

    /// Build the client.
    ///
    /// # Errors
    ///
    /// Same as [`Client::new`]: the read side must be free.
    pub fn build(self) -> Client {
        self.finish()
    }

    /// Assemble the client from the builder's fields.
    fn finish(self) -> Client {
        let Self {
            conn,
            on_result,
            max_batch_size,
            max_in_flight,
            zc_threshold,
            #[cfg(feature = "metrics")]
            with_metrics,
        } = self;
        let (tx, rx) = conn.split();
        Client {
            tx,
            rx,
            on_result,
            pending: VecDeque::with_capacity(16),
            write_buf: Vec::new(),
            write_guards: Vec::new(),
            flushed_count: 0,
            max_batch_size,
            max_in_flight,
            zc_threshold,
            binary: false,
            buffered_ops: 0,
            encode_buf: Vec::new(),
            #[cfg(feature = "metrics")]
            metrics: if with_metrics {
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
/// metrics. Use `Client::builder(conn)` to configure per-request callbacks
/// and built-in histogram tracking.
pub struct Client {
    tx: SendHalf,
    rx: RecvHalf,
    on_result: Option<ResultCallback>,
    pending: VecDeque<PendingOp>,
    /// Write buffer for coalescing `fire_*` commands. Contains all copy data
    /// (command framing, prefixes, suffixes, non-guard values). Guard values
    /// are stored separately in `write_guards` with byte offsets into this buffer.
    write_buf: Vec<u8>,
    /// Zero-copy guards pending flush. Each entry is `(offset, guard)` where
    /// `offset` is the byte position in `write_buf` where the guard value
    /// should be inserted in the byte stream.
    write_guards: Vec<(usize, GuardBox)>,
    /// Number of pending ops whose start time has been finalized (at flush time).
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
    /// Use the Memcache binary protocol (framing + parsing) instead of ASCII.
    binary: bool,
    /// Number of ops buffered in `write_buf` that have not yet been flushed.
    buffered_ops: usize,
    /// Reusable scratch buffer for encoding requests. Cleared before each
    /// use; keeps its capacity across requests so steady-state encoding is
    /// allocation-free.
    encode_buf: Vec<u8>,
    #[cfg(feature = "metrics")]
    metrics: Option<ClientMetrics>,
}

impl Client {
    /// Create a new client wrapping an established connection.
    ///
    /// No callbacks, no metrics — zero overhead.
    /// Cannot fail: a [`Connection`] already owns both halves (#528).
    pub fn new(conn: Connection) -> Self {
        let (tx, rx) = conn.split();
        Self {
            tx,
            rx,
            on_result: None,
            pending: VecDeque::new(),
            write_buf: Vec::new(),
            write_guards: Vec::new(),
            flushed_count: 0,
            max_batch_size: 1,
            max_in_flight: usize::MAX,
            zc_threshold: DEFAULT_ZC_THRESHOLD,
            binary: false,
            buffered_ops: 0,
            encode_buf: Vec::new(),
            #[cfg(feature = "metrics")]
            metrics: None,
        }
    }

    /// Create a builder for a client with per-request callbacks.
    pub fn builder(conn: Connection) -> ClientBuilder {
        ClientBuilder::new(conn)
    }

    /// Close the connection.
    pub fn close(&mut self) {
        self.tx.close();
    }

    /// This connection's [`ConnId`](ringline::ConnId).
    pub fn id(&self) -> ringline::ConnId {
        self.tx.id()
    }

    /// Is the connection still usable?
    pub fn is_alive(&self) -> bool {
        self.tx.is_alive()
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
    fn timing_start(&self) -> Option<Instant> {
        // Only read the clock if callbacks or metrics are configured.
        if self.is_instrumented() {
            Some(Instant::now())
        } else {
            None
        }
    }

    /// `timing_start()` for `fire_*` call sites, evaluated after the op has
    /// been buffered or sent. A buffered op (`buffered_ops >= 1`) gets its
    /// start time from `flush()`, which stamps every op it sends, so a clock
    /// read here would be discarded.
    #[inline]
    fn timing_start_buffered(&self) -> Option<Instant> {
        if self.buffered_ops >= 1 {
            None
        } else {
            self.timing_start()
        }
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
            self.tx
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
            self.tx
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

        // Stamp every op this flush sent. A buffered op got no start time
        // at fire time (see `timing_start_buffered`).
        if self.buffered_ops >= 1 {
            let start = self.timing_start();
            for pending in self.pending.iter_mut().skip(self.flushed_count) {
                pending.start = start;
            }
        }
        self.flushed_count = self.pending.len();

        self.write_buf.clear();
        self.write_guards.clear();
        self.buffered_ops = 0;

        Ok(())
    }

    /// Send any buffered `fire_*` requests, then return a future that resolves
    /// when bytes of the next reply have arrived or the connection has
    /// finished receiving.
    ///
    /// The future consumes nothing and does not borrow the client, so the
    /// caller can fire more requests while it is pending. A caller that sends
    /// while a reply is pending waits on this future together with its own
    /// source of requests: when a request is ready it calls `fire_*` and then
    /// `recv_ready` again, which flushes; when the future resolves it calls
    /// [`recv`](Self::recv), which then waits only for the rest of a reply
    /// that has started arriving. A caller that keeps one future pending
    /// across fires must call [`flush`](Self::flush) after firing, or a
    /// buffered request waits until a flush: the batch filling, a guarded
    /// fire that would pass the scatter-gather limit, or the next `flush`,
    /// `recv_ready` or `recv`.
    ///
    /// The future registers the task that polls it and does not use the
    /// `Context`'s waker, so it works in a `poll_fn` or a select that polls
    /// every branch on each wake, and never resolves under a combinator that
    /// re-polls only the child whose own waker fired, such as
    /// `FuturesUnordered`. Dropping it while pending loses no bytes.
    ///
    /// Returns `Err(Error::NoPending)` if no request is in flight after the
    /// flush, and the flush's error if the flush fails.
    pub fn recv_ready(&mut self) -> Result<RecvReadyFuture, Error> {
        self.flush()?;
        if self.pending.is_empty() {
            return Err(Error::NoPending);
        }
        Ok(self.rx.recv_ready())
    }

    /// Fire a GET request without waiting for the response.
    pub fn fire_get(&mut self, key: &[u8], user_data: u64) -> Result<(), Error> {
        self.pre_flush_if_needed(false)?;
        let tx_bytes;
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            // Direct send — skip write_buf round-trip.
            self.encode_buf.clear();
            append_get(self.binary, key, &mut self.encode_buf)?;
            tx_bytes = self.encode_buf.len() as u32;
            self.tx.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            append_get(self.binary, key, &mut self.write_buf)?;
            tx_bytes = (self.write_buf.len() - before) as u32;
            self.buffered_ops += 1;
        }
        let start = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Get,
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
        let tx_bytes;
        if self.max_batch_size == 1 && self.write_guards.is_empty() && self.write_buf.is_empty() {
            // Direct send — skip write_buf round-trip.
            self.encode_buf.clear();
            append_set(
                self.binary,
                key,
                value,
                flags,
                exptime,
                &mut self.encode_buf,
            )?;
            tx_bytes = self.encode_buf.len() as u32;
            self.tx.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            append_set(self.binary, key, value, flags, exptime, &mut self.write_buf)?;
            tx_bytes = (self.write_buf.len() - before) as u32;
            self.buffered_ops += 1;
        }
        let start = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Set,
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
        if self.binary {
            // Binary SET framing: header + 8-byte extras + key, then the guard
            // value follows zero-copy. No trailing CRLF (binary is length-framed).
            append_bin_set_guard_prefix(
                &mut self.write_buf,
                key,
                value_len as usize,
                flags,
                exptime,
            )?;
            self.write_guards
                .push((self.write_buf.len(), GuardBox::new(guard)));
        } else {
            append_set_guard_prefix(&mut self.write_buf, key, value_len as usize, flags, exptime)?;
            self.write_guards
                .push((self.write_buf.len(), GuardBox::new(guard)));
            self.write_buf.extend_from_slice(b"\r\n");
        }
        let tx_bytes = (self.write_buf.len() - before + value_len as usize) as u32;
        self.buffered_ops += 1;
        let start = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Set,
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
            append_delete(self.binary, key, &mut self.encode_buf)?;
            tx_bytes = self.encode_buf.len() as u32;
            self.tx.send_nowait(&self.encode_buf)?;
        } else {
            let before = self.write_buf.len();
            append_delete(self.binary, key, &mut self.write_buf)?;
            tx_bytes = (self.write_buf.len() - before) as u32;
            self.buffered_ops += 1;
        }
        let start = self.timing_start_buffered();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Delete,
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

        let (response, rx_bytes, arrival) = self.read_reply().await;
        let response = match response {
            Ok(v) => v,
            Err(e) => {
                // Connection is broken — clear remaining pending ops so
                // subsequent recv() calls return NoPending instead of
                // reading stale/misaligned responses. Reset `flushed_count`
                // too — otherwise a stale count > 0 makes the next batched
                // `flush()` skip the start-time rewrite for newly-buffered ops.
                self.pending.clear();
                self.flushed_count = 0;
                return Err(e);
            }
        };
        let latency_ns = match pending.start {
            Some(start) => elapsed_ns(start),
            None => 0,
        };
        let (ttfb_ns, ttlb_ns) = arrival_ns(arrival.as_ref(), pending.start);
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
                    ttfb_ns,
                    ttlb_ns,
                    hit,
                    success,
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
                    ttfb_ns,
                    ttlb_ns,
                    hit: None,
                    success: result.is_ok(),
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
                    ttfb_ns,
                    ttlb_ns,
                    hit: None,
                    success: result.is_ok(),
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
    pub(crate) async fn read_response(&mut self) -> Result<McResponseBytes, Error> {
        self.read_reply().await.0
    }

    /// [`read_response`](Self::read_response), with the bytes read and, on an
    /// instrumented client, their arrival times.
    async fn read_reply(&mut self) -> Reply<McResponseBytes> {
        let mut result: Option<Result<McResponseBytes, Error>> = None;
        let binary = self.binary;
        let n = self
            .rx
            .with_bytes(|bytes| {
                let len = bytes.len();
                if binary {
                    return match parse_binary_response(&bytes) {
                        Ok(Some((response, consumed))) => {
                            result = Some(Ok(response));
                            ParseResult::Consumed(consumed)
                        }
                        Ok(None) => ParseResult::Consumed(0),
                        Err(e) => {
                            result = Some(Err(Error::Protocol(e)));
                            ParseResult::Consumed(len)
                        }
                    };
                }
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
        let arrival = if n > 0 && self.is_instrumented() {
            self.rx.recv_arrival()
        } else {
            None
        };
        if n == 0 {
            return (result.unwrap_or(Err(Error::ConnectionClosed)), 0, arrival);
        }
        let r = result.unwrap();
        if matches!(r, Err(Error::Protocol(_))) {
            self.tx.close();
        }
        (r, n as u32, arrival)
    }

    /// Send an already-encoded command on this client's write half.
    ///
    /// Lets the sharded/cluster routers do their one send *through the client*
    /// they are about to build anyway, instead of taking the connection's write
    /// half separately first — which cost an extra driver round trip and a
    /// redundant claim set/clear on the per-command path.
    pub(crate) fn send_raw(&mut self, encoded: &[u8]) -> Result<(), Error> {
        self.tx.send(encoded)?;
        Ok(())
    }

    /// Send an encoded command and read the response, converting error
    /// responses into `Error::Memcache`.
    async fn execute(&mut self, encoded: &[u8]) -> Result<McResponseBytes, Error> {
        self.tx.send(encoded)?;
        let response = self.read_response().await?;
        check_error_bytes(&response)?;
        Ok(response)
    }

    /// Like [`Client::execute`], but sends the reusable `encode_buf` in place.
    ///
    /// `self.execute(&self.encode_buf)` no longer type-checks: reading now
    /// needs `&mut self`, so passing a borrow of one of `self`'s own fields as
    /// the argument holds an immutable borrow of all of `self` across the
    /// call. Borrowing `tx` and `encode_buf` as separate fields *inside* the
    /// method is disjoint, so the scratch buffer keeps being reused — no copy
    /// and no per-op allocation, which is the whole point of `encode_buf`.
    async fn execute_encoded(&mut self) -> Reply<McResponseBytes> {
        if let Err(e) = self.tx.send(&self.encode_buf) {
            return (Err(e.into()), 0, None);
        }
        let (result, rx_bytes, arrival) = self.read_reply().await;
        let result = result.and_then(|r| check_error_bytes(&r).map(|()| r));
        (result, rx_bytes, arrival)
    }

    // -- Commands (instrumented hot-path) ---------------------------------

    /// Get the value of a key. Returns `None` on cache miss.
    pub async fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Value>, Error> {
        let key = key.as_ref();
        self.encode_buf.clear();
        encode_request_into(&McRequest::get(key), &mut self.encode_buf)?;

        if !self.is_instrumented() {
            let response = self.execute_encoded().await.0?;
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
        let start = Instant::now();
        let (response, rx_bytes, arrival) = self.execute_encoded().await;
        let latency_ns = elapsed_ns(start);
        let (ttfb_ns, ttlb_ns) = arrival_ns(arrival.as_ref(), Some(start));

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
            ttfb_ns,
            ttlb_ns,
            hit,
            success,
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
            let response = self.execute_encoded().await.0?;
            return match response {
                McResponseBytes::Stored => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let tx_bytes = self.encode_buf.len() as u32;
        let start = Instant::now();
        let (response, rx_bytes, arrival) = self.execute_encoded().await;
        let latency_ns = elapsed_ns(start);
        let (ttfb_ns, ttlb_ns) = arrival_ns(arrival.as_ref(), Some(start));

        let result = match response {
            Ok(McResponseBytes::Stored) => Ok(()),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Set,
            latency_ns,
            ttfb_ns,
            ttlb_ns,
            hit: None,
            success: result.is_ok(),
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
            let response = self.execute_encoded().await.0?;
            return match response {
                McResponseBytes::Deleted => Ok(true),
                McResponseBytes::NotFound => Ok(false),
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let tx_bytes = self.encode_buf.len() as u32;
        let start = Instant::now();
        let (response, rx_bytes, arrival) = self.execute_encoded().await;
        let latency_ns = elapsed_ns(start);
        let (ttfb_ns, ttlb_ns) = arrival_ns(arrival.as_ref(), Some(start));

        let result = match response {
            Ok(McResponseBytes::Deleted) => Ok(true),
            Ok(McResponseBytes::NotFound) => Ok(false),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Delete,
            latency_ns,
            ttfb_ns,
            ttlb_ns,
            hit: None,
            success: result.is_ok(),
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
            self.tx.send_parts().build(move |b| {
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

        let start = Instant::now();

        let prefix: &[u8] = &self.encode_buf;
        let sent = self.tx.send_parts().build(move |b| {
            b.copy(prefix)
                .guard(GuardBox::new(guard))
                .copy(b"\r\n")
                .submit()
        });

        // A send error is recorded too, with nothing read.
        let (response, rx_bytes, arrival) = match sent {
            Ok(_) => self.read_reply().await,
            Err(e) => (Err(e.into()), 0, None),
        };
        let latency_ns = elapsed_ns(start);
        let (ttfb_ns, ttlb_ns) = arrival_ns(arrival.as_ref(), Some(start));

        // A read error and an error reply are recorded as failures.
        let result = response.and_then(|r| {
            check_error_bytes(&r)?;
            match r {
                McResponseBytes::Stored => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            }
        });
        self.record(&CommandResult {
            command: CommandType::Set,
            latency_ns,
            ttfb_ns,
            ttlb_ns,
            hit: None,
            success: result.is_ok(),
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
    /// via [`SendHalf::send`](ringline::SendHalf::send) (awaited per chunk for
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
                self.tx.close();
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
        self.tx.send_nowait(&self.encode_buf)?;

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
            self.tx.send(&chunk)?.await?;
        }
        if sent != len {
            // Under-produce: header declared `len`, source gave fewer → desync.
            return Err(Error::LengthMismatch);
        }

        // Trailing `\r\n`, then the `STORED\r\n` reply.
        self.tx.send_nowait(b"\r\n")?;
        self.read_response().await
    }
}

/// A Memcache client speaking the **binary** protocol.
///
/// Built with [`ClientBuilder::build_binary`]. The binary protocol implements
/// the fire/recv pipelining API only, so that is exactly the surface this type
/// exposes — the ASCII request/response methods (`get`, `set`, `delete`, the
/// arithmetic and streaming methods) are absent rather than failing at
/// runtime. Framing and parsing are otherwise identical in shape to
/// [`Client`]: requests carry the binary header, responses are parsed from the
/// 24-byte binary header, and correlation stays FIFO (opaque is always 0).
///
/// ```no_run
/// # use ringline_memcache::{Client, Error};
/// # async fn demo(conn: ringline::Connection) -> Result<(), Error> {
/// let mut client = Client::builder(conn).max_batch_size(16).build_binary();
/// client.fire_get(b"key", 1)?;
/// let op = client.recv().await?;
/// # Ok(())
/// # }
/// ```
///
/// This client owns the connection outright: it holds both halves, so there is
/// no way to hand the connection back out and drive it with an ASCII
/// [`Client`].
pub struct BinaryClient {
    inner: Client,
}

impl BinaryClient {
    /// Close the connection.
    pub fn close(&mut self) {
        self.inner.close();
    }

    /// This connection's [`ConnId`](ringline::ConnId).
    pub fn id(&self) -> ringline::ConnId {
        self.inner.id()
    }

    /// Is the connection still usable?
    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    /// Returns the metrics collector, if `with_metrics` was set on the builder.
    #[cfg(feature = "metrics")]
    pub fn metrics(&self) -> Option<&ClientMetrics> {
        self.inner.metrics()
    }

    /// Returns a mutable reference to the metrics collector, if enabled.
    #[cfg(feature = "metrics")]
    pub fn metrics_mut(&mut self) -> Option<&mut ClientMetrics> {
        self.inner.metrics_mut()
    }

    /// Number of fired requests still awaiting [`recv`](Self::recv).
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }

    /// Flush any buffered `fire_*` commands.
    pub fn flush(&mut self) -> Result<(), Error> {
        self.inner.flush()
    }

    /// Send any buffered `fire_*` commands, then return a future that
    /// resolves when bytes of the next response have arrived. See
    /// [`Client::recv_ready`].
    pub fn recv_ready(&mut self) -> Result<RecvReadyFuture, Error> {
        self.inner.recv_ready()
    }

    /// Fire a GET without waiting for the response.
    pub fn fire_get(&mut self, key: &[u8], user_data: u64) -> Result<(), Error> {
        self.inner.fire_get(key, user_data)
    }

    /// Fire a SET without waiting for the response.
    pub fn fire_set(
        &mut self,
        key: &[u8],
        value: &[u8],
        flags: u32,
        exptime: u32,
        user_data: u64,
    ) -> Result<(), Error> {
        self.inner.fire_set(key, value, flags, exptime, user_data)
    }

    /// Fire a SET whose value stays in place behind a [`SendGuard`].
    ///
    /// Values below the client's `zc_threshold` fold into the coalescing copy
    /// buffer instead of taking the scatter-gather path, as for [`Client`].
    pub fn fire_set_with_guard<G: SendGuard>(
        &mut self,
        key: &[u8],
        guard: G,
        flags: u32,
        exptime: u32,
        user_data: u64,
    ) -> Result<(), Error> {
        self.inner
            .fire_set_with_guard(key, guard, flags, exptime, user_data)
    }

    /// Fire a DELETE without waiting for the response.
    pub fn fire_delete(&mut self, key: &[u8], user_data: u64) -> Result<(), Error> {
        self.inner.fire_delete(key, user_data)
    }

    /// Receive the next response, in FIFO order with the fired requests.
    pub async fn recv(&mut self) -> Result<CompletedOp, Error> {
        self.inner.recv().await
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

// ── Binary protocol helpers ─────────────────────────────────────────────
//
// These append a binary-framed request when `binary` is set, otherwise fall
// back to the ASCII `encode_request_into`. Opaque is always 0: the client
// correlates responses to requests by FIFO order (the `pending` queue), the
// same way it does for ASCII, so per-request opaque tagging is unnecessary.
//
// Each binary branch validates the key itself (the ASCII branch gets this
// from `encode_request_into` -> `validate_request`). Binary framing writes
// the key length into a `u16` header field, so an unchecked key is worse
// here than in ASCII: at >= 64 KiB the length wraps while the full key still
// goes on the wire, desyncing the stream permanently. Validation runs before
// any bytes are appended, so a rejected request leaves `buf` untouched.

#[inline]
fn append_get(binary: bool, key: &[u8], buf: &mut Vec<u8>) -> Result<(), Error> {
    if binary {
        validate_key(key)?;
        let start = buf.len();
        buf.resize(start + memcache_proto::binary::HEADER_SIZE + key.len(), 0);
        let n = BinaryRequest::encode_get(&mut buf[start..], key, 0);
        buf.truncate(start + n);
        Ok(())
    } else {
        encode_request_into(&McRequest::get(key), buf)
    }
}

#[inline]
fn append_set(
    binary: bool,
    key: &[u8],
    value: &[u8],
    flags: u32,
    exptime: u32,
    buf: &mut Vec<u8>,
) -> Result<(), Error> {
    if binary {
        validate_key(key)?;
        let start = buf.len();
        buf.resize(
            start + memcache_proto::binary::HEADER_SIZE + 8 + key.len() + value.len(),
            0,
        );
        let n = BinaryRequest::encode_set(&mut buf[start..], key, value, flags, exptime, 0, 0);
        buf.truncate(start + n);
        Ok(())
    } else {
        encode_request_into(
            &McRequest::Set {
                key,
                value,
                flags,
                exptime,
            },
            buf,
        )
    }
}

#[inline]
fn append_delete(binary: bool, key: &[u8], buf: &mut Vec<u8>) -> Result<(), Error> {
    if binary {
        validate_key(key)?;
        let start = buf.len();
        buf.resize(start + memcache_proto::binary::HEADER_SIZE + key.len(), 0);
        let n = BinaryRequest::encode_delete(&mut buf[start..], key, 0, 0);
        buf.truncate(start + n);
        Ok(())
    } else {
        encode_request_into(&McRequest::delete(key), buf)
    }
}

/// Append a binary SET header + 8-byte extras (flags, expiration) + key, with
/// `total_body_length` sized for the value that follows zero-copy via a guard.
/// Binary is length-framed, so there is no trailing CRLF.
///
/// Validates `key` (≤ [`MAX_KEY_LEN`]) before appending, mirroring
/// [`append_set_guard_prefix`]: returns [`Error::KeyTooLong`] with nothing
/// appended to `buf`, so no partial frame can reach the wire.
fn append_bin_set_guard_prefix(
    buf: &mut Vec<u8>,
    key: &[u8],
    value_len: usize,
    flags: u32,
    exptime: u32,
) -> Result<(), Error> {
    validate_key(key)?;
    const HDR: usize = memcache_proto::binary::HEADER_SIZE;
    let total_body = 8 + key.len() + value_len;
    let mut h = [0u8; HDR];
    h[0] = memcache_proto::binary::REQUEST_MAGIC;
    h[1] = 0x01; // Set opcode
    h[2..4].copy_from_slice(&(key.len() as u16).to_be_bytes());
    h[4] = 8; // extras length
    h[8..12].copy_from_slice(&(total_body as u32).to_be_bytes());
    buf.extend_from_slice(&h);
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&exptime.to_be_bytes());
    buf.extend_from_slice(key);
    Ok(())
}

/// Parse one binary response from `bytes`, mapping it into the ASCII
/// `McResponseBytes` representation so recv/timing/callbacks stay
/// protocol-agnostic. `Ok(None)` = need more bytes; `Err` = framing error
/// (terminal — the caller closes the connection).
fn parse_binary_response(
    bytes: &bytes::Bytes,
) -> Result<Option<(McResponseBytes, usize)>, memcache_proto::ParseError> {
    const HDR: usize = memcache_proto::binary::HEADER_SIZE;
    if bytes.len() < HDR {
        return Ok(None);
    }
    let b = &bytes[..];
    if b[0] != memcache_proto::binary::RESPONSE_MAGIC {
        return Err(memcache_proto::ParseError::Protocol(
            "invalid binary response magic",
        ));
    }
    let opcode = b[1];
    let key_len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let extras_len = b[4] as usize;
    let status = u16::from_be_bytes([b[6], b[7]]);
    let total_body = u32::from_be_bytes([b[8], b[9], b[10], b[11]]) as usize;
    let total = HDR + total_body;
    if bytes.len() < total {
        return Ok(None);
    }
    if extras_len + key_len > total_body {
        return Err(memcache_proto::ParseError::Protocol(
            "binary header lengths exceed body",
        ));
    }
    let resp = if status == 0 {
        match opcode {
            0x00 => {
                let flags = if extras_len >= 4 {
                    u32::from_be_bytes([b[HDR], b[HDR + 1], b[HDR + 2], b[HDR + 3]])
                } else {
                    0
                };
                let vstart = HDR + extras_len + key_len;
                McResponseBytes::Values(vec![ValueBytes {
                    key: bytes::Bytes::new(),
                    flags,
                    data: bytes.slice(vstart..total),
                    cas: None,
                }])
            }
            0x01 => McResponseBytes::Stored,
            0x04 => McResponseBytes::Deleted,
            _ => McResponseBytes::Ok,
        }
    } else {
        match (opcode, status) {
            (0x00, 0x0001) => McResponseBytes::Values(vec![]),
            (0x04, 0x0001) => McResponseBytes::NotFound,
            _ => McResponseBytes::ServerError(bytes.slice(HDR + extras_len + key_len..total)),
        }
    };
    Ok(Some((resp, total)))
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

// ── Timing helper ──────────────────────────────────────────────────────────

/// Nanoseconds elapsed since `start`.
#[inline]
fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos() as u64
}

/// A reply read from the connection: the result, the bytes read, and, on an
/// instrumented client, the arrival times of those bytes. An operation that
/// fails before it reads has 0 bytes and no arrival.
type Reply<T> = (Result<T, Error>, u32, Option<RecvArrival>);

/// Nanoseconds from `start` to the arrival of the first and of the last
/// response byte, for [`CommandResult::ttfb_ns`] and
/// [`CommandResult::ttlb_ns`]. `None` when there is no arrival or no start,
/// or for a time before the start.
fn arrival_ns(arrival: Option<&RecvArrival>, start: Option<Instant>) -> (Option<u64>, Option<u64>) {
    let since = |t: Instant| {
        start
            .and_then(|start| t.checked_duration_since(start))
            .map(|d| d.as_nanos() as u64)
    };
    match arrival {
        Some(a) => (since(a.first()), since(a.last())),
        None => (None, None),
    }
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
    use ringline::{RegionId, SendGuard};

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

    /// A `Client` backed by a dangling `Connection`. Only safe for tests that
    /// stay in the buffered path (no flush, no direct send, no recv).
    fn test_client(max_batch_size: usize, zc_threshold: u32) -> Client {
        let conn = ringline::Connection::for_test(0, 0);
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

#[cfg(test)]
mod binary_tests {
    use super::*;
    use ringline::{RegionId, SendGuard};

    const KEY: &[u8] = b"user:123456789";
    const HDR: usize = memcache_proto::binary::HEADER_SIZE;

    /// Heap-backed guard for tests (see `zc_threshold_tests::VecGuard`).
    struct VecGuard(Vec<u8>);

    impl SendGuard for VecGuard {
        fn as_ptr_len(&self) -> (*const u8, u32) {
            (self.0.as_ptr(), self.0.len() as u32)
        }
        fn region(&self) -> RegionId {
            RegionId::UNREGISTERED
        }
    }

    /// A [`BinaryClient`] backed by a dangling `Connection`. A
    /// `max_batch_size` above 1 keeps every `fire_*` in the buffered path (no
    /// direct send, no recv), the only path safe to exercise without a live
    /// connection.
    fn binary_client(max_batch_size: usize, zc_threshold: u32) -> BinaryClient {
        Client::builder(ringline::Connection::for_test(0, 0))
            .max_batch_size(max_batch_size)
            .zc_threshold(zc_threshold)
            .build_binary_for_test()
    }

    fn long_key() -> Vec<u8> {
        vec![b'k'; MAX_KEY_LEN + 1]
    }

    // ── Key validation parity with the ASCII path ───────────────────────
    //
    // `MAX_KEY_LEN` / `Error::KeyTooLong` is documented public behavior. It
    // must hold in binary mode too: the binary encoders write the key length
    // as a `u16`, so a key that is merely over-long wastes a round trip, and
    // a key >= 64 KiB truncates the header length while the full key still
    // goes on the wire — desyncing the connection permanently.

    #[test]
    fn binary_get_rejects_long_key() {
        let mut client = binary_client(4, 4096);
        assert!(matches!(
            client.fire_get(&long_key(), 1),
            Err(Error::KeyTooLong)
        ));
    }

    #[test]
    fn binary_set_rejects_long_key() {
        let mut client = binary_client(4, 4096);
        assert!(matches!(
            client.fire_set(&long_key(), b"v", 0, 0, 1),
            Err(Error::KeyTooLong)
        ));
    }

    #[test]
    fn binary_delete_rejects_long_key() {
        let mut client = binary_client(4, 4096);
        assert!(matches!(
            client.fire_delete(&long_key(), 1),
            Err(Error::KeyTooLong)
        ));
    }

    #[test]
    fn binary_guarded_set_rejects_long_key() {
        // zc_threshold = 0 forces the guard path (no fold into fire_set).
        let mut client = binary_client(4, 0);
        assert!(matches!(
            client.fire_set_with_guard(&long_key(), VecGuard(vec![0u8; 64]), 0, 0, 1),
            Err(Error::KeyTooLong)
        ));
    }

    #[test]
    fn binary_rejected_request_appends_no_bytes() {
        // A rejected request must leave no partial frame in write_buf, and
        // must not register a guard or a pending op — otherwise the next
        // flush ships a corrupt frame and recv() desyncs.
        let mut client = binary_client(4, 0);
        client.fire_get(KEY, 1).unwrap();
        let clean = client.inner.write_buf.clone();

        assert!(client.fire_get(&long_key(), 2).is_err());
        assert!(client.fire_set(&long_key(), b"v", 0, 0, 3).is_err());
        assert!(client.fire_delete(&long_key(), 4).is_err());
        assert!(
            client
                .fire_set_with_guard(&long_key(), VecGuard(vec![0u8; 64]), 0, 0, 5)
                .is_err()
        );

        assert_eq!(
            client.inner.write_buf, clean,
            "no partial frame may be appended"
        );
        assert!(client.inner.write_guards.is_empty());
        assert_eq!(client.inner.buffered_ops, 1);
        assert_eq!(client.inner.pending.len(), 1);
    }

    #[test]
    fn binary_accepts_max_len_key() {
        let key = vec![b'k'; MAX_KEY_LEN];
        let mut client = binary_client(4, 4096);
        client.fire_get(&key, 1).unwrap();
        client.fire_set(&key, b"v", 0, 0, 2).unwrap();
        client.fire_delete(&key, 3).unwrap();
        assert_eq!(client.inner.buffered_ops, 3);
    }

    // ── Request framing ─────────────────────────────────────────────────
    //
    // These pin the on-wire bytes of the binary encoders. The client talks to
    // real binary-protocol servers, so header field placement is a wire
    // contract, not an implementation detail.

    /// Decode the fixed header fields of a request frame for assertions.
    fn hdr(buf: &[u8]) -> (u8, u8, usize, usize, usize) {
        (
            buf[0],
            buf[1],
            u16::from_be_bytes([buf[2], buf[3]]) as usize,
            buf[4] as usize,
            u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize,
        )
    }

    #[test]
    fn binary_get_frames_header_then_key() {
        let mut buf = Vec::new();
        append_get(true, KEY, &mut buf).unwrap();
        let (magic, opcode, key_len, extras_len, total_body) = hdr(&buf);
        assert_eq!(magic, memcache_proto::binary::REQUEST_MAGIC);
        assert_eq!(opcode, 0x00, "Get opcode");
        assert_eq!(key_len, KEY.len());
        assert_eq!(extras_len, 0, "Get carries no extras");
        assert_eq!(total_body, KEY.len());
        assert_eq!(&buf[HDR..], KEY);
        assert_eq!(buf.len(), HDR + total_body);
    }

    #[test]
    fn binary_delete_frames_header_then_key() {
        let mut buf = Vec::new();
        append_delete(true, KEY, &mut buf).unwrap();
        let (magic, opcode, key_len, extras_len, total_body) = hdr(&buf);
        assert_eq!(magic, memcache_proto::binary::REQUEST_MAGIC);
        assert_eq!(opcode, 0x04, "Delete opcode");
        assert_eq!(key_len, KEY.len());
        assert_eq!(extras_len, 0);
        assert_eq!(total_body, KEY.len());
        assert_eq!(&buf[HDR..], KEY);
    }

    #[test]
    fn binary_set_frames_extras_key_and_value() {
        let value = b"hello world";
        let mut buf = Vec::new();
        append_set(true, KEY, value, 7, 42, &mut buf).unwrap();
        let (magic, opcode, key_len, extras_len, total_body) = hdr(&buf);
        assert_eq!(magic, memcache_proto::binary::REQUEST_MAGIC);
        assert_eq!(opcode, 0x01, "Set opcode");
        assert_eq!(key_len, KEY.len());
        assert_eq!(extras_len, 8, "Set extras are flags + expiration");
        assert_eq!(total_body, 8 + KEY.len() + value.len());
        assert_eq!(buf.len(), HDR + total_body);
        // Extras are flags then expiration, both big-endian.
        assert_eq!(&buf[HDR..HDR + 4], &7u32.to_be_bytes());
        assert_eq!(&buf[HDR + 4..HDR + 8], &42u32.to_be_bytes());
        assert_eq!(&buf[HDR + 8..HDR + 8 + KEY.len()], KEY);
        assert_eq!(&buf[HDR + 8 + KEY.len()..], value);
    }

    #[test]
    fn binary_appends_leave_existing_bytes_untouched() {
        // The coalescing layer appends commands back-to-back into write_buf.
        let mut buf = b"EXISTING".to_vec();
        append_get(true, KEY, &mut buf).unwrap();
        assert_eq!(&buf[..8], b"EXISTING");
        assert_eq!(buf.len(), 8 + HDR + KEY.len());
    }

    #[test]
    fn binary_guarded_set_prefix_matches_a_plain_binary_set() {
        // The guard path emits header+extras+key and lets the guarded value
        // follow zero-copy. Prefix ++ value must be byte-identical to the
        // copy-path encoding of the same SET, or the two paths disagree on
        // the wire. (ASCII pins the same invariant in zc_threshold_tests.)
        let value = vec![0xABu8; 8192];

        let mut guarded = Vec::new();
        append_bin_set_guard_prefix(&mut guarded, KEY, value.len(), 7, 42).unwrap();
        guarded.extend_from_slice(&value);

        let mut plain = Vec::new();
        append_set(true, KEY, &value, 7, 42, &mut plain).unwrap();

        assert_eq!(guarded, plain);
    }

    #[test]
    fn binary_guarded_set_declares_the_full_body_length() {
        // total_body must account for the value that follows via the guard,
        // even though those bytes never enter write_buf.
        let mut buf = Vec::new();
        append_bin_set_guard_prefix(&mut buf, KEY, 8192, 0, 0).unwrap();
        let (_, opcode, key_len, extras_len, total_body) = hdr(&buf);
        assert_eq!(opcode, 0x01);
        assert_eq!(key_len, KEY.len());
        assert_eq!(extras_len, 8);
        assert_eq!(total_body, 8 + KEY.len() + 8192);
        assert_eq!(buf.len(), HDR + 8 + KEY.len(), "value is not copied in");
        assert!(!buf.ends_with(b"\r\n"), "binary is length-framed, no CRLF");
    }

    #[test]
    fn binary_guarded_set_splices_the_guard_after_the_key() {
        let mut client = binary_client(4, 4096);
        client
            .fire_set_with_guard(KEY, VecGuard(vec![0u8; 8192]), 0, 0, 1)
            .unwrap();
        assert_eq!(client.inner.write_guards.len(), 1);
        assert_eq!(client.inner.write_guards[0].0, HDR + 8 + KEY.len());
    }

    // ── Response parsing ────────────────────────────────────────────────

    /// Build a binary response frame.
    fn resp(opcode: u8, status: u16, extras: &[u8], key: &[u8], value: &[u8]) -> bytes::Bytes {
        let total_body = extras.len() + key.len() + value.len();
        let mut b = vec![0u8; HDR];
        b[0] = memcache_proto::binary::RESPONSE_MAGIC;
        b[1] = opcode;
        b[2..4].copy_from_slice(&(key.len() as u16).to_be_bytes());
        b[4] = extras.len() as u8;
        b[6..8].copy_from_slice(&status.to_be_bytes());
        b[8..12].copy_from_slice(&(total_body as u32).to_be_bytes());
        b.extend_from_slice(extras);
        b.extend_from_slice(key);
        b.extend_from_slice(value);
        bytes::Bytes::from(b)
    }

    #[test]
    fn parse_get_hit_yields_value_and_flags() {
        let frame = resp(0x00, 0, &7u32.to_be_bytes(), b"", b"payload");
        let (r, consumed) = parse_binary_response(&frame).unwrap().unwrap();
        assert_eq!(consumed, frame.len());
        match r {
            McResponseBytes::Values(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].flags, 7);
                assert_eq!(&v[0].data[..], b"payload");
                assert!(v[0].cas.is_none());
            }
            other => panic!("expected Values, got {other:?}"),
        }
    }

    #[test]
    fn parse_get_miss_yields_empty_values() {
        // KEY_ENOENT (0x0001) on a Get is a miss, not an error.
        let frame = resp(0x00, 0x0001, b"", b"", b"Not found");
        let (r, consumed) = parse_binary_response(&frame).unwrap().unwrap();
        assert_eq!(consumed, frame.len());
        assert!(matches!(r, McResponseBytes::Values(v) if v.is_empty()));
    }

    #[test]
    fn parse_set_success_yields_stored() {
        let frame = resp(0x01, 0, b"", b"", b"");
        let (r, consumed) = parse_binary_response(&frame).unwrap().unwrap();
        assert_eq!(consumed, HDR);
        assert!(matches!(r, McResponseBytes::Stored));
    }

    #[test]
    fn parse_delete_success_yields_deleted() {
        let frame = resp(0x04, 0, b"", b"", b"");
        let (r, _) = parse_binary_response(&frame).unwrap().unwrap();
        assert!(matches!(r, McResponseBytes::Deleted));
    }

    #[test]
    fn parse_delete_miss_yields_not_found() {
        let frame = resp(0x04, 0x0001, b"", b"", b"Not found");
        let (r, _) = parse_binary_response(&frame).unwrap().unwrap();
        assert!(matches!(r, McResponseBytes::NotFound));
    }

    #[test]
    fn parse_error_status_yields_server_error_with_body() {
        // A non-zero status that is not a documented miss carries the
        // server's error text as the body.
        let frame = resp(0x01, 0x0004, b"", b"", b"Invalid arguments");
        let (r, _) = parse_binary_response(&frame).unwrap().unwrap();
        match r {
            McResponseBytes::ServerError(msg) => assert_eq!(&msg[..], b"Invalid arguments"),
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn parse_needs_more_on_partial_header() {
        let frame = resp(0x01, 0, b"", b"", b"");
        for n in 0..HDR {
            assert!(
                parse_binary_response(&frame.slice(..n)).unwrap().is_none(),
                "{n} header bytes must not parse"
            );
        }
    }

    #[test]
    fn parse_needs_more_on_partial_body() {
        let frame = resp(0x00, 0, &[0u8; 4], b"", b"payload");
        for n in HDR..frame.len() {
            assert!(
                parse_binary_response(&frame.slice(..n)).unwrap().is_none(),
                "{n} of {} bytes must not parse",
                frame.len()
            );
        }
        assert!(parse_binary_response(&frame).unwrap().is_some());
    }

    #[test]
    fn parse_consumes_exactly_one_frame_when_pipelined() {
        // Responses arrive coalesced; the parser must stop after frame one so
        // FIFO correlation with the pending queue stays aligned.
        let first = resp(0x01, 0, b"", b"", b"");
        let second = resp(0x04, 0, b"", b"", b"");
        let mut both = first.to_vec();
        both.extend_from_slice(&second);
        let joined = bytes::Bytes::from(both);

        let (r, consumed) = parse_binary_response(&joined).unwrap().unwrap();
        assert!(matches!(r, McResponseBytes::Stored));
        assert_eq!(consumed, first.len());

        let (r2, _) = parse_binary_response(&joined.slice(consumed..))
            .unwrap()
            .unwrap();
        assert!(matches!(r2, McResponseBytes::Deleted));
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut b = resp(0x01, 0, b"", b"", b"").to_vec();
        b[0] = 0x80; // request magic where a response magic belongs
        assert!(parse_binary_response(&bytes::Bytes::from(b)).is_err());
    }

    #[test]
    fn parse_rejects_lengths_exceeding_body() {
        // key_len + extras_len > total_body would slice out of range.
        let mut b = resp(0x00, 0, b"", b"", b"payload").to_vec();
        b[2..4].copy_from_slice(&999u16.to_be_bytes());
        assert!(parse_binary_response(&bytes::Bytes::from(b)).is_err());
    }

    // ── The binary surface is enforced by the type system ───────────────
    //
    // `build_binary` yields a `BinaryClient`, which exposes only the fire/recv
    // API. The ASCII request/response methods are absent from that type, so a
    // protocol mix-up (ASCII on the wire, binary parse on the way back) is a
    // compile error rather than a runtime failure. These tests pin the two
    // halves of that split.

    #[test]
    fn build_binary_yields_a_binary_client() {
        let c = binary_client(4, 4096);
        assert!(c.inner.binary, "build_binary must set the binary flag");
    }

    #[test]
    fn build_yields_an_ascii_client() {
        // The flag must not leak into the plain `build()` path.
        let c = Client::builder(ringline::Connection::for_test(0, 0))
            .max_batch_size(4)
            .build();
        assert!(!c.binary);
        let mut buf = Vec::new();
        append_get(c.binary, KEY, &mut buf).unwrap();
        assert!(buf.starts_with(b"get "), "ASCII mode still encodes ASCII");
    }

    #[test]
    fn binary_client_exposes_the_fire_recv_api() {
        let mut c = binary_client(8, 4096);
        c.fire_get(KEY, 1).unwrap();
        c.fire_set(KEY, b"v", 0, 0, 2).unwrap();
        c.fire_delete(KEY, 3).unwrap();
        c.fire_set_with_guard(KEY, VecGuard(vec![0u8; 8192]), 0, 0, 4)
            .unwrap();
        assert_eq!(c.pending_count(), 4);
    }
}
