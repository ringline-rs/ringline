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

    /// Value exceeds memcache's default `-I` 1 MiB cap ([`MAX_VALUE_LEN`]).
    /// Same rationale as [`Error::KeyTooLong`].
    #[error("value too long (max 1048576 bytes)")]
    ValueTooLong,
}

/// Maximum key length per memcache text-protocol spec.
pub const MAX_KEY_LEN: usize = 250;

/// Maximum value length matching the parser cap in `memcache-proto`
/// (`MAX_VALUE_DATA_LEN`) and memcached's default `-I` 1 MiB item size.
pub const MAX_VALUE_LEN: usize = 1024 * 1024;

#[inline]
fn validate_key(key: &[u8]) -> Result<(), Error> {
    if key.len() > MAX_KEY_LEN {
        Err(Error::KeyTooLong)
    } else {
        Ok(())
    }
}

#[inline]
fn validate_value(value: &[u8]) -> Result<(), Error> {
    if value.len() > MAX_VALUE_LEN {
        Err(Error::ValueTooLong)
    } else {
        Ok(())
    }
}

#[inline]
fn validate_value_len(value_len: usize) -> Result<(), Error> {
    if value_len > MAX_VALUE_LEN {
        Err(Error::ValueTooLong)
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
    max_in_flight: usize,
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
            max_in_flight: usize::MAX,
            #[cfg(feature = "timestamps")]
            use_kernel_ts: false,
            #[cfg(feature = "metrics")]
            with_metrics: false,
        }
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
            max_in_flight: self.max_in_flight,
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
    /// Cap on `pending.len()`; `fire_*` returns `Error::TooManyInFlight`
    /// past it. `usize::MAX` (default) disables.
    max_in_flight: usize,
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
            max_in_flight: usize::MAX,
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

    /// Returns `Err(TooManyInFlight)` if the pending queue has hit
    /// `max_in_flight`. Called at the start of every `fire_*` to enforce
    /// the cap and bail before doing any encode / send work.
    #[inline]
    fn check_in_flight(&self) -> Result<(), Error> {
        if self.pending.len() >= self.max_in_flight {
            Err(Error::TooManyInFlight)
        } else {
            Ok(())
        }
    }

    /// Fire a GET request without waiting for the response.
    pub fn fire_get(&mut self, key: &[u8], user_data: u64) -> Result<(), Error> {
        self.check_in_flight()?;
        self.encode_buf.clear();
        encode_request_into(&McRequest::get(key), &mut self.encode_buf)?;
        let tx_bytes = self.encode_buf.len() as u32;
        self.conn.send_nowait(&self.encode_buf)?;
        let (send_ts, start) = self.timing_start();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Get,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
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
        self.check_in_flight()?;
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
        let tx_bytes = self.encode_buf.len() as u32;
        self.conn.send_nowait(&self.encode_buf)?;
        let (send_ts, start) = self.timing_start();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Set,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
        Ok(())
    }

    /// Fire a SET request with zero-copy value via SendGuard.
    pub fn fire_set_with_guard<G: SendGuard>(
        &mut self,
        key: &[u8],
        guard: G,
        flags: u32,
        exptime: u32,
        user_data: u64,
    ) -> Result<(), Error> {
        self.check_in_flight()?;
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
        let prefix: &[u8] = &self.encode_buf;
        self.conn.send_parts().build(move |b| {
            b.copy(prefix)
                .guard(GuardBox::new(guard))
                .copy(b"\r\n")
                .submit()
        })?;
        let (send_ts, start) = self.timing_start();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Set,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
        Ok(())
    }

    /// Fire a DELETE request without waiting for the response.
    pub fn fire_delete(&mut self, key: &[u8], user_data: u64) -> Result<(), Error> {
        self.check_in_flight()?;
        self.encode_buf.clear();
        encode_request_into(&McRequest::delete(key), &mut self.encode_buf)?;
        let tx_bytes = self.encode_buf.len() as u32;
        self.conn.send_nowait(&self.encode_buf)?;
        let (send_ts, start) = self.timing_start();
        self.pending.push_back(PendingOp {
            kind: PendingOpKind::Delete,
            send_ts,
            start,
            user_data,
            tx_bytes,
        });
        Ok(())
    }

    /// Receive the next completed operation from the pipeline.
    ///
    /// Returns `Err(Error::NoPending)` if there are no in-flight requests.
    pub async fn recv(&mut self) -> Result<CompletedOp, Error> {
        let pending = self.pending.pop_front().ok_or(Error::NoPending)?;

        // Capture pre-read recv timestamp for TTFB before blocking on data.
        let ttfb_ns = self.compute_ttfb(pending.send_ts);

        let response = match self.read_response().await {
            Ok(v) => v,
            Err(e) => {
                // Connection is broken — clear remaining pending ops so
                // subsequent recv() calls return NoPending instead of
                // reading stale/misaligned responses.
                self.pending.clear();
                return Err(e);
            }
        };
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

// -- Zero-copy SET encoding helpers ------------------------------------------

/// Append the memcache text SET prefix for guard-based sends to `buf`:
/// `set {key} {flags} {exptime} {valuelen}\r\n`.
/// The caller must append value bytes (via guard) + `\r\n` suffix.
///
/// Validates `key` (≤ [`MAX_KEY_LEN`]) and `value_len` (≤ [`MAX_VALUE_LEN`]);
/// returns the corresponding `Error` variant if either bound is exceeded so
/// that no bytes hit the wire for a request the server will reject. On error
/// nothing is appended to `buf`.
fn append_set_guard_prefix(
    buf: &mut Vec<u8>,
    key: &[u8],
    value_len: usize,
    flags: u32,
    exptime: u32,
) -> Result<(), Error> {
    validate_key(key)?;
    validate_value_len(value_len)?;
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

/// Reject requests whose key or value exceeds the protocol-defined caps.
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
        McRequest::Set { key, value, .. }
        | McRequest::Add { key, value, .. }
        | McRequest::Replace { key, value, .. }
        | McRequest::Append { key, value }
        | McRequest::Prepend { key, value }
        | McRequest::Cas { key, value, .. } => {
            validate_key(key)?;
            validate_value(value)
        }
        McRequest::FlushAll | McRequest::Version | McRequest::Quit => Ok(()),
    }
}

/// Append the encoding of a `McRequest` to `buf`, rejecting oversized
/// keys/values up-front (see [`validate_request`]). No allocation once
/// `buf` has sufficient capacity. On error nothing is appended to `buf`.
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
/// oversized keys/values up-front (see [`validate_request`]). Hot paths in
/// [`Client`] use [`encode_request_into`] with a reusable buffer instead.
pub(crate) fn encode_request(req: &McRequest<'_>) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    encode_request_into(req, &mut buf)?;
    Ok(buf)
}

/// Encode a SET command into a `Vec<u8>`.
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
    fn validate_value_accepts_max_len() {
        let v = vec![0u8; MAX_VALUE_LEN];
        assert!(validate_value(&v).is_ok());
    }

    #[test]
    fn validate_value_rejects_oversized() {
        let v = vec![0u8; MAX_VALUE_LEN + 1];
        assert!(matches!(validate_value(&v), Err(Error::ValueTooLong)));
    }

    #[test]
    fn encode_request_get_rejects_long_key() {
        let key = vec![b'k'; MAX_KEY_LEN + 1];
        let r = encode_request(&McRequest::get(&key));
        assert!(matches!(r, Err(Error::KeyTooLong)));
    }

    #[test]
    fn encode_request_set_rejects_long_value() {
        let key = b"k";
        let value = vec![0u8; MAX_VALUE_LEN + 1];
        let r = encode_request(&McRequest::Set {
            key,
            value: &value,
            flags: 0,
            exptime: 0,
        });
        assert!(matches!(r, Err(Error::ValueTooLong)));
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
    fn set_guard_prefix_rejects_long_value_len() {
        let r = append_set_guard_prefix(&mut Vec::new(), b"k", MAX_VALUE_LEN + 1, 0, 0);
        assert!(matches!(r, Err(Error::ValueTooLong)));
    }

    #[test]
    fn set_guard_prefix_accepts_max_value_len() {
        let r = append_set_guard_prefix(&mut Vec::new(), b"k", MAX_VALUE_LEN, 0, 0);
        assert!(r.is_ok());
    }

    #[test]
    fn encode_request_passes_through_at_caps() {
        let key = vec![b'k'; MAX_KEY_LEN];
        let value = vec![0u8; MAX_VALUE_LEN];
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
