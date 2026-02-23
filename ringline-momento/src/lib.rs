//! ringline-native Momento cache client for use inside the ringline async runtime.
//!
//! This client uses the Momento protosocket protocol (length-delimited protobuf
//! over TLS) for high-performance cache operations. It is **fully multiplexed**:
//! multiple requests can be in-flight on a single connection, correlated by
//! message ID.
//!
//! # Example
//!
//! ```no_run
//! use ringline::ConnCtx;
//! use ringline_momento::{Client, Credential};
//!
//! async fn example() -> Result<(), ringline_momento::Error> {
//!     let credential = Credential::from_env()?;
//!     let mut client = Client::connect(&credential).await?;
//!
//!     // Sequential convenience API
//!     client.set("my-cache", b"key", b"value", 60_000).await?;
//!     let value = client.get("my-cache", b"key").await?;
//!
//!     // Multiplexed fire/recv API
//!     let id1 = client.fire_get("my-cache", b"key1")?;
//!     let id2 = client.fire_get("my-cache", b"key2")?;
//!     let op1 = client.recv().await?;
//!     let op2 = client.recv().await?;
//!
//!     Ok(())
//! }
//! ```

pub mod credential;
pub mod error;
pub mod pool;
pub mod proto;

pub use credential::Credential;
pub use error::Error;
pub use pool::{Pool, PoolConfig};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use ringline::{ConnCtx, ParseResult};

use crate::proto::{
    CacheCommand, CacheResponse, CacheResponseResult, StatusCode, UnaryCommand,
    decode_length_delimited_message,
};

// ── Request tracking ────────────────────────────────────────────────────

/// Identifies an in-flight request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(u64);

impl RequestId {
    /// Get the raw ID value.
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// The type of cache command that completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandType {
    Get,
    Set,
    Delete,
}

/// A completed cache operation.
#[derive(Debug)]
pub enum CompletedOp {
    /// Get operation completed.
    Get {
        id: RequestId,
        key: Bytes,
        result: Result<Option<Bytes>, Error>,
        /// Latency in nanoseconds (send → response parsed).
        latency_ns: u64,
    },
    /// Set operation completed.
    Set {
        id: RequestId,
        key: Bytes,
        result: Result<(), Error>,
        /// Latency in nanoseconds (send → response parsed).
        latency_ns: u64,
    },
    /// Delete operation completed.
    Delete {
        id: RequestId,
        key: Bytes,
        result: Result<(), Error>,
        /// Latency in nanoseconds (send → response parsed).
        latency_ns: u64,
    },
}

/// Result metadata for a completed command, passed to the `on_result` callback.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// The command type.
    pub command: CommandType,
    /// Latency in nanoseconds (send → response parsed).
    pub latency_ns: u64,
    /// Whether the command succeeded.
    pub success: bool,
}

/// Callback type for per-request result notifications.
type ResultCallback = Box<dyn Fn(&CommandResult)>;

// ── Pending operation state ─────────────────────────────────────────────

/// The type of a pending operation.
enum PendingOpKind {
    Get,
    Set,
    Delete,
}

/// State of a pending operation.
struct PendingOp {
    kind: PendingOpKind,
    key: Bytes,
    send_ts: u64,
    start: Instant,
}

// ── ClientMetrics ───────────────────────────────────────────────────────

/// Built-in histogram-based metrics, available when the `metrics` feature is
/// enabled.
#[cfg(feature = "metrics")]
pub struct ClientMetrics {
    /// Latency histogram.
    pub latency: histogram::Histogram,
    /// Total requests completed.
    pub requests: u64,
    /// Total errors.
    pub errors: u64,
}

#[cfg(feature = "metrics")]
impl ClientMetrics {
    fn new() -> Self {
        Self {
            latency: histogram::Histogram::new(7, 64).unwrap(),
            requests: 0,
            errors: 0,
        }
    }

    fn record(&mut self, result: &CommandResult) {
        self.requests += 1;
        let _ = self.latency.increment(result.latency_ns);

        if !result.success {
            self.errors += 1;
        }
    }
}

// ── ClientBuilder ───────────────────────────────────────────────────────

/// Builder for creating a [`Client`] with per-request callbacks and metrics.
pub struct ClientBuilder {
    conn: ConnCtx,
    on_result: Option<ResultCallback>,
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
            #[cfg(feature = "timestamps")]
            use_kernel_ts: false,
            #[cfg(feature = "metrics")]
            with_metrics: false,
        }
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

    /// Build the client (already authenticated).
    pub fn build(self) -> Client {
        Client {
            conn: self.conn,
            next_message_id: 1,
            pending: HashMap::new(),
            send_buf: Vec::with_capacity(4096),
            on_result: self.on_result,
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

/// A ringline-native Momento cache client wrapping a single connection.
///
/// Supports both multiplexed (fire/recv) and sequential (get/set/delete)
/// operation modes. Use [`Client::connect`] to establish an authenticated
/// connection, or [`Client::builder`] after manual authentication.
pub struct Client {
    conn: ConnCtx,
    next_message_id: u64,
    pending: HashMap<u64, PendingOp>,
    send_buf: Vec<u8>,
    on_result: Option<ResultCallback>,
    #[cfg(feature = "timestamps")]
    use_kernel_ts: bool,
    #[cfg(feature = "metrics")]
    metrics: Option<ClientMetrics>,
}

impl Client {
    /// Connect to Momento, authenticate, and return a ready client.
    pub async fn connect(credential: &Credential) -> Result<Self, Error> {
        let host = credential.host();
        let port = credential.port();
        let addr: SocketAddr = Self::resolve_addr(host, port)?;
        let tls_host = credential.tls_host();

        let conn = ringline::connect_tls(addr, tls_host)?.await?;

        let mut client = Self {
            conn,
            next_message_id: 1,
            pending: HashMap::new(),
            send_buf: Vec::with_capacity(4096),
            on_result: None,
            #[cfg(feature = "timestamps")]
            use_kernel_ts: false,
            #[cfg(feature = "metrics")]
            metrics: None,
        };

        client.authenticate(credential.token()).await?;
        Ok(client)
    }

    /// Connect with a timeout.
    pub async fn connect_with_timeout(
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<Self, Error> {
        let host = credential.host();
        let port = credential.port();
        let addr: SocketAddr = Self::resolve_addr(host, port)?;
        let tls_host = credential.tls_host();

        let conn = ringline::connect_tls_with_timeout(addr, tls_host, timeout_ms)?.await?;

        let mut client = Self {
            conn,
            next_message_id: 1,
            pending: HashMap::new(),
            send_buf: Vec::with_capacity(4096),
            on_result: None,
            #[cfg(feature = "timestamps")]
            use_kernel_ts: false,
            #[cfg(feature = "metrics")]
            metrics: None,
        };

        client.authenticate(credential.token()).await?;
        Ok(client)
    }

    /// Create a builder for a client with per-request callbacks.
    ///
    /// The connection must already be authenticated.
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

    /// Number of in-flight requests.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    // ── Multiplexed fire API ────────────────────────────────────────────

    /// Fire a GET request. Returns immediately with a RequestId.
    pub fn fire_get(&mut self, cache: &str, key: &[u8]) -> Result<RequestId, Error> {
        let message_id = self.next_id();
        let cmd = CacheCommand::new(
            message_id,
            UnaryCommand::Get {
                namespace: cache.to_string(),
                key: Bytes::copy_from_slice(key),
            },
        );

        self.send_command(&cmd)?;

        let (send_ts, start) = self.timing_start();
        self.pending.insert(
            message_id,
            PendingOp {
                kind: PendingOpKind::Get,
                key: Bytes::copy_from_slice(key),
                send_ts,
                start,
            },
        );

        Ok(RequestId(message_id))
    }

    /// Fire a SET request. Returns immediately with a RequestId.
    pub fn fire_set(
        &mut self,
        cache: &str,
        key: &[u8],
        value: &[u8],
        ttl_ms: u64,
    ) -> Result<RequestId, Error> {
        let message_id = self.next_id();
        let cmd = CacheCommand::new(
            message_id,
            UnaryCommand::Set {
                namespace: cache.to_string(),
                key: Bytes::copy_from_slice(key),
                value: Bytes::copy_from_slice(value),
                ttl_millis: ttl_ms,
            },
        );

        self.send_command(&cmd)?;

        let (send_ts, start) = self.timing_start();
        self.pending.insert(
            message_id,
            PendingOp {
                kind: PendingOpKind::Set,
                key: Bytes::copy_from_slice(key),
                send_ts,
                start,
            },
        );

        Ok(RequestId(message_id))
    }

    /// Fire a DELETE request. Returns immediately with a RequestId.
    pub fn fire_delete(&mut self, cache: &str, key: &[u8]) -> Result<RequestId, Error> {
        let message_id = self.next_id();
        let cmd = CacheCommand::new(
            message_id,
            UnaryCommand::Delete {
                namespace: cache.to_string(),
                key: Bytes::copy_from_slice(key),
            },
        );

        self.send_command(&cmd)?;

        let (send_ts, start) = self.timing_start();
        self.pending.insert(
            message_id,
            PendingOp {
                kind: PendingOpKind::Delete,
                key: Bytes::copy_from_slice(key),
                send_ts,
                start,
            },
        );

        Ok(RequestId(message_id))
    }

    // ── Multiplexed recv API ────────────────────────────────────────────

    /// Await the next completed operation. Reads from the connection,
    /// decodes the response, and correlates by message_id.
    pub async fn recv(&mut self) -> Result<CompletedOp, Error> {
        let pending = &mut self.pending;
        let mut dispatch_result: Option<DispatchResult> = None;

        let n = self
            .conn
            .with_data(|data| {
                match decode_length_delimited_message(data) {
                    Some((consumed, msg_bytes)) => {
                        if let Some(response) = CacheResponse::decode(msg_bytes) {
                            dispatch_result = dispatch_response(response, pending);
                        }
                        ParseResult::Consumed(consumed)
                    }
                    None => ParseResult::Consumed(0), // need more data
                }
            })
            .await;

        if n == 0 {
            return Err(Error::ConnectionClosed);
        }

        let dr =
            dispatch_result.ok_or_else(|| Error::Protocol("failed to decode response".into()))?;

        let latency_ns = self.finish_timing(dr.send_ts, dr.start);

        if self.is_instrumented() {
            self.record(&CommandResult {
                command: dr.cmd_type,
                latency_ns,
                success: dr.success,
            });
        }

        let mut op = dr.op;
        match &mut op {
            CompletedOp::Get { latency_ns: l, .. }
            | CompletedOp::Set { latency_ns: l, .. }
            | CompletedOp::Delete { latency_ns: l, .. } => *l = latency_ns,
        }
        Ok(op)
    }

    // ── Sequential convenience API ──────────────────────────────────────

    /// Sequential get: fire + recv.
    pub async fn get(&mut self, cache: &str, key: &[u8]) -> Result<Option<Bytes>, Error> {
        let _id = self.fire_get(cache, key)?;
        match self.recv().await? {
            CompletedOp::Get { result, .. } => result,
            _ => Err(Error::Protocol("unexpected response type".into())),
        }
    }

    /// Sequential set.
    pub async fn set(
        &mut self,
        cache: &str,
        key: &[u8],
        value: &[u8],
        ttl_ms: u64,
    ) -> Result<(), Error> {
        let _id = self.fire_set(cache, key, value, ttl_ms)?;
        match self.recv().await? {
            CompletedOp::Set { result, .. } => result,
            _ => Err(Error::Protocol("unexpected response type".into())),
        }
    }

    /// Sequential delete.
    pub async fn delete(&mut self, cache: &str, key: &[u8]) -> Result<(), Error> {
        let _id = self.fire_delete(cache, key)?;
        match self.recv().await? {
            CompletedOp::Delete { result, .. } => result,
            _ => Err(Error::Protocol("unexpected response type".into())),
        }
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn next_id(&mut self) -> u64 {
        let id = self.next_message_id;
        self.next_message_id += 1;
        id
    }

    fn send_command(&mut self, cmd: &CacheCommand) -> Result<(), Error> {
        self.send_buf.clear();
        let encoded = cmd.encode_length_delimited();
        self.conn.send_nowait(&encoded)?;
        Ok(())
    }

    async fn authenticate(&mut self, token: &str) -> Result<(), Error> {
        let message_id = self.next_id();
        let cmd = CacheCommand::new(
            message_id,
            UnaryCommand::Authenticate {
                auth_token: token.to_string(),
            },
        );

        let encoded = cmd.encode_length_delimited();
        self.conn.send_nowait(&encoded)?;

        // Wait for auth response
        let mut auth_result: Option<Result<(), Error>> = None;

        let n = self
            .conn
            .with_data(|data| match decode_length_delimited_message(data) {
                Some((consumed, msg_bytes)) => {
                    if let Some(response) = CacheResponse::decode(msg_bytes)
                        && response.message_id == message_id
                    {
                        match response.result {
                            CacheResponseResult::Authenticate => {
                                auth_result = Some(Ok(()));
                            }
                            CacheResponseResult::Error(err) => {
                                auth_result = Some(Err(Error::AuthFailed(err.message)));
                            }
                            _ => {
                                auth_result = Some(Err(Error::Protocol(
                                    "unexpected auth response type".into(),
                                )));
                            }
                        }
                    }
                    ParseResult::Consumed(consumed)
                }
                None => ParseResult::Consumed(0),
            })
            .await;

        if n == 0 {
            return Err(Error::ConnectionClosed);
        }

        auth_result.unwrap_or(Err(Error::Protocol(
            "failed to decode auth response".into(),
        )))
    }

    fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr, Error> {
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", host, port);
        addr_str
            .to_socket_addrs()
            .map_err(|e| Error::Config(format!("failed to resolve {}: {}", addr_str, e)))?
            .next()
            .ok_or_else(|| Error::Config(format!("no addresses found for {}", addr_str)))
    }

    // ── Timing helpers ──────────────────────────────────────────────────

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

    #[inline]
    fn timing_start(&self) -> (u64, Instant) {
        if self.is_instrumented() {
            (self.send_timestamp(), Instant::now())
        } else {
            (0, Instant::now())
        }
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
}

// ── Response dispatch ───────────────────────────────────────────────────

/// Result of dispatching a response to a pending operation.
struct DispatchResult {
    op: CompletedOp,
    cmd_type: CommandType,
    success: bool,
    send_ts: u64,
    start: Instant,
}

/// Dispatch a decoded CacheResponse to the appropriate pending operation.
fn dispatch_response(
    response: CacheResponse,
    pending: &mut HashMap<u64, PendingOp>,
) -> Option<DispatchResult> {
    let message_id = response.message_id;
    let id = RequestId(message_id);

    let op = pending.remove(&message_id)?;
    let send_ts = op.send_ts;
    let start = op.start;

    match op.kind {
        PendingOpKind::Get => {
            let result = match response.result {
                CacheResponseResult::Get { value } => Ok(value),
                CacheResponseResult::Error(ref err) if err.code == StatusCode::NotFound => Ok(None),
                CacheResponseResult::Error(err) => Err(Error::Protocol(format!(
                    "{}: {}",
                    err.code as u32, err.message
                ))),
                _ => Err(Error::Protocol("unexpected response type for get".into())),
            };
            let success = result.is_ok();
            Some(DispatchResult {
                op: CompletedOp::Get {
                    id,
                    key: op.key,
                    result,
                    latency_ns: 0, // filled in by recv()
                },
                cmd_type: CommandType::Get,
                success,
                send_ts,
                start,
            })
        }
        PendingOpKind::Set => {
            let result = match response.result {
                CacheResponseResult::Set => Ok(()),
                CacheResponseResult::Error(err) => Err(Error::Protocol(format!(
                    "{}: {}",
                    err.code as u32, err.message
                ))),
                _ => Err(Error::Protocol("unexpected response type for set".into())),
            };
            let success = result.is_ok();
            Some(DispatchResult {
                op: CompletedOp::Set {
                    id,
                    key: op.key,
                    result,
                    latency_ns: 0, // filled in by recv()
                },
                cmd_type: CommandType::Set,
                success,
                send_ts,
                start,
            })
        }
        PendingOpKind::Delete => {
            let result = match response.result {
                CacheResponseResult::Delete => Ok(()),
                CacheResponseResult::Error(err) => Err(Error::Protocol(format!(
                    "{}: {}",
                    err.code as u32, err.message
                ))),
                _ => Err(Error::Protocol(
                    "unexpected response type for delete".into(),
                )),
            };
            let success = result.is_ok();
            Some(DispatchResult {
                op: CompletedOp::Delete {
                    id,
                    key: op.key,
                    result,
                    latency_ns: 0, // filled in by recv()
                },
                cmd_type: CommandType::Delete,
                success,
                send_ts,
                start,
            })
        }
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
