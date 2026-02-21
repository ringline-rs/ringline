//! ringline-native Memcache client for use inside the ringline async runtime.
//!
//! This client wraps a [`ringline::ConnCtx`] and provides typed Memcache command
//! methods that use `with_data()` + `Response::parse()` for incremental
//! parsing. It is designed for single-threaded, single-connection use within
//! ringline's `AsyncEventHandler::on_start()` or connection tasks.
//!
//! All key and value parameters accept `impl AsRef<[u8]>`, so you can pass
//! `&str`, `String`, `&[u8]`, `Vec<u8>`, `Bytes`, etc.
//!
//! # Example
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

pub mod pool;
pub mod sharded;
pub use pool::{Pool, PoolConfig};
pub use sharded::{ShardedClient, ShardedConfig};

use std::io;
use std::time::Instant;

use bytes::Bytes;
use memcache_proto::{Request as McRequest, Response as McResponse};
use ringline::{ConnCtx, GuardBox, ParseResult, SendGuard};

// -- Error -------------------------------------------------------------------

/// Errors returned by the ringline Memcache client.
#[derive(Debug, thiserror::Error)]
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

// ── ClientBuilder ───────────────────────────────────────────────────────

/// Builder for creating a [`Client`] with per-request callbacks and metrics.
pub struct ClientBuilder {
    conn: ConnCtx,
    on_result: Option<Box<dyn Fn(&CommandResult)>>,
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

    /// Build the client.
    pub fn build(self) -> Client {
        Client {
            conn: self.conn,
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

// -- Client ------------------------------------------------------------------

/// A ringline-native Memcache client wrapping a single connection.
///
/// `Client::new(conn)` creates a zero-overhead client with no callbacks or
/// metrics. Use `Client::builder(conn)` to configure per-request callbacks,
/// kernel timestamps, and built-in histogram tracking.
pub struct Client {
    conn: ConnCtx,
    on_result: Option<Box<dyn Fn(&CommandResult)>>,
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

    // ── Internal I/O (unchanged) ────────────────────────────────────────

    /// Read and parse a single Memcache response from the connection.
    pub(crate) async fn read_response(&self) -> Result<McResponse, Error> {
        let mut result: Option<Result<McResponse, Error>> = None;
        let n = self
            .conn
            .with_data(|data| match McResponse::parse(data) {
                Ok((response, consumed)) => {
                    result = Some(Ok(response));
                    ParseResult::Consumed(consumed)
                }
                Err(e) if e.is_incomplete() => ParseResult::Consumed(0),
                Err(e) => {
                    result = Some(Err(Error::Protocol(e)));
                    ParseResult::Consumed(0)
                }
            })
            .await;
        if n == 0 {
            return result.unwrap_or(Err(Error::ConnectionClosed));
        }
        result.unwrap()
    }

    /// Send an encoded command and read the response, converting error
    /// responses into `Error::Memcache`.
    async fn execute(&self, encoded: &[u8]) -> Result<McResponse, Error> {
        self.conn.send(encoded)?;
        let response = self.read_response().await?;
        check_error(&response)?;
        Ok(response)
    }

    // -- Commands (instrumented hot-path) ---------------------------------

    /// Get the value of a key. Returns `None` on cache miss.
    pub async fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Value>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::get(key));

        if !self.is_instrumented() {
            let response = self.execute(&encoded).await?;
            return match response {
                McResponse::Values(mut values) => {
                    if values.is_empty() {
                        Ok(None)
                    } else {
                        let v = values.swap_remove(0);
                        Ok(Some(Value {
                            data: Bytes::from(v.data),
                            flags: v.flags,
                        }))
                    }
                }
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let response = self.execute(&encoded).await;
        let latency_ns = self.finish_timing(send_ts, start);

        let result = match response {
            Ok(McResponse::Values(mut values)) => {
                if values.is_empty() {
                    Ok(None)
                } else {
                    let v = values.swap_remove(0);
                    Ok(Some(Value {
                        data: Bytes::from(v.data),
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
        });
        result
    }

    /// Get values for multiple keys. Returns only hits, each with its key and CAS token.
    pub async fn gets(&mut self, keys: &[&[u8]]) -> Result<Vec<GetValue>, Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let encoded = encode_request(&McRequest::gets(keys));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Values(values) => Ok(values
                .into_iter()
                .map(|v| GetValue {
                    key: Bytes::from(v.key),
                    data: Bytes::from(v.data),
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
        let encoded = encode_set(key, value, flags, exptime);

        if !self.is_instrumented() {
            let response = self.execute(&encoded).await?;
            return match response {
                McResponse::Stored => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let response = self.execute(&encoded).await;
        let latency_ns = self.finish_timing(send_ts, start);

        let result = match response {
            Ok(McResponse::Stored) => Ok(()),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Set,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
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
        let encoded = encode_add(key, value);
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
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
        });
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Increment a numeric value by delta. Returns the new value after incrementing.
    /// Returns `None` if the key does not exist.
    pub async fn incr(&mut self, key: impl AsRef<[u8]>, delta: u64) -> Result<Option<u64>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::incr(key, delta));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Numeric(val) => Ok(Some(val)),
            McResponse::NotFound => Ok(None),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Decrement a numeric value by delta. Returns the new value after decrementing.
    /// Returns `None` if the key does not exist.
    pub async fn decr(&mut self, key: impl AsRef<[u8]>, delta: u64) -> Result<Option<u64>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::decr(key, delta));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Numeric(val) => Ok(Some(val)),
            McResponse::NotFound => Ok(None),
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
        let encoded = encode_request(&McRequest::append(key, value));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
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
        let encoded = encode_request(&McRequest::prepend(key, value));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
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
        let encoded = encode_request(&McRequest::cas(key, value, cas_unique));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::Exists => Ok(false),
            McResponse::NotFound => Err(Error::Memcache("NOT_FOUND".into())),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Delete a key. Returns `true` if deleted, `false` if not found.
    pub async fn delete(&mut self, key: impl AsRef<[u8]>) -> Result<bool, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::delete(key));

        if !self.is_instrumented() {
            let response = self.execute(&encoded).await?;
            return match response {
                McResponse::Deleted => Ok(true),
                McResponse::NotFound => Ok(false),
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let response = self.execute(&encoded).await;
        let latency_ns = self.finish_timing(send_ts, start);

        let result = match response {
            Ok(McResponse::Deleted) => Ok(true),
            Ok(McResponse::NotFound) => Ok(false),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Delete,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
        });
        result
    }

    /// Flush all items from the cache.
    pub async fn flush_all(&mut self) -> Result<(), Error> {
        let encoded = encode_request(&McRequest::flush_all());
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Get the server version string.
    pub async fn version(&mut self) -> Result<String, Error> {
        let encoded = encode_request(&McRequest::version());
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Version(v) => Ok(String::from_utf8_lossy(&v).into_owned()),
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
            let prefix = encode_set_guard_prefix(key, value_len as usize, flags, exptime);

            self.conn.send_parts().build(move |b| {
                b.copy(&prefix)
                    .guard(GuardBox::new(guard))
                    .copy(b"\r\n")
                    .submit()
            })?;

            let response = self.read_response().await?;
            check_error(&response)?;
            return match response {
                McResponse::Stored => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let send_ts = self.send_timestamp();
        let start = Instant::now();

        let (_, value_len) = guard.as_ptr_len();
        let prefix = encode_set_guard_prefix(key, value_len as usize, flags, exptime);

        self.conn.send_parts().build(move |b| {
            b.copy(&prefix)
                .guard(GuardBox::new(guard))
                .copy(b"\r\n")
                .submit()
        })?;

        let response = self.read_response().await;
        let latency_ns = self.finish_timing(send_ts, start);

        let result = match response {
            Ok(ref r) => {
                check_error(r)?;
                match r {
                    McResponse::Stored => Ok(()),
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
        });
        result
    }
}

// -- Zero-copy SET encoding helpers ------------------------------------------

/// Encode memcache text SET prefix for guard-based sends.
///
/// Returns: `set {key} {flags} {exptime} {valuelen}\r\n`
/// The caller must append value bytes (via guard) + `\r\n` suffix.
fn encode_set_guard_prefix(key: &[u8], value_len: usize, flags: u32, exptime: u32) -> Vec<u8> {
    use std::io::Write;
    let mut buf = Vec::with_capacity(32 + key.len());
    buf.extend_from_slice(b"set ");
    buf.extend_from_slice(key);
    write!(buf, " {} {} {}\r\n", flags, exptime, value_len).unwrap();
    buf
}

// -- Encoding helpers --------------------------------------------------------

/// Encode a `McRequest` into a `Vec<u8>`.
pub(crate) fn encode_request(req: &McRequest<'_>) -> Vec<u8> {
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
    let mut buf = vec![0u8; size];
    let len = req.encode(&mut buf);
    buf.truncate(len);
    buf
}

/// Encode a SET command into a `Vec<u8>`.
pub(crate) fn encode_set(key: &[u8], value: &[u8], flags: u32, exptime: u32) -> Vec<u8> {
    encode_request(&McRequest::Set {
        key,
        value,
        flags,
        exptime,
    })
}

/// Encode an ADD command into a `Vec<u8>`.
pub(crate) fn encode_add(key: &[u8], value: &[u8]) -> Vec<u8> {
    encode_request(&McRequest::Add {
        key,
        value,
        flags: 0,
        exptime: 0,
    })
}

/// Check a response for error variants and return an appropriate `Error`.
pub(crate) fn check_error(response: &McResponse) -> Result<(), Error> {
    match response {
        McResponse::Error => Err(Error::Memcache("ERROR".into())),
        McResponse::ClientError(msg) => Err(Error::Memcache(format!(
            "CLIENT_ERROR {}",
            String::from_utf8_lossy(msg)
        ))),
        McResponse::ServerError(msg) => Err(Error::Memcache(format!(
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
