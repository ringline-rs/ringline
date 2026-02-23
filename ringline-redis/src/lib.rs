//! ringline-native RESP client for use inside the ringline async runtime.
//!
//! This client wraps a [`ringline::ConnCtx`] and provides typed Redis command
//! methods that use `with_data()` + `Value::parse()` for incremental RESP
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

pub mod cluster;
pub mod pool;
pub mod sharded;
pub use cluster::{ClusterClient, ClusterConfig};
pub use pool::{Pool, PoolConfig};
pub use sharded::{ShardedClient, ShardedConfig};

use std::io;
use std::time::Instant;

use bytes::Bytes;
use resp_proto::{Request, Value};
use ringline::{ConnCtx, GuardBox, ParseResult, SendGuard};

// ── Error ───────────────────────────────────────────────────────────────

/// Errors returned by the ringline RESP client.
#[derive(Debug, thiserror::Error)]
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
}

// ── Command types ───────────────────────────────────────────────────────

/// The type of Redis command that completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

// ── ClientBuilder ───────────────────────────────────────────────────────

type ResultCallback = Box<dyn Fn(&CommandResult)>;

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

// ── Client ──────────────────────────────────────────────────────────────

/// A ringline-native RESP client wrapping a single connection.
///
/// `Client::new(conn)` creates a zero-overhead client with no callbacks or
/// metrics. Use `Client::builder(conn)` to configure per-request callbacks,
/// kernel timestamps, and built-in histogram tracking.
pub struct Client {
    conn: ConnCtx,
    on_result: Option<ResultCallback>,
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

    // ── Internal protocol methods (pub(crate), &self) ───────────────────

    /// Read and parse a single RESP value from the connection.
    ///
    /// Uses zero-copy parsing via `with_bytes` + `Value::parse_bytes`:
    /// bulk string values are `Bytes::slice()` references into the
    /// accumulator's buffer rather than freshly allocated `Vec<u8>`.
    pub(crate) async fn read_value(&self) -> Result<Value, Error> {
        let mut result: Option<Result<Value, Error>> = None;
        let n = self
            .conn
            .with_bytes(|bytes| match Value::parse_bytes(bytes) {
                Ok((value, consumed)) => {
                    result = Some(Ok(value));
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

    /// Encode a `Request` into a `Vec<u8>`.
    pub(crate) fn encode_request(req: &Request<'_>) -> Vec<u8> {
        let len = req.encoded_len();
        let mut buf = vec![0u8; len];
        req.encode(&mut buf);
        buf
    }

    /// Encode a `SetRequest` into a `Vec<u8>`.
    pub(crate) fn encode_set_request(req: &resp_proto::SetRequest<'_>) -> Vec<u8> {
        let len = req.encoded_len();
        let mut buf = vec![0u8; len];
        req.encode(&mut buf);
        buf
    }

    // ── Instrumented String commands ────────────────────────────────────

    /// Get the value of a key.
    pub async fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        if !self.is_instrumented() {
            return self
                .execute_bulk(&Self::encode_request(&Request::get(key)))
                .await;
        }
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self
            .execute_bulk(&Self::encode_request(&Request::get(key)))
            .await;
        let latency_ns = self.finish_timing(send_ts, start);
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

    /// Set a key-value pair.
    pub async fn set(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        if !self.is_instrumented() {
            let resp = self.execute_set(&Request::set(key, value), value).await?;
            return match resp {
                Value::SimpleString(_) | Value::Null => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self.execute_set(&Request::set(key, value), value).await;
        let latency_ns = self.finish_timing(send_ts, start);
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
        if !self.is_instrumented() {
            let resp = self
                .execute_set(&Request::set(key, value).ex(ttl_secs), value)
                .await?;
            return match resp {
                Value::SimpleString(_) => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self
            .execute_set(&Request::set(key, value).ex(ttl_secs), value)
            .await;
        let latency_ns = self.finish_timing(send_ts, start);
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
        if !self.is_instrumented() {
            return self
                .execute_int(&Self::encode_request(&Request::del(key)))
                .await
                .map(|n| n as u64);
        }
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self
            .execute_int(&Self::encode_request(&Request::del(key)))
            .await
            .map(|n| n as u64);
        let latency_ns = self.finish_timing(send_ts, start);
        self.record(&CommandResult {
            command: CommandType::Del,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
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
        let delta_str = delta.to_string();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"INCRBY").arg(key).arg(delta_str.as_bytes()),
        ))
        .await
    }

    /// Decrement the integer value of a key by a given amount.
    pub async fn decrby(&mut self, key: impl AsRef<[u8]>, delta: i64) -> Result<i64, Error> {
        let key = key.as_ref();
        let delta_str = delta.to_string();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"DECRBY").arg(key).arg(delta_str.as_bytes()),
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
        let secs_str = seconds.to_string();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"EXPIRE").arg(key).arg(secs_str.as_bytes()),
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
        let delta_str = delta.to_string();
        self.execute_int(&Self::encode_request(
            &Request::cmd(b"HINCRBY")
                .arg(key)
                .arg(field)
                .arg(delta_str.as_bytes()),
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
        let idx_str = index.to_string();
        self.execute_bulk(&Self::encode_request(
            &Request::cmd(b"LINDEX").arg(key).arg(idx_str.as_bytes()),
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
        let start_str = start.to_string();
        let stop_str = stop.to_string();
        let value = self
            .execute(&Self::encode_request(
                &Request::cmd(b"LRANGE")
                    .arg(key)
                    .arg(start_str.as_bytes())
                    .arg(stop_str.as_bytes()),
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
        let start_str = start.to_string();
        let stop_str = stop.to_string();
        self.execute_ok(&Self::encode_request(
            &Request::cmd(b"LTRIM")
                .arg(key)
                .arg(start_str.as_bytes())
                .arg(stop_str.as_bytes()),
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
        let idx_str = index.to_string();
        self.execute_ok(&Self::encode_request(
            &Request::cmd(b"LSET")
                .arg(key)
                .arg(idx_str.as_bytes())
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
        let count_str = count.to_string();
        let value = self
            .execute(&Self::encode_request(
                &Request::cmd(b"SRANDMEMBER")
                    .arg(key)
                    .arg(count_str.as_bytes()),
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
        if !self.is_instrumented() {
            let value = self
                .execute(&Self::encode_request(&Request::ping()))
                .await?;
            return match value {
                Value::SimpleString(_) => Ok(()),
                _ => Err(Error::UnexpectedResponse),
            };
        }
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let result = self.execute(&Self::encode_request(&Request::ping())).await;
        let latency_ns = self.finish_timing(send_ts, start);
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
            let prefix = encode_set_guard_prefix(key, value_len as usize, None);
            self.conn.send_parts().build(move |b| {
                b.copy(&prefix)
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
        let prefix = encode_set_guard_prefix(key, value_len as usize, None);
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        self.conn.send_parts().build(move |b| {
            b.copy(&prefix)
                .guard(GuardBox::new(guard))
                .copy(b"\r\n")
                .submit()
        })?;
        let resp = self.read_value().await?;
        let latency_ns = self.finish_timing(send_ts, start);
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
            let (prefix, suffix) = encode_set_guard_prefix_ex(key, value_len as usize, ttl_secs);
            self.conn.send_parts().build(move |b| {
                b.copy(&prefix)
                    .guard(GuardBox::new(guard))
                    .copy(&suffix)
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
        let (prefix, suffix) = encode_set_guard_prefix_ex(key, value_len as usize, ttl_secs);
        let send_ts = self.send_timestamp();
        let start = Instant::now();
        self.conn.send_parts().build(move |b| {
            b.copy(&prefix)
                .guard(GuardBox::new(guard))
                .copy(&suffix)
                .submit()
        })?;
        let resp = self.read_value().await?;
        let latency_ns = self.finish_timing(send_ts, start);
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
        });
        result
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

/// Encode RESP SET prefix for guard-based sends.
///
/// Returns the prefix bytes: `*3\r\n$3\r\nSET\r\n${keylen}\r\n{key}\r\n${valuelen}\r\n`
/// (or `*5\r\n...` when `noreply` args are needed).
/// The caller must append value bytes (via guard) + `\r\n` suffix.
fn encode_set_guard_prefix(key: &[u8], value_len: usize, _options: Option<()>) -> Vec<u8> {
    use std::io::Write;
    let mut buf = Vec::with_capacity(32 + key.len());
    buf.extend_from_slice(b"*3\r\n$3\r\nSET\r\n");
    write!(buf, "${}\r\n", key.len()).unwrap();
    buf.extend_from_slice(key);
    buf.extend_from_slice(b"\r\n");
    write!(buf, "${}\r\n", value_len).unwrap();
    buf
}

/// Encode RESP SET EX prefix + suffix for guard-based sends.
///
/// Returns `(prefix, suffix)` where:
/// - prefix: `*5\r\n$3\r\nSET\r\n${keylen}\r\n{key}\r\n${valuelen}\r\n`
/// - suffix: `\r\n$2\r\nEX\r\n${ttllen}\r\n{ttl}\r\n`
fn encode_set_guard_prefix_ex(key: &[u8], value_len: usize, ttl_secs: u64) -> (Vec<u8>, Vec<u8>) {
    use std::io::Write;
    let ttl_str = ttl_secs.to_string();

    let mut prefix = Vec::with_capacity(32 + key.len());
    prefix.extend_from_slice(b"*5\r\n$3\r\nSET\r\n");
    write!(prefix, "${}\r\n", key.len()).unwrap();
    prefix.extend_from_slice(key);
    prefix.extend_from_slice(b"\r\n");
    write!(prefix, "${}\r\n", value_len).unwrap();

    let mut suffix = Vec::with_capacity(32);
    suffix.extend_from_slice(b"\r\n$2\r\nEX\r\n");
    write!(suffix, "${}\r\n{}\r\n", ttl_str.len(), ttl_str).unwrap();

    (prefix, suffix)
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
        self.buf.extend_from_slice(&Client::encode_request(request));
        self.count += 1;
        self
    }

    /// Add a SET command to the pipeline.
    pub fn set(mut self, key: &[u8], value: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&Client::encode_set_request(&Request::set(key, value)));
        self.count += 1;
        self
    }

    /// Add a GET command to the pipeline.
    pub fn get(mut self, key: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&Client::encode_request(&Request::get(key)));
        self.count += 1;
        self
    }

    /// Add a DEL command to the pipeline.
    pub fn del(mut self, key: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&Client::encode_request(&Request::del(key)));
        self.count += 1;
        self
    }

    /// Add an INCR command to the pipeline.
    pub fn incr(mut self, key: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&Client::encode_request(&Request::cmd(b"INCR").arg(key)));
        self.count += 1;
        self
    }

    /// Execute all commands in the pipeline and return their results in order.
    pub async fn execute(self) -> Result<Vec<Value>, Error> {
        if self.count == 0 {
            return Ok(Vec::new());
        }
        self.conn.send(&self.buf)?;

        // Use a temporary Client to read values.
        let client = Client::new(self.conn);
        let mut results = Vec::with_capacity(self.count);
        for _ in 0..self.count {
            let value = client.read_value().await?;
            if let Value::Error(ref msg) = value {
                return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
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
