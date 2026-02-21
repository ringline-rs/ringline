//! Instrumented Redis client with per-request latency callbacks and optional
//! built-in histogram tracking.
//!
//! # Example
//!
//! ```no_run
//! use ringline::ConnCtx;
//! use ringline_redis::{Client, InstrumentedClient, CommandResult};
//!
//! async fn example(conn: ConnCtx) {
//!     let mut client = Client::builder(conn)
//!         .on_result(|r: &CommandResult| {
//!             println!("command {:?} took {}ns", r.command, r.latency_ns);
//!         })
//!         .build();
//!
//!     client.set("hello", "world").await.unwrap();
//!     let _val = client.get("hello").await.unwrap();
//! }
//! ```

use std::time::Instant;

use bytes::Bytes;
use ringline::{ConnCtx, SendGuard};

use crate::{Client, Error};

/// Callback type for per-command result notifications.
type ResultCallback = Box<dyn Fn(&CommandResult)>;

// ── Types ───────────────────────────────────────────────────────────────

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

/// Builder for creating an [`InstrumentedClient`] with callbacks and metrics.
pub struct ClientBuilder {
    conn: ConnCtx,
    on_result: Option<ResultCallback>,
    #[cfg(feature = "metrics")]
    with_metrics: bool,
}

impl ClientBuilder {
    pub(crate) fn new(conn: ConnCtx) -> Self {
        Self {
            conn,
            on_result: None,
            #[cfg(feature = "metrics")]
            with_metrics: false,
        }
    }

    /// Register a callback invoked after each command completes.
    pub fn on_result<F: Fn(&CommandResult) + 'static>(mut self, f: F) -> Self {
        self.on_result = Some(Box::new(f));
        self
    }

    /// Enable built-in histogram tracking (requires `metrics` feature).
    #[cfg(feature = "metrics")]
    pub fn with_metrics(mut self) -> Self {
        self.with_metrics = true;
        self
    }

    /// Build the instrumented client.
    pub fn build(self) -> InstrumentedClient {
        InstrumentedClient {
            client: Client::new(self.conn),
            on_result: self.on_result,
            #[cfg(feature = "metrics")]
            metrics: if self.with_metrics {
                Some(ClientMetrics::new())
            } else {
                None
            },
        }
    }
}

// ── InstrumentedClient ──────────────────────────────────────────────────

/// A Redis client wrapper that measures per-request latency and invokes
/// an optional callback after each command.
///
/// Unlike [`Client`], this type is **not** `Copy` — it holds an optional
/// boxed callback and/or histogram state.
pub struct InstrumentedClient {
    client: Client,
    on_result: Option<ResultCallback>,
    #[cfg(feature = "metrics")]
    metrics: Option<ClientMetrics>,
}

impl InstrumentedClient {
    /// Returns the underlying connection context.
    pub fn conn(&self) -> ConnCtx {
        self.client.conn()
    }

    /// Returns the inner [`Client`] (Copy, no instrumentation).
    pub fn inner(&self) -> Client {
        self.client
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

    // ── String commands ─────────────────────────────────────────────────

    /// Get the value of a key.
    pub async fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let start = Instant::now();
        let result = self.client.get(key).await;
        let latency_ns = start.elapsed().as_nanos() as u64;
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
        let start = Instant::now();
        let result = self.client.set(key, value).await;
        let latency_ns = start.elapsed().as_nanos() as u64;
        self.record(&CommandResult {
            command: CommandType::Set,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
        });
        result
    }

    /// Set a key-value pair with TTL in seconds.
    pub async fn set_ex(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        ttl_secs: u64,
    ) -> Result<(), Error> {
        let start = Instant::now();
        let result = self.client.set_ex(key, value, ttl_secs).await;
        let latency_ns = start.elapsed().as_nanos() as u64;
        self.record(&CommandResult {
            command: CommandType::Set,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
        });
        result
    }

    /// Delete a key. Returns the number of keys deleted.
    pub async fn del(&mut self, key: impl AsRef<[u8]>) -> Result<u64, Error> {
        let start = Instant::now();
        let result = self.client.del(key).await;
        let latency_ns = start.elapsed().as_nanos() as u64;
        self.record(&CommandResult {
            command: CommandType::Del,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
        });
        result
    }

    /// Ping the server.
    pub async fn ping(&mut self) -> Result<(), Error> {
        let start = Instant::now();
        let result = self.client.ping().await;
        let latency_ns = start.elapsed().as_nanos() as u64;
        self.record(&CommandResult {
            command: CommandType::Ping,
            latency_ns,
            hit: None,
            success: result.is_ok(),
            ttfb_ns: None,
        });
        result
    }

    // ── Zero-copy SET ───────────────────────────────────────────────────

    /// SET with zero-copy value via SendGuard.
    pub async fn set_with_guard<G: SendGuard>(
        &mut self,
        key: &[u8],
        guard: G,
    ) -> Result<(), Error> {
        let start = Instant::now();
        let result = self.client.set_with_guard(key, guard).await;
        let latency_ns = start.elapsed().as_nanos() as u64;
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
        let start = Instant::now();
        let result = self.client.set_ex_with_guard(key, guard, ttl_secs).await;
        let latency_ns = start.elapsed().as_nanos() as u64;
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
