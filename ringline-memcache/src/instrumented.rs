//! Instrumented Memcache client with per-request latency callbacks and optional
//! built-in histogram tracking.

use std::time::Instant;

use ringline::{ConnCtx, SendGuard};

use crate::{Client, Error, Value};

// ── Types ───────────────────────────────────────────────────────────────

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

#[cfg(feature = "metrics")]
pub struct ClientMetrics {
    pub latency: histogram::Histogram,
    pub get_latency: histogram::Histogram,
    pub set_latency: histogram::Histogram,
    pub del_latency: histogram::Histogram,
    pub requests: u64,
    pub errors: u64,
    pub hits: u64,
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

pub struct ClientBuilder {
    conn: ConnCtx,
    on_result: Option<Box<dyn Fn(&CommandResult)>>,
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

/// A Memcache client wrapper that measures per-request latency and invokes
/// an optional callback after each command.
pub struct InstrumentedClient {
    client: Client,
    on_result: Option<Box<dyn Fn(&CommandResult)>>,
    #[cfg(feature = "metrics")]
    metrics: Option<ClientMetrics>,
}

impl InstrumentedClient {
    pub fn conn(&self) -> ConnCtx {
        self.client.conn()
    }

    pub fn inner(&self) -> Client {
        self.client
    }

    #[cfg(feature = "metrics")]
    pub fn metrics(&self) -> Option<&ClientMetrics> {
        self.metrics.as_ref()
    }

    #[cfg(feature = "metrics")]
    pub fn metrics_mut(&mut self) -> Option<&mut ClientMetrics> {
        self.metrics.as_mut()
    }

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

    // ── Commands ────────────────────────────────────────────────────────

    /// Get the value of a key.
    pub async fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Value>, Error> {
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

    /// Set a key-value pair with default flags (0) and no expiration.
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

    /// Set a key-value pair with custom flags and expiration time.
    pub async fn set_with_options(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        flags: u32,
        exptime: u32,
    ) -> Result<(), Error> {
        let start = Instant::now();
        let result = self.client.set_with_options(key, value, flags, exptime).await;
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

    /// Delete a key.
    pub async fn delete(&mut self, key: impl AsRef<[u8]>) -> Result<bool, Error> {
        let start = Instant::now();
        let result = self.client.delete(key).await;
        let latency_ns = start.elapsed().as_nanos() as u64;
        self.record(&CommandResult {
            command: CommandType::Delete,
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
        flags: u32,
        exptime: u32,
    ) -> Result<(), Error> {
        let start = Instant::now();
        let result = self.client.set_with_guard(key, guard, flags, exptime).await;
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
