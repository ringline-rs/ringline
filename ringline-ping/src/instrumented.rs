//! Instrumented Ping client with per-request latency callbacks and optional
//! built-in histogram tracking.

use std::time::Instant;

use ringline::ConnCtx;

use crate::{Client, Error};

/// Callback type for per-command result notifications.
type ResultCallback = Box<dyn Fn(&CommandResult)>;

// ── Types ───────────────────────────────────────────────────────────────

/// The type of Ping command that completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandType {
    Ping,
}

/// Result metadata for a completed command, passed to the `on_result` callback.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// The command type.
    pub command: CommandType,
    /// Latency in nanoseconds (send → response parsed).
    pub latency_ns: u64,
    /// Whether the command succeeded (no error response).
    pub success: bool,
    /// Time-to-first-byte in nanoseconds (not available in sequential mode).
    pub ttfb_ns: Option<u64>,
}

// ── ClientMetrics ───────────────────────────────────────────────────────

#[cfg(feature = "metrics")]
pub struct ClientMetrics {
    pub latency: histogram::Histogram,
    pub requests: u64,
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

/// A Ping client wrapper that measures per-request latency and invokes
/// an optional callback after each command.
pub struct InstrumentedClient {
    client: Client,
    on_result: Option<ResultCallback>,
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

    /// Send a PING and wait for a PONG response.
    pub async fn ping(&mut self) -> Result<(), Error> {
        let start = Instant::now();
        let result = self.client.ping().await;
        let latency_ns = start.elapsed().as_nanos() as u64;
        self.record(&CommandResult {
            command: CommandType::Ping,
            latency_ns,
            success: result.is_ok(),
            ttfb_ns: None,
        });
        result
    }
}
