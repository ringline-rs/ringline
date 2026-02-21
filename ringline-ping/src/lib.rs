//! ringline-native Ping client for use inside the ringline async runtime.
//!
//! This client wraps a [`ringline::ConnCtx`] and provides a typed `ping()`
//! method that sends `PING\r\n` and waits for a `PONG` response.
//!
//! # Example
//!
//! ```no_run
//! use ringline::ConnCtx;
//! use ringline_ping::Client;
//!
//! async fn example(conn: ConnCtx) -> Result<(), ringline_ping::Error> {
//!     let mut client = Client::new(conn);
//!     client.ping().await?;
//!     Ok(())
//! }
//! ```

pub mod pool;
pub use pool::{Pool, PoolConfig};

use std::io;
use std::time::Instant;

use ping_proto::{Request as PingRequest, Response as PingResponse};
use ringline::{ConnCtx, ParseResult};

// -- Error -------------------------------------------------------------------

/// Errors returned by the ringline Ping client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The connection was closed before a response was received.
    #[error("connection closed")]
    ConnectionClosed,

    /// The response type did not match the expected type for the command.
    #[error("unexpected response")]
    UnexpectedResponse,

    /// Ping protocol parse error.
    #[error("protocol error: {0}")]
    Protocol(#[from] ping_proto::ParseError),

    /// I/O error during send.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// All connections in the pool are down and reconnection failed.
    #[error("all connections failed")]
    AllConnectionsFailed,
}

// ── Command types ───────────────────────────────────────────────────────

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

/// Built-in histogram-based metrics, available when the `metrics` feature is
/// enabled.
#[cfg(feature = "metrics")]
pub struct ClientMetrics {
    /// Ping latency histogram.
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

/// A ringline-native Ping client wrapping a single connection.
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

    /// Read and parse a single Ping response from the connection.
    pub(crate) async fn read_response(&self) -> Result<PingResponse, Error> {
        let mut result: Option<Result<PingResponse, Error>> = None;
        let n = self
            .conn
            .with_data(|data| match PingResponse::parse(data) {
                Ok((response, consumed)) => {
                    result = Some(Ok(response));
                    ParseResult::Consumed(consumed)
                }
                Err(ping_proto::ParseError::Incomplete) => ParseResult::Consumed(0),
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

    /// Send an encoded command and read the response.
    async fn execute(&self, encoded: &[u8]) -> Result<PingResponse, Error> {
        self.conn.send(encoded)?;
        self.read_response().await
    }

    // -- Commands -------------------------------------------------------------

    /// Send a PING and wait for a PONG response.
    pub async fn ping(&mut self) -> Result<(), Error> {
        let mut buf = [0u8; 6];
        let len = PingRequest::Ping.encode(&mut buf);

        if !self.is_instrumented() {
            let response = self.execute(&buf[..len]).await?;
            return match response {
                PingResponse::Pong => Ok(()),
                #[allow(unreachable_patterns)]
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let send_ts = self.send_timestamp();
        let start = Instant::now();
        let response = self.execute(&buf[..len]).await;
        let latency_ns = self.finish_timing(send_ts, start);

        let result = match response {
            Ok(PingResponse::Pong) => Ok(()),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Ping,
            latency_ns,
            success: result.is_ok(),
            ttfb_ns: None,
        });
        result
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
