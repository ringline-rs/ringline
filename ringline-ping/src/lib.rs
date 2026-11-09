//! ringline-native Ping client for use inside the ringline async runtime.
//!
//! This client wraps a [`ringline::Connection`] and provides a typed `ping()`
//! method that sends `PING\r\n` and waits for a `PONG` response.
//!
//! # Example
//!
//! ```no_run
//! use ringline::Connection;
//! use ringline_ping::Client;
//!
//! async fn example(conn: Connection) -> Result<(), ringline_ping::Error> {
//!     let mut client = Client::new(conn);
//!     client.ping().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Copy Semantics
//!
//! | Path | Copies | Mechanism |
//! |------|--------|-----------|
//! | **Recv** | **0** | `with_data()` pattern-matches `PONG\r\n` -- no value extraction. |
//! | **Send** | 1 | 6-byte `PING\r\n` copied into the send pool. |

pub mod pool;
pub use pool::{Pool, PoolConfig, PooledClient};

use std::io;
use std::time::Instant;

use ping_proto::{Request as PingRequest, Response as PingResponse};
use ringline::{Connection, ParseResult, RecvArrival, RecvHalf, SendHalf};

// -- Error -------------------------------------------------------------------

/// Errors returned by the ringline Ping client.
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
    /// Every pooled connection is currently checked out.
    ///
    /// Distinct from [`AllConnectionsFailed`](Self::AllConnectionsFailed):
    /// nothing failed and no connect was attempted. Drop a
    /// [`PooledClient`] or size the pool for the number of
    /// concurrent users.
    #[error("every pooled connection is checked out")]
    PoolExhausted,
}

// ── Command types ───────────────────────────────────────────────────────

/// The type of Ping command that completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommandType {
    Ping,
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
    /// Whether the command succeeded (no error response).
    pub success: bool,
    /// Bytes transmitted for this command (protocol-encoded request size).
    pub tx_bytes: u32,
    /// Bytes received for this command (protocol-encoded response size).
    pub rx_bytes: u32,
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

type ResultCallback = Box<dyn Fn(&CommandResult)>;

/// Builder for creating a [`Client`] with per-request callbacks and metrics.
pub struct ClientBuilder {
    conn: Connection,
    on_result: Option<ResultCallback>,
    #[cfg(feature = "metrics")]
    with_metrics: bool,
}

impl ClientBuilder {
    pub(crate) fn new(conn: Connection) -> Self {
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

    /// Build the client.
    ///
    /// Cannot fail; see [`Client::new`].
    pub fn build(self) -> Client {
        // Destructure first: `Connection::split` consumes the connection and
        // the other fields are still needed.
        let Self {
            conn,
            on_result,
            #[cfg(feature = "metrics")]
            with_metrics,
        } = self;
        let (tx, rx) = conn.split();
        Client {
            tx,
            rx,
            on_result,
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

/// A ringline-native Ping client wrapping a single connection.
///
/// `Client::new(conn)` creates a zero-overhead client with no callbacks or
/// metrics. Use `Client::builder(conn)` to configure per-request callbacks
/// and built-in histogram tracking.
pub struct Client {
    tx: SendHalf,
    rx: RecvHalf,
    on_result: Option<ResultCallback>,
    #[cfg(feature = "metrics")]
    metrics: Option<ClientMetrics>,
}

impl Client {
    /// Create a new client wrapping an established connection.
    ///
    /// No callbacks, no metrics — zero overhead.
    ///
    /// Cannot fail: a [`Connection`] already owns both halves (#528).
    pub fn new(conn: Connection) -> Self {
        let (tx, rx) = conn.split();
        Self {
            tx,
            rx,
            on_result: None,
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

    /// Is the connection still usable: no close has been requested, and the
    /// server has not closed its side (a reply could still arrive)?
    pub fn is_alive(&self) -> bool {
        self.tx.is_alive() && !self.rx.peer_closed()
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

    // ── Internal I/O (unchanged) ────────────────────────────────────────

    /// Read and parse a single Ping response from the connection.
    ///
    /// Returns the result, the bytes read, and, on an instrumented client,
    /// the arrival times of those bytes.
    ///
    /// On `Error::Protocol` (parse failure) the underlying connection is
    /// closed: even though the parser advanced past the malformed bytes,
    /// the request/response framing is now irrecoverably misaligned and
    /// the next `ping()` would read garbage. Surfacing `Protocol` as a
    /// terminal error matches the memcache client (PR #177) and avoids
    /// silently desynced clients.
    pub(crate) async fn read_response(
        &mut self,
    ) -> (Result<PingResponse, Error>, u32, Option<RecvArrival>) {
        let mut result: Option<Result<PingResponse, Error>> = None;
        let n = self
            .rx
            .with_data(|data| match PingResponse::parse(data) {
                Ok((response, consumed)) => {
                    result = Some(Ok(response));
                    ParseResult::Consumed(consumed)
                }
                Err(ping_proto::ParseError::Incomplete) => ParseResult::Consumed(0),
                Err(e) => {
                    result = Some(Err(Error::Protocol(e)));
                    ParseResult::Consumed(data.len())
                }
            })
            .await;
        let arrival = if self.is_instrumented() {
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

    /// Send an encoded command and read the response. A send error reads
    /// nothing: 0 bytes and no arrival.
    async fn execute(
        &mut self,
        encoded: &[u8],
    ) -> (Result<PingResponse, Error>, u32, Option<RecvArrival>) {
        if let Err(e) = self.tx.send(encoded) {
            return (Err(e.into()), 0, None);
        }
        self.read_response().await
    }

    // -- Commands -------------------------------------------------------------

    /// Send a PING and wait for a PONG response.
    pub async fn ping(&mut self) -> Result<(), Error> {
        let mut buf = [0u8; 6];
        let len = PingRequest::Ping.encode(&mut buf);

        if !self.is_instrumented() {
            let response = self.execute(&buf[..len]).await.0?;
            return match response {
                PingResponse::Pong => Ok(()),
                #[allow(unreachable_patterns)]
                _ => Err(Error::UnexpectedResponse),
            };
        }

        let tx_bytes = len as u32;
        let start = Instant::now();
        let (response, rx_bytes, arrival) = self.execute(&buf[..len]).await;
        let latency_ns = elapsed_ns(start);
        let (ttfb_ns, ttlb_ns) = arrival_ns(arrival.as_ref(), start);

        let result = match response {
            Ok(PingResponse::Pong) => Ok(()),
            Ok(_) => Err(Error::UnexpectedResponse),
            Err(e) => Err(e),
        };
        self.record(&CommandResult {
            command: CommandType::Ping,
            latency_ns,
            ttfb_ns,
            ttlb_ns,
            success: result.is_ok(),
            tx_bytes,
            rx_bytes,
        });
        result
    }
}

// ── Timing helper ──────────────────────────────────────────────────────────

/// Nanoseconds elapsed since `start`.
#[inline]
fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos() as u64
}

/// Nanoseconds from `start` to the arrival of the first and of the last
/// response byte. `None` when there is no arrival, or for a time before
/// `start`.
fn arrival_ns(arrival: Option<&RecvArrival>, start: Instant) -> (Option<u64>, Option<u64>) {
    let since = |t: Instant| t.checked_duration_since(start).map(|d| d.as_nanos() as u64);
    match arrival {
        Some(a) => (since(a.first()), since(a.last())),
        None => (None, None),
    }
}
