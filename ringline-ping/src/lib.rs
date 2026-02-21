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
//!     let client = Client::new(conn);
//!     client.ping().await?;
//!     Ok(())
//! }
//! ```

pub mod instrumented;
pub mod pool;
pub use instrumented::{ClientBuilder, CommandResult, CommandType, InstrumentedClient};
pub use pool::{Pool, PoolConfig};

use std::io;

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

// -- Client ------------------------------------------------------------------

/// A ringline-native Ping client wrapping a single connection.
///
/// `Client` is `Copy` because `ConnCtx` is `Copy`. There is no pooling
/// or channel overhead — commands go directly over the connection.
#[derive(Clone, Copy)]
pub struct Client {
    conn: ConnCtx,
}

impl Client {
    /// Create a new client wrapping an established connection.
    pub fn new(conn: ConnCtx) -> Self {
        Self { conn }
    }

    /// Returns the underlying connection context.
    pub fn conn(&self) -> ConnCtx {
        self.conn
    }

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
    pub async fn ping(&self) -> Result<(), Error> {
        let mut buf = [0u8; 6];
        let len = PingRequest::Ping.encode(&mut buf);
        let response = self.execute(&buf[..len]).await?;
        match response {
            PingResponse::Pong => Ok(()),
            #[allow(unreachable_patterns)]
            _ => Err(Error::UnexpectedResponse),
        }
    }

    // -- Builder ---------------------------------------------------------------

    /// Create a builder for an instrumented client with per-request callbacks.
    pub fn builder(conn: ConnCtx) -> ClientBuilder {
        ClientBuilder::new(conn)
    }
}
