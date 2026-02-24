use std::io;

use ringline_h2::H2Error;

/// Errors produced by the HTTP client.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The connection was closed unexpectedly.
    #[error("connection closed")]
    ConnectionClosed,

    /// HTTP/2 framing error.
    #[error("h2 error: {0}")]
    H2(#[from] H2Error),

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Invalid URL or path.
    #[error("invalid url: {0}")]
    InvalidUrl(String),

    /// Response parsing error.
    #[error("parse error")]
    Parse,

    /// Request timed out.
    #[error("timeout")]
    Timeout,

    /// H2 flow control blocked and could not be resolved.
    #[error("flow control error")]
    FlowControl,

    /// All connections in a pool failed.
    #[error("all connections failed")]
    AllConnectionsFailed,

    /// Protocol error (unexpected event, bad state).
    #[error("protocol error: {0}")]
    Protocol(String),
}
