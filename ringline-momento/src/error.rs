//! Error types for the Momento client.

use std::io;

/// Result type for Momento operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when using the Momento client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The connection was closed before a response was received.
    #[error("connection closed")]
    ConnectionClosed,

    /// Not authenticated (auth command not yet completed).
    #[error("not authenticated")]
    NotAuthenticated,

    /// Authentication with Momento failed.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Protocol-level error (malformed response, unexpected message type).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Configuration error (bad token, missing env var).
    #[error("config error: {0}")]
    Config(String),

    /// I/O error during send or recv.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// All connections in the pool are down and reconnection failed.
    #[error("all connections failed")]
    AllConnectionsFailed,
}
