//! Error types for the Momento client.

use std::io;

/// Result type for Momento operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when using the Momento client.
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

    /// `recv()` was called with no in-flight requests.
    #[error("no pending requests")]
    NoPending,

    /// All connections in the pool are down and reconnection failed.
    #[error("all connections failed")]
    AllConnectionsFailed,

    /// The in-flight pending-op map reached `max_in_flight`. Drain via
    /// `recv()` before issuing more `fire_*` calls. Configurable via
    /// [`crate::ClientBuilder::max_in_flight`].
    #[error("too many in-flight operations")]
    TooManyInFlight,

    /// A sequential API call ([`crate::Client::get`] / `set` / `delete`)
    /// was issued while one or more `fire_*` ops were still in flight.
    /// Momento is multiplexed and `recv()` returns whatever `message_id`
    /// arrives first; the convenience APIs discard the id/key and would
    /// silently return data for the wrong request. Drain `recv()` until
    /// `pending_count() == 0` before calling the sequential API, or use
    /// `fire_*` + `recv()` exclusively.
    #[error("sequential API requires no in-flight fire_* ops; drain recv() first")]
    PendingOpsInFlight,
}
