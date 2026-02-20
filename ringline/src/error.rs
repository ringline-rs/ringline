use std::io;

use thiserror::Error;

/// Errors returned by the ringline driver.
#[derive(Debug, Error)]
pub enum Error {
    /// io_uring setup or operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Ring setup failed (e.g., unsupported kernel features).
    #[error("ring setup: {0}")]
    RingSetup(String),
    /// Buffer registration failed.
    #[error("buffer registration: {0}")]
    BufferRegistration(String),
    /// No free connection slots available.
    #[error("connection limit reached")]
    ConnectionLimitReached,
    /// Invalid connection token (stale or out of range).
    #[error("invalid connection")]
    InvalidConnection,
    /// No send pool slots available.
    #[error("send pool exhausted")]
    SendPoolExhausted,
    /// Invalid memory region ID.
    #[error("invalid memory region ID")]
    InvalidRegion,
    /// Pointer not within the specified registered region.
    #[error("pointer not within registered region")]
    PointerOutOfRegion,
    /// System resource limit too low (e.g., RLIMIT_NOFILE).
    #[error("{0}")]
    ResourceLimit(String),
}

/// Errors returned by UDP send operations.
#[derive(Debug, Error)]
pub enum UdpSendError {
    /// UDP send pool exhausted.
    #[error("UDP send pool exhausted")]
    PoolExhausted,
    /// UDP send already in-flight.
    #[error("UDP send already in-flight")]
    SendInFlight,
    /// UDP submission queue full.
    #[error("UDP submission queue full")]
    SubmissionQueueFull,
    /// UDP I/O error.
    #[error("UDP I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Error returned by [`try_sleep`](crate::try_sleep) and
/// [`try_timeout`](crate::try_timeout) when the timer slot pool is full.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("timer slot pool exhausted")]
pub struct TimerExhausted;
