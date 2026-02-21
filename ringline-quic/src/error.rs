use std::io;

use quinn_proto::{ConnectError, ConnectionError, ReadError, ReadableError, WriteError};

/// Errors returned by ringline-quic operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("connection closed")]
    ConnectionClosed,

    #[error("invalid connection")]
    InvalidConnection,

    #[error("connect: {0}")]
    Connect(#[from] ConnectError),

    #[error("connection: {0}")]
    Connection(#[from] ConnectionError),

    #[error("write: {0}")]
    Write(#[from] WriteError),

    #[error("read: {0}")]
    Read(#[from] ReadError),

    #[error("readable: {0}")]
    Readable(#[from] ReadableError),

    #[error("io: {0}")]
    Io(#[from] io::Error),
}
