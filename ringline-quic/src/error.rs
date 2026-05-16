use std::io;

use bytes::Bytes;
use quinn_proto::{ConnectError, ConnectionError, ReadError, ReadableError, VarInt, WriteError};

/// Errors returned by ringline-quic operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("connection closed")]
    ConnectionClosed,

    /// The connection has been locally closed but quinn-proto is still in
    /// its draining window — distinguished from `ConnectionClosed` so
    /// callers don't retry sends in a tight loop.
    #[error("connection is closing")]
    ConnectionClosing,

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

    /// Operation targeted a stream that has already been finished, reset,
    /// or stopped. Distinguished from connection-level closure so callers
    /// can surface stream-scoped errors without tearing the connection.
    #[error("stream is closed")]
    StreamClosed,

    /// Peer issued STOP_SENDING with the given application error code.
    /// Surfaced from `stream_finish` (and any future send that races the
    /// STOP) so the caller learns the application-defined reason.
    #[error("peer stopped sending: code={}", .0.into_inner())]
    StreamStopped(VarInt),

    /// Datagrams are disabled by local transport config — sends will never
    /// succeed on this connection.
    #[error("datagrams disabled locally")]
    DatagramDisabled,

    /// Datagrams are disabled by the peer — sends will never succeed on
    /// this connection.
    #[error("datagrams unsupported by peer")]
    DatagramUnsupportedByPeer,

    /// Datagram payload exceeded the peer's `max_datagram_size`. Caller
    /// must split or shrink.
    #[error("datagram too large for peer")]
    DatagramTooLarge,

    /// The outgoing datagram buffer is full. `Bytes` carries back the
    /// caller's original payload so it can be re-sent on the next
    /// `QuicEvent::DatagramsUnblocked` without re-allocating.
    #[error("datagram buffer blocked")]
    DatagramBlocked(Bytes),

    #[error("io: {0}")]
    Io(#[from] io::Error),
}
