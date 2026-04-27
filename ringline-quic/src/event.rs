use bytes::Bytes;
use quinn_proto::{ConnectionError, Dir, StreamId, VarInt};

/// Opaque identifier for a QUIC connection within a [`QuicEndpoint`](crate::QuicEndpoint).
///
/// Wraps a slab index. Use [`index()`](QuicConnId::index) for per-connection
/// state arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuicConnId(pub(crate) u32);

impl QuicConnId {
    /// Returns the underlying index, suitable for indexing per-connection arrays.
    pub fn index(&self) -> usize {
        self.0 as usize
    }
}

/// Application-facing events produced by [`QuicEndpoint`](crate::QuicEndpoint).
///
/// Poll these via [`QuicEndpoint::poll_event()`](crate::QuicEndpoint::poll_event).
#[derive(Debug)]
pub enum QuicEvent {
    /// An inbound QUIC connection completed its handshake.
    NewConnection(QuicConnId),

    /// An outbound QUIC connection completed its handshake.
    Connected(QuicConnId),

    /// The peer opened a new stream.
    StreamOpened {
        conn: QuicConnId,
        stream: StreamId,
        bidi: bool,
    },

    /// Data is available to read on a stream.
    StreamReadable { conn: QuicConnId, stream: StreamId },

    /// Flow control window opened — the stream is writable again.
    StreamWritable { conn: QuicConnId, stream: StreamId },

    /// A send stream has been fully acknowledged by the peer.
    StreamFinished { conn: QuicConnId, stream: StreamId },

    /// The peer asked us to stop sending on this stream
    /// (peer called the equivalent of `stop_sending`).
    ///
    /// After this event, further writes on `stream` will fail; the stream
    /// can no longer be flushed to the peer.
    StreamStopped {
        conn: QuicConnId,
        stream: StreamId,
        error_code: VarInt,
    },

    /// The peer raised the per-direction stream concurrency limit, so a
    /// previously-rejected `open_bi` / `open_uni` may now succeed.
    ///
    /// Quinn-proto only fires this once per "limit was hit, then opened
    /// up" cycle. Applications that bumped into the limit should use
    /// this as a signal to retry their open call rather than polling.
    StreamsAvailable { conn: QuicConnId, dir: Dir },

    /// An unreliable QUIC datagram (RFC 9221) was received from the peer.
    DatagramReceived { conn: QuicConnId, data: Bytes },

    /// A QUIC connection was closed or lost.
    ConnectionClosed {
        conn: QuicConnId,
        reason: ConnectionError,
    },
}
