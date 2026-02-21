use quinn_proto::{ConnectionError, StreamId};

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

    /// A QUIC connection was closed or lost.
    ConnectionClosed {
        conn: QuicConnId,
        reason: ConnectionError,
    },
}
