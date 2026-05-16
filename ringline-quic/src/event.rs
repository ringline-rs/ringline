use std::net::SocketAddr;

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

    /// The outgoing datagram buffer for this connection has space again
    /// after a previous `Error::DatagramBlocked(Bytes)`. The application
    /// should retry whatever payload it was holding.
    DatagramsUnblocked { conn: QuicConnId },

    /// The server has parsed enough of the client's ClientHello to answer
    /// questions about ALPN / SNI / cert selection — but the full handshake
    /// has not yet completed (no `NewConnection` event yet).
    ///
    /// Servers that need per-SNI dispatch or per-ALPN routing inspect
    /// `quinn_proto::Connection::crypto_session().handshake_data()` from
    /// this event. Fires once per inbound connection.
    HandshakeDataReady { conn: QuicConnId },

    /// 0-RTT was attempted on this outbound connection but the peer
    /// rejected it. Anything sent before the handshake completed has
    /// been discarded by quinn-proto and must be re-sent over 1-RTT.
    ///
    /// Fires once, after the handshake completes (alongside or just
    /// after `Connected`). Only fires for outbound connections that
    /// genuinely had 0-RTT keys — connections that never had keys
    /// don't generate the event.
    ZeroRttRejected { conn: QuicConnId },

    /// The peer's address changed (NAT rebinding, mobile network handoff,
    /// etc.) and quinn-proto has *initiated* path migration. This event
    /// fires the moment quinn updates `Connection::remote_address()` —
    /// which happens synchronously when a non-probing packet arrives from
    /// a new source address — **not** after PATH_CHALLENGE / PATH_RESPONSE
    /// validation completes. Until validation finishes the new path is
    /// still on probation: quinn caps bytes-in-flight to roughly 3× the
    /// validated amount, and will fall back to the previous path if the
    /// challenge fails.
    ///
    /// Applications that key per-peer state on the source address (logs,
    /// abuse rate limits) should treat this as "the peer *claims* to be at
    /// `current` now"; the path is unsafe to trust for unbounded data
    /// until validation completes.
    ///
    /// Server-side migration is gated on
    /// [`quinn_proto::ServerConfig::migration`] (default true). If
    /// `migration` is false, peer-initiated path changes are dropped
    /// and this event never fires.
    PeerAddressChanged {
        conn: QuicConnId,
        previous: SocketAddr,
        current: SocketAddr,
    },

    /// A QUIC connection was closed or lost.
    ConnectionClosed {
        conn: QuicConnId,
        reason: ConnectionError,
    },
}
