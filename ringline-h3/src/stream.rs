//! Per-stream state tracking for HTTP/3 request streams.

/// State of an HTTP/3 request stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamState {
    /// Waiting for the initial HEADERS frame.
    WaitingHeaders,
    /// Headers received; may receive DATA frames.
    Open,
    /// Peer sent FIN (no more incoming data).
    HalfClosedRemote,
    /// We sent FIN (no more outgoing data).
    HalfClosedLocal,
    /// Fully closed.
    Closed,
}

/// Tracks the state and partial data for a single HTTP/3 request stream.
pub(crate) struct RequestStream {
    /// Current stream state.
    pub state: StreamState,
    /// Accumulates partial frame data between reads. `BytesMut` (rather
    /// than `Vec<u8>`) lets us freeze a consumed prefix into a `Bytes`
    /// and slice DATA payloads zero-copy out of it instead of memcpy'ing
    /// the body into a fresh `Vec` in the frame decoder.
    pub recv_buf: bytes::BytesMut,
    /// Whether this stream was opened by us (client request) or the peer (server request).
    pub client_initiated: bool,
    /// True once we have processed the initial HEADERS from the peer. A
    /// HEADERS frame *after* this point is trailers (and must be the last
    /// frame on the stream). Tracked independently of `state` because
    /// `HalfClosedLocal` (we sent FIN) does not imply we've seen the peer's
    /// initial HEADERS yet.
    pub initial_headers_received: bool,
    /// True once a trailing HEADERS frame has been processed. After that any
    /// further frame on this stream is `H3_FRAME_UNEXPECTED`.
    pub trailers_received: bool,
}

impl RequestStream {
    pub fn new(client_initiated: bool) -> Self {
        Self {
            state: StreamState::WaitingHeaders,
            recv_buf: bytes::BytesMut::new(),
            client_initiated,
            initial_headers_received: false,
            trailers_received: false,
        }
    }
}
