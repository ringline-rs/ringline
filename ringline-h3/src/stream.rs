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
    /// Accumulates partial frame data between reads.
    pub recv_buf: Vec<u8>,
}

impl RequestStream {
    pub fn new() -> Self {
        Self {
            state: StreamState::WaitingHeaders,
            recv_buf: Vec::new(),
        }
    }
}
