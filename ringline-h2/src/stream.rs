//! Per-stream state tracking for HTTP/2 (RFC 7540 Section 5.1).

use crate::flowcontrol::FlowControl;

/// State of an HTTP/2 stream (RFC 7540 Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StreamState {
    /// Stream created but no frames sent.
    Idle,
    /// HEADERS sent, waiting for response (client-side).
    Open,
    /// We sent END_STREAM (no more outgoing data).
    HalfClosedLocal,
    /// Peer sent END_STREAM (no more incoming data).
    HalfClosedRemote,
    /// Fully closed (both sides done, or RST_STREAM received/sent).
    Closed,
}

/// Tracks the state and flow control for a single HTTP/2 stream.
pub(crate) struct H2Stream {
    pub state: StreamState,
    pub recv_window: FlowControl,
    pub send_window: FlowControl,
    /// Accumulates partial header block fragments (HEADERS + CONTINUATION).
    pub header_buf: Vec<u8>,
    /// Whether we are in the middle of receiving a header block.
    pub receiving_headers: bool,
    /// Whether the HEADERS/CONTINUATION that started this header block
    /// had END_STREAM set.
    pub headers_end_stream: bool,
}

impl H2Stream {
    pub fn new(initial_recv_window: i64, initial_send_window: i64) -> Self {
        Self {
            state: StreamState::Open,
            recv_window: FlowControl::new(initial_recv_window),
            send_window: FlowControl::new(initial_send_window),
            header_buf: Vec::new(),
            receiving_headers: false,
            headers_end_stream: false,
        }
    }
}
