/// HTTP/3 error codes (RFC 9114 §8.1).
///
/// Used as the `error_code` argument to `QuicEndpoint::close_connection` /
/// `reset_stream` / `stop_sending` when the H3 layer surfaces a protocol
/// violation. The numeric values are wire-format and must not change.
pub mod error_code {
    pub const H3_NO_ERROR: u32 = 0x100;
    pub const H3_GENERAL_PROTOCOL_ERROR: u32 = 0x101;
    pub const H3_INTERNAL_ERROR: u32 = 0x102;
    pub const H3_STREAM_CREATION_ERROR: u32 = 0x103;
    pub const H3_CLOSED_CRITICAL_STREAM: u32 = 0x104;
    pub const H3_FRAME_UNEXPECTED: u32 = 0x105;
    pub const H3_FRAME_ERROR: u32 = 0x106;
    pub const H3_EXCESSIVE_LOAD: u32 = 0x107;
    pub const H3_ID_ERROR: u32 = 0x108;
    pub const H3_SETTINGS_ERROR: u32 = 0x109;
    pub const H3_MISSING_SETTINGS: u32 = 0x10a;
    pub const H3_REQUEST_REJECTED: u32 = 0x10b;
    pub const H3_REQUEST_CANCELLED: u32 = 0x10c;
    pub const H3_REQUEST_INCOMPLETE: u32 = 0x10d;
    pub const H3_MESSAGE_ERROR: u32 = 0x10e;
    pub const H3_CONNECT_ERROR: u32 = 0x10f;
    pub const H3_VERSION_FALLBACK: u32 = 0x110;
}

/// Errors produced by the HTTP/3 framing layer.
///
/// Marked `#[non_exhaustive]` because new error kinds are expected as RFC
/// coverage grows. Downstream `match` blocks must include a wildcard arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum H3Error {
    /// QUIC transport error.
    Quic(ringline_quic::Error),
    /// Received a frame type reserved from HTTP/2 (0x02, 0x06, 0x08, 0x09)
    /// or a frame on a stream where it isn't permitted (DATA on the control
    /// stream, GOAWAY on a request stream, HEADERS after trailers, etc.).
    FrameUnexpected,
    /// Control stream did not start with a SETTINGS frame.
    MissingSettings,
    /// Frame decoding error (truncated varint, invalid payload, duplicate
    /// SETTINGS identifier, etc.).
    FrameError,
    /// A frame's declared payload length exceeds the implementation limit.
    ExcessiveSize,
    /// QPACK header block decoding failed.
    QpackDecodingFailed,
    /// A critical stream (control) was closed prematurely.
    ClosedCriticalStream,
    /// Pseudo-header / message-level validation failed (missing required
    /// pseudo-header, duplicate pseudo-header, forbidden connection-specific
    /// field, etc.).
    MessageError,
    /// An illegal stream type was opened by the peer (server pushed without
    /// prior MAX_PUSH_ID, client opened a push stream, etc.).
    IdError,
    /// Locally-buffered outbound bytes for a stream exceeded the configured
    /// `max_pending_bytes` ceiling. Callers should drain pending writes (poll
    /// for `StreamWritable`) before trying again.
    BackpressureExceeded,
    /// Internal error with a description.
    Internal(String),
}

impl H3Error {
    /// Wire-format HTTP/3 error code for this error, used when closing the
    /// connection / resetting a stream in response to the violation.
    pub fn code(&self) -> u32 {
        use error_code::*;
        match self {
            Self::Quic(_) | Self::Internal(_) => H3_INTERNAL_ERROR,
            Self::FrameUnexpected => H3_FRAME_UNEXPECTED,
            Self::MissingSettings => H3_MISSING_SETTINGS,
            Self::FrameError => H3_FRAME_ERROR,
            Self::ExcessiveSize => H3_EXCESSIVE_LOAD,
            Self::QpackDecodingFailed => H3_FRAME_ERROR,
            Self::ClosedCriticalStream => H3_CLOSED_CRITICAL_STREAM,
            Self::MessageError => H3_MESSAGE_ERROR,
            Self::IdError => H3_ID_ERROR,
            Self::BackpressureExceeded => H3_EXCESSIVE_LOAD,
        }
    }
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quic(e) => write!(f, "quic: {e}"),
            Self::FrameUnexpected => write!(f, "unexpected frame type"),
            Self::MissingSettings => write!(f, "missing SETTINGS on control stream"),
            Self::FrameError => write!(f, "frame error"),
            Self::ExcessiveSize => write!(f, "frame payload exceeds size limit"),
            Self::MessageError => write!(f, "HTTP message validation failed"),
            Self::IdError => write!(f, "illegal stream type from peer"),
            Self::BackpressureExceeded => write!(f, "outbound pending bytes exceeded limit"),
            Self::QpackDecodingFailed => write!(f, "QPACK decoding failed"),
            Self::ClosedCriticalStream => write!(f, "critical stream closed"),
            Self::Internal(s) => write!(f, "internal: {s}"),
        }
    }
}

impl std::error::Error for H3Error {}

impl From<ringline_quic::Error> for H3Error {
    fn from(e: ringline_quic::Error) -> Self {
        Self::Quic(e)
    }
}
