/// Errors produced by the HTTP/3 framing layer.
#[derive(Debug)]
pub enum H3Error {
    /// QUIC transport error.
    Quic(ringline_quic::Error),
    /// Received a frame type reserved from HTTP/2 (0x02, 0x06, 0x08, 0x09).
    FrameUnexpected,
    /// Control stream did not start with a SETTINGS frame.
    MissingSettings,
    /// Frame decoding error (truncated varint, invalid payload, etc.).
    FrameError,
    /// QPACK header block decoding failed.
    QpackDecodingFailed,
    /// A critical stream (control) was closed prematurely.
    ClosedCriticalStream,
    /// Internal error with a description.
    Internal(String),
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quic(e) => write!(f, "quic: {e}"),
            Self::FrameUnexpected => write!(f, "unexpected frame type"),
            Self::MissingSettings => write!(f, "missing SETTINGS on control stream"),
            Self::FrameError => write!(f, "frame error"),
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
