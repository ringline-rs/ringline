/// HTTP/2 error codes (RFC 7540 Section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

impl ErrorCode {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x2 => Self::InternalError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            _ => Self::InternalError,
        }
    }
}

/// Errors produced by the HTTP/2 framing layer.
#[derive(Debug)]
pub enum H2Error {
    /// Frame decoding error (truncated, invalid payload, etc.).
    FrameError,
    /// Received a frame that violates the protocol.
    ProtocolError(String),
    /// HPACK header compression/decompression error.
    CompressionError,
    /// Flow control violation.
    FlowControlError,
    /// Frame size exceeds the maximum allowed.
    FrameSizeError,
    /// Connection-level error with an error code.
    ConnectionError(ErrorCode),
    /// Stream-level error with an error code.
    StreamError(u32, ErrorCode),
    /// Internal error with a description.
    Internal(String),
}

impl std::fmt::Display for H2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameError => write!(f, "frame error"),
            Self::ProtocolError(s) => write!(f, "protocol error: {s}"),
            Self::CompressionError => write!(f, "HPACK compression error"),
            Self::FlowControlError => write!(f, "flow control error"),
            Self::FrameSizeError => write!(f, "frame size error"),
            Self::ConnectionError(code) => write!(f, "connection error: {code:?}"),
            Self::StreamError(id, code) => write!(f, "stream {id} error: {code:?}"),
            Self::Internal(s) => write!(f, "internal: {s}"),
        }
    }
}

impl std::error::Error for H2Error {}
