/// gRPC status codes (<https://grpc.github.io/grpc/core/md_doc_statuscodes.html>).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// Parse a status code from an integer value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::Cancelled,
            2 => Self::Unknown,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            10 => Self::Aborted,
            11 => Self::OutOfRange,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            14 => Self::Unavailable,
            15 => Self::DataLoss,
            16 => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for GrpcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Cancelled => write!(f, "CANCELLED"),
            Self::Unknown => write!(f, "UNKNOWN"),
            Self::InvalidArgument => write!(f, "INVALID_ARGUMENT"),
            Self::DeadlineExceeded => write!(f, "DEADLINE_EXCEEDED"),
            Self::NotFound => write!(f, "NOT_FOUND"),
            Self::AlreadyExists => write!(f, "ALREADY_EXISTS"),
            Self::PermissionDenied => write!(f, "PERMISSION_DENIED"),
            Self::ResourceExhausted => write!(f, "RESOURCE_EXHAUSTED"),
            Self::FailedPrecondition => write!(f, "FAILED_PRECONDITION"),
            Self::Aborted => write!(f, "ABORTED"),
            Self::OutOfRange => write!(f, "OUT_OF_RANGE"),
            Self::Unimplemented => write!(f, "UNIMPLEMENTED"),
            Self::Internal => write!(f, "INTERNAL"),
            Self::Unavailable => write!(f, "UNAVAILABLE"),
            Self::DataLoss => write!(f, "DATA_LOSS"),
            Self::Unauthenticated => write!(f, "UNAUTHENTICATED"),
        }
    }
}

/// Errors produced by the gRPC framing layer.
#[derive(Debug)]
pub enum GrpcError {
    /// Underlying HTTP/2 error.
    H2(ringline_h2::H2Error),
    /// Invalid gRPC message framing (truncated prefix, etc.).
    InvalidMessage(String),
    /// Connection is not ready (settings exchange incomplete).
    NotReady,
}

impl std::fmt::Display for GrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::H2(e) => write!(f, "h2: {e}"),
            Self::InvalidMessage(s) => write!(f, "invalid grpc message: {s}"),
            Self::NotReady => write!(f, "connection not ready"),
        }
    }
}

impl std::error::Error for GrpcError {}

impl From<ringline_h2::H2Error> for GrpcError {
    fn from(e: ringline_h2::H2Error) -> Self {
        Self::H2(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trip() {
        for code in 0..=16u8 {
            let status = GrpcStatus::from_u8(code);
            assert_eq!(status as u8, code);
        }
    }

    #[test]
    fn unknown_status_code() {
        assert_eq!(GrpcStatus::from_u8(99), GrpcStatus::Unknown);
        assert_eq!(GrpcStatus::from_u8(255), GrpcStatus::Unknown);
    }

    #[test]
    fn status_display() {
        assert_eq!(GrpcStatus::Ok.to_string(), "OK");
        assert_eq!(GrpcStatus::Internal.to_string(), "INTERNAL");
        assert_eq!(GrpcStatus::Unauthenticated.to_string(), "UNAUTHENTICATED");
    }

    #[test]
    fn error_display() {
        let err = GrpcError::NotReady;
        assert_eq!(err.to_string(), "connection not ready");

        let err = GrpcError::InvalidMessage("bad prefix".into());
        assert_eq!(err.to_string(), "invalid grpc message: bad prefix");
    }
}
