//! Error types for RESP protocol parsing.

/// Error type for RESP parsing operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Need more data to complete parsing.
    /// This is not a fatal error - the caller should buffer more data and retry.
    #[error("incomplete data")]
    Incomplete,

    /// Invalid type prefix byte.
    #[error("invalid prefix byte: {0:#04x}")]
    InvalidPrefix(u8),

    /// Invalid integer format.
    #[error("invalid integer: {0}")]
    InvalidInteger(String),

    /// Invalid bulk string length.
    #[error("invalid bulk string length")]
    InvalidLength,

    /// Protocol violation.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Unknown or unsupported command.
    #[error("unknown command: {0}")]
    UnknownCommand(String),

    /// Wrong number of arguments for command.
    #[error("wrong number of arguments: {0}")]
    WrongArity(String),

    /// Collection size exceeds maximum allowed limit.
    #[error("collection too large: {0} elements exceeds limit")]
    CollectionTooLarge(usize),

    /// Nesting depth exceeds maximum allowed limit.
    #[error("nesting too deep: depth {0} exceeds limit")]
    NestingTooDeep(usize),

    /// Bulk string exceeds maximum allowed size.
    #[error("bulk string too long: {len} bytes exceeds {max} byte limit")]
    BulkStringTooLong { len: usize, max: usize },

    /// Invalid floating point number (RESP3).
    #[cfg(feature = "resp3")]
    #[error("invalid double: {0}")]
    InvalidDouble(String),

    /// Invalid boolean value (RESP3).
    #[cfg(feature = "resp3")]
    #[error("invalid boolean: expected 't' or 'f'")]
    InvalidBoolean,

    /// Invalid verbatim string format (RESP3).
    #[cfg(feature = "resp3")]
    #[error("invalid verbatim string format")]
    InvalidVerbatimFormat,
}

impl ParseError {
    /// Returns true if this error indicates more data is needed.
    #[inline]
    pub fn is_incomplete(&self) -> bool {
        matches!(self, ParseError::Incomplete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_incomplete() {
        assert!(ParseError::Incomplete.is_incomplete());
        assert!(!ParseError::InvalidPrefix(0x00).is_incomplete());
        assert!(!ParseError::InvalidInteger("test".to_string()).is_incomplete());
        assert!(!ParseError::InvalidLength.is_incomplete());
        assert!(!ParseError::Protocol("test".to_string()).is_incomplete());
        assert!(!ParseError::UnknownCommand("test".to_string()).is_incomplete());
        assert!(!ParseError::WrongArity("test".to_string()).is_incomplete());
        assert!(!ParseError::CollectionTooLarge(100).is_incomplete());
        assert!(!ParseError::BulkStringTooLong { len: 100, max: 50 }.is_incomplete());
    }

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", ParseError::Incomplete), "incomplete data");
        assert_eq!(
            format!("{}", ParseError::InvalidPrefix(0x42)),
            "invalid prefix byte: 0x42"
        );
        assert_eq!(
            format!("{}", ParseError::InvalidInteger("bad".to_string())),
            "invalid integer: bad"
        );
        assert_eq!(
            format!("{}", ParseError::InvalidLength),
            "invalid bulk string length"
        );
        assert_eq!(
            format!("{}", ParseError::Protocol("error".to_string())),
            "protocol error: error"
        );
        assert_eq!(
            format!("{}", ParseError::UnknownCommand("FOO".to_string())),
            "unknown command: FOO"
        );
        assert_eq!(
            format!("{}", ParseError::WrongArity("wrong".to_string())),
            "wrong number of arguments: wrong"
        );
        assert_eq!(
            format!("{}", ParseError::CollectionTooLarge(999999)),
            "collection too large: 999999 elements exceeds limit"
        );
    }

    #[test]
    fn test_error_debug() {
        let err = ParseError::Incomplete;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Incomplete"));
    }

    #[test]
    fn test_error_clone() {
        let err1 = ParseError::InvalidPrefix(0x42);
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_error_eq() {
        assert_eq!(ParseError::Incomplete, ParseError::Incomplete);
        assert_ne!(ParseError::Incomplete, ParseError::InvalidLength);
        assert_eq!(
            ParseError::InvalidPrefix(0x42),
            ParseError::InvalidPrefix(0x42)
        );
        assert_ne!(
            ParseError::InvalidPrefix(0x42),
            ParseError::InvalidPrefix(0x43)
        );
    }

    #[cfg(feature = "resp3")]
    #[test]
    fn test_resp3_errors() {
        assert!(!ParseError::InvalidDouble("bad".to_string()).is_incomplete());
        assert!(!ParseError::InvalidBoolean.is_incomplete());
        assert!(!ParseError::InvalidVerbatimFormat.is_incomplete());

        assert_eq!(
            format!("{}", ParseError::InvalidDouble("bad".to_string())),
            "invalid double: bad"
        );
        assert_eq!(
            format!("{}", ParseError::InvalidBoolean),
            "invalid boolean: expected 't' or 'f'"
        );
        assert_eq!(
            format!("{}", ParseError::InvalidVerbatimFormat),
            "invalid verbatim string format"
        );
    }
}
