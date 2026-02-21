//! Error types for Memcache protocol parsing.

/// Error type for Memcache parsing operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Need more data to complete parsing.
    /// This is not a fatal error - the caller should buffer more data and retry.
    #[error("incomplete data")]
    Incomplete,

    /// Invalid protocol format (static message).
    #[error("protocol error: {0}")]
    Protocol(&'static str),

    /// Invalid protocol format (dynamic message).
    #[cfg(feature = "binary")]
    #[error("protocol error: {0}")]
    ProtocolDynamic(String),

    /// Invalid number format.
    #[error("invalid number")]
    InvalidNumber,

    /// Unknown command.
    #[error("unknown command")]
    UnknownCommand,

    /// Unknown opcode in binary protocol.
    #[cfg(feature = "binary")]
    #[error("unknown opcode: {0:#04x}")]
    UnknownOpcode(u8),

    /// Invalid magic byte in binary protocol.
    #[cfg(feature = "binary")]
    #[error("invalid magic byte: {0:#04x}")]
    InvalidMagic(u8),
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
        assert!(!ParseError::Protocol("test").is_incomplete());
        assert!(!ParseError::InvalidNumber.is_incomplete());
        assert!(!ParseError::UnknownCommand.is_incomplete());
    }

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", ParseError::Incomplete), "incomplete data");
        assert_eq!(
            format!("{}", ParseError::Protocol("bad format")),
            "protocol error: bad format"
        );
        assert_eq!(format!("{}", ParseError::InvalidNumber), "invalid number");
        assert_eq!(format!("{}", ParseError::UnknownCommand), "unknown command");
    }

    #[test]
    fn test_error_debug() {
        let err = ParseError::Incomplete;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Incomplete"));
    }

    #[test]
    fn test_error_clone() {
        let err1 = ParseError::Protocol("test");
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_error_eq() {
        assert_eq!(ParseError::Incomplete, ParseError::Incomplete);
        assert_ne!(ParseError::Incomplete, ParseError::InvalidNumber);
        assert_eq!(ParseError::Protocol("test"), ParseError::Protocol("test"));
        assert_ne!(ParseError::Protocol("a"), ParseError::Protocol("b"));
    }

    #[cfg(feature = "binary")]
    #[test]
    fn test_binary_errors() {
        assert!(!ParseError::ProtocolDynamic("test".to_string()).is_incomplete());
        assert!(!ParseError::UnknownOpcode(0x42).is_incomplete());
        assert!(!ParseError::InvalidMagic(0x80).is_incomplete());

        assert_eq!(
            format!("{}", ParseError::ProtocolDynamic("error".to_string())),
            "protocol error: error"
        );
        assert_eq!(
            format!("{}", ParseError::UnknownOpcode(0x42)),
            "unknown opcode: 0x42"
        );
        assert_eq!(
            format!("{}", ParseError::InvalidMagic(0x80)),
            "invalid magic byte: 0x80"
        );
    }
}
