//! Memcache binary protocol implementation.
//!
//! This module provides complete Memcache binary protocol support for both
//! client and server implementations.
//!
//! # Protocol Overview
//!
//! The Memcache binary protocol uses fixed 24-byte headers for both requests
//! and responses. The protocol is more efficient than ASCII for high-throughput
//! scenarios as it avoids text parsing overhead.
//!
//! - Request magic: 0x80
//! - Response magic: 0x81
//!
//! # Example - Client Side
//!
//! ```
//! use protocol_memcache::binary::{BinaryRequest, ParsedBinaryResponse, Opcode};
//!
//! // Encode a GET request
//! let mut buf = [0u8; 256];
//! let len = BinaryRequest::encode_get(&mut buf, b"mykey", 1);
//!
//! // Parse a response (after receiving from server)
//! // let (response, consumed) = ParsedBinaryResponse::parse(&response_data).unwrap();
//! ```
//!
//! # Example - Server Side
//!
//! ```
//! use protocol_memcache::binary::{BinaryCommand, BinaryResponse, Opcode};
//!
//! // Parse an incoming command
//! // let (cmd, consumed) = BinaryCommand::parse(&request_data).unwrap();
//!
//! // Encode a response
//! let mut buf = [0u8; 256];
//! let len = BinaryResponse::encode_stored(&mut buf, Opcode::Set, 1, 123);
//! ```

mod command;
mod header;
mod request;
mod response;
mod streaming;

pub use command::BinaryCommand;
pub use header::{
    HEADER_SIZE, Opcode, REQUEST_MAGIC, RESPONSE_MAGIC, RequestHeader, ResponseHeader, Status,
};
pub use request::BinaryRequest;
pub use response::{BinaryResponse, ParsedBinaryResponse};
pub use streaming::{
    BINARY_STREAMING_THRESHOLD, BinaryParseProgress, BinarySetHeader,
    complete_set as complete_binary_set, parse_streaming as parse_binary_streaming,
};

/// Detect if the data starts with a binary protocol request.
///
/// Returns true if the first byte is the binary request magic (0x80).
#[inline]
pub fn is_binary_request(data: &[u8]) -> bool {
    data.first().copied() == Some(REQUEST_MAGIC)
}

/// Detect if the data starts with a binary protocol response.
///
/// Returns true if the first byte is the binary response magic (0x81).
#[inline]
pub fn is_binary_response(data: &[u8]) -> bool {
    data.first().copied() == Some(RESPONSE_MAGIC)
}

/// The detected protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemcacheProtocol {
    /// ASCII text protocol
    Ascii,
    /// Binary protocol
    Binary,
}

/// Detect the protocol type from the first byte of incoming data.
///
/// Returns `None` if the buffer is empty.
pub fn detect_protocol(data: &[u8]) -> Option<MemcacheProtocol> {
    match data.first()? {
        &REQUEST_MAGIC | &RESPONSE_MAGIC => Some(MemcacheProtocol::Binary),
        _ => Some(MemcacheProtocol::Ascii),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_binary_request() {
        assert!(is_binary_request(&[REQUEST_MAGIC, 0x00]));
        assert!(!is_binary_request(&[RESPONSE_MAGIC, 0x00]));
        assert!(!is_binary_request(b"get"));
        assert!(!is_binary_request(&[]));
    }

    #[test]
    fn test_is_binary_response() {
        assert!(is_binary_response(&[RESPONSE_MAGIC, 0x00]));
        assert!(!is_binary_response(&[REQUEST_MAGIC, 0x00]));
        assert!(!is_binary_response(b"STO"));
        assert!(!is_binary_response(&[]));
    }

    #[test]
    fn test_detect_protocol_binary() {
        assert_eq!(
            detect_protocol(&[REQUEST_MAGIC, 0x00]),
            Some(MemcacheProtocol::Binary)
        );
        assert_eq!(
            detect_protocol(&[RESPONSE_MAGIC, 0x00]),
            Some(MemcacheProtocol::Binary)
        );
    }

    #[test]
    fn test_detect_protocol_ascii() {
        assert_eq!(
            detect_protocol(b"get mykey\r\n"),
            Some(MemcacheProtocol::Ascii)
        );
        assert_eq!(
            detect_protocol(b"STORED\r\n"),
            Some(MemcacheProtocol::Ascii)
        );
    }

    #[test]
    fn test_detect_protocol_empty() {
        assert_eq!(detect_protocol(&[]), None);
    }

    #[test]
    fn test_memcache_protocol_traits() {
        let p1 = MemcacheProtocol::Ascii;
        let p2 = p1;
        assert_eq!(p1, p2);

        let p3 = MemcacheProtocol::Binary;
        assert_ne!(p1, p3);

        let debug_str = format!("{:?}", p1);
        assert!(debug_str.contains("Ascii"));
    }
}
