//! Binary protocol response encoding.
//!
//! This module provides types for encoding Memcache binary protocol responses.

use super::header::{HEADER_SIZE, Opcode, ResponseHeader, Status};

/// A binary protocol response builder.
///
/// Provides methods for encoding various response types directly into a buffer.
pub struct BinaryResponse;

impl BinaryResponse {
    /// Encode a successful GET response with value.
    ///
    /// The response includes a 4-byte flags extra.
    pub fn encode_get(
        buf: &mut [u8],
        opcode: Opcode,
        opaque: u32,
        cas: u64,
        flags: u32,
        value: &[u8],
    ) -> usize {
        let extras_len = 4;
        let total_body = extras_len + value.len();

        let mut header = ResponseHeader::new(opcode, Status::NoError);
        header.extras_length = extras_len as u8;
        header.total_body_length = total_body as u32;
        header.opaque = opaque;
        header.cas = cas;
        header.encode(buf);

        // Write flags extra
        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&flags.to_be_bytes());

        // Write value
        buf[HEADER_SIZE + 4..HEADER_SIZE + 4 + value.len()].copy_from_slice(value);

        HEADER_SIZE + total_body
    }

    /// Encode a successful GETK response with key and value.
    pub fn encode_getk(
        buf: &mut [u8],
        opcode: Opcode,
        opaque: u32,
        cas: u64,
        flags: u32,
        key: &[u8],
        value: &[u8],
    ) -> usize {
        let extras_len = 4;
        let total_body = extras_len + key.len() + value.len();

        let mut header = ResponseHeader::new(opcode, Status::NoError);
        header.extras_length = extras_len as u8;
        header.key_length = key.len() as u16;
        header.total_body_length = total_body as u32;
        header.opaque = opaque;
        header.cas = cas;
        header.encode(buf);

        // Write flags extra
        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&flags.to_be_bytes());

        // Write key
        let key_start = HEADER_SIZE + 4;
        buf[key_start..key_start + key.len()].copy_from_slice(key);

        // Write value
        let value_start = key_start + key.len();
        buf[value_start..value_start + value.len()].copy_from_slice(value);

        HEADER_SIZE + total_body
    }

    /// Encode a SET/ADD/REPLACE success response.
    pub fn encode_stored(buf: &mut [u8], opcode: Opcode, opaque: u32, cas: u64) -> usize {
        let mut header = ResponseHeader::new(opcode, Status::NoError);
        header.opaque = opaque;
        header.cas = cas;
        header.encode(buf);
        HEADER_SIZE
    }

    /// Encode a DELETE success response.
    pub fn encode_deleted(buf: &mut [u8], opcode: Opcode, opaque: u32) -> usize {
        let mut header = ResponseHeader::new(opcode, Status::NoError);
        header.opaque = opaque;
        header.encode(buf);
        HEADER_SIZE
    }

    /// Encode an INCREMENT/DECREMENT success response.
    ///
    /// Returns the new counter value.
    pub fn encode_counter(
        buf: &mut [u8],
        opcode: Opcode,
        opaque: u32,
        cas: u64,
        value: u64,
    ) -> usize {
        let mut header = ResponseHeader::new(opcode, Status::NoError);
        header.opaque = opaque;
        header.cas = cas;
        header.total_body_length = 8;
        header.encode(buf);

        // Write counter value
        buf[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(&value.to_be_bytes());

        HEADER_SIZE + 8
    }

    /// Encode a TOUCH success response.
    pub fn encode_touched(buf: &mut [u8], opcode: Opcode, opaque: u32) -> usize {
        let mut header = ResponseHeader::new(opcode, Status::NoError);
        header.opaque = opaque;
        header.encode(buf);
        HEADER_SIZE
    }

    /// Encode a VERSION response.
    pub fn encode_version(buf: &mut [u8], opaque: u32, version: &[u8]) -> usize {
        let mut header = ResponseHeader::new(Opcode::Version, Status::NoError);
        header.opaque = opaque;
        header.total_body_length = version.len() as u32;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + version.len()].copy_from_slice(version);

        HEADER_SIZE + version.len()
    }

    /// Encode a NOOP response.
    pub fn encode_noop(buf: &mut [u8], opaque: u32) -> usize {
        let mut header = ResponseHeader::new(Opcode::Noop, Status::NoError);
        header.opaque = opaque;
        header.encode(buf);
        HEADER_SIZE
    }

    /// Encode a FLUSH success response.
    pub fn encode_flushed(buf: &mut [u8], opaque: u32) -> usize {
        let mut header = ResponseHeader::new(Opcode::Flush, Status::NoError);
        header.opaque = opaque;
        header.encode(buf);
        HEADER_SIZE
    }

    /// Encode an error response.
    pub fn encode_error(buf: &mut [u8], opcode: Opcode, opaque: u32, status: Status) -> usize {
        let message = status.as_str().as_bytes();

        let mut header = ResponseHeader::new(opcode, status);
        header.opaque = opaque;
        header.total_body_length = message.len() as u32;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + message.len()].copy_from_slice(message);

        HEADER_SIZE + message.len()
    }

    /// Encode a key-not-found error.
    pub fn encode_not_found(buf: &mut [u8], opcode: Opcode, opaque: u32) -> usize {
        Self::encode_error(buf, opcode, opaque, Status::KeyNotFound)
    }

    /// Encode a key-exists error.
    pub fn encode_exists(buf: &mut [u8], opcode: Opcode, opaque: u32) -> usize {
        Self::encode_error(buf, opcode, opaque, Status::KeyExists)
    }

    /// Encode an out-of-memory error.
    pub fn encode_out_of_memory(buf: &mut [u8], opcode: Opcode, opaque: u32) -> usize {
        Self::encode_error(buf, opcode, opaque, Status::OutOfMemory)
    }

    /// Encode an item-not-stored error.
    pub fn encode_not_stored(buf: &mut [u8], opcode: Opcode, opaque: u32) -> usize {
        Self::encode_error(buf, opcode, opaque, Status::ItemNotStored)
    }

    /// Encode an invalid-arguments error.
    pub fn encode_invalid_arguments(buf: &mut [u8], opcode: Opcode, opaque: u32) -> usize {
        Self::encode_error(buf, opcode, opaque, Status::InvalidArguments)
    }

    /// Encode a non-numeric-value error (for incr/decr on non-numeric).
    pub fn encode_non_numeric(buf: &mut [u8], opcode: Opcode, opaque: u32) -> usize {
        Self::encode_error(buf, opcode, opaque, Status::NonNumericValue)
    }

    /// Encode an unknown-command error.
    pub fn encode_unknown_command(buf: &mut [u8], opcode: Opcode, opaque: u32) -> usize {
        Self::encode_error(buf, opcode, opaque, Status::UnknownCommand)
    }

    /// Encode a STAT response entry.
    ///
    /// A STAT response consists of multiple entries, each with a key-value pair.
    /// The final entry has an empty key and value.
    pub fn encode_stat(buf: &mut [u8], opaque: u32, key: &[u8], value: &[u8]) -> usize {
        let mut header = ResponseHeader::new(Opcode::Stat, Status::NoError);
        header.opaque = opaque;
        header.key_length = key.len() as u16;
        header.total_body_length = (key.len() + value.len()) as u32;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + key.len()].copy_from_slice(key);
        buf[HEADER_SIZE + key.len()..HEADER_SIZE + key.len() + value.len()].copy_from_slice(value);

        HEADER_SIZE + key.len() + value.len()
    }

    /// Encode a STAT response end marker (empty key and value).
    pub fn encode_stat_end(buf: &mut [u8], opaque: u32) -> usize {
        Self::encode_stat(buf, opaque, &[], &[])
    }
}

/// Parsed binary response for client use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedBinaryResponse<'a> {
    /// GET/GETK response with value
    Value {
        opcode: Opcode,
        status: Status,
        opaque: u32,
        cas: u64,
        flags: u32,
        key: Option<&'a [u8]>,
        value: &'a [u8],
    },
    /// Counter response (INCR/DECR)
    Counter {
        opcode: Opcode,
        status: Status,
        opaque: u32,
        cas: u64,
        value: u64,
    },
    /// Simple success response (SET, DELETE, TOUCH, etc.)
    Success {
        opcode: Opcode,
        status: Status,
        opaque: u32,
        cas: u64,
    },
    /// Error response
    Error {
        opcode: Opcode,
        status: Status,
        opaque: u32,
        message: &'a [u8],
    },
    /// VERSION response
    Version { opaque: u32, version: &'a [u8] },
    /// STAT response entry
    Stat {
        opaque: u32,
        key: &'a [u8],
        value: &'a [u8],
    },
}

impl<'a> ParsedBinaryResponse<'a> {
    /// Parse a binary response from a buffer.
    pub fn parse(data: &'a [u8]) -> Result<(Self, usize), crate::error::ParseError> {
        let header = ResponseHeader::parse(data)?;

        let total_len = HEADER_SIZE + header.total_body_length as usize;
        if data.len() < total_len {
            return Err(crate::error::ParseError::Incomplete);
        }

        // Validate that header lengths are consistent with total body length
        let extras_len = header.extras_length as usize;
        let key_len = header.key_length as usize;
        if extras_len + key_len > header.total_body_length as usize {
            return Err(crate::error::ParseError::Protocol(
                "header lengths exceed body length",
            ));
        }

        let body = &data[HEADER_SIZE..total_len];

        // Handle error responses
        if !header.status.is_success() {
            return Ok((
                ParsedBinaryResponse::Error {
                    opcode: header.opcode,
                    status: header.status,
                    opaque: header.opaque,
                    message: body,
                },
                total_len,
            ));
        }

        let response = match header.opcode {
            Opcode::Get | Opcode::GetQ | Opcode::Gat | Opcode::GatQ => {
                let flags = if header.extras_length >= 4 {
                    u32::from_be_bytes([body[0], body[1], body[2], body[3]])
                } else {
                    0
                };
                let value = &body[header.extras_length as usize..];
                ParsedBinaryResponse::Value {
                    opcode: header.opcode,
                    status: header.status,
                    opaque: header.opaque,
                    cas: header.cas,
                    flags,
                    key: None,
                    value,
                }
            }
            Opcode::GetK | Opcode::GetKQ | Opcode::GatK | Opcode::GatKQ => {
                let flags = if header.extras_length >= 4 {
                    u32::from_be_bytes([body[0], body[1], body[2], body[3]])
                } else {
                    0
                };
                let key_start = header.extras_length as usize;
                let key_end = key_start + header.key_length as usize;
                let key = &body[key_start..key_end];
                let value = &body[key_end..];
                ParsedBinaryResponse::Value {
                    opcode: header.opcode,
                    status: header.status,
                    opaque: header.opaque,
                    cas: header.cas,
                    flags,
                    key: Some(key),
                    value,
                }
            }
            Opcode::Increment | Opcode::Decrement | Opcode::IncrementQ | Opcode::DecrementQ => {
                let value = if body.len() >= 8 {
                    u64::from_be_bytes([
                        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
                    ])
                } else {
                    0
                };
                ParsedBinaryResponse::Counter {
                    opcode: header.opcode,
                    status: header.status,
                    opaque: header.opaque,
                    cas: header.cas,
                    value,
                }
            }
            Opcode::Version => ParsedBinaryResponse::Version {
                opaque: header.opaque,
                version: body,
            },
            Opcode::Stat => {
                let key_end = header.key_length as usize;
                ParsedBinaryResponse::Stat {
                    opaque: header.opaque,
                    key: &body[..key_end],
                    value: &body[key_end..],
                }
            }
            _ => ParsedBinaryResponse::Success {
                opcode: header.opcode,
                status: header.status,
                opaque: header.opaque,
                cas: header.cas,
            },
        };

        Ok((response, total_len))
    }

    /// Returns the opaque value from this response.
    pub fn opaque(&self) -> u32 {
        match self {
            ParsedBinaryResponse::Value { opaque, .. }
            | ParsedBinaryResponse::Counter { opaque, .. }
            | ParsedBinaryResponse::Success { opaque, .. }
            | ParsedBinaryResponse::Error { opaque, .. }
            | ParsedBinaryResponse::Version { opaque, .. }
            | ParsedBinaryResponse::Stat { opaque, .. } => *opaque,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::header::RESPONSE_MAGIC;
    use super::*;

    #[test]
    fn test_encode_get() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_get(&mut buf, Opcode::Get, 42, 123, 0, b"hello");

        assert_eq!(buf[0], RESPONSE_MAGIC);
        assert_eq!(buf[1], Opcode::Get as u8);
        assert_eq!(len, HEADER_SIZE + 4 + 5); // header + flags + value
    }

    #[test]
    fn test_encode_stored() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_stored(&mut buf, Opcode::Set, 42, 123);

        assert_eq!(len, HEADER_SIZE);
        assert_eq!(buf[0], RESPONSE_MAGIC);
    }

    #[test]
    fn test_encode_not_found() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_not_found(&mut buf, Opcode::Get, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Error {
                status: Status::KeyNotFound,
                ..
            }
        ));
    }

    #[test]
    fn test_roundtrip_get() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_get(&mut buf, Opcode::Get, 42, 123, 7, b"world");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);

        if let ParsedBinaryResponse::Value {
            opaque,
            cas,
            flags,
            value,
            ..
        } = resp
        {
            assert_eq!(opaque, 42);
            assert_eq!(cas, 123);
            assert_eq!(flags, 7);
            assert_eq!(value, b"world");
        } else {
            panic!("Expected Value response");
        }
    }

    #[test]
    fn test_roundtrip_counter() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_counter(&mut buf, Opcode::Increment, 10, 50, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);

        if let ParsedBinaryResponse::Counter { opaque, value, .. } = resp {
            assert_eq!(opaque, 10);
            assert_eq!(value, 42);
        } else {
            panic!("Expected Counter response");
        }
    }

    // Additional tests for improved coverage

    #[test]
    fn test_encode_getk() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_getk(&mut buf, Opcode::GetK, 42, 123, 7, b"mykey", b"val");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);

        if let ParsedBinaryResponse::Value {
            opcode,
            opaque,
            cas,
            flags,
            key,
            value,
            ..
        } = resp
        {
            assert_eq!(opcode, Opcode::GetK);
            assert_eq!(opaque, 42);
            assert_eq!(cas, 123);
            assert_eq!(flags, 7);
            assert_eq!(key, Some(b"mykey".as_slice()));
            assert_eq!(value, b"val");
        } else {
            panic!("Expected Value response");
        }
    }

    #[test]
    fn test_encode_deleted() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_deleted(&mut buf, Opcode::Delete, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Success { opaque: 42, .. }
        ));
    }

    #[test]
    fn test_encode_touched() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_touched(&mut buf, Opcode::Touch, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Success { opaque: 42, .. }
        ));
    }

    #[test]
    fn test_encode_version() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_version(&mut buf, 42, b"1.6.9");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);

        if let ParsedBinaryResponse::Version { opaque, version } = resp {
            assert_eq!(opaque, 42);
            assert_eq!(version, b"1.6.9");
        } else {
            panic!("Expected Version response");
        }
    }

    #[test]
    fn test_encode_noop() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_noop(&mut buf, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Success { opaque: 42, .. }
        ));
    }

    #[test]
    fn test_encode_flushed() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_flushed(&mut buf, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Success { opaque: 42, .. }
        ));
    }

    #[test]
    fn test_encode_error() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_error(&mut buf, Opcode::Get, 42, Status::OutOfMemory);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);

        if let ParsedBinaryResponse::Error {
            opcode,
            status,
            opaque,
            message,
        } = resp
        {
            assert_eq!(opcode, Opcode::Get);
            assert_eq!(status, Status::OutOfMemory);
            assert_eq!(opaque, 42);
            assert_eq!(message, b"Out of memory");
        } else {
            panic!("Expected Error response");
        }
    }

    #[test]
    fn test_encode_exists() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_exists(&mut buf, Opcode::Add, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Error {
                status: Status::KeyExists,
                opaque: 42,
                ..
            }
        ));
    }

    #[test]
    fn test_encode_out_of_memory() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_out_of_memory(&mut buf, Opcode::Set, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Error {
                status: Status::OutOfMemory,
                opaque: 42,
                ..
            }
        ));
    }

    #[test]
    fn test_encode_not_stored() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_not_stored(&mut buf, Opcode::Set, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Error {
                status: Status::ItemNotStored,
                opaque: 42,
                ..
            }
        ));
    }

    #[test]
    fn test_encode_invalid_arguments() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_invalid_arguments(&mut buf, Opcode::Set, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Error {
                status: Status::InvalidArguments,
                opaque: 42,
                ..
            }
        ));
    }

    #[test]
    fn test_encode_non_numeric() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_non_numeric(&mut buf, Opcode::Increment, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Error {
                status: Status::NonNumericValue,
                opaque: 42,
                ..
            }
        ));
    }

    #[test]
    fn test_encode_unknown_command() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_unknown_command(&mut buf, Opcode::Noop, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Error {
                status: Status::UnknownCommand,
                opaque: 42,
                ..
            }
        ));
    }

    #[test]
    fn test_encode_stat() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_stat(&mut buf, 42, b"pid", b"12345");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);

        if let ParsedBinaryResponse::Stat { opaque, key, value } = resp {
            assert_eq!(opaque, 42);
            assert_eq!(key, b"pid");
            assert_eq!(value, b"12345");
        } else {
            panic!("Expected Stat response");
        }
    }

    #[test]
    fn test_encode_stat_end() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_stat_end(&mut buf, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);

        if let ParsedBinaryResponse::Stat { opaque, key, value } = resp {
            assert_eq!(opaque, 42);
            assert!(key.is_empty());
            assert!(value.is_empty());
        } else {
            panic!("Expected Stat response");
        }
    }

    #[test]
    fn test_parse_incomplete() {
        let data = [0x81; 10]; // Only 10 bytes, need 24
        assert!(matches!(
            ParsedBinaryResponse::parse(&data),
            Err(crate::error::ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_parse_incomplete_body() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_get(&mut buf, Opcode::Get, 42, 123, 0, b"hello");

        // Truncate the body
        assert!(matches!(
            ParsedBinaryResponse::parse(&buf[..HEADER_SIZE]),
            Err(crate::error::ParseError::Incomplete)
        ));
        assert_eq!(len, HEADER_SIZE + 9);
    }

    #[test]
    fn test_parse_header_lengths_exceed_body() {
        let mut buf = [0u8; 256];
        BinaryResponse::encode_get(&mut buf, Opcode::Get, 42, 123, 0, b"hello");

        // Set key_length larger than total_body_length
        buf[2] = 0xFF;
        buf[3] = 0xFF;

        assert!(matches!(
            ParsedBinaryResponse::parse(&buf),
            Err(crate::error::ParseError::Protocol(
                "header lengths exceed body length"
            ))
        ));
    }

    #[test]
    fn test_parse_getq_response() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_get(&mut buf, Opcode::GetQ, 42, 123, 7, b"val");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Value {
                opcode: Opcode::GetQ,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_gat_response() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_get(&mut buf, Opcode::Gat, 42, 123, 7, b"val");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Value {
                opcode: Opcode::Gat,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_gatq_response() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_get(&mut buf, Opcode::GatQ, 42, 123, 7, b"val");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Value {
                opcode: Opcode::GatQ,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_getkq_response() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_getk(&mut buf, Opcode::GetKQ, 42, 123, 7, b"k", b"v");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Value {
                opcode: Opcode::GetKQ,
                key: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_gatk_response() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_getk(&mut buf, Opcode::GatK, 42, 123, 7, b"k", b"v");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Value {
                opcode: Opcode::GatK,
                key: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_gatkq_response() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_getk(&mut buf, Opcode::GatKQ, 42, 123, 7, b"k", b"v");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Value {
                opcode: Opcode::GatKQ,
                key: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_decrement_response() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_counter(&mut buf, Opcode::Decrement, 10, 50, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Counter {
                opcode: Opcode::Decrement,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_incrementq_response() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_counter(&mut buf, Opcode::IncrementQ, 10, 50, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Counter {
                opcode: Opcode::IncrementQ,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_decrementq_response() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_counter(&mut buf, Opcode::DecrementQ, 10, 50, 42);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            resp,
            ParsedBinaryResponse::Counter {
                opcode: Opcode::DecrementQ,
                ..
            }
        ));
    }

    #[test]
    fn test_opaque_all_variants() {
        let mut buf = [0u8; 256];

        // Value
        let len = BinaryResponse::encode_get(&mut buf, Opcode::Get, 1, 0, 0, b"v");
        let (resp, _) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(resp.opaque(), 1);

        // Counter
        let len = BinaryResponse::encode_counter(&mut buf, Opcode::Increment, 2, 0, 0);
        let (resp, _) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(resp.opaque(), 2);

        // Success
        let len = BinaryResponse::encode_stored(&mut buf, Opcode::Set, 3, 0);
        let (resp, _) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(resp.opaque(), 3);

        // Error
        let len = BinaryResponse::encode_not_found(&mut buf, Opcode::Get, 4);
        let (resp, _) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(resp.opaque(), 4);

        // Version
        let len = BinaryResponse::encode_version(&mut buf, 5, b"1.0");
        let (resp, _) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(resp.opaque(), 5);

        // Stat
        let len = BinaryResponse::encode_stat(&mut buf, 6, b"k", b"v");
        let (resp, _) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();
        assert_eq!(resp.opaque(), 6);
    }

    #[test]
    fn test_response_traits() {
        let mut buf = [0u8; 256];
        let len = BinaryResponse::encode_get(&mut buf, Opcode::Get, 42, 123, 7, b"val");
        let (resp, _) = ParsedBinaryResponse::parse(&buf[..len]).unwrap();

        let resp2 = resp.clone();
        assert_eq!(resp, resp2);

        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("Value"));
    }

    #[test]
    fn test_parse_value_no_extras() {
        // Create a response with no extras (flags = 0 by default)
        let mut buf = [0u8; 256];
        let mut header = ResponseHeader::new(Opcode::Get, Status::NoError);
        header.extras_length = 0; // No extras
        header.total_body_length = 5; // Just value
        header.opaque = 42;
        header.encode(&mut buf);
        buf[HEADER_SIZE..HEADER_SIZE + 5].copy_from_slice(b"hello");

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..HEADER_SIZE + 5]).unwrap();
        assert_eq!(consumed, HEADER_SIZE + 5);

        if let ParsedBinaryResponse::Value { flags, value, .. } = resp {
            assert_eq!(flags, 0); // Default when no extras
            assert_eq!(value, b"hello");
        } else {
            panic!("Expected Value response");
        }
    }

    #[test]
    fn test_parse_counter_short_body() {
        // Create counter response with short body (< 8 bytes)
        let mut buf = [0u8; 256];
        let mut header = ResponseHeader::new(Opcode::Increment, Status::NoError);
        header.total_body_length = 4; // Less than 8 bytes
        header.opaque = 42;
        header.encode(&mut buf);
        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&[0, 0, 0, 1]);

        let (resp, consumed) = ParsedBinaryResponse::parse(&buf[..HEADER_SIZE + 4]).unwrap();
        assert_eq!(consumed, HEADER_SIZE + 4);

        if let ParsedBinaryResponse::Counter { value, .. } = resp {
            assert_eq!(value, 0); // Default when body too short
        } else {
            panic!("Expected Counter response");
        }
    }
}
