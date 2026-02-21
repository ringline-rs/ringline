//! Streaming parser for large memcache binary SET commands.
//!
//! This module provides streaming support for SET commands with large values,
//! allowing zero-copy receive directly into cache segment memory.
//!
//! # Overview
//!
//! For SET/SetQ/Add/AddQ/Replace/ReplaceQ commands with values >= `STREAMING_THRESHOLD`,
//! the parser returns `NeedValue` after parsing the header and extras, allowing the
//! caller to receive the value directly into a target buffer.
//!
//! For all other commands (including small SETs), it behaves identically to
//! `BinaryCommand::parse()`.
//!
//! # Example
//!
//! ```ignore
//! use protocol_memcache::binary::{parse_streaming, BinaryParseProgress, BINARY_STREAMING_THRESHOLD};
//!
//! match parse_streaming(data, BINARY_STREAMING_THRESHOLD)? {
//!     BinaryParseProgress::NeedValue { header, value_len, value_prefix, header_consumed } => {
//!         // Allocate buffer and receive value directly
//!         let mut reservation = cache.begin_segment_set(&header.key, value_len, ttl)?;
//!         reservation.value_mut()[..value_prefix.len()].copy_from_slice(value_prefix);
//!         // ... receive remaining bytes ...
//!     }
//!     BinaryParseProgress::Complete(cmd, consumed) => {
//!         // Small SET or other command - handle normally
//!     }
//!     BinaryParseProgress::Incomplete => {
//!         // Need more data
//!     }
//! }
//! ```

use super::command::BinaryCommand;
use super::header::{HEADER_SIZE, Opcode, RequestHeader};
use crate::error::ParseError;

/// Threshold for streaming large values (64KB).
///
/// SET commands with values >= this size will use the streaming path,
/// returning `NeedValue` to allow zero-copy receive.
pub const BINARY_STREAMING_THRESHOLD: usize = 64 * 1024;

/// Parsed binary SET command header (before value data).
///
/// Contains all metadata needed to complete the SET after receiving the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinarySetHeader<'a> {
    /// The key to set.
    pub key: &'a [u8],
    /// Client-defined flags.
    pub flags: u32,
    /// Expiration time in seconds.
    pub expiration: u32,
    /// CAS value for compare-and-swap.
    pub cas: u64,
    /// Opaque value (echoed in response).
    pub opaque: u32,
    /// The original opcode (Set, SetQ, Add, AddQ, Replace, ReplaceQ, Append, Prepend).
    pub opcode: Opcode,
}

/// Result of incremental parsing for binary protocol.
#[derive(Debug)]
pub enum BinaryParseProgress<'a> {
    /// Need more data to continue parsing.
    Incomplete,

    /// SET header parsed, waiting for value data.
    ///
    /// The caller should:
    /// 1. Allocate a buffer for the value (e.g., in cache segment)
    /// 2. Copy `value_prefix` to the start of that buffer
    /// 3. Receive remaining `value_len - value_prefix.len()` bytes into the buffer
    /// 4. Consume `total_consumed` bytes from the input buffer when complete
    NeedValue {
        /// Parsed command header with metadata.
        header: BinarySetHeader<'a>,
        /// Total size of the value in bytes.
        value_len: usize,
        /// Bytes of value already in the parse buffer (may be empty).
        /// These must be copied to the target buffer before receiving more.
        value_prefix: &'a [u8],
        /// Total bytes that will be consumed when value is complete.
        /// This is HEADER_SIZE + total_body_length.
        total_consumed: usize,
    },

    /// Fully parsed command.
    ///
    /// The tuple contains the parsed command and the number of bytes consumed.
    Complete(BinaryCommand<'a>, usize),
}

/// Parse a memcache binary command with streaming support for large values.
///
/// For SET/SetQ/Add/AddQ/Replace/ReplaceQ commands with values >= `streaming_threshold`,
/// this returns `NeedValue` after parsing the header, allowing the caller to receive
/// the value directly into a target buffer.
///
/// For all other commands (including small SETs), it behaves identically to
/// `BinaryCommand::parse()`.
///
/// # Arguments
///
/// * `buffer` - The input buffer containing memcache binary protocol data
/// * `streaming_threshold` - Minimum value size for streaming (use `BINARY_STREAMING_THRESHOLD`)
///
/// # Returns
///
/// * `Ok(BinaryParseProgress::Incomplete)` - Need more data
/// * `Ok(BinaryParseProgress::NeedValue { .. })` - SET header parsed, value pending
/// * `Ok(BinaryParseProgress::Complete(cmd, consumed))` - Fully parsed command
/// * `Err(ParseError)` - Parse error
pub fn parse_streaming(
    buffer: &[u8],
    streaming_threshold: usize,
) -> Result<BinaryParseProgress<'_>, ParseError> {
    // Need at least the header
    if buffer.len() < HEADER_SIZE {
        return Ok(BinaryParseProgress::Incomplete);
    }

    // Parse the request header
    let header = RequestHeader::parse(buffer)?;

    let total_len = HEADER_SIZE + header.total_body_length as usize;

    // Check if this is a storage command with a value
    let is_storage_command = matches!(
        header.opcode,
        Opcode::Set
            | Opcode::SetQ
            | Opcode::Add
            | Opcode::AddQ
            | Opcode::Replace
            | Opcode::ReplaceQ
            | Opcode::Append
            | Opcode::AppendQ
            | Opcode::Prepend
            | Opcode::PrependQ
    );

    if !is_storage_command {
        // For non-storage commands, use standard parser
        if buffer.len() < total_len {
            return Ok(BinaryParseProgress::Incomplete);
        }
        return match BinaryCommand::parse(buffer) {
            Ok((cmd, consumed)) => Ok(BinaryParseProgress::Complete(cmd, consumed)),
            Err(ParseError::Incomplete) => Ok(BinaryParseProgress::Incomplete),
            Err(e) => Err(e),
        };
    }

    // For storage commands, we need extras and key to determine if streaming
    let extras_len = header.extras_length as usize;
    let key_len = header.key_length as usize;

    // Validate header lengths
    if extras_len + key_len > header.total_body_length as usize {
        return Err(ParseError::Protocol("header lengths exceed body length"));
    }

    // Calculate value length
    let value_len = header.total_body_length as usize - extras_len - key_len;

    // Check if we should use streaming
    if value_len < streaming_threshold {
        // Small value - use standard parser
        if buffer.len() < total_len {
            return Ok(BinaryParseProgress::Incomplete);
        }
        return match BinaryCommand::parse(buffer) {
            Ok((cmd, consumed)) => Ok(BinaryParseProgress::Complete(cmd, consumed)),
            Err(ParseError::Incomplete) => Ok(BinaryParseProgress::Incomplete),
            Err(e) => Err(e),
        };
    }

    // Large value - use streaming path
    // We need at least the header, extras, and key
    let header_and_key_len = HEADER_SIZE + extras_len + key_len;
    if buffer.len() < header_and_key_len {
        return Ok(BinaryParseProgress::Incomplete);
    }

    // Parse extras (flags and expiration for SET/Add/Replace)
    let body = &buffer[HEADER_SIZE..];
    let extras = &body[..extras_len];

    let (flags, expiration) = if matches!(
        header.opcode,
        Opcode::Set
            | Opcode::SetQ
            | Opcode::Add
            | Opcode::AddQ
            | Opcode::Replace
            | Opcode::ReplaceQ
    ) {
        if extras.len() < 8 {
            return Err(ParseError::Protocol(
                "storage command requires 8 bytes of extras",
            ));
        }
        let flags = u32::from_be_bytes([extras[0], extras[1], extras[2], extras[3]]);
        let expiration = u32::from_be_bytes([extras[4], extras[5], extras[6], extras[7]]);
        (flags, expiration)
    } else {
        // Append/Prepend don't have extras
        (0, 0)
    };

    // Extract key
    let key_start = extras_len;
    let key_end = key_start + key_len;
    let key = &body[key_start..key_end];

    // Calculate how much of the value is already in the buffer
    let value_start = header_and_key_len;
    let available = buffer.len().saturating_sub(value_start);
    let prefix_len = std::cmp::min(available, value_len);
    let value_prefix = &buffer[value_start..value_start + prefix_len];

    Ok(BinaryParseProgress::NeedValue {
        header: BinarySetHeader {
            key,
            flags,
            expiration,
            cas: header.cas,
            opaque: header.opaque,
            opcode: header.opcode,
        },
        value_len,
        value_prefix,
        total_consumed: total_len,
    })
}

/// Complete a binary SET command after receiving the full value.
///
/// This is a helper for constructing the final BinaryCommand after streaming receive.
/// The caller is responsible for ensuring the value data is correct.
///
/// # Arguments
///
/// * `header` - The parsed SET header from `NeedValue`
/// * `value` - The complete value data (must match the expected length)
///
/// # Returns
///
/// A `BinaryCommand` appropriate for the opcode with the provided value.
pub fn complete_set<'a>(header: &BinarySetHeader<'_>, value: &'a [u8]) -> BinaryCommand<'a> {
    // Safety: The key reference is valid for the lifetime of the original buffer.
    // We transmute the lifetime to match the value's lifetime since the caller
    // is responsible for ensuring both are valid.
    let key: &'a [u8] = unsafe { std::mem::transmute::<&[u8], &'a [u8]>(header.key) };

    match header.opcode {
        Opcode::Set => BinaryCommand::Set {
            key,
            value,
            flags: header.flags,
            expiration: header.expiration,
            cas: header.cas,
            opaque: header.opaque,
        },
        Opcode::SetQ => BinaryCommand::SetQ {
            key,
            value,
            flags: header.flags,
            expiration: header.expiration,
            cas: header.cas,
            opaque: header.opaque,
        },
        Opcode::Add | Opcode::AddQ => BinaryCommand::Add {
            key,
            value,
            flags: header.flags,
            expiration: header.expiration,
            opaque: header.opaque,
        },
        Opcode::Replace | Opcode::ReplaceQ => BinaryCommand::Replace {
            key,
            value,
            flags: header.flags,
            expiration: header.expiration,
            cas: header.cas,
            opaque: header.opaque,
        },
        Opcode::Append | Opcode::AppendQ => BinaryCommand::Append {
            key,
            value,
            cas: header.cas,
            opaque: header.opaque,
        },
        Opcode::Prepend | Opcode::PrependQ => BinaryCommand::Prepend {
            key,
            value,
            cas: header.cas,
            opaque: header.opaque,
        },
        // Should not happen if used correctly, but provide a fallback
        _ => BinaryCommand::Set {
            key,
            value,
            flags: header.flags,
            expiration: header.expiration,
            cas: header.cas,
            opaque: header.opaque,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_set_request(key: &[u8], value: &[u8], flags: u32, expiration: u32) -> Vec<u8> {
        let extras = [
            (flags >> 24) as u8,
            (flags >> 16) as u8,
            (flags >> 8) as u8,
            flags as u8,
            (expiration >> 24) as u8,
            (expiration >> 16) as u8,
            (expiration >> 8) as u8,
            expiration as u8,
        ];
        let body_len = extras.len() + key.len() + value.len();

        let mut buf = vec![0u8; HEADER_SIZE + body_len];
        let mut header = RequestHeader::new(Opcode::Set);
        header.key_length = key.len() as u16;
        header.extras_length = extras.len() as u8;
        header.total_body_length = body_len as u32;
        header.encode(&mut buf);

        let body_start = HEADER_SIZE;
        buf[body_start..body_start + extras.len()].copy_from_slice(&extras);
        buf[body_start + extras.len()..body_start + extras.len() + key.len()].copy_from_slice(key);
        buf[body_start + extras.len() + key.len()..].copy_from_slice(value);
        buf
    }

    fn make_get_request(key: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE + key.len()];
        let mut header = RequestHeader::new(Opcode::Get);
        header.key_length = key.len() as u16;
        header.total_body_length = key.len() as u32;
        header.encode(&mut buf);

        buf[HEADER_SIZE..].copy_from_slice(key);
        buf
    }

    #[test]
    fn test_small_set_complete() {
        let data = make_set_request(b"mykey", b"myvalue", 0, 3600);
        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::Complete(cmd, consumed) => {
                if let BinaryCommand::Set {
                    key,
                    value,
                    flags,
                    expiration,
                    ..
                } = cmd
                {
                    assert_eq!(key, b"mykey");
                    assert_eq!(value, b"myvalue");
                    assert_eq!(flags, 0);
                    assert_eq!(expiration, 3600);
                } else {
                    panic!("Expected Set command");
                }
                assert_eq!(consumed, data.len());
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn test_large_set_needs_value() {
        let value_len = 100 * 1024; // 100KB
        let key = b"mykey";
        let flags = 42u32;
        let expiration = 3600u32;

        // Create header + extras + key, but only partial value
        let extras = [
            (flags >> 24) as u8,
            (flags >> 16) as u8,
            (flags >> 8) as u8,
            flags as u8,
            (expiration >> 24) as u8,
            (expiration >> 16) as u8,
            (expiration >> 8) as u8,
            expiration as u8,
        ];
        let body_len = extras.len() + key.len() + value_len;

        let mut data = vec![0u8; HEADER_SIZE + extras.len() + key.len() + 1000]; // Only 1000 bytes of value
        let mut header = RequestHeader::new(Opcode::Set);
        header.key_length = key.len() as u16;
        header.extras_length = extras.len() as u8;
        header.total_body_length = body_len as u32;
        header.opaque = 123;
        header.cas = 456;
        header.encode(&mut data);

        let body_start = HEADER_SIZE;
        data[body_start..body_start + extras.len()].copy_from_slice(&extras);
        data[body_start + extras.len()..body_start + extras.len() + key.len()].copy_from_slice(key);
        // Fill in partial value
        for i in 0..1000 {
            data[body_start + extras.len() + key.len() + i] = b'x';
        }

        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::NeedValue {
                header: set_header,
                value_len: vl,
                value_prefix,
                total_consumed,
            } => {
                assert_eq!(set_header.key, b"mykey");
                assert_eq!(set_header.flags, 42);
                assert_eq!(set_header.expiration, 3600);
                assert_eq!(set_header.opaque, 123);
                assert_eq!(set_header.cas, 456);
                assert_eq!(set_header.opcode, Opcode::Set);
                assert_eq!(vl, 100 * 1024);
                assert_eq!(value_prefix.len(), 1000);
                assert!(value_prefix.iter().all(|&b| b == b'x'));
                assert_eq!(total_consumed, HEADER_SIZE + body_len);
            }
            _ => panic!("expected NeedValue, got {:?}", result),
        }
    }

    #[test]
    fn test_get_uses_normal_path() {
        let data = make_get_request(b"mykey");
        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::Complete(cmd, consumed) => {
                assert!(matches!(cmd, BinaryCommand::Get { key: b"mykey", .. }));
                assert_eq!(consumed, data.len());
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn test_incomplete_header() {
        let data = [0x80, 0x01]; // Only 2 bytes
        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::Incomplete => {}
            _ => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn test_incomplete_small_value() {
        // Create a small SET but don't include all the data
        let key = b"mykey";
        let value_len = 100; // Small value
        let extras = [0u8; 8];
        let body_len = extras.len() + key.len() + value_len;

        let mut data = vec![0u8; HEADER_SIZE + extras.len() + key.len() + 10]; // Only 10 bytes of value
        let mut header = RequestHeader::new(Opcode::Set);
        header.key_length = key.len() as u16;
        header.extras_length = extras.len() as u8;
        header.total_body_length = body_len as u32;
        header.encode(&mut data);

        data[HEADER_SIZE..HEADER_SIZE + extras.len()].copy_from_slice(&extras);
        data[HEADER_SIZE + extras.len()..HEADER_SIZE + extras.len() + key.len()]
            .copy_from_slice(key);

        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::Incomplete => {}
            _ => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn test_threshold_boundary() {
        // At threshold - should use streaming
        let value_len = BINARY_STREAMING_THRESHOLD;
        let key = b"mykey";
        let extras = [0u8; 8];
        let body_len = extras.len() + key.len() + value_len;

        let mut data = vec![0u8; HEADER_SIZE + extras.len() + key.len()]; // No value yet
        let mut header = RequestHeader::new(Opcode::Set);
        header.key_length = key.len() as u16;
        header.extras_length = extras.len() as u8;
        header.total_body_length = body_len as u32;
        header.encode(&mut data);

        data[HEADER_SIZE..HEADER_SIZE + extras.len()].copy_from_slice(&extras);
        data[HEADER_SIZE + extras.len()..].copy_from_slice(key);

        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::NeedValue { value_len: vl, .. } => {
                assert_eq!(vl, BINARY_STREAMING_THRESHOLD);
            }
            _ => panic!("expected NeedValue at threshold"),
        }

        // Just below threshold - should use normal path (but incomplete)
        let value_len = BINARY_STREAMING_THRESHOLD - 1;
        let body_len = extras.len() + key.len() + value_len;

        let mut data = vec![0u8; HEADER_SIZE + extras.len() + key.len()]; // No value yet
        let mut header = RequestHeader::new(Opcode::Set);
        header.key_length = key.len() as u16;
        header.extras_length = extras.len() as u8;
        header.total_body_length = body_len as u32;
        header.encode(&mut data);

        data[HEADER_SIZE..HEADER_SIZE + extras.len()].copy_from_slice(&extras);
        data[HEADER_SIZE + extras.len()..].copy_from_slice(key);

        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::Incomplete => {}
            _ => panic!("expected Incomplete for sub-threshold without data"),
        }
    }

    #[test]
    fn test_setq_streaming() {
        let value_len = 100 * 1024;
        let key = b"key";
        let extras = [0u8; 8];
        let body_len = extras.len() + key.len() + value_len;

        let mut data = vec![0u8; HEADER_SIZE + extras.len() + key.len()];
        let mut header = RequestHeader::new(Opcode::SetQ);
        header.key_length = key.len() as u16;
        header.extras_length = extras.len() as u8;
        header.total_body_length = body_len as u32;
        header.encode(&mut data);

        data[HEADER_SIZE..HEADER_SIZE + extras.len()].copy_from_slice(&extras);
        data[HEADER_SIZE + extras.len()..].copy_from_slice(key);

        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::NeedValue { header, .. } => {
                assert_eq!(header.opcode, Opcode::SetQ);
            }
            _ => panic!("expected NeedValue"),
        }
    }

    #[test]
    fn test_add_streaming() {
        let value_len = 100 * 1024;
        let key = b"key";
        let extras = [0u8; 8];
        let body_len = extras.len() + key.len() + value_len;

        let mut data = vec![0u8; HEADER_SIZE + extras.len() + key.len()];
        let mut header = RequestHeader::new(Opcode::Add);
        header.key_length = key.len() as u16;
        header.extras_length = extras.len() as u8;
        header.total_body_length = body_len as u32;
        header.encode(&mut data);

        data[HEADER_SIZE..HEADER_SIZE + extras.len()].copy_from_slice(&extras);
        data[HEADER_SIZE + extras.len()..].copy_from_slice(key);

        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::NeedValue { header, .. } => {
                assert_eq!(header.opcode, Opcode::Add);
            }
            _ => panic!("expected NeedValue"),
        }
    }

    #[test]
    fn test_append_streaming() {
        // Append has no extras
        let value_len = 100 * 1024;
        let key = b"key";
        let body_len = key.len() + value_len;

        let mut data = vec![0u8; HEADER_SIZE + key.len()];
        let mut header = RequestHeader::new(Opcode::Append);
        header.key_length = key.len() as u16;
        header.extras_length = 0;
        header.total_body_length = body_len as u32;
        header.encode(&mut data);

        data[HEADER_SIZE..].copy_from_slice(key);

        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::NeedValue { header, .. } => {
                assert_eq!(header.opcode, Opcode::Append);
                assert_eq!(header.flags, 0);
                assert_eq!(header.expiration, 0);
            }
            _ => panic!("expected NeedValue"),
        }
    }

    #[test]
    fn test_complete_set_helper() {
        let header = BinarySetHeader {
            key: b"mykey",
            flags: 42,
            expiration: 3600,
            cas: 123,
            opaque: 456,
            opcode: Opcode::Set,
        };
        let value = b"myvalue";

        let cmd = complete_set(&header, value);

        match cmd {
            BinaryCommand::Set {
                key,
                value: v,
                flags,
                expiration,
                cas,
                opaque,
            } => {
                assert_eq!(key, b"mykey");
                assert_eq!(v, b"myvalue");
                assert_eq!(flags, 42);
                assert_eq!(expiration, 3600);
                assert_eq!(cas, 123);
                assert_eq!(opaque, 456);
            }
            _ => panic!("expected Set command"),
        }
    }

    #[test]
    fn test_complete_set_helper_setq() {
        let header = BinarySetHeader {
            key: b"key",
            flags: 0,
            expiration: 0,
            cas: 0,
            opaque: 0,
            opcode: Opcode::SetQ,
        };

        let cmd = complete_set(&header, b"val");
        assert!(matches!(cmd, BinaryCommand::SetQ { .. }));
    }

    #[test]
    fn test_complete_set_helper_add() {
        let header = BinarySetHeader {
            key: b"key",
            flags: 0,
            expiration: 0,
            cas: 0,
            opaque: 0,
            opcode: Opcode::Add,
        };

        let cmd = complete_set(&header, b"val");
        assert!(matches!(cmd, BinaryCommand::Add { .. }));
    }

    #[test]
    fn test_complete_set_helper_replace() {
        let header = BinarySetHeader {
            key: b"key",
            flags: 0,
            expiration: 0,
            cas: 0,
            opaque: 0,
            opcode: Opcode::Replace,
        };

        let cmd = complete_set(&header, b"val");
        assert!(matches!(cmd, BinaryCommand::Replace { .. }));
    }

    #[test]
    fn test_complete_set_helper_append() {
        let header = BinarySetHeader {
            key: b"key",
            flags: 0,
            expiration: 0,
            cas: 0,
            opaque: 0,
            opcode: Opcode::Append,
        };

        let cmd = complete_set(&header, b"val");
        assert!(matches!(cmd, BinaryCommand::Append { .. }));
    }

    #[test]
    fn test_complete_set_helper_prepend() {
        let header = BinarySetHeader {
            key: b"key",
            flags: 0,
            expiration: 0,
            cas: 0,
            opaque: 0,
            opcode: Opcode::Prepend,
        };

        let cmd = complete_set(&header, b"val");
        assert!(matches!(cmd, BinaryCommand::Prepend { .. }));
    }

    #[test]
    fn test_noop_command() {
        let mut data = vec![0u8; HEADER_SIZE];
        let header = RequestHeader::new(Opcode::Noop);
        header.encode(&mut data);

        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::Complete(cmd, _) => {
                assert!(matches!(cmd, BinaryCommand::Noop { .. }));
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn test_delete_command() {
        let key = b"mykey";
        let mut data = vec![0u8; HEADER_SIZE + key.len()];
        let mut header = RequestHeader::new(Opcode::Delete);
        header.key_length = key.len() as u16;
        header.total_body_length = key.len() as u32;
        header.encode(&mut data);

        data[HEADER_SIZE..].copy_from_slice(key);

        let result = parse_streaming(&data, BINARY_STREAMING_THRESHOLD).unwrap();

        match result {
            BinaryParseProgress::Complete(cmd, consumed) => {
                assert!(matches!(cmd, BinaryCommand::Delete { key: b"mykey", .. }));
                assert_eq!(consumed, data.len());
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn test_header_traits() {
        let header = BinarySetHeader {
            key: b"test",
            flags: 0,
            expiration: 0,
            cas: 0,
            opaque: 0,
            opcode: Opcode::Set,
        };
        let header2 = header.clone();
        assert_eq!(header, header2);

        let debug_str = format!("{:?}", header);
        assert!(debug_str.contains("BinarySetHeader"));
    }
}
