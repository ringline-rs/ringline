//! Streaming parser for large memcache SET commands.
//!
//! This module provides streaming support for SET commands with large values,
//! allowing zero-copy receive directly into cache segment memory.
//!
//! # Overview
//!
//! For SET commands with values >= `STREAMING_THRESHOLD`, the parser returns
//! `NeedValue` after parsing the command header, allowing the caller to receive
//! the value directly into a target buffer (e.g., cache segment memory).
//!
//! For all other commands (including small SETs), it behaves identically to
//! `Command::parse()`.
//!
//! # Example
//!
//! ```ignore
//! use protocol_memcache::{parse_streaming, ParseProgress, STREAMING_THRESHOLD};
//!
//! let data = b"set mykey 0 3600 100000\r\n";
//!
//! match parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD)? {
//!     ParseProgress::NeedValue { header, value_len, value_prefix, header_consumed } => {
//!         // Allocate buffer and receive value directly
//!         let mut reservation = cache.begin_segment_set(&header.key, value_len, ttl)?;
//!         reservation.value_mut()[..value_prefix.len()].copy_from_slice(value_prefix);
//!         // ... receive remaining bytes ...
//!     }
//!     ParseProgress::Complete(cmd, consumed) => {
//!         // Small SET or other command - handle normally
//!     }
//!     ParseProgress::Incomplete => {
//!         // Need more data
//!     }
//! }
//! ```

use crate::command::{Command, ParseOptions};
use crate::error::ParseError;

/// Threshold for streaming large values (64KB).
///
/// SET commands with values >= this size will use the streaming path,
/// returning `NeedValue` to allow zero-copy receive.
pub const STREAMING_THRESHOLD: usize = 64 * 1024;

/// Parsed SET command header (before value data).
///
/// Contains all metadata needed to complete the SET after receiving the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetHeader<'a> {
    /// The key to set.
    pub key: &'a [u8],
    /// Client-defined flags (opaque to server).
    pub flags: u32,
    /// Expiration time in seconds (0 = never, or Unix timestamp if > 30 days).
    pub exptime: u32,
    /// Whether to suppress the response ("noreply" option).
    pub noreply: bool,
}

/// Result of incremental parsing.
#[derive(Debug)]
pub enum ParseProgress<'a> {
    /// Need more data to continue parsing.
    Incomplete,

    /// SET header parsed, waiting for value data.
    ///
    /// The caller should:
    /// 1. Allocate a buffer for the value (e.g., in cache segment)
    /// 2. Copy `value_prefix` to the start of that buffer
    /// 3. Receive remaining `value_len - value_prefix.len()` bytes into the buffer
    /// 4. Consume `header_consumed + value_len + 2` bytes from the input buffer
    NeedValue {
        /// Parsed command header with metadata.
        header: SetHeader<'a>,
        /// Total size of the value in bytes.
        value_len: usize,
        /// Bytes of value already in the parse buffer (may be empty).
        /// These must be copied to the target buffer before receiving more.
        value_prefix: &'a [u8],
        /// Bytes consumed from buffer so far (header + CRLF, before value).
        header_consumed: usize,
    },

    /// Fully parsed command.
    ///
    /// The tuple contains the parsed command and the number of bytes consumed.
    Complete(Command<'a>, usize),
}

/// Parse a memcache command with streaming support for large values.
///
/// For SET commands with values >= `streaming_threshold`, this returns
/// `NeedValue` after parsing the header, allowing the caller to receive
/// the value directly into a target buffer.
///
/// For all other commands (including small SETs), it behaves identically to
/// `Command::parse_with_options()`.
///
/// # Arguments
///
/// * `buffer` - The input buffer containing memcache protocol data
/// * `options` - Parse options (max lengths, etc.)
/// * `streaming_threshold` - Minimum value size for streaming (use `STREAMING_THRESHOLD`)
///
/// # Returns
///
/// * `Ok(ParseProgress::Incomplete)` - Need more data
/// * `Ok(ParseProgress::NeedValue { .. })` - SET header parsed, value pending
/// * `Ok(ParseProgress::Complete(cmd, consumed))` - Fully parsed command
/// * `Err(ParseError)` - Parse error
pub fn parse_streaming<'a>(
    buffer: &'a [u8],
    options: &ParseOptions,
    streaming_threshold: usize,
) -> Result<ParseProgress<'a>, ParseError> {
    // Find the end of the command line
    let max_line_len = options.max_line_len();
    let line_end = match find_crlf(buffer, max_line_len)? {
        Some(pos) => pos,
        None => return Ok(ParseProgress::Incomplete),
    };

    let line = &buffer[..line_end];
    let mut parts = line.split(|&b| b == b' ');

    let cmd = parts.next().ok_or(ParseError::Protocol("empty command"))?;

    // Only SET commands use the streaming path
    if cmd != b"set" && cmd != b"SET" {
        // Use the standard parser for non-SET commands
        return match Command::parse_with_options(buffer, options) {
            Ok((cmd, consumed)) => Ok(ParseProgress::Complete(cmd, consumed)),
            Err(ParseError::Incomplete) => Ok(ParseProgress::Incomplete),
            Err(e) => Err(e),
        };
    }

    // Parse SET command header
    let key = parts
        .next()
        .ok_or(ParseError::Protocol("set requires key"))?;
    if key.is_empty() {
        return Err(ParseError::Protocol("empty key"));
    }
    if key.len() > options.max_key_len {
        return Err(ParseError::Protocol("key too large"));
    }

    let flags_str = parts
        .next()
        .ok_or(ParseError::Protocol("set requires flags"))?;
    let exptime_str = parts
        .next()
        .ok_or(ParseError::Protocol("set requires exptime"))?;
    let bytes_str = parts
        .next()
        .ok_or(ParseError::Protocol("set requires bytes"))?;

    let flags = parse_u32(flags_str)?;
    let exptime = parse_u32(exptime_str)?;
    let value_len = parse_usize(bytes_str)?;

    if value_len > options.max_value_len {
        return Err(ParseError::Protocol("value too large"));
    }

    // Check for optional "noreply"
    let noreply = parts.next().map(|s| s == b"noreply").unwrap_or(false);

    // Header ends after the CRLF
    let header_consumed = line_end + 2;

    // For large values, return NeedValue to allow streaming
    if value_len >= streaming_threshold {
        // Calculate how much of the value is already in the buffer
        let value_start = header_consumed;
        let available = buffer.len().saturating_sub(value_start);
        let prefix_len = std::cmp::min(available, value_len);
        let value_prefix = &buffer[value_start..value_start + prefix_len];

        return Ok(ParseProgress::NeedValue {
            header: SetHeader {
                key,
                flags,
                exptime,
                noreply,
            },
            value_len,
            value_prefix,
            header_consumed,
        });
    }

    // For small values, parse the complete command
    let data_start = header_consumed;
    let data_end = data_start
        .checked_add(value_len)
        .ok_or(ParseError::InvalidNumber)?;
    let total_len = data_end.checked_add(2).ok_or(ParseError::InvalidNumber)?;

    if buffer.len() < total_len {
        return Ok(ParseProgress::Incomplete);
    }

    // Verify trailing \r\n
    if buffer[data_end] != b'\r' || buffer[data_end + 1] != b'\n' {
        return Err(ParseError::Protocol("missing data terminator"));
    }

    let data = &buffer[data_start..data_end];
    Ok(ParseProgress::Complete(
        Command::Set {
            key,
            flags,
            exptime,
            data,
        },
        total_len,
    ))
}

/// Complete a SET command after receiving the full value.
///
/// This is a helper for constructing the final Command after streaming receive.
/// The caller is responsible for ensuring the value data is correct.
///
/// # Arguments
///
/// * `header` - The parsed SET header from `NeedValue`
/// * `value` - The complete value data (must match the expected length)
///
/// # Returns
///
/// A `Command::Set` with the provided value.
pub fn complete_set<'a>(header: &SetHeader<'_>, value: &'a [u8]) -> Command<'a> {
    Command::Set {
        key: unsafe {
            // Safety: The key reference is valid for the lifetime of the original buffer.
            // We transmute the lifetime to match the value's lifetime since the caller
            // is responsible for ensuring both are valid.
            std::mem::transmute::<&[u8], &'a [u8]>(header.key)
        },
        flags: header.flags,
        exptime: header.exptime,
        data: value,
    }
}

/// Find \r\n in buffer, return position of \r.
fn find_crlf(buffer: &[u8], max_line_len: usize) -> Result<Option<usize>, ParseError> {
    if let Some(pos) = memchr::memchr(b'\r', buffer)
        .filter(|&pos| pos + 1 < buffer.len() && buffer[pos + 1] == b'\n')
    {
        return Ok(Some(pos));
    }

    // No CRLF found - check if we've exceeded the line length limit
    if buffer.len() > max_line_len {
        return Err(ParseError::Protocol("line too long"));
    }

    Ok(None)
}

/// Parse a u32 from ASCII decimal.
fn parse_u32(data: &[u8]) -> Result<u32, ParseError> {
    std::str::from_utf8(data)
        .map_err(|_| ParseError::InvalidNumber)?
        .parse()
        .map_err(|_| ParseError::InvalidNumber)
}

/// Parse a usize from ASCII decimal.
fn parse_usize(data: &[u8]) -> Result<usize, ParseError> {
    std::str::from_utf8(data)
        .map_err(|_| ParseError::InvalidNumber)?
        .parse()
        .map_err(|_| ParseError::InvalidNumber)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_set_complete() {
        let data = b"set mykey 0 3600 7\r\nmyvalue\r\n";
        let result = parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::Complete(cmd, consumed) => {
                assert_eq!(
                    cmd,
                    Command::Set {
                        key: b"mykey",
                        flags: 0,
                        exptime: 3600,
                        data: b"myvalue",
                    }
                );
                assert_eq!(consumed, data.len());
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn test_large_set_needs_value() {
        let value_len = 100 * 1024; // 100KB
        let header = format!("set mykey 0 3600 {}\r\n", value_len);
        let mut data = header.as_bytes().to_vec();
        // Add some value prefix
        data.extend_from_slice(&vec![b'x'; 1000]);

        let result = parse_streaming(&data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::NeedValue {
                header,
                value_len: vl,
                value_prefix,
                header_consumed,
            } => {
                assert_eq!(header.key, b"mykey");
                assert_eq!(header.flags, 0);
                assert_eq!(header.exptime, 3600);
                assert!(!header.noreply);
                assert_eq!(vl, 100 * 1024);
                assert_eq!(value_prefix.len(), 1000);
                assert!(value_prefix.iter().all(|&b| b == b'x'));
                assert_eq!(header_consumed, 25); // "set mykey 0 3600 102400\r\n".len()
            }
            _ => panic!("expected NeedValue, got {:?}", result),
        }
    }

    #[test]
    fn test_set_with_noreply() {
        let value_len = 100 * 1024;
        let header = format!("set mykey 0 3600 {} noreply\r\n", value_len);

        let result = parse_streaming(
            header.as_bytes(),
            &ParseOptions::default(),
            STREAMING_THRESHOLD,
        )
        .unwrap();

        match result {
            ParseProgress::NeedValue { header, .. } => {
                assert!(header.noreply);
            }
            _ => panic!("expected NeedValue"),
        }
    }

    #[test]
    fn test_get_uses_normal_path() {
        let data = b"get mykey\r\n";
        let result = parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::Complete(cmd, consumed) => {
                assert_eq!(cmd, Command::Get { key: b"mykey" });
                assert_eq!(consumed, data.len());
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn test_incomplete_header() {
        let data = b"set mykey 0 360";
        let result = parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::Incomplete => {}
            _ => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn test_incomplete_small_value() {
        let data = b"set mykey 0 3600 100\r\npartial";
        let result = parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::Incomplete => {}
            _ => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn test_threshold_boundary() {
        // At threshold - should use streaming
        let value_len = STREAMING_THRESHOLD;
        let header = format!("set mykey 0 3600 {}\r\n", value_len);

        let result = parse_streaming(
            header.as_bytes(),
            &ParseOptions::default(),
            STREAMING_THRESHOLD,
        )
        .unwrap();

        match result {
            ParseProgress::NeedValue { value_len: vl, .. } => {
                assert_eq!(vl, STREAMING_THRESHOLD);
            }
            _ => panic!("expected NeedValue at threshold"),
        }

        // Just below threshold - should use normal path (but incomplete without value)
        let value_len = STREAMING_THRESHOLD - 1;
        let header = format!("set mykey 0 3600 {}\r\n", value_len);

        let result = parse_streaming(
            header.as_bytes(),
            &ParseOptions::default(),
            STREAMING_THRESHOLD,
        )
        .unwrap();

        match result {
            ParseProgress::Incomplete => {}
            _ => panic!("expected Incomplete for sub-threshold without data"),
        }
    }

    #[test]
    fn test_delete_command() {
        let data = b"delete mykey\r\n";
        let result = parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::Complete(Command::Delete { key }, consumed) => {
                assert_eq!(key, b"mykey");
                assert_eq!(consumed, data.len());
            }
            _ => panic!("expected Complete Delete"),
        }
    }

    #[test]
    fn test_flush_all_command() {
        let data = b"flush_all\r\n";
        let result = parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::Complete(Command::FlushAll, consumed) => {
                assert_eq!(consumed, data.len());
            }
            _ => panic!("expected Complete FlushAll"),
        }
    }

    #[test]
    fn test_complete_set_helper() {
        let header = SetHeader {
            key: b"mykey",
            flags: 42,
            exptime: 3600,
            noreply: false,
        };
        let value = b"myvalue";

        let cmd = complete_set(&header, value);

        match cmd {
            Command::Set {
                key,
                flags,
                exptime,
                data,
            } => {
                assert_eq!(key, b"mykey");
                assert_eq!(flags, 42);
                assert_eq!(exptime, 3600);
                assert_eq!(data, b"myvalue");
            }
            _ => panic!("expected Set command"),
        }
    }
}
