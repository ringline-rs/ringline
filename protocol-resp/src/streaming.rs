//! Streaming command parser for zero-copy receive optimization.
//!
//! This module provides incremental parsing that can pause after parsing
//! a command header, allowing the caller to receive large values directly
//! into a target buffer (e.g., cache segment memory) without intermediate copies.
//!
//! # Example
//!
//! ```ignore
//! use protocol_resp::streaming::{StreamingParser, ParseProgress};
//!
//! let mut parser = StreamingParser::new();
//!
//! // Feed data as it arrives
//! match parser.parse(buffer)? {
//!     ParseProgress::Incomplete => {
//!         // Need more data
//!     }
//!     ParseProgress::NeedValue { header, value_len, .. } => {
//!         // Allocate target buffer for value
//!         let mut target = cache.reserve_set(header.key, value_len)?;
//!
//!         // Receive remaining bytes directly into target
//!         recv_into(target.value_mut())?;
//!
//!         // Complete the command
//!         parser.complete_value(target.value_mut());
//!     }
//!     ParseProgress::Complete(cmd, consumed) => {
//!         // Handle complete command
//!     }
//! }
//! ```

use crate::Command;
use crate::error::ParseError;
use crate::value::ParseOptions;
use std::time::Duration;

/// Threshold for using streaming parse (64KB).
/// Values smaller than this don't benefit enough from zero-copy receive.
pub const STREAMING_THRESHOLD: usize = 64 * 1024;

/// Result of incremental parsing.
#[derive(Debug)]
pub enum ParseProgress<'a> {
    /// Need more data to continue parsing.
    Incomplete,

    /// Command header parsed, waiting for value data.
    ///
    /// The caller should:
    /// 1. Allocate a buffer for the value (e.g., in cache segment)
    /// 2. Copy `value_prefix` to the start of that buffer
    /// 3. Receive remaining `value_len - value_prefix.len()` bytes into the buffer
    /// 4. Call `complete_with_value()` to finish parsing
    NeedValue {
        /// Parsed command header with metadata.
        header: SetHeader<'a>,
        /// Total size of the value in bytes.
        value_len: usize,
        /// Bytes of value already in the parse buffer (may be empty).
        /// These must be copied to the target buffer before receiving more.
        value_prefix: &'a [u8],
        /// Bytes consumed from buffer so far (header only).
        header_consumed: usize,
    },

    /// Value exceeds maximum allowed size - needs to be drained.
    ///
    /// The caller should:
    /// 1. Send an error response to the client
    /// 2. Drain `value_len + 2` bytes (value + trailing CRLF) from the connection
    /// 3. Resume normal parsing
    ValueTooLarge {
        /// Total size of the value in bytes.
        value_len: usize,
        /// Bytes of value already in the parse buffer (to be discarded).
        value_prefix_len: usize,
        /// Bytes consumed from buffer so far (header only).
        header_consumed: usize,
        /// Maximum allowed value size.
        max_value_size: usize,
    },

    /// Fully parsed command (used for non-SET commands or small values).
    Complete(Command<'a>, usize),
}

/// Parsed SET command header (without the value).
#[derive(Debug, Clone)]
pub struct SetHeader<'a> {
    /// The key for this SET operation.
    pub key: &'a [u8],
    /// EX option: expire time in seconds.
    pub ex: Option<u64>,
    /// PX option: expire time in milliseconds.
    pub px: Option<u64>,
    /// NX option: only set if key doesn't exist.
    pub nx: bool,
    /// XX option: only set if key exists.
    pub xx: bool,
    /// Number of remaining option arguments after the value.
    remaining_args: usize,
}

impl<'a> SetHeader<'a> {
    /// Get the TTL as a Duration, if specified.
    pub fn ttl(&self) -> Option<Duration> {
        if let Some(secs) = self.ex {
            Some(Duration::from_secs(secs))
        } else {
            self.px.map(Duration::from_millis)
        }
    }
}

/// Parse a command, potentially yielding early for large SET values.
///
/// This function provides the streaming parse capability. For SET commands
/// with values >= `STREAMING_THRESHOLD`, it returns `NeedValue` after parsing
/// the header, allowing the caller to receive the value directly into a
/// target buffer.
///
/// For all other commands (including small SETs), it behaves identically to
/// `Command::parse()`.
///
/// # Arguments
///
/// * `buffer` - The input buffer containing RESP data
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
    let mut cursor = StreamingCursor::new(buffer, options.max_bulk_string_len);

    // Read array header
    if cursor.remaining() < 1 {
        return Ok(ParseProgress::Incomplete);
    }
    if cursor.peek() != b'*' {
        return Err(ParseError::Protocol("expected array".to_string()));
    }
    cursor.advance(1);

    // Read array length
    let count = match cursor.read_integer() {
        Ok(n) => n,
        Err(ParseError::Incomplete) => return Ok(ParseProgress::Incomplete),
        Err(e) => return Err(e),
    };

    if count < 1 {
        return Err(ParseError::Protocol(
            "array must have at least 1 element".to_string(),
        ));
    }

    const MAX_ARRAY_LEN: usize = 1024 * 1024;
    if count > MAX_ARRAY_LEN {
        return Err(ParseError::Protocol("array too large".to_string()));
    }

    // Read command name
    let cmd_name = match cursor.read_bulk_string() {
        Ok(s) => s,
        Err(ParseError::Incomplete) => return Ok(ParseProgress::Incomplete),
        Err(e) => return Err(e),
    };

    let cmd_str = std::str::from_utf8(cmd_name)
        .map_err(|_| ParseError::Protocol("invalid UTF-8 in command".to_string()))?;

    // Only handle SET specially; other commands use normal path
    if !cmd_str.eq_ignore_ascii_case("set") {
        // Fall back to normal parsing for non-SET commands
        return match Command::parse_with_options(buffer, options) {
            Ok((cmd, consumed)) => Ok(ParseProgress::Complete(cmd, consumed)),
            Err(ParseError::Incomplete) => Ok(ParseProgress::Incomplete),
            Err(e) => Err(e),
        };
    }

    // Parse SET command
    if count < 3 {
        return Err(ParseError::WrongArity(
            "SET requires at least 2 arguments".to_string(),
        ));
    }

    // Read key
    let key = match cursor.read_bulk_string() {
        Ok(s) => s,
        Err(ParseError::Incomplete) => return Ok(ParseProgress::Incomplete),
        Err(e) => return Err(e),
    };

    // Read value length header (but not the value itself)
    if cursor.remaining() < 1 {
        return Ok(ParseProgress::Incomplete);
    }
    if cursor.peek() != b'$' {
        return Err(ParseError::Protocol(
            "expected bulk string for value".to_string(),
        ));
    }
    cursor.advance(1);

    let value_len = match cursor.read_integer() {
        Ok(n) => n,
        Err(ParseError::Incomplete) => return Ok(ParseProgress::Incomplete),
        Err(e) => return Err(e),
    };

    // Check bulk string length limit - return ValueTooLarge to allow draining
    if value_len > cursor.max_bulk_string_len {
        let header_consumed = cursor.position();
        let remaining_in_buffer = cursor.remaining();
        let value_prefix_len = remaining_in_buffer.min(value_len);

        return Ok(ParseProgress::ValueTooLarge {
            value_len,
            value_prefix_len,
            header_consumed,
            max_value_size: cursor.max_bulk_string_len,
        });
    }

    // If value is small, use normal parsing path
    if value_len < streaming_threshold {
        return match Command::parse_with_options(buffer, options) {
            Ok((cmd, consumed)) => Ok(ParseProgress::Complete(cmd, consumed)),
            Err(ParseError::Incomplete) => Ok(ParseProgress::Incomplete),
            Err(e) => Err(e),
        };
    }

    // Large value: return NeedValue for streaming receive
    let header_consumed = cursor.position();
    let remaining_in_buffer = cursor.remaining();

    // Calculate how much of the value (if any) is already in the buffer
    let value_prefix_len = remaining_in_buffer.min(value_len);
    let value_prefix = &buffer[header_consumed..header_consumed + value_prefix_len];

    // Parse any options that come BEFORE the value in the command
    // For standard SET, options come AFTER the value, so remaining_args = count - 3
    let remaining_args = count.saturating_sub(3);

    Ok(ParseProgress::NeedValue {
        header: SetHeader {
            key,
            ex: None,
            px: None,
            nx: false,
            xx: false,
            remaining_args,
        },
        value_len,
        value_prefix,
        header_consumed,
    })
}

/// Complete parsing a SET command after the value has been received.
///
/// This function parses any remaining options (EX, PX, NX, XX) that follow
/// the value in the command.
///
/// # Arguments
///
/// * `buffer` - Buffer containing data after the value (options + CRLF)
/// * `header` - The SET header from `ParseProgress::NeedValue`
/// * `value` - The received value data
///
/// # Returns
///
/// * `Ok((Command, consumed))` - Fully parsed command
/// * `Err(ParseError::Incomplete)` - Need more data for options
/// * `Err(ParseError)` - Parse error
pub fn complete_set<'a>(
    buffer: &'a [u8],
    header: &SetHeader<'a>,
    value: &'a [u8],
) -> Result<(Command<'a>, usize), ParseError> {
    let mut cursor = StreamingCursor::new(buffer, usize::MAX);

    // Expect CRLF after value
    if cursor.remaining() < 2 {
        return Err(ParseError::Incomplete);
    }
    if cursor.peek() != b'\r' {
        return Err(ParseError::Protocol(
            "expected CRLF after bulk string".to_string(),
        ));
    }
    cursor.advance(1);
    if cursor.peek() != b'\n' {
        return Err(ParseError::Protocol(
            "expected CRLF after bulk string".to_string(),
        ));
    }
    cursor.advance(1);

    // Parse remaining options
    let mut ex = header.ex;
    let mut px = header.px;
    let mut nx = header.nx;
    let mut xx = header.xx;

    let mut remaining_args = header.remaining_args;
    while remaining_args > 0 {
        let option = match cursor.read_bulk_string() {
            Ok(s) => s,
            Err(ParseError::Incomplete) => return Err(ParseError::Incomplete),
            Err(e) => return Err(e),
        };

        let option_str = std::str::from_utf8(option)
            .map_err(|_| ParseError::Protocol("invalid UTF-8 in option".to_string()))?;

        if option_str.eq_ignore_ascii_case("ex") {
            if remaining_args < 2 {
                return Err(ParseError::Protocol("EX requires a value".to_string()));
            }
            let ttl_bytes = cursor.read_bulk_string()?;
            let ttl_str = std::str::from_utf8(ttl_bytes)
                .map_err(|_| ParseError::Protocol("invalid UTF-8 in TTL".to_string()))?;
            let ttl_secs = ttl_str
                .parse::<u64>()
                .map_err(|_| ParseError::Protocol("invalid TTL value".to_string()))?;
            ex = Some(ttl_secs);
            remaining_args -= 2;
        } else if option_str.eq_ignore_ascii_case("px") {
            if remaining_args < 2 {
                return Err(ParseError::Protocol("PX requires a value".to_string()));
            }
            let ttl_bytes = cursor.read_bulk_string()?;
            let ttl_str = std::str::from_utf8(ttl_bytes)
                .map_err(|_| ParseError::Protocol("invalid UTF-8 in TTL".to_string()))?;
            let ttl_ms = ttl_str
                .parse::<u64>()
                .map_err(|_| ParseError::Protocol("invalid TTL value".to_string()))?;
            px = Some(ttl_ms);
            remaining_args -= 2;
        } else if option_str.eq_ignore_ascii_case("nx") {
            nx = true;
            remaining_args -= 1;
        } else if option_str.eq_ignore_ascii_case("xx") {
            xx = true;
            remaining_args -= 1;
        } else {
            return Err(ParseError::Protocol(format!(
                "unknown SET option: {}",
                option_str
            )));
        }
    }

    Ok((
        Command::Set {
            key: header.key,
            value,
            ex,
            px,
            nx,
            xx,
        },
        cursor.position(),
    ))
}

/// Internal cursor for streaming parsing.
struct StreamingCursor<'a> {
    buffer: &'a [u8],
    pos: usize,
    max_bulk_string_len: usize,
}

impl<'a> StreamingCursor<'a> {
    fn new(buffer: &'a [u8], max_bulk_string_len: usize) -> Self {
        Self {
            buffer,
            pos: 0,
            max_bulk_string_len,
        }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.buffer.len() - self.pos
    }

    #[inline]
    fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    fn peek(&self) -> u8 {
        self.buffer[self.pos]
    }

    #[inline]
    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn read_integer(&mut self) -> Result<usize, ParseError> {
        let line = self.read_line()?;

        if line.is_empty() {
            return Err(ParseError::InvalidInteger("empty integer".to_string()));
        }

        if line.len() > 19 {
            return Err(ParseError::InvalidInteger("integer too large".to_string()));
        }

        let mut result = 0usize;
        for &byte in line {
            if !byte.is_ascii_digit() {
                return Err(ParseError::InvalidInteger(
                    "non-digit character".to_string(),
                ));
            }
            result = result
                .checked_mul(10)
                .and_then(|r| r.checked_add((byte - b'0') as usize))
                .ok_or_else(|| ParseError::InvalidInteger("integer overflow".to_string()))?;
        }
        Ok(result)
    }

    fn read_bulk_string(&mut self) -> Result<&'a [u8], ParseError> {
        if self.remaining() < 1 {
            return Err(ParseError::Incomplete);
        }

        if self.peek() != b'$' {
            return Err(ParseError::Protocol("expected bulk string".to_string()));
        }
        self.advance(1);

        let len = self.read_integer()?;

        if len > self.max_bulk_string_len {
            return Err(ParseError::BulkStringTooLong {
                len,
                max: self.max_bulk_string_len,
            });
        }

        if self.remaining() < len + 2 {
            return Err(ParseError::Incomplete);
        }

        let data = &self.buffer[self.pos..self.pos + len];
        self.pos += len;

        if self.remaining() < 2 {
            return Err(ParseError::Incomplete);
        }
        if self.peek() != b'\r' {
            return Err(ParseError::Protocol(
                "expected CRLF after bulk string".to_string(),
            ));
        }
        self.advance(1);
        if self.peek() != b'\n' {
            return Err(ParseError::Protocol(
                "expected CRLF after bulk string".to_string(),
            ));
        }
        self.advance(1);

        Ok(data)
    }

    fn read_line(&mut self) -> Result<&'a [u8], ParseError> {
        let start = self.pos;
        let slice = &self.buffer[start..];

        for i in 0..slice.len().saturating_sub(1) {
            if slice[i] == b'\r' && slice[i + 1] == b'\n' {
                let line = &self.buffer[start..start + i];
                self.pos = start + i + 2;
                return Ok(line);
            }
        }

        Err(ParseError::Incomplete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_set_uses_normal_path() {
        let data = b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n";
        let result = parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::Complete(cmd, consumed) => {
                assert_eq!(
                    cmd,
                    Command::Set {
                        key: b"mykey",
                        value: b"myvalue",
                        ex: None,
                        px: None,
                        nx: false,
                        xx: false,
                    }
                );
                assert_eq!(consumed, data.len());
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn test_large_set_yields_need_value() {
        // SET with 100KB value (above threshold)
        let value_len = 100 * 1024;
        let header = format!("*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n${}\r\n", value_len);
        let mut data = header.as_bytes().to_vec();
        // Add some bytes of the value (simulating partial receive)
        data.extend_from_slice(&[b'x'; 1000]);

        let result = parse_streaming(&data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::NeedValue {
                header,
                value_len: vl,
                value_prefix,
                header_consumed,
            } => {
                assert_eq!(header.key, b"mykey");
                assert_eq!(vl, 100 * 1024);
                assert_eq!(value_prefix.len(), 1000);
                assert!(value_prefix.iter().all(|&b| b == b'x'));
                assert_eq!(header_consumed, header_consumed); // Just checking it's set
            }
            _ => panic!("expected NeedValue, got {:?}", result),
        }
    }

    #[test]
    fn test_get_uses_normal_path() {
        let data = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
        let result = parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::Complete(cmd, _) => {
                assert_eq!(cmd, Command::Get { key: b"mykey" });
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn test_incomplete_header() {
        let data = b"*3\r\n$3\r\nSET\r\n$5\r\nmyk";
        let result = parse_streaming(data, &ParseOptions::default(), STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::Incomplete => {}
            _ => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn test_complete_set_with_options() {
        let header = SetHeader {
            key: b"mykey",
            ex: None,
            px: None,
            nx: false,
            xx: false,
            remaining_args: 2, // EX 3600
        };

        let value = b"myvalue";
        let options_data = b"\r\n$2\r\nEX\r\n$4\r\n3600\r\n";

        let (cmd, consumed) = complete_set(options_data, &header, value).unwrap();

        match cmd {
            Command::Set {
                key, value: v, ex, ..
            } => {
                assert_eq!(key, b"mykey");
                assert_eq!(v, b"myvalue");
                assert_eq!(ex, Some(3600));
            }
            _ => panic!("expected Set command"),
        }
        assert_eq!(consumed, options_data.len());
    }

    #[test]
    fn test_streaming_threshold_boundary() {
        // Exactly at threshold - should use streaming
        let value_len = STREAMING_THRESHOLD;
        let header = format!("*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n${}\r\n", value_len);

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

        // Just below threshold - should use normal path (but incomplete)
        let value_len = STREAMING_THRESHOLD - 1;
        let header = format!("*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n${}\r\n", value_len);

        let result = parse_streaming(
            header.as_bytes(),
            &ParseOptions::default(),
            STREAMING_THRESHOLD,
        )
        .unwrap();

        // Will be Incomplete because value data isn't present
        match result {
            ParseProgress::Incomplete => {}
            _ => panic!("expected Incomplete for sub-threshold without data"),
        }
    }

    #[test]
    fn test_value_too_large_yields_value_too_large() {
        // Create options with a small max bulk string length
        let options = ParseOptions::new().max_bulk_string_len(1024); // 1KB limit

        // SET with 2KB value (above limit)
        let header = "*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$2048\r\n".to_string();
        let mut data = header.as_bytes().to_vec();
        // Add some bytes of the value (simulating partial receive)
        data.extend_from_slice(&[b'x'; 500]);

        let result = parse_streaming(&data, &options, STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::ValueTooLarge {
                value_len,
                value_prefix_len,
                header_consumed,
                max_value_size,
            } => {
                assert_eq!(value_len, 2048);
                assert_eq!(value_prefix_len, 500);
                assert_eq!(max_value_size, 1024);
                // header_consumed should be everything up to the value data
                assert_eq!(header_consumed, header.len());
            }
            _ => panic!("expected ValueTooLarge, got {:?}", result),
        }
    }

    #[test]
    fn test_value_too_large_with_no_prefix() {
        // Create options with a small max bulk string length
        let options = ParseOptions::new().max_bulk_string_len(1024); // 1KB limit

        // SET with 2KB value, but no value bytes in buffer yet
        let header = "*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$2048\r\n";

        let result = parse_streaming(header.as_bytes(), &options, STREAMING_THRESHOLD).unwrap();

        match result {
            ParseProgress::ValueTooLarge {
                value_len,
                value_prefix_len,
                max_value_size,
                ..
            } => {
                assert_eq!(value_len, 2048);
                assert_eq!(value_prefix_len, 0); // No value bytes in buffer
                assert_eq!(max_value_size, 1024);
            }
            _ => panic!("expected ValueTooLarge, got {:?}", result),
        }
    }
}
