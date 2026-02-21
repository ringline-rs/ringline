//! Memcache response types and parsing/encoding.
//!
//! Response types:
//! - `VALUE <key> <flags> <bytes>\r\n<data>\r\n... END\r\n` - GET response
//! - `STORED\r\n` - SET success
//! - `NOT_STORED\r\n` - SET failure
//! - `DELETED\r\n` - DELETE success
//! - `NOT_FOUND\r\n` - DELETE miss
//! - `ERROR\r\n` - Generic error
//! - `CLIENT_ERROR <msg>\r\n` - Client error
//! - `SERVER_ERROR <msg>\r\n` - Server error

use crate::error::ParseError;
use std::io::Write;

/// A single value from a GET response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub key: Vec<u8>,
    pub flags: u32,
    pub data: Vec<u8>,
    /// CAS unique token, present when the response is from a `gets` command.
    pub cas: Option<u64>,
}

/// A parsed Memcache response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Value response from GET (may contain multiple values for multi-get)
    Values(Vec<Value>),
    /// STORED response from SET
    Stored,
    /// NOT_STORED response from SET
    NotStored,
    /// DELETED response from DELETE
    Deleted,
    /// NOT_FOUND response from DELETE
    NotFound,
    /// EXISTS response from CAS
    Exists,
    /// OK response (from flush_all, touch, etc.)
    Ok,
    /// Numeric response from INCR/DECR (the new value after the operation).
    Numeric(u64),
    /// VERSION response
    Version(Vec<u8>),
    /// Generic error
    Error,
    /// Client error with message
    ClientError(Vec<u8>),
    /// Server error with message
    ServerError(Vec<u8>),
}

impl Response {
    // ========================================================================
    // Constructors (for server-side encoding)
    // ========================================================================

    /// Create a STORED response.
    #[inline]
    pub fn stored() -> Self {
        Response::Stored
    }

    /// Create a NOT_STORED response.
    #[inline]
    pub fn not_stored() -> Self {
        Response::NotStored
    }

    /// Create a DELETED response.
    #[inline]
    pub fn deleted() -> Self {
        Response::Deleted
    }

    /// Create a NOT_FOUND response.
    #[inline]
    pub fn not_found() -> Self {
        Response::NotFound
    }

    /// Create an OK response.
    #[inline]
    pub fn ok() -> Self {
        Response::Ok
    }

    /// Create a numeric response (from INCR/DECR).
    #[inline]
    pub fn numeric(value: u64) -> Self {
        Response::Numeric(value)
    }

    /// Create an empty VALUES response (cache miss).
    #[inline]
    pub fn miss() -> Self {
        Response::Values(vec![])
    }

    /// Create a VALUES response with a single value (cache hit).
    #[inline]
    pub fn hit(key: &[u8], flags: u32, data: &[u8]) -> Self {
        Response::Values(vec![Value {
            key: key.to_vec(),
            flags,
            data: data.to_vec(),
            cas: None,
        }])
    }

    /// Create an ERROR response.
    #[inline]
    pub fn error() -> Self {
        Response::Error
    }

    /// Create a CLIENT_ERROR response.
    #[inline]
    pub fn client_error(msg: &[u8]) -> Self {
        Response::ClientError(msg.to_vec())
    }

    /// Create a SERVER_ERROR response.
    #[inline]
    pub fn server_error(msg: &[u8]) -> Self {
        Response::ServerError(msg.to_vec())
    }

    // ========================================================================
    // Type checks
    // ========================================================================

    /// Returns true if this is an error response.
    #[inline]
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Response::Error | Response::ClientError(_) | Response::ServerError(_)
        )
    }

    /// Returns true if this represents a cache miss.
    #[inline]
    pub fn is_miss(&self) -> bool {
        match self {
            Response::Values(values) => values.is_empty(),
            Response::NotFound => true,
            _ => false,
        }
    }

    /// Returns true if this is a successful storage response.
    #[inline]
    pub fn is_stored(&self) -> bool {
        matches!(self, Response::Stored)
    }

    // ========================================================================
    // Parsing (client-side)
    // ========================================================================

    /// Parse a response from a byte buffer.
    ///
    /// Returns the parsed response and the number of bytes consumed.
    #[inline]
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ParseError> {
        // Find the first line
        let line_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
        let line = &data[..line_end];

        // Check for simple responses first
        if line == b"STORED" {
            return Ok((Response::Stored, line_end + 2));
        }
        if line == b"NOT_STORED" {
            return Ok((Response::NotStored, line_end + 2));
        }
        if line == b"DELETED" {
            return Ok((Response::Deleted, line_end + 2));
        }
        if line == b"NOT_FOUND" {
            return Ok((Response::NotFound, line_end + 2));
        }
        if line == b"EXISTS" {
            return Ok((Response::Exists, line_end + 2));
        }
        if line == b"END" {
            // Empty GET response (miss)
            return Ok((Response::Values(vec![]), line_end + 2));
        }
        if line == b"OK" {
            return Ok((Response::Ok, line_end + 2));
        }
        if line == b"ERROR" {
            return Ok((Response::Error, line_end + 2));
        }
        if line.starts_with(b"CLIENT_ERROR ") {
            let msg = line[13..].to_vec();
            return Ok((Response::ClientError(msg), line_end + 2));
        }
        if line.starts_with(b"SERVER_ERROR ") {
            let msg = line[13..].to_vec();
            return Ok((Response::ServerError(msg), line_end + 2));
        }
        if line.starts_with(b"VERSION ") {
            let version = line[8..].to_vec();
            return Ok((Response::Version(version), line_end + 2));
        }

        // Check for VALUE response
        if line.starts_with(b"VALUE ") {
            return parse_value_response(data);
        }

        // Check for numeric response (INCR/DECR returns `<number>\r\n`)
        if !line.is_empty() && line.iter().all(|&b| b.is_ascii_digit()) {
            let value = parse_u64(line)?;
            return Ok((Response::Numeric(value), line_end + 2));
        }

        Err(ParseError::Protocol("unknown response"))
    }

    // ========================================================================
    // Encoding (server-side)
    // ========================================================================

    /// Encode this response into a buffer.
    ///
    /// Returns the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        match self {
            Response::Stored => {
                buf[..8].copy_from_slice(b"STORED\r\n");
                8
            }
            Response::NotStored => {
                buf[..12].copy_from_slice(b"NOT_STORED\r\n");
                12
            }
            Response::Deleted => {
                buf[..9].copy_from_slice(b"DELETED\r\n");
                9
            }
            Response::NotFound => {
                buf[..11].copy_from_slice(b"NOT_FOUND\r\n");
                11
            }
            Response::Exists => {
                buf[..8].copy_from_slice(b"EXISTS\r\n");
                8
            }
            Response::Ok => {
                buf[..4].copy_from_slice(b"OK\r\n");
                4
            }
            Response::Numeric(value) => {
                let mut cursor = std::io::Cursor::new(&mut buf[..]);
                write!(cursor, "{}\r\n", value).unwrap();
                cursor.position() as usize
            }
            Response::Error => {
                buf[..7].copy_from_slice(b"ERROR\r\n");
                7
            }
            Response::ClientError(msg) => {
                let mut pos = 0;
                buf[pos..pos + 13].copy_from_slice(b"CLIENT_ERROR ");
                pos += 13;
                buf[pos..pos + msg.len()].copy_from_slice(msg);
                pos += msg.len();
                buf[pos..pos + 2].copy_from_slice(b"\r\n");
                pos + 2
            }
            Response::ServerError(msg) => {
                let mut pos = 0;
                buf[pos..pos + 13].copy_from_slice(b"SERVER_ERROR ");
                pos += 13;
                buf[pos..pos + msg.len()].copy_from_slice(msg);
                pos += msg.len();
                buf[pos..pos + 2].copy_from_slice(b"\r\n");
                pos + 2
            }
            Response::Version(v) => {
                let mut pos = 0;
                buf[pos..pos + 8].copy_from_slice(b"VERSION ");
                pos += 8;
                buf[pos..pos + v.len()].copy_from_slice(v);
                pos += v.len();
                buf[pos..pos + 2].copy_from_slice(b"\r\n");
                pos + 2
            }
            Response::Values(values) => encode_values(buf, values),
        }
    }

    // ========================================================================
    // Direct encoding helpers (for server hot path)
    // ========================================================================

    /// Encode STORED directly to buffer.
    #[inline]
    pub fn encode_stored(buf: &mut [u8]) -> usize {
        buf[..8].copy_from_slice(b"STORED\r\n");
        8
    }

    /// Encode NOT_STORED directly to buffer.
    #[inline]
    pub fn encode_not_stored(buf: &mut [u8]) -> usize {
        buf[..12].copy_from_slice(b"NOT_STORED\r\n");
        12
    }

    /// Encode DELETED directly to buffer.
    #[inline]
    pub fn encode_deleted(buf: &mut [u8]) -> usize {
        buf[..9].copy_from_slice(b"DELETED\r\n");
        9
    }

    /// Encode NOT_FOUND directly to buffer.
    #[inline]
    pub fn encode_not_found(buf: &mut [u8]) -> usize {
        buf[..11].copy_from_slice(b"NOT_FOUND\r\n");
        11
    }

    /// Encode END (empty get response) directly to buffer.
    #[inline]
    pub fn encode_end(buf: &mut [u8]) -> usize {
        buf[..5].copy_from_slice(b"END\r\n");
        5
    }

    /// Encode a single VALUE response directly to buffer.
    #[inline]
    pub fn encode_value(buf: &mut [u8], key: &[u8], flags: u32, data: &[u8]) -> usize {
        let mut pos = 0;

        // VALUE <key> <flags> <bytes>\r\n
        buf[pos..pos + 6].copy_from_slice(b"VALUE ");
        pos += 6;
        buf[pos..pos + key.len()].copy_from_slice(key);
        pos += key.len();
        buf[pos] = b' ';
        pos += 1;

        let mut cursor = std::io::Cursor::new(&mut buf[pos..]);
        write!(cursor, "{} {}\r\n", flags, data.len()).unwrap();
        pos += cursor.position() as usize;

        // <data>\r\n
        buf[pos..pos + data.len()].copy_from_slice(data);
        pos += data.len();
        buf[pos..pos + 2].copy_from_slice(b"\r\n");
        pos += 2;

        // END\r\n
        buf[pos..pos + 5].copy_from_slice(b"END\r\n");
        pos + 5
    }

    /// Encode a single VALUE response with CAS token directly to buffer (GETS response).
    ///
    /// Format: `VALUE <key> <flags> <bytes> <cas>\r\n<data>\r\nEND\r\n`
    #[inline]
    pub fn encode_value_with_cas(
        buf: &mut [u8],
        key: &[u8],
        flags: u32,
        data: &[u8],
        cas: u64,
    ) -> usize {
        let mut pos = 0;

        // VALUE <key> <flags> <bytes> <cas>\r\n
        buf[pos..pos + 6].copy_from_slice(b"VALUE ");
        pos += 6;
        buf[pos..pos + key.len()].copy_from_slice(key);
        pos += key.len();
        buf[pos] = b' ';
        pos += 1;

        let mut cursor = std::io::Cursor::new(&mut buf[pos..]);
        write!(cursor, "{} {} {}\r\n", flags, data.len(), cas).unwrap();
        pos += cursor.position() as usize;

        // <data>\r\n
        buf[pos..pos + data.len()].copy_from_slice(data);
        pos += data.len();
        buf[pos..pos + 2].copy_from_slice(b"\r\n");
        pos += 2;

        // END\r\n
        buf[pos..pos + 5].copy_from_slice(b"END\r\n");
        pos + 5
    }

    /// Encode EXISTS response directly to buffer.
    #[inline]
    pub fn encode_exists(buf: &mut [u8]) -> usize {
        buf[..8].copy_from_slice(b"EXISTS\r\n");
        8
    }

    /// Encode a numeric response directly to buffer (INCR/DECR result).
    #[inline]
    pub fn encode_numeric(buf: &mut [u8], value: u64) -> usize {
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        write!(cursor, "{}\r\n", value).unwrap();
        cursor.position() as usize
    }

    /// Encode a SERVER_ERROR response directly to buffer.
    #[inline]
    pub fn encode_server_error(buf: &mut [u8], msg: &[u8]) -> usize {
        let mut pos = 0;
        buf[pos..pos + 13].copy_from_slice(b"SERVER_ERROR ");
        pos += 13;
        buf[pos..pos + msg.len()].copy_from_slice(msg);
        pos += msg.len();
        buf[pos..pos + 2].copy_from_slice(b"\r\n");
        pos + 2
    }
}

/// Find \r\n in data, return position of \r
fn find_crlf(data: &[u8]) -> Option<usize> {
    memchr::memchr(b'\r', data).and_then(|pos| {
        if pos + 1 < data.len() && data[pos + 1] == b'\n' {
            Some(pos)
        } else {
            None
        }
    })
}

/// Parse a VALUE response (potentially with multiple values).
fn parse_value_response(data: &[u8]) -> Result<(Response, usize), ParseError> {
    let mut values = Vec::new();
    let mut pos = 0;

    loop {
        // Find the line end
        let remaining = &data[pos..];
        let line_end = find_crlf(remaining).ok_or(ParseError::Incomplete)?;
        let line = &remaining[..line_end];

        // Check for END
        if line == b"END" {
            pos += line_end + 2;
            break;
        }

        // Parse VALUE line: VALUE <key> <flags> <bytes> [<cas unique>]
        if !line.starts_with(b"VALUE ") {
            return Err(ParseError::Protocol("expected VALUE or END"));
        }

        let parts: Vec<&[u8]> = line[6..].split(|&b| b == b' ').collect();
        if parts.len() < 3 {
            return Err(ParseError::Protocol("invalid VALUE line"));
        }

        let key = parts[0].to_vec();
        let flags = parse_u32(parts[1])?;
        let bytes = parse_usize(parts[2])?;
        let cas = if parts.len() >= 4 {
            Some(parse_u64(parts[3])?)
        } else {
            None
        };

        // Move past the VALUE line
        pos += line_end + 2;

        // Read the data
        let data_end = pos + bytes;
        if data.len() < data_end + 2 {
            return Err(ParseError::Incomplete);
        }

        // Verify trailing \r\n
        if data[data_end] != b'\r' || data[data_end + 1] != b'\n' {
            return Err(ParseError::Protocol("missing data terminator"));
        }

        let value_data = data[pos..data_end].to_vec();
        pos = data_end + 2;

        values.push(Value {
            key,
            flags,
            data: value_data,
            cas,
        });
    }

    Ok((Response::Values(values), pos))
}

/// Encode multiple values as a response.
fn encode_values(buf: &mut [u8], values: &[Value]) -> usize {
    let mut pos = 0;

    for value in values {
        // VALUE <key> <flags> <bytes> [<cas>]\r\n
        buf[pos..pos + 6].copy_from_slice(b"VALUE ");
        pos += 6;
        buf[pos..pos + value.key.len()].copy_from_slice(&value.key);
        pos += value.key.len();
        buf[pos] = b' ';
        pos += 1;

        let mut cursor = std::io::Cursor::new(&mut buf[pos..]);
        if let Some(cas) = value.cas {
            write!(cursor, "{} {} {}\r\n", value.flags, value.data.len(), cas).unwrap();
        } else {
            write!(cursor, "{} {}\r\n", value.flags, value.data.len()).unwrap();
        }
        pos += cursor.position() as usize;

        // <data>\r\n
        buf[pos..pos + value.data.len()].copy_from_slice(&value.data);
        pos += value.data.len();
        buf[pos..pos + 2].copy_from_slice(b"\r\n");
        pos += 2;
    }

    // END\r\n
    buf[pos..pos + 5].copy_from_slice(b"END\r\n");
    pos + 5
}

/// Parse a u32 from ASCII decimal.
fn parse_u32(data: &[u8]) -> Result<u32, ParseError> {
    std::str::from_utf8(data)
        .map_err(|_| ParseError::InvalidNumber)?
        .parse()
        .map_err(|_| ParseError::InvalidNumber)
}

/// Parse a u64 from ASCII decimal.
fn parse_u64(data: &[u8]) -> Result<u64, ParseError> {
    std::str::from_utf8(data)
        .map_err(|_| ParseError::InvalidNumber)?
        .parse()
        .map_err(|_| ParseError::InvalidNumber)
}

/// Maximum value data size (1MB, matching DEFAULT_MAX_VALUE_LEN).
const MAX_VALUE_DATA_LEN: usize = 1024 * 1024;

/// Parse a usize from ASCII decimal, with a maximum limit.
fn parse_usize(data: &[u8]) -> Result<usize, ParseError> {
    let value: usize = std::str::from_utf8(data)
        .map_err(|_| ParseError::InvalidNumber)?
        .parse()
        .map_err(|_| ParseError::InvalidNumber)?;

    if value > MAX_VALUE_DATA_LEN {
        return Err(ParseError::Protocol("value data too large"));
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stored() {
        let (resp, consumed) = Response::parse(b"STORED\r\n").unwrap();
        assert_eq!(resp, Response::Stored);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_not_stored() {
        let (resp, consumed) = Response::parse(b"NOT_STORED\r\n").unwrap();
        assert_eq!(resp, Response::NotStored);
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_deleted() {
        let (resp, consumed) = Response::parse(b"DELETED\r\n").unwrap();
        assert_eq!(resp, Response::Deleted);
        assert_eq!(consumed, 9);
    }

    #[test]
    fn test_parse_not_found() {
        let (resp, consumed) = Response::parse(b"NOT_FOUND\r\n").unwrap();
        assert_eq!(resp, Response::NotFound);
        assert_eq!(consumed, 11);
    }

    #[test]
    fn test_parse_end() {
        let (resp, consumed) = Response::parse(b"END\r\n").unwrap();
        assert_eq!(resp, Response::Values(vec![]));
        assert_eq!(consumed, 5);
        assert!(resp.is_miss());
    }

    #[test]
    fn test_parse_value() {
        let data = b"VALUE mykey 0 7\r\nmyvalue\r\nEND\r\n";
        let (resp, consumed) = Response::parse(data).unwrap();
        assert_eq!(consumed, data.len());
        match resp {
            Response::Values(values) => {
                assert_eq!(values.len(), 1);
                assert_eq!(values[0].key, b"mykey");
                assert_eq!(values[0].flags, 0);
                assert_eq!(values[0].data, b"myvalue");
            }
            _ => panic!("expected Values"),
        }
    }

    #[test]
    fn test_parse_multi_value() {
        let data = b"VALUE key1 0 3\r\nfoo\r\nVALUE key2 0 3\r\nbar\r\nEND\r\n";
        let (resp, consumed) = Response::parse(data).unwrap();
        assert_eq!(consumed, data.len());
        match resp {
            Response::Values(values) => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0].key, b"key1");
                assert_eq!(values[0].data, b"foo");
                assert_eq!(values[1].key, b"key2");
                assert_eq!(values[1].data, b"bar");
            }
            _ => panic!("expected Values"),
        }
    }

    #[test]
    fn test_parse_error() {
        let (resp, _) = Response::parse(b"ERROR\r\n").unwrap();
        assert!(resp.is_error());
    }

    #[test]
    fn test_parse_server_error() {
        let (resp, _) = Response::parse(b"SERVER_ERROR out of memory\r\n").unwrap();
        assert!(resp.is_error());
        match resp {
            Response::ServerError(msg) => assert_eq!(msg, b"out of memory"),
            _ => panic!("expected ServerError"),
        }
    }

    #[test]
    fn test_parse_incomplete() {
        assert!(matches!(
            Response::parse(b"VALUE mykey 0 7\r\nmyval"),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_encode_stored() {
        let mut buf = [0u8; 64];
        let len = Response::stored().encode(&mut buf);
        assert_eq!(&buf[..len], b"STORED\r\n");
    }

    #[test]
    fn test_encode_deleted() {
        let mut buf = [0u8; 64];
        let len = Response::deleted().encode(&mut buf);
        assert_eq!(&buf[..len], b"DELETED\r\n");
    }

    #[test]
    fn test_encode_value() {
        let mut buf = [0u8; 128];
        let len = Response::encode_value(&mut buf, b"mykey", 0, b"myvalue");
        assert_eq!(&buf[..len], b"VALUE mykey 0 7\r\nmyvalue\r\nEND\r\n");
    }

    #[test]
    fn test_encode_miss() {
        let mut buf = [0u8; 64];
        let len = Response::miss().encode(&mut buf);
        assert_eq!(&buf[..len], b"END\r\n");
    }

    #[test]
    fn test_roundtrip() {
        let mut buf = [0u8; 256];

        // Test simple responses
        let responses = vec![
            Response::stored(),
            Response::not_stored(),
            Response::deleted(),
            Response::not_found(),
            Response::ok(),
            Response::numeric(0),
            Response::numeric(42),
            Response::numeric(18446744073709551615),
            Response::error(),
            Response::miss(),
        ];

        for original in responses {
            let len = original.encode(&mut buf);
            let (parsed, consumed) = Response::parse(&buf[..len]).unwrap();
            assert_eq!(original, parsed);
            assert_eq!(len, consumed);
        }
    }

    // Additional tests for improved coverage

    #[test]
    fn test_parse_exists() {
        let (resp, consumed) = Response::parse(b"EXISTS\r\n").unwrap();
        assert_eq!(resp, Response::Exists);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_client_error() {
        let (resp, consumed) = Response::parse(b"CLIENT_ERROR bad request\r\n").unwrap();
        assert!(resp.is_error());
        assert_eq!(consumed, 26);
        match resp {
            Response::ClientError(msg) => assert_eq!(msg, b"bad request"),
            _ => panic!("expected ClientError"),
        }
    }

    #[test]
    fn test_parse_version() {
        let (resp, consumed) = Response::parse(b"VERSION 1.6.9\r\n").unwrap();
        assert_eq!(consumed, 15);
        match resp {
            Response::Version(v) => assert_eq!(v, b"1.6.9"),
            _ => panic!("expected Version"),
        }
    }

    #[test]
    fn test_parse_unknown_response() {
        let result = Response::parse(b"UNKNOWN\r\n");
        assert!(matches!(
            result,
            Err(ParseError::Protocol("unknown response"))
        ));
    }

    #[test]
    fn test_parse_incomplete_no_crlf() {
        assert!(matches!(
            Response::parse(b"STORED"),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_parse_value_incomplete_data() {
        // VALUE line complete but data incomplete
        assert!(matches!(
            Response::parse(b"VALUE k 0 10\r\nshort\r\nEND\r\n"),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_parse_value_missing_terminator() {
        // Data is correct length but missing \r\n terminator
        assert!(matches!(
            Response::parse(b"VALUE k 0 5\r\nhelloXXEND\r\n"),
            Err(ParseError::Protocol("missing data terminator"))
        ));
    }

    #[test]
    fn test_parse_value_invalid_format() {
        // VALUE line with too few parts
        assert!(matches!(
            Response::parse(b"VALUE k\r\nEND\r\n"),
            Err(ParseError::Protocol("invalid VALUE line"))
        ));
    }

    #[test]
    fn test_parse_value_invalid_flags() {
        // Non-numeric flags
        assert!(matches!(
            Response::parse(b"VALUE k abc 5\r\nhello\r\nEND\r\n"),
            Err(ParseError::InvalidNumber)
        ));
    }

    #[test]
    fn test_parse_value_invalid_bytes() {
        // Non-numeric bytes
        assert!(matches!(
            Response::parse(b"VALUE k 0 xyz\r\nhello\r\nEND\r\n"),
            Err(ParseError::InvalidNumber)
        ));
    }

    #[test]
    fn test_parse_value_expected_end() {
        // After VALUE data, expect END or another VALUE
        assert!(matches!(
            Response::parse(b"VALUE k 0 5\r\nhello\r\nSTORED\r\n"),
            Err(ParseError::Protocol("expected VALUE or END"))
        ));
    }

    #[test]
    fn test_parse_ok() {
        let (resp, consumed) = Response::parse(b"OK\r\n").unwrap();
        assert_eq!(resp, Response::Ok);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_encode_ok() {
        let mut buf = [0u8; 64];
        let len = Response::ok().encode(&mut buf);
        assert_eq!(&buf[..len], b"OK\r\n");
    }

    #[test]
    fn test_parse_numeric() {
        let (resp, consumed) = Response::parse(b"42\r\n").unwrap();
        assert_eq!(resp, Response::Numeric(42));
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_parse_numeric_zero() {
        let (resp, consumed) = Response::parse(b"0\r\n").unwrap();
        assert_eq!(resp, Response::Numeric(0));
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_parse_numeric_large() {
        let (resp, consumed) = Response::parse(b"18446744073709551615\r\n").unwrap();
        assert_eq!(resp, Response::Numeric(u64::MAX));
        assert_eq!(consumed, 22);
    }

    #[test]
    fn test_encode_numeric() {
        let mut buf = [0u8; 64];
        let len = Response::numeric(42).encode(&mut buf);
        assert_eq!(&buf[..len], b"42\r\n");
    }

    #[test]
    fn test_encode_numeric_zero() {
        let mut buf = [0u8; 64];
        let len = Response::numeric(0).encode(&mut buf);
        assert_eq!(&buf[..len], b"0\r\n");
    }

    #[test]
    fn test_direct_encode_numeric() {
        let mut buf = [0u8; 64];
        let len = Response::encode_numeric(&mut buf, 12345);
        assert_eq!(&buf[..len], b"12345\r\n");
    }

    #[test]
    fn test_is_error_variants() {
        assert!(Response::Error.is_error());
        assert!(Response::ClientError(b"msg".to_vec()).is_error());
        assert!(Response::ServerError(b"msg".to_vec()).is_error());
        assert!(!Response::Stored.is_error());
        assert!(!Response::NotStored.is_error());
        assert!(!Response::Deleted.is_error());
        assert!(!Response::NotFound.is_error());
        assert!(!Response::Exists.is_error());
        assert!(!Response::Ok.is_error());
        assert!(!Response::Numeric(42).is_error());
        assert!(!Response::Values(vec![]).is_error());
        assert!(!Response::Version(b"1.0".to_vec()).is_error());
    }

    #[test]
    fn test_is_miss_variants() {
        // Empty values is a miss
        assert!(Response::Values(vec![]).is_miss());
        // NotFound is a miss
        assert!(Response::NotFound.is_miss());
        // Non-empty values is not a miss
        assert!(
            !Response::Values(vec![Value {
                key: b"k".to_vec(),
                flags: 0,
                data: b"v".to_vec(),
                cas: None,
            }])
            .is_miss()
        );
        // Other responses are not misses
        assert!(!Response::Stored.is_miss());
        assert!(!Response::Deleted.is_miss());
        assert!(!Response::Ok.is_miss());
        assert!(!Response::Numeric(0).is_miss());
        assert!(!Response::Error.is_miss());
    }

    #[test]
    fn test_is_stored_variants() {
        assert!(Response::Stored.is_stored());
        assert!(!Response::NotStored.is_stored());
        assert!(!Response::Deleted.is_stored());
        assert!(!Response::Error.is_stored());
    }

    #[test]
    fn test_encode_not_stored() {
        let mut buf = [0u8; 64];
        let len = Response::not_stored().encode(&mut buf);
        assert_eq!(&buf[..len], b"NOT_STORED\r\n");
    }

    #[test]
    fn test_encode_not_found() {
        let mut buf = [0u8; 64];
        let len = Response::not_found().encode(&mut buf);
        assert_eq!(&buf[..len], b"NOT_FOUND\r\n");
    }

    #[test]
    fn test_encode_exists() {
        let mut buf = [0u8; 64];
        let len = Response::Exists.encode(&mut buf);
        assert_eq!(&buf[..len], b"EXISTS\r\n");
    }

    #[test]
    fn test_encode_error() {
        let mut buf = [0u8; 64];
        let len = Response::error().encode(&mut buf);
        assert_eq!(&buf[..len], b"ERROR\r\n");
    }

    #[test]
    fn test_encode_client_error() {
        let mut buf = [0u8; 64];
        let len = Response::client_error(b"bad request").encode(&mut buf);
        assert_eq!(&buf[..len], b"CLIENT_ERROR bad request\r\n");
    }

    #[test]
    fn test_encode_server_error() {
        let mut buf = [0u8; 64];
        let len = Response::server_error(b"out of memory").encode(&mut buf);
        assert_eq!(&buf[..len], b"SERVER_ERROR out of memory\r\n");
    }

    #[test]
    fn test_encode_version() {
        let mut buf = [0u8; 64];
        let len = Response::Version(b"1.6.9".to_vec()).encode(&mut buf);
        assert_eq!(&buf[..len], b"VERSION 1.6.9\r\n");
    }

    #[test]
    fn test_encode_hit() {
        let mut buf = [0u8; 128];
        let resp = Response::hit(b"mykey", 42, b"myvalue");
        let len = resp.encode(&mut buf);
        assert_eq!(&buf[..len], b"VALUE mykey 42 7\r\nmyvalue\r\nEND\r\n");
    }

    #[test]
    fn test_encode_multi_values() {
        let mut buf = [0u8; 256];
        let resp = Response::Values(vec![
            Value {
                key: b"k1".to_vec(),
                flags: 0,
                data: b"v1".to_vec(),
                cas: None,
            },
            Value {
                key: b"k2".to_vec(),
                flags: 1,
                data: b"v2".to_vec(),
                cas: None,
            },
        ]);
        let len = resp.encode(&mut buf);
        assert_eq!(
            &buf[..len],
            b"VALUE k1 0 2\r\nv1\r\nVALUE k2 1 2\r\nv2\r\nEND\r\n"
        );
    }

    #[test]
    fn test_direct_encode_stored() {
        let mut buf = [0u8; 64];
        let len = Response::encode_stored(&mut buf);
        assert_eq!(&buf[..len], b"STORED\r\n");
    }

    #[test]
    fn test_direct_encode_not_stored() {
        let mut buf = [0u8; 64];
        let len = Response::encode_not_stored(&mut buf);
        assert_eq!(&buf[..len], b"NOT_STORED\r\n");
    }

    #[test]
    fn test_direct_encode_deleted() {
        let mut buf = [0u8; 64];
        let len = Response::encode_deleted(&mut buf);
        assert_eq!(&buf[..len], b"DELETED\r\n");
    }

    #[test]
    fn test_direct_encode_not_found() {
        let mut buf = [0u8; 64];
        let len = Response::encode_not_found(&mut buf);
        assert_eq!(&buf[..len], b"NOT_FOUND\r\n");
    }

    #[test]
    fn test_direct_encode_end() {
        let mut buf = [0u8; 64];
        let len = Response::encode_end(&mut buf);
        assert_eq!(&buf[..len], b"END\r\n");
    }

    #[test]
    fn test_direct_encode_server_error() {
        let mut buf = [0u8; 64];
        let len = Response::encode_server_error(&mut buf, b"error message");
        assert_eq!(&buf[..len], b"SERVER_ERROR error message\r\n");
    }

    #[test]
    fn test_roundtrip_client_error() {
        let mut buf = [0u8; 256];
        let original = Response::client_error(b"test error");
        let len = original.encode(&mut buf);
        let (parsed, consumed) = Response::parse(&buf[..len]).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(len, consumed);
    }

    #[test]
    fn test_roundtrip_server_error() {
        let mut buf = [0u8; 256];
        let original = Response::server_error(b"test error");
        let len = original.encode(&mut buf);
        let (parsed, consumed) = Response::parse(&buf[..len]).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(len, consumed);
    }

    #[test]
    fn test_roundtrip_values() {
        let mut buf = [0u8; 256];
        let original = Response::hit(b"testkey", 123, b"testvalue");
        let len = original.encode(&mut buf);
        let (parsed, consumed) = Response::parse(&buf[..len]).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(len, consumed);
    }

    #[test]
    fn test_value_debug() {
        let v = Value {
            key: b"k".to_vec(),
            flags: 0,
            data: b"v".to_vec(),
            cas: None,
        };
        let debug_str = format!("{:?}", v);
        assert!(debug_str.contains("Value"));
    }

    #[test]
    fn test_value_clone() {
        let v1 = Value {
            key: b"k".to_vec(),
            flags: 42,
            data: b"v".to_vec(),
            cas: None,
        };
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_response_debug() {
        let resp = Response::Stored;
        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("Stored"));
    }

    #[test]
    fn test_response_clone() {
        let r1 = Response::Stored;
        let r2 = r1.clone();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_parse_value_with_flags() {
        let data = b"VALUE mykey 12345 5\r\nhello\r\nEND\r\n";
        let (resp, _) = Response::parse(data).unwrap();
        match resp {
            Response::Values(values) => {
                assert_eq!(values[0].flags, 12345);
            }
            _ => panic!("expected Values"),
        }
    }

    #[test]
    fn test_find_crlf_edge_cases() {
        // \r at end without \n
        assert!(Response::parse(b"STORED\r").is_err());
    }

    #[test]
    fn test_parse_value_data_too_large() {
        // Value data size exceeding MAX_VALUE_DATA_LEN should be rejected
        let data = b"VALUE k 0 18446744073709551615\r\n";
        let result = Response::parse(data);
        assert!(matches!(
            result,
            Err(ParseError::Protocol("value data too large"))
        ));
    }

    #[test]
    fn test_parse_value_with_cas() {
        let data = b"VALUE mykey 0 5 12345\r\nhello\r\nEND\r\n";
        let (resp, consumed) = Response::parse(data).unwrap();
        assert_eq!(consumed, data.len());
        match resp {
            Response::Values(values) => {
                assert_eq!(values.len(), 1);
                assert_eq!(values[0].key, b"mykey");
                assert_eq!(values[0].data, b"hello");
                assert_eq!(values[0].cas, Some(12345));
            }
            _ => panic!("expected Values"),
        }
    }

    #[test]
    fn test_parse_value_without_cas() {
        let data = b"VALUE mykey 0 5\r\nhello\r\nEND\r\n";
        let (resp, _) = Response::parse(data).unwrap();
        match resp {
            Response::Values(values) => {
                assert_eq!(values[0].cas, None);
            }
            _ => panic!("expected Values"),
        }
    }

    #[test]
    fn test_roundtrip_value_with_cas() {
        let mut buf = [0u8; 256];
        let original = Response::Values(vec![Value {
            key: b"testkey".to_vec(),
            flags: 0,
            data: b"testvalue".to_vec(),
            cas: Some(98765),
        }]);
        let len = original.encode(&mut buf);
        let (parsed, consumed) = Response::parse(&buf[..len]).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(len, consumed);
    }

    #[test]
    fn test_parse_multi_value_with_cas() {
        let data = b"VALUE k1 0 2 100\r\nv1\r\nVALUE k2 0 2 200\r\nv2\r\nEND\r\n";
        let (resp, consumed) = Response::parse(data).unwrap();
        assert_eq!(consumed, data.len());
        match resp {
            Response::Values(values) => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0].cas, Some(100));
                assert_eq!(values[1].cas, Some(200));
            }
            _ => panic!("expected Values"),
        }
    }
}
