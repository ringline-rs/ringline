//! Server-side command parsing for Memcache ASCII protocol.
//!
//! This module parses incoming Memcache requests into structured commands.

use crate::error::ParseError;

/// Default maximum key size in bytes (memcached default is 250)
pub const DEFAULT_MAX_KEY_LEN: usize = 250;

/// Default maximum value size in bytes (memcached default is 1MB)
pub const DEFAULT_MAX_VALUE_LEN: usize = 1024 * 1024;

/// Default maximum number of keys in a multi-GET command (batch size).
pub const DEFAULT_MAX_KEYS: usize = 1024;

/// Configuration options for command parsing.
///
/// These options allow customizing the DoS protection limits for different
/// deployment scenarios. More restrictive limits provide better protection
/// against resource exhaustion attacks.
#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    /// Maximum key size in bytes.
    pub max_key_len: usize,
    /// Maximum value size in bytes.
    pub max_value_len: usize,
    /// Maximum number of keys in a multi-GET command.
    pub max_keys: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_key_len: DEFAULT_MAX_KEY_LEN,
            max_value_len: DEFAULT_MAX_VALUE_LEN,
            max_keys: DEFAULT_MAX_KEYS,
        }
    }
}

impl ParseOptions {
    /// Create new parse options with default values.
    pub const fn new() -> Self {
        Self {
            max_key_len: DEFAULT_MAX_KEY_LEN,
            max_value_len: DEFAULT_MAX_VALUE_LEN,
            max_keys: DEFAULT_MAX_KEYS,
        }
    }

    /// Set the maximum key length.
    pub const fn max_key_len(mut self, len: usize) -> Self {
        self.max_key_len = len;
        self
    }

    /// Set the maximum value length.
    pub const fn max_value_len(mut self, len: usize) -> Self {
        self.max_value_len = len;
        self
    }

    /// Set the maximum number of keys in a multi-GET command.
    pub const fn max_keys(mut self, count: usize) -> Self {
        self.max_keys = count;
        self
    }

    /// Calculate the maximum command line length based on the configured limits.
    ///
    /// The longest line is a multi-GET with max_keys keys of max_key_len each:
    /// `get <key1> <key2> ... <keyN>\r\n`
    pub const fn max_line_len(&self) -> usize {
        // "get " + (key + space) * max_keys
        4 + (self.max_key_len + 1) * self.max_keys
    }
}

/// A parsed Memcache command with references to the original buffer.
///
/// Commands are parsed with zero-copy semantics where possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command<'a> {
    /// GET command
    Get { key: &'a [u8] },
    /// Multi-GET command
    Gets { keys: Vec<&'a [u8]> },
    /// SET command
    Set {
        key: &'a [u8],
        flags: u32,
        exptime: u32,
        data: &'a [u8],
    },
    /// ADD command - store only if key doesn't exist
    Add {
        key: &'a [u8],
        flags: u32,
        exptime: u32,
        data: &'a [u8],
    },
    /// REPLACE command - store only if key exists
    Replace {
        key: &'a [u8],
        flags: u32,
        exptime: u32,
        data: &'a [u8],
    },
    /// CAS (compare-and-swap) command
    Cas {
        key: &'a [u8],
        flags: u32,
        exptime: u32,
        data: &'a [u8],
        cas_unique: u64,
    },
    /// DELETE command
    Delete { key: &'a [u8] },
    /// FLUSH_ALL command
    FlushAll,
    /// VERSION command
    Version,
    /// QUIT command
    Quit,
    /// INCR command - increment numeric value
    Incr {
        key: &'a [u8],
        delta: u64,
        noreply: bool,
    },
    /// DECR command - decrement numeric value
    Decr {
        key: &'a [u8],
        delta: u64,
        noreply: bool,
    },
    /// APPEND command - append data to existing value
    Append {
        key: &'a [u8],
        data: &'a [u8],
        noreply: bool,
    },
    /// PREPEND command - prepend data to existing value
    Prepend {
        key: &'a [u8],
        data: &'a [u8],
        noreply: bool,
    },
}

impl<'a> Command<'a> {
    /// Parse a command from a byte buffer using default options.
    ///
    /// Returns the parsed command and the number of bytes consumed.
    ///
    /// # Zero-copy
    ///
    /// The returned command contains references to the input buffer for keys
    /// and data, avoiding allocation in the hot path.
    #[inline]
    pub fn parse(buffer: &'a [u8]) -> Result<(Self, usize), ParseError> {
        Self::parse_with_options(buffer, &ParseOptions::default())
    }

    /// Parse a command from a byte buffer with custom options.
    ///
    /// This allows configuring DoS protection limits like maximum key size,
    /// value size, and line length.
    pub fn parse_with_options(
        buffer: &'a [u8],
        options: &ParseOptions,
    ) -> Result<(Self, usize), ParseError> {
        // Find the end of the command line
        let max_line_len = options.max_line_len();
        let line_end = find_crlf(buffer, max_line_len)?.ok_or(ParseError::Incomplete)?;
        let line = &buffer[..line_end];
        let mut parts = line.split(|&b| b == b' ');

        let cmd = parts.next().ok_or(ParseError::Protocol("empty command"))?;

        match cmd {
            b"get" | b"GET" => {
                // Collect all keys
                let keys: Vec<&[u8]> = parts.filter(|k| !k.is_empty()).collect();
                if keys.is_empty() {
                    return Err(ParseError::Protocol("get requires key"));
                }
                if keys.len() > options.max_keys {
                    return Err(ParseError::Protocol("too many keys"));
                }
                if keys.len() == 1 {
                    Ok((Command::Get { key: keys[0] }, line_end + 2))
                } else {
                    Ok((Command::Gets { keys }, line_end + 2))
                }
            }

            b"gets" | b"GETS" => {
                // gets always returns CAS tokens — maps to Command::Gets
                let keys: Vec<&[u8]> = parts.filter(|k| !k.is_empty()).collect();
                if keys.is_empty() {
                    return Err(ParseError::Protocol("gets requires key"));
                }
                if keys.len() > options.max_keys {
                    return Err(ParseError::Protocol("too many keys"));
                }
                Ok((Command::Gets { keys }, line_end + 2))
            }

            b"set" | b"SET" => {
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
                let data_len = parse_usize(bytes_str)?;
                if data_len > options.max_value_len {
                    return Err(ParseError::Protocol("value too large"));
                }

                // Data block follows the command line: <data>\r\n
                let data_start = line_end + 2;
                let data_end = data_start
                    .checked_add(data_len)
                    .ok_or(ParseError::InvalidNumber)?;
                let total_len = data_end.checked_add(2).ok_or(ParseError::InvalidNumber)?;

                if buffer.len() < total_len {
                    return Err(ParseError::Incomplete);
                }

                // Verify trailing \r\n
                if buffer[data_end] != b'\r' || buffer[data_end + 1] != b'\n' {
                    return Err(ParseError::Protocol("missing data terminator"));
                }

                let data = &buffer[data_start..data_end];
                Ok((
                    Command::Set {
                        key,
                        flags,
                        exptime,
                        data,
                    },
                    total_len,
                ))
            }

            b"add" | b"ADD" => {
                let key = parts
                    .next()
                    .ok_or(ParseError::Protocol("add requires key"))?;
                if key.is_empty() {
                    return Err(ParseError::Protocol("empty key"));
                }
                if key.len() > options.max_key_len {
                    return Err(ParseError::Protocol("key too large"));
                }
                let flags_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("add requires flags"))?;
                let exptime_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("add requires exptime"))?;
                let bytes_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("add requires bytes"))?;

                let flags = parse_u32(flags_str)?;
                let exptime = parse_u32(exptime_str)?;
                let data_len = parse_usize(bytes_str)?;
                if data_len > options.max_value_len {
                    return Err(ParseError::Protocol("value too large"));
                }

                // Data block follows the command line: <data>\r\n
                let data_start = line_end + 2;
                let data_end = data_start
                    .checked_add(data_len)
                    .ok_or(ParseError::InvalidNumber)?;
                let total_len = data_end.checked_add(2).ok_or(ParseError::InvalidNumber)?;

                if buffer.len() < total_len {
                    return Err(ParseError::Incomplete);
                }

                // Verify trailing \r\n
                if buffer[data_end] != b'\r' || buffer[data_end + 1] != b'\n' {
                    return Err(ParseError::Protocol("missing data terminator"));
                }

                let data = &buffer[data_start..data_end];
                Ok((
                    Command::Add {
                        key,
                        flags,
                        exptime,
                        data,
                    },
                    total_len,
                ))
            }

            b"replace" | b"REPLACE" => {
                let key = parts
                    .next()
                    .ok_or(ParseError::Protocol("replace requires key"))?;
                if key.is_empty() {
                    return Err(ParseError::Protocol("empty key"));
                }
                if key.len() > options.max_key_len {
                    return Err(ParseError::Protocol("key too large"));
                }
                let flags_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("replace requires flags"))?;
                let exptime_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("replace requires exptime"))?;
                let bytes_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("replace requires bytes"))?;

                let flags = parse_u32(flags_str)?;
                let exptime = parse_u32(exptime_str)?;
                let data_len = parse_usize(bytes_str)?;
                if data_len > options.max_value_len {
                    return Err(ParseError::Protocol("value too large"));
                }

                // Data block follows the command line: <data>\r\n
                let data_start = line_end + 2;
                let data_end = data_start
                    .checked_add(data_len)
                    .ok_or(ParseError::InvalidNumber)?;
                let total_len = data_end.checked_add(2).ok_or(ParseError::InvalidNumber)?;

                if buffer.len() < total_len {
                    return Err(ParseError::Incomplete);
                }

                // Verify trailing \r\n
                if buffer[data_end] != b'\r' || buffer[data_end + 1] != b'\n' {
                    return Err(ParseError::Protocol("missing data terminator"));
                }

                let data = &buffer[data_start..data_end];
                Ok((
                    Command::Replace {
                        key,
                        flags,
                        exptime,
                        data,
                    },
                    total_len,
                ))
            }

            b"cas" | b"CAS" => {
                let key = parts
                    .next()
                    .ok_or(ParseError::Protocol("cas requires key"))?;
                if key.is_empty() {
                    return Err(ParseError::Protocol("empty key"));
                }
                if key.len() > options.max_key_len {
                    return Err(ParseError::Protocol("key too large"));
                }
                let flags_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("cas requires flags"))?;
                let exptime_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("cas requires exptime"))?;
                let bytes_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("cas requires bytes"))?;
                let cas_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("cas requires cas_unique"))?;

                let flags = parse_u32(flags_str)?;
                let exptime = parse_u32(exptime_str)?;
                let data_len = parse_usize(bytes_str)?;
                let cas_unique = parse_u64(cas_str)?;
                if data_len > options.max_value_len {
                    return Err(ParseError::Protocol("value too large"));
                }

                // Data block follows the command line: <data>\r\n
                let data_start = line_end + 2;
                let data_end = data_start
                    .checked_add(data_len)
                    .ok_or(ParseError::InvalidNumber)?;
                let total_len = data_end.checked_add(2).ok_or(ParseError::InvalidNumber)?;

                if buffer.len() < total_len {
                    return Err(ParseError::Incomplete);
                }

                // Verify trailing \r\n
                if buffer[data_end] != b'\r' || buffer[data_end + 1] != b'\n' {
                    return Err(ParseError::Protocol("missing data terminator"));
                }

                let data = &buffer[data_start..data_end];
                Ok((
                    Command::Cas {
                        key,
                        flags,
                        exptime,
                        data,
                        cas_unique,
                    },
                    total_len,
                ))
            }

            b"delete" | b"DELETE" => {
                let key = parts
                    .next()
                    .ok_or(ParseError::Protocol("delete requires key"))?;
                if key.is_empty() {
                    return Err(ParseError::Protocol("empty key"));
                }
                Ok((Command::Delete { key }, line_end + 2))
            }

            b"flush_all" | b"FLUSH_ALL" => Ok((Command::FlushAll, line_end + 2)),

            b"version" | b"VERSION" => Ok((Command::Version, line_end + 2)),

            b"quit" | b"QUIT" => Ok((Command::Quit, line_end + 2)),

            b"incr" | b"INCR" => {
                let key = parts
                    .next()
                    .ok_or(ParseError::Protocol("incr requires key"))?;
                if key.is_empty() {
                    return Err(ParseError::Protocol("empty key"));
                }
                if key.len() > options.max_key_len {
                    return Err(ParseError::Protocol("key too large"));
                }
                let delta_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("incr requires delta"))?;
                let delta = parse_u64(delta_str)?;
                let noreply = parts
                    .next()
                    .map(|s| s == b"noreply" || s == b"NOREPLY")
                    .unwrap_or(false);
                Ok((
                    Command::Incr {
                        key,
                        delta,
                        noreply,
                    },
                    line_end + 2,
                ))
            }

            b"decr" | b"DECR" => {
                let key = parts
                    .next()
                    .ok_or(ParseError::Protocol("decr requires key"))?;
                if key.is_empty() {
                    return Err(ParseError::Protocol("empty key"));
                }
                if key.len() > options.max_key_len {
                    return Err(ParseError::Protocol("key too large"));
                }
                let delta_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("decr requires delta"))?;
                let delta = parse_u64(delta_str)?;
                let noreply = parts
                    .next()
                    .map(|s| s == b"noreply" || s == b"NOREPLY")
                    .unwrap_or(false);
                Ok((
                    Command::Decr {
                        key,
                        delta,
                        noreply,
                    },
                    line_end + 2,
                ))
            }

            b"append" | b"APPEND" => {
                let key = parts
                    .next()
                    .ok_or(ParseError::Protocol("append requires key"))?;
                if key.is_empty() {
                    return Err(ParseError::Protocol("empty key"));
                }
                if key.len() > options.max_key_len {
                    return Err(ParseError::Protocol("key too large"));
                }
                // flags and exptime are required by protocol but ignored for append
                let _flags_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("append requires flags"))?;
                let _exptime_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("append requires exptime"))?;
                let bytes_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("append requires bytes"))?;

                let data_len = parse_usize(bytes_str)?;
                if data_len > options.max_value_len {
                    return Err(ParseError::Protocol("value too large"));
                }

                // Check for noreply
                let noreply = parts
                    .next()
                    .map(|s| s == b"noreply" || s == b"NOREPLY")
                    .unwrap_or(false);

                // Data block follows the command line: <data>\r\n
                let data_start = line_end + 2;
                let data_end = data_start
                    .checked_add(data_len)
                    .ok_or(ParseError::InvalidNumber)?;
                let total_len = data_end.checked_add(2).ok_or(ParseError::InvalidNumber)?;

                if buffer.len() < total_len {
                    return Err(ParseError::Incomplete);
                }

                // Verify trailing \r\n
                if buffer[data_end] != b'\r' || buffer[data_end + 1] != b'\n' {
                    return Err(ParseError::Protocol("missing data terminator"));
                }

                let data = &buffer[data_start..data_end];
                Ok((Command::Append { key, data, noreply }, total_len))
            }

            b"prepend" | b"PREPEND" => {
                let key = parts
                    .next()
                    .ok_or(ParseError::Protocol("prepend requires key"))?;
                if key.is_empty() {
                    return Err(ParseError::Protocol("empty key"));
                }
                if key.len() > options.max_key_len {
                    return Err(ParseError::Protocol("key too large"));
                }
                // flags and exptime are required by protocol but ignored for prepend
                let _flags_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("prepend requires flags"))?;
                let _exptime_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("prepend requires exptime"))?;
                let bytes_str = parts
                    .next()
                    .ok_or(ParseError::Protocol("prepend requires bytes"))?;

                let data_len = parse_usize(bytes_str)?;
                if data_len > options.max_value_len {
                    return Err(ParseError::Protocol("value too large"));
                }

                // Check for noreply
                let noreply = parts
                    .next()
                    .map(|s| s == b"noreply" || s == b"NOREPLY")
                    .unwrap_or(false);

                // Data block follows the command line: <data>\r\n
                let data_start = line_end + 2;
                let data_end = data_start
                    .checked_add(data_len)
                    .ok_or(ParseError::InvalidNumber)?;
                let total_len = data_end.checked_add(2).ok_or(ParseError::InvalidNumber)?;

                if buffer.len() < total_len {
                    return Err(ParseError::Incomplete);
                }

                // Verify trailing \r\n
                if buffer[data_end] != b'\r' || buffer[data_end + 1] != b'\n' {
                    return Err(ParseError::Protocol("missing data terminator"));
                }

                let data = &buffer[data_start..data_end];
                Ok((Command::Prepend { key, data, noreply }, total_len))
            }

            _ => Err(ParseError::UnknownCommand),
        }
    }

    /// Returns the command name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Get { .. } => "GET",
            Command::Gets { .. } => "GETS",
            Command::Set { .. } => "SET",
            Command::Add { .. } => "ADD",
            Command::Replace { .. } => "REPLACE",
            Command::Cas { .. } => "CAS",
            Command::Delete { .. } => "DELETE",
            Command::FlushAll => "FLUSH_ALL",
            Command::Version => "VERSION",
            Command::Quit => "QUIT",
            Command::Incr { .. } => "INCR",
            Command::Decr { .. } => "DECR",
            Command::Append { .. } => "APPEND",
            Command::Prepend { .. } => "PREPEND",
        }
    }

    /// Returns true if this command should close the connection.
    pub fn is_quit(&self) -> bool {
        matches!(self, Command::Quit)
    }
}

/// Find \r\n in buffer, return position of \r.
///
/// Returns:
/// - `Ok(Some(pos))` if CRLF found at position `pos`
/// - `Ok(None)` if no CRLF found yet (need more data)
/// - `Err(ParseError::Protocol)` if buffer exceeds max_line_len without CRLF
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

/// Parse a u64 from ASCII decimal.
fn parse_u64(data: &[u8]) -> Result<u64, ParseError> {
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
    fn test_parse_get() {
        let data = b"get mykey\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Get { key: b"mykey" });
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_gets() {
        let data = b"get key1 key2 key3\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        match cmd {
            Command::Gets { keys } => {
                assert_eq!(keys.len(), 3);
                assert_eq!(keys[0], b"key1");
                assert_eq!(keys[1], b"key2");
                assert_eq!(keys[2], b"key3");
            }
            _ => panic!("expected Gets"),
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_set() {
        let data = b"set mykey 0 3600 7\r\nmyvalue\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        match cmd {
            Command::Set {
                key,
                flags,
                exptime,
                data: value,
            } => {
                assert_eq!(key, b"mykey");
                assert_eq!(flags, 0);
                assert_eq!(exptime, 3600);
                assert_eq!(value, b"myvalue");
            }
            _ => panic!("expected Set"),
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_delete() {
        let data = b"delete mykey\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Delete { key: b"mykey" });
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_flush_all() {
        let data = b"flush_all\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::FlushAll);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_version() {
        let data = b"version\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Version);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_quit() {
        let data = b"quit\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Quit);
        assert!(cmd.is_quit());
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_case_insensitive() {
        let (cmd, _) = Command::parse(b"GET mykey\r\n").unwrap();
        assert_eq!(cmd, Command::Get { key: b"mykey" });

        let (cmd, _) = Command::parse(b"SET k 0 0 1\r\nv\r\n").unwrap();
        assert!(matches!(cmd, Command::Set { .. }));
    }

    #[test]
    fn test_parse_incomplete() {
        assert!(matches!(
            Command::parse(b"set mykey 0 0 7\r\nmyval"),
            Err(ParseError::Incomplete)
        ));
        assert!(matches!(
            Command::parse(b"get mykey"),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_parse_unknown() {
        assert!(matches!(
            Command::parse(b"unknown\r\n"),
            Err(ParseError::UnknownCommand)
        ));
    }

    #[test]
    fn test_command_name() {
        assert_eq!(Command::Get { key: b"k" }.name(), "GET");
        assert_eq!(
            Command::Set {
                key: b"k",
                flags: 0,
                exptime: 0,
                data: b"v"
            }
            .name(),
            "SET"
        );
        assert_eq!(Command::FlushAll.name(), "FLUSH_ALL");
    }

    // Additional tests for improved coverage

    #[test]
    fn test_command_name_all() {
        assert_eq!(Command::Gets { keys: vec![b"k"] }.name(), "GETS");
        assert_eq!(Command::Delete { key: b"k" }.name(), "DELETE");
        assert_eq!(Command::Version.name(), "VERSION");
        assert_eq!(Command::Quit.name(), "QUIT");
    }

    #[test]
    fn test_parse_get_no_key() {
        assert!(matches!(
            Command::parse(b"get\r\n"),
            Err(ParseError::Protocol("get requires key"))
        ));
    }

    #[test]
    fn test_parse_get_empty_key() {
        // "get  \r\n" has empty parts which are filtered out
        assert!(matches!(
            Command::parse(b"get  \r\n"),
            Err(ParseError::Protocol("get requires key"))
        ));
    }

    #[test]
    fn test_parse_set_missing_key() {
        assert!(matches!(
            Command::parse(b"set\r\n"),
            Err(ParseError::Protocol("set requires key"))
        ));
    }

    #[test]
    fn test_parse_set_missing_flags() {
        assert!(matches!(
            Command::parse(b"set mykey\r\n"),
            Err(ParseError::Protocol("set requires flags"))
        ));
    }

    #[test]
    fn test_parse_set_missing_exptime() {
        assert!(matches!(
            Command::parse(b"set mykey 0\r\n"),
            Err(ParseError::Protocol("set requires exptime"))
        ));
    }

    #[test]
    fn test_parse_set_missing_bytes() {
        assert!(matches!(
            Command::parse(b"set mykey 0 0\r\n"),
            Err(ParseError::Protocol("set requires bytes"))
        ));
    }

    #[test]
    fn test_parse_set_invalid_flags() {
        assert!(matches!(
            Command::parse(b"set mykey abc 0 5\r\nhello\r\n"),
            Err(ParseError::InvalidNumber)
        ));
    }

    #[test]
    fn test_parse_set_invalid_exptime() {
        assert!(matches!(
            Command::parse(b"set mykey 0 xyz 5\r\nhello\r\n"),
            Err(ParseError::InvalidNumber)
        ));
    }

    #[test]
    fn test_parse_set_invalid_bytes() {
        assert!(matches!(
            Command::parse(b"set mykey 0 0 abc\r\nhello\r\n"),
            Err(ParseError::InvalidNumber)
        ));
    }

    #[test]
    fn test_parse_set_missing_terminator() {
        // Data is correct length but doesn't have \r\n after
        assert!(matches!(
            Command::parse(b"set mykey 0 0 5\r\nhelloXX"),
            Err(ParseError::Protocol("missing data terminator"))
        ));
    }

    #[test]
    fn test_parse_delete_missing_key() {
        assert!(matches!(
            Command::parse(b"delete\r\n"),
            Err(ParseError::Protocol("delete requires key"))
        ));
    }

    #[test]
    fn test_parse_delete_empty_key() {
        // The code checks if key.is_empty() - we need to trigger this
        // Actually looking at the code, after parts.next() we check if empty
        // Need to have a space followed by empty
        assert!(matches!(
            Command::parse(b"delete \r\n"),
            Err(ParseError::Protocol("empty key"))
        ));
    }

    #[test]
    fn test_parse_case_insensitive_delete() {
        let (cmd, _) = Command::parse(b"DELETE mykey\r\n").unwrap();
        assert_eq!(cmd, Command::Delete { key: b"mykey" });
    }

    #[test]
    fn test_parse_case_insensitive_flush_all() {
        let (cmd, _) = Command::parse(b"FLUSH_ALL\r\n").unwrap();
        assert_eq!(cmd, Command::FlushAll);
    }

    #[test]
    fn test_parse_case_insensitive_version() {
        let (cmd, _) = Command::parse(b"VERSION\r\n").unwrap();
        assert_eq!(cmd, Command::Version);
    }

    #[test]
    fn test_parse_case_insensitive_quit() {
        let (cmd, _) = Command::parse(b"QUIT\r\n").unwrap();
        assert_eq!(cmd, Command::Quit);
    }

    #[test]
    fn test_is_quit_false() {
        assert!(!Command::Get { key: b"k" }.is_quit());
        assert!(
            !Command::Set {
                key: b"k",
                flags: 0,
                exptime: 0,
                data: b"v"
            }
            .is_quit()
        );
        assert!(!Command::Delete { key: b"k" }.is_quit());
        assert!(!Command::FlushAll.is_quit());
        assert!(!Command::Version.is_quit());
    }

    #[test]
    fn test_command_debug() {
        let cmd = Command::Get { key: b"test" };
        let debug_str = format!("{:?}", cmd);
        assert!(debug_str.contains("Get"));
    }

    #[test]
    fn test_command_clone() {
        let cmd1 = Command::Get { key: b"test" };
        let cmd2 = cmd1.clone();
        assert_eq!(cmd1, cmd2);
    }

    #[test]
    fn test_command_eq() {
        assert_eq!(Command::FlushAll, Command::FlushAll);
        assert_ne!(Command::FlushAll, Command::Version);
        assert_eq!(Command::Get { key: b"k" }, Command::Get { key: b"k" });
        assert_ne!(Command::Get { key: b"k1" }, Command::Get { key: b"k2" });
    }

    #[test]
    fn test_parse_set_data_with_zeros() {
        // Test that binary data with null bytes works
        let data = b"set mykey 0 0 5\r\n\x00\x01\x02\x03\x04\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        match cmd {
            Command::Set { data: value, .. } => {
                assert_eq!(value, b"\x00\x01\x02\x03\x04");
            }
            _ => panic!("expected Set"),
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_find_crlf_edge_case() {
        // \r at end without \n
        assert!(matches!(
            Command::parse(b"get mykey\r"),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_parse_set_overflow_bytes() {
        // A value larger than MAX_VALUE_LEN is rejected with "value too large"
        // This catches the DoS before we even try arithmetic that could overflow
        assert!(matches!(
            Command::parse(b"SET k 0 0 18446744073709551615\r\n"),
            Err(ParseError::Protocol("value too large"))
        ));

        // Test that truly invalid numbers (not parseable as usize) still error
        assert!(matches!(
            Command::parse(b"set k 0 0 abc\r\nhello\r\n"),
            Err(ParseError::InvalidNumber)
        ));
    }

    #[test]
    fn test_parse_set_empty_key() {
        // SET with empty key (double space after SET)
        assert!(matches!(
            Command::parse(b"SET  0 0 5\r\nhello\r\n"),
            Err(ParseError::Protocol("empty key"))
        ));
    }

    #[test]
    fn test_parse_line_too_long() {
        // Calculate the default max line length
        let max_line_len = ParseOptions::default().max_line_len();

        // Create a buffer that exceeds max_line_len without CRLF
        let mut data = vec![b'g', b'e', b't', b' '];
        data.extend(std::iter::repeat_n(b'a', max_line_len + 1));
        // No CRLF - should error, not return Incomplete
        assert!(matches!(
            Command::parse(&data),
            Err(ParseError::Protocol("line too long"))
        ));
    }

    #[test]
    fn test_parse_key_too_large() {
        // Key exceeds DEFAULT_MAX_KEY_LEN
        let mut data = b"set ".to_vec();
        data.extend(std::iter::repeat_n(b'a', DEFAULT_MAX_KEY_LEN + 1));
        data.extend(b" 0 0 5\r\nhello\r\n");
        assert!(matches!(
            Command::parse(&data),
            Err(ParseError::Protocol("key too large"))
        ));
    }

    #[test]
    fn test_parse_value_too_large() {
        // Value size exceeds DEFAULT_MAX_VALUE_LEN
        let cmd = format!("set k 0 0 {}\r\n", DEFAULT_MAX_VALUE_LEN + 1);
        let mut data = cmd.as_bytes().to_vec();
        // Don't actually append the value data, just the header
        data.extend(std::iter::repeat_n(b'x', DEFAULT_MAX_VALUE_LEN + 1));
        data.extend(b"\r\n");
        assert!(matches!(
            Command::parse(&data),
            Err(ParseError::Protocol("value too large"))
        ));
    }

    // ========================================================================
    // DoS Protection Edge Case Tests
    // ========================================================================

    #[test]
    fn test_line_length_at_exact_limit() {
        let max_line_len = ParseOptions::default().max_line_len();
        // Line exactly at max_line_len should return Incomplete (need more data)
        let mut data = b"get ".to_vec();
        // Fill to exactly max_line_len bytes (no CRLF)
        let remaining = max_line_len - data.len();
        data.extend(std::iter::repeat_n(b'a', remaining));
        assert_eq!(data.len(), max_line_len);
        assert!(matches!(Command::parse(&data), Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_line_length_one_over_limit() {
        let max_line_len = ParseOptions::default().max_line_len();
        // Line at max_line_len + 1 should error (not Incomplete)
        let mut data = b"get ".to_vec();
        let remaining = max_line_len + 1 - data.len();
        data.extend(std::iter::repeat_n(b'a', remaining));
        assert_eq!(data.len(), max_line_len + 1);
        assert!(matches!(
            Command::parse(&data),
            Err(ParseError::Protocol("line too long"))
        ));
    }

    #[test]
    fn test_long_line_with_crlf_within_limit() {
        // A line close to the limit but with CRLF should parse
        // With default max_keys=256 and max_key_len=250, we have plenty of room
        let mut data = b"get ".to_vec();
        // Add enough keys to approach but not exceed limit
        for i in 0..10 {
            data.extend(format!("key{} ", i).as_bytes());
        }
        data.extend(b"\r\n");
        let result = Command::parse(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_length_at_exact_limit() {
        // Key exactly at DEFAULT_MAX_KEY_LEN should succeed
        let mut data = b"set ".to_vec();
        data.extend(std::iter::repeat_n(b'k', DEFAULT_MAX_KEY_LEN));
        data.extend(b" 0 0 1\r\nv\r\n");
        let result = Command::parse(&data);
        assert!(result.is_ok());
        if let Ok((Command::Set { key, .. }, _)) = result {
            assert_eq!(key.len(), DEFAULT_MAX_KEY_LEN);
        }
    }

    #[test]
    fn test_key_length_one_over_limit() {
        // Key at DEFAULT_MAX_KEY_LEN + 1 should fail
        let mut data = b"set ".to_vec();
        data.extend(std::iter::repeat_n(b'k', DEFAULT_MAX_KEY_LEN + 1));
        data.extend(b" 0 0 1\r\nv\r\n");
        assert!(matches!(
            Command::parse(&data),
            Err(ParseError::Protocol("key too large"))
        ));
    }

    #[test]
    fn test_value_length_at_exact_limit() {
        // Value exactly at DEFAULT_MAX_VALUE_LEN should succeed
        let cmd = format!("set k 0 0 {}\r\n", DEFAULT_MAX_VALUE_LEN);
        let mut data = cmd.as_bytes().to_vec();
        data.extend(std::iter::repeat_n(b'v', DEFAULT_MAX_VALUE_LEN));
        data.extend(b"\r\n");
        let result = Command::parse(&data);
        assert!(result.is_ok());
        if let Ok((Command::Set { data: value, .. }, _)) = result {
            assert_eq!(value.len(), DEFAULT_MAX_VALUE_LEN);
        }
    }

    #[test]
    fn test_value_length_one_over_limit() {
        // Value at DEFAULT_MAX_VALUE_LEN + 1 should fail
        let cmd = format!("set k 0 0 {}\r\n", DEFAULT_MAX_VALUE_LEN + 1);
        let mut data = cmd.as_bytes().to_vec();
        data.extend(std::iter::repeat_n(b'v', DEFAULT_MAX_VALUE_LEN + 1));
        data.extend(b"\r\n");
        assert!(matches!(
            Command::parse(&data),
            Err(ParseError::Protocol("value too large"))
        ));
    }

    #[test]
    fn test_multiget_many_keys() {
        // Multi-GET with many keys should work up to line limit
        let mut data = b"get".to_vec();
        for i in 0..100 {
            data.extend(format!(" key{}", i).as_bytes());
        }
        data.extend(b"\r\n");

        let result = Command::parse(&data);
        assert!(result.is_ok());
        if let Ok((Command::Gets { keys }, _)) = result {
            assert_eq!(keys.len(), 100);
        }
    }

    #[test]
    fn test_arithmetic_overflow_protection() {
        // Ensure checked arithmetic prevents overflow
        // data_start + data_len + 2 could overflow without checked_add
        // We already reject huge data_len via DEFAULT_MAX_VALUE_LEN, but test the check

        // A value size that would overflow usize when added to data_start
        // This is caught by the "value too large" check first
        let cmd = format!("set k 0 0 {}\r\n", usize::MAX);
        let data = cmd.as_bytes();
        let result = Command::parse(data);
        // Should fail with "value too large" (early check) or InvalidNumber
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_buffer() {
        assert!(matches!(Command::parse(b""), Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_only_whitespace_no_crlf() {
        let data = b"   ";
        assert!(matches!(Command::parse(data), Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_cr_without_lf() {
        let data = b"get key\r";
        assert!(matches!(Command::parse(data), Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_cr_without_lf_exceeds_limit() {
        let max_line_len = ParseOptions::default().max_line_len();
        // \r found but no \n, and buffer exceeds limit
        let mut data = b"get ".to_vec();
        data.extend(std::iter::repeat_n(b'a', max_line_len));
        data.push(b'\r');
        assert!(matches!(
            Command::parse(&data),
            Err(ParseError::Protocol("line too long"))
        ));
    }

    #[test]
    fn test_get_with_key_at_limit() {
        // GET doesn't check key length, but make sure it parses
        let mut data = b"get ".to_vec();
        data.extend(std::iter::repeat_n(b'k', DEFAULT_MAX_KEY_LEN));
        data.extend(b"\r\n");
        let result = Command::parse(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_with_key_not_checked() {
        // DELETE doesn't currently check key length in the same way SET does
        // It only checks for empty key
        let mut data = b"delete ".to_vec();
        data.extend(std::iter::repeat_n(b'k', DEFAULT_MAX_KEY_LEN + 100));
        data.extend(b"\r\n");
        // DELETE doesn't have key length validation like SET does
        // This test documents current behavior - may want to add validation
        let result = Command::parse(&data);
        assert!(result.is_ok()); // Currently passes - could be a gap to fix
    }

    #[test]
    fn test_too_many_keys() {
        // Multi-GET with too many keys should fail
        let mut data = b"get".to_vec();
        for i in 0..DEFAULT_MAX_KEYS + 1 {
            data.extend(format!(" k{}", i).as_bytes());
        }
        data.extend(b"\r\n");
        assert!(matches!(
            Command::parse(&data),
            Err(ParseError::Protocol("too many keys"))
        ));
    }

    #[test]
    fn test_custom_options() {
        // Test that custom options work correctly
        let options = ParseOptions::new()
            .max_key_len(10)
            .max_value_len(100)
            .max_keys(5);

        // Key at custom limit should work
        let mut data = b"set kkkkkkkkkk 0 0 1\r\nv\r\n".to_vec();
        let result = Command::parse_with_options(&data, &options);
        assert!(result.is_ok());

        // Key over custom limit should fail
        data = b"set kkkkkkkkkkk 0 0 1\r\nv\r\n".to_vec(); // 11 chars
        let result = Command::parse_with_options(&data, &options);
        assert!(matches!(result, Err(ParseError::Protocol("key too large"))));

        // Value over custom limit should fail
        let cmd = b"set k 0 0 101\r\n";
        let mut value_data = cmd.to_vec();
        value_data.extend(std::iter::repeat_n(b'v', 101));
        value_data.extend(b"\r\n");
        let result = Command::parse_with_options(&value_data, &options);
        assert!(matches!(
            result,
            Err(ParseError::Protocol("value too large"))
        ));

        // Too many keys with custom limit should fail
        let data = b"get k1 k2 k3 k4 k5 k6\r\n";
        let result = Command::parse_with_options(data, &options);
        assert!(matches!(result, Err(ParseError::Protocol("too many keys"))));
    }

    // ========================================================================
    // INCR/DECR Tests
    // ========================================================================

    #[test]
    fn test_parse_incr() {
        let data = b"incr counter 5\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        match cmd {
            Command::Incr {
                key,
                delta,
                noreply,
            } => {
                assert_eq!(key, b"counter");
                assert_eq!(delta, 5);
                assert!(!noreply);
            }
            _ => panic!("expected Incr"),
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_incr_noreply() {
        let data = b"incr counter 10 noreply\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        match cmd {
            Command::Incr {
                key,
                delta,
                noreply,
            } => {
                assert_eq!(key, b"counter");
                assert_eq!(delta, 10);
                assert!(noreply);
            }
            _ => panic!("expected Incr"),
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_incr_case_insensitive() {
        let (cmd, _) = Command::parse(b"INCR key 1\r\n").unwrap();
        assert!(matches!(cmd, Command::Incr { .. }));
    }

    #[test]
    fn test_parse_incr_noreply_case_insensitive() {
        let (cmd, _) = Command::parse(b"incr key 1 NOREPLY\r\n").unwrap();
        match cmd {
            Command::Incr { noreply, .. } => assert!(noreply),
            _ => panic!("expected Incr"),
        }
    }

    #[test]
    fn test_parse_incr_missing_key() {
        assert!(matches!(
            Command::parse(b"incr\r\n"),
            Err(ParseError::Protocol("incr requires key"))
        ));
    }

    #[test]
    fn test_parse_incr_empty_key() {
        assert!(matches!(
            Command::parse(b"incr  5\r\n"),
            Err(ParseError::Protocol("empty key"))
        ));
    }

    #[test]
    fn test_parse_incr_missing_delta() {
        assert!(matches!(
            Command::parse(b"incr key\r\n"),
            Err(ParseError::Protocol("incr requires delta"))
        ));
    }

    #[test]
    fn test_parse_incr_invalid_delta() {
        assert!(matches!(
            Command::parse(b"incr key abc\r\n"),
            Err(ParseError::InvalidNumber)
        ));
    }

    #[test]
    fn test_parse_incr_key_too_large() {
        let mut data = b"incr ".to_vec();
        data.extend(std::iter::repeat_n(b'k', DEFAULT_MAX_KEY_LEN + 1));
        data.extend(b" 5\r\n");
        assert!(matches!(
            Command::parse(&data),
            Err(ParseError::Protocol("key too large"))
        ));
    }

    #[test]
    fn test_parse_decr() {
        let data = b"decr counter 3\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        match cmd {
            Command::Decr {
                key,
                delta,
                noreply,
            } => {
                assert_eq!(key, b"counter");
                assert_eq!(delta, 3);
                assert!(!noreply);
            }
            _ => panic!("expected Decr"),
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_decr_noreply() {
        let data = b"decr counter 10 noreply\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        match cmd {
            Command::Decr {
                key,
                delta,
                noreply,
            } => {
                assert_eq!(key, b"counter");
                assert_eq!(delta, 10);
                assert!(noreply);
            }
            _ => panic!("expected Decr"),
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_decr_case_insensitive() {
        let (cmd, _) = Command::parse(b"DECR key 1\r\n").unwrap();
        assert!(matches!(cmd, Command::Decr { .. }));
    }

    #[test]
    fn test_parse_decr_missing_key() {
        assert!(matches!(
            Command::parse(b"decr\r\n"),
            Err(ParseError::Protocol("decr requires key"))
        ));
    }

    #[test]
    fn test_parse_decr_missing_delta() {
        assert!(matches!(
            Command::parse(b"decr key\r\n"),
            Err(ParseError::Protocol("decr requires delta"))
        ));
    }

    #[test]
    fn test_parse_decr_invalid_delta() {
        assert!(matches!(
            Command::parse(b"decr key xyz\r\n"),
            Err(ParseError::InvalidNumber)
        ));
    }

    #[test]
    fn test_incr_decr_command_names() {
        assert_eq!(
            Command::Incr {
                key: b"k",
                delta: 1,
                noreply: false
            }
            .name(),
            "INCR"
        );
        assert_eq!(
            Command::Decr {
                key: b"k",
                delta: 1,
                noreply: false
            }
            .name(),
            "DECR"
        );
    }

    #[test]
    fn test_incr_decr_is_quit() {
        assert!(
            !Command::Incr {
                key: b"k",
                delta: 1,
                noreply: false
            }
            .is_quit()
        );
        assert!(
            !Command::Decr {
                key: b"k",
                delta: 1,
                noreply: false
            }
            .is_quit()
        );
    }

    #[test]
    fn test_incr_large_delta() {
        let data = b"incr key 18446744073709551615\r\n"; // u64::MAX
        let (cmd, _) = Command::parse(data).unwrap();
        match cmd {
            Command::Incr { delta, .. } => {
                assert_eq!(delta, u64::MAX);
            }
            _ => panic!("expected Incr"),
        }
    }
}
