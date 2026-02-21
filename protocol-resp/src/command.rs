//! Server-side command parsing.
//!
//! This module parses RESP protocol data into structured commands for server implementations.
//! It provides zero-copy parsing where possible, with command arguments referencing the input buffer.

use crate::error::ParseError;
use crate::value::ParseOptions;

/// A parsed Redis command with references to the original buffer.
///
/// Commands are parsed with zero-copy semantics - the key and value fields
/// reference slices of the original input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command<'a> {
    /// PING command
    Ping,
    /// GET key
    Get { key: &'a [u8] },
    /// SET key value [EX seconds] [PX milliseconds] [NX|XX]
    Set {
        key: &'a [u8],
        value: &'a [u8],
        ex: Option<u64>,
        px: Option<u64>,
        nx: bool,
        xx: bool,
    },
    /// DEL key
    Del { key: &'a [u8] },
    /// MGET key [key ...]
    MGet { keys: Vec<&'a [u8]> },
    /// CONFIG subcommand [args...]
    Config {
        subcommand: &'a [u8],
        args: Vec<&'a [u8]>,
    },
    /// CLUSTER subcommand [args...]
    Cluster {
        subcommand: &'a [u8],
        args: Vec<&'a [u8]>,
    },
    /// ASKING — used before retrying a command after an ASK redirect
    Asking,
    /// READONLY — enable read queries on a replica node
    ReadOnly,
    /// READWRITE — disable READONLY mode
    ReadWrite,
    /// FLUSHDB
    FlushDb,
    /// FLUSHALL
    FlushAll,
    /// INCR key - Increment the integer value of a key by one
    Incr { key: &'a [u8] },
    /// DECR key - Decrement the integer value of a key by one
    Decr { key: &'a [u8] },
    /// INCRBY key delta - Increment the integer value of a key by delta
    IncrBy { key: &'a [u8], delta: i64 },
    /// DECRBY key delta - Decrement the integer value of a key by delta
    DecrBy { key: &'a [u8], delta: i64 },
    /// APPEND key value - Append a value to a key
    Append { key: &'a [u8], value: &'a [u8] },
    /// HELLO [protover [AUTH username password] [SETNAME clientname]]
    /// Used for RESP3 protocol negotiation.
    #[cfg(feature = "resp3")]
    Hello {
        /// Protocol version (2 or 3)
        proto_version: Option<u8>,
        /// AUTH username and password
        auth: Option<(&'a [u8], &'a [u8])>,
        /// Client name
        client_name: Option<&'a [u8]>,
    },

    // ========================================================================
    // Hash Commands
    // ========================================================================
    /// HSET key field value [field value ...] - Set field(s) in a hash
    HSet {
        key: &'a [u8],
        fields: Vec<(&'a [u8], &'a [u8])>,
    },
    /// HGET key field - Get a field from a hash
    HGet { key: &'a [u8], field: &'a [u8] },
    /// HMGET key field [field ...] - Get multiple fields from a hash
    HMGet {
        key: &'a [u8],
        fields: Vec<&'a [u8]>,
    },
    /// HGETALL key - Get all fields and values from a hash
    HGetAll { key: &'a [u8] },
    /// HDEL key field [field ...] - Delete field(s) from a hash
    HDel {
        key: &'a [u8],
        fields: Vec<&'a [u8]>,
    },
    /// HEXISTS key field - Check if field exists in a hash
    HExists { key: &'a [u8], field: &'a [u8] },
    /// HLEN key - Get the number of fields in a hash
    HLen { key: &'a [u8] },
    /// HKEYS key - Get all field names in a hash
    HKeys { key: &'a [u8] },
    /// HVALS key - Get all values in a hash
    HVals { key: &'a [u8] },
    /// HSETNX key field value - Set field only if it doesn't exist
    HSetNx {
        key: &'a [u8],
        field: &'a [u8],
        value: &'a [u8],
    },
    /// HINCRBY key field increment - Increment hash field by integer
    HIncrBy {
        key: &'a [u8],
        field: &'a [u8],
        delta: i64,
    },

    // ========================================================================
    // List Commands
    // ========================================================================
    /// LPUSH key element [element ...] - Push to left of list
    LPush {
        key: &'a [u8],
        values: Vec<&'a [u8]>,
    },
    /// RPUSH key element [element ...] - Push to right of list
    RPush {
        key: &'a [u8],
        values: Vec<&'a [u8]>,
    },
    /// LPOP key `[count]` - Pop from left of list
    LPop { key: &'a [u8], count: Option<usize> },
    /// RPOP key `[count]` - Pop from right of list
    RPop { key: &'a [u8], count: Option<usize> },
    /// LRANGE key start stop - Get range of elements
    LRange {
        key: &'a [u8],
        start: i64,
        stop: i64,
    },
    /// LLEN key - Get list length
    LLen { key: &'a [u8] },
    /// LINDEX key index - Get element by index
    LIndex { key: &'a [u8], index: i64 },
    /// LSET key index element - Set element by index
    LSet {
        key: &'a [u8],
        index: i64,
        value: &'a [u8],
    },
    /// LTRIM key start stop - Trim list to range
    LTrim {
        key: &'a [u8],
        start: i64,
        stop: i64,
    },
    /// LPUSHX key element [element ...] - Push to left only if list exists
    LPushX {
        key: &'a [u8],
        values: Vec<&'a [u8]>,
    },
    /// RPUSHX key element [element ...] - Push to right only if list exists
    RPushX {
        key: &'a [u8],
        values: Vec<&'a [u8]>,
    },

    // ========================================================================
    // Set Commands
    // ========================================================================
    /// SADD key member [member ...] - Add members to set
    SAdd {
        key: &'a [u8],
        members: Vec<&'a [u8]>,
    },
    /// SREM key member [member ...] - Remove members from set
    SRem {
        key: &'a [u8],
        members: Vec<&'a [u8]>,
    },
    /// SMEMBERS key - Get all members of set
    SMembers { key: &'a [u8] },
    /// SISMEMBER key member - Check if member exists in set
    SIsMember { key: &'a [u8], member: &'a [u8] },
    /// SMISMEMBER key member [member ...] - Check multiple members
    SMisMember {
        key: &'a [u8],
        members: Vec<&'a [u8]>,
    },
    /// SCARD key - Get set cardinality
    SCard { key: &'a [u8] },
    /// SPOP key `[count]` - Remove and return random member(s)
    SPop { key: &'a [u8], count: Option<usize> },
    /// SRANDMEMBER key `[count]` - Get random member(s) without removal
    SRandMember { key: &'a [u8], count: Option<i64> },

    // ========================================================================
    // Type Command
    // ========================================================================
    /// TYPE key - Get the type of key
    Type { key: &'a [u8] },
}

impl<'a> Command<'a> {
    /// Parse a command from a byte buffer using default limits.
    ///
    /// Returns the parsed command and the number of bytes consumed.
    ///
    /// # Zero-copy
    ///
    /// The returned command contains references to the input buffer, so the buffer
    /// must outlive the command. This avoids allocation for keys and values.
    ///
    /// # Errors
    ///
    /// Returns `ParseError::Incomplete` if more data is needed.
    /// Returns other errors for malformed or unknown commands.
    #[inline]
    pub fn parse(buffer: &'a [u8]) -> Result<(Self, usize), ParseError> {
        Self::parse_with_options(buffer, &ParseOptions::default())
    }

    /// Parse a command from a byte buffer with custom options.
    ///
    /// This is useful for setting custom limits on bulk string size to prevent
    /// denial-of-service attacks or to enforce server-side value size limits.
    ///
    /// # Zero-copy
    ///
    /// The returned command contains references to the input buffer, so the buffer
    /// must outlive the command. This avoids allocation for keys and values.
    ///
    /// # Errors
    ///
    /// Returns `ParseError::Incomplete` if more data is needed.
    /// Returns `ParseError::BulkStringTooLong` if a bulk string exceeds the limit.
    /// Returns other errors for malformed or unknown commands.
    #[inline]
    pub fn parse_with_options(
        buffer: &'a [u8],
        options: &ParseOptions,
    ) -> Result<(Self, usize), ParseError> {
        let mut cursor = Cursor::new(buffer, options.max_bulk_string_len);

        // Read array header
        if cursor.remaining() < 1 {
            return Err(ParseError::Incomplete);
        }
        if cursor.get_u8() != b'*' {
            return Err(ParseError::Protocol("expected array".to_string()));
        }

        // Read array length
        let count = cursor.read_integer()?;
        if count < 1 {
            return Err(ParseError::Protocol(
                "array must have at least 1 element".to_string(),
            ));
        }
        // Reject unreasonably large arrays to prevent OOM attacks
        const MAX_ARRAY_LEN: usize = 1024 * 1024; // 1M elements max
        if count > MAX_ARRAY_LEN {
            return Err(ParseError::Protocol("array too large".to_string()));
        }

        // Read command name
        let cmd_name = cursor.read_bulk_string()?;
        let cmd_str = std::str::from_utf8(cmd_name)
            .map_err(|_| ParseError::Protocol("invalid UTF-8 in command".to_string()))?;

        // Parse command based on name (case-insensitive)
        let command = match () {
            _ if cmd_str.eq_ignore_ascii_case("ping") => {
                if count != 1 {
                    return Err(ParseError::WrongArity(
                        "PING takes no arguments".to_string(),
                    ));
                }
                Command::Ping
            }

            _ if cmd_str.eq_ignore_ascii_case("get") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "GET requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::Get { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("set") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "SET requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let value = cursor.read_bulk_string()?;

                let mut ex = None;
                let mut px = None;
                let mut nx = false;
                let mut xx = false;

                let mut remaining_args = count - 3;
                while remaining_args > 0 {
                    let option = cursor.read_bulk_string()?;
                    let option_str = std::str::from_utf8(option)
                        .map_err(|_| ParseError::Protocol("invalid UTF-8 in option".to_string()))?;

                    if option_str.eq_ignore_ascii_case("ex") {
                        if remaining_args < 2 {
                            return Err(ParseError::Protocol("EX requires a value".to_string()));
                        }
                        let ttl_bytes = cursor.read_bulk_string()?;
                        let ttl_str = std::str::from_utf8(ttl_bytes).map_err(|_| {
                            ParseError::Protocol("invalid UTF-8 in TTL".to_string())
                        })?;
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
                        let ttl_str = std::str::from_utf8(ttl_bytes).map_err(|_| {
                            ParseError::Protocol("invalid UTF-8 in TTL".to_string())
                        })?;
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

                Command::Set {
                    key,
                    value,
                    ex,
                    px,
                    nx,
                    xx,
                }
            }

            _ if cmd_str.eq_ignore_ascii_case("del") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "DEL requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::Del { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("mget") => {
                if count < 2 {
                    return Err(ParseError::WrongArity(
                        "MGET requires at least 1 argument".to_string(),
                    ));
                }
                let mut keys = Vec::with_capacity(count - 1);
                for _ in 0..(count - 1) {
                    keys.push(cursor.read_bulk_string()?);
                }
                Command::MGet { keys }
            }

            _ if cmd_str.eq_ignore_ascii_case("config") => {
                if count < 2 {
                    return Err(ParseError::WrongArity(
                        "CONFIG requires at least 1 argument".to_string(),
                    ));
                }
                let subcommand = cursor.read_bulk_string()?;
                let mut args = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    args.push(cursor.read_bulk_string()?);
                }
                Command::Config { subcommand, args }
            }

            _ if cmd_str.eq_ignore_ascii_case("cluster") => {
                if count < 2 {
                    return Err(ParseError::WrongArity(
                        "CLUSTER requires at least 1 argument".to_string(),
                    ));
                }
                let subcommand = cursor.read_bulk_string()?;
                let mut args = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    args.push(cursor.read_bulk_string()?);
                }
                Command::Cluster { subcommand, args }
            }

            _ if cmd_str.eq_ignore_ascii_case("asking") => {
                if count != 1 {
                    return Err(ParseError::WrongArity(
                        "ASKING takes no arguments".to_string(),
                    ));
                }
                Command::Asking
            }

            _ if cmd_str.eq_ignore_ascii_case("readonly") => {
                if count != 1 {
                    return Err(ParseError::WrongArity(
                        "READONLY takes no arguments".to_string(),
                    ));
                }
                Command::ReadOnly
            }

            _ if cmd_str.eq_ignore_ascii_case("readwrite") => {
                if count != 1 {
                    return Err(ParseError::WrongArity(
                        "READWRITE takes no arguments".to_string(),
                    ));
                }
                Command::ReadWrite
            }

            _ if cmd_str.eq_ignore_ascii_case("flushdb") => Command::FlushDb,
            _ if cmd_str.eq_ignore_ascii_case("flushall") => Command::FlushAll,

            _ if cmd_str.eq_ignore_ascii_case("incr") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "INCR requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::Incr { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("decr") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "DECR requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::Decr { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("incrby") => {
                if count != 3 {
                    return Err(ParseError::WrongArity(
                        "INCRBY requires exactly 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let delta_bytes = cursor.read_bulk_string()?;
                let delta_str = std::str::from_utf8(delta_bytes)
                    .map_err(|_| ParseError::Protocol("invalid UTF-8 in delta".to_string()))?;
                let delta = delta_str
                    .parse::<i64>()
                    .map_err(|_| ParseError::Protocol("invalid delta value".to_string()))?;
                Command::IncrBy { key, delta }
            }

            _ if cmd_str.eq_ignore_ascii_case("decrby") => {
                if count != 3 {
                    return Err(ParseError::WrongArity(
                        "DECRBY requires exactly 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let delta_bytes = cursor.read_bulk_string()?;
                let delta_str = std::str::from_utf8(delta_bytes)
                    .map_err(|_| ParseError::Protocol("invalid UTF-8 in delta".to_string()))?;
                let delta = delta_str
                    .parse::<i64>()
                    .map_err(|_| ParseError::Protocol("invalid delta value".to_string()))?;
                Command::DecrBy { key, delta }
            }

            _ if cmd_str.eq_ignore_ascii_case("append") => {
                if count != 3 {
                    return Err(ParseError::WrongArity(
                        "APPEND requires exactly 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let value = cursor.read_bulk_string()?;
                Command::Append { key, value }
            }

            // ================================================================
            // Hash Commands
            // ================================================================
            _ if cmd_str.eq_ignore_ascii_case("hset") => {
                if count < 4 || (count - 2) % 2 != 0 {
                    return Err(ParseError::WrongArity(
                        "HSET requires key and field-value pairs".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut fields = Vec::with_capacity((count - 2) / 2);
                for _ in 0..((count - 2) / 2) {
                    let field = cursor.read_bulk_string()?;
                    let value = cursor.read_bulk_string()?;
                    fields.push((field, value));
                }
                Command::HSet { key, fields }
            }

            _ if cmd_str.eq_ignore_ascii_case("hget") => {
                if count != 3 {
                    return Err(ParseError::WrongArity(
                        "HGET requires exactly 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let field = cursor.read_bulk_string()?;
                Command::HGet { key, field }
            }

            _ if cmd_str.eq_ignore_ascii_case("hmget") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "HMGET requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut fields = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    fields.push(cursor.read_bulk_string()?);
                }
                Command::HMGet { key, fields }
            }

            _ if cmd_str.eq_ignore_ascii_case("hgetall") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "HGETALL requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::HGetAll { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("hdel") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "HDEL requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut fields = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    fields.push(cursor.read_bulk_string()?);
                }
                Command::HDel { key, fields }
            }

            _ if cmd_str.eq_ignore_ascii_case("hexists") => {
                if count != 3 {
                    return Err(ParseError::WrongArity(
                        "HEXISTS requires exactly 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let field = cursor.read_bulk_string()?;
                Command::HExists { key, field }
            }

            _ if cmd_str.eq_ignore_ascii_case("hlen") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "HLEN requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::HLen { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("hkeys") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "HKEYS requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::HKeys { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("hvals") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "HVALS requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::HVals { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("hsetnx") => {
                if count != 4 {
                    return Err(ParseError::WrongArity(
                        "HSETNX requires exactly 3 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let field = cursor.read_bulk_string()?;
                let value = cursor.read_bulk_string()?;
                Command::HSetNx { key, field, value }
            }

            _ if cmd_str.eq_ignore_ascii_case("hincrby") => {
                if count != 4 {
                    return Err(ParseError::WrongArity(
                        "HINCRBY requires exactly 3 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let field = cursor.read_bulk_string()?;
                let delta_bytes = cursor.read_bulk_string()?;
                let delta_str = std::str::from_utf8(delta_bytes)
                    .map_err(|_| ParseError::Protocol("invalid UTF-8 in increment".to_string()))?;
                let delta = delta_str
                    .parse::<i64>()
                    .map_err(|_| ParseError::Protocol("invalid increment value".to_string()))?;
                Command::HIncrBy { key, field, delta }
            }

            // ================================================================
            // List Commands
            // ================================================================
            _ if cmd_str.eq_ignore_ascii_case("lpush") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "LPUSH requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut values = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    values.push(cursor.read_bulk_string()?);
                }
                Command::LPush { key, values }
            }

            _ if cmd_str.eq_ignore_ascii_case("rpush") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "RPUSH requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut values = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    values.push(cursor.read_bulk_string()?);
                }
                Command::RPush { key, values }
            }

            _ if cmd_str.eq_ignore_ascii_case("lpop") => {
                if !(2..=3).contains(&count) {
                    return Err(ParseError::WrongArity(
                        "LPOP requires 1 or 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let count_opt = if count == 3 {
                    let count_bytes = cursor.read_bulk_string()?;
                    let count_str = std::str::from_utf8(count_bytes)
                        .map_err(|_| ParseError::Protocol("invalid UTF-8 in count".to_string()))?;
                    Some(
                        count_str
                            .parse::<usize>()
                            .map_err(|_| ParseError::Protocol("invalid count value".to_string()))?,
                    )
                } else {
                    None
                };
                Command::LPop {
                    key,
                    count: count_opt,
                }
            }

            _ if cmd_str.eq_ignore_ascii_case("rpop") => {
                if !(2..=3).contains(&count) {
                    return Err(ParseError::WrongArity(
                        "RPOP requires 1 or 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let count_opt = if count == 3 {
                    let count_bytes = cursor.read_bulk_string()?;
                    let count_str = std::str::from_utf8(count_bytes)
                        .map_err(|_| ParseError::Protocol("invalid UTF-8 in count".to_string()))?;
                    Some(
                        count_str
                            .parse::<usize>()
                            .map_err(|_| ParseError::Protocol("invalid count value".to_string()))?,
                    )
                } else {
                    None
                };
                Command::RPop {
                    key,
                    count: count_opt,
                }
            }

            _ if cmd_str.eq_ignore_ascii_case("lrange") => {
                if count != 4 {
                    return Err(ParseError::WrongArity(
                        "LRANGE requires exactly 3 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let start_bytes = cursor.read_bulk_string()?;
                let stop_bytes = cursor.read_bulk_string()?;
                let start_str = std::str::from_utf8(start_bytes)
                    .map_err(|_| ParseError::Protocol("invalid UTF-8 in start".to_string()))?;
                let stop_str = std::str::from_utf8(stop_bytes)
                    .map_err(|_| ParseError::Protocol("invalid UTF-8 in stop".to_string()))?;
                let start = start_str
                    .parse::<i64>()
                    .map_err(|_| ParseError::Protocol("invalid start value".to_string()))?;
                let stop = stop_str
                    .parse::<i64>()
                    .map_err(|_| ParseError::Protocol("invalid stop value".to_string()))?;
                Command::LRange { key, start, stop }
            }

            _ if cmd_str.eq_ignore_ascii_case("llen") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "LLEN requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::LLen { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("lindex") => {
                if count != 3 {
                    return Err(ParseError::WrongArity(
                        "LINDEX requires exactly 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let index_bytes = cursor.read_bulk_string()?;
                let index_str = std::str::from_utf8(index_bytes)
                    .map_err(|_| ParseError::Protocol("invalid UTF-8 in index".to_string()))?;
                let index = index_str
                    .parse::<i64>()
                    .map_err(|_| ParseError::Protocol("invalid index value".to_string()))?;
                Command::LIndex { key, index }
            }

            _ if cmd_str.eq_ignore_ascii_case("lset") => {
                if count != 4 {
                    return Err(ParseError::WrongArity(
                        "LSET requires exactly 3 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let index_bytes = cursor.read_bulk_string()?;
                let value = cursor.read_bulk_string()?;
                let index_str = std::str::from_utf8(index_bytes)
                    .map_err(|_| ParseError::Protocol("invalid UTF-8 in index".to_string()))?;
                let index = index_str
                    .parse::<i64>()
                    .map_err(|_| ParseError::Protocol("invalid index value".to_string()))?;
                Command::LSet { key, index, value }
            }

            _ if cmd_str.eq_ignore_ascii_case("ltrim") => {
                if count != 4 {
                    return Err(ParseError::WrongArity(
                        "LTRIM requires exactly 3 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let start_bytes = cursor.read_bulk_string()?;
                let stop_bytes = cursor.read_bulk_string()?;
                let start_str = std::str::from_utf8(start_bytes)
                    .map_err(|_| ParseError::Protocol("invalid UTF-8 in start".to_string()))?;
                let stop_str = std::str::from_utf8(stop_bytes)
                    .map_err(|_| ParseError::Protocol("invalid UTF-8 in stop".to_string()))?;
                let start = start_str
                    .parse::<i64>()
                    .map_err(|_| ParseError::Protocol("invalid start value".to_string()))?;
                let stop = stop_str
                    .parse::<i64>()
                    .map_err(|_| ParseError::Protocol("invalid stop value".to_string()))?;
                Command::LTrim { key, start, stop }
            }

            _ if cmd_str.eq_ignore_ascii_case("lpushx") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "LPUSHX requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut values = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    values.push(cursor.read_bulk_string()?);
                }
                Command::LPushX { key, values }
            }

            _ if cmd_str.eq_ignore_ascii_case("rpushx") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "RPUSHX requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut values = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    values.push(cursor.read_bulk_string()?);
                }
                Command::RPushX { key, values }
            }

            // ================================================================
            // Set Commands
            // ================================================================
            _ if cmd_str.eq_ignore_ascii_case("sadd") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "SADD requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut members = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    members.push(cursor.read_bulk_string()?);
                }
                Command::SAdd { key, members }
            }

            _ if cmd_str.eq_ignore_ascii_case("srem") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "SREM requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut members = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    members.push(cursor.read_bulk_string()?);
                }
                Command::SRem { key, members }
            }

            _ if cmd_str.eq_ignore_ascii_case("smembers") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "SMEMBERS requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::SMembers { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("sismember") => {
                if count != 3 {
                    return Err(ParseError::WrongArity(
                        "SISMEMBER requires exactly 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let member = cursor.read_bulk_string()?;
                Command::SIsMember { key, member }
            }

            _ if cmd_str.eq_ignore_ascii_case("smismember") => {
                if count < 3 {
                    return Err(ParseError::WrongArity(
                        "SMISMEMBER requires at least 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let mut members = Vec::with_capacity(count - 2);
                for _ in 0..(count - 2) {
                    members.push(cursor.read_bulk_string()?);
                }
                Command::SMisMember { key, members }
            }

            _ if cmd_str.eq_ignore_ascii_case("scard") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "SCARD requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::SCard { key }
            }

            _ if cmd_str.eq_ignore_ascii_case("spop") => {
                if !(2..=3).contains(&count) {
                    return Err(ParseError::WrongArity(
                        "SPOP requires 1 or 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let count_opt = if count == 3 {
                    let count_bytes = cursor.read_bulk_string()?;
                    let count_str = std::str::from_utf8(count_bytes)
                        .map_err(|_| ParseError::Protocol("invalid UTF-8 in count".to_string()))?;
                    Some(
                        count_str
                            .parse::<usize>()
                            .map_err(|_| ParseError::Protocol("invalid count value".to_string()))?,
                    )
                } else {
                    None
                };
                Command::SPop {
                    key,
                    count: count_opt,
                }
            }

            _ if cmd_str.eq_ignore_ascii_case("srandmember") => {
                if !(2..=3).contains(&count) {
                    return Err(ParseError::WrongArity(
                        "SRANDMEMBER requires 1 or 2 arguments".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                let count_opt = if count == 3 {
                    let count_bytes = cursor.read_bulk_string()?;
                    let count_str = std::str::from_utf8(count_bytes)
                        .map_err(|_| ParseError::Protocol("invalid UTF-8 in count".to_string()))?;
                    Some(
                        count_str
                            .parse::<i64>()
                            .map_err(|_| ParseError::Protocol("invalid count value".to_string()))?,
                    )
                } else {
                    None
                };
                Command::SRandMember {
                    key,
                    count: count_opt,
                }
            }

            // ================================================================
            // Type Command
            // ================================================================
            _ if cmd_str.eq_ignore_ascii_case("type") => {
                if count != 2 {
                    return Err(ParseError::WrongArity(
                        "TYPE requires exactly 1 argument".to_string(),
                    ));
                }
                let key = cursor.read_bulk_string()?;
                Command::Type { key }
            }

            #[cfg(feature = "resp3")]
            _ if cmd_str.eq_ignore_ascii_case("hello") => {
                let mut proto_version = None;
                let mut auth = None;
                let mut client_name = None;

                let mut remaining_args = count - 1;

                // Parse optional protocol version
                if remaining_args > 0 {
                    let version_bytes = cursor.read_bulk_string()?;
                    let version_str = std::str::from_utf8(version_bytes).map_err(|_| {
                        ParseError::Protocol("invalid UTF-8 in version".to_string())
                    })?;
                    let version: u8 = version_str.parse().map_err(|_| {
                        ParseError::Protocol("invalid protocol version".to_string())
                    })?;
                    proto_version = Some(version);
                    remaining_args -= 1;
                }

                // Parse optional AUTH and SETNAME
                while remaining_args > 0 {
                    let option = cursor.read_bulk_string()?;
                    let option_str = std::str::from_utf8(option)
                        .map_err(|_| ParseError::Protocol("invalid UTF-8 in option".to_string()))?;

                    if option_str.eq_ignore_ascii_case("auth") {
                        if remaining_args < 3 {
                            return Err(ParseError::Protocol(
                                "AUTH requires username and password".to_string(),
                            ));
                        }
                        let username = cursor.read_bulk_string()?;
                        let password = cursor.read_bulk_string()?;
                        auth = Some((username, password));
                        remaining_args -= 3;
                    } else if option_str.eq_ignore_ascii_case("setname") {
                        if remaining_args < 2 {
                            return Err(ParseError::Protocol(
                                "SETNAME requires a name".to_string(),
                            ));
                        }
                        let name = cursor.read_bulk_string()?;
                        client_name = Some(name);
                        remaining_args -= 2;
                    } else {
                        return Err(ParseError::Protocol(format!(
                            "unknown HELLO option: {}",
                            option_str
                        )));
                    }
                }

                Command::Hello {
                    proto_version,
                    auth,
                    client_name,
                }
            }

            _ => {
                return Err(ParseError::UnknownCommand(cmd_str.to_string()));
            }
        };

        Ok((command, cursor.position()))
    }

    /// Returns the command name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Ping => "PING",
            Command::Get { .. } => "GET",
            Command::Set { .. } => "SET",
            Command::Del { .. } => "DEL",
            Command::MGet { .. } => "MGET",
            Command::Config { .. } => "CONFIG",
            Command::Cluster { .. } => "CLUSTER",
            Command::Asking => "ASKING",
            Command::ReadOnly => "READONLY",
            Command::ReadWrite => "READWRITE",
            Command::FlushDb => "FLUSHDB",
            Command::FlushAll => "FLUSHALL",
            Command::Incr { .. } => "INCR",
            Command::Decr { .. } => "DECR",
            Command::IncrBy { .. } => "INCRBY",
            Command::DecrBy { .. } => "DECRBY",
            Command::Append { .. } => "APPEND",
            // Hash commands
            Command::HSet { .. } => "HSET",
            Command::HGet { .. } => "HGET",
            Command::HMGet { .. } => "HMGET",
            Command::HGetAll { .. } => "HGETALL",
            Command::HDel { .. } => "HDEL",
            Command::HExists { .. } => "HEXISTS",
            Command::HLen { .. } => "HLEN",
            Command::HKeys { .. } => "HKEYS",
            Command::HVals { .. } => "HVALS",
            Command::HSetNx { .. } => "HSETNX",
            Command::HIncrBy { .. } => "HINCRBY",
            // List commands
            Command::LPush { .. } => "LPUSH",
            Command::RPush { .. } => "RPUSH",
            Command::LPop { .. } => "LPOP",
            Command::RPop { .. } => "RPOP",
            Command::LRange { .. } => "LRANGE",
            Command::LLen { .. } => "LLEN",
            Command::LIndex { .. } => "LINDEX",
            Command::LSet { .. } => "LSET",
            Command::LTrim { .. } => "LTRIM",
            Command::LPushX { .. } => "LPUSHX",
            Command::RPushX { .. } => "RPUSHX",
            // Set commands
            Command::SAdd { .. } => "SADD",
            Command::SRem { .. } => "SREM",
            Command::SMembers { .. } => "SMEMBERS",
            Command::SIsMember { .. } => "SISMEMBER",
            Command::SMisMember { .. } => "SMISMEMBER",
            Command::SCard { .. } => "SCARD",
            Command::SPop { .. } => "SPOP",
            Command::SRandMember { .. } => "SRANDMEMBER",
            // Type command
            Command::Type { .. } => "TYPE",
            #[cfg(feature = "resp3")]
            Command::Hello { .. } => "HELLO",
        }
    }
}

/// A cursor for reading RESP data from a buffer.
struct Cursor<'a> {
    buffer: &'a [u8],
    pos: usize,
    max_bulk_string_len: usize,
}

impl<'a> Cursor<'a> {
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
    fn get_u8(&mut self) -> u8 {
        let b = self.buffer[self.pos];
        self.pos += 1;
        b
    }

    fn read_integer(&mut self) -> Result<usize, ParseError> {
        let line = self.read_line()?;

        if line.is_empty() {
            return Err(ParseError::InvalidInteger("empty integer".to_string()));
        }

        // Limit integer length to prevent overflow during parsing.
        // usize::MAX is at most 20 digits, so 19 is a safe limit.
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

        if self.get_u8() != b'$' {
            return Err(ParseError::Protocol("expected bulk string".to_string()));
        }

        let len = self.read_integer()?;

        // Check bulk string length limit
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

        // Verify CRLF
        if self.remaining() < 2 {
            return Err(ParseError::Incomplete);
        }
        if self.get_u8() != b'\r' || self.get_u8() != b'\n' {
            return Err(ParseError::Protocol(
                "expected CRLF after bulk string".to_string(),
            ));
        }

        Ok(data)
    }

    fn read_line(&mut self) -> Result<&'a [u8], ParseError> {
        let start = self.pos;
        let slice = &self.buffer[start..];

        if let Some(pos) = memchr::memchr(b'\r', slice)
            && pos + 1 < slice.len()
            && slice[pos + 1] == b'\n'
        {
            let end = start + pos;
            let line = &self.buffer[start..end];
            self.pos = end + 2;
            return Ok(line);
        }

        Err(ParseError::Incomplete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ping() {
        let data = b"*1\r\n$4\r\nPING\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Ping);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_get() {
        let data = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Get { key: b"mykey" });
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_set() {
        let data = b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
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

    #[test]
    fn test_parse_set_ex() {
        let data = b"*5\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n$2\r\nEX\r\n$4\r\n3600\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(
            cmd,
            Command::Set {
                key: b"mykey",
                value: b"myvalue",
                ex: Some(3600),
                px: None,
                nx: false,
                xx: false,
            }
        );
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_set_px_nx() {
        let data =
            b"*5\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\nPX\r\n$4\r\n1000\r\n*5\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\nb\r\n$2\r\nNX\r\n";
        let (cmd, _) = Command::parse(data).unwrap();
        if let Command::Set { px, .. } = cmd {
            assert_eq!(px, Some(1000));
        } else {
            panic!("Expected SET command");
        }
    }

    #[test]
    fn test_parse_del() {
        let data = b"*2\r\n$3\r\nDEL\r\n$5\r\nmykey\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Del { key: b"mykey" });
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_mget() {
        let data = b"*4\r\n$4\r\nMGET\r\n$4\r\nkey1\r\n$4\r\nkey2\r\n$4\r\nkey3\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(
            cmd,
            Command::MGet {
                keys: vec![b"key1" as &[u8], b"key2", b"key3"]
            }
        );
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_config() {
        let data = b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$10\r\nmaxclients\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(
            cmd,
            Command::Config {
                subcommand: b"GET",
                args: vec![b"maxclients" as &[u8]]
            }
        );
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_flushdb() {
        let data = b"*1\r\n$7\r\nFLUSHDB\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::FlushDb);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_flushall() {
        let data = b"*1\r\n$8\r\nFLUSHALL\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::FlushAll);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_case_insensitive() {
        let data = b"*2\r\n$3\r\nget\r\n$5\r\nmykey\r\n";
        let (cmd, _) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Get { key: b"mykey" });

        let data = b"*2\r\n$3\r\nGeT\r\n$5\r\nmykey\r\n";
        let (cmd, _) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Get { key: b"mykey" });
    }

    #[test]
    fn test_parse_incomplete() {
        assert!(matches!(
            Command::parse(b"*2\r\n$3\r\nGET"),
            Err(ParseError::Incomplete)
        ));
        assert!(matches!(
            Command::parse(b"*2\r\n"),
            Err(ParseError::Incomplete)
        ));
        assert!(matches!(Command::parse(b""), Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_unknown_command() {
        let data = b"*1\r\n$7\r\nUNKNOWN\r\n";
        assert!(matches!(
            Command::parse(data),
            Err(ParseError::UnknownCommand(_))
        ));
    }

    #[test]
    fn test_parse_wrong_arity() {
        let data = b"*1\r\n$3\r\nGET\r\n"; // GET with no key
        assert!(matches!(
            Command::parse(data),
            Err(ParseError::WrongArity(_))
        ));
    }

    #[test]
    fn test_command_name() {
        assert_eq!(Command::Ping.name(), "PING");
        assert_eq!(Command::Get { key: b"k" }.name(), "GET");
        assert_eq!(
            Command::Set {
                key: b"k",
                value: b"v",
                ex: None,
                px: None,
                nx: false,
                xx: false
            }
            .name(),
            "SET"
        );
        assert_eq!(Command::Del { key: b"k" }.name(), "DEL");
        assert_eq!(Command::MGet { keys: vec![] }.name(), "MGET");
        assert_eq!(
            Command::Config {
                subcommand: b"GET",
                args: vec![]
            }
            .name(),
            "CONFIG"
        );
        assert_eq!(Command::FlushDb.name(), "FLUSHDB");
        assert_eq!(Command::FlushAll.name(), "FLUSHALL");
    }

    #[test]
    fn test_parse_set_xx() {
        let data = b"*4\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\nXX\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        if let Command::Set { xx, nx, .. } = cmd {
            assert!(xx);
            assert!(!nx);
        } else {
            panic!("Expected SET command");
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_set_unknown_option() {
        let data = b"*4\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$7\r\nINVALID\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_set_ex_missing_value() {
        // SET k v EX (missing the expiration value)
        let data = b"*4\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\nEX\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_set_px_missing_value() {
        // SET k v PX (missing the expiration value)
        let data = b"*4\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\nPX\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_set_invalid_ttl() {
        // SET k v EX invalid
        let data = b"*5\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\nEX\r\n$3\r\nabc\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_ping_wrong_arity() {
        // PING with extra argument
        let data = b"*2\r\n$4\r\nPING\r\n$5\r\nextra\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_del_wrong_arity() {
        // DEL with no key
        let data = b"*1\r\n$3\r\nDEL\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_mget_wrong_arity() {
        // MGET with no keys
        let data = b"*1\r\n$4\r\nMGET\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_config_wrong_arity() {
        // CONFIG with no subcommand
        let data = b"*1\r\n$6\r\nCONFIG\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_set_wrong_arity() {
        // SET with only key
        let data = b"*2\r\n$3\r\nSET\r\n$1\r\nk\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_not_array() {
        // Command not starting with array
        let data = b"+OK\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_empty_array() {
        // Empty array (0 elements)
        let data = b"*0\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_command_debug() {
        let cmd = Command::Ping;
        let debug_str = format!("{:?}", cmd);
        assert!(debug_str.contains("Ping"));
    }

    #[test]
    fn test_command_clone() {
        let cmd1 = Command::Get { key: b"mykey" };
        let cmd2 = cmd1.clone();
        assert_eq!(cmd1, cmd2);
    }

    #[test]
    fn test_command_eq() {
        assert_eq!(Command::Ping, Command::Ping);
        assert_ne!(Command::Ping, Command::FlushDb);
        assert_eq!(Command::Get { key: b"a" }, Command::Get { key: b"a" });
        assert_ne!(Command::Get { key: b"a" }, Command::Get { key: b"b" });
    }

    #[test]
    fn test_parse_config_set() {
        let data = b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\nmaxclients\r\n$3\r\n100\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        if let Command::Config { subcommand, args } = cmd {
            assert_eq!(subcommand, b"SET");
            assert_eq!(args.len(), 2);
        } else {
            panic!("Expected CONFIG command");
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_config_no_args() {
        let data = b"*2\r\n$6\r\nCONFIG\r\n$4\r\nINFO\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        if let Command::Config { subcommand, args } = cmd {
            assert_eq!(subcommand, b"INFO");
            assert!(args.is_empty());
        } else {
            panic!("Expected CONFIG command");
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_integer_too_large() {
        // Array with length that's too large (>19 digits)
        let data = b"*12345678901234567890123\r\n$4\r\nPING\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::InvalidInteger(_))));
    }

    #[test]
    fn test_parse_integer_non_digit() {
        // Array length with non-digit character
        let data = b"*12a\r\n$4\r\nPING\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::InvalidInteger(_))));
    }

    #[test]
    fn test_parse_integer_overflow() {
        // Array length that causes overflow
        let data = b"*99999999999999999999\r\n$4\r\nPING\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::InvalidInteger(_))));
    }

    #[test]
    fn test_parse_bulk_string_missing_crlf() {
        // Bulk string with wrong trailing bytes
        let data = b"*2\r\n$3\r\nGET\r\n$5\r\nmykeyXX";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_not_bulk_string() {
        // Command name not a bulk string
        let data = b"*2\r\n+GET\r\n$5\r\nmykey\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_invalid_utf8_command() {
        // Command name with invalid UTF-8
        let data = b"*1\r\n$2\r\n\xff\xfe\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_set_invalid_utf8_option() {
        // SET with invalid UTF-8 in option
        let data = b"*4\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\n\xff\xfe\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_set_invalid_utf8_in_ttl() {
        // SET with invalid UTF-8 in TTL value
        let data = b"*5\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\nEX\r\n$2\r\n\xff\xfe\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_set_invalid_px_ttl() {
        // SET k v PX invalid
        let data = b"*5\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\nPX\r\n$3\r\nabc\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_set_nx() {
        let data = b"*4\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\nNX\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        if let Command::Set { nx, xx, .. } = cmd {
            assert!(nx);
            assert!(!xx);
        } else {
            panic!("Expected SET command");
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_bulk_string_incomplete() {
        // Bulk string with incomplete data
        let data = b"*2\r\n$3\r\nGET\r\n$100\r\nmykey\r\n"; // claims 100 bytes but only 5
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_mget_huge_count_no_oom() {
        // MGET with huge array count should reject as protocol error, not OOM
        let data = b"*1177777777\r\n$4\r\nmGet\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_array_too_large() {
        // Array larger than MAX_ARRAY_LEN (1M) should be rejected
        let data = b"*1048577\r\n$4\r\nPING\r\n"; // 1M + 1
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    // ========================================================================
    // INCR/DECR Tests
    // ========================================================================

    #[test]
    fn test_parse_incr() {
        let data = b"*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Incr { key: b"counter" });
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_incr_case_insensitive() {
        let data = b"*2\r\n$4\r\nincr\r\n$3\r\nkey\r\n";
        let (cmd, _) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Incr { key: b"key" });
    }

    #[test]
    fn test_parse_incr_wrong_arity_no_key() {
        let data = b"*1\r\n$4\r\nINCR\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_incr_wrong_arity_extra_args() {
        let data = b"*3\r\n$4\r\nINCR\r\n$3\r\nkey\r\n$5\r\nextra\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_decr() {
        let data = b"*2\r\n$4\r\nDECR\r\n$7\r\ncounter\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Decr { key: b"counter" });
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_decr_case_insensitive() {
        let data = b"*2\r\n$4\r\ndecr\r\n$3\r\nkey\r\n";
        let (cmd, _) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Decr { key: b"key" });
    }

    #[test]
    fn test_parse_decr_wrong_arity() {
        let data = b"*1\r\n$4\r\nDECR\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_incrby() {
        let data = b"*3\r\n$6\r\nINCRBY\r\n$7\r\ncounter\r\n$2\r\n10\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(
            cmd,
            Command::IncrBy {
                key: b"counter",
                delta: 10
            }
        );
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_incrby_negative() {
        let data = b"*3\r\n$6\r\nINCRBY\r\n$3\r\nkey\r\n$3\r\n-10\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(
            cmd,
            Command::IncrBy {
                key: b"key",
                delta: -10
            }
        );
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_incrby_case_insensitive() {
        let data = b"*3\r\n$6\r\nincrby\r\n$3\r\nkey\r\n$1\r\n5\r\n";
        let (cmd, _) = Command::parse(data).unwrap();
        assert_eq!(
            cmd,
            Command::IncrBy {
                key: b"key",
                delta: 5
            }
        );
    }

    #[test]
    fn test_parse_incrby_wrong_arity() {
        let data = b"*2\r\n$6\r\nINCRBY\r\n$3\r\nkey\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_incrby_invalid_delta() {
        let data = b"*3\r\n$6\r\nINCRBY\r\n$3\r\nkey\r\n$3\r\nabc\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_decrby() {
        let data = b"*3\r\n$6\r\nDECRBY\r\n$7\r\ncounter\r\n$2\r\n10\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(
            cmd,
            Command::DecrBy {
                key: b"counter",
                delta: 10
            }
        );
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_decrby_case_insensitive() {
        let data = b"*3\r\n$6\r\ndecrby\r\n$3\r\nkey\r\n$1\r\n5\r\n";
        let (cmd, _) = Command::parse(data).unwrap();
        assert_eq!(
            cmd,
            Command::DecrBy {
                key: b"key",
                delta: 5
            }
        );
    }

    #[test]
    fn test_parse_decrby_wrong_arity() {
        let data = b"*2\r\n$6\r\nDECRBY\r\n$3\r\nkey\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_decrby_invalid_delta() {
        let data = b"*3\r\n$6\r\nDECRBY\r\n$3\r\nkey\r\n$3\r\nabc\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_incr_decr_command_names() {
        assert_eq!(Command::Incr { key: b"k" }.name(), "INCR");
        assert_eq!(Command::Decr { key: b"k" }.name(), "DECR");
        assert_eq!(
            Command::IncrBy {
                key: b"k",
                delta: 1
            }
            .name(),
            "INCRBY"
        );
        assert_eq!(
            Command::DecrBy {
                key: b"k",
                delta: 1
            }
            .name(),
            "DECRBY"
        );
    }

    // ========================================================================
    // Cluster Command Tests
    // ========================================================================

    #[test]
    fn test_parse_cluster_slots() {
        let data = b"*2\r\n$7\r\nCLUSTER\r\n$5\r\nSLOTS\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(
            cmd,
            Command::Cluster {
                subcommand: b"SLOTS",
                args: vec![],
            }
        );
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_cluster_info() {
        let data = b"*2\r\n$7\r\ncluster\r\n$4\r\nINFO\r\n";
        let (cmd, _) = Command::parse(data).unwrap();
        if let Command::Cluster { subcommand, args } = cmd {
            assert_eq!(subcommand, b"INFO");
            assert!(args.is_empty());
        } else {
            panic!("Expected CLUSTER command");
        }
    }

    #[test]
    fn test_parse_cluster_wrong_arity() {
        let data = b"*1\r\n$7\r\nCLUSTER\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_asking() {
        let data = b"*1\r\n$6\r\nASKING\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Asking);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_asking_case_insensitive() {
        let data = b"*1\r\n$6\r\nasking\r\n";
        let (cmd, _) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::Asking);
    }

    #[test]
    fn test_parse_asking_wrong_arity() {
        let data = b"*2\r\n$6\r\nASKING\r\n$3\r\nfoo\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_readonly() {
        let data = b"*1\r\n$8\r\nREADONLY\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::ReadOnly);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_readonly_wrong_arity() {
        let data = b"*2\r\n$8\r\nREADONLY\r\n$3\r\nfoo\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_parse_readwrite() {
        let data = b"*1\r\n$9\r\nREADWRITE\r\n";
        let (cmd, consumed) = Command::parse(data).unwrap();
        assert_eq!(cmd, Command::ReadWrite);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_readwrite_wrong_arity() {
        let data = b"*2\r\n$9\r\nREADWRITE\r\n$3\r\nfoo\r\n";
        let result = Command::parse(data);
        assert!(matches!(result, Err(ParseError::WrongArity(_))));
    }

    #[test]
    fn test_cluster_command_names() {
        assert_eq!(
            Command::Cluster {
                subcommand: b"SLOTS",
                args: vec![]
            }
            .name(),
            "CLUSTER"
        );
        assert_eq!(Command::Asking.name(), "ASKING");
        assert_eq!(Command::ReadOnly.name(), "READONLY");
        assert_eq!(Command::ReadWrite.name(), "READWRITE");
    }

    // ========================================================================
    // RESP3 Tests
    // ========================================================================

    #[cfg(feature = "resp3")]
    mod resp3_tests {
        use super::*;

        #[test]
        fn test_parse_hello_no_args() {
            let data = b"*1\r\n$5\r\nHELLO\r\n";
            let (cmd, consumed) = Command::parse(data).unwrap();
            assert_eq!(
                cmd,
                Command::Hello {
                    proto_version: None,
                    auth: None,
                    client_name: None,
                }
            );
            assert_eq!(consumed, data.len());
        }

        #[test]
        fn test_parse_hello_with_version() {
            let data = b"*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n";
            let (cmd, consumed) = Command::parse(data).unwrap();
            assert_eq!(
                cmd,
                Command::Hello {
                    proto_version: Some(3),
                    auth: None,
                    client_name: None,
                }
            );
            assert_eq!(consumed, data.len());
        }

        #[test]
        fn test_parse_hello_with_auth() {
            // HELLO 3 AUTH username password
            let data =
                b"*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n$4\r\npass\r\n";
            let (cmd, consumed) = Command::parse(data).unwrap();
            assert_eq!(
                cmd,
                Command::Hello {
                    proto_version: Some(3),
                    auth: Some((b"user" as &[u8], b"pass" as &[u8])),
                    client_name: None,
                }
            );
            assert_eq!(consumed, data.len());
        }

        #[test]
        fn test_parse_hello_with_setname() {
            // HELLO 3 SETNAME myapp
            let data = b"*4\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$7\r\nSETNAME\r\n$5\r\nmyapp\r\n";
            let (cmd, consumed) = Command::parse(data).unwrap();
            assert_eq!(
                cmd,
                Command::Hello {
                    proto_version: Some(3),
                    auth: None,
                    client_name: Some(b"myapp" as &[u8]),
                }
            );
            assert_eq!(consumed, data.len());
        }

        #[test]
        fn test_parse_hello_full() {
            // HELLO 3 AUTH user pass SETNAME myapp
            let data = b"*7\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n$4\r\npass\r\n$7\r\nSETNAME\r\n$5\r\nmyapp\r\n";
            let (cmd, consumed) = Command::parse(data).unwrap();
            assert_eq!(
                cmd,
                Command::Hello {
                    proto_version: Some(3),
                    auth: Some((b"user" as &[u8], b"pass" as &[u8])),
                    client_name: Some(b"myapp" as &[u8]),
                }
            );
            assert_eq!(consumed, data.len());
        }

        #[test]
        fn test_hello_command_name() {
            assert_eq!(
                Command::Hello {
                    proto_version: Some(3),
                    auth: None,
                    client_name: None
                }
                .name(),
                "HELLO"
            );
        }

        #[test]
        fn test_parse_hello_auth_missing_args() {
            // HELLO 3 AUTH user (missing password)
            let data = b"*4\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n";
            let result = Command::parse(data);
            assert!(matches!(result, Err(ParseError::Protocol(_))));
        }

        #[test]
        fn test_parse_hello_setname_missing_args() {
            // HELLO 3 SETNAME (missing name)
            let data = b"*3\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$7\r\nSETNAME\r\n";
            let result = Command::parse(data);
            assert!(matches!(result, Err(ParseError::Protocol(_))));
        }

        #[test]
        fn test_parse_hello_unknown_option() {
            // HELLO 3 INVALID
            let data = b"*3\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$7\r\nINVALID\r\n";
            let result = Command::parse(data);
            assert!(matches!(result, Err(ParseError::Protocol(_))));
        }

        #[test]
        fn test_parse_hello_invalid_version() {
            // HELLO abc (invalid version)
            let data = b"*2\r\n$5\r\nHELLO\r\n$3\r\nabc\r\n";
            let result = Command::parse(data);
            assert!(matches!(result, Err(ParseError::Protocol(_))));
        }

        #[test]
        fn test_parse_hello_invalid_utf8_option() {
            // HELLO 3 with invalid UTF-8 option
            let data = b"*3\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$2\r\n\xff\xfe\r\n";
            let result = Command::parse(data);
            assert!(matches!(result, Err(ParseError::Protocol(_))));
        }

        #[test]
        fn test_parse_hello_invalid_utf8_version() {
            // HELLO with invalid UTF-8 version
            let data = b"*2\r\n$5\r\nHELLO\r\n$2\r\n\xff\xfe\r\n";
            let result = Command::parse(data);
            assert!(matches!(result, Err(ParseError::Protocol(_))));
        }
    }
}
