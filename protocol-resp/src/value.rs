//! RESP value types and parsing/encoding.
//!
//! RESP2 defines the following value types:
//! - Simple String: `+OK\r\n`
//! - Error: `-ERR message\r\n`
//! - Integer: `:1000\r\n`
//! - Bulk String: `$6\r\nfoobar\r\n`
//! - Null Bulk String: `$-1\r\n`
//! - Array: `*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n`
//!
//! RESP3 adds the following types (enabled with the `resp3` feature):
//! - Null: `_\r\n`
//! - Boolean: `#t\r\n` or `#f\r\n`
//! - Double: `,3.14159\r\n`
//! - Big Number: `(12345678901234567890\r\n`
//! - Bulk Error: `!<len>\r\n<error>\r\n`
//! - Verbatim String: `=<len>\r\ntxt:<data>\r\n`
//! - Map: `%<len>\r\n<key><val>...`
//! - Set: `~<len>\r\n<elem>...`
//! - Push: `><len>\r\n<elem>...`
//! - Attribute: `|<len>\r\n<attrs>...<value>`

use crate::error::ParseError;
use bytes::Bytes;
use std::io::Write;

/// Default maximum key length in bytes.
///
/// This matches the memcache protocol default of 250 bytes.
pub const DEFAULT_MAX_KEY_LEN: usize = 250;

/// Default maximum number of elements in a collection (array, map, set, etc.).
///
/// This limit prevents denial-of-service attacks where a malicious client sends
/// a message claiming to have billions of elements, causing the server to attempt
/// a massive allocation.
pub const DEFAULT_MAX_COLLECTION_ELEMENTS: usize = 1024;

/// Default maximum size of a bulk string in bytes (1MB).
///
/// This limit prevents denial-of-service attacks where a malicious client sends
/// a message claiming to have a huge bulk string, causing the server to attempt
/// a massive allocation.
///
/// For cache implementations, you may want to set this to match your segment size
/// minus header overhead using `ParseOptions::max_bulk_string_len()`.
pub const DEFAULT_MAX_BULK_STRING_LEN: usize = 1024 * 1024;

/// Default maximum nesting depth for recursive structures (arrays, maps, sets, etc.).
///
/// This limit prevents denial-of-service attacks where deeply nested structures
/// cause stack overflow or excessive memory allocation through cumulative
/// Vec::with_capacity() calls.
///
/// The value of 8 is sufficient for typical Redis use cases (commands, responses,
/// pub/sub messages) which rarely exceed 2-3 levels of nesting.
pub const DEFAULT_MAX_DEPTH: usize = 8;

/// Default maximum total items across all collections in a single parse.
///
/// This is the critical DoS protection limit. Without this, nested collections
/// could cause exponential memory allocation: MAX_ITEMS^MAX_DEPTH elements.
///
/// This limit caps the total number of collection elements across ALL levels
/// of nesting in a single parse operation to prevent such attacks.
pub const DEFAULT_MAX_TOTAL_ITEMS: usize = 1024;

/// Configuration options for RESP value parsing.
///
/// These options allow customizing the DoS protection limits for different
/// deployment scenarios. More restrictive limits provide better protection
/// against resource exhaustion attacks.
#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    /// Maximum key length in bytes.
    pub max_key_len: usize,
    /// Maximum number of elements in a single collection.
    pub max_collection_elements: usize,
    /// Maximum size of a bulk string in bytes.
    pub max_bulk_string_len: usize,
    /// Maximum nesting depth for recursive structures.
    pub max_depth: usize,
    /// Maximum total items across all collections in a single parse.
    ///
    /// This is the critical limit for preventing exponential allocation attacks
    /// from nested collections. Without this, an attacker could send nested
    /// arrays where total items = max_collection_elements^max_depth.
    pub max_total_items: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_key_len: DEFAULT_MAX_KEY_LEN,
            max_collection_elements: DEFAULT_MAX_COLLECTION_ELEMENTS,
            max_bulk_string_len: DEFAULT_MAX_BULK_STRING_LEN,
            max_depth: DEFAULT_MAX_DEPTH,
            max_total_items: DEFAULT_MAX_TOTAL_ITEMS,
        }
    }
}

impl ParseOptions {
    /// Create new parse options with default values.
    pub const fn new() -> Self {
        Self {
            max_key_len: DEFAULT_MAX_KEY_LEN,
            max_collection_elements: DEFAULT_MAX_COLLECTION_ELEMENTS,
            max_bulk_string_len: DEFAULT_MAX_BULK_STRING_LEN,
            max_depth: DEFAULT_MAX_DEPTH,
            max_total_items: DEFAULT_MAX_TOTAL_ITEMS,
        }
    }

    /// Set the maximum key length.
    pub const fn max_key_len(mut self, len: usize) -> Self {
        self.max_key_len = len;
        self
    }

    /// Set the maximum collection element count.
    pub const fn max_collection_elements(mut self, count: usize) -> Self {
        self.max_collection_elements = count;
        self
    }

    /// Set the maximum bulk string length.
    pub const fn max_bulk_string_len(mut self, len: usize) -> Self {
        self.max_bulk_string_len = len;
        self
    }

    /// Set the maximum nesting depth.
    pub const fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set the maximum total items across all collections.
    pub const fn max_total_items(mut self, count: usize) -> Self {
        self.max_total_items = count;
        self
    }
}

/// A RESP protocol value.
///
/// This enum supports both RESP2 and RESP3 types. RESP3 types are only
/// available when the `resp3` feature is enabled.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Simple string: `+OK\r\n`
    SimpleString(Bytes),
    /// Error: `-ERR message\r\n`
    Error(Bytes),
    /// Integer: `:1000\r\n`
    Integer(i64),
    /// Bulk string: `$6\r\nfoobar\r\n`
    BulkString(Bytes),
    /// Null value.
    /// RESP2: `$-1\r\n` or `*-1\r\n`
    /// RESP3: `_\r\n`
    Null,
    /// Array: `*2\r\n...`
    Array(Vec<Value>),

    // ========================================================================
    // RESP3 Types (feature-gated)
    // ========================================================================
    /// Boolean: `#t\r\n` or `#f\r\n`
    #[cfg(feature = "resp3")]
    Boolean(bool),
    /// Double-precision floating point: `,3.14159\r\n`
    #[cfg(feature = "resp3")]
    Double(f64),
    /// Big number (arbitrary precision): `(12345678901234567890\r\n`
    /// Stored as the raw decimal string representation.
    #[cfg(feature = "resp3")]
    BigNumber(Bytes),
    /// Bulk error: `!<len>\r\n<error>\r\n`
    #[cfg(feature = "resp3")]
    BulkError(Bytes),
    /// Verbatim string: `=<len>\r\ntxt:<data>\r\n`
    /// The format is a 3-byte encoding type (e.g., "txt", "mkd").
    #[cfg(feature = "resp3")]
    VerbatimString {
        /// 3-byte format identifier (e.g., b"txt", b"mkd")
        format: [u8; 3],
        /// The actual data
        data: Bytes,
    },
    /// Map: `%<len>\r\n<key><val>...`
    #[cfg(feature = "resp3")]
    Map(Vec<(Value, Value)>),
    /// Set: `~<len>\r\n<elem>...`
    #[cfg(feature = "resp3")]
    Set(Vec<Value>),
    /// Push message (server-initiated): `><len>\r\n<elem>...`
    #[cfg(feature = "resp3")]
    Push(Vec<Value>),
    /// Attribute (metadata attached to next value): `|<len>\r\n<attrs>...<value>`
    #[cfg(feature = "resp3")]
    Attribute {
        /// Metadata key-value pairs
        attrs: Vec<(Value, Value)>,
        /// The actual value this metadata is attached to
        value: Box<Value>,
    },
}

impl Value {
    // ========================================================================
    // Constructors
    // ========================================================================

    /// Create a simple string value.
    #[inline]
    pub fn simple_string(s: &[u8]) -> Self {
        Value::SimpleString(Bytes::copy_from_slice(s))
    }

    /// Create an error value.
    #[inline]
    pub fn error(msg: &[u8]) -> Self {
        Value::Error(Bytes::copy_from_slice(msg))
    }

    /// Create an integer value.
    #[inline]
    pub fn integer(n: i64) -> Self {
        Value::Integer(n)
    }

    /// Create a bulk string value.
    #[inline]
    pub fn bulk_string(data: &[u8]) -> Self {
        Value::BulkString(Bytes::copy_from_slice(data))
    }

    /// Create a null value.
    #[inline]
    pub fn null() -> Self {
        Value::Null
    }

    /// Create an array value.
    #[inline]
    pub fn array(elements: Vec<Value>) -> Self {
        Value::Array(elements)
    }

    // RESP3 constructors (feature-gated)

    /// Create a boolean value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn boolean(b: bool) -> Self {
        Value::Boolean(b)
    }

    /// Create a double value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn double(d: f64) -> Self {
        Value::Double(d)
    }

    /// Create a big number value from a decimal string (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn big_number(num: &[u8]) -> Self {
        Value::BigNumber(Bytes::copy_from_slice(num))
    }

    /// Create a bulk error value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn bulk_error(msg: &[u8]) -> Self {
        Value::BulkError(Bytes::copy_from_slice(msg))
    }

    /// Create a verbatim string value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn verbatim_string(format: [u8; 3], data: &[u8]) -> Self {
        Value::VerbatimString {
            format,
            data: Bytes::copy_from_slice(data),
        }
    }

    /// Create a map value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn map(entries: Vec<(Value, Value)>) -> Self {
        Value::Map(entries)
    }

    /// Create a set value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn set(elements: Vec<Value>) -> Self {
        Value::Set(elements)
    }

    /// Create a push message value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn push(elements: Vec<Value>) -> Self {
        Value::Push(elements)
    }

    /// Create an attribute value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn attribute(attrs: Vec<(Value, Value)>, value: Value) -> Self {
        Value::Attribute {
            attrs,
            value: Box::new(value),
        }
    }

    // ========================================================================
    // Type checks
    // ========================================================================

    /// Returns true if this is a null value.
    #[inline]
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Returns true if this is an error value.
    #[inline]
    pub fn is_error(&self) -> bool {
        matches!(self, Value::Error(_))
    }

    /// Returns true if this is a simple string.
    #[inline]
    pub fn is_simple_string(&self) -> bool {
        matches!(self, Value::SimpleString(_))
    }

    /// Returns true if this is a bulk string.
    #[inline]
    pub fn is_bulk_string(&self) -> bool {
        matches!(self, Value::BulkString(_))
    }

    /// Returns true if this is an integer.
    #[inline]
    pub fn is_integer(&self) -> bool {
        matches!(self, Value::Integer(_))
    }

    /// Returns true if this is an array.
    #[inline]
    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }

    // RESP3 type checks (feature-gated)

    /// Returns true if this is a boolean value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn is_boolean(&self) -> bool {
        matches!(self, Value::Boolean(_))
    }

    /// Returns true if this is a double value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn is_double(&self) -> bool {
        matches!(self, Value::Double(_))
    }

    /// Returns true if this is a big number value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn is_big_number(&self) -> bool {
        matches!(self, Value::BigNumber(_))
    }

    /// Returns true if this is a bulk error value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn is_bulk_error(&self) -> bool {
        matches!(self, Value::BulkError(_))
    }

    /// Returns true if this is a verbatim string value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn is_verbatim_string(&self) -> bool {
        matches!(self, Value::VerbatimString { .. })
    }

    /// Returns true if this is a map value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn is_map(&self) -> bool {
        matches!(self, Value::Map(_))
    }

    /// Returns true if this is a set value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn is_set(&self) -> bool {
        matches!(self, Value::Set(_))
    }

    /// Returns true if this is a push message (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn is_push(&self) -> bool {
        matches!(self, Value::Push(_))
    }

    /// Returns true if this is an attribute value (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn is_attribute(&self) -> bool {
        matches!(self, Value::Attribute { .. })
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Returns the value as bytes if it's a string type (simple or bulk).
    #[inline]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::SimpleString(s) | Value::BulkString(s) | Value::Error(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as an integer.
    #[inline]
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the value as an array.
    #[inline]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(arr) => Some(arr),
            _ => None,
        }
    }

    // RESP3 accessors (feature-gated)

    /// Returns the value as a boolean (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the value as a double (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn as_double(&self) -> Option<f64> {
        match self {
            Value::Double(d) => Some(*d),
            _ => None,
        }
    }

    /// Returns the value as a big number decimal string (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn as_big_number(&self) -> Option<&[u8]> {
        match self {
            Value::BigNumber(n) => Some(n),
            _ => None,
        }
    }

    /// Returns the value as a map (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the value as a set (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn as_set(&self) -> Option<&[Value]> {
        match self {
            Value::Set(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as a push message (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn as_push(&self) -> Option<&[Value]> {
        match self {
            Value::Push(p) => Some(p),
            _ => None,
        }
    }

    /// Returns the verbatim string format and data (RESP3).
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn as_verbatim_string(&self) -> Option<(&[u8; 3], &[u8])> {
        match self {
            Value::VerbatimString { format, data } => Some((format, data)),
            _ => None,
        }
    }

    // ========================================================================
    // Parsing
    // ========================================================================

    /// Parse a RESP value from a byte buffer.
    ///
    /// Returns the parsed value and the number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `ParseError::Incomplete` if more data is needed to complete parsing.
    /// Returns other errors for malformed data.
    #[inline]
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ParseError> {
        Self::parse_with_options(data, &ParseOptions::default())
    }

    /// Parse a RESP value from raw bytes with custom options.
    ///
    /// This allows configuring DoS protection limits like maximum collection size
    /// and bulk string length.
    pub fn parse_with_options(
        data: &[u8],
        options: &ParseOptions,
    ) -> Result<(Self, usize), ParseError> {
        let mut total_items = 0;
        Self::parse_internal(data, options, 0, &mut total_items)
    }

    /// Parse a RESP value zero-copy from a `Bytes` buffer.
    ///
    /// String variants (`BulkString`, `SimpleString`, etc.) are returned as
    /// `Bytes::slice()` references into the input — no allocation or copy.
    /// Returns the parsed value and the number of bytes consumed.
    #[inline]
    pub fn parse_bytes(data: Bytes) -> Result<(Self, usize), ParseError> {
        Self::parse_bytes_with_options(data, &ParseOptions::default())
    }

    /// Parse a RESP value zero-copy from a `Bytes` buffer with custom options.
    pub fn parse_bytes_with_options(
        data: Bytes,
        options: &ParseOptions,
    ) -> Result<(Self, usize), ParseError> {
        let mut total_items = 0;
        Self::parse_bytes_internal(&data, options, 0, &mut total_items)
    }

    /// Internal zero-copy parsing function.
    fn parse_bytes_internal(
        data: &Bytes,
        options: &ParseOptions,
        depth: usize,
        total_items: &mut usize,
    ) -> Result<(Self, usize), ParseError> {
        if data.is_empty() {
            return Err(ParseError::Incomplete);
        }

        match data[0] {
            b'+' => parse_simple_string_bytes(data),
            b'-' => parse_error_bytes(data),
            b':' => parse_integer(&data[..]),
            b'$' => parse_bulk_string_bytes(data, options),
            b'*' => parse_array_bytes(data, options, depth, total_items),
            #[cfg(feature = "resp3")]
            b'_' => parse_null(&data[..]),
            #[cfg(feature = "resp3")]
            b'#' => parse_boolean(&data[..]),
            #[cfg(feature = "resp3")]
            b',' => parse_double(&data[..]),
            #[cfg(feature = "resp3")]
            b'(' => parse_big_number_bytes(data),
            #[cfg(feature = "resp3")]
            b'!' => parse_bulk_error_bytes(data, options),
            #[cfg(feature = "resp3")]
            b'=' => parse_verbatim_string_bytes(data, options),
            #[cfg(feature = "resp3")]
            b'%' => parse_map_bytes(data, options, depth, total_items),
            #[cfg(feature = "resp3")]
            b'~' => parse_set_bytes(data, options, depth, total_items),
            #[cfg(feature = "resp3")]
            b'>' => parse_push_bytes(data, options, depth, total_items),
            #[cfg(feature = "resp3")]
            b'|' => parse_attribute_bytes(data, options, depth, total_items),
            other => Err(ParseError::InvalidPrefix(other)),
        }
    }

    /// Internal parsing function that tracks nesting depth and total items.
    fn parse_internal(
        data: &[u8],
        options: &ParseOptions,
        depth: usize,
        total_items: &mut usize,
    ) -> Result<(Self, usize), ParseError> {
        if data.is_empty() {
            return Err(ParseError::Incomplete);
        }

        match data[0] {
            // RESP2 types
            b'+' => parse_simple_string(data),
            b'-' => parse_error(data),
            b':' => parse_integer(data),
            b'$' => parse_bulk_string(data, options),
            b'*' => parse_array(data, options, depth, total_items),
            // RESP3 types
            #[cfg(feature = "resp3")]
            b'_' => parse_null(data),
            #[cfg(feature = "resp3")]
            b'#' => parse_boolean(data),
            #[cfg(feature = "resp3")]
            b',' => parse_double(data),
            #[cfg(feature = "resp3")]
            b'(' => parse_big_number(data),
            #[cfg(feature = "resp3")]
            b'!' => parse_bulk_error(data, options),
            #[cfg(feature = "resp3")]
            b'=' => parse_verbatim_string(data, options),
            #[cfg(feature = "resp3")]
            b'%' => parse_map(data, options, depth, total_items),
            #[cfg(feature = "resp3")]
            b'~' => parse_set(data, options, depth, total_items),
            #[cfg(feature = "resp3")]
            b'>' => parse_push(data, options, depth, total_items),
            #[cfg(feature = "resp3")]
            b'|' => parse_attribute(data, options, depth, total_items),
            other => Err(ParseError::InvalidPrefix(other)),
        }
    }

    // ========================================================================
    // Encoding
    // ========================================================================

    /// Encode this value into a byte buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panics
    ///
    /// Panics if the buffer is too small. Use `encoded_len()` to check the required size.
    #[inline]
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        match self {
            Value::SimpleString(s) => encode_simple_string(buf, s),
            Value::Error(msg) => encode_error(buf, msg),
            Value::Integer(n) => encode_integer(buf, *n),
            Value::BulkString(data) => encode_bulk_string(buf, data),
            Value::Null => encode_resp2_null(buf),
            Value::Array(elements) => encode_array(buf, elements),
            #[cfg(feature = "resp3")]
            Value::Boolean(b) => encode_boolean(buf, *b),
            #[cfg(feature = "resp3")]
            Value::Double(d) => encode_double(buf, *d),
            #[cfg(feature = "resp3")]
            Value::BigNumber(n) => encode_big_number(buf, n),
            #[cfg(feature = "resp3")]
            Value::BulkError(msg) => encode_bulk_error(buf, msg),
            #[cfg(feature = "resp3")]
            Value::VerbatimString { format, data } => encode_verbatim_string(buf, format, data),
            #[cfg(feature = "resp3")]
            Value::Map(entries) => encode_map(buf, entries),
            #[cfg(feature = "resp3")]
            Value::Set(elements) => encode_set(buf, elements),
            #[cfg(feature = "resp3")]
            Value::Push(elements) => encode_push(buf, elements),
            #[cfg(feature = "resp3")]
            Value::Attribute { attrs, value } => encode_attribute(buf, attrs, value),
        }
    }

    /// Calculate the encoded length of this value.
    pub fn encoded_len(&self) -> usize {
        match self {
            Value::SimpleString(s) => 1 + s.len() + 2, // +<data>\r\n
            Value::Error(msg) => 1 + msg.len() + 2,    // -<data>\r\n
            Value::Integer(n) => {
                let mut buf = itoa::Buffer::new();
                1 + buf.format(*n).len() + 2 // :<int>\r\n
            }
            Value::BulkString(data) => {
                let mut buf = itoa::Buffer::new();
                1 + buf.format(data.len()).len() + 2 + data.len() + 2 // $<len>\r\n<data>\r\n
            }
            Value::Null => 5, // $-1\r\n
            Value::Array(elements) => {
                let mut buf = itoa::Buffer::new();
                let header_len = 1 + buf.format(elements.len()).len() + 2;
                header_len + elements.iter().map(|e| e.encoded_len()).sum::<usize>()
            }
            // RESP3 types
            #[cfg(feature = "resp3")]
            Value::Boolean(_) => 4, // #t\r\n or #f\r\n
            #[cfg(feature = "resp3")]
            Value::Double(d) => {
                // ,<float>\r\n - use ryu for efficient length calculation
                let mut buf = ryu::Buffer::new();
                1 + buf.format(*d).len() + 2
            }
            #[cfg(feature = "resp3")]
            Value::BigNumber(n) => 1 + n.len() + 2, // (<num>\r\n
            #[cfg(feature = "resp3")]
            Value::BulkError(msg) => {
                let mut buf = itoa::Buffer::new();
                1 + buf.format(msg.len()).len() + 2 + msg.len() + 2 // !<len>\r\n<msg>\r\n
            }
            #[cfg(feature = "resp3")]
            Value::VerbatimString { data, .. } => {
                let mut buf = itoa::Buffer::new();
                // =<len>\r\n<fmt>:<data>\r\n where len = 3 + 1 + data.len()
                let total_len = 4 + data.len(); // "fmt:" (3 + 1) + data
                1 + buf.format(total_len).len() + 2 + total_len + 2
            }
            #[cfg(feature = "resp3")]
            Value::Map(entries) => {
                let mut buf = itoa::Buffer::new();
                let header_len = 1 + buf.format(entries.len()).len() + 2;
                header_len
                    + entries
                        .iter()
                        .map(|(k, v)| k.encoded_len() + v.encoded_len())
                        .sum::<usize>()
            }
            #[cfg(feature = "resp3")]
            Value::Set(elements) => {
                let mut buf = itoa::Buffer::new();
                let header_len = 1 + buf.format(elements.len()).len() + 2;
                header_len + elements.iter().map(|e| e.encoded_len()).sum::<usize>()
            }
            #[cfg(feature = "resp3")]
            Value::Push(elements) => {
                let mut buf = itoa::Buffer::new();
                let header_len = 1 + buf.format(elements.len()).len() + 2;
                header_len + elements.iter().map(|e| e.encoded_len()).sum::<usize>()
            }
            #[cfg(feature = "resp3")]
            Value::Attribute { attrs, value } => {
                let mut buf = itoa::Buffer::new();
                let header_len = 1 + buf.format(attrs.len()).len() + 2;
                let attrs_len = attrs
                    .iter()
                    .map(|(k, v)| k.encoded_len() + v.encoded_len())
                    .sum::<usize>();
                header_len + attrs_len + value.encoded_len()
            }
        }
    }

    /// Encode null value in RESP3 format: `_\r\n`
    #[cfg(feature = "resp3")]
    #[inline]
    pub fn encode_resp3_null(buf: &mut [u8]) -> usize {
        buf[..3].copy_from_slice(b"_\r\n");
        3
    }
}

// ============================================================================
// Parsing helpers
// ============================================================================

/// Find the position of \r\n in the data.
#[inline]
fn find_crlf(data: &[u8]) -> Option<usize> {
    memchr::memchr(b'\r', data).and_then(|pos| {
        if pos + 1 < data.len() && data[pos + 1] == b'\n' {
            Some(pos)
        } else {
            None
        }
    })
}

/// Parse a simple string: +OK\r\n
fn parse_simple_string(data: &[u8]) -> Result<(Value, usize), ParseError> {
    let end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let content = Bytes::copy_from_slice(&data[1..end]);
    Ok((Value::SimpleString(content), end + 2))
}

/// Parse an error: -ERR message\r\n
fn parse_error(data: &[u8]) -> Result<(Value, usize), ParseError> {
    let end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let content = Bytes::copy_from_slice(&data[1..end]);
    Ok((Value::Error(content), end + 2))
}

/// Parse an integer: :1000\r\n
fn parse_integer(data: &[u8]) -> Result<(Value, usize), ParseError> {
    let end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let s = std::str::from_utf8(&data[1..end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let value: i64 = s
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;
    Ok((Value::Integer(value), end + 2))
}

/// Parse a bulk string: $6\r\nfoobar\r\n or $-1\r\n
fn parse_bulk_string(data: &[u8], options: &ParseOptions) -> Result<(Value, usize), ParseError> {
    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: i64 = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len < 0 {
        // Null bulk string
        return Ok((Value::Null, len_end + 2));
    }

    let len = len as usize;
    if len > options.max_bulk_string_len {
        return Err(ParseError::Protocol("bulk string too large".to_string()));
    }

    let data_start = len_end + 2;
    let data_end = data_start
        .checked_add(len)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;
    let total_end = data_end
        .checked_add(2)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;

    if data.len() < total_end {
        return Err(ParseError::Incomplete);
    }

    // Verify trailing \r\n
    if data[data_end] != b'\r' || data[data_end + 1] != b'\n' {
        return Err(ParseError::Protocol("missing trailing CRLF".to_string()));
    }

    let content = Bytes::copy_from_slice(&data[data_start..data_end]);
    Ok((Value::BulkString(content), total_end))
}

/// Parse an array: *2\r\n...
fn parse_array(
    data: &[u8],
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: i64 = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len < 0 {
        // Null array (treated as null)
        return Ok((Value::Null, len_end + 2));
    }

    let len = len as usize;
    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    // Check total items budget (prevents exponential allocation attacks)
    *total_items = total_items
        .checked_add(len)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut elements = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let (value, consumed) =
            Value::parse_internal(&data[pos..], options, depth + 1, total_items)?;
        elements.push(value);
        pos += consumed;
    }

    Ok((Value::Array(elements), pos))
}

// ============================================================================
// Zero-copy (Bytes) parsing helpers
// ============================================================================

/// Parse a simple string zero-copy: +OK\r\n
fn parse_simple_string_bytes(data: &Bytes) -> Result<(Value, usize), ParseError> {
    let end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let content = data.slice(1..end);
    Ok((Value::SimpleString(content), end + 2))
}

/// Parse an error zero-copy: -ERR message\r\n
fn parse_error_bytes(data: &Bytes) -> Result<(Value, usize), ParseError> {
    let end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let content = data.slice(1..end);
    Ok((Value::Error(content), end + 2))
}

/// Parse a bulk string zero-copy: $6\r\nfoobar\r\n or $-1\r\n
fn parse_bulk_string_bytes(
    data: &Bytes,
    options: &ParseOptions,
) -> Result<(Value, usize), ParseError> {
    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: i64 = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len < 0 {
        return Ok((Value::Null, len_end + 2));
    }

    let len = len as usize;
    if len > options.max_bulk_string_len {
        return Err(ParseError::Protocol("bulk string too large".to_string()));
    }

    let data_start = len_end + 2;
    let data_end = data_start
        .checked_add(len)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;
    let total_end = data_end
        .checked_add(2)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;

    if data.len() < total_end {
        return Err(ParseError::Incomplete);
    }

    if data[data_end] != b'\r' || data[data_end + 1] != b'\n' {
        return Err(ParseError::Protocol("missing trailing CRLF".to_string()));
    }

    let content = data.slice(data_start..data_end);
    Ok((Value::BulkString(content), total_end))
}

/// Parse an array zero-copy: *2\r\n...
fn parse_array_bytes(
    data: &Bytes,
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: i64 = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len < 0 {
        return Ok((Value::Null, len_end + 2));
    }

    let len = len as usize;
    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    *total_items = total_items
        .checked_add(len)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut elements = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let sub = data.slice(pos..);
        let (value, consumed) = Value::parse_bytes_internal(&sub, options, depth + 1, total_items)?;
        elements.push(value);
        pos += consumed;
    }

    Ok((Value::Array(elements), pos))
}

/// Parse RESP3 big number zero-copy: (12345678901234567890\r\n
#[cfg(feature = "resp3")]
fn parse_big_number_bytes(data: &Bytes) -> Result<(Value, usize), ParseError> {
    let end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let content = data.slice(1..end);
    Ok((Value::BigNumber(content), end + 2))
}

/// Parse RESP3 bulk error zero-copy: !<len>\r\n<error>\r\n
#[cfg(feature = "resp3")]
fn parse_bulk_error_bytes(
    data: &Bytes,
    options: &ParseOptions,
) -> Result<(Value, usize), ParseError> {
    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_bulk_string_len {
        return Err(ParseError::Protocol("bulk error too large".to_string()));
    }

    let data_start = len_end + 2;
    let data_end = data_start
        .checked_add(len)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;
    let total_end = data_end
        .checked_add(2)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;

    if data.len() < total_end {
        return Err(ParseError::Incomplete);
    }

    if data[data_end] != b'\r' || data[data_end + 1] != b'\n' {
        return Err(ParseError::Protocol("missing trailing CRLF".to_string()));
    }

    let content = data.slice(data_start..data_end);
    Ok((Value::BulkError(content), total_end))
}

/// Parse RESP3 verbatim string zero-copy: =<len>\r\ntxt:<data>\r\n
#[cfg(feature = "resp3")]
fn parse_verbatim_string_bytes(
    data: &Bytes,
    options: &ParseOptions,
) -> Result<(Value, usize), ParseError> {
    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_bulk_string_len {
        return Err(ParseError::Protocol(
            "verbatim string too large".to_string(),
        ));
    }

    let data_start = len_end + 2;
    let data_end = data_start
        .checked_add(len)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;
    let total_end = data_end
        .checked_add(2)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;

    if data.len() < total_end {
        return Err(ParseError::Incomplete);
    }

    if len < 4 || data[data_start + 3] != b':' {
        return Err(ParseError::InvalidVerbatimFormat);
    }

    if data[data_end] != b'\r' || data[data_end + 1] != b'\n' {
        return Err(ParseError::Protocol("missing trailing CRLF".to_string()));
    }

    let format: [u8; 3] = data[data_start..data_start + 3]
        .try_into()
        .map_err(|_| ParseError::InvalidVerbatimFormat)?;
    let content = data.slice(data_start + 4..data_end);

    Ok((
        Value::VerbatimString {
            format,
            data: content,
        },
        total_end,
    ))
}

/// Parse RESP3 map zero-copy: %<len>\r\n<key><val>...
#[cfg(feature = "resp3")]
fn parse_map_bytes(
    data: &Bytes,
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    let items_to_add = len
        .checked_mul(2)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    *total_items = total_items
        .checked_add(items_to_add)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut entries = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let sub = data.slice(pos..);
        let (key, key_consumed) =
            Value::parse_bytes_internal(&sub, options, depth + 1, total_items)?;
        pos += key_consumed;

        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let sub = data.slice(pos..);
        let (value, val_consumed) =
            Value::parse_bytes_internal(&sub, options, depth + 1, total_items)?;
        pos += val_consumed;

        entries.push((key, value));
    }

    Ok((Value::Map(entries), pos))
}

/// Parse RESP3 set zero-copy: ~<len>\r\n<elem>...
#[cfg(feature = "resp3")]
fn parse_set_bytes(
    data: &Bytes,
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    *total_items = total_items
        .checked_add(len)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut elements = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let sub = data.slice(pos..);
        let (value, consumed) = Value::parse_bytes_internal(&sub, options, depth + 1, total_items)?;
        elements.push(value);
        pos += consumed;
    }

    Ok((Value::Set(elements), pos))
}

/// Parse RESP3 push message zero-copy: ><len>\r\n<elem>...
#[cfg(feature = "resp3")]
fn parse_push_bytes(
    data: &Bytes,
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    *total_items = total_items
        .checked_add(len)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut elements = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let sub = data.slice(pos..);
        let (value, consumed) = Value::parse_bytes_internal(&sub, options, depth + 1, total_items)?;
        elements.push(value);
        pos += consumed;
    }

    Ok((Value::Push(elements), pos))
}

/// Parse RESP3 attribute zero-copy: |<len>\r\n<attrs>...<value>
#[cfg(feature = "resp3")]
fn parse_attribute_bytes(
    data: &Bytes,
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    let items_to_add = len
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    *total_items = total_items
        .checked_add(items_to_add)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut attrs = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let sub = data.slice(pos..);
        let (key, key_consumed) =
            Value::parse_bytes_internal(&sub, options, depth + 1, total_items)?;
        pos += key_consumed;

        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let sub = data.slice(pos..);
        let (val, val_consumed) =
            Value::parse_bytes_internal(&sub, options, depth + 1, total_items)?;
        pos += val_consumed;

        attrs.push((key, val));
    }

    if pos >= data.len() {
        return Err(ParseError::Incomplete);
    }
    let sub = data.slice(pos..);
    let (value, val_consumed) = Value::parse_bytes_internal(&sub, options, depth + 1, total_items)?;
    pos += val_consumed;

    Ok((
        Value::Attribute {
            attrs,
            value: Box::new(value),
        },
        pos,
    ))
}

// ============================================================================
// Encoding helpers
// ============================================================================

/// Encode a simple string: +<data>\r\n
fn encode_simple_string(buf: &mut [u8], s: &[u8]) -> usize {
    buf[0] = b'+';
    buf[1..1 + s.len()].copy_from_slice(s);
    buf[1 + s.len()] = b'\r';
    buf[2 + s.len()] = b'\n';
    3 + s.len()
}

/// Encode an error: -<data>\r\n
fn encode_error(buf: &mut [u8], msg: &[u8]) -> usize {
    buf[0] = b'-';
    buf[1..1 + msg.len()].copy_from_slice(msg);
    buf[1 + msg.len()] = b'\r';
    buf[2 + msg.len()] = b'\n';
    3 + msg.len()
}

/// Encode an integer: :<n>\r\n
fn encode_integer(buf: &mut [u8], n: i64) -> usize {
    buf[0] = b':';
    let mut cursor = std::io::Cursor::new(&mut buf[1..]);
    write!(cursor, "{}\r\n", n).unwrap();
    1 + cursor.position() as usize
}

/// Encode a bulk string: $<len>\r\n<data>\r\n
fn encode_bulk_string(buf: &mut [u8], data: &[u8]) -> usize {
    buf[0] = b'$';
    let mut cursor = std::io::Cursor::new(&mut buf[1..]);
    write!(cursor, "{}\r\n", data.len()).unwrap();
    let header_len = 1 + cursor.position() as usize;

    buf[header_len..header_len + data.len()].copy_from_slice(data);
    buf[header_len + data.len()] = b'\r';
    buf[header_len + data.len() + 1] = b'\n';
    header_len + data.len() + 2
}

/// Encode null (RESP2 format): $-1\r\n
fn encode_resp2_null(buf: &mut [u8]) -> usize {
    buf[..5].copy_from_slice(b"$-1\r\n");
    5
}

/// Encode an array: *<len>\r\n<elements>
fn encode_array(buf: &mut [u8], elements: &[Value]) -> usize {
    buf[0] = b'*';
    let mut cursor = std::io::Cursor::new(&mut buf[1..]);
    write!(cursor, "{}\r\n", elements.len()).unwrap();
    let mut pos = 1 + cursor.position() as usize;

    for element in elements {
        pos += element.encode(&mut buf[pos..]);
    }
    pos
}

// ============================================================================
// RESP3 Parsing helpers
// ============================================================================

/// Parse RESP3 null: _\r\n
#[cfg(feature = "resp3")]
fn parse_null(data: &[u8]) -> Result<(Value, usize), ParseError> {
    if data.len() < 3 {
        return Err(ParseError::Incomplete);
    }
    if data[1] != b'\r' || data[2] != b'\n' {
        return Err(ParseError::Protocol("expected CRLF after null".to_string()));
    }
    Ok((Value::Null, 3))
}

/// Parse RESP3 boolean: #t\r\n or #f\r\n
#[cfg(feature = "resp3")]
fn parse_boolean(data: &[u8]) -> Result<(Value, usize), ParseError> {
    if data.len() < 4 {
        return Err(ParseError::Incomplete);
    }
    let value = match data[1] {
        b't' => true,
        b'f' => false,
        _ => return Err(ParseError::InvalidBoolean),
    };
    if data[2] != b'\r' || data[3] != b'\n' {
        return Err(ParseError::Protocol(
            "expected CRLF after boolean".to_string(),
        ));
    }
    Ok((Value::Boolean(value), 4))
}

/// Parse RESP3 double: ,3.14159\r\n
#[cfg(feature = "resp3")]
fn parse_double(data: &[u8]) -> Result<(Value, usize), ParseError> {
    let end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let s =
        std::str::from_utf8(&data[1..end]).map_err(|e| ParseError::InvalidDouble(e.to_string()))?;

    // Handle special values
    let value = match s {
        "inf" => f64::INFINITY,
        "-inf" => f64::NEG_INFINITY,
        "nan" => f64::NAN,
        _ => s
            .parse()
            .map_err(|e: std::num::ParseFloatError| ParseError::InvalidDouble(e.to_string()))?,
    };
    Ok((Value::Double(value), end + 2))
}

/// Parse RESP3 big number: (12345678901234567890\r\n
#[cfg(feature = "resp3")]
fn parse_big_number(data: &[u8]) -> Result<(Value, usize), ParseError> {
    let end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let content = Bytes::copy_from_slice(&data[1..end]);
    Ok((Value::BigNumber(content), end + 2))
}

/// Parse RESP3 bulk error: !<len>\r\n<error>\r\n
#[cfg(feature = "resp3")]
fn parse_bulk_error(data: &[u8], options: &ParseOptions) -> Result<(Value, usize), ParseError> {
    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_bulk_string_len {
        return Err(ParseError::Protocol("bulk error too large".to_string()));
    }

    let data_start = len_end + 2;
    let data_end = data_start
        .checked_add(len)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;
    let total_end = data_end
        .checked_add(2)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;

    if data.len() < total_end {
        return Err(ParseError::Incomplete);
    }

    if data[data_end] != b'\r' || data[data_end + 1] != b'\n' {
        return Err(ParseError::Protocol("missing trailing CRLF".to_string()));
    }

    let content = Bytes::copy_from_slice(&data[data_start..data_end]);
    Ok((Value::BulkError(content), total_end))
}

/// Parse RESP3 verbatim string: =<len>\r\ntxt:<data>\r\n
#[cfg(feature = "resp3")]
fn parse_verbatim_string(
    data: &[u8],
    options: &ParseOptions,
) -> Result<(Value, usize), ParseError> {
    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_bulk_string_len {
        return Err(ParseError::Protocol(
            "verbatim string too large".to_string(),
        ));
    }

    let data_start = len_end + 2;
    let data_end = data_start
        .checked_add(len)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;
    let total_end = data_end
        .checked_add(2)
        .ok_or_else(|| ParseError::InvalidInteger("length overflow".to_string()))?;

    if data.len() < total_end {
        return Err(ParseError::Incomplete);
    }

    // Format is: fmt:data where fmt is 3 bytes
    if len < 4 || data[data_start + 3] != b':' {
        return Err(ParseError::InvalidVerbatimFormat);
    }

    if data[data_end] != b'\r' || data[data_end + 1] != b'\n' {
        return Err(ParseError::Protocol("missing trailing CRLF".to_string()));
    }

    let format: [u8; 3] = data[data_start..data_start + 3]
        .try_into()
        .map_err(|_| ParseError::InvalidVerbatimFormat)?;
    let content = Bytes::copy_from_slice(&data[data_start + 4..data_end]);

    Ok((
        Value::VerbatimString {
            format,
            data: content,
        },
        total_end,
    ))
}

/// Parse RESP3 map: %<len>\r\n<key><val>...
#[cfg(feature = "resp3")]
fn parse_map(
    data: &[u8],
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    // Check total items budget (map entries count as 2 items each: key + value)
    let items_to_add = len
        .checked_mul(2)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    *total_items = total_items
        .checked_add(items_to_add)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut entries = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let (key, key_consumed) =
            Value::parse_internal(&data[pos..], options, depth + 1, total_items)?;
        pos += key_consumed;

        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let (value, val_consumed) =
            Value::parse_internal(&data[pos..], options, depth + 1, total_items)?;
        pos += val_consumed;

        entries.push((key, value));
    }

    Ok((Value::Map(entries), pos))
}

/// Parse RESP3 set: ~<len>\r\n<elem>...
#[cfg(feature = "resp3")]
fn parse_set(
    data: &[u8],
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    // Check total items budget
    *total_items = total_items
        .checked_add(len)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut elements = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let (value, consumed) =
            Value::parse_internal(&data[pos..], options, depth + 1, total_items)?;
        elements.push(value);
        pos += consumed;
    }

    Ok((Value::Set(elements), pos))
}

/// Parse RESP3 push message: ><len>\r\n<elem>...
#[cfg(feature = "resp3")]
fn parse_push(
    data: &[u8],
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    // Check total items budget
    *total_items = total_items
        .checked_add(len)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut elements = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let (value, consumed) =
            Value::parse_internal(&data[pos..], options, depth + 1, total_items)?;
        elements.push(value);
        pos += consumed;
    }

    Ok((Value::Push(elements), pos))
}

/// Parse RESP3 attribute: |<len>\r\n<attrs>...<value>
#[cfg(feature = "resp3")]
fn parse_attribute(
    data: &[u8],
    options: &ParseOptions,
    depth: usize,
    total_items: &mut usize,
) -> Result<(Value, usize), ParseError> {
    if depth >= options.max_depth {
        return Err(ParseError::NestingTooDeep(depth));
    }

    let len_end = find_crlf(data).ok_or(ParseError::Incomplete)?;
    let len_str = std::str::from_utf8(&data[1..len_end])
        .map_err(|e| ParseError::InvalidInteger(e.to_string()))?;
    let len: usize = len_str
        .parse()
        .map_err(|e: std::num::ParseIntError| ParseError::InvalidInteger(e.to_string()))?;

    if len > options.max_collection_elements {
        return Err(ParseError::CollectionTooLarge(len));
    }

    // Check total items budget (attribute entries count as 2 items each: key + value, plus 1 for the value)
    let items_to_add = len
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    *total_items = total_items
        .checked_add(items_to_add)
        .ok_or(ParseError::CollectionTooLarge(usize::MAX))?;
    if *total_items > options.max_total_items {
        return Err(ParseError::CollectionTooLarge(*total_items));
    }

    let mut pos = len_end + 2;
    let mut attrs = Vec::with_capacity(len);

    for _ in 0..len {
        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let (key, key_consumed) =
            Value::parse_internal(&data[pos..], options, depth + 1, total_items)?;
        pos += key_consumed;

        if pos >= data.len() {
            return Err(ParseError::Incomplete);
        }
        let (val, val_consumed) =
            Value::parse_internal(&data[pos..], options, depth + 1, total_items)?;
        pos += val_consumed;

        attrs.push((key, val));
    }

    // Parse the actual value that follows the attributes
    if pos >= data.len() {
        return Err(ParseError::Incomplete);
    }
    let (value, val_consumed) =
        Value::parse_internal(&data[pos..], options, depth + 1, total_items)?;
    pos += val_consumed;

    Ok((
        Value::Attribute {
            attrs,
            value: Box::new(value),
        },
        pos,
    ))
}

// ============================================================================
// RESP3 Encoding helpers
// ============================================================================

/// Encode RESP3 boolean: #t\r\n or #f\r\n
#[cfg(feature = "resp3")]
fn encode_boolean(buf: &mut [u8], b: bool) -> usize {
    buf[0] = b'#';
    buf[1] = if b { b't' } else { b'f' };
    buf[2] = b'\r';
    buf[3] = b'\n';
    4
}

/// Encode RESP3 double: ,<float>\r\n
#[cfg(feature = "resp3")]
fn encode_double(buf: &mut [u8], d: f64) -> usize {
    buf[0] = b',';
    let s = if d.is_infinite() {
        if d.is_sign_positive() { "inf" } else { "-inf" }
    } else if d.is_nan() {
        "nan"
    } else {
        // Use ryu for efficient float formatting
        let mut ryu_buf = ryu::Buffer::new();
        let formatted = ryu_buf.format(d);
        buf[1..1 + formatted.len()].copy_from_slice(formatted.as_bytes());
        buf[1 + formatted.len()] = b'\r';
        buf[2 + formatted.len()] = b'\n';
        return 3 + formatted.len();
    };
    buf[1..1 + s.len()].copy_from_slice(s.as_bytes());
    buf[1 + s.len()] = b'\r';
    buf[2 + s.len()] = b'\n';
    3 + s.len()
}

/// Encode RESP3 big number: (<num>\r\n
#[cfg(feature = "resp3")]
fn encode_big_number(buf: &mut [u8], n: &[u8]) -> usize {
    buf[0] = b'(';
    buf[1..1 + n.len()].copy_from_slice(n);
    buf[1 + n.len()] = b'\r';
    buf[2 + n.len()] = b'\n';
    3 + n.len()
}

/// Encode RESP3 bulk error: !<len>\r\n<msg>\r\n
#[cfg(feature = "resp3")]
fn encode_bulk_error(buf: &mut [u8], msg: &[u8]) -> usize {
    buf[0] = b'!';
    let mut cursor = std::io::Cursor::new(&mut buf[1..]);
    write!(cursor, "{}\r\n", msg.len()).unwrap();
    let header_len = 1 + cursor.position() as usize;

    buf[header_len..header_len + msg.len()].copy_from_slice(msg);
    buf[header_len + msg.len()] = b'\r';
    buf[header_len + msg.len() + 1] = b'\n';
    header_len + msg.len() + 2
}

/// Encode RESP3 verbatim string: =<len>\r\n<fmt>:<data>\r\n
#[cfg(feature = "resp3")]
fn encode_verbatim_string(buf: &mut [u8], format: &[u8; 3], data: &[u8]) -> usize {
    buf[0] = b'=';
    let total_len = 4 + data.len(); // "fmt:" + data
    let mut cursor = std::io::Cursor::new(&mut buf[1..]);
    write!(cursor, "{}\r\n", total_len).unwrap();
    let header_len = 1 + cursor.position() as usize;

    buf[header_len..header_len + 3].copy_from_slice(format);
    buf[header_len + 3] = b':';
    buf[header_len + 4..header_len + 4 + data.len()].copy_from_slice(data);
    buf[header_len + 4 + data.len()] = b'\r';
    buf[header_len + 5 + data.len()] = b'\n';
    header_len + 6 + data.len()
}

/// Encode RESP3 map: %<len>\r\n<key><val>...
#[cfg(feature = "resp3")]
fn encode_map(buf: &mut [u8], entries: &[(Value, Value)]) -> usize {
    buf[0] = b'%';
    let mut cursor = std::io::Cursor::new(&mut buf[1..]);
    write!(cursor, "{}\r\n", entries.len()).unwrap();
    let mut pos = 1 + cursor.position() as usize;

    for (key, value) in entries {
        pos += key.encode(&mut buf[pos..]);
        pos += value.encode(&mut buf[pos..]);
    }
    pos
}

/// Encode RESP3 set: ~<len>\r\n<elem>...
#[cfg(feature = "resp3")]
fn encode_set(buf: &mut [u8], elements: &[Value]) -> usize {
    buf[0] = b'~';
    let mut cursor = std::io::Cursor::new(&mut buf[1..]);
    write!(cursor, "{}\r\n", elements.len()).unwrap();
    let mut pos = 1 + cursor.position() as usize;

    for element in elements {
        pos += element.encode(&mut buf[pos..]);
    }
    pos
}

/// Encode RESP3 push: ><len>\r\n<elem>...
#[cfg(feature = "resp3")]
fn encode_push(buf: &mut [u8], elements: &[Value]) -> usize {
    buf[0] = b'>';
    let mut cursor = std::io::Cursor::new(&mut buf[1..]);
    write!(cursor, "{}\r\n", elements.len()).unwrap();
    let mut pos = 1 + cursor.position() as usize;

    for element in elements {
        pos += element.encode(&mut buf[pos..]);
    }
    pos
}

/// Encode RESP3 attribute: |<len>\r\n<attrs>...<value>
#[cfg(feature = "resp3")]
fn encode_attribute(buf: &mut [u8], attrs: &[(Value, Value)], value: &Value) -> usize {
    buf[0] = b'|';
    let mut cursor = std::io::Cursor::new(&mut buf[1..]);
    write!(cursor, "{}\r\n", attrs.len()).unwrap();
    let mut pos = 1 + cursor.position() as usize;

    for (key, val) in attrs {
        pos += key.encode(&mut buf[pos..]);
        pos += val.encode(&mut buf[pos..]);
    }
    pos += value.encode(&mut buf[pos..]);
    pos
}

// ============================================================================
// Common response values (for server use)
// ============================================================================

impl Value {
    /// OK simple string response.
    pub const OK: &'static [u8] = b"+OK\r\n";

    /// PONG simple string response.
    pub const PONG: &'static [u8] = b"+PONG\r\n";

    /// Null bulk string response.
    pub const NULL_BULK: &'static [u8] = b"$-1\r\n";

    /// Empty array response.
    pub const EMPTY_ARRAY: &'static [u8] = b"*0\r\n";

    /// Encode an OK response directly to a buffer.
    #[inline]
    pub fn encode_ok(buf: &mut [u8]) -> usize {
        buf[..5].copy_from_slice(Self::OK);
        5
    }

    /// Encode a PONG response directly to a buffer.
    #[inline]
    pub fn encode_pong(buf: &mut [u8]) -> usize {
        buf[..7].copy_from_slice(Self::PONG);
        7
    }

    /// Encode a null bulk string response directly to a buffer.
    #[inline]
    pub fn encode_null_bulk(buf: &mut [u8]) -> usize {
        buf[..5].copy_from_slice(Self::NULL_BULK);
        5
    }

    /// Encode an integer response directly to a buffer.
    #[inline]
    pub fn encode_int(buf: &mut [u8], n: i64) -> usize {
        encode_integer(buf, n)
    }

    /// Encode a bulk string response directly to a buffer (zero-copy for data).
    #[inline]
    pub fn encode_bulk(buf: &mut [u8], data: &[u8]) -> usize {
        encode_bulk_string(buf, data)
    }

    /// Encode an error response directly to a buffer.
    #[inline]
    pub fn encode_err(buf: &mut [u8], msg: &[u8]) -> usize {
        encode_error(buf, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_string() {
        let (value, consumed) = Value::parse(b"+OK\r\n").unwrap();
        assert_eq!(value, Value::SimpleString(Bytes::from_static(b"OK")));
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_parse_error() {
        let (value, consumed) = Value::parse(b"-ERR unknown command\r\n").unwrap();
        assert_eq!(
            value,
            Value::Error(Bytes::from_static(b"ERR unknown command"))
        );
        assert_eq!(consumed, 22);
    }

    #[test]
    fn test_parse_integer() {
        let (value, consumed) = Value::parse(b":1000\r\n").unwrap();
        assert_eq!(value, Value::Integer(1000));
        assert_eq!(consumed, 7);

        let (value, _) = Value::parse(b":-42\r\n").unwrap();
        assert_eq!(value, Value::Integer(-42));
    }

    #[test]
    fn test_parse_bulk_string() {
        let (value, consumed) = Value::parse(b"$6\r\nfoobar\r\n").unwrap();
        assert_eq!(value, Value::BulkString(Bytes::from_static(b"foobar")));
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_null() {
        let (value, consumed) = Value::parse(b"$-1\r\n").unwrap();
        assert_eq!(value, Value::Null);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_parse_array() {
        let (value, consumed) = Value::parse(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n").unwrap();
        assert_eq!(
            value,
            Value::Array(vec![
                Value::BulkString(Bytes::from_static(b"foo")),
                Value::BulkString(Bytes::from_static(b"bar")),
            ])
        );
        assert_eq!(consumed, 22);
    }

    #[test]
    fn test_parse_empty_array() {
        let (value, consumed) = Value::parse(b"*0\r\n").unwrap();
        assert_eq!(value, Value::Array(vec![]));
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_parse_incomplete() {
        assert!(matches!(
            Value::parse(b"$6\r\nfoo"),
            Err(ParseError::Incomplete)
        ));
        assert!(matches!(Value::parse(b"+OK"), Err(ParseError::Incomplete)));
        assert!(matches!(Value::parse(b""), Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_encode_simple_string() {
        let mut buf = [0u8; 64];
        let len = Value::simple_string(b"OK").encode(&mut buf);
        assert_eq!(&buf[..len], b"+OK\r\n");
    }

    #[test]
    fn test_encode_error() {
        let mut buf = [0u8; 64];
        let len = Value::error(b"ERR unknown").encode(&mut buf);
        assert_eq!(&buf[..len], b"-ERR unknown\r\n");
    }

    #[test]
    fn test_encode_integer() {
        let mut buf = [0u8; 64];
        let len = Value::integer(42).encode(&mut buf);
        assert_eq!(&buf[..len], b":42\r\n");

        let len = Value::integer(-100).encode(&mut buf);
        assert_eq!(&buf[..len], b":-100\r\n");
    }

    #[test]
    fn test_encode_bulk_string() {
        let mut buf = [0u8; 64];
        let len = Value::bulk_string(b"hello").encode(&mut buf);
        assert_eq!(&buf[..len], b"$5\r\nhello\r\n");
    }

    #[test]
    fn test_encode_null() {
        let mut buf = [0u8; 64];
        let len = Value::null().encode(&mut buf);
        assert_eq!(&buf[..len], b"$-1\r\n");
    }

    #[test]
    fn test_encode_array() {
        let mut buf = [0u8; 64];
        let arr = Value::array(vec![Value::bulk_string(b"foo"), Value::bulk_string(b"bar")]);
        let len = arr.encode(&mut buf);
        assert_eq!(&buf[..len], b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n");
    }

    #[test]
    fn test_roundtrip() {
        let values = vec![
            Value::simple_string(b"OK"),
            Value::error(b"ERR test"),
            Value::integer(12345),
            Value::bulk_string(b"hello world"),
            Value::null(),
            Value::array(vec![
                Value::integer(1),
                Value::bulk_string(b"two"),
                Value::null(),
            ]),
        ];

        for original in values {
            let mut buf = [0u8; 256];
            let len = original.encode(&mut buf);
            let (parsed, consumed) = Value::parse(&buf[..len]).unwrap();
            assert_eq!(original, parsed);
            assert_eq!(len, consumed);
        }
    }

    #[test]
    fn test_encoded_len() {
        let values = vec![
            Value::simple_string(b"OK"),
            Value::error(b"ERR test"),
            Value::integer(12345),
            Value::bulk_string(b"hello world"),
            Value::null(),
            Value::array(vec![Value::integer(1), Value::bulk_string(b"two")]),
        ];

        for value in values {
            let mut buf = [0u8; 256];
            let actual_len = value.encode(&mut buf);
            assert_eq!(value.encoded_len(), actual_len);
        }
    }

    // ========================================================================
    // Type Check Tests
    // ========================================================================

    #[test]
    fn test_is_null() {
        assert!(Value::Null.is_null());
        assert!(!Value::integer(1).is_null());
    }

    #[test]
    fn test_is_error() {
        assert!(Value::error(b"ERR").is_error());
        assert!(!Value::simple_string(b"OK").is_error());
    }

    #[test]
    fn test_is_simple_string() {
        assert!(Value::simple_string(b"OK").is_simple_string());
        assert!(!Value::bulk_string(b"OK").is_simple_string());
    }

    #[test]
    fn test_is_bulk_string() {
        assert!(Value::bulk_string(b"data").is_bulk_string());
        assert!(!Value::simple_string(b"data").is_bulk_string());
    }

    #[test]
    fn test_is_integer() {
        assert!(Value::integer(42).is_integer());
        assert!(!Value::bulk_string(b"42").is_integer());
    }

    #[test]
    fn test_is_array() {
        assert!(Value::array(vec![]).is_array());
        assert!(!Value::null().is_array());
    }

    // ========================================================================
    // Accessor Tests
    // ========================================================================

    #[test]
    fn test_as_bytes() {
        assert_eq!(Value::simple_string(b"OK").as_bytes(), Some(&b"OK"[..]));
        assert_eq!(Value::bulk_string(b"data").as_bytes(), Some(&b"data"[..]));
        assert_eq!(Value::error(b"ERR").as_bytes(), Some(&b"ERR"[..]));
        assert_eq!(Value::integer(42).as_bytes(), None);
        assert_eq!(Value::null().as_bytes(), None);
    }

    #[test]
    fn test_as_integer() {
        assert_eq!(Value::integer(42).as_integer(), Some(42));
        assert_eq!(Value::integer(-100).as_integer(), Some(-100));
        assert_eq!(Value::bulk_string(b"42").as_integer(), None);
    }

    #[test]
    fn test_as_array() {
        let arr = Value::array(vec![Value::integer(1), Value::integer(2)]);
        assert_eq!(arr.as_array().map(|a| a.len()), Some(2));
        assert_eq!(Value::null().as_array(), None);
    }

    // ========================================================================
    // Static Response Tests
    // ========================================================================

    #[test]
    fn test_encode_ok() {
        let mut buf = [0u8; 16];
        let len = Value::encode_ok(&mut buf);
        assert_eq!(&buf[..len], b"+OK\r\n");
    }

    #[test]
    fn test_encode_pong() {
        let mut buf = [0u8; 16];
        let len = Value::encode_pong(&mut buf);
        assert_eq!(&buf[..len], b"+PONG\r\n");
    }

    #[test]
    fn test_encode_null_bulk() {
        let mut buf = [0u8; 16];
        let len = Value::encode_null_bulk(&mut buf);
        assert_eq!(&buf[..len], b"$-1\r\n");
    }

    #[test]
    fn test_encode_int() {
        let mut buf = [0u8; 32];
        let len = Value::encode_int(&mut buf, 42);
        assert_eq!(&buf[..len], b":42\r\n");

        let len = Value::encode_int(&mut buf, -100);
        assert_eq!(&buf[..len], b":-100\r\n");
    }

    #[test]
    fn test_encode_bulk() {
        let mut buf = [0u8; 32];
        let len = Value::encode_bulk(&mut buf, b"hello");
        assert_eq!(&buf[..len], b"$5\r\nhello\r\n");
    }

    #[test]
    fn test_encode_err() {
        let mut buf = [0u8; 64];
        let len = Value::encode_err(&mut buf, b"ERR unknown command");
        assert_eq!(&buf[..len], b"-ERR unknown command\r\n");
    }

    // ========================================================================
    // Static Constants Tests
    // ========================================================================

    #[test]
    fn test_static_constants() {
        assert_eq!(Value::OK, b"+OK\r\n");
        assert_eq!(Value::PONG, b"+PONG\r\n");
        assert_eq!(Value::NULL_BULK, b"$-1\r\n");
        assert_eq!(Value::EMPTY_ARRAY, b"*0\r\n");
    }

    // ========================================================================
    // Error Path Tests
    // ========================================================================

    #[test]
    fn test_parse_invalid_prefix() {
        // Use an invalid prefix byte
        let result = Value::parse(b"Q12345\r\n");
        assert!(matches!(result, Err(ParseError::InvalidPrefix(b'Q'))));
    }

    #[test]
    fn test_parse_bulk_string_missing_crlf() {
        // Bulk string without proper trailing CRLF (has wrong bytes after data)
        let result = Value::parse(b"$5\r\nhelloXY");
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_null_array() {
        // Null array (negative length)
        let (value, consumed) = Value::parse(b"*-1\r\n").unwrap();
        assert_eq!(value, Value::Null);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_parse_array_collection_too_large() {
        // Array claiming to have too many elements
        let result = Value::parse(b"*99999999\r\n");
        assert!(matches!(result, Err(ParseError::CollectionTooLarge(_))));
    }

    #[test]
    fn test_parse_nested_array() {
        // Array containing another array
        let data = b"*2\r\n*2\r\n:1\r\n:2\r\n*2\r\n:3\r\n:4\r\n";
        let (value, consumed) = Value::parse(data).unwrap();
        assert_eq!(
            value,
            Value::Array(vec![
                Value::Array(vec![Value::Integer(1), Value::Integer(2)]),
                Value::Array(vec![Value::Integer(3), Value::Integer(4)]),
            ])
        );
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_value_clone() {
        let v1 = Value::array(vec![Value::integer(1), Value::bulk_string(b"test")]);
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_value_debug() {
        let value = Value::integer(42);
        let debug_str = format!("{:?}", value);
        assert!(debug_str.contains("Integer"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_large_integer() {
        let (value, _) = Value::parse(b":9223372036854775807\r\n").unwrap();
        assert_eq!(value, Value::Integer(i64::MAX));

        let (value, _) = Value::parse(b":-9223372036854775808\r\n").unwrap();
        assert_eq!(value, Value::Integer(i64::MIN));
    }

    #[test]
    fn test_empty_bulk_string() {
        let (value, consumed) = Value::parse(b"$0\r\n\r\n").unwrap();
        assert_eq!(value, Value::BulkString(Bytes::new()));
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_binary_bulk_string() {
        // Bulk string with binary data including null bytes
        let (value, _) = Value::parse(b"$5\r\n\x00\x01\x02\x03\x04\r\n").unwrap();
        assert_eq!(
            value,
            Value::BulkString(Bytes::from_static(&[0, 1, 2, 3, 4]))
        );
    }

    // ========================================================================
    // RESP3 Tests
    // ========================================================================

    #[cfg(feature = "resp3")]
    mod resp3_tests {
        use super::*;

        #[test]
        fn test_parse_resp3_null() {
            let (value, consumed) = Value::parse(b"_\r\n").unwrap();
            assert_eq!(value, Value::Null);
            assert_eq!(consumed, 3);
        }

        #[test]
        fn test_parse_boolean() {
            let (value, consumed) = Value::parse(b"#t\r\n").unwrap();
            assert_eq!(value, Value::Boolean(true));
            assert_eq!(consumed, 4);

            let (value, consumed) = Value::parse(b"#f\r\n").unwrap();
            assert_eq!(value, Value::Boolean(false));
            assert_eq!(consumed, 4);
        }

        #[test]
        fn test_parse_double() {
            let (value, consumed) = Value::parse(b",1.23456\r\n").unwrap();
            if let Value::Double(d) = value {
                assert!((d - 1.23456).abs() < 0.00001);
            } else {
                panic!("Expected Double");
            }
            assert_eq!(consumed, 10);

            // Test special values
            let (value, _) = Value::parse(b",inf\r\n").unwrap();
            assert_eq!(value, Value::Double(f64::INFINITY));

            let (value, _) = Value::parse(b",-inf\r\n").unwrap();
            assert_eq!(value, Value::Double(f64::NEG_INFINITY));

            let (value, _) = Value::parse(b",nan\r\n").unwrap();
            if let Value::Double(d) = value {
                assert!(d.is_nan());
            } else {
                panic!("Expected Double");
            }
        }

        #[test]
        fn test_parse_big_number() {
            let (value, consumed) = Value::parse(b"(12345678901234567890\r\n").unwrap();
            assert_eq!(
                value,
                Value::BigNumber(Bytes::from_static(b"12345678901234567890"))
            );
            assert_eq!(consumed, 23);
        }

        #[test]
        fn test_parse_bulk_error() {
            let (value, consumed) = Value::parse(b"!21\r\nSYNTAX invalid syntax\r\n").unwrap();
            assert_eq!(
                value,
                Value::BulkError(Bytes::from_static(b"SYNTAX invalid syntax"))
            );
            assert_eq!(consumed, 28);
        }

        #[test]
        fn test_parse_verbatim_string() {
            let (value, consumed) = Value::parse(b"=15\r\ntxt:Hello World\r\n").unwrap();
            assert_eq!(
                value,
                Value::VerbatimString {
                    format: *b"txt",
                    data: Bytes::from_static(b"Hello World"),
                }
            );
            assert_eq!(consumed, 22);
        }

        #[test]
        fn test_parse_map() {
            // %2\r\n+first\r\n:1\r\n+second\r\n:2\r\n
            // = 4 + 8 + 4 + 9 + 4 = 29 bytes
            let (value, consumed) =
                Value::parse(b"%2\r\n+first\r\n:1\r\n+second\r\n:2\r\n").unwrap();
            assert_eq!(
                value,
                Value::Map(vec![
                    (
                        Value::SimpleString(Bytes::from_static(b"first")),
                        Value::Integer(1)
                    ),
                    (
                        Value::SimpleString(Bytes::from_static(b"second")),
                        Value::Integer(2)
                    ),
                ])
            );
            assert_eq!(consumed, 29);
        }

        #[test]
        fn test_parse_set() {
            // ~3\r\n:1\r\n:2\r\n:3\r\n = 4 + 4 + 4 + 4 = 16 bytes
            let (value, consumed) = Value::parse(b"~3\r\n:1\r\n:2\r\n:3\r\n").unwrap();
            assert_eq!(
                value,
                Value::Set(vec![
                    Value::Integer(1),
                    Value::Integer(2),
                    Value::Integer(3),
                ])
            );
            assert_eq!(consumed, 16);
        }

        #[test]
        fn test_parse_push() {
            let (value, consumed) = Value::parse(b">2\r\n+message\r\n+hello\r\n").unwrap();
            assert_eq!(
                value,
                Value::Push(vec![
                    Value::SimpleString(Bytes::from_static(b"message")),
                    Value::SimpleString(Bytes::from_static(b"hello")),
                ])
            );
            assert_eq!(consumed, 22);
        }

        #[test]
        fn test_parse_attribute() {
            // |1\r\n+key\r\n+value\r\n+actual\r\n
            // = 4 + 6 + 8 + 9 = 27 bytes
            let (value, consumed) = Value::parse(b"|1\r\n+key\r\n+value\r\n+actual\r\n").unwrap();
            assert_eq!(
                value,
                Value::Attribute {
                    attrs: vec![(
                        Value::SimpleString(Bytes::from_static(b"key")),
                        Value::SimpleString(Bytes::from_static(b"value"))
                    )],
                    value: Box::new(Value::SimpleString(Bytes::from_static(b"actual"))),
                }
            );
            assert_eq!(consumed, 27);
        }

        #[test]
        fn test_encode_boolean() {
            let mut buf = [0u8; 64];
            let len = Value::boolean(true).encode(&mut buf);
            assert_eq!(&buf[..len], b"#t\r\n");

            let len = Value::boolean(false).encode(&mut buf);
            assert_eq!(&buf[..len], b"#f\r\n");
        }

        #[test]
        fn test_encode_double() {
            let mut buf = [0u8; 64];
            let len = Value::double(1.5).encode(&mut buf);
            // ryu format may vary slightly, just check the structure
            assert_eq!(buf[0], b',');
            assert!(buf[len - 2] == b'\r' && buf[len - 1] == b'\n');

            // Test special values
            let len = Value::double(f64::INFINITY).encode(&mut buf);
            assert_eq!(&buf[..len], b",inf\r\n");

            let len = Value::double(f64::NEG_INFINITY).encode(&mut buf);
            assert_eq!(&buf[..len], b",-inf\r\n");
        }

        #[test]
        fn test_encode_big_number() {
            let mut buf = [0u8; 64];
            let len = Value::big_number(b"12345678901234567890").encode(&mut buf);
            assert_eq!(&buf[..len], b"(12345678901234567890\r\n");
        }

        #[test]
        fn test_encode_bulk_error() {
            let mut buf = [0u8; 64];
            let len = Value::bulk_error(b"SYNTAX error").encode(&mut buf);
            assert_eq!(&buf[..len], b"!12\r\nSYNTAX error\r\n");
        }

        #[test]
        fn test_encode_verbatim_string() {
            let mut buf = [0u8; 64];
            let len = Value::verbatim_string(*b"txt", b"Hello").encode(&mut buf);
            assert_eq!(&buf[..len], b"=9\r\ntxt:Hello\r\n");
        }

        #[test]
        fn test_encode_map() {
            let mut buf = [0u8; 64];
            let len =
                Value::map(vec![(Value::simple_string(b"a"), Value::integer(1))]).encode(&mut buf);
            assert_eq!(&buf[..len], b"%1\r\n+a\r\n:1\r\n");
        }

        #[test]
        fn test_encode_set() {
            let mut buf = [0u8; 64];
            let len = Value::set(vec![Value::integer(1), Value::integer(2)]).encode(&mut buf);
            assert_eq!(&buf[..len], b"~2\r\n:1\r\n:2\r\n");
        }

        #[test]
        fn test_encode_push() {
            let mut buf = [0u8; 64];
            let len = Value::push(vec![
                Value::simple_string(b"message"),
                Value::simple_string(b"hello"),
            ])
            .encode(&mut buf);
            assert_eq!(&buf[..len], b">2\r\n+message\r\n+hello\r\n");
        }

        #[test]
        fn test_resp3_roundtrip() {
            let values = vec![
                Value::boolean(true),
                Value::boolean(false),
                Value::double(3.5), // Use exact floats to avoid ryu formatting issues
                Value::double(100.0),
                Value::double(f64::INFINITY),
                Value::double(f64::NEG_INFINITY),
                Value::big_number(b"99999999999999999999"),
                Value::bulk_error(b"ERR something went wrong"),
                Value::verbatim_string(*b"txt", b"Hello World"),
                Value::map(vec![
                    (Value::simple_string(b"key1"), Value::integer(1)),
                    (Value::simple_string(b"key2"), Value::integer(2)),
                ]),
                Value::set(vec![
                    Value::integer(1),
                    Value::integer(2),
                    Value::integer(3),
                ]),
                Value::push(vec![
                    Value::simple_string(b"subscribe"),
                    Value::simple_string(b"channel"),
                ]),
            ];

            for original in values {
                let mut buf = [0u8; 512];
                let len = original.encode(&mut buf);
                let (parsed, consumed) = Value::parse(&buf[..len]).unwrap();
                // For Double, compare values directly since infinity is exact
                if let (Value::Double(d1), Value::Double(d2)) = (&original, &parsed) {
                    if d1.is_nan() {
                        assert!(d2.is_nan());
                    } else if d1.is_infinite() {
                        assert_eq!(d1, d2, "Infinities should be exactly equal");
                    } else {
                        // For finite doubles, use relative tolerance
                        let diff = (d1 - d2).abs();
                        let tolerance = d1.abs() * 1e-10;
                        assert!(diff <= tolerance, "Doubles differ: {} vs {}", d1, d2);
                    }
                } else {
                    assert_eq!(original, parsed);
                }
                assert_eq!(len, consumed);
            }
        }

        #[test]
        fn test_resp3_encoded_len() {
            let values = vec![
                Value::boolean(true),
                Value::double(1.23456),
                Value::big_number(b"12345"),
                Value::bulk_error(b"ERR test"),
                Value::verbatim_string(*b"txt", b"hello"),
                Value::map(vec![(Value::simple_string(b"a"), Value::integer(1))]),
                Value::set(vec![Value::integer(1), Value::integer(2)]),
                Value::push(vec![Value::simple_string(b"msg")]),
            ];

            for value in values {
                let mut buf = [0u8; 512];
                let actual_len = value.encode(&mut buf);
                assert_eq!(
                    value.encoded_len(),
                    actual_len,
                    "Length mismatch for {:?}",
                    value
                );
            }
        }
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_parse_cr_without_lf() {
        // Simple string with \r but not followed by \n
        let result = Value::parse(b"+OK\rX");
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_array_incomplete_elements() {
        // Array with 3 elements but only 2 provided
        let result = Value::parse(b"*3\r\n:1\r\n:2\r\n");
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_array_truncated_after_length() {
        // Array length parsed but no elements follow
        let result = Value::parse(b"*2\r\n");
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_bulk_string_truncated_content() {
        // Bulk string with length 10 but only 5 bytes of content
        let result = Value::parse(b"$10\r\nhello");
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_nested_array_incomplete() {
        // Outer array expects 2 elements, inner array is complete, second element missing
        let result = Value::parse(b"*2\r\n*1\r\n:1\r\n");
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_integer_no_crlf() {
        // Integer without terminating CRLF
        let result = Value::parse(b":12345");
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_error_no_crlf() {
        // Error without terminating CRLF
        let result = Value::parse(b"-ERR something");
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_simple_string_only_cr() {
        // Simple string with only \r at end (no \n)
        let result = Value::parse(b"+OK\r");
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    // ========================================================================
    // DoS Protection Tests
    // ========================================================================

    #[test]
    fn test_parse_bulk_string_too_large() {
        // Bulk string claiming to be larger than DEFAULT_MAX_BULK_STRING_LEN (512MB)
        // Use a length that's clearly over the limit
        let data = b"$536870913\r\n"; // 512MB + 1
        let result = Value::parse(data);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_parse_bulk_string_huge_length() {
        // Very large bulk string length
        let data = b"$99999999999999\r\n";
        let result = Value::parse(data);
        // Should fail with Protocol error (too large) or InvalidInteger (can't parse)
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_array_at_limit() {
        // Array at collection limit should work
        // We can't actually test 1M elements, but ensure the limit check exists
        let data = b"*1000001\r\n"; // Just over 1M
        let result = Value::parse(data);
        assert!(matches!(result, Err(ParseError::CollectionTooLarge(_))));
    }

    #[test]
    fn test_parse_integer_overflow_protection() {
        // Integer that would overflow i64
        let data = b":99999999999999999999\r\n";
        let result = Value::parse(data);
        assert!(matches!(result, Err(ParseError::InvalidInteger(_))));
    }

    #[test]
    fn test_custom_parse_options() {
        // Test with very restrictive custom options
        let options = ParseOptions::new()
            .max_collection_elements(2)
            .max_bulk_string_len(10);

        // Array at limit should work
        let data = b"*2\r\n:1\r\n:2\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(result.is_ok());

        // Array over limit should fail
        let data = b"*3\r\n:1\r\n:2\r\n:3\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(matches!(result, Err(ParseError::CollectionTooLarge(3))));

        // Bulk string at limit should work
        let data = b"$10\r\n0123456789\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(result.is_ok());

        // Bulk string over limit should fail
        let data = b"$11\r\n01234567890\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(matches!(result, Err(ParseError::Protocol(_))));
    }

    #[test]
    fn test_total_items_budget_flat_array() {
        // Total items budget prevents allocating too many items
        let options = ParseOptions::new()
            .max_collection_elements(100)
            .max_total_items(10);

        // 5 items is within budget
        let data = b"*5\r\n:1\r\n:2\r\n:3\r\n:4\r\n:5\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(result.is_ok());

        // 11 items exceeds total budget of 10
        let data = b"*11\r\n:1\r\n:2\r\n:3\r\n:4\r\n:5\r\n:6\r\n:7\r\n:8\r\n:9\r\n:10\r\n:11\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(matches!(result, Err(ParseError::CollectionTooLarge(_))));
    }

    #[test]
    fn test_total_items_budget_nested_arrays() {
        // Test that nested arrays accumulate against the total budget
        // This is the critical test for preventing exponential allocation attacks
        let options = ParseOptions::new()
            .max_collection_elements(100)
            .max_total_items(10)
            .max_depth(8);

        // Nested arrays: outer has 2 elements, each inner has 3 elements
        // Total items: 2 (outer) + 3 (first inner) + 3 (second inner) = 8
        let data = b"*2\r\n*3\r\n:1\r\n:2\r\n:3\r\n*3\r\n:4\r\n:5\r\n:6\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(result.is_ok());

        // Nested arrays that exceed total budget:
        // outer has 3 elements, each inner has 3 elements
        // Total items: 3 (outer) + 3 + 3 + 3 = 12 > 10
        let data =
            b"*3\r\n*3\r\n:1\r\n:2\r\n:3\r\n*3\r\n:4\r\n:5\r\n:6\r\n*3\r\n:7\r\n:8\r\n:9\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(matches!(result, Err(ParseError::CollectionTooLarge(_))));
    }

    #[test]
    fn test_nesting_depth_limit() {
        // Test that nesting depth is enforced
        let options = ParseOptions::new()
            .max_collection_elements(100)
            .max_total_items(1000)
            .max_depth(2);

        // Depth 1: single array (depth 0 at start, array at depth 1)
        let data = b"*1\r\n:1\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(result.is_ok());

        // Depth 2: nested array (outer at depth 1, inner at depth 2)
        let data = b"*1\r\n*1\r\n:1\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(result.is_ok());

        // Depth 3: exceeds max_depth of 2
        let data = b"*1\r\n*1\r\n*1\r\n:1\r\n";
        let result = Value::parse_with_options(data, &options);
        assert!(matches!(result, Err(ParseError::NestingTooDeep(_))));
    }

    #[test]
    fn test_exponential_attack_prevented() {
        // This test verifies that the total items budget prevents exponential
        // allocation attacks. Without the budget, this would try to allocate:
        // 100 * 100 * 100 = 1,000,000 items. With the budget, it fails early.
        let options = ParseOptions::new()
            .max_collection_elements(100)
            .max_total_items(1000)
            .max_depth(8);

        // Create a deeply nested structure where each level has 100 elements
        // Level 0: array of 100 elements
        // Level 1: first element is array of 100 elements
        // This alone is 100 + 100 = 200 items
        // If the first element's first element is also an array of 100...
        // We'd have 100 + 100 + 100 = 300 items
        // The budget prevents this from growing to 100^depth

        // Build: *100\r\n*100\r\n*100\r\n... (3 levels)
        let mut data = Vec::new();
        // Outer array: 100 elements (first is another array, rest are integers)
        data.extend_from_slice(b"*100\r\n");
        // Second level: 100 elements
        data.extend_from_slice(b"*100\r\n");
        // Third level: 100 elements
        data.extend_from_slice(b"*100\r\n");
        // Fill third level with integers
        for i in 0..100 {
            let s = format!(":{}\r\n", i);
            data.extend_from_slice(s.as_bytes());
        }
        // Fill rest of second level with integers (99 more)
        for i in 0..99 {
            let s = format!(":{}\r\n", i);
            data.extend_from_slice(s.as_bytes());
        }
        // Fill rest of first level with integers (99 more)
        for i in 0..99 {
            let s = format!(":{}\r\n", i);
            data.extend_from_slice(s.as_bytes());
        }

        let result = Value::parse_with_options(&data, &options);
        // Should fail because total items = 100 + 100 + 100 = 300 > 1000? No wait...
        // 100 + 100 + 100 = 300, which is less than 1000
        // But we set budget to 1000, so this should pass
        // Let me recalculate: we want to show it would fail with a smaller budget
        // Actually this test is fine - it shows that even with depth 8,
        // the total items budget (300) is tracked correctly
        assert!(result.is_ok());

        // Now test with a tighter budget that would fail
        let strict_options = ParseOptions::new()
            .max_collection_elements(100)
            .max_total_items(250) // Less than 300
            .max_depth(8);

        let result = Value::parse_with_options(&data, &strict_options);
        assert!(matches!(result, Err(ParseError::CollectionTooLarge(_))));
    }
}
