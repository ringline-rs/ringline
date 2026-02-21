//! Memcache binary protocol headers.
//!
//! The binary protocol uses fixed 24-byte headers for both requests and responses.
//! This module provides types for parsing and encoding these headers.

use crate::error::ParseError;

/// Magic byte for binary request packets.
pub const REQUEST_MAGIC: u8 = 0x80;

/// Magic byte for binary response packets.
pub const RESPONSE_MAGIC: u8 = 0x81;

/// Minimum header size for binary protocol.
pub const HEADER_SIZE: usize = 24;

/// Binary protocol opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Get = 0x00,
    Set = 0x01,
    Add = 0x02,
    Replace = 0x03,
    Delete = 0x04,
    Increment = 0x05,
    Decrement = 0x06,
    Quit = 0x07,
    Flush = 0x08,
    GetQ = 0x09,
    Noop = 0x0A,
    Version = 0x0B,
    GetK = 0x0C,
    GetKQ = 0x0D,
    Append = 0x0E,
    Prepend = 0x0F,
    Stat = 0x10,
    SetQ = 0x11,
    AddQ = 0x12,
    ReplaceQ = 0x13,
    DeleteQ = 0x14,
    IncrementQ = 0x15,
    DecrementQ = 0x16,
    QuitQ = 0x17,
    FlushQ = 0x18,
    AppendQ = 0x19,
    PrependQ = 0x1A,
    Touch = 0x1C,
    Gat = 0x1D,
    GatQ = 0x1E,
    GatK = 0x23,
    GatKQ = 0x24,
}

impl Opcode {
    /// Try to convert a byte to an opcode.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Opcode::Get),
            0x01 => Some(Opcode::Set),
            0x02 => Some(Opcode::Add),
            0x03 => Some(Opcode::Replace),
            0x04 => Some(Opcode::Delete),
            0x05 => Some(Opcode::Increment),
            0x06 => Some(Opcode::Decrement),
            0x07 => Some(Opcode::Quit),
            0x08 => Some(Opcode::Flush),
            0x09 => Some(Opcode::GetQ),
            0x0A => Some(Opcode::Noop),
            0x0B => Some(Opcode::Version),
            0x0C => Some(Opcode::GetK),
            0x0D => Some(Opcode::GetKQ),
            0x0E => Some(Opcode::Append),
            0x0F => Some(Opcode::Prepend),
            0x10 => Some(Opcode::Stat),
            0x11 => Some(Opcode::SetQ),
            0x12 => Some(Opcode::AddQ),
            0x13 => Some(Opcode::ReplaceQ),
            0x14 => Some(Opcode::DeleteQ),
            0x15 => Some(Opcode::IncrementQ),
            0x16 => Some(Opcode::DecrementQ),
            0x17 => Some(Opcode::QuitQ),
            0x18 => Some(Opcode::FlushQ),
            0x19 => Some(Opcode::AppendQ),
            0x1A => Some(Opcode::PrependQ),
            0x1C => Some(Opcode::Touch),
            0x1D => Some(Opcode::Gat),
            0x1E => Some(Opcode::GatQ),
            0x23 => Some(Opcode::GatK),
            0x24 => Some(Opcode::GatKQ),
            _ => None,
        }
    }

    /// Returns true if this is a "quiet" opcode (no response on success/miss).
    pub fn is_quiet(&self) -> bool {
        matches!(
            self,
            Opcode::GetQ
                | Opcode::GetKQ
                | Opcode::SetQ
                | Opcode::AddQ
                | Opcode::ReplaceQ
                | Opcode::DeleteQ
                | Opcode::IncrementQ
                | Opcode::DecrementQ
                | Opcode::QuitQ
                | Opcode::FlushQ
                | Opcode::AppendQ
                | Opcode::PrependQ
                | Opcode::GatQ
                | Opcode::GatKQ
        )
    }

    /// Returns the non-quiet version of this opcode.
    pub fn to_non_quiet(&self) -> Opcode {
        match self {
            Opcode::GetQ => Opcode::Get,
            Opcode::GetKQ => Opcode::GetK,
            Opcode::SetQ => Opcode::Set,
            Opcode::AddQ => Opcode::Add,
            Opcode::ReplaceQ => Opcode::Replace,
            Opcode::DeleteQ => Opcode::Delete,
            Opcode::IncrementQ => Opcode::Increment,
            Opcode::DecrementQ => Opcode::Decrement,
            Opcode::QuitQ => Opcode::Quit,
            Opcode::FlushQ => Opcode::Flush,
            Opcode::AppendQ => Opcode::Append,
            Opcode::PrependQ => Opcode::Prepend,
            Opcode::GatQ => Opcode::Gat,
            Opcode::GatKQ => Opcode::GatK,
            other => *other,
        }
    }
}

/// Response status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Status {
    NoError = 0x0000,
    KeyNotFound = 0x0001,
    KeyExists = 0x0002,
    ValueTooLarge = 0x0003,
    InvalidArguments = 0x0004,
    ItemNotStored = 0x0005,
    NonNumericValue = 0x0006,
    WrongVbucket = 0x0007,
    AuthError = 0x0008,
    AuthContinue = 0x0009,
    UnknownCommand = 0x0081,
    OutOfMemory = 0x0082,
    NotSupported = 0x0083,
    InternalError = 0x0084,
    Busy = 0x0085,
    TempFailure = 0x0086,
}

impl Status {
    /// Try to convert a u16 to a status.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Status::NoError),
            0x0001 => Some(Status::KeyNotFound),
            0x0002 => Some(Status::KeyExists),
            0x0003 => Some(Status::ValueTooLarge),
            0x0004 => Some(Status::InvalidArguments),
            0x0005 => Some(Status::ItemNotStored),
            0x0006 => Some(Status::NonNumericValue),
            0x0007 => Some(Status::WrongVbucket),
            0x0008 => Some(Status::AuthError),
            0x0009 => Some(Status::AuthContinue),
            0x0081 => Some(Status::UnknownCommand),
            0x0082 => Some(Status::OutOfMemory),
            0x0083 => Some(Status::NotSupported),
            0x0084 => Some(Status::InternalError),
            0x0085 => Some(Status::Busy),
            0x0086 => Some(Status::TempFailure),
            _ => None,
        }
    }

    /// Returns true if this status indicates success.
    pub fn is_success(&self) -> bool {
        *self == Status::NoError
    }

    /// Returns the status as a short description.
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::NoError => "No error",
            Status::KeyNotFound => "Key not found",
            Status::KeyExists => "Key exists",
            Status::ValueTooLarge => "Value too large",
            Status::InvalidArguments => "Invalid arguments",
            Status::ItemNotStored => "Item not stored",
            Status::NonNumericValue => "Incr/Decr on non-numeric value",
            Status::WrongVbucket => "Wrong vbucket",
            Status::AuthError => "Authentication error",
            Status::AuthContinue => "Authentication continue",
            Status::UnknownCommand => "Unknown command",
            Status::OutOfMemory => "Out of memory",
            Status::NotSupported => "Not supported",
            Status::InternalError => "Internal error",
            Status::Busy => "Busy",
            Status::TempFailure => "Temporary failure",
        }
    }
}

/// Binary protocol request header (24 bytes).
///
/// Format:
/// ```text
/// Byte/     0       |       1       |       2       |       3       |
///    /              |               |               |               |
///   |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///   +---------------+---------------+---------------+---------------+
///  0| Magic         | Opcode        | Key length                    |
///   +---------------+---------------+---------------+---------------+
///  4| Extras length | Data type     | vbucket id                    |
///   +---------------+---------------+---------------+---------------+
///  8| Total body length                                             |
///   +---------------+---------------+---------------+---------------+
/// 12| Opaque                                                        |
///   +---------------+---------------+---------------+---------------+
/// 16| CAS                                                           |
///   |                                                               |
///   +---------------+---------------+---------------+---------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHeader {
    /// Magic byte (should be REQUEST_MAGIC)
    pub magic: u8,
    /// Command opcode
    pub opcode: Opcode,
    /// Key length in bytes
    pub key_length: u16,
    /// Length of extras (flags, expiration, etc.)
    pub extras_length: u8,
    /// Data type (reserved, should be 0)
    pub data_type: u8,
    /// Virtual bucket ID (reserved, usually 0)
    pub vbucket_id: u16,
    /// Total body length = extras_length + key_length + value_length
    pub total_body_length: u32,
    /// Opaque value (passed back in response)
    pub opaque: u32,
    /// CAS value for compare-and-swap operations
    pub cas: u64,
}

impl RequestHeader {
    /// Create a new request header.
    pub fn new(opcode: Opcode) -> Self {
        Self {
            magic: REQUEST_MAGIC,
            opcode,
            key_length: 0,
            extras_length: 0,
            data_type: 0,
            vbucket_id: 0,
            total_body_length: 0,
            opaque: 0,
            cas: 0,
        }
    }

    /// Parse a request header from a byte buffer.
    ///
    /// Returns the header and consumes HEADER_SIZE bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < HEADER_SIZE {
            return Err(ParseError::Incomplete);
        }

        if data[0] != REQUEST_MAGIC {
            return Err(ParseError::InvalidMagic(data[0]));
        }

        let opcode = Opcode::from_u8(data[1]).ok_or(ParseError::UnknownOpcode(data[1]))?;

        Ok(Self {
            magic: data[0],
            opcode,
            key_length: u16::from_be_bytes([data[2], data[3]]),
            extras_length: data[4],
            data_type: data[5],
            vbucket_id: u16::from_be_bytes([data[6], data[7]]),
            total_body_length: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            opaque: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            cas: u64::from_be_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]),
        })
    }

    /// Encode the header into a byte buffer.
    ///
    /// Returns HEADER_SIZE (24).
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        buf[0] = self.magic;
        buf[1] = self.opcode as u8;
        buf[2..4].copy_from_slice(&self.key_length.to_be_bytes());
        buf[4] = self.extras_length;
        buf[5] = self.data_type;
        buf[6..8].copy_from_slice(&self.vbucket_id.to_be_bytes());
        buf[8..12].copy_from_slice(&self.total_body_length.to_be_bytes());
        buf[12..16].copy_from_slice(&self.opaque.to_be_bytes());
        buf[16..24].copy_from_slice(&self.cas.to_be_bytes());
        HEADER_SIZE
    }

    /// Calculate the value length from the header fields.
    pub fn value_length(&self) -> usize {
        self.total_body_length as usize - self.extras_length as usize - self.key_length as usize
    }
}

/// Binary protocol response header (24 bytes).
///
/// The response header has the same layout as the request header,
/// but uses RESPONSE_MAGIC and has a status field instead of vbucket_id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    /// Magic byte (should be RESPONSE_MAGIC)
    pub magic: u8,
    /// Command opcode (echoed from request)
    pub opcode: Opcode,
    /// Key length in bytes (for GetK responses)
    pub key_length: u16,
    /// Length of extras (flags for GET responses)
    pub extras_length: u8,
    /// Data type (reserved, should be 0)
    pub data_type: u8,
    /// Response status
    pub status: Status,
    /// Total body length = extras_length + key_length + value_length
    pub total_body_length: u32,
    /// Opaque value (echoed from request)
    pub opaque: u32,
    /// CAS value
    pub cas: u64,
}

impl ResponseHeader {
    /// Create a new response header with the given opcode and status.
    pub fn new(opcode: Opcode, status: Status) -> Self {
        Self {
            magic: RESPONSE_MAGIC,
            opcode,
            key_length: 0,
            extras_length: 0,
            data_type: 0,
            status,
            total_body_length: 0,
            opaque: 0,
            cas: 0,
        }
    }

    /// Parse a response header from a byte buffer.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < HEADER_SIZE {
            return Err(ParseError::Incomplete);
        }

        if data[0] != RESPONSE_MAGIC {
            return Err(ParseError::InvalidMagic(data[0]));
        }

        let opcode = Opcode::from_u8(data[1]).ok_or(ParseError::UnknownOpcode(data[1]))?;

        let status_val = u16::from_be_bytes([data[6], data[7]]);
        let status = Status::from_u16(status_val).unwrap_or(Status::InternalError); // Default to InternalError for unknown statuses

        Ok(Self {
            magic: data[0],
            opcode,
            key_length: u16::from_be_bytes([data[2], data[3]]),
            extras_length: data[4],
            data_type: data[5],
            status,
            total_body_length: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            opaque: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            cas: u64::from_be_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]),
        })
    }

    /// Encode the header into a byte buffer.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        buf[0] = self.magic;
        buf[1] = self.opcode as u8;
        buf[2..4].copy_from_slice(&self.key_length.to_be_bytes());
        buf[4] = self.extras_length;
        buf[5] = self.data_type;
        buf[6..8].copy_from_slice(&(self.status as u16).to_be_bytes());
        buf[8..12].copy_from_slice(&self.total_body_length.to_be_bytes());
        buf[12..16].copy_from_slice(&self.opaque.to_be_bytes());
        buf[16..24].copy_from_slice(&self.cas.to_be_bytes());
        HEADER_SIZE
    }

    /// Calculate the value length from the header fields.
    pub fn value_length(&self) -> usize {
        self.total_body_length as usize - self.extras_length as usize - self.key_length as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_roundtrip() {
        for val in 0..=0xFF {
            if let Some(op) = Opcode::from_u8(val) {
                assert_eq!(op as u8, val);
            }
        }
    }

    #[test]
    fn test_status_roundtrip() {
        let statuses = [
            Status::NoError,
            Status::KeyNotFound,
            Status::KeyExists,
            Status::OutOfMemory,
        ];
        for status in statuses {
            assert_eq!(Status::from_u16(status as u16), Some(status));
        }
    }

    #[test]
    fn test_request_header_encode_parse() {
        let mut header = RequestHeader::new(Opcode::Get);
        header.key_length = 5;
        header.total_body_length = 5;
        header.opaque = 0x12345678;

        let mut buf = [0u8; 24];
        header.encode(&mut buf);

        let parsed = RequestHeader::parse(&buf).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_response_header_encode_parse() {
        let mut header = ResponseHeader::new(Opcode::Get, Status::NoError);
        header.key_length = 5;
        header.extras_length = 4;
        header.total_body_length = 13; // 4 extras + 5 key + 4 value
        header.opaque = 0xDEADBEEF;
        header.cas = 0x123456789ABCDEF0;

        let mut buf = [0u8; 24];
        header.encode(&mut buf);

        let parsed = ResponseHeader::parse(&buf).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_quiet_opcodes() {
        assert!(Opcode::GetQ.is_quiet());
        assert!(Opcode::SetQ.is_quiet());
        assert!(!Opcode::Get.is_quiet());
        assert!(!Opcode::Set.is_quiet());

        assert_eq!(Opcode::GetQ.to_non_quiet(), Opcode::Get);
        assert_eq!(Opcode::SetQ.to_non_quiet(), Opcode::Set);
    }

    #[test]
    fn test_value_length() {
        let mut header = RequestHeader::new(Opcode::Set);
        header.extras_length = 8;
        header.key_length = 10;
        header.total_body_length = 28; // 8 + 10 + 10 value
        assert_eq!(header.value_length(), 10);
    }

    // Additional tests for improved coverage

    #[test]
    fn test_all_opcodes_from_u8() {
        // Test all known opcodes
        assert_eq!(Opcode::from_u8(0x00), Some(Opcode::Get));
        assert_eq!(Opcode::from_u8(0x01), Some(Opcode::Set));
        assert_eq!(Opcode::from_u8(0x02), Some(Opcode::Add));
        assert_eq!(Opcode::from_u8(0x03), Some(Opcode::Replace));
        assert_eq!(Opcode::from_u8(0x04), Some(Opcode::Delete));
        assert_eq!(Opcode::from_u8(0x05), Some(Opcode::Increment));
        assert_eq!(Opcode::from_u8(0x06), Some(Opcode::Decrement));
        assert_eq!(Opcode::from_u8(0x07), Some(Opcode::Quit));
        assert_eq!(Opcode::from_u8(0x08), Some(Opcode::Flush));
        assert_eq!(Opcode::from_u8(0x09), Some(Opcode::GetQ));
        assert_eq!(Opcode::from_u8(0x0A), Some(Opcode::Noop));
        assert_eq!(Opcode::from_u8(0x0B), Some(Opcode::Version));
        assert_eq!(Opcode::from_u8(0x0C), Some(Opcode::GetK));
        assert_eq!(Opcode::from_u8(0x0D), Some(Opcode::GetKQ));
        assert_eq!(Opcode::from_u8(0x0E), Some(Opcode::Append));
        assert_eq!(Opcode::from_u8(0x0F), Some(Opcode::Prepend));
        assert_eq!(Opcode::from_u8(0x10), Some(Opcode::Stat));
        assert_eq!(Opcode::from_u8(0x11), Some(Opcode::SetQ));
        assert_eq!(Opcode::from_u8(0x12), Some(Opcode::AddQ));
        assert_eq!(Opcode::from_u8(0x13), Some(Opcode::ReplaceQ));
        assert_eq!(Opcode::from_u8(0x14), Some(Opcode::DeleteQ));
        assert_eq!(Opcode::from_u8(0x15), Some(Opcode::IncrementQ));
        assert_eq!(Opcode::from_u8(0x16), Some(Opcode::DecrementQ));
        assert_eq!(Opcode::from_u8(0x17), Some(Opcode::QuitQ));
        assert_eq!(Opcode::from_u8(0x18), Some(Opcode::FlushQ));
        assert_eq!(Opcode::from_u8(0x19), Some(Opcode::AppendQ));
        assert_eq!(Opcode::from_u8(0x1A), Some(Opcode::PrependQ));
        assert_eq!(Opcode::from_u8(0x1C), Some(Opcode::Touch));
        assert_eq!(Opcode::from_u8(0x1D), Some(Opcode::Gat));
        assert_eq!(Opcode::from_u8(0x1E), Some(Opcode::GatQ));
        assert_eq!(Opcode::from_u8(0x23), Some(Opcode::GatK));
        assert_eq!(Opcode::from_u8(0x24), Some(Opcode::GatKQ));
        // Unknown opcodes
        assert_eq!(Opcode::from_u8(0x1B), None);
        assert_eq!(Opcode::from_u8(0xFF), None);
    }

    #[test]
    fn test_all_quiet_opcodes() {
        // All quiet opcodes
        assert!(Opcode::GetQ.is_quiet());
        assert!(Opcode::GetKQ.is_quiet());
        assert!(Opcode::SetQ.is_quiet());
        assert!(Opcode::AddQ.is_quiet());
        assert!(Opcode::ReplaceQ.is_quiet());
        assert!(Opcode::DeleteQ.is_quiet());
        assert!(Opcode::IncrementQ.is_quiet());
        assert!(Opcode::DecrementQ.is_quiet());
        assert!(Opcode::QuitQ.is_quiet());
        assert!(Opcode::FlushQ.is_quiet());
        assert!(Opcode::AppendQ.is_quiet());
        assert!(Opcode::PrependQ.is_quiet());
        assert!(Opcode::GatQ.is_quiet());
        assert!(Opcode::GatKQ.is_quiet());
        // Non-quiet opcodes
        assert!(!Opcode::Get.is_quiet());
        assert!(!Opcode::Set.is_quiet());
        assert!(!Opcode::Add.is_quiet());
        assert!(!Opcode::Replace.is_quiet());
        assert!(!Opcode::Delete.is_quiet());
        assert!(!Opcode::Noop.is_quiet());
        assert!(!Opcode::Version.is_quiet());
    }

    #[test]
    fn test_all_to_non_quiet() {
        assert_eq!(Opcode::GetQ.to_non_quiet(), Opcode::Get);
        assert_eq!(Opcode::GetKQ.to_non_quiet(), Opcode::GetK);
        assert_eq!(Opcode::SetQ.to_non_quiet(), Opcode::Set);
        assert_eq!(Opcode::AddQ.to_non_quiet(), Opcode::Add);
        assert_eq!(Opcode::ReplaceQ.to_non_quiet(), Opcode::Replace);
        assert_eq!(Opcode::DeleteQ.to_non_quiet(), Opcode::Delete);
        assert_eq!(Opcode::IncrementQ.to_non_quiet(), Opcode::Increment);
        assert_eq!(Opcode::DecrementQ.to_non_quiet(), Opcode::Decrement);
        assert_eq!(Opcode::QuitQ.to_non_quiet(), Opcode::Quit);
        assert_eq!(Opcode::FlushQ.to_non_quiet(), Opcode::Flush);
        assert_eq!(Opcode::AppendQ.to_non_quiet(), Opcode::Append);
        assert_eq!(Opcode::PrependQ.to_non_quiet(), Opcode::Prepend);
        assert_eq!(Opcode::GatQ.to_non_quiet(), Opcode::Gat);
        assert_eq!(Opcode::GatKQ.to_non_quiet(), Opcode::GatK);
        // Non-quiet should return itself
        assert_eq!(Opcode::Get.to_non_quiet(), Opcode::Get);
        assert_eq!(Opcode::Noop.to_non_quiet(), Opcode::Noop);
    }

    #[test]
    fn test_all_status_from_u16() {
        assert_eq!(Status::from_u16(0x0000), Some(Status::NoError));
        assert_eq!(Status::from_u16(0x0001), Some(Status::KeyNotFound));
        assert_eq!(Status::from_u16(0x0002), Some(Status::KeyExists));
        assert_eq!(Status::from_u16(0x0003), Some(Status::ValueTooLarge));
        assert_eq!(Status::from_u16(0x0004), Some(Status::InvalidArguments));
        assert_eq!(Status::from_u16(0x0005), Some(Status::ItemNotStored));
        assert_eq!(Status::from_u16(0x0006), Some(Status::NonNumericValue));
        assert_eq!(Status::from_u16(0x0007), Some(Status::WrongVbucket));
        assert_eq!(Status::from_u16(0x0008), Some(Status::AuthError));
        assert_eq!(Status::from_u16(0x0009), Some(Status::AuthContinue));
        assert_eq!(Status::from_u16(0x0081), Some(Status::UnknownCommand));
        assert_eq!(Status::from_u16(0x0082), Some(Status::OutOfMemory));
        assert_eq!(Status::from_u16(0x0083), Some(Status::NotSupported));
        assert_eq!(Status::from_u16(0x0084), Some(Status::InternalError));
        assert_eq!(Status::from_u16(0x0085), Some(Status::Busy));
        assert_eq!(Status::from_u16(0x0086), Some(Status::TempFailure));
        // Unknown status
        assert_eq!(Status::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_status_is_success() {
        assert!(Status::NoError.is_success());
        assert!(!Status::KeyNotFound.is_success());
        assert!(!Status::KeyExists.is_success());
        assert!(!Status::OutOfMemory.is_success());
    }

    #[test]
    fn test_status_as_str() {
        assert_eq!(Status::NoError.as_str(), "No error");
        assert_eq!(Status::KeyNotFound.as_str(), "Key not found");
        assert_eq!(Status::KeyExists.as_str(), "Key exists");
        assert_eq!(Status::ValueTooLarge.as_str(), "Value too large");
        assert_eq!(Status::InvalidArguments.as_str(), "Invalid arguments");
        assert_eq!(Status::ItemNotStored.as_str(), "Item not stored");
        assert_eq!(
            Status::NonNumericValue.as_str(),
            "Incr/Decr on non-numeric value"
        );
        assert_eq!(Status::WrongVbucket.as_str(), "Wrong vbucket");
        assert_eq!(Status::AuthError.as_str(), "Authentication error");
        assert_eq!(Status::AuthContinue.as_str(), "Authentication continue");
        assert_eq!(Status::UnknownCommand.as_str(), "Unknown command");
        assert_eq!(Status::OutOfMemory.as_str(), "Out of memory");
        assert_eq!(Status::NotSupported.as_str(), "Not supported");
        assert_eq!(Status::InternalError.as_str(), "Internal error");
        assert_eq!(Status::Busy.as_str(), "Busy");
        assert_eq!(Status::TempFailure.as_str(), "Temporary failure");
    }

    #[test]
    fn test_request_header_parse_incomplete() {
        let data = [0x80; 10]; // Only 10 bytes, need 24
        assert!(matches!(
            RequestHeader::parse(&data),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_request_header_parse_invalid_magic() {
        let mut data = [0u8; 24];
        data[0] = 0x00; // Invalid magic
        assert!(matches!(
            RequestHeader::parse(&data),
            Err(ParseError::InvalidMagic(0x00))
        ));
    }

    #[test]
    fn test_request_header_parse_unknown_opcode() {
        let mut data = [0u8; 24];
        data[0] = REQUEST_MAGIC;
        data[1] = 0xFF; // Unknown opcode
        assert!(matches!(
            RequestHeader::parse(&data),
            Err(ParseError::UnknownOpcode(0xFF))
        ));
    }

    #[test]
    fn test_response_header_parse_incomplete() {
        let data = [0x81; 10]; // Only 10 bytes, need 24
        assert!(matches!(
            ResponseHeader::parse(&data),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_response_header_parse_invalid_magic() {
        let mut data = [0u8; 24];
        data[0] = 0x00; // Invalid magic
        assert!(matches!(
            ResponseHeader::parse(&data),
            Err(ParseError::InvalidMagic(0x00))
        ));
    }

    #[test]
    fn test_response_header_parse_unknown_opcode() {
        let mut data = [0u8; 24];
        data[0] = RESPONSE_MAGIC;
        data[1] = 0xFF; // Unknown opcode
        assert!(matches!(
            ResponseHeader::parse(&data),
            Err(ParseError::UnknownOpcode(0xFF))
        ));
    }

    #[test]
    fn test_response_header_value_length() {
        let mut header = ResponseHeader::new(Opcode::Get, Status::NoError);
        header.extras_length = 4;
        header.key_length = 5;
        header.total_body_length = 19; // 4 + 5 + 10 value
        assert_eq!(header.value_length(), 10);
    }

    #[test]
    fn test_opcode_traits() {
        let op1 = Opcode::Get;
        let op2 = op1;
        assert_eq!(op1, op2);

        let debug_str = format!("{:?}", op1);
        assert!(debug_str.contains("Get"));
    }

    #[test]
    fn test_status_traits() {
        let s1 = Status::NoError;
        let s2 = s1;
        assert_eq!(s1, s2);

        let debug_str = format!("{:?}", s1);
        assert!(debug_str.contains("NoError"));
    }

    #[test]
    fn test_request_header_traits() {
        let h1 = RequestHeader::new(Opcode::Get);
        let h2 = h1;
        assert_eq!(h1, h2);

        let debug_str = format!("{:?}", h1);
        assert!(debug_str.contains("RequestHeader"));
    }

    #[test]
    fn test_response_header_traits() {
        let h1 = ResponseHeader::new(Opcode::Get, Status::NoError);
        let h2 = h1;
        assert_eq!(h1, h2);

        let debug_str = format!("{:?}", h1);
        assert!(debug_str.contains("ResponseHeader"));
    }

    #[test]
    fn test_response_header_parse_unknown_status() {
        // When parsing an unknown status, it defaults to InternalError
        let mut buf = [0u8; 24];
        let header = ResponseHeader::new(Opcode::Get, Status::NoError);
        header.encode(&mut buf);
        // Manually set an unknown status
        buf[6] = 0xFF;
        buf[7] = 0xFF;

        let parsed = ResponseHeader::parse(&buf).unwrap();
        assert_eq!(parsed.status, Status::InternalError);
    }
}
