//! Minimal protobuf encoding/decoding for Momento cache messages.
//!
//! This implements just enough protobuf wire format to encode/decode
//! the protosocket cache API messages without requiring prost or other heavy deps.

use bytes::Bytes;

/// Wire type for varint (int32, int64, uint32, uint64, bool, enum).
const WIRE_TYPE_VARINT: u8 = 0;
/// Wire type for length-delimited (string, bytes, embedded messages).
const WIRE_TYPE_LEN: u8 = 2;

/// Encode a varint.
pub fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a varint from a buffer.
pub fn decode_varint(buf: &mut &[u8]) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;

    loop {
        if buf.is_empty() {
            return None;
        }
        let byte = buf[0];
        *buf = &buf[1..];

        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None; // Overflow
        }
    }
}

/// Encode a field tag.
pub fn encode_tag(field_number: u32, wire_type: u8, buf: &mut Vec<u8>) {
    encode_varint(((field_number as u64) << 3) | (wire_type as u64), buf);
}

/// Decode a field tag, returning (field_number, wire_type).
pub fn decode_tag(buf: &mut &[u8]) -> Option<(u32, u8)> {
    let tag = decode_varint(buf)?;
    let field_number = (tag >> 3) as u32;
    let wire_type = (tag & 0x07) as u8;
    Some((field_number, wire_type))
}

/// Encode a bytes field.
pub fn encode_bytes(field_number: u32, data: &[u8], buf: &mut Vec<u8>) {
    encode_tag(field_number, WIRE_TYPE_LEN, buf);
    encode_varint(data.len() as u64, buf);
    buf.extend_from_slice(data);
}

/// Encode a string field (same as bytes in protobuf).
pub fn encode_string(field_number: u32, s: &str, buf: &mut Vec<u8>) {
    encode_bytes(field_number, s.as_bytes(), buf);
}

/// Encode a uint64 field.
pub fn encode_uint64(field_number: u32, value: u64, buf: &mut Vec<u8>) {
    encode_tag(field_number, WIRE_TYPE_VARINT, buf);
    encode_varint(value, buf);
}

/// Encode an embedded message field.
pub fn encode_message(field_number: u32, message: &[u8], buf: &mut Vec<u8>) {
    encode_tag(field_number, WIRE_TYPE_LEN, buf);
    encode_varint(message.len() as u64, buf);
    buf.extend_from_slice(message);
}

/// Compute the encoded size of a varint.
pub fn varint_size(mut value: u64) -> usize {
    let mut size = 1;
    while value >= 0x80 {
        value >>= 7;
        size += 1;
    }
    size
}

/// Compute the encoded size of a field tag.
fn tag_size(field_number: u32) -> usize {
    varint_size(((field_number as u64) << 3) | (WIRE_TYPE_LEN as u64))
}

/// Compute the encoded size of a bytes/string field (tag + length varint + data).
fn field_size_bytes(field_number: u32, data: &[u8]) -> usize {
    tag_size(field_number) + varint_size(data.len() as u64) + data.len()
}

/// Compute the encoded size of a string field.
fn field_size_string(field_number: u32, s: &str) -> usize {
    field_size_bytes(field_number, s.as_bytes())
}

/// Compute the encoded size of a uint64 field (tag + varint value).
fn field_size_uint64(field_number: u32, value: u64) -> usize {
    varint_size(((field_number as u64) << 3) | (WIRE_TYPE_VARINT as u64)) + varint_size(value)
}

/// Decode a length-delimited field, returning the bytes.
pub fn decode_length_delimited<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = decode_varint(buf)? as usize;
    if buf.len() < len {
        return None;
    }
    let data = &buf[..len];
    *buf = &buf[len..];
    Some(data)
}

/// Skip a field based on its wire type.
pub fn skip_field(wire_type: u8, buf: &mut &[u8]) -> Option<()> {
    match wire_type {
        WIRE_TYPE_VARINT => {
            decode_varint(buf)?;
        }
        WIRE_TYPE_LEN => {
            decode_length_delimited(buf)?;
        }
        1 => {
            // 64-bit fixed
            if buf.len() < 8 {
                return None;
            }
            *buf = &buf[8..];
        }
        5 => {
            // 32-bit fixed
            if buf.len() < 4 {
                return None;
            }
            *buf = &buf[4..];
        }
        _ => return None,
    }
    Some(())
}

// ============================================================================
// Protosocket Wire Format Messages
// ============================================================================

/// Control codes for protosocket messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ControlCode {
    /// Normal message.
    #[default]
    Normal = 0,
    /// Cancel the RPC.
    Cancel = 1,
    /// End of stream (for streaming RPCs).
    End = 2,
}

impl ControlCode {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => ControlCode::Normal,
            1 => ControlCode::Cancel,
            2 => ControlCode::End,
            _ => ControlCode::Normal,
        }
    }
}

/// Status codes for protosocket responses (matches gRPC codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum StatusCode {
    #[default]
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl StatusCode {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => StatusCode::Ok,
            1 => StatusCode::Cancelled,
            2 => StatusCode::Unknown,
            3 => StatusCode::InvalidArgument,
            4 => StatusCode::DeadlineExceeded,
            5 => StatusCode::NotFound,
            6 => StatusCode::AlreadyExists,
            7 => StatusCode::PermissionDenied,
            8 => StatusCode::ResourceExhausted,
            9 => StatusCode::FailedPrecondition,
            10 => StatusCode::Aborted,
            11 => StatusCode::OutOfRange,
            12 => StatusCode::Unimplemented,
            13 => StatusCode::Internal,
            14 => StatusCode::Unavailable,
            15 => StatusCode::DataLoss,
            16 => StatusCode::Unauthenticated,
            _ => StatusCode::Unknown,
        }
    }
}

/// Error from a protosocket command.
#[derive(Debug, Clone)]
pub struct CommandError {
    pub code: StatusCode,
    pub message: String,
}

impl CommandError {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        self.encode_into(&mut buf);
        buf
    }

    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        encode_uint64(1, self.code as u64, buf);
        if !self.message.is_empty() {
            encode_string(2, &self.message, buf);
        }
    }

    pub fn encoded_size(&self) -> usize {
        let mut size = field_size_uint64(1, self.code as u64);
        if !self.message.is_empty() {
            size += field_size_string(2, &self.message);
        }
        size
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        let mut code = StatusCode::Unknown;
        let mut message = String::new();

        while !buf.is_empty() {
            let (field_number, wire_type) = decode_tag(&mut buf)?;
            match field_number {
                1 => code = StatusCode::from_u32(decode_varint(&mut buf)? as u32),
                2 => {
                    let bytes = decode_length_delimited(&mut buf)?;
                    message = String::from_utf8_lossy(bytes).into_owned();
                }
                _ => skip_field(wire_type, &mut buf)?,
            }
        }

        Some(Self { code, message })
    }
}

/// Unary command types for protosocket.
#[derive(Debug, Clone)]
pub enum UnaryCommand {
    Authenticate {
        auth_token: String,
    },
    Get {
        namespace: String,
        key: Bytes,
    },
    Set {
        namespace: String,
        key: Bytes,
        value: Bytes,
        ttl_millis: u64,
    },
    Delete {
        namespace: String,
        key: Bytes,
    },
}

impl UnaryCommand {
    /// Encode the inner command fields (without the Unary wrapper) into `buf`.
    fn encode_inner_into(&self, buf: &mut Vec<u8>) {
        match self {
            UnaryCommand::Authenticate { auth_token } => {
                encode_string(1, auth_token, buf);
            }
            UnaryCommand::Get { namespace, key } => {
                encode_string(1, namespace, buf);
                encode_bytes(2, key, buf);
            }
            UnaryCommand::Set {
                namespace,
                key,
                value,
                ttl_millis,
            } => {
                encode_string(1, namespace, buf);
                encode_bytes(2, key, buf);
                encode_bytes(3, value, buf);
                encode_uint64(4, *ttl_millis, buf);
            }
            UnaryCommand::Delete { namespace, key } => {
                encode_string(1, namespace, buf);
                encode_bytes(2, key, buf);
            }
        }
    }

    /// Compute the encoded size of the inner command fields (without tags or length prefixes).
    fn inner_encoded_size(&self) -> usize {
        match self {
            UnaryCommand::Authenticate { auth_token } => field_size_string(1, auth_token),
            UnaryCommand::Get { namespace, key } => {
                field_size_string(1, namespace) + field_size_bytes(2, key)
            }
            UnaryCommand::Set {
                namespace,
                key,
                value,
                ttl_millis,
            } => {
                field_size_string(1, namespace)
                    + field_size_bytes(2, key)
                    + field_size_bytes(3, value)
                    + field_size_uint64(4, *ttl_millis)
            }
            UnaryCommand::Delete { namespace, key } => {
                field_size_string(1, namespace) + field_size_bytes(2, key)
            }
        }
    }

    /// The protobuf field number for this command variant within the Unary message.
    fn field_number(&self) -> u32 {
        match self {
            UnaryCommand::Authenticate { .. } => 1,
            UnaryCommand::Get { .. } => 2,
            UnaryCommand::Set { .. } => 3,
            UnaryCommand::Delete { .. } => 4,
        }
    }

    /// Encode as a Unary message with the command in the appropriate field.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        self.encode_into(&mut buf);
        buf
    }

    /// Compute the total encoded size of the Unary message (tag + length prefix + inner).
    pub fn encoded_size(&self) -> usize {
        let inner_size = self.inner_encoded_size();
        tag_size(self.field_number()) + varint_size(inner_size as u64) + inner_size
    }

    /// Encode as a Unary message directly into `buf` (single-pass, no intermediate allocations).
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        let inner_size = self.inner_encoded_size();
        // Unary wrapper: tag + length prefix + inner fields
        encode_tag(self.field_number(), WIRE_TYPE_LEN, buf);
        encode_varint(inner_size as u64, buf);
        self.encode_inner_into(buf);
    }

    /// Decode a Unary message.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut buf = data;

        while !buf.is_empty() {
            let (field_number, wire_type) = decode_tag(&mut buf)?;
            if wire_type != WIRE_TYPE_LEN {
                skip_field(wire_type, &mut buf)?;
                continue;
            }

            let inner = decode_length_delimited(&mut buf)?;
            return match field_number {
                1 => Self::decode_authenticate(inner),
                2 => Self::decode_get(inner),
                3 => Self::decode_set(inner),
                4 => Self::decode_delete(inner),
                _ => None,
            };
        }

        None
    }

    fn decode_authenticate(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        let mut auth_token = String::new();

        while !buf.is_empty() {
            let (field_number, wire_type) = decode_tag(&mut buf)?;
            match field_number {
                1 => {
                    let bytes = decode_length_delimited(&mut buf)?;
                    auth_token = String::from_utf8_lossy(bytes).into_owned();
                }
                _ => skip_field(wire_type, &mut buf)?,
            }
        }

        Some(UnaryCommand::Authenticate { auth_token })
    }

    fn decode_get(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        let mut namespace = String::new();
        let mut key = Bytes::new();

        while !buf.is_empty() {
            let (field_number, wire_type) = decode_tag(&mut buf)?;
            match field_number {
                1 => {
                    let bytes = decode_length_delimited(&mut buf)?;
                    namespace = String::from_utf8_lossy(bytes).into_owned();
                }
                2 => {
                    let bytes = decode_length_delimited(&mut buf)?;
                    key = Bytes::copy_from_slice(bytes);
                }
                _ => skip_field(wire_type, &mut buf)?,
            }
        }

        Some(UnaryCommand::Get { namespace, key })
    }

    fn decode_set(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        let mut namespace = String::new();
        let mut key = Bytes::new();
        let mut value = Bytes::new();
        let mut ttl_millis = 0u64;

        while !buf.is_empty() {
            let (field_number, wire_type) = decode_tag(&mut buf)?;
            match field_number {
                1 => {
                    let bytes = decode_length_delimited(&mut buf)?;
                    namespace = String::from_utf8_lossy(bytes).into_owned();
                }
                2 => {
                    let bytes = decode_length_delimited(&mut buf)?;
                    key = Bytes::copy_from_slice(bytes);
                }
                3 => {
                    let bytes = decode_length_delimited(&mut buf)?;
                    value = Bytes::copy_from_slice(bytes);
                }
                4 => {
                    ttl_millis = decode_varint(&mut buf)?;
                }
                _ => skip_field(wire_type, &mut buf)?,
            }
        }

        Some(UnaryCommand::Set {
            namespace,
            key,
            value,
            ttl_millis,
        })
    }

    fn decode_delete(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        let mut namespace = String::new();
        let mut key = Bytes::new();

        while !buf.is_empty() {
            let (field_number, wire_type) = decode_tag(&mut buf)?;
            match field_number {
                1 => {
                    let bytes = decode_length_delimited(&mut buf)?;
                    namespace = String::from_utf8_lossy(bytes).into_owned();
                }
                2 => {
                    let bytes = decode_length_delimited(&mut buf)?;
                    key = Bytes::copy_from_slice(bytes);
                }
                _ => skip_field(wire_type, &mut buf)?,
            }
        }

        Some(UnaryCommand::Delete { namespace, key })
    }
}

/// A command sent from client to server over protosocket.
#[derive(Debug, Clone)]
pub struct CacheCommand {
    pub message_id: u64,
    pub control_code: ControlCode,
    pub command: Option<UnaryCommand>,
}

impl CacheCommand {
    /// Create a new command with the given message ID.
    pub fn new(message_id: u64, command: UnaryCommand) -> Self {
        Self {
            message_id,
            control_code: ControlCode::Normal,
            command: Some(command),
        }
    }

    /// Create a cancel command.
    pub fn cancel(message_id: u64) -> Self {
        Self {
            message_id,
            control_code: ControlCode::Cancel,
            command: None,
        }
    }

    /// Encode the command to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        self.encode_into(&mut buf);
        buf
    }

    /// Encode directly into `buf` (single-pass, no intermediate allocations).
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        // Field 2: message_id (per official proto)
        encode_uint64(2, self.message_id, buf);

        // Field 3: control_code (per official proto)
        encode_uint64(3, self.control_code as u64, buf);

        // Field 10: unary command (per official proto)
        if let Some(ref cmd) = self.command {
            // Write the field 10 tag + length prefix, then encode inner fields directly.
            let unary_size = cmd.encoded_size();
            encode_tag(10, WIRE_TYPE_LEN, buf);
            encode_varint(unary_size as u64, buf);
            cmd.encode_into(buf);
        }
    }

    /// Compute the encoded size of the command (without length-delimited prefix).
    fn encoded_size(&self) -> usize {
        let mut size =
            field_size_uint64(2, self.message_id) + field_size_uint64(3, self.control_code as u64);
        if let Some(ref cmd) = self.command {
            let unary_size = cmd.encoded_size();
            size += tag_size(10) + varint_size(unary_size as u64) + unary_size;
        }
        size
    }

    /// Encode with length prefix for protosocket wire format (single allocation).
    pub fn encode_length_delimited(&self) -> Vec<u8> {
        let msg_size = self.encoded_size();
        let mut buf = Vec::with_capacity(varint_size(msg_size as u64) + msg_size);
        self.encode_length_delimited_into(&mut buf);
        buf
    }

    /// Encode with length prefix directly into `buf` (zero intermediate allocations).
    pub fn encode_length_delimited_into(&self, buf: &mut Vec<u8>) {
        let msg_size = self.encoded_size();
        encode_varint(msg_size as u64, buf);
        self.encode_into(buf);
    }

    /// Decode a command from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        let mut message_id = 0u64;
        let mut control_code = ControlCode::Normal;
        let mut command = None;

        while !buf.is_empty() {
            let (field_number, wire_type) = decode_tag(&mut buf)?;
            match field_number {
                2 => message_id = decode_varint(&mut buf)?,
                3 => control_code = ControlCode::from_u32(decode_varint(&mut buf)? as u32),
                10 => {
                    let unary_data = decode_length_delimited(&mut buf)?;
                    command = UnaryCommand::decode(unary_data);
                }
                _ => skip_field(wire_type, &mut buf)?,
            }
        }

        Some(Self {
            message_id,
            control_code,
            command,
        })
    }
}

/// A response sent from server to client over protosocket.
#[derive(Debug, Clone)]
pub struct CacheResponse {
    pub message_id: u64,
    pub control_code: ControlCode,
    pub result: CacheResponseResult,
}

/// The result portion of a CacheResponse.
#[derive(Debug, Clone)]
pub enum CacheResponseResult {
    Authenticate,
    Get { value: Option<Bytes> },
    Set,
    Delete,
    Error(CommandError),
}

impl CacheResponse {
    /// Create a successful authenticate response.
    pub fn authenticate(message_id: u64) -> Self {
        Self {
            message_id,
            control_code: ControlCode::Normal,
            result: CacheResponseResult::Authenticate,
        }
    }

    /// Create a successful get response (hit).
    pub fn get_hit(message_id: u64, value: Bytes) -> Self {
        Self {
            message_id,
            control_code: ControlCode::Normal,
            result: CacheResponseResult::Get { value: Some(value) },
        }
    }

    /// Create a get miss response.
    pub fn get_miss(message_id: u64) -> Self {
        Self {
            message_id,
            control_code: ControlCode::Normal,
            result: CacheResponseResult::Get { value: None },
        }
    }

    /// Create a successful set response.
    pub fn set_ok(message_id: u64) -> Self {
        Self {
            message_id,
            control_code: ControlCode::Normal,
            result: CacheResponseResult::Set,
        }
    }

    /// Create a successful delete response.
    pub fn delete_ok(message_id: u64) -> Self {
        Self {
            message_id,
            control_code: ControlCode::Normal,
            result: CacheResponseResult::Delete,
        }
    }

    /// Create an error response.
    pub fn error(message_id: u64, code: StatusCode, message: impl Into<String>) -> Self {
        Self {
            message_id,
            control_code: ControlCode::Normal,
            result: CacheResponseResult::Error(CommandError {
                code,
                message: message.into(),
            }),
        }
    }

    /// Encode the response to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        self.encode_into(&mut buf);
        buf
    }

    /// Encode directly into `buf` (single-pass, no intermediate allocations).
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        // Field 1: message_id
        encode_uint64(1, self.message_id, buf);

        // Field 2: control_code
        encode_uint64(2, self.control_code as u64, buf);

        // Response kind (per official proto field numbers)
        match &self.result {
            CacheResponseResult::Error(err) => {
                // Field 9: error — encode inline
                let inner_size = err.encoded_size();
                encode_tag(9, WIRE_TYPE_LEN, buf);
                encode_varint(inner_size as u64, buf);
                err.encode_into(buf);
            }
            CacheResponseResult::Authenticate => {
                // Field 10: authenticate response (empty)
                encode_message(10, &[], buf);
            }
            CacheResponseResult::Get { value } => {
                // Field 11: get response — encode inline
                let inner_size = match value {
                    Some(v) => field_size_bytes(1, v),
                    None => 0,
                };
                encode_tag(11, WIRE_TYPE_LEN, buf);
                encode_varint(inner_size as u64, buf);
                if let Some(v) = value {
                    encode_bytes(1, v, buf);
                }
            }
            CacheResponseResult::Set => {
                // Field 12: set response (empty)
                encode_message(12, &[], buf);
            }
            CacheResponseResult::Delete => {
                // Field 13: delete response (empty)
                encode_message(13, &[], buf);
            }
        }
    }

    /// Compute the encoded size of the response (without length-delimited prefix).
    fn encoded_size(&self) -> usize {
        let mut size =
            field_size_uint64(1, self.message_id) + field_size_uint64(2, self.control_code as u64);
        match &self.result {
            CacheResponseResult::Error(err) => {
                let inner = err.encoded_size();
                size += tag_size(9) + varint_size(inner as u64) + inner;
            }
            CacheResponseResult::Authenticate => {
                size += tag_size(10) + varint_size(0);
            }
            CacheResponseResult::Get { value } => {
                let inner = match value {
                    Some(v) => field_size_bytes(1, v),
                    None => 0,
                };
                size += tag_size(11) + varint_size(inner as u64) + inner;
            }
            CacheResponseResult::Set => {
                size += tag_size(12) + varint_size(0);
            }
            CacheResponseResult::Delete => {
                size += tag_size(13) + varint_size(0);
            }
        }
        size
    }

    /// Encode with length prefix for protosocket wire format (single allocation).
    pub fn encode_length_delimited(&self) -> Vec<u8> {
        let msg_size = self.encoded_size();
        let mut buf = Vec::with_capacity(varint_size(msg_size as u64) + msg_size);
        encode_varint(msg_size as u64, &mut buf);
        self.encode_into(&mut buf);
        buf
    }

    /// Decode a response from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut buf = data;
        let mut message_id = 0u64;
        let mut control_code = ControlCode::Normal;
        let mut result = None;

        while !buf.is_empty() {
            let (field_number, wire_type) = decode_tag(&mut buf)?;
            match field_number {
                1 if wire_type == WIRE_TYPE_VARINT => {
                    message_id = decode_varint(&mut buf)?;
                }
                2 if wire_type == WIRE_TYPE_VARINT => {
                    control_code = ControlCode::from_u32(decode_varint(&mut buf)? as u32);
                }
                // Response kinds (per official proto field numbers)
                9 if wire_type == WIRE_TYPE_LEN => {
                    let inner = decode_length_delimited(&mut buf)?;
                    let err = CommandError::decode(inner)?;
                    result = Some(CacheResponseResult::Error(err));
                }
                10 if wire_type == WIRE_TYPE_LEN => {
                    let _inner = decode_length_delimited(&mut buf)?;
                    result = Some(CacheResponseResult::Authenticate);
                }
                11 if wire_type == WIRE_TYPE_LEN => {
                    let inner = decode_length_delimited(&mut buf)?;
                    result = Some(Self::decode_get_response(inner));
                }
                12 if wire_type == WIRE_TYPE_LEN => {
                    let _inner = decode_length_delimited(&mut buf)?;
                    result = Some(CacheResponseResult::Set);
                }
                13 if wire_type == WIRE_TYPE_LEN => {
                    let _inner = decode_length_delimited(&mut buf)?;
                    result = Some(CacheResponseResult::Delete);
                }
                _ => skip_field(wire_type, &mut buf)?,
            }
        }

        Some(Self {
            message_id,
            control_code,
            result: result.unwrap_or(CacheResponseResult::Error(CommandError {
                code: StatusCode::Internal,
                message: "missing response".to_string(),
            })),
        })
    }

    fn decode_get_response(data: &[u8]) -> CacheResponseResult {
        let mut buf = data;
        let mut value = None;

        while !buf.is_empty() {
            if let Some((field_number, wire_type)) = decode_tag(&mut buf) {
                match field_number {
                    1 => {
                        if let Some(bytes) = decode_length_delimited(&mut buf) {
                            value = Some(Bytes::copy_from_slice(bytes));
                        }
                    }
                    _ => {
                        if skip_field(wire_type, &mut buf).is_none() {
                            break;
                        }
                    }
                }
            } else {
                break;
            }
        }

        CacheResponseResult::Get { value }
    }
}

/// Decode a length-delimited message from a buffer.
/// Returns (bytes_consumed, message) or None if incomplete.
pub fn decode_length_delimited_message(buf: &[u8]) -> Option<(usize, &[u8])> {
    let mut cursor = buf;
    let original_len = buf.len();

    // Decode varint length
    let len = decode_varint(&mut cursor)? as usize;
    let header_len = original_len - cursor.len();

    // Check if we have enough data
    if cursor.len() < len {
        return None;
    }

    let message = &cursor[..len];
    Some((header_len + len, message))
}

// ============================================================================
// Zero-copy Bytes-aware decoders
// ============================================================================
//
// These decode functions work with `Bytes` handles, returning `Bytes::slice()`
// sub-references instead of copying. Used by the recv path to avoid copies when
// extracting values from the accumulator.

/// Decode a length-delimited field from a `Bytes` handle, returning a zero-copy slice.
///
/// Advances `offset` past the consumed bytes. Returns `None` if incomplete.
fn decode_length_delimited_bytes(data: &Bytes, offset: &mut usize) -> Option<Bytes> {
    let buf = &data[*offset..];
    let mut cursor = buf;
    let len = decode_varint(&mut cursor)? as usize;
    let header_len = buf.len() - cursor.len();
    if cursor.len() < len {
        return None;
    }
    let start = *offset + header_len;
    *offset = start + len;
    Some(data.slice(start..start + len))
}

/// Skip a field in a `Bytes` buffer by advancing `offset`.
fn skip_field_bytes(wire_type: u8, data: &[u8], offset: &mut usize) -> Option<()> {
    let buf = &data[*offset..];
    let mut cursor = buf;
    skip_field(wire_type, &mut cursor)?;
    *offset += buf.len() - cursor.len();
    Some(())
}

/// Decode a varint from a `Bytes` buffer, advancing `offset`.
fn decode_varint_bytes(data: &[u8], offset: &mut usize) -> Option<u64> {
    let buf = &data[*offset..];
    let mut cursor = buf;
    let value = decode_varint(&mut cursor)?;
    *offset += buf.len() - cursor.len();
    Some(value)
}

/// Decode a tag from a `Bytes` buffer, advancing `offset`.
fn decode_tag_bytes(data: &[u8], offset: &mut usize) -> Option<(u32, u8)> {
    let buf = &data[*offset..];
    let mut cursor = buf;
    let tag = decode_tag(&mut cursor)?;
    *offset += buf.len() - cursor.len();
    Some(tag)
}

impl CacheResponse {
    /// Decode a response from a `Bytes` handle using zero-copy slicing.
    ///
    /// Extracted values (e.g., GET response bodies) are `Bytes::slice()` references
    /// into the original buffer — no allocation or memcpy.
    pub fn decode_bytes(data: Bytes) -> Option<Self> {
        let mut offset = 0;
        let mut message_id = 0u64;
        let mut control_code = ControlCode::Normal;
        let mut result = None;

        while offset < data.len() {
            let (field_number, wire_type) = decode_tag_bytes(&data, &mut offset)?;
            match field_number {
                1 if wire_type == WIRE_TYPE_VARINT => {
                    message_id = decode_varint_bytes(&data, &mut offset)?;
                }
                2 if wire_type == WIRE_TYPE_VARINT => {
                    control_code =
                        ControlCode::from_u32(decode_varint_bytes(&data, &mut offset)? as u32);
                }
                9 if wire_type == WIRE_TYPE_LEN => {
                    let inner = decode_length_delimited_bytes(&data, &mut offset)?;
                    let err = CommandError::decode(&inner)?;
                    result = Some(CacheResponseResult::Error(err));
                }
                10 if wire_type == WIRE_TYPE_LEN => {
                    let _inner = decode_length_delimited_bytes(&data, &mut offset)?;
                    result = Some(CacheResponseResult::Authenticate);
                }
                11 if wire_type == WIRE_TYPE_LEN => {
                    // GET response — decode inline with zero-copy value extraction
                    let inner = decode_length_delimited_bytes(&data, &mut offset)?;
                    result = Some(Self::decode_get_response_bytes(inner));
                }
                12 if wire_type == WIRE_TYPE_LEN => {
                    let _inner = decode_length_delimited_bytes(&data, &mut offset)?;
                    result = Some(CacheResponseResult::Set);
                }
                13 if wire_type == WIRE_TYPE_LEN => {
                    let _inner = decode_length_delimited_bytes(&data, &mut offset)?;
                    result = Some(CacheResponseResult::Delete);
                }
                _ => skip_field_bytes(wire_type, &data, &mut offset)?,
            }
        }

        Some(Self {
            message_id,
            control_code,
            result: result.unwrap_or(CacheResponseResult::Error(CommandError {
                code: StatusCode::Internal,
                message: "missing response".to_string(),
            })),
        })
    }

    /// Decode a GET response from a `Bytes` handle — zero-copy value extraction.
    fn decode_get_response_bytes(data: Bytes) -> CacheResponseResult {
        let mut offset = 0;
        let mut value = None;

        while offset < data.len() {
            if let Some((field_number, wire_type)) = decode_tag_bytes(&data, &mut offset) {
                match field_number {
                    1 if wire_type == WIRE_TYPE_LEN => {
                        value = decode_length_delimited_bytes(&data, &mut offset);
                    }
                    _ => {
                        if skip_field_bytes(wire_type, &data, &mut offset).is_none() {
                            break;
                        }
                    }
                }
            } else {
                break;
            }
        }

        CacheResponseResult::Get { value }
    }
}

/// Decode a length-delimited message from a `Bytes` handle.
/// Returns (bytes_consumed, message_bytes) or None if incomplete.
pub fn decode_length_delimited_message_bytes(buf: &Bytes) -> Option<(usize, Bytes)> {
    let mut offset = 0;
    let len = decode_varint_bytes(buf, &mut offset)? as usize;

    // Check if we have enough data
    if buf.len() - offset < len {
        return None;
    }

    let message = buf.slice(offset..offset + len);
    Some((offset + len, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Varint tests

    #[test]
    fn test_varint_roundtrip() {
        let values = [0, 1, 127, 128, 300, 16383, 16384, u64::MAX];

        for &value in &values {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);

            let mut slice = &buf[..];
            let decoded = decode_varint(&mut slice).unwrap();
            assert_eq!(decoded, value);
            assert!(slice.is_empty());
        }
    }

    #[test]
    fn test_decode_varint_empty() {
        let mut buf: &[u8] = &[];
        assert!(decode_varint(&mut buf).is_none());
    }

    #[test]
    fn test_decode_varint_overflow() {
        let mut buf: &[u8] = &[0x80; 11];
        assert!(decode_varint(&mut buf).is_none());
    }

    // Tag tests

    #[test]
    fn test_encode_decode_tag() {
        let test_cases = [(1, 0), (1, 2), (15, 0), (100, 2), (1000, 0)];

        for (field_number, wire_type) in test_cases {
            let mut buf = Vec::new();
            encode_tag(field_number, wire_type, &mut buf);

            let mut slice = &buf[..];
            let (decoded_field, decoded_wire) = decode_tag(&mut slice).unwrap();
            assert_eq!(decoded_field, field_number);
            assert_eq!(decoded_wire, wire_type);
        }
    }

    #[test]
    fn test_decode_tag_empty() {
        let mut buf: &[u8] = &[];
        assert!(decode_tag(&mut buf).is_none());
    }

    // Length-delimited tests

    #[test]
    fn test_decode_length_delimited() {
        let mut buf = Vec::new();
        encode_varint(5, &mut buf); // length = 5
        buf.extend_from_slice(b"hello");

        let mut slice = &buf[..];
        let data = decode_length_delimited(&mut slice).unwrap();
        assert_eq!(data, b"hello");
        assert!(slice.is_empty());
    }

    #[test]
    fn test_decode_length_delimited_empty() {
        let mut buf = Vec::new();
        encode_varint(0, &mut buf); // length = 0

        let mut slice = &buf[..];
        let data = decode_length_delimited(&mut slice).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn test_decode_length_delimited_insufficient() {
        let mut buf = Vec::new();
        encode_varint(10, &mut buf); // length = 10
        buf.extend_from_slice(b"short"); // only 5 bytes

        let mut slice = &buf[..];
        assert!(decode_length_delimited(&mut slice).is_none());
    }

    // Skip field tests

    #[test]
    fn test_skip_field_varint() {
        let mut buf = Vec::new();
        encode_varint(12345, &mut buf);

        let mut slice = &buf[..];
        assert!(skip_field(WIRE_TYPE_VARINT, &mut slice).is_some());
        assert!(slice.is_empty());
    }

    #[test]
    fn test_skip_field_length_delimited() {
        let mut buf = Vec::new();
        encode_varint(3, &mut buf);
        buf.extend_from_slice(b"abc");

        let mut slice = &buf[..];
        assert!(skip_field(WIRE_TYPE_LEN, &mut slice).is_some());
        assert!(slice.is_empty());
    }

    #[test]
    fn test_skip_field_64bit() {
        let buf = [0u8; 8];
        let mut slice = &buf[..];
        assert!(skip_field(1, &mut slice).is_some());
        assert!(slice.is_empty());
    }

    #[test]
    fn test_skip_field_64bit_insufficient() {
        let buf = [0u8; 4];
        let mut slice = &buf[..];
        assert!(skip_field(1, &mut slice).is_none());
    }

    #[test]
    fn test_skip_field_32bit() {
        let buf = [0u8; 4];
        let mut slice = &buf[..];
        assert!(skip_field(5, &mut slice).is_some());
        assert!(slice.is_empty());
    }

    #[test]
    fn test_skip_field_32bit_insufficient() {
        let buf = [0u8; 2];
        let mut slice = &buf[..];
        assert!(skip_field(5, &mut slice).is_none());
    }

    #[test]
    fn test_skip_field_unknown_wire_type() {
        let buf = [0u8; 8];
        let mut slice = &buf[..];
        assert!(skip_field(6, &mut slice).is_none());
    }

    // encode_string and encode_message tests

    #[test]
    fn test_encode_string() {
        let mut buf = Vec::new();
        encode_string(1, "hello", &mut buf);

        let mut expected = Vec::new();
        encode_bytes(1, b"hello", &mut expected);

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_encode_message() {
        let inner_msg = b"inner message";
        let mut buf = Vec::new();
        encode_message(1, inner_msg, &mut buf);

        let mut expected = Vec::new();
        encode_bytes(1, inner_msg, &mut expected);

        assert_eq!(buf, expected);
    }

    // ControlCode tests

    #[test]
    fn test_control_code_from_u32() {
        assert_eq!(ControlCode::from_u32(0), ControlCode::Normal);
        assert_eq!(ControlCode::from_u32(1), ControlCode::Cancel);
        assert_eq!(ControlCode::from_u32(2), ControlCode::End);
        assert_eq!(ControlCode::from_u32(99), ControlCode::Normal);
    }

    #[test]
    fn test_control_code_default() {
        assert_eq!(ControlCode::default(), ControlCode::Normal);
    }

    // StatusCode tests

    #[test]
    fn test_status_code_from_u32() {
        assert_eq!(StatusCode::from_u32(0), StatusCode::Ok);
        assert_eq!(StatusCode::from_u32(5), StatusCode::NotFound);
        assert_eq!(StatusCode::from_u32(14), StatusCode::Unavailable);
        assert_eq!(StatusCode::from_u32(16), StatusCode::Unauthenticated);
        assert_eq!(StatusCode::from_u32(99), StatusCode::Unknown);
    }

    #[test]
    fn test_status_code_default() {
        assert_eq!(StatusCode::default(), StatusCode::Ok);
    }

    // CommandError tests

    #[test]
    fn test_command_error_roundtrip() {
        let err = CommandError {
            code: StatusCode::NotFound,
            message: "key not found".to_string(),
        };
        let encoded = err.encode();
        let decoded = CommandError::decode(&encoded).unwrap();
        assert_eq!(decoded.code, StatusCode::NotFound);
        assert_eq!(decoded.message, "key not found");
    }

    #[test]
    fn test_command_error_empty_message() {
        let err = CommandError {
            code: StatusCode::Internal,
            message: String::new(),
        };
        let encoded = err.encode();
        let decoded = CommandError::decode(&encoded).unwrap();
        assert_eq!(decoded.code, StatusCode::Internal);
        assert!(decoded.message.is_empty());
    }

    // UnaryCommand tests

    #[test]
    fn test_unary_command_authenticate_roundtrip() {
        let cmd = UnaryCommand::Authenticate {
            auth_token: "test-token-123".to_string(),
        };
        let encoded = cmd.encode();
        let decoded = UnaryCommand::decode(&encoded).unwrap();
        match decoded {
            UnaryCommand::Authenticate { auth_token } => {
                assert_eq!(auth_token, "test-token-123");
            }
            _ => panic!("expected Authenticate"),
        }
    }

    #[test]
    fn test_unary_command_get_roundtrip() {
        let cmd = UnaryCommand::Get {
            namespace: "my-cache".to_string(),
            key: Bytes::from_static(b"my-key"),
        };
        let encoded = cmd.encode();
        let decoded = UnaryCommand::decode(&encoded).unwrap();
        match decoded {
            UnaryCommand::Get { namespace, key } => {
                assert_eq!(namespace, "my-cache");
                assert_eq!(key.as_ref(), b"my-key");
            }
            _ => panic!("expected Get"),
        }
    }

    #[test]
    fn test_unary_command_set_roundtrip() {
        let cmd = UnaryCommand::Set {
            namespace: "cache".to_string(),
            key: Bytes::from_static(b"key"),
            value: Bytes::from_static(b"value"),
            ttl_millis: 60000,
        };
        let encoded = cmd.encode();
        let decoded = UnaryCommand::decode(&encoded).unwrap();
        match decoded {
            UnaryCommand::Set {
                namespace,
                key,
                value,
                ttl_millis,
            } => {
                assert_eq!(namespace, "cache");
                assert_eq!(key.as_ref(), b"key");
                assert_eq!(value.as_ref(), b"value");
                assert_eq!(ttl_millis, 60000);
            }
            _ => panic!("expected Set"),
        }
    }

    #[test]
    fn test_unary_command_delete_roundtrip() {
        let cmd = UnaryCommand::Delete {
            namespace: "cache".to_string(),
            key: Bytes::from_static(b"delete-me"),
        };
        let encoded = cmd.encode();
        let decoded = UnaryCommand::decode(&encoded).unwrap();
        match decoded {
            UnaryCommand::Delete { namespace, key } => {
                assert_eq!(namespace, "cache");
                assert_eq!(key.as_ref(), b"delete-me");
            }
            _ => panic!("expected Delete"),
        }
    }

    // CacheCommand tests

    #[test]
    fn test_cache_command_roundtrip() {
        let cmd = CacheCommand::new(
            42,
            UnaryCommand::Get {
                namespace: "test".to_string(),
                key: Bytes::from_static(b"key"),
            },
        );
        let encoded = cmd.encode();
        let decoded = CacheCommand::decode(&encoded).unwrap();
        assert_eq!(decoded.message_id, 42);
        assert_eq!(decoded.control_code, ControlCode::Normal);
        assert!(decoded.command.is_some());
    }

    #[test]
    fn test_cache_command_cancel() {
        let cmd = CacheCommand::cancel(99);
        let encoded = cmd.encode();
        let decoded = CacheCommand::decode(&encoded).unwrap();
        assert_eq!(decoded.message_id, 99);
        assert_eq!(decoded.control_code, ControlCode::Cancel);
        assert!(decoded.command.is_none());
    }

    #[test]
    fn test_cache_command_length_delimited() {
        let cmd = CacheCommand::new(
            1,
            UnaryCommand::Authenticate {
                auth_token: "token".to_string(),
            },
        );
        let encoded = cmd.encode_length_delimited();
        let (consumed, message) = decode_length_delimited_message(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        let decoded = CacheCommand::decode(message).unwrap();
        assert_eq!(decoded.message_id, 1);
    }

    // CacheResponse tests

    #[test]
    fn test_cache_response_authenticate() {
        let resp = CacheResponse::authenticate(1);
        let encoded = resp.encode();
        let decoded = CacheResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.message_id, 1);
        assert!(matches!(decoded.result, CacheResponseResult::Authenticate));
    }

    #[test]
    fn test_cache_response_get_hit() {
        let resp = CacheResponse::get_hit(2, Bytes::from_static(b"value"));
        let encoded = resp.encode();
        let decoded = CacheResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.message_id, 2);
        match decoded.result {
            CacheResponseResult::Get { value } => {
                assert_eq!(value, Some(Bytes::from_static(b"value")));
            }
            _ => panic!("expected Get"),
        }
    }

    #[test]
    fn test_cache_response_get_miss() {
        let resp = CacheResponse::get_miss(3);
        let encoded = resp.encode();
        let decoded = CacheResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.message_id, 3);
        match decoded.result {
            CacheResponseResult::Get { value } => {
                assert!(value.is_none());
            }
            _ => panic!("expected Get"),
        }
    }

    #[test]
    fn test_cache_response_set_ok() {
        let resp = CacheResponse::set_ok(4);
        let encoded = resp.encode();
        let decoded = CacheResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.message_id, 4);
        assert!(matches!(decoded.result, CacheResponseResult::Set));
    }

    #[test]
    fn test_cache_response_delete_ok() {
        let resp = CacheResponse::delete_ok(5);
        let encoded = resp.encode();
        let decoded = CacheResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.message_id, 5);
        assert!(matches!(decoded.result, CacheResponseResult::Delete));
    }

    #[test]
    fn test_cache_response_error() {
        let resp = CacheResponse::error(6, StatusCode::NotFound, "not found");
        let encoded = resp.encode();
        let decoded = CacheResponse::decode(&encoded).unwrap();
        assert_eq!(decoded.message_id, 6);
        match decoded.result {
            CacheResponseResult::Error(err) => {
                assert_eq!(err.code, StatusCode::NotFound);
                assert_eq!(err.message, "not found");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_cache_response_length_delimited() {
        let resp = CacheResponse::set_ok(7);
        let encoded = resp.encode_length_delimited();
        let (consumed, message) = decode_length_delimited_message(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        let decoded = CacheResponse::decode(message).unwrap();
        assert_eq!(decoded.message_id, 7);
    }

    // decode_length_delimited_message tests

    #[test]
    fn test_decode_length_delimited_message_complete() {
        let data = b"hello";
        let mut buf = Vec::new();
        encode_varint(data.len() as u64, &mut buf);
        buf.extend_from_slice(data);

        let (consumed, message) = decode_length_delimited_message(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(message, data);
    }

    #[test]
    fn test_decode_length_delimited_message_incomplete() {
        let mut buf = Vec::new();
        encode_varint(100, &mut buf); // Says 100 bytes
        buf.extend_from_slice(b"short"); // Only 5 bytes

        let result = decode_length_delimited_message(&buf);
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_length_delimited_message_empty() {
        let result = decode_length_delimited_message(&[]);
        assert!(result.is_none());
    }
}
