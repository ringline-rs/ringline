use crate::frame::{decode_varint, encode_varint, varint_len};

/// HTTP/3 SETTINGS parameters (RFC 9114 Section 7.2.4.1).
#[derive(Debug, Clone)]
pub struct Settings {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01). Default 0 (no dynamic table).
    pub qpack_max_table_capacity: u64,
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (0x06). Default unlimited.
    pub max_field_section_size: u64,
    /// SETTINGS_QPACK_BLOCKED_STREAMS (0x07). Default 0.
    pub qpack_blocked_streams: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            qpack_max_table_capacity: 0,
            max_field_section_size: u64::MAX,
            qpack_blocked_streams: 0,
        }
    }
}

impl Settings {
    /// Encode settings as a sequence of (identifier, value) varint pairs.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        // Only encode non-default values to save space.
        if self.qpack_max_table_capacity != 0 {
            encode_varint(buf, 0x01);
            encode_varint(buf, self.qpack_max_table_capacity);
        }
        if self.max_field_section_size != u64::MAX {
            encode_varint(buf, 0x06);
            encode_varint(buf, self.max_field_section_size);
        }
        if self.qpack_blocked_streams != 0 {
            encode_varint(buf, 0x07);
            encode_varint(buf, self.qpack_blocked_streams);
        }
    }

    /// Decode settings from a byte buffer containing (identifier, value) varint pairs.
    pub fn decode(mut buf: &[u8]) -> Option<Self> {
        let mut settings = Settings::default();
        while !buf.is_empty() {
            let (id, n) = decode_varint(buf)?;
            buf = &buf[n..];
            let (value, n) = decode_varint(buf)?;
            buf = &buf[n..];
            match id {
                0x01 => settings.qpack_max_table_capacity = value,
                0x06 => settings.max_field_section_size = value,
                0x07 => settings.qpack_blocked_streams = value,
                // Unknown settings are ignored per spec (RFC 9114 Section 7.2.4).
                _ => {}
            }
        }
        Some(settings)
    }

    /// Byte length when encoded.
    pub fn encoded_len(&self) -> usize {
        let mut len = 0;
        if self.qpack_max_table_capacity != 0 {
            len += varint_len(0x01) + varint_len(self.qpack_max_table_capacity);
        }
        if self.max_field_section_size != u64::MAX {
            len += varint_len(0x06) + varint_len(self.max_field_section_size);
        }
        if self.qpack_blocked_streams != 0 {
            len += varint_len(0x07) + varint_len(self.qpack_blocked_streams);
        }
        len
    }
}
