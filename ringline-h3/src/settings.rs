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
    ///
    /// Returns `None` if the buffer is malformed or if any setting identifier
    /// appears more than once (RFC 9114 §7.2.4 makes duplicates an
    /// `H3_SETTINGS_ERROR`).
    pub fn decode(mut buf: &[u8]) -> Option<Self> {
        let mut settings = Settings::default();
        let mut seen: Vec<u64> = Vec::new();
        while !buf.is_empty() {
            let (id, n) = decode_varint(buf)?;
            buf = &buf[n..];
            let (value, n) = decode_varint(buf)?;
            buf = &buf[n..];
            // Duplicate identifier (including duplicate-unknown) is a settings
            // error.  Keep the seen list inline — settings frames are small.
            if seen.contains(&id) {
                return None;
            }
            seen.push(id);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_setting_id_rejected() {
        // (0x01, 100) twice — RFC 9114 §7.2.4 H3_SETTINGS_ERROR.
        let mut buf = Vec::new();
        encode_varint(&mut buf, 0x01);
        encode_varint(&mut buf, 100);
        encode_varint(&mut buf, 0x01);
        encode_varint(&mut buf, 200);
        assert!(Settings::decode(&buf).is_none());
    }

    #[test]
    fn duplicate_unknown_setting_id_rejected() {
        // Duplicate unknown id is still a settings error.
        let mut buf = Vec::new();
        encode_varint(&mut buf, 0x42);
        encode_varint(&mut buf, 1);
        encode_varint(&mut buf, 0x42);
        encode_varint(&mut buf, 2);
        assert!(Settings::decode(&buf).is_none());
    }

    #[test]
    fn distinct_settings_accepted() {
        let mut buf = Vec::new();
        encode_varint(&mut buf, 0x01);
        encode_varint(&mut buf, 100);
        encode_varint(&mut buf, 0x07);
        encode_varint(&mut buf, 5);
        let s = Settings::decode(&buf).expect("decode");
        assert_eq!(s.qpack_max_table_capacity, 100);
        assert_eq!(s.qpack_blocked_streams, 5);
    }
}
