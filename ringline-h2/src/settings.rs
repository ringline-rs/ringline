//! HTTP/2 SETTINGS parameters (RFC 7540 Section 6.5.1).

use crate::error::H2Error;

// Settings identifiers.
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// HTTP/2 SETTINGS parameters.
#[derive(Debug, Clone)]
pub struct Settings {
    /// SETTINGS_HEADER_TABLE_SIZE (0x1). Default 4096.
    pub header_table_size: u32,
    /// SETTINGS_ENABLE_PUSH (0x2). Default 1 (enabled).
    pub enable_push: bool,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (0x3). Default unlimited.
    pub max_concurrent_streams: Option<u32>,
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x4). Default 65535.
    pub initial_window_size: u32,
    /// SETTINGS_MAX_FRAME_SIZE (0x5). Default 16384.
    pub max_frame_size: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (0x6). Default unlimited.
    pub max_header_list_size: Option<u32>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: 65535,
            max_frame_size: 16384,
            max_header_list_size: None,
        }
    }
}

impl Settings {
    /// Client defaults: push disabled (ENABLE_PUSH=0).
    pub fn client_default() -> Self {
        Self {
            enable_push: false,
            ..Default::default()
        }
    }

    /// Encode settings as a sequence of 6-byte (id: u16, value: u32) pairs.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    /// Encode settings into `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        encode_setting(buf, SETTINGS_HEADER_TABLE_SIZE, self.header_table_size);
        encode_setting(
            buf,
            SETTINGS_ENABLE_PUSH,
            if self.enable_push { 1 } else { 0 },
        );
        if let Some(v) = self.max_concurrent_streams {
            encode_setting(buf, SETTINGS_MAX_CONCURRENT_STREAMS, v);
        }
        encode_setting(buf, SETTINGS_INITIAL_WINDOW_SIZE, self.initial_window_size);
        encode_setting(buf, SETTINGS_MAX_FRAME_SIZE, self.max_frame_size);
        if let Some(v) = self.max_header_list_size {
            encode_setting(buf, SETTINGS_MAX_HEADER_LIST_SIZE, v);
        }
    }

    /// Decode settings from a byte buffer of 6-byte pairs.
    pub fn decode(buf: &[u8]) -> Result<Self, H2Error> {
        if !buf.len().is_multiple_of(6) {
            return Err(H2Error::FrameSizeError);
        }
        let mut settings = Settings::default();
        let mut pos = 0;
        while pos + 6 <= buf.len() {
            let id = (u16::from(buf[pos]) << 8) | u16::from(buf[pos + 1]);
            let value = (u32::from(buf[pos + 2]) << 24)
                | (u32::from(buf[pos + 3]) << 16)
                | (u32::from(buf[pos + 4]) << 8)
                | u32::from(buf[pos + 5]);
            pos += 6;
            match id {
                SETTINGS_HEADER_TABLE_SIZE => settings.header_table_size = value,
                SETTINGS_ENABLE_PUSH => {
                    if value > 1 {
                        return Err(H2Error::ProtocolError("ENABLE_PUSH must be 0 or 1".into()));
                    }
                    settings.enable_push = value == 1;
                }
                SETTINGS_MAX_CONCURRENT_STREAMS => {
                    settings.max_concurrent_streams = Some(value);
                }
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if value > 0x7fff_ffff {
                        return Err(H2Error::FlowControlError);
                    }
                    settings.initial_window_size = value;
                }
                SETTINGS_MAX_FRAME_SIZE => {
                    if !(16384..=16_777_215).contains(&value) {
                        return Err(H2Error::ProtocolError("MAX_FRAME_SIZE out of range".into()));
                    }
                    settings.max_frame_size = value;
                }
                SETTINGS_MAX_HEADER_LIST_SIZE => {
                    settings.max_header_list_size = Some(value);
                }
                // Unknown settings MUST be ignored (RFC 7540 Section 6.5.2).
                _ => {}
            }
        }
        Ok(settings)
    }
}

fn encode_setting(buf: &mut Vec<u8>, id: u16, value: u32) {
    buf.push((id >> 8) as u8);
    buf.push(id as u8);
    buf.push((value >> 24) as u8);
    buf.push((value >> 16) as u8);
    buf.push((value >> 8) as u8);
    buf.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_round_trip() {
        let settings = Settings::default();
        let encoded = settings.encode_to_vec();
        let decoded = Settings::decode(&encoded).unwrap();
        assert_eq!(decoded.header_table_size, 4096);
        assert!(decoded.enable_push);
        assert_eq!(decoded.initial_window_size, 65535);
        assert_eq!(decoded.max_frame_size, 16384);
    }

    #[test]
    fn client_settings_round_trip() {
        let settings = Settings::client_default();
        let encoded = settings.encode_to_vec();
        let decoded = Settings::decode(&encoded).unwrap();
        assert!(!decoded.enable_push);
    }

    #[test]
    fn custom_settings_round_trip() {
        let settings = Settings {
            header_table_size: 8192,
            enable_push: false,
            max_concurrent_streams: Some(100),
            initial_window_size: 1048576,
            max_frame_size: 32768,
            max_header_list_size: Some(65536),
        };
        let encoded = settings.encode_to_vec();
        let decoded = Settings::decode(&encoded).unwrap();
        assert_eq!(decoded.header_table_size, 8192);
        assert!(!decoded.enable_push);
        assert_eq!(decoded.max_concurrent_streams, Some(100));
        assert_eq!(decoded.initial_window_size, 1048576);
        assert_eq!(decoded.max_frame_size, 32768);
        assert_eq!(decoded.max_header_list_size, Some(65536));
    }

    #[test]
    fn invalid_enable_push_rejected() {
        let mut buf = Vec::new();
        encode_setting(&mut buf, 0x2, 2); // ENABLE_PUSH = 2 is invalid
        assert!(Settings::decode(&buf).is_err());
    }

    #[test]
    fn invalid_window_size_rejected() {
        let mut buf = Vec::new();
        encode_setting(&mut buf, 0x4, 0x8000_0000); // > 2^31 - 1
        assert!(Settings::decode(&buf).is_err());
    }

    #[test]
    fn invalid_max_frame_size_rejected() {
        let mut buf = Vec::new();
        encode_setting(&mut buf, 0x5, 100); // < 16384
        assert!(Settings::decode(&buf).is_err());
    }

    #[test]
    fn unknown_setting_ignored() {
        let mut buf = Vec::new();
        encode_setting(&mut buf, 0xff, 42);
        let decoded = Settings::decode(&buf).unwrap();
        assert_eq!(decoded.header_table_size, 4096); // still default
    }
}
