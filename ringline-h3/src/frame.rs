//! HTTP/3 frame encoding/decoding and QUIC variable-length integer codec.
//!
//! HTTP/3 frames consist of a varint type, varint length, and payload.
//! This is much simpler than HTTP/2's fixed 9-byte header because QUIC
//! handles stream multiplexing and flow control.

use crate::error::H3Error;
use crate::settings::Settings;

// ── Frame type constants (RFC 9114 Section 7.2) ─────────────────────

pub const FRAME_DATA: u64 = 0x00;
pub const FRAME_HEADERS: u64 = 0x01;
pub const FRAME_SETTINGS: u64 = 0x04;
pub const FRAME_GOAWAY: u64 = 0x07;

/// HTTP/2 frame types that MUST NOT appear in HTTP/3 (RFC 9114 Section 7.2.8).
const RESERVED_H2_TYPES: &[u64] = &[0x02, 0x03, 0x06, 0x08, 0x09];

// ── QUIC Variable-Length Integer (RFC 9000 Section 16) ──────────────

/// Encode a QUIC variable-length integer into `buf`.
///
/// Values 0..2^6 use 1 byte, 2^6..2^14 use 2, 2^14..2^30 use 4, 2^30..2^62 use 8.
pub fn encode_varint(buf: &mut Vec<u8>, value: u64) {
    debug_assert!(value < (1 << 62), "varint value too large");
    if value < (1 << 6) {
        buf.push(value as u8);
    } else if value < (1 << 14) {
        buf.push(0x40 | (value >> 8) as u8);
        buf.push(value as u8);
    } else if value < (1 << 30) {
        buf.push(0x80 | (value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        buf.push(0xc0 | (value >> 56) as u8);
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    }
}

/// Decode a QUIC variable-length integer from the start of `buf`.
///
/// Returns `(value, bytes_consumed)` or `None` if the buffer is too short.
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, len))
}

/// Returns the encoded byte length for a varint value (1, 2, 4, or 8).
pub fn varint_len(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

// ── Frame types ─────────────────────────────────────────────────────

/// An HTTP/3 frame.
#[derive(Debug, Clone)]
pub enum Frame {
    /// DATA frame (type 0x00): carries request or response body.
    Data { payload: Vec<u8> },
    /// HEADERS frame (type 0x01): QPACK-encoded header block.
    Headers { encoded: Vec<u8> },
    /// SETTINGS frame (type 0x04): configuration parameters.
    Settings(Settings),
    /// GOAWAY frame (type 0x07): graceful shutdown with last stream ID.
    GoAway { stream_id: u64 },
    /// Unknown frame type — MUST be ignored per spec (RFC 9114 Section 7.2.8).
    Unknown { frame_type: u64, payload: Vec<u8> },
}

// ── Frame encoding ──────────────────────────────────────────────────

/// Encode a frame header (type + length varints) into `buf`.
pub fn encode_frame_header(buf: &mut Vec<u8>, frame_type: u64, payload_len: u64) {
    encode_varint(buf, frame_type);
    encode_varint(buf, payload_len);
}

impl Frame {
    /// Encode this frame into `buf` (header + payload).
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Frame::Data { payload } => {
                encode_frame_header(buf, FRAME_DATA, payload.len() as u64);
                buf.extend_from_slice(payload);
            }
            Frame::Headers { encoded } => {
                encode_frame_header(buf, FRAME_HEADERS, encoded.len() as u64);
                buf.extend_from_slice(encoded);
            }
            Frame::Settings(settings) => {
                let payload_len = settings.encoded_len();
                encode_frame_header(buf, FRAME_SETTINGS, payload_len as u64);
                settings.encode(buf);
            }
            Frame::GoAway { stream_id } => {
                encode_frame_header(buf, FRAME_GOAWAY, varint_len(*stream_id) as u64);
                encode_varint(buf, *stream_id);
            }
            Frame::Unknown {
                frame_type,
                payload,
            } => {
                encode_frame_header(buf, *frame_type, payload.len() as u64);
                buf.extend_from_slice(payload);
            }
        }
    }
}

// ── Frame decoding ──────────────────────────────────────────────────

/// Decode one frame from the start of `buf`.
///
/// Returns `Ok(Some((frame, bytes_consumed)))` on success,
/// `Ok(None)` if the buffer is incomplete (need more data),
/// or `Err` on protocol error.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, H3Error> {
    // Decode frame type varint.
    let (frame_type, type_len) = match decode_varint(buf) {
        Some(v) => v,
        None => return Ok(None),
    };

    // Decode payload length varint.
    let (payload_len, len_len) = match decode_varint(&buf[type_len..]) {
        Some(v) => v,
        None => return Ok(None),
    };

    let header_len = type_len + len_len;
    let total_len = header_len + payload_len as usize;

    // Check if we have the full frame.
    if buf.len() < total_len {
        return Ok(None);
    }

    let payload = &buf[header_len..total_len];

    // Check for reserved HTTP/2 frame types.
    if RESERVED_H2_TYPES.contains(&frame_type) {
        return Err(H3Error::FrameUnexpected);
    }

    let frame = match frame_type {
        FRAME_DATA => Frame::Data {
            payload: payload.to_vec(),
        },
        FRAME_HEADERS => Frame::Headers {
            encoded: payload.to_vec(),
        },
        FRAME_SETTINGS => {
            let settings = Settings::decode(payload).ok_or(H3Error::FrameError)?;
            Frame::Settings(settings)
        }
        FRAME_GOAWAY => {
            let (stream_id, _) = decode_varint(payload).ok_or(H3Error::FrameError)?;
            Frame::GoAway { stream_id }
        }
        _ => Frame::Unknown {
            frame_type,
            payload: payload.to_vec(),
        },
    };

    Ok(Some((frame, total_len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        let values = [0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824];
        for &v in &values {
            let mut buf = Vec::new();
            encode_varint(&mut buf, v);
            assert_eq!(buf.len(), varint_len(v));
            let (decoded, len) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(len, buf.len());
        }
    }

    #[test]
    fn varint_lengths() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(63), 1);
        assert_eq!(varint_len(64), 2);
        assert_eq!(varint_len(16383), 2);
        assert_eq!(varint_len(16384), 4);
        assert_eq!(varint_len(1073741823), 4);
        assert_eq!(varint_len(1073741824), 8);
    }

    #[test]
    fn frame_data_round_trip() {
        let frame = Frame::Data {
            payload: b"hello".to_vec(),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::Data { payload } => assert_eq!(payload, b"hello"),
            _ => panic!("expected Data frame"),
        }
    }

    #[test]
    fn frame_headers_round_trip() {
        let frame = Frame::Headers {
            encoded: vec![0x00, 0x00, 0xd1],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::Headers { encoded } => assert_eq!(encoded, vec![0x00, 0x00, 0xd1]),
            _ => panic!("expected Headers frame"),
        }
    }

    #[test]
    fn frame_settings_round_trip() {
        let settings = Settings::default();
        let frame = Frame::Settings(settings);
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::Settings(s) => {
                assert_eq!(s.qpack_max_table_capacity, 0);
                assert_eq!(s.qpack_blocked_streams, 0);
            }
            _ => panic!("expected Settings frame"),
        }
    }

    #[test]
    fn frame_goaway_round_trip() {
        let frame = Frame::GoAway { stream_id: 4 };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::GoAway { stream_id } => assert_eq!(stream_id, 4),
            _ => panic!("expected GoAway frame"),
        }
    }

    #[test]
    fn reserved_h2_type_rejected() {
        // Type 0x02 (HTTP/2 PRIORITY) is reserved.
        let mut buf = Vec::new();
        encode_varint(&mut buf, 0x02); // type
        encode_varint(&mut buf, 0); // length
        assert!(matches!(decode_frame(&buf), Err(H3Error::FrameUnexpected)));
    }

    #[test]
    fn incomplete_frame_returns_none() {
        // Just a type byte, no length.
        assert!(decode_frame(&[0x00]).unwrap().is_none());
        // Type + length says 5 bytes payload, but only 2 present.
        let mut buf = Vec::new();
        encode_varint(&mut buf, 0x00);
        encode_varint(&mut buf, 5);
        buf.extend_from_slice(b"he");
        assert!(decode_frame(&buf).unwrap().is_none());
    }

    #[test]
    fn unknown_frame_type_accepted() {
        let mut buf = Vec::new();
        encode_varint(&mut buf, 0xff); // unknown type
        encode_varint(&mut buf, 3);
        buf.extend_from_slice(b"abc");
        let (frame, consumed) = decode_frame(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match frame {
            Frame::Unknown {
                frame_type,
                payload,
            } => {
                assert_eq!(frame_type, 0xff);
                assert_eq!(payload, b"abc");
            }
            _ => panic!("expected Unknown frame"),
        }
    }
}
