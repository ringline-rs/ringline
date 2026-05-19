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

/// Upper bound on the payload length we'll accept for a single HTTP/3 frame.
///
/// A QUIC varint can encode up to 2^62 − 1; without a ceiling, a malicious or
/// buggy peer can declare an enormous frame length and force the decoder to
/// buffer toward that size before we ever see the payload. 16 MiB comfortably
/// fits the largest HEADERS / DATA frames we expect in practice while keeping
/// per-stream and control-stream memory bounded.
pub const MAX_FRAME_PAYLOAD: u64 = 16 * 1024 * 1024;

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
    ///
    /// `payload` is a refcounted `Bytes`; when the frame is decoded
    /// from a parent buffer via [`decode_frame_in`] the payload is an
    /// O(1) slice into that buffer, avoiding any copy of the body.
    Data { payload: bytes::Bytes },
    /// HEADERS frame (type 0x01): QPACK-encoded header block.
    Headers { encoded: Vec<u8> },
    /// SETTINGS frame (type 0x04): configuration parameters.
    Settings(Settings),
    /// GOAWAY frame (type 0x07): graceful shutdown with last stream ID.
    GoAway { stream_id: u64 },
    /// Unknown frame type — MUST be ignored per spec (RFC 9114 Section 7.2.8).
    Unknown {
        frame_type: u64,
        payload: bytes::Bytes,
    },
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

/// Layout of the next frame, without owning any payload bytes.
///
/// Used by [`peek_frame`] to drive the zero-copy decode path:
/// callers parse the frame header, learn the total length, and only
/// commit + slice the payload once they hold the bytes that back the
/// frame.
#[derive(Debug, Clone, Copy)]
struct FrameLayout {
    frame_type: u64,
    header_len: usize,
    payload_len: usize,
}

impl FrameLayout {
    fn total_len(&self) -> usize {
        self.header_len + self.payload_len
    }
}

/// Read the frame header from the start of `buf` without copying any
/// payload bytes. Returns `Ok(None)` if `buf` does not yet contain
/// the full header.
fn peek_frame(buf: &[u8]) -> Result<Option<FrameLayout>, H3Error> {
    let (frame_type, type_len) = match decode_varint(buf) {
        Some(v) => v,
        None => return Ok(None),
    };

    let (payload_len, len_len) = match decode_varint(&buf[type_len..]) {
        Some(v) => v,
        None => return Ok(None),
    };

    // Reject pathological lengths before we let them anywhere near a usize
    // cast or an allocation. Without this a peer can declare a 2^62-byte frame
    // and force us to grow a recv buffer toward that size before we'd ever
    // notice.
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(H3Error::ExcessiveSize);
    }
    let payload_len = payload_len as usize; // safe: bounded by MAX_FRAME_PAYLOAD

    // Check for reserved HTTP/2 frame types.
    if RESERVED_H2_TYPES.contains(&frame_type) {
        return Err(H3Error::FrameUnexpected);
    }

    Ok(Some(FrameLayout {
        frame_type,
        header_len: type_len + len_len,
        payload_len,
    }))
}

/// Build the owned `Frame` for a layout whose payload bytes are
/// already in hand. `payload` must be exactly `layout.payload_len`
/// bytes long.
fn finish_frame(layout: FrameLayout, payload: bytes::Bytes) -> Result<Frame, H3Error> {
    debug_assert_eq!(payload.len(), layout.payload_len);
    let frame = match layout.frame_type {
        FRAME_DATA => Frame::Data { payload },
        FRAME_HEADERS => Frame::Headers {
            encoded: payload.to_vec(),
        },
        FRAME_SETTINGS => {
            let settings = Settings::decode(&payload).ok_or(H3Error::FrameError)?;
            Frame::Settings(settings)
        }
        FRAME_GOAWAY => {
            let (stream_id, _) = decode_varint(&payload).ok_or(H3Error::FrameError)?;
            Frame::GoAway { stream_id }
        }
        frame_type => Frame::Unknown {
            frame_type,
            payload,
        },
    };
    Ok(frame)
}

/// Decode one frame from the start of `buf`.
///
/// Returns `Ok(Some((frame, bytes_consumed)))` on success,
/// `Ok(None)` if the buffer is incomplete (need more data),
/// or `Err` on protocol error.
///
/// The frame's payload is copied into a fresh `Bytes`. The hot
/// receive path in [`crate::H3Connection`] uses [`decode_frame_in`]
/// instead, which slices the payload zero-copy out of the parent
/// `Bytes`. This entry point is convenient for tests and call sites
/// that only have a borrowed slice.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, H3Error> {
    let layout = match peek_frame(buf)? {
        Some(l) => l,
        None => return Ok(None),
    };
    let total_len = layout.total_len();
    if buf.len() < total_len {
        return Ok(None);
    }
    let payload = bytes::Bytes::copy_from_slice(
        &buf[layout.header_len..layout.header_len + layout.payload_len],
    );
    let frame = finish_frame(layout, payload)?;
    Ok(Some((frame, total_len)))
}

/// Zero-copy counterpart of [`decode_frame`]. Decodes a frame whose
/// bytes sit at `parent[offset..]`; DATA / Unknown payloads come
/// back as `parent.slice(...)` — a refcount bump, no memcpy.
///
/// Returns `Ok(None)` when `parent` does not yet contain the full
/// frame past `offset`, leaving the caller to read more bytes and
/// retry.
pub fn decode_frame_in(
    parent: &bytes::Bytes,
    offset: usize,
) -> Result<Option<(Frame, usize)>, H3Error> {
    let buf = &parent[offset..];
    let layout = match peek_frame(buf)? {
        Some(l) => l,
        None => return Ok(None),
    };
    let total_len = layout.total_len();
    if buf.len() < total_len {
        return Ok(None);
    }
    let payload_start = offset + layout.header_len;
    let payload_end = payload_start + layout.payload_len;
    let payload = parent.slice(payload_start..payload_end);
    let frame = finish_frame(layout, payload)?;
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
            payload: bytes::Bytes::from_static(b"hello"),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::Data { payload } => assert_eq!(payload.as_ref(), b"hello"),
            _ => panic!("expected Data frame"),
        }
    }

    #[test]
    fn frame_data_decode_in_zero_copy() {
        // Build a parent buffer that holds two DATA frames back-to-back.
        let mut wire = Vec::new();
        Frame::Data {
            payload: bytes::Bytes::from_static(b"hello"),
        }
        .encode(&mut wire);
        Frame::Data {
            payload: bytes::Bytes::from_static(b"world!"),
        }
        .encode(&mut wire);
        let parent = bytes::Bytes::from(wire);
        let (first, consumed_a) = decode_frame_in(&parent, 0).unwrap().unwrap();
        let (second, _consumed_b) = decode_frame_in(&parent, consumed_a).unwrap().unwrap();
        match (first, second) {
            (Frame::Data { payload: a }, Frame::Data { payload: b }) => {
                assert_eq!(a.as_ref(), b"hello");
                assert_eq!(b.as_ref(), b"world!");
                // Both payloads must point into `parent` — verify by checking
                // that slicing the parent at the same range yields equal bytes
                // (the `slice` method panics on a different allocation).
                assert_eq!(a, parent.slice(2..2 + 5));
            }
            _ => panic!("expected two DATA frames"),
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
    fn oversize_frame_rejected() {
        // A peer-declared payload length above MAX_FRAME_PAYLOAD must be
        // rejected before we look at (or buffer toward) the payload.
        let mut buf = Vec::new();
        encode_varint(&mut buf, FRAME_DATA);
        encode_varint(&mut buf, MAX_FRAME_PAYLOAD + 1);
        assert!(matches!(decode_frame(&buf), Err(H3Error::ExcessiveSize)));

        // The pathological 2^62 - 1 ceiling that a malicious peer might use.
        let mut buf = Vec::new();
        encode_varint(&mut buf, FRAME_DATA);
        encode_varint(&mut buf, (1u64 << 62) - 1);
        assert!(matches!(decode_frame(&buf), Err(H3Error::ExcessiveSize)));
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
                assert_eq!(payload.as_ref(), b"abc");
            }
            _ => panic!("expected Unknown frame"),
        }
    }
}
