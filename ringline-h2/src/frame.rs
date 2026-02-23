//! HTTP/2 frame encoding/decoding (RFC 7540 Section 4).
//!
//! HTTP/2 frames have a fixed 9-byte header:
//! ```text
//! +-----------------------------------------------+
//! |                 Length (24)                    |
//! +---------------+---------------+---------------+
//! |   Type (8)    |   Flags (8)   |
//! +-+-------------+---------------+------...------+
//! |R|                 Stream Identifier (31)       |
//! +-+---------------------------------------------+
//! |                   Frame Payload ...            |
//! +-----------------------------------------------+
//! ```

use crate::error::{ErrorCode, H2Error};
use crate::settings::Settings;

/// Frame header size in bytes.
pub const FRAME_HEADER_LEN: usize = 9;

// Frame type constants (RFC 7540 Section 6).
pub const FRAME_DATA: u8 = 0x0;
pub const FRAME_HEADERS: u8 = 0x1;
pub const FRAME_PRIORITY: u8 = 0x2;
pub const FRAME_RST_STREAM: u8 = 0x3;
pub const FRAME_SETTINGS: u8 = 0x4;
pub const FRAME_PUSH_PROMISE: u8 = 0x5;
pub const FRAME_PING: u8 = 0x6;
pub const FRAME_GOAWAY: u8 = 0x7;
pub const FRAME_WINDOW_UPDATE: u8 = 0x8;
pub const FRAME_CONTINUATION: u8 = 0x9;

// Flag constants.
pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_ACK: u8 = 0x1;
pub const FLAG_END_HEADERS: u8 = 0x4;
pub const FLAG_PADDED: u8 = 0x8;
pub const FLAG_PRIORITY: u8 = 0x20;

/// An HTTP/2 frame.
#[derive(Debug, Clone)]
pub enum Frame {
    /// DATA frame (type 0x0): carries request or response body.
    Data {
        stream_id: u32,
        payload: Vec<u8>,
        end_stream: bool,
    },
    /// HEADERS frame (type 0x1): HPACK-encoded header block fragment.
    Headers {
        stream_id: u32,
        encoded: Vec<u8>,
        end_stream: bool,
        end_headers: bool,
        priority: Option<Priority>,
    },
    /// PRIORITY frame (type 0x2): stream dependency and weight.
    Priority { stream_id: u32, priority: Priority },
    /// RST_STREAM frame (type 0x3): abnormal stream termination.
    RstStream {
        stream_id: u32,
        error_code: ErrorCode,
    },
    /// SETTINGS frame (type 0x4): configuration parameters.
    Settings { ack: bool, settings: Settings },
    /// PUSH_PROMISE frame (type 0x5): server push (not used for client-only).
    PushPromise {
        stream_id: u32,
        promised_stream_id: u32,
        encoded: Vec<u8>,
        end_headers: bool,
    },
    /// PING frame (type 0x6): connection liveness check.
    Ping { ack: bool, opaque_data: [u8; 8] },
    /// GOAWAY frame (type 0x7): graceful shutdown.
    GoAway {
        last_stream_id: u32,
        error_code: ErrorCode,
        debug_data: Vec<u8>,
    },
    /// WINDOW_UPDATE frame (type 0x8): flow control window increment.
    WindowUpdate { stream_id: u32, increment: u32 },
    /// CONTINUATION frame (type 0x9): header block continuation.
    Continuation {
        stream_id: u32,
        encoded: Vec<u8>,
        end_headers: bool,
    },
    /// Unknown frame type — ignored per spec.
    Unknown {
        frame_type: u8,
        flags: u8,
        stream_id: u32,
        payload: Vec<u8>,
    },
}

/// Stream priority information.
#[derive(Debug, Clone, Copy)]
pub struct Priority {
    pub exclusive: bool,
    pub dependency: u32,
    pub weight: u8,
}

// -- Frame header encoding/decoding --

/// Encode a 9-byte frame header.
pub fn encode_frame_header(
    buf: &mut Vec<u8>,
    payload_len: u32,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
) {
    buf.push((payload_len >> 16) as u8);
    buf.push((payload_len >> 8) as u8);
    buf.push(payload_len as u8);
    buf.push(frame_type);
    buf.push(flags);
    let sid = stream_id & 0x7fff_ffff; // clear reserved bit
    buf.push((sid >> 24) as u8);
    buf.push((sid >> 16) as u8);
    buf.push((sid >> 8) as u8);
    buf.push(sid as u8);
}

/// Decoded frame header.
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

/// Decode a 9-byte frame header from the start of `buf`.
/// Returns `None` if the buffer is too short.
pub fn decode_frame_header(buf: &[u8]) -> Option<FrameHeader> {
    if buf.len() < FRAME_HEADER_LEN {
        return None;
    }
    let length = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
    let frame_type = buf[3];
    let flags = buf[4];
    let stream_id = (u32::from(buf[5]) << 24)
        | (u32::from(buf[6]) << 16)
        | (u32::from(buf[7]) << 8)
        | u32::from(buf[8]);
    let stream_id = stream_id & 0x7fff_ffff; // clear reserved bit
    Some(FrameHeader {
        length,
        frame_type,
        flags,
        stream_id,
    })
}

// -- Frame encoding --

impl Frame {
    /// Encode this frame into `buf` (header + payload).
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Frame::Data {
                stream_id,
                payload,
                end_stream,
            } => {
                let flags = if *end_stream { FLAG_END_STREAM } else { 0 };
                encode_frame_header(buf, payload.len() as u32, FRAME_DATA, flags, *stream_id);
                buf.extend_from_slice(payload);
            }
            Frame::Headers {
                stream_id,
                encoded,
                end_stream,
                end_headers,
                priority,
            } => {
                let mut flags = 0u8;
                if *end_stream {
                    flags |= FLAG_END_STREAM;
                }
                if *end_headers {
                    flags |= FLAG_END_HEADERS;
                }
                let mut payload_len = encoded.len() as u32;
                if let Some(pri) = priority {
                    flags |= FLAG_PRIORITY;
                    payload_len += 5; // 4 bytes dependency + 1 byte weight
                    encode_frame_header(buf, payload_len, FRAME_HEADERS, flags, *stream_id);
                    let dep = if pri.exclusive {
                        pri.dependency | 0x8000_0000
                    } else {
                        pri.dependency
                    };
                    buf.push((dep >> 24) as u8);
                    buf.push((dep >> 16) as u8);
                    buf.push((dep >> 8) as u8);
                    buf.push(dep as u8);
                    buf.push(pri.weight);
                } else {
                    encode_frame_header(buf, payload_len, FRAME_HEADERS, flags, *stream_id);
                }
                buf.extend_from_slice(encoded);
            }
            Frame::Priority {
                stream_id,
                priority,
            } => {
                encode_frame_header(buf, 5, FRAME_PRIORITY, 0, *stream_id);
                let dep = if priority.exclusive {
                    priority.dependency | 0x8000_0000
                } else {
                    priority.dependency
                };
                buf.push((dep >> 24) as u8);
                buf.push((dep >> 16) as u8);
                buf.push((dep >> 8) as u8);
                buf.push(dep as u8);
                buf.push(priority.weight);
            }
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                encode_frame_header(buf, 4, FRAME_RST_STREAM, 0, *stream_id);
                let code = *error_code as u32;
                buf.push((code >> 24) as u8);
                buf.push((code >> 16) as u8);
                buf.push((code >> 8) as u8);
                buf.push(code as u8);
            }
            Frame::Settings { ack, settings } => {
                let flags = if *ack { FLAG_ACK } else { 0 };
                if *ack {
                    encode_frame_header(buf, 0, FRAME_SETTINGS, flags, 0);
                } else {
                    let payload = settings.encode_to_vec();
                    encode_frame_header(buf, payload.len() as u32, FRAME_SETTINGS, flags, 0);
                    buf.extend_from_slice(&payload);
                }
            }
            Frame::PushPromise {
                stream_id,
                promised_stream_id,
                encoded,
                end_headers,
            } => {
                let flags = if *end_headers { FLAG_END_HEADERS } else { 0 };
                let payload_len = 4 + encoded.len() as u32;
                encode_frame_header(buf, payload_len, FRAME_PUSH_PROMISE, flags, *stream_id);
                let psid = *promised_stream_id & 0x7fff_ffff;
                buf.push((psid >> 24) as u8);
                buf.push((psid >> 16) as u8);
                buf.push((psid >> 8) as u8);
                buf.push(psid as u8);
                buf.extend_from_slice(encoded);
            }
            Frame::Ping { ack, opaque_data } => {
                let flags = if *ack { FLAG_ACK } else { 0 };
                encode_frame_header(buf, 8, FRAME_PING, flags, 0);
                buf.extend_from_slice(opaque_data);
            }
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                let payload_len = 8 + debug_data.len() as u32;
                encode_frame_header(buf, payload_len, FRAME_GOAWAY, 0, 0);
                let lsid = *last_stream_id & 0x7fff_ffff;
                buf.push((lsid >> 24) as u8);
                buf.push((lsid >> 16) as u8);
                buf.push((lsid >> 8) as u8);
                buf.push(lsid as u8);
                let code = *error_code as u32;
                buf.push((code >> 24) as u8);
                buf.push((code >> 16) as u8);
                buf.push((code >> 8) as u8);
                buf.push(code as u8);
                buf.extend_from_slice(debug_data);
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                encode_frame_header(buf, 4, FRAME_WINDOW_UPDATE, 0, *stream_id);
                let inc = *increment & 0x7fff_ffff;
                buf.push((inc >> 24) as u8);
                buf.push((inc >> 16) as u8);
                buf.push((inc >> 8) as u8);
                buf.push(inc as u8);
            }
            Frame::Continuation {
                stream_id,
                encoded,
                end_headers,
            } => {
                let flags = if *end_headers { FLAG_END_HEADERS } else { 0 };
                encode_frame_header(
                    buf,
                    encoded.len() as u32,
                    FRAME_CONTINUATION,
                    flags,
                    *stream_id,
                );
                buf.extend_from_slice(encoded);
            }
            Frame::Unknown {
                frame_type,
                flags,
                stream_id,
                payload,
            } => {
                encode_frame_header(buf, payload.len() as u32, *frame_type, *flags, *stream_id);
                buf.extend_from_slice(payload);
            }
        }
    }
}

// -- Frame decoding --

/// Decode one frame from the start of `buf`.
///
/// Returns `Ok(Some((frame, bytes_consumed)))` on success,
/// `Ok(None)` if the buffer is incomplete (need more data),
/// or `Err` on protocol error.
pub fn decode_frame(buf: &[u8], max_frame_size: u32) -> Result<Option<(Frame, usize)>, H2Error> {
    let header = match decode_frame_header(buf) {
        Some(h) => h,
        None => return Ok(None),
    };

    let total_len = FRAME_HEADER_LEN + header.length as usize;
    if buf.len() < total_len {
        return Ok(None);
    }

    // Check frame size limit (except SETTINGS, which can be up to 6*N).
    if header.length > max_frame_size && header.frame_type != FRAME_SETTINGS {
        return Err(H2Error::FrameSizeError);
    }

    let payload = &buf[FRAME_HEADER_LEN..total_len];
    let flags = header.flags;
    let stream_id = header.stream_id;

    let frame = match header.frame_type {
        FRAME_DATA => {
            if stream_id == 0 {
                return Err(H2Error::ProtocolError("DATA on stream 0".into()));
            }
            let (payload_data, _pad) = strip_padding(payload, flags)?;
            Frame::Data {
                stream_id,
                payload: payload_data.to_vec(),
                end_stream: flags & FLAG_END_STREAM != 0,
            }
        }
        FRAME_HEADERS => {
            if stream_id == 0 {
                return Err(H2Error::ProtocolError("HEADERS on stream 0".into()));
            }
            let (data, _pad) = strip_padding(payload, flags)?;
            let (priority, header_block) = if flags & FLAG_PRIORITY != 0 {
                if data.len() < 5 {
                    return Err(H2Error::FrameSizeError);
                }
                let dep_raw = (u32::from(data[0]) << 24)
                    | (u32::from(data[1]) << 16)
                    | (u32::from(data[2]) << 8)
                    | u32::from(data[3]);
                let exclusive = dep_raw & 0x8000_0000 != 0;
                let dependency = dep_raw & 0x7fff_ffff;
                let weight = data[4];
                (
                    Some(Priority {
                        exclusive,
                        dependency,
                        weight,
                    }),
                    &data[5..],
                )
            } else {
                (None, data)
            };
            Frame::Headers {
                stream_id,
                encoded: header_block.to_vec(),
                end_stream: flags & FLAG_END_STREAM != 0,
                end_headers: flags & FLAG_END_HEADERS != 0,
                priority,
            }
        }
        FRAME_PRIORITY => {
            if stream_id == 0 {
                return Err(H2Error::ProtocolError("PRIORITY on stream 0".into()));
            }
            if payload.len() != 5 {
                return Err(H2Error::FrameSizeError);
            }
            let dep_raw = (u32::from(payload[0]) << 24)
                | (u32::from(payload[1]) << 16)
                | (u32::from(payload[2]) << 8)
                | u32::from(payload[3]);
            Frame::Priority {
                stream_id,
                priority: Priority {
                    exclusive: dep_raw & 0x8000_0000 != 0,
                    dependency: dep_raw & 0x7fff_ffff,
                    weight: payload[4],
                },
            }
        }
        FRAME_RST_STREAM => {
            if stream_id == 0 {
                return Err(H2Error::ProtocolError("RST_STREAM on stream 0".into()));
            }
            if payload.len() != 4 {
                return Err(H2Error::FrameSizeError);
            }
            let code = (u32::from(payload[0]) << 24)
                | (u32::from(payload[1]) << 16)
                | (u32::from(payload[2]) << 8)
                | u32::from(payload[3]);
            Frame::RstStream {
                stream_id,
                error_code: ErrorCode::from_u32(code),
            }
        }
        FRAME_SETTINGS => {
            if stream_id != 0 {
                return Err(H2Error::ProtocolError("SETTINGS on non-zero stream".into()));
            }
            let ack = flags & FLAG_ACK != 0;
            if ack {
                if !payload.is_empty() {
                    return Err(H2Error::FrameSizeError);
                }
                Frame::Settings {
                    ack: true,
                    settings: Settings::default(),
                }
            } else {
                if !payload.len().is_multiple_of(6) {
                    return Err(H2Error::FrameSizeError);
                }
                let settings = Settings::decode(payload)?;
                Frame::Settings {
                    ack: false,
                    settings,
                }
            }
        }
        FRAME_PUSH_PROMISE => {
            if stream_id == 0 {
                return Err(H2Error::ProtocolError("PUSH_PROMISE on stream 0".into()));
            }
            let (data, _pad) = strip_padding(payload, flags)?;
            if data.len() < 4 {
                return Err(H2Error::FrameSizeError);
            }
            let psid = (u32::from(data[0]) << 24)
                | (u32::from(data[1]) << 16)
                | (u32::from(data[2]) << 8)
                | u32::from(data[3]);
            let psid = psid & 0x7fff_ffff;
            Frame::PushPromise {
                stream_id,
                promised_stream_id: psid,
                encoded: data[4..].to_vec(),
                end_headers: flags & FLAG_END_HEADERS != 0,
            }
        }
        FRAME_PING => {
            if stream_id != 0 {
                return Err(H2Error::ProtocolError("PING on non-zero stream".into()));
            }
            if payload.len() != 8 {
                return Err(H2Error::FrameSizeError);
            }
            let mut data = [0u8; 8];
            data.copy_from_slice(payload);
            Frame::Ping {
                ack: flags & FLAG_ACK != 0,
                opaque_data: data,
            }
        }
        FRAME_GOAWAY => {
            if stream_id != 0 {
                return Err(H2Error::ProtocolError("GOAWAY on non-zero stream".into()));
            }
            if payload.len() < 8 {
                return Err(H2Error::FrameSizeError);
            }
            let lsid = (u32::from(payload[0]) << 24)
                | (u32::from(payload[1]) << 16)
                | (u32::from(payload[2]) << 8)
                | u32::from(payload[3]);
            let lsid = lsid & 0x7fff_ffff;
            let code = (u32::from(payload[4]) << 24)
                | (u32::from(payload[5]) << 16)
                | (u32::from(payload[6]) << 8)
                | u32::from(payload[7]);
            Frame::GoAway {
                last_stream_id: lsid,
                error_code: ErrorCode::from_u32(code),
                debug_data: payload[8..].to_vec(),
            }
        }
        FRAME_WINDOW_UPDATE => {
            if payload.len() != 4 {
                return Err(H2Error::FrameSizeError);
            }
            let inc = (u32::from(payload[0]) << 24)
                | (u32::from(payload[1]) << 16)
                | (u32::from(payload[2]) << 8)
                | u32::from(payload[3]);
            let inc = inc & 0x7fff_ffff;
            if inc == 0 {
                return Err(H2Error::ProtocolError(
                    "WINDOW_UPDATE with 0 increment".into(),
                ));
            }
            Frame::WindowUpdate {
                stream_id,
                increment: inc,
            }
        }
        FRAME_CONTINUATION => {
            if stream_id == 0 {
                return Err(H2Error::ProtocolError("CONTINUATION on stream 0".into()));
            }
            Frame::Continuation {
                stream_id,
                encoded: payload.to_vec(),
                end_headers: flags & FLAG_END_HEADERS != 0,
            }
        }
        _ => Frame::Unknown {
            frame_type: header.frame_type,
            flags,
            stream_id,
            payload: payload.to_vec(),
        },
    };

    Ok(Some((frame, total_len)))
}

/// Strip padding from a frame payload if the PADDED flag is set.
fn strip_padding(payload: &[u8], flags: u8) -> Result<(&[u8], usize), H2Error> {
    if flags & FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(H2Error::FrameSizeError);
        }
        let pad_len = payload[0] as usize;
        if pad_len >= payload.len() {
            return Err(H2Error::ProtocolError("padding exceeds payload".into()));
        }
        Ok((&payload[1..payload.len() - pad_len], pad_len))
    } else {
        Ok((payload, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_round_trip() {
        let mut buf = Vec::new();
        encode_frame_header(&mut buf, 100, FRAME_DATA, FLAG_END_STREAM, 1);
        assert_eq!(buf.len(), 9);
        let header = decode_frame_header(&buf).unwrap();
        assert_eq!(header.length, 100);
        assert_eq!(header.frame_type, FRAME_DATA);
        assert_eq!(header.flags, FLAG_END_STREAM);
        assert_eq!(header.stream_id, 1);
    }

    #[test]
    fn data_frame_round_trip() {
        let frame = Frame::Data {
            stream_id: 1,
            payload: b"hello".to_vec(),
            end_stream: true,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf, 16384).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::Data {
                stream_id,
                payload,
                end_stream,
            } => {
                assert_eq!(stream_id, 1);
                assert_eq!(payload, b"hello");
                assert!(end_stream);
            }
            _ => panic!("expected Data frame"),
        }
    }

    #[test]
    fn headers_frame_round_trip() {
        let frame = Frame::Headers {
            stream_id: 3,
            encoded: vec![0x82, 0x86, 0x84],
            end_stream: false,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf, 16384).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::Headers {
                stream_id,
                encoded,
                end_stream,
                end_headers,
                priority,
            } => {
                assert_eq!(stream_id, 3);
                assert_eq!(encoded, vec![0x82, 0x86, 0x84]);
                assert!(!end_stream);
                assert!(end_headers);
                assert!(priority.is_none());
            }
            _ => panic!("expected Headers frame"),
        }
    }

    #[test]
    fn headers_with_priority_round_trip() {
        let frame = Frame::Headers {
            stream_id: 1,
            encoded: vec![0x82],
            end_stream: true,
            end_headers: true,
            priority: Some(Priority {
                exclusive: true,
                dependency: 0,
                weight: 255,
            }),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, _) = decode_frame(&buf, 16384).unwrap().unwrap();
        match decoded {
            Frame::Headers {
                priority: Some(pri),
                ..
            } => {
                assert!(pri.exclusive);
                assert_eq!(pri.dependency, 0);
                assert_eq!(pri.weight, 255);
            }
            _ => panic!("expected Headers with priority"),
        }
    }

    #[test]
    fn settings_frame_round_trip() {
        let frame = Frame::Settings {
            ack: false,
            settings: Settings::default(),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf, 16384).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::Settings { ack, settings } => {
                assert!(!ack);
                assert_eq!(settings.initial_window_size, 65535);
                assert_eq!(settings.max_frame_size, 16384);
            }
            _ => panic!("expected Settings frame"),
        }
    }

    #[test]
    fn settings_ack_round_trip() {
        let frame = Frame::Settings {
            ack: true,
            settings: Settings::default(),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf, 16384).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::Settings { ack, .. } => assert!(ack),
            _ => panic!("expected Settings frame"),
        }
    }

    #[test]
    fn ping_round_trip() {
        let frame = Frame::Ping {
            ack: false,
            opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf, 16384).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::Ping { ack, opaque_data } => {
                assert!(!ack);
                assert_eq!(opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
            }
            _ => panic!("expected Ping frame"),
        }
    }

    #[test]
    fn goaway_round_trip() {
        let frame = Frame::GoAway {
            last_stream_id: 5,
            error_code: ErrorCode::NoError,
            debug_data: b"bye".to_vec(),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf, 16384).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                assert_eq!(last_stream_id, 5);
                assert_eq!(error_code, ErrorCode::NoError);
                assert_eq!(debug_data, b"bye");
            }
            _ => panic!("expected GoAway frame"),
        }
    }

    #[test]
    fn window_update_round_trip() {
        let frame = Frame::WindowUpdate {
            stream_id: 1,
            increment: 1000,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf, 16384).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                assert_eq!(stream_id, 1);
                assert_eq!(increment, 1000);
            }
            _ => panic!("expected WindowUpdate frame"),
        }
    }

    #[test]
    fn rst_stream_round_trip() {
        let frame = Frame::RstStream {
            stream_id: 1,
            error_code: ErrorCode::Cancel,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, consumed) = decode_frame(&buf, 16384).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                assert_eq!(stream_id, 1);
                assert_eq!(error_code, ErrorCode::Cancel);
            }
            _ => panic!("expected RstStream frame"),
        }
    }

    #[test]
    fn incomplete_frame_returns_none() {
        // Just header, no payload.
        let mut buf = Vec::new();
        encode_frame_header(&mut buf, 5, FRAME_DATA, 0, 1);
        buf.extend_from_slice(b"he");
        assert!(decode_frame(&buf, 16384).unwrap().is_none());
    }

    #[test]
    fn unknown_frame_type_accepted() {
        let mut buf = Vec::new();
        encode_frame_header(&mut buf, 3, 0xfe, 0x42, 7);
        buf.extend_from_slice(b"abc");
        let (frame, consumed) = decode_frame(&buf, 16384).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match frame {
            Frame::Unknown {
                frame_type,
                flags,
                stream_id,
                payload,
            } => {
                assert_eq!(frame_type, 0xfe);
                assert_eq!(flags, 0x42);
                assert_eq!(stream_id, 7);
                assert_eq!(payload, b"abc");
            }
            _ => panic!("expected Unknown frame"),
        }
    }

    #[test]
    fn data_on_stream_zero_rejected() {
        let mut buf = Vec::new();
        encode_frame_header(&mut buf, 0, FRAME_DATA, 0, 0);
        assert!(matches!(
            decode_frame(&buf, 16384),
            Err(H2Error::ProtocolError(_))
        ));
    }

    #[test]
    fn window_update_zero_increment_rejected() {
        let mut buf = Vec::new();
        encode_frame_header(&mut buf, 4, FRAME_WINDOW_UPDATE, 0, 1);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(
            decode_frame(&buf, 16384),
            Err(H2Error::ProtocolError(_))
        ));
    }
}
