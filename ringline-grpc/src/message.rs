/// Encode a gRPC length-prefixed message.
///
/// Format: 1 byte compress flag (0 = uncompressed) + 4 byte big-endian length + payload.
pub fn encode(payload: &[u8], out: &mut Vec<u8>) {
    out.push(0); // compress flag: uncompressed
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Result of attempting to decode a gRPC length-prefixed message from a buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeResult {
    /// A complete message was decoded. Contains the payload and bytes consumed.
    Complete { payload: Vec<u8>, consumed: usize },
    /// Not enough data yet; need at least this many more bytes.
    Incomplete(usize),
}

/// Try to decode one gRPC length-prefixed message from the front of `buf`.
///
/// Returns `Complete` with the payload and total consumed bytes, or `Incomplete`
/// with the number of additional bytes needed.
pub fn decode(buf: &[u8]) -> DecodeResult {
    if buf.len() < 5 {
        return DecodeResult::Incomplete(5 - buf.len());
    }

    // byte 0: compress flag (ignored for now — we don't support compression)
    let length = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let total = 5 + length;

    if buf.len() < total {
        return DecodeResult::Incomplete(total - buf.len());
    }

    DecodeResult::Complete {
        payload: buf[5..total].to_vec(),
        consumed: total,
    }
}

/// Per-stream buffer for reassembling gRPC messages from DATA frame chunks.
#[derive(Debug, Default)]
pub struct MessageBuffer {
    buf: Vec<u8>,
}

impl MessageBuffer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append data from a DATA frame.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to drain one complete message. Returns `None` if incomplete.
    pub fn try_decode(&mut self) -> Option<Vec<u8>> {
        match decode(&self.buf) {
            DecodeResult::Complete { payload, consumed } => {
                self.buf.drain(..consumed);
                Some(payload)
            }
            DecodeResult::Incomplete(_) => None,
        }
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let payload = b"hello grpc";
        let mut buf = Vec::new();
        encode(payload, &mut buf);

        assert_eq!(buf.len(), 5 + payload.len());
        assert_eq!(buf[0], 0); // no compression
        assert_eq!(
            u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            payload.len() as u32
        );

        match decode(&buf) {
            DecodeResult::Complete {
                payload: decoded,
                consumed,
            } => {
                assert_eq!(decoded, payload);
                assert_eq!(consumed, buf.len());
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn decode_incomplete_header() {
        assert_eq!(decode(&[]), DecodeResult::Incomplete(5));
        assert_eq!(decode(&[0, 0]), DecodeResult::Incomplete(3));
        assert_eq!(decode(&[0, 0, 0, 0]), DecodeResult::Incomplete(1));
    }

    #[test]
    fn decode_incomplete_payload() {
        let mut buf = Vec::new();
        encode(b"hello", &mut buf);
        // Truncate to just the header + 2 bytes of payload.
        buf.truncate(7);
        assert_eq!(decode(&buf), DecodeResult::Incomplete(3));
    }

    #[test]
    fn encode_empty_message() {
        let mut buf = Vec::new();
        encode(b"", &mut buf);
        assert_eq!(buf, &[0, 0, 0, 0, 0]);
        match decode(&buf) {
            DecodeResult::Complete {
                payload, consumed, ..
            } => {
                assert!(payload.is_empty());
                assert_eq!(consumed, 5);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn message_buffer_reassembly() {
        let payload = b"reassembled message";
        let mut encoded = Vec::new();
        encode(payload, &mut encoded);

        let mut mb = MessageBuffer::new();
        assert!(mb.is_empty());

        // Feed in chunks.
        mb.push(&encoded[..3]);
        assert!(mb.try_decode().is_none());

        mb.push(&encoded[3..8]);
        assert!(mb.try_decode().is_none());

        mb.push(&encoded[8..]);
        let decoded = mb.try_decode().unwrap();
        assert_eq!(decoded, payload);
        assert!(mb.is_empty());
    }

    #[test]
    fn message_buffer_multiple_messages() {
        let mut encoded = Vec::new();
        encode(b"first", &mut encoded);
        encode(b"second", &mut encoded);

        let mut mb = MessageBuffer::new();
        mb.push(&encoded);

        assert_eq!(mb.try_decode().unwrap(), b"first");
        assert_eq!(mb.try_decode().unwrap(), b"second");
        assert!(mb.try_decode().is_none());
        assert!(mb.is_empty());
    }
}
