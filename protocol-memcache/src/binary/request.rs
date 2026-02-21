//! Client-side binary protocol request encoding.
//!
//! This module provides methods for encoding Memcache binary protocol requests.

use super::header::{HEADER_SIZE, Opcode, RequestHeader};

/// A binary protocol request builder.
///
/// Provides methods for encoding various request types directly into a buffer.
pub struct BinaryRequest;

impl BinaryRequest {
    /// Encode a GET request.
    pub fn encode_get(buf: &mut [u8], key: &[u8], opaque: u32) -> usize {
        let mut header = RequestHeader::new(Opcode::Get);
        header.key_length = key.len() as u16;
        header.total_body_length = key.len() as u32;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + key.len()].copy_from_slice(key);
        HEADER_SIZE + key.len()
    }

    /// Encode a GETQ (quiet GET) request.
    pub fn encode_getq(buf: &mut [u8], key: &[u8], opaque: u32) -> usize {
        let mut header = RequestHeader::new(Opcode::GetQ);
        header.key_length = key.len() as u16;
        header.total_body_length = key.len() as u32;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + key.len()].copy_from_slice(key);
        HEADER_SIZE + key.len()
    }

    /// Encode a GETK request (returns key in response).
    pub fn encode_getk(buf: &mut [u8], key: &[u8], opaque: u32) -> usize {
        let mut header = RequestHeader::new(Opcode::GetK);
        header.key_length = key.len() as u16;
        header.total_body_length = key.len() as u32;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + key.len()].copy_from_slice(key);
        HEADER_SIZE + key.len()
    }

    /// Encode a SET request.
    pub fn encode_set(
        buf: &mut [u8],
        key: &[u8],
        value: &[u8],
        flags: u32,
        expiration: u32,
        cas: u64,
        opaque: u32,
    ) -> usize {
        let extras_len = 8;
        let total_body = extras_len + key.len() + value.len();

        let mut header = RequestHeader::new(Opcode::Set);
        header.key_length = key.len() as u16;
        header.extras_length = extras_len as u8;
        header.total_body_length = total_body as u32;
        header.cas = cas;
        header.opaque = opaque;
        header.encode(buf);

        // Write extras (flags + expiration)
        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&flags.to_be_bytes());
        buf[HEADER_SIZE + 4..HEADER_SIZE + 8].copy_from_slice(&expiration.to_be_bytes());

        // Write key
        let key_start = HEADER_SIZE + 8;
        buf[key_start..key_start + key.len()].copy_from_slice(key);

        // Write value
        let value_start = key_start + key.len();
        buf[value_start..value_start + value.len()].copy_from_slice(value);

        HEADER_SIZE + total_body
    }

    /// Encode a SETQ (quiet SET) request.
    pub fn encode_setq(
        buf: &mut [u8],
        key: &[u8],
        value: &[u8],
        flags: u32,
        expiration: u32,
        cas: u64,
        opaque: u32,
    ) -> usize {
        let extras_len = 8;
        let total_body = extras_len + key.len() + value.len();

        let mut header = RequestHeader::new(Opcode::SetQ);
        header.key_length = key.len() as u16;
        header.extras_length = extras_len as u8;
        header.total_body_length = total_body as u32;
        header.cas = cas;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&flags.to_be_bytes());
        buf[HEADER_SIZE + 4..HEADER_SIZE + 8].copy_from_slice(&expiration.to_be_bytes());

        let key_start = HEADER_SIZE + 8;
        buf[key_start..key_start + key.len()].copy_from_slice(key);

        let value_start = key_start + key.len();
        buf[value_start..value_start + value.len()].copy_from_slice(value);

        HEADER_SIZE + total_body
    }

    /// Encode an ADD request (only store if key doesn't exist).
    pub fn encode_add(
        buf: &mut [u8],
        key: &[u8],
        value: &[u8],
        flags: u32,
        expiration: u32,
        opaque: u32,
    ) -> usize {
        let extras_len = 8;
        let total_body = extras_len + key.len() + value.len();

        let mut header = RequestHeader::new(Opcode::Add);
        header.key_length = key.len() as u16;
        header.extras_length = extras_len as u8;
        header.total_body_length = total_body as u32;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&flags.to_be_bytes());
        buf[HEADER_SIZE + 4..HEADER_SIZE + 8].copy_from_slice(&expiration.to_be_bytes());

        let key_start = HEADER_SIZE + 8;
        buf[key_start..key_start + key.len()].copy_from_slice(key);

        let value_start = key_start + key.len();
        buf[value_start..value_start + value.len()].copy_from_slice(value);

        HEADER_SIZE + total_body
    }

    /// Encode a REPLACE request (only store if key exists).
    pub fn encode_replace(
        buf: &mut [u8],
        key: &[u8],
        value: &[u8],
        flags: u32,
        expiration: u32,
        cas: u64,
        opaque: u32,
    ) -> usize {
        let extras_len = 8;
        let total_body = extras_len + key.len() + value.len();

        let mut header = RequestHeader::new(Opcode::Replace);
        header.key_length = key.len() as u16;
        header.extras_length = extras_len as u8;
        header.total_body_length = total_body as u32;
        header.cas = cas;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&flags.to_be_bytes());
        buf[HEADER_SIZE + 4..HEADER_SIZE + 8].copy_from_slice(&expiration.to_be_bytes());

        let key_start = HEADER_SIZE + 8;
        buf[key_start..key_start + key.len()].copy_from_slice(key);

        let value_start = key_start + key.len();
        buf[value_start..value_start + value.len()].copy_from_slice(value);

        HEADER_SIZE + total_body
    }

    /// Encode a DELETE request.
    pub fn encode_delete(buf: &mut [u8], key: &[u8], cas: u64, opaque: u32) -> usize {
        let mut header = RequestHeader::new(Opcode::Delete);
        header.key_length = key.len() as u16;
        header.total_body_length = key.len() as u32;
        header.cas = cas;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + key.len()].copy_from_slice(key);
        HEADER_SIZE + key.len()
    }

    /// Encode a DELETEQ (quiet DELETE) request.
    pub fn encode_deleteq(buf: &mut [u8], key: &[u8], cas: u64, opaque: u32) -> usize {
        let mut header = RequestHeader::new(Opcode::DeleteQ);
        header.key_length = key.len() as u16;
        header.total_body_length = key.len() as u32;
        header.cas = cas;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + key.len()].copy_from_slice(key);
        HEADER_SIZE + key.len()
    }

    /// Encode an INCREMENT request.
    pub fn encode_increment(
        buf: &mut [u8],
        key: &[u8],
        delta: u64,
        initial: u64,
        expiration: u32,
        cas: u64,
        opaque: u32,
    ) -> usize {
        let extras_len = 20;
        let total_body = extras_len + key.len();

        let mut header = RequestHeader::new(Opcode::Increment);
        header.key_length = key.len() as u16;
        header.extras_length = extras_len as u8;
        header.total_body_length = total_body as u32;
        header.cas = cas;
        header.opaque = opaque;
        header.encode(buf);

        // Write extras: delta (8) + initial (8) + expiration (4)
        buf[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(&delta.to_be_bytes());
        buf[HEADER_SIZE + 8..HEADER_SIZE + 16].copy_from_slice(&initial.to_be_bytes());
        buf[HEADER_SIZE + 16..HEADER_SIZE + 20].copy_from_slice(&expiration.to_be_bytes());

        // Write key
        buf[HEADER_SIZE + 20..HEADER_SIZE + 20 + key.len()].copy_from_slice(key);

        HEADER_SIZE + total_body
    }

    /// Encode a DECREMENT request.
    pub fn encode_decrement(
        buf: &mut [u8],
        key: &[u8],
        delta: u64,
        initial: u64,
        expiration: u32,
        cas: u64,
        opaque: u32,
    ) -> usize {
        let extras_len = 20;
        let total_body = extras_len + key.len();

        let mut header = RequestHeader::new(Opcode::Decrement);
        header.key_length = key.len() as u16;
        header.extras_length = extras_len as u8;
        header.total_body_length = total_body as u32;
        header.cas = cas;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(&delta.to_be_bytes());
        buf[HEADER_SIZE + 8..HEADER_SIZE + 16].copy_from_slice(&initial.to_be_bytes());
        buf[HEADER_SIZE + 16..HEADER_SIZE + 20].copy_from_slice(&expiration.to_be_bytes());

        buf[HEADER_SIZE + 20..HEADER_SIZE + 20 + key.len()].copy_from_slice(key);

        HEADER_SIZE + total_body
    }

    /// Encode an APPEND request.
    pub fn encode_append(buf: &mut [u8], key: &[u8], value: &[u8], cas: u64, opaque: u32) -> usize {
        let total_body = key.len() + value.len();

        let mut header = RequestHeader::new(Opcode::Append);
        header.key_length = key.len() as u16;
        header.total_body_length = total_body as u32;
        header.cas = cas;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + key.len()].copy_from_slice(key);
        buf[HEADER_SIZE + key.len()..HEADER_SIZE + key.len() + value.len()].copy_from_slice(value);

        HEADER_SIZE + total_body
    }

    /// Encode a PREPEND request.
    pub fn encode_prepend(
        buf: &mut [u8],
        key: &[u8],
        value: &[u8],
        cas: u64,
        opaque: u32,
    ) -> usize {
        let total_body = key.len() + value.len();

        let mut header = RequestHeader::new(Opcode::Prepend);
        header.key_length = key.len() as u16;
        header.total_body_length = total_body as u32;
        header.cas = cas;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + key.len()].copy_from_slice(key);
        buf[HEADER_SIZE + key.len()..HEADER_SIZE + key.len() + value.len()].copy_from_slice(value);

        HEADER_SIZE + total_body
    }

    /// Encode a TOUCH request.
    pub fn encode_touch(buf: &mut [u8], key: &[u8], expiration: u32, opaque: u32) -> usize {
        let extras_len = 4;
        let total_body = extras_len + key.len();

        let mut header = RequestHeader::new(Opcode::Touch);
        header.key_length = key.len() as u16;
        header.extras_length = extras_len as u8;
        header.total_body_length = total_body as u32;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&expiration.to_be_bytes());
        buf[HEADER_SIZE + 4..HEADER_SIZE + 4 + key.len()].copy_from_slice(key);

        HEADER_SIZE + total_body
    }

    /// Encode a GAT (Get And Touch) request.
    pub fn encode_gat(buf: &mut [u8], key: &[u8], expiration: u32, opaque: u32) -> usize {
        let extras_len = 4;
        let total_body = extras_len + key.len();

        let mut header = RequestHeader::new(Opcode::Gat);
        header.key_length = key.len() as u16;
        header.extras_length = extras_len as u8;
        header.total_body_length = total_body as u32;
        header.opaque = opaque;
        header.encode(buf);

        buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&expiration.to_be_bytes());
        buf[HEADER_SIZE + 4..HEADER_SIZE + 4 + key.len()].copy_from_slice(key);

        HEADER_SIZE + total_body
    }

    /// Encode a FLUSH request.
    pub fn encode_flush(buf: &mut [u8], expiration: u32, opaque: u32) -> usize {
        if expiration == 0 {
            // No extras needed
            let mut header = RequestHeader::new(Opcode::Flush);
            header.opaque = opaque;
            header.encode(buf);
            HEADER_SIZE
        } else {
            // Include expiration extra
            let mut header = RequestHeader::new(Opcode::Flush);
            header.extras_length = 4;
            header.total_body_length = 4;
            header.opaque = opaque;
            header.encode(buf);

            buf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&expiration.to_be_bytes());
            HEADER_SIZE + 4
        }
    }

    /// Encode a NOOP request.
    pub fn encode_noop(buf: &mut [u8], opaque: u32) -> usize {
        let mut header = RequestHeader::new(Opcode::Noop);
        header.opaque = opaque;
        header.encode(buf);
        HEADER_SIZE
    }

    /// Encode a VERSION request.
    pub fn encode_version(buf: &mut [u8], opaque: u32) -> usize {
        let mut header = RequestHeader::new(Opcode::Version);
        header.opaque = opaque;
        header.encode(buf);
        HEADER_SIZE
    }

    /// Encode a QUIT request.
    pub fn encode_quit(buf: &mut [u8], opaque: u32) -> usize {
        let mut header = RequestHeader::new(Opcode::Quit);
        header.opaque = opaque;
        header.encode(buf);
        HEADER_SIZE
    }

    /// Encode a STAT request.
    pub fn encode_stat(buf: &mut [u8], key: Option<&[u8]>, opaque: u32) -> usize {
        let key_len = key.map(|k| k.len()).unwrap_or(0);

        let mut header = RequestHeader::new(Opcode::Stat);
        header.key_length = key_len as u16;
        header.total_body_length = key_len as u32;
        header.opaque = opaque;
        header.encode(buf);

        if let Some(k) = key {
            buf[HEADER_SIZE..HEADER_SIZE + k.len()].copy_from_slice(k);
        }

        HEADER_SIZE + key_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::command::BinaryCommand;

    #[test]
    fn test_encode_get() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_get(&mut buf, b"mykey", 42);

        assert_eq!(len, HEADER_SIZE + 5);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            cmd,
            BinaryCommand::Get {
                key: b"mykey",
                opaque: 42
            }
        ));
    }

    #[test]
    fn test_encode_set() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_set(&mut buf, b"key", b"value", 7, 3600, 0, 99);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);

        if let BinaryCommand::Set {
            key,
            value,
            flags,
            expiration,
            opaque,
            ..
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(value, b"value");
            assert_eq!(flags, 7);
            assert_eq!(expiration, 3600);
            assert_eq!(opaque, 99);
        } else {
            panic!("Expected Set command");
        }
    }

    #[test]
    fn test_encode_delete() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_delete(&mut buf, b"delkey", 0, 55);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            cmd,
            BinaryCommand::Delete {
                key: b"delkey",
                opaque: 55,
                ..
            }
        ));
    }

    #[test]
    fn test_encode_flush() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_flush(&mut buf, 0, 1);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(cmd, BinaryCommand::Flush { expiration: 0, .. }));
    }

    #[test]
    fn test_encode_noop() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_noop(&mut buf, 123);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(cmd, BinaryCommand::Noop { opaque: 123 }));
    }

    // Additional tests for improved coverage

    #[test]
    fn test_encode_getq() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_getq(&mut buf, b"key", 1);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            cmd,
            BinaryCommand::GetQ {
                key: b"key",
                opaque: 1
            }
        ));
    }

    #[test]
    fn test_encode_getk() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_getk(&mut buf, b"key", 2);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(
            cmd,
            BinaryCommand::GetK {
                key: b"key",
                opaque: 2
            }
        ));
    }

    #[test]
    fn test_encode_setq() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_setq(&mut buf, b"key", b"val", 1, 60, 100, 3);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::SetQ {
            key,
            value,
            flags,
            expiration,
            cas,
            opaque,
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(value, b"val");
            assert_eq!(flags, 1);
            assert_eq!(expiration, 60);
            assert_eq!(cas, 100);
            assert_eq!(opaque, 3);
        } else {
            panic!("Expected SetQ");
        }
    }

    #[test]
    fn test_encode_add() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_add(&mut buf, b"key", b"val", 0, 3600, 4);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Add {
            key,
            value,
            flags,
            expiration,
            opaque,
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(value, b"val");
            assert_eq!(flags, 0);
            assert_eq!(expiration, 3600);
            assert_eq!(opaque, 4);
        } else {
            panic!("Expected Add");
        }
    }

    #[test]
    fn test_encode_replace() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_replace(&mut buf, b"key", b"val", 0, 3600, 50, 5);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Replace {
            key, cas, opaque, ..
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(cas, 50);
            assert_eq!(opaque, 5);
        } else {
            panic!("Expected Replace");
        }
    }

    #[test]
    fn test_encode_deleteq() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_deleteq(&mut buf, b"key", 10, 6);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::DeleteQ { key, cas, opaque } = cmd {
            assert_eq!(key, b"key");
            assert_eq!(cas, 10);
            assert_eq!(opaque, 6);
        } else {
            panic!("Expected DeleteQ");
        }
    }

    #[test]
    fn test_encode_increment() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_increment(&mut buf, b"counter", 1, 0, 3600, 0, 7);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Increment {
            key,
            delta,
            initial,
            expiration,
            opaque,
            ..
        } = cmd
        {
            assert_eq!(key, b"counter");
            assert_eq!(delta, 1);
            assert_eq!(initial, 0);
            assert_eq!(expiration, 3600);
            assert_eq!(opaque, 7);
        } else {
            panic!("Expected Increment");
        }
    }

    #[test]
    fn test_encode_decrement() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_decrement(&mut buf, b"counter", 5, 100, 0, 20, 8);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Decrement {
            key,
            delta,
            initial,
            cas,
            opaque,
            ..
        } = cmd
        {
            assert_eq!(key, b"counter");
            assert_eq!(delta, 5);
            assert_eq!(initial, 100);
            assert_eq!(cas, 20);
            assert_eq!(opaque, 8);
        } else {
            panic!("Expected Decrement");
        }
    }

    #[test]
    fn test_encode_append() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_append(&mut buf, b"key", b"suffix", 30, 9);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Append {
            key,
            value,
            cas,
            opaque,
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(value, b"suffix");
            assert_eq!(cas, 30);
            assert_eq!(opaque, 9);
        } else {
            panic!("Expected Append");
        }
    }

    #[test]
    fn test_encode_prepend() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_prepend(&mut buf, b"key", b"prefix", 40, 10);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Prepend {
            key,
            value,
            cas,
            opaque,
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(value, b"prefix");
            assert_eq!(cas, 40);
            assert_eq!(opaque, 10);
        } else {
            panic!("Expected Prepend");
        }
    }

    #[test]
    fn test_encode_touch() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_touch(&mut buf, b"key", 600, 11);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Touch {
            key,
            expiration,
            opaque,
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(expiration, 600);
            assert_eq!(opaque, 11);
        } else {
            panic!("Expected Touch");
        }
    }

    #[test]
    fn test_encode_gat() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_gat(&mut buf, b"key", 300, 12);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Gat {
            key,
            expiration,
            opaque,
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(expiration, 300);
            assert_eq!(opaque, 12);
        } else {
            panic!("Expected Gat");
        }
    }

    #[test]
    fn test_encode_flush_with_expiration() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_flush(&mut buf, 60, 13);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Flush { expiration, opaque } = cmd {
            assert_eq!(expiration, 60);
            assert_eq!(opaque, 13);
        } else {
            panic!("Expected Flush");
        }
    }

    #[test]
    fn test_encode_version() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_version(&mut buf, 14);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(cmd, BinaryCommand::Version { opaque: 14 }));
    }

    #[test]
    fn test_encode_quit() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_quit(&mut buf, 15);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        assert!(matches!(cmd, BinaryCommand::Quit { opaque: 15 }));
    }

    #[test]
    fn test_encode_stat_no_key() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_stat(&mut buf, None, 16);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Stat { key, opaque } = cmd {
            assert!(key.is_none());
            assert_eq!(opaque, 16);
        } else {
            panic!("Expected Stat");
        }
    }

    #[test]
    fn test_encode_stat_with_key() {
        let mut buf = [0u8; 256];
        let len = BinaryRequest::encode_stat(&mut buf, Some(b"items"), 17);

        let (cmd, consumed) = BinaryCommand::parse(&buf[..len]).unwrap();
        assert_eq!(consumed, len);
        if let BinaryCommand::Stat { key, opaque } = cmd {
            assert_eq!(key, Some(b"items".as_slice()));
            assert_eq!(opaque, 17);
        } else {
            panic!("Expected Stat");
        }
    }
}
