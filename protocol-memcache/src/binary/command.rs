//! Server-side binary protocol command parsing.
//!
//! This module parses Memcache binary protocol packets into structured commands.

use super::header::{HEADER_SIZE, Opcode, RequestHeader};
use crate::error::ParseError;

/// A parsed Memcache binary protocol command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryCommand<'a> {
    /// GET key
    Get { key: &'a [u8], opaque: u32 },
    /// GET key (quiet - no response on miss)
    GetQ { key: &'a [u8], opaque: u32 },
    /// GETK key (returns key in response)
    GetK { key: &'a [u8], opaque: u32 },
    /// GETKQ key (quiet, returns key in response)
    GetKQ { key: &'a [u8], opaque: u32 },
    /// SET key value
    Set {
        key: &'a [u8],
        value: &'a [u8],
        flags: u32,
        expiration: u32,
        cas: u64,
        opaque: u32,
    },
    /// SET key value (quiet - no response on success)
    SetQ {
        key: &'a [u8],
        value: &'a [u8],
        flags: u32,
        expiration: u32,
        cas: u64,
        opaque: u32,
    },
    /// ADD key value (only if key doesn't exist)
    Add {
        key: &'a [u8],
        value: &'a [u8],
        flags: u32,
        expiration: u32,
        opaque: u32,
    },
    /// REPLACE key value (only if key exists)
    Replace {
        key: &'a [u8],
        value: &'a [u8],
        flags: u32,
        expiration: u32,
        cas: u64,
        opaque: u32,
    },
    /// DELETE key
    Delete {
        key: &'a [u8],
        cas: u64,
        opaque: u32,
    },
    /// DELETE key (quiet)
    DeleteQ {
        key: &'a [u8],
        cas: u64,
        opaque: u32,
    },
    /// INCREMENT key delta initial expiration
    Increment {
        key: &'a [u8],
        delta: u64,
        initial: u64,
        expiration: u32,
        cas: u64,
        opaque: u32,
    },
    /// DECREMENT key delta initial expiration
    Decrement {
        key: &'a [u8],
        delta: u64,
        initial: u64,
        expiration: u32,
        cas: u64,
        opaque: u32,
    },
    /// APPEND key value
    Append {
        key: &'a [u8],
        value: &'a [u8],
        cas: u64,
        opaque: u32,
    },
    /// PREPEND key value
    Prepend {
        key: &'a [u8],
        value: &'a [u8],
        cas: u64,
        opaque: u32,
    },
    /// TOUCH key expiration
    Touch {
        key: &'a [u8],
        expiration: u32,
        opaque: u32,
    },
    /// GAT (Get and Touch) key expiration
    Gat {
        key: &'a [u8],
        expiration: u32,
        opaque: u32,
    },
    /// FLUSH \[expiration\]
    Flush { expiration: u32, opaque: u32 },
    /// NOOP (used for pipelining)
    Noop { opaque: u32 },
    /// VERSION
    Version { opaque: u32 },
    /// QUIT
    Quit { opaque: u32 },
    /// STAT \[key\]
    Stat { key: Option<&'a [u8]>, opaque: u32 },
}

impl<'a> BinaryCommand<'a> {
    /// Parse a binary command from a byte buffer.
    ///
    /// Returns the parsed command and the number of bytes consumed.
    pub fn parse(data: &'a [u8]) -> Result<(Self, usize), ParseError> {
        let header = RequestHeader::parse(data)?;

        let total_len = HEADER_SIZE + header.total_body_length as usize;
        if data.len() < total_len {
            return Err(ParseError::Incomplete);
        }

        // Validate that header lengths are consistent with total body length
        let extras_len = header.extras_length as usize;
        let key_len = header.key_length as usize;
        if extras_len + key_len > header.total_body_length as usize {
            return Err(ParseError::Protocol("header lengths exceed body length"));
        }

        let body = &data[HEADER_SIZE..total_len];
        let extras = &body[..extras_len];
        let key_start = extras_len;
        let key_end = key_start + key_len;
        let key = &body[key_start..key_end];
        let value = &body[key_end..];

        let cmd = match header.opcode {
            Opcode::Get => BinaryCommand::Get {
                key,
                opaque: header.opaque,
            },
            Opcode::GetQ => BinaryCommand::GetQ {
                key,
                opaque: header.opaque,
            },
            Opcode::GetK => BinaryCommand::GetK {
                key,
                opaque: header.opaque,
            },
            Opcode::GetKQ => BinaryCommand::GetKQ {
                key,
                opaque: header.opaque,
            },
            Opcode::Set => {
                if extras.len() < 8 {
                    return Err(ParseError::Protocol("SET requires 8 bytes of extras"));
                }
                let flags = u32::from_be_bytes([extras[0], extras[1], extras[2], extras[3]]);
                let expiration = u32::from_be_bytes([extras[4], extras[5], extras[6], extras[7]]);
                BinaryCommand::Set {
                    key,
                    value,
                    flags,
                    expiration,
                    cas: header.cas,
                    opaque: header.opaque,
                }
            }
            Opcode::SetQ => {
                if extras.len() < 8 {
                    return Err(ParseError::Protocol("SETQ requires 8 bytes of extras"));
                }
                let flags = u32::from_be_bytes([extras[0], extras[1], extras[2], extras[3]]);
                let expiration = u32::from_be_bytes([extras[4], extras[5], extras[6], extras[7]]);
                BinaryCommand::SetQ {
                    key,
                    value,
                    flags,
                    expiration,
                    cas: header.cas,
                    opaque: header.opaque,
                }
            }
            Opcode::Add | Opcode::AddQ => {
                if extras.len() < 8 {
                    return Err(ParseError::Protocol("ADD requires 8 bytes of extras"));
                }
                let flags = u32::from_be_bytes([extras[0], extras[1], extras[2], extras[3]]);
                let expiration = u32::from_be_bytes([extras[4], extras[5], extras[6], extras[7]]);
                BinaryCommand::Add {
                    key,
                    value,
                    flags,
                    expiration,
                    opaque: header.opaque,
                }
            }
            Opcode::Replace | Opcode::ReplaceQ => {
                if extras.len() < 8 {
                    return Err(ParseError::Protocol("REPLACE requires 8 bytes of extras"));
                }
                let flags = u32::from_be_bytes([extras[0], extras[1], extras[2], extras[3]]);
                let expiration = u32::from_be_bytes([extras[4], extras[5], extras[6], extras[7]]);
                BinaryCommand::Replace {
                    key,
                    value,
                    flags,
                    expiration,
                    cas: header.cas,
                    opaque: header.opaque,
                }
            }
            Opcode::Delete => BinaryCommand::Delete {
                key,
                cas: header.cas,
                opaque: header.opaque,
            },
            Opcode::DeleteQ => BinaryCommand::DeleteQ {
                key,
                cas: header.cas,
                opaque: header.opaque,
            },
            Opcode::Increment | Opcode::IncrementQ => {
                if extras.len() < 20 {
                    return Err(ParseError::Protocol(
                        "INCREMENT requires 20 bytes of extras",
                    ));
                }
                let delta = u64::from_be_bytes([
                    extras[0], extras[1], extras[2], extras[3], extras[4], extras[5], extras[6],
                    extras[7],
                ]);
                let initial = u64::from_be_bytes([
                    extras[8], extras[9], extras[10], extras[11], extras[12], extras[13],
                    extras[14], extras[15],
                ]);
                let expiration =
                    u32::from_be_bytes([extras[16], extras[17], extras[18], extras[19]]);
                BinaryCommand::Increment {
                    key,
                    delta,
                    initial,
                    expiration,
                    cas: header.cas,
                    opaque: header.opaque,
                }
            }
            Opcode::Decrement | Opcode::DecrementQ => {
                if extras.len() < 20 {
                    return Err(ParseError::Protocol(
                        "DECREMENT requires 20 bytes of extras",
                    ));
                }
                let delta = u64::from_be_bytes([
                    extras[0], extras[1], extras[2], extras[3], extras[4], extras[5], extras[6],
                    extras[7],
                ]);
                let initial = u64::from_be_bytes([
                    extras[8], extras[9], extras[10], extras[11], extras[12], extras[13],
                    extras[14], extras[15],
                ]);
                let expiration =
                    u32::from_be_bytes([extras[16], extras[17], extras[18], extras[19]]);
                BinaryCommand::Decrement {
                    key,
                    delta,
                    initial,
                    expiration,
                    cas: header.cas,
                    opaque: header.opaque,
                }
            }
            Opcode::Append | Opcode::AppendQ => BinaryCommand::Append {
                key,
                value,
                cas: header.cas,
                opaque: header.opaque,
            },
            Opcode::Prepend | Opcode::PrependQ => BinaryCommand::Prepend {
                key,
                value,
                cas: header.cas,
                opaque: header.opaque,
            },
            Opcode::Touch => {
                if extras.len() < 4 {
                    return Err(ParseError::Protocol("TOUCH requires 4 bytes of extras"));
                }
                let expiration = u32::from_be_bytes([extras[0], extras[1], extras[2], extras[3]]);
                BinaryCommand::Touch {
                    key,
                    expiration,
                    opaque: header.opaque,
                }
            }
            Opcode::Gat | Opcode::GatQ | Opcode::GatK | Opcode::GatKQ => {
                if extras.len() < 4 {
                    return Err(ParseError::Protocol("GAT requires 4 bytes of extras"));
                }
                let expiration = u32::from_be_bytes([extras[0], extras[1], extras[2], extras[3]]);
                BinaryCommand::Gat {
                    key,
                    expiration,
                    opaque: header.opaque,
                }
            }
            Opcode::Flush | Opcode::FlushQ => {
                let expiration = if extras.len() >= 4 {
                    u32::from_be_bytes([extras[0], extras[1], extras[2], extras[3]])
                } else {
                    0
                };
                BinaryCommand::Flush {
                    expiration,
                    opaque: header.opaque,
                }
            }
            Opcode::Noop => BinaryCommand::Noop {
                opaque: header.opaque,
            },
            Opcode::Version => BinaryCommand::Version {
                opaque: header.opaque,
            },
            Opcode::Quit | Opcode::QuitQ => BinaryCommand::Quit {
                opaque: header.opaque,
            },
            Opcode::Stat => BinaryCommand::Stat {
                key: if key.is_empty() { None } else { Some(key) },
                opaque: header.opaque,
            },
        };

        Ok((cmd, total_len))
    }

    /// Returns true if this is a quiet command (no response expected on success/miss).
    pub fn is_quiet(&self) -> bool {
        matches!(
            self,
            BinaryCommand::GetQ { .. }
                | BinaryCommand::GetKQ { .. }
                | BinaryCommand::SetQ { .. }
                | BinaryCommand::DeleteQ { .. }
        )
    }

    /// Returns the opaque value for this command.
    pub fn opaque(&self) -> u32 {
        match self {
            BinaryCommand::Get { opaque, .. }
            | BinaryCommand::GetQ { opaque, .. }
            | BinaryCommand::GetK { opaque, .. }
            | BinaryCommand::GetKQ { opaque, .. }
            | BinaryCommand::Set { opaque, .. }
            | BinaryCommand::SetQ { opaque, .. }
            | BinaryCommand::Add { opaque, .. }
            | BinaryCommand::Replace { opaque, .. }
            | BinaryCommand::Delete { opaque, .. }
            | BinaryCommand::DeleteQ { opaque, .. }
            | BinaryCommand::Increment { opaque, .. }
            | BinaryCommand::Decrement { opaque, .. }
            | BinaryCommand::Append { opaque, .. }
            | BinaryCommand::Prepend { opaque, .. }
            | BinaryCommand::Touch { opaque, .. }
            | BinaryCommand::Gat { opaque, .. }
            | BinaryCommand::Flush { opaque, .. }
            | BinaryCommand::Noop { opaque }
            | BinaryCommand::Version { opaque }
            | BinaryCommand::Quit { opaque }
            | BinaryCommand::Stat { opaque, .. } => *opaque,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(opcode: Opcode, key: &[u8], extras: &[u8], value: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE + extras.len() + key.len() + value.len()];
        let mut header = RequestHeader::new(opcode);
        header.key_length = key.len() as u16;
        header.extras_length = extras.len() as u8;
        header.total_body_length = (extras.len() + key.len() + value.len()) as u32;
        header.encode(&mut buf);

        let body_start = HEADER_SIZE;
        buf[body_start..body_start + extras.len()].copy_from_slice(extras);
        buf[body_start + extras.len()..body_start + extras.len() + key.len()].copy_from_slice(key);
        buf[body_start + extras.len() + key.len()..].copy_from_slice(value);
        buf
    }

    fn make_request_with_cas(
        opcode: Opcode,
        key: &[u8],
        extras: &[u8],
        value: &[u8],
        cas: u64,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE + extras.len() + key.len() + value.len()];
        let mut header = RequestHeader::new(opcode);
        header.key_length = key.len() as u16;
        header.extras_length = extras.len() as u8;
        header.total_body_length = (extras.len() + key.len() + value.len()) as u32;
        header.cas = cas;
        header.encode(&mut buf);

        let body_start = HEADER_SIZE;
        buf[body_start..body_start + extras.len()].copy_from_slice(extras);
        buf[body_start + extras.len()..body_start + extras.len() + key.len()].copy_from_slice(key);
        buf[body_start + extras.len() + key.len()..].copy_from_slice(value);
        buf
    }

    #[test]
    fn test_parse_get() {
        let data = make_request(Opcode::Get, b"mykey", &[], &[]);
        let (cmd, consumed) = BinaryCommand::parse(&data).unwrap();
        assert_eq!(
            cmd,
            BinaryCommand::Get {
                key: b"mykey",
                opaque: 0
            }
        );
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_set() {
        let extras = [0, 0, 0, 42, 0, 0, 0, 60]; // flags=42, expiration=60
        let data = make_request(Opcode::Set, b"key", &extras, b"value");
        let (cmd, consumed) = BinaryCommand::parse(&data).unwrap();

        if let BinaryCommand::Set {
            key,
            value,
            flags,
            expiration,
            ..
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(value, b"value");
            assert_eq!(flags, 42);
            assert_eq!(expiration, 60);
        } else {
            panic!("Expected Set command");
        }
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_delete() {
        let data = make_request(Opcode::Delete, b"deletekey", &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Delete { key, .. } if key == b"deletekey"));
    }

    #[test]
    fn test_parse_flush() {
        let data = make_request(Opcode::Flush, &[], &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Flush { expiration: 0, .. }));
    }

    #[test]
    fn test_parse_noop() {
        let data = make_request(Opcode::Noop, &[], &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Noop { .. }));
    }

    #[test]
    fn test_parse_incomplete() {
        let data = [0x80, 0x00]; // Only 2 bytes
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_opaque() {
        let mut data = make_request(Opcode::Get, b"key", &[], &[]);
        // Set opaque in header bytes 12-15
        data[12..16].copy_from_slice(&0x12345678u32.to_be_bytes());

        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert_eq!(cmd.opaque(), 0x12345678);
    }

    // Additional tests for improved coverage

    #[test]
    fn test_parse_getq() {
        let data = make_request(Opcode::GetQ, b"key", &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::GetQ { key: b"key", .. }));
        assert!(cmd.is_quiet());
    }

    #[test]
    fn test_parse_getk() {
        let data = make_request(Opcode::GetK, b"key", &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::GetK { key: b"key", .. }));
    }

    #[test]
    fn test_parse_getkq() {
        let data = make_request(Opcode::GetKQ, b"key", &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::GetKQ { key: b"key", .. }));
        assert!(cmd.is_quiet());
    }

    #[test]
    fn test_parse_setq() {
        let extras = [0, 0, 0, 1, 0, 0, 0, 0]; // flags=1, expiration=0
        let data = make_request(Opcode::SetQ, b"key", &extras, b"val");
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::SetQ { key: b"key", .. }));
        assert!(cmd.is_quiet());
    }

    #[test]
    fn test_parse_add() {
        let extras = [0, 0, 0, 1, 0, 0, 0, 60];
        let data = make_request(Opcode::Add, b"key", &extras, b"val");
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Add { key: b"key", .. }));
    }

    #[test]
    fn test_parse_addq() {
        let extras = [0, 0, 0, 1, 0, 0, 0, 60];
        let data = make_request(Opcode::AddQ, b"key", &extras, b"val");
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Add { key: b"key", .. }));
    }

    #[test]
    fn test_parse_replace() {
        let extras = [0, 0, 0, 1, 0, 0, 0, 60];
        let data = make_request_with_cas(Opcode::Replace, b"key", &extras, b"val", 123);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        if let BinaryCommand::Replace { cas, .. } = cmd {
            assert_eq!(cas, 123);
        } else {
            panic!("Expected Replace");
        }
    }

    #[test]
    fn test_parse_replaceq() {
        let extras = [0, 0, 0, 1, 0, 0, 0, 60];
        let data = make_request(Opcode::ReplaceQ, b"key", &extras, b"val");
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Replace { .. }));
    }

    #[test]
    fn test_parse_deleteq() {
        let data = make_request(Opcode::DeleteQ, b"key", &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::DeleteQ { key: b"key", .. }));
        assert!(cmd.is_quiet());
    }

    #[test]
    fn test_parse_increment() {
        // 8 bytes delta + 8 bytes initial + 4 bytes expiration = 20 bytes extras
        let mut extras = [0u8; 20];
        extras[0..8].copy_from_slice(&10u64.to_be_bytes()); // delta = 10
        extras[8..16].copy_from_slice(&0u64.to_be_bytes()); // initial = 0
        extras[16..20].copy_from_slice(&3600u32.to_be_bytes()); // expiration = 3600

        let data = make_request(Opcode::Increment, b"counter", &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();

        if let BinaryCommand::Increment {
            key,
            delta,
            initial,
            expiration,
            ..
        } = cmd
        {
            assert_eq!(key, b"counter");
            assert_eq!(delta, 10);
            assert_eq!(initial, 0);
            assert_eq!(expiration, 3600);
        } else {
            panic!("Expected Increment");
        }
    }

    #[test]
    fn test_parse_incrementq() {
        let mut extras = [0u8; 20];
        extras[0..8].copy_from_slice(&1u64.to_be_bytes());
        extras[8..16].copy_from_slice(&0u64.to_be_bytes());
        extras[16..20].copy_from_slice(&0u32.to_be_bytes());

        let data = make_request(Opcode::IncrementQ, b"c", &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Increment { .. }));
    }

    #[test]
    fn test_parse_decrement() {
        let mut extras = [0u8; 20];
        extras[0..8].copy_from_slice(&5u64.to_be_bytes()); // delta = 5
        extras[8..16].copy_from_slice(&100u64.to_be_bytes()); // initial = 100
        extras[16..20].copy_from_slice(&0u32.to_be_bytes()); // expiration = 0

        let data = make_request(Opcode::Decrement, b"counter", &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();

        if let BinaryCommand::Decrement { delta, initial, .. } = cmd {
            assert_eq!(delta, 5);
            assert_eq!(initial, 100);
        } else {
            panic!("Expected Decrement");
        }
    }

    #[test]
    fn test_parse_decrementq() {
        let mut extras = [0u8; 20];
        extras[0..8].copy_from_slice(&1u64.to_be_bytes());
        extras[8..16].copy_from_slice(&0u64.to_be_bytes());
        extras[16..20].copy_from_slice(&0u32.to_be_bytes());

        let data = make_request(Opcode::DecrementQ, b"c", &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Decrement { .. }));
    }

    #[test]
    fn test_parse_append() {
        let data = make_request(Opcode::Append, b"key", &[], b"suffix");
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        if let BinaryCommand::Append { key, value, .. } = cmd {
            assert_eq!(key, b"key");
            assert_eq!(value, b"suffix");
        } else {
            panic!("Expected Append");
        }
    }

    #[test]
    fn test_parse_appendq() {
        let data = make_request(Opcode::AppendQ, b"key", &[], b"suffix");
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Append { .. }));
    }

    #[test]
    fn test_parse_prepend() {
        let data = make_request(Opcode::Prepend, b"key", &[], b"prefix");
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        if let BinaryCommand::Prepend { key, value, .. } = cmd {
            assert_eq!(key, b"key");
            assert_eq!(value, b"prefix");
        } else {
            panic!("Expected Prepend");
        }
    }

    #[test]
    fn test_parse_prependq() {
        let data = make_request(Opcode::PrependQ, b"key", &[], b"prefix");
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Prepend { .. }));
    }

    #[test]
    fn test_parse_touch() {
        let extras = 3600u32.to_be_bytes();
        let data = make_request(Opcode::Touch, b"key", &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();

        if let BinaryCommand::Touch {
            key, expiration, ..
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(expiration, 3600);
        } else {
            panic!("Expected Touch");
        }
    }

    #[test]
    fn test_parse_gat() {
        let extras = 600u32.to_be_bytes();
        let data = make_request(Opcode::Gat, b"key", &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();

        if let BinaryCommand::Gat {
            key, expiration, ..
        } = cmd
        {
            assert_eq!(key, b"key");
            assert_eq!(expiration, 600);
        } else {
            panic!("Expected Gat");
        }
    }

    #[test]
    fn test_parse_gatq() {
        let extras = 600u32.to_be_bytes();
        let data = make_request(Opcode::GatQ, b"key", &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Gat { .. }));
    }

    #[test]
    fn test_parse_gatk() {
        let extras = 600u32.to_be_bytes();
        let data = make_request(Opcode::GatK, b"key", &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Gat { .. }));
    }

    #[test]
    fn test_parse_gatkq() {
        let extras = 600u32.to_be_bytes();
        let data = make_request(Opcode::GatKQ, b"key", &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Gat { .. }));
    }

    #[test]
    fn test_parse_flush_with_expiration() {
        let extras = 60u32.to_be_bytes();
        let data = make_request(Opcode::Flush, &[], &extras, &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();

        if let BinaryCommand::Flush { expiration, .. } = cmd {
            assert_eq!(expiration, 60);
        } else {
            panic!("Expected Flush");
        }
    }

    #[test]
    fn test_parse_flushq() {
        let data = make_request(Opcode::FlushQ, &[], &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Flush { .. }));
    }

    #[test]
    fn test_parse_version() {
        let data = make_request(Opcode::Version, &[], &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Version { .. }));
    }

    #[test]
    fn test_parse_quit() {
        let data = make_request(Opcode::Quit, &[], &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Quit { .. }));
    }

    #[test]
    fn test_parse_quitq() {
        let data = make_request(Opcode::QuitQ, &[], &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        assert!(matches!(cmd, BinaryCommand::Quit { .. }));
    }

    #[test]
    fn test_parse_stat_no_key() {
        let data = make_request(Opcode::Stat, &[], &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        if let BinaryCommand::Stat { key, .. } = cmd {
            assert!(key.is_none());
        } else {
            panic!("Expected Stat");
        }
    }

    #[test]
    fn test_parse_stat_with_key() {
        let data = make_request(Opcode::Stat, b"items", &[], &[]);
        let (cmd, _) = BinaryCommand::parse(&data).unwrap();
        if let BinaryCommand::Stat { key, .. } = cmd {
            assert_eq!(key, Some(b"items".as_slice()));
        } else {
            panic!("Expected Stat");
        }
    }

    #[test]
    fn test_parse_incomplete_body() {
        let mut data = make_request(Opcode::Get, b"key", &[], &[]);
        // Truncate the body
        data.truncate(HEADER_SIZE);
        // But keep total_body_length saying we need more
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Incomplete)
        ));
    }

    #[test]
    fn test_parse_header_lengths_exceed_body() {
        let mut data = make_request(Opcode::Get, b"key", &[], &[]);
        // Set key_length larger than total_body_length
        data[2] = 0xFF;
        data[3] = 0xFF;
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Protocol("header lengths exceed body length"))
        ));
    }

    #[test]
    fn test_parse_set_missing_extras() {
        // SET with no extras should fail
        let data = make_request(Opcode::Set, b"key", &[], b"value");
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Protocol("SET requires 8 bytes of extras"))
        ));
    }

    #[test]
    fn test_parse_setq_missing_extras() {
        let data = make_request(Opcode::SetQ, b"key", &[], b"value");
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Protocol("SETQ requires 8 bytes of extras"))
        ));
    }

    #[test]
    fn test_parse_add_missing_extras() {
        let data = make_request(Opcode::Add, b"key", &[], b"value");
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Protocol("ADD requires 8 bytes of extras"))
        ));
    }

    #[test]
    fn test_parse_replace_missing_extras() {
        let data = make_request(Opcode::Replace, b"key", &[], b"value");
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Protocol("REPLACE requires 8 bytes of extras"))
        ));
    }

    #[test]
    fn test_parse_increment_missing_extras() {
        let data = make_request(Opcode::Increment, b"key", &[], &[]);
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Protocol(
                "INCREMENT requires 20 bytes of extras"
            ))
        ));
    }

    #[test]
    fn test_parse_decrement_missing_extras() {
        let data = make_request(Opcode::Decrement, b"key", &[], &[]);
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Protocol(
                "DECREMENT requires 20 bytes of extras"
            ))
        ));
    }

    #[test]
    fn test_parse_touch_missing_extras() {
        let data = make_request(Opcode::Touch, b"key", &[], &[]);
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Protocol("TOUCH requires 4 bytes of extras"))
        ));
    }

    #[test]
    fn test_parse_gat_missing_extras() {
        let data = make_request(Opcode::Gat, b"key", &[], &[]);
        assert!(matches!(
            BinaryCommand::parse(&data),
            Err(ParseError::Protocol("GAT requires 4 bytes of extras"))
        ));
    }

    #[test]
    fn test_is_quiet_all_variants() {
        assert!(
            !BinaryCommand::Get {
                key: b"",
                opaque: 0
            }
            .is_quiet()
        );
        assert!(
            BinaryCommand::GetQ {
                key: b"",
                opaque: 0
            }
            .is_quiet()
        );
        assert!(
            !BinaryCommand::GetK {
                key: b"",
                opaque: 0
            }
            .is_quiet()
        );
        assert!(
            BinaryCommand::GetKQ {
                key: b"",
                opaque: 0
            }
            .is_quiet()
        );
        assert!(
            !BinaryCommand::Set {
                key: b"",
                value: b"",
                flags: 0,
                expiration: 0,
                cas: 0,
                opaque: 0
            }
            .is_quiet()
        );
        assert!(
            BinaryCommand::SetQ {
                key: b"",
                value: b"",
                flags: 0,
                expiration: 0,
                cas: 0,
                opaque: 0
            }
            .is_quiet()
        );
        assert!(
            !BinaryCommand::Delete {
                key: b"",
                cas: 0,
                opaque: 0
            }
            .is_quiet()
        );
        assert!(
            BinaryCommand::DeleteQ {
                key: b"",
                cas: 0,
                opaque: 0
            }
            .is_quiet()
        );
    }

    #[test]
    fn test_opaque_all_variants() {
        assert_eq!(
            BinaryCommand::Get {
                key: b"",
                opaque: 1
            }
            .opaque(),
            1
        );
        assert_eq!(
            BinaryCommand::GetQ {
                key: b"",
                opaque: 2
            }
            .opaque(),
            2
        );
        assert_eq!(
            BinaryCommand::GetK {
                key: b"",
                opaque: 3
            }
            .opaque(),
            3
        );
        assert_eq!(
            BinaryCommand::GetKQ {
                key: b"",
                opaque: 4
            }
            .opaque(),
            4
        );
        assert_eq!(
            BinaryCommand::Set {
                key: b"",
                value: b"",
                flags: 0,
                expiration: 0,
                cas: 0,
                opaque: 5
            }
            .opaque(),
            5
        );
        assert_eq!(
            BinaryCommand::SetQ {
                key: b"",
                value: b"",
                flags: 0,
                expiration: 0,
                cas: 0,
                opaque: 6
            }
            .opaque(),
            6
        );
        assert_eq!(
            BinaryCommand::Add {
                key: b"",
                value: b"",
                flags: 0,
                expiration: 0,
                opaque: 7
            }
            .opaque(),
            7
        );
        assert_eq!(
            BinaryCommand::Replace {
                key: b"",
                value: b"",
                flags: 0,
                expiration: 0,
                cas: 0,
                opaque: 8
            }
            .opaque(),
            8
        );
        assert_eq!(
            BinaryCommand::Delete {
                key: b"",
                cas: 0,
                opaque: 9
            }
            .opaque(),
            9
        );
        assert_eq!(
            BinaryCommand::DeleteQ {
                key: b"",
                cas: 0,
                opaque: 10
            }
            .opaque(),
            10
        );
        assert_eq!(
            BinaryCommand::Increment {
                key: b"",
                delta: 0,
                initial: 0,
                expiration: 0,
                cas: 0,
                opaque: 11
            }
            .opaque(),
            11
        );
        assert_eq!(
            BinaryCommand::Decrement {
                key: b"",
                delta: 0,
                initial: 0,
                expiration: 0,
                cas: 0,
                opaque: 12
            }
            .opaque(),
            12
        );
        assert_eq!(
            BinaryCommand::Append {
                key: b"",
                value: b"",
                cas: 0,
                opaque: 13
            }
            .opaque(),
            13
        );
        assert_eq!(
            BinaryCommand::Prepend {
                key: b"",
                value: b"",
                cas: 0,
                opaque: 14
            }
            .opaque(),
            14
        );
        assert_eq!(
            BinaryCommand::Touch {
                key: b"",
                expiration: 0,
                opaque: 15
            }
            .opaque(),
            15
        );
        assert_eq!(
            BinaryCommand::Gat {
                key: b"",
                expiration: 0,
                opaque: 16
            }
            .opaque(),
            16
        );
        assert_eq!(
            BinaryCommand::Flush {
                expiration: 0,
                opaque: 17
            }
            .opaque(),
            17
        );
        assert_eq!(BinaryCommand::Noop { opaque: 18 }.opaque(), 18);
        assert_eq!(BinaryCommand::Version { opaque: 19 }.opaque(), 19);
        assert_eq!(BinaryCommand::Quit { opaque: 20 }.opaque(), 20);
        assert_eq!(
            BinaryCommand::Stat {
                key: None,
                opaque: 21
            }
            .opaque(),
            21
        );
    }

    #[test]
    fn test_command_traits() {
        let cmd = BinaryCommand::Get {
            key: b"test",
            opaque: 0,
        };
        let cmd2 = cmd.clone();
        assert_eq!(cmd, cmd2);

        let debug_str = format!("{:?}", cmd);
        assert!(debug_str.contains("Get"));
    }
}
