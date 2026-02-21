//! Redis Cluster protocol building blocks.
//!
//! Stateless utilities for Redis Cluster: CRC16 hash slot calculation,
//! MOVED/ASK redirect parsing, and CLUSTER SLOTS response decoding.

use crate::Value;

// ============================================================================
// CRC16-XMODEM
// ============================================================================

/// CRC16-XMODEM lookup table (same polynomial as Redis `src/crc16.c`).
#[rustfmt::skip]
static CRC16_TABLE: [u16; 256] = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0,
];

/// Compute CRC16-XMODEM checksum (same algorithm as Redis).
#[inline]
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        let index = ((crc >> 8) ^ byte as u16) as u8;
        crc = (crc << 8) ^ CRC16_TABLE[index as usize];
    }
    crc
}

// ============================================================================
// Hash Slot
// ============================================================================

/// Total number of hash slots in a Redis Cluster.
pub const SLOT_COUNT: u16 = 16384;

/// Compute the hash slot for a key.
///
/// If the key contains a hash tag (first `{` to next `}` with non-empty content),
/// only the content inside the braces is hashed.
#[inline]
pub fn hash_slot(key: &[u8]) -> u16 {
    let data = match memchr::memchr(b'{', key) {
        Some(start) => {
            let rest = &key[start + 1..];
            match memchr::memchr(b'}', rest) {
                Some(0) => key,            // empty tag like {}
                Some(end) => &rest[..end], // use tag content
                None => key,               // no closing brace
            }
        }
        None => key,
    };
    crc16(data) % SLOT_COUNT
}

// ============================================================================
// Redirect Parsing
// ============================================================================

/// The kind of cluster redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
    /// MOVED — slot permanently owned by another node.
    Moved,
    /// ASK — one-time redirect during slot migration.
    Ask,
}

/// A parsed MOVED or ASK redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub kind: RedirectKind,
    pub slot: u16,
    /// Address as `host:port` string. Kept as String because some deployments use hostnames.
    pub address: String,
}

/// Parse a MOVED or ASK redirect from a RESP error value.
///
/// Returns `None` if the value is not an error or not a redirect.
pub fn parse_redirect(value: &Value) -> Option<Redirect> {
    let msg = match value {
        Value::Error(e) => e,
        _ => return None,
    };

    let s = std::str::from_utf8(msg).ok()?;
    let (kind, rest) = if let Some(rest) = s.strip_prefix("MOVED ") {
        (RedirectKind::Moved, rest)
    } else if let Some(rest) = s.strip_prefix("ASK ") {
        (RedirectKind::Ask, rest)
    } else {
        return None;
    };

    let mut parts = rest.splitn(2, ' ');
    let slot: u16 = parts.next()?.parse().ok()?;
    let address = parts.next()?;
    if address.is_empty() {
        return None;
    }

    Some(Redirect {
        kind,
        slot,
        address: address.to_string(),
    })
}

// ============================================================================
// CLUSTER SLOTS Response Parsing
// ============================================================================

/// Information about a single cluster node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// Address as `host:port`.
    pub address: String,
    /// Optional node ID (40-char hex string).
    pub node_id: Option<String>,
}

/// A contiguous range of hash slots owned by a primary (with optional replicas).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotRange {
    /// Inclusive start slot.
    pub start: u16,
    /// Inclusive end slot.
    pub end: u16,
    /// Primary node for this range.
    pub primary: NodeInfo,
    /// Replica nodes.
    pub replicas: Vec<NodeInfo>,
}

/// A parsed slot map from `CLUSTER SLOTS`.
///
/// Slot ranges are sorted by start slot for binary-search lookups.
#[derive(Debug, Clone)]
pub struct SlotMap {
    ranges: Vec<SlotRange>,
}

impl SlotMap {
    /// Parse a `CLUSTER SLOTS` response into a slot map.
    ///
    /// Returns `None` if the value is not a valid CLUSTER SLOTS response.
    pub fn from_cluster_slots(value: &Value) -> Option<Self> {
        let entries = match value {
            Value::Array(arr) => arr,
            _ => return None,
        };

        let mut ranges = Vec::with_capacity(entries.len());

        for entry in entries {
            let items = match entry {
                Value::Array(arr) => arr,
                _ => return None,
            };

            // Minimum: [start, end, primary_node]
            if items.len() < 3 {
                return None;
            }

            let start = int_value(&items[0])? as u16;
            let end = int_value(&items[1])? as u16;
            let primary = parse_node_info(&items[2])?;

            let mut replicas = Vec::with_capacity(items.len().saturating_sub(3));
            for item in &items[3..] {
                replicas.push(parse_node_info(item)?);
            }

            ranges.push(SlotRange {
                start,
                end,
                primary,
                replicas,
            });
        }

        ranges.sort_by_key(|r| r.start);

        Some(SlotMap { ranges })
    }

    /// Look up the slot range that contains the given slot.
    pub fn lookup(&self, slot: u16) -> Option<&SlotRange> {
        let idx = self
            .ranges
            .partition_point(|r| r.start <= slot)
            .checked_sub(1)?;
        let range = &self.ranges[idx];
        if slot <= range.end { Some(range) } else { None }
    }

    /// Returns the slot ranges.
    pub fn ranges(&self) -> &[SlotRange] {
        &self.ranges
    }

    /// Returns true if the slot map is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Extract an integer from a RESP value (Integer or BulkString).
fn int_value(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(n) => Some(*n),
        Value::BulkString(s) => std::str::from_utf8(s).ok()?.parse().ok(),
        _ => None,
    }
}

/// Parse a node info array: `[ip, port]` or `[ip, port, node_id]`.
fn parse_node_info(value: &Value) -> Option<NodeInfo> {
    let items = match value {
        Value::Array(arr) => arr,
        _ => return None,
    };

    if items.len() < 2 {
        return None;
    }

    let ip = match &items[0] {
        Value::BulkString(s) => std::str::from_utf8(s).ok()?,
        _ => return None,
    };
    let port = int_value(&items[1])?;

    let address = format!("{}:{}", ip, port);

    let node_id = if items.len() >= 3 {
        match &items[2] {
            Value::BulkString(s) => {
                let id = std::str::from_utf8(s).ok()?;
                if id.is_empty() {
                    None
                } else {
                    Some(id.to_string())
                }
            }
            _ => None,
        }
    } else {
        None
    };

    Some(NodeInfo { address, node_id })
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    // ====================================================================
    // CRC16
    // ====================================================================

    #[test]
    fn test_crc16_empty() {
        assert_eq!(crc16(b""), 0);
    }

    #[test]
    fn test_crc16_known_vector() {
        // Standard CRC16-XMODEM test vector
        assert_eq!(crc16(b"123456789"), 0x31C3);
    }

    // ====================================================================
    // Hash Slot
    // ====================================================================

    #[test]
    fn test_hash_slot_range() {
        let slot = hash_slot(b"somekey");
        assert!(slot < SLOT_COUNT);
    }

    #[test]
    fn test_hash_slot_deterministic() {
        assert_eq!(hash_slot(b"foo"), hash_slot(b"foo"));
    }

    #[test]
    fn test_hash_slot_tag() {
        // {user}.name and {user}.email should hash to the same slot
        assert_eq!(hash_slot(b"{user}.name"), hash_slot(b"{user}.email"));
    }

    #[test]
    fn test_hash_slot_empty_tag() {
        // {} is an empty tag — the whole key is hashed
        let slot_full = crc16(b"{}key") % SLOT_COUNT;
        assert_eq!(hash_slot(b"{}key"), slot_full);
    }

    #[test]
    fn test_hash_slot_nested_braces() {
        // {{user}} — first { to first } gives "{user"
        assert_eq!(hash_slot(b"{{user}}"), crc16(b"{user") % SLOT_COUNT);
    }

    #[test]
    fn test_hash_slot_no_closing_brace() {
        // {user without } — whole key is hashed
        let slot = crc16(b"{user") % SLOT_COUNT;
        assert_eq!(hash_slot(b"{user"), slot);
    }

    // ====================================================================
    // Redirect Parsing
    // ====================================================================

    #[test]
    fn test_parse_redirect_moved() {
        let value = Value::Error(Bytes::from_static(b"MOVED 3999 127.0.0.1:6380"));
        let r = parse_redirect(&value).unwrap();
        assert_eq!(r.kind, RedirectKind::Moved);
        assert_eq!(r.slot, 3999);
        assert_eq!(r.address, "127.0.0.1:6380");
    }

    #[test]
    fn test_parse_redirect_ask() {
        let value = Value::Error(Bytes::from_static(b"ASK 100 10.0.0.1:7000"));
        let r = parse_redirect(&value).unwrap();
        assert_eq!(r.kind, RedirectKind::Ask);
        assert_eq!(r.slot, 100);
        assert_eq!(r.address, "10.0.0.1:7000");
    }

    #[test]
    fn test_parse_redirect_non_error() {
        let value = Value::SimpleString(Bytes::from_static(b"OK"));
        assert!(parse_redirect(&value).is_none());
    }

    #[test]
    fn test_parse_redirect_non_redirect_error() {
        let value = Value::Error(Bytes::from_static(b"ERR unknown command"));
        assert!(parse_redirect(&value).is_none());
    }

    #[test]
    fn test_parse_redirect_malformed_missing_address() {
        let value = Value::Error(Bytes::from_static(b"MOVED 3999"));
        assert!(parse_redirect(&value).is_none());
    }

    #[test]
    fn test_parse_redirect_malformed_bad_slot() {
        let value = Value::Error(Bytes::from_static(b"MOVED abc 127.0.0.1:6380"));
        assert!(parse_redirect(&value).is_none());
    }

    // ====================================================================
    // SlotMap
    // ====================================================================

    fn make_node(ip: &str, port: i64, node_id: Option<&str>) -> Value {
        let mut arr = vec![
            Value::BulkString(Bytes::copy_from_slice(ip.as_bytes())),
            Value::Integer(port),
        ];
        if let Some(id) = node_id {
            arr.push(Value::BulkString(Bytes::copy_from_slice(id.as_bytes())));
        }
        Value::Array(arr)
    }

    #[test]
    fn test_slot_map_three_nodes() {
        let resp = Value::Array(vec![
            Value::Array(vec![
                Value::Integer(0),
                Value::Integer(5460),
                make_node("10.0.0.1", 7000, Some("node1")),
            ]),
            Value::Array(vec![
                Value::Integer(5461),
                Value::Integer(10922),
                make_node("10.0.0.2", 7000, Some("node2")),
            ]),
            Value::Array(vec![
                Value::Integer(10923),
                Value::Integer(16383),
                make_node("10.0.0.3", 7000, Some("node3")),
            ]),
        ]);

        let map = SlotMap::from_cluster_slots(&resp).unwrap();
        assert_eq!(map.ranges().len(), 3);
        assert!(!map.is_empty());

        // Boundary lookups
        let r = map.lookup(0).unwrap();
        assert_eq!(r.primary.address, "10.0.0.1:7000");

        let r = map.lookup(5460).unwrap();
        assert_eq!(r.primary.address, "10.0.0.1:7000");

        let r = map.lookup(5461).unwrap();
        assert_eq!(r.primary.address, "10.0.0.2:7000");

        let r = map.lookup(16383).unwrap();
        assert_eq!(r.primary.address, "10.0.0.3:7000");
    }

    #[test]
    fn test_slot_map_with_replicas() {
        let resp = Value::Array(vec![Value::Array(vec![
            Value::Integer(0),
            Value::Integer(16383),
            make_node("10.0.0.1", 7000, Some("primary1")),
            make_node("10.0.0.2", 7001, Some("replica1")),
            make_node("10.0.0.3", 7002, None),
        ])]);

        let map = SlotMap::from_cluster_slots(&resp).unwrap();
        let r = map.lookup(0).unwrap();
        assert_eq!(r.replicas.len(), 2);
        assert_eq!(r.replicas[0].address, "10.0.0.2:7001");
        assert_eq!(r.replicas[0].node_id.as_deref(), Some("replica1"));
        assert_eq!(r.replicas[1].address, "10.0.0.3:7002");
        assert!(r.replicas[1].node_id.is_none());
    }

    #[test]
    fn test_slot_map_empty_response() {
        let resp = Value::Array(vec![]);
        let map = SlotMap::from_cluster_slots(&resp).unwrap();
        assert!(map.is_empty());
        assert!(map.lookup(0).is_none());
    }

    #[test]
    fn test_slot_map_non_array() {
        let resp = Value::SimpleString(Bytes::from_static(b"OK"));
        assert!(SlotMap::from_cluster_slots(&resp).is_none());
    }

    #[test]
    fn test_slot_map_lookup_gap() {
        // Create a map with a gap (slots 100-200 and 300-400)
        let resp = Value::Array(vec![
            Value::Array(vec![
                Value::Integer(100),
                Value::Integer(200),
                make_node("10.0.0.1", 7000, None),
            ]),
            Value::Array(vec![
                Value::Integer(300),
                Value::Integer(400),
                make_node("10.0.0.2", 7000, None),
            ]),
        ]);

        let map = SlotMap::from_cluster_slots(&resp).unwrap();
        assert!(map.lookup(250).is_none()); // in the gap
        assert!(map.lookup(50).is_none()); // before first range
        assert!(map.lookup(500).is_none()); // after last range
        assert!(map.lookup(150).is_some());
        assert!(map.lookup(350).is_some());
    }
}
