//! QPACK header compression — static table only (RFC 9204).
//!
//! Phase 1 uses stateless QPACK: only the 99-entry static table, no dynamic
//! table, no encoder/decoder streams. This covers all standard HTTP headers
//! and is what many HTTP/3 implementations default to.

use crate::error::H3Error;

/// A single header name-value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl HeaderField {
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

// ── QPACK prefix integer codec (RFC 9204 Section 4.1.1) ────────────
//
// Different from QUIC varints! Uses a prefix of N bits. If the value fits
// in N bits (< 2^N - 1), encode directly. Otherwise, encode 2^N - 1 in
// the prefix bits and the remainder in subsequent bytes using 7-bit chunks.

fn encode_prefix_int(buf: &mut Vec<u8>, value: u64, prefix_bits: u8, pattern: u8) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        buf.push(pattern | value as u8);
    } else {
        buf.push(pattern | max as u8);
        let mut remaining = value - max;
        while remaining >= 128 {
            buf.push(0x80 | (remaining & 0x7f) as u8);
            remaining >>= 7;
        }
        buf.push(remaining as u8);
    }
}

fn decode_prefix_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let max = (1u64 << prefix_bits) - 1;
    let value = u64::from(buf[0]) & max;
    if value < max {
        return Some((value, 1));
    }
    // Multi-byte encoding.
    let mut value = max;
    let mut shift = 0u32;
    for (i, &b) in buf[1..].iter().enumerate() {
        value += u64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some((value, i + 2));
        }
        if shift > 56 {
            return None; // overflow protection
        }
    }
    None // incomplete
}

// ── Static table (RFC 9204 Appendix A) ──────────────────────────────

/// QPACK static table entries: (name, value). 99 entries indexed 0..98.
const STATIC_TABLE: &[(&[u8], &[u8])] = &[
    (b":authority", b""),                                    // 0
    (b":path", b"/"),                                        // 1
    (b"age", b"0"),                                          // 2
    (b"content-disposition", b""),                           // 3
    (b"content-length", b"0"),                               // 4
    (b"cookie", b""),                                        // 5
    (b"date", b""),                                          // 6
    (b"etag", b""),                                          // 7
    (b"if-modified-since", b""),                             // 8
    (b"if-none-match", b""),                                 // 9
    (b"last-modified", b""),                                 // 10
    (b"link", b""),                                          // 11
    (b"location", b""),                                      // 12
    (b"referer", b""),                                       // 13
    (b"set-cookie", b""),                                    // 14
    (b":method", b"CONNECT"),                                // 15
    (b":method", b"DELETE"),                                 // 16
    (b":method", b"GET"),                                    // 17
    (b":method", b"HEAD"),                                   // 18
    (b":method", b"OPTIONS"),                                // 19
    (b":method", b"POST"),                                   // 20
    (b":method", b"PUT"),                                    // 21
    (b":scheme", b"http"),                                   // 22
    (b":scheme", b"https"),                                  // 23
    (b":status", b"103"),                                    // 24
    (b":status", b"200"),                                    // 25
    (b":status", b"304"),                                    // 26
    (b":status", b"404"),                                    // 27
    (b":status", b"503"),                                    // 28
    (b"accept", b"*/*"),                                     // 29
    (b"accept", b"application/dns-message"),                 // 30
    (b"accept-encoding", b"gzip, deflate, br"),              // 31
    (b"accept-ranges", b"bytes"),                            // 32
    (b"access-control-allow-headers", b"cache-control"),     // 33
    (b"access-control-allow-headers", b"content-type"),      // 34
    (b"access-control-allow-origin", b"*"),                  // 35
    (b"cache-control", b"max-age=0"),                        // 36
    (b"cache-control", b"max-age=2592000"),                  // 37
    (b"cache-control", b"max-age=604800"),                   // 38
    (b"cache-control", b"no-cache"),                         // 39
    (b"cache-control", b"no-store"),                         // 40
    (b"cache-control", b"public, max-age=31536000"),         // 41
    (b"content-encoding", b"br"),                            // 42
    (b"content-encoding", b"gzip"),                          // 43
    (b"content-type", b"application/dns-message"),           // 44
    (b"content-type", b"application/javascript"),            // 45
    (b"content-type", b"application/json"),                  // 46
    (b"content-type", b"application/x-www-form-urlencoded"), // 47
    (b"content-type", b"image/gif"),                         // 48
    (b"content-type", b"image/jpeg"),                        // 49
    (b"content-type", b"image/png"),                         // 50
    (b"content-type", b"text/css"),                          // 51
    (b"content-type", b"text/html; charset=utf-8"),          // 52
    (b"content-type", b"text/plain"),                        // 53
    (b"content-type", b"text/plain;charset=utf-8"),          // 54
    (b"range", b"bytes=0-"),                                 // 55
    (b"strict-transport-security", b"max-age=31536000"),     // 56
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ), // 57
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ), // 58
    (b"vary", b"accept-encoding"),                           // 59
    (b"vary", b"origin"),                                    // 60
    (b"x-content-type-options", b"nosniff"),                 // 61
    (b"x-xss-protection", b"1; mode=block"),                 // 62
    (b":status", b"100"),                                    // 63
    (b":status", b"204"),                                    // 64
    (b":status", b"206"),                                    // 65
    (b":status", b"302"),                                    // 66
    (b":status", b"400"),                                    // 67
    (b":status", b"403"),                                    // 68
    (b":status", b"421"),                                    // 69
    (b":status", b"425"),                                    // 70
    (b":status", b"500"),                                    // 71
    (b"accept-language", b""),                               // 72
    (b"access-control-allow-credentials", b"FALSE"),         // 73
    (b"access-control-allow-credentials", b"TRUE"),          // 74
    (b"access-control-allow-headers", b"*"),                 // 75
    (b"access-control-allow-methods", b"get"),               // 76
    (b"access-control-allow-methods", b"get, post, options"), // 77
    (b"access-control-allow-methods", b"options"),           // 78
    (b"access-control-expose-headers", b"content-length"),   // 79
    (b"access-control-request-headers", b"content-type"),    // 80
    (b"access-control-request-method", b"get"),              // 81
    (b"access-control-request-method", b"post"),             // 82
    (b"alt-svc", b"clear"),                                  // 83
    (b"authorization", b""),                                 // 84
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ), // 85
    (b"early-data", b"1"),                                   // 86
    (b"expect-ct", b""),                                     // 87
    (b"forwarded", b""),                                     // 88
    (b"if-range", b""),                                      // 89
    (b"origin", b""),                                        // 90
    (b"purpose", b"prefetch"),                               // 91
    (b"server", b""),                                        // 92
    (b"timing-allow-origin", b"*"),                          // 93
    (b"upgrade-insecure-requests", b"1"),                    // 94
    (b"user-agent", b""),                                    // 95
    (b"x-forwarded-for", b""),                               // 96
    (b"x-frame-options", b"deny"),                           // 97
    (b"x-frame-options", b"sameorigin"),                     // 98
];

/// Find a static table entry matching both name and value.
/// Returns the index if found.
fn find_static_name_value(name: &[u8], value: &[u8]) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| *n == name && *v == value)
}

/// Find a static table entry matching just the name.
/// Returns the index of the first match.
fn find_static_name(name: &[u8]) -> Option<usize> {
    STATIC_TABLE.iter().position(|(n, _)| *n == name)
}

// ── Encoder ─────────────────────────────────────────────────────────

/// Encode a string literal with optional Huffman compression.
/// Uses Huffman when it produces shorter output.
/// Format: H bit (bit 7) + 7-bit prefix length + data.
fn encode_string_literal(buf: &mut Vec<u8>, data: &[u8]) {
    let huf_len = crate::huffman::encoded_len(data);
    if huf_len < data.len() {
        // Huffman is shorter — set H bit (0x80).
        encode_prefix_int(buf, huf_len as u64, 7, 0x80);
        crate::huffman::encode(data, buf);
    } else {
        // Raw is shorter or equal — no H bit (0x00).
        encode_prefix_int(buf, data.len() as u64, 7, 0x00);
        buf.extend_from_slice(data);
    }
}

/// Encode a list of headers into a QPACK header block (static table only).
///
/// Writes the Required Insert Count (0) and Delta Base (0) prefix,
/// then encodes each header using the most compact representation available.
pub fn encode(headers: &[HeaderField], buf: &mut Vec<u8>) {
    // QPACK header block prefix (RFC 9204 Section 4.5.1):
    // Required Insert Count = 0 (8-bit prefix integer with 0 pattern)
    encode_prefix_int(buf, 0, 8, 0x00);
    // Delta Base = 0, Sign bit = 0 (7-bit prefix integer with 0 pattern)
    encode_prefix_int(buf, 0, 7, 0x00);

    for header in headers {
        if let Some(index) = find_static_name_value(&header.name, &header.value) {
            // Indexed field line (RFC 9204 Section 4.5.2):
            // Static table reference, pattern 1 1 T=1 (0xc0), 6-bit index.
            encode_prefix_int(buf, index as u64, 6, 0xc0);
        } else if let Some(name_index) = find_static_name(&header.name) {
            // Literal field line with name reference (RFC 9204 Section 4.5.4):
            // Pattern 0 1 N=0 T=1 (0x50), 4-bit name index.
            encode_prefix_int(buf, name_index as u64, 4, 0x50);
            encode_string_literal(buf, &header.value);
        } else {
            // Literal field line with literal name (RFC 9204 Section 4.5.6):
            // Name: H bit is bit 3 → pattern 0x28 (H=1) or 0x20 (H=0), 3-bit prefix.
            let huf_len = crate::huffman::encoded_len(&header.name);
            if huf_len < header.name.len() {
                encode_prefix_int(buf, huf_len as u64, 3, 0x28);
                crate::huffman::encode(&header.name, buf);
            } else {
                encode_prefix_int(buf, header.name.len() as u64, 3, 0x20);
                buf.extend_from_slice(&header.name);
            }
            encode_string_literal(buf, &header.value);
        }
    }
}

// ── Decoder ─────────────────────────────────────────────────────────

/// Decode a QPACK header block (static table only).
///
/// Returns the list of decoded header fields or an error.
pub fn decode(buf: &[u8]) -> Result<Vec<HeaderField>, H3Error> {
    if buf.is_empty() {
        return Err(H3Error::QpackDecodingFailed);
    }

    let mut pos = 0;

    // Decode Required Insert Count.
    let (ric, n) = decode_prefix_int(&buf[pos..], 8).ok_or(H3Error::QpackDecodingFailed)?;
    pos += n;
    if ric != 0 {
        // We only support static table — dynamic table references have RIC > 0.
        return Err(H3Error::QpackDecodingFailed);
    }

    // Decode Delta Base (we ignore it since RIC=0 means no dynamic refs).
    if pos >= buf.len() {
        return Err(H3Error::QpackDecodingFailed);
    }
    let (_delta_base, n) = decode_prefix_int(&buf[pos..], 7).ok_or(H3Error::QpackDecodingFailed)?;
    pos += n;

    let mut headers = Vec::new();

    while pos < buf.len() {
        let first = buf[pos];

        if first & 0x80 != 0 {
            // Indexed field line (Section 4.5.2): pattern 1xxxxxxx
            // Bit 6 (T) indicates static (1) vs dynamic (0) table.
            let is_static = first & 0x40 != 0;
            if !is_static {
                return Err(H3Error::QpackDecodingFailed);
            }
            let (index, n) =
                decode_prefix_int(&buf[pos..], 6).ok_or(H3Error::QpackDecodingFailed)?;
            pos += n;
            let (name, value) = STATIC_TABLE
                .get(index as usize)
                .ok_or(H3Error::QpackDecodingFailed)?;
            headers.push(HeaderField {
                name: name.to_vec(),
                value: value.to_vec(),
            });
        } else if first & 0x40 != 0 {
            // Literal with name reference (Section 4.5.4): pattern 01xxxxxx
            // Bit 5 (N): never-index flag (we ignore).
            // Bit 4 (T): static (1) vs dynamic (0).
            let is_static = first & 0x10 != 0;
            if !is_static {
                return Err(H3Error::QpackDecodingFailed);
            }
            let (name_index, n) =
                decode_prefix_int(&buf[pos..], 4).ok_or(H3Error::QpackDecodingFailed)?;
            pos += n;
            let (name, _) = STATIC_TABLE
                .get(name_index as usize)
                .ok_or(H3Error::QpackDecodingFailed)?;

            // Decode value (bit 7 = Huffman flag).
            let huffman_value = pos < buf.len() && buf[pos] & 0x80 != 0;
            let (value_len, n) =
                decode_prefix_int(&buf[pos..], 7).ok_or(H3Error::QpackDecodingFailed)?;
            pos += n;
            let value_len = value_len as usize;
            if pos + value_len > buf.len() {
                return Err(H3Error::QpackDecodingFailed);
            }
            let value = if huffman_value {
                crate::huffman::decode(&buf[pos..pos + value_len])?
            } else {
                buf[pos..pos + value_len].to_vec()
            };
            pos += value_len;

            headers.push(HeaderField {
                name: name.to_vec(),
                value,
            });
        } else if first & 0x20 != 0 {
            // Literal with literal name (Section 4.5.6): pattern 001xxxxx
            // Bit 4 (N): never-index (ignored).
            // Bit 3 (H): Huffman-encoded name.
            let huffman_name = first & 0x08 != 0;
            let (name_len, n) =
                decode_prefix_int(&buf[pos..], 3).ok_or(H3Error::QpackDecodingFailed)?;
            pos += n;
            let name_len = name_len as usize;
            if pos + name_len > buf.len() {
                return Err(H3Error::QpackDecodingFailed);
            }
            let name = if huffman_name {
                crate::huffman::decode(&buf[pos..pos + name_len])?
            } else {
                buf[pos..pos + name_len].to_vec()
            };
            pos += name_len;

            // Decode value (bit 7 = Huffman flag).
            let huffman_value = pos < buf.len() && buf[pos] & 0x80 != 0;
            let (value_len, n) =
                decode_prefix_int(&buf[pos..], 7).ok_or(H3Error::QpackDecodingFailed)?;
            pos += n;
            let value_len = value_len as usize;
            if pos + value_len > buf.len() {
                return Err(H3Error::QpackDecodingFailed);
            }
            let value = if huffman_value {
                crate::huffman::decode(&buf[pos..pos + value_len])?
            } else {
                buf[pos..pos + value_len].to_vec()
            };
            pos += value_len;

            headers.push(HeaderField { name, value });
        } else if first & 0x10 != 0 {
            // Indexed field line with post-base index (Section 4.5.3): pattern 0001xxxx
            // Requires dynamic table — not supported.
            return Err(H3Error::QpackDecodingFailed);
        } else {
            // Literal with post-base name reference (Section 4.5.5): pattern 0000xxxx
            // Requires dynamic table — not supported.
            return Err(H3Error::QpackDecodingFailed);
        }
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_int_round_trip() {
        for &(value, prefix_bits, pattern) in &[
            (0u64, 6, 0xc0u8),
            (5, 6, 0xc0),
            (62, 6, 0xc0),
            (63, 6, 0xc0),
            (64, 6, 0xc0),
            (1000, 6, 0xc0),
            (0, 4, 0x50),
            (15, 4, 0x50),
            (16, 4, 0x50),
            (255, 4, 0x50),
            (0, 7, 0x00),
            (127, 7, 0x00),
            (128, 7, 0x00),
            (10000, 7, 0x00),
        ] {
            let mut buf = Vec::new();
            encode_prefix_int(&mut buf, value, prefix_bits, pattern);
            let (decoded, len) = decode_prefix_int(&buf, prefix_bits).unwrap();
            assert_eq!(
                decoded, value,
                "mismatch for value={value} prefix={prefix_bits}"
            );
            assert_eq!(len, buf.len());
            // Verify the pattern bits are preserved.
            let mask = !((1u8 << prefix_bits) - 1);
            assert_eq!(buf[0] & mask, pattern & mask);
        }
    }

    #[test]
    fn encode_decode_indexed() {
        // :method GET is index 17 — should encode as indexed field line.
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let mut buf = Vec::new();
        encode(&headers, &mut buf);
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_decode_name_reference() {
        // :path /foo — :path is at index 1 with value "/", so name matches
        // but value doesn't. Should encode as literal with name reference.
        let headers = vec![HeaderField::new(b":path", b"/foo")];
        let mut buf = Vec::new();
        encode(&headers, &mut buf);
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_decode_literal() {
        // Completely custom header.
        let headers = vec![HeaderField::new(b"x-custom", b"value123")];
        let mut buf = Vec::new();
        encode(&headers, &mut buf);
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_decode_multiple_headers() {
        let headers = vec![
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b":path", b"/"),
            HeaderField::new(b":scheme", b"https"),
            HeaderField::new(b":authority", b"example.com"),
            HeaderField::new(b"accept", b"*/*"),
            HeaderField::new(b"x-request-id", b"abc123"),
        ];
        let mut buf = Vec::new();
        encode(&headers, &mut buf);
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_decode_status_200() {
        let headers = vec![
            HeaderField::new(b":status", b"200"),
            HeaderField::new(b"content-type", b"text/plain"),
        ];
        let mut buf = Vec::new();
        encode(&headers, &mut buf);
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_decode_empty_value() {
        let headers = vec![HeaderField::new(b":authority", b"")];
        let mut buf = Vec::new();
        encode(&headers, &mut buf);
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn static_table_size() {
        assert_eq!(STATIC_TABLE.len(), 99);
    }
}
