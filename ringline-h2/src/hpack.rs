//! HPACK header compression (RFC 7541).
//!
//! Implements the full HPACK encoder and decoder with:
//! - 61-entry static table (RFC 7541 Appendix A)
//! - Dynamic table with size management
//! - Huffman encoding/decoding
//! - Prefix integer codec

use std::collections::VecDeque;

use crate::error::H2Error;

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

    /// Size of this header field for dynamic table accounting (RFC 7541 Section 4.1).
    /// Size = len(name) + len(value) + 32
    fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

// -- HPACK prefix integer codec (RFC 7541 Section 5.1) --

pub(crate) fn encode_prefix_int(buf: &mut Vec<u8>, value: u64, prefix_bits: u8, pattern: u8) {
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

pub(crate) fn decode_prefix_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let max = (1u64 << prefix_bits) - 1;
    let value = u64::from(buf[0]) & max;
    if value < max {
        return Some((value, 1));
    }
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

// -- Static table (RFC 7541 Appendix A) --

/// HPACK static table entries: (name, value). 61 entries indexed 1..61.
const STATIC_TABLE: &[(&[u8], &[u8])] = &[
    (b":authority", b""),                  // 1
    (b":method", b"GET"),                  // 2
    (b":method", b"POST"),                 // 3
    (b":path", b"/"),                      // 4
    (b":path", b"/index.html"),            // 5
    (b":scheme", b"http"),                 // 6
    (b":scheme", b"https"),                // 7
    (b":status", b"200"),                  // 8
    (b":status", b"204"),                  // 9
    (b":status", b"206"),                  // 10
    (b":status", b"304"),                  // 11
    (b":status", b"400"),                  // 12
    (b":status", b"404"),                  // 13
    (b":status", b"500"),                  // 14
    (b"accept-charset", b""),              // 15
    (b"accept-encoding", b"gzip, deflate"), // 16
    (b"accept-language", b""),             // 17
    (b"accept-ranges", b""),               // 18
    (b"accept", b""),                      // 19
    (b"access-control-allow-origin", b""), // 20
    (b"age", b""),                         // 21
    (b"allow", b""),                       // 22
    (b"authorization", b""),               // 23
    (b"cache-control", b""),               // 24
    (b"content-disposition", b""),         // 25
    (b"content-encoding", b""),            // 26
    (b"content-language", b""),            // 27
    (b"content-length", b""),              // 28
    (b"content-location", b""),            // 29
    (b"content-range", b""),               // 30
    (b"content-type", b""),                // 31
    (b"cookie", b""),                      // 32
    (b"date", b""),                        // 33
    (b"etag", b""),                        // 34
    (b"expect", b""),                      // 35
    (b"expires", b""),                     // 36
    (b"from", b""),                        // 37
    (b"host", b""),                        // 38
    (b"if-match", b""),                    // 39
    (b"if-modified-since", b""),           // 40
    (b"if-none-match", b""),               // 41
    (b"if-range", b""),                    // 42
    (b"if-unmodified-since", b""),         // 43
    (b"last-modified", b""),               // 44
    (b"link", b""),                        // 45
    (b"location", b""),                    // 46
    (b"max-forwards", b""),                // 47
    (b"proxy-authenticate", b""),          // 48
    (b"proxy-authorization", b""),         // 49
    (b"range", b""),                       // 50
    (b"referer", b""),                     // 51
    (b"refresh", b""),                     // 52
    (b"retry-after", b""),                 // 53
    (b"server", b""),                      // 54
    (b"set-cookie", b""),                  // 55
    (b"strict-transport-security", b""),   // 56
    (b"transfer-encoding", b""),           // 57
    (b"user-agent", b""),                  // 58
    (b"vary", b""),                        // 59
    (b"via", b""),                         // 60
    (b"www-authenticate", b""),            // 61
];

/// Find a static table entry matching both name and value.
/// Returns the 1-based index if found.
fn find_static_name_value(name: &[u8], value: &[u8]) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| *n == name && *v == value)
        .map(|i| i + 1) // HPACK static table is 1-indexed
}

/// Find a static table entry matching just the name.
/// Returns the 1-based index of the first match.
fn find_static_name(name: &[u8]) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, _)| *n == name)
        .map(|i| i + 1)
}

// -- Dynamic table --

/// HPACK dynamic table (RFC 7541 Section 2.3.2).
///
/// Entries are stored newest-first. Index 0 of the VecDeque corresponds to
/// HPACK dynamic table index (static_table_len + 1).
pub struct DynamicTable {
    entries: VecDeque<HeaderField>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    /// Get an entry by 0-based dynamic table index.
    pub fn get(&self, index: usize) -> Option<&HeaderField> {
        self.entries.get(index)
    }

    /// Insert a new entry at the beginning of the dynamic table.
    pub fn insert(&mut self, field: HeaderField) {
        let entry_size = field.size();
        // Evict entries to make room (RFC 7541 Section 4.4).
        while self.size + entry_size > self.max_size && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop_back() {
                self.size -= evicted.size();
            }
        }
        // If the entry itself is larger than the max, don't add it but clear the table.
        if entry_size > self.max_size {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.entries.push_front(field);
        self.size += entry_size;
    }

    /// Update the maximum table size, evicting entries as needed.
    pub fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        while self.size > self.max_size && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop_back() {
                self.size -= evicted.size();
            }
        }
    }

    /// Find a dynamic table entry matching both name and value.
    /// Returns the HPACK index (62 + position) if found.
    fn find_name_value(&self, name: &[u8], value: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .position(|h| h.name == name && h.value == value)
            .map(|i| i + 62) // 61 static + 1-indexed
    }

    /// Find a dynamic table entry matching just the name.
    /// Returns the HPACK index (62 + position) if found.
    fn find_name(&self, name: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .position(|h| h.name == name)
            .map(|i| i + 62)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// -- String literal encoding/decoding --

/// Encode a string literal with optional Huffman compression.
fn encode_string_literal(buf: &mut Vec<u8>, data: &[u8]) {
    let huf_len = crate::huffman::encoded_len(data);
    if huf_len < data.len() {
        // Huffman is shorter -- set H bit (0x80).
        encode_prefix_int(buf, huf_len as u64, 7, 0x80);
        crate::huffman::encode(data, buf);
    } else {
        // Raw is shorter or equal -- no H bit.
        encode_prefix_int(buf, data.len() as u64, 7, 0x00);
        buf.extend_from_slice(data);
    }
}

/// Decode a string literal (Huffman or raw).
fn decode_string_literal(buf: &[u8]) -> Result<(Vec<u8>, usize), H2Error> {
    if buf.is_empty() {
        return Err(H2Error::CompressionError);
    }
    let huffman = buf[0] & 0x80 != 0;
    let (str_len, n) = decode_prefix_int(buf, 7).ok_or(H2Error::CompressionError)?;
    let str_len = str_len as usize;
    let total = n + str_len;
    if buf.len() < total {
        return Err(H2Error::CompressionError);
    }
    let data = &buf[n..total];
    let value = if huffman {
        crate::huffman::decode(data)?
    } else {
        data.to_vec()
    };
    Ok((value, total))
}

// -- Encoder --

/// HPACK encoder with dynamic table.
pub struct Encoder {
    dynamic_table: DynamicTable,
}

impl Encoder {
    pub fn new(max_table_size: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::new(max_table_size),
        }
    }

    /// Encode a list of headers into an HPACK header block.
    pub fn encode(&mut self, headers: &[HeaderField], buf: &mut Vec<u8>) {
        for header in headers {
            self.encode_header(header, buf);
        }
    }

    fn encode_header(&mut self, header: &HeaderField, buf: &mut Vec<u8>) {
        // 1. Check for exact match in static table.
        if let Some(index) = find_static_name_value(&header.name, &header.value) {
            // Indexed header field (RFC 7541 Section 6.1): pattern 1xxxxxxx, 7-bit index.
            encode_prefix_int(buf, index as u64, 7, 0x80);
            return;
        }

        // 2. Check for exact match in dynamic table.
        if let Some(index) = self.dynamic_table.find_name_value(&header.name, &header.value) {
            encode_prefix_int(buf, index as u64, 7, 0x80);
            return;
        }

        // 3. Check for name match in static table -- use incremental indexing.
        if let Some(name_index) = find_static_name(&header.name) {
            // Literal with incremental indexing (RFC 7541 Section 6.2.1):
            // pattern 01xxxxxx, 6-bit name index.
            encode_prefix_int(buf, name_index as u64, 6, 0x40);
            encode_string_literal(buf, &header.value);
            self.dynamic_table.insert(header.clone());
            return;
        }

        // 4. Check for name match in dynamic table.
        if let Some(name_index) = self.dynamic_table.find_name(&header.name) {
            encode_prefix_int(buf, name_index as u64, 6, 0x40);
            encode_string_literal(buf, &header.value);
            self.dynamic_table.insert(header.clone());
            return;
        }

        // 5. Literal with incremental indexing, new name.
        // Pattern 0100_0000 = 0x40, 6-bit index = 0.
        buf.push(0x40);
        encode_string_literal(buf, &header.name);
        encode_string_literal(buf, &header.value);
        self.dynamic_table.insert(header.clone());
    }

    /// Signal a dynamic table size update to the decoder.
    pub fn set_max_table_size(&mut self, new_size: usize, buf: &mut Vec<u8>) {
        self.dynamic_table.set_max_size(new_size);
        // Dynamic table size update (RFC 7541 Section 6.3):
        // pattern 001xxxxx, 5-bit prefix.
        encode_prefix_int(buf, new_size as u64, 5, 0x20);
    }
}

// -- Decoder --

/// HPACK decoder with dynamic table.
pub struct Decoder {
    dynamic_table: DynamicTable,
    max_table_size: usize,
}

impl Decoder {
    pub fn new(max_table_size: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::new(max_table_size),
            max_table_size,
        }
    }

    /// Decode an HPACK header block.
    pub fn decode(&mut self, buf: &[u8]) -> Result<Vec<HeaderField>, H2Error> {
        let mut headers = Vec::new();
        let mut pos = 0;

        while pos < buf.len() {
            let first = buf[pos];

            if first & 0x80 != 0 {
                // Indexed header field (Section 6.1): pattern 1xxxxxxx.
                let (index, n) =
                    decode_prefix_int(&buf[pos..], 7).ok_or(H2Error::CompressionError)?;
                pos += n;
                let field = self.get_indexed(index as usize)?;
                headers.push(field);
            } else if first & 0x40 != 0 {
                // Literal with incremental indexing (Section 6.2.1): pattern 01xxxxxx.
                let (name_index, n) =
                    decode_prefix_int(&buf[pos..], 6).ok_or(H2Error::CompressionError)?;
                pos += n;
                let name = if name_index > 0 {
                    self.get_name(name_index as usize)?
                } else {
                    let (name, consumed) = decode_string_literal(&buf[pos..])?;
                    pos += consumed;
                    name
                };
                let (value, consumed) = decode_string_literal(&buf[pos..])?;
                pos += consumed;
                let field = HeaderField {
                    name: name.clone(),
                    value,
                };
                self.dynamic_table.insert(field.clone());
                headers.push(field);
            } else if first & 0x20 != 0 {
                // Dynamic table size update (Section 6.3): pattern 001xxxxx.
                let (new_size, n) =
                    decode_prefix_int(&buf[pos..], 5).ok_or(H2Error::CompressionError)?;
                pos += n;
                let new_size = new_size as usize;
                if new_size > self.max_table_size {
                    return Err(H2Error::CompressionError);
                }
                self.dynamic_table.set_max_size(new_size);
            } else if first & 0x10 != 0 {
                // Literal never indexed (Section 6.2.3): pattern 0001xxxx.
                let (name_index, n) =
                    decode_prefix_int(&buf[pos..], 4).ok_or(H2Error::CompressionError)?;
                pos += n;
                let name = if name_index > 0 {
                    self.get_name(name_index as usize)?
                } else {
                    let (name, consumed) = decode_string_literal(&buf[pos..])?;
                    pos += consumed;
                    name
                };
                let (value, consumed) = decode_string_literal(&buf[pos..])?;
                pos += consumed;
                headers.push(HeaderField { name, value });
                // Never indexed: do NOT add to dynamic table.
            } else {
                // Literal without indexing (Section 6.2.2): pattern 0000xxxx.
                let (name_index, n) =
                    decode_prefix_int(&buf[pos..], 4).ok_or(H2Error::CompressionError)?;
                pos += n;
                let name = if name_index > 0 {
                    self.get_name(name_index as usize)?
                } else {
                    let (name, consumed) = decode_string_literal(&buf[pos..])?;
                    pos += consumed;
                    name
                };
                let (value, consumed) = decode_string_literal(&buf[pos..])?;
                pos += consumed;
                headers.push(HeaderField { name, value });
                // Without indexing: do NOT add to dynamic table.
            }
        }

        Ok(headers)
    }

    /// Look up an indexed header field (static or dynamic).
    fn get_indexed(&self, index: usize) -> Result<HeaderField, H2Error> {
        if index == 0 {
            return Err(H2Error::CompressionError);
        }
        if index <= STATIC_TABLE.len() {
            let (name, value) = STATIC_TABLE[index - 1];
            Ok(HeaderField {
                name: name.to_vec(),
                value: value.to_vec(),
            })
        } else {
            let dyn_index = index - STATIC_TABLE.len() - 1;
            self.dynamic_table
                .get(dyn_index)
                .cloned()
                .ok_or(H2Error::CompressionError)
        }
    }

    /// Look up only the name from an indexed entry.
    fn get_name(&self, index: usize) -> Result<Vec<u8>, H2Error> {
        if index == 0 {
            return Err(H2Error::CompressionError);
        }
        if index <= STATIC_TABLE.len() {
            Ok(STATIC_TABLE[index - 1].0.to_vec())
        } else {
            let dyn_index = index - STATIC_TABLE.len() - 1;
            self.dynamic_table
                .get(dyn_index)
                .map(|h| h.name.clone())
                .ok_or(H2Error::CompressionError)
        }
    }

    /// Update the maximum dynamic table size allowed by SETTINGS.
    pub fn set_max_table_size(&mut self, max_size: usize) {
        self.max_table_size = max_size;
        // The actual resize happens when we receive a dynamic table size update
        // instruction in the header block.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_int_round_trip() {
        for &(value, prefix_bits, pattern) in &[
            (0u64, 7, 0x80u8),
            (5, 7, 0x80),
            (126, 7, 0x80),
            (127, 7, 0x80),
            (128, 7, 0x80),
            (1000, 7, 0x80),
            (0, 6, 0x40),
            (62, 6, 0x40),
            (63, 6, 0x40),
            (64, 6, 0x40),
            (255, 6, 0x40),
            (0, 5, 0x20),
            (31, 5, 0x20),
            (32, 5, 0x20),
            (4096, 5, 0x20),
            (0, 4, 0x00),
            (15, 4, 0x00),
            (16, 4, 0x00),
        ] {
            let mut buf = Vec::new();
            encode_prefix_int(&mut buf, value, prefix_bits, pattern);
            let (decoded, len) = decode_prefix_int(&buf, prefix_bits).unwrap();
            assert_eq!(
                decoded, value,
                "mismatch for value={value} prefix={prefix_bits}"
            );
            assert_eq!(len, buf.len());
            let mask = !((1u8 << prefix_bits) - 1);
            assert_eq!(buf[0] & mask, pattern & mask);
        }
    }

    #[test]
    fn static_table_size() {
        assert_eq!(STATIC_TABLE.len(), 61);
    }

    #[test]
    fn encode_decode_indexed() {
        // :method GET is static index 2.
        let mut encoder = Encoder::new(4096);
        let mut decoder = Decoder::new(4096);
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let mut buf = Vec::new();
        encoder.encode(&headers, &mut buf);
        let decoded = decoder.decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_decode_name_reference() {
        // :path /foo -- :path is at index 4 with value "/".
        let mut encoder = Encoder::new(4096);
        let mut decoder = Decoder::new(4096);
        let headers = vec![HeaderField::new(b":path", b"/foo")];
        let mut buf = Vec::new();
        encoder.encode(&headers, &mut buf);
        let decoded = decoder.decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_decode_literal() {
        let mut encoder = Encoder::new(4096);
        let mut decoder = Decoder::new(4096);
        let headers = vec![HeaderField::new(b"x-custom", b"value123")];
        let mut buf = Vec::new();
        encoder.encode(&headers, &mut buf);
        let decoded = decoder.decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_decode_multiple_headers() {
        let mut encoder = Encoder::new(4096);
        let mut decoder = Decoder::new(4096);
        let headers = vec![
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b":path", b"/"),
            HeaderField::new(b":scheme", b"https"),
            HeaderField::new(b":authority", b"example.com"),
            HeaderField::new(b"accept", b"*/*"),
            HeaderField::new(b"x-request-id", b"abc123"),
        ];
        let mut buf = Vec::new();
        encoder.encode(&headers, &mut buf);
        let decoded = decoder.decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn dynamic_table_reuse() {
        let mut encoder = Encoder::new(4096);
        let mut decoder = Decoder::new(4096);

        // First request encodes custom header -- adds to dynamic table.
        let headers1 = vec![
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b"x-token", b"abc"),
        ];
        let mut buf1 = Vec::new();
        encoder.encode(&headers1, &mut buf1);
        let decoded1 = decoder.decode(&buf1).unwrap();
        assert_eq!(decoded1, headers1);

        // Second request reuses the same custom header -- should use dynamic table index.
        let headers2 = vec![
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b"x-token", b"abc"),
        ];
        let mut buf2 = Vec::new();
        encoder.encode(&headers2, &mut buf2);
        let decoded2 = decoder.decode(&buf2).unwrap();
        assert_eq!(decoded2, headers2);

        // Second encoding should be shorter (uses indexed representation).
        assert!(buf2.len() <= buf1.len());
    }

    #[test]
    fn dynamic_table_eviction() {
        // Tiny max size to force eviction.
        let mut encoder = Encoder::new(64);
        let mut decoder = Decoder::new(64);

        let headers = vec![
            HeaderField::new(b"x-long-header-name", b"a-somewhat-long-value"),
        ];
        let mut buf = Vec::new();
        encoder.encode(&headers, &mut buf);
        let decoded = decoder.decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_decode_status_200() {
        let mut encoder = Encoder::new(4096);
        let mut decoder = Decoder::new(4096);
        let headers = vec![
            HeaderField::new(b":status", b"200"),
            HeaderField::new(b"content-type", b"text/plain"),
        ];
        let mut buf = Vec::new();
        encoder.encode(&headers, &mut buf);
        let decoded = decoder.decode(&buf).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn table_size_update() {
        let mut encoder = Encoder::new(4096);
        let mut decoder = Decoder::new(4096);

        let mut buf = Vec::new();
        encoder.set_max_table_size(256, &mut buf);
        encoder.encode(
            &[HeaderField::new(b":method", b"GET")],
            &mut buf,
        );
        let decoded = decoder.decode(&buf).unwrap();
        assert_eq!(decoded, vec![HeaderField::new(b":method", b"GET")]);
    }

    #[test]
    fn rfc7541_appendix_c1_integer_examples() {
        // C.1.1: Encoding 10 using a 5-bit prefix.
        let mut buf = Vec::new();
        encode_prefix_int(&mut buf, 10, 5, 0x00);
        assert_eq!(buf, vec![0x0a]);

        // C.1.2: Encoding 1337 using a 5-bit prefix.
        let mut buf = Vec::new();
        encode_prefix_int(&mut buf, 1337, 5, 0x00);
        assert_eq!(buf, vec![0x1f, 0x9a, 0x0a]);

        // C.1.3: Encoding 42 starting at an octet boundary (8-bit prefix).
        let mut buf = Vec::new();
        encode_prefix_int(&mut buf, 42, 8, 0x00);
        assert_eq!(buf, vec![0x2a]);
    }
}
