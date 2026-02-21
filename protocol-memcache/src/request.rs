//! Client-side request encoding for Memcache ASCII protocol.
//!
//! This module provides encoding of Memcache commands for client applications.

use std::io::Write;

/// A request builder for encoding Memcache commands.
#[derive(Debug, Clone)]
pub enum Request<'a> {
    /// GET command: `get <key>\r\n`
    Get { key: &'a [u8] },
    /// Multi-GET command: `get <key1> <key2> ...\r\n`
    Gets { keys: &'a [&'a [u8]] },
    /// SET command: `set <key> <flags> <exptime> <bytes>\r\n<data>\r\n`
    Set {
        key: &'a [u8],
        value: &'a [u8],
        flags: u32,
        exptime: u32,
    },
    /// ADD command: `add <key> <flags> <exptime> <bytes>\r\n<data>\r\n`
    ///
    /// Stores the item only if the key does not already exist.
    Add {
        key: &'a [u8],
        value: &'a [u8],
        flags: u32,
        exptime: u32,
    },
    /// REPLACE command: `replace <key> <flags> <exptime> <bytes>\r\n<data>\r\n`
    ///
    /// Stores the item only if the key already exists.
    Replace {
        key: &'a [u8],
        value: &'a [u8],
        flags: u32,
        exptime: u32,
    },
    /// INCR command: `incr <key> <delta>\r\n`
    Incr { key: &'a [u8], delta: u64 },
    /// DECR command: `decr <key> <delta>\r\n`
    Decr { key: &'a [u8], delta: u64 },
    /// APPEND command: `append <key> 0 0 <bytes>\r\n<data>\r\n`
    ///
    /// Appends data to an existing item's value.
    Append { key: &'a [u8], value: &'a [u8] },
    /// PREPEND command: `prepend <key> 0 0 <bytes>\r\n<data>\r\n`
    ///
    /// Prepends data to an existing item's value.
    Prepend { key: &'a [u8], value: &'a [u8] },
    /// CAS command: `cas <key> <flags> <exptime> <bytes> <cas_unique>\r\n<data>\r\n`
    ///
    /// Compare-and-swap: stores only if the CAS token matches.
    Cas {
        key: &'a [u8],
        value: &'a [u8],
        flags: u32,
        exptime: u32,
        cas_unique: u64,
    },
    /// DELETE command: `delete <key>\r\n`
    Delete { key: &'a [u8] },
    /// FLUSH_ALL command: `flush_all\r\n`
    FlushAll,
    /// VERSION command: `version\r\n`
    Version,
    /// QUIT command: `quit\r\n`
    Quit,
}

impl<'a> Request<'a> {
    /// Create a GET request.
    #[inline]
    pub fn get(key: &'a [u8]) -> Self {
        Request::Get { key }
    }

    /// Create a multi-GET request.
    #[inline]
    pub fn gets(keys: &'a [&'a [u8]]) -> Self {
        Request::Gets { keys }
    }

    /// Create a SET request.
    #[inline]
    pub fn set(key: &'a [u8], value: &'a [u8]) -> SetRequest<'a> {
        SetRequest {
            key,
            value,
            flags: 0,
            exptime: 0,
        }
    }

    /// Create an ADD request (store only if key does not exist).
    #[inline]
    pub fn add(key: &'a [u8], value: &'a [u8]) -> AddRequest<'a> {
        AddRequest {
            key,
            value,
            flags: 0,
            exptime: 0,
        }
    }

    /// Create a REPLACE request (store only if key already exists).
    #[inline]
    pub fn replace(key: &'a [u8], value: &'a [u8]) -> ReplaceRequest<'a> {
        ReplaceRequest {
            key,
            value,
            flags: 0,
            exptime: 0,
        }
    }

    /// Create an INCR request.
    #[inline]
    pub fn incr(key: &'a [u8], delta: u64) -> Self {
        Request::Incr { key, delta }
    }

    /// Create a DECR request.
    #[inline]
    pub fn decr(key: &'a [u8], delta: u64) -> Self {
        Request::Decr { key, delta }
    }

    /// Create an APPEND request.
    #[inline]
    pub fn append(key: &'a [u8], value: &'a [u8]) -> Self {
        Request::Append { key, value }
    }

    /// Create a PREPEND request.
    #[inline]
    pub fn prepend(key: &'a [u8], value: &'a [u8]) -> Self {
        Request::Prepend { key, value }
    }

    /// Create a CAS (compare-and-swap) request.
    #[inline]
    pub fn cas(key: &'a [u8], value: &'a [u8], cas_unique: u64) -> Self {
        Request::Cas {
            key,
            value,
            flags: 0,
            exptime: 0,
            cas_unique,
        }
    }

    /// Create a DELETE request.
    #[inline]
    pub fn delete(key: &'a [u8]) -> Self {
        Request::Delete { key }
    }

    /// Create a FLUSH_ALL request.
    #[inline]
    pub fn flush_all() -> Self {
        Request::FlushAll
    }

    /// Create a VERSION request.
    #[inline]
    pub fn version() -> Self {
        Request::Version
    }

    /// Create a QUIT request.
    #[inline]
    pub fn quit() -> Self {
        Request::Quit
    }

    /// Encode this request into a buffer.
    ///
    /// Returns the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        match self {
            Request::Get { key } => encode_get(buf, key),
            Request::Gets { keys } => encode_gets(buf, keys),
            Request::Set {
                key,
                value,
                flags,
                exptime,
            } => encode_storage(buf, b"set", key, value, *flags, *exptime),
            Request::Add {
                key,
                value,
                flags,
                exptime,
            } => encode_storage(buf, b"add", key, value, *flags, *exptime),
            Request::Replace {
                key,
                value,
                flags,
                exptime,
            } => encode_storage(buf, b"replace", key, value, *flags, *exptime),
            Request::Incr { key, delta } => encode_incr_decr(buf, b"incr", key, *delta),
            Request::Decr { key, delta } => encode_incr_decr(buf, b"decr", key, *delta),
            Request::Append { key, value } => encode_storage(buf, b"append", key, value, 0, 0),
            Request::Prepend { key, value } => encode_storage(buf, b"prepend", key, value, 0, 0),
            Request::Cas {
                key,
                value,
                flags,
                exptime,
                cas_unique,
            } => encode_cas(buf, key, value, *flags, *exptime, *cas_unique),
            Request::Delete { key } => encode_delete(buf, key),
            Request::FlushAll => encode_simple(buf, b"flush_all"),
            Request::Version => encode_simple(buf, b"version"),
            Request::Quit => encode_simple(buf, b"quit"),
        }
    }
}

/// Builder for SET requests with optional flags and exptime.
#[derive(Debug, Clone)]
pub struct SetRequest<'a> {
    key: &'a [u8],
    value: &'a [u8],
    flags: u32,
    exptime: u32,
}

impl<'a> SetRequest<'a> {
    /// Set the flags value.
    #[inline]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Set the expiration time in seconds.
    #[inline]
    pub fn exptime(mut self, exptime: u32) -> Self {
        self.exptime = exptime;
        self
    }

    /// Build the final request.
    #[inline]
    pub fn build(self) -> Request<'a> {
        Request::Set {
            key: self.key,
            value: self.value,
            flags: self.flags,
            exptime: self.exptime,
        }
    }

    /// Encode this request directly into a buffer.
    ///
    /// Returns the number of bytes written.
    #[inline]
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        encode_storage(buf, b"set", self.key, self.value, self.flags, self.exptime)
    }
}

/// Builder for ADD requests with optional flags and exptime.
#[derive(Debug, Clone)]
pub struct AddRequest<'a> {
    key: &'a [u8],
    value: &'a [u8],
    flags: u32,
    exptime: u32,
}

impl<'a> AddRequest<'a> {
    /// Set the flags value.
    #[inline]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Set the expiration time in seconds.
    #[inline]
    pub fn exptime(mut self, exptime: u32) -> Self {
        self.exptime = exptime;
        self
    }

    /// Build the final request.
    #[inline]
    pub fn build(self) -> Request<'a> {
        Request::Add {
            key: self.key,
            value: self.value,
            flags: self.flags,
            exptime: self.exptime,
        }
    }

    /// Encode this request directly into a buffer.
    ///
    /// Returns the number of bytes written.
    #[inline]
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        encode_storage(buf, b"add", self.key, self.value, self.flags, self.exptime)
    }
}

/// Builder for REPLACE requests with optional flags and exptime.
#[derive(Debug, Clone)]
pub struct ReplaceRequest<'a> {
    key: &'a [u8],
    value: &'a [u8],
    flags: u32,
    exptime: u32,
}

impl<'a> ReplaceRequest<'a> {
    /// Set the flags value.
    #[inline]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Set the expiration time in seconds.
    #[inline]
    pub fn exptime(mut self, exptime: u32) -> Self {
        self.exptime = exptime;
        self
    }

    /// Build the final request.
    #[inline]
    pub fn build(self) -> Request<'a> {
        Request::Replace {
            key: self.key,
            value: self.value,
            flags: self.flags,
            exptime: self.exptime,
        }
    }

    /// Encode this request directly into a buffer.
    ///
    /// Returns the number of bytes written.
    #[inline]
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        encode_storage(
            buf,
            b"replace",
            self.key,
            self.value,
            self.flags,
            self.exptime,
        )
    }
}

/// Encode a GET command: `get <key>\r\n`
fn encode_get(buf: &mut [u8], key: &[u8]) -> usize {
    let mut pos = 0;
    buf[pos..pos + 4].copy_from_slice(b"get ");
    pos += 4;
    buf[pos..pos + key.len()].copy_from_slice(key);
    pos += key.len();
    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos + 2
}

/// Encode a multi-GET command with CAS: `gets <key1> <key2> ...\r\n`
fn encode_gets(buf: &mut [u8], keys: &[&[u8]]) -> usize {
    if keys.is_empty() {
        return 0;
    }

    let mut pos = 0;
    buf[pos..pos + 4].copy_from_slice(b"gets");
    pos += 4;

    for key in keys {
        buf[pos] = b' ';
        pos += 1;
        buf[pos..pos + key.len()].copy_from_slice(key);
        pos += key.len();
    }

    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos + 2
}

/// Encode a storage command: `<cmd> <key> <flags> <exptime> <bytes>\r\n<data>\r\n`
///
/// Used for SET, ADD, REPLACE, etc. — all share the same wire format.
fn encode_storage(
    buf: &mut [u8],
    cmd: &[u8],
    key: &[u8],
    value: &[u8],
    flags: u32,
    exptime: u32,
) -> usize {
    let mut pos = 0;

    // <cmd> <key>
    buf[pos..pos + cmd.len()].copy_from_slice(cmd);
    pos += cmd.len();
    buf[pos] = b' ';
    pos += 1;
    buf[pos..pos + key.len()].copy_from_slice(key);
    pos += key.len();
    buf[pos] = b' ';
    pos += 1;

    // <flags> <exptime> <bytes>\r\n
    let mut cursor = std::io::Cursor::new(&mut buf[pos..]);
    write!(cursor, "{} {} {}\r\n", flags, exptime, value.len()).unwrap();
    pos += cursor.position() as usize;

    // <data>\r\n
    buf[pos..pos + value.len()].copy_from_slice(value);
    pos += value.len();
    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos + 2
}

/// Encode a DELETE command: `delete <key>\r\n`
fn encode_delete(buf: &mut [u8], key: &[u8]) -> usize {
    let mut pos = 0;
    buf[pos..pos + 7].copy_from_slice(b"delete ");
    pos += 7;
    buf[pos..pos + key.len()].copy_from_slice(key);
    pos += key.len();
    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos + 2
}

/// Encode a CAS command: `cas <key> <flags> <exptime> <bytes> <cas_unique>\r\n<data>\r\n`
fn encode_cas(
    buf: &mut [u8],
    key: &[u8],
    value: &[u8],
    flags: u32,
    exptime: u32,
    cas_unique: u64,
) -> usize {
    let mut pos = 0;

    // cas <key>
    buf[pos..pos + 4].copy_from_slice(b"cas ");
    pos += 4;
    buf[pos..pos + key.len()].copy_from_slice(key);
    pos += key.len();
    buf[pos] = b' ';
    pos += 1;

    // <flags> <exptime> <bytes> <cas_unique>\r\n
    let mut cursor = std::io::Cursor::new(&mut buf[pos..]);
    write!(
        cursor,
        "{} {} {} {}\r\n",
        flags,
        exptime,
        value.len(),
        cas_unique
    )
    .unwrap();
    pos += cursor.position() as usize;

    // <data>\r\n
    buf[pos..pos + value.len()].copy_from_slice(value);
    pos += value.len();
    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos + 2
}

/// Encode an INCR/DECR command: `<cmd> <key> <delta>\r\n`
fn encode_incr_decr(buf: &mut [u8], cmd: &[u8], key: &[u8], delta: u64) -> usize {
    let mut pos = 0;
    buf[pos..pos + cmd.len()].copy_from_slice(cmd);
    pos += cmd.len();
    buf[pos] = b' ';
    pos += 1;
    buf[pos..pos + key.len()].copy_from_slice(key);
    pos += key.len();
    buf[pos] = b' ';
    pos += 1;

    let mut cursor = std::io::Cursor::new(&mut buf[pos..]);
    write!(cursor, "{}\r\n", delta).unwrap();
    pos += cursor.position() as usize;
    pos
}

/// Encode a simple command with no arguments.
fn encode_simple(buf: &mut [u8], cmd: &[u8]) -> usize {
    buf[..cmd.len()].copy_from_slice(cmd);
    buf[cmd.len()..cmd.len() + 2].copy_from_slice(b"\r\n");
    cmd.len() + 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_get() {
        let mut buf = [0u8; 64];
        let len = Request::get(b"mykey").encode(&mut buf);
        assert_eq!(&buf[..len], b"get mykey\r\n");
    }

    #[test]
    fn test_encode_gets() {
        let mut buf = [0u8; 64];
        let keys: &[&[u8]] = &[b"key1", b"key2", b"key3"];
        let len = Request::gets(keys).encode(&mut buf);
        assert_eq!(&buf[..len], b"gets key1 key2 key3\r\n");
    }

    #[test]
    fn test_encode_set() {
        let mut buf = [0u8; 64];
        let len = Request::set(b"mykey", b"myvalue").encode(&mut buf);
        assert_eq!(&buf[..len], b"set mykey 0 0 7\r\nmyvalue\r\n");
    }

    #[test]
    fn test_encode_set_with_options() {
        let mut buf = [0u8; 64];
        let len = Request::set(b"mykey", b"myvalue")
            .flags(123)
            .exptime(3600)
            .encode(&mut buf);
        assert_eq!(&buf[..len], b"set mykey 123 3600 7\r\nmyvalue\r\n");
    }

    #[test]
    fn test_encode_delete() {
        let mut buf = [0u8; 64];
        let len = Request::delete(b"mykey").encode(&mut buf);
        assert_eq!(&buf[..len], b"delete mykey\r\n");
    }

    #[test]
    fn test_encode_flush_all() {
        let mut buf = [0u8; 64];
        let len = Request::flush_all().encode(&mut buf);
        assert_eq!(&buf[..len], b"flush_all\r\n");
    }

    #[test]
    fn test_encode_version() {
        let mut buf = [0u8; 64];
        let len = Request::version().encode(&mut buf);
        assert_eq!(&buf[..len], b"version\r\n");
    }

    #[test]
    fn test_encode_quit() {
        let mut buf = [0u8; 64];
        let len = Request::quit().encode(&mut buf);
        assert_eq!(&buf[..len], b"quit\r\n");
    }

    // Additional tests for improved coverage

    #[test]
    fn test_set_request_build() {
        let mut buf = [0u8; 64];
        let request = Request::set(b"mykey", b"myvalue")
            .flags(42)
            .exptime(600)
            .build();
        let len = request.encode(&mut buf);
        assert_eq!(&buf[..len], b"set mykey 42 600 7\r\nmyvalue\r\n");
    }

    #[test]
    fn test_encode_gets_empty() {
        let mut buf = [0u8; 64];
        let keys: &[&[u8]] = &[];
        let len = Request::gets(keys).encode(&mut buf);
        assert_eq!(len, 0);
    }

    #[test]
    fn test_encode_gets_single() {
        let mut buf = [0u8; 64];
        let keys: &[&[u8]] = &[b"single"];
        let len = Request::gets(keys).encode(&mut buf);
        assert_eq!(&buf[..len], b"gets single\r\n");
    }

    #[test]
    fn test_request_debug() {
        let req = Request::get(b"key");
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("Get"));
    }

    #[test]
    fn test_request_clone() {
        let req1 = Request::get(b"key");
        let req2 = req1.clone();
        // Both should encode the same
        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];
        let len1 = req1.encode(&mut buf1);
        let len2 = req2.encode(&mut buf2);
        assert_eq!(&buf1[..len1], &buf2[..len2]);
    }

    #[test]
    fn test_set_request_debug() {
        let req = Request::set(b"key", b"value");
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("SetRequest"));
    }

    #[test]
    fn test_set_request_clone() {
        let req1 = Request::set(b"key", b"value").flags(1);
        let req2 = req1.clone();
        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];
        let len1 = req1.encode(&mut buf1);
        let len2 = req2.encode(&mut buf2);
        assert_eq!(&buf1[..len1], &buf2[..len2]);
    }

    #[test]
    fn test_encode_set_via_request() {
        let mut buf = [0u8; 64];
        let request = Request::Set {
            key: b"k",
            value: b"v",
            flags: 0,
            exptime: 0,
        };
        let len = request.encode(&mut buf);
        assert_eq!(&buf[..len], b"set k 0 0 1\r\nv\r\n");
    }

    #[test]
    fn test_encode_gets_via_request() {
        let mut buf = [0u8; 64];
        let keys: &[&[u8]] = &[b"a", b"b"];
        let request = Request::Gets { keys };
        let len = request.encode(&mut buf);
        assert_eq!(&buf[..len], b"gets a b\r\n");
    }

    #[test]
    fn test_encode_add() {
        let mut buf = [0u8; 64];
        let len = Request::add(b"mykey", b"myvalue").encode(&mut buf);
        assert_eq!(&buf[..len], b"add mykey 0 0 7\r\nmyvalue\r\n");
    }

    #[test]
    fn test_encode_add_with_options() {
        let mut buf = [0u8; 64];
        let len = Request::add(b"mykey", b"myvalue")
            .flags(99)
            .exptime(300)
            .encode(&mut buf);
        assert_eq!(&buf[..len], b"add mykey 99 300 7\r\nmyvalue\r\n");
    }

    #[test]
    fn test_add_request_build() {
        let mut buf = [0u8; 64];
        let request = Request::add(b"mykey", b"myvalue")
            .flags(42)
            .exptime(600)
            .build();
        let len = request.encode(&mut buf);
        assert_eq!(&buf[..len], b"add mykey 42 600 7\r\nmyvalue\r\n");
    }

    #[test]
    fn test_encode_add_via_request() {
        let mut buf = [0u8; 64];
        let request = Request::Add {
            key: b"k",
            value: b"v",
            flags: 0,
            exptime: 0,
        };
        let len = request.encode(&mut buf);
        assert_eq!(&buf[..len], b"add k 0 0 1\r\nv\r\n");
    }

    #[test]
    fn test_encode_replace() {
        let mut buf = [0u8; 64];
        let len = Request::replace(b"mykey", b"myvalue").encode(&mut buf);
        assert_eq!(&buf[..len], b"replace mykey 0 0 7\r\nmyvalue\r\n");
    }

    #[test]
    fn test_encode_replace_with_options() {
        let mut buf = [0u8; 64];
        let len = Request::replace(b"mykey", b"myvalue")
            .flags(99)
            .exptime(300)
            .encode(&mut buf);
        assert_eq!(&buf[..len], b"replace mykey 99 300 7\r\nmyvalue\r\n");
    }

    #[test]
    fn test_replace_request_build() {
        let mut buf = [0u8; 64];
        let request = Request::replace(b"mykey", b"myvalue")
            .flags(42)
            .exptime(600)
            .build();
        let len = request.encode(&mut buf);
        assert_eq!(&buf[..len], b"replace mykey 42 600 7\r\nmyvalue\r\n");
    }

    #[test]
    fn test_encode_replace_via_request() {
        let mut buf = [0u8; 64];
        let request = Request::Replace {
            key: b"k",
            value: b"v",
            flags: 0,
            exptime: 0,
        };
        let len = request.encode(&mut buf);
        assert_eq!(&buf[..len], b"replace k 0 0 1\r\nv\r\n");
    }

    #[test]
    fn test_encode_incr() {
        let mut buf = [0u8; 64];
        let len = Request::incr(b"counter", 1).encode(&mut buf);
        assert_eq!(&buf[..len], b"incr counter 1\r\n");
    }

    #[test]
    fn test_encode_incr_large_delta() {
        let mut buf = [0u8; 64];
        let len = Request::incr(b"counter", 12345).encode(&mut buf);
        assert_eq!(&buf[..len], b"incr counter 12345\r\n");
    }

    #[test]
    fn test_encode_decr() {
        let mut buf = [0u8; 64];
        let len = Request::decr(b"counter", 5).encode(&mut buf);
        assert_eq!(&buf[..len], b"decr counter 5\r\n");
    }

    #[test]
    fn test_encode_decr_large_delta() {
        let mut buf = [0u8; 64];
        let len = Request::decr(b"counter", 99999).encode(&mut buf);
        assert_eq!(&buf[..len], b"decr counter 99999\r\n");
    }

    #[test]
    fn test_encode_append() {
        let mut buf = [0u8; 64];
        let len = Request::append(b"mykey", b"extra").encode(&mut buf);
        assert_eq!(&buf[..len], b"append mykey 0 0 5\r\nextra\r\n");
    }

    #[test]
    fn test_encode_prepend() {
        let mut buf = [0u8; 64];
        let len = Request::prepend(b"mykey", b"prefix").encode(&mut buf);
        assert_eq!(&buf[..len], b"prepend mykey 0 0 6\r\nprefix\r\n");
    }

    #[test]
    fn test_encode_cas() {
        let mut buf = [0u8; 128];
        let len = Request::cas(b"mykey", b"myvalue", 12345).encode(&mut buf);
        assert_eq!(&buf[..len], b"cas mykey 0 0 7 12345\r\nmyvalue\r\n");
    }

    #[test]
    fn test_encode_cas_via_request() {
        let mut buf = [0u8; 128];
        let request = Request::Cas {
            key: b"k",
            value: b"v",
            flags: 42,
            exptime: 600,
            cas_unique: 99,
        };
        let len = request.encode(&mut buf);
        assert_eq!(&buf[..len], b"cas k 42 600 1 99\r\nv\r\n");
    }
}
