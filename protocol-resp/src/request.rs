//! Client-side request encoding.
//!
//! This module provides efficient encoding of Redis commands for client applications.
//! Commands are encoded as RESP arrays of bulk strings.

use std::io::Write;

/// A request builder for encoding Redis commands.
///
/// This provides a fluent interface for building and encoding commands.
///
/// # Example
///
/// ```
/// use protocol_resp::Request;
///
/// let mut buf = vec![0u8; 1024];
///
/// // Simple GET
/// let len = Request::get(b"mykey").encode(&mut buf);
///
/// // SET with expiration
/// let len = Request::set(b"mykey", b"myvalue").ex(3600).encode(&mut buf);
/// ```
#[derive(Debug, Clone)]
pub struct Request<'a> {
    args: Vec<&'a [u8]>,
}

impl<'a> Request<'a> {
    /// Create a new request with the given arguments.
    #[inline]
    pub fn new(args: Vec<&'a [u8]>) -> Self {
        Self { args }
    }

    /// Create a PING command.
    #[inline]
    pub fn ping() -> Self {
        Self {
            args: vec![b"PING"],
        }
    }

    /// Create a GET command.
    #[inline]
    pub fn get(key: &'a [u8]) -> Self {
        Self {
            args: vec![b"GET", key],
        }
    }

    /// Create a SET command.
    #[inline]
    pub fn set(key: &'a [u8], value: &'a [u8]) -> SetRequest<'a> {
        SetRequest {
            key,
            value,
            ex: None,
            px: None,
            nx: false,
            xx: false,
        }
    }

    /// Create a DEL command.
    #[inline]
    pub fn del(key: &'a [u8]) -> Self {
        Self {
            args: vec![b"DEL", key],
        }
    }

    /// Create a MGET command (multiple keys).
    #[inline]
    pub fn mget(keys: &[&'a [u8]]) -> Self {
        let mut args = Vec::with_capacity(1 + keys.len());
        args.push(b"MGET" as &[u8]);
        args.extend_from_slice(keys);
        Self { args }
    }

    /// Create a CONFIG GET command.
    #[inline]
    pub fn config_get(key: &'a [u8]) -> Self {
        Self {
            args: vec![b"CONFIG", b"GET", key],
        }
    }

    /// Create a CONFIG SET command.
    #[inline]
    pub fn config_set(key: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            args: vec![b"CONFIG", b"SET", key, value],
        }
    }

    /// Create a FLUSHDB command.
    #[inline]
    pub fn flushdb() -> Self {
        Self {
            args: vec![b"FLUSHDB"],
        }
    }

    /// Create a FLUSHALL command.
    #[inline]
    pub fn flushall() -> Self {
        Self {
            args: vec![b"FLUSHALL"],
        }
    }

    /// Create a CLUSTER SLOTS command.
    #[inline]
    pub fn cluster_slots() -> Self {
        Self {
            args: vec![b"CLUSTER", b"SLOTS"],
        }
    }

    /// Create a CLUSTER NODES command.
    #[inline]
    pub fn cluster_nodes() -> Self {
        Self {
            args: vec![b"CLUSTER", b"NODES"],
        }
    }

    /// Create a CLUSTER INFO command.
    #[inline]
    pub fn cluster_info() -> Self {
        Self {
            args: vec![b"CLUSTER", b"INFO"],
        }
    }

    /// Create a CLUSTER MYID command.
    #[inline]
    pub fn cluster_myid() -> Self {
        Self {
            args: vec![b"CLUSTER", b"MYID"],
        }
    }

    /// Create an ASKING command.
    #[inline]
    pub fn asking() -> Self {
        Self {
            args: vec![b"ASKING"],
        }
    }

    /// Create a READONLY command.
    #[inline]
    pub fn readonly() -> Self {
        Self {
            args: vec![b"READONLY"],
        }
    }

    /// Create a READWRITE command.
    #[inline]
    pub fn readwrite() -> Self {
        Self {
            args: vec![b"READWRITE"],
        }
    }

    /// Create a custom command with arbitrary arguments.
    #[inline]
    pub fn cmd(name: &'a [u8]) -> Self {
        Self { args: vec![name] }
    }

    /// Add an argument to the command.
    #[inline]
    pub fn arg(mut self, arg: &'a [u8]) -> Self {
        self.args.push(arg);
        self
    }

    /// Encode this request into a buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panics
    ///
    /// Panics if the buffer is too small.
    #[inline]
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        encode_command(buf, &self.args)
    }

    /// Calculate the encoded length of this request.
    pub fn encoded_len(&self) -> usize {
        let mut len = 0;

        // Array header: *<count>\r\n
        let mut count_buf = itoa::Buffer::new();
        len += 1 + count_buf.format(self.args.len()).len() + 2;

        // Each argument: $<len>\r\n<data>\r\n
        for arg in &self.args {
            let mut arg_len_buf = itoa::Buffer::new();
            len += 1 + arg_len_buf.format(arg.len()).len() + 2 + arg.len() + 2;
        }

        len
    }
}

/// Builder for SET commands with options.
#[derive(Debug, Clone)]
pub struct SetRequest<'a> {
    key: &'a [u8],
    value: &'a [u8],
    ex: Option<u64>,
    px: Option<u64>,
    nx: bool,
    xx: bool,
}

impl<'a> SetRequest<'a> {
    /// Set expiration in seconds (EX option).
    #[inline]
    pub fn ex(mut self, seconds: u64) -> Self {
        self.ex = Some(seconds);
        self.px = None; // EX and PX are mutually exclusive
        self
    }

    /// Set expiration in milliseconds (PX option).
    #[inline]
    pub fn px(mut self, milliseconds: u64) -> Self {
        self.px = Some(milliseconds);
        self.ex = None; // EX and PX are mutually exclusive
        self
    }

    /// Only set if key does not exist (NX option).
    #[inline]
    pub fn nx(mut self) -> Self {
        self.nx = true;
        self.xx = false; // NX and XX are mutually exclusive
        self
    }

    /// Only set if key exists (XX option).
    #[inline]
    pub fn xx(mut self) -> Self {
        self.xx = true;
        self.nx = false; // NX and XX are mutually exclusive
        self
    }

    /// Encode this SET request as `(prefix, suffix)` for scatter-gather sends.
    ///
    /// The caller supplies the value bytes separately. The full RESP encoding is
    /// `[prefix, value, suffix].concat()`.
    ///
    /// - **prefix**: array header + SET bulk string + key bulk string + value length header (`$Lv\r\n`)
    /// - **suffix**: `\r\n` after the value + any option bulk strings (EX/PX/NX/XX)
    pub fn encode_parts(&self) -> (Vec<u8>, Vec<u8>) {
        let mut ex_str = itoa::Buffer::new();
        let mut px_str = itoa::Buffer::new();

        // Count total args: SET + key + value + options
        let mut arg_count: usize = 3;
        if self.ex.is_some() || self.px.is_some() {
            arg_count += 2;
        }
        if self.nx || self.xx {
            arg_count += 1;
        }

        // Build prefix: *<count>\r\n $3\r\nSET\r\n $<klen>\r\n<key>\r\n $<vlen>\r\n
        let mut prefix = Vec::new();
        let mut count_buf = itoa::Buffer::new();
        write!(prefix, "*{}\r\n", count_buf.format(arg_count)).unwrap();
        // SET bulk string
        write!(prefix, "$3\r\nSET\r\n").unwrap();
        // Key bulk string
        let mut klen_buf = itoa::Buffer::new();
        write!(prefix, "${}\r\n", klen_buf.format(self.key.len())).unwrap();
        prefix.extend_from_slice(self.key);
        write!(prefix, "\r\n").unwrap();
        // Value length header (value data supplied by caller)
        let mut vlen_buf = itoa::Buffer::new();
        write!(prefix, "${}\r\n", vlen_buf.format(self.value.len())).unwrap();

        // Build suffix: \r\n + option bulk strings
        let mut suffix = Vec::new();
        write!(suffix, "\r\n").unwrap();
        if let Some(seconds) = self.ex {
            let s = ex_str.format(seconds);
            let mut slen_buf = itoa::Buffer::new();
            write!(suffix, "$2\r\nEX\r\n${}\r\n", slen_buf.format(s.len())).unwrap();
            suffix.extend_from_slice(s.as_bytes());
            write!(suffix, "\r\n").unwrap();
        } else if let Some(millis) = self.px {
            let s = px_str.format(millis);
            let mut slen_buf = itoa::Buffer::new();
            write!(suffix, "$2\r\nPX\r\n${}\r\n", slen_buf.format(s.len())).unwrap();
            suffix.extend_from_slice(s.as_bytes());
            write!(suffix, "\r\n").unwrap();
        }
        if self.nx {
            write!(suffix, "$2\r\nNX\r\n").unwrap();
        } else if self.xx {
            write!(suffix, "$2\r\nXX\r\n").unwrap();
        }

        (prefix, suffix)
    }

    /// Encode this SET request into a buffer.
    ///
    /// Returns the number of bytes written.
    #[inline]
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        // Build argument list
        let mut ex_str = itoa::Buffer::new();
        let mut px_str = itoa::Buffer::new();

        let mut args: Vec<&[u8]> = vec![b"SET", self.key, self.value];

        if let Some(seconds) = self.ex {
            args.push(b"EX");
            args.push(ex_str.format(seconds).as_bytes());
        } else if let Some(millis) = self.px {
            args.push(b"PX");
            args.push(px_str.format(millis).as_bytes());
        }

        if self.nx {
            args.push(b"NX");
        } else if self.xx {
            args.push(b"XX");
        }

        encode_command(buf, &args)
    }

    /// Calculate the encoded length of this request.
    pub fn encoded_len(&self) -> usize {
        // Build the argument list to compute exact length
        let mut ex_str = itoa::Buffer::new();
        let mut px_str = itoa::Buffer::new();

        let mut args: Vec<&[u8]> = vec![b"SET", self.key, self.value];

        if let Some(seconds) = self.ex {
            args.push(b"EX");
            args.push(ex_str.format(seconds).as_bytes());
        } else if let Some(millis) = self.px {
            args.push(b"PX");
            args.push(px_str.format(millis).as_bytes());
        }

        if self.nx {
            args.push(b"NX");
        } else if self.xx {
            args.push(b"XX");
        }

        // Calculate exact length using same logic as Request::encoded_len()
        let mut len = 0;

        // Array header: *<count>\r\n
        let mut count_buf = itoa::Buffer::new();
        len += 1 + count_buf.format(args.len()).len() + 2;

        // Each argument: $<len>\r\n<data>\r\n
        for arg in &args {
            let mut arg_len_buf = itoa::Buffer::new();
            len += 1 + arg_len_buf.format(arg.len()).len() + 2 + arg.len() + 2;
        }

        len
    }
}

/// Encode a command (array of bulk strings) into a buffer.
///
/// Returns the number of bytes written.
#[inline]
pub fn encode_command(buf: &mut [u8], args: &[&[u8]]) -> usize {
    let mut pos = 0;

    // Write array header: *<count>\r\n
    buf[pos] = b'*';
    pos += 1;
    let mut cursor = std::io::Cursor::new(&mut buf[pos..]);
    write!(cursor, "{}\r\n", args.len()).unwrap();
    pos += cursor.position() as usize;

    // Write each argument as bulk string
    for arg in args {
        // $<len>\r\n
        buf[pos] = b'$';
        pos += 1;
        let mut cursor = std::io::Cursor::new(&mut buf[pos..]);
        write!(cursor, "{}\r\n", arg.len()).unwrap();
        pos += cursor.position() as usize;

        // <data>\r\n
        buf[pos..pos + arg.len()].copy_from_slice(arg);
        pos += arg.len();
        buf[pos] = b'\r';
        buf[pos + 1] = b'\n';
        pos += 2;
    }

    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_ping() {
        let mut buf = [0u8; 64];
        let len = Request::ping().encode(&mut buf);
        assert_eq!(&buf[..len], b"*1\r\n$4\r\nPING\r\n");
    }

    #[test]
    fn test_encode_get() {
        let mut buf = [0u8; 64];
        let len = Request::get(b"mykey").encode(&mut buf);
        assert_eq!(&buf[..len], b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n");
    }

    #[test]
    fn test_encode_set() {
        let mut buf = [0u8; 64];
        let len = Request::set(b"mykey", b"myvalue").encode(&mut buf);
        assert_eq!(
            &buf[..len],
            b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n"
        );
    }

    #[test]
    fn test_encode_set_ex() {
        let mut buf = [0u8; 128];
        let len = Request::set(b"mykey", b"myvalue").ex(3600).encode(&mut buf);
        assert_eq!(
            &buf[..len],
            b"*5\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n$2\r\nEX\r\n$4\r\n3600\r\n"
        );
    }

    #[test]
    fn test_encode_set_px() {
        let mut buf = [0u8; 128];
        let len = Request::set(b"key", b"val").px(1000).encode(&mut buf);
        assert!(std::str::from_utf8(&buf[..len]).unwrap().contains("PX"));
    }

    #[test]
    fn test_encode_set_nx() {
        let mut buf = [0u8; 128];
        let len = Request::set(b"key", b"val").nx().encode(&mut buf);
        assert!(std::str::from_utf8(&buf[..len]).unwrap().contains("NX"));
    }

    #[test]
    fn test_encode_del() {
        let mut buf = [0u8; 64];
        let len = Request::del(b"mykey").encode(&mut buf);
        assert_eq!(&buf[..len], b"*2\r\n$3\r\nDEL\r\n$5\r\nmykey\r\n");
    }

    #[test]
    fn test_encode_mget() {
        let mut buf = [0u8; 128];
        let keys: &[&[u8]] = &[b"key1", b"key2", b"key3"];
        let len = Request::mget(keys).encode(&mut buf);
        assert_eq!(
            &buf[..len],
            b"*4\r\n$4\r\nMGET\r\n$4\r\nkey1\r\n$4\r\nkey2\r\n$4\r\nkey3\r\n"
        );
    }

    #[test]
    fn test_encode_flushdb() {
        let mut buf = [0u8; 64];
        let len = Request::flushdb().encode(&mut buf);
        assert_eq!(&buf[..len], b"*1\r\n$7\r\nFLUSHDB\r\n");
    }

    #[test]
    fn test_encode_custom() {
        let mut buf = [0u8; 64];
        let len = Request::cmd(b"INCR").arg(b"counter").encode(&mut buf);
        assert_eq!(&buf[..len], b"*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n");
    }

    #[test]
    fn test_encoded_len() {
        let requests: Vec<Request> = vec![
            Request::ping(),
            Request::get(b"mykey"),
            Request::del(b"test"),
        ];

        for req in requests {
            let mut buf = [0u8; 256];
            let actual_len = req.encode(&mut buf);
            assert_eq!(req.encoded_len(), actual_len);
        }
    }

    #[test]
    fn test_request_new() {
        let args: Vec<&[u8]> = vec![b"CUSTOM", b"arg1", b"arg2"];
        let req = Request::new(args);
        let mut buf = [0u8; 128];
        let len = req.encode(&mut buf);
        assert!(len > 0);
        assert!(std::str::from_utf8(&buf[..len]).unwrap().contains("CUSTOM"));
    }

    #[test]
    fn test_encode_config_get() {
        let mut buf = [0u8; 128];
        let len = Request::config_get(b"maxclients").encode(&mut buf);
        let encoded = std::str::from_utf8(&buf[..len]).unwrap();
        assert!(encoded.contains("CONFIG"));
        assert!(encoded.contains("GET"));
        assert!(encoded.contains("maxclients"));
    }

    #[test]
    fn test_encode_config_set() {
        let mut buf = [0u8; 128];
        let len = Request::config_set(b"maxclients", b"100").encode(&mut buf);
        let encoded = std::str::from_utf8(&buf[..len]).unwrap();
        assert!(encoded.contains("CONFIG"));
        assert!(encoded.contains("SET"));
        assert!(encoded.contains("maxclients"));
        assert!(encoded.contains("100"));
    }

    #[test]
    fn test_encode_flushall() {
        let mut buf = [0u8; 64];
        let len = Request::flushall().encode(&mut buf);
        assert_eq!(&buf[..len], b"*1\r\n$8\r\nFLUSHALL\r\n");
    }

    #[test]
    fn test_encode_set_xx() {
        let mut buf = [0u8; 128];
        let len = Request::set(b"key", b"val").xx().encode(&mut buf);
        assert!(std::str::from_utf8(&buf[..len]).unwrap().contains("XX"));
    }

    #[test]
    fn test_set_px_overrides_ex() {
        // Setting PX should clear EX
        let mut buf = [0u8; 128];
        let len = Request::set(b"key", b"val")
            .ex(100)
            .px(5000)
            .encode(&mut buf);
        let encoded = std::str::from_utf8(&buf[..len]).unwrap();
        assert!(encoded.contains("PX"));
        assert!(!encoded.contains("EX\r\n")); // Should not have EX as separate arg
    }

    #[test]
    fn test_set_ex_overrides_px() {
        // Setting EX should clear PX
        let mut buf = [0u8; 128];
        let len = Request::set(b"key", b"val")
            .px(5000)
            .ex(100)
            .encode(&mut buf);
        let encoded = std::str::from_utf8(&buf[..len]).unwrap();
        assert!(encoded.contains("EX"));
        assert!(!encoded.contains("PX"));
    }

    #[test]
    fn test_set_xx_overrides_nx() {
        // Setting XX should clear NX
        let set_req = Request::set(b"key", b"val").nx().xx();
        assert!(set_req.xx);
        assert!(!set_req.nx);
    }

    #[test]
    fn test_set_nx_overrides_xx() {
        // Setting NX should clear XX
        let set_req = Request::set(b"key", b"val").xx().nx();
        assert!(set_req.nx);
        assert!(!set_req.xx);
    }

    #[test]
    fn test_set_request_encoded_len() {
        // Test various SetRequest configurations
        let configs = vec![
            Request::set(b"key", b"value"),
            Request::set(b"key", b"value").ex(3600),
            Request::set(b"key", b"value").px(5000),
            Request::set(b"key", b"value").nx(),
            Request::set(b"key", b"value").xx(),
            Request::set(b"key", b"value").ex(3600).nx(),
        ];

        for config in configs {
            let mut buf = [0u8; 256];
            let actual_len = config.encode(&mut buf);
            let estimated_len = config.encoded_len();
            assert_eq!(
                estimated_len, actual_len,
                "encoded_len() should match actual encoded length"
            );
        }
    }

    #[test]
    fn test_set_request_encoded_len_large_values() {
        // Test with larger keys and values to ensure length calculation handles
        // multi-digit lengths correctly
        let large_key = vec![b'k'; 1000];
        let large_value = vec![b'v'; 10000];

        let config = Request::set(&large_key, &large_value).ex(86400);
        let mut buf = vec![0u8; 20000];
        let actual_len = config.encode(&mut buf);
        let estimated_len = config.encoded_len();
        assert_eq!(
            estimated_len, actual_len,
            "encoded_len() should match for large values"
        );
    }

    #[test]
    fn test_encode_parts_matches_encode() {
        let configs: Vec<SetRequest<'_>> = vec![
            Request::set(b"mykey", b"myvalue"),
            Request::set(b"k", b"v").ex(3600),
            Request::set(b"key", b"val").px(1000),
            Request::set(b"key", b"val").nx(),
            Request::set(b"key", b"val").xx(),
            Request::set(b"key", b"val").ex(86400).nx(),
            Request::set(b"key", b"val").px(500).xx(),
        ];

        for config in &configs {
            // Full encode
            let mut buf = vec![0u8; 512];
            let len = config.encode(&mut buf);
            let full = &buf[..len];

            // Parts encode
            let (prefix, suffix) = config.encode_parts();
            let mut assembled = Vec::new();
            assembled.extend_from_slice(&prefix);
            assembled.extend_from_slice(config.value);
            assembled.extend_from_slice(&suffix);

            assert_eq!(
                assembled, full,
                "encode_parts concat must match encode() for {:?}",
                config
            );
        }
    }

    #[test]
    fn test_request_debug() {
        let req = Request::ping();
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("Request"));
    }

    #[test]
    fn test_request_clone() {
        let req1 = Request::get(b"mykey");
        let req2 = req1.clone();
        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];
        let len1 = req1.encode(&mut buf1);
        let len2 = req2.encode(&mut buf2);
        assert_eq!(&buf1[..len1], &buf2[..len2]);
    }

    #[test]
    fn test_set_request_debug() {
        let set_req = Request::set(b"key", b"value");
        let debug_str = format!("{:?}", set_req);
        assert!(debug_str.contains("SetRequest"));
    }

    #[test]
    fn test_set_request_clone() {
        let set1 = Request::set(b"key", b"value").ex(100);
        let set2 = set1.clone();
        let mut buf1 = [0u8; 128];
        let mut buf2 = [0u8; 128];
        let len1 = set1.encode(&mut buf1);
        let len2 = set2.encode(&mut buf2);
        assert_eq!(&buf1[..len1], &buf2[..len2]);
    }

    #[test]
    fn test_encode_cluster_slots() {
        let mut buf = [0u8; 128];
        let len = Request::cluster_slots().encode(&mut buf);
        assert_eq!(&buf[..len], b"*2\r\n$7\r\nCLUSTER\r\n$5\r\nSLOTS\r\n");
    }

    #[test]
    fn test_encode_cluster_nodes() {
        let mut buf = [0u8; 128];
        let len = Request::cluster_nodes().encode(&mut buf);
        assert_eq!(&buf[..len], b"*2\r\n$7\r\nCLUSTER\r\n$5\r\nNODES\r\n");
    }

    #[test]
    fn test_encode_cluster_info() {
        let mut buf = [0u8; 128];
        let len = Request::cluster_info().encode(&mut buf);
        assert_eq!(&buf[..len], b"*2\r\n$7\r\nCLUSTER\r\n$4\r\nINFO\r\n");
    }

    #[test]
    fn test_encode_cluster_myid() {
        let mut buf = [0u8; 128];
        let len = Request::cluster_myid().encode(&mut buf);
        assert_eq!(&buf[..len], b"*2\r\n$7\r\nCLUSTER\r\n$4\r\nMYID\r\n");
    }

    #[test]
    fn test_encode_asking() {
        let mut buf = [0u8; 64];
        let len = Request::asking().encode(&mut buf);
        assert_eq!(&buf[..len], b"*1\r\n$6\r\nASKING\r\n");
    }

    #[test]
    fn test_encode_readonly() {
        let mut buf = [0u8; 64];
        let len = Request::readonly().encode(&mut buf);
        assert_eq!(&buf[..len], b"*1\r\n$8\r\nREADONLY\r\n");
    }

    #[test]
    fn test_encode_readwrite() {
        let mut buf = [0u8; 64];
        let len = Request::readwrite().encode(&mut buf);
        assert_eq!(&buf[..len], b"*1\r\n$9\r\nREADWRITE\r\n");
    }

    #[test]
    fn test_mget_empty() {
        let keys: &[&[u8]] = &[];
        let req = Request::mget(keys);
        let mut buf = [0u8; 64];
        let len = req.encode(&mut buf);
        // Should just be MGET with no keys
        assert_eq!(&buf[..len], b"*1\r\n$4\r\nMGET\r\n");
    }
}
