//! HTTP/1.1 connection.
//!
//! Simple request-response on a single `ConnCtx`. No multiplexing — each
//! request blocks until its response is fully received.

use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use ringline::{ConnCtx, ParseResult};

use crate::error::HttpError;
use crate::response::Response;

/// An HTTP/1.1 connection wrapping a `ConnCtx`.
pub struct H1Conn {
    conn: ConnCtx,
    host: String,
}

impl H1Conn {
    /// Connect to an HTTP/1.1 server over TLS.
    pub async fn connect_tls(addr: SocketAddr, host: &str) -> Result<Self, HttpError> {
        let conn = ringline::connect_tls(addr, host)?.await?;
        Ok(Self {
            conn,
            host: host.to_string(),
        })
    }

    /// Connect to an HTTP/1.1 server over plaintext TCP.
    pub async fn connect_plain(addr: SocketAddr, host: &str) -> Result<Self, HttpError> {
        let conn = ringline::connect(addr)?.await?;
        Ok(Self {
            conn,
            host: host.to_string(),
        })
    }

    /// Returns the underlying connection context.
    pub fn conn(&self) -> ConnCtx {
        self.conn
    }

    /// Returns the host name.
    pub fn close(&self) {
        self.conn.close();
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// Send an HTTP/1.1 request and receive the response.
    pub async fn send_request(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response, HttpError> {
        let hdr = self
            .send_and_parse_headers(method, path, extra_headers, body)
            .await?;

        let mut body_buf = hdr.body_leftover;

        // Phase 2: Read body.
        if let Some(cl) = hdr.content_length {
            // Content-Length body.
            while body_buf.len() < cl {
                let target_len = cl;
                let n = self
                    .conn
                    .with_data(|data| {
                        body_buf.extend_from_slice(data);
                        if body_buf.len() >= target_len {
                            ParseResult::Consumed(data.len())
                        } else {
                            // Consume what we got, need more.
                            ParseResult::Consumed(data.len())
                        }
                    })
                    .await;

                if n == 0 {
                    break;
                }
            }
            body_buf.truncate(cl);
        } else if hdr.chunked {
            // Chunked transfer encoding.
            let mut decoded = BytesMut::new();
            let mut leftover = body_buf.to_vec();
            body_buf.clear();

            loop {
                match decode_chunk(&leftover) {
                    ChunkResult::Complete {
                        data,
                        consumed,
                        is_last,
                    } => {
                        decoded.extend_from_slice(data);
                        leftover = leftover[consumed..].to_vec();
                        if is_last {
                            break;
                        }
                    }
                    ChunkResult::NeedMore => {
                        // Read more data.
                        let n = self
                            .conn
                            .with_data(|data| {
                                leftover.extend_from_slice(data);
                                ParseResult::Consumed(data.len())
                            })
                            .await;

                        if n == 0 {
                            break;
                        }
                    }
                }
            }

            body_buf = decoded;
        }
        // else: no body (e.g. HEAD response, 204, 304)

        // Decompress body if Content-Encoding is set.
        #[cfg(any(feature = "gzip", feature = "zstd", feature = "brotli"))]
        if let Some(ref encoding) = hdr.content_encoding {
            let decompressed = crate::compress::decompress(encoding, &body_buf)?;
            return Ok(Response::new(
                hdr.status,
                hdr.headers,
                bytes::Bytes::from(decompressed),
            ));
        }

        Ok(Response::new(hdr.status, hdr.headers, body_buf.freeze()))
    }

    /// Send a request and return a streaming response after headers arrive.
    ///
    /// The caller must drain the body via [`H1StreamingResponse::next_chunk()`]
    /// before issuing further requests on this connection.
    pub async fn send_request_streaming(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<H1StreamingResponse<'_>, HttpError> {
        let hdr = self
            .send_and_parse_headers(method, path, extra_headers, body)
            .await?;

        let state = if let Some(cl) = hdr.content_length {
            H1StreamState::ContentLength {
                remaining: cl.saturating_sub(hdr.body_leftover.len()),
                leftover: hdr.body_leftover,
            }
        } else if hdr.chunked {
            H1StreamState::Chunked {
                leftover: hdr.body_leftover.to_vec(),
            }
        } else {
            H1StreamState::Done
        };

        Ok(H1StreamingResponse {
            conn: &mut self.conn,
            status: hdr.status,
            headers: hdr.headers,
            state,
        })
    }

    /// Serialize the request, send it, and parse response headers.
    async fn send_and_parse_headers(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<H1HeaderResult, HttpError> {
        // Serialize the request.
        let mut req = Vec::with_capacity(256);
        req.extend_from_slice(method.as_bytes());
        req.push(b' ');
        req.extend_from_slice(path.as_bytes());
        req.extend_from_slice(b" HTTP/1.1\r\n");
        req.extend_from_slice(b"host: ");
        req.extend_from_slice(self.host.as_bytes());
        req.extend_from_slice(b"\r\n");

        let has_accept_encoding = extra_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"));

        for (name, value) in extra_headers {
            req.extend_from_slice(name.as_bytes());
            req.extend_from_slice(b": ");
            req.extend_from_slice(value.as_bytes());
            req.extend_from_slice(b"\r\n");
        }

        // Auto-inject Accept-Encoding when compression features are enabled
        // and the caller has not already set one.
        if !has_accept_encoding && let Some(ae) = crate::compress::accept_encoding_value() {
            req.extend_from_slice(b"accept-encoding: ");
            req.extend_from_slice(ae.as_bytes());
            req.extend_from_slice(b"\r\n");
        }

        if let Some(b) = body
            && !b.is_empty()
        {
            req.extend_from_slice(b"content-length: ");
            req.extend_from_slice(b.len().to_string().as_bytes());
            req.extend_from_slice(b"\r\n");
        }

        req.extend_from_slice(b"\r\n");

        if let Some(b) = body
            && !b.is_empty()
        {
            req.extend_from_slice(b);
        }

        self.conn.send_nowait(&req)?;

        // Parse response headers.
        let mut status: u16 = 0;
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut content_encoding: Option<String> = None;
        let mut headers_done = false;
        let mut body_leftover = BytesMut::new();
        let mut parse_error = false;

        while !headers_done {
            let n = self
                .conn
                .with_data(|data| {
                    if let Some(end) = find_header_end(data) {
                        let header_bytes = &data[..end];
                        if let Some(parsed) = parse_response_headers(header_bytes) {
                            status = parsed.status;
                            headers = parsed.headers;
                            content_length = parsed.content_length;
                            chunked = parsed.chunked;
                            content_encoding = parsed.content_encoding;
                            headers_done = true;
                            let header_consumed = end + 4;

                            let remaining = &data[header_consumed..];
                            if !remaining.is_empty() {
                                body_leftover.extend_from_slice(remaining);
                            }
                        } else {
                            parse_error = true;
                        }
                        ParseResult::Consumed(data.len())
                    } else {
                        ParseResult::Consumed(0)
                    }
                })
                .await;

            if n == 0 {
                return Err(HttpError::ConnectionClosed);
            }
            if parse_error {
                return Err(HttpError::Parse);
            }
        }

        Ok(H1HeaderResult {
            status,
            headers,
            content_length,
            chunked,
            content_encoding,
            body_leftover,
        })
    }
}

/// Result of parsing HTTP/1.1 response headers.
struct H1HeaderResult {
    status: u16,
    headers: Vec<(String, String)>,
    content_length: Option<usize>,
    chunked: bool,
    #[cfg_attr(
        not(any(feature = "gzip", feature = "zstd", feature = "brotli")),
        allow(dead_code)
    )]
    content_encoding: Option<String>,
    body_leftover: BytesMut,
}

/// Internal state for H1 streaming body reads.
enum H1StreamState {
    ContentLength {
        remaining: usize,
        leftover: BytesMut,
    },
    Chunked {
        leftover: Vec<u8>,
    },
    Done,
}

/// Streaming HTTP/1.1 response. Borrows the connection exclusively.
///
/// Body chunks are yielded one at a time via [`next_chunk()`](Self::next_chunk).
pub struct H1StreamingResponse<'a> {
    conn: &'a mut ConnCtx,
    status: u16,
    headers: Vec<(String, String)>,
    state: H1StreamState,
}

impl<'a> H1StreamingResponse<'a> {
    /// HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Response headers as (name, value) pairs.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Get the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Yield the next body chunk, or `None` when the body is complete.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        loop {
            match &mut self.state {
                H1StreamState::ContentLength {
                    remaining,
                    leftover,
                } => {
                    // Yield leftover first.
                    if !leftover.is_empty() {
                        let chunk = leftover.split().freeze();
                        *remaining = remaining.saturating_sub(chunk.len());
                        return Ok(Some(chunk));
                    }
                    if *remaining == 0 {
                        self.state = H1StreamState::Done;
                        return Ok(None);
                    }
                    // Read more from wire.
                    let rem = *remaining;
                    let mut got = BytesMut::new();
                    let n = self
                        .conn
                        .with_data(|data| {
                            let take = data.len().min(rem);
                            got.extend_from_slice(&data[..take]);
                            ParseResult::Consumed(take)
                        })
                        .await;
                    if n == 0 {
                        self.state = H1StreamState::Done;
                        return Err(HttpError::ConnectionClosed);
                    }
                    *remaining -= got.len();
                    return Ok(Some(got.freeze()));
                }
                H1StreamState::Chunked { leftover } => {
                    match decode_chunk(leftover) {
                        ChunkResult::Complete {
                            data,
                            consumed,
                            is_last,
                        } => {
                            let chunk = Bytes::copy_from_slice(data);
                            *leftover = leftover[consumed..].to_vec();
                            if is_last {
                                self.state = H1StreamState::Done;
                                if chunk.is_empty() {
                                    return Ok(None);
                                }
                                return Ok(Some(chunk));
                            }
                            return Ok(Some(chunk));
                        }
                        ChunkResult::NeedMore => {
                            // Read more data.
                            let n = self
                                .conn
                                .with_data(|data| {
                                    leftover.extend_from_slice(data);
                                    ParseResult::Consumed(data.len())
                                })
                                .await;
                            if n == 0 {
                                self.state = H1StreamState::Done;
                                return Err(HttpError::ConnectionClosed);
                            }
                            // Loop back to try decoding again.
                        }
                    }
                }
                H1StreamState::Done => return Ok(None),
            }
        }
    }
}

/// Find the position of `\r\n\r\n` in data, returns index of the first `\r`.
fn find_header_end(data: &[u8]) -> Option<usize> {
    (0..data.len().saturating_sub(3)).find(|&i| {
        data[i] == b'\r' && data[i + 1] == b'\n' && data[i + 2] == b'\r' && data[i + 3] == b'\n'
    })
}

struct ParsedHeaders {
    status: u16,
    headers: Vec<(String, String)>,
    content_length: Option<usize>,
    chunked: bool,
    content_encoding: Option<String>,
}

/// Parse HTTP/1.1 response headers (everything before `\r\n\r\n`).
fn parse_response_headers(data: &[u8]) -> Option<ParsedHeaders> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n");

    // Status line: HTTP/1.1 200 OK
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next()?;
    let status_str = parts.next()?;
    let status: u16 = status_str.parse().ok()?;

    let mut headers = Vec::new();
    let mut content_length = None;
    let mut chunked = false;
    let mut content_encoding = None;

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();

            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().ok();
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.eq_ignore_ascii_case("chunked")
            {
                chunked = true;
            }
            if name.eq_ignore_ascii_case("content-encoding") {
                content_encoding = Some(value.clone());
            }

            headers.push((name, value));
        }
    }

    Some(ParsedHeaders {
        status,
        headers,
        content_length,
        chunked,
        content_encoding,
    })
}

enum ChunkResult<'a> {
    Complete {
        data: &'a [u8],
        consumed: usize,
        is_last: bool,
    },
    NeedMore,
}

/// Decode one chunk from chunked transfer encoding.
fn decode_chunk(data: &[u8]) -> ChunkResult<'_> {
    // Find the chunk size line: <hex>\r\n
    let crlf = match find_crlf(data) {
        Some(pos) => pos,
        None => return ChunkResult::NeedMore,
    };

    let size_str = match std::str::from_utf8(&data[..crlf]) {
        Ok(s) => s.trim(),
        Err(_) => return ChunkResult::NeedMore,
    };

    // Strip chunk extensions (;key=value).
    let size_hex = size_str.split(';').next().unwrap_or("").trim();

    let size = match usize::from_str_radix(size_hex, 16) {
        Ok(s) => s,
        Err(_) => return ChunkResult::NeedMore,
    };

    if size == 0 {
        // Last chunk: 0\r\n followed by optional trailer headers and
        // a final \r\n. Scan past any trailers to find the empty line.
        let after_zero = crlf + 2;
        let mut pos = after_zero;
        loop {
            match find_crlf(&data[pos..]) {
                Some(0) => {
                    // Empty line — end of trailer section.
                    return ChunkResult::Complete {
                        data: &[],
                        consumed: pos + 2,
                        is_last: true,
                    };
                }
                Some(next_crlf) => {
                    // Trailer header line — skip it.
                    pos += next_crlf + 2;
                }
                None => return ChunkResult::NeedMore,
            }
        }
    }

    let chunk_start = crlf + 2;
    let chunk_end = chunk_start + size;
    let total = chunk_end + 2; // trailing \r\n

    if data.len() < total {
        return ChunkResult::NeedMore;
    }

    ChunkResult::Complete {
        data: &data[chunk_start..chunk_end],
        consumed: total,
        is_last: false,
    }
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    (0..data.len().saturating_sub(1)).find(|&i| data[i] == b'\r' && data[i + 1] == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_response() {
        let data = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n";
        let parsed = parse_response_headers(data).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.content_length, Some(5));
        assert!(!parsed.chunked);
        assert_eq!(parsed.headers.len(), 1);
    }

    #[test]
    fn parse_chunked_response() {
        let data = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n";
        let parsed = parse_response_headers(data).unwrap();
        assert_eq!(parsed.status, 200);
        assert!(parsed.chunked);
        assert_eq!(parsed.content_length, None);
    }

    #[test]
    fn find_header_end_found() {
        let data = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\nbody";
        assert_eq!(find_header_end(data), Some(34));
    }

    #[test]
    fn find_header_end_not_found() {
        let data = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n";
        assert_eq!(find_header_end(data), None);
    }

    #[test]
    fn decode_chunk_simple() {
        let data = b"5\r\nhello\r\n";
        match decode_chunk(data) {
            ChunkResult::Complete {
                data,
                consumed,
                is_last,
            } => {
                assert_eq!(data, b"hello");
                assert_eq!(consumed, 10);
                assert!(!is_last);
            }
            ChunkResult::NeedMore => panic!("expected Complete"),
        }
    }

    #[test]
    fn decode_chunk_last_with_empty_trailers() {
        // Terminal chunk: "0\r\n\r\n" (no trailers, just the empty line).
        let data = b"0\r\n\r\n";
        match decode_chunk(data) {
            ChunkResult::Complete {
                is_last, consumed, ..
            } => {
                assert!(is_last);
                assert_eq!(consumed, 5, "should consume 0\\r\\n\\r\\n");
            }
            ChunkResult::NeedMore => panic!("expected Complete"),
        }
    }

    #[test]
    fn decode_chunk_last_needs_trailing_crlf() {
        // Just "0\r\n" without the trailing \r\n — need more data.
        let data = b"0\r\n";
        match decode_chunk(data) {
            ChunkResult::NeedMore => {}
            ChunkResult::Complete { .. } => panic!("expected NeedMore"),
        }
    }

    #[test]
    fn decode_chunk_last_with_trailers() {
        // Terminal chunk with trailer headers.
        let data = b"0\r\nTrailer: value\r\n\r\n";
        match decode_chunk(data) {
            ChunkResult::Complete {
                is_last, consumed, ..
            } => {
                assert!(is_last);
                assert_eq!(
                    consumed,
                    data.len(),
                    "should consume entire trailer section"
                );
            }
            ChunkResult::NeedMore => panic!("expected Complete"),
        }
    }

    #[test]
    fn decode_chunk_last_does_not_consume_next_response() {
        // Terminal chunk followed by the start of the next response.
        let data = b"0\r\n\r\nHTTP/1.1 200 OK\r\n";
        match decode_chunk(data) {
            ChunkResult::Complete {
                is_last, consumed, ..
            } => {
                assert!(is_last);
                assert_eq!(consumed, 5, "should only consume 0\\r\\n\\r\\n");
                assert_eq!(&data[consumed..], b"HTTP/1.1 200 OK\r\n");
            }
            ChunkResult::NeedMore => panic!("expected Complete"),
        }
    }

    #[test]
    fn decode_chunk_need_more() {
        let data = b"5\r\nhel";
        match decode_chunk(data) {
            ChunkResult::NeedMore => {}
            ChunkResult::Complete { .. } => panic!("expected NeedMore"),
        }
    }

    #[test]
    fn parse_malformed_status_line_returns_none() {
        // Missing status code.
        assert!(parse_response_headers(b"HTTP/1.1 \r\n").is_none());
        // Completely garbled.
        assert!(parse_response_headers(b"NOT-HTTP\r\n").is_none());
        // Empty.
        assert!(parse_response_headers(b"").is_none());
        // Just the version with no space.
        assert!(parse_response_headers(b"HTTP/1.1\r\n").is_none());
    }
}
