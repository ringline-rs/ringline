//! HTTP/1.1 connection.
//!
//! Simple request-response on a single `ConnCtx`. No multiplexing — each
//! request blocks until its response is fully received.

use std::net::SocketAddr;

use bytes::BytesMut;
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
        // Serialize the request.
        let mut req = Vec::with_capacity(256);
        req.extend_from_slice(method.as_bytes());
        req.push(b' ');
        req.extend_from_slice(path.as_bytes());
        req.extend_from_slice(b" HTTP/1.1\r\n");
        req.extend_from_slice(b"host: ");
        req.extend_from_slice(self.host.as_bytes());
        req.extend_from_slice(b"\r\n");

        for (name, value) in extra_headers {
            req.extend_from_slice(name.as_bytes());
            req.extend_from_slice(b": ");
            req.extend_from_slice(value.as_bytes());
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

        // Parse the response.
        let mut status: u16 = 0;
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut headers_done = false;
        let mut body_buf = BytesMut::new();
        let mut header_consumed: usize = 0;

        // Phase 1: Read headers.
        while !headers_done {
            let n = self
                .conn
                .with_data(|data| {
                    // Look for \r\n\r\n to find end of headers.
                    if let Some(end) = find_header_end(data) {
                        let header_bytes = &data[..end];
                        if let Some(parsed) = parse_response_headers(header_bytes) {
                            status = parsed.status;
                            headers = parsed.headers;
                            content_length = parsed.content_length;
                            chunked = parsed.chunked;
                            headers_done = true;
                            header_consumed = end + 4; // +4 for \r\n\r\n

                            // There may be body bytes after the headers.
                            let remaining = &data[header_consumed..];
                            if !remaining.is_empty() {
                                body_buf.extend_from_slice(remaining);
                            }
                        }
                        ParseResult::Consumed(data.len())
                    } else {
                        ParseResult::Consumed(0) // need more data
                    }
                })
                .await;

            if n == 0 {
                return Err(HttpError::ConnectionClosed);
            }
        }

        // Phase 2: Read body.
        if let Some(cl) = content_length {
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
        } else if chunked {
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
                        let mut got_data = false;
                        let n = self
                            .conn
                            .with_data(|data| {
                                leftover.extend_from_slice(data);
                                got_data = true;
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

        Ok(Response::new(status, headers, body_buf.freeze()))
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

            headers.push((name, value));
        }
    }

    Some(ParsedHeaders {
        status,
        headers,
        content_length,
        chunked,
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
        // Last chunk.
        return ChunkResult::Complete {
            data: &[],
            consumed: crlf + 2, // size line + \r\n
            is_last: true,
        };
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
    fn decode_chunk_last() {
        let data = b"0\r\n";
        match decode_chunk(data) {
            ChunkResult::Complete { is_last, .. } => {
                assert!(is_last);
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
}
