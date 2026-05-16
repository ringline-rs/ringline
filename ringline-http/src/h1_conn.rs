//! HTTP/1.1 connection.
//!
//! Simple request-response on a single `ConnCtx`. No multiplexing — each
//! request blocks until its response is fully received.

use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use ringline::{ConnCtx, ParseResult};

use crate::error::HttpError;
use crate::response::Response;

/// Default cap on the response header section size (status line + all
/// header fields up to the blank line). 64 KiB is generous for real-world
/// servers and bounds the worst case while a peer dribbles bytes in.
pub const DEFAULT_MAX_HEADER_SECTION: usize = 64 * 1024;

/// Default cap on a single chunk's data length. Bounds an attacker that
/// claims a `Transfer-Encoding: chunked` body with chunk size `ffffffff`
/// or larger. 16 MiB matches typical streaming buffer sizes.
pub const DEFAULT_MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Default cap on the chunked-encoding trailer section (everything between
/// the terminating `0\r\n` and the final empty line).
pub const DEFAULT_MAX_TRAILER_SECTION: usize = 4 * 1024;

/// Default cap on the total response body length, applied to both
/// `Content-Length` bodies and the cumulative size of chunked bodies.
pub const DEFAULT_MAX_BODY_SIZE: usize = 16 * 1024 * 1024;

/// An HTTP/1.1 connection wrapping a `ConnCtx`.
pub struct H1Conn {
    conn: ConnCtx,
    host: String,
    /// Whether the peer asked us to close after this response (`Connection: close`
    /// or we're talking to an HTTP/1.0 server without `keep-alive`).
    peer_will_close: bool,
    max_header_section: usize,
    max_chunk_size: usize,
    max_trailer_section: usize,
    max_body_size: usize,
    max_decompressed_size: usize,
}

impl H1Conn {
    fn new(conn: ConnCtx, host: &str) -> Self {
        Self {
            conn,
            host: host.to_string(),
            peer_will_close: false,
            max_header_section: DEFAULT_MAX_HEADER_SECTION,
            max_chunk_size: DEFAULT_MAX_CHUNK_SIZE,
            max_trailer_section: DEFAULT_MAX_TRAILER_SECTION,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            max_decompressed_size: crate::compress::DEFAULT_MAX_DECOMPRESSED_SIZE,
        }
    }

    /// Connect to an HTTP/1.1 server over TLS.
    pub async fn connect_tls(addr: SocketAddr, host: &str) -> Result<Self, HttpError> {
        let conn = ringline::connect_tls(addr, host)?.await?;
        Ok(Self::new(conn, host))
    }

    /// Connect to an HTTP/1.1 server over plaintext TCP.
    pub async fn connect_plain(addr: SocketAddr, host: &str) -> Result<Self, HttpError> {
        let conn = ringline::connect(addr)?.await?;
        Ok(Self::new(conn, host))
    }

    /// Override the cap on the response header section size (bytes from
    /// the status line up to the blank line). Default
    /// [`DEFAULT_MAX_HEADER_SECTION`].
    pub fn set_max_header_section(&mut self, n: usize) {
        self.max_header_section = n;
    }

    /// Override the cap on a single chunked-encoding chunk's payload size.
    /// Default [`DEFAULT_MAX_CHUNK_SIZE`].
    pub fn set_max_chunk_size(&mut self, n: usize) {
        self.max_chunk_size = n;
    }

    /// Override the cap on the chunked trailer section. Default
    /// [`DEFAULT_MAX_TRAILER_SECTION`].
    pub fn set_max_trailer_section(&mut self, n: usize) {
        self.max_trailer_section = n;
    }

    /// Override the cap on the total response body length (Content-Length
    /// or accumulated chunked size). Default [`DEFAULT_MAX_BODY_SIZE`].
    pub fn set_max_body_size(&mut self, n: usize) {
        self.max_body_size = n;
    }

    /// Override the cap on a decompressed response body. Default 64 MiB —
    /// defends against decompression bombs where a small compressed input
    /// expands to many GiB of zeros.
    pub fn set_max_decompressed_size(&mut self, n: usize) {
        self.max_decompressed_size = n;
    }

    /// Whether the peer signalled it will close after the current response
    /// (HTTP/1.0 default, or `Connection: close` on the response). When
    /// `true`, the application should drop this `H1Conn` and reconnect for
    /// the next request rather than risk a smuggling-class desync.
    pub fn peer_will_close(&self) -> bool {
        self.peer_will_close
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

        // RFC 9112 §6.3: responses to HEAD and any 1xx/204/304 status are
        // body-less regardless of headers present. Honour this before
        // looking at content-length/chunked so a misbehaving server can't
        // dump a body into the next response's framing.
        let no_body = response_has_no_body(method, hdr.status);

        if no_body {
            // Drop any framing-relevant headers — body is empty.
        } else if let Some(cl) = hdr.content_length {
            if cl > self.max_body_size {
                return Err(HttpError::MaxSizeExceeded(format!(
                    "Content-Length {cl} exceeds {} body cap",
                    self.max_body_size
                )));
            }
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
                    return Err(HttpError::ConnectionClosed);
                }
            }
            body_buf.truncate(cl);
        } else if hdr.chunked {
            // Chunked transfer encoding.
            let mut decoded = BytesMut::new();
            let mut leftover = body_buf.to_vec();
            body_buf.clear();
            let max_body = self.max_body_size;
            let max_chunk = self.max_chunk_size;
            let max_trailer = self.max_trailer_section;

            loop {
                match decode_chunk(&leftover, max_chunk, max_trailer) {
                    ChunkResult::Complete {
                        data,
                        consumed,
                        is_last,
                    } => {
                        if decoded.len() + data.len() > max_body {
                            return Err(HttpError::MaxSizeExceeded(format!(
                                "chunked body exceeds {max_body} byte cap"
                            )));
                        }
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
                            return Err(HttpError::ConnectionClosed);
                        }
                    }
                    ChunkResult::Invalid(reason) => {
                        return Err(HttpError::InvalidMessage(format!(
                            "chunked decoding: {reason}"
                        )));
                    }
                }
            }

            body_buf = decoded;
        } else if hdr.version == HttpVersion::Http10 || self.peer_will_close {
            // RFC 9112 §6.3 case 7: HTTP/1.0 (or `Connection: close`)
            // without CL or chunked = read until the connection closes.
            // Apply the body cap defensively in case the peer never closes.
            let max_body = self.max_body_size;
            loop {
                if body_buf.len() > max_body {
                    return Err(HttpError::MaxSizeExceeded(format!(
                        "close-delimited body exceeds {max_body} byte cap"
                    )));
                }
                let n = self
                    .conn
                    .with_data(|data| {
                        body_buf.extend_from_slice(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    break; // clean close = body complete
                }
            }
        }
        // else: no framing info, no close signal — empty body.

        // Decompress body if Content-Encoding is set.
        #[cfg(any(feature = "gzip", feature = "zstd", feature = "brotli"))]
        if let Some(ref encoding) = hdr.content_encoding {
            let decompressed =
                crate::compress::decompress(encoding, &body_buf, self.max_decompressed_size)?;
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

        let max_chunk = self.max_chunk_size;
        let max_trailer = self.max_trailer_section;
        let no_body = response_has_no_body(method, hdr.status);

        let state = if no_body {
            H1StreamState::Done
        } else if let Some(cl) = hdr.content_length {
            if cl > self.max_body_size {
                return Err(HttpError::MaxSizeExceeded(format!(
                    "Content-Length {cl} exceeds {} body cap",
                    self.max_body_size
                )));
            }
            H1StreamState::ContentLength {
                remaining: cl.saturating_sub(hdr.body_leftover.len()),
                leftover: hdr.body_leftover,
            }
        } else if hdr.chunked {
            H1StreamState::Chunked {
                leftover: hdr.body_leftover.to_vec(),
                max_chunk,
                max_trailer,
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
        // Validate caller-supplied request components before serializing —
        // a `\r\n` slipped into a header value or path would otherwise let
        // a caller (often via untrusted input) inject additional request
        // lines or headers into what the server reads.
        validate_method(method)?;
        validate_request_target(path)?;
        validate_token(&self.host)
            .map_err(|_| HttpError::InvalidMessage("host contains forbidden bytes".into()))?;
        for (name, value) in extra_headers {
            validate_field_name(name)?;
            validate_field_value(value)?;
        }

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

        // Parse response headers. Cap the header section size to bound a
        // peer that dribbles bytes forever.
        let max_section = self.max_header_section;
        let mut bytes_seen = 0usize;
        let mut parse_error: Option<HttpError> = None;
        let mut status: u16 = 0;
        let mut version: HttpVersion = HttpVersion::Http10;
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut content_encoding: Option<String> = None;
        let mut connection_close = false;
        let mut headers_done = false;
        let mut body_leftover = BytesMut::new();

        while !headers_done {
            let n = self
                .conn
                .with_data(|data| {
                    bytes_seen = data.len();
                    if bytes_seen > max_section {
                        parse_error = Some(HttpError::MaxSizeExceeded(format!(
                            "response header section exceeds {max_section} bytes"
                        )));
                        return ParseResult::Consumed(data.len());
                    }
                    if let Some(end) = find_header_end(data) {
                        let header_bytes = &data[..end];
                        match parse_response_headers(header_bytes) {
                            Ok(parsed) => {
                                status = parsed.status;
                                version = parsed.version;
                                headers = parsed.headers;
                                content_length = parsed.content_length;
                                chunked = parsed.chunked;
                                content_encoding = parsed.content_encoding;
                                connection_close = parsed.connection_close;
                                headers_done = true;
                                let header_consumed = end + 4;

                                let remaining = &data[header_consumed..];
                                if !remaining.is_empty() {
                                    body_leftover.extend_from_slice(remaining);
                                }
                            }
                            Err(e) => parse_error = Some(e),
                        }
                        ParseResult::Consumed(data.len())
                    } else {
                        ParseResult::Consumed(0)
                    }
                })
                .await;

            if let Some(e) = parse_error.take() {
                return Err(e);
            }
            if n == 0 {
                return Err(HttpError::ConnectionClosed);
            }
        }

        // RFC 9112 §9.3: HTTP/1.0 defaults to non-persistent connection
        // unless `Connection: keep-alive`; HTTP/1.1 defaults to persistent
        // unless `Connection: close`. Either way, this connection will
        // close after this response.
        self.peer_will_close = match version {
            HttpVersion::Http10 => !headers.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("connection") && contains_token(v, "keep-alive")
            }),
            HttpVersion::Http11 => connection_close,
        };

        Ok(H1HeaderResult {
            status,
            version,
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
    #[allow(dead_code)] // currently used only for peer_will_close decision
    version: HttpVersion,
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

/// HTTP version line decoded from the status line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpVersion {
    Http10,
    Http11,
}

/// Internal state for H1 streaming body reads.
enum H1StreamState {
    ContentLength {
        remaining: usize,
        leftover: BytesMut,
    },
    Chunked {
        leftover: Vec<u8>,
        max_chunk: usize,
        max_trailer: usize,
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
                H1StreamState::Chunked {
                    leftover,
                    max_chunk,
                    max_trailer,
                } => {
                    match decode_chunk(leftover, *max_chunk, *max_trailer) {
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
                        ChunkResult::Invalid(reason) => {
                            self.state = H1StreamState::Done;
                            return Err(HttpError::InvalidMessage(format!(
                                "chunked decoding: {reason}"
                            )));
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
    version: HttpVersion,
    headers: Vec<(String, String)>,
    content_length: Option<usize>,
    chunked: bool,
    content_encoding: Option<String>,
    connection_close: bool,
}

/// Parse HTTP/1.1 response headers (everything before `\r\n\r\n`).
///
/// Returns:
///  - `Err(HttpError::Parse)` for syntactic problems (malformed status
///    line, missing `:` in a header).
///  - `Err(HttpError::InvalidMessage)` for semantic violations relevant to
///    request smuggling defenses (TE+CL together, multiple conflicting CL,
///    unsupported transfer codings, CR/LF inside a header value).
fn parse_response_headers(data: &[u8]) -> Result<ParsedHeaders, HttpError> {
    let text = std::str::from_utf8(data).map_err(|_| HttpError::Parse)?;
    let mut lines = text.split("\r\n");

    // Status line: HTTP/1.X <status> [reason]
    let status_line = lines.next().ok_or(HttpError::Parse)?;
    let mut parts = status_line.splitn(3, ' ');
    let version_str = parts.next().ok_or(HttpError::Parse)?;
    let version = match version_str {
        "HTTP/1.0" => HttpVersion::Http10,
        "HTTP/1.1" => HttpVersion::Http11,
        _ => return Err(HttpError::Parse),
    };
    let status_str = parts.next().ok_or(HttpError::Parse)?;
    if status_str.len() != 3 || !status_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(HttpError::Parse);
    }
    let status: u16 = status_str.parse().map_err(|_| HttpError::Parse)?;

    let mut headers = Vec::new();
    let mut content_lengths: Vec<usize> = Vec::new();
    let mut transfer_encodings: Vec<String> = Vec::new();
    let mut content_encoding = None;
    let mut connection_close = false;

    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::Parse)?;
        let name = name.trim().to_string();
        let value = value.trim().to_string();

        // RFC 9110 §5.5: field-value MUST NOT contain CR, LF, or NUL.
        // (Our line-split already handled the well-formed CRLF case; the
        // check below catches a bare LF or NUL embedded mid-line, which
        // an attacker can use to inject additional headers.)
        if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(HttpError::InvalidMessage(format!(
                "header `{name}` contains CR/LF/NUL"
            )));
        }
        // RFC 9110 §5.1: field-name is a token (no whitespace, no
        // separators); enforce non-empty and printable-ASCII.
        if name.is_empty() || name.bytes().any(|b| !is_token_char(b)) {
            return Err(HttpError::Parse);
        }

        let name_lc = name.to_ascii_lowercase();
        match name_lc.as_str() {
            "content-length" => {
                // RFC 9112 §6.1: a CL value may be a list of identical
                // integers; multiple CL headers must agree. Any deviation
                // is grounds to treat the message as invalid (smuggling
                // defense).
                for piece in value.split(',') {
                    let n: usize = piece.trim().parse().map_err(|_| {
                        HttpError::InvalidMessage("malformed Content-Length".into())
                    })?;
                    content_lengths.push(n);
                }
            }
            "transfer-encoding" => {
                for piece in value.split(',') {
                    transfer_encodings.push(piece.trim().to_ascii_lowercase());
                }
            }
            "content-encoding" => content_encoding = Some(value.clone()),
            "connection" if contains_token(&value, "close") => {
                connection_close = true;
            }
            _ => {}
        }

        headers.push((name, value));
    }

    // RFC 9112 §6.1: each Transfer-Encoding coding must be one the
    // recipient supports, and if any TE is present then `chunked` MUST be
    // the final coding (otherwise the response framing is unknown).
    let chunked = if transfer_encodings.is_empty() {
        false
    } else {
        // Only `chunked` is supported; reject anything else as the final
        // (or only) coding. This conservatively rejects TE: gzip on a
        // response since we can't safely frame it.
        if transfer_encodings.iter().any(|c| c != "chunked") {
            return Err(HttpError::InvalidMessage(format!(
                "unsupported Transfer-Encoding: {transfer_encodings:?}"
            )));
        }
        if transfer_encodings.last().map(String::as_str) != Some("chunked") {
            return Err(HttpError::InvalidMessage(
                "Transfer-Encoding: chunked must be the final coding".into(),
            ));
        }
        true
    };

    // RFC 9112 §6.1: TE + CL together is request smuggling territory —
    // reject the response.
    if chunked && !content_lengths.is_empty() {
        return Err(HttpError::InvalidMessage(
            "Transfer-Encoding and Content-Length both present".into(),
        ));
    }

    // All Content-Length values must agree.
    let content_length = match content_lengths.as_slice() {
        [] => None,
        values => {
            let first = values[0];
            if values.iter().any(|&v| v != first) {
                return Err(HttpError::InvalidMessage(
                    "conflicting Content-Length values".into(),
                ));
            }
            Some(first)
        }
    };

    Ok(ParsedHeaders {
        status,
        version,
        headers,
        content_length,
        chunked,
        content_encoding,
        connection_close,
    })
}

/// `true` if the comma-separated `field` contains `token` as one of its
/// trimmed, case-insensitive elements.
fn contains_token(field: &str, token: &str) -> bool {
    field
        .split(',')
        .any(|p| p.trim().eq_ignore_ascii_case(token))
}

/// RFC 9110 §5.6.2 token character set: visible ASCII excluding separators.
fn is_token_char(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' |
        b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

fn validate_method(method: &str) -> Result<(), HttpError> {
    if method.is_empty() || method.bytes().any(|b| !is_token_char(b)) {
        return Err(HttpError::InvalidMessage(format!(
            "invalid method `{method}`"
        )));
    }
    Ok(())
}

fn validate_request_target(target: &str) -> Result<(), HttpError> {
    if target.is_empty() {
        return Err(HttpError::InvalidMessage("empty request target".into()));
    }
    // Per RFC 9112 §3.2: request-target is one of origin-form, absolute-form,
    // authority-form, or asterisk-form — all subsets of visible ASCII with
    // no control chars or whitespace. Reject anything that could break the
    // request line.
    for b in target.bytes() {
        if b <= 0x20 || b == 0x7f || b == b'\r' || b == b'\n' {
            return Err(HttpError::InvalidMessage(
                "request target contains control or whitespace bytes".into(),
            ));
        }
    }
    Ok(())
}

fn validate_field_name(name: &str) -> Result<(), HttpError> {
    if name.is_empty() || name.bytes().any(|b| !is_token_char(b)) {
        return Err(HttpError::InvalidMessage(format!(
            "invalid header name `{name}`"
        )));
    }
    Ok(())
}

fn validate_field_value(value: &str) -> Result<(), HttpError> {
    // RFC 9110 §5.5: field-value = *( field-content / obs-fold ) where
    // field-content excludes CR, LF, NUL. obs-fold (deprecated) starts
    // with CRLF + WSP — reject either form.
    for b in value.bytes() {
        if b == b'\r' || b == b'\n' || b == 0 {
            return Err(HttpError::InvalidMessage(
                "header value contains CR/LF/NUL".into(),
            ));
        }
    }
    Ok(())
}

/// RFC 9112 §6.3: HEAD responses and 1xx/204/304 responses always have
/// no body, regardless of any Content-Length or Transfer-Encoding the
/// server sent.
fn response_has_no_body(method: &str, status: u16) -> bool {
    method.eq_ignore_ascii_case("HEAD") || matches!(status, 100..=199 | 204 | 304)
}

fn validate_token(s: &str) -> Result<(), ()> {
    if s.is_empty() || s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(());
    }
    Ok(())
}

enum ChunkResult<'a> {
    Complete {
        data: &'a [u8],
        consumed: usize,
        is_last: bool,
    },
    NeedMore,
    /// Malformed chunked encoding — caller must fail the response (not
    /// loop reading more data, which is an infinite-read DoS).
    Invalid(&'static str),
}

/// Decode one chunk from chunked transfer encoding. `max_chunk_size`
/// bounds the size of a single chunk's payload; `max_trailer_section`
/// bounds the bytes between the terminating `0\r\n` and the final empty
/// line.
fn decode_chunk(data: &[u8], max_chunk_size: usize, max_trailer_section: usize) -> ChunkResult<'_> {
    // Find the chunk size line: <hex>\r\n
    let crlf = match find_crlf(data) {
        Some(pos) => pos,
        None => return ChunkResult::NeedMore,
    };

    let size_str = match std::str::from_utf8(&data[..crlf]) {
        Ok(s) => s.trim(),
        // Non-UTF-8 in the chunk header line is malformed framing.
        Err(_) => return ChunkResult::Invalid("non-UTF-8 chunk header"),
    };

    // Strip chunk extensions (;key=value).
    let size_hex = size_str.split(';').next().unwrap_or("").trim();
    if size_hex.is_empty() || !size_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return ChunkResult::Invalid("malformed chunk size");
    }
    let size = match usize::from_str_radix(size_hex, 16) {
        Ok(s) => s,
        Err(_) => return ChunkResult::Invalid("chunk size overflows usize"),
    };
    if size > max_chunk_size {
        return ChunkResult::Invalid("chunk size exceeds configured cap");
    }

    if size == 0 {
        // Last chunk: 0\r\n followed by optional trailer headers and
        // a final \r\n. Scan past any trailers to find the empty line.
        let after_zero = crlf + 2;
        let mut pos = after_zero;
        loop {
            if pos - after_zero > max_trailer_section {
                return ChunkResult::Invalid("trailer section exceeds cap");
            }
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

    // Validate the trailing CRLF actually is one — a server claiming
    // `5\r\nhello??` (no CRLF after `hello`) must not silently re-frame.
    if data[chunk_end] != b'\r' || data[chunk_end + 1] != b'\n' {
        return ChunkResult::Invalid("missing CRLF after chunk data");
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
        match decode_chunk(data, usize::MAX, usize::MAX) {
            ChunkResult::Complete {
                data,
                consumed,
                is_last,
            } => {
                assert_eq!(data, b"hello");
                assert_eq!(consumed, 10);
                assert!(!is_last);
            }
            ChunkResult::NeedMore | ChunkResult::Invalid(_) => panic!("expected Complete"),
        }
    }

    #[test]
    fn decode_chunk_last_with_empty_trailers() {
        // Terminal chunk: "0\r\n\r\n" (no trailers, just the empty line).
        let data = b"0\r\n\r\n";
        match decode_chunk(data, usize::MAX, usize::MAX) {
            ChunkResult::Complete {
                is_last, consumed, ..
            } => {
                assert!(is_last);
                assert_eq!(consumed, 5, "should consume 0\\r\\n\\r\\n");
            }
            ChunkResult::NeedMore | ChunkResult::Invalid(_) => panic!("expected Complete"),
        }
    }

    #[test]
    fn decode_chunk_last_needs_trailing_crlf() {
        // Just "0\r\n" without the trailing \r\n — need more data.
        let data = b"0\r\n";
        match decode_chunk(data, usize::MAX, usize::MAX) {
            ChunkResult::NeedMore => {}
            ChunkResult::Complete { .. } | ChunkResult::Invalid(_) => panic!("expected NeedMore"),
        }
    }

    #[test]
    fn decode_chunk_last_with_trailers() {
        // Terminal chunk with trailer headers.
        let data = b"0\r\nTrailer: value\r\n\r\n";
        match decode_chunk(data, usize::MAX, usize::MAX) {
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
            ChunkResult::NeedMore | ChunkResult::Invalid(_) => panic!("expected Complete"),
        }
    }

    #[test]
    fn decode_chunk_last_does_not_consume_next_response() {
        // Terminal chunk followed by the start of the next response.
        let data = b"0\r\n\r\nHTTP/1.1 200 OK\r\n";
        match decode_chunk(data, usize::MAX, usize::MAX) {
            ChunkResult::Complete {
                is_last, consumed, ..
            } => {
                assert!(is_last);
                assert_eq!(consumed, 5, "should only consume 0\\r\\n\\r\\n");
                assert_eq!(&data[consumed..], b"HTTP/1.1 200 OK\r\n");
            }
            ChunkResult::NeedMore | ChunkResult::Invalid(_) => panic!("expected Complete"),
        }
    }

    #[test]
    fn decode_chunk_need_more() {
        let data = b"5\r\nhel";
        match decode_chunk(data, usize::MAX, usize::MAX) {
            ChunkResult::NeedMore => {}
            ChunkResult::Complete { .. } | ChunkResult::Invalid(_) => panic!("expected NeedMore"),
        }
    }

    #[test]
    fn parse_malformed_status_line_returns_err() {
        // Missing status code.
        assert!(parse_response_headers(b"HTTP/1.1 \r\n").is_err());
        // Completely garbled.
        assert!(parse_response_headers(b"NOT-HTTP\r\n").is_err());
        // Empty.
        assert!(parse_response_headers(b"").is_err());
        // Just the version with no space.
        assert!(parse_response_headers(b"HTTP/1.1\r\n").is_err());
        // Wrong-version status line (audit fix H9).
        assert!(parse_response_headers(b"HTTP/2.0 200 OK\r\n").is_err());
        // Non-digit status code (audit fix).
        assert!(parse_response_headers(b"HTTP/1.1 20X OK\r\n").is_err());
    }

    // -- Audit tests: RFC 9112 conformance + robustness --

    #[test]
    fn parse_rejects_te_and_cl_together() {
        // Request smuggling defense (H1).
        let data = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n";
        let err = parse_response_headers(data).err().unwrap();
        assert!(matches!(err, HttpError::InvalidMessage(_)));
    }

    #[test]
    fn parse_rejects_multiple_conflicting_content_length() {
        // H3: multiple CL with different values = smuggling vector.
        let data = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ncontent-length: 7\r\n";
        let err = parse_response_headers(data).err().unwrap();
        assert!(matches!(err, HttpError::InvalidMessage(_)));
    }

    #[test]
    fn parse_accepts_multiple_identical_content_length() {
        // RFC 9112 §6.1: identical values are OK to collapse.
        let data = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ncontent-length: 5\r\n";
        let parsed = parse_response_headers(data).unwrap();
        assert_eq!(parsed.content_length, Some(5));
    }

    #[test]
    fn parse_rejects_unsupported_transfer_encoding() {
        // H2: TE: gzip (no chunked) cannot be framed safely.
        let data = b"HTTP/1.1 200 OK\r\ntransfer-encoding: gzip\r\n";
        let err = parse_response_headers(data).err().unwrap();
        assert!(matches!(err, HttpError::InvalidMessage(_)));
    }

    #[test]
    fn parse_rejects_chunked_not_final_coding() {
        // RFC §6.1: chunked must be the last coding.
        let data = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked, gzip\r\n";
        let err = parse_response_headers(data).err().unwrap();
        assert!(matches!(err, HttpError::InvalidMessage(_)));
    }

    #[test]
    fn parse_rejects_header_value_with_embedded_lf() {
        // H4: bare LF in a header value would let a peer inject another header.
        let data = b"HTTP/1.1 200 OK\r\nx-evil: value\nset-cookie: pwned\r\n";
        let err = parse_response_headers(data).err().unwrap();
        assert!(matches!(err, HttpError::InvalidMessage(_)));
    }

    #[test]
    fn parse_honors_connection_close() {
        let data = b"HTTP/1.1 200 OK\r\nconnection: close\r\n";
        let parsed = parse_response_headers(data).unwrap();
        assert!(parsed.connection_close);
    }

    #[test]
    fn parse_http10_version() {
        let data = b"HTTP/1.0 200 OK\r\n";
        let parsed = parse_response_headers(data).unwrap();
        assert_eq!(parsed.version, HttpVersion::Http10);
    }

    #[test]
    fn decode_chunk_rejects_malformed_size() {
        // H10: previously returned NeedMore → infinite loop.
        let data = b"xyz\r\n";
        assert!(matches!(
            decode_chunk(data, usize::MAX, usize::MAX),
            ChunkResult::Invalid(_)
        ));
    }

    #[test]
    fn decode_chunk_rejects_oversize() {
        // H11.
        let data = b"1000\r\n"; // 0x1000 = 4096 bytes
        assert!(matches!(
            decode_chunk(data, 100, usize::MAX),
            ChunkResult::Invalid(_)
        ));
    }

    #[test]
    fn decode_chunk_rejects_missing_trailing_crlf() {
        // Body bytes present but trailing CRLF is wrong.
        let data = b"5\r\nhello\x00\x00";
        assert!(matches!(
            decode_chunk(data, usize::MAX, usize::MAX),
            ChunkResult::Invalid(_)
        ));
    }

    #[test]
    fn decode_chunk_rejects_oversize_trailers() {
        // H14: 0\r\n followed by a huge trailer line.
        let trailer: Vec<u8> = b"0\r\n"
            .iter()
            .copied()
            .chain(std::iter::repeat_n(b'a', 200))
            .chain(b"\r\n\r\n".iter().copied())
            .collect();
        assert!(matches!(
            decode_chunk(&trailer, usize::MAX, 100),
            ChunkResult::Invalid(_)
        ));
    }

    #[test]
    fn validate_field_value_rejects_crlf() {
        assert!(validate_field_value("value\r\nx: y").is_err());
        assert!(validate_field_value("value\nx: y").is_err());
        assert!(validate_field_value("normal").is_ok());
    }

    #[test]
    fn validate_request_target_rejects_whitespace() {
        assert!(validate_request_target("/path with space").is_err());
        assert!(validate_request_target("/path\r\nGET").is_err());
        assert!(validate_request_target("/normal").is_ok());
    }

    #[test]
    fn response_has_no_body_for_head_and_status_codes() {
        assert!(response_has_no_body("HEAD", 200));
        assert!(response_has_no_body("GET", 100));
        assert!(response_has_no_body("GET", 204));
        assert!(response_has_no_body("GET", 304));
        assert!(!response_has_no_body("GET", 200));
        assert!(!response_has_no_body("POST", 201));
    }
}
