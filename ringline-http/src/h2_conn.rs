//! Async HTTP/2 connection wrapping `H2Connection` with a pump loop.
//!
//! Uses a fire/recv pipelining pattern: fire requests synchronously, then pump
//! the connection (recv bytes → feed H2 → dispatch events → flush sends) until
//! a stream completes.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use ringline::ConnCtx;
// `ParseResult` is only used by the mio/portable `with_data` recv path; the
// io_uring path feeds h2 via `with_segments` (returns `SegConsumed`).
#[cfg(not(has_io_uring))]
use ringline::ParseResult;
use ringline_h2::hpack::HeaderField;
use ringline_h2::settings::Settings;
use ringline_h2::{H2Connection, H2Event};

use crate::error::HttpError;
use crate::response::Response;

/// State of a pending HTTP/2 stream.
struct PendingStream {
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: BytesMut,
    done: bool,
    /// Terminal error for this stream — set when validation fails or the
    /// peer violates protocol. Surfaced as the stream's completion result.
    error: Option<HttpError>,
    /// When true, DATA payloads are pushed to `chunks` instead of `body`.
    streaming: bool,
    /// Buffered chunks for streaming responses.
    chunks: VecDeque<Bytes>,
    /// Content-Encoding from response headers (for decompression).
    content_encoding: Option<String>,
    /// Running total of header bytes (name + value) accepted so far,
    /// bounded by `H2AsyncConn::max_header_section`.
    header_bytes: usize,
    /// Running total of body bytes accepted so far, bounded by
    /// `H2AsyncConn::max_body_size`.
    body_bytes: usize,
}

impl PendingStream {
    fn new() -> Self {
        Self {
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
            done: false,
            error: None,
            streaming: false,
            chunks: VecDeque::new(),
            content_encoding: None,
            header_bytes: 0,
            body_bytes: 0,
        }
    }

    /// Mark the stream terminally failed with `err`. First error wins —
    /// later errors are ignored so the caller sees the underlying cause.
    fn fail(&mut self, err: HttpError) {
        if self.error.is_none() {
            self.error = Some(err);
        }
        self.done = true;
    }

    #[cfg_attr(
        not(any(feature = "gzip", feature = "zstd", feature = "brotli")),
        allow(unused_variables)
    )]
    fn into_response(self, max_decompressed_size: usize) -> Result<Response, HttpError> {
        if let Some(err) = self.error {
            return Err(err);
        }
        // :status must have been set and validated before the stream
        // completes — into_response should only run for non-error
        // completions, and the parser sets `error` when :status is bad.
        let status = self
            .status
            .ok_or_else(|| HttpError::InvalidMessage("response missing :status".into()))?;

        // Decompress body if Content-Encoding is set.
        if let Some(ref encoding) = self.content_encoding
            && !is_identity_encoding(encoding)
        {
            #[cfg(any(feature = "gzip", feature = "zstd", feature = "brotli"))]
            {
                let decompressed =
                    crate::compress::decompress(encoding, &self.body, max_decompressed_size)?;
                return Ok(Response::new(
                    status,
                    self.headers,
                    Bytes::from(decompressed),
                ));
            }
            // Compression features off — we cannot validate the body
            // matches the declared encoding. Refusing to silently hand a
            // gzipped payload to the caller as plaintext (silent data
            // corruption class). Mirrors ringline-grpc PR #174 finding 4.
            #[cfg(not(any(feature = "gzip", feature = "zstd", feature = "brotli")))]
            {
                return Err(HttpError::InvalidMessage(format!(
                    "unsupported content-encoding `{encoding}` (no decompressor compiled in)"
                )));
            }
        }

        Ok(Response::new(status, self.headers, self.body.freeze()))
    }
}

/// `true` when the Content-Encoding is empty/`identity`, meaning the
/// body is delivered as-is and no decompression is required.
fn is_identity_encoding(encoding: &str) -> bool {
    let e = encoding.trim();
    e.is_empty() || e.eq_ignore_ascii_case("identity")
}

/// Parse and validate an HTTP/2 `:status` pseudo-header value per RFC
/// 9110 §15: exactly three ASCII digits, value 100–999. Anything else
/// (missing, non-numeric, wrong length, out of range) is a protocol
/// violation — returning `None` lets the caller fail the stream with a
/// specific error instead of silently substituting 0 (a real HTTP status
/// code does not exist outside this range).
fn parse_status(value: &[u8]) -> Option<u16> {
    if value.len() != 3 {
        return None;
    }
    if !value.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let s = std::str::from_utf8(value).ok()?;
    let n: u16 = s.parse().ok()?;
    if (100..=999).contains(&n) {
        Some(n)
    } else {
        None
    }
}

/// Apply a HEADERS event to a pending stream, validating `:status` and
/// enforcing the per-stream header-section cap.
fn handle_response_headers(
    ps: &mut PendingStream,
    headers: &[HeaderField],
    end_stream: bool,
    max_header_section: usize,
) {
    for h in headers {
        if h.name == b":status" {
            match parse_status(&h.value) {
                Some(n) => ps.status = Some(n),
                None => {
                    ps.fail(HttpError::InvalidMessage(format!(
                        "invalid :status `{}`",
                        String::from_utf8_lossy(&h.value)
                    )));
                    return;
                }
            }
            continue;
        }

        // Track the running header-section size. Counting name + value
        // bytes (no per-entry overhead) mirrors HPACK accounting and
        // keeps the cap interpretable for callers configuring it.
        let add = h.name.len().saturating_add(h.value.len());
        ps.header_bytes = ps.header_bytes.saturating_add(add);
        if ps.header_bytes > max_header_section {
            ps.fail(HttpError::MaxSizeExceeded(format!(
                "response header section exceeds {max_header_section} bytes"
            )));
            return;
        }

        let name = String::from_utf8_lossy(&h.name).into_owned();
        let value = String::from_utf8_lossy(&h.value).into_owned();
        if name.eq_ignore_ascii_case("content-encoding") {
            ps.content_encoding = Some(value.clone());
        }
        ps.headers.push((name, value));
    }
    if end_stream {
        // If end_stream arrives without `:status`, surface it now so the
        // caller doesn't get a successful response with status 0.
        if ps.status.is_none() && ps.error.is_none() {
            ps.fail(HttpError::InvalidMessage(
                "response HEADERS missing :status".into(),
            ));
        } else {
            ps.done = true;
        }
    }
}

/// Apply a DATA event to a pending stream, enforcing the per-stream
/// body-size cap.
fn handle_response_data(
    ps: &mut PendingStream,
    payload: Vec<u8>,
    end_stream: bool,
    max_body_size: usize,
) {
    let new_total = ps.body_bytes.saturating_add(payload.len());
    if new_total > max_body_size {
        ps.fail(HttpError::MaxSizeExceeded(format!(
            "response body exceeds {max_body_size} bytes"
        )));
        return;
    }
    ps.body_bytes = new_total;
    if ps.streaming {
        ps.chunks.push_back(Bytes::from(payload));
    } else {
        ps.body.extend_from_slice(&payload);
    }
    if end_stream {
        ps.done = true;
    }
}

/// Data for a send blocked on flow control.
struct BlockedSend {
    stream_id: u32,
    data: Vec<u8>,
    end_stream: bool,
}

/// Drain and dispatch all queued H2 events into the pending streams, then retry
/// any flow-control-blocked sends. Shared by both recv feed paths (io_uring
/// `with_segments` and the mio/portable `with_data` fallback) so the two paths
/// differ *only* in how socket bytes reach `h2.recv` — all protocol handling
/// (headers, data, resets, GOAWAY, connection errors, blocked-send retry) is
/// byte-for-byte identical.
#[allow(clippy::too_many_arguments)]
fn dispatch_h2_events(
    h2: &mut H2Connection,
    pending: &mut HashMap<u32, PendingStream>,
    blocked: &mut VecDeque<BlockedSend>,
    settings_acked: &mut bool,
    goaway_received: &mut bool,
    max_header_section: usize,
    max_body_size: usize,
    connection_error: &mut Option<HttpError>,
) {
    // Dispatch all events.
    while let Some(event) = h2.poll_event() {
        match event {
            H2Event::SettingsAcknowledged => {
                *settings_acked = true;
            }
            H2Event::Response {
                stream_id,
                headers,
                end_stream,
            } => {
                if let Some(ps) = pending.get_mut(&stream_id) {
                    handle_response_headers(ps, &headers, end_stream, max_header_section);
                }
            }
            H2Event::Data {
                stream_id,
                data: payload,
                end_stream,
            } => {
                if let Some(ps) = pending.get_mut(&stream_id) {
                    handle_response_data(ps, payload, end_stream, max_body_size);
                }
            }
            H2Event::Trailers { stream_id, .. } => {
                if let Some(ps) = pending.get_mut(&stream_id) {
                    ps.done = true;
                }
            }
            H2Event::StreamReset {
                stream_id,
                error_code,
            } => {
                if let Some(ps) = pending.get_mut(&stream_id) {
                    ps.fail(HttpError::H2(ringline_h2::H2Error::StreamError(
                        stream_id, error_code,
                    )));
                }
            }
            H2Event::GoAway { .. } => {
                *goaway_received = true;
                // Mark all pending streams as done. Streams that already
                // received complete responses resolve normally; streams still
                // mid-response surface a ConnectionClosed-shaped error when
                // into_response runs (missing :status → InvalidMessage).
                for ps in pending.values_mut() {
                    ps.done = true;
                }
            }
            H2Event::Error(e) => {
                // Connection-level protocol error from the sans-IO state
                // machine. The connection is dead; surface to the caller
                // instead of silently hanging.
                *connection_error = Some(HttpError::H2(e));
            }
            H2Event::PingAcknowledged { .. } => {}
        }
    }

    // Retry blocked sends — flow control windows may have opened.
    let mut retry = VecDeque::new();
    std::mem::swap(blocked, &mut retry);
    for bs in retry {
        match h2.send_data(bs.stream_id, &bs.data, bs.end_stream) {
            Ok(()) => {}
            Err(ringline_h2::H2Error::FlowControlError) => {
                // Still blocked, re-queue.
                blocked.push_back(bs);
            }
            Err(e) => {
                // Stream gone or other unrecoverable send failure — fail the
                // originating stream so the caller learns the request didn't
                // ship.
                if let Some(ps) = pending.get_mut(&bs.stream_id) {
                    ps.fail(HttpError::H2(e));
                }
            }
        }
    }
}

/// Async HTTP/2 connection with multiplexed request support.
///
/// Wraps a sans-IO `H2Connection` and a `ConnCtx`, providing a pump loop
/// that bridges bytes between the transport and the H2 state machine.
pub struct H2AsyncConn {
    conn: ConnCtx,
    h2: H2Connection,
    pending_streams: HashMap<u32, PendingStream>,
    blocked_sends: VecDeque<BlockedSend>,
    /// Streams that completed during a pump cycle, ready for pickup.
    /// Each entry carries either a successful response or a per-stream
    /// error (bad `:status`, oversize headers/body, unsupported encoding).
    completed: VecDeque<(u32, Result<Response, HttpError>)>,
    settings_acked: bool,
    /// Cap on a decompressed response body. Defaults to 64 MiB.
    max_decompressed_size: usize,
    /// Cap on the total bytes (name + value) accumulated per stream's
    /// response header section. Defaults to 64 KiB.
    max_header_section: usize,
    /// Cap on a single stream's accumulated response body. Defaults to
    /// 16 MiB.
    max_body_size: usize,
    /// Set once the peer has sent GOAWAY — this connection must not be
    /// used for further requests.
    goaway_received: bool,
}

impl H2AsyncConn {
    /// Override the cap on a decompressed response body. Default 64 MiB —
    /// defends against decompression bombs.
    pub fn set_max_decompressed_size(&mut self, n: usize) {
        self.max_decompressed_size = n;
    }

    /// Override the cap on the total response header bytes (sum of name +
    /// value lengths) collected per stream. Default 64 KiB.
    pub fn set_max_header_section(&mut self, n: usize) {
        self.max_header_section = n;
    }

    /// Override the cap on a single stream's accumulated response body.
    /// Default 16 MiB.
    pub fn set_max_body_size(&mut self, n: usize) {
        self.max_body_size = n;
    }

    /// Whether the peer has signalled it will not accept further requests
    /// (GOAWAY received). When `true`, callers should reconnect rather
    /// than reuse this connection.
    pub fn peer_will_close(&self) -> bool {
        self.goaway_received
    }
}

impl H2AsyncConn {
    /// Connect to an HTTP/2 server over TLS.
    ///
    /// Performs TLS handshake, sends the H2 connection preface, and waits
    /// for the server SETTINGS exchange to complete.
    pub async fn connect(addr: SocketAddr, host: &str) -> Result<Self, HttpError> {
        let conn = ringline::connect_tls(addr, host)?.await?;
        Self::from_conn(conn).await
    }

    /// Connect with a timeout (milliseconds).
    pub async fn connect_with_timeout(
        addr: SocketAddr,
        host: &str,
        timeout_ms: u64,
    ) -> Result<Self, HttpError> {
        let conn = ringline::connect_tls_with_timeout(addr, host, timeout_ms)?.await?;
        Self::from_conn(conn).await
    }

    /// Wrap an already-connected `ConnCtx` (must be TLS for H2).
    ///
    /// Sends the H2 preface and waits for SETTINGS exchange.
    pub async fn from_conn(conn: ConnCtx) -> Result<Self, HttpError> {
        let h2 = H2Connection::new(Settings::client_default());

        let mut this = Self {
            conn,
            h2,
            pending_streams: HashMap::new(),
            blocked_sends: VecDeque::new(),
            completed: VecDeque::new(),
            settings_acked: false,
            max_decompressed_size: crate::compress::DEFAULT_MAX_DECOMPRESSED_SIZE,
            max_header_section: crate::h1_conn::DEFAULT_MAX_HEADER_SECTION,
            max_body_size: crate::h1_conn::DEFAULT_MAX_BODY_SIZE,
            goaway_received: false,
        };

        // Send the connection preface (magic + SETTINGS).
        this.flush_pending_send()?;

        // Pump until we get SettingsAcknowledged.
        while !this.settings_acked {
            this.pump_once().await?;
        }

        Ok(this)
    }

    /// Returns the underlying connection context.
    pub fn close(&self) {
        self.conn.close();
    }

    pub fn conn(&self) -> ConnCtx {
        self.conn
    }

    /// Number of in-flight streams.
    pub fn pending_count(&self) -> usize {
        self.pending_streams.len()
    }

    // ── Sequential API ─────────────────────────────────────────────────

    /// Send a request and wait for the complete response.
    pub async fn send_request(
        &mut self,
        method: &str,
        path: &str,
        host: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response, HttpError> {
        let stream_id = self.fire_request(method, path, host, extra_headers, body)?;
        self.recv_stream(stream_id).await
    }

    // ── Multiplexed fire API ───────────────────────────────────────────

    /// Fire an HTTP/2 request. Returns the stream ID immediately.
    ///
    /// The request is queued for sending; call `recv()` or `recv_stream()`
    /// to pump the connection and collect responses.
    pub fn fire_request(
        &mut self,
        method: &str,
        path: &str,
        host: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<u32, HttpError> {
        let has_body = body.is_some_and(|b| !b.is_empty());

        let mut headers = vec![
            HeaderField::new(b":method", method.as_bytes()),
            HeaderField::new(b":path", path.as_bytes()),
            HeaderField::new(b":scheme", b"https"),
            HeaderField::new(b":authority", host.as_bytes()),
        ];

        let has_accept_encoding = extra_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"));

        for (name, value) in extra_headers {
            headers.push(HeaderField::new(name.as_bytes(), value.as_bytes()));
        }

        // Auto-inject Accept-Encoding when compression features are enabled
        // and the caller has not already set one.
        if !has_accept_encoding && let Some(ae) = crate::compress::accept_encoding_value() {
            headers.push(HeaderField::new(b"accept-encoding", ae.as_bytes()));
        }

        let end_stream = !has_body;
        let stream_id = self.h2.send_request(&headers, end_stream)?;

        if let Some(data) = body
            && !data.is_empty()
            && let Err(e) = self.h2.send_data(stream_id, data, true)
        {
            if matches!(e, ringline_h2::H2Error::FlowControlError) {
                self.blocked_sends.push_back(BlockedSend {
                    stream_id,
                    data: data.to_vec(),
                    end_stream: true,
                });
            } else {
                return Err(HttpError::H2(e));
            }
        }

        self.pending_streams.insert(stream_id, PendingStream::new());

        // Flush the request frames to the transport.
        self.flush_pending_send()?;

        Ok(stream_id)
    }

    // ── Multiplexed recv API ───────────────────────────────────────────

    /// Pump until any stream completes. Returns `(stream_id, Response)`,
    /// or surfaces a per-stream `HttpError` for that stream.
    pub async fn recv(&mut self) -> Result<(u32, Response), HttpError> {
        // Check if we already have a completed response queued.
        if let Some((id, result)) = self.completed.pop_front() {
            return result.map(|r| (id, r));
        }

        loop {
            self.pump_once().await?;

            if let Some((id, result)) = self.completed.pop_front() {
                return result.map(|r| (id, r));
            }
        }
    }

    /// Pump until a specific stream completes.
    pub async fn recv_stream(&mut self, stream_id: u32) -> Result<Response, HttpError> {
        // Check completed queue first.
        if let Some(idx) = self.completed.iter().position(|(sid, _)| *sid == stream_id) {
            let (_, result) = self.completed.remove(idx).unwrap();
            return result;
        }

        loop {
            self.pump_once().await?;

            // Check if our target stream completed.
            if let Some(idx) = self.completed.iter().position(|(sid, _)| *sid == stream_id) {
                let (_, result) = self.completed.remove(idx).unwrap();
                return result;
            }
        }
    }

    // ── Internal pump loop ─────────────────────────────────────────────

    /// One round of the pump loop:
    /// 1. Flush pending H2 output to transport
    /// 2. Read bytes from transport, feed to H2
    /// 3. Dispatch H2 events to pending streams
    /// 4. Retry blocked sends (flow control may have opened)
    /// 5. Flush any protocol responses (WINDOW_UPDATE, PING ACK, etc.)
    async fn pump_once(&mut self) -> Result<(), HttpError> {
        // Flush any pending output before blocking on recv.
        self.flush_pending_send()?;

        // Borrow-split: capture mutable refs before the closure.
        let h2 = &mut self.h2;
        let pending = &mut self.pending_streams;
        let blocked = &mut self.blocked_sends;
        let settings_acked = &mut self.settings_acked;
        let goaway_received = &mut self.goaway_received;
        let max_header_section = self.max_header_section;
        let max_body_size = self.max_body_size;
        // Connection-level error captured during dispatch (recv error,
        // unrecoverable send error, H2Event::Error). The pump returns
        // this once the closure unwinds.
        let mut connection_error: Option<HttpError> = None;

        // Feed socket bytes into the h2 codec. On io_uring, read via
        // `with_segments` and hand each borrowed provided-buffer segment
        // straight to `h2.recv` (which re-accumulates into its own `recv_buf`),
        // eliminating the redundant `RecvAccumulator` copy — h2 drains fully
        // every call, so we return `SegConsumed(total_len)`. On mio (no
        // `with_segments`), keep the existing `with_data` path: h2 buffers
        // internally, so we consume all input.
        #[cfg(has_io_uring)]
        let n = self
            .conn
            .with_segments(|chain| {
                // Feed each borrowed segment, in order, to H2. Stop on the
                // first codec error (h2 is now dead) — mirrors the `with_data`
                // path's early return, skipping event dispatch so the captured
                // error surfaces below.
                for seg in chain.iter() {
                    if let Err(e) = h2.recv(seg) {
                        connection_error = Some(HttpError::H2(e));
                        return ringline::SegConsumed(chain.total_len());
                    }
                }

                dispatch_h2_events(
                    h2,
                    pending,
                    blocked,
                    settings_acked,
                    goaway_received,
                    max_header_section,
                    max_body_size,
                    &mut connection_error,
                );

                // h2.recv consumes all input into its own recv_buf; report the
                // whole chain as consumed so the runtime replenishes every held
                // buffer and keeps no redundant accumulator copy.
                ringline::SegConsumed(chain.total_len())
            })
            .await?;

        #[cfg(not(has_io_uring))]
        let n = self
            .conn
            .with_data(|data| {
                // Feed bytes to H2.
                if let Err(e) = h2.recv(data) {
                    connection_error = Some(HttpError::H2(e));
                    return ParseResult::Consumed(data.len());
                }

                dispatch_h2_events(
                    h2,
                    pending,
                    blocked,
                    settings_acked,
                    goaway_received,
                    max_header_section,
                    max_body_size,
                    &mut connection_error,
                );

                // H2 buffers internally, consume all input.
                ParseResult::Consumed(data.len())
            })
            .await;

        if let Some(e) = connection_error {
            return Err(e);
        }
        if n == 0 {
            return Err(HttpError::ConnectionClosed);
        }

        // Move completed non-streaming streams to the completed queue.
        let done_ids: Vec<u32> = self
            .pending_streams
            .iter()
            .filter(|(_, ps)| ps.done && !ps.streaming)
            .map(|(id, _)| *id)
            .collect();
        for id in done_ids {
            if let Some(ps) = self.pending_streams.remove(&id) {
                let result = ps.into_response(self.max_decompressed_size);
                self.completed.push_back((id, result));
            }
        }

        // Flush protocol responses (SETTINGS ACK, WINDOW_UPDATE, PING ACK).
        self.flush_pending_send()?;

        Ok(())
    }

    // ── Streaming API ──────────────────────────────────────────────────

    /// Send a request and return a streaming response after headers arrive.
    ///
    /// The caller must drain the body via [`H2StreamingResponse::next_chunk()`]
    /// before issuing further requests on this connection.
    pub async fn send_request_streaming(
        &mut self,
        method: &str,
        path: &str,
        host: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<H2StreamingResponse<'_>, HttpError> {
        let stream_id = self.fire_request(method, path, host, extra_headers, body)?;

        // Mark the stream as streaming.
        if let Some(ps) = self.pending_streams.get_mut(&stream_id) {
            ps.streaming = true;
        }

        // Pump until headers arrive for this stream — or it errors.
        loop {
            if let Some(ps) = self.pending_streams.get_mut(&stream_id) {
                if let Some(err) = ps.error.take() {
                    self.pending_streams.remove(&stream_id);
                    return Err(err);
                }
                if ps.status.is_some() {
                    break;
                }
            } else {
                return Err(HttpError::Protocol("stream vanished".into()));
            }

            self.pump_once().await?;
        }

        Ok(H2StreamingResponse {
            conn: self,
            stream_id,
        })
    }

    /// Drain `h2.take_pending_send()` to `conn.send_nowait()`.
    fn flush_pending_send(&mut self) -> Result<(), HttpError> {
        let pending = self.h2.take_pending_send();
        if !pending.is_empty() {
            self.conn.send_nowait(&pending)?;
        }
        Ok(())
    }
}

/// Streaming HTTP/2 response. Borrows the connection exclusively.
///
/// Body chunks are yielded one at a time via [`next_chunk()`](Self::next_chunk).
/// When all chunks have been consumed (returns `Ok(None)`), the stream is
/// cleaned up automatically. The stream is also cleaned up on drop.
pub struct H2StreamingResponse<'a> {
    conn: &'a mut H2AsyncConn,
    stream_id: u32,
}

impl<'a> H2StreamingResponse<'a> {
    /// HTTP status code.
    pub fn status(&self) -> u16 {
        self.conn
            .pending_streams
            .get(&self.stream_id)
            .and_then(|ps| ps.status)
            .unwrap_or(0)
    }

    /// Response headers as (name, value) pairs.
    pub fn headers(&self) -> &[(String, String)] {
        self.conn
            .pending_streams
            .get(&self.stream_id)
            .map(|ps| ps.headers.as_slice())
            .unwrap_or(&[])
    }

    /// Get the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers()
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Yield the next body chunk, or `None` when the body is complete.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        loop {
            if let Some(ps) = self.conn.pending_streams.get_mut(&self.stream_id) {
                // Surface a deferred per-stream error (body cap exceeded,
                // unrecoverable send-data failure) before yielding more
                // bytes. Take it so we only report it once.
                if let Some(err) = ps.error.take() {
                    self.conn.pending_streams.remove(&self.stream_id);
                    return Err(err);
                }
                // Return a buffered chunk if available.
                if let Some(chunk) = ps.chunks.pop_front() {
                    return Ok(Some(chunk));
                }
                // No more chunks and stream is done.
                if ps.done {
                    self.conn.pending_streams.remove(&self.stream_id);
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }

            // Pump to get more data.
            self.conn.pump_once().await?;
        }
    }
}

impl Drop for H2StreamingResponse<'_> {
    fn drop(&mut self) {
        self.conn.pending_streams.remove(&self.stream_id);
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the I/O-free helpers and `PendingStream` state
    //! machine. The full pump loop is exercised by the public-servers
    //! integration tests (`tests/public_servers.rs`).

    use super::*;

    fn header(name: &[u8], value: &[u8]) -> HeaderField {
        HeaderField::new(name, value)
    }

    // ── parse_status ───────────────────────────────────────────────────

    #[test]
    fn parse_status_accepts_three_digit_codes() {
        assert_eq!(parse_status(b"200"), Some(200));
        assert_eq!(parse_status(b"404"), Some(404));
        assert_eq!(parse_status(b"100"), Some(100));
        assert_eq!(parse_status(b"599"), Some(599));
        assert_eq!(parse_status(b"999"), Some(999));
    }

    #[test]
    fn parse_status_rejects_wrong_length() {
        assert_eq!(parse_status(b""), None);
        assert_eq!(parse_status(b"2"), None);
        assert_eq!(parse_status(b"20"), None);
        assert_eq!(parse_status(b"2000"), None);
    }

    #[test]
    fn parse_status_rejects_non_digits() {
        assert_eq!(parse_status(b"abc"), None);
        assert_eq!(parse_status(b"2x0"), None);
        assert_eq!(parse_status(b"-10"), None);
    }

    #[test]
    fn parse_status_rejects_out_of_range() {
        // 099 fails the >= 100 check.
        assert_eq!(parse_status(b"099"), None);
        // No real HTTP status sits below 100 per RFC 9110 §15.
    }

    // ── handle_response_headers (4a, 4f) ───────────────────────────────

    #[test]
    fn invalid_status_fails_stream() {
        let mut ps = PendingStream::new();
        let headers = vec![header(b":status", b"oops")];
        handle_response_headers(&mut ps, &headers, true, 64 * 1024);
        assert!(ps.error.is_some());
        match ps.error.unwrap() {
            HttpError::InvalidMessage(_) => {}
            other => panic!("expected InvalidMessage, got {other:?}"),
        }
    }

    #[test]
    fn missing_status_with_end_stream_fails() {
        let mut ps = PendingStream::new();
        let headers = vec![header(b"content-type", b"text/plain")];
        handle_response_headers(&mut ps, &headers, true, 64 * 1024);
        assert!(matches!(ps.error, Some(HttpError::InvalidMessage(_))));
    }

    #[test]
    fn oversize_header_section_fails_stream() {
        let mut ps = PendingStream::new();
        // 200 bytes of value plus a small name pushes past the 100-byte cap.
        let big_value = vec![b'x'; 200];
        let headers = vec![header(b":status", b"200"), header(b"x", &big_value)];
        handle_response_headers(&mut ps, &headers, false, 100);
        assert!(matches!(ps.error, Some(HttpError::MaxSizeExceeded(_))));
    }

    #[test]
    fn valid_status_accepts_and_collects_headers() {
        let mut ps = PendingStream::new();
        let headers = vec![header(b":status", b"204"), header(b"x-custom", b"value")];
        handle_response_headers(&mut ps, &headers, true, 64 * 1024);
        assert_eq!(ps.status, Some(204));
        assert!(ps.error.is_none());
        assert!(ps.done);
        assert_eq!(
            ps.headers,
            vec![("x-custom".to_string(), "value".to_string())]
        );
    }

    // ── handle_response_data (4f) ──────────────────────────────────────

    #[test]
    fn oversize_body_fails_stream() {
        let mut ps = PendingStream::new();
        let payload = vec![0u8; 200];
        handle_response_data(&mut ps, payload, false, 100);
        assert!(matches!(ps.error, Some(HttpError::MaxSizeExceeded(_))));
    }

    #[test]
    fn body_within_cap_accumulates() {
        let mut ps = PendingStream::new();
        handle_response_data(&mut ps, vec![1, 2, 3], false, 100);
        handle_response_data(&mut ps, vec![4, 5], true, 100);
        assert!(ps.error.is_none());
        assert!(ps.done);
        assert_eq!(&ps.body[..], &[1, 2, 3, 4, 5]);
    }

    // ── into_response (4a, 4e) ─────────────────────────────────────────

    #[test]
    fn into_response_surfaces_stream_error() {
        let mut ps = PendingStream::new();
        ps.fail(HttpError::InvalidMessage("test".into()));
        let res = ps.into_response(usize::MAX);
        assert!(matches!(res, Err(HttpError::InvalidMessage(_))));
    }

    #[cfg(not(any(feature = "gzip", feature = "zstd", feature = "brotli")))]
    #[test]
    fn into_response_rejects_unsupported_content_encoding_without_features() {
        let mut ps = PendingStream::new();
        ps.status = Some(200);
        ps.content_encoding = Some("gzip".into());
        ps.body.extend_from_slice(&[1, 2, 3]);
        let res = ps.into_response(usize::MAX);
        match res {
            Err(HttpError::InvalidMessage(msg)) => assert!(msg.contains("gzip")),
            other => panic!("expected InvalidMessage for gzip without features, got {other:?}"),
        }
    }

    #[test]
    fn into_response_identity_encoding_returns_body_as_is() {
        let mut ps = PendingStream::new();
        ps.status = Some(200);
        ps.content_encoding = Some("identity".into());
        ps.body.extend_from_slice(&[1, 2, 3]);
        let res = ps.into_response(usize::MAX);
        let resp = res.expect("identity encoding must not error");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.bytes().as_ref(), &[1, 2, 3]);
    }

    // ── is_identity_encoding ───────────────────────────────────────────

    #[test]
    fn is_identity_encoding_recognises_variants() {
        assert!(is_identity_encoding(""));
        assert!(is_identity_encoding("identity"));
        assert!(is_identity_encoding("Identity"));
        assert!(is_identity_encoding("  identity  "));
        assert!(!is_identity_encoding("gzip"));
        assert!(!is_identity_encoding("br"));
    }
}
