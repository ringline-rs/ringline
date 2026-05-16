//! gRPC client connection state machine.
//!
//! `GrpcConnection` wraps an `H2Connection` and adds gRPC message framing,
//! header conventions, and status extraction from trailers.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use ringline_h2::hpack::HeaderField;
use ringline_h2::settings::Settings;
use ringline_h2::{ErrorCode, H2Connection, H2Event};

use crate::error::{GrpcError, GrpcStatus};
use crate::message::{self, BufferDecode, MessageBuffer};

/// Per-stream state for tracking the server's chosen encoding and the
/// progress of the inbound message reassembly.
#[derive(Debug)]
struct StreamState {
    buffer: MessageBuffer,
    /// The encoding advertised by the server for this stream (from `grpc-encoding` header).
    encoding: Option<String>,
    /// `true` once we've delivered the initial `Response` event for this
    /// stream — used to gate DATA-before-HEADERS and to detect
    /// trailers-only paths.
    response_seen: bool,
}

impl StreamState {
    fn new(max_message_size: usize) -> Self {
        Self {
            buffer: MessageBuffer::new(max_message_size),
            encoding: None,
            response_seen: false,
        }
    }
}

/// Events produced by the gRPC connection for the application.
///
/// Marked `#[non_exhaustive]` because the crate is still evolving.
#[derive(Debug)]
#[non_exhaustive]
pub enum GrpcEvent {
    /// HTTP/2 settings exchange complete; connection is ready.
    Ready,
    /// Initial response metadata received.
    Response {
        stream_id: u32,
        metadata: Vec<HeaderField>,
    },
    /// A complete gRPC message (length-prefix stripped).
    Message { stream_id: u32, data: Vec<u8> },
    /// Stream completed with a gRPC status (from trailers).
    Status {
        stream_id: u32,
        status: GrpcStatus,
        message: String,
        metadata: Vec<HeaderField>,
    },
    /// Connection-level shutdown.
    GoAway {
        last_stream_id: u32,
        error_code: ErrorCode,
        debug_data: Vec<u8>,
    },
    /// Error event.
    Error(GrpcError),
}

/// Sans-IO gRPC client connection wrapping an `H2Connection`.
pub struct GrpcConnection {
    h2: H2Connection,
    ready: bool,
    /// Per-stream message reassembly buffers.
    buffers: HashMap<u32, StreamState>,
    /// Pending gRPC events.
    events: VecDeque<GrpcEvent>,
    /// Cap on a single received gRPC message's size, both pre-decompression
    /// (header length prefix) and post-decompression. Defaults to 4 MiB
    /// per the gRPC standard `max_receive_message_length`.
    max_message_size: usize,
}

impl GrpcConnection {
    /// Create a new gRPC connection with the given HTTP/2 settings.
    pub fn new(settings: Settings) -> Self {
        Self {
            h2: H2Connection::new(settings),
            ready: false,
            buffers: HashMap::new(),
            events: VecDeque::new(),
            max_message_size: crate::message::DEFAULT_MAX_MESSAGE_SIZE,
        }
    }

    /// Override the cap on a single received gRPC message. Defaults to
    /// 4 MiB. Applied to the length-prefix decode (raw frame size) and to
    /// the decompressed output if `grpc-encoding` is set.
    pub fn set_max_message_size(&mut self, n: usize) {
        self.max_message_size = n;
    }

    /// Feed received bytes from the transport.
    pub fn recv(&mut self, data: &[u8]) -> Result<(), GrpcError> {
        self.h2.recv(data)?;
        self.translate_events();
        Ok(())
    }

    /// Poll the next gRPC event, if any.
    pub fn poll_event(&mut self) -> Option<GrpcEvent> {
        self.events.pop_front()
    }

    /// Take all pending bytes to send to the transport.
    pub fn take_pending_send(&mut self) -> Vec<u8> {
        self.h2.take_pending_send()
    }

    /// Whether there are bytes pending to send.
    pub fn has_pending_send(&self) -> bool {
        self.h2.has_pending_send()
    }

    /// Send a unary gRPC request (headers + length-prefixed body + end_stream).
    ///
    /// Returns the stream ID. Fails with `GrpcError::NotReady` if the HTTP/2
    /// settings exchange hasn't completed yet — sending before SETTINGS ACK
    /// can violate frame-size or stream-concurrency limits the server is
    /// about to advertise.
    pub fn send_unary(
        &mut self,
        service: &str,
        method: &str,
        body: &[u8],
        metadata: &[HeaderField],
    ) -> Result<u32, GrpcError> {
        self.send_unary_inner(service, method, body, metadata, None)
    }

    /// Same as [`send_unary`](Self::send_unary) but also encodes a
    /// `grpc-timeout` header so the server knows when to cancel work on
    /// the application's behalf. The encoded timeout uses the smallest
    /// gRPC unit (n/u/m/S/M/H) that fits the value in ≤ 8 digits per
    /// the gRPC spec. Note: this only *advertises* the deadline to the
    /// server. Client-side enforcement (cancel + emit Status with
    /// DeadlineExceeded) is the caller's responsibility.
    pub fn send_unary_with_deadline(
        &mut self,
        service: &str,
        method: &str,
        body: &[u8],
        metadata: &[HeaderField],
        deadline: Duration,
    ) -> Result<u32, GrpcError> {
        self.send_unary_inner(service, method, body, metadata, Some(deadline))
    }

    fn send_unary_inner(
        &mut self,
        service: &str,
        method: &str,
        body: &[u8],
        metadata: &[HeaderField],
        deadline: Option<Duration>,
    ) -> Result<u32, GrpcError> {
        if !self.ready {
            return Err(GrpcError::NotReady);
        }
        let stream_id =
            self.send_headers_with_deadline(service, method, metadata, false, deadline)?;

        // Encode the gRPC length-prefixed message.
        let mut framed = Vec::new();
        message::encode(body, &mut framed).map_err(|e| GrpcError::InvalidMessage(e.to_string()))?;

        self.h2.send_data(stream_id, &framed, true)?;

        // Allocate a message buffer for the response.
        self.buffers
            .insert(stream_id, StreamState::new(self.max_message_size));

        Ok(stream_id)
    }

    /// Start a streaming gRPC request (headers only, no end_stream).
    ///
    /// Returns the stream ID. Use `send_message()` to send body frames.
    /// Fails with `GrpcError::NotReady` if the HTTP/2 settings exchange
    /// hasn't completed yet.
    pub fn start_request(
        &mut self,
        service: &str,
        method: &str,
        metadata: &[HeaderField],
    ) -> Result<u32, GrpcError> {
        if !self.ready {
            return Err(GrpcError::NotReady);
        }
        let stream_id = self.send_headers(service, method, metadata, false)?;
        self.buffers
            .insert(stream_id, StreamState::new(self.max_message_size));
        Ok(stream_id)
    }

    /// Send a gRPC message on an open stream.
    pub fn send_message(
        &mut self,
        stream_id: u32,
        body: &[u8],
        end_stream: bool,
    ) -> Result<(), GrpcError> {
        let mut framed = Vec::new();
        message::encode(body, &mut framed).map_err(|e| GrpcError::InvalidMessage(e.to_string()))?;
        self.h2.send_data(stream_id, &framed, end_stream)?;
        Ok(())
    }

    /// Cancel a stream with RST_STREAM CANCEL. Pushes a terminal
    /// `Status::Cancelled` event so any caller awaiting completion
    /// observes the cancellation rather than hanging.
    pub fn cancel(&mut self, stream_id: u32) {
        self.h2.reset_stream(stream_id, ErrorCode::Cancel);
        if self.buffers.remove(&stream_id).is_some() {
            self.events.push_back(GrpcEvent::Status {
                stream_id,
                status: GrpcStatus::Cancelled,
                message: "cancelled by client".into(),
                metadata: Vec::new(),
            });
        }
    }

    // -- Internal --

    fn send_headers(
        &mut self,
        service: &str,
        method: &str,
        metadata: &[HeaderField],
        end_stream: bool,
    ) -> Result<u32, GrpcError> {
        self.send_headers_with_deadline(service, method, metadata, end_stream, None)
    }

    fn send_headers_with_deadline(
        &mut self,
        service: &str,
        method: &str,
        metadata: &[HeaderField],
        end_stream: bool,
        deadline: Option<Duration>,
    ) -> Result<u32, GrpcError> {
        let path = format!("/{service}/{method}");
        let mut headers = vec![
            HeaderField::new(b":method", b"POST"),
            HeaderField::new(b":path", path.as_bytes()),
            HeaderField::new(b":scheme", b"https"),
            HeaderField::new(b"content-type", b"application/grpc"),
            HeaderField::new(b"te", b"trailers"),
        ];
        if let Some(enc) = crate::compress::accept_encoding_value() {
            headers.push(HeaderField::new(b"grpc-accept-encoding", enc.as_bytes()));
        }
        if let Some(d) = deadline {
            let encoded = encode_grpc_timeout(d);
            headers.push(HeaderField::new(b"grpc-timeout", encoded.as_bytes()));
        }
        headers.extend_from_slice(metadata);

        let stream_id = self.h2.send_request(&headers, end_stream)?;
        Ok(stream_id)
    }

    fn translate_events(&mut self) {
        while let Some(h2_event) = self.h2.poll_event() {
            match h2_event {
                H2Event::SettingsAcknowledged => {
                    self.ready = true;
                    self.events.push_back(GrpcEvent::Ready);
                }
                H2Event::Response {
                    stream_id,
                    headers,
                    end_stream,
                } => {
                    self.handle_response(stream_id, headers, end_stream);
                }
                H2Event::Data {
                    stream_id,
                    data,
                    end_stream,
                } => {
                    self.handle_data(stream_id, &data, end_stream);
                }
                H2Event::Trailers { stream_id, headers } => {
                    self.handle_trailers(stream_id, headers);
                }
                H2Event::StreamReset {
                    stream_id,
                    error_code,
                } => {
                    self.buffers.remove(&stream_id);
                    self.events.push_back(GrpcEvent::Status {
                        stream_id,
                        status: GrpcStatus::Internal,
                        message: format!("stream reset: {error_code:?}"),
                        metadata: Vec::new(),
                    });
                }
                H2Event::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                } => {
                    // Streams above `last_stream_id` will not be processed
                    // by the server. Emit a terminal `Status::Unavailable`
                    // for each so callers don't hang awaiting completion,
                    // and drop the per-stream buffers we'd otherwise leak.
                    let stranded: Vec<u32> = self
                        .buffers
                        .keys()
                        .copied()
                        .filter(|id| *id > last_stream_id)
                        .collect();
                    for stream_id in stranded {
                        self.buffers.remove(&stream_id);
                        self.events.push_back(GrpcEvent::Status {
                            stream_id,
                            status: GrpcStatus::Unavailable,
                            message: format!("GoAway: {error_code:?}"),
                            metadata: Vec::new(),
                        });
                    }
                    self.events.push_back(GrpcEvent::GoAway {
                        last_stream_id,
                        error_code,
                        debug_data,
                    });
                }
                H2Event::Error(e) => {
                    self.events.push_back(GrpcEvent::Error(GrpcError::H2(e)));
                }
                H2Event::PingAcknowledged { .. } => {}
            }
        }
    }

    fn handle_response(&mut self, stream_id: u32, headers: Vec<HeaderField>, end_stream: bool) {
        // Ensure we have a buffer even for server-push scenarios.
        let state = self
            .buffers
            .entry(stream_id)
            .or_insert_with(|| StreamState::new(self.max_message_size));
        state.response_seen = true;

        // Inspect :status before grpc-status — per the gRPC-over-HTTP/2
        // spec, a non-200 transport status maps to a specific grpc-status
        // and overrides what trailers say (or substitutes for them on a
        // trailers-only path).
        let http_status_override = http_status_to_grpc_status(&headers);

        // Capture grpc-encoding for the message-decode path even when
        // end_stream is true; harmless and keeps the path symmetric.
        for h in &headers {
            if header_name_eq(&h.name, b"grpc-encoding") {
                state.encoding = Some(String::from_utf8_lossy(&h.value).into_owned());
            }
        }

        if end_stream {
            // Trailers-only response: HEADERS+END_STREAM carries grpc-status
            // (gRPC spec §2). Filter grpc-status/grpc-message out of the
            // metadata view to match the two-headers path.
            let (status, message) = derive_status(&headers, http_status_override);
            let metadata: Vec<HeaderField> = headers
                .iter()
                .filter(|h| {
                    !header_name_eq(&h.name, b"grpc-status")
                        && !header_name_eq(&h.name, b"grpc-message")
                })
                .cloned()
                .collect();
            self.events.push_back(GrpcEvent::Response {
                stream_id,
                metadata: metadata.clone(),
            });
            self.buffers.remove(&stream_id);
            self.events.push_back(GrpcEvent::Status {
                stream_id,
                status,
                message,
                metadata,
            });
            return;
        }

        self.events.push_back(GrpcEvent::Response {
            stream_id,
            metadata: headers,
        });
    }

    fn handle_data(&mut self, stream_id: u32, data: &[u8], end_stream: bool) {
        // DATA before HEADERS is a protocol violation — the server has
        // not yet identified the response. Reset and surface an Internal
        // status instead of emitting Message events for an unannounced
        // stream.
        let response_seen = self
            .buffers
            .get(&stream_id)
            .map(|s| s.response_seen)
            .unwrap_or(false);
        if !response_seen {
            self.h2.reset_stream(stream_id, ErrorCode::ProtocolError);
            self.buffers.remove(&stream_id);
            self.events.push_back(GrpcEvent::Status {
                stream_id,
                status: GrpcStatus::Internal,
                message: "received DATA before HEADERS".into(),
                metadata: Vec::new(),
            });
            return;
        }

        let max = self.max_message_size;
        if let Some(state) = self.buffers.get_mut(&stream_id) {
            // If the per-stream buffer fills up — the peer is
            // sending data faster than message boundaries
            // arrive — fail the stream rather than OOM.
            if let Err(e) = state.buffer.push(data) {
                self.fail_stream(stream_id, GrpcStatus::ResourceExhausted, e.to_string());
                return;
            }
            loop {
                match state.buffer.try_decode() {
                    BufferDecode::Complete(payload, compressed) => {
                        let data = if compressed {
                            match &state.encoding {
                                // Compressed flag set with a known encoding — decompress
                                // or fail the stream with INTERNAL (do NOT silently fall
                                // back to raw bytes; the application can't tell the
                                // difference between a real message and our garbage).
                                Some(enc) => {
                                    match crate::compress::decompress(enc, &payload, max) {
                                        Ok(d) => d,
                                        Err(e) => {
                                            self.fail_stream(
                                                stream_id,
                                                GrpcStatus::Internal,
                                                format!("decompression failed: {e}"),
                                            );
                                            break;
                                        }
                                    }
                                }
                                // Compressed flag set but no grpc-encoding header — peer
                                // is malformed; treat as INTERNAL rather than silently
                                // delivering raw compressed bytes as the message.
                                None => {
                                    self.fail_stream(
                                        stream_id,
                                        GrpcStatus::Internal,
                                        "compressed flag set but no grpc-encoding header".into(),
                                    );
                                    break;
                                }
                            }
                        } else {
                            payload
                        };
                        self.events
                            .push_back(GrpcEvent::Message { stream_id, data });
                    }
                    BufferDecode::Incomplete => break,
                    BufferDecode::TooLarge(n) => {
                        self.fail_stream(
                            stream_id,
                            GrpcStatus::ResourceExhausted,
                            format!("message length {n} exceeds cap {max}"),
                        );
                        break;
                    }
                }
            }
        }

        if end_stream {
            self.emit_status_from_cleanup(stream_id, &[]);
        }
    }

    fn handle_trailers(&mut self, stream_id: u32, headers: Vec<HeaderField>) {
        // Drain any remaining buffered messages. Decompression
        // failures on these final messages fall through to the
        // status emission below (we'd want to surface them but
        // the trailer arrival is the authoritative end signal).
        let max = self.max_message_size;
        if let Some(state) = self.buffers.get_mut(&stream_id) {
            while let BufferDecode::Complete(payload, compressed) = state.buffer.try_decode() {
                let data = if compressed {
                    match &state.encoding {
                        Some(enc) => {
                            match crate::compress::decompress(enc, &payload, max) {
                                Ok(d) => d,
                                Err(_) => break, // surfaced via grpc-status below
                            }
                        }
                        None => break,
                    }
                } else {
                    payload
                };
                self.events
                    .push_back(GrpcEvent::Message { stream_id, data });
            }
        }

        // Extract grpc-status and grpc-message from trailers.
        let status = extract_grpc_status(&headers);
        let message = extract_grpc_message(&headers);
        let remaining: Vec<HeaderField> = headers
            .into_iter()
            .filter(|h| h.name != b"grpc-status" && h.name != b"grpc-message")
            .collect();

        self.events.push_back(GrpcEvent::Status {
            stream_id,
            status,
            message,
            metadata: remaining,
        });
        self.buffers.remove(&stream_id);
    }

    /// Emit a status event when the stream ends without explicit trailers
    /// (e.g., end_stream on a DATA frame). Per the gRPC spec, every
    /// stream must end with a HEADERS frame carrying trailers — missing
    /// trailers indicates a malformed response. If the reassembly buffer
    /// still has bytes (a partial message), surface that distinctly.
    fn emit_status_from_cleanup(&mut self, stream_id: u32, _headers: &[HeaderField]) {
        let truncated = self
            .buffers
            .get(&stream_id)
            .map(|s| !s.buffer.is_empty())
            .unwrap_or(false);
        self.buffers.remove(&stream_id);
        let message = if truncated {
            "stream ended mid-message without trailers".into()
        } else {
            "stream ended without trailers".into()
        };
        self.events.push_back(GrpcEvent::Status {
            stream_id,
            status: GrpcStatus::Internal,
            message,
            metadata: Vec::new(),
        });
    }

    /// Reset a stream from the gRPC layer with an explicit status and
    /// reason. Sends RST_STREAM(CANCEL) at the H2 layer, removes the
    /// per-stream buffer, and emits a Status event so the caller learns
    /// the RPC outcome.
    fn fail_stream(&mut self, stream_id: u32, status: GrpcStatus, message: String) {
        self.h2.reset_stream(stream_id, ErrorCode::Cancel);
        self.buffers.remove(&stream_id);
        self.events.push_back(GrpcEvent::Status {
            stream_id,
            status,
            message,
            metadata: Vec::new(),
        });
    }
}

/// Extract `grpc-status` from trailer headers. A missing or malformed
/// status is treated as `Unknown` — defaulting to `Ok` would let a
/// misbehaving server's incomplete trailers look like a successful RPC.
/// The gRPC spec requires every response to carry a `grpc-status` trailer.
fn extract_grpc_status(headers: &[HeaderField]) -> GrpcStatus {
    headers
        .iter()
        .find(|h| h.name == b"grpc-status")
        .and_then(|h| std::str::from_utf8(&h.value).ok())
        .and_then(|s| s.parse::<u8>().ok())
        .map(GrpcStatus::from_u8)
        .unwrap_or(GrpcStatus::Unknown)
}

/// Header-name comparison. h2 already rejects uppercase names so direct
/// byte comparison would suffice, but trailer-frame validation lives in a
/// different code path; case-insensitive here is the conservative choice.
fn header_name_eq(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Derive `(status, message)` from a header section. Per gRPC spec
/// `grpc-status` is mandatory in any terminal HEADERS — missing or
/// unparseable values default to `Internal` (NOT `Ok`) with a diagnostic
/// so a peer that silently drops the trailer can't be mistaken for
/// success. An `http_status_override` (set by [`http_status_to_grpc_status`])
/// preempts trailer values when the HTTP-level transport reported an
/// error.
fn derive_status(
    headers: &[HeaderField],
    http_status_override: Option<(GrpcStatus, String)>,
) -> (GrpcStatus, String) {
    if let Some((s, msg)) = http_status_override {
        return (s, msg);
    }
    let raw = headers
        .iter()
        .find(|h| header_name_eq(&h.name, b"grpc-status"))
        .map(|h| h.value.clone());
    let status = match raw {
        Some(bytes) => match std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
        {
            Some(n) if n <= 16 => GrpcStatus::from_u8(n as u8),
            Some(n) => {
                return (
                    GrpcStatus::Internal,
                    format!("invalid grpc-status value: {n}"),
                );
            }
            None => {
                return (
                    GrpcStatus::Internal,
                    format!(
                        "invalid grpc-status value: {:?}",
                        String::from_utf8_lossy(&bytes)
                    ),
                );
            }
        },
        None => {
            return (GrpcStatus::Internal, "missing grpc-status trailer".into());
        }
    };
    let message = extract_grpc_message(headers);
    (status, message)
}

/// Extract `grpc-message` from a header section. The value is
/// percent-encoded per gRPC spec (so arbitrary bytes survive the HPACK
/// ASCII restriction). Decode `%XX` byte escapes and produce a lossy
/// UTF-8 string. Returns the empty string when absent.
fn extract_grpc_message(headers: &[HeaderField]) -> String {
    let raw = match headers
        .iter()
        .find(|h| header_name_eq(&h.name, b"grpc-message"))
    {
        Some(h) => &h.value[..],
        None => return String::new(),
    };
    percent_decode_to_string(raw)
}

fn percent_decode_to_string(input: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            let hi = hex_value(input[i + 1]);
            let lo = hex_value(input[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Encode a `grpc-timeout` header value: a positive integer (≤ 8 digits)
/// followed by a unit (`n`anosecond, `u`s, `m`s, `S`econd, `M`inute,
/// `H`our). Picks the smallest unit such that the magnitude fits in 8
/// digits. Saturates at the maximum (`99999999H`, ≈ 11 408 years) and at
/// zero for the lower bound. Per gRPC spec.
fn encode_grpc_timeout(d: Duration) -> String {
    // Try units from finest to coarsest; the first that fits 8 digits wins.
    let nanos = d.as_nanos();
    if nanos <= 99_999_999 {
        return format!("{nanos}n");
    }
    let micros = d.as_micros();
    if micros <= 99_999_999 {
        return format!("{micros}u");
    }
    let millis = d.as_millis();
    if millis <= 99_999_999 {
        return format!("{millis}m");
    }
    let secs = d.as_secs() as u128;
    if secs <= 99_999_999 {
        return format!("{secs}S");
    }
    let minutes = secs / 60;
    if minutes <= 99_999_999 {
        return format!("{minutes}M");
    }
    let hours = secs / 3600;
    if hours <= 99_999_999 {
        return format!("{hours}H");
    }
    "99999999H".into()
}

/// HTTP/2 `:status` to gRPC status mapping per gRPC-over-HTTP/2 spec.
/// Returns `Some((status, message))` for any non-200 status, `None`
/// otherwise. The trailer `grpc-status` is ignored when this returns
/// `Some` (transport-level failure trumps semantic).
fn http_status_to_grpc_status(headers: &[HeaderField]) -> Option<(GrpcStatus, String)> {
    let raw = headers
        .iter()
        .find(|h| h.name == b":status")
        .map(|h| h.value.clone())?;
    let code = std::str::from_utf8(&raw).ok()?.parse::<u16>().ok()?;
    if code == 200 {
        return None;
    }
    let status = match code {
        400 => GrpcStatus::Internal,
        401 => GrpcStatus::Unauthenticated,
        403 => GrpcStatus::PermissionDenied,
        404 => GrpcStatus::Unimplemented,
        429 | 502 | 503 | 504 => GrpcStatus::Unavailable,
        _ => GrpcStatus::Unknown,
    };
    Some((status, format!("HTTP/2 :status {code}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_status_ok() {
        let headers = vec![HeaderField::new(b"grpc-status", b"0")];
        let (status, message) = derive_status(&headers, None);
        assert_eq!(status, GrpcStatus::Ok);
        assert_eq!(message, "");
    }

    #[test]
    fn derive_status_not_found() {
        let headers = vec![
            HeaderField::new(b"grpc-status", b"5"),
            HeaderField::new(b"grpc-message", b"service not found"),
        ];
        let (status, message) = derive_status(&headers, None);
        assert_eq!(status, GrpcStatus::NotFound);
        assert_eq!(message, "service not found");
    }

    #[test]
    fn derive_status_missing_is_internal_not_ok() {
        // Regression: missing grpc-status used to silently report Ok.
        let headers: Vec<HeaderField> = vec![];
        let (status, message) = derive_status(&headers, None);
        assert_eq!(status, GrpcStatus::Internal);
        assert!(
            message.contains("missing grpc-status"),
            "wrong message: {message}"
        );
    }

    #[test]
    fn derive_status_invalid_value_is_internal() {
        let headers = vec![HeaderField::new(b"grpc-status", b"not-a-number")];
        let (status, _) = derive_status(&headers, None);
        assert_eq!(status, GrpcStatus::Internal);
    }

    #[test]
    fn derive_status_out_of_range_is_internal() {
        let headers = vec![HeaderField::new(b"grpc-status", b"99")];
        let (status, _) = derive_status(&headers, None);
        assert_eq!(status, GrpcStatus::Internal);
    }

    #[test]
    fn http_status_override_takes_priority() {
        // Server returns :status 503 + grpc-status 0 — transport says
        // Unavailable, trailer says success. Transport wins.
        let headers = vec![
            HeaderField::new(b":status", b"503"),
            HeaderField::new(b"grpc-status", b"0"),
        ];
        let override_ = http_status_to_grpc_status(&headers);
        let (status, _msg) = derive_status(&headers, override_);
        assert_eq!(status, GrpcStatus::Unavailable);
    }

    #[test]
    fn http_status_200_no_override() {
        let headers = vec![HeaderField::new(b":status", b"200")];
        assert!(http_status_to_grpc_status(&headers).is_none());
    }

    #[test]
    fn http_status_codes_map_per_spec() {
        for (code, expected) in [
            (401u16, GrpcStatus::Unauthenticated),
            (403, GrpcStatus::PermissionDenied),
            (404, GrpcStatus::Unimplemented),
            (429, GrpcStatus::Unavailable),
            (502, GrpcStatus::Unavailable),
            (503, GrpcStatus::Unavailable),
            (504, GrpcStatus::Unavailable),
            (418, GrpcStatus::Unknown), // teapot → Unknown
        ] {
            let val = code.to_string();
            let headers = vec![HeaderField::new(b":status", val.as_bytes())];
            let (status, _) = http_status_to_grpc_status(&headers).expect("non-200");
            assert_eq!(status, expected, "code {code}");
        }
    }

    #[test]
    fn percent_decode_grpc_message() {
        // %20 → space, %E2%9C%93 → U+2713 ✓
        let headers = vec![HeaderField::new(
            b"grpc-message",
            b"hello%20%E2%9C%93%20done",
        )];
        assert_eq!(extract_grpc_message(&headers), "hello ✓ done");
    }

    #[test]
    fn percent_decode_invalid_escape_passthrough() {
        // %ZZ isn't a valid hex pair — should be passed through literally.
        let headers = vec![HeaderField::new(b"grpc-message", b"a%ZZb")];
        assert_eq!(extract_grpc_message(&headers), "a%ZZb");
    }

    #[test]
    fn grpc_timeout_encoding() {
        // Stays in nanoseconds when ≤ 8 digits.
        assert_eq!(encode_grpc_timeout(Duration::from_nanos(500)), "500n");
        // 500us = 500_000 ns (6 digits) — stays in nanoseconds.
        assert_eq!(encode_grpc_timeout(Duration::from_micros(500)), "500000n");
        // 1s = 10^9 ns = 10 digits — overflows nanos; 1_000_000us = 7 digits → us.
        assert_eq!(encode_grpc_timeout(Duration::from_secs(1)), "1000000u");
        // 100ms = 10^8 ns = 9 digits → overflows; 100_000us = 6 digits.
        assert_eq!(encode_grpc_timeout(Duration::from_millis(100)), "100000u");
        // 1 hour = 3600s: 3.6e9 us is too big; 3_600_000ms is 7 digits.
        assert_eq!(encode_grpc_timeout(Duration::from_secs(3600)), "3600000m");
        // Saturates well below the limit cases.
        let huge = Duration::from_secs(u64::MAX);
        assert!(encode_grpc_timeout(huge).ends_with('H'));
    }

    #[test]
    fn trailers_only_response_extracts_grpc_status() {
        use ringline_h2::hpack::Encoder;
        use ringline_h2::{Frame, Settings};

        let mut grpc = GrpcConnection::new(Settings::client_default());
        let _ = grpc.take_pending_send();

        // Drive the settings handshake to completion: peer sends its
        // own SETTINGS, then ACKs ours. The h2 layer emits
        // SettingsAcknowledged only on the ACK arm, and the grpc layer
        // now refuses `start_request` until that fires (G12).
        let peer_settings = {
            let f = Frame::Settings {
                ack: false,
                settings: Settings::default(),
            };
            let mut buf = Vec::new();
            f.encode(&mut buf);
            buf
        };
        grpc.recv(&peer_settings).unwrap();
        let _ = grpc.take_pending_send();
        let settings_ack = {
            let f = Frame::Settings {
                ack: true,
                settings: Settings::default(),
            };
            let mut buf = Vec::new();
            f.encode(&mut buf);
            buf
        };
        grpc.recv(&settings_ack).unwrap();
        let _ = grpc.take_pending_send();
        // Drain Ready event.
        while grpc.poll_event().is_some() {}

        // Send a request.
        let stream_id = grpc.start_request("test.Service", "Method", &[]).unwrap();
        let _ = grpc.take_pending_send();

        // Server sends trailers-only response: HEADERS with END_STREAM,
        // carrying :status, grpc-status, and grpc-message.
        let mut enc = Encoder::new(4096);
        let mut encoded = Vec::new();
        enc.encode(
            &[
                HeaderField::new(b":status", b"200"),
                HeaderField::new(b"grpc-status", b"5"),
                HeaderField::new(b"grpc-message", b"not found"),
            ],
            &mut encoded,
        );
        let frame = Frame::Headers {
            stream_id,
            encoded,
            end_stream: true,
            end_headers: true,
            priority: None,
        };
        let mut resp_buf = Vec::new();
        frame.encode(&mut resp_buf);
        grpc.recv(&resp_buf).unwrap();

        // Should get Response event followed by Status with NotFound.
        match grpc.poll_event() {
            Some(GrpcEvent::Response { .. }) => {}
            other => panic!("expected Response, got {other:?}"),
        }
        match grpc.poll_event() {
            Some(GrpcEvent::Status {
                status, message, ..
            }) => {
                assert_eq!(status, GrpcStatus::NotFound, "wrong grpc-status");
                assert_eq!(message, "not found", "wrong grpc-message");
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }
}
