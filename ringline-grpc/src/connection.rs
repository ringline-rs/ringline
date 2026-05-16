//! gRPC client connection state machine.
//!
//! `GrpcConnection` wraps an `H2Connection` and adds gRPC message framing,
//! header conventions, and status extraction from trailers.

use std::collections::{HashMap, VecDeque};

use ringline_h2::hpack::HeaderField;
use ringline_h2::settings::Settings;
use ringline_h2::{ErrorCode, H2Connection, H2Event};

use crate::error::{GrpcError, GrpcStatus};
use crate::message::{self, MessageBuffer};

/// Per-stream state for tracking the server's chosen encoding.
#[derive(Debug)]
struct StreamState {
    buffer: MessageBuffer,
    /// The encoding advertised by the server for this stream (from `grpc-encoding` header).
    encoding: Option<String>,
}

impl StreamState {
    fn new(max_message_size: usize) -> Self {
        Self {
            buffer: MessageBuffer::new(max_message_size),
            encoding: None,
        }
    }
}

/// Events produced by the gRPC connection for the application.
#[derive(Debug)]
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
    /// Returns the stream ID.
    pub fn send_unary(
        &mut self,
        service: &str,
        method: &str,
        body: &[u8],
        metadata: &[HeaderField],
    ) -> Result<u32, GrpcError> {
        let stream_id = self.send_headers(service, method, metadata, false)?;

        // Encode the gRPC length-prefixed message.
        let mut framed = Vec::new();
        message::encode(body, &mut framed);

        self.h2.send_data(stream_id, &framed, true)?;

        // Allocate a message buffer for the response.
        self.buffers
            .insert(stream_id, StreamState::new(self.max_message_size));

        Ok(stream_id)
    }

    /// Start a streaming gRPC request (headers only, no end_stream).
    ///
    /// Returns the stream ID. Use `send_message()` to send body frames.
    pub fn start_request(
        &mut self,
        service: &str,
        method: &str,
        metadata: &[HeaderField],
    ) -> Result<u32, GrpcError> {
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
        message::encode(body, &mut framed);
        self.h2.send_data(stream_id, &framed, end_stream)?;
        Ok(())
    }

    /// Cancel a stream with RST_STREAM CANCEL.
    pub fn cancel(&mut self, stream_id: u32) {
        self.h2.reset_stream(stream_id, ErrorCode::Cancel);
        self.buffers.remove(&stream_id);
    }

    // -- Internal --

    fn send_headers(
        &mut self,
        service: &str,
        method: &str,
        metadata: &[HeaderField],
        end_stream: bool,
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
                    // Ensure we have a buffer even for server-push scenarios.
                    let max = self.max_message_size;
                    self.buffers
                        .entry(stream_id)
                        .or_insert_with(|| StreamState::new(max));

                    if end_stream {
                        // Trailers-only response: HEADERS with END_STREAM carries
                        // grpc-status in the same frame (gRPC spec Section 2).
                        let status = extract_grpc_status(&headers);
                        let message = extract_grpc_message(&headers);
                        self.events.push_back(GrpcEvent::Response {
                            stream_id,
                            metadata: headers.clone(),
                        });
                        self.buffers.remove(&stream_id);
                        self.events.push_back(GrpcEvent::Status {
                            stream_id,
                            status,
                            message,
                            metadata: headers,
                        });
                    } else {
                        // Extract grpc-encoding from response headers.
                        if let Some(state) = self.buffers.get_mut(&stream_id) {
                            for h in &headers {
                                if h.name.eq_ignore_ascii_case(b"grpc-encoding") {
                                    state.encoding =
                                        Some(String::from_utf8_lossy(&h.value).into_owned());
                                }
                            }
                        }
                        self.events.push_back(GrpcEvent::Response {
                            stream_id,
                            metadata: headers,
                        });
                    }
                }
                H2Event::Data {
                    stream_id,
                    data,
                    end_stream,
                } => {
                    let max = self.max_message_size;
                    if let Some(state) = self.buffers.get_mut(&stream_id) {
                        // If the per-stream buffer fills up — the peer is
                        // sending data faster than message boundaries
                        // arrive — fail the stream rather than OOM.
                        if let Err(e) = state.buffer.push(&data) {
                            self.fail_stream(
                                stream_id,
                                GrpcStatus::ResourceExhausted,
                                e.to_string(),
                            );
                            continue;
                        }
                        loop {
                            match state.buffer.try_decode() {
                                crate::message::BufferDecode::Complete(payload, compressed) => {
                                    let data = if compressed {
                                        match &state.encoding {
                                            // Compressed flag set with a known encoding — decompress
                                            // or fail the stream with INTERNAL (do NOT silently fall
                                            // back to raw bytes; the application can't tell the
                                            // difference between a real message and our garbage).
                                            Some(enc) => match crate::compress::decompress(
                                                enc, &payload, max,
                                            ) {
                                                Ok(d) => d,
                                                Err(e) => {
                                                    self.fail_stream(
                                                        stream_id,
                                                        GrpcStatus::Internal,
                                                        format!("decompression failed: {e}"),
                                                    );
                                                    break;
                                                }
                                            },
                                            // Compressed flag set but no grpc-encoding header — peer
                                            // is malformed; treat as INTERNAL rather than silently
                                            // delivering raw compressed bytes as the message.
                                            None => {
                                                self.fail_stream(
                                                    stream_id,
                                                    GrpcStatus::Internal,
                                                    "compressed flag set but no grpc-encoding header"
                                                        .into(),
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
                                crate::message::BufferDecode::Incomplete => break,
                                crate::message::BufferDecode::TooLarge(n) => {
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
                H2Event::Trailers { stream_id, headers } => {
                    // Drain any remaining buffered messages. Decompression
                    // failures on these final messages fall through to the
                    // status emission below (we'd want to surface them but
                    // the trailer arrival is the authoritative end signal).
                    let max = self.max_message_size;
                    if let Some(state) = self.buffers.get_mut(&stream_id) {
                        while let crate::message::BufferDecode::Complete(payload, compressed) =
                            state.buffer.try_decode()
                        {
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

    /// Emit a status event when the stream ends without explicit trailers
    /// (e.g., end_stream on a DATA frame). Per the gRPC spec, every
    /// stream must end with a HEADERS frame carrying trailers — missing
    /// trailers indicates a malformed response.
    fn emit_status_from_cleanup(&mut self, stream_id: u32, _headers: &[HeaderField]) {
        self.buffers.remove(&stream_id);
        self.events.push_back(GrpcEvent::Status {
            stream_id,
            status: GrpcStatus::Internal,
            message: "stream ended without trailers".into(),
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

/// Extract `grpc-message` from trailer headers, defaulting to empty string.
fn extract_grpc_message(headers: &[HeaderField]) -> String {
    headers
        .iter()
        .find(|h| h.name == b"grpc-message")
        .and_then(|h| std::str::from_utf8(&h.value).ok())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_status_ok() {
        let headers = vec![HeaderField::new(b"grpc-status", b"0")];
        assert_eq!(extract_grpc_status(&headers), GrpcStatus::Ok);
    }

    #[test]
    fn extract_status_not_found() {
        let headers = vec![
            HeaderField::new(b"grpc-status", b"5"),
            HeaderField::new(b"grpc-message", b"service not found"),
        ];
        assert_eq!(extract_grpc_status(&headers), GrpcStatus::NotFound);
        assert_eq!(extract_grpc_message(&headers), "service not found");
    }

    #[test]
    fn extract_status_missing_defaults_to_unknown() {
        // Audit: G8. Missing grpc-status used to default to Ok, hiding
        // misbehaving servers under a successful-looking RPC.
        let headers = vec![];
        assert_eq!(extract_grpc_status(&headers), GrpcStatus::Unknown);
        assert_eq!(extract_grpc_message(&headers), "");
    }

    #[test]
    fn trailers_only_response_extracts_grpc_status() {
        use ringline_h2::hpack::Encoder;
        use ringline_h2::{Frame, Settings};

        let mut grpc = GrpcConnection::new(Settings::client_default());
        let _ = grpc.take_pending_send();

        // Settings exchange.
        let settings = {
            let f = Frame::Settings {
                ack: false,
                settings: Settings::default(),
            };
            let mut buf = Vec::new();
            f.encode(&mut buf);
            buf
        };
        grpc.recv(&settings).unwrap();
        let _ = grpc.take_pending_send();
        // Drain SettingsAcknowledged event.
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
