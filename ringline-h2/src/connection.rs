//! HTTP/2 client connection state machine.
//!
//! `H2Connection` is a sans-IO HTTP/2 client. Feed bytes in via `recv()`,
//! pull bytes out via `take_pending_send()`, and drain events with `poll_event()`.

use std::collections::{HashMap, VecDeque};

use crate::error::{ErrorCode, H2Error};
use crate::flowcontrol::{self, FlowControl};
use crate::frame::{self, Frame};
use crate::hpack::{Decoder, Encoder, HeaderField};
use crate::settings::Settings;
use crate::stream::{H2Stream, StreamState};

/// HTTP/2 connection preface (RFC 7540 Section 3.5).
const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Validate response header section per RFC 9113 §8.3 and §8.2:
/// exactly one `:status`, pseudo-headers before regular headers, no
/// connection-specific headers, lowercase names, `TE: trailers` only.
fn validate_response(headers: &[HeaderField]) -> Result<(), H2Error> {
    let mut seen_regular = false;
    let mut status_count = 0;
    for h in headers {
        if h.name.is_empty() {
            return Err(H2Error::MessageError("empty header name".into()));
        }
        let is_pseudo = h.name[0] == b':';
        if is_pseudo {
            if seen_regular {
                return Err(H2Error::MessageError(
                    "pseudo-header after regular header".into(),
                ));
            }
            // Responses may only have :status; client doesn't send back :method etc.
            if h.name.as_slice() != b":status" {
                return Err(H2Error::MessageError(format!(
                    "unexpected pseudo-header in response: {}",
                    String::from_utf8_lossy(&h.name)
                )));
            }
            status_count += 1;
            if status_count > 1 {
                return Err(H2Error::MessageError("duplicate :status".into()));
            }
        } else {
            seen_regular = true;
            validate_regular_header(h)?;
        }
    }
    if status_count == 0 {
        return Err(H2Error::MessageError(
            "missing :status pseudo-header".into(),
        ));
    }
    Ok(())
}

/// Validate a trailers header section per RFC 9113 §8.1: no pseudo-headers
/// allowed, plus the usual regular-header rules.
fn validate_trailers(headers: &[HeaderField]) -> Result<(), H2Error> {
    for h in headers {
        if h.name.is_empty() {
            return Err(H2Error::MessageError("empty header name".into()));
        }
        if h.name[0] == b':' {
            return Err(H2Error::MessageError("pseudo-header in trailers".into()));
        }
        validate_regular_header(h)?;
    }
    Ok(())
}

fn validate_regular_header(h: &HeaderField) -> Result<(), H2Error> {
    // RFC 9113 §8.2.1: header names must be lowercase (excluding pseudo
    // names, handled above).
    for &b in &h.name {
        if b.is_ascii_uppercase() {
            return Err(H2Error::MessageError(format!(
                "uppercase header name: {}",
                String::from_utf8_lossy(&h.name)
            )));
        }
    }
    // RFC 9113 §8.2.2: connection-specific headers are forbidden in HTTP/2.
    let forbidden: &[&[u8]] = &[
        b"connection",
        b"proxy-connection",
        b"keep-alive",
        b"transfer-encoding",
        b"upgrade",
    ];
    if forbidden.contains(&h.name.as_slice()) {
        return Err(H2Error::MessageError(format!(
            "connection-specific header forbidden in HTTP/2: {}",
            String::from_utf8_lossy(&h.name)
        )));
    }
    // RFC 9113 §8.2.2: `TE` header may only contain `trailers`.
    if h.name.as_slice() == b"te" && h.value.as_slice() != b"trailers" {
        return Err(H2Error::MessageError(
            "TE header may only contain `trailers` in HTTP/2".into(),
        ));
    }
    Ok(())
}

/// Auto WINDOW_UPDATE threshold: send update when half the window is consumed.
const WINDOW_UPDATE_THRESHOLD: i64 = 32768;

/// Maximum stream identifier (RFC 7540 §5.1.1). When `next_stream_id`
/// would exceed this, `send_request` fails — the connection must be
/// recycled.
const MAX_STREAM_ID: u32 = 0x7fff_ffff;

/// Default cap on the in-process recv buffer. A peer can dribble in
/// partial frames; without a cap, ringline would buffer everything before
/// having a chance to detect the protocol error. 256 KiB is large enough
/// for several default-sized (16 KiB) frames in flight while bounding the
/// worst case. Configurable via `H2Connection::set_max_recv_buf`.
pub const DEFAULT_MAX_RECV_BUF: usize = 262_144;

/// Events produced by the HTTP/2 connection for the application.
#[derive(Debug)]
pub enum H2Event {
    /// Received response headers on a stream.
    Response {
        stream_id: u32,
        headers: Vec<HeaderField>,
        end_stream: bool,
    },
    /// Received response body data on a stream.
    Data {
        stream_id: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    /// Received trailing headers on a stream.
    Trailers {
        stream_id: u32,
        headers: Vec<HeaderField>,
    },
    /// Stream was reset by the peer.
    StreamReset {
        stream_id: u32,
        error_code: ErrorCode,
    },
    /// Peer sent GOAWAY.
    GoAway {
        last_stream_id: u32,
        error_code: ErrorCode,
        debug_data: Vec<u8>,
    },
    /// Peer acknowledged our PING.
    PingAcknowledged { opaque_data: [u8; 8] },
    /// Peer acknowledged our SETTINGS.
    SettingsAcknowledged,
    /// Connection-level error.
    Error(H2Error),
}

/// Internal connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnState {
    /// Waiting for server preface (SETTINGS frame).
    WaitingPreface,
    /// SETTINGS exchanged, ready for requests.
    Ready,
    /// GOAWAY sent or received.
    Closing,
    /// Connection closed.
    Closed,
}

/// Client-side HTTP/2 connection.
///
/// Pure sans-IO: feed received bytes via `recv()`, take outgoing bytes via
/// `take_pending_send()`, drain events with `poll_event()`.
pub struct H2Connection {
    state: ConnState,
    local_settings: Settings,
    remote_settings: Settings,

    /// Per-stream state, keyed by stream ID.
    streams: HashMap<u32, H2Stream>,

    /// Next client stream ID (odd numbers, starting at 1).
    next_stream_id: u32,

    /// Connection-level flow control for receiving.
    conn_recv_window: FlowControl,
    /// Connection-level flow control for sending.
    conn_send_window: FlowControl,

    /// HPACK encoder (client -> server).
    encoder: Encoder,
    /// HPACK decoder (server -> client).
    decoder: Decoder,

    /// Stream ID currently receiving a header block (HEADERS + CONTINUATION).
    /// No other frames may interleave until END_HEADERS.
    continuation_stream: Option<u32>,

    /// Incoming data buffer (accumulated from recv() calls).
    recv_buf: Vec<u8>,
    /// Outgoing data buffer (drained by take_pending_send()).
    send_buf: Vec<u8>,

    /// Application-visible event queue.
    events: VecDeque<H2Event>,

    /// Track initial recv window to calculate WINDOW_UPDATE.
    initial_recv_window: i64,

    /// Cap on `recv_buf` size — guards against a peer dribbling in partial
    /// frames to exhaust memory before we get a chance to detect the
    /// protocol violation.
    max_recv_buf: usize,

    /// Have we received any frame yet? The first frame from the server
    /// MUST be SETTINGS per RFC 7540 §3.5; we track this to fail loudly
    /// on a malformed preface instead of silently limping along.
    received_any_frame: bool,
}

impl H2Connection {
    /// Create a new client-side HTTP/2 connection.
    ///
    /// Queues the client connection preface (magic + SETTINGS) into the send buffer.
    pub fn new(settings: Settings) -> Self {
        let mut send_buf = Vec::new();

        // Send client connection preface.
        send_buf.extend_from_slice(CLIENT_PREFACE);

        // Send our SETTINGS frame.
        let settings_frame = Frame::Settings {
            ack: false,
            settings: settings.clone(),
        };
        settings_frame.encode(&mut send_buf);

        // Send connection-level WINDOW_UPDATE if our initial window > 65535.
        let initial_recv = settings.initial_window_size as i64;
        if initial_recv > flowcontrol::DEFAULT_WINDOW_SIZE {
            let increment = (initial_recv - flowcontrol::DEFAULT_WINDOW_SIZE) as u32;
            let wu = Frame::WindowUpdate {
                stream_id: 0,
                increment,
            };
            wu.encode(&mut send_buf);
        }

        Self {
            state: ConnState::WaitingPreface,
            local_settings: settings.clone(),
            remote_settings: Settings::default(),
            streams: HashMap::new(),
            next_stream_id: 1,
            conn_recv_window: FlowControl::new(initial_recv),
            conn_send_window: FlowControl::default(),
            encoder: Encoder::new(settings.header_table_size as usize),
            decoder: Decoder::new(4096), // remote default until SETTINGS received
            continuation_stream: None,
            recv_buf: Vec::new(),
            send_buf,
            events: VecDeque::new(),
            initial_recv_window: initial_recv,
            max_recv_buf: DEFAULT_MAX_RECV_BUF,
            received_any_frame: false,
        }
    }

    /// Set the maximum number of bytes the connection will hold in its
    /// receive buffer awaiting frame parsing. Defaults to
    /// [`DEFAULT_MAX_RECV_BUF`]. The cap protects against a peer that
    /// dribbles in arbitrarily many partial frames before the framing layer
    /// can detect a protocol error.
    pub fn set_max_recv_buf(&mut self, n: usize) {
        self.max_recv_buf = n;
    }

    /// Feed received bytes from the transport.
    pub fn recv(&mut self, data: &[u8]) -> Result<(), H2Error> {
        if matches!(self.state, ConnState::Closing | ConnState::Closed) {
            return Ok(());
        }
        if self.recv_buf.len().saturating_add(data.len()) > self.max_recv_buf {
            // The peer is sending more data than we can buffer waiting for a
            // complete frame. Close the connection cleanly so the peer learns
            // that we have given up on it (instead of an OS-level RST when
            // we eventually run out of memory).
            self.fatal_error(H2Error::MaxSizeExceeded(format!(
                "recv_buf would exceed {} bytes",
                self.max_recv_buf
            )));
            return Ok(());
        }
        self.recv_buf.extend_from_slice(data);
        self.process_recv_buf()
    }

    /// Send a GOAWAY with the appropriate error code, transition to
    /// `Closing`, and emit an `Error` event. RFC 7540 §5.4.1: an endpoint
    /// that encounters a connection error SHOULD send a GOAWAY before
    /// closing.
    fn fatal_error(&mut self, err: H2Error) {
        if matches!(self.state, ConnState::Closing | ConnState::Closed) {
            return;
        }
        let code = err.code();
        let last_stream_id = self.next_stream_id.saturating_sub(2);
        let goaway = Frame::GoAway {
            last_stream_id,
            error_code: code,
            debug_data: Vec::new(),
        };
        goaway.encode(&mut self.send_buf);
        self.state = ConnState::Closing;
        self.events.push_back(H2Event::Error(err));
    }

    /// Poll the next event, if any.
    pub fn poll_event(&mut self) -> Option<H2Event> {
        self.events.pop_front()
    }

    /// Take all pending bytes to send to the transport.
    pub fn take_pending_send(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.send_buf)
    }

    /// Whether there are bytes pending to send.
    pub fn has_pending_send(&self) -> bool {
        !self.send_buf.is_empty()
    }

    /// Send a request. Returns the stream ID.
    ///
    /// `headers` should include pseudo-headers (:method, :path, :scheme, :authority).
    pub fn send_request(
        &mut self,
        headers: &[HeaderField],
        end_stream: bool,
    ) -> Result<u32, H2Error> {
        if self.state == ConnState::Closed || self.state == ConnState::Closing {
            return Err(H2Error::ConnectionError(ErrorCode::RefusedStream));
        }

        // Enforce MAX_CONCURRENT_STREAMS from the server's SETTINGS.
        if let Some(max) = self.remote_settings.max_concurrent_streams {
            let active = self
                .streams
                .values()
                .filter(|s| !matches!(s.state, StreamState::Closed))
                .count() as u32;
            if active >= max {
                return Err(H2Error::ConnectionError(ErrorCode::RefusedStream));
            }
        }

        // RFC 7540 §5.1.1: stream IDs are 31-bit. Once we've exhausted
        // the space, the connection must be recycled — silent wrap to small
        // IDs would violate the "monotonically increasing" requirement.
        if self.next_stream_id > MAX_STREAM_ID {
            return Err(H2Error::ConnectionError(ErrorCode::RefusedStream));
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.saturating_add(2);

        // Encode headers with HPACK.
        let mut encoded = Vec::new();
        self.encoder.encode(headers, &mut encoded);

        // Create HEADERS frame.
        let frame = Frame::Headers {
            stream_id,
            encoded,
            end_stream,
            end_headers: true,
            priority: None,
        };
        frame.encode(&mut self.send_buf);

        // Create stream state.
        let initial_send = self.remote_settings.initial_window_size as i64;
        let mut stream = H2Stream::new(self.initial_recv_window, initial_send);
        if end_stream {
            stream.state = StreamState::HalfClosedLocal;
        }
        self.streams.insert(stream_id, stream);

        Ok(stream_id)
    }

    /// Send DATA on a stream.
    pub fn send_data(
        &mut self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
    ) -> Result<(), H2Error> {
        // Check stream state.
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(H2Error::Internal("unknown stream".into()))?;

        match stream.state {
            StreamState::Open | StreamState::HalfClosedRemote => {}
            _ => {
                return Err(H2Error::StreamError(stream_id, ErrorCode::StreamClosed));
            }
        }

        // Check both flow control windows have capacity before consuming
        // either. This prevents leaking one window if the other check fails.
        let len = data.len() as u32;
        if len > 0 {
            if stream.send_window.window() < i64::from(len) {
                return Err(H2Error::FlowControlError);
            }
            if self.conn_send_window.window() < i64::from(len) {
                return Err(H2Error::FlowControlError);
            }
            // Both checks passed — consume is infallible now.
            let _ = stream.send_window.consume(len);
            let _ = self.conn_send_window.consume(len);
        }

        // Split data into frames respecting the remote peer's MAX_FRAME_SIZE.
        let max_frame = self.remote_settings.max_frame_size as usize;
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(max_frame).collect()
        };
        let last_idx = chunks.len() - 1;

        for (i, chunk) in chunks.iter().enumerate() {
            let is_last_chunk = i == last_idx;
            let frame = Frame::Data {
                stream_id,
                payload: chunk.to_vec(),
                end_stream: end_stream && is_last_chunk,
            };
            frame.encode(&mut self.send_buf);
        }

        if end_stream {
            let stream = self.streams.get_mut(&stream_id).unwrap();
            stream.state = match stream.state {
                StreamState::HalfClosedRemote => StreamState::Closed,
                _ => StreamState::HalfClosedLocal,
            };
        }

        Ok(())
    }

    /// Reset a stream with an error code.
    pub fn reset_stream(&mut self, stream_id: u32, error_code: ErrorCode) {
        let frame = Frame::RstStream {
            stream_id,
            error_code,
        };
        frame.encode(&mut self.send_buf);
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = StreamState::Closed;
        }
    }

    /// Send a PING frame.
    pub fn send_ping(&mut self) {
        let frame = Frame::Ping {
            ack: false,
            opaque_data: [0; 8],
        };
        frame.encode(&mut self.send_buf);
    }

    /// Send a GOAWAY frame.
    pub fn send_goaway(&mut self, error_code: ErrorCode) {
        let last_stream_id = 0; // We're the client; no server-initiated streams.
        let frame = Frame::GoAway {
            last_stream_id,
            error_code,
            debug_data: Vec::new(),
        };
        frame.encode(&mut self.send_buf);
        self.state = ConnState::Closing;
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.state == ConnState::Closed
    }

    // -- Internal processing --

    fn process_recv_buf(&mut self) -> Result<(), H2Error> {
        loop {
            if matches!(self.state, ConnState::Closing | ConnState::Closed) {
                break;
            }
            let max_frame = self.local_settings.max_frame_size;
            match frame::decode_frame(&self.recv_buf, max_frame) {
                Ok(Some((frame, consumed))) => {
                    self.recv_buf.drain(..consumed);
                    if let Err(e) = self.handle_frame(frame) {
                        self.fatal_error(e);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    self.recv_buf.clear();
                    self.fatal_error(e);
                }
            }
        }
        Ok(())
    }

    fn handle_frame(&mut self, frame: Frame) -> Result<(), H2Error> {
        // RFC 7540 §3.5: the first frame from the server MUST be a SETTINGS
        // frame (potentially empty, never ACK). Reject anything else as a
        // PROTOCOL_ERROR rather than silently letting the connection limp
        // along until something stream-related blows up.
        if !self.received_any_frame {
            match &frame {
                Frame::Settings { ack: false, .. } => {}
                _ => {
                    return Err(H2Error::ProtocolError(
                        "first server frame must be SETTINGS".into(),
                    ));
                }
            }
        }
        self.received_any_frame = true;

        // CONTINUATION enforcement: if we're in a header block, only
        // CONTINUATION frames for that stream are allowed. And conversely,
        // a CONTINUATION outside of an active header block is a PROTOCOL_ERROR
        // (RFC 7540 §6.10).
        if let Some(expected_sid) = self.continuation_stream {
            match &frame {
                Frame::Continuation { stream_id, .. } if *stream_id == expected_sid => {
                    // OK, process below.
                }
                _ => {
                    return Err(H2Error::ProtocolError("expected CONTINUATION frame".into()));
                }
            }
        } else if matches!(frame, Frame::Continuation { .. }) {
            return Err(H2Error::ProtocolError(
                "CONTINUATION without preceding HEADERS without END_HEADERS".into(),
            ));
        }

        match frame {
            Frame::Settings { ack, settings } => {
                self.handle_settings(ack, settings)?;
            }
            Frame::Headers {
                stream_id,
                encoded,
                end_stream,
                end_headers,
                ..
            } => {
                self.handle_headers(stream_id, encoded, end_stream, end_headers)?;
            }
            Frame::Continuation {
                stream_id,
                encoded,
                end_headers,
            } => {
                self.handle_continuation(stream_id, encoded, end_headers)?;
            }
            Frame::Data {
                stream_id,
                payload,
                end_stream,
            } => {
                self.handle_data(stream_id, payload, end_stream)?;
            }
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                // Remove the stream rather than just marking it closed —
                // ringline never sends frames on a stream we've reset, and
                // keeping the entry around forever leaks per-stream state
                // for the lifetime of the connection.
                self.streams.remove(&stream_id);
                self.events.push_back(H2Event::StreamReset {
                    stream_id,
                    error_code,
                });
            }
            Frame::Ping { ack, opaque_data } => {
                if ack {
                    self.events
                        .push_back(H2Event::PingAcknowledged { opaque_data });
                } else {
                    // Respond with PING ACK.
                    let pong = Frame::Ping {
                        ack: true,
                        opaque_data,
                    };
                    pong.encode(&mut self.send_buf);
                }
            }
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                self.state = ConnState::Closing;
                self.events.push_back(H2Event::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                });
                // Per RFC 7540 Section 6.8: streams with IDs > last_stream_id
                // were never processed. Reset them so waiting callers get notified.
                let to_reset: Vec<u32> = self
                    .streams
                    .keys()
                    .filter(|&&id| id > last_stream_id)
                    .copied()
                    .collect();
                for id in to_reset {
                    self.streams.remove(&id);
                    self.events.push_back(H2Event::StreamReset {
                        stream_id: id,
                        error_code: ErrorCode::RefusedStream,
                    });
                }
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                self.handle_window_update(stream_id, increment)?;
            }
            Frame::Priority { .. } => {
                // Priority is advisory; ignore.
            }
            Frame::PushPromise { .. } => {
                // We sent ENABLE_PUSH=0, so this is a protocol error.
                if !self.local_settings.enable_push {
                    return Err(H2Error::ProtocolError(
                        "PUSH_PROMISE received but ENABLE_PUSH=0".into(),
                    ));
                }
            }
            Frame::Unknown { .. } => {
                // Unknown frame types MUST be ignored.
            }
        }

        Ok(())
    }

    fn handle_settings(&mut self, ack: bool, settings: Settings) -> Result<(), H2Error> {
        if ack {
            self.events.push_back(H2Event::SettingsAcknowledged);
            return Ok(());
        }

        // Apply remote settings.
        let old_initial_window = self.remote_settings.initial_window_size as i64;
        let new_initial_window = settings.initial_window_size as i64;
        let delta = new_initial_window - old_initial_window;

        self.remote_settings = settings;

        // Update HPACK encoder max table size from remote settings.
        // The remote peer's HEADER_TABLE_SIZE limits what our encoder can reference
        // (RFC 7541 Section 6.3). The size update is emitted at the start of the
        // next header block.
        self.encoder
            .update_max_table_size(self.remote_settings.header_table_size as usize);

        // Adjust send windows on all open streams (RFC 7540 Section 6.9.2).
        if delta != 0 {
            for stream in self.streams.values_mut() {
                if stream.state != StreamState::Closed {
                    stream.send_window.adjust(delta)?;
                }
            }
        }

        // Send SETTINGS ACK.
        let ack_frame = Frame::Settings {
            ack: true,
            settings: Settings::default(),
        };
        ack_frame.encode(&mut self.send_buf);

        if self.state == ConnState::WaitingPreface {
            self.state = ConnState::Ready;
        }

        Ok(())
    }

    fn handle_headers(
        &mut self,
        stream_id: u32,
        encoded: Vec<u8>,
        end_stream: bool,
        end_headers: bool,
    ) -> Result<(), H2Error> {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => {
                // We're a client. Streams we initiated are odd; HEADERS on
                // an unknown odd stream means the peer is referring to a
                // stream we never opened (or already GC'd) — RFC 7540
                // §5.1.1: PROTOCOL_ERROR. Even-numbered HEADERS would be a
                // server push, which we don't implement, so reject those
                // too. The peer has misbehaved either way.
                return Err(H2Error::ProtocolError(format!(
                    "HEADERS on unknown stream {stream_id}"
                )));
            }
        };

        if end_headers {
            // Complete header block in a single frame.
            let mut full_block = std::mem::take(&mut stream.header_buf);
            full_block.extend_from_slice(&encoded);
            self.decode_and_emit_headers(stream_id, &full_block, end_stream)?;
        } else {
            // Start of a multi-frame header block.
            stream.header_buf.extend_from_slice(&encoded);
            stream.receiving_headers = true;
            stream.headers_end_stream = end_stream;
            self.continuation_stream = Some(stream_id);
        }

        Ok(())
    }

    fn handle_continuation(
        &mut self,
        stream_id: u32,
        encoded: Vec<u8>,
        end_headers: bool,
    ) -> Result<(), H2Error> {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(()),
        };

        stream.header_buf.extend_from_slice(&encoded);

        if end_headers {
            self.continuation_stream = None;
            let full_block = {
                let stream = self.streams.get_mut(&stream_id).unwrap();
                stream.receiving_headers = false;
                std::mem::take(&mut stream.header_buf)
            };
            let end_stream = self
                .streams
                .get(&stream_id)
                .map(|s| s.headers_end_stream)
                .unwrap_or(false);
            self.decode_and_emit_headers(stream_id, &full_block, end_stream)?;
        }

        Ok(())
    }

    fn decode_and_emit_headers(
        &mut self,
        stream_id: u32,
        encoded: &[u8],
        end_stream: bool,
    ) -> Result<(), H2Error> {
        // Enforce SETTINGS_MAX_HEADER_LIST_SIZE on the *encoded* bytes too —
        // a malformed peer can otherwise force us to run HPACK decode over
        // an oversize buffer before we'd notice the post-decode total.
        if let Some(max) = self.local_settings.max_header_list_size
            && (encoded.len() as u64) > u64::from(max)
        {
            return Err(H2Error::MaxSizeExceeded(format!(
                "header block ({} bytes) exceeds SETTINGS_MAX_HEADER_LIST_SIZE ({max})",
                encoded.len()
            )));
        }

        let headers = self.decoder.decode(encoded)?;

        // Decoded header-list-size check (RFC 7541 §4.1: 32 bytes per
        // entry + name/value sizes).
        if let Some(max) = self.local_settings.max_header_list_size {
            let total: u64 = headers
                .iter()
                .map(|h| (h.name.len() + h.value.len() + 32) as u64)
                .sum();
            if total > u64::from(max) {
                return Err(H2Error::MaxSizeExceeded(format!(
                    "decoded header list size {total} exceeds SETTINGS_MAX_HEADER_LIST_SIZE ({max})"
                )));
            }
        }

        // `handle_headers` rejects unknown streams up-front, so by the time
        // we land here the stream is known (or it was GC'd between frames
        // of a multi-CONTINUATION block; in that race we silently drop).
        let stream = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(()),
        };

        // Once we've delivered the initial response HEADERS on this stream,
        // any subsequent HEADERS is trailers. Stream state alone can't
        // disambiguate: an initial HEADERS without END_STREAM leaves the
        // state in HalfClosedLocal, and the trailing HEADERS arrives with
        // the state still HalfClosedLocal — the two look identical to the
        // state machine.
        let is_initial_response = !stream.received_initial_response;

        // Validate header section semantics before mutating any state.
        if is_initial_response {
            validate_response(&headers)?;
        } else {
            validate_trailers(&headers)?;
            if !end_stream {
                // Trailers must close the stream (RFC 9113 §8.1).
                return Err(H2Error::ProtocolError("trailers without END_STREAM".into()));
            }
        }

        if is_initial_response {
            stream.received_initial_response = true;
        }
        if end_stream {
            stream.state = match stream.state {
                StreamState::HalfClosedLocal => StreamState::Closed,
                _ => StreamState::HalfClosedRemote,
            };
        }
        let stream_closed = stream.state == StreamState::Closed;

        if is_initial_response {
            self.events.push_back(H2Event::Response {
                stream_id,
                headers,
                end_stream,
            });
        } else {
            self.events
                .push_back(H2Event::Trailers { stream_id, headers });
        }

        if stream_closed {
            self.streams.remove(&stream_id);
        }

        Ok(())
    }

    fn handle_data(
        &mut self,
        stream_id: u32,
        payload: Vec<u8>,
        end_stream: bool,
    ) -> Result<(), H2Error> {
        let data_len = payload.len() as u32;

        // Update connection-level receive window. The peer's flow-control
        // accounting requires us to debit it regardless of whether we know
        // about the stream; otherwise the two views diverge.
        if data_len > 0 {
            self.conn_recv_window.consume(data_len)?;
        }

        let stream = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => {
                // Unknown / already-closed stream — reply with RST_STREAM
                // per RFC 7540 §5.1, and replenish the connection window we
                // just debited so we don't starve ourselves on garbage.
                if data_len > 0 {
                    let _ = self.conn_recv_window.increase(data_len);
                    let wu = Frame::WindowUpdate {
                        stream_id: 0,
                        increment: data_len,
                    };
                    wu.encode(&mut self.send_buf);
                }
                let rst = Frame::RstStream {
                    stream_id,
                    error_code: ErrorCode::StreamClosed,
                };
                rst.encode(&mut self.send_buf);
                return Ok(());
            }
        };

        // RFC 7540 §5.1: receiving DATA on a fully-closed or half-closed-remote
        // stream is a STREAM_CLOSED stream error.
        if matches!(
            stream.state,
            StreamState::Closed | StreamState::HalfClosedRemote
        ) {
            // Replenish connection window — peer was wrong, but we still
            // accounted for the bytes.
            if data_len > 0 {
                let _ = self.conn_recv_window.increase(data_len);
                let wu = Frame::WindowUpdate {
                    stream_id: 0,
                    increment: data_len,
                };
                wu.encode(&mut self.send_buf);
            }
            let rst = Frame::RstStream {
                stream_id,
                error_code: ErrorCode::StreamClosed,
            };
            rst.encode(&mut self.send_buf);
            stream.state = StreamState::Closed;
            self.streams.remove(&stream_id);
            return Ok(());
        }

        // Update stream-level receive window.
        if data_len > 0 {
            stream.recv_window.consume(data_len)?;
        }

        let mut stream_closed = false;
        if end_stream {
            stream.state = match stream.state {
                StreamState::HalfClosedLocal => StreamState::Closed,
                _ => StreamState::HalfClosedRemote,
            };
            stream_closed = stream.state == StreamState::Closed;
        }

        self.events.push_back(H2Event::Data {
            stream_id,
            data: payload,
            end_stream,
        });

        // Auto-send WINDOW_UPDATE when significant data consumed.
        self.maybe_send_window_updates(stream_id, data_len);

        if stream_closed {
            self.streams.remove(&stream_id);
        }

        Ok(())
    }

    fn handle_window_update(&mut self, stream_id: u32, increment: u32) -> Result<(), H2Error> {
        if stream_id == 0 {
            self.conn_send_window.increase(increment)?;
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.send_window.increase(increment)?;
        }
        Ok(())
    }

    fn maybe_send_window_updates(&mut self, stream_id: u32, data_len: u32) {
        if data_len == 0 {
            return;
        }

        // Connection-level WINDOW_UPDATE.
        if self.conn_recv_window.window() < WINDOW_UPDATE_THRESHOLD {
            let increment = (self.initial_recv_window - self.conn_recv_window.window()) as u32;
            if increment > 0 {
                let frame = Frame::WindowUpdate {
                    stream_id: 0,
                    increment,
                };
                frame.encode(&mut self.send_buf);
                let _ = self.conn_recv_window.increase(increment);
            }
        }

        // Stream-level WINDOW_UPDATE.
        if let Some(stream) = self.streams.get_mut(&stream_id)
            && stream.state != StreamState::Closed
            && stream.state != StreamState::HalfClosedRemote
            && stream.recv_window.window() < WINDOW_UPDATE_THRESHOLD
        {
            let increment = (self.initial_recv_window - stream.recv_window.window()) as u32;
            if increment > 0 {
                let frame = Frame::WindowUpdate {
                    stream_id,
                    increment,
                };
                frame.encode(&mut self.send_buf);
                let _ = stream.recv_window.increase(increment);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_settings_frame(settings: &Settings, ack: bool) -> Vec<u8> {
        let frame = Frame::Settings {
            ack,
            settings: settings.clone(),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        buf
    }

    #[test]
    fn connection_preface_includes_magic_and_settings() {
        let conn = H2Connection::new(Settings::client_default());
        let send = conn.send_buf.clone();

        // Starts with client preface magic.
        assert!(send.starts_with(CLIENT_PREFACE));

        // After the magic should be a SETTINGS frame.
        let after_magic = &send[CLIENT_PREFACE.len()..];
        let header = frame::decode_frame_header(after_magic).unwrap();
        assert_eq!(header.frame_type, frame::FRAME_SETTINGS);
        assert_eq!(header.flags, 0); // not ACK
        assert_eq!(header.stream_id, 0);
    }

    #[test]
    fn settings_exchange() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send(); // discard preface

        // Simulate server sending SETTINGS.
        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();

        // Connection should transition to Ready.
        assert_eq!(conn.state, ConnState::Ready);

        // Should have queued a SETTINGS ACK.
        let send = conn.take_pending_send();
        let header = frame::decode_frame_header(&send).unwrap();
        assert_eq!(header.frame_type, frame::FRAME_SETTINGS);
        assert_eq!(header.flags, frame::FLAG_ACK);
    }

    #[test]
    fn send_request_and_receive_response() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        // Server sends SETTINGS.
        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send(); // SETTINGS ACK

        // Send a GET request.
        let headers = vec![
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b":path", b"/"),
            HeaderField::new(b":scheme", b"https"),
            HeaderField::new(b":authority", b"example.com"),
        ];
        let stream_id = conn.send_request(&headers, true).unwrap();
        assert_eq!(stream_id, 1);

        // The send buffer should contain a HEADERS frame.
        let send = conn.take_pending_send();
        let header = frame::decode_frame_header(&send).unwrap();
        assert_eq!(header.frame_type, frame::FRAME_HEADERS);
        assert_eq!(header.stream_id, 1);
        assert_ne!(header.flags & frame::FLAG_END_STREAM, 0);
        assert_ne!(header.flags & frame::FLAG_END_HEADERS, 0);

        // Simulate server response: HEADERS with :status 200.
        let mut response_encoder = Encoder::new(4096);
        let mut encoded_response = Vec::new();
        response_encoder.encode(
            &[HeaderField::new(b":status", b"200")],
            &mut encoded_response,
        );
        let resp_frame = Frame::Headers {
            stream_id: 1,
            encoded: encoded_response,
            end_stream: false,
            end_headers: true,
            priority: None,
        };
        let mut resp_buf = Vec::new();
        resp_frame.encode(&mut resp_buf);
        conn.recv(&resp_buf).unwrap();

        let event = conn.poll_event().unwrap();
        match event {
            H2Event::Response {
                stream_id: sid,
                headers: h,
                end_stream: es,
            } => {
                assert_eq!(sid, 1);
                assert!(!es);
                assert_eq!(h[0].name, b":status");
                assert_eq!(h[0].value, b"200");
            }
            _ => panic!("expected Response event, got {event:?}"),
        }
    }

    #[test]
    fn ping_response() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        // Server sends SETTINGS.
        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send();

        // Server sends PING.
        let ping = Frame::Ping {
            ack: false,
            opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut ping_buf = Vec::new();
        ping.encode(&mut ping_buf);
        conn.recv(&ping_buf).unwrap();

        // Should auto-respond with PING ACK.
        let send = conn.take_pending_send();
        let (decoded, _) = frame::decode_frame(&send, 16384).unwrap().unwrap();
        match decoded {
            Frame::Ping { ack, opaque_data } => {
                assert!(ack);
                assert_eq!(opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
            }
            _ => panic!("expected Ping ACK"),
        }
    }

    #[test]
    fn ping_ack_event() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        // Server sends SETTINGS.
        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send();
        // Drain SettingsAcknowledged event.
        while conn.poll_event().is_some() {}

        // Client sends PING.
        conn.send_ping();
        let _ = conn.take_pending_send();

        // Server responds with PING ACK.
        let ping_ack = Frame::Ping {
            ack: true,
            opaque_data: [0; 8],
        };
        let mut buf = Vec::new();
        ping_ack.encode(&mut buf);
        conn.recv(&buf).unwrap();

        // Should emit PingAcknowledged event.
        match conn.poll_event() {
            Some(H2Event::PingAcknowledged { opaque_data }) => {
                assert_eq!(opaque_data, [0; 8]);
            }
            other => panic!("expected PingAcknowledged, got {other:?}"),
        }
    }

    #[test]
    fn goaway_handling() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send();

        let goaway = Frame::GoAway {
            last_stream_id: 0,
            error_code: ErrorCode::NoError,
            debug_data: Vec::new(),
        };
        let mut buf = Vec::new();
        goaway.encode(&mut buf);
        conn.recv(&buf).unwrap();

        assert_eq!(conn.state, ConnState::Closing);
        match conn.poll_event().unwrap() {
            H2Event::GoAway { error_code, .. } => assert_eq!(error_code, ErrorCode::NoError),
            e => panic!("expected GoAway, got {e:?}"),
        }
    }

    #[test]
    fn stream_ids_increment() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send();

        let headers = vec![HeaderField::new(b":method", b"GET")];
        let s1 = conn.send_request(&headers, true).unwrap();
        let s2 = conn.send_request(&headers, true).unwrap();
        let s3 = conn.send_request(&headers, true).unwrap();
        assert_eq!(s1, 1);
        assert_eq!(s2, 3);
        assert_eq!(s3, 5);
    }

    #[test]
    fn window_update_on_data() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send();

        // Open a stream.
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let stream_id = conn.send_request(&headers, true).unwrap();
        let _ = conn.take_pending_send();

        // Simulate server sending response headers.
        let mut enc = Encoder::new(4096);
        let mut encoded = Vec::new();
        enc.encode(&[HeaderField::new(b":status", b"200")], &mut encoded);
        let resp = Frame::Headers {
            stream_id,
            encoded,
            end_stream: false,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        conn.recv(&buf).unwrap();
        let _ = conn.poll_event(); // Response event
        let _ = conn.take_pending_send();

        // Simulate server sending multiple DATA frames that exceed the
        // WINDOW_UPDATE threshold (each must be <= max_frame_size=16384).
        let mut data_buf = Vec::new();
        for _ in 0..4 {
            let chunk = vec![0u8; 10000];
            let data_frame = Frame::Data {
                stream_id,
                payload: chunk,
                end_stream: false,
            };
            data_frame.encode(&mut data_buf);
        }
        conn.recv(&data_buf).unwrap();

        // Should have generated WINDOW_UPDATE frames (40000 bytes consumed,
        // window drops to 25535 which is below the 32768 threshold).
        let send = conn.take_pending_send();
        assert!(!send.is_empty(), "expected WINDOW_UPDATE frames");
    }

    #[test]
    fn decode_error_emits_single_event_and_transitions_to_closing() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        // Complete settings exchange so we're in Ready state.
        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send();
        while conn.poll_event().is_some() {}

        // Feed a SETTINGS frame with invalid length (must be multiple of 6).
        let bad_settings = [
            0x00, 0x00, 0x05, // length = 5 (not multiple of 6)
            0x04, // type = SETTINGS
            0x00, // flags
            0x00, 0x00, 0x00, 0x00, // stream id 0
            0x00, 0x01, 0x02, 0x03, 0x04, // 5 bytes (invalid)
        ];
        conn.recv(&bad_settings).unwrap();

        // Should have exactly one error event.
        let event = conn.poll_event();
        assert!(
            matches!(event, Some(H2Event::Error(_))),
            "expected Error event, got {event:?}"
        );

        // No more events.
        assert!(conn.poll_event().is_none(), "expected no more events");

        // State should be Closing.
        assert_eq!(conn.state, ConnState::Closing);

        // Feeding more data should not produce additional error events.
        conn.recv(&bad_settings).unwrap();
        assert!(
            conn.poll_event().is_none(),
            "expected no events after Closing"
        );
    }

    #[test]
    fn goaway_resets_streams_above_last_stream_id() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        // Settings exchange.
        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send();
        while conn.poll_event().is_some() {}

        // Open 3 streams: 1, 3, 5.
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let s1 = conn.send_request(&headers, true).unwrap();
        let s3 = conn.send_request(&headers, true).unwrap();
        let s5 = conn.send_request(&headers, true).unwrap();
        let _ = conn.take_pending_send();
        assert_eq!(s1, 1);
        assert_eq!(s3, 3);
        assert_eq!(s5, 5);

        // Server sends GOAWAY with last_stream_id = 1.
        let goaway = Frame::GoAway {
            last_stream_id: 1,
            error_code: ErrorCode::NoError,
            debug_data: Vec::new(),
        };
        let mut buf = Vec::new();
        goaway.encode(&mut buf);
        conn.recv(&buf).unwrap();

        // Should get GoAway event + StreamReset for streams 3 and 5.
        let mut got_goaway = false;
        let mut reset_ids = Vec::new();
        while let Some(event) = conn.poll_event() {
            match event {
                H2Event::GoAway { .. } => got_goaway = true,
                H2Event::StreamReset { stream_id, .. } => reset_ids.push(stream_id),
                _ => {}
            }
        }
        assert!(got_goaway, "expected GoAway event");
        reset_ids.sort();
        assert_eq!(
            reset_ids,
            vec![3, 5],
            "expected streams 3 and 5 to be reset"
        );
    }

    // -- Audit tests: RFC conformance + robustness --

    fn settled_conn() -> H2Connection {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();
        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send();
        while conn.poll_event().is_some() {}
        conn
    }

    #[test]
    fn first_frame_must_be_settings() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        // Server "preface" is actually a PING — must be rejected.
        let ping = Frame::Ping {
            ack: false,
            opaque_data: [0; 8],
        };
        let mut buf = Vec::new();
        ping.encode(&mut buf);
        conn.recv(&buf).unwrap();

        assert_eq!(conn.state, ConnState::Closing);
        // GOAWAY should have been queued in send_buf.
        let out = conn.take_pending_send();
        let (decoded, _) = frame::decode_frame(&out, 16384).unwrap().unwrap();
        assert!(matches!(decoded, Frame::GoAway { .. }));
    }

    #[test]
    fn protocol_error_sends_goaway() {
        let mut conn = settled_conn();
        // Spurious CONTINUATION — invalid without a preceding HEADERS.
        let cont = Frame::Continuation {
            stream_id: 1,
            encoded: vec![0x82],
            end_headers: true,
        };
        let mut buf = Vec::new();
        cont.encode(&mut buf);
        conn.recv(&buf).unwrap();

        assert_eq!(conn.state, ConnState::Closing);
        let out = conn.take_pending_send();
        let (decoded, _) = frame::decode_frame(&out, 16384).unwrap().unwrap();
        match decoded {
            Frame::GoAway { error_code, .. } => {
                assert_eq!(error_code, ErrorCode::ProtocolError);
            }
            f => panic!("expected GOAWAY, got {f:?}"),
        }
    }

    #[test]
    fn response_missing_status_rejected() {
        let mut conn = settled_conn();
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let _ = conn.send_request(&headers, true).unwrap();
        let _ = conn.take_pending_send();

        // Server returns "headers" without :status.
        let mut enc = Encoder::new(4096);
        let mut encoded = Vec::new();
        enc.encode(
            &[HeaderField::new(b"content-type", b"text/plain")],
            &mut encoded,
        );
        let resp = Frame::Headers {
            stream_id: 1,
            encoded,
            end_stream: false,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        conn.recv(&buf).unwrap();

        assert_eq!(conn.state, ConnState::Closing);
        let mut got_error = false;
        while let Some(ev) = conn.poll_event() {
            if let H2Event::Error(H2Error::MessageError(_)) = ev {
                got_error = true;
            }
        }
        assert!(got_error, "expected MessageError event");
    }

    #[test]
    fn response_uppercase_header_rejected() {
        let mut conn = settled_conn();
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let _ = conn.send_request(&headers, true).unwrap();
        let _ = conn.take_pending_send();

        let mut enc = Encoder::new(4096);
        let mut encoded = Vec::new();
        enc.encode(
            &[
                HeaderField::new(b":status", b"200"),
                HeaderField::new(b"Content-Type", b"text/plain"),
            ],
            &mut encoded,
        );
        let resp = Frame::Headers {
            stream_id: 1,
            encoded,
            end_stream: false,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        conn.recv(&buf).unwrap();
        assert_eq!(conn.state, ConnState::Closing);
    }

    #[test]
    fn response_connection_specific_header_rejected() {
        let mut conn = settled_conn();
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let _ = conn.send_request(&headers, true).unwrap();
        let _ = conn.take_pending_send();

        let mut enc = Encoder::new(4096);
        let mut encoded = Vec::new();
        enc.encode(
            &[
                HeaderField::new(b":status", b"200"),
                HeaderField::new(b"connection", b"close"),
            ],
            &mut encoded,
        );
        let resp = Frame::Headers {
            stream_id: 1,
            encoded,
            end_stream: false,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        conn.recv(&buf).unwrap();
        assert_eq!(conn.state, ConnState::Closing);
    }

    #[test]
    fn spurious_continuation_rejected() {
        let mut conn = settled_conn();
        let cont = Frame::Continuation {
            stream_id: 1,
            encoded: vec![0x82],
            end_headers: true,
        };
        let mut buf = Vec::new();
        cont.encode(&mut buf);
        conn.recv(&buf).unwrap();
        assert_eq!(conn.state, ConnState::Closing);
    }

    #[test]
    fn data_on_closed_stream_emits_rst() {
        let mut conn = settled_conn();
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let stream_id = conn.send_request(&headers, true).unwrap();
        let _ = conn.take_pending_send();

        // Server sends response with END_STREAM, closing the stream.
        let mut enc = Encoder::new(4096);
        let mut encoded = Vec::new();
        enc.encode(&[HeaderField::new(b":status", b"200")], &mut encoded);
        let resp = Frame::Headers {
            stream_id,
            encoded,
            end_stream: true,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        conn.recv(&buf).unwrap();
        let _ = conn.take_pending_send();
        while conn.poll_event().is_some() {}

        // Stream is now closed and GC'd. Server sends DATA — should get RST.
        let data = Frame::Data {
            stream_id,
            payload: b"surprise".to_vec(),
            end_stream: false,
        };
        let mut buf = Vec::new();
        data.encode(&mut buf);
        conn.recv(&buf).unwrap();

        let out = conn.take_pending_send();
        // Find RST_STREAM in the output.
        let mut found_rst = false;
        let mut pos = 0;
        while pos < out.len() {
            let (frame, consumed) = frame::decode_frame(&out[pos..], 16384).unwrap().unwrap();
            if matches!(
                frame,
                Frame::RstStream {
                    error_code: ErrorCode::StreamClosed,
                    ..
                }
            ) {
                found_rst = true;
            }
            pos += consumed;
        }
        assert!(found_rst, "expected RST_STREAM with StreamClosed");
    }

    #[test]
    fn streams_gc_after_close() {
        let mut conn = settled_conn();
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let stream_id = conn.send_request(&headers, true).unwrap();
        let _ = conn.take_pending_send();

        // Stream is HalfClosedLocal (we sent END_STREAM). Server responds with END_STREAM.
        let mut enc = Encoder::new(4096);
        let mut encoded = Vec::new();
        enc.encode(&[HeaderField::new(b":status", b"200")], &mut encoded);
        let resp = Frame::Headers {
            stream_id,
            encoded,
            end_stream: true,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        conn.recv(&buf).unwrap();
        while conn.poll_event().is_some() {}

        // Stream should be GC'd.
        assert!(!conn.streams.contains_key(&stream_id));
    }

    #[test]
    fn recv_buf_capped() {
        let mut conn = settled_conn();
        conn.set_max_recv_buf(64);

        // Push 100 bytes (one byte at a time would also trigger, but bulk is fine).
        conn.recv(&[0u8; 100]).unwrap();
        assert_eq!(conn.state, ConnState::Closing);
        // GOAWAY should be queued.
        let out = conn.take_pending_send();
        let (decoded, _) = frame::decode_frame(&out, 16384).unwrap().unwrap();
        assert!(matches!(decoded, Frame::GoAway { .. }));
    }

    #[test]
    fn unknown_odd_stream_rejected() {
        let mut conn = settled_conn();
        // Server sends HEADERS on stream 7 (odd, never allocated by us).
        let mut enc = Encoder::new(4096);
        let mut encoded = Vec::new();
        enc.encode(&[HeaderField::new(b":status", b"200")], &mut encoded);
        let resp = Frame::Headers {
            stream_id: 7,
            encoded,
            end_stream: true,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf);
        conn.recv(&buf).unwrap();
        assert_eq!(conn.state, ConnState::Closing);
    }

    #[test]
    fn trailers_after_initial_headers_emits_trailers_event() {
        // Regression: an initial HEADERS without END_STREAM leaves the
        // stream in HalfClosedLocal; the trailing HEADERS arrives with the
        // state unchanged. The second HEADERS must be classified as
        // trailers (no `:status` required), not as a second response.
        let mut conn = settled_conn();
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let stream_id = conn.send_request(&headers, true).unwrap();
        let _ = conn.take_pending_send();

        // 1) Initial response HEADERS without END_STREAM.
        let mut enc = Encoder::new(4096);
        let mut buf = Vec::new();
        let mut encoded = Vec::new();
        enc.encode(
            &[
                HeaderField::new(b":status", b"200"),
                HeaderField::new(b"content-type", b"application/grpc"),
            ],
            &mut encoded,
        );
        Frame::Headers {
            stream_id,
            encoded,
            end_stream: false,
            end_headers: true,
            priority: None,
        }
        .encode(&mut buf);

        // 2) Trailers (no `:status`, must end the stream).
        let mut encoded_t = Vec::new();
        enc.encode(&[HeaderField::new(b"grpc-status", b"0")], &mut encoded_t);
        Frame::Headers {
            stream_id,
            encoded: encoded_t,
            end_stream: true,
            end_headers: true,
            priority: None,
        }
        .encode(&mut buf);

        conn.recv(&buf).unwrap();
        assert_eq!(conn.state, ConnState::Ready, "should not close");

        let mut got_response = false;
        let mut got_trailers = false;
        while let Some(ev) = conn.poll_event() {
            match ev {
                H2Event::Response { .. } => got_response = true,
                H2Event::Trailers { headers, .. } => {
                    got_trailers = true;
                    assert_eq!(headers[0].name, b"grpc-status");
                }
                _ => {}
            }
        }
        assert!(got_response, "expected Response event");
        assert!(got_trailers, "expected Trailers event");
    }

    #[test]
    fn stream_id_overflow_returns_error() {
        let mut conn = settled_conn();
        conn.next_stream_id = MAX_STREAM_ID + 2; // already past the limit
        let headers = vec![HeaderField::new(b":method", b"GET")];
        let err = conn.send_request(&headers, true).err().unwrap();
        assert!(matches!(
            err,
            H2Error::ConnectionError(ErrorCode::RefusedStream)
        ));
    }

    #[test]
    fn send_data_splits_large_payload_into_multiple_frames() {
        let mut conn = H2Connection::new(Settings::client_default());
        let _ = conn.take_pending_send();

        // Server sends SETTINGS with max_frame_size = 16384 (default).
        let server_settings = make_settings_frame(&Settings::default(), false);
        conn.recv(&server_settings).unwrap();
        let _ = conn.take_pending_send();

        // Open a stream.
        let headers = vec![
            HeaderField::new(b":method", b"POST"),
            HeaderField::new(b":path", b"/upload"),
            HeaderField::new(b":scheme", b"https"),
            HeaderField::new(b":authority", b"example.com"),
        ];
        let stream_id = conn.send_request(&headers, false).unwrap();
        let _ = conn.take_pending_send();

        // Send data larger than max_frame_size (16384).
        let large_data = vec![0xABu8; 40000];
        conn.send_data(stream_id, &large_data, true).unwrap();

        let send = conn.take_pending_send();

        // Should have produced multiple DATA frames.
        // Parse frame headers to count them.
        let mut offset = 0;
        let mut frame_count = 0;
        let mut total_payload = 0;
        let mut last_end_stream = false;

        while offset + 9 <= send.len() {
            let header = frame::decode_frame_header(&send[offset..]).unwrap();
            assert_eq!(header.frame_type, frame::FRAME_DATA);
            assert_eq!(header.stream_id, stream_id);
            assert!(
                header.length <= 16384,
                "frame payload {} exceeds max_frame_size 16384",
                header.length
            );
            total_payload += header.length as usize;
            last_end_stream = header.flags & frame::FLAG_END_STREAM != 0;
            offset += 9 + header.length as usize;
            frame_count += 1;
        }

        assert!(
            frame_count >= 3,
            "expected at least 3 frames for 40000 bytes, got {frame_count}"
        );
        assert_eq!(total_payload, 40000, "total payload mismatch");
        assert!(
            last_end_stream,
            "END_STREAM should be set only on the last frame"
        );
    }
}
