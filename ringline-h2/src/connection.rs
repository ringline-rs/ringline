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

/// Auto WINDOW_UPDATE threshold: send update when half the window is consumed.
const WINDOW_UPDATE_THRESHOLD: i64 = 32768;

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
        }
    }

    /// Feed received bytes from the transport.
    pub fn recv(&mut self, data: &[u8]) -> Result<(), H2Error> {
        self.recv_buf.extend_from_slice(data);
        self.process_recv_buf()
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

        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;

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
                return Err(H2Error::StreamError(
                    stream_id,
                    ErrorCode::StreamClosed,
                ));
            }
        }

        // Check flow control.
        if !data.is_empty() {
            self.conn_send_window.consume(data.len() as u32)?;
            stream.send_window.consume(data.len() as u32)?;
        }

        let frame = Frame::Data {
            stream_id,
            payload: data.to_vec(),
            end_stream,
        };
        frame.encode(&mut self.send_buf);

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
            let max_frame = self.local_settings.max_frame_size;
            match frame::decode_frame(&self.recv_buf, max_frame) {
                Ok(Some((frame, consumed))) => {
                    self.recv_buf.drain(..consumed);
                    self.handle_frame(frame)?;
                }
                Ok(None) => break,
                Err(e) => {
                    self.events.push_back(H2Event::Error(H2Error::ProtocolError(
                        format!("{e}"),
                    )));
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_frame(&mut self, frame: Frame) -> Result<(), H2Error> {
        // CONTINUATION enforcement: if we're in a header block, only
        // CONTINUATION frames for that stream are allowed.
        if let Some(expected_sid) = self.continuation_stream {
            match &frame {
                Frame::Continuation { stream_id, .. } if *stream_id == expected_sid => {
                    // OK, process below.
                }
                _ => {
                    return Err(H2Error::ProtocolError(
                        "expected CONTINUATION frame".into(),
                    ));
                }
            }
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
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.state = StreamState::Closed;
                }
                self.events.push_back(H2Event::StreamReset {
                    stream_id,
                    error_code,
                });
            }
            Frame::Ping { ack, opaque_data } => {
                if !ack {
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

        // Update HPACK decoder max table size.
        self.decoder
            .set_max_table_size(self.remote_settings.header_table_size as usize);

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
                // Unknown stream -- could be a server-initiated stream or stale.
                return Ok(());
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
            let end_stream = self.streams.get(&stream_id)
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
        let headers = self.decoder.decode(encoded)?;

        let stream = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(()),
        };

        // Determine if this is a response or trailers.
        let is_initial_response = stream.state == StreamState::Open
            || stream.state == StreamState::HalfClosedLocal;

        if end_stream {
            stream.state = match stream.state {
                StreamState::HalfClosedLocal => StreamState::Closed,
                _ => StreamState::HalfClosedRemote,
            };
        }

        // Check if headers contain :status (response) or not (trailers).
        let has_status = headers.iter().any(|h| h.name == b":status");

        if has_status && is_initial_response {
            self.events.push_back(H2Event::Response {
                stream_id,
                headers,
                end_stream,
            });
        } else {
            self.events.push_back(H2Event::Trailers {
                stream_id,
                headers,
            });
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

        // Update connection-level receive window.
        if data_len > 0 {
            self.conn_recv_window.consume(data_len)?;
        }

        let stream = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(()),
        };

        // Update stream-level receive window.
        if data_len > 0 {
            stream.recv_window.consume(data_len)?;
        }

        if end_stream {
            stream.state = match stream.state {
                StreamState::HalfClosedLocal => StreamState::Closed,
                _ => StreamState::HalfClosedRemote,
            };
        }

        self.events.push_back(H2Event::Data {
            stream_id,
            data: payload,
            end_stream,
        });

        // Auto-send WINDOW_UPDATE when significant data consumed.
        self.maybe_send_window_updates(stream_id, data_len);

        Ok(())
    }

    fn handle_window_update(
        &mut self,
        stream_id: u32,
        increment: u32,
    ) -> Result<(), H2Error> {
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
            let increment =
                (self.initial_recv_window - stream.recv_window.window()) as u32;
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
            H2Event::GoAway {
                error_code, ..
            } => assert_eq!(error_code, ErrorCode::NoError),
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
}
