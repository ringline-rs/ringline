//! HTTP/3 connection state machine.
//!
//! `H3Connection` sits on top of a `QuicEndpoint`, processing QUIC events
//! and producing HTTP-level events. Server-side only for Phase 1.

use std::collections::{HashMap, VecDeque};

use ringline_quic::{QuicConnId, QuicEndpoint, QuicEvent, StreamId};

use crate::error::H3Error;
use crate::frame::{self, Frame};
use crate::qpack::{self, HeaderField};
use crate::settings::Settings;
use crate::stream::{RequestStream, StreamState};

/// HTTP/3 uni-stream type identifiers (RFC 9114 Section 6.2).
const STREAM_TYPE_CONTROL: u64 = 0x00;
const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// Events produced by the HTTP/3 connection for the application.
#[derive(Debug)]
pub enum H3Event {
    /// Received a complete request (headers, and optionally end of stream).
    Request {
        stream_id: StreamId,
        headers: Vec<HeaderField>,
        end_stream: bool,
    },
    /// Received request body data on a stream.
    Data {
        stream_id: StreamId,
        data: Vec<u8>,
        end_stream: bool,
    },
    /// Peer sent GOAWAY frame.
    GoAway { stream_id: u64 },
    /// Connection-level error.
    Error(H3Error),
}

/// Internal connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H3State {
    /// Waiting for peer's control stream + SETTINGS.
    Initializing,
    /// SETTINGS exchanged, ready for requests.
    Ready,
    /// GOAWAY sent or received.
    Closing,
    /// Connection closed.
    Closed,
}

/// Server-side HTTP/3 connection.
///
/// Processes QUIC events from a `QuicEndpoint` and produces HTTP/3 events.
/// The application calls `handle_quic_event()` to feed events, then
/// `poll_event()` to retrieve HTTP-level events.
pub struct H3Connection {
    state: H3State,
    local_settings: Settings,
    remote_settings: Option<Settings>,

    /// Per-request-stream state, keyed by QUIC stream ID bits.
    request_streams: HashMap<u64, RequestStream>,

    /// Peer's control stream (unidirectional).
    control_stream_id: Option<StreamId>,
    /// Our control stream (unidirectional, opened on accept).
    our_control_stream: Option<StreamId>,

    /// Accumulates partial frame data on the peer's control stream.
    control_recv_buf: Vec<u8>,

    /// Pending uni streams that we've seen open but haven't read the type byte yet.
    pending_uni_streams: Vec<StreamId>,

    /// Application-visible event queue.
    events: VecDeque<H3Event>,

    /// Whether we've sent our SETTINGS.
    settings_sent: bool,

    /// The QUIC connection this H3 session belongs to.
    conn_id: Option<QuicConnId>,

    /// Read buffer for stream_recv calls (avoids repeated allocation).
    read_buf: Vec<u8>,
}

impl H3Connection {
    /// Create a new server-side HTTP/3 connection.
    pub fn new(settings: Settings) -> Self {
        Self {
            state: H3State::Initializing,
            local_settings: settings,
            remote_settings: None,
            request_streams: HashMap::new(),
            control_stream_id: None,
            our_control_stream: None,
            control_recv_buf: Vec::new(),
            pending_uni_streams: Vec::new(),
            events: VecDeque::new(),
            settings_sent: false,
            conn_id: None,
            read_buf: vec![0u8; 65536],
        }
    }

    /// Initialize the HTTP/3 connection for a new QUIC connection.
    ///
    /// Opens our control unidirectional stream and sends the SETTINGS frame.
    pub fn accept(&mut self, quic: &mut QuicEndpoint, conn: QuicConnId) -> Result<(), H3Error> {
        self.conn_id = Some(conn);

        // Open our control uni stream.
        let stream = quic
            .open_uni(conn)?
            .ok_or_else(|| H3Error::Internal("cannot open control stream".into()))?;
        self.our_control_stream = Some(stream);

        // Send stream type (control = 0x00) + SETTINGS frame.
        let mut buf = Vec::new();
        frame::encode_varint(&mut buf, STREAM_TYPE_CONTROL);
        Frame::Settings(self.local_settings.clone()).encode(&mut buf);
        quic.stream_send(conn, stream, &buf)?;
        // Note: do NOT call stream_finish on the control stream.
        // RFC 9114 Section 6.2.1: closing the control stream is a connection error.

        self.settings_sent = true;
        Ok(())
    }

    /// Process a QUIC event and update HTTP/3 state.
    ///
    /// After calling this, drain events with `poll_event()`.
    pub fn handle_quic_event(
        &mut self,
        quic: &mut QuicEndpoint,
        event: &QuicEvent,
    ) -> Result<(), H3Error> {
        match event {
            QuicEvent::NewConnection(conn) => {
                self.accept(quic, *conn)?;
            }
            QuicEvent::StreamOpened { conn, stream, bidi } => {
                if *bidi {
                    // New bidirectional stream = new HTTP request.
                    self.request_streams
                        .insert(u64::from(*stream), RequestStream::new());
                    // Proactively try to read — data may have arrived in the
                    // same QUIC packet that opened the stream, in which case
                    // quinn-proto won't fire a separate StreamReadable event.
                    self.read_request_stream(quic, *conn, *stream)?;
                } else {
                    // Unidirectional stream — need to read the type byte.
                    // Try to identify immediately (data may already be available).
                    self.identify_uni_stream(quic, *conn, *stream)?;
                }
            }
            QuicEvent::StreamReadable { conn, stream } => {
                self.handle_stream_readable(quic, *conn, *stream)?;
            }
            QuicEvent::ConnectionClosed { .. } => {
                self.state = H3State::Closed;
            }
            // StreamWritable, StreamFinished, Connected — not relevant for server.
            _ => {}
        }
        Ok(())
    }

    /// Poll the next HTTP/3 event, if any.
    pub fn poll_event(&mut self) -> Option<H3Event> {
        self.events.pop_front()
    }

    /// Send response headers on a stream.
    pub fn send_response(
        &mut self,
        quic: &mut QuicEndpoint,
        stream_id: StreamId,
        headers: &[HeaderField],
        end_stream: bool,
    ) -> Result<(), H3Error> {
        let conn = self
            .conn_id
            .ok_or(H3Error::Internal("no connection".into()))?;

        let mut encoded_headers = Vec::new();
        qpack::encode(headers, &mut encoded_headers);

        let mut buf = Vec::new();
        Frame::Headers {
            encoded: encoded_headers,
        }
        .encode(&mut buf);

        quic.stream_send(conn, stream_id, &buf)?;

        if end_stream {
            quic.stream_finish(conn, stream_id)?;
            if let Some(rs) = self.request_streams.get_mut(&u64::from(stream_id)) {
                rs.state = match rs.state {
                    StreamState::HalfClosedRemote => StreamState::Closed,
                    _ => StreamState::HalfClosedLocal,
                };
            }
        }

        Ok(())
    }

    /// Send response body data on a stream.
    pub fn send_data(
        &mut self,
        quic: &mut QuicEndpoint,
        stream_id: StreamId,
        data: &[u8],
        end_stream: bool,
    ) -> Result<(), H3Error> {
        let conn = self
            .conn_id
            .ok_or(H3Error::Internal("no connection".into()))?;

        let mut buf = Vec::new();
        Frame::Data {
            payload: data.to_vec(),
        }
        .encode(&mut buf);

        quic.stream_send(conn, stream_id, &buf)?;

        if end_stream {
            quic.stream_finish(conn, stream_id)?;
            if let Some(rs) = self.request_streams.get_mut(&u64::from(stream_id)) {
                rs.state = match rs.state {
                    StreamState::HalfClosedRemote => StreamState::Closed,
                    _ => StreamState::HalfClosedLocal,
                };
            }
        }

        Ok(())
    }

    /// Send a GOAWAY frame on the control stream (graceful shutdown).
    pub fn send_goaway(
        &mut self,
        quic: &mut QuicEndpoint,
        last_stream_id: u64,
    ) -> Result<(), H3Error> {
        let conn = self
            .conn_id
            .ok_or(H3Error::Internal("no connection".into()))?;
        let control = self
            .our_control_stream
            .ok_or(H3Error::Internal("no control stream".into()))?;

        let mut buf = Vec::new();
        Frame::GoAway {
            stream_id: last_stream_id,
        }
        .encode(&mut buf);

        quic.stream_send(conn, control, &buf)?;
        self.state = H3State::Closing;
        Ok(())
    }

    // ── Internal helpers ────────────────────────────────────────────

    fn handle_stream_readable(
        &mut self,
        quic: &mut QuicEndpoint,
        conn: QuicConnId,
        stream: StreamId,
    ) -> Result<(), H3Error> {
        // Check if this is a pending uni stream that needs type identification.
        if let Some(pos) = self.pending_uni_streams.iter().position(|s| *s == stream) {
            self.pending_uni_streams.swap_remove(pos);
            return self.identify_uni_stream(quic, conn, stream);
        }

        // Check if it's the control stream.
        if self.control_stream_id == Some(stream) {
            return self.read_control_stream(quic, conn, stream);
        }

        // Must be a request stream.
        if self.request_streams.contains_key(&u64::from(stream)) {
            return self.read_request_stream(quic, conn, stream);
        }

        // Unknown stream — could be a uni stream type we don't track.
        Ok(())
    }

    fn identify_uni_stream(
        &mut self,
        quic: &mut QuicEndpoint,
        conn: QuicConnId,
        stream: StreamId,
    ) -> Result<(), H3Error> {
        // Read the stream type byte.
        let mut type_buf = [0u8; 8]; // varints up to 8 bytes
        let (n, _fin) = quic.stream_recv(conn, stream, &mut type_buf)?;
        if n == 0 {
            // No data yet — re-add to pending.
            self.pending_uni_streams.push(stream);
            return Ok(());
        }

        let (stream_type, _consumed) = match frame::decode_varint(&type_buf[..n]) {
            Some(v) => v,
            None => {
                // Incomplete varint — re-add to pending.
                self.pending_uni_streams.push(stream);
                return Ok(());
            }
        };

        match stream_type {
            STREAM_TYPE_CONTROL => {
                if self.control_stream_id.is_some() {
                    // Duplicate control stream is a connection error.
                    self.events
                        .push_back(H3Event::Error(H3Error::FrameUnexpected));
                    return Ok(());
                }
                self.control_stream_id = Some(stream);
                // There may be data already available — try reading.
                // Any remaining bytes after the type varint go into control_recv_buf.
                let consumed = frame::decode_varint(&type_buf[..n])
                    .map(|(_, c)| c)
                    .unwrap_or(0);
                if consumed < n {
                    self.control_recv_buf
                        .extend_from_slice(&type_buf[consumed..n]);
                }
                self.read_control_stream(quic, conn, stream)?;
            }
            STREAM_TYPE_QPACK_ENCODER | STREAM_TYPE_QPACK_DECODER => {
                // Phase 1: no dynamic table — ignore QPACK streams.
            }
            _ => {
                // Unknown uni stream types MUST be ignored per spec.
            }
        }

        Ok(())
    }

    fn read_control_stream(
        &mut self,
        quic: &mut QuicEndpoint,
        conn: QuicConnId,
        stream: StreamId,
    ) -> Result<(), H3Error> {
        // Read available data.
        loop {
            let (n, fin) = match quic.stream_recv(conn, stream, &mut self.read_buf) {
                Ok(r) => r,
                Err(_) => break,
            };
            if n > 0 {
                self.control_recv_buf.extend_from_slice(&self.read_buf[..n]);
            }
            if fin {
                // Control stream closed — this is an error in HTTP/3.
                self.events
                    .push_back(H3Event::Error(H3Error::ClosedCriticalStream));
                return Ok(());
            }
            if n == 0 {
                break;
            }
        }

        // Process frames from the control stream buffer.
        self.process_control_frames()
    }

    fn process_control_frames(&mut self) -> Result<(), H3Error> {
        loop {
            let buf = &self.control_recv_buf;
            if buf.is_empty() {
                break;
            }
            match frame::decode_frame(buf) {
                Ok(Some((frame, consumed))) => {
                    let consumed_bytes = consumed;
                    match frame {
                        Frame::Settings(settings) => {
                            if self.remote_settings.is_some() {
                                // Duplicate SETTINGS is a connection error.
                                self.events
                                    .push_back(H3Event::Error(H3Error::FrameUnexpected));
                                return Ok(());
                            }
                            self.remote_settings = Some(settings);
                            if self.state == H3State::Initializing && self.settings_sent {
                                self.state = H3State::Ready;
                            }
                        }
                        Frame::GoAway { stream_id } => {
                            self.state = H3State::Closing;
                            self.events.push_back(H3Event::GoAway { stream_id });
                        }
                        Frame::Data { .. } | Frame::Headers { .. } => {
                            // DATA and HEADERS on control stream are errors.
                            self.events
                                .push_back(H3Event::Error(H3Error::FrameUnexpected));
                            return Ok(());
                        }
                        Frame::Unknown { .. } => {
                            // Unknown frames on control stream are ignored.
                        }
                    }
                    // Remove consumed bytes.
                    self.control_recv_buf = self.control_recv_buf[consumed_bytes..].to_vec();
                }
                Ok(None) => break, // Incomplete frame, need more data.
                Err(e) => {
                    self.events.push_back(H3Event::Error(e));
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn read_request_stream(
        &mut self,
        quic: &mut QuicEndpoint,
        conn: QuicConnId,
        stream: StreamId,
    ) -> Result<(), H3Error> {
        let mut fin_received = false;

        // Read available data into the stream's recv_buf.
        loop {
            let (n, fin) = match quic.stream_recv(conn, stream, &mut self.read_buf) {
                Ok(r) => r,
                Err(_) => break,
            };
            if n > 0
                && let Some(rs) = self.request_streams.get_mut(&u64::from(stream))
            {
                rs.recv_buf.extend_from_slice(&self.read_buf[..n]);
            }
            if fin {
                fin_received = true;
            }
            if n == 0 || fin {
                break;
            }
        }

        // Process frames from the stream's recv_buf.
        self.process_request_frames(stream, fin_received)
    }

    fn process_request_frames(
        &mut self,
        stream: StreamId,
        fin_received: bool,
    ) -> Result<(), H3Error> {
        // We need to work with the recv_buf without holding a mutable borrow on self
        // the entire time, so we swap it out.
        let mut recv_buf = match self.request_streams.get_mut(&u64::from(stream)) {
            Some(rs) => std::mem::take(&mut rs.recv_buf),
            None => return Ok(()),
        };

        let mut offset = 0;

        loop {
            let remaining = &recv_buf[offset..];
            if remaining.is_empty() {
                break;
            }

            match frame::decode_frame(remaining) {
                Ok(Some((frame, consumed))) => {
                    offset += consumed;

                    match frame {
                        Frame::Headers { encoded } => {
                            let headers = qpack::decode(&encoded)?;
                            let at_end = fin_received && offset == recv_buf.len();

                            // Update stream state.
                            if let Some(rs) = self.request_streams.get_mut(&u64::from(stream)) {
                                rs.state = if at_end {
                                    StreamState::HalfClosedRemote
                                } else {
                                    StreamState::Open
                                };
                            }

                            self.events.push_back(H3Event::Request {
                                stream_id: stream,
                                headers,
                                end_stream: at_end,
                            });
                        }
                        Frame::Data { payload } => {
                            let at_end = fin_received && offset == recv_buf.len();

                            if at_end
                                && let Some(rs) = self.request_streams.get_mut(&u64::from(stream))
                            {
                                rs.state = StreamState::HalfClosedRemote;
                            }

                            self.events.push_back(H3Event::Data {
                                stream_id: stream,
                                data: payload,
                                end_stream: at_end,
                            });
                        }
                        Frame::Settings(_) => {
                            // SETTINGS on a request stream is an error.
                            self.events
                                .push_back(H3Event::Error(H3Error::FrameUnexpected));
                            break;
                        }
                        Frame::GoAway { .. } => {
                            // GOAWAY on a request stream is an error.
                            self.events
                                .push_back(H3Event::Error(H3Error::FrameUnexpected));
                            break;
                        }
                        Frame::Unknown { .. } => {
                            // Unknown frames on request streams are ignored.
                        }
                    }
                }
                Ok(None) => break, // Incomplete frame.
                Err(e) => {
                    self.events.push_back(H3Event::Error(e));
                    break;
                }
            }
        }

        // Handle FIN with no remaining frames — the stream is done.
        if fin_received && offset == recv_buf.len() {
            // If the stream was still WaitingHeaders when FIN arrived with no data,
            // that's fine — the stream just closed without sending anything.
            if let Some(rs) = self.request_streams.get_mut(&u64::from(stream))
                && rs.state == StreamState::Open
            {
                rs.state = StreamState::HalfClosedRemote;
                // Emit a Data event with empty body to signal end_stream.
                self.events.push_back(H3Event::Data {
                    stream_id: stream,
                    data: Vec::new(),
                    end_stream: true,
                });
            }
        }

        // Put unconsumed data back.
        if offset > 0 {
            recv_buf.drain(..offset);
        }
        if let Some(rs) = self.request_streams.get_mut(&u64::from(stream)) {
            rs.recv_buf = recv_buf;
        }

        Ok(())
    }
}
