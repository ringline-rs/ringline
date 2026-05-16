//! HTTP/3 connection state machine.
//!
//! `H3Connection` sits on top of a `QuicEndpoint`, processing QUIC events
//! and producing HTTP-level events. Supports both client and server roles.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use ringline_quic::{QuicConnId, QuicEndpoint, QuicEvent, ReadError, StreamId, VarInt, WriteError};

use crate::error::H3Error;
use crate::frame::{self, Frame, encode_frame_header};
use crate::qpack::{self, HeaderField};
use crate::settings::Settings;
use crate::stream::{RequestStream, StreamState};

/// Refcounted payload chunks queued for a stream that didn't fit in the
/// current flow-control window. Drained on `StreamWritable` events.
///
/// Each chunk stays as a distinct `Bytes` so slicing stays O(1) and we don't
/// re-copy user payloads onto a contiguous `Vec<u8>` when we have to queue
/// behind a slow receiver.
#[derive(Default)]
struct PendingStream {
    queue: VecDeque<Bytes>,
    /// Caller requested FIN once `queue` fully drains. `stream_finish` fires
    /// then, not when the app called the send method.
    pending_fin: bool,
}

impl PendingStream {
    fn is_done(&self) -> bool {
        self.queue.is_empty() && !self.pending_fin
    }
}

/// HTTP/3 uni-stream type identifiers (RFC 9114 Section 6.2).
const STREAM_TYPE_CONTROL: u64 = 0x00;
const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// Categorises a header section for the validator (RFC 9114 §4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderKind {
    Request,
    Response,
    Trailer,
}

/// Sum of `name.len() + value.len() + 32` for every field, the
/// "field section size" the peer is allowed to bound via
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2). Saturates
/// rather than overflows.
fn field_section_size(headers: &[HeaderField]) -> u64 {
    let mut total: u64 = 0;
    for f in headers {
        let per = (f.name.len() as u64)
            .saturating_add(f.value.len() as u64)
            .saturating_add(32);
        total = total.saturating_add(per);
    }
    total
}

/// Validate a decoded header section per RFC 9114 §4.2 + §4.3.1.1.
///
/// Returns `H3Error::MessageError` on any violation: pseudo-headers after a
/// regular field, duplicate pseudo-header, unknown pseudo-header, missing
/// required pseudo-header for the role, presence of a forbidden
/// connection-specific field, or `TE` with anything other than `trailers`.
/// Pseudo-headers are forbidden in trailers entirely.
fn validate_headers(kind: HeaderKind, headers: &[HeaderField]) -> Result<(), H3Error> {
    let mut seen_pseudo: Vec<&[u8]> = Vec::new();
    let mut saw_regular = false;
    let mut method: Option<&[u8]> = None;
    let mut path: Option<&[u8]> = None;
    let mut scheme: Option<&[u8]> = None;
    let mut authority: Option<&[u8]> = None;
    let mut status_seen = false;

    for field in headers {
        let name = field.name.as_slice();
        let value = field.value.as_slice();
        let is_pseudo = name.first() == Some(&b':');

        if is_pseudo {
            if saw_regular {
                return Err(H3Error::MessageError);
            }
            if matches!(kind, HeaderKind::Trailer) {
                return Err(H3Error::MessageError);
            }
            if seen_pseudo.contains(&name) {
                return Err(H3Error::MessageError);
            }
            seen_pseudo.push(name);

            match name {
                b":method" => method = Some(value),
                b":path" => path = Some(value),
                b":scheme" => scheme = Some(value),
                b":authority" => authority = Some(value),
                b":status" => status_seen = true,
                _ => return Err(H3Error::MessageError),
            }
        } else {
            saw_regular = true;
            match name {
                b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
                | b"upgrade" => return Err(H3Error::MessageError),
                b"te" if value != b"trailers" => return Err(H3Error::MessageError),
                _ => {}
            }
        }
    }

    match kind {
        HeaderKind::Request => {
            let m = method.ok_or(H3Error::MessageError)?;
            if m == b"CONNECT" {
                // :scheme and :path MUST be omitted for CONNECT (extended
                // CONNECT in RFC 9220 is not yet supported by this stack).
                if path.is_some() || scheme.is_some() {
                    return Err(H3Error::MessageError);
                }
                if authority.is_none() {
                    return Err(H3Error::MessageError);
                }
            } else if path.is_none() || scheme.is_none() || authority.is_none() {
                return Err(H3Error::MessageError);
            }
        }
        HeaderKind::Response => {
            if !status_seen {
                return Err(H3Error::MessageError);
            }
        }
        HeaderKind::Trailer => {
            // Trailers must contain no pseudo-headers — already checked.
        }
    }

    Ok(())
}

/// Events produced by the HTTP/3 connection for the application.
///
/// Marked `#[non_exhaustive]` because we expect to grow this surface as
/// the H3 layer adds extensions (server push, WebTransport, etc.).
/// Downstream `match` blocks must include a wildcard arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum H3Event {
    /// Received a complete request (headers, and optionally end of stream).
    Request {
        stream_id: StreamId,
        headers: Vec<HeaderField>,
        end_stream: bool,
    },
    /// Received response headers on a client-initiated stream.
    Response {
        stream_id: StreamId,
        headers: Vec<HeaderField>,
        end_stream: bool,
    },
    /// Received trailing HEADERS (trailers) on a request stream that had
    /// already received the initial HEADERS. Per RFC 9114 §4.1 trailers must
    /// be the last frame on the stream, so `end_stream` is always implied
    /// `true` here.
    Trailers {
        stream_id: StreamId,
        headers: Vec<HeaderField>,
    },
    /// Received request body data on a stream.
    Data {
        stream_id: StreamId,
        data: Vec<u8>,
        end_stream: bool,
    },
    /// Peer sent GOAWAY frame.
    GoAway { stream_id: u64 },
    /// The peer reset a stream (`RESET_STREAM`) or asked us to stop sending
    /// on it (`STOP_SENDING`). All buffered state for `stream_id` has been
    /// dropped — any further calls on that stream will fail.
    StreamReset {
        stream_id: StreamId,
        error_code: u64,
    },
    /// The server rejected 0-RTT. Any requests issued before the handshake
    /// completed were discarded by quinn-proto and the H3 layer has cleared
    /// its per-stream tracking. The application is responsible for
    /// re-issuing those requests over 1-RTT.
    ZeroRttRejected,
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

/// Whether this `H3Connection` is playing the client or server role.
/// Determines how peer-opened bidi streams are interpreted (request vs
/// illegal push) and which pseudo-headers are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Client,
    Server,
}

/// HTTP/3 connection (client and server).
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

    /// Partial type-varint bytes buffered for streams whose type varint arrived
    /// split across QUIC packets.  Keyed by stream ID bits.
    partial_uni_type_bufs: HashMap<u64, Vec<u8>>,

    /// Application-visible event queue.
    events: VecDeque<H3Event>,

    /// Whether we've sent our SETTINGS.
    settings_sent: bool,

    /// The QUIC connection this H3 session belongs to.
    conn_id: Option<QuicConnId>,

    /// Read buffer for stream_recv calls (avoids repeated allocation).
    read_buf: Vec<u8>,

    /// Per-stream buffered outbound bytes that didn't fit in the flow-control
    /// window at the time of the send. Drained on `QuicEvent::StreamWritable`.
    pending_sends: HashMap<u64, PendingStream>,

    /// Cap on total bytes currently queued in `pending_sends`. When the next
    /// `queue_send` would push the running total past this limit, the send
    /// fails with `H3Error::BackpressureExceeded` instead of growing the
    /// queue. `usize::MAX` (default) disables the cap.
    max_pending_bytes: usize,

    /// Whether we've seen our role for this connection. `Server` is set in
    /// `accept`, `Client` in `initiate`. None means neither has been called
    /// yet, in which case role-sensitive checks default to lenient.
    role: Option<Role>,
}

impl H3Connection {
    /// Create a new HTTP/3 connection.
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
            partial_uni_type_bufs: HashMap::new(),
            events: VecDeque::new(),
            settings_sent: false,
            conn_id: None,
            read_buf: vec![0u8; 65536],
            pending_sends: HashMap::new(),
            max_pending_bytes: usize::MAX,
            role: None,
        }
    }

    /// Configure the maximum number of outbound bytes the connection will
    /// hold in its per-stream queues while waiting for flow-control credit.
    ///
    /// When the running total of queued bytes would exceed `limit`,
    /// `send_data` / `send_data_bytes` / `send_response` return
    /// [`H3Error::BackpressureExceeded`] instead of growing the queue.
    /// Callers should observe [`has_pending_writes`](Self::has_pending_writes)
    /// (or wait for `StreamWritable` events) and retry once the queue drains.
    ///
    /// The default is `usize::MAX` (effectively unbounded). Set this on any
    /// long-lived server / client that accepts user input feeding into the
    /// send path — otherwise a hot loop or slow peer will eventually OOM the
    /// process.
    pub fn set_max_pending_bytes(&mut self, limit: usize) {
        self.max_pending_bytes = limit;
    }

    /// Sum of bytes currently buffered for flow-control-blocked streams.
    ///
    /// Re-computed on demand from the per-stream queues; not cached. Cheap
    /// for small workloads (handful of streams, handful of chunks each); if
    /// you need to gate on this every hot-path call, prefer
    /// `has_pending_writes`.
    pub fn pending_bytes(&self) -> usize {
        self.compute_pending_bytes()
    }

    fn compute_pending_bytes(&self) -> usize {
        self.pending_sends
            .values()
            .map(|p| p.queue.iter().map(|b| b.len()).sum::<usize>())
            .sum()
    }

    /// Initialize the HTTP/3 connection for a new QUIC connection.
    ///
    /// Opens our control unidirectional stream and sends the SETTINGS frame.
    pub fn accept(&mut self, quic: &mut QuicEndpoint, conn: QuicConnId) -> Result<(), H3Error> {
        self.conn_id = Some(conn);
        self.role = Some(Role::Server);

        // Open our control uni stream.
        let stream = quic
            .open_uni(conn)?
            .ok_or_else(|| H3Error::Internal("cannot open control stream".into()))?;
        self.our_control_stream = Some(stream);

        // Send stream type (control = 0x00) + SETTINGS frame. Route through
        // queue_send so a flow-control-blocked write doesn't silently lose the
        // SETTINGS bytes. Never FIN: RFC 9114 §6.2.1 makes closing the control
        // stream a connection error.
        let mut buf = Vec::new();
        frame::encode_varint(&mut buf, STREAM_TYPE_CONTROL);
        Frame::Settings(self.local_settings.clone()).encode(&mut buf);
        self.queue_send(quic, conn, stream, vec![Bytes::from(buf)], false)?;

        // Only mark SETTINGS as fully sent once nothing is queued behind it.
        // If queue_send had to defer due to flow control, `drain_pending_stream`
        // flips this when the bytes actually hit the wire.
        self.settings_sent = !self.has_pending_writes(stream);
        Ok(())
    }

    /// Initialize the HTTP/3 connection for an outbound QUIC connection.
    ///
    /// Opens our control unidirectional stream and sends the SETTINGS frame.
    /// This is the client-side counterpart of [`accept()`](Self::accept).
    pub fn initiate(&mut self, quic: &mut QuicEndpoint, conn: QuicConnId) -> Result<(), H3Error> {
        self.conn_id = Some(conn);
        self.role = Some(Role::Client);

        // Open our control uni stream.
        let stream = quic
            .open_uni(conn)?
            .ok_or_else(|| H3Error::Internal("cannot open control stream".into()))?;
        self.our_control_stream = Some(stream);

        // Same routing as accept().
        let mut buf = Vec::new();
        frame::encode_varint(&mut buf, STREAM_TYPE_CONTROL);
        Frame::Settings(self.local_settings.clone()).encode(&mut buf);
        self.queue_send(quic, conn, stream, vec![Bytes::from(buf)], false)?;

        self.settings_sent = !self.has_pending_writes(stream);
        Ok(())
    }

    /// Send a request on a new bidirectional stream (client-side).
    ///
    /// Opens a new bidi stream, encodes the HEADERS frame, and optionally
    /// finishes the send side if `end_stream` is true. Returns the stream ID
    /// for subsequent `send_data()` calls.
    pub fn send_request(
        &mut self,
        quic: &mut QuicEndpoint,
        headers: &[HeaderField],
        end_stream: bool,
    ) -> Result<StreamId, H3Error> {
        // RFC 9114 §5.2: after sending or receiving GOAWAY, the client MUST
        // NOT initiate new requests. Server may also be Closing for an
        // explicit local shutdown. Bail out before opening the stream — the
        // peer would reset it anyway, and the application gets a clear error.
        if matches!(self.state, H3State::Closing | H3State::Closed) {
            return Err(H3Error::Internal(
                "connection is shutting down; cannot send new request".into(),
            ));
        }

        // Honour the peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` if it has been
        // received. Past it the peer will close the connection with
        // H3_EXCESSIVE_LOAD — better to surface that as a local error than
        // ship the bytes and discover the failure later.
        if let Some(remote) = &self.remote_settings
            && field_section_size(headers) > remote.max_field_section_size
        {
            return Err(H3Error::ExcessiveSize);
        }

        let conn = self
            .conn_id
            .ok_or(H3Error::Internal("no connection".into()))?;

        let stream_id = quic
            .open_bi(conn)?
            .ok_or_else(|| H3Error::Internal("cannot open bidi stream".into()))?;

        let mut encoded_headers = Vec::new();
        qpack::encode(headers, &mut encoded_headers);

        let mut buf = Vec::new();
        Frame::Headers {
            encoded: encoded_headers,
        }
        .encode(&mut buf);

        // Register the stream up-front so queue_send's finalize_local_close
        // finds it when the FIN actually reaches the wire (possibly later,
        // once flow control opens).
        let mut rs = RequestStream::new(true);
        rs.state = if end_stream {
            StreamState::HalfClosedLocal
        } else {
            StreamState::Open
        };
        self.request_streams.insert(u64::from(stream_id), rs);

        self.queue_send(quic, conn, stream_id, vec![Bytes::from(buf)], end_stream)?;

        Ok(stream_id)
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
            QuicEvent::Connected(conn) => {
                self.initiate(quic, *conn)?;
            }
            QuicEvent::StreamOpened { conn, stream, bidi } => {
                if *bidi {
                    // On the server, a peer-opened bidi stream is a new HTTP
                    // request. On the client, it would be a server-pushed
                    // resource — but we never sent `MAX_PUSH_ID`, so the
                    // server is not permitted to push (RFC 9114 §4.6 +
                    // §7.2.4.1). Reject with H3_ID_ERROR rather than parsing
                    // arbitrary frames the peer was never authorized to send.
                    if self.role == Some(Role::Client) {
                        // Best-effort reset + stop_sending; ignore errors —
                        // the connection close that follows will tear
                        // everything down anyway.
                        let code = VarInt::from_u32(H3Error::IdError.code());
                        let _ = quic.reset_stream(*conn, *stream, code);
                        let _ = quic.stop_sending(*conn, *stream, code);
                        self.fatal_error(quic, H3Error::IdError);
                        return Ok(());
                    }
                    self.request_streams
                        .insert(u64::from(*stream), RequestStream::new(false));
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
            QuicEvent::StreamWritable { conn, stream } => {
                self.drain_pending_stream(quic, *conn, *stream)?;
            }
            QuicEvent::ZeroRttRejected { .. } => {
                // Quinn discarded everything we sent on 0-RTT keys. Our
                // per-stream tracking now points at streams the server never
                // saw. Drop it all and tell the application to re-issue.
                self.pending_sends.clear();
                self.request_streams.clear();
                self.events.push_back(H3Event::ZeroRttRejected);
            }
            QuicEvent::StreamStopped {
                stream, error_code, ..
            } => {
                // Peer sent STOP_SENDING. Any further writes will fail; the
                // queued chunks in pending_sends will never reach the wire and
                // would otherwise pin memory for the life of the connection.
                self.cleanup_request_stream(*stream);
                self.events.push_back(H3Event::StreamReset {
                    stream_id: *stream,
                    error_code: error_code.into_inner(),
                });
            }
            QuicEvent::ConnectionClosed { .. } => {
                self.state = H3State::Closed;
                // Drop everything keyed by the now-dead connection. Without
                // this, long-lived endpoints accumulate per-stream state for
                // every connection they ever had.
                self.pending_sends.clear();
                self.request_streams.clear();
                self.partial_uni_type_bufs.clear();
                self.pending_uni_streams.clear();
                self.control_recv_buf.clear();
                // Signal the application that the connection is shutting down.
                // GoAway rather than Error: callers waiting for graceful teardown
                // see this as a clean termination; callers that also handle Error
                // (e.g. the receiving side in a test) accept it too.
                self.events.push_back(H3Event::GoAway { stream_id: 0 });
            }
            _ => {}
        }
        Ok(())
    }

    /// Poll the next HTTP/3 event, if any.
    pub fn poll_event(&mut self) -> Option<H3Event> {
        self.events.pop_front()
    }

    /// Send response headers on a stream.
    ///
    /// Partial writes due to flow-control backpressure are queued and
    /// flushed on subsequent `QuicEvent::StreamWritable` events; see
    /// [`send_data`](Self::send_data) for the same semantics.
    pub fn send_response(
        &mut self,
        quic: &mut QuicEndpoint,
        stream_id: StreamId,
        headers: &[HeaderField],
        end_stream: bool,
    ) -> Result<(), H3Error> {
        if let Some(remote) = &self.remote_settings
            && field_section_size(headers) > remote.max_field_section_size
        {
            return Err(H3Error::ExcessiveSize);
        }

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

        self.queue_send(quic, conn, stream_id, vec![Bytes::from(buf)], end_stream)
    }

    /// Send response body data on a stream.
    ///
    /// If the peer's flow-control window can't absorb all of `data`, the
    /// remainder is queued and flushed on subsequent `QuicEvent::StreamWritable`
    /// events. `stream_finish` is deferred to the moment the queue drains.
    /// Poll [`has_pending_writes`](Self::has_pending_writes) to observe
    /// progress.
    ///
    /// The body is copied into a refcounted `Bytes`. Callers that already
    /// own a `Bytes` (e.g. from a file-backed response) should use
    /// [`send_data_bytes`](Self::send_data_bytes) instead to avoid the copy.
    pub fn send_data(
        &mut self,
        quic: &mut QuicEndpoint,
        stream_id: StreamId,
        data: &[u8],
        end_stream: bool,
    ) -> Result<(), H3Error> {
        self.send_data_bytes(quic, stream_id, Bytes::copy_from_slice(data), end_stream)
    }

    /// Zero-copy counterpart of [`send_data`](Self::send_data). The payload
    /// is sent as a refcounted `Bytes`: the DATA frame header is the only
    /// freshly-allocated bytes on the wire path, and any portion that gets
    /// queued behind flow control keeps its refcount — no memcpy on
    /// backpressure.
    pub fn send_data_bytes(
        &mut self,
        quic: &mut QuicEndpoint,
        stream_id: StreamId,
        data: Bytes,
        end_stream: bool,
    ) -> Result<(), H3Error> {
        let conn = self
            .conn_id
            .ok_or(H3Error::Internal("no connection".into()))?;

        // DATA frame = type varint + length varint + payload. The first two
        // are tiny (≤ 9 bytes); build them as a small `Bytes` and hand the
        // payload through as its own chunk so quinn-proto sees it without
        // a memcpy.
        let mut header = Vec::with_capacity(16);
        encode_frame_header(&mut header, frame::FRAME_DATA, data.len() as u64);
        let chunks = vec![Bytes::from(header), data];

        self.queue_send(quic, conn, stream_id, chunks, end_stream)
    }

    /// Send trailing HEADERS (trailers) on a request stream and finish the
    /// stream. Trailers per RFC 9114 §4.1 MUST be the last frame on the
    /// stream, so this method always implies `end_stream = true`. The
    /// trailer header section must not contain pseudo-headers; this is
    /// enforced when the peer decodes them, and ideally the caller validates
    /// up-front.
    pub fn send_trailers(
        &mut self,
        quic: &mut QuicEndpoint,
        stream_id: StreamId,
        trailers: &[HeaderField],
    ) -> Result<(), H3Error> {
        if let Some(remote) = &self.remote_settings
            && field_section_size(trailers) > remote.max_field_section_size
        {
            return Err(H3Error::ExcessiveSize);
        }

        let conn = self
            .conn_id
            .ok_or(H3Error::Internal("no connection".into()))?;

        let mut encoded_headers = Vec::new();
        qpack::encode(trailers, &mut encoded_headers);

        let mut buf = Vec::new();
        Frame::Headers {
            encoded: encoded_headers,
        }
        .encode(&mut buf);

        self.queue_send(quic, conn, stream_id, vec![Bytes::from(buf)], true)
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

        self.queue_send(quic, conn, control, vec![Bytes::from(buf)], false)?;
        self.state = H3State::Closing;
        Ok(())
    }

    /// Returns `true` if any bytes destined for this stream are still waiting
    /// for flow-control credit. Callers that want to observe drain progress
    /// (e.g. "has all my response body been handed to QUIC yet?") can poll
    /// this after processing events.
    pub fn has_pending_writes(&self, stream_id: StreamId) -> bool {
        self.pending_sends
            .get(&u64::from(stream_id))
            .is_some_and(|p| !p.queue.is_empty() || p.pending_fin)
    }

    /// Returns `true` if the H3 layer is tracking per-stream state for
    /// `stream_id` (i.e. it has a `RequestStream` entry). Cleared once both
    /// directions FIN, or when the peer aborts the stream. Useful for
    /// asserting that long-lived connections aren't accumulating stale
    /// state.
    pub fn has_request_stream(&self, stream_id: StreamId) -> bool {
        self.request_streams.contains_key(&u64::from(stream_id))
    }

    /// Number of streams the H3 layer is currently tracking. Drops to zero
    /// once every request has completed (either gracefully via two-sided FIN,
    /// or because the peer reset / stopped the stream).
    pub fn tracked_stream_count(&self) -> usize {
        self.request_streams.len()
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Push one or more [`Bytes`] chunks onto a stream. Chunks that don't
    /// fit in the current flow-control window are queued verbatim — they
    /// stay refcounted, no `extend_from_slice` — and flushed on the next
    /// [`QuicEvent::StreamWritable`]. If `fin` is set, the stream is
    /// finished either immediately (everything flushed) or later
    /// ([`drain_pending_stream`]).
    fn queue_send(
        &mut self,
        quic: &mut QuicEndpoint,
        conn: QuicConnId,
        stream_id: StreamId,
        mut chunks: Vec<Bytes>,
        fin: bool,
    ) -> Result<(), H3Error> {
        let key = u64::from(stream_id);

        // Worst-case: if nothing fits in the peer's window right now, every
        // byte we were handed will land in `pending_sends`. Reject the send
        // up-front if that would push us past the configured cap, rather
        // than partially sending and then failing — partial success would
        // leave the caller unable to safely retry.
        if self.max_pending_bytes != usize::MAX {
            let incoming: usize = chunks.iter().map(|b| b.len()).sum();
            let projected = self.compute_pending_bytes().saturating_add(incoming);
            if projected > self.max_pending_bytes {
                return Err(H3Error::BackpressureExceeded);
            }
        }

        // If this stream already has queued bytes, preserve FIFO ordering by
        // appending instead of racing the head. The queue drains on the next
        // StreamWritable.
        if let Some(pending) = self.pending_sends.get_mut(&key)
            && (!pending.queue.is_empty() || pending.pending_fin)
        {
            for chunk in chunks.drain(..) {
                if !chunk.is_empty() {
                    pending.queue.push_back(chunk);
                }
            }
            if fin {
                pending.pending_fin = true;
            }
            return Ok(());
        }

        match quic.stream_send_chunks(conn, stream_id, &mut chunks) {
            Ok(_) => {}
            Err(ringline_quic::Error::Write(WriteError::Blocked)) => {
                // Budget was zero — all chunks still hold their original
                // data. Fall through and queue them.
            }
            Err(e) => return Err(e.into()),
        }

        // Anything left in any chunk is the remainder. Queue it.
        let mut any_remaining = false;
        for chunk in chunks.drain(..) {
            if !chunk.is_empty() {
                self.pending_sends
                    .entry(key)
                    .or_default()
                    .queue
                    .push_back(chunk);
                any_remaining = true;
            }
        }

        if !any_remaining && fin {
            quic.stream_finish(conn, stream_id)?;
            self.finalize_local_close(stream_id);
            self.pending_sends.remove(&key);
            return Ok(());
        }

        if fin {
            self.pending_sends.entry(key).or_default().pending_fin = true;
        }

        // Garbage-collect entries that wound up with nothing to track.
        if self
            .pending_sends
            .get(&key)
            .is_some_and(PendingStream::is_done)
        {
            self.pending_sends.remove(&key);
        }
        Ok(())
    }

    /// Drain queued bytes for `stream_id` until either the queue is empty or
    /// quinn-proto blocks again. If the queue empties and FIN was deferred,
    /// call `stream_finish` now.
    fn drain_pending_stream(
        &mut self,
        quic: &mut QuicEndpoint,
        conn: QuicConnId,
        stream_id: StreamId,
    ) -> Result<(), H3Error> {
        let key = u64::from(stream_id);
        loop {
            let pending = match self.pending_sends.get_mut(&key) {
                Some(p) => p,
                None => return Ok(()),
            };
            if pending.queue.is_empty() {
                break;
            }
            // `make_contiguous` rearranges VecDeque into a single slice so we
            // can hand quinn-proto multiple chunks per write call. Partial
            // chunks are advanced in place via `split_to`.
            let chunks = pending.queue.make_contiguous();
            let result = quic.stream_send_chunks(conn, stream_id, chunks);

            // Regardless of Ok/Err, scrub now-empty chunks from the front.
            while pending.queue.front().is_some_and(Bytes::is_empty) {
                pending.queue.pop_front();
            }

            match result {
                Ok(0) => break,
                Ok(_) => {}
                Err(ringline_quic::Error::Write(WriteError::Blocked)) => break,
                Err(e) => {
                    // Stream stopped/reset/unwritable. Drop the queue and
                    // surface the error; the app can observe it via poll_event.
                    self.pending_sends.remove(&key);
                    self.events.push_back(H3Event::Error(e.into()));
                    return Ok(());
                }
            }
        }

        // Buffer is empty (or we broke on block). Finish if we deferred FIN
        // earlier and there's truly nothing left to write.
        let (queue_drained, do_fin) = self
            .pending_sends
            .get(&key)
            .map(|p| (p.queue.is_empty(), p.pending_fin))
            .unwrap_or((false, false));
        if queue_drained {
            if do_fin {
                quic.stream_finish(conn, stream_id)?;
                self.finalize_local_close(stream_id);
                self.pending_sends.remove(&key);
            } else {
                // Nothing queued and no deferred FIN → nothing left to track.
                self.pending_sends.remove(&key);
            }
            // If this was our control stream and SETTINGS was previously
            // deferred (queued behind flow control), mark it sent now that
            // it has actually reached the wire.
            if Some(stream_id) == self.our_control_stream {
                self.settings_sent = true;
            }
        }
        Ok(())
    }

    /// Emit a connection-level H3 error and close the QUIC connection with
    /// the corresponding wire error code (RFC 9114 §8.1). Should be used
    /// instead of just `events.push_back(H3Event::Error(...))` whenever the
    /// protocol invariants are violated — without closing, the H3 state
    /// machine is corrupt yet the QUIC connection keeps running and the
    /// peer is never told what went wrong.
    fn fatal_error(&mut self, quic: &mut QuicEndpoint, err: H3Error) {
        let code = err.code();
        if let Some(conn) = self.conn_id
            && !matches!(self.state, H3State::Closed)
        {
            quic.close_connection(conn, code, err.to_string().as_bytes());
        }
        self.state = H3State::Closed;
        self.events.push_back(H3Event::Error(err));
    }

    /// Advance the request-stream state machine when the local send side
    /// closes (either immediately after a successful write or later after the
    /// queue drains). Removes the entry once both halves are closed.
    fn finalize_local_close(&mut self, stream_id: StreamId) {
        let key = u64::from(stream_id);
        let now_closed = if let Some(rs) = self.request_streams.get_mut(&key) {
            rs.state = match rs.state {
                StreamState::HalfClosedRemote | StreamState::Closed => StreamState::Closed,
                _ => StreamState::HalfClosedLocal,
            };
            rs.state == StreamState::Closed
        } else {
            false
        };
        if now_closed {
            self.request_streams.remove(&key);
        }
    }

    /// Advance the request-stream state machine when the remote send side
    /// closes (peer FIN). Removes the entry once both halves are closed.
    fn finalize_remote_close(&mut self, stream_id: StreamId) -> bool {
        let key = u64::from(stream_id);
        let now_closed = if let Some(rs) = self.request_streams.get_mut(&key) {
            rs.state = match rs.state {
                StreamState::HalfClosedLocal | StreamState::Closed => StreamState::Closed,
                _ => StreamState::HalfClosedRemote,
            };
            rs.state == StreamState::Closed
        } else {
            false
        };
        if now_closed {
            self.request_streams.remove(&key);
        }
        now_closed
    }

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
        let sid = u64::from(stream);

        // Restore any bytes from a previous partial read.
        let mut accumulated: Vec<u8> = self.partial_uni_type_bufs.remove(&sid).unwrap_or_default();

        // Read more bytes into the remainder of an 8-byte scratch space.
        let mut scratch = [0u8; 8];
        let want = 8usize.saturating_sub(accumulated.len());
        let (n, _fin) = quic.stream_recv(conn, stream, &mut scratch[..want])?;
        if n == 0 && accumulated.is_empty() {
            // No data at all yet — re-add to pending.
            self.pending_uni_streams.push(stream);
            return Ok(());
        }
        accumulated.extend_from_slice(&scratch[..n]);

        let (stream_type, _consumed) = match frame::decode_varint(&accumulated) {
            Some(v) => v,
            None => {
                // Still incomplete — save what we have and retry later.
                self.partial_uni_type_bufs.insert(sid, accumulated);
                self.pending_uni_streams.push(stream);
                return Ok(());
            }
        };

        match stream_type {
            STREAM_TYPE_CONTROL => {
                if self.control_stream_id.is_some() {
                    // Duplicate control stream is a connection error.
                    self.fatal_error(quic, H3Error::FrameUnexpected);
                    return Ok(());
                }
                self.control_stream_id = Some(stream);
                // Any bytes after the type varint in our accumulated buffer
                // belong to the first control-stream frame — seed the recv buf.
                let consumed = frame::decode_varint(&accumulated)
                    .map(|(_, c)| c)
                    .unwrap_or(0);
                if consumed < accumulated.len() {
                    self.control_recv_buf
                        .extend_from_slice(&accumulated[consumed..]);
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
                // Control stream closed — this is a fatal HTTP/3 error.
                self.fatal_error(quic, H3Error::ClosedCriticalStream);
                return Ok(());
            }
            if n == 0 {
                break;
            }
        }

        // Process frames from the control stream buffer.
        self.process_control_frames(quic)
    }

    fn process_control_frames(&mut self, quic: &mut QuicEndpoint) -> Result<(), H3Error> {
        loop {
            let buf = &self.control_recv_buf;
            if buf.is_empty() {
                break;
            }
            match frame::decode_frame(buf) {
                Ok(Some((frame, consumed))) => {
                    let consumed_bytes = consumed;
                    // RFC 9114 §7.2.4: the first frame on the control stream
                    // MUST be SETTINGS. Anything else — including the unknown
                    // (GREASE) frames that are normally ignored — is a
                    // connection error of type H3_MISSING_SETTINGS.
                    if self.remote_settings.is_none() && !matches!(frame, Frame::Settings(_)) {
                        self.fatal_error(quic, H3Error::MissingSettings);
                        return Ok(());
                    }
                    match frame {
                        Frame::Settings(settings) => {
                            if self.remote_settings.is_some() {
                                // Duplicate SETTINGS is a connection error.
                                self.fatal_error(quic, H3Error::FrameUnexpected);
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
                            // DATA and HEADERS on the control stream are
                            // connection errors.
                            self.fatal_error(quic, H3Error::FrameUnexpected);
                            return Ok(());
                        }
                        Frame::Unknown { .. } => {
                            // Unknown frames are ignored once SETTINGS has
                            // been received (RFC 9114 §7.2.8).
                        }
                    }
                    // Remove consumed bytes in place — reallocating a fresh Vec
                    // here was a per-frame O(n) tax on the control stream.
                    self.control_recv_buf.drain(..consumed_bytes);
                }
                Ok(None) => break, // Incomplete frame, need more data.
                Err(e) => {
                    self.fatal_error(quic, e);
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
                Err(ringline_quic::Error::Read(ReadError::Reset(code))) => {
                    // Peer reset the stream. Without an explicit signal, the
                    // application would sit forever awaiting body bytes that
                    // will never come, and our per-stream state would linger.
                    self.cleanup_request_stream(stream);
                    self.events.push_back(H3Event::StreamReset {
                        stream_id: stream,
                        error_code: code.into_inner(),
                    });
                    return Ok(());
                }
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
        self.process_request_frames(quic, stream, fin_received)
    }

    /// Drop all per-stream state for `stream`. Used when the peer aborts the
    /// stream (STOP_SENDING, RESET_STREAM) or when both directions are FINed.
    fn cleanup_request_stream(&mut self, stream: StreamId) {
        let key = u64::from(stream);
        self.pending_sends.remove(&key);
        self.request_streams.remove(&key);
        self.partial_uni_type_bufs.remove(&key);
    }

    fn process_request_frames(
        &mut self,
        quic: &mut QuicEndpoint,
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
        let mut aborted = false;

        loop {
            let remaining = &recv_buf[offset..];
            if remaining.is_empty() {
                break;
            }

            match frame::decode_frame(remaining) {
                Ok(Some((frame, consumed))) => {
                    offset += consumed;
                    let at_end = fin_received && offset == recv_buf.len();

                    // Snapshot the state machine before dispatching so we can
                    // detect spec violations like DATA-before-HEADERS or
                    // frames after trailers.
                    let snapshot = self.request_streams.get(&u64::from(stream)).map(|rs| {
                        (
                            rs.client_initiated,
                            rs.initial_headers_received,
                            rs.trailers_received,
                            rs.state == StreamState::WaitingHeaders,
                        )
                    });

                    match frame {
                        Frame::Headers { encoded } => {
                            let Some((client_initiated, initial_seen, already_trailed, _)) =
                                snapshot
                            else {
                                break;
                            };
                            // After trailers we accept no further frames on
                            // this stream.
                            if already_trailed {
                                self.fatal_error(quic, H3Error::FrameUnexpected);
                                aborted = true;
                                break;
                            }
                            // Initial vs trailing HEADERS is determined by
                            // whether we've already processed an initial
                            // HEADERS frame on this stream — *not* by the
                            // local FIN state.
                            let is_trailer = initial_seen;
                            // Trailers MUST be the last frame on the stream.
                            if is_trailer && !at_end {
                                self.fatal_error(quic, H3Error::FrameUnexpected);
                                aborted = true;
                                break;
                            }

                            // Pre-decode upper bound: the encoded HEADERS
                            // payload can never be larger than the field
                            // section size for fields that aren't QPACK
                            // dynamic-table references (we don't use the
                            // dynamic table). Reject obvious memory bombs
                            // before we let QPACK allocate.
                            let local_limit = self.local_settings.max_field_section_size;
                            if (encoded.len() as u64) > local_limit {
                                self.fatal_error(quic, H3Error::ExcessiveSize);
                                aborted = true;
                                break;
                            }
                            let headers = match qpack::decode(&encoded) {
                                Ok(h) => h,
                                Err(e) => {
                                    self.fatal_error(quic, e);
                                    aborted = true;
                                    break;
                                }
                            };
                            // Post-decode authoritative check on the field
                            // section size per RFC 9114 §4.2.2.
                            if field_section_size(&headers) > local_limit {
                                self.fatal_error(quic, H3Error::ExcessiveSize);
                                aborted = true;
                                break;
                            }

                            // Validate the header section per RFC 9114
                            // §4.3.1.1 before exposing it to the application.
                            let kind = if is_trailer {
                                HeaderKind::Trailer
                            } else if client_initiated {
                                HeaderKind::Response
                            } else {
                                HeaderKind::Request
                            };
                            if let Err(e) = validate_headers(kind, &headers) {
                                self.fatal_error(quic, e);
                                aborted = true;
                                break;
                            }

                            if is_trailer {
                                if let Some(rs) = self.request_streams.get_mut(&u64::from(stream)) {
                                    rs.trailers_received = true;
                                }
                                // Trailers always end the remote half.
                                self.finalize_remote_close(stream);
                                self.events.push_back(H3Event::Trailers {
                                    stream_id: stream,
                                    headers,
                                });
                                continue;
                            }

                            // Initial headers. Mark seen + advance state.
                            if let Some(rs) = self.request_streams.get_mut(&u64::from(stream)) {
                                rs.initial_headers_received = true;
                            }
                            if at_end {
                                self.finalize_remote_close(stream);
                            } else if let Some(rs) =
                                self.request_streams.get_mut(&u64::from(stream))
                                && rs.state == StreamState::WaitingHeaders
                            {
                                rs.state = StreamState::Open;
                            }
                            if client_initiated {
                                self.events.push_back(H3Event::Response {
                                    stream_id: stream,
                                    headers,
                                    end_stream: at_end,
                                });
                            } else {
                                self.events.push_back(H3Event::Request {
                                    stream_id: stream,
                                    headers,
                                    end_stream: at_end,
                                });
                            }
                        }
                        Frame::Data { payload } => {
                            let Some((_, initial_seen, already_trailed, _)) = snapshot else {
                                break;
                            };
                            // DATA before HEADERS, or DATA after trailers, is
                            // an HTTP/3 message error.
                            if !initial_seen || already_trailed {
                                self.fatal_error(quic, H3Error::FrameUnexpected);
                                aborted = true;
                                break;
                            }

                            if at_end {
                                self.finalize_remote_close(stream);
                            }

                            self.events.push_back(H3Event::Data {
                                stream_id: stream,
                                data: payload,
                                end_stream: at_end,
                            });
                        }
                        Frame::Settings(_) | Frame::GoAway { .. } => {
                            // SETTINGS / GOAWAY are control-stream frames;
                            // their appearance on a request stream is a
                            // connection error.
                            self.fatal_error(quic, H3Error::FrameUnexpected);
                            aborted = true;
                            break;
                        }
                        Frame::Unknown { .. } => {
                            // Unknown frames on request streams are ignored
                            // post-HEADERS; pre-HEADERS they're still a
                            // violation (RFC 9114 §4.1 is strict about the
                            // first frame). We accept them lenient like
                            // most stacks to avoid breaking GREASE.
                        }
                    }
                }
                Ok(None) => break, // Incomplete frame.
                Err(e) => {
                    self.fatal_error(quic, e);
                    aborted = true;
                    break;
                }
            }
        }

        // Handle FIN with no remaining frames — the stream is done.
        if !aborted && fin_received && offset == recv_buf.len() {
            // Synthesize an end-of-stream Data event for streams that received
            // HEADERS but no DATA frame carrying the FIN. WaitingHeaders + FIN
            // (peer cancelled before headers) or HalfClosedLocal + FIN (already
            // FINed) just drive the state machine — no event.
            let emit_empty_fin = self
                .request_streams
                .get(&u64::from(stream))
                .is_some_and(|rs| rs.state == StreamState::Open);
            self.finalize_remote_close(stream);
            if emit_empty_fin {
                self.events.push_back(H3Event::Data {
                    stream_id: stream,
                    data: Vec::new(),
                    end_stream: true,
                });
            }
        }

        // Put unconsumed data back if the entry still exists. If we aborted
        // or finalize_remote_close removed the stream, we drop the buffer.
        if !aborted {
            if offset > 0 {
                recv_buf.drain(..offset);
            }
            if let Some(rs) = self.request_streams.get_mut(&u64::from(stream)) {
                rs.recv_buf = recv_buf;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod validate_headers_tests {
    use super::{HeaderKind, field_section_size, validate_headers};
    use crate::qpack::HeaderField;

    fn h(name: &[u8], value: &[u8]) -> HeaderField {
        HeaderField::new(name, value)
    }

    #[test]
    fn request_requires_method_path_scheme_authority() {
        let ok = vec![
            h(b":method", b"GET"),
            h(b":path", b"/"),
            h(b":scheme", b"https"),
            h(b":authority", b"x"),
        ];
        assert!(validate_headers(HeaderKind::Request, &ok).is_ok());

        // Missing :path.
        let bad = vec![
            h(b":method", b"GET"),
            h(b":scheme", b"https"),
            h(b":authority", b"x"),
        ];
        assert!(validate_headers(HeaderKind::Request, &bad).is_err());
    }

    #[test]
    fn response_requires_status() {
        let ok = vec![h(b":status", b"200")];
        assert!(validate_headers(HeaderKind::Response, &ok).is_ok());
        let bad: Vec<HeaderField> = vec![];
        assert!(validate_headers(HeaderKind::Response, &bad).is_err());
    }

    #[test]
    fn pseudo_after_regular_rejected() {
        let bad = vec![
            h(b":method", b"GET"),
            h(b"user-agent", b"x"),
            h(b":path", b"/"), // pseudo after regular
            h(b":scheme", b"https"),
            h(b":authority", b"x"),
        ];
        assert!(validate_headers(HeaderKind::Request, &bad).is_err());
    }

    #[test]
    fn duplicate_pseudo_rejected() {
        let bad = vec![
            h(b":method", b"GET"),
            h(b":method", b"POST"),
            h(b":path", b"/"),
            h(b":scheme", b"https"),
            h(b":authority", b"x"),
        ];
        assert!(validate_headers(HeaderKind::Request, &bad).is_err());
    }

    #[test]
    fn unknown_pseudo_rejected() {
        let bad = vec![
            h(b":method", b"GET"),
            h(b":weird", b"x"),
            h(b":path", b"/"),
            h(b":scheme", b"https"),
            h(b":authority", b"x"),
        ];
        assert!(validate_headers(HeaderKind::Request, &bad).is_err());
    }

    #[test]
    fn forbidden_connection_specific_rejected() {
        for forbidden in [
            b"connection".as_ref(),
            b"keep-alive".as_ref(),
            b"proxy-connection".as_ref(),
            b"transfer-encoding".as_ref(),
            b"upgrade".as_ref(),
        ] {
            let bad = vec![
                h(b":method", b"GET"),
                h(b":path", b"/"),
                h(b":scheme", b"https"),
                h(b":authority", b"x"),
                h(forbidden, b"value"),
            ];
            assert!(
                validate_headers(HeaderKind::Request, &bad).is_err(),
                "expected {} to be rejected",
                std::str::from_utf8(forbidden).unwrap(),
            );
        }
    }

    #[test]
    fn te_only_trailers_allowed() {
        let bad = vec![
            h(b":method", b"GET"),
            h(b":path", b"/"),
            h(b":scheme", b"https"),
            h(b":authority", b"x"),
            h(b"te", b"gzip"),
        ];
        assert!(validate_headers(HeaderKind::Request, &bad).is_err());

        let ok = vec![
            h(b":method", b"GET"),
            h(b":path", b"/"),
            h(b":scheme", b"https"),
            h(b":authority", b"x"),
            h(b"te", b"trailers"),
        ];
        assert!(validate_headers(HeaderKind::Request, &ok).is_ok());
    }

    #[test]
    fn trailers_forbid_pseudo_headers() {
        let bad = vec![h(b":status", b"200"), h(b"trailer-name", b"v")];
        assert!(validate_headers(HeaderKind::Trailer, &bad).is_err());
        let ok = vec![h(b"trailer-name", b"v")];
        assert!(validate_headers(HeaderKind::Trailer, &ok).is_ok());
    }

    #[test]
    fn connect_request_requires_authority_only() {
        let ok = vec![h(b":method", b"CONNECT"), h(b":authority", b"x:443")];
        assert!(validate_headers(HeaderKind::Request, &ok).is_ok());
        // CONNECT with :path is invalid.
        let bad = vec![
            h(b":method", b"CONNECT"),
            h(b":authority", b"x:443"),
            h(b":path", b"/"),
        ];
        assert!(validate_headers(HeaderKind::Request, &bad).is_err());
    }

    #[test]
    fn field_section_size_includes_per_field_overhead() {
        // RFC 9114 §4.2.2: name.len() + value.len() + 32 per field.
        let headers = vec![h(b"a", b"bc"), h(b"def", b"")];
        // (1+2+32) + (3+0+32) = 35 + 35 = 70
        assert_eq!(field_section_size(&headers), 70);
    }
}
