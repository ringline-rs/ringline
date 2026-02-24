//! Async HTTP/2 connection wrapping `H2Connection` with a pump loop.
//!
//! Follows the momento pattern: fire requests synchronously, then pump the
//! connection (recv bytes → feed H2 → dispatch events → flush sends) until
//! a stream completes.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use bytes::BytesMut;
use ringline::{ConnCtx, ParseResult};
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
}

impl PendingStream {
    fn new() -> Self {
        Self {
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
            done: false,
        }
    }

    fn into_response(self) -> Response {
        Response::new(self.status.unwrap_or(0), self.headers, self.body.freeze())
    }
}

/// Data for a send blocked on flow control.
struct BlockedSend {
    stream_id: u32,
    data: Vec<u8>,
    end_stream: bool,
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
    completed: VecDeque<(u32, Response)>,
    settings_acked: bool,
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

        for (name, value) in extra_headers {
            headers.push(HeaderField::new(name.as_bytes(), value.as_bytes()));
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

    /// Pump until any stream completes. Returns `(stream_id, Response)`.
    pub async fn recv(&mut self) -> Result<(u32, Response), HttpError> {
        // Check if we already have a completed response queued.
        if let Some(completed) = self.completed.pop_front() {
            return Ok(completed);
        }

        loop {
            self.pump_once().await?;

            if let Some(completed) = self.completed.pop_front() {
                return Ok(completed);
            }
        }
    }

    /// Pump until a specific stream completes.
    pub async fn recv_stream(&mut self, stream_id: u32) -> Result<Response, HttpError> {
        // Check completed queue first.
        if let Some(idx) = self.completed.iter().position(|(sid, _)| *sid == stream_id) {
            let (_, resp) = self.completed.remove(idx).unwrap();
            return Ok(resp);
        }

        loop {
            self.pump_once().await?;

            // Check if our target stream completed.
            if let Some(idx) = self.completed.iter().position(|(sid, _)| *sid == stream_id) {
                let (_, resp) = self.completed.remove(idx).unwrap();
                return Ok(resp);
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
        let completed = &mut self.completed;
        let blocked = &mut self.blocked_sends;
        let settings_acked = &mut self.settings_acked;

        let n = self
            .conn
            .with_data(|data| {
                // Feed bytes to H2.
                if let Err(_e) = h2.recv(data) {
                    return ParseResult::Consumed(data.len());
                }

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
                                // Extract :status pseudo-header.
                                for h in &headers {
                                    if h.name == b":status" {
                                        if let Ok(s) = std::str::from_utf8(&h.value) {
                                            ps.status = s.parse().ok();
                                        }
                                    } else {
                                        let name = String::from_utf8_lossy(&h.name).into_owned();
                                        let value = String::from_utf8_lossy(&h.value).into_owned();
                                        ps.headers.push((name, value));
                                    }
                                }
                                if end_stream {
                                    ps.done = true;
                                }
                            }
                        }
                        H2Event::Data {
                            stream_id,
                            data: payload,
                            end_stream,
                        } => {
                            if let Some(ps) = pending.get_mut(&stream_id) {
                                ps.body.extend_from_slice(&payload);
                                if end_stream {
                                    ps.done = true;
                                }
                            }
                        }
                        H2Event::Trailers { stream_id, .. } => {
                            if let Some(ps) = pending.get_mut(&stream_id) {
                                ps.done = true;
                            }
                        }
                        H2Event::StreamReset { stream_id, .. } => {
                            if let Some(ps) = pending.get_mut(&stream_id) {
                                ps.done = true;
                            }
                        }
                        H2Event::GoAway { .. } => {
                            // Mark all pending streams as done.
                            for ps in pending.values_mut() {
                                ps.done = true;
                            }
                        }
                        H2Event::Error(_) => {}
                    }
                }

                // Retry blocked sends — flow control windows may have opened.
                let mut retry = VecDeque::new();
                std::mem::swap(blocked, &mut retry);
                for bs in retry {
                    if let Err(_e) = h2.send_data(bs.stream_id, &bs.data, bs.end_stream) {
                        // Still blocked, re-queue.
                        blocked.push_back(bs);
                    }
                }

                // H2 buffers internally, consume all input.
                ParseResult::Consumed(data.len())
            })
            .await;

        if n == 0 {
            return Err(HttpError::ConnectionClosed);
        }

        // Move completed streams to the completed queue.
        let done_ids: Vec<u32> = pending
            .iter()
            .filter(|(_, ps)| ps.done)
            .map(|(id, _)| *id)
            .collect();
        for id in done_ids {
            if let Some(ps) = pending.remove(&id) {
                completed.push_back((id, ps.into_response()));
            }
        }

        // Flush protocol responses (SETTINGS ACK, WINDOW_UPDATE, PING ACK).
        self.flush_pending_send()?;

        Ok(())
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
