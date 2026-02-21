use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::BytesMut;
use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, Dir, Event, StreamEvent, StreamId,
};
use slab::Slab;

use crate::config::QuicConfig;
use crate::error::Error;
use crate::event::{QuicConnId, QuicEvent};

/// A sans-IO QUIC endpoint.
///
/// Wraps [`quinn_proto::Endpoint`] and exposes an event-queue API.
/// This crate has no runtime dependency — callers are responsible for
/// sending outgoing packets (via [`poll_send`](Self::poll_send)) and
/// feeding incoming datagrams.
///
/// # Usage
///
/// 1. Feed incoming UDP datagrams via [`handle_datagram`](Self::handle_datagram).
/// 2. Drive connection timers via [`drive_timers`](Self::drive_timers).
/// 3. Poll application events via [`poll_event`](Self::poll_event).
/// 4. Drain outgoing packets via [`poll_send`](Self::poll_send).
pub struct QuicEndpoint {
    endpoint: quinn_proto::Endpoint,
    connections: Slab<QuicConnection>,
    /// Maps `ConnectionHandle.0` → slab key.  Grows as needed.
    handle_map: Vec<Option<u32>>,
    /// Application-facing event queue.
    events: VecDeque<QuicEvent>,
    /// Outgoing UDP packets waiting to be sent.
    send_queue: VecDeque<OutgoingPacket>,
    /// Scratch buffer for `poll_transmit`.
    transmit_buf: Vec<u8>,
    /// Scratch buffer for `endpoint.handle()` responses.
    response_buf: Vec<u8>,
    local_addr: SocketAddr,
    client_config: Option<ClientConfig>,
    send_queue_capacity: usize,
}

struct QuicConnection {
    handle: ConnectionHandle,
    conn: quinn_proto::Connection,
    established: bool,
    outbound: bool,
}

struct OutgoingPacket {
    destination: SocketAddr,
    data: Vec<u8>,
}

impl QuicEndpoint {
    /// Create a new QUIC endpoint.
    ///
    /// `local_addr` is the address of the UDP socket this endpoint is bound to.
    pub fn new(config: QuicConfig, local_addr: SocketAddr) -> Self {
        let endpoint = quinn_proto::Endpoint::new(
            config.endpoint_config,
            config.server_config,
            config.allow_mtud,
            config.rng_seed,
        );

        Self {
            endpoint,
            connections: Slab::new(),
            handle_map: Vec::new(),
            events: VecDeque::new(),
            send_queue: VecDeque::new(),
            transmit_buf: Vec::with_capacity(1500),
            response_buf: Vec::with_capacity(1500),
            local_addr,
            client_config: config.client_config,
            send_queue_capacity: config.send_queue_capacity,
        }
    }

    /// Feed an incoming UDP datagram to the QUIC state machine.
    pub fn handle_datagram(&mut self, now: Instant, data: &[u8], peer: SocketAddr) {
        let data = BytesMut::from(data);
        let event = self.endpoint.handle(
            now,
            peer,
            Some(self.local_addr.ip()),
            None, // ECN not yet supported
            data,
            &mut self.response_buf,
        );

        match event {
            Some(DatagramEvent::ConnectionEvent(ch, event)) => {
                if let Some(&Some(key)) = self.handle_map.get(ch.0) {
                    let key = key as usize;
                    self.connections[key].conn.handle_event(event);
                    self.poll_connection(key, now);
                }
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                let result = self.endpoint.accept(
                    incoming,
                    now,
                    &mut self.response_buf,
                    None, // use default server config
                );
                match result {
                    Ok((ch, conn)) => {
                        let key = self.insert_connection(ch, conn, false);
                        self.drain_transmits(key, now);
                        self.poll_connection(key, now);
                    }
                    Err(_) => {
                        // Accept failed (e.g. no server config). Silently drop.
                    }
                }
            }
            Some(DatagramEvent::Response(transmit)) => {
                // Stateless response (e.g. version negotiation, retry).
                let data = self.response_buf[..transmit.size].to_vec();
                self.queue_packet(transmit.destination, data);
            }
            None => {}
        }
    }

    /// Fire expired per-connection timeouts.
    pub fn drive_timers(&mut self, now: Instant) {
        // Collect keys to avoid borrow conflict with poll_connection.
        let keys: Vec<u32> = self.connections.iter().map(|(k, _)| k as u32).collect();

        for key in keys {
            let key = key as usize;
            if !self.connections.contains(key) {
                continue;
            }
            if let Some(timeout) = self.connections[key].conn.poll_timeout()
                && timeout <= now
            {
                self.connections[key].conn.handle_timeout(now);
                self.drain_transmits(key, now);
                self.poll_connection(key, now);
            }
        }
    }

    /// Poll the next application event.
    ///
    /// Returns `None` when no more events are queued.
    pub fn poll_event(&mut self) -> Option<QuicEvent> {
        self.events.pop_front()
    }

    /// Poll the next outgoing UDP packet.
    ///
    /// Returns `(destination, data)` or `None` when the send queue is empty.
    /// The caller is responsible for sending the packet via their UDP socket.
    pub fn poll_send(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.send_queue
            .pop_front()
            .map(|pkt| (pkt.destination, pkt.data))
    }

    /// Initiate an outbound QUIC connection.
    ///
    /// Returns a [`QuicConnId`] that will appear in a future
    /// [`QuicEvent::Connected`] event once the handshake completes.
    pub fn connect(
        &mut self,
        now: Instant,
        peer: SocketAddr,
        server_name: &str,
    ) -> Result<QuicConnId, Error> {
        let client_config = self.client_config.clone().ok_or(Error::ConnectionClosed)?;

        let (ch, conn) = self
            .endpoint
            .connect(now, client_config, peer, server_name)?;

        let key = self.insert_connection(ch, conn, true);
        self.drain_transmits(key, now);
        Ok(QuicConnId(key as u32))
    }

    /// Write data to a QUIC stream.
    ///
    /// Returns the number of bytes written (may be less than `data.len()` due to
    /// flow control).
    pub fn stream_send(
        &mut self,
        conn: QuicConnId,
        stream: StreamId,
        data: &[u8],
    ) -> Result<usize, Error> {
        let c = self.get_conn_mut(conn)?;
        let n = c.conn.send_stream(stream).write(data)?;
        Ok(n)
    }

    /// Read data from a QUIC stream into `buf`.
    ///
    /// Returns `(bytes_read, is_finished)`. When `is_finished` is true, the peer
    /// has finished sending on this stream.
    pub fn stream_recv(
        &mut self,
        conn: QuicConnId,
        stream: StreamId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        let c = self.get_conn_mut(conn)?;
        let mut recv = c.conn.recv_stream(stream);
        let mut chunks = recv.read(true)?;
        let mut total = 0;
        let mut finished = false;

        while total < buf.len() {
            match chunks.next(buf.len() - total) {
                Ok(Some(chunk)) => {
                    let len = chunk.bytes.len();
                    buf[total..total + len].copy_from_slice(&chunk.bytes);
                    total += len;
                }
                Ok(None) => {
                    finished = true;
                    break;
                }
                Err(quinn_proto::ReadError::Blocked) => break,
                Err(e) => {
                    let _ = chunks.finalize();
                    return Err(Error::Read(e));
                }
            }
        }
        let _ = chunks.finalize();
        Ok((total, finished))
    }

    /// Send FIN on a stream, indicating no more data will be sent.
    pub fn stream_finish(&mut self, conn: QuicConnId, stream: StreamId) -> Result<(), Error> {
        let c = self.get_conn_mut(conn)?;
        c.conn
            .send_stream(stream)
            .finish()
            .map_err(|_| Error::ConnectionClosed)?;
        Ok(())
    }

    /// Open a bidirectional stream.
    ///
    /// Returns `None` if the peer's stream concurrency limit has been reached.
    pub fn open_bi(&mut self, conn: QuicConnId) -> Result<Option<StreamId>, Error> {
        let c = self.get_conn_mut(conn)?;
        Ok(c.conn.streams().open(Dir::Bi))
    }

    /// Open a unidirectional stream.
    ///
    /// Returns `None` if the peer's stream concurrency limit has been reached.
    pub fn open_uni(&mut self, conn: QuicConnId) -> Result<Option<StreamId>, Error> {
        let c = self.get_conn_mut(conn)?;
        Ok(c.conn.streams().open(Dir::Uni))
    }

    /// Close a QUIC connection with the given error code and reason.
    pub fn close_connection(&mut self, conn: QuicConnId, code: u32, reason: &[u8]) {
        if let Ok(c) = self.get_conn_mut(conn) {
            c.conn.close(
                Instant::now(),
                quinn_proto::VarInt::from_u32(code),
                bytes::Bytes::copy_from_slice(reason),
            );
        }
    }

    /// Number of active QUIC connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Number of pending outgoing packets.
    pub fn send_queue_len(&self) -> usize {
        self.send_queue.len()
    }

    /// Peer address for a connection, if it exists.
    pub fn remote_addr(&self, conn: QuicConnId) -> Option<SocketAddr> {
        self.connections
            .get(conn.0 as usize)
            .map(|c| c.conn.remote_address())
    }

    // ── Internal helpers ─────────────────────────────────────────────

    fn insert_connection(
        &mut self,
        ch: ConnectionHandle,
        conn: quinn_proto::Connection,
        outbound: bool,
    ) -> usize {
        let key = self.connections.insert(QuicConnection {
            handle: ch,
            conn,
            established: false,
            outbound,
        });

        // Grow handle_map if needed.
        let idx = ch.0;
        if idx >= self.handle_map.len() {
            self.handle_map.resize(idx + 1, None);
        }
        self.handle_map[idx] = Some(key as u32);

        key
    }

    fn get_conn_mut(&mut self, conn: QuicConnId) -> Result<&mut QuicConnection, Error> {
        self.connections
            .get_mut(conn.0 as usize)
            .ok_or(Error::InvalidConnection)
    }

    /// Drain all pending transmits from a connection into the send queue.
    fn drain_transmits(&mut self, key: usize, now: Instant) {
        loop {
            self.transmit_buf.clear();
            let transmit = self.connections[key]
                .conn
                .poll_transmit(now, 1, &mut self.transmit_buf);

            match transmit {
                Some(t) => {
                    let data = self.transmit_buf[..t.size].to_vec();
                    self.queue_packet(t.destination, data);
                }
                None => break,
            }
        }
    }

    /// Drain endpoint events and application events from a connection.
    fn poll_connection(&mut self, key: usize, now: Instant) {
        // 1. Drain endpoint events (e.g. connection ID updates).
        while let Some(event) = self.connections[key].conn.poll_endpoint_events() {
            if let Some(conn_event) = self
                .endpoint
                .handle_event(self.connections[key].handle, event)
            {
                self.connections[key].conn.handle_event(conn_event);
            }
        }

        // 2. Drain transmits generated by endpoint event handling.
        self.drain_transmits(key, now);

        // 3. Drain application events.
        let conn_id = QuicConnId(key as u32);
        while let Some(event) = self.connections[key].conn.poll() {
            match event {
                Event::Connected => {
                    self.connections[key].established = true;
                    if self.connections[key].outbound {
                        self.events.push_back(QuicEvent::Connected(conn_id));
                    } else {
                        self.events.push_back(QuicEvent::NewConnection(conn_id));
                    }
                }
                Event::ConnectionLost { reason } => {
                    self.events.push_back(QuicEvent::ConnectionClosed {
                        conn: conn_id,
                        reason,
                    });
                    self.remove_connection(key);
                    return; // Connection is gone, stop polling.
                }
                Event::Stream(stream_event) => match stream_event {
                    StreamEvent::Opened { dir } => {
                        // Accept all new streams from the peer.
                        while let Some(stream) = self.connections[key].conn.streams().accept(dir) {
                            self.events.push_back(QuicEvent::StreamOpened {
                                conn: conn_id,
                                stream,
                                bidi: dir == Dir::Bi,
                            });
                        }
                    }
                    StreamEvent::Readable { id } => {
                        self.events.push_back(QuicEvent::StreamReadable {
                            conn: conn_id,
                            stream: id,
                        });
                    }
                    StreamEvent::Writable { id } => {
                        self.events.push_back(QuicEvent::StreamWritable {
                            conn: conn_id,
                            stream: id,
                        });
                    }
                    StreamEvent::Finished { id } => {
                        self.events.push_back(QuicEvent::StreamFinished {
                            conn: conn_id,
                            stream: id,
                        });
                    }
                    StreamEvent::Stopped { .. } | StreamEvent::Available { .. } => {
                        // Not surfaced to application.
                    }
                },
                Event::HandshakeDataReady | Event::DatagramReceived | Event::DatagramsUnblocked => {
                    // Not surfaced.
                }
            }
        }

        // 4. Final drain of transmits generated by event processing.
        self.drain_transmits(key, now);

        // 5. If the connection is drained, remove it.
        if self.connections.contains(key) && self.connections[key].conn.is_drained() {
            self.remove_connection(key);
        }
    }

    fn remove_connection(&mut self, key: usize) {
        let qc = self.connections.remove(key);
        let idx = qc.handle.0;
        if idx < self.handle_map.len() {
            self.handle_map[idx] = None;
        }
    }

    fn queue_packet(&mut self, destination: SocketAddr, data: Vec<u8>) {
        if self.send_queue.len() < self.send_queue_capacity {
            self.send_queue
                .push_back(OutgoingPacket { destination, data });
        }
        // Drop excess packets — QUIC handles retransmission.
    }
}
