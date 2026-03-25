use std::io::{self, Read as _, Write as _};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection};

use crate::accumulator::AccumulatorTable;
use crate::buffer::send_copy::SendCopyPool;
use crate::ring::Ring;

/// Information about a negotiated TLS session.
pub struct TlsInfo {
    pub protocol_version: Option<rustls::ProtocolVersion>,
    pub cipher_suite: Option<rustls::SupportedCipherSuite>,
    pub alpn_protocol: Option<Vec<u8>>,
    pub sni_hostname: Option<String>,
}

/// TLS connection kind — server (inbound) or client (outbound).
pub enum TlsConnKind {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl TlsConnKind {
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        match self {
            TlsConnKind::Server(c) => c.read_tls(rd),
            TlsConnKind::Client(c) => c.read_tls(rd),
        }
    }

    pub fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        match self {
            TlsConnKind::Server(c) => c.write_tls(wr),
            TlsConnKind::Client(c) => c.write_tls(wr),
        }
    }

    pub fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match self {
            TlsConnKind::Server(c) => c.process_new_packets(),
            TlsConnKind::Client(c) => c.process_new_packets(),
        }
    }

    pub fn reader(&mut self) -> rustls::Reader<'_> {
        match self {
            TlsConnKind::Server(c) => c.reader(),
            TlsConnKind::Client(c) => c.reader(),
        }
    }

    pub fn writer(&mut self) -> rustls::Writer<'_> {
        match self {
            TlsConnKind::Server(c) => c.writer(),
            TlsConnKind::Client(c) => c.writer(),
        }
    }

    pub fn wants_write(&self) -> bool {
        match self {
            TlsConnKind::Server(c) => c.wants_write(),
            TlsConnKind::Client(c) => c.wants_write(),
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self {
            TlsConnKind::Server(c) => c.is_handshaking(),
            TlsConnKind::Client(c) => c.is_handshaking(),
        }
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            TlsConnKind::Server(c) => c.alpn_protocol(),
            TlsConnKind::Client(c) => c.alpn_protocol(),
        }
    }

    pub fn negotiated_cipher_suite(&self) -> Option<rustls::SupportedCipherSuite> {
        match self {
            TlsConnKind::Server(c) => c.negotiated_cipher_suite(),
            TlsConnKind::Client(c) => c.negotiated_cipher_suite(),
        }
    }

    pub fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        match self {
            TlsConnKind::Server(c) => c.protocol_version(),
            TlsConnKind::Client(c) => c.protocol_version(),
        }
    }

    pub fn sni_hostname(&self) -> Option<&str> {
        match self {
            TlsConnKind::Server(c) => c.server_name(),
            TlsConnKind::Client(_) => None,
        }
    }

    pub fn send_close_notify(&mut self) {
        match self {
            TlsConnKind::Server(c) => c.send_close_notify(),
            TlsConnKind::Client(c) => c.send_close_notify(),
        }
    }
}

/// Per-connection TLS state.
pub struct TlsConn {
    pub conn: TlsConnKind,
    pub handshake_complete: bool,
}

/// Table of TLS connections, indexed by connection slot.
/// Stored as a separate EventLoop field for borrow splitting.
pub struct TlsTable {
    conns: Vec<Option<TlsConn>>,
    server_config: Option<Arc<rustls::ServerConfig>>,
    client_config: Option<Arc<rustls::ClientConfig>>,
    /// Single shared ciphertext scratch buffer (one per worker thread).
    /// Only used synchronously — we process one connection at a time.
    write_buf: Vec<u8>,
}

impl TlsTable {
    /// Create a table with capacity for `max_connections`.
    pub fn new(
        max_connections: u32,
        server_config: Option<Arc<rustls::ServerConfig>>,
        client_config: Option<Arc<rustls::ClientConfig>>,
    ) -> Self {
        let mut conns = Vec::with_capacity(max_connections as usize);
        conns.resize_with(max_connections as usize, || None);
        TlsTable {
            conns,
            server_config,
            client_config,
            write_buf: Vec::new(),
        }
    }

    /// Whether a server config is present (for TLS accept on inbound connections).
    pub fn has_server_config(&self) -> bool {
        self.server_config.is_some()
    }

    /// Whether a client config is present (for TLS connect on outbound connections).
    pub fn has_client_config(&self) -> bool {
        self.client_config.is_some()
    }

    /// Create a new TLS server connection at the given index.
    pub fn create(&mut self, conn_index: u32) {
        let server_config = self
            .server_config
            .as_ref()
            .expect("create() called without server_config");
        let conn = ServerConnection::new(server_config.clone())
            .expect("rustls ServerConnection::new failed");
        self.conns[conn_index as usize] = Some(TlsConn {
            conn: TlsConnKind::Server(conn),
            handshake_complete: false,
        });
    }

    /// Create a new TLS client connection at the given index.
    pub fn create_client(&mut self, conn_index: u32, server_name: ServerName<'static>) {
        let client_config = self
            .client_config
            .as_ref()
            .expect("create_client() called without client_config");
        let conn = ClientConnection::new(client_config.clone(), server_name)
            .expect("rustls ClientConnection::new failed");
        self.conns[conn_index as usize] = Some(TlsConn {
            conn: TlsConnKind::Client(conn),
            handshake_complete: false,
        });
    }

    /// Get a mutable reference to the TLS connection at the given index.
    pub fn get_mut(&mut self, conn_index: u32) -> Option<&mut TlsConn> {
        self.conns[conn_index as usize].as_mut()
    }

    /// Check if a connection has TLS state.
    pub fn has(&self, conn_index: u32) -> bool {
        self.conns[conn_index as usize].is_some()
    }

    /// Remove TLS state for a connection.
    pub fn remove(&mut self, conn_index: u32) {
        self.conns[conn_index as usize] = None;
    }

    /// Get TLS session information for a connection.
    pub fn get_info(&self, conn_index: u32) -> Option<TlsInfo> {
        let tls_conn = self.conns[conn_index as usize].as_ref()?;
        Some(TlsInfo {
            protocol_version: tls_conn.conn.protocol_version(),
            cipher_suite: tls_conn.conn.negotiated_cipher_suite(),
            alpn_protocol: tls_conn.conn.alpn_protocol().map(|s| s.to_vec()),
            sni_hostname: tls_conn.conn.sni_hostname().map(|s| s.to_string()),
        })
    }

    /// Send a TLS close_notify alert and flush the resulting ciphertext.
    /// All SQEs are submitted with IOSQE_IO_LINK so the caller's subsequent
    /// Close SQE is chained and only runs after the close_notify is sent.
    pub fn send_close_notify(
        &mut self,
        conn_index: u32,
        ring: &mut Ring,
        send_copy_pool: &mut SendCopyPool,
    ) {
        let (conn_slot, write_buf) = borrow_conn_and_buf(self, conn_index);
        if let Some(tls_conn) = conn_slot {
            tls_conn.conn.send_close_notify();
            flush_close_notify_linked(tls_conn, write_buf, ring, send_copy_pool, conn_index);
        }
    }
}

/// Result of feeding ciphertext into a TLS connection.
pub enum TlsRecvResult {
    /// Data processed successfully.
    Ok,
    /// TLS handshake just completed — caller should fire on_accept.
    HandshakeJustCompleted,
    /// TLS error occurred.
    Error(rustls::Error),
    /// Peer sent close_notify or connection is cleanly closed.
    Closed,
}

/// Feed received ciphertext into the TLS connection, decrypt plaintext into
/// the accumulator, and flush any TLS output (handshake responses, alerts).
pub fn feed_tls_recv(
    tls_table: &mut TlsTable,
    accumulators: &mut AccumulatorTable,
    ring: &mut Ring,
    send_copy_pool: &mut SendCopyPool,
    scratch: &mut Vec<u8>,
    conn_index: u32,
    ciphertext: &[u8],
) -> TlsRecvResult {
    let tls_conn = match tls_table.conns[conn_index as usize].as_mut() {
        Some(tc) => tc,
        None => return TlsRecvResult::Closed,
    };

    let was_handshaking = !tls_conn.handshake_complete;

    // Feed ciphertext into rustls.
    let mut cursor = io::Cursor::new(ciphertext);
    if let Err(e) = tls_conn.conn.read_tls(&mut cursor) {
        return TlsRecvResult::Error(rustls::Error::General(e.to_string()));
    }

    // Drive the TLS state machine.
    let state = match tls_conn.conn.process_new_packets() {
        Ok(state) => state,
        Err(e) => {
            // Try to flush alert before returning error.
            if tls_conn.conn.wants_write() {
                flush_tls_output_inner(
                    tls_conn,
                    &mut tls_table.write_buf,
                    ring,
                    send_copy_pool,
                    conn_index,
                );
            }
            return TlsRecvResult::Error(e);
        }
    };

    // Read decrypted plaintext into accumulator.
    if state.plaintext_bytes_to_read() > 0 {
        let mut reader = tls_conn.conn.reader();
        loop {
            match reader.read(scratch.as_mut_slice()) {
                Ok(0) => break,
                Ok(n) => {
                    accumulators.append(conn_index, &scratch[..n]);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    // Flush any TLS output (handshake messages, alerts, etc.).
    if tls_conn.conn.wants_write() {
        flush_tls_output_inner(
            tls_conn,
            &mut tls_table.write_buf,
            ring,
            send_copy_pool,
            conn_index,
        );
    }

    // Check if handshake just completed.
    if was_handshaking && !tls_conn.conn.is_handshaking() {
        tls_conn.handshake_complete = true;
        return TlsRecvResult::HandshakeJustCompleted;
    }

    // Check for clean close.
    if state.peer_has_closed() {
        return TlsRecvResult::Closed;
    }

    TlsRecvResult::Ok
}

/// Flush pending TLS output to the network. Public entry point takes `&mut TlsTable`.
pub fn flush_tls_output(
    tls_table: &mut TlsTable,
    ring: &mut Ring,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
) {
    let (conn_slot, write_buf) = borrow_conn_and_buf(tls_table, conn_index);
    if let Some(tls_conn) = conn_slot {
        flush_tls_output_inner(tls_conn, write_buf, ring, send_copy_pool, conn_index);
    }
}

/// Inner flush: takes disjoint borrows of TlsConn and the shared write_buf.
fn flush_tls_output_inner(
    tls_conn: &mut TlsConn,
    write_buf: &mut Vec<u8>,
    ring: &mut Ring,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
) {
    write_buf.clear();
    if tls_conn.conn.write_tls(write_buf).is_err() {
        return;
    }

    if write_buf.is_empty() {
        return;
    }

    let slot_size = send_copy_pool.slot_size() as usize;

    // Chunk ciphertext into pool-sized pieces and submit as TlsSend.
    for chunk in write_buf.chunks(slot_size) {
        if let Some((slot, ptr, len)) = send_copy_pool.copy_in(chunk) {
            let _ = ring.submit_tls_send(conn_index, ptr, len, slot);
        }
    }
}

/// Flush close_notify ciphertext using linked SQEs (IOSQE_IO_LINK).
/// All TlsSend SQEs are linked so the caller's subsequent Close SQE
/// is chained — the kernel won't close the fd until the alert is sent.
fn flush_close_notify_linked(
    tls_conn: &mut TlsConn,
    write_buf: &mut Vec<u8>,
    ring: &mut Ring,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
) {
    write_buf.clear();
    if tls_conn.conn.write_tls(write_buf).is_err() {
        return;
    }

    if write_buf.is_empty() {
        return;
    }

    let slot_size = send_copy_pool.slot_size() as usize;

    for chunk in write_buf.chunks(slot_size) {
        if let Some((slot, ptr, len)) = send_copy_pool.copy_in(chunk) {
            let _ = ring.submit_tls_send_linked(conn_index, ptr, len, slot);
        }
    }
}

/// Encrypt plaintext and send it. Uses OpTag::Send so the handler
/// receives on_send_complete.
pub fn encrypt_and_send(
    tls_table: &mut TlsTable,
    ring: &mut Ring,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
    plaintext: &[u8],
) -> io::Result<()> {
    let (conn_slot, write_buf) = borrow_conn_and_buf(tls_table, conn_index);
    let tls_conn = conn_slot.as_mut().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotConnected, "no TLS state for connection")
    })?;

    // Write plaintext into rustls (encrypts in place).
    tls_conn
        .conn
        .writer()
        .write_all(plaintext)
        .map_err(io::Error::other)?;

    // Extract ciphertext into shared scratch buffer.
    write_buf.clear();
    tls_conn
        .conn
        .write_tls(write_buf)
        .map_err(io::Error::other)?;

    if write_buf.is_empty() {
        return Ok(());
    }

    let slot_size = send_copy_pool.slot_size() as usize;
    let total_chunks = write_buf.len().div_ceil(slot_size);
    let last_idx = total_chunks.saturating_sub(1);

    for (i, chunk) in write_buf.chunks(slot_size).enumerate() {
        let (slot, ptr, len) = send_copy_pool
            .copy_in(chunk)
            .ok_or_else(|| io::Error::other("send copy pool exhausted for TLS"))?;

        if i == last_idx {
            // Last chunk uses OpTag::Send so handler gets on_send_complete.
            ring.submit_send_copied(conn_index, ptr, len, slot)?;
        } else {
            // Intermediate chunks use TlsSend (no callback, just release slot).
            ring.submit_tls_send(conn_index, ptr, len, slot)?;
        }
    }

    Ok(())
}

/// Borrow a connection slot and the shared write_buf from a TlsTable simultaneously.
/// This is the borrow-splitting helper: `conns[i]` and `write_buf` are disjoint fields.
fn borrow_conn_and_buf(
    table: &mut TlsTable,
    conn_index: u32,
) -> (&mut Option<TlsConn>, &mut Vec<u8>) {
    (&mut table.conns[conn_index as usize], &mut table.write_buf)
}
