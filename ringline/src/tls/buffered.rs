// Without the `tls-buffered` feature, `TlsTable::create`/`create_client` select
// the unbuffered engine and the dispatchers in `backend_mio`/`backend_uring`
// never route here, so every item in this file is compiled-but-unselected.
// That is not dead code to delete: enabling `tls-buffered` brings the whole
// engine back, and an item-by-item allow would just spell the same statement
// out nine times. On mio this is invisible (`lib.rs` masks the whole `tls`
// module); a Linux io_uring build without `tls-buffered` fails `-D warnings`
// without this allow.
#![cfg_attr(not(feature = "tls-buffered"), allow(dead_code))]

#[allow(unused_imports)]
use std::io::{self, Read as _, Write as _};
#[allow(unused_imports)]
use std::sync::Arc;

#[allow(unused_imports)]
use ringline_tls::pki_types::ServerName;
#[allow(unused_imports)]
use ringline_tls::{ClientConnection, ServerConnection};

#[allow(unused_imports)]
use crate::accumulator::AccumulatorTable;
#[cfg(has_io_uring)]
#[allow(unused_imports)]
use crate::buffer::send_copy::SendCopyPool;

use super::*;

/// A rustls connection driven through the *buffered* API
/// (`read_tls` / `process_new_packets` / `write_tls` / `send_close_notify`).
///
/// Without the `tls-buffered` feature, `TlsTable::create`/`create_client`
/// build the unbuffered engine, so nothing constructs these variants — the
/// buffered engine is compiled but unselected. That is not dead code to
/// delete: enabling `tls-buffered` brings the whole engine back.
/// Subsumed by the module-level allow at the top of this file, and kept
/// anyway: these two constructors are the root of why the rest of the module
/// is unselected, so the statement belongs on them even if the file-level
/// attribute is what silences the lint.
#[cfg_attr(not(feature = "tls-buffered"), allow(dead_code))]
pub enum BufferedKind {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl BufferedKind {
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        match self {
            BufferedKind::Server(c) => c.read_tls(rd),
            BufferedKind::Client(c) => c.read_tls(rd),
        }
    }

    pub fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        match self {
            BufferedKind::Server(c) => c.write_tls(wr),
            BufferedKind::Client(c) => c.write_tls(wr),
        }
    }

    pub fn process_new_packets(&mut self) -> Result<ringline_tls::IoState, ringline_tls::Error> {
        match self {
            BufferedKind::Server(c) => c.process_new_packets(),
            BufferedKind::Client(c) => c.process_new_packets(),
        }
    }

    pub fn reader(&mut self) -> ringline_tls::Reader<'_> {
        match self {
            BufferedKind::Server(c) => c.reader(),
            BufferedKind::Client(c) => c.reader(),
        }
    }

    pub fn writer(&mut self) -> ringline_tls::Writer<'_> {
        match self {
            BufferedKind::Server(c) => c.writer(),
            BufferedKind::Client(c) => c.writer(),
        }
    }

    pub fn wants_write(&self) -> bool {
        match self {
            BufferedKind::Server(c) => c.wants_write(),
            BufferedKind::Client(c) => c.wants_write(),
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self {
            BufferedKind::Server(c) => c.is_handshaking(),
            BufferedKind::Client(c) => c.is_handshaking(),
        }
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            BufferedKind::Server(c) => c.alpn_protocol(),
            BufferedKind::Client(c) => c.alpn_protocol(),
        }
    }

    pub fn negotiated_cipher_suite(&self) -> Option<ringline_tls::SupportedCipherSuite> {
        match self {
            BufferedKind::Server(c) => c.negotiated_cipher_suite(),
            BufferedKind::Client(c) => c.negotiated_cipher_suite(),
        }
    }

    pub fn protocol_version(&self) -> Option<ringline_tls::ProtocolVersion> {
        match self {
            BufferedKind::Server(c) => c.protocol_version(),
            BufferedKind::Client(c) => c.protocol_version(),
        }
    }

    pub fn sni_hostname(&self) -> Option<&str> {
        match self {
            BufferedKind::Server(c) => c.server_name(),
            BufferedKind::Client(_) => None,
        }
    }

    /// Buffered-only, like `read_tls` et al. above -- not because rustls
    /// scopes `CommonState::send_close_notify` to the buffered API (it
    /// doesn't; `CommonState` is shared by both engines), but because it
    /// isn't reachable through the unbuffered connection types regardless:
    /// `UnbufferedConnectionCommon` implements `Deref` to `CommonState` but
    /// not `DerefMut`, so a `&mut self` call can't reach it through
    /// `UnbufferedServerConnection`/`UnbufferedClientConnection` (verified
    /// against rustls 0.23.41's `src/conn.rs`). The unbuffered engine's
    /// close_notify goes through `WriteTraffic::queue_close_notify` instead
    /// -- see `docs/tls-unbuffered-design.md` ("### close_notify").
    pub fn send_close_notify(&mut self) {
        match self {
            BufferedKind::Server(c) => c.send_close_notify(),
            BufferedKind::Client(c) => c.send_close_notify(),
        }
    }
}

/// Unwrap the buffered engine out of a `TlsConn`. Every `TlsConn` reaching
/// this module is driven by the buffered engine: the dispatchers in
/// `backend_mio`/`backend_uring` only route here in a build where
/// `TlsTable::create` selects it, so `None` is a routing bug, not a runtime
/// condition. This panics rather than threading an `Option` through call sites
/// that don't return `io::Result` (those that do get a fallible version
/// inline instead — see e.g. `encrypt_to_sends_buffered`).
fn buffered_mut(tls_conn: &mut TlsConn) -> &mut BufferedKind {
    tls_conn
        .conn
        .as_buffered_mut()
        .expect("TLS connection not driven by the buffered engine")
}

/// Feed received ciphertext into the TLS connection, decrypt plaintext into
/// the accumulator, and flush any TLS output (handshake responses, alerts).
/// Any TLS output produced (handshake responses, alerts) is appended to
/// `out_sends`; the caller must route those through the per-connection send
/// queue whatever the return value (dropping them leaks their pool slots).
#[cfg(has_io_uring)]
pub(super) fn feed_tls_recv_buffered(
    tls_table: &mut TlsTable,
    accumulators: &mut AccumulatorTable,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
    generation: u32,
    ciphertext: &[u8],
    out_sends: &mut Vec<crate::handler::BuiltSend>,
) -> TlsRecvResult {
    let tls_conn = match tls_table.conns[conn_index as usize].as_mut() {
        Some(tc) => tc,
        None => return TlsRecvResult::Closed,
    };

    let was_handshaking = !tls_conn.handshake_complete;

    // Feed ciphertext into rustls. Loop until rustls has consumed the
    // entire ciphertext slice, OR a single `read_tls` call returned
    // 0 (meaning rustls's internal buffer is full and refuses more
    // bytes until we drain plaintext). rustls's `read_tls` reads in
    // chunks bounded by its internal buffer size (4 KiB at the time
    // of writing); a single ciphertext slice that crosses that
    // boundary — common for any TLS record carrying ≥ ~4 KiB of
    // plaintext, since rustls hasn't decrypted enough yet to free
    // buffer space — would otherwise leave the tail unfed,
    // permanently desynchronising the application from the wire.
    let mut cursor = io::Cursor::new(ciphertext);
    while cursor.position() < ciphertext.len() as u64 {
        match buffered_mut(tls_conn).read_tls(&mut cursor) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                return TlsRecvResult::Error(e);
            }
        }
        // Drive the state machine after each chunk so rustls can
        // free buffer space (by decrypting+queueing plaintext) and
        // accept the next chunk on the following iteration.
        let state = match buffered_mut(tls_conn).process_new_packets() {
            Ok(state) => state,
            Err(e) => {
                if tls_conn.conn.wants_write() {
                    let _ = take_tls_output_sends(
                        tls_conn,
                        send_copy_pool,
                        conn_index,
                        generation,
                        out_sends,
                    );
                }
                return TlsRecvResult::Error(super::record_layer_error(e));
            }
        };

        // Drain plaintext after each call so rustls's internal
        // buffer has room for the next `read_tls`.
        if state.plaintext_bytes_to_read() > 0
            && !drain_tls_plaintext(tls_conn, accumulators, conn_index)
        {
            return TlsRecvResult::Error(crate::accumulator::recv_cap_exceeded());
        }
    }

    // Final state read for the wants_write / handshake / closed
    // checks below.
    let state = match buffered_mut(tls_conn).process_new_packets() {
        Ok(state) => state,
        Err(e) => {
            if tls_conn.conn.wants_write() {
                let _ = take_tls_output_sends(
                    tls_conn,
                    send_copy_pool,
                    conn_index,
                    generation,
                    out_sends,
                );
            }
            return TlsRecvResult::Error(super::record_layer_error(e));
        }
    };

    // Drain any remaining plaintext that the final state machine
    // tick produced (e.g. from a record whose ciphertext was
    // entirely buffered earlier in the loop).
    if state.plaintext_bytes_to_read() > 0
        && !drain_tls_plaintext(tls_conn, accumulators, conn_index)
    {
        return TlsRecvResult::Error(crate::accumulator::recv_cap_exceeded());
    }

    // Collect any TLS output (handshake messages, alerts, etc.).
    if tls_conn.conn.wants_write()
        && !take_tls_output_sends(tls_conn, send_copy_pool, conn_index, generation, out_sends)
    {
        return TlsRecvResult::Error(io::Error::other(
            "send pool exhausted during TLS output flush",
        ));
    }

    let peer_closed = state.peer_has_closed();
    if peer_closed {
        tls_conn.peer_sent_close_notify = true;
    }

    // Check if handshake just completed.
    if was_handshaking && !tls_conn.conn.is_handshaking() {
        tls_conn.handshake_complete = true;
        return TlsRecvResult::HandshakeJustCompleted { peer_closed };
    }

    // Check for clean close.
    if peer_closed {
        return TlsRecvResult::Closed;
    }

    TlsRecvResult::Ok
}

/// Collect pending TLS output as queueable sends. Public entry point takes
/// `&mut TlsTable`. Returns `false` if pool exhaustion prevented draining
/// all output; sends already appended must still be queued by the caller.
#[cfg(has_io_uring)]
pub(super) fn flush_tls_output_buffered(
    tls_table: &mut TlsTable,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
    generation: u32,
    out_sends: &mut Vec<crate::handler::BuiltSend>,
) -> bool {
    if let Some(tls_conn) = tls_table.get_mut(conn_index) {
        take_tls_output_sends(tls_conn, send_copy_pool, conn_index, generation, out_sends)
    } else {
        true
    }
}

/// `io::Write` adapter that lands `write_tls` output directly in
/// `SendCopyPool` slots, eliminating the ciphertext bounce through a scratch
/// `Vec` (rustls buffer → scratch → pool becomes rustls buffer → pool).
///
/// Slots are filled front-to-back and sealed when full; the partially
/// filled tail slot is sealed by [`into_filled`](Self::into_filled). On pool
/// exhaustion `write` reports whatever it copied (rustls keeps the rest
/// buffered) and errors on the next call — callers treat exhaustion as a
/// broken connection either way, and [`release_all`](Self::release_all)
/// returns every slot on the error path.
#[cfg(has_io_uring)]
struct PoolWriter<'a> {
    pool: &'a mut SendCopyPool,
    /// Slot currently being filled: (slot, base, capacity, used).
    current: Option<(u16, *mut u8, usize, usize)>,
    /// Sealed slots in fill order: (slot, len).
    filled: Vec<(u16, u32)>,
    exhausted: bool,
}

#[cfg(has_io_uring)]
impl<'a> PoolWriter<'a> {
    fn new(pool: &'a mut SendCopyPool) -> Self {
        PoolWriter {
            pool,
            current: None,
            filled: Vec::new(),
            exhausted: false,
        }
    }

    /// Seal the partially-filled tail slot (if any) into `filled`.
    fn seal_current(&mut self) {
        if let Some((slot, _, _, used)) = self.current.take() {
            if used > 0 {
                self.pool.set_filled(slot, used as u32);
                self.filled.push((slot, used as u32));
            } else {
                self.pool.release(slot);
            }
        }
    }

    /// Finish writing: seal the tail and return the filled slots in order.
    fn into_filled(mut self) -> Vec<(u16, u32)> {
        self.seal_current();
        std::mem::take(&mut self.filled)
    }

    /// Error path: return every allocated slot to the pool.
    fn release_all(mut self) {
        if let Some((slot, _, _, _)) = self.current.take() {
            self.pool.release(slot);
        }
        for (slot, _) in self.filled.drain(..) {
            self.pool.release(slot);
        }
    }
}

#[cfg(has_io_uring)]
impl io::Write for PoolWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.exhausted {
            return Err(io::Error::other("send copy pool exhausted for TLS"));
        }
        let mut copied = 0;
        while copied < buf.len() {
            if self.current.is_none() {
                match self.pool.alloc_raw() {
                    Some((slot, ptr, cap)) => {
                        self.current = Some((slot, ptr, cap as usize, 0));
                    }
                    None => {
                        self.exhausted = true;
                        if copied > 0 {
                            // Short write: rustls keeps the remainder
                            // buffered; the next call errors.
                            return Ok(copied);
                        }
                        return Err(io::Error::other("send copy pool exhausted for TLS"));
                    }
                }
            }
            let (_, ptr, cap, used) = self.current.as_mut().expect("just ensured");
            let n = (buf.len() - copied).min(*cap - *used);
            // Safety: `ptr` is the base of an in_use pool slot of size `cap`;
            // `used + n <= cap` by construction, and `buf` is a live slice.
            unsafe {
                std::ptr::copy_nonoverlapping(buf.as_ptr().add(copied), ptr.add(*used), n);
            }
            *used += n;
            copied += n;
            if *used == *cap {
                self.seal_current();
            }
        }
        Ok(copied)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Drain rustls' pending TLS output (handshake messages, alerts) into
/// pool-backed sends appended to `out`, tagged `TlsSend`.
///
/// Returns `false` on pool exhaustion or a `write_tls` error — the
/// connection should be considered broken. Sends already appended to `out`
/// must still be queued by the caller (their pool slots are otherwise
/// leaked); queueing a prefix of the output ahead of a close is safe.
// `pub(super)` rather than private: `TlsTable::send_close_notify_queued` in the
// parent module calls this. A child can see an ancestor's privates but not the
// reverse, so the single-file version's module-private visibility has to be
// spelled out now that the file is split. This is no wider than it was.
#[cfg(has_io_uring)]
pub(super) fn take_tls_output_sends(
    tls_conn: &mut TlsConn,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
    generation: u32,
    out: &mut Vec<crate::handler::BuiltSend>,
) -> bool {
    let mut writer = PoolWriter::new(send_copy_pool);
    while tls_conn.conn.wants_write() {
        match buffered_mut(tls_conn).write_tls(&mut writer) {
            Ok(0) | Err(_) => {
                // Pool exhaustion or writer error: release what this call
                // allocated. Sends appended to `out` by *earlier* calls are
                // untouched, preserving the caller contract.
                writer.release_all();
                return false;
            }
            Ok(_) => {}
        }
    }
    for (slot, len) in writer.into_filled() {
        let (ptr, _) = send_copy_pool.current_ptr_remaining(slot);
        out.push(build_pool_send(
            conn_index,
            generation,
            ptr,
            len,
            slot,
            crate::completion::OpTag::TlsSend,
        ));
    }
    true
}

#[cfg(has_io_uring)]
pub(super) fn encrypt_to_sends_buffered(
    tls_table: &mut TlsTable,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
    generation: u32,
    plaintext: &[u8],
) -> io::Result<Vec<crate::handler::BuiltSend>> {
    let tls_conn = tls_table.get_mut(conn_index).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotConnected, "no TLS state for connection")
    })?;
    let buffered = tls_conn
        .conn
        .as_buffered_mut()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;

    let mut writer = PoolWriter::new(send_copy_pool);
    let mut offset = 0;
    while offset < plaintext.len() {
        let n = match buffered.writer().write(&plaintext[offset..]) {
            Ok(n) => n,
            Err(e) => {
                writer.release_all();
                return Err(io::Error::other(e));
            }
        };
        offset += n;

        // Drain whatever ciphertext this write produced.
        let mut drained = 0usize;
        while buffered.wants_write() {
            match buffered.write_tls(&mut writer) {
                Ok(0) => break,
                Ok(w) => drained += w,
                Err(e) => {
                    writer.release_all();
                    return Err(io::Error::other(e));
                }
            }
        }
        if n == 0 && drained == 0 {
            // rustls accepted nothing and produced nothing — no progress
            // (includes writer exhaustion with nothing drained).
            writer.release_all();
            return Err(io::Error::other("TLS encryption made no progress"));
        }
    }

    let filled = writer.into_filled();
    let mut built = Vec::with_capacity(filled.len());
    for (i, &(slot, len)) in filled.iter().enumerate() {
        let (ptr, _) = send_copy_pool.current_ptr_remaining(slot);
        // Final chunk completes the logical send (settles its id, drives
        // the queue via handle_send); intermediates are TLS-internal.
        let tag = if i + 1 == filled.len() {
            crate::completion::OpTag::Send
        } else {
            crate::completion::OpTag::TlsSend
        };
        built.push(build_pool_send(conn_index, generation, ptr, len, slot, tag));
    }
    Ok(built)
}

// ── Mio backend TLS helpers ─────────────────────────────────────────────

/// Buffered-engine half of [`super::backend_mio::feed_tls_recv_mio`]: feed
/// received ciphertext into the TLS connection, decrypt plaintext into the
/// accumulator, and queue any TLS output (handshake responses, alerts) onto
/// the connection's send FIFO.
#[cfg(not(has_io_uring))]
pub(super) fn feed_tls_recv_mio_buffered(
    tls_table: &mut TlsTable,
    accumulators: &mut AccumulatorTable,
    pending: &mut std::collections::VecDeque<crate::backend::mio::driver::PendingSend>,
    conn_index: u32,
    ciphertext: &[u8],
) -> TlsRecvResult {
    let tls_conn = match tls_table.conns[conn_index as usize].as_mut() {
        Some(tc) => tc,
        None => return TlsRecvResult::Closed,
    };

    let was_handshaking = !tls_conn.handshake_complete;
    let mut peer_closed = false;
    let mut remaining = ciphertext;

    // Feed ciphertext into rustls in a loop. `read_tls` may not consume all
    // input at once (rustls has an internal buffer limit, typically 4KB).
    // After each `read_tls` + `process_new_packets`, drain decrypted plaintext
    // and retry with remaining ciphertext.
    while !remaining.is_empty() {
        let mut cursor = io::Cursor::new(remaining);
        if let Err(e) = buffered_mut(tls_conn).read_tls(&mut cursor) {
            return TlsRecvResult::Error(e);
        }
        let consumed = cursor.position() as usize;
        if consumed == 0 {
            // read_tls consumed nothing — shouldn't happen with a non-empty
            // cursor, but guard against infinite loops.
            break;
        }
        remaining = &remaining[consumed..];

        // Drive the TLS state machine.
        let state = match buffered_mut(tls_conn).process_new_packets() {
            Ok(state) => state,
            Err(e) => {
                // Try to flush alert before returning error.
                if tls_conn.conn.wants_write() {
                    flush_tls_output_mio_inner(tls_conn, &mut tls_table.write_buf, pending);
                }
                return TlsRecvResult::Error(super::record_layer_error(e));
            }
        };

        // Read decrypted plaintext into accumulator.
        if state.plaintext_bytes_to_read() > 0
            && !drain_tls_plaintext(tls_conn, accumulators, conn_index)
        {
            return TlsRecvResult::Error(crate::accumulator::recv_cap_exceeded());
        }

        // Queue any TLS output (handshake messages, alerts, etc.).
        if tls_conn.conn.wants_write() {
            flush_tls_output_mio_inner(tls_conn, &mut tls_table.write_buf, pending);
        }

        if state.peer_has_closed() {
            peer_closed = true;
            tls_conn.peer_sent_close_notify = true;
        }
    }

    // Check if handshake just completed.
    if was_handshaking && !tls_conn.conn.is_handshaking() {
        tls_conn.handshake_complete = true;
        return TlsRecvResult::HandshakeJustCompleted { peer_closed };
    }

    // Check for clean close.
    if peer_closed {
        return TlsRecvResult::Closed;
    }

    TlsRecvResult::Ok
}

/// Buffered-engine half of [`super::backend_mio::flush_tls_output_mio_queued`]:
/// drain rustls' pending TLS output onto the connection's send FIFO.
#[cfg(not(has_io_uring))]
pub(super) fn flush_tls_output_mio_queued_buffered(
    tls_table: &mut TlsTable,
    pending: &mut std::collections::VecDeque<crate::backend::mio::driver::PendingSend>,
    conn_index: u32,
) {
    let (conn_slot, write_buf) = borrow_conn_and_buf(tls_table, conn_index);
    if let Some(tls_conn) = conn_slot {
        flush_tls_output_mio_inner(tls_conn, write_buf, pending);
    }
}

/// Inner flush for mio: queue ciphertext into the connection's pending-send
/// FIFO instead of writing to the stream directly. Direct writes dropped
/// the unwritten remainder on WouldBlock — losing handshake/alert bytes
/// with no retry (a truncated TLS record stalls the peer's handshake) —
/// and could reorder records around ciphertext already sitting in
/// pending_sends.
#[cfg(not(has_io_uring))]
fn flush_tls_output_mio_inner(
    tls_conn: &mut TlsConn,
    write_buf: &mut Vec<u8>,
    pending: &mut std::collections::VecDeque<crate::backend::mio::driver::PendingSend>,
) {
    write_buf.clear();
    if drain_tls_output(tls_conn, write_buf).is_err() {
        return;
    }

    if write_buf.is_empty() {
        return;
    }

    pending.push_back(crate::backend::mio::driver::PendingSend::plain(
        std::mem::take(write_buf),
    ));
}

/// Append all of rustls' pending TLS output to `buf`. One `write_tls` call
/// writes at most 64 of rustls' buffered chunks, so a flight of more records
/// than that takes several calls. The rest would stay in rustls until the
/// next receive or send, which a peer waiting for the rest of the flight
/// does not cause.
#[cfg(not(has_io_uring))]
fn drain_tls_output(tls_conn: &mut TlsConn, buf: &mut Vec<u8>) -> io::Result<()> {
    while tls_conn.conn.wants_write() {
        if buffered_mut(tls_conn).write_tls(buf)? == 0 {
            break;
        }
    }
    Ok(())
}

/// Buffered-engine half of [`super::backend_mio::flush_tls_output_mio_direct`]:
/// direct-write flush for close paths (close_notify). The connection is being
/// torn down, so best-effort nonblocking writes are appropriate — there is no
/// later flush opportunity. The alert itself was queued by the caller's
/// `send_close_notify`; this only drains what rustls already holds.
#[cfg(not(has_io_uring))]
pub(super) fn flush_tls_output_mio_direct_buffered(
    tls_table: &mut TlsTable,
    stream: &mut mio::net::TcpStream,
    conn_index: u32,
) {
    let (conn_slot, write_buf) = borrow_conn_and_buf(tls_table, conn_index);
    let Some(tls_conn) = conn_slot else { return };
    write_buf.clear();
    if drain_tls_output(tls_conn, write_buf).is_err() || write_buf.is_empty() {
        return;
    }
    let mut offset = 0;
    while offset < write_buf.len() {
        match stream.write(&write_buf[offset..]) {
            Ok(0) => break,
            Ok(n) => offset += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

/// Buffered-engine half of [`super::backend_mio::encrypt_for_send_mio`]:
/// encrypt plaintext and return the ciphertext bytes. The caller pushes the
/// result into the pending_sends queue for the event loop to flush when the
/// socket is writable.
#[cfg(not(has_io_uring))]
pub(super) fn encrypt_for_send_mio_buffered(
    tls_table: &mut TlsTable,
    conn_index: u32,
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    let (conn_slot, _write_buf) = borrow_conn_and_buf(tls_table, conn_index);
    let tls_conn = conn_slot.as_mut().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotConnected, "no TLS state for connection")
    })?;
    let buffered = tls_conn
        .conn
        .as_buffered_mut()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    encrypt_buffered(buffered, plaintext)
}

/// Encrypt `plaintext` on `buffered` and return all of the ciphertext.
#[cfg(not(has_io_uring))]
fn encrypt_buffered(buffered: &mut BufferedKind, plaintext: &[u8]) -> io::Result<Vec<u8>> {
    // Interleave writer().write with write_tls draining: rustls caps its
    // ciphertext buffer at 64 KiB, so a single write_all of a larger
    // plaintext fails with WriteZero after the first 64 KiB was already
    // encrypted (same fix as the io_uring path's encrypt_to_sends).
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 128);
    let mut offset = 0;
    while offset < plaintext.len() {
        let n = buffered
            .writer()
            .write(&plaintext[offset..])
            .map_err(io::Error::other)?;
        offset += n;
        let before = ciphertext.len();
        // One `write_tls` call writes at most 64 records, and one `write`
        // makes more than that when the records are small
        // (`max_fragment_size`).
        while buffered.wants_write() {
            if buffered
                .write_tls(&mut ciphertext)
                .map_err(io::Error::other)?
                == 0
            {
                break;
            }
        }
        if n == 0 && ciphertext.len() == before {
            return Err(io::Error::other("TLS encryption made no progress"));
        }
    }

    Ok(ciphertext)
}

/// Borrow a connection slot and the shared write_buf from a TlsTable simultaneously.
/// This is the borrow-splitting helper: `conns[i]` and `write_buf` are disjoint fields.
#[cfg(not(has_io_uring))]
pub(super) fn borrow_conn_and_buf(
    table: &mut TlsTable,
    conn_index: u32,
) -> (&mut Option<TlsConn>, &mut Vec<u8>) {
    (&mut table.conns[conn_index as usize], &mut table.write_buf)
}

/// In-memory rustls handshake harness shared by the TLS tests.
///
/// Portable on purpose: it builds real rustls records with no sockets and no
/// backend, so the drain test below and the admission tests elsewhere use
/// the same records.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::io::Cursor;

    pub(crate) fn test_certs() -> (
        Vec<ringline_tls::pki_types::CertificateDer<'static>>,
        ringline_tls::pki_types::PrivateKeyDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = ringline_tls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert_der = ringline_tls::pki_types::CertificateDer::from(cert.cert);
        (vec![cert_der], key.into())
    }

    /// Move all of `from`'s pending TLS output into `to`, driving `to`'s state
    /// machine. Used to pump a handshake to completion.
    pub(crate) fn pump(from: &mut BufferedKind, to: &mut BufferedKind) {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).unwrap();
        }
        if buf.is_empty() {
            return;
        }
        let mut cursor = Cursor::new(&buf[..]);
        while (cursor.position() as usize) < buf.len() {
            let n = to.read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
            to.process_new_packets().unwrap();
        }
    }

    /// A completed in-memory TLS session: (server, client), both past handshake.
    pub(crate) fn handshaked() -> (BufferedKind, BufferedKind) {
        handshaked_with_versions(ringline_tls::DEFAULT_VERSIONS)
    }

    /// As [`handshaked`], with the server's records limited to
    /// `max_fragment_size` bytes.
    #[cfg(not(has_io_uring))]
    pub(crate) fn handshaked_with_max_fragment(
        max_fragment_size: usize,
    ) -> (BufferedKind, BufferedKind) {
        handshaked_with(ringline_tls::DEFAULT_VERSIONS, Some(max_fragment_size))
    }

    /// As [`handshaked`], pinned to the given protocol versions.
    ///
    /// `&[&ringline_tls::version::TLS12]` is the reason this exists: the ciphertext
    /// bound budgets 29 bytes of per-record overhead for TLS 1.2 GCM's
    /// explicit nonce plus tag, against TLS 1.3's 22, and a worst case that is
    /// only ever asserted against the cheaper version is not a worst case.
    /// The builders enable TLS 1.2 by default, so connections reach it.
    pub(crate) fn handshaked_with_versions(
        versions: &[&'static ringline_tls::SupportedProtocolVersion],
    ) -> (BufferedKind, BufferedKind) {
        handshaked_with(versions, None)
    }

    fn handshaked_with(
        versions: &[&'static ringline_tls::SupportedProtocolVersion],
        max_fragment_size: Option<usize>,
    ) -> (BufferedKind, BufferedKind) {
        let (certs, key) = test_certs();
        let mut server_config =
            ringline_tls::ServerConfig::builder_with_protocol_versions(versions)
                .with_no_client_auth()
                .with_single_cert(certs.clone(), key)
                .unwrap();
        server_config.max_fragment_size = max_fragment_size;
        let server_config = Arc::new(server_config);
        let mut roots = ringline_tls::RootCertStore::empty();
        for c in &certs {
            roots.add(c.clone()).unwrap();
        }
        let client_config: Arc<ringline_tls::ClientConfig> =
            ringline_tls::ClientConfig::builder_with_protocol_versions(versions)
                .with_root_certificates(roots)
                .with_no_client_auth()
                .into();
        let server_name: ringline_tls::pki_types::ServerName<'_> = "localhost".try_into().unwrap();

        let mut server = BufferedKind::Server(ServerConnection::new(server_config).unwrap());
        let mut client =
            BufferedKind::Client(ClientConnection::new(client_config, server_name).unwrap());

        for _ in 0..30 {
            pump(&mut client, &mut server);
            pump(&mut server, &mut client);
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(
            !client.is_handshaking() && !server.is_handshaking(),
            "in-memory TLS handshake did not complete"
        );
        (server, client)
    }

    /// Decrypt `ciphertext` at `to` and return the plaintext, or the error
    /// rustls reported (a sequence gap is `bad_record_mac`).
    pub(crate) fn decrypt_at(to: &mut BufferedKind, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        use std::io::Read;
        let mut cursor = Cursor::new(ciphertext);
        while (cursor.position() as usize) < ciphertext.len() {
            if to.read_tls(&mut cursor).map_err(|e| e.to_string())? == 0 {
                break;
            }
            to.process_new_packets().map_err(|e| e.to_string())?;
        }
        let mut out = Vec::new();
        match to.reader().read_to_end(&mut out) {
            Ok(_) => Ok(out),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(out),
            Err(e) => Err(e.to_string()),
        }
    }

    pub(crate) fn wrap_server(server: BufferedKind) -> TlsConn {
        TlsConn {
            conn: TlsConnKind::Buffered(server),
            handshake_complete: true,
            peer_sent_close_notify: false,
            close_notify_sent: false,
            max_plaintext_per_record: crate::tls::DEFAULT_MAX_PLAINTEXT_PER_RECORD,
        }
    }
}

#[cfg(test)]
mod drain_tests {
    use super::test_support::*;
    use super::*;
    use std::io::Cursor;

    // The accumulator bound is enforced: a chunk that would take the
    // accumulator past its `max_size` is NOT consumed and the drain returns false (the
    // caller's connection-kill signal), mirroring the accumulator `append`
    // contract.
    #[test]
    fn plaintext_over_bound_returns_false() {
        let (server, mut client) = handshaked();
        let mut tls_conn = wrap_server(server);

        // One small record of plaintext (single chunk).
        let plaintext = vec![0x5Au8; 2048];
        client.writer().write_all(&plaintext).unwrap();
        let mut cipher = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut cipher).unwrap();
        }
        let mut cursor = Cursor::new(&cipher[..]);
        while (cursor.position() as usize) < cipher.len() {
            let n = buffered_mut(&mut tls_conn).read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
            buffered_mut(&mut tls_conn).process_new_packets().unwrap();
        }

        // max below the chunk size: the first chunk breaches the bound, is left
        // unconsumed in rustls, and drain reports the flood.
        let mut accs = AccumulatorTable::new_with_max(1, 1024, 1024);
        assert!(
            !drain_tls_plaintext(&mut tls_conn, &mut accs, 0),
            "over-limit plaintext must return false (connection-kill signal)"
        );
        assert!(
            accs.is_empty(0),
            "nothing is appended once the bound is breached"
        );
    }
}

#[cfg(all(test, not(has_io_uring)))]
mod mio_flush_tests {
    use super::test_support::*;
    use super::*;
    use std::io::{Cursor, Read};

    /// Decrypt `ciphertext` at `to`, draining plaintext after each record so
    /// rustls' received-plaintext limit does not stop it, and return how many
    /// plaintext bytes it carried.
    fn decrypted_len(to: &mut BufferedKind, ciphertext: &[u8]) -> usize {
        let mut cursor = Cursor::new(ciphertext);
        let mut total = 0;
        let mut buf = vec![0u8; 64 * 1024];
        while (cursor.position() as usize) < ciphertext.len() {
            if to.read_tls(&mut cursor).unwrap() == 0 {
                break;
            }
            to.process_new_packets().unwrap();
            loop {
                match to.reader().read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("{e}"),
                }
            }
        }
        total
    }

    /// A flush queues every record rustls holds, not only the first 64.
    #[test]
    fn a_flush_queues_more_than_64_records() {
        let (server, mut client) = handshaked();
        let mut tls_conn = wrap_server(server);
        for _ in 0..100 {
            buffered_mut(&mut tls_conn)
                .writer()
                .write_all(&[0x5A; 10])
                .unwrap();
        }
        let mut pending = std::collections::VecDeque::new();
        let mut buf = Vec::new();
        flush_tls_output_mio_inner(&mut tls_conn, &mut buf, &mut pending);
        assert!(!tls_conn.conn.wants_write(), "output left in rustls");
        let cipher: Vec<u8> = pending.iter().flat_map(|p| p.data.clone()).collect();
        assert_eq!(decrypted_len(&mut client, &cipher), 1000);
    }

    /// A send whose records are small enough that one rustls write makes more
    /// than 64 of them returns all of its ciphertext.
    #[test]
    fn a_send_of_more_than_64_records_is_encrypted_in_full() {
        let (mut server, mut client) = handshaked_with_max_fragment(512);
        let plaintext = vec![0x5A; 64 * 1024];
        let cipher = encrypt_buffered(&mut server, &plaintext).unwrap();
        assert!(!server.wants_write(), "output left in rustls");
        assert_eq!(decrypted_len(&mut client, &cipher), plaintext.len());
    }
}
