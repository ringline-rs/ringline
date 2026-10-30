//! mio-facing TLS entry points, dispatching by engine.
//!
//! The mio backend writes ciphertext into `Vec<u8>` buffers queued on the
//! connection's `pending_sends` FIFO (there is no send-pool slot lifecycle to
//! respect, and no SQE whose memory must outlive the call). Both engines
//! therefore produce plain byte vectors here; only the engine that fills them
//! differs.
//!
//! Each function keeps the name and signature the backend already called, so
//! `backend/mio/{event_loop,driver}.rs` and `handler.rs` are unaware of which
//! record layer is compiled in. The buffered halves live in
//! [`super::buffered`] under `*_buffered` names.
//!
//! **Never drive the state machine to "flush" leftovers after encrypting or
//! queueing an alert.** rustls' `write_fragments` drains `sendable_tls` into
//! the *front* of the destination buffer ahead of the fragments it is about to
//! encrypt, and `check_required_size` reserves that space (verified against
//! ringline-tls 0.1.1's `CommonState`). Anything already queued — a TLS 1.3
//! `key_update`, most notably — therefore rides out inside the destination,
//! correctly ordered. Driving afterwards and queueing that output as a
//! separate send puts it *after* those records on the wire, and the peer fails
//! with `bad_record_mac`. See `docs/tls-unbuffered-design.md`.

use std::io;

use crate::accumulator::AccumulatorTable;
use crate::backend::mio::driver::PendingSend;

use super::{TlsRecvResult, TlsTable, buffered};

#[cfg(not(feature = "tls-buffered"))]
use super::unbuffered;

/// Feed received ciphertext, decrypt into the accumulator, and queue any TLS
/// output (handshake responses, alerts) onto `pending`.
///
/// The output is queued whatever the outcome: an alert generated on the way to
/// a fatal error still has to reach the peer.
pub fn feed_tls_recv_mio(
    tls_table: &mut TlsTable,
    accumulators: &mut AccumulatorTable,
    pending: &mut std::collections::VecDeque<PendingSend>,
    conn_index: u32,
    ciphertext: &[u8],
) -> TlsRecvResult {
    #[cfg(not(feature = "tls-buffered"))]
    {
        let (conn_slot, write_buf) = buffered::borrow_conn_and_buf(tls_table, conn_index);
        let Some(tls_conn) = conn_slot.as_mut() else {
            return TlsRecvResult::Closed;
        };
        write_buf.clear();
        let outcome = unbuffered::feed(
            tls_conn,
            Some(accumulators),
            write_buf,
            ciphertext,
            conn_index,
        );
        if !write_buf.is_empty() {
            pending.push_back(PendingSend::plain(std::mem::take(write_buf)));
        }
        match outcome {
            unbuffered::DriveOutcome::Ok => TlsRecvResult::Ok,
            unbuffered::DriveOutcome::HandshakeJustCompleted => {
                TlsRecvResult::HandshakeJustCompleted {
                    peer_closed: tls_conn.peer_sent_close_notify,
                }
            }
            unbuffered::DriveOutcome::Closed => TlsRecvResult::Closed,
            unbuffered::DriveOutcome::Error(e) => TlsRecvResult::Error(e),
        }
    }
    #[cfg(feature = "tls-buffered")]
    buffered::feed_tls_recv_mio_buffered(tls_table, accumulators, pending, conn_index, ciphertext)
}

/// Flush pending TLS output onto the connection's send FIFO. Used on the
/// client path to push the ClientHello once the TCP connect completes.
pub fn flush_tls_output_mio_queued(
    tls_table: &mut TlsTable,
    pending: &mut std::collections::VecDeque<PendingSend>,
    conn_index: u32,
) {
    #[cfg(not(feature = "tls-buffered"))]
    {
        let (conn_slot, write_buf) = buffered::borrow_conn_and_buf(tls_table, conn_index);
        let Some(tls_conn) = conn_slot.as_mut() else {
            return;
        };
        write_buf.clear();
        // No ciphertext to add: driving an idle machine is what emits the
        // ClientHello (`EncodeTlsData` with an empty incoming buffer). `feed`
        // treats an empty slice as a deliberate flush for exactly this.
        let _ = unbuffered::feed(tls_conn, None, write_buf, &[], conn_index);
        if !write_buf.is_empty() {
            pending.push_back(PendingSend::plain(std::mem::take(write_buf)));
        }
    }
    #[cfg(feature = "tls-buffered")]
    buffered::flush_tls_output_mio_queued_buffered(tls_table, pending, conn_index)
}

/// Best-effort nonblocking flush for close paths: the connection is going
/// away, so there is no later opportunity to retry.
///
/// Generating the alert is engine-specific. The buffered caller queues it with
/// `send_close_notify` first and this only drains rustls' output; the
/// unbuffered engine has no such call (`CommonState::send_close_notify` is not
/// reachable through `UnbufferedConnectionCommon`), so the alert is encrypted
/// here via `WriteTraffic::queue_close_notify`. A connection that never
/// reached traffic state has nothing to queue and leaves `write_buf` empty —
/// not an error.
pub fn flush_tls_output_mio_direct(
    tls_table: &mut TlsTable,
    stream: &mut mio::net::TcpStream,
    conn_index: u32,
) {
    #[cfg(not(feature = "tls-buffered"))]
    {
        use std::io::Write as _;

        let (conn_slot, write_buf) = buffered::borrow_conn_and_buf(tls_table, conn_index);
        let Some(tls_conn) = conn_slot.as_mut() else {
            return;
        };
        write_buf.clear();
        if unbuffered::queue_close_notify(tls_conn, write_buf).is_err() || write_buf.is_empty() {
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
    #[cfg(feature = "tls-buffered")]
    buffered::flush_tls_output_mio_direct_buffered(tls_table, stream, conn_index)
}

/// Encrypt application data for the pending-send FIFO.
pub fn encrypt_for_send_mio(
    tls_table: &mut TlsTable,
    conn_index: u32,
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    #[cfg(not(feature = "tls-buffered"))]
    {
        let (conn_slot, _) = buffered::borrow_conn_and_buf(tls_table, conn_index);
        let tls_conn = conn_slot.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no TLS state for connection")
        })?;
        let mut out = Vec::with_capacity(plaintext.len() + 128);
        unbuffered::encrypt_to_vec(tls_conn, plaintext, &mut out)?;
        Ok(out)
    }
    #[cfg(feature = "tls-buffered")]
    buffered::encrypt_for_send_mio_buffered(tls_table, conn_index, plaintext)
}
