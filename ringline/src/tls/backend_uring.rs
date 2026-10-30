//! io_uring-facing TLS entry points, dispatching by engine.
//!
//! Each function keeps the name and signature the backend already called, so
//! `backend/uring/event_loop.rs` and `handler.rs` are unaware of which record
//! layer is compiled in. The buffered halves live in [`super::buffered`] under
//! `*_buffered` names — the same split [`super::backend_mio`] uses.
//!
//! Unlike mio, ciphertext here lands in [`SendCopyPool`] slots whose lifetime
//! the completion handlers own, so the contract from
//! `docs/send-completion-design.md` is preserved verbatim: no CQE-skip, slots
//! live until their CQE, and a logical send that spans several slots tags the
//! intermediate ones [`OpTag::TlsSend`] and only the final one [`OpTag::Send`],
//! so an awaited send's id, on that final chunk, settles once. Every send built here
//! is routed through the per-connection send queue by the caller: io_uring does
//! not order independent SQEs, and interleaved TLS records are `bad_record_mac`
//! at the peer.
//!
//! Handshake output takes a scratch `Vec` on the way to those slots.
//! `EncodeTlsData::encode` is all-or-nothing on one contiguous buffer, and a
//! full-size handshake record (`5 + 16384 + overhead`) does not fit the default
//! 16384-byte `send_copy_slot_size` — so the engine writes it to a `Vec` and
//! [`ciphertext_to_sends`] chunks it across slots. Application data does not
//! come through that scratch: `WriteTraffic::encrypt` writes into the slot
//! directly. On TLS 1.3 that is one copy of the plaintext, against two on the
//! buffered engine; TLS 1.2 costs two on both (see the `unbuffered` module
//! docs).
//!
//! **Never drive the state machine to "flush" leftovers after encrypting or
//! queueing an alert.** rustls' `write_fragments` drains `sendable_tls` into
//! the *front* of the destination buffer ahead of the fragments it is about to
//! encrypt, and `check_required_size` reserves that space (verified against
//! ringline-tls 0.1.1's `CommonState`). Anything already queued — a TLS 1.3
//! `key_update`, most notably — therefore rides out inside the destination,
//! correctly ordered. Driving afterwards and queueing that output as a separate
//! send puts it *after* those records on the wire, and the peer fails with
//! `bad_record_mac`. See `docs/tls-unbuffered-design.md`.

use std::io;

use crate::accumulator::AccumulatorTable;
use crate::buffer::send_copy::SendCopyPool;
use crate::handler::BuiltSend;

use super::{TlsRecvResult, TlsTable};

#[cfg(feature = "tls-buffered")]
use super::buffered;

#[cfg(not(feature = "tls-buffered"))]
use super::{build_pool_send, unbuffered};
#[cfg(not(feature = "tls-buffered"))]
use crate::completion::OpTag;

/// Copy `ciphertext` into pool slots and append the resulting sends to `out`,
/// all tagged [`OpTag::TlsSend`] — this only ever carries handshake records and
/// alerts, which never complete a logical application send.
///
/// **All-or-nothing.** Slots are staged locally and appended to `out` only once
/// the whole blob has one; running out of pool partway releases everything this
/// call took and appends nothing, returning `false`. Appending a prefix would
/// put a truncated TLS record on the wire — half a Certificate message is
/// strictly worse for the peer than none of it — and the callers tear the
/// connection down on `false` either way. Sends appended to `out` by *earlier*
/// calls are untouched, which is where this matches
/// [`buffered::take_tls_output_sends`][super::buffered::take_tls_output_sends]:
/// it stages into a `PoolWriter` and drains into the caller's vector only on
/// success, for the same reason.
///
/// An empty `ciphertext` appends nothing and succeeds.
#[cfg(not(feature = "tls-buffered"))]
pub(super) fn ciphertext_to_sends(
    pool: &mut SendCopyPool,
    conn_index: u32,
    generation: u32,
    ciphertext: &[u8],
    out: &mut Vec<BuiltSend>,
) -> bool {
    let slot_size = pool.slot_size() as usize;
    // (slot, ciphertext length) in transmission order, same staging shape as
    // `encrypt_to_sends` below.
    let mut staged: Vec<(u16, u32)> = Vec::new();
    for chunk in ciphertext.chunks(slot_size) {
        // `submit_next_queued` may coalesce these chunks, with other queued
        // copy sends, into one `SendMsgCoalesced` (#628); queue order is
        // transmission order, so records stay in sequence. Only a slot that
        // carries a send id settles anything, so a coalesced run still wakes
        // each logical send once.
        match pool.copy_in(chunk) {
            Some((slot, _, len)) => staged.push((slot, len)),
            None => {
                release_all(pool, &staged);
                return false;
            }
        }
    }
    for &(slot, len) in &staged {
        let (ptr, _) = pool.current_ptr_remaining(slot);
        out.push(build_pool_send(
            conn_index,
            generation,
            ptr,
            len,
            slot,
            OpTag::TlsSend,
        ));
    }
    true
}

/// Map an unbuffered drive's outcome to the backend result, after turning its
/// output into sends.
#[cfg(not(feature = "tls-buffered"))]
fn finish_unbuffered_feed(
    peer_sent_close_notify: bool,
    outcome: unbuffered::DriveOutcome,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
    generation: u32,
    scratch: &[u8],
    out_sends: &mut Vec<BuiltSend>,
) -> TlsRecvResult {
    if !ciphertext_to_sends(send_copy_pool, conn_index, generation, scratch, out_sends) {
        return TlsRecvResult::Error(ringline_tls::Error::General(
            "send pool exhausted during TLS output flush".into(),
        ));
    }
    match outcome {
        unbuffered::DriveOutcome::Ok => TlsRecvResult::Ok,
        unbuffered::DriveOutcome::HandshakeJustCompleted => TlsRecvResult::HandshakeJustCompleted {
            peer_closed: peer_sent_close_notify,
        },
        unbuffered::DriveOutcome::Closed => TlsRecvResult::Closed,
        unbuffered::DriveOutcome::Error(e) => TlsRecvResult::Error(e),
    }
}

/// Where a direct receive on a TLS connection writes ciphertext.
pub struct TlsRecvTarget {
    /// A buffer the receive owns while it is in flight: with the buffered
    /// engine, a buffer from the table's free list. `None` with the
    /// unbuffered engine, whose receive writes into the connection's own
    /// ciphertext buffer.
    pub buf: Option<Vec<u8>>,
    /// Where the receive writes.
    pub ptr: *mut u8,
    /// How many bytes it may write.
    pub len: usize,
}

/// Start a direct receive on `conn_index`, asking for up to `want` bytes.
/// The unbuffered engine receives behind the unprocessed bytes of its
/// incoming-ciphertext buffer, so no copy is made into it, and keeps those
/// bytes readable while the receive is in flight; the buffered engine
/// receives into a free buffer from the table, which `read_tls` copies from.
///
/// `None` if the slot has no TLS state, or if the unbuffered engine's buffer
/// is already full of unprocessed bytes, which a conforming peer cannot
/// cause.
pub fn tls_recv_arm(
    tls_table: &mut TlsTable,
    conn_index: u32,
    want: usize,
) -> Option<TlsRecvTarget> {
    #[cfg(not(feature = "tls-buffered"))]
    {
        let (ptr, len) = tls_table
            .get_mut(conn_index)?
            .conn
            .as_unbuffered_mut()?
            .arm_recv(want)?;
        Some(TlsRecvTarget {
            buf: None,
            ptr,
            len,
        })
    }
    #[cfg(feature = "tls-buffered")]
    {
        if !tls_table.has(conn_index) {
            return None;
        }
        let mut buf = tls_table.recv_buffers.pop().unwrap_or_default();
        buf.clear();
        buf.reserve(want);
        let ptr = buf.as_mut_ptr();
        Some(TlsRecvTarget {
            buf: Some(buf),
            ptr,
            len: want,
        })
    }
}

/// End a receive from [`tls_recv_arm`] without delivering anything it wrote,
/// giving back what it held. A buffered-engine buffer goes back to the free
/// list.
pub fn tls_recv_cancel(tls_table: &mut TlsTable, conn_index: u32, buf: Option<Vec<u8>>) {
    #[cfg(not(feature = "tls-buffered"))]
    {
        debug_assert!(buf.is_none());
        if let Some(conn) = tls_table
            .get_mut(conn_index)
            .and_then(|c| c.conn.as_unbuffered_mut())
        {
            // SAFETY: `recv_done(0)` makes no received bytes readable,
            // whatever the receive wrote.
            unsafe { conn.recv_done(0) };
        }
    }
    #[cfg(feature = "tls-buffered")]
    {
        let _ = conn_index;
        if let Some(buf) = buf {
            tls_table.recv_buffers.push(buf);
        }
    }
}

/// Take the allocation an in-flight receive on `conn_index` writes into out
/// of the connection's TLS state, so that dropping the state does not free
/// it. `None` when no receive is in flight, and always with the buffered
/// engine, whose receive owns its buffer.
pub fn tls_take_recv_allocation(tls_table: &mut TlsTable, conn_index: u32) -> Option<Vec<u8>> {
    #[cfg(not(feature = "tls-buffered"))]
    {
        tls_table
            .get_mut(conn_index)?
            .conn
            .as_unbuffered_mut()?
            .take_in_flight()
    }
    #[cfg(feature = "tls-buffered")]
    {
        let _ = (tls_table, conn_index);
        None
    }
}

/// Feed the `received` bytes a receive from [`tls_recv_arm`] wrote to the
/// TLS connection: decrypted plaintext goes to the accumulator, and TLS
/// output (handshake responses, alerts) is appended to `out_sends`. The
/// output is appended whatever the outcome, since an alert generated on the
/// way to a fatal error still has to reach the peer, and the caller must
/// queue it whatever the result, or the pool slots leak. `buf` is the
/// target's `buf`.
///
/// # Safety
///
/// The receive must come from [`tls_recv_arm`] for this connection, and the
/// `received` bytes at the target's `ptr` must have been written, within its
/// `len`.
#[allow(clippy::too_many_arguments)]
pub unsafe fn feed_tls_received(
    tls_table: &mut TlsTable,
    accumulators: &mut AccumulatorTable,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
    generation: u32,
    buf: Option<Vec<u8>>,
    received: usize,
    out_sends: &mut Vec<BuiltSend>,
) -> TlsRecvResult {
    #[cfg(not(feature = "tls-buffered"))]
    {
        debug_assert!(buf.is_none());
        let Some(tls_conn) = tls_table.get_mut(conn_index) else {
            return TlsRecvResult::Closed;
        };
        let Some(conn) = tls_conn.conn.as_unbuffered_mut() else {
            return TlsRecvResult::Closed;
        };
        // SAFETY: forwarded to the caller.
        unsafe { conn.recv_done(received) };
        let mut scratch = Vec::new();
        let outcome = unbuffered::drive(tls_conn, Some(accumulators), &mut scratch, conn_index);
        finish_unbuffered_feed(
            tls_conn.peer_sent_close_notify,
            outcome,
            send_copy_pool,
            conn_index,
            generation,
            &scratch,
            out_sends,
        )
    }
    #[cfg(feature = "tls-buffered")]
    {
        let Some(mut buf) = buf else {
            return TlsRecvResult::Closed;
        };
        // SAFETY: forwarded to the caller; `tls_recv_arm` hands out an
        // empty buffer, so the received bytes start at 0.
        unsafe { buf.set_len(received) };
        let result = buffered::feed_tls_recv_buffered(
            tls_table,
            accumulators,
            send_copy_pool,
            conn_index,
            generation,
            &buf,
            out_sends,
        );
        buf.clear();
        tls_table.recv_buffers.push(buf);
        result
    }
}

/// Collect pending TLS output as queueable sends. Used on the client path to
/// push the ClientHello once the connect CQE lands.
///
/// Returns `false` if the output could not be produced or drained in full;
/// sends already appended must still be queued by the caller.
pub fn flush_tls_output(
    tls_table: &mut TlsTable,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
    generation: u32,
    out_sends: &mut Vec<BuiltSend>,
) -> bool {
    #[cfg(not(feature = "tls-buffered"))]
    {
        let Some(tls_conn) = tls_table.get_mut(conn_index) else {
            return true;
        };
        let mut scratch = Vec::new();
        // No ciphertext to add: driving an idle machine is what emits the
        // ClientHello (`EncodeTlsData` with an empty incoming buffer). `feed`
        // treats an empty slice as a deliberate flush for exactly this.
        if let unbuffered::DriveOutcome::Error(_) =
            unbuffered::feed(tls_conn, None, &mut scratch, &[], conn_index)
        {
            return false;
        }
        ciphertext_to_sends(send_copy_pool, conn_index, generation, &scratch, out_sends)
    }
    #[cfg(feature = "tls-buffered")]
    buffered::flush_tls_output_buffered(
        tls_table,
        send_copy_pool,
        conn_index,
        generation,
        out_sends,
    )
}

/// Encrypt application data into pool-backed sends for the per-connection send
/// queue.
///
/// `WriteTraffic::encrypt` encrypts into the slot. A TLS 1.3 record is copied
/// once, into the slot, and sealed there (`MessageEncrypter::encrypt_into`). A
/// TLS 1.2 record is sealed in a per-record buffer and then copied into the
/// slot.
///
/// On any failure every slot allocated by this call is released before
/// returning, so a rejected send leaks nothing and nothing reaches the send
/// queue. It is *not* retryable, though: records encrypted before the failure
/// consumed TLS sequence numbers that no longer have ciphertext on the wire, so
/// the connection is finished. Treat an error here as fatal for the connection
/// and close it — the same rule `DriverCtx::send` documents for its own
/// mid-buffer failures, and the same behaviour the buffered engine has.
pub fn encrypt_to_sends(
    tls_table: &mut TlsTable,
    send_copy_pool: &mut SendCopyPool,
    conn_index: u32,
    generation: u32,
    plaintext: &[u8],
) -> io::Result<Vec<BuiltSend>> {
    #[cfg(not(feature = "tls-buffered"))]
    {
        let tls_conn = tls_table.get_mut(conn_index).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no TLS state for connection")
        })?;

        // (slot, ciphertext length) in transmission order.
        let mut filled: Vec<(u16, u32)> = Vec::new();
        let mut offset = 0;
        while offset < plaintext.len() {
            // `submit_next_queued` may coalesce these chunks with other queued
            // copy sends into one `SendMsgCoalesced` (#628); the send id rides
            // on the final chunk only, so the logical send settles once.
            let Some((slot, ptr, cap)) = send_copy_pool.alloc_raw() else {
                release_all(send_copy_pool, &filled);
                return Err(io::Error::other("send copy pool exhausted for TLS"));
            };
            // SAFETY: `ptr`/`cap` are the base and size of the slot `alloc_raw`
            // just handed out; this call holds it exclusively until the
            // `set_filled`/`release` below, and the borrow ends before either.
            let dst = unsafe { std::slice::from_raw_parts_mut(ptr, cap as usize) };
            match unbuffered::encrypt_chunk(tls_conn, &plaintext[offset..], dst) {
                // `used_ct` can exceed this chunk's own records: rustls drains
                // anything it had queued (a TLS 1.3 `key_update`) into the front
                // of `dst`. Transmitting `dst` as-is is what keeps that ordered.
                Ok((used_pt, used_ct)) if used_pt > 0 && used_ct > 0 => {
                    send_copy_pool.set_filled(slot, used_ct as u32);
                    filled.push((slot, used_ct as u32));
                    offset += used_pt;
                }
                Ok(_) => {
                    send_copy_pool.release(slot);
                    release_all(send_copy_pool, &filled);
                    return Err(io::Error::other("TLS encryption made no progress"));
                }
                Err(e) => {
                    send_copy_pool.release(slot);
                    release_all(send_copy_pool, &filled);
                    return Err(e);
                }
            }
        }

        let mut built = Vec::with_capacity(filled.len());
        for (i, &(slot, len)) in filled.iter().enumerate() {
            let (ptr, _) = send_copy_pool.current_ptr_remaining(slot);
            // Final chunk completes the logical send (settles its id, drives
            // the queue via handle_send); intermediates are TLS-internal.
            let tag = if i + 1 == filled.len() {
                OpTag::Send
            } else {
                OpTag::TlsSend
            };
            built.push(build_pool_send(conn_index, generation, ptr, len, slot, tag));
        }
        Ok(built)
    }
    #[cfg(feature = "tls-buffered")]
    buffered::encrypt_to_sends_buffered(
        tls_table,
        send_copy_pool,
        conn_index,
        generation,
        plaintext,
    )
}

/// Return every slot in `filled` to the pool. Error paths only: a slot that
/// never becomes an SQE has no CQE coming to release it.
#[cfg(not(feature = "tls-buffered"))]
fn release_all(pool: &mut SendCopyPool, filled: &[(u16, u32)]) {
    for &(slot, _) in filled {
        pool.release(slot);
    }
}

#[cfg(all(test, not(feature = "tls-buffered")))]
mod tests {
    use super::*;

    // Pool exhaustion partway through a blob must append nothing and leak
    // nothing. A prefix reaching the wire is a truncated TLS record at the
    // peer, and staged slots have no CQE coming to release them.
    #[test]
    fn ciphertext_to_sends_is_all_or_nothing_on_exhaustion() {
        let mut pool = SendCopyPool::new(2, 64);
        let mut out = Vec::new();
        // Three slots' worth of output into a two-slot pool: the third
        // `copy_in` is the one that fails.
        let ciphertext = vec![0xA5u8; 3 * 64];

        assert!(
            !ciphertext_to_sends(&mut pool, 0, 0, &ciphertext, &mut out),
            "exhaustion must be reported to the caller"
        );
        assert!(
            out.is_empty(),
            "a partial blob must not reach the send queue"
        );
        assert_eq!(
            pool.free_count(),
            2,
            "every slot this call took must be released"
        );
    }

    // Output already in `out` from an earlier call is the caller's, and a
    // later failure must not disturb it.
    #[test]
    fn ciphertext_to_sends_leaves_earlier_sends_alone() {
        let mut pool = SendCopyPool::new(3, 64);
        let mut out = Vec::new();

        assert!(ciphertext_to_sends(&mut pool, 0, 0, &[7u8; 16], &mut out));
        assert_eq!(out.len(), 1);

        // Two slots left, three needed.
        assert!(!ciphertext_to_sends(
            &mut pool,
            0,
            0,
            &[9u8; 3 * 64],
            &mut out
        ));
        assert_eq!(out.len(), 1, "the earlier call's send must survive");
        assert_eq!(pool.free_count(), 2, "only the first call still holds one");
    }

    // The success path splits across slots in order and appends one send each.
    #[test]
    fn ciphertext_to_sends_chunks_across_slots() {
        let mut pool = SendCopyPool::new(4, 64);
        let mut out = Vec::new();
        let ciphertext = vec![0x5Au8; 130];

        assert!(ciphertext_to_sends(&mut pool, 0, 0, &ciphertext, &mut out));
        assert_eq!(out.len(), 3, "130 bytes over 64-byte slots is 64 + 64 + 2");
        let lens: Vec<u32> = out
            .iter()
            .map(|b| match b.entry.op {
                crate::backend::uring::sqe::Op::Send { len, .. } => len,
                op => panic!("expected a send, got {op:?}"),
            })
            .collect();
        assert_eq!(
            lens.iter().sum::<u32>(),
            130,
            "every byte must be accounted for exactly once"
        );
        assert_eq!(lens[2], 2, "the tail slot carries the remainder");
        assert_eq!(pool.free_count(), 1);
    }

    // An empty blob is a no-op, not a failure: `feed`/`flush` call this
    // unconditionally and the steady state has no handshake output at all.
    #[test]
    fn ciphertext_to_sends_accepts_an_empty_blob() {
        let mut pool = SendCopyPool::new(2, 64);
        let mut out = Vec::new();
        assert!(ciphertext_to_sends(&mut pool, 0, 0, &[], &mut out));
        assert!(out.is_empty());
        assert_eq!(pool.free_count(), 2);
    }
}
