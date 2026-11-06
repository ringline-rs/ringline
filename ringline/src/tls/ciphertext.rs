//! Incoming-ciphertext buffer for the unbuffered TLS engine.
//!
//! rustls' `process_tls_records` takes a contiguous `&mut [u8]` whose front is
//! the next unprocessed byte, and requires the caller to remove `discard` bytes
//! from that front before calling again. A wrapping ring cannot satisfy the
//! contiguity requirement, and a naive `drain(..discard)` memmoves the
//! remainder on every call — the O(N*K) shape fixed in #279.
//!
//! This is a linear buffer with a start offset: `discard` is O(1). Relocation
//! (compaction) is amortized O(1) per byte because compaction only runs when
//! it pays for itself — when the bytes it moves are no more than the bytes it
//! reclaims (`start >= live`) — and it is tried *before* growth, so the
//! resident allocation tracks the working set rather than ballooning to `cap`.
//! A buffer that is full of *live* data (no productive compaction possible and
//! no room left to grow within `cap`) returns `WouldBlock` from `append`
//! rather than degrading into an unamortized memmove; the caller must drain
//! before appending more. `MIN_CIPHERTEXT_CAP` is sized so that `WouldBlock`
//! can only fire when the caller already holds a complete, drainable message —
//! see its doc comment for the argument. Halving it reintroduces a remotely
//! triggerable hang.
//!
//! Callers must not `append` between reading an `UnbufferedStatus` from
//! `process_tls_records` and calling the corresponding `discard`: `discard`'s
//! byte count is relative to the slice length at the moment that status was
//! produced, and an intervening `append` would shift what it actually removes.

use std::io;

/// Largest single TLS record rustls will deframe: a 5-byte header, a 16 KiB
/// payload, and a 2 KiB overhead budget (AEAD expansion / TLS 1.2 explicit
/// nonce / content-type byte) — rustls 0.23's `MAX_WIRE_SIZE`, not RFC 8446's
/// smaller 2^14 + 256.
///
/// **This is a receive-side bound, and only a receive-side bound.** It is how
/// much this buffer must be prepared to hold for one inbound record, with
/// deliberate slack. It is *not* the size of a record ringline emits: a
/// full-size TLS 1.3 record on the wire is 16406 bytes (see
/// one maximum-size TLS 1.3 record, 16406 bytes), 2 KiB smaller. Sizing a send-side
/// buffer, slot, or chunk from this constant overshoots by that slack and has
/// produced three separate wrong answers in this area — do not reach for it
/// from the send path.
pub(crate) const MAX_TLS_WIRE_RECORD: usize = 5 + 16_384 + 2_048;

/// Largest live set rustls may leave unprocessed. Its unbuffered path joins
/// handshake messages spanning records *inside the caller's buffer*, up to
/// `MAX_HANDSHAKE_SIZE` (0xffff), returning `discard == 0` until the message
/// completes. Until then the caller cannot drain a byte.
pub(crate) const MAX_UNPROCESSABLE: usize = 0xffff + MAX_TLS_WIRE_RECORD;

/// Largest single `append` the recv path may perform. `append` itself
/// enforces this (`debug_assert`) because `MIN_CIPHERTEXT_CAP`'s no-deadlock
/// derivation assumes it: the engine's recv buffer must be sized at or below
/// this so every `append` call stays within the bound the derivation relies
/// on.
pub(crate) const MAX_SINGLE_APPEND: usize = 64 * 1024;

/// Minimum workable `cap`.
///
/// Sized so `WouldBlock` can never fire while the engine is stuck. `WouldBlock`
/// implies `live > (cap - additional)/2`; with this floor that exceeds
/// `MAX_UNPROCESSABLE`, so a refused append proves the caller already holds a
/// complete message and can drain. Halve this and you get a remotely
/// triggerable hang: a peer positions `start` with application data, then sends
/// a large incomplete handshake flight.
pub(crate) const MIN_CIPHERTEXT_CAP: usize = 2 * MAX_UNPROCESSABLE + MAX_SINGLE_APPEND;

/// Allocation a fully drained buffer falls back to. Above
/// `MAX_TLS_WIRE_RECORD` so a single max-size record cannot trigger a
/// grow/shrink cycle on every exchange.
pub(crate) const INITIAL_SHRINK_TO: usize = 32 * 1024;

/// Contiguous buffer of received ciphertext awaiting `process_tls_records`.
///
/// The backing `Vec<u8>` is never zero-filled: reserved-but-unwritten
/// capacity is left uninitialized (demand-paged, untouched by the CPU) and
/// `buf.len()` is kept equal to `end` at all times, extended only over bytes
/// actually received: by `Vec::extend_from_slice` in `append`, or by
/// `recv_done` over bytes a receive wrote. See
/// `reserved`'s doc comment for why the allocation ceiling this type reports
/// is tracked as a separate field rather than read back off `Vec::capacity()`.
pub(crate) struct CiphertextBuf {
    buf: Vec<u8>,
    /// First unprocessed byte.
    start: usize,
    /// One past the last byte written. Invariant: `buf.len() == end` always
    /// (compaction truncates to match; growth only reserves capacity, it
    /// never extends `len`) — so the only bytes ever exposed as "logically
    /// present" in `buf` are bytes written by `append`, or by a receive and
    /// committed with `recv_done`.
    end: usize,
    /// Hard ceiling on `reserved`.
    cap: usize,
    /// Caller-requested starting allocation, honored again by the post-drain
    /// shrink target (not just on construction).
    initial: usize,
    /// Allocation ceiling this buffer has explicitly requested, via the
    /// initial `Vec::with_capacity` or a subsequent `Vec::reserve_exact`.
    ///
    /// This is deliberately not `Vec::capacity()`: `reserve`/`reserve_exact`
    /// are documented to allow the allocator to hand back more than asked
    /// for ("the allocator may give the collection more space than it
    /// requests"), and letting that rounding leak into `capacity()` would
    /// mean the `cap` invariant is only as tight as whatever the allocator
    /// felt like doing that day — not a property of this type's own
    /// arithmetic. `reserved` mirrors exactly the value `grow_to` computes
    /// (`needed.next_power_of_two().min(cap).max(needed)`), so a bug in that
    /// arithmetic (e.g. a stale `needed` defeating the `.min(cap)` clamp)
    /// still shows up here even if the allocator would have rounded a bad
    /// value up to something that happened to look fine.
    reserved: usize,
    /// Total bytes relocated by compaction. Diagnostic; asserted by tests to
    /// stay linear in throughput.
    bytes_moved: u64,
    /// A receive is writing into the spare capacity behind `end`
    /// (`arm_recv` until `recv_done`). Meanwhile the unprocessed bytes stay
    /// readable and `discard` advances past them, but nothing may move or
    /// free the allocation: `append` is refused, a full `discard` does not
    /// reset or reallocate, and dropping the buffer leaks the allocation.
    recv_in_flight: bool,
}

impl CiphertextBuf {
    /// `initial` is the starting allocation; `cap` the hard ceiling, raised to
    /// [`MIN_CIPHERTEXT_CAP`] if smaller. Tests may pass a smaller `cap` via
    /// [`Self::with_cap_unchecked`].
    pub(crate) fn new(initial: usize, cap: usize) -> Self {
        Self::with_cap_unchecked(initial, cap.max(MIN_CIPHERTEXT_CAP))
    }

    /// Construct without raising `cap` to the floor. Tests only: a `cap` below
    /// [`MIN_CIPHERTEXT_CAP`] cannot hold a real handshake flight, and can
    /// deadlock — see the module doc.
    pub(crate) fn with_cap_unchecked(initial: usize, cap: usize) -> Self {
        let reserved = initial.min(cap);
        Self {
            // `with_capacity` reserves the allocation without initializing
            // it -- unlike `vec![0u8; n]`, no memset, and the untouched
            // pages stay demand-paged (never resident) until actually
            // written by `append`.
            buf: Vec::with_capacity(reserved),
            start: 0,
            end: 0,
            cap,
            initial,
            reserved,
            bytes_moved: 0,
            recv_in_flight: false,
        }
    }

    /// Unprocessed bytes, as the contiguous slice to hand to rustls.
    pub(crate) fn pending(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.end]
    }

    pub(crate) fn len(&self) -> usize {
        self.end - self.start
    }

    /// Test-only: the engine tracks emptiness through [`Self::len`]; this
    /// backs `UnbufferedConn::set_ciphertext_cap_for_test`'s guard.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Diagnostic only: asserted by the compaction tests, never consulted by
    /// the engine.
    #[allow(dead_code)]
    pub(crate) fn bytes_moved(&self) -> u64 {
        self.bytes_moved
    }

    /// Current backing allocation ceiling (not the same as `len()`; includes
    /// already-consumed and not-yet-written-but-reserved capacity). This is
    /// `reserved`, not `Vec::capacity()` -- see that field's doc comment.
    ///
    /// Diagnostic only, like [`Self::bytes_moved`].
    #[allow(dead_code)]
    pub(crate) fn capacity(&self) -> usize {
        self.reserved
    }

    /// Drop `n` bytes from the front, per rustls' `UnbufferedStatus::discard`
    /// contract. O(1): the data does not move. `n` must not exceed the
    /// currently pending length — panics rather than silently clamping, since
    /// a caller that over-discards has a bug that would otherwise desync the
    /// TLS record stream and surface later as an unrelated `bad_record_mac`.
    pub(crate) fn discard(&mut self, n: usize) {
        assert!(
            n <= self.len(),
            "discard {n} exceeds {} pending bytes",
            self.len()
        );
        self.start += n;
        if self.start == self.end && !self.recv_in_flight {
            self.start = 0;
            self.end = 0;
            // Keep the `buf.len() == end` invariant. Free: no data movement,
            // no drop work for `u8`, and the allocation is retained -- same
            // "reset is free" cost as before.
            self.buf.clear();
            // Hysteresis: only release a genuinely oversized allocation, so a
            // connection oscillating near the threshold does not churn. This
            // is a deliberate memory-for-churn trade, not a bug: a connection
            // that saw exactly one flight sized just at or under 4x target
            // (e.g. a single 64 KiB handshake against the default 32 KiB
            // target) stays resident at that size rather than shrinking, in
            // exchange for not reallocating on every exchange near the
            // threshold. Measured at 4x: 4 reallocations per 500 flight/drain
            // cycles; tightening the `>` to `>=` would catch that one-flight
            // case but pushes the same measurement to ~1000 reallocations.
            let target = self.initial.max(INITIAL_SHRINK_TO).min(self.cap);
            if self.reserved > 4 * target {
                // Drop the oversized allocation and reserve a fresh,
                // unfilled one -- same non-zero-fill discipline as
                // construction.
                self.buf = Vec::with_capacity(target);
                self.reserved = target;
            }
            debug_assert!(self.reserved <= self.cap);
        }
    }

    /// Append received ciphertext.
    ///
    /// All-or-nothing: on error nothing is consumed, so a caller that gets
    /// `WouldBlock` must retain the chunk and retry after draining, or the
    /// bytes are lost.
    ///
    /// `ErrorKind::WouldBlock` means the buffer is full of live data — drain
    /// via `process_tls_records` + `discard` and retry. It is not fatal, and
    /// it can persist across many appends (until `start` catches up to
    /// `live`), so the caller must not spin on it.
    ///
    /// `ErrorKind::InvalidData` means the append cannot ever fit within `cap`
    /// — a protocol error; close the connection.
    pub(crate) fn append(&mut self, src: &[u8]) -> io::Result<()> {
        if self.recv_in_flight {
            debug_assert!(false, "append while a receive writes into the buffer");
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TLS ciphertext buffer is held by a receive",
            ));
        }
        debug_assert!(
            src.len() <= MAX_SINGLE_APPEND,
            "append of {} bytes exceeds MAX_SINGLE_APPEND ({MAX_SINGLE_APPEND}); \
             MIN_CIPHERTEXT_CAP's no-deadlock derivation assumes this bound",
            src.len()
        );
        if self.end + src.len() > self.buf.capacity() {
            self.make_room(src.len())?;
        }
        self.write_tail(src);
        Ok(())
    }

    /// Make room for a receive that writes into this buffer, behind the
    /// unprocessed bytes, and mark it in flight. Room for up to `want` bytes
    /// is made within `cap`, as `append` makes it: compacting only when that
    /// moves no more bytes than it reclaims, unless growing would pass `cap`.
    /// Returns where the receive writes and how many bytes it may write.
    /// Until [`recv_done`](Self::recv_done), the allocation does not move.
    ///
    /// `None` when the unprocessed bytes already fill `cap`, or when a
    /// receive is already in flight.
    #[cfg(has_io_uring)]
    pub(crate) fn arm_recv(&mut self, want: usize) -> Option<(*mut u8, usize)> {
        if self.recv_in_flight {
            return None;
        }
        let live = self.len();
        let room = want.min(self.cap - live);
        if room == 0 {
            return None;
        }
        if self.make_room(room).is_err() {
            // Growing at the tail would pass `cap`; `live + room` fits once
            // the unprocessed bytes are at the front.
            self.compact();
            if self.end + room > self.buf.capacity() {
                self.grow_to(self.end + room);
            }
        }
        debug_assert!(self.buf.capacity() >= self.end + room);
        self.recv_in_flight = true;
        // SAFETY: `end == buf.len()`, and `room` bytes are reserved behind it.
        Some((unsafe { self.buf.as_mut_ptr().add(self.end) }, room))
    }

    /// The receive [`arm_recv`](Self::arm_recv) started has completed, with
    /// `received` bytes written behind the unprocessed bytes.
    ///
    /// # Safety
    ///
    /// The `received` bytes at the pointer `arm_recv` returned must have been
    /// written, and `received` must not exceed the room it returned.
    #[cfg(has_io_uring)]
    pub(crate) unsafe fn recv_done(&mut self, received: usize) {
        debug_assert!(self.recv_in_flight, "recv_done without arm_recv");
        debug_assert!(self.end + received <= self.buf.capacity());
        // SAFETY: the caller guarantees the bytes are written and in bounds.
        unsafe { self.buf.set_len(self.end + received) };
        self.end += received;
        self.recv_in_flight = false;
        // A full `discard` during the receive left `start == end` without
        // resetting; do it now.
        if self.start == self.end {
            self.discard(0);
        }
    }

    /// Take the allocation from under an in-flight receive, so that it
    /// outlives this buffer until the receive completes. Leaves this buffer
    /// empty. `None` when no receive is in flight.
    #[cfg(has_io_uring)]
    pub(crate) fn take_in_flight(&mut self) -> Option<Vec<u8>> {
        if !self.recv_in_flight {
            return None;
        }
        self.recv_in_flight = false;
        self.start = 0;
        self.end = 0;
        Some(std::mem::take(&mut self.buf))
    }

    /// Write `src` at `end`, extending `buf`'s logical length to match.
    ///
    /// Uses `Vec::extend_from_slice` rather than indexing into a pre-sized
    /// slice: it copies `src` directly into the already-reserved spare
    /// capacity and only then advances `len`, so it never reads or exposes
    /// bytes this type has not itself written -- the reserved-but-unused
    /// tail of `buf` stays uninitialized (and, in practice, unfaulted) the
    /// whole time. Capacity for `end + src.len()` bytes must already be
    /// reserved by the caller (`append`'s `make_room` call).
    fn write_tail(&mut self, src: &[u8]) {
        debug_assert_eq!(self.buf.len(), self.end, "buf length must track `end`");
        debug_assert!(
            self.buf.capacity() >= self.end + src.len(),
            "write_tail called without reserving room first"
        );
        self.buf.extend_from_slice(src);
        self.end += src.len();
    }

    /// Ensure `additional` bytes fit after `end`.
    ///
    /// Compaction is tried first, and only when it pays for itself
    /// (`start >= live`, so bytes moved never exceed bytes reclaimed) — that
    /// is what bounds relocation to O(1) amortized per byte, and it keeps the
    /// resident allocation proportional to the working set rather than to
    /// `cap`. Growth is the fallback when compaction would move more than it
    /// reclaims.
    ///
    /// Every error path returns before any mutation. That is structural here,
    /// not incidental: once `compact()` runs, `end == live` and
    /// `live + additional <= cap` was already checked, so the remainder cannot
    /// fail. Preserve that if you touch this.
    fn make_room(&mut self, additional: usize) -> io::Result<()> {
        let live = self.len();
        if live + additional > self.cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS ciphertext exceeds the configured buffer cap",
            ));
        }
        if self.end + additional <= self.buf.capacity() {
            return Ok(()); // already fits at the tail
        }

        if self.start >= live {
            // Compaction pays for itself.
            self.compact();
            if self.end + additional > self.buf.capacity() {
                self.grow_to(self.end + additional);
            }
            return Ok(());
        }

        // Compaction would move more than it reclaims; grow instead.
        let needed = self.end + additional;
        if needed > self.cap {
            // Full of live data. By the MIN_CIPHERTEXT_CAP argument, `live`
            // here exceeds MAX_UNPROCESSABLE whenever `cap` respects that
            // floor, so the caller holds at least one complete message and
            // can drain. The argument is conditional on the floor, so only
            // check it when `cap` actually observes it -- `with_cap_unchecked`
            // exists precisely to let tests use a smaller `cap` that can
            // legitimately WouldBlock on a live set below MAX_UNPROCESSABLE
            // (that is the deadlock risk its own doc comment calls out, not a
            // bug here). If this assert ever fires with `cap >=
            // MIN_CIPHERTEXT_CAP`, the floor's derivation is wrong and the
            // connection would deadlock.
            debug_assert!(
                self.cap < MIN_CIPHERTEXT_CAP || live > MAX_UNPROCESSABLE,
                "WouldBlock with an unprocessable live set ({live} bytes) despite \
                 cap ({}) respecting the floor: would deadlock",
                self.cap
            );
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TLS ciphertext buffer full; drain before appending",
            ));
        }
        self.grow_to(needed);
        Ok(())
    }

    /// Reserve capacity for at least `needed` bytes, never exceeding `cap`.
    /// Reserves only -- does not touch `buf`'s logical length or initialize
    /// the new capacity; that happens lazily, in `write_tail`, only for
    /// bytes actually received.
    fn grow_to(&mut self, needed: usize) {
        debug_assert!(needed <= self.cap, "grow_to past the cap");
        let new_len = needed.next_power_of_two().min(self.cap).max(needed);
        debug_assert!(
            new_len >= self.buf.len(),
            "grow_to must never shrink below the current length"
        );
        // `reserve_exact`, not `reserve`: we already apply our own
        // power-of-two growth policy above, so we don't also want Vec's
        // amortized-growth heuristic padding on top of it.
        self.buf.reserve_exact(new_len - self.buf.len());
        self.reserved = new_len;
        debug_assert!(
            self.buf.capacity() >= new_len,
            "reserve_exact under-reserved"
        );
        debug_assert!(self.reserved <= self.cap, "allocation exceeded the cap");
    }

    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        let live = self.len();
        self.buf.copy_within(self.start..self.end, 0);
        // Keep the `buf.len() == end` invariant: the bytes past `live` are
        // still-initialized (they're stale copies of real received data,
        // not new zero-fill), but they're no longer part of the live
        // window, so drop them from `buf`'s logical length rather than
        // leaving `write_tail`'s invariant to reason about the gap.
        self.buf.truncate(live);
        self.bytes_moved += live as u64;
        self.start = 0;
        self.end = live;
    }
}

impl Drop for CiphertextBuf {
    /// An in-flight receive still writes into the allocation, so it is
    /// leaked rather than freed. The driver takes it first
    /// ([`take_in_flight`](Self::take_in_flight)) whenever it drops TLS state
    /// with a receive in flight.
    fn drop(&mut self) {
        if self.recv_in_flight {
            // Not while unwinding: a second panic aborts.
            if !std::thread::panicking() {
                debug_assert!(false, "TLS state dropped with a receive in flight");
            }
            std::mem::forget(std::mem::take(&mut self.buf));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `data` where the kernel would, at the pointer `arm_recv`
    /// returned.
    #[cfg(has_io_uring)]
    fn write_at(ptr: *mut u8, data: &[u8]) {
        // SAFETY: the test arms with at least `data.len()` bytes of room.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len()) };
    }

    /// A receive writes behind the unprocessed bytes, which stay readable and
    /// discardable while it is in flight; its bytes become pending behind
    /// whatever is left.
    #[cfg(has_io_uring)]
    #[test]
    fn a_receive_writes_behind_the_unprocessed_bytes() {
        let mut b = CiphertextBuf::with_cap_unchecked(256, 1024);
        b.append(b"abcdef").unwrap();
        b.discard(2);
        let (ptr, room) = b.arm_recv(100).expect("room");
        assert_eq!(room, 100);
        assert!(b.arm_recv(100).is_none(), "one receive at a time");
        assert_eq!(b.pending(), b"cdef", "the unprocessed bytes stay readable");
        b.discard(2);
        write_at(ptr, b"ghi");
        // SAFETY: three bytes were written at `ptr`.
        unsafe { b.recv_done(3) };
        assert_eq!(b.pending(), b"efghi");
        b.append(b"j").unwrap();
        assert_eq!(b.pending(), b"efghij");
        assert_eq!(
            b.bytes_moved(),
            0,
            "a receive with room at the tail moves nothing"
        );
    }

    /// A full `discard` while a receive is in flight keeps the write position;
    /// the received bytes are all that is pending afterwards.
    #[cfg(has_io_uring)]
    #[test]
    fn a_full_discard_during_a_receive_keeps_the_write_position() {
        let mut b = CiphertextBuf::with_cap_unchecked(256, 1024);
        b.append(b"abc").unwrap();
        let (ptr, _) = b.arm_recv(10).expect("room");
        b.discard(3);
        assert!(b.is_empty());
        write_at(ptr, b"xy");
        // SAFETY: two bytes were written at `ptr`.
        unsafe { b.recv_done(2) };
        assert_eq!(b.pending(), b"xy");
    }

    /// When growing at the tail would pass `cap`, the unprocessed bytes move
    /// to the front to make the room.
    #[cfg(has_io_uring)]
    #[test]
    fn a_receive_compacts_when_the_tail_would_pass_the_cap() {
        let mut b = CiphertextBuf::with_cap_unchecked(16, 64);
        b.append(&[7u8; 40]).unwrap();
        b.discard(15);
        // 25 unprocessed bytes after a 15-byte prefix: 30 more at the tail
        // would end at 70, past the cap, so the 25 move to the front.
        let (ptr, room) = b.arm_recv(30).expect("room");
        assert_eq!(room, 30);
        assert_eq!(b.pending(), [7u8; 25]);
        write_at(ptr, &[8u8; 30]);
        // SAFETY: 30 bytes were written at `ptr`.
        unsafe { b.recv_done(30) };
        let mut want = vec![7u8; 25];
        want.extend_from_slice(&[8u8; 30]);
        assert_eq!(b.pending(), &want[..]);
    }

    /// The room is bounded by what `cap` leaves behind the unprocessed bytes,
    /// and none at all is a refusal.
    #[cfg(has_io_uring)]
    #[test]
    fn a_receive_gets_at_most_the_room_under_the_cap() {
        let mut b = CiphertextBuf::with_cap_unchecked(16, 64);
        b.append(&[1u8; 60]).unwrap();
        let (_, room) = b.arm_recv(100).expect("room");
        assert_eq!(room, 4);
        // SAFETY: nothing was written.
        unsafe { b.recv_done(0) };
        b.append(&[2u8; 4]).unwrap();
        assert!(b.arm_recv(100).is_none(), "the cap is full");
        assert_eq!(b.len(), 64, "a refusal leaves the bytes in place");
    }

    /// Taking the allocation from under a receive leaves the buffer empty
    /// and returns the allocation the receive writes into.
    #[cfg(has_io_uring)]
    #[test]
    fn take_in_flight_hands_over_the_allocation() {
        let mut b = CiphertextBuf::with_cap_unchecked(256, 1024);
        b.append(b"abc").unwrap();
        assert!(b.take_in_flight().is_none(), "no receive in flight");
        let (ptr, _) = b.arm_recv(10).expect("room");
        let taken = b.take_in_flight().expect("in flight");
        // SAFETY: `ptr` points 3 bytes into the allocation that `taken` owns.
        assert_eq!(unsafe { taken.as_ptr().add(3) }, ptr.cast_const());
        assert!(b.is_empty());
    }

    #[test]
    fn append_then_pending_returns_what_was_written() {
        let mut b = CiphertextBuf::with_cap_unchecked(64, 1024);
        b.append(b"hello").unwrap();
        assert_eq!(b.pending(), b"hello");
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn discard_advances_without_moving_bytes() {
        let mut b = CiphertextBuf::with_cap_unchecked(64, 1024);
        b.append(b"abcdef").unwrap();
        b.discard(2);
        assert_eq!(b.pending(), b"cdef");
        assert_eq!(b.bytes_moved(), 0, "a partial discard must not compact");
    }

    #[test]
    fn full_discard_resets_to_the_front() {
        let mut b = CiphertextBuf::with_cap_unchecked(64, 1024);
        b.append(b"abcdef").unwrap();
        b.discard(6);
        assert!(b.is_empty());
        b.append(b"xy").unwrap();
        assert_eq!(b.pending(), b"xy");
        assert_eq!(b.bytes_moved(), 0, "reset is free; nothing to move");
    }

    #[test]
    fn append_grows_up_to_the_cap() {
        let mut b = CiphertextBuf::with_cap_unchecked(8, 1024);
        let big = vec![7u8; 500];
        b.append(&big).unwrap();
        assert_eq!(b.len(), 500);
        assert_eq!(b.pending(), &big[..]);
    }

    #[test]
    fn append_beyond_cap_is_an_error_and_leaves_the_buffer_intact() {
        let mut b = CiphertextBuf::with_cap_unchecked(8, 64);
        b.append(b"keep").unwrap();
        assert!(b.append(&[0u8; 128]).is_err());
        assert_eq!(
            b.pending(),
            b"keep",
            "a failed append must not corrupt state"
        );
    }

    #[test]
    fn compaction_reclaims_the_consumed_prefix() {
        // Fill to capacity, consume most of it, then append again: the buffer
        // must reclaim the prefix rather than fail.
        let mut b = CiphertextBuf::with_cap_unchecked(16, 16);
        b.append(&[1u8; 16]).unwrap();
        b.discard(12);
        b.append(&[2u8; 12]).unwrap();
        assert_eq!(b.len(), 16);
        assert_eq!(&b.pending()[..4], &[1u8; 4]);
        assert_eq!(&b.pending()[4..], &[2u8; 12]);
    }

    /// The anti-#279 test. Streaming N bytes through the buffer in small
    /// chunks must move O(N) bytes in total, not O(N^2). A naive
    /// `drain(..discard)` moves the remainder on every call and fails this.
    #[test]
    fn streaming_moves_bytes_at_most_a_constant_factor_of_throughput() {
        const CHUNK: usize = 64;
        const ROUNDS: usize = 4096;
        const TOTAL: u64 = (CHUNK * ROUNDS) as u64;

        let mut b = CiphertextBuf::with_cap_unchecked(4096, 1 << 20);
        for _ in 0..ROUNDS {
            b.append(&[0u8; CHUNK]).unwrap();
            // Consume all but a 16-byte "partial record" remainder, the
            // pathological shape: never empty, so never a free reset.
            let keep = 16.min(b.len());
            let n = b.len() - keep;
            b.discard(n);
        }

        assert!(
            b.bytes_moved() <= 4 * TOTAL,
            "moved {} bytes to stream {TOTAL}; compaction is not amortized",
            b.bytes_moved()
        );
    }

    /// The regression test for the unguarded second compaction. The existing
    /// streaming test runs at ~0% occupancy, where the bound holds trivially;
    /// this one runs the buffer nearly full, which is where it did not.
    #[test]
    fn high_occupancy_streaming_stays_amortized() {
        const CAP: usize = 64 * 1024;
        const CHUNK: usize = 1448; // MTU-sized segments
        let live_target = CAP * 9 / 10;

        let mut b = CiphertextBuf::with_cap_unchecked(CAP, CAP);
        b.append(&vec![0u8; live_target]).unwrap();

        let mut throughput = 0u64;
        for _ in 0..2000 {
            if b.append(&[0u8; CHUNK]).is_err() {
                b.discard(CHUNK.min(b.len()));
                continue;
            }
            throughput += CHUNK as u64;
            b.discard(CHUNK.min(b.len()));
        }

        assert!(
            b.bytes_moved() <= 4 * throughput.max(1),
            "moved {} bytes for {throughput} of throughput at 90% occupancy",
            b.bytes_moved()
        );
    }

    #[test]
    fn allocation_never_exceeds_the_cap() {
        // Reach grow_to *after* a compaction that pays for itself
        // (start=10 >= live=8) -- the path where a stale, pre-compaction
        // `needed` used to defeat the `.min(cap)` clamp and overshoot the cap
        // (verified against 453bc21: this exact sequence resizes to 41 there).
        let mut b = CiphertextBuf::with_cap_unchecked(24, 32);
        b.append(&[1u8; 18]).unwrap();
        b.discard(10);
        b.append(&[2u8; 23]).unwrap();
        assert_eq!(b.len(), 31);
        assert!(
            b.capacity() <= 32,
            "allocation {} exceeded cap 32",
            b.capacity()
        );
    }

    /// Pins the 800 GbE-motivated property directly: `CiphertextBuf` must
    /// never initialize (zero-fill or otherwise touch) bytes the peer has
    /// not sent, even when constructed with a large `cap`. RSS itself isn't
    /// measurable in-process, so this asserts on the honest in-process proxy
    /// -- `Vec::len()` vs `Vec::capacity()` -- rather than trying to sample
    /// memory: a reservation-based buffer's `len()` tracks only what was
    /// actually appended, never jumping up to `capacity()`/`cap` the way
    /// `vec![0u8; n]` or `Vec::resize(n, 0)` would. A large, mostly-unwritten
    /// reservation is exactly the case the repo's demand-paging finding
    /// depends on: untouched pages behind `capacity()` are never faulted in,
    /// so they cost no resident memory -- a property zero-filling forfeits
    /// outright.
    #[test]
    fn growth_does_not_initialize_unreceived_bytes() {
        const LARGE_CAP: usize = 1 << 20; // 1 MiB

        let mut b = CiphertextBuf::with_cap_unchecked(LARGE_CAP, LARGE_CAP);
        assert_eq!(
            b.buf.len(),
            0,
            "constructing with a 1 MiB initial/cap must not eagerly fill it"
        );

        b.append(b"hello").unwrap();

        assert_eq!(
            b.buf.len(),
            5,
            "Vec length must track only the bytes actually received, not \
             capacity or cap"
        );
        assert!(
            b.buf.capacity() >= LARGE_CAP,
            "capacity should still reflect the requested reservation"
        );
        assert_eq!(b.len(), 5);
        assert_eq!(b.pending(), b"hello");
    }
}
