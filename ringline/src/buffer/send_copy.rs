use crate::runtime::send_completion::SendId;

/// A promise of `remaining` free slots made by [`SendCopyPool::reserve_slots`].
/// Filled with [`SendCopyPool::copy_in_reserved`]; the unfilled remainder must
/// go back through [`SendCopyPool::release_reservation`]. On io_uring a
/// reservation lives inside one synchronous `DriverCtx::send`; on mio a
/// `send_backpressured` permit is held, unfilled, until its entry flushes or
/// is discarded. The pool honours a reservation held across other
/// allocations either way.
#[must_use = "an unfilled reservation must be returned with release_reservation"]
pub struct SlotReservation {
    remaining: usize,
}

impl SlotReservation {
    /// Slots promised by this reservation that have not been filled yet.
    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

impl Drop for SlotReservation {
    fn drop(&mut self) {
        // A reservation cannot release itself (it has no handle to the pool),
        // so misuse is caught here in debug/test builds rather than silently
        // shrinking the pool. Skipped while unwinding: a second panic from a
        // guard's Drop would abort the process and hide the original one.
        if !std::thread::panicking() {
            debug_assert_eq!(
                self.remaining, 0,
                "SlotReservation dropped with {} unfilled slots; call release_reservation",
                self.remaining
            );
        }
    }
}

/// Why [`SendCopyPool::reserve_slots`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveError {
    /// Fewer than the requested slots are free right now (retryable).
    Exhausted,
    /// The request exceeds the pool's total slot count (never retryable).
    TooLarge {
        /// Slots the caller asked for.
        needed: usize,
        /// Slots the pool holds in total.
        capacity: usize,
    },
}

/// Pool of library-owned buffers for copying send data (soundness fix).
///
/// When `send()` is called, the data is copied into a pool slot so the SQE
/// points to memory owned by the library. The slot is released on the Send CQE.
pub struct SendCopyPool {
    backing: Vec<u8>,
    slot_size: u32,
    count: u16,
    free_list: Vec<u16>,
    slot_offset: Vec<u32>, // current byte offset within slot (advances on partial send)
    slot_remaining: Vec<u32>, // bytes remaining to send
    in_use: Vec<bool>,     // double-free protection
    // The awaited send whose completion this slot carries, and the logical
    // (plaintext) length that operation reports on success. A send larger
    // than one slot is split across several slots; only the last one carries
    // the id, so the send settles once rather than once per chunk. `None` on
    // every freshly allocated slot; see `set_send_id`.
    slot_send_id: Vec<Option<(SendId, u32)>>,
    // Free-list slots promised to outstanding `SlotReservation`s but not yet
    // popped. Every allocator subtracts this from `free_list.len()` before
    // taking a slot, so a reservation is honoured even if another allocation
    // interleaves with it.
    reserved: usize,
}

impl SendCopyPool {
    /// Leak the pool's memory. An in-flight zero-copy send can name a slot, and
    /// the kernel can read it after the driver is gone. Called at worker exit,
    /// when the bound on waiting has run out.
    pub fn leak_backing(&mut self) {
        std::mem::forget(std::mem::take(&mut self.backing));
    }

    /// Create a new pool with `count` slots, each `slot_size` bytes.
    pub fn new(count: u16, slot_size: u32) -> Self {
        let total = count as usize * slot_size as usize;
        let backing = vec![0u8; total];
        let free_list: Vec<u16> = (0..count).rev().collect();
        let n = count as usize;
        SendCopyPool {
            backing,
            slot_size,
            count,
            free_list,
            slot_offset: vec![0u32; n],
            slot_remaining: vec![0u32; n],
            in_use: vec![false; n],
            slot_send_id: vec![None; n],
            reserved: 0,
        }
    }

    /// Fault every slot in before traffic arrives. See
    /// [`crate::buffer::prefault`] for why, and why it must run on the worker
    /// thread that owns the pool.
    pub(crate) fn prefault(&mut self) {
        crate::buffer::prefault::prefault(&mut self.backing);
    }

    /// Pop an unreserved slot from the free list, or `None` (with the
    /// `SEND_EXHAUSTED` metric) when every free slot is either gone or
    /// promised to an outstanding reservation.
    fn pop_unreserved(&mut self) -> Option<u16> {
        if self.free_count() == 0 {
            crate::metrics::POOL.increment(crate::metrics::pool::SEND_EXHAUSTED);
            return None;
        }
        // free_count() > 0 implies free_list is non-empty.
        self.free_list.pop()
    }

    /// Copy `data` into an already-popped slot and initialise its tracking.
    /// Shared by `copy_in` and `copy_in_reserved` so the two cannot drift.
    /// The caller has checked `data.len() <= slot_size`.
    fn fill_slot(&mut self, idx: u16, data: &[u8]) -> (u16, *const u8, u32) {
        let offset = idx as usize * self.slot_size as usize;
        self.backing[offset..offset + data.len()].copy_from_slice(data);
        let ptr = self.backing.as_ptr().wrapping_add(offset);
        self.slot_offset[idx as usize] = 0;
        self.slot_remaining[idx as usize] = data.len() as u32;
        self.in_use[idx as usize] = true;
        self.slot_send_id[idx as usize] = None;
        (idx, ptr, data.len() as u32)
    }

    /// Allocate a slot, copy `data` into it, and return (slot_index, ptr, len).
    /// Returns `None` if no unreserved slots are free or data exceeds slot size.
    pub fn copy_in(&mut self, data: &[u8]) -> Option<(u16, *const u8, u32)> {
        if data.len() > self.slot_size as usize {
            return None;
        }
        let idx = self.pop_unreserved()?;
        Some(self.fill_slot(idx, data))
    }

    /// Allocate a slot and copy multiple contiguous segments into it sequentially.
    /// Returns `None` if no unreserved slots are free or `total_len` exceeds slot size.
    ///
    /// # Safety
    /// Each `(ptr, len)` pair must point to valid readable memory.
    pub unsafe fn copy_in_gather(
        &mut self,
        parts: &[(*const u8, usize)],
        total_len: usize,
    ) -> Option<(u16, *const u8, u32)> {
        if total_len > self.slot_size as usize {
            return None;
        }
        let idx = self.pop_unreserved()?;
        let base = idx as usize * self.slot_size as usize;
        let mut dest_offset = 0;
        for &(ptr, len) in parts {
            let src = unsafe { std::slice::from_raw_parts(ptr, len) };
            self.backing[base + dest_offset..base + dest_offset + len].copy_from_slice(src);
            dest_offset += len;
        }
        let out_ptr = self.backing.as_ptr().wrapping_add(base);
        self.slot_offset[idx as usize] = 0;
        self.slot_remaining[idx as usize] = total_len as u32;
        self.in_use[idx as usize] = true;
        self.slot_send_id[idx as usize] = None;
        Some((idx, out_ptr, total_len as u32))
    }

    /// Allocate an empty slot for incremental filling (e.g. TLS ciphertext
    /// written directly by `write_tls` via `PoolWriter`). Returns
    /// `(slot, base_ptr, capacity)`. The caller fills bytes front-to-back
    /// and must call [`set_filled`](Self::set_filled) with the final length
    /// before the slot is used in an SQE (until then remaining == 0).
    /// Returns `None` if no unreserved slots are free.
    pub fn alloc_raw(&mut self) -> Option<(u16, *mut u8, u32)> {
        let idx = self.pop_unreserved()?;
        let offset = idx as usize * self.slot_size as usize;
        self.slot_offset[idx as usize] = 0;
        self.slot_remaining[idx as usize] = 0;
        self.in_use[idx as usize] = true;
        self.slot_send_id[idx as usize] = None;
        let ptr = self.backing.as_mut_ptr().wrapping_add(offset);
        Some((idx, ptr, self.slot_size))
    }

    /// Record how many bytes were filled into a slot from [`alloc_raw`](Self::alloc_raw).
    pub fn set_filled(&mut self, slot: u16, len: u32) {
        let i = slot as usize;
        debug_assert!(self.in_use[i]);
        debug_assert!(len <= self.slot_size);
        self.slot_offset[i] = 0;
        self.slot_remaining[i] = len;
    }

    /// Promise `n` slots to the caller without popping them. Fails without
    /// side effects (other than the `SEND_EXHAUSTED` metric on
    /// [`ReserveError::Exhausted`]). `n == 0` succeeds with an empty
    /// reservation. While the reservation is outstanding, `copy_in`,
    /// `copy_in_gather` and `alloc_raw` see `n` fewer free slots.
    pub fn reserve_slots(&mut self, n: usize) -> Result<SlotReservation, ReserveError> {
        let capacity = self.slot_count();
        if n > capacity {
            return Err(ReserveError::TooLarge {
                needed: n,
                capacity,
            });
        }
        if n > self.free_count() {
            crate::metrics::POOL.increment(crate::metrics::pool::SEND_EXHAUSTED);
            return Err(ReserveError::Exhausted);
        }
        self.reserved += n;
        Ok(SlotReservation { remaining: n })
    }

    /// Pop one promised slot and copy `data` into it; same fill as `copy_in`.
    /// Returns (slot_index, ptr, len). `data.len()` must be `<= slot_size` and
    /// the reservation must have slots remaining (both `debug_assert`ed; the
    /// caller iterates `chunks(slot_size)` over a buffer whose chunk count it
    /// reserved).
    pub fn copy_in_reserved(
        &mut self,
        r: &mut SlotReservation,
        data: &[u8],
    ) -> (u16, *const u8, u32) {
        debug_assert!(
            r.remaining > 0,
            "copy_in_reserved past the end of the reservation"
        );
        debug_assert!(data.len() <= self.slot_size as usize);
        let idx = self
            .free_list
            .pop()
            .expect("reserved slot missing from free list");
        r.remaining -= 1;
        self.reserved -= 1;
        self.fill_slot(idx, data)
    }

    /// Give back all but `keep` of a reservation's unfilled slots.
    ///
    /// mio-only, and gated rather than `allow(dead_code)`d, because io_uring
    /// has no way to reach it: its bounded TLS path cannot hold a reservation
    /// across encryption at all (encryption allocates from this same pool and
    /// the reservation would hide those slots from it), so it admits with a
    /// plain capacity check and never over-reserves. Its plain path reserves
    /// exactly what it needs. mio queues an owned buffer instead, so its
    /// permit is pure admission accounting and *can* be narrowed after the
    /// fact.
    ///
    /// A bounded TLS send has to reserve against a conservative *ciphertext*
    /// bound before rustls mutates, and only learns the true cost once the
    /// records exist. This narrows the promise in place. Release-then-
    /// re-reserve would be wrong here: the re-reservation can fail, and it
    /// would only be sound because nothing runs in between — an invariant
    /// that stops being true the moment someone adds a call.
    ///
    /// `keep` must not exceed what is left (`debug_assert`ed): a reservation
    /// cannot grow, because growing can fail and this method cannot report
    /// that.
    #[cfg(not(has_io_uring))]
    pub fn shrink_reservation(&mut self, r: &mut SlotReservation, keep: usize) {
        debug_assert!(
            keep <= r.remaining,
            "shrink_reservation cannot grow a reservation from {} to {keep}",
            r.remaining
        );
        let returned = r.remaining.saturating_sub(keep);
        debug_assert!(
            returned <= self.reserved,
            "reservation remainder exceeds the pool's outstanding reservations"
        );
        self.reserved -= returned;
        r.remaining -= returned;
    }

    /// Return the unfilled remainder of a reservation to the pool.
    pub fn release_reservation(&mut self, mut r: SlotReservation) {
        debug_assert!(
            r.remaining() <= self.reserved,
            "reservation remainder exceeds the pool's outstanding reservations"
        );
        self.reserved -= r.remaining;
        r.remaining = 0; // satisfies the Drop debug_assert
    }

    /// Release a slot back to the free list (called on Send CQE).
    ///
    /// A slot must not still carry an awaited send when it is released: every
    /// disposal path has to take the id with
    /// [`take_send_id`](Self::take_send_id) and settle the send first, or
    /// the caller's future never resolves. The
    /// `debug_assert` below is that audit's tripwire (it is what makes
    /// "delete a settle site and watch a test fail" work), and it sits
    /// *before* the `!in_use` double-free early return on purpose: the
    /// invariant is "no slot carries an id at release", and it holds for free
    /// slots too — the three allocators reset the entry and this method clears
    /// it. Putting the check after the early return would exempt exactly the
    /// slots whose bookkeeping is already suspect (a slot released twice, or
    /// one that had an id attached while free), which are the shapes a buggy
    /// disposal path produces. The clear is unconditional for the same reason,
    /// so a release build degrades to a lost completion rather than to a
    /// recycled slot that still names a dead operation.
    pub fn release(&mut self, idx: u16) {
        debug_assert!((idx as usize) < self.count as usize);
        let carried = self.slot_send_id[idx as usize].take();
        debug_assert!(
            carried.is_none(),
            "slot {idx} released while still carrying awaited send {carried:?}; \
             every disposal path must take the id and complete or fail it first",
        );
        if !self.in_use[idx as usize] {
            return; // already released — prevent double-free
        }
        self.in_use[idx as usize] = false;
        self.slot_offset[idx as usize] = 0;
        self.slot_remaining[idx as usize] = 0;
        self.free_list.push(idx);
    }

    /// Try to advance a partial send. If `bytes_sent < remaining`, updates
    /// offset/remaining and returns `Some((new_ptr, new_remaining))` for
    /// resubmission. Returns `None` if fully sent.
    pub fn try_advance(&mut self, slot: u16, bytes_sent: u32) -> Option<(*const u8, u32)> {
        let i = slot as usize;
        debug_assert!(self.in_use[i]);
        debug_assert!(bytes_sent <= self.slot_remaining[i]);
        let new_remaining = self.slot_remaining[i] - bytes_sent;
        if new_remaining == 0 {
            return None;
        }
        self.slot_offset[i] += bytes_sent;
        self.slot_remaining[i] = new_remaining;
        let base = i * self.slot_size as usize;
        let ptr = self
            .backing
            .as_ptr()
            .wrapping_add(base + self.slot_offset[i] as usize);
        Some((ptr, new_remaining))
    }

    /// Whether a slot is currently in use (allocated but not yet released).
    pub fn in_use(&self, slot: u16) -> bool {
        self.in_use.get(slot as usize).copied().unwrap_or(false)
    }

    /// Get the current pointer and remaining length for a slot (for resubmission retries).
    pub fn current_ptr_remaining(&self, slot: u16) -> (*const u8, u32) {
        let i = slot as usize;
        let base = i * self.slot_size as usize;
        let ptr = self
            .backing
            .as_ptr()
            .wrapping_add(base + self.slot_offset[i] as usize);
        (ptr, self.slot_remaining[i])
    }

    /// Get the original total length for a slot: offset + remaining.
    /// Valid between `copy_in` and `release`.
    pub fn original_len(&self, slot: u16) -> u32 {
        let i = slot as usize;
        debug_assert!(self.in_use[i]);
        self.slot_offset[i] + self.slot_remaining[i]
    }

    /// Attach an awaited send's identity to this slot, together with the
    /// **logical (plaintext) length** the send reports on success.
    ///
    /// Set only on the final slot of its logical send, so one logical send
    /// owns at most one entry. The length travels with the id because no
    /// completion handler can recompute it: a TLS send's final `OpTag::Send`
    /// chunk is one ciphertext record, and a split send's final chunk is part
    /// of it.
    ///
    /// Written by `DriverCtx::send_awaited`, `SendBuilder::submit_awaited`
    /// and `DriverCtx::send_bounded` and, when a coalescing run is unwound,
    /// by `Driver::submit_next_queued_inner`; read back by the send
    /// completion handlers and the teardown paths.
    pub fn set_send_id(&mut self, slot: u16, id: SendId, logical_len: u32) {
        self.slot_send_id[slot as usize] = Some((id, logical_len));
    }

    /// Take the awaited send attached to this slot, if any, leaving `None`.
    ///
    /// Taking — rather than peeking — is the point: an id can only be settled
    /// once, and the fact that it is gone is what lets
    /// [`release`](Self::release) assert that some disposal path settled the
    /// operation. A handler that means to settle must take here and must not
    /// look again.
    ///
    /// Called by the send/TLS-send completion handlers, their error and
    /// `close_submitted` branches, the teardown paths, and
    /// `Driver::submit_next_queued_inner` when it lifts the id onto a
    /// coalesced slab entry.
    pub fn take_send_id(&mut self, slot: u16) -> Option<(SendId, u32)> {
        self.slot_send_id[slot as usize].take()
    }

    /// Bytes per slot.
    pub fn slot_size(&self) -> u32 {
        self.slot_size
    }

    /// Slots available to a new allocation: the free list minus slots
    /// promised to outstanding reservations.
    pub fn free_count(&self) -> usize {
        self.free_list.len() - self.reserved
    }

    /// Total slots in the pool.
    pub fn slot_count(&self) -> usize {
        self.count as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::send_completion::SendCompletions;

    /// `SendId` has no public constructor — the admission queue is the
    /// only source of ids, which is exactly how the driver gets one too.
    fn an_id() -> SendId {
        SendCompletions::new().enqueue(0, 1, 1, 0)
    }

    #[test]
    fn copy_in_and_release() {
        let mut pool = SendCopyPool::new(4, 128);
        assert_eq!(pool.free_count(), 4);

        let (idx, ptr, len) = pool.copy_in(b"hello").unwrap();
        assert_eq!(len, 5);
        assert_eq!(pool.free_count(), 3);

        // Verify data was copied
        let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
        assert_eq!(slice, b"hello");

        pool.release(idx);
        assert_eq!(pool.free_count(), 4);
    }

    #[test]
    fn exhaust_pool() {
        let mut pool = SendCopyPool::new(2, 64);
        let _ = pool.copy_in(b"a").unwrap();
        let _ = pool.copy_in(b"b").unwrap();
        assert!(pool.copy_in(b"c").is_none());
    }

    #[test]
    fn exhausted_pool_returns_none_copy_in() {
        // A 1-slot pool: first alloc succeeds, second returns None (SEND_EXHAUSTED
        // metric is incremented inside; we assert the observable None behavior).
        let mut pool = SendCopyPool::new(1, 64);
        let _ = pool.copy_in(b"first").unwrap();
        assert_eq!(pool.free_count(), 0);
        assert!(pool.copy_in(b"second").is_none());
    }

    #[test]
    fn exhausted_pool_returns_none_copy_in_gather() {
        // Same as above but exercising the gather variant.
        let mut pool = SendCopyPool::new(1, 64);
        let data = b"first";
        let parts: &[(*const u8, usize)] = &[(data.as_ptr(), data.len())];
        let _ = unsafe { pool.copy_in_gather(parts, data.len()) }.unwrap();
        assert_eq!(pool.free_count(), 0);
        let data2 = b"second";
        let parts2: &[(*const u8, usize)] = &[(data2.as_ptr(), data2.len())];
        assert!(unsafe { pool.copy_in_gather(parts2, data2.len()) }.is_none());
    }

    #[test]
    fn data_too_large() {
        let mut pool = SendCopyPool::new(4, 4);
        assert!(pool.copy_in(b"toolarge").is_none());
    }

    #[test]
    fn try_advance_partial() {
        let mut pool = SendCopyPool::new(4, 128);
        let (idx, _ptr, len) = pool.copy_in(b"hello world").unwrap();
        assert_eq!(len, 11);
        assert_eq!(pool.original_len(idx), 11);

        // Partial send: 5 of 11 bytes sent.
        let result = pool.try_advance(idx, 5);
        assert!(result.is_some());
        let (new_ptr, new_remaining) = result.unwrap();
        assert_eq!(new_remaining, 6);
        assert_eq!(pool.original_len(idx), 11);

        // Verify the pointer points to the remaining data.
        let slice = unsafe { std::slice::from_raw_parts(new_ptr, new_remaining as usize) };
        assert_eq!(slice, b" world");

        // Second partial: 4 of 6 remaining.
        let result = pool.try_advance(idx, 4);
        assert!(result.is_some());
        let (new_ptr2, new_remaining2) = result.unwrap();
        assert_eq!(new_remaining2, 2);
        assert_eq!(pool.original_len(idx), 11);

        let slice2 = unsafe { std::slice::from_raw_parts(new_ptr2, new_remaining2 as usize) };
        assert_eq!(slice2, b"ld");

        // Final send: all remaining bytes sent.
        let result = pool.try_advance(idx, 2);
        assert!(result.is_none());

        pool.release(idx);
        assert_eq!(pool.free_count(), 4);
    }

    #[test]
    fn try_advance_full_send() {
        let mut pool = SendCopyPool::new(4, 128);
        let (idx, _ptr, len) = pool.copy_in(b"hello").unwrap();
        assert_eq!(len, 5);

        // Full send on first attempt — returns None.
        let result = pool.try_advance(idx, 5);
        assert!(result.is_none());
        assert_eq!(pool.original_len(idx), 5);

        pool.release(idx);
    }

    #[test]
    fn release_clears_tracking() {
        let mut pool = SendCopyPool::new(4, 128);
        let (idx, _ptr, _len) = pool.copy_in(b"test data").unwrap();

        // Partial send.
        pool.try_advance(idx, 4);
        assert_eq!(pool.original_len(idx), 9);

        // Release clears tracking.
        pool.release(idx);

        // Re-allocate — LIFO free list returns the just-released slot.
        let (idx2, _ptr2, len2) = pool.copy_in(b"new").unwrap();
        assert_eq!(idx2, idx);
        assert_eq!(len2, 3);
        assert_eq!(pool.original_len(idx2), 3);
    }

    #[test]
    #[cfg(not(has_io_uring))]
    fn shrink_reservation_returns_the_difference_and_keeps_the_rest_usable() {
        let mut pool = SendCopyPool::new(4, 8);

        // The TLS bounded path reserves a conservative ciphertext bound, then
        // learns the real cost once rustls has produced the records.
        let mut r = pool.reserve_slots(3).unwrap();
        assert_eq!(pool.free_count(), 1);

        pool.shrink_reservation(&mut r, 1);
        assert_eq!(r.remaining(), 1);
        // The two over-reserved slots are available to everyone again.
        assert_eq!(pool.free_count(), 3);
        assert_eq!(pool.reserved, 1);

        // The kept slot is still promised: filling it takes no more than it.
        let (idx, _, _) = pool.copy_in_reserved(&mut r, b"x");
        assert_eq!(r.remaining(), 0);
        assert_eq!(pool.free_count(), 3);
        assert!(pool.in_use(idx));

        pool.release_reservation(r);
        assert_eq!(pool.reserved, 0);
    }

    #[test]
    #[cfg(not(has_io_uring))]
    fn shrink_reservation_to_zero_is_a_full_release() {
        let mut pool = SendCopyPool::new(2, 8);
        let mut r = pool.reserve_slots(2).unwrap();
        assert_eq!(pool.free_count(), 0);

        pool.shrink_reservation(&mut r, 0);
        assert_eq!(r.remaining(), 0);
        assert_eq!(pool.free_count(), 2);
        assert_eq!(pool.reserved, 0);

        // Dropping the emptied reservation must not trip the Drop assert, and
        // releasing it again must stay a no-op rather than double-count.
        pool.release_reservation(r);
        assert_eq!(pool.reserved, 0);
        assert_eq!(pool.free_count(), 2);
    }

    #[test]
    #[cfg(not(has_io_uring))]
    fn shrink_reservation_to_its_current_size_changes_nothing() {
        let mut pool = SendCopyPool::new(4, 8);
        let mut r = pool.reserve_slots(2).unwrap();

        pool.shrink_reservation(&mut r, 2);
        assert_eq!(r.remaining(), 2);
        assert_eq!(pool.free_count(), 2);
        assert_eq!(pool.reserved, 2);

        pool.release_reservation(r);
    }

    #[test]
    fn reserve_then_fill_consumes_exactly_the_reserved_slots() {
        let mut pool = SendCopyPool::new(4, 8);
        assert_eq!(pool.slot_count(), 4);

        let mut r = pool.reserve_slots(3).unwrap();
        assert_eq!(r.remaining(), 3);
        // Reserved slots are still on the free list but no longer available.
        assert_eq!(pool.free_count(), 1);
        assert_eq!(pool.free_list.len(), 4);

        let mut slots = Vec::new();
        for chunk in [&b"aaa"[..], b"bb", b"c"] {
            let (idx, ptr, len) = pool.copy_in_reserved(&mut r, chunk);
            assert_eq!(len as usize, chunk.len());
            let copied = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
            assert_eq!(copied, chunk);
            assert!(pool.in_use(idx));
            slots.push(idx);
        }
        assert_eq!(r.remaining(), 0);
        // Filling consumed exactly the promised slots: the unreserved one is
        // still there and nothing extra was taken.
        assert_eq!(pool.free_count(), 1);
        assert_eq!(pool.free_list.len(), 1);

        pool.release_reservation(r);
        assert_eq!(pool.reserved, 0);
        assert_eq!(pool.free_count(), pool.free_list.len());

        // The filled slots are ordinary slots: releasing them restores the pool.
        for idx in slots {
            pool.release(idx);
        }
        assert_eq!(pool.free_count(), 4);
    }

    #[test]
    fn reserve_fails_without_side_effects_when_short() {
        let mut pool = SendCopyPool::new(2, 8);
        let _ = pool.copy_in(b"x").unwrap();
        assert_eq!(pool.free_count(), 1);

        assert_eq!(pool.reserve_slots(2).err(), Some(ReserveError::Exhausted));
        // Nothing was reserved: the count is unchanged and a plain allocation
        // still gets the remaining slot.
        assert_eq!(pool.reserved, 0);
        assert_eq!(pool.free_count(), 1);
        assert!(pool.copy_in(b"y").is_some());
        assert_eq!(pool.free_count(), 0);
    }

    #[test]
    fn reserve_rejects_more_than_the_pool_holds() {
        let mut pool = SendCopyPool::new(2, 8);
        assert_eq!(
            pool.reserve_slots(3).err(),
            Some(ReserveError::TooLarge {
                needed: 3,
                capacity: 2
            })
        );
        assert_eq!(pool.reserved, 0);
        assert_eq!(pool.free_count(), 2);
        // Exactly the pool's size is still a valid request.
        let r = pool.reserve_slots(2).unwrap();
        assert_eq!(pool.free_count(), 0);
        pool.release_reservation(r);
    }

    #[test]
    fn reservation_blocks_plain_allocation_until_released() {
        let mut pool = SendCopyPool::new(2, 8);
        let r = pool.reserve_slots(2).unwrap();
        assert_eq!(pool.free_count(), 0);

        // Both slots are still on the free list, so without the reservation
        // accounting every one of these would succeed.
        assert_eq!(pool.free_list.len(), 2);
        assert!(pool.copy_in(b"a").is_none());
        assert!(pool.alloc_raw().is_none());
        let data = b"g";
        let parts: &[(*const u8, usize)] = &[(data.as_ptr(), data.len())];
        assert!(unsafe { pool.copy_in_gather(parts, data.len()) }.is_none());
        // Refusals do not disturb the reservation.
        assert_eq!(pool.free_list.len(), 2);
        assert_eq!(pool.reserved, 2);

        pool.release_reservation(r);
        assert_eq!(pool.free_count(), 2);
        assert!(pool.copy_in(b"a").is_some());
        assert!(pool.alloc_raw().is_some());
        assert_eq!(pool.free_count(), 0);
    }

    #[test]
    fn partially_filled_reservation_releases_the_rest() {
        let mut pool = SendCopyPool::new(3, 8);
        let mut r = pool.reserve_slots(3).unwrap();
        assert_eq!(pool.free_count(), 0);

        let (idx, _ptr, _len) = pool.copy_in_reserved(&mut r, b"one");
        assert_eq!(r.remaining(), 2);
        assert_eq!(pool.free_count(), 0);

        pool.release_reservation(r);
        // One slot is held by the filled chunk; the two unfilled promises are
        // back in circulation.
        assert_eq!(pool.reserved, 0);
        assert_eq!(pool.free_count(), 2);
        assert!(pool.in_use(idx));
        assert!(pool.copy_in(b"a").is_some());
        assert!(pool.copy_in(b"b").is_some());
        assert!(pool.copy_in(b"c").is_none());
    }

    #[test]
    fn zero_slot_reservation_is_a_no_op() {
        let mut pool = SendCopyPool::new(2, 8);
        let r = pool.reserve_slots(0).unwrap();
        assert_eq!(r.remaining(), 0);
        assert_eq!(pool.reserved, 0);
        assert_eq!(pool.free_count(), 2);
        // Nothing is withheld from other allocators while it is outstanding.
        let (idx, _ptr, _len) = pool.copy_in(b"a").unwrap();
        assert_eq!(pool.free_count(), 1);
        pool.release_reservation(r);
        assert_eq!(pool.free_count(), 1);
        pool.release(idx);
        assert_eq!(pool.free_count(), 2);

        // An empty pool still grants an empty reservation (empty sends stay a
        // no-op even under full pressure).
        let mut full = SendCopyPool::new(1, 8);
        let _ = full.copy_in(b"x").unwrap();
        assert_eq!(full.free_count(), 0);
        let r = full.reserve_slots(0).unwrap();
        assert_eq!(full.free_count(), 0);
        full.release_reservation(r);
    }

    #[test]
    fn set_then_take_returns_the_pair_once() {
        let mut pool = SendCopyPool::new(2, 32);
        let id = an_id();
        let (idx, _ptr, _len) = pool.copy_in(b"payload").unwrap();

        // Freshly allocated slots carry nothing.
        assert_eq!(pool.take_send_id(idx), None);

        // The logical length is the caller's, not the slot's byte count —
        // under TLS they differ, which is the whole reason it is carried.
        pool.set_send_id(idx, id, 4096);
        assert_eq!(pool.take_send_id(idx), Some((id, 4096)));
        // Taking settles the operation, so a second take must find nothing.
        assert_eq!(pool.take_send_id(idx), None);

        // The id is per-slot: attaching to one leaves its neighbour alone.
        let (other, _p, _l) = pool.copy_in(b"other").unwrap();
        assert_ne!(other, idx);
        pool.set_send_id(idx, id, 7);
        assert_eq!(pool.take_send_id(other), None);
        assert_eq!(pool.take_send_id(idx), Some((id, 7)));

        pool.release(idx);
        pool.release(other);
    }

    #[test]
    fn every_allocator_hands_out_a_slot_without_a_bounded_send() {
        let mut pool = SendCopyPool::new(4, 32);

        let (a, _p, _l) = pool.copy_in(b"a").unwrap();
        assert_eq!(pool.take_send_id(a), None);

        let data = b"gather";
        let parts: &[(*const u8, usize)] = &[(data.as_ptr(), data.len())];
        let (b, _p, _l) = unsafe { pool.copy_in_gather(parts, data.len()) }.unwrap();
        assert_eq!(pool.take_send_id(b), None);

        let (c, _p, _cap) = pool.alloc_raw().unwrap();
        assert_eq!(pool.take_send_id(c), None);

        let mut r = pool.reserve_slots(1).unwrap();
        let (d, _p, _l) = pool.copy_in_reserved(&mut r, b"reserved");
        assert_eq!(pool.take_send_id(d), None);
        pool.release_reservation(r);

        // A slot recycled from the free list after carrying an id comes back
        // clean: the disposal path takes the id and the allocator resets the
        // entry regardless.
        let id = an_id();
        pool.set_send_id(a, id, 11);
        assert_eq!(pool.take_send_id(a), Some((id, 11)));
        pool.release(a);
        let (again, _p, _l) = pool.copy_in(b"recycled").unwrap();
        assert_eq!(again, a, "LIFO free list should hand back the same slot");
        assert_eq!(pool.take_send_id(again), None);

        for slot in [again, b, c, d] {
            pool.release(slot);
        }
        assert_eq!(pool.free_count(), 4);
    }

    #[test]
    fn release_of_a_slot_without_an_id_is_unaffected() {
        let mut pool = SendCopyPool::new(2, 32);
        let (idx, _ptr, _len) = pool.copy_in(b"plain send").unwrap();
        assert_eq!(pool.free_count(), 1);

        pool.release(idx);
        assert_eq!(pool.free_count(), 2);
        assert!(!pool.in_use(idx));
        // The double-free early return still short-circuits.
        pool.release(idx);
        assert_eq!(pool.free_count(), 2);
    }

    /// Releasing a slot that still names a live bounded send means some
    /// disposal path forgot to settle it; the tripwire fires in debug builds
    /// (where tests normally run), which is what makes the PR 7b audit
    /// mechanical rather than asserted.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "still carrying awaited send")]
    fn release_with_a_live_bounded_send_trips_debug_assert() {
        let mut pool = SendCopyPool::new(1, 32);
        let id = an_id();
        let (idx, _ptr, _len) = pool.copy_in(b"unsettled").unwrap();
        pool.set_send_id(idx, id, 9);
        pool.release(idx);
    }

    /// In a release build the tripwire is compiled out, so the documented
    /// degradation is what must hold: the entry is cleared anyway, and the
    /// recycled slot never reports a dead operation's id.
    #[test]
    #[cfg(not(debug_assertions))]
    fn release_clears_a_live_bounded_send_without_the_tripwire() {
        let mut pool = SendCopyPool::new(1, 32);
        let id = an_id();
        let (idx, _ptr, _len) = pool.copy_in(b"unsettled").unwrap();
        pool.set_send_id(idx, id, 9);
        pool.release(idx);
        assert_eq!(pool.take_send_id(idx), None);
        let (again, _p, _l) = pool.copy_in(b"next").unwrap();
        assert_eq!(again, idx);
        assert_eq!(pool.take_send_id(again), None);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod prefault_tests {
    use super::*;

    /// The pool's `prefault` must make *its own* backing resident.
    ///
    /// Asserts residency of the pool's pages via `mincore`, not process RSS:
    /// `/proc/self/statm` is process-wide and the suite runs in parallel, so an
    /// unrelated thread freeing memory between samples makes the delta
    /// meaningless — and, when it goes negative, panics. (It did, on CI.)
    /// `mincore` answers the question this test is actually asking.
    #[test]
    fn prefault_makes_the_pools_own_pages_resident() {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as usize;
        let slots = 512u16;
        let slot = 64 * 1024u32;
        let mut pool = SendCopyPool::new(slots, slot);

        // Page-aligned window inside the pool's backing.
        let base = pool.backing.as_ptr() as usize;
        let aligned = base.div_ceil(page) * page;
        let pages = (pool.backing.len() - (aligned - base)) / page;
        let ptr = aligned as *mut libc::c_void;
        let len = pages * page;

        let resident = |ptr: *mut libc::c_void, len: usize| -> usize {
            let mut vec = vec![0u8; len / page];
            // SAFETY: `ptr` is page-aligned and `len` bytes from it lie inside
            // the pool's live backing; `vec` has one byte per page.
            let rc = unsafe { libc::mincore(ptr, len, vec.as_mut_ptr()) };
            assert_eq!(rc, 0, "mincore: {}", std::io::Error::last_os_error());
            vec.iter().filter(|b| *b & 1 == 1).count()
        };

        let before = resident(ptr, len);
        assert!(
            before < pages / 2,
            "the pool should start mostly cold, found {before}/{pages} resident — \
             the test cannot show prefaulting does anything otherwise"
        );

        pool.prefault();

        assert_eq!(
            resident(ptr, len),
            pages,
            "every page of the pool's backing must be resident after prefault"
        );
    }
}
