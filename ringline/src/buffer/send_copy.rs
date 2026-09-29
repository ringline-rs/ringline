/// A promise of `remaining` free slots made by [`SendCopyPool::reserve_slots`].
/// Filled with [`SendCopyPool::copy_in_reserved`]; the unfilled remainder must
/// go back through [`SendCopyPool::release_reservation`]. Holding one across
/// any other pool allocation is not needed today (a reservation lives inside
/// one synchronous `DriverCtx::send`), but the pool honours it if it happens.
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
    // Whether this slot holds the final chunk of its logical send. A send
    // larger than one slot is split across several slots; only the last one
    // is marked, so the send waiter is woken once per logical send rather
    // than once per chunk. Independent single-slot sends are always final.
    slot_end_of_send: Vec<bool>,
    // Free-list slots promised to outstanding `SlotReservation`s but not yet
    // popped. Every allocator subtracts this from `free_list.len()` before
    // taking a slot, so a reservation is honoured even if another allocation
    // interleaves with it.
    reserved: usize,
}

impl SendCopyPool {
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
            slot_end_of_send: vec![true; n],
            reserved: 0,
        }
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
        self.slot_end_of_send[idx as usize] = true;
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
        self.slot_end_of_send[idx as usize] = true;
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
        self.slot_end_of_send[idx as usize] = true;
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
    pub fn release(&mut self, idx: u16) {
        debug_assert!((idx as usize) < self.count as usize);
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

    /// Mark whether this slot holds the final chunk of its logical send.
    /// Defaults to `true` on allocation; `DriverCtx::send` clears it on every
    /// chunk but the last when a send is split across slots.
    pub fn set_end_of_send(&mut self, slot: u16, end_of_send: bool) {
        self.slot_end_of_send[slot as usize] = end_of_send;
    }

    /// Whether this slot holds the final chunk of its logical send.
    pub fn is_end_of_send(&self, slot: u16) -> bool {
        self.slot_end_of_send[slot as usize]
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
}
