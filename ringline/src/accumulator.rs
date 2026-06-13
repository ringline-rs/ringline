/// Per-connection byte accumulator for contiguous recv data.
///
/// Handlers always see a contiguous `&[u8]` and return the number of bytes consumed.
/// Unconsumed bytes are retained via O(1) `advance()` instead of shifting.
use bytes::{Bytes, BytesMut};

pub struct RecvAccumulator {
    buf: BytesMut,
    /// Upper bound on `buf.len()` after an `append`. `append` reports
    /// overflow rather than growing past this.
    max_size: usize,
}

impl RecvAccumulator {
    /// Create a new accumulator with the given initial capacity and an
    /// unlimited size cap. For runtime use, prefer
    /// [`new_with_max`](Self::new_with_max).
    #[allow(dead_code)]
    pub fn new(capacity: usize) -> Self {
        Self::new_with_max(capacity, usize::MAX)
    }

    /// Create a new accumulator with an initial capacity and an upper-bound
    /// `max_size`. `append` rejects data that would push `buf.len()` past
    /// `max_size`, leaving the existing contents intact so the caller can
    /// fail the connection rather than OOM.
    pub fn new_with_max(capacity: usize, max_size: usize) -> Self {
        RecvAccumulator {
            buf: BytesMut::with_capacity(capacity),
            max_size,
        }
    }

    /// Append received bytes. Returns `false` if the append would push the
    /// accumulator past its `max_size` — in that case the existing contents
    /// are preserved and the caller should close the connection (or accept
    /// that intermediate-flush data is dropped, depending on context).
    ///
    /// Not marked `#[must_use]`: not every caller is in a position to fail
    /// the connection (e.g. intermediate buffer-shuffling paths inside
    /// `WithDataFuture::poll`). The authoritative cap-enforcement sites are
    /// the kernel-recv handlers in `backend/uring/event_loop.rs`.
    pub fn append(&mut self, data: &[u8]) -> bool {
        if self.buf.len().saturating_add(data.len()) > self.max_size {
            return false;
        }
        self.buf.extend_from_slice(data);
        true
    }

    /// Get a reference to the accumulated data.
    pub fn data(&self) -> &[u8] {
        &self.buf[..]
    }

    /// Consume `n` bytes from the front — O(1) via `BytesMut::advance`.
    pub fn consume(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        debug_assert!(
            n <= self.buf.len(),
            "consume({n}) exceeds buffer length {}",
            self.buf.len()
        );
        let n = n.min(self.buf.len());
        self.buf.advance(n);
    }

    /// Reset the accumulator (discard all data).
    pub fn reset(&mut self) {
        self.buf.clear();
    }

    /// Return the current backing-buffer capacity. Test-only.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.buf.capacity()
    }
}

use bytes::Buf;

/// Parallel `Vec<RecvAccumulator>` indexed by connection index.
/// Stored as a separate field in EventLoop for borrow splitting.
pub struct AccumulatorTable {
    accumulators: Vec<RecvAccumulator>,
}

impl AccumulatorTable {
    /// Create a table with `count` accumulators, each with the given initial
    /// capacity and no upper-bound size.
    #[allow(dead_code)]
    pub fn new(count: u32, capacity: usize) -> Self {
        Self::new_with_max(count, capacity, usize::MAX)
    }

    /// Create a table with `count` accumulators, each with the given initial
    /// capacity and upper-bound `max_size`.
    pub fn new_with_max(count: u32, capacity: usize, max_size: usize) -> Self {
        let mut accumulators = Vec::with_capacity(count as usize);
        for _ in 0..count {
            accumulators.push(RecvAccumulator::new_with_max(capacity, max_size));
        }
        AccumulatorTable { accumulators }
    }

    /// Append data to the accumulator at the given index. Returns `false`
    /// if the append would exceed the accumulator's `max_size`; in that
    /// case the existing buffer is unchanged. The authoritative
    /// cap-enforcement sites are the kernel-recv handlers; intermediate
    /// flush callers may ignore the return value.
    pub fn append(&mut self, index: u32, data: &[u8]) -> bool {
        self.accumulators[index as usize].append(data)
    }

    /// Get accumulated data at the given index.
    pub fn data(&self, index: u32) -> &[u8] {
        self.accumulators[index as usize].data()
    }

    /// Consume `n` bytes from the accumulator at the given index.
    pub fn consume(&mut self, index: u32, n: usize) {
        self.accumulators[index as usize].consume(n);
    }

    /// Reset the accumulator at the given index.
    pub fn reset(&mut self, index: u32) {
        self.accumulators[index as usize].reset();
    }

    /// Return the current backing-buffer capacity for the accumulator at
    /// the given index. Test-only.
    #[cfg(test)]
    pub(crate) fn capacity(&self, index: u32) -> usize {
        self.accumulators[index as usize].capacity()
    }

    /// Detach the accumulator's buffer as a frozen `Bytes` (O(1)).
    ///
    /// The accumulator is left empty. Use `prepend()` to put back
    /// any unconsumed remainder after zero-copy parsing.
    pub fn take_frozen(&mut self, index: u32) -> Bytes {
        let acc = &mut self.accumulators[index as usize];
        std::mem::replace(&mut acc.buf, BytesMut::new()).freeze()
    }

    /// Put unconsumed data back into the accumulator.
    ///
    /// Called after `take_frozen()` when the parser didn't consume
    /// everything (e.g. pipelined remainder or incomplete next message).
    pub fn prepend(&mut self, index: u32, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let acc = &mut self.accumulators[index as usize];
        // The accumulator should be empty after take_frozen(), but if new
        // data arrived (impossible in single-threaded poll), handle it.
        if acc.buf.is_empty() {
            acc.buf.extend_from_slice(data);
        } else {
            // Rare path: new data already present. Prepend by building a
            // new buffer with remainder first.
            let mut new_buf = BytesMut::with_capacity(data.len() + acc.buf.len());
            new_buf.extend_from_slice(data);
            new_buf.extend_from_slice(&acc.buf);
            acc.buf = new_buf;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_consume() {
        let mut acc = RecvAccumulator::new(64);
        assert!(acc.append(b"hello "));
        assert!(acc.append(b"world"));
        assert_eq!(acc.data(), b"hello world");
        acc.consume(6);
        assert_eq!(acc.data(), b"world");
        acc.consume(5);
        assert_eq!(acc.data(), b"");
    }

    #[test]
    fn grow_on_overflow() {
        let mut acc = RecvAccumulator::new(4);
        assert!(acc.append(b"abcdef")); // exceeds initial capacity but not max
        assert_eq!(acc.data(), b"abcdef");
    }

    #[test]
    fn reset_clears() {
        let mut acc = RecvAccumulator::new(16);
        assert!(acc.append(b"data"));
        acc.reset();
        assert_eq!(acc.data(), b"");
    }

    #[test]
    fn append_past_max_returns_false_and_preserves_contents() {
        let mut acc = RecvAccumulator::new_with_max(8, 8);
        assert!(acc.append(b"abcdef"));
        // Would push to 9 bytes, exceeding max=8.
        assert!(!acc.append(b"xyz"));
        // Existing contents intact.
        assert_eq!(acc.data(), b"abcdef");
    }

    #[test]
    fn table_operations() {
        let mut table = AccumulatorTable::new(4, 64);
        assert!(table.append(2, b"hello"));
        assert_eq!(table.data(2), b"hello");
        table.consume(2, 3);
        assert_eq!(table.data(2), b"lo");
        table.reset(2);
        assert_eq!(table.data(2), b"");
    }

    #[test]
    fn table_append_past_max_returns_false() {
        let mut table = AccumulatorTable::new_with_max(1, 4, 4);
        assert!(table.append(0, b"abcd"));
        assert!(!table.append(0, b"e"));
        assert_eq!(table.data(0), b"abcd");
    }

    #[test]
    fn take_frozen_and_prepend() {
        let mut table = AccumulatorTable::new(2, 64);
        assert!(table.append(0, b"$5\r\nhello\r\n$3\r\nbar\r\n"));

        let frozen = table.take_frozen(0);
        assert_eq!(&frozen[..], b"$5\r\nhello\r\n$3\r\nbar\r\n");
        // Accumulator is now empty.
        assert_eq!(table.data(0), b"");

        // Put back the unconsumed remainder.
        table.prepend(0, &frozen[11..]);
        assert_eq!(table.data(0), b"$3\r\nbar\r\n");
    }

    /// After `take_frozen` + `prepend(remainder)`, the accumulator must NOT
    /// have allocated a new backing buffer — the tail capacity from the
    /// split must still be in place (`capacity() > 0` immediately after
    /// `take_frozen`, and the `prepend` does not reallocate).
    #[test]
    fn take_frozen_preserves_tail_capacity() {
        let mut table = AccumulatorTable::new(1, 256);
        // Fill with data that will have a remainder after the first parse.
        assert!(table.append(0, b"$5\r\nhello\r\n$3\r\nbar\r\n"));

        let frozen = table.take_frozen(0);
        // Capacity must be non-zero — the tail allocation is retained.
        assert!(
            table.capacity(0) > 0,
            "take_frozen must retain tail capacity, got 0"
        );

        // Prepend the unconsumed remainder — must not reallocate.
        let cap_after_take = table.capacity(0);
        let remainder = &frozen[11..];
        table.prepend(0, remainder);
        assert_eq!(
            table.capacity(0),
            cap_after_take,
            "prepend(remainder) must reuse the retained capacity, not reallocate"
        );
        assert_eq!(table.data(0), b"$3\r\nbar\r\n");

        // Multiple cycles must each preserve capacity (no per-cycle realloc).
        for _ in 0..3 {
            assert!(table.append(0, b" extra"));
            let f = table.take_frozen(0);
            assert!(table.capacity(0) > 0, "cycle: take_frozen must retain capacity");
            let cap_before = table.capacity(0);
            table.prepend(0, &f[..3]);
            assert_eq!(
                table.capacity(0),
                cap_before,
                "cycle: prepend must reuse retained capacity"
            );
            drop(f);
        }
    }

    #[test]
    fn take_frozen_empty() {
        let mut table = AccumulatorTable::new(1, 16);
        let frozen = table.take_frozen(0);
        assert!(frozen.is_empty());
    }

    #[test]
    fn prepend_to_empty() {
        let mut table = AccumulatorTable::new(1, 16);
        table.prepend(0, b"leftover");
        assert_eq!(table.data(0), b"leftover");
    }

    #[test]
    fn prepend_empty_is_noop() {
        let mut table = AccumulatorTable::new(1, 16);
        assert!(table.append(0, b"existing"));
        table.prepend(0, b"");
        assert_eq!(table.data(0), b"existing");
    }
}
