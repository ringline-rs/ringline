/// Per-connection byte accumulator for contiguous recv data.
///
/// Handlers always see a contiguous `&[u8]` and return the number of bytes consumed.
/// Unconsumed bytes are retained via O(1) `advance()` instead of shifting.
use bytes::{Bytes, BytesMut};

pub struct RecvAccumulator {
    buf: BytesMut,
}

impl RecvAccumulator {
    /// Create a new accumulator with the given initial capacity.
    pub fn new(capacity: usize) -> Self {
        RecvAccumulator {
            buf: BytesMut::with_capacity(capacity),
        }
    }

    /// Append received bytes. Grows the buffer if necessary.
    pub fn append(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
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
        debug_assert!(n <= self.buf.len(), "consume({n}) exceeds buffer length {}", self.buf.len());
        let n = n.min(self.buf.len());
        self.buf.advance(n);
    }

    /// Reset the accumulator (discard all data).
    pub fn reset(&mut self) {
        self.buf.clear();
    }
}

use bytes::Buf;

/// Parallel `Vec<RecvAccumulator>` indexed by connection index.
/// Stored as a separate field in EventLoop for borrow splitting.
pub struct AccumulatorTable {
    accumulators: Vec<RecvAccumulator>,
}

impl AccumulatorTable {
    /// Create a table with `count` accumulators, each with the given capacity.
    pub fn new(count: u32, capacity: usize) -> Self {
        let mut accumulators = Vec::with_capacity(count as usize);
        for _ in 0..count {
            accumulators.push(RecvAccumulator::new(capacity));
        }
        AccumulatorTable { accumulators }
    }

    /// Append data to the accumulator at the given index.
    pub fn append(&mut self, index: u32, data: &[u8]) {
        self.accumulators[index as usize].append(data);
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
        acc.append(b"hello ");
        acc.append(b"world");
        assert_eq!(acc.data(), b"hello world");
        acc.consume(6);
        assert_eq!(acc.data(), b"world");
        acc.consume(5);
        assert_eq!(acc.data(), b"");
    }

    #[test]
    fn grow_on_overflow() {
        let mut acc = RecvAccumulator::new(4);
        acc.append(b"abcdef"); // exceeds initial capacity
        assert_eq!(acc.data(), b"abcdef");
    }

    #[test]
    fn reset_clears() {
        let mut acc = RecvAccumulator::new(16);
        acc.append(b"data");
        acc.reset();
        assert_eq!(acc.data(), b"");
    }

    #[test]
    fn table_operations() {
        let mut table = AccumulatorTable::new(4, 64);
        table.append(2, b"hello");
        assert_eq!(table.data(2), b"hello");
        table.consume(2, 3);
        assert_eq!(table.data(2), b"lo");
        table.reset(2);
        assert_eq!(table.data(2), b"");
    }

    #[test]
    fn take_frozen_and_prepend() {
        let mut table = AccumulatorTable::new(2, 64);
        table.append(0, b"$5\r\nhello\r\n$3\r\nbar\r\n");

        let frozen = table.take_frozen(0);
        assert_eq!(&frozen[..], b"$5\r\nhello\r\n$3\r\nbar\r\n");
        // Accumulator is now empty.
        assert_eq!(table.data(0), b"");

        // Put back the unconsumed remainder.
        table.prepend(0, &frozen[11..]);
        assert_eq!(table.data(0), b"$3\r\nbar\r\n");
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
        table.append(0, b"existing");
        table.prepend(0, b"");
        assert_eq!(table.data(0), b"existing");
    }
}
