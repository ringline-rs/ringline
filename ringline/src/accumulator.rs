/// Per-connection byte accumulator for contiguous recv data.
///
/// Handlers always see a contiguous `&[u8]` and return the number of bytes consumed.
/// Unconsumed bytes are retained via O(1) `advance()` instead of shifting.
use bytes::{Bytes, BytesMut};

/// Count `n` bytes copied into receive storage (`recv_ring::BYTES_COPIED`).
pub(crate) fn note_copied(n: usize) {
    if n > 0 {
        crate::metrics::RECV_RING.add(crate::metrics::recv_ring::BYTES_COPIED, n as u64);
        #[cfg(test)]
        TEST_BYTES_COPIED.with(|c| c.set(c.get() + n as u64));
    }
}

#[cfg(test)]
thread_local! {
    /// This thread's `note_copied` total. Tests read it instead of the
    /// process-wide metric, which concurrent tests in one process also move.
    static TEST_BYTES_COPIED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// This thread's `note_copied` total.
#[cfg(test)]
pub(crate) fn test_bytes_copied() -> u64 {
    TEST_BYTES_COPIED.with(|c| c.get())
}

/// Bytes `buf` held before an operation that may have moved them: `kept` if
/// its data pointer is no longer `before`, otherwise 0.
fn moved(buf: &BytesMut, before: *const u8, kept: usize) -> usize {
    if kept > 0 && buf.as_ptr() != before {
        kept
    } else {
        0
    }
}

pub struct RecvAccumulator {
    buf: BytesMut,
    /// Unconsumed remainder of a previously frozen (`take_frozen`) view,
    /// held as a refcounted slice. Serving subsequent parses from this is
    /// O(1); it is merged (one copy) into `buf` only when NEW data arrives
    /// while a remainder is held. The old representation copied the whole
    /// remainder back into `buf` on every put-back — O(B²) over a
    /// pipelined batch of B responses and O(N·K) for an N-byte value
    /// arriving in K chunks.
    ///
    /// Invariant: `frozen` is `None` or non-empty.
    frozen: Option<Bytes>,
    /// Upper bound on total buffered bytes (`frozen` remainder + `buf`)
    /// after an `append`. `append` reports overflow rather than growing
    /// past this.
    max_size: usize,
    /// High-water total-size target announced via [`reserve`](Self::reserve)
    /// (a length-prefixed parser that has seen its header). Consulted by
    /// every growth site — `append` and the `unfreeze` merge — so a
    /// multi-chunk message allocates once at full size instead of running
    /// the doubling-regrowth cascade. Cleared when the contents drain.
    reserve_target: usize,
    /// The largest message a parser has consumed in one call
    /// (`note_consumed`), until `reset` or `release`. Sizes direct receives
    /// (`detach_for_recv`).
    largest_message: usize,
    /// The largest `buf.capacity()` after an `append`, until `reset` or
    /// `release`. `compact_at_message_start` restores this capacity ahead of
    /// a message that has just started.
    grown: usize,
    /// The last frozen view of a direct connection's buffer that a parser
    /// consumed whole (`keep_spent`). `detach_for_recv` takes the allocation
    /// back from it when no slice of it is alive, instead of allocating a
    /// new receive buffer.
    #[cfg(has_io_uring)]
    spent: Option<Bytes>,
    /// A direct connection's own buffer while `buf` is one borrowed from the
    /// worker's [`DirectPool`] for a message larger than it. `None` when
    /// `buf` is the connection's own.
    #[cfg(has_io_uring)]
    own: Option<BytesMut>,
    /// Capacity `buf` is allocated with, and returns to on
    /// [`release`](Self::release).
    initial_capacity: usize,
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
            frozen: None,
            max_size,
            reserve_target: 0,
            largest_message: 0,
            grown: 0,
            #[cfg(has_io_uring)]
            spent: None,
            #[cfg(has_io_uring)]
            own: None,
            initial_capacity: capacity,
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
        let total = self.total_len();
        if total.saturating_add(data.len()) > self.max_size {
            return false;
        }
        let before = self.buf.as_ptr();
        let kept = self.buf.len();
        // When a growth is imminent and a reserve target was announced,
        // size the allocation for the whole remaining message up front.
        if self.buf.capacity() - self.buf.len() < data.len() {
            let want = self.reserve_target.saturating_sub(total).max(data.len());
            self.buf.reserve(want);
        }
        self.buf.extend_from_slice(data);
        note_copied(data.len() + moved(&self.buf, before, kept));
        self.grown = self.grown.max(self.buf.capacity());
        true
    }

    /// Called by `with_data` when a parser stops at an incomplete message
    /// and when it parks with nothing buffered. Moves the contents to the
    /// front of the allocation with `BytesMut::try_reclaim` when
    /// `buf.capacity()`, the room from the start of the contents, is at most
    /// `grown / 2` and the contents fill at most half of that room, or when
    /// nothing is buffered and the room is below `grown`. The message being
    /// received then has the grown capacity ahead of it, so `append` does
    /// not have to move most of it once it reaches the end of the
    /// allocation. `try_reclaim` does not allocate, and does nothing while a
    /// `Bytes` taken from the allocation (`take_frozen`, a forward's guard)
    /// is alive. Returns early while a frozen remainder is held.
    pub fn compact_at_message_start(&mut self) {
        if self.frozen.is_some() {
            return;
        }
        let live = self.buf.len();
        let room = self.buf.capacity();
        let start =
            (room <= self.grown / 2 && live * 2 <= room) || (live == 0 && room < self.grown);
        if !start {
            return;
        }
        let before = self.buf.as_ptr();
        if self.buf.try_reclaim(self.grown - live) {
            note_copied(moved(&self.buf, before, live));
        }
    }

    /// Total buffered bytes: held frozen remainder + mutable tail.
    fn total_len(&self) -> usize {
        self.frozen.as_ref().map_or(0, |f| f.len()) + self.buf.len()
    }

    /// Whether the accumulator holds no bytes at all — O(1), and unlike
    /// `data().is_empty()` it never merges a held frozen remainder into
    /// `buf`. Hot paths that only need emptiness (e.g. the zero-copy recv
    /// fast-path check) must use this: a `data()` call while a remainder is
    /// held and new bytes have arrived forces a full merge copy per call —
    /// O(N·K) over an N-byte value arriving in K chunks.
    pub fn is_empty(&self) -> bool {
        self.total_len() == 0
    }

    /// Total buffered bytes — O(1) and non-merging, like
    /// [`is_empty`](Self::is_empty).
    pub fn len(&self) -> usize {
        self.total_len()
    }

    /// Merge a held frozen remainder into `buf` so the contents are one
    /// contiguous mutable region again. One copy of the remainder; only
    /// needed when new data arrived while a remainder was held, or when a
    /// borrowed-slice consumer needs a single `&[u8]` view.
    fn unfreeze(&mut self) {
        let Some(rem) = self.frozen.take() else {
            return;
        };
        // If the parser kept no slices alive (streaming NeedMore cycles),
        // the remainder is uniquely referenced and `try_into_mut` recovers
        // the original allocation with the data already in place — the
        // merge then costs only the newly appended bytes, not the whole
        // remainder. With live parser slices (pipelined batches) this
        // falls back to one full copy, which only happens when new data
        // arrives mid-batch.
        match rem.try_into_mut() {
            Ok(mut recovered) => {
                if !self.buf.is_empty() {
                    // Honor a pending reserve target so the streaming
                    // NeedAtLeast cycle merges into a full-size buffer once
                    // instead of regrowing per appended chunk.
                    let want = self
                        .reserve_target
                        .saturating_sub(recovered.len() + self.buf.len())
                        .saturating_add(self.buf.len());
                    let before = recovered.as_ptr();
                    let kept = recovered.len();
                    if recovered.capacity() - recovered.len() < want {
                        recovered.reserve(want);
                    }
                    recovered.extend_from_slice(&self.buf);
                    note_copied(self.buf.len() + moved(&recovered, before, kept));
                }
                self.buf = recovered;
            }
            Err(rem) => {
                if self.buf.is_empty() {
                    self.buf.extend_from_slice(&rem);
                    note_copied(rem.len());
                } else {
                    let merged_len = rem.len() + self.buf.len();
                    let mut merged = BytesMut::with_capacity(merged_len.max(self.reserve_target));
                    merged.extend_from_slice(&rem);
                    merged.extend_from_slice(&self.buf);
                    note_copied(merged_len);
                    self.buf = merged;
                }
            }
        }
    }

    /// Get a reference to the accumulated data.
    ///
    /// Merges a held frozen remainder first so the view is contiguous —
    /// borrowed-slice consumers (`with_data`, streams, TLS drains) pay the
    /// merge only when they interleave with `with_bytes` on one connection.
    pub fn data(&mut self) -> &[u8] {
        if self.frozen.is_some() && !self.buf.is_empty() {
            self.unfreeze();
        }
        if let Some(ref f) = self.frozen {
            &f[..]
        } else {
            &self.buf[..]
        }
    }

    /// Consume `n` bytes from the front — O(1).
    pub fn consume(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        // After a `data()` view, at most one of `frozen` / `buf` is
        // non-empty (data() merges when both are).
        if let Some(ref mut f) = self.frozen {
            debug_assert!(
                n <= f.len(),
                "consume({n}) exceeds frozen remainder length {}",
                f.len()
            );
            let n = n.min(f.len());
            f.advance(n);
            if f.is_empty() {
                self.frozen = None;
            }
            if self.total_len() == 0 {
                self.reserve_target = 0;
            }
            return;
        }
        debug_assert!(
            n <= self.buf.len(),
            "consume({n}) exceeds buffer length {}",
            self.buf.len()
        );
        let n = n.min(self.buf.len());
        self.buf.advance(n);
        if self.total_len() == 0 {
            self.reserve_target = 0;
        }
    }

    /// Announce that at least `additional` more bytes are expected beyond
    /// the current contents (a length-prefixed parser that has seen its
    /// header). Records a high-water total-size target — clamped to
    /// `max_size` — that `append` and the `unfreeze` merge use to allocate
    /// once at full size instead of running the doubling-regrowth cascade
    /// (~2× the payload in extra memcpy for a multi-MB message arriving
    /// in chunks). The target clears when the contents drain.
    pub fn reserve(&mut self, additional: usize) {
        let target = self
            .total_len()
            .saturating_add(additional)
            .min(self.max_size);
        self.reserve_target = self.reserve_target.max(target);
    }

    /// Reset the accumulator (discard all data). Keeps the allocation.
    pub fn reset(&mut self) {
        self.frozen = None;
        self.buf.clear();
        self.reserve_target = 0;
        self.largest_message = 0;
        self.grown = 0;
        #[cfg(has_io_uring)]
        {
            self.spent = None;
        }
    }

    /// Discard all data and the allocation, and allocate the initial
    /// capacity again. Called when a connection closes, since an accumulator
    /// grows to the largest message its connection buffered. `Bytes` taken
    /// with `take_frozen` (parser slices, an in-flight zero-copy forward's
    /// guard) keep the old allocation until they drop.
    ///
    /// The reallocation is unconditional: after `take_frozen`, `buf` is the
    /// tail of the old allocation, so a small `capacity()` does not mean a
    /// small allocation.
    pub fn release(&mut self) {
        self.frozen = None;
        self.buf = BytesMut::with_capacity(self.initial_capacity);
        self.reserve_target = 0;
        self.largest_message = 0;
        self.grown = 0;
        #[cfg(has_io_uring)]
        {
            self.spent = None;
            self.own = None;
        }
    }

    /// Return the current backing-buffer capacity. Test-only.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.buf.capacity()
    }
}

/// Smallest buffer a direct connection borrows from its worker's
/// [`DirectPool`]: 64 KiB.
#[cfg(has_io_uring)]
const DIRECT_BORROW_MIN: usize = 64 * 1024;
/// Default for `ConfigBuilder::recv_direct_pool_max`: 16 MiB.
#[cfg(has_io_uring)]
pub(crate) const DIRECT_POOL_MAX_DEFAULT: usize = 16 << 20;

/// The size of a new borrowed buffer for `n` bytes: at least
/// `DIRECT_BORROW_MIN`; up to 2 MiB, `n` rounded up to one of eight steps per
/// power of two (about 9% apart), so that messages of nearly the same size
/// reuse each other's buffers; above 2 MiB, a multiple of 2 MiB, the size of a
/// transparent huge page.
#[cfg(has_io_uring)]
fn direct_borrow_size(n: usize) -> usize {
    const HUGE_PAGE: usize = 2 << 20;
    if n <= DIRECT_BORROW_MIN {
        return DIRECT_BORROW_MIN;
    }
    let step = if n > HUGE_PAGE {
        HUGE_PAGE
    } else {
        1usize << (usize::BITS - 1 - n.leading_zeros() - 3)
    };
    n.div_ceil(step).saturating_mul(step)
}

/// Free buffers that a worker's direct connections borrow for messages
/// larger than their own buffer, so that a buffer moves from one connection
/// to the next without going back to the allocator. Keyed by capacity. New
/// buffers are allocated at one of eight sizes per power of two up to 2 MiB
/// and at multiples of 2 MiB above (`direct_borrow_size`); a buffer given
/// back keeps the capacity it has.
#[cfg(has_io_uring)]
struct DirectPool {
    free: std::collections::BTreeMap<usize, Vec<BytesMut>>,
    free_bytes: usize,
    /// The most bytes of free buffers kept (see `put`).
    max_free_bytes: usize,
}

#[cfg(has_io_uring)]
impl DirectPool {
    fn new(max_free_bytes: usize) -> Self {
        DirectPool {
            free: std::collections::BTreeMap::new(),
            free_bytes: 0,
            max_free_bytes,
        }
    }

    /// An empty buffer of at least `n` bytes: the smallest free one that
    /// holds `n` and is at most twice `direct_borrow_size(n)`, or a new one
    /// of `direct_borrow_size(n)`.
    fn take(&mut self, n: usize) -> BytesMut {
        let size = direct_borrow_size(n);
        let fit = self
            .free
            .range(n..=size.saturating_mul(2))
            .next()
            .map(|(&cap, _)| cap);
        if let Some(cap) = fit {
            let list = self.free.get_mut(&cap).expect("key from range");
            let buf = list.pop().expect("lists are not left empty");
            if list.is_empty() {
                self.free.remove(&cap);
            }
            self.free_bytes -= cap;
            crate::metrics::RECV_DIRECT.increment(crate::metrics::recv_direct::POOL_REUSED);
            return buf;
        }
        crate::metrics::RECV_DIRECT.increment(crate::metrics::recv_direct::POOL_ALLOCATED);
        BytesMut::with_capacity(size)
    }

    /// Keep `buf` for reuse if it is at least `DIRECT_BORROW_MIN` and at
    /// most the cap on free bytes; otherwise free it. When the free buffers
    /// have no room for it, the largest free buffers larger than `buf` are
    /// freed to make room, and `buf` is freed if that is not enough.
    ///
    /// A buffer recovered from a view (`keep_spent`) starts where the view
    /// started, so its `capacity()` excludes the bytes before that;
    /// `try_reclaim` moves its start back to the start of the allocation
    /// without allocating.
    fn put(&mut self, mut buf: BytesMut) {
        buf.clear();
        let _ = buf.try_reclaim(buf.capacity() + 1);
        let cap = buf.capacity();
        if cap < DIRECT_BORROW_MIN || cap > self.max_free_bytes {
            return;
        }
        while self.free_bytes + cap > self.max_free_bytes {
            let Some(mut largest) = self.free.last_entry() else {
                break;
            };
            if *largest.key() <= cap {
                return;
            }
            let freed = *largest.key();
            largest.get_mut().pop();
            if largest.get().is_empty() {
                largest.remove();
            }
            self.free_bytes -= freed;
        }
        self.free_bytes += cap;
        self.free.entry(cap).or_default().push(buf);
    }
}

use bytes::Buf;

/// The error a reader parked on `with_data_result` gets when its plaintext
/// connection is closed for running past `recv_accumulator_max`. One
/// constructor, so both backends report the same kind. On a TLS connection
/// the overflow is reported by the record layer as a `TlsRecvResult::Error`
/// and the reader gets `Ok(0)`.
pub(crate) fn recv_cap_exceeded() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::QuotaExceeded,
        "a message ran past recv_accumulator_max",
    )
}

/// Parallel `Vec<RecvAccumulator>` indexed by connection index.
/// Stored as a separate field in EventLoop for borrow splitting.
pub struct AccumulatorTable {
    accumulators: Vec<RecvAccumulator>,
    /// Buffers direct connections borrow for messages larger than their own.
    #[cfg(has_io_uring)]
    direct_pool: DirectPool,
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
        AccumulatorTable {
            accumulators,
            #[cfg(has_io_uring)]
            direct_pool: DirectPool::new(DIRECT_POOL_MAX_DEFAULT),
        }
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
    ///
    /// `&mut` because a held frozen remainder may need a one-time merge to
    /// present a contiguous view (see [`RecvAccumulator::data`]).
    pub fn data(&mut self, index: u32) -> &[u8] {
        self.accumulators[index as usize].data()
    }

    /// Whether the accumulator at the given index is empty — O(1) and
    /// non-merging, unlike `data(index).is_empty()` (see
    /// [`RecvAccumulator::is_empty`]).
    pub fn is_empty(&self, index: u32) -> bool {
        self.accumulators[index as usize].is_empty()
    }

    /// Bytes held by the accumulator at the given index — O(1) and
    /// non-merging (see [`RecvAccumulator::len`]).
    pub fn len(&self, index: u32) -> usize {
        self.accumulators[index as usize].len()
    }

    /// Consume `n` bytes from the accumulator at the given index.
    pub fn consume(&mut self, index: u32, n: usize) {
        self.accumulators[index as usize].consume(n);
    }

    /// Reserve capacity for `additional` more bytes at the given index
    /// (clamped to the accumulator's `max_size`).
    pub fn reserve(&mut self, index: u32, additional: usize) {
        self.accumulators[index as usize].reserve(additional);
    }

    /// See [`RecvAccumulator::compact_at_message_start`].
    pub fn compact_at_message_start(&mut self, index: u32) {
        self.accumulators[index as usize].compact_at_message_start();
    }

    /// Reset the accumulator at the given index.
    pub fn reset(&mut self, index: u32) {
        self.accumulators[index as usize].reset();
    }

    /// Discard the accumulator's data and allocation at the given index.
    /// See [`RecvAccumulator::release`].
    pub fn release(&mut self, index: u32) {
        #[cfg(has_io_uring)]
        {
            let acc = &mut self.accumulators[index as usize];
            if acc.own.is_some() {
                self.direct_pool.put(std::mem::take(&mut acc.buf));
            }
        }
        self.accumulators[index as usize].release();
    }

    /// Set the most bytes of free buffers the direct-receive pool keeps.
    #[cfg(has_io_uring)]
    pub(crate) fn set_direct_pool_max(&mut self, bytes: usize) {
        self.direct_pool.max_free_bytes = bytes;
    }

    /// Give a direct receive's buffer whose connection is gone to the pool.
    #[cfg(has_io_uring)]
    pub(crate) fn recycle_direct(&mut self, buf: BytesMut) {
        self.direct_pool.put(buf);
    }

    /// Return the current backing-buffer capacity for the accumulator at
    /// the given index. Test-only.
    #[cfg(test)]
    pub(crate) fn capacity(&self, index: u32) -> usize {
        self.accumulators[index as usize].capacity()
    }

    /// Detach the accumulator's buffer as a frozen `Bytes` (O(1)).
    ///
    /// The accumulator is left empty but retains the tail capacity of the
    /// same allocation via `split_to`. Any subsequent `prepend()` of an
    /// unconsumed remainder (the hot pipelined-parse path) reuses that
    /// capacity instead of heap-allocating a fresh `BytesMut`.
    ///
    /// Note: when the returned `Bytes` (or sub-slices the parser keeps, as in
    /// `with_bytes`) outlive the next `append()`, the shared allocation cannot
    /// reclaim its front, so the tail capacity shrinks across cycles and a
    /// later `append()` may still reallocate. The win is the avoided per-parse
    /// remainder allocation, not elimination of all reallocation.
    pub fn take_frozen(&mut self, index: u32) -> Bytes {
        let acc = &mut self.accumulators[index as usize];
        // Serving a held remainder with no new data is the pipelined hot
        // path: a batch of B responses is frozen once and each recv()
        // cycle takes/puts-back the same refcounted Bytes — O(1) per
        // cycle, no copies (previously the remainder was memcpy'd back
        // into the buffer every cycle: O(B²) over the batch).
        if let Some(rem) = acc.frozen.take() {
            if acc.buf.is_empty() {
                return rem;
            }
            // New data arrived while a remainder was held — merge once.
            acc.frozen = Some(rem);
            acc.unfreeze();
        }
        let len = acc.buf.len();
        // Fast path: empty accumulator — `split_to(0)` would unnecessarily
        // upgrade `BytesMut` to shared mode, blocking later front-reclaim.
        if len == 0 {
            return Bytes::new();
        }
        // `split_to(len)` hands back the filled front as `other` and leaves
        // `acc.buf` empty but still owning the tail capacity of the same
        // allocation — O(1), no copy. The `freeze()` on the front is also
        // O(1). Both operations are non-allocating.
        acc.buf.split_to(len).freeze()
    }

    /// Put back the unconsumed remainder of a `take_frozen()` view — O(1).
    ///
    /// Called from the `with_bytes` path when the parser didn't consume
    /// everything (pipelined remainder or incomplete next message). The
    /// remainder is stored as a refcounted slice; it is copied at most once
    /// more (by `unfreeze`) and only if new data arrives before the next
    /// take.
    pub fn put_back(&mut self, index: u32, data: Bytes) {
        if data.is_empty() {
            return;
        }
        let acc = &mut self.accumulators[index as usize];
        debug_assert!(
            acc.frozen.is_none(),
            "put_back: a frozen remainder is already held (take/put must alternate)"
        );
        // `put_back` follows `take_frozen` within one poll, so `buf` holds
        // only data appended after the take (normally nothing).
        //
        // Drop `buf`'s handle when it is empty: `take_frozen`'s `split_to`
        // left it sharing the remainder's allocation, and that extra
        // reference makes `try_into_mut` in `unfreeze` fail — forcing a
        // full-remainder copy on EVERY merge instead of an in-place append
        // of just the new bytes. For an N-byte response streamed in K
        // chunks that is O(N·K): measured 69 GB memcpy'd to receive 4.8 GB
        // of 64 MiB values. Nothing is lost by dropping the handle — once
        // the remainder is uniquely referenced, `try_into_mut` recovers the
        // full original allocation (including this tail capacity).
        if acc.buf.is_empty() {
            acc.buf = BytesMut::new();
        }
        acc.frozen = Some(data);
    }

    /// Make a remainder held by [`put_back`](Self::put_back) the mutable
    /// buffer again, with nothing appended, before a caller appends a run of
    /// data behind it. When the remainder is the only reference to its
    /// allocation (the parser kept no slice of it), `try_into_mut` recovers
    /// the allocation with the bytes in place and nothing is copied.
    /// Otherwise the remainder is copied once into a new buffer sized for the
    /// reserve target ([`reserve`](Self::reserve)), so a caller that reserves
    /// first grows the buffer once.
    pub fn reclaim(&mut self, index: u32) {
        let acc = &mut self.accumulators[index as usize];
        if !acc.buf.is_empty() {
            // Bytes were appended since the put-back: the ordinary merge.
            acc.unfreeze();
            return;
        }
        let Some(rem) = acc.frozen.take() else {
            return;
        };
        match rem.try_into_mut() {
            Ok(recovered) => acc.buf = recovered,
            Err(rem) => {
                let mut buf = BytesMut::with_capacity(rem.len().max(acc.reserve_target));
                buf.extend_from_slice(&rem);
                note_copied(rem.len());
                acc.buf = buf;
            }
        }
    }

    /// Detach the accumulator's buffer, with its unconsumed bytes, as the
    /// destination of a direct receive. The
    /// kernel writes into the returned buffer's spare capacity, starting at
    /// its length; [`attach_received`](Self::attach_received) puts it back.
    /// While it is detached the accumulator is empty.
    ///
    /// Returns the buffer, the number of bytes to receive (all its spare
    /// capacity, up to `max_size`), and whether it was sized for a known
    /// message length. `None` when the accumulator is at `max_size`.
    ///
    /// With nothing buffered, the receive goes into the connection's own
    /// buffer of `region` bytes, and a buffer borrowed for an earlier message
    /// goes back to the pool. With part of a message buffered, the buffer
    /// grows when less than `need` (the parser's `NeedAtLeast` value), or
    /// less than half of `region`, is spare: to hold the rest of the message
    /// when `need` is at least `region`, and otherwise to the larger of the
    /// receive size and the buffered bytes plus `region`. The receive size is
    /// `region`, or for a connection whose largest message (`note_consumed`)
    /// is `m`, the larger of `region` and `min(4m, m + 4 * region)`; a
    /// receive several messages long moves a partial message once per
    /// several messages. The connection's own buffer grows by borrowing one
    /// from the pool, into which the buffered bytes are copied. A borrowed
    /// buffer moves the buffered bytes to the front of its allocation when
    /// that makes room, and otherwise takes a buffer of the new size from the
    /// pool and gives the old one back; for a message longer than any before
    /// it on the connection, it grows with `reserve`.
    ///
    /// A remainder held by `put_back` is made mutable first (`reclaim`), so
    /// a remainder the parser kept no slice of is received behind in place,
    /// and a view the parser consumed whole (`keep_spent`) gives its
    /// allocation back when no slice of it is alive.
    #[cfg(has_io_uring)]
    pub(crate) fn detach_for_recv(
        &mut self,
        index: u32,
        region: usize,
        need: Option<usize>,
    ) -> Option<(BytesMut, usize, bool)> {
        // A direct connection sizes its buffer here, from `need` and the
        // pool, so the reserve target `with_bytes` records for a
        // `NeedAtLeast` must not size the copy `reclaim` makes of a shared
        // remainder: that copy would become the connection's own buffer, at
        // the size of the message, outside the pool.
        self.accumulators[index as usize].reserve_target = 0;
        self.reclaim(index);
        let acc = &mut self.accumulators[index as usize];
        debug_assert!(acc.frozen.is_none(), "reclaim leaves no frozen remainder");
        if let Some(spent) = acc.spent.take()
            && acc.buf.is_empty()
        {
            // `buf` is empty, so it is at most the tail of the spent
            // allocation; its reference would keep `try_into_mut` from
            // succeeding.
            acc.buf = BytesMut::new();
            if let Ok(mut recovered) = spent.try_into_mut() {
                recovered.clear();
                acc.buf = recovered;
            }
        }
        let len = acc.buf.len();
        let room = acc.max_size.saturating_sub(len);
        if room == 0 {
            return None;
        }
        if len == 0 {
            if let Some(own) = acc.own.take() {
                self.direct_pool.put(std::mem::replace(&mut acc.buf, own));
            } else if acc.buf.capacity() > region.saturating_mul(2) {
                // An own buffer larger than twice the region goes to the
                // pool, and the connection receives into a new one.
                self.direct_pool.put(std::mem::take(&mut acc.buf));
            }
            if acc.buf.capacity() < region && !acc.buf.try_reclaim(region) {
                // A new buffer of the region: `reserve` would double a
                // buffer a little smaller than the region.
                acc.buf = BytesMut::with_capacity(region);
            }
            let n = acc.buf.capacity().min(room).min(u32::MAX as usize);
            return Some((std::mem::take(&mut acc.buf), n, false));
        }
        let need = need.unwrap_or(0).min(room);
        let known = need >= region;
        let spare = acc.buf.capacity() - len;
        if spare < need || spare < region / 2 {
            let m = acc.largest_message;
            let size = region.max(
                m.saturating_mul(4)
                    .min(m.saturating_add(region.saturating_mul(4))),
            );
            // The capacity to hold: with a known length, the rest of the
            // message; otherwise the receive size, or the buffered bytes and
            // a region more when the message is already longer than it.
            let want = if known {
                len.saturating_add(need)
            } else {
                size.max(len.saturating_add(need.max(region)))
            }
            .min(len.saturating_add(room));
            if acc.own.is_some() && !known && want > size {
                // A message longer than any before it: grow geometrically
                // (`reserve`), in place where the allocator can (`realloc`
                // moves pages rather than bytes for large allocations).
                let before = acc.buf.as_ptr();
                acc.buf.reserve(want - len);
                note_copied(moved(&acc.buf, before, len));
            } else {
                // Move the buffered bytes to the front of this allocation if
                // that makes room, else into a buffer of `want` from the
                // pool. `reserve` would double the allocation instead.
                let before = acc.buf.as_ptr();
                if acc.own.is_some() && acc.buf.try_reclaim(want - len) {
                    note_copied(moved(&acc.buf, before, len));
                } else {
                    let mut bigger = self.direct_pool.take(want);
                    bigger.extend_from_slice(&acc.buf);
                    note_copied(len);
                    let old = std::mem::replace(&mut acc.buf, bigger);
                    if acc.own.is_some() {
                        self.direct_pool.put(old);
                    } else {
                        // The connection's own buffer, kept for the next
                        // message that fits it.
                        let mut own = old;
                        own.clear();
                        acc.own = Some(own);
                    }
                }
            }
        }
        let spare = acc.buf.capacity() - len;
        let n = spare.min(room).min(u32::MAX as usize);
        Some((std::mem::take(&mut acc.buf), n, known))
    }

    /// Keep `consumed`, a frozen view a direct connection's parser consumed
    /// whole, for `detach_for_recv` to take its allocation back.
    #[cfg(has_io_uring)]
    pub(crate) fn keep_spent(&mut self, index: u32, consumed: Bytes) {
        self.accumulators[index as usize].spent = Some(consumed);
    }

    /// Record that a parser consumed a message of `n` bytes in one call.
    #[cfg(has_io_uring)]
    pub(crate) fn note_consumed(&mut self, index: u32, n: usize) {
        let acc = &mut self.accumulators[index as usize];
        acc.largest_message = acc.largest_message.max(n);
    }

    /// Put back a buffer detached by [`detach_for_recv`](Self::detach_for_recv)
    /// with `received` more bytes written behind its contents.
    ///
    /// # Safety
    ///
    /// The kernel must have written `received` initialized bytes into `buf`'s
    /// spare capacity, starting at `buf.len()`.
    #[cfg(has_io_uring)]
    pub(crate) unsafe fn attach_received(
        &mut self,
        index: u32,
        mut buf: BytesMut,
        received: usize,
    ) {
        debug_assert!(received <= buf.capacity() - buf.len());
        // SAFETY: the caller guarantees the bytes are initialized.
        unsafe { buf.set_len(buf.len() + received) };
        let acc = &mut self.accumulators[index as usize];
        if acc.frozen.is_none() && acc.buf.is_empty() {
            acc.buf = buf;
            return;
        }
        // Nothing appends to a direct connection's accumulator while its
        // buffer is detached, so this is not reached. Keep the order anyway:
        // the detached bytes are older.
        debug_assert!(false, "accumulator changed while its buffer was detached");
        let newer = acc.data().to_vec();
        acc.frozen = None;
        acc.buf = buf;
        acc.buf.extend_from_slice(&newer);
        note_copied(newer.len());
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
        // A held frozen remainder belongs BEHIND the prepended data
        // (prepend callers put back OLDER bytes). Merge it into `buf`
        // first so the ordering below is correct.
        acc.unfreeze();
        // NOTE: `buf` may legitimately be non-empty here — either data
        // appended after a `take_frozen`, or a frozen remainder merged by
        // the `unfreeze()` above. The prepended bytes are the OLDEST, so
        // they go in front either way.
        if acc.buf.is_empty() {
            // Fast path (invariant): buffer is empty, tail capacity is
            // retained from `take_frozen`'s `split_to` — no allocation.
            acc.buf.extend_from_slice(data);
            note_copied(data.len());
        } else {
            // Slow path: new data already present (cannot happen in the
            // single-threaded runtime). Prepend by building a new buffer
            // with remainder first.
            let mut new_buf = BytesMut::with_capacity(data.len() + acc.buf.len());
            new_buf.extend_from_slice(data);
            new_buf.extend_from_slice(&acc.buf);
            note_copied(new_buf.len());
            acc.buf = new_buf;
        }
    }
}

#[cfg(test)]
mod tests {

    #[cfg(has_io_uring)]
    #[test]
    fn borrowed_buffer_sizes_round_to_steps_and_huge_pages() {
        assert_eq!(direct_borrow_size(1), 64 * 1024);
        assert_eq!(direct_borrow_size(64 * 1024 + 1), 72 * 1024);
        assert_eq!(direct_borrow_size(1 << 20), 1 << 20);
        assert_eq!(direct_borrow_size((1 << 20) + 1), 1152 * 1024);
        assert_eq!(direct_borrow_size((2 << 20) + 1), 4 << 20);
        assert_eq!(direct_borrow_size(100 << 20), 100 << 20);
        assert_eq!(direct_borrow_size((100 << 20) + 13), 102 << 20);
    }

    #[cfg(has_io_uring)]
    #[test]
    fn the_pool_reuses_a_fitting_buffer_and_keeps_at_most_its_cap() {
        // Room for the 4 MiB buffer and less than another 1 MiB.
        let mut pool = DirectPool::new((4 << 20) + (512 << 10));
        let a = pool.take(3 << 20);
        let a_ptr = a.as_ptr();
        assert_eq!(a.capacity(), 4 << 20);
        pool.put(a);
        // A later message of nearly the same size gets the same buffer.
        let b = pool.take((3 << 20) + 100);
        assert_eq!(b.as_ptr(), a_ptr);
        // One more than twice the size it needs is not taken.
        pool.put(b);
        let small = pool.take(1 << 20);
        assert_ne!(small.as_ptr(), a_ptr);
        assert_eq!(pool.free_bytes, 4 << 20);
        // Past the cap, a smaller buffer given back replaces the largest
        // free one.
        let small_ptr = small.as_ptr();
        pool.put(small);
        assert_eq!(pool.free_bytes, 1 << 20);
        // A larger one does not replace a smaller one: it is freed.
        let mut big = BytesMut::with_capacity(4 << 20);
        big.extend_from_slice(&[1]);
        pool.put(big);
        assert_eq!(pool.free_bytes, 1 << 20);
        assert_eq!(pool.take(1 << 20).as_ptr(), small_ptr);
        // Below the smallest borrowed size, nothing is kept.
        pool.put(BytesMut::with_capacity(4096));
        assert_eq!(pool.free_bytes, 0);
    }

    #[cfg(has_io_uring)]
    #[test]
    fn a_direct_connection_returns_a_borrowed_buffer_when_nothing_is_buffered() {
        let mut table = AccumulatorTable::new(1, 4096);
        let region = 32 * 1024;
        // Part of a 1 MiB message, with the parser asking for the rest.
        let (mut buf, n, _) = table.detach_for_recv(0, region, None).unwrap();
        assert_eq!(n, region);
        buf.extend_from_slice(&[7u8; 1000]);
        unsafe { table.attach_received(0, buf, 0) };
        let (buf, n, known) = table
            .detach_for_recv(0, region, Some((1 << 20) - 1000))
            .unwrap();
        assert!(known);
        assert!(n >= (1 << 20) - 1000);
        let borrowed = buf.as_ptr();
        unsafe { table.attach_received(0, buf, 0) };
        // The parser consumes the message whole and keeps nothing.
        let frozen = table.take_frozen(0);
        table.keep_spent(0, frozen);
        let (buf, n, _) = table.detach_for_recv(0, region, None).unwrap();
        assert_eq!(n, buf.capacity());
        assert!(buf.capacity() < 64 * 1024, "the own buffer is back");
        unsafe { table.attach_received(0, buf, 0) };
        assert_eq!(table.direct_pool.free_bytes, 1 << 20);
        // The next large message borrows the same buffer.
        let (mut buf, _, _) = table.detach_for_recv(0, region, None).unwrap();
        buf.extend_from_slice(&[7u8; 10]);
        unsafe { table.attach_received(0, buf, 0) };
        let (buf, _, _) = table
            .detach_for_recv(0, region, Some((1 << 20) - 10))
            .unwrap();
        assert_eq!(buf.as_ptr(), borrowed);
        unsafe { table.attach_received(0, buf, 0) };
    }

    /// A borrowed buffer that runs out of room with part of a message of no
    /// known length buffered grows to the receive size, not to double its
    /// capacity: here the buffered bytes move to the front of the same
    /// allocation.
    #[cfg(has_io_uring)]
    #[test]
    fn a_borrowed_buffer_grows_to_the_receive_size() {
        let mut table = AccumulatorTable::new(1, 4096);
        let region = 32 * 1024;
        let mib = 1 << 20;
        table.note_consumed(0, mib);
        // The own buffer receives a 4 KiB message and the start of a 1 MiB
        // one; the parser consumes the 4 KiB message.
        let (mut buf, n, _) = table.detach_for_recv(0, region, None).unwrap();
        assert_eq!(n, region);
        buf.resize(region, 1);
        unsafe { table.attach_received(0, buf, 0) };
        let frozen = table.take_frozen(0);
        table.put_back(0, frozen.slice(4096..));
        drop(frozen);
        // The rest of the 1 MiB message goes into a borrowed buffer of the
        // receive size, 1 MiB and four regions.
        let (mut buf, _, known) = table.detach_for_recv(0, region, None).unwrap();
        assert!(!known);
        let borrowed = buf.as_ptr();
        let cap = buf.capacity();
        assert_eq!(cap, mib + 4 * region);
        buf.resize(cap, 2);
        unsafe { table.attach_received(0, buf, 0) };
        // The parser consumes that message and three 4 KiB messages; the
        // start of the next 1 MiB message stays buffered.
        let frozen = table.take_frozen(0);
        let consumed = mib + 3 * 4096;
        table.put_back(0, frozen.slice(consumed..));
        drop(frozen);
        let (buf, n, _) = table.detach_for_recv(0, region, None).unwrap();
        assert_eq!(
            buf.capacity(),
            cap,
            "the buffer did not grow past the receive size"
        );
        assert_eq!(
            buf.as_ptr(),
            borrowed,
            "the bytes moved within the allocation"
        );
        assert_eq!(buf.len(), cap - consumed);
        assert_eq!(n, consumed);
        unsafe { table.attach_received(0, buf, 0) };
    }

    /// A message of known length whose start arrived while the parser held a
    /// value from the same buffer goes into a borrowed buffer, so once it is
    /// consumed the idle connection is back to its own buffer and the large
    /// one is in the pool.
    #[cfg(has_io_uring)]
    #[test]
    fn a_held_value_does_not_leave_a_large_own_buffer() {
        let mut table = AccumulatorTable::new(1, 4096);
        let region = 32 * 1024;
        let mib = 1 << 20;
        // The own buffer receives a 100-byte message and the start of a
        // 1 MiB one.
        let (mut buf, _, _) = table.detach_for_recv(0, region, None).unwrap();
        buf.resize(region, 1);
        unsafe { table.attach_received(0, buf, 0) };
        // The parser keeps the 100-byte value and asks for the rest of the
        // 1 MiB message, as `with_bytes` records a `NeedAtLeast`.
        let frozen = table.take_frozen(0);
        let value = frozen.slice(..100);
        table.put_back(0, frozen.slice(100..));
        drop(frozen);
        let need = mib - (region - 100);
        table.reserve(0, need);
        let (mut buf, _, known) = table.detach_for_recv(0, region, Some(need)).unwrap();
        assert!(known);
        // The message went into a borrowed buffer; the connection's own
        // buffer is the remainder's copy, no larger than the region.
        let own = table.accumulators[0].own.as_ref().map(BytesMut::capacity);
        assert!(
            own.is_some_and(|c| c <= region),
            "own buffer {own:?} while the message is borrowed"
        );
        let len = buf.len();
        buf.resize(len + need, 2);
        unsafe { table.attach_received(0, buf, 0) };
        // The parser consumes the message whole, then drops the value.
        let frozen = table.take_frozen(0);
        table.keep_spent(0, frozen);
        drop(value);
        let (buf, _, _) = table.detach_for_recv(0, region, None).unwrap();
        assert_eq!(buf.capacity(), region, "the idle connection's buffer");
        unsafe { table.attach_received(0, buf, 0) };
        assert!(
            table.direct_pool.free_bytes >= mib,
            "the large buffer is in the pool"
        );
    }

    /// An own buffer larger than twice the region goes to the pool when
    /// nothing is buffered, and the connection receives into a buffer of
    /// the region.
    #[cfg(has_io_uring)]
    #[test]
    fn an_idle_connection_gives_a_large_own_buffer_to_the_pool() {
        let mut table = AccumulatorTable::new(1, 4096);
        let region = 32 * 1024;
        table.accumulators[0].buf = BytesMut::with_capacity(1 << 20);
        let (buf, n, _) = table.detach_for_recv(0, region, None).unwrap();
        assert_eq!(buf.capacity(), region);
        assert_eq!(n, region);
        unsafe { table.attach_received(0, buf, 0) };
        assert_eq!(table.direct_pool.free_bytes, 1 << 20);
    }
    use super::*;

    fn bytes_copied() -> u64 {
        test_bytes_copied()
    }

    /// An append counts its bytes, and a growth that moves the existing
    /// bytes counts those too. A growth the allocator does in place moves
    /// nothing; a second handle on the allocation forces a move.
    #[test]
    fn bytes_copied_counts_appends_and_the_bytes_a_growth_moves() {
        let mut acc = RecvAccumulator::new(8);
        let start = bytes_copied();
        acc.append(b"abcd");
        assert_eq!(bytes_copied() - start, 4);
        let before = acc.buf.as_ptr();
        let start = bytes_copied();
        acc.append(&[0u8; 64]);
        let moved = if acc.buf.as_ptr() == before { 0 } else { 4 };
        assert_eq!(bytes_copied() - start, 64 + moved);

        let mut acc = RecvAccumulator::new(8);
        acc.append(b"abcd");
        let tail = acc.buf.split_off(acc.buf.len());
        let before = acc.buf.as_ptr();
        let start = bytes_copied();
        acc.append(&[0u8; 64]);
        assert_ne!(
            acc.buf.as_ptr(),
            before,
            "a shared allocation is not grown in place"
        );
        assert_eq!(bytes_copied() - start, 64 + 4, "the growth moved 4 bytes");
        drop(tail);

        // With the other half dropped the allocation is uniquely owned and
        // has room, so the growth reuses it in place and moves nothing.
        let mut acc = RecvAccumulator::new(8);
        acc.append(b"abcd");
        drop(acc.buf.split_off(acc.buf.len()));
        let before = acc.buf.as_ptr();
        let start = bytes_copied();
        acc.append(b"efgh");
        assert_eq!(
            acc.buf.as_ptr(),
            before,
            "a unique shared buffer grows in place"
        );
        assert_eq!(bytes_copied() - start, 4);
    }

    /// Reclaiming a remainder nothing else references copies nothing;
    /// reclaiming one a parser kept a slice of copies it once, into a buffer
    /// of the reserve target's size.
    #[test]
    fn reclaim_copies_a_remainder_only_while_a_slice_of_it_is_alive() {
        let mut table = AccumulatorTable::new(1, 64);
        table.append(0, b"0123456789");
        let frozen = table.take_frozen(0);
        table.put_back(0, frozen);
        let start = bytes_copied();
        table.reclaim(0);
        assert_eq!(bytes_copied(), start);
        assert_eq!(table.data(0), b"0123456789");

        let frozen = table.take_frozen(0);
        let kept = frozen.slice(0..2);
        table.put_back(0, frozen);
        table.reserve(0, 1000);
        let start = bytes_copied();
        table.reclaim(0);
        assert_eq!(bytes_copied() - start, 10);
        assert!(table.capacity(0) >= 1010);
        assert_eq!(table.data(0), b"0123456789");
        assert_eq!(&kept[..], b"01");
    }

    #[test]
    fn reserve_sizes_append_growth_once() {
        let mut acc = RecvAccumulator::new(64);
        acc.append(b"header");
        // Announce a 1MB remainder: the next growth allocates it all.
        acc.reserve(1024 * 1024);
        acc.append(&[0u8; 128]); // forces growth past the initial 64
        let cap_after_first_growth = acc.capacity();
        assert!(
            cap_after_first_growth >= 6 + 1024 * 1024,
            "growth ignored reserve target: cap {cap_after_first_growth}"
        );
        // Streaming the remainder never reallocates again.
        for _ in 0..15 {
            acc.append(&[0u8; 64 * 1024]);
        }
        assert_eq!(acc.capacity(), cap_after_first_growth);
    }

    #[test]
    fn reserve_survives_freeze_merge_cycle() {
        // The with_bytes cycle: take_frozen → NeedAtLeast → put_back →
        // kernel appends → next take_frozen merges. The merge must land in
        // a full-size buffer, not regrow per chunk.
        let mut table = AccumulatorTable::new(1, 64);
        table.append(0, b"$16\r\npartial");
        let frozen = table.take_frozen(0);
        table.put_back(0, frozen);
        table.reserve(0, 1024 * 1024);
        table.append(0, &[0u8; 1024]); // new data while remainder held
        let _ = table.data(0); // forces the merge
        let cap = table.capacity(0);
        assert!(
            cap >= 1024 * 1024,
            "merge ignored reserve target: cap {cap}"
        );
    }

    #[test]
    fn reserve_clamps_to_max_size() {
        let mut acc = RecvAccumulator::new_with_max(16, 1024);
        acc.append(b"x");
        acc.reserve(usize::MAX);
        acc.append(&[0u8; 64]);
        assert!(
            acc.capacity() <= 4096,
            "reserve target must clamp at max_size, cap {}",
            acc.capacity()
        );
    }

    #[test]
    fn release_returns_to_the_initial_capacity() {
        let mut acc = RecvAccumulator::new(4096);
        acc.append(&vec![0u8; 1024 * 1024]);
        acc.reset();
        assert!(acc.capacity() >= 1024 * 1024, "reset keeps the allocation");
        acc.release();
        assert!(acc.is_empty());
        assert_eq!(acc.capacity(), 4096);
    }

    #[test]
    fn release_leaves_a_kept_slice_intact() {
        let mut table = AccumulatorTable::new(1, 64);
        table.append(0, b"value");
        let kept = table.take_frozen(0);
        table.release(0);
        assert_eq!(&kept[..], b"value");
        assert!(table.is_empty(0));
    }

    #[test]
    fn reserve_target_clears_when_drained() {
        let mut acc = RecvAccumulator::new(16);
        acc.append(b"abc");
        acc.reserve(1024 * 1024);
        acc.consume(3);
        assert_eq!(acc.reserve_target, 0, "drain must clear the target");
        // Post-drain appends grow normally, not to the stale megabyte.
        acc.append(&[0u8; 64]);
        assert!(acc.capacity() < 1024 * 1024);
    }

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
            assert!(
                table.capacity(0) > 0,
                "cycle: take_frozen must retain capacity"
            );
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

    /// Streaming NeedMore cycles (take → put_back whole → new data arrives →
    /// merge) must recover the remainder's allocation in place and append
    /// only the new bytes — NOT re-copy the whole remainder each cycle.
    /// This is the O(N·K) large-response path: the accumulator's empty `buf`
    /// keeping a `split_to` handle to the remainder's allocation used to
    /// defeat `try_into_mut` on every merge.
    #[test]
    fn streaming_merge_recovers_allocation_in_place() {
        let mut table = AccumulatorTable::new(1, 1024);
        assert!(table.append(0, b"0123456789"));
        let frozen = table.take_frozen(0);
        let alloc_ptr = frozen.as_ptr();
        // Parser saw an incomplete message: put the whole view back.
        table.put_back(0, frozen);
        // Next chunk arrives; the merge must take the in-place path.
        assert!(table.append(0, b"ABCDEF"));
        let merged = table.take_frozen(0);
        assert_eq!(&merged[..], b"0123456789ABCDEF");
        assert_eq!(
            merged.as_ptr(),
            alloc_ptr,
            "merge must recover the original allocation (try_into_mut), not copy"
        );
        // And again — every cycle of the stream, not just the first.
        table.put_back(0, merged);
        assert!(table.append(0, b"GHIJ"));
        let merged2 = table.take_frozen(0);
        assert_eq!(&merged2[..], b"0123456789ABCDEFGHIJ");
        assert_eq!(
            merged2.as_ptr(),
            alloc_ptr,
            "second cycle must also be in place"
        );
    }

    #[test]
    fn is_empty_is_non_merging() {
        let mut table = AccumulatorTable::new(1, 64);
        assert!(table.is_empty(0));
        assert!(table.append(0, b"abcd"));
        assert!(!table.is_empty(0));
        let frozen = table.take_frozen(0);
        assert!(table.is_empty(0));
        table.put_back(0, frozen);
        assert!(!table.is_empty(0));
        // New data while a remainder is held: emptiness must be answerable
        // without merging (can't observe the non-merge directly here, but
        // the streaming test above fails if a merge sneaks in and copies).
        assert!(table.append(0, b"ef"));
        assert!(!table.is_empty(0));
        assert_eq!(table.data(0), b"abcdef");
    }

    #[test]
    fn put_back_then_take_is_same_bytes_no_copy() {
        let mut table = AccumulatorTable::new(1, 64);
        assert!(table.append(0, b"aaaabbbbcccc"));
        let frozen = table.take_frozen(0);
        // Consume one "response", put the rest back.
        let rem = frozen.slice(4..);
        let rem_ptr = rem.as_ptr();
        table.put_back(0, rem);
        // Re-take must hand back the same allocation (O(1), no copy).
        let again = table.take_frozen(0);
        assert_eq!(&again[..], b"bbbbcccc");
        assert_eq!(again.as_ptr(), rem_ptr, "re-take must not copy");
    }

    #[test]
    fn append_while_frozen_held_merges_in_order() {
        let mut table = AccumulatorTable::new(1, 64);
        assert!(table.append(0, b"old-"));
        let frozen = table.take_frozen(0);
        table.put_back(0, frozen);
        // New data arrives while the remainder is held.
        assert!(table.append(0, b"new"));
        assert_eq!(table.data(0), b"old-new");
        let merged = table.take_frozen(0);
        assert_eq!(&merged[..], b"old-new");
    }

    #[test]
    fn cap_accounts_for_frozen_remainder() {
        let mut table = AccumulatorTable::new_with_max(1, 8, 8);
        assert!(table.append(0, b"abcdef"));
        let frozen = table.take_frozen(0);
        table.put_back(0, frozen);
        // 6 held + 3 new = 9 > 8: must be rejected.
        assert!(!table.append(0, b"xyz"));
        // 6 + 2 = 8: fits.
        assert!(table.append(0, b"gh"));
        assert_eq!(table.data(0), b"abcdefgh");
    }

    #[test]
    fn consume_from_frozen_remainder() {
        let mut table = AccumulatorTable::new(1, 64);
        assert!(table.append(0, b"0123456789"));
        let frozen = table.take_frozen(0);
        table.put_back(0, frozen);
        // Borrowed-slice consumer path (with_data) over a held remainder.
        assert_eq!(table.data(0), b"0123456789");
        table.consume(0, 4);
        assert_eq!(table.data(0), b"456789");
        table.consume(0, 6);
        assert_eq!(table.data(0), b"");
        // Accumulator is fully reusable afterwards.
        assert!(table.append(0, b"next"));
        assert_eq!(table.data(0), b"next");
    }

    #[test]
    fn prepend_orders_ahead_of_frozen_remainder() {
        let mut table = AccumulatorTable::new(1, 64);
        assert!(table.append(0, b"MID"));
        let frozen = table.take_frozen(0);
        table.put_back(0, frozen);
        assert!(table.append(0, b"TAIL"));
        // Oldest bytes prepended in front of remainder + new data.
        table.prepend(0, b"HEAD");
        assert_eq!(table.data(0), b"HEADMIDTAIL");
    }

    #[test]
    fn reset_clears_frozen_remainder() {
        let mut table = AccumulatorTable::new(1, 64);
        assert!(table.append(0, b"data"));
        let frozen = table.take_frozen(0);
        table.put_back(0, frozen);
        table.reset(0);
        assert_eq!(table.data(0), b"");
        assert!(table.append(0, b"fresh"));
        assert_eq!(table.data(0), b"fresh");
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

    /// Pipelined RESP commands, four GETs then one SET of `vlen` value
    /// bytes, repeated `sets` times. Returns the stream and each command's
    /// length.
    fn resp_stream(vlen: usize, sets: usize) -> (Vec<u8>, Vec<usize>) {
        let get = b"*2\r\n$3\r\nGET\r\n$16\r\nkkkkkkkkkkkkkkkk\r\n";
        let set = format!("*3\r\n$3\r\nSET\r\n$16\r\nkkkkkkkkkkkkkkkk\r\n${vlen}\r\n");
        let mut stream = Vec::new();
        let mut lens = Vec::new();
        for _ in 0..sets {
            for _ in 0..4 {
                stream.extend_from_slice(get);
                lens.push(get.len());
            }
            stream.extend_from_slice(set.as_bytes());
            stream.resize(stream.len() + vlen, b'v');
            stream.extend_from_slice(b"\r\n");
            lens.push(set.len() + vlen + 2);
        }
        (stream, lens)
    }

    /// Bytes moved per SET value byte when the stream arrives in
    /// `chunk`-byte appends and a parser consumes each whole command and
    /// stops at an incomplete one or at an empty buffer, as `with_data`
    /// does, calling `compact_at_message_start` there when `compact` is set.
    /// With `hint`, it reserves the rest of a SET once its header has
    /// arrived, as `with_data` does for `NeedAtLeast`.
    fn moved_per_value_byte_with(vlen: usize, compact: bool, chunk: usize, hint: bool) -> f64 {
        // About 32 MiB of SET values, at least 50 and at most 2000 SETs, so
        // the result is the steady state and not the first growths from
        // 4096 bytes.
        let sets = ((32 << 20) / vlen).clamp(50, 2000);
        let (stream, lens) = resp_stream(vlen, sets);
        let mut acc = RecvAccumulator::new_with_max(4096, usize::MAX);
        let start = test_bytes_copied();
        let mut next = 0;
        for data in stream.chunks(chunk) {
            assert!(acc.append(data));
            while next < lens.len() && acc.len() >= lens[next] {
                acc.consume(lens[next]);
                next += 1;
            }
            if hint && next < lens.len() && lens[next] > 64 && acc.len() >= 64 {
                acc.reserve(lens[next] - acc.len());
            }
            if compact {
                acc.compact_at_message_start();
            }
        }
        assert_eq!(next, lens.len());
        let moved = test_bytes_copied() - start - stream.len() as u64;
        moved as f64 / (sets * vlen) as f64
    }

    /// A SET larger than an append arrives over several appends. Without the
    /// move at its start, the buffer runs out near the end of most SETs and
    /// `append` moves nearly the whole command.
    #[test]
    fn compact_at_message_start_moves_few_bytes() {
        // (value bytes, append size, NeedAtLeast hint, least moved without
        // the call, most moved with it), per value byte. Measured in steady
        // state: 0.87 -> 0.13, 0.86 -> 0.13, 0.75 -> 0.25, 0.98 -> 0.04 and
        // about 1.0 -> 0.01.
        for (vlen, chunk, hint, least, most) in [
            (65536, 16384, false, 0.7, 0.2),
            (65536, 16384, true, 0.7, 0.2),
            (65536, 32768, false, 0.6, 0.35),
            (256 * 1024, 16384, false, 0.8, 0.08),
            (1 << 20, 16384, false, 0.8, 0.03),
        ] {
            let without = moved_per_value_byte_with(vlen, false, chunk, hint);
            assert!(
                without >= least,
                "{vlen}-byte SETs in {chunk}-byte appends move {without:.3} per value byte \
                 without the call, below {least}; the harness no longer shows the move"
            );
            let with = moved_per_value_byte_with(vlen, true, chunk, hint);
            assert!(
                with <= most,
                "{vlen}-byte SETs in {chunk}-byte appends (hint {hint}): {with:.3} bytes \
                 moved per value byte, above {most}"
            );
        }
    }

    #[test]
    fn compact_at_message_start_keeps_the_contents() {
        let mut acc = RecvAccumulator::new_with_max(4096, usize::MAX);
        let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        assert!(acc.append(&data));
        let grown = acc.capacity();
        acc.consume(2990);
        acc.compact_at_message_start();
        assert_eq!(acc.data(), &data[2990..]);
        assert_eq!(
            acc.capacity(),
            grown,
            "the grown capacity is available again"
        );
    }

    #[test]
    fn compact_at_message_start_resets_an_empty_buffer() {
        // Nothing buffered, and more than half the grown capacity, but not
        // all of it, ahead of the start.
        let mut acc = RecvAccumulator::new_with_max(4096, usize::MAX);
        assert!(acc.append(&[1u8; 1000]));
        let grown = acc.capacity();
        acc.consume(1000);
        assert!(acc.capacity() > grown / 2 && acc.capacity() < grown);
        acc.compact_at_message_start();
        assert_eq!(acc.capacity(), grown);
    }

    #[test]
    fn compact_at_message_start_leaves_a_full_or_roomy_buffer() {
        // More than half the remaining room is live.
        let mut acc = RecvAccumulator::new_with_max(64, usize::MAX);
        assert!(acc.append(&[1u8; 4096]));
        acc.consume(4096 - acc.capacity() / 4 - 1);
        let ptr = acc.buf.as_ptr();
        acc.compact_at_message_start();
        assert_eq!(acc.buf.as_ptr(), ptr);
        // More than half the grown capacity remains ahead of a few live
        // bytes.
        let mut acc = RecvAccumulator::new_with_max(4096, usize::MAX);
        assert!(acc.append(&[1u8; 1024]));
        acc.consume(1000);
        let ptr = acc.buf.as_ptr();
        acc.compact_at_message_start();
        assert_eq!(acc.buf.as_ptr(), ptr);
    }
}
