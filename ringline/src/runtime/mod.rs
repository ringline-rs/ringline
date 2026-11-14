//! Async runtime for ringline: task executor, waker, and I/O primitives.
//!
//! # Portability boundary
//!
//! This module is designed so that the core async machinery is portable
//! across I/O backends (io_uring, mio/epoll, kqueue):
//!
//! - **Portable** (no io_uring dependency):
//!   - `task` — `TaskSlab`, `TaskSlot` (slab of per-connection futures)
//!   - `waker` — `conn_waker()`, thread-local `READY_QUEUE`, cross-thread wake inboxes
//!   - `mod.rs` — `Executor`, `IoResult` (waiter flags, ready queue, result storage)
//!   - `handler` — `AsyncEventHandler` trait
//!
//! - **Backend-specific** (tied to the concrete `Driver` type):
//!   - `io` — `Connection`, futures (`WithDataFuture`, `SendCompletion`, `ConnectFuture`)
//!     accesses `Driver` via thread-local pointer
//!
//! A mio backend would provide an alternative `driver.rs`, `async_event_loop.rs`,
//! and `runtime/io.rs` while reusing everything else unchanged.

pub(crate) mod cancellation;
pub mod channel;
pub(crate) mod handler;
pub(crate) mod io;
pub(crate) mod join;
pub(crate) mod select;
pub(crate) mod send_completion;
pub(crate) mod stream;
pub(crate) mod task;
pub(crate) mod waker;

use std::cell::Cell;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io as stdio;

use self::task::{StandaloneTaskSlab, TaskSlab, Wake};
use self::waker::drain_ready_queue;

/// I/O result stored per-connection for async task wakeup.
pub(crate) enum IoResult {
    /// Connect completed with success or error.
    Connect(stdio::Result<()>),
}

/// A queued UDP datagram waiting for an async consumer.
///
/// On the io_uring backend the buffer is borrowed from the kernel-provided buffer
/// ring (`Kernel` variant) and the consumer must push the `bid` to the driver's
/// `udp_pending_replenish` after reading the data so the buffer goes back to the
/// kernel. On the mio backend the buffer is owned (`Owned` variant) and the
/// `Vec<u8>` is dropped normally.
pub(crate) struct PendingUdpDatagram {
    pub(crate) peer: std::net::SocketAddr,
    pub(crate) buf: PendingUdpBuf,
    /// Wall-clock instant the driver first observed this datagram in
    /// the CQE drain (io_uring) or `recv_from` poll (mio). Used by
    /// `recv_batch_timed` callers (typically protocol drivers like
    /// `quinn-proto`) so RTT measurements don't include the executor
    /// wake + task poll latency that elapses between arrival and the
    /// callback firing.
    pub(crate) recv_at: std::time::Instant,
    /// UDP GRO segment size. When non-zero, `buf` holds several datagrams
    /// coalesced by the kernel and the drain path splits it into chunks of
    /// this size (the last chunk may be shorter), invoking the recv callback
    /// once per chunk. Zero means a single, un-coalesced datagram.
    pub(crate) segment_size: u32,
    /// Bytes already handed out by segment-wise consumers
    /// (`recv_from`/`with_datagram` on a GRO-coalesced entry). Zero for
    /// whole-entry consumers (`recv_batch`, non-GRO paths).
    pub(crate) consumed: u32,
}

pub(crate) enum PendingUdpBuf {
    /// User-owned buffer (mio backend or any path that needed to copy).
    /// Only constructed by the mio backend; on io_uring this variant is dead
    /// code (the kernel-buffer path is always used).
    #[cfg_attr(has_io_uring, allow(dead_code))]
    Owned(Vec<u8>),
    /// Reference into a kernel-provided buffer (io_uring backend, zero-copy).
    ///
    /// The pointer is into `ProvidedBufRing::mem` (a `RingMemory`), which is
    /// allocated once and not resized, so it remains valid until `bid` is replenished.
    /// `payload_len` is the datagram payload length (excludes recvmsg header).
    #[cfg(has_io_uring)]
    Kernel {
        bid: u16,
        ptr: *const u8,
        payload_len: u32,
    },
}

impl PendingUdpDatagram {
    /// Borrow the payload bytes. Valid until the buffer is released.
    // On mio-only builds the enum has a single variant, so these matches are
    // infallible. clippy complains; cfg-gating the lint avoids contorting
    // the code with `if let` chains that only exist to please mio builds.
    #[cfg_attr(not(has_io_uring), allow(clippy::infallible_destructuring_match))]
    pub(crate) fn data(&self) -> &[u8] {
        match &self.buf {
            PendingUdpBuf::Owned(v) => v.as_slice(),
            #[cfg(has_io_uring)]
            PendingUdpBuf::Kernel {
                ptr, payload_len, ..
            } => unsafe { std::slice::from_raw_parts(*ptr, *payload_len as usize) },
        }
    }

    /// Invoke `f` once per contained datagram: once for an un-coalesced
    /// entry, or once per `segment_size` chunk (last chunk possibly shorter)
    /// for a GRO-coalesced entry. Centralises the split so both drain loops
    /// share it and neither risks a `chunks(0)` panic.
    pub(crate) fn for_each_segment<F: FnMut(&[u8])>(&self, mut f: F) {
        let data = self.data();
        if self.segment_size == 0 {
            f(data);
        } else {
            for chunk in data.chunks(self.segment_size as usize) {
                f(chunk);
            }
        }
    }

    /// Byte range of the next un-consumed datagram: the whole payload for
    /// an un-coalesced entry, one `segment_size` chunk for a GRO entry.
    pub(crate) fn next_segment_range(&self) -> (usize, usize) {
        let len = self.data().len();
        if self.segment_size == 0 {
            (0, len)
        } else {
            let start = (self.consumed as usize).min(len);
            let end = (start + self.segment_size as usize).min(len);
            (start, end)
        }
    }

    /// Whether all contained datagrams have been handed out.
    pub(crate) fn exhausted(&self) -> bool {
        self.segment_size == 0 || self.consumed as usize >= self.data().len()
    }

    /// If this entry holds a kernel-provided buffer, return the bid so the
    /// caller can push it to `udp_pending_replenish`. Returns `None` for
    /// owned-buffer entries (mio).
    #[cfg_attr(not(has_io_uring), allow(clippy::match_single_binding))]
    pub(crate) fn bid_to_release(&self) -> Option<u16> {
        match &self.buf {
            PendingUdpBuf::Owned(_) => None,
            #[cfg(has_io_uring)]
            PendingUdpBuf::Kernel { bid, .. } => Some(*bid),
        }
    }

    /// Consume the entry as an owned `(Vec<u8>, SocketAddr)` pair. Allocates a
    /// fresh `Vec` for the kernel-buffer variant; the caller must still push
    /// `bid_to_release()` to `udp_pending_replenish` to free the kernel
    /// buffer.
    #[cfg_attr(not(has_io_uring), allow(clippy::infallible_destructuring_match))]
    pub(crate) fn into_owned(self) -> (Vec<u8>, std::net::SocketAddr) {
        let peer = self.peer;
        let v = match self.buf {
            PendingUdpBuf::Owned(v) => v,
            #[cfg(has_io_uring)]
            PendingUdpBuf::Kernel {
                ptr, payload_len, ..
            } => unsafe { std::slice::from_raw_parts(ptr, payload_len as usize).to_vec() },
        };
        (v, peer)
    }
}

thread_local! {
    /// The current task ID being polled. Set by the executor before each poll.
    /// Connection tasks: conn_index (bits 0..23).
    /// Standalone tasks: task_idx | STANDALONE_BIT.
    /// Used by SleepFuture to know which task to wake on timer completion.
    pub(crate) static CURRENT_TASK_ID: Cell<u32> = const { Cell::new(0) };
}

/// Timer slots per worker: the most [`sleep()`](crate::sleep),
/// [`timeout()`](crate::timeout) and related timers one worker can have
/// pending at once. The pool takes about 1.7 MiB per worker, and its deadline
/// heap up to about 3 MiB more while that many timers are pending.
pub const TIMER_SLOTS: u32 = 1 << 16;

/// The deadline heap is compacted when it reaches this many entries, or
/// twice the entries left by the previous compaction if that is more.
const TIMER_HEAP_COMPACT_MIN: usize = 1024;

/// Pool of timer slots and the deadline heap the event loop waits on.
///
/// Each `sleep()` call allocates a slot and records its deadline. Generation
/// counters keep a heap entry left by a released slot from firing a later
/// occupant.
pub(crate) struct TimerSlotPool {
    /// Each slot's deadline, or `None` for a free slot or a timer that never
    /// fires.
    pub(crate) deadlines: Vec<Option<std::time::Instant>>,
    /// Min-heap of (deadline, slot, generation). The event loop reads its
    /// earliest live entry to bound its wait, and pops expired entries to
    /// fire them. Entries are invalidated lazily: a popped or peeked entry
    /// counts only if the slot's generation and exact deadline still match
    /// (`heap_entry_live`).
    expiry_heap: std::collections::BinaryHeap<std::cmp::Reverse<(std::time::Instant, u32, u16)>>,
    /// The heap length at which `set_deadline` drops the dead entries.
    compact_at: usize,
    /// Which task (with STANDALONE_BIT encoding) to wake when this timer fires.
    pub(crate) waker_ids: Vec<u32>,
    /// Whether this timer's deadline has passed and the event loop fired it.
    pub(crate) fired: Vec<bool>,
    /// Generation counter per slot, incremented on release.
    pub(crate) generations: Vec<u16>,
    /// Free slot indices for O(1) allocation.
    free_list: Vec<u32>,
}

impl TimerSlotPool {
    /// Create a new pool with the given capacity.
    pub(crate) fn new(capacity: u32) -> Self {
        let cap = capacity as usize;
        let mut free_list = Vec::with_capacity(cap);
        for i in 0..capacity {
            free_list.push(i);
        }
        TimerSlotPool {
            deadlines: vec![None; cap],
            expiry_heap: std::collections::BinaryHeap::new(),
            compact_at: TIMER_HEAP_COMPACT_MIN,
            waker_ids: vec![0; cap],
            fired: vec![false; cap],
            generations: vec![0; cap],
            free_list,
        }
    }

    /// Allocate a timer slot. Returns `(slot_index, generation)` or None if full.
    pub(crate) fn allocate(&mut self, waker_id: u32) -> Option<(u32, u16)> {
        let slot = self.free_list.pop()?;
        let idx = slot as usize;
        self.waker_ids[idx] = waker_id;
        self.fired[idx] = false;
        let generation = self.generations[idx];
        Some((slot, generation))
    }

    /// Release a timer slot back to the free list. Its heap entry, if any,
    /// is dead from here on: the generation no longer matches.
    pub(crate) fn release(&mut self, slot: u32) {
        let idx = slot as usize;
        if idx < self.generations.len() {
            self.generations[idx] = self.generations[idx].wrapping_add(1);
            self.deadlines[idx] = None;
            self.free_list.push(slot);
        }
    }

    /// Mark a timer as fired. Returns the waker_id if generation matches.
    pub(crate) fn fire(&mut self, slot: u32, generation: u16) -> Option<u32> {
        let idx = slot as usize;
        if idx >= self.generations.len() || self.generations[idx] != generation {
            return None; // the slot was released since
        }
        self.fired[idx] = true;
        Some(self.waker_ids[idx])
    }

    /// Total number of slots in the pool.
    pub(crate) fn capacity(&self) -> usize {
        self.generations.len()
    }

    /// Number of slots not held.
    #[cfg(test)]
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) fn free_slots(&self) -> usize {
        self.free_list.len()
    }

    /// Number of heap entries, live and dead.
    #[cfg(test)]
    pub(crate) fn heap_len(&self) -> usize {
        self.expiry_heap.len()
    }

    /// Check if a timer slot has fired.
    pub(crate) fn is_fired(&self, slot: u32) -> bool {
        self.fired.get(slot as usize).copied().unwrap_or(false)
    }

    /// Store a deadline `duration` from now. A deadline past what `Instant`
    /// can hold is never reached: the slot gets no deadline and never fires.
    pub(crate) fn set_relative(&mut self, slot: u32, duration: std::time::Duration) {
        let deadline = std::time::Instant::now().checked_add(duration);
        self.set_deadline(slot, deadline);
    }

    /// Store `deadline`, or none for a timer that never fires.
    fn set_deadline(&mut self, slot: u32, deadline: Option<std::time::Instant>) {
        let idx = slot as usize;
        self.deadlines[idx] = deadline;
        if let Some(deadline) = deadline {
            if self.expiry_heap.len() >= self.compact_at {
                self.compact();
            }
            self.expiry_heap
                .push(std::cmp::Reverse((deadline, slot, self.generations[idx])));
        }
    }

    /// Drop every dead heap entry. A timer released before its deadline,
    /// such as the timer of a `timeout()` whose future completed first,
    /// leaves its entry behind until the entry reaches the top of the heap,
    /// so without this the heap would grow with every such timer until its
    /// deadline passes. Compacting at twice the entries the last compaction
    /// kept makes the cost O(1) per push, amortized.
    fn compact(&mut self) {
        let mut heap = std::mem::take(&mut self.expiry_heap).into_vec();
        heap.retain(|&std::cmp::Reverse((deadline, slot, generation))| {
            self.heap_entry_live(deadline, slot, generation)
        });
        self.compact_at = (2 * heap.len()).max(TIMER_HEAP_COMPACT_MIN);
        self.expiry_heap = heap.into();
    }

    /// Store an absolute deadline, given as `CLOCK_MONOTONIC` seconds and
    /// nanoseconds ([`Deadline`](crate::Deadline)).
    pub(crate) fn set_absolute(&mut self, slot: u32, secs: u64, nsecs: u32) {
        // Approximate: compute offset from current monotonic clock to the deadline.
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        }
        let now_ns = ts.tv_sec as u128 * 1_000_000_000 + ts.tv_nsec as u128;
        let deadline_ns = secs as u128 * 1_000_000_000 + nsecs as u128;
        // A deadline past what `Instant` can hold is never reached.
        let deadline = if deadline_ns > now_ns {
            u64::try_from(deadline_ns - now_ns).ok().and_then(|ns| {
                std::time::Instant::now().checked_add(std::time::Duration::from_nanos(ns))
            })
        } else {
            Some(std::time::Instant::now())
        };
        self.set_deadline(slot, deadline);
    }

    /// A heap entry is live iff the slot still holds this exact deadline in
    /// the same generation and hasn't fired. Anything else is a stale entry
    /// left behind by release/re-arm and is skipped (lazy deletion).
    fn heap_entry_live(&self, deadline: std::time::Instant, slot: u32, generation: u16) -> bool {
        let idx = slot as usize;
        idx < self.generations.len()
            && self.generations[idx] == generation
            && !self.fired[idx]
            && self.deadlines[idx] == Some(deadline)
    }

    /// Earliest live deadline, discarding stale heap heads.
    pub(crate) fn next_deadline(&mut self) -> Option<std::time::Instant> {
        while let Some(&std::cmp::Reverse((deadline, slot, generation))) = self.expiry_heap.peek() {
            if self.heap_entry_live(deadline, slot, generation) {
                return Some(deadline);
            }
            self.expiry_heap.pop();
        }
        None
    }

    /// Pop the next timer whose deadline is <= `now`. Returns
    /// `(slot, generation)` ready to pass to [`fire`](Self::fire).
    pub(crate) fn pop_expired(&mut self, now: std::time::Instant) -> Option<(u32, u16)> {
        while let Some(&std::cmp::Reverse((deadline, slot, generation))) = self.expiry_heap.peek() {
            if !self.heap_entry_live(deadline, slot, generation) {
                self.expiry_heap.pop();
                continue;
            }
            if deadline > now {
                return None;
            }
            self.expiry_heap.pop();
            return Some((slot, generation));
        }
        None
    }

    /// Whether the heap holds no entry, live or dead.
    pub(crate) fn heap_is_empty(&self) -> bool {
        self.expiry_heap.is_empty()
    }
}

/// Hasher for the 32-bit disk-I/O keys: one multiply and a fold, where the
/// default hasher runs SipHash over the four bytes. The low bits of a product
/// depend only on the low bits of the key, which on io_uring are the slab
/// index, and hashbrown takes the bucket from the low bits of the hash; so
/// `finish` folds the high half of the product, which depends on every key
/// bit, into the low half. Without the fold every key of one slab slot would
/// start its probe at the same bucket.
#[derive(Default, Clone, Copy)]
pub(crate) struct KeyHasher(u64);

impl std::hash::Hasher for KeyHasher {
    fn finish(&self) -> u64 {
        self.0 ^ (self.0 >> 32)
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }

    fn write_u32(&mut self, i: u32) {
        self.0 = u64::from(i).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

/// A map keyed by disk-I/O keys.
pub(crate) type KeyMap<V> = HashMap<u32, V, std::hash::BuildHasherDefault<KeyHasher>>;
/// A set of disk-I/O keys.
pub(crate) type KeySet = std::collections::HashSet<u32, std::hash::BuildHasherDefault<KeyHasher>>;

/// What the executor holds for one disk-I/O key, from the future's creation
/// until the future takes its result or is dropped, or until the completion
/// releases what a dropped future left behind.
pub(crate) enum DiskIoEntry {
    /// A future holds the key: the task to wake when the operation
    /// completes, and the result and stat metadata once it has.
    Held {
        waiter: Option<u32>,
        result: Option<i32>,
        metadata: Option<crate::fs::Metadata>,
    },
    /// The future was dropped with its read or write in flight; the buffer
    /// stays here until the completion frees it, so the kernel's pointer
    /// stays valid. Buffers still here when the executor drops are leaked;
    /// see `impl Drop for Executor`.
    Parked(Box<dyn std::any::Any>),
    /// The `OpenFuture` was dropped with its open in flight; the completion
    /// closes the file and releases its slot instead of delivering a result.
    AbandonedOpen,
}

thread_local! {
    // Disk-I/O keys a future holds on this worker: added when the future is
    // created, removed when it takes its result or is dropped. The executor
    // stores a result only for a held key, and the key allocators, which
    // have the driver but not the executor, do not hand out a held key, so
    // a result is never taken by an operation it does not belong to (#574).
    static DISK_IO_LIVE: std::cell::RefCell<KeySet> =
        std::cell::RefCell::new(KeySet::default());
}

/// Something a future owned by a connection's task must release when the
/// task is dropped at connection teardown, outside any task poll, where the
/// driver is not reachable (#575).
pub(crate) enum Orphan {
    /// A `SleepFuture`'s timer slot.
    TimerSlot(u32),
    /// A `SpawnFuture`'s `pending_spawns` entry, and with it a delivered
    /// child's pidfd.
    Spawn(u64),
    /// A `WaitFuture`'s `pidfd_waiters` and `pidfd_results` entries, and its
    /// pidfd poll if it is still armed.
    Wait(u32),
    /// A `ConnectFuture`'s outbound connection.
    Connect { conn_index: u32, generation: u32 },
    /// A half of a connection, dropped outside a task poll.
    ConnHalf {
        conn_index: u32,
        generation: u32,
        half: io::Half,
        abrupt: bool,
    },
    /// A `BlockingJoinHandle`'s `pending_blocking` entry, and with it a
    /// delivered result.
    Blocking(u64),
    /// A `ResolveFuture`'s `pending_resolves` entry.
    Resolve(u64),
}

thread_local! {
    // Released by `release_orphans`, which the event loop calls at the start
    // of every task-poll pass, after the first pass, and before it waits for
    // I/O.
    static ORPHANS: std::cell::RefCell<Vec<Orphan>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Queue `orphan` for `release_orphans`, which the event loop calls at the
/// start of every task-poll pass, after the first pass, and before the
/// worker waits for I/O. Entries queued after the worker's last loop
/// iteration are never released; the worker's pools go with it.
pub(crate) fn defer_release(orphan: Orphan) {
    let _ = ORPHANS.try_with(|orphans| orphans.borrow_mut().push(orphan));
}

/// Release what futures dropped outside the executor queued with
/// [`defer_release`].
pub(crate) fn release_orphans(driver: &mut crate::backend::Driver, executor: &mut Executor) {
    let orphans = ORPHANS.with(|orphans| std::mem::take(&mut *orphans.borrow_mut()));
    for orphan in orphans {
        match orphan {
            Orphan::TimerSlot(slot) => executor.timer_pool.release(slot),
            Orphan::Spawn(request_id) => {
                executor.pending_spawns.remove(&request_id);
            }
            Orphan::Wait(seq) => {
                crate::process::release_wait(driver, executor, seq);
            }
            Orphan::Connect {
                conn_index,
                generation,
            } => {
                io::release_connect(driver, executor, conn_index, generation);
            }
            Orphan::ConnHalf {
                conn_index,
                generation,
                half,
                abrupt,
            } => {
                io::release_half(driver, conn_index, generation, half, abrupt);
            }
            Orphan::Blocking(request_id) => {
                let dropped = executor.pending_blocking.remove(&request_id);
                executor.task_slab.drop_noting_panic(dropped);
            }
            Orphan::Resolve(request_id) => {
                executor.pending_resolves.remove(&request_id);
            }
        }
    }
}

/// Whether a future on this worker holds the disk-I/O key `key`.
pub(crate) fn disk_io_key_held(key: u32) -> bool {
    DISK_IO_LIVE.with(|live| live.borrow().contains(&key))
}

/// Stop holding the disk-I/O key `key` on this worker.
pub(crate) fn untrack_disk_io(key: u32) {
    DISK_IO_LIVE.with(|live| {
        live.borrow_mut().remove(&key);
    });
}

/// Per-worker async executor. Owns the task slab and coordinates
/// CQE-driven wakeups with future polling.
pub(crate) struct Executor {
    /// This worker's id and inbox. Wakers carry the id; one woken on another
    /// thread delivers its task id to the inbox, which `collect_wakeups`
    /// drains.
    pub(crate) wakes: waker::WorkerWakes,
    pub(crate) task_slab: TaskSlab,
    /// Standalone tasks not bound to any connection.
    pub(crate) standalone_slab: StandaloneTaskSlab,
    /// Timer slot pool for sleep/timeout.
    pub(crate) timer_pool: TimerSlotPool,
    /// Connection indices (and standalone task indices with STANDALONE_BIT) ready to poll.
    pub(crate) ready_queue: VecDeque<u32>,
    /// Scratch for draining the thread-local waker queue and the cross-thread
    /// inbox.
    waker_drain_scratch: VecDeque<u32>,
    /// Per-connection: task is awaiting recv data.
    pub(crate) recv_waiters: Vec<bool>,
    /// Per-connection: the error that ended the stream — a transport error,
    /// or the reason the runtime closed the connection itself — tagged
    /// with the connection generation it belongs to. Written by
    /// [`fail_recv`](Self::fail_recv), read once by
    /// [`take_recv_error`](Self::take_recv_error). Only `with_data_result`
    /// consults it; `with_data` keeps reporting EOF for both cases.
    ///
    /// Deliberately not cleared by `remove_connection`: the generation tag
    /// already prevents a reused slot from seeing the old error, and leaving
    /// it lets a task that polls after teardown learn the cause instead of a
    /// bare `0`. The next `fail_recv` on the slot overwrites it, whatever its
    /// generation (last writer wins; every backend error site is terminal
    /// for the connection, so a second error for the same generation does
    /// not occur in practice).
    ///
    /// Contract for readers: `WithDataResultFuture` consults this slot with
    /// the generation it captured at construction, *after* the inner
    /// `WithDataFuture` reports `0` — including when that `0` came from the
    /// generation-mismatch short-circuit. That is what lets a poll that lands
    /// after teardown still see the error.
    pub(crate) recv_errors: Vec<Option<(u32, stdio::Error)>>,
    /// Worker-wide table of awaited sends: the FIFO that decides which
    /// bounded send may reserve copy-pool slots next, and the state and
    /// result of every awaited send. Driven through the
    /// wrappers in [`send_completion`]; `remove_connection` resolves the
    /// entries of a torn-down connection (provisionally — see that module's
    /// docs on why a driver result still overwrites the abort).
    pub(crate) send_completions: send_completion::SendCompletions,
    /// Per-connection: task is awaiting connect result.
    pub(crate) connect_waiters: Vec<bool>,
    /// Per-connection: CQE result storage for send/connect.
    pub(crate) io_results: Vec<Option<IoResult>>,
    /// Maps conn_index → owning task ID. For accepted connections, `owner_task[i] = Some(i)`
    /// (self-owned). For outbound connections created via `connect()`,
    /// `owner_task[i] = Some(calling_task_id)` where `calling_task_id` is the task
    /// that initiated the connect. This indirection allows `wake_recv`/`wake_connect`
    /// to wake the correct task even when the connection index differs from the
    /// task index.
    pub(crate) owner_task: Vec<Option<u32>>,
    /// Per-UDP-socket datagram recv queue for async tasks.
    ///
    /// Holds buffer references into the kernel-provided UDP recv ring (zero-copy)
    /// rather than owned `Vec<u8>`s. The consumer pops, reads the slice, and
    /// pushes the `bid` to `Driver::udp_pending_replenish` to return the buffer
    /// to the kernel ring.
    pub(crate) udp_recv_queues: Vec<VecDeque<PendingUdpDatagram>>,
    /// Hard cap on each `udp_recv_queues[i]`. Datagrams arriving when the
    /// queue is full are dropped (`udp::DATAGRAMS_DROPPED` is incremented).
    /// This prevents unbounded memory growth when the consumer future
    /// stalls or has exited. On io_uring a cap equal to the ring size is never
    /// reached, because the ring runs out first and the socket stops reading.
    pub(crate) udp_recv_queue_capacity: usize,
    /// Per-UDP-socket: task ID waiting for recv_from (None = no waiter).
    pub(crate) udp_recv_waiters: Vec<Option<u32>>,
    /// Per-UDP-socket: task ID waiting for a free send slot (None = no waiter).
    /// Driven by the io_uring backend's slot ring; the mio backend leaves this
    /// empty because sends are synchronous and never suspend.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) udp_send_ready_waiters: Vec<Option<u32>>,
    /// Disk I/O: what the executor holds per key ([`DiskIoEntry`]); each step
    /// of an operation is one lookup in this map, plus an update of the held
    /// set (`DISK_IO_LIVE`) when the step begins or ends the future's hold.
    pub(crate) disk_io: KeyMap<DiskIoEntry>,
    /// Pending DNS resolve requests: request_id -> (task_id to wake, result slot).
    pub(crate) pending_resolves: HashMap<u64, (u32, Option<stdio::Result<std::net::SocketAddr>>)>,
    /// Monotonic counter for resolve request IDs.
    pub(crate) next_resolve_id: u64,
    /// Pending process spawn requests: request_id -> (task_id to wake, result slot).
    pub(crate) pending_spawns:
        HashMap<u64, (u32, Option<stdio::Result<crate::spawner::SpawnResult>>)>,
    /// Monotonic counter for spawn request IDs.
    pub(crate) next_spawn_id: u64,
    /// Pidfd poll waiters: seq -> task_id to wake on pidfd readability.
    pub(crate) pidfd_waiters: HashMap<u32, u32>,
    /// Pidfd poll results: seq -> CQE result (stored until polled by WaitFuture).
    pub(crate) pidfd_results: HashMap<u32, i32>,
    /// Monotonic counter for pidfd poll sequence numbers.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) next_pidfd_seq: u32,
    /// Pending blocking requests: request_id -> (task_id to wake, result slot).
    pub(crate) pending_blocking: HashMap<u64, (u32, Option<crate::blocking::BlockingResult>)>,
    /// Monotonic counter for blocking request IDs.
    pub(crate) next_blocking_id: u64,
    /// Per-batch dedup bitset for connection-task ready-queue entries.
    ///
    /// Indexed by `conn_index`. Set to `true` when that id is first seen in
    /// `poll_ready_tasks`; cleared only for the entries touched, never
    /// globally. Sized to `max_connections` at construction — zero per-call
    /// allocation.
    pub(crate) poll_dedup_conn: Vec<bool>,
    /// Per-batch dedup bitset for standalone-task ready-queue entries.
    ///
    /// Indexed by `task_idx & !STANDALONE_BIT`. Same lifecycle as
    /// `poll_dedup_conn`. Sized to `standalone_task_capacity`.
    pub(crate) poll_dedup_standalone: Vec<bool>,
    /// Test-only: how many times `wake_send_capacity` has actually woken the
    /// send-capacity FIFO head.
    ///
    /// The mio loop promises *one* capacity wake per iteration however many
    /// copy-pool permits came back during it, and the ready queue cannot
    /// witness that: `wake_task` pushes only on a Parked → Ready transition,
    /// so a second wake of the same head in the same iteration leaves
    /// `ready_queue.len()` at 1 as well. Counting the wakes at their source
    /// is what makes "once" observable.
    #[cfg(test)]
    pub(crate) send_capacity_wakes: u32,
}

impl Drop for Executor {
    fn drop(&mut self) {
        // A buffer still parked belongs to an operation whose
        // completion this executor has not seen. The exit drain waited for the
        // operation, or on mio had the pool skip it, or the worker leaked this
        // executor; the drain delivers no completions, so the buffer is here
        // all the same. Leak it; the leak is bounded by the operations in
        // flight when the worker exits.
        for (_, entry) in self.disk_io.drain() {
            if let DiskIoEntry::Parked(buf) = entry {
                std::mem::forget(buf);
            }
        }
    }
}

impl Executor {
    /// Create a new executor with the given capacities.
    pub(crate) fn new(
        max_connections: u32,
        standalone_capacity: u32,
        timer_slots: u32,
        udp_count: u32,
        udp_recv_queue_capacity: usize,
    ) -> Self {
        let cap = max_connections as usize;
        let udp = udp_count as usize;
        Executor {
            wakes: waker::WorkerWakes::register(),
            task_slab: TaskSlab::new(max_connections),
            standalone_slab: StandaloneTaskSlab::new(standalone_capacity),
            timer_pool: TimerSlotPool::new(timer_slots),
            ready_queue: VecDeque::with_capacity(64),
            waker_drain_scratch: VecDeque::with_capacity(64),
            recv_waiters: vec![false; cap],
            recv_errors: {
                let mut v = Vec::with_capacity(cap);
                v.resize_with(cap, || None);
                v
            },
            send_completions: send_completion::SendCompletions::new(),
            connect_waiters: vec![false; cap],
            io_results: {
                let mut v = Vec::with_capacity(cap);
                for _ in 0..cap {
                    v.push(None);
                }
                v
            },
            owner_task: vec![None; cap],
            udp_recv_queues: (0..udp).map(|_| VecDeque::new()).collect(),
            udp_recv_queue_capacity,
            udp_recv_waiters: vec![None; udp],
            udp_send_ready_waiters: vec![None; udp],
            disk_io: KeyMap::default(),
            pending_resolves: HashMap::new(),
            next_resolve_id: 0,
            pending_spawns: HashMap::new(),
            next_spawn_id: 0,
            pidfd_waiters: HashMap::new(),
            pidfd_results: HashMap::new(),
            next_pidfd_seq: 0,
            pending_blocking: HashMap::new(),
            next_blocking_id: 0,
            poll_dedup_conn: vec![false; cap],
            poll_dedup_standalone: vec![false; standalone_capacity as usize],
            #[cfg(test)]
            send_capacity_wakes: 0,
        }
    }

    /// Drain the thread-local waker queue and this worker's cross-thread
    /// inbox, moving each woken task from Parked to Ready through `ready_task`,
    /// which does not fire kept wakers, and queueing it for poll. `ready_task`
    /// also records a wake of the task being polled.
    pub(crate) fn collect_wakeups(&mut self) {
        drain_ready_queue(&mut self.waker_drain_scratch);
        self.wakes.drain_into(&mut self.waker_drain_scratch);
        while let Some(id) = self.waker_drain_scratch.pop_front() {
            let _ = self.ready_task(id);
        }
    }

    /// Drop every task, catching a panic in any future's `Drop`. Run at worker
    /// exit, so that one panic does not abort the process by way of a second
    /// during the unwind.
    pub(crate) fn drop_tasks(&mut self) {
        self.task_slab.clear();
        self.standalone_slab.clear();
        for (_, entry) in std::mem::take(&mut self.pending_blocking) {
            self.task_slab.drop_noting_panic(entry);
        }
    }

    /// Take the panics caught in the `Drop` of removed futures.
    pub(crate) fn take_drop_panics(&mut self) -> Vec<crate::task_panic::PanicPayload> {
        let mut panics = self.task_slab.take_drop_panics();
        panics.append(&mut self.standalone_slab.take_drop_panics());
        panics.append(&mut crate::task_panic::take_guard_drop_panics());
        panics
    }

    /// The connection task `conn_index` returned or panicked. Drop the task
    /// and the ownership of the awaited sends it created, and nothing else:
    /// the connection is closing, not closed, and the sends other tasks
    /// await on it are settled by the driver as the queue drains ahead of
    /// the close. [`remove_connection`](Self::remove_connection) runs when
    /// the backend releases the slot. Called from the task-exit arms of
    /// `poll_ready_tasks` on both backends, with the driver state
    /// installed.
    pub(crate) fn remove_connection_task(&mut self, conn_index: u32) {
        self.task_slab.remove(conn_index);
        for task_id in self.send_completions.remove_task(conn_index) {
            let _ = self.wake_task(task_id);
        }
    }

    /// Reset all per-connection state for a connection that was closed.
    ///
    /// Drops the connection's task if it is still alive. The backends call
    /// this under `with_driver_state`, so the futures that task holds clean
    /// up as they do inside a poll (a `SendCompletion` cancels its entry, a
    /// `SleepFuture` its timer).
    pub(crate) fn remove_connection(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        self.task_slab.remove(conn_index);
        // Awaited sends waiting on or in flight for this connection resolve
        // to ConnectionAborted; wake their owners (standalone or cross-index
        // tasks that outlive the connection) and the FIFO's new head. That
        // abort is provisional: a driver result arriving afterwards
        // overwrites it (`send_completion`'s module docs). Runs after
        // `task_slab.remove` on purpose: the task's futures cancel their
        // entries when the task is dropped, so an entry the task still owns
        // here is held by a future it handed off, and `remove_connection`
        // keeps it for that future.
        for task_id in self.send_completions.remove_connection(conn_index) {
            let _ = self.wake_task(task_id);
        }
        if idx < self.recv_waiters.len() {
            // If a *standalone* task was awaiting recv/connect on this
            // connection, it isn't removed by `task_slab.remove`. Push it
            // back onto the ready queue so its future polls once more and
            // sees the new generation via the `ConnCtx`-stored gen check
            // — at which point it returns `ConnectionAborted` instead of
            // sitting parked forever. (Connection-bound tasks have already
            // been dropped by `task_slab.remove`.)
            let any_waiter = self.recv_waiters[idx] || self.connect_waiters[idx];
            if any_waiter
                && let Some(task_id) = self.owner_task[idx]
                && (task_id & waker::STANDALONE_BIT != 0 || task_id != conn_index)
            {
                // Push to the ready queue; the standalone task slab still
                // holds the future, and the next poll will short-circuit on
                // the generation mismatch.
                let _ = self.wake_task(task_id);
            }
            self.recv_waiters[idx] = false;
            self.connect_waiters[idx] = false;
            self.io_results[idx] = None;
            self.owner_task[idx] = None;
        }
    }

    /// Fire every timer whose deadline is at or before now and wake its
    /// task. Both event loops call this after each wait.
    pub(crate) fn fire_expired_timers(&mut self) {
        if self.timer_pool.heap_is_empty() {
            return;
        }
        let now = std::time::Instant::now();
        while let Some((slot, generation)) = self.timer_pool.pop_expired(now) {
            if let Some(waker_id) = self.timer_pool.fire(slot, generation) {
                self.wake_task(waker_id);
            }
        }
    }

    /// Fire the task's kept wakers, then queue it. Leaf completions, which
    /// wake a task by the ID it registered, call this.
    ///
    /// Handles both connection tasks (plain index) and standalone tasks
    /// (index | STANDALONE_BIT). Returns true if the task was parked, or the
    /// wake was recorded on the poll in progress.
    pub(crate) fn wake_task(&mut self, task_id: u32) -> bool {
        waker::wake_combinators(task_id);
        self.ready_task(task_id)
    }

    /// Queue a task for its next poll. A wake through the task's own
    /// [`Waker`](std::task::Waker) comes here directly.
    fn ready_task(&mut self, task_id: u32) -> bool {
        let wake = if task_id & waker::STANDALONE_BIT != 0 {
            self.standalone_slab.wake(task_id & !waker::STANDALONE_BIT)
        } else {
            self.task_slab.wake(task_id)
        };
        if wake == Wake::Ready {
            self.ready_queue.push_back(task_id);
        }
        wake != Wake::None
    }

    /// Wake a task that was waiting for recv data.
    ///
    /// Resolves through `owner_task` so that outbound connections correctly
    /// wake the task that owns them (which may differ from the conn_index).
    pub(crate) fn wake_recv(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        if idx < self.recv_waiters.len() && self.recv_waiters[idx] {
            self.recv_waiters[idx] = false;
            let task_id = self.owner_task[idx].unwrap_or(conn_index);
            self.wake_task(task_id);
        }
    }

    /// Record the error that ended `conn_index`'s stream and wake the recv
    /// waiter, exactly as [`wake_recv`](Self::wake_recv) would.
    ///
    /// Backends call this instead of `wake_recv` at every site where a recv
    /// failed with a real (non-`WouldBlock`) socket error, and where the
    /// runtime closes the connection on its own account (a failed write, the
    /// accumulator cap, a TLS record the engine could not process). `with_data`
    /// callers still observe EOF; `with_data_result` callers observe the
    /// error via [`take_recv_error`](Self::take_recv_error).
    pub(crate) fn fail_recv(&mut self, conn_index: u32, generation: u32, error: stdio::Error) {
        let idx = conn_index as usize;
        if idx < self.recv_errors.len() {
            self.recv_errors[idx] = Some((generation, error));
        }
        self.wake_recv(conn_index);
    }

    /// Take the recorded transport error for `conn_index`, if one was
    /// recorded for exactly `generation`. One-shot: a second call returns
    /// `None`.
    pub(crate) fn take_recv_error(
        &mut self,
        conn_index: u32,
        generation: u32,
    ) -> Option<stdio::Error> {
        let slot = self.recv_errors.get_mut(conn_index as usize)?;
        match slot {
            Some((stored_generation, _)) if *stored_generation == generation => {
                slot.take().map(|(_, error)| error)
            }
            _ => None,
        }
    }

    /// Wake a task that was waiting for a UDP datagram.
    pub(crate) fn wake_udp_recv(&mut self, udp_index: u32) {
        let idx = udp_index as usize;
        if idx < self.udp_recv_waiters.len()
            && let Some(task_id) = self.udp_recv_waiters[idx].take()
        {
            self.wake_task(task_id);
        }
    }

    /// Wake a task that was waiting for a free UDP send slot.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) fn wake_udp_send_ready(&mut self, udp_index: u32) {
        let idx = udp_index as usize;
        if idx < self.udp_send_ready_waiters.len()
            && let Some(task_id) = self.udp_send_ready_waiters[idx].take()
        {
            self.wake_task(task_id);
        }
    }

    /// Wake a task that was waiting for connect completion.
    pub(crate) fn wake_connect(&mut self, conn_index: u32, result: stdio::Result<()>) {
        let idx = conn_index as usize;
        if idx < self.connect_waiters.len() && self.connect_waiters[idx] {
            self.connect_waiters[idx] = false;
            self.io_results[idx] = Some(IoResult::Connect(result));
            let task_id = self.owner_task[idx].unwrap_or(conn_index);
            self.wake_task(task_id);
        }
    }

    /// Hold the key `seq` for a future created by `task_id`'s task, which is
    /// woken when the operation completes.
    pub(crate) fn wait_disk_io(&mut self, seq: u32, task_id: u32) {
        match self.disk_io.entry(seq) {
            Entry::Occupied(mut e) => match e.get_mut() {
                DiskIoEntry::Held { waiter, .. } => *waiter = Some(task_id),
                // A parked buffer or abandoned open keeps its entry until its
                // completion; until then no new future can be given its key,
                // because on io_uring the key's slab slot stays allocated and
                // on mio the allocator skips a key in `disk_io_in_flight`.
                _ => debug_assert!(false, "disk-I/O key {seq:#x} reused while in flight"),
            },
            Entry::Vacant(e) => {
                e.insert(DiskIoEntry::Held {
                    waiter: Some(task_id),
                    result: None,
                    metadata: None,
                });
            }
        }
        DISK_IO_LIVE.with(|live| live.borrow_mut().insert(seq));
    }

    /// One poll of the future holding `seq` from `task_id`'s task: the result
    /// and stat metadata if the operation has completed, which ends the
    /// future's interest in the key; otherwise `task_id` becomes the task to
    /// wake.
    pub(crate) fn poll_disk_io(
        &mut self,
        seq: u32,
        task_id: u32,
    ) -> Option<(i32, Option<crate::fs::Metadata>)> {
        let Entry::Occupied(mut e) = self.disk_io.entry(seq) else {
            return None;
        };
        match e.get_mut() {
            DiskIoEntry::Held {
                result: Some(_), ..
            } => {}
            DiskIoEntry::Held { waiter, .. } => {
                *waiter = Some(task_id);
                return None;
            }
            // A parked or abandoned key: no future polls it.
            _ => return None,
        }
        let DiskIoEntry::Held {
            result: Some(result),
            metadata,
            ..
        } = e.remove()
        else {
            unreachable!("checked above");
        };
        untrack_disk_io(seq);
        Some((result, metadata))
    }

    /// Take the result of the operation `seq`, if it has completed. Taking
    /// it ends the future's interest in the key.
    pub(crate) fn take_disk_io_result(&mut self, seq: u32) -> Option<i32> {
        let Entry::Occupied(e) = self.disk_io.entry(seq) else {
            return None;
        };
        let DiskIoEntry::Held {
            result: Some(result),
            ..
        } = *e.get()
        else {
            return None;
        };
        e.remove();
        untrack_disk_io(seq);
        Some(result)
    }

    /// Forget the operation `seq`, whose future was dropped before it took
    /// its result: drop its entry, result and stat metadata included, and
    /// its key from the held set, so `wake_disk_io` discards a result that
    /// arrives later.
    pub(crate) fn abandon_disk_io(&mut self, seq: u32) {
        if let Entry::Occupied(e) = self.disk_io.entry(seq)
            && matches!(e.get(), DiskIoEntry::Held { .. })
        {
            e.remove();
        }
        untrack_disk_io(seq);
    }

    /// Park `buf`, the buffer of a dropped read or write whose operation
    /// `seq` is still in flight, until the completion frees it.
    pub(crate) fn park_disk_io(&mut self, seq: u32, buf: Box<dyn std::any::Any>) {
        self.disk_io.insert(seq, DiskIoEntry::Parked(buf));
        untrack_disk_io(seq);
    }

    /// Mark the open `seq` as abandoned: its `OpenFuture` was dropped while
    /// the open was in flight, and the completion handler closes the file.
    pub(crate) fn abandon_disk_io_open(&mut self, seq: u32) {
        self.disk_io.insert(seq, DiskIoEntry::AbandonedOpen);
        untrack_disk_io(seq);
    }

    /// Whether the open `seq` was abandoned; if so, forget it.
    pub(crate) fn take_abandoned_open(&mut self, seq: u32) -> bool {
        match self.disk_io.entry(seq) {
            Entry::Occupied(e) if matches!(e.get(), DiskIoEntry::AbandonedOpen) => {
                e.remove();
                true
            }
            _ => false,
        }
    }

    /// Deliver the completion of the operation `seq`: see
    /// [`wake_disk_io_with`](Self::wake_disk_io_with).
    pub(crate) fn wake_disk_io(&mut self, seq: u32, result: i32) {
        self.wake_disk_io_with(seq, result, None);
    }

    /// Deliver the completion of the operation `seq`, with the stat metadata
    /// of a completed stat.
    ///
    /// A parked buffer (its future was dropped before the operation
    /// completed) is freed and the result discarded. A held key stores the
    /// result and wakes the waiting task. Any other key has no future to
    /// take the result, which is discarded. Keyed by the disk-I/O key, not
    /// the connection.
    pub(crate) fn wake_disk_io_with(
        &mut self,
        seq: u32,
        result: i32,
        metadata: Option<crate::fs::Metadata>,
    ) {
        let Entry::Occupied(mut e) = self.disk_io.entry(seq) else {
            return;
        };
        let task_id = match e.get_mut() {
            DiskIoEntry::Parked(_) => {
                e.remove();
                return;
            }
            DiskIoEntry::Held {
                waiter,
                result: slot,
                metadata: slot_metadata,
            } => {
                *slot = Some(result);
                *slot_metadata = metadata;
                waiter.take()
            }
            DiskIoEntry::AbandonedOpen => return,
        };
        if let Some(task_id) = task_id {
            self.wake_task(task_id);
        }
    }

    /// Deliver a process spawn response and wake the waiting task.
    pub(crate) fn deliver_spawn(
        &mut self,
        request_id: u64,
        result: stdio::Result<crate::spawner::SpawnResult>,
    ) {
        if let Some((task_id, slot)) = self.pending_spawns.get_mut(&request_id) {
            *slot = Some(result);
            let task_id = *task_id;
            self.wake_task(task_id);
        } else {
            // The SpawnFuture was dropped before the response arrived; dropping
            // the result closes the pidfd.
            drop(result);
        }
    }

    /// Wake a task waiting for pidfd poll completion (child process exit).
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) fn wake_pidfd(&mut self, seq: u32, result: i32) {
        // The waiter is registered from `Child::wait` (and each pending poll)
        // until its completion arrives or the future is released; with none,
        // nothing will take the result.
        if let Some(task_id) = self.pidfd_waiters.remove(&seq) {
            self.pidfd_results.insert(seq, result);
            self.wake_task(task_id);
        }
    }

    /// Deliver a blocking response and wake the waiting task. With no entry
    /// (the handle was dropped), the result is dropped here.
    pub(crate) fn deliver_blocking(
        &mut self,
        request_id: u64,
        result: crate::blocking::BlockingResult,
    ) {
        if let Some((task_id, slot)) = self.pending_blocking.get_mut(&request_id) {
            *slot = Some(result);
            let task_id = *task_id;
            self.wake_task(task_id);
        } else {
            self.task_slab.drop_noting_panic(result);
        }
    }

    /// Deliver a DNS resolve response and wake the waiting task. With no
    /// entry (the future was dropped), the result is dropped here.
    pub(crate) fn deliver_resolve(
        &mut self,
        request_id: u64,
        result: stdio::Result<std::net::SocketAddr>,
    ) {
        if let Some((task_id, slot)) = self.pending_resolves.get_mut(&request_id) {
            *slot = Some(result);
            let task_id = *task_id;
            self.wake_task(task_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pidfd completion that arrives after its `WaitFuture` was dropped,
    /// with no waiter left, is not stored: nothing would remove it.
    #[test]
    fn a_pidfd_completion_with_no_waiter_is_not_stored() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.wake_pidfd(5, 0);
        assert!(!exec.pidfd_results.contains_key(&5));

        // With a waiter, the result is stored for the future to take.
        exec.pidfd_waiters.insert(6, 0);
        exec.wake_pidfd(6, 0);
        assert_eq!(exec.pidfd_results.get(&6), Some(&0));
    }

    #[test]
    fn collect_wakeups_transitions_parked_to_ready() {
        // A std Waker pushes only the raw id onto the thread-local queue.
        // collect_wakeups must transition the slot Parked -> Ready or the
        // wake is lost (take_ready returns None for Parked slots).
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.task_slab.spawn(3, Box::pin(async {}));
        let fut = exec.task_slab.take_ready(3).unwrap();
        exec.task_slab.park(3, fut);

        waker::conn_waker(exec.wakes.id(), 3).wake_by_ref();
        exec.collect_wakeups();

        assert_eq!(exec.ready_queue.len(), 1);
        assert!(
            exec.task_slab.take_ready(3).is_some(),
            "waker-woken parked task must be Ready"
        );
    }

    #[test]
    fn wake_task_during_own_poll_is_recorded() {
        // While a task is being polled its future is checked out (slot
        // `Polling`); a self-wake must be recorded in the slot instead of
        // being dropped.
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.task_slab.spawn(2, Box::pin(async {}));
        let fut = exec.task_slab.take_ready(2).unwrap();

        assert!(exec.wake_task(2), "self-wake must be accepted");
        assert!(exec.ready_queue.is_empty());

        // The poll loop parks, which reports the wake:
        assert!(exec.task_slab.park(2, fut));
        assert!(exec.task_slab.take_ready(2).is_some());
    }

    #[test]
    fn remove_connection_wakes_cross_index_connection_task_owner() {
        // Proxy pattern: connection task 3 (inbound) awaits recv on
        // upstream connection 5. Teardown of 5 must re-wake task 3 even
        // though it is not a standalone task.
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.task_slab.spawn(3, Box::pin(async {}));
        let fut = exec.task_slab.take_ready(3).unwrap();
        exec.task_slab.park(3, fut);

        exec.recv_waiters[5] = true;
        exec.owner_task[5] = Some(3);
        exec.remove_connection(5);

        assert!(
            exec.task_slab.take_ready(3).is_some(),
            "cross-index owner task must be re-woken on teardown"
        );
    }

    #[test]
    fn fail_recv_stores_error_and_wakes_recv_waiter() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.task_slab.spawn(2, Box::pin(async {}));
        let fut = exec.task_slab.take_ready(2).unwrap();
        exec.task_slab.park(2, fut);
        exec.recv_waiters[2] = true;

        exec.fail_recv(2, 7, stdio::Error::from_raw_os_error(libc::ECONNRESET));

        assert!(
            !exec.recv_waiters[2],
            "fail_recv must clear the waiter flag like wake_recv"
        );
        assert!(
            exec.task_slab.take_ready(2).is_some(),
            "fail_recv must wake the parked task"
        );
        let err = exec
            .take_recv_error(2, 7)
            .expect("error recorded for generation 7");
        assert_eq!(err.raw_os_error(), Some(libc::ECONNRESET));
        assert!(exec.take_recv_error(2, 7).is_none(), "take is one-shot");
    }

    #[test]
    fn take_recv_error_rejects_other_generation() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.fail_recv(3, 7, stdio::Error::from_raw_os_error(libc::EPIPE));

        assert!(
            exec.take_recv_error(3, 8).is_none(),
            "a reused slot must not see the old error"
        );
        assert!(
            exec.take_recv_error(3, 7).is_some(),
            "the original generation still can"
        );
    }

    #[test]
    fn recv_error_survives_remove_connection_for_its_generation() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.fail_recv(4, 7, stdio::Error::from_raw_os_error(libc::ECONNRESET));
        exec.remove_connection(4);

        assert!(
            exec.take_recv_error(4, 7).is_some(),
            "a late poll still learns the cause"
        );
        assert!(exec.take_recv_error(4, 9).is_none());
    }

    #[test]
    fn fail_recv_out_of_range_is_a_no_op() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.fail_recv(200, 1, stdio::Error::from_raw_os_error(libc::EIO));
        assert!(exec.take_recv_error(200, 1).is_none());
    }

    #[test]
    fn timer_release_clears_deadline() {
        // A deadline left on a free slot would make its heap entry live
        // again for the slot's next occupant.
        let mut pool = TimerSlotPool::new(4);
        let (slot, _gen) = pool.allocate(42).unwrap();
        pool.deadlines[slot as usize] =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
        pool.release(slot);
        assert!(
            pool.deadlines[slot as usize].is_none(),
            "released slot must not retain a deadline"
        );
    }

    #[test]
    fn next_segment_range_walks_gro_entry() {
        // 2.5 segments of 1000: ranges must advance one segment at a time.
        let mut e = owned_datagram(vec![0u8; 2500], 1000);
        assert_eq!(e.next_segment_range(), (0, 1000));
        e.consumed = 1000;
        assert!(!e.exhausted());
        assert_eq!(e.next_segment_range(), (1000, 2000));
        e.consumed = 2000;
        assert_eq!(e.next_segment_range(), (2000, 2500));
        e.consumed = 2500;
        assert!(e.exhausted());
    }

    #[test]
    fn next_segment_range_uncoalesced_is_whole_payload() {
        let e = owned_datagram(vec![7u8; 1200], 0);
        assert_eq!(e.next_segment_range(), (0, 1200));
        assert!(e.exhausted());
    }

    fn owned_datagram(payload: Vec<u8>, segment_size: u32) -> PendingUdpDatagram {
        PendingUdpDatagram {
            peer: "127.0.0.1:0".parse().unwrap(),
            buf: PendingUdpBuf::Owned(payload),
            recv_at: std::time::Instant::now(),
            segment_size,
            consumed: 0,
        }
    }

    #[test]
    fn for_each_segment_no_gro_yields_whole_payload() {
        let entry = owned_datagram(vec![7u8; 1200], 0);
        let mut lens = Vec::new();
        entry.for_each_segment(|s| lens.push(s.len()));
        assert_eq!(lens, vec![1200]);
    }

    #[test]
    fn for_each_segment_splits_coalesced_payload() {
        // 2.5 segments of 1000 → chunks 1000, 1000, 500.
        let entry = owned_datagram(vec![0u8; 2500], 1000);
        let mut lens = Vec::new();
        entry.for_each_segment(|s| lens.push(s.len()));
        assert_eq!(lens, vec![1000, 1000, 500]);
    }

    #[test]
    fn for_each_segment_exact_multiple() {
        let entry = owned_datagram(vec![0u8; 3000], 1500);
        let mut count = 0;
        entry.for_each_segment(|s| {
            assert_eq!(s.len(), 1500);
            count += 1;
        });
        assert_eq!(count, 2);
    }

    #[test]
    fn executor_new() {
        let exec = Executor::new(16, 8, 8, 0, 0);
        assert!(exec.ready_queue.is_empty());
        assert_eq!(exec.recv_waiters.len(), 16);
        assert_eq!(exec.recv_errors.len(), 16);
        assert_eq!(exec.connect_waiters.len(), 16);
        assert_eq!(exec.io_results.len(), 16);
        assert_eq!(exec.owner_task.len(), 16);
    }

    #[test]
    fn remove_connection_clears_state() {
        let mut exec = Executor::new(4, 4, 4, 0, 0);
        exec.recv_waiters[1] = true;
        exec.connect_waiters[1] = true;
        exec.io_results[1] = Some(IoResult::Connect(Ok(())));
        exec.owner_task[1] = Some(0);

        exec.remove_connection(1);
        assert!(!exec.recv_waiters[1]);
        assert!(!exec.connect_waiters[1]);
        assert!(exec.io_results[1].is_none());
        assert!(exec.owner_task[1].is_none());
    }

    #[test]
    fn wake_task_connection_task() {
        let mut exec = Executor::new(4, 4, 4, 0, 0);
        // Spawn a task at index 1 (simulated by setting it up as Ready then parking).
        exec.task_slab
            .spawn(1, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(1).unwrap();
        exec.task_slab.park(1, fut);

        assert!(exec.wake_task(1));
        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 1);
    }

    #[test]
    fn wake_task_standalone_task() {
        let mut exec = Executor::new(4, 4, 4, 0, 0);
        let idx = exec
            .standalone_slab
            .spawn(Box::pin(std::future::pending::<()>()))
            .unwrap();
        let fut = exec.standalone_slab.take_ready(idx).unwrap();
        exec.standalone_slab.park(idx, fut);

        let task_id = idx | waker::STANDALONE_BIT;
        assert!(exec.wake_task(task_id));
        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], task_id);
    }

    /// Spawn and park a standalone task; returns its full task id.
    fn parked_standalone(exec: &mut Executor) -> u32 {
        let idx = exec
            .standalone_slab
            .spawn(Box::pin(std::future::pending::<()>()))
            .unwrap();
        let fut = exec.standalone_slab.take_ready(idx).unwrap();
        exec.standalone_slab.park(idx, fut);
        idx | waker::STANDALONE_BIT
    }

    #[test]
    fn remove_connection_wakes_bounded_send_owner_on_a_standalone_task() {
        // A standalone task owns an in-flight bounded send on connection 3.
        // Tearing down 3 must resolve the send and wake the task, which
        // outlives the connection.
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        let task_id = parked_standalone(&mut exec);
        let id = exec.enqueue_send_capacity(3, 1, 1, task_id);
        exec.mark_send_submitted(id);
        assert!(exec.ready_queue.is_empty());

        exec.remove_connection(3);

        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], task_id);
        assert!(
            exec.standalone_slab
                .take_ready(task_id & !waker::STANDALONE_BIT)
                .is_some(),
            "owner must be Ready after teardown"
        );
        let err = exec
            .take_send_result(id)
            .expect("result recorded")
            .expect_err("teardown fails the send");
        assert_eq!(err.kind(), stdio::ErrorKind::ConnectionAborted);
    }

    #[test]
    fn complete_bounded_send_wakes_the_refreshed_owner() {
        // The future was enqueued from task A and later polled from task B
        // (owner refreshed each poll). The completion must wake B, not A.
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        let a = parked_standalone(&mut exec);
        let b = parked_standalone(&mut exec);
        let id = exec.enqueue_send_capacity(2, 1, 1, a);
        exec.mark_send_submitted(id);
        exec.set_send_owner(id, b);

        exec.complete_send(id, Ok(7));

        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], b);
        assert!(
            exec.standalone_slab
                .take_ready(b & !waker::STANDALONE_BIT)
                .is_some(),
            "refreshed owner is Ready"
        );
        assert!(
            exec.standalone_slab
                .take_ready(a & !waker::STANDALONE_BIT)
                .is_none(),
            "original owner stays parked"
        );
        assert_eq!(exec.take_send_result(id).unwrap().unwrap(), 7);
    }

    #[test]
    fn send_capacity_wrappers_wake_through_wake_task() {
        // The remaining wrappers: a slot release wakes the head only once it
        // fits, a cancelled head promotes the next waiter, and a write
        // shutdown fails the waiters of that connection generation.
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        let a = parked_standalone(&mut exec);
        let b = parked_standalone(&mut exec);
        let c = parked_standalone(&mut exec);
        let head = exec.enqueue_send_capacity(2, 1, 4, a);
        let next = exec.enqueue_send_capacity(5, 1, 1, b);
        let last = exec.enqueue_send_capacity(5, 1, 1, c);

        assert!(!exec.send_capacity_turn(head, 3));
        exec.wake_send_capacity(3);
        assert!(exec.ready_queue.is_empty(), "head still cannot fit");
        assert!(exec.send_capacity_turn(head, 4));
        exec.wake_send_capacity(4);
        assert_eq!(exec.ready_queue.pop_front(), Some(a));

        exec.cancel_send(head);
        assert_eq!(exec.ready_queue.pop_front(), Some(b), "next head woken");
        assert!(exec.send_capacity_turn(next, 1));

        exec.fail_waiting_bounded_sends(5, 1, stdio::ErrorKind::BrokenPipe, "shut down");
        assert_eq!(
            exec.ready_queue.pop_front(),
            Some(c),
            "c was still parked; b was already Ready so it is not re-queued"
        );
        assert!(exec.ready_queue.is_empty());
        for id in [next, last] {
            let err = exec
                .take_send_result(id)
                .expect("failed waiter has a result")
                .expect_err("failed");
            assert_eq!(err.kind(), stdio::ErrorKind::BrokenPipe);
        }
        assert!(!exec.send_capacity_turn(next, 8));
    }

    #[test]
    fn owner_task_routes_recv_wakeup() {
        let mut exec = Executor::new(16, 4, 4, 0, 0);

        // Task at index 5 owns connection 12 (outbound connect scenario).
        exec.task_slab
            .spawn(5, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(5).unwrap();
        exec.task_slab.park(5, fut);

        exec.owner_task[12] = Some(5);
        exec.recv_waiters[12] = true;

        exec.wake_recv(12);

        // The task at index 5 should be woken, not index 12.
        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 5);
        assert!(!exec.recv_waiters[12]);
    }

    /// A registered send is owned by the task that registered it, and its
    /// completion wakes that task, whichever connection the send targets.
    #[test]
    fn a_registered_send_wakes_the_task_that_registered_it() {
        let mut exec = Executor::new(16, 4, 4, 0, 0);

        exec.task_slab
            .spawn(3, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(3).unwrap();
        exec.task_slab.park(3, fut);

        CURRENT_TASK_ID.with(|c| c.set(3));
        let id = exec.register_send(10);
        exec.complete_send(id, Ok(42));

        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 3);
        assert_eq!(exec.take_send_result(id).unwrap().unwrap(), 42);
    }

    #[test]
    fn owner_task_routes_connect_wakeup() {
        let mut exec = Executor::new(16, 4, 4, 0, 0);

        exec.task_slab
            .spawn(2, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(2).unwrap();
        exec.task_slab.park(2, fut);

        exec.owner_task[8] = Some(2);
        exec.connect_waiters[8] = true;

        exec.wake_connect(8, Ok(()));

        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 2);
        assert!(!exec.connect_waiters[8]);
    }

    #[test]
    fn owner_task_none_falls_back_to_conn_index() {
        let mut exec = Executor::new(4, 4, 4, 0, 0);

        // owner_task is None — should fall back to using conn_index directly.
        exec.task_slab
            .spawn(1, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(1).unwrap();
        exec.task_slab.park(1, fut);

        exec.recv_waiters[1] = true;
        exec.wake_recv(1);

        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 1);
    }

    // ── TimerSlotPool tests ────────────────────────────────────────

    #[test]
    fn timer_allocate_and_fire() {
        let mut pool = TimerSlotPool::new(4);

        let (slot, generation) = pool.allocate(42).unwrap();
        assert!(!pool.is_fired(slot));

        let waker_id = pool.fire(slot, generation).unwrap();
        assert_eq!(waker_id, 42);
        assert!(pool.is_fired(slot));
    }

    #[test]
    fn timer_fire_stale_generation_returns_none() {
        let mut pool = TimerSlotPool::new(4);

        let (slot, generation) = pool.allocate(10).unwrap();
        pool.release(slot); // increments generation

        // Fire with old generation — should return None (stale).
        assert!(pool.fire(slot, generation).is_none());
    }

    #[test]
    fn timer_release_increments_generation() {
        let mut pool = TimerSlotPool::new(4);

        let (slot, gen0) = pool.allocate(1).unwrap();
        pool.release(slot);

        let (slot2, gen1) = pool.allocate(2).unwrap();
        assert_eq!(slot2, slot); // same slot reused
        assert_eq!(gen1, gen0 + 1);

        pool.release(slot2);
    }

    #[test]
    fn timer_generation_wraps_at_u16_max() {
        let mut pool = TimerSlotPool::new(1);

        let (slot, _) = pool.allocate(1).unwrap();
        pool.generations[slot as usize] = u16::MAX;
        pool.release(slot);

        let (slot2, generation) = pool.allocate(2).unwrap();
        assert_eq!(slot2, slot);
        assert_eq!(generation, 0); // wrapped from u16::MAX
    }

    /// Every slot of a full-size pool is distinct.
    #[test]
    fn every_timer_slot_is_allocated_once() {
        let mut pool = TimerSlotPool::new(TIMER_SLOTS);
        let mut seen = vec![false; TIMER_SLOTS as usize];
        for _ in 0..TIMER_SLOTS {
            let (slot, _) = pool.allocate(0).unwrap();
            assert!(!seen[slot as usize], "slot {slot} allocated twice");
            seen[slot as usize] = true;
        }
        assert!(pool.allocate(0).is_none());
    }

    /// The heap entry of a released slot does not fire the slot's next
    /// occupant, even when that occupant's deadline is later, and the
    /// occupant fires at its own deadline.
    #[test]
    fn a_released_timers_heap_entry_does_not_fire_the_next_occupant() {
        use std::time::{Duration, Instant};
        let mut pool = TimerSlotPool::new(1);
        let (slot, _) = pool.allocate(1).unwrap();
        pool.set_relative(slot, Duration::ZERO);
        pool.release(slot);
        let (slot2, gen2) = pool.allocate(2).unwrap();
        assert_eq!(slot2, slot);
        pool.set_relative(slot2, Duration::from_secs(60));
        let now = Instant::now() + Duration::from_millis(1);
        assert_eq!(pool.pop_expired(now), None, "the dead entry fired");
        let next = pool.next_deadline().expect("the live entry");
        assert!(next > now + Duration::from_secs(59));
        assert_eq!(
            pool.pop_expired(now + Duration::from_secs(61)),
            Some((slot2, gen2))
        );
        assert_eq!(pool.fire(slot2, gen2), Some(2));
    }

    /// Expired timers pop in deadline order, and a timer that never expires
    /// (`Duration::MAX`) has no heap entry.
    #[test]
    fn timers_pop_in_deadline_order() {
        use std::time::{Duration, Instant};
        let mut pool = TimerSlotPool::new(4);
        let (a, ga) = pool.allocate(1).unwrap();
        let (b, gb) = pool.allocate(2).unwrap();
        let (c, _) = pool.allocate(3).unwrap();
        pool.set_relative(a, Duration::from_millis(20));
        pool.set_relative(b, Duration::from_millis(10));
        pool.set_relative(c, Duration::MAX);
        assert_eq!(pool.heap_len(), 2);
        let later = Instant::now() + Duration::from_secs(1);
        assert_eq!(pool.pop_expired(later), Some((b, gb)));
        assert_eq!(pool.pop_expired(later), Some((a, ga)));
        assert_eq!(pool.pop_expired(later), None);
        assert_eq!(pool.next_deadline(), None);
    }

    /// Timers released before their deadline, as a `timeout()` whose future
    /// wins releases its timer, leave dead heap entries; compaction keeps the
    /// heap from growing with them.
    #[test]
    fn released_timers_do_not_grow_the_heap() {
        use std::time::Duration;
        let mut pool = TimerSlotPool::new(4);
        let (held, _) = pool.allocate(0).unwrap();
        pool.set_relative(held, Duration::from_secs(3600));
        for _ in 0..100_000 {
            let (slot, _) = pool.allocate(1).unwrap();
            pool.set_relative(slot, Duration::from_secs(60));
            pool.release(slot);
        }
        assert!(
            pool.heap_len() <= TIMER_HEAP_COMPACT_MIN,
            "heap holds {} entries",
            pool.heap_len()
        );
        assert!(pool.next_deadline().is_some(), "the held timer was dropped");
    }

    #[test]
    fn timer_exhaust_pool() {
        let mut pool = TimerSlotPool::new(2);

        let (s0, _) = pool.allocate(1).unwrap();
        let (s1, _) = pool.allocate(2).unwrap();
        assert!(pool.allocate(3).is_none()); // full

        pool.release(s0);
        assert!(pool.allocate(4).is_some()); // one freed
        assert!(pool.allocate(5).is_none()); // full again

        pool.release(s1);
    }

    #[test]
    fn timer_is_fired_out_of_bounds() {
        let pool = TimerSlotPool::new(2);
        assert!(!pool.is_fired(99)); // out of bounds returns false
    }

    #[test]
    fn timer_fire_out_of_bounds_returns_none() {
        let mut pool = TimerSlotPool::new(2);
        assert!(pool.fire(99, 0).is_none());
    }

    #[test]
    fn timer_allocate_resets_fired_flag() {
        let mut pool = TimerSlotPool::new(2);

        let (slot, generation) = pool.allocate(1).unwrap();
        pool.fire(slot, generation).unwrap();
        assert!(pool.is_fired(slot));

        pool.release(slot);
        let (slot2, _) = pool.allocate(2).unwrap();
        assert_eq!(slot2, slot);
        assert!(!pool.is_fired(slot2)); // fired flag reset on allocate
    }

    // The disk-I/O entry map: one entry per key from the future's creation
    // until the result is taken or the completion frees what a drop left.

    #[test]
    fn a_disk_io_result_delivered_before_the_poll_is_taken_once() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        let key = 0x4000_0101;
        exec.wait_disk_io(key, 0);
        assert!(disk_io_key_held(key));
        exec.wake_disk_io(key, 7);
        assert!(matches!(exec.poll_disk_io(key, 0), Some((7, None))));
        assert!(!disk_io_key_held(key), "taking the result releases the key");
        assert!(!exec.disk_io.contains_key(&key));
        assert!(
            exec.poll_disk_io(key, 0).is_none(),
            "a result is taken once"
        );
    }

    #[test]
    fn a_disk_io_completion_wakes_the_task_that_polled_last() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.task_slab.spawn(2, Box::pin(async {}));
        let fut = exec.task_slab.take_ready(2).unwrap();
        exec.task_slab.park(2, fut);
        let key = 0x4000_0102;
        exec.wait_disk_io(key, 5);
        // The poll before the completion records the polling task.
        assert!(exec.poll_disk_io(key, 2).is_none());
        exec.wake_disk_io(key, 3);
        assert!(
            exec.task_slab.take_ready(2).is_some(),
            "the completion wakes the task that polled last"
        );
        assert!(matches!(exec.poll_disk_io(key, 2), Some((3, None))));
    }

    #[test]
    fn a_parked_disk_io_buffer_is_freed_by_its_completion() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        let key = 0x4000_0103;
        exec.wait_disk_io(key, 0);
        exec.park_disk_io(key, Box::new(bytes::BytesMut::with_capacity(16)));
        assert!(!disk_io_key_held(key), "a parked key is not held");
        assert!(matches!(
            exec.disk_io.get(&key),
            Some(DiskIoEntry::Parked(_))
        ));
        exec.wake_disk_io(key, 0);
        assert!(
            !exec.disk_io.contains_key(&key),
            "the completion frees the parked buffer"
        );
    }

    #[test]
    fn an_abandoned_disk_io_open_is_taken_once_and_its_result_discarded() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        let key = 0x4000_0104;
        exec.wait_disk_io(key, 0);
        exec.abandon_disk_io_open(key);
        assert!(!disk_io_key_held(key));
        assert!(exec.take_abandoned_open(key));
        assert!(!exec.take_abandoned_open(key), "taken once");
        assert!(!exec.disk_io.contains_key(&key));
        // A completion for a key nothing holds is discarded.
        exec.wake_disk_io(key, 9);
        assert!(!exec.disk_io.contains_key(&key));
    }

    #[test]
    fn an_abandoned_disk_io_key_discards_a_later_result() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        let key = 0x4000_0105;
        exec.wait_disk_io(key, 0);
        exec.abandon_disk_io(key);
        assert!(!disk_io_key_held(key));
        exec.wake_disk_io(key, 9);
        assert!(!exec.disk_io.contains_key(&key));
        assert_eq!(exec.take_disk_io_result(key), None);
    }
}
