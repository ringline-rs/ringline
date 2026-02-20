//! Sharded counter implementation for high-throughput metrics.
//!
//! The [`CounterGroup`] provides sharded storage for up to 16 counters,
//! with each thread writing to its own shard to avoid cache-line contention.
//! The [`Counter`] type references a slot in a group and implements
//! [`metriken::Metric`] for Prometheus exposition.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

const CACHE_LINE: usize = 128;
const SLOTS: usize = CACHE_LINE / 8; // 16 counters per cache line
const NUM_SHARDS: usize = 64;

thread_local! {
    /// Thread-local shard ID, set by `set_thread_shard()`.
    /// If not set, falls back to a hash of the TLS address.
    static SHARD_ID: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Set the shard ID for the current thread.
///
/// Call this at the start of each worker thread to ensure deterministic
/// shard assignment and avoid false sharing between workers.
pub fn set_thread_shard(id: usize) {
    SHARD_ID.set(Some(id % NUM_SHARDS));
}

#[repr(C, align(128))]
struct Shard {
    slots: [AtomicU64; SLOTS],
}

/// Sharded storage for up to 16 counters.
///
/// Each thread writes to its own shard (selected by thread ID), so multiple
/// counters in the same group don't cause false sharing. This allows packing
/// 16 counters into the same set of cache lines.
pub struct CounterGroup {
    shards: [Shard; NUM_SHARDS],
}

// Safety: All fields are atomics, safe to share across threads
unsafe impl Send for CounterGroup {}
unsafe impl Sync for CounterGroup {}

impl CounterGroup {
    /// Create a new counter group with all slots initialized to zero.
    #[allow(clippy::declare_interior_mutable_const)]
    pub const fn new() -> Self {
        const ZERO: AtomicU64 = AtomicU64::new(0);
        const SHARD: Shard = Shard {
            slots: [ZERO; SLOTS],
        };
        Self {
            shards: [SHARD; NUM_SHARDS],
        }
    }

    #[inline]
    fn increment(&self, slot: usize) {
        self.add(slot, 1);
    }

    #[inline]
    fn add(&self, slot: usize, value: u64) {
        debug_assert!(slot < SLOTS, "slot index out of bounds");
        let shard = shard_index();
        self.shards[shard].slots[slot].fetch_add(value, Ordering::Relaxed);
    }

    fn value(&self, slot: usize) -> u64 {
        debug_assert!(slot < SLOTS, "slot index out of bounds");
        self.shards
            .iter()
            .map(|s| s.slots[slot].load(Ordering::Relaxed))
            .sum()
    }
}

impl Default for CounterGroup {
    fn default() -> Self {
        Self::new()
    }
}

/// A sharded counter that can be registered with metriken.
///
/// References a slot in a [`CounterGroup`] for storage. Implements
/// [`metriken::Metric`] so it can be used with the `#[metric]` attribute.
pub struct Counter {
    group: &'static CounterGroup,
    slot: usize,
}

// Safety: CounterGroup is Sync, and slot is immutable
unsafe impl Send for Counter {}
unsafe impl Sync for Counter {}

impl Counter {
    /// Create a counter backed by a slot in the given group.
    ///
    /// # Panics
    ///
    /// Debug builds will panic if `slot >= 16`.
    pub const fn new(group: &'static CounterGroup, slot: usize) -> Self {
        Self { group, slot }
    }

    /// Increment the counter by 1.
    #[inline]
    pub fn increment(&self) {
        self.group.increment(self.slot);
    }

    /// Add a value to the counter.
    #[inline]
    pub fn add(&self, value: u64) {
        self.group.add(self.slot, value);
    }

    /// Get the current value (aggregated across all shards).
    pub fn value(&self) -> u64 {
        self.group.value(self.slot)
    }
}

impl metriken::Metric for Counter {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn value(&self) -> Option<metriken::Value<'_>> {
        Some(metriken::Value::Counter(Counter::value(self)))
    }
}

/// Get the shard index for the current thread.
///
/// Uses the explicitly set shard ID if available (via `set_thread_shard()`),
/// otherwise falls back to a hash of a TLS address.
#[inline]
fn shard_index() -> usize {
    SHARD_ID.get().unwrap_or_else(|| {
        // Fallback: use TLS address as a cheap thread identifier
        thread_local! {
            static ID: u8 = const { 0 };
        }
        ID.with(|x| x as *const u8 as usize) % NUM_SHARDS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_counter() {
        static GROUP: CounterGroup = CounterGroup::new();
        let counter = Counter::new(&GROUP, 0);

        assert_eq!(counter.value(), 0);
        counter.increment();
        assert_eq!(counter.value(), 1);
        counter.add(10);
        assert_eq!(counter.value(), 11);
    }

    #[test]
    fn multiple_slots() {
        static GROUP: CounterGroup = CounterGroup::new();
        let a = Counter::new(&GROUP, 0);
        let b = Counter::new(&GROUP, 1);

        a.increment();
        b.add(5);

        assert_eq!(a.value(), 1);
        assert_eq!(b.value(), 5);
    }

    #[test]
    fn thread_distribution() {
        use std::sync::Arc;
        use std::thread;

        static GROUP: CounterGroup = CounterGroup::new();
        let counter = Arc::new(Counter::new(&GROUP, 2));
        let iterations = 1000;
        let num_threads = 4;

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let c = Arc::clone(&counter);
                thread::spawn(move || {
                    for _ in 0..iterations {
                        c.increment();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(counter.value(), iterations * num_threads);
    }

    #[test]
    fn metriken_trait() {
        use metriken::Metric;

        static GROUP: CounterGroup = CounterGroup::new();
        let counter = Counter::new(&GROUP, 3);
        counter.add(42);

        let value = Metric::value(&counter);
        assert!(matches!(value, Some(metriken::Value::Counter(42))));
    }
}
