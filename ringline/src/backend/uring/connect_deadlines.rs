//! Deadlines for outbound connects with a timeout (`TcpConnect::timeout`).

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::Instant;

use crate::connection::{ConnectionTable, Lifecycle};

/// The heap is compacted when it reaches this many entries, or twice the
/// entries left by the previous compaction if that is more.
const COMPACT_MIN: usize = 64;

/// One worker's connect deadlines, as a min-heap of
/// `(deadline, conn_index, generation)`.
///
/// Timeouts differ per connect, so the deadlines are not in arming order. An
/// entry is not removed when its connect completes, fails or is closed: it is
/// live only while [`live`] holds, and is dropped when it reaches the top of
/// the heap or at a compaction.
pub(crate) struct ConnectDeadlines {
    heap: BinaryHeap<Reverse<(Instant, u32, u32)>>,
    compact_at: usize,
}

impl ConnectDeadlines {
    pub(crate) fn new() -> Self {
        ConnectDeadlines {
            heap: BinaryHeap::new(),
            compact_at: COMPACT_MIN,
        }
    }

    /// Record `deadline` for the connect of `conn_index` in `generation`.
    /// The connection's `connect_deadline` must already hold it.
    pub(crate) fn arm(
        &mut self,
        conn_index: u32,
        generation: u32,
        deadline: Instant,
        connections: &ConnectionTable,
    ) {
        if self.heap.len() >= self.compact_at {
            self.heap
                .retain(|&Reverse((d, i, g))| live(connections, i, g, d));
            self.compact_at = (2 * self.heap.len()).max(COMPACT_MIN);
        }
        self.heap.push(Reverse((deadline, conn_index, generation)));
    }

    /// The earliest live deadline, dropping dead entries at the top.
    pub(crate) fn next_deadline(&mut self, connections: &ConnectionTable) -> Option<Instant> {
        while let Some(&Reverse((d, i, g))) = self.heap.peek() {
            if live(connections, i, g, d) {
                return Some(d);
            }
            self.heap.pop();
        }
        None
    }

    /// Remove and return the next live entry whose deadline is at or before
    /// `now`, as `(conn_index, generation)`.
    pub(crate) fn pop_expired(
        &mut self,
        now: Instant,
        connections: &ConnectionTable,
    ) -> Option<(u32, u32)> {
        while let Some(&Reverse((d, i, g))) = self.heap.peek() {
            if !live(connections, i, g, d) {
                self.heap.pop();
                continue;
            }
            if d > now {
                return None;
            }
            self.heap.pop();
            return Some((i, g));
        }
        None
    }

    /// Number of entries, live and dead.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.heap.len()
    }
}

/// Whether the entry `(deadline, conn_index, generation)` is live: the slot
/// still holds that connection, its connect has not completed, and the
/// deadline it armed is this one.
fn live(
    connections: &ConnectionTable,
    conn_index: u32,
    generation: u32,
    deadline: Instant,
) -> bool {
    connections.get(conn_index).is_some_and(|c| {
        c.generation == generation
            && matches!(c.lifecycle, Lifecycle::Connecting)
            && c.connect_deadline == Some(deadline)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn arm(
        table: &mut ConnectionTable,
        heap: &mut ConnectDeadlines,
        after: Duration,
    ) -> (u32, u32, Instant) {
        let idx = table.allocate_outbound().unwrap();
        let generation = table.generation(idx);
        let deadline = Instant::now() + after;
        table.get_mut(idx).unwrap().connect_deadline = Some(deadline);
        heap.arm(idx, generation, deadline, table);
        (idx, generation, deadline)
    }

    /// Deadlines pop in deadline order, not arming order.
    #[test]
    fn deadlines_pop_in_order() {
        let mut table = ConnectionTable::new(8);
        let mut heap = ConnectDeadlines::new();
        let (a, ga, _) = arm(&mut table, &mut heap, Duration::from_secs(5));
        let (b, gb, db) = arm(&mut table, &mut heap, Duration::from_millis(10));
        assert_eq!(heap.next_deadline(&table), Some(db));
        let later = Instant::now() + Duration::from_secs(10);
        assert_eq!(heap.pop_expired(later, &table), Some((b, gb)));
        assert_eq!(heap.pop_expired(later, &table), Some((a, ga)));
        assert_eq!(heap.pop_expired(later, &table), None);
    }

    /// A connect that completed, or whose slot was reused, has no live
    /// entry: the new occupant's own later deadline is the next one.
    #[test]
    fn a_completed_or_reused_slot_has_no_live_entry() {
        let mut table = ConnectionTable::new(8);
        let mut heap = ConnectDeadlines::new();
        let (a, _, _) = arm(&mut table, &mut heap, Duration::ZERO);
        table.get_mut(a).unwrap().lifecycle = Lifecycle::Open;
        let (b, _, _) = arm(&mut table, &mut heap, Duration::ZERO);
        table.release(b);
        let (c, gc, dc) = arm(&mut table, &mut heap, Duration::from_secs(60));
        assert_eq!(c, b, "precondition: the slot is reused");
        let now = Instant::now() + Duration::from_millis(1);
        assert_eq!(heap.pop_expired(now, &table), None);
        assert_eq!(heap.next_deadline(&table), Some(dc));
        assert_eq!(
            heap.pop_expired(dc + Duration::from_secs(1), &table),
            Some((c, gc))
        );
    }

    /// Connects that complete before their deadline do not grow the heap.
    #[test]
    fn completed_connects_do_not_grow_the_heap() {
        let mut table = ConnectionTable::new(4);
        let mut heap = ConnectDeadlines::new();
        for _ in 0..10_000 {
            let (i, _, _) = arm(&mut table, &mut heap, Duration::from_secs(60));
            table.release(i);
        }
        assert!(heap.len() <= COMPACT_MIN, "{} entries", heap.len());
    }
}
