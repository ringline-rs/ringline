//! Ordering of an fsync after the writes submitted before it on the same
//! file (#905), shared by both backends.
//!
//! Reads and writes on one file stay unordered with respect to each other.
//! An fsync (`fs::fsync`, `direct_io_fsync`) is held, not submitted, until
//! every write submitted before it on the same file has completed. A write
//! submitted after an fsync does not wait for it, and a later write does not
//! hold back an earlier fsync. Held fsyncs are not linked to the writes
//! (`IOSQE_IO_LINK`), so a failed write cancels nothing.

use std::collections::{BTreeSet, HashMap, VecDeque};

use crate::runtime::KeyMap;

/// The file an operation is on: its subsystem, table slot and generation.
/// The generation keeps a slot reused after a close apart from the file that
/// held it before.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct OrderKey {
    pub(crate) subsystem: Subsystem,
    pub(crate) index: u16,
    pub(crate) generation: u32,
}

/// The file subsystems whose fsyncs are ordered.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Subsystem {
    Fs,
    DirectIo,
}

/// One file's writes in flight and the fsyncs held behind them.
struct FileOrder<S> {
    /// The ticket of the next write submitted on the file.
    next: u64,
    /// Tickets of the writes submitted and not completed.
    writes: BTreeSet<u64>,
    /// Held fsyncs, in submission order, each with the ticket of the first
    /// write submitted after it: it is released once no write with a lower
    /// ticket is in flight.
    held: VecDeque<(u64, S)>,
}

/// Every file's write order on one worker. `S` is what a held fsync needs to
/// be submitted later: on io_uring its fixed file index and user_data, on
/// mio its pool request.
pub(crate) struct WriteOrders<S> {
    files: HashMap<OrderKey, FileOrder<S>>,
    /// The file and ticket of each write in flight, by disk-I/O key.
    writes: KeyMap<(OrderKey, u64)>,
}

impl<S> Default for WriteOrders<S> {
    fn default() -> Self {
        WriteOrders {
            files: HashMap::new(),
            writes: KeyMap::default(),
        }
    }
}

impl<S> WriteOrders<S> {
    /// Record a write submitted on `file` under disk-I/O key `op`.
    pub(crate) fn begin_write(&mut self, file: OrderKey, op: u32) {
        let order = self.files.entry(file).or_insert_with(|| FileOrder {
            next: 0,
            writes: BTreeSet::new(),
            held: VecDeque::new(),
        });
        let ticket = order.next;
        order.next += 1;
        order.writes.insert(ticket);
        self.writes.insert(op, (file, ticket));
    }

    /// An fsync on `file`: returned to submit now when no earlier write is
    /// in flight, otherwise held until those writes complete.
    pub(crate) fn sync(&mut self, file: OrderKey, sync: S) -> Option<S> {
        match self.files.get_mut(&file) {
            Some(order) if !order.writes.is_empty() => {
                order.held.push_back((order.next, sync));
                None
            }
            _ => Some(sync),
        }
    }

    /// The operation under disk-I/O key `op` completed. If it was a write,
    /// return the fsyncs it was the last earlier write of, in submission
    /// order, to submit now.
    pub(crate) fn end_write(&mut self, op: u32) -> Vec<S> {
        let Some((file, ticket)) = self.writes.remove(&op) else {
            return Vec::new();
        };
        let Some(order) = self.files.get_mut(&file) else {
            return Vec::new();
        };
        order.writes.remove(&ticket);
        // Every write with a lower ticket than this has completed.
        let oldest = order.writes.first().copied().unwrap_or(order.next);
        let mut released = Vec::new();
        while order
            .held
            .front()
            .is_some_and(|&(bound, _)| bound <= oldest)
        {
            released.push(order.held.pop_front().expect("checked above").1);
        }
        if order.writes.is_empty() && order.held.is_empty() {
            self.files.remove(&file);
        }
        released
    }

    /// Take every held fsync, at worker exit (io_uring; on mio the held
    /// requests are dropped with the driver, unsent).
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) fn drain_held(&mut self) -> Vec<S> {
        let mut held = Vec::new();
        for order in self.files.values_mut() {
            held.extend(order.held.drain(..).map(|(_, sync)| sync));
        }
        held
    }

    /// The number of fsyncs held.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.files.values().map(|order| order.held.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(index: u16) -> OrderKey {
        OrderKey {
            subsystem: Subsystem::Fs,
            index,
            generation: 0,
        }
    }

    #[test]
    fn an_fsync_with_no_write_in_flight_is_not_held() {
        let mut orders = WriteOrders::default();
        assert_eq!(orders.sync(file(0), "sync"), Some("sync"));
        orders.begin_write(file(1), 1);
        assert_eq!(orders.sync(file(0), "other file"), Some("other file"));
    }

    #[test]
    fn an_fsync_waits_for_every_earlier_write() {
        let mut orders = WriteOrders::default();
        orders.begin_write(file(0), 1);
        orders.begin_write(file(0), 2);
        assert_eq!(orders.sync(file(0), "sync"), None);
        assert!(orders.end_write(2).is_empty(), "write 1 is still in flight");
        assert_eq!(orders.end_write(1), vec!["sync"]);
        assert_eq!(orders.held(), 0);
    }

    #[test]
    fn a_later_write_does_not_hold_back_an_earlier_fsync() {
        let mut orders = WriteOrders::default();
        orders.begin_write(file(0), 1);
        assert_eq!(orders.sync(file(0), "sync"), None);
        orders.begin_write(file(0), 2);
        assert_eq!(orders.end_write(1), vec!["sync"], "write 2 came after it");
        // A second fsync waits for write 2, which is still in flight.
        assert_eq!(orders.sync(file(0), "second"), None);
        assert_eq!(orders.end_write(2), vec!["second"]);
    }

    #[test]
    fn fsyncs_are_released_in_submission_order() {
        let mut orders = WriteOrders::default();
        orders.begin_write(file(0), 1);
        assert_eq!(orders.sync(file(0), "first"), None);
        orders.begin_write(file(0), 2);
        assert_eq!(orders.sync(file(0), "second"), None);
        // Write 2 completes first: neither is released, since the first
        // waits for write 1 and the second waits for both.
        assert!(orders.end_write(2).is_empty());
        assert_eq!(orders.end_write(1), vec!["first", "second"]);
    }

    #[test]
    fn a_reused_slot_is_a_different_file() {
        let mut orders = WriteOrders::default();
        orders.begin_write(file(0), 1);
        let reused = OrderKey {
            generation: 1,
            ..file(0)
        };
        assert_eq!(orders.sync(reused, "sync"), Some("sync"));
    }

    #[test]
    fn a_completion_that_was_not_a_write_releases_nothing() {
        let mut orders = WriteOrders::<&str>::default();
        orders.begin_write(file(0), 1);
        assert!(orders.end_write(7).is_empty());
        assert_eq!(orders.sync(file(0), "sync"), None, "write 1 is in flight");
    }

    #[test]
    fn drain_takes_every_held_fsync() {
        let mut orders = WriteOrders::default();
        orders.begin_write(file(0), 1);
        orders.begin_write(file(1), 2);
        assert_eq!(orders.sync(file(0), "a"), None);
        assert_eq!(orders.sync(file(1), "b"), None);
        let mut held = orders.drain_held();
        held.sort();
        assert_eq!(held, vec!["a", "b"]);
        assert_eq!(orders.held(), 0);
    }
}
