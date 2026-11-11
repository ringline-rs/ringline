//! Deadlines for TLS handshakes in progress
//! ([`ConfigBuilder::tls_handshake_timeout`](crate::ConfigBuilder::tls_handshake_timeout)).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::connection::ConnectionTable;

/// One worker's TLS handshakes in progress, oldest first, as
/// `(conn_index, generation, deadline)`.
///
/// Every entry is armed with the same timeout from a monotonic clock, so the
/// queue is in deadline order and a check reads only its front. An entry is
/// not removed when its handshake completes or its connection closes: the
/// check drops it when it reaches the front, so one handshake still in
/// progress at the front holds every entry armed after it. When the queue
/// passes twice `max_connections` entries, `arm` drops every entry whose
/// handshake is no longer in progress. At most `max_connections` remain,
/// so the queue holds at most `2 * max_connections + 1` entries.
pub(crate) struct HandshakeDeadlines {
    timeout: Duration,
    /// The length past which `arm` drops entries no longer in progress.
    compact_at: usize,
    queue: VecDeque<(u32, u32, Instant)>,
}

impl HandshakeDeadlines {
    pub(crate) fn new(timeout: Duration, max_connections: u32) -> Self {
        HandshakeDeadlines {
            timeout,
            compact_at: 2 * max_connections as usize,
            queue: VecDeque::new(),
        }
    }

    /// Whether no handshake is queued.
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Start the deadline for the handshake on `conn_index`, whose
    /// connection has generation `generation`. `in_progress` is as for
    /// [`pop_expired`](Self::pop_expired).
    pub(crate) fn arm(
        &mut self,
        conn_index: u32,
        generation: u32,
        in_progress: impl FnMut(u32, u32) -> bool,
    ) {
        self.arm_at(conn_index, generation, Instant::now(), in_progress);
    }

    fn arm_at(
        &mut self,
        conn_index: u32,
        generation: u32,
        now: Instant,
        mut in_progress: impl FnMut(u32, u32) -> bool,
    ) {
        if self.queue.len() > self.compact_at {
            self.queue.retain(|&(i, g, _)| in_progress(i, g));
        }
        self.queue
            .push_back((conn_index, generation, now + self.timeout));
    }

    /// The front entry's deadline. Its handshake may have completed since,
    /// so a wait until it can end with nothing to close.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.queue.front().map(|&(_, _, deadline)| deadline)
    }

    /// Remove and return the next connection whose handshake is still in
    /// progress (`in_progress(conn_index, generation)`) and whose deadline is
    /// at or before `now`. Entries at the front whose handshake is no longer
    /// in progress are dropped, whatever their deadline.
    pub(crate) fn pop_expired(
        &mut self,
        now: Instant,
        mut in_progress: impl FnMut(u32, u32) -> bool,
    ) -> Option<u32> {
        while let Some(&(conn_index, generation, deadline)) = self.queue.front() {
            if !in_progress(conn_index, generation) {
                self.queue.pop_front();
                continue;
            }
            if deadline > now {
                return None;
            }
            self.queue.pop_front();
            return Some(conn_index);
        }
        None
    }
}

/// Whether the connection at `conn_index` is still the one with
/// `generation`, its TLS handshake has not completed, and no close has been
/// requested.
pub(crate) fn in_progress(connections: &ConnectionTable, conn_index: u32, generation: u32) -> bool {
    connections.generation(conn_index) == generation
        && connections
            .get(conn_index)
            .is_some_and(|c| !c.established && !c.close_requested())
}

/// The error an outbound connect resolves with when its TLS handshake does
/// not complete within the timeout.
pub(crate) fn timed_out() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "TLS handshake did not complete within tls_handshake_timeout",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_expires_before_its_deadline() {
        let start = Instant::now();
        let mut d = HandshakeDeadlines::new(Duration::from_secs(10), 16);
        d.arm_at(1, 0, start, |_, _| true);
        assert_eq!(d.next_deadline(), Some(start + Duration::from_secs(10)));
        assert_eq!(
            d.pop_expired(start + Duration::from_secs(9), |_, _| true),
            None
        );
        assert_eq!(d.next_deadline(), Some(start + Duration::from_secs(10)));
    }

    #[test]
    fn expired_entries_come_out_in_order() {
        let start = Instant::now();
        let mut d = HandshakeDeadlines::new(Duration::from_secs(10), 16);
        d.arm_at(1, 0, start, |_, _| true);
        d.arm_at(2, 0, start + Duration::from_secs(1), |_, _| true);
        d.arm_at(3, 0, start + Duration::from_secs(5), |_, _| true);
        let now = start + Duration::from_secs(11);
        assert_eq!(d.pop_expired(now, |_, _| true), Some(1));
        assert_eq!(d.pop_expired(now, |_, _| true), Some(2));
        assert_eq!(d.pop_expired(now, |_, _| true), None);
        assert_eq!(d.next_deadline(), Some(start + Duration::from_secs(15)));
    }

    #[test]
    fn a_completed_handshake_is_dropped_without_expiring() {
        let start = Instant::now();
        let mut d = HandshakeDeadlines::new(Duration::from_secs(10), 16);
        d.arm_at(1, 0, start, |_, _| true);
        d.arm_at(2, 0, start, |_, _| true);
        // Slot 1's handshake completed; slot 2's is still in progress.
        assert_eq!(d.pop_expired(start, |i, _| i != 1), None);
        assert_eq!(d.next_deadline(), Some(start + Duration::from_secs(10)));
        assert_eq!(
            d.pop_expired(start + Duration::from_secs(10), |i, _| i != 1),
            Some(2)
        );
        assert_eq!(d.next_deadline(), None);
    }

    #[test]
    fn a_reused_slot_is_checked_with_the_generation_it_was_armed_with() {
        let start = Instant::now();
        let mut d = HandshakeDeadlines::new(Duration::from_secs(10), 16);
        d.arm_at(1, 4, start, |_, _| true);
        d.arm_at(1, 5, start + Duration::from_secs(1), |_, _| true);
        let now = start + Duration::from_secs(20);
        let mut asked = Vec::new();
        let first = d.pop_expired(now, |i, g| {
            asked.push((i, g));
            g == 5
        });
        assert_eq!(first, Some(1));
        assert_eq!(asked, vec![(1, 4), (1, 5)]);
        assert_eq!(d.next_deadline(), None);
    }

    #[test]
    fn arm_drops_finished_entries_past_twice_max_connections() {
        let start = Instant::now();
        let mut d = HandshakeDeadlines::new(Duration::from_secs(10), 4);
        // Slot 0's handshake never completes; every other one has.
        for i in 0..100 {
            d.arm_at(i, 0, start, |i, _| i == 0);
            assert!(d.queue.len() <= 9, "{} entries", d.queue.len());
        }
        assert_eq!(d.queue.front().map(|e| e.0), Some(0));
        assert_eq!(
            d.pop_expired(start + Duration::from_secs(10), |i, _| i == 0),
            Some(0)
        );
    }
}
