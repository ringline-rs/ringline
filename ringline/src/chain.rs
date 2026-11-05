//! Per-connection send chain state tracking for IOSQE_IO_LINK chains.
//!
//! When multiple SQEs are linked with IO_LINK, the kernel executes them
//! sequentially. Each SQE produces its own CQE. This module tracks the
//! aggregate result across all CQEs in a chain and fires a single
//! `on_send_complete` when the entire chain is done.

/// Events returned by chain state updates.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChainEvent {
    /// More CQEs expected for this chain.
    Pending,
    /// All operation CQEs received, but ZC notifications still pending.
    AllOpsComplete,
    /// Chain fully complete (all operation CQEs + all ZC notifications).
    Complete { bytes_sent: u32, error: Option<i32> },
}

use crate::runtime::send_completion::SendId;

/// State for a single in-flight send chain on a connection.
pub(crate) struct ChainState {
    /// Total SQEs in the chain.
    total_sqes: u16,
    /// Operation CQEs received so far.
    cqes_received: u16,
    /// Cumulative bytes from successful SQEs.
    pub(crate) bytes_sent: u32,
    /// Bytes in the chain's SQEs. 0 if unset.
    expected_bytes: u32,
    /// Chain broke (an error on a linked SQE).
    broken: bool,
    /// First error errno encountered (if any).
    pub(crate) first_error: Option<i32>,
    /// Outstanding SendMsgZc NOTIF CQEs.
    zc_notifs_pending: u16,
    /// The awaited send this chain settles (`SendHalf::send_chain`), with
    /// `bytes_sent` on success; `None` for `send_chain_nowait`.
    pub(crate) send_id: Option<SendId>,
}

impl ChainState {
    /// Why the stream has a gap, if it does. A failed SQE leaves one. So does
    /// an SQE that sent part of its bytes and then failed, whose CQE reports
    /// the part it sent, and whose error is lost: the SQEs after it report only
    /// `ECANCELED`.
    pub(crate) fn failure(&self) -> Option<std::io::Error> {
        let short = self.bytes_sent < self.expected_bytes;
        match self.first_error {
            Some(errno) if !(short && errno == -libc::ECANCELED) => {
                Some(std::io::Error::from_raw_os_error(-errno))
            }
            _ if short => Some(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "send chain sent part of its bytes",
            )),
            _ => None,
        }
    }

    fn is_complete(&self) -> bool {
        self.cqes_received == self.total_sqes && self.zc_notifs_pending == 0
    }

    fn to_event(&self) -> ChainEvent {
        if self.is_complete() {
            ChainEvent::Complete {
                bytes_sent: self.bytes_sent,
                error: self.first_error,
            }
        } else if self.cqes_received == self.total_sqes {
            ChainEvent::AllOpsComplete
        } else {
            ChainEvent::Pending
        }
    }
}

/// Table of per-connection chain states.
pub(crate) struct SendChainTable {
    chains: Vec<Option<ChainState>>,
}

impl SendChainTable {
    /// Create a table with capacity for `max_connections` slots.
    pub fn new(max_connections: u32) -> Self {
        let mut chains = Vec::with_capacity(max_connections as usize);
        chains.resize_with(max_connections as usize, || None);
        SendChainTable { chains }
    }

    /// Start tracking a new chain for the given connection.
    ///
    /// # Panics (debug)
    /// Panics if a chain is already active for this connection.
    pub fn start(&mut self, conn_index: u32, total_sqes: u16) {
        let slot = match self.chains.get_mut(conn_index as usize) {
            Some(s) => s,
            None => {
                debug_assert!(false, "chain start: conn_index {conn_index} out of range");
                return;
            }
        };
        debug_assert!(
            slot.is_none(),
            "starting chain on conn {conn_index} with existing active chain"
        );
        *slot = Some(ChainState {
            total_sqes,
            cqes_received: 0,
            bytes_sent: 0,
            expected_bytes: 0,
            broken: false,
            first_error: None,
            zc_notifs_pending: 0,
            send_id: None,
        });
    }

    /// Record how many bytes the connection's active chain carries.
    pub fn set_expected_bytes(&mut self, conn_index: u32, bytes: u32) {
        if let Some(Some(chain)) = self.chains.get_mut(conn_index as usize) {
            chain.expected_bytes = bytes;
        }
    }

    /// Attach the awaited send `id` to the connection's active chain. Does
    /// nothing when no chain is active.
    pub fn set_send_id(&mut self, conn_index: u32, id: SendId) {
        if let Some(Some(chain)) = self.chains.get_mut(conn_index as usize) {
            chain.send_id = Some(id);
        }
    }

    /// Whether the connection's active chain carries `id`.
    pub fn carries(&self, conn_index: u32, id: SendId) -> bool {
        matches!(
            self.chains.get(conn_index as usize),
            Some(Some(ChainState { send_id: Some(carried), .. })) if *carried == id
        )
    }

    /// Check if a chain is active for the connection.
    #[inline]
    pub fn is_active(&self, conn_index: u32) -> bool {
        self.chains
            .get(conn_index as usize)
            .map(|s| s.is_some())
            .unwrap_or(false)
    }

    /// Record an operation CQE result. Returns the chain event.
    pub fn on_operation_cqe(&mut self, conn_index: u32, result: i32) -> ChainEvent {
        let chain = match self.chains.get_mut(conn_index as usize) {
            Some(Some(c)) => c,
            _ => return ChainEvent::Pending,
        };

        chain.cqes_received += 1;

        if result >= 0 {
            chain.bytes_sent += result as u32;
        } else {
            // Error or ECANCELED
            chain.broken = true;
            if chain.first_error.is_none() {
                chain.first_error = Some(result);
            }
        }

        chain.to_event()
    }

    /// Increment expected ZC notifications for a chain.
    pub fn inc_zc_notif(&mut self, conn_index: u32) {
        if let Some(Some(chain)) = self.chains.get_mut(conn_index as usize) {
            chain.zc_notifs_pending += 1;
        }
    }

    /// Record a ZC notification CQE. Returns the chain event.
    pub fn on_notif_cqe(&mut self, conn_index: u32) -> ChainEvent {
        let chain = match self.chains.get_mut(conn_index as usize) {
            Some(Some(c)) => c,
            _ => return ChainEvent::Pending,
        };

        debug_assert!(
            chain.zc_notifs_pending > 0,
            "ZC notif underflow on conn {conn_index}"
        );
        chain.zc_notifs_pending -= 1;

        chain.to_event()
    }

    /// Take and clear the chain state for a connection.
    /// Returns `None` if no chain is active or the index is out of range.
    pub fn take(&mut self, conn_index: u32) -> Option<ChainState> {
        self.chains
            .get_mut(conn_index as usize)
            .and_then(|s| s.take())
    }

    /// Force-cancel a chain (used on connection close). Returns the
    /// awaited send the chain carried, for the caller to fail.
    pub fn cancel(&mut self, conn_index: u32) -> Option<SendId> {
        self.chains
            .get_mut(conn_index as usize)
            .and_then(|s| s.take())
            .and_then(|chain| chain.send_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_short_of_its_bytes_failed() {
        let mut table = SendChainTable::new(16);
        table.start(0, 2);
        table.set_expected_bytes(0, 100);
        table.on_operation_cqe(0, 60);
        table.on_operation_cqe(0, 40);
        assert!(table.take(0).unwrap().failure().is_none());

        // The last SQE sent part and then failed: its CQE reports the part.
        table.start(0, 2);
        table.set_expected_bytes(0, 100);
        table.on_operation_cqe(0, 60);
        table.on_operation_cqe(0, 10);
        let failure = table.take(0).unwrap().failure().unwrap();
        assert_eq!(failure.kind(), std::io::ErrorKind::WriteZero);

        // A middle SQE did: the next is cancelled, and that says nothing.
        table.start(0, 2);
        table.set_expected_bytes(0, 100);
        table.on_operation_cqe(0, 60);
        table.on_operation_cqe(0, -libc::ECANCELED);
        let failure = table.take(0).unwrap().failure().unwrap();
        assert_eq!(failure.kind(), std::io::ErrorKind::WriteZero);

        // A real error is reported as itself.
        table.start(0, 2);
        table.set_expected_bytes(0, 100);
        table.on_operation_cqe(0, -libc::EPIPE);
        table.on_operation_cqe(0, -libc::ECANCELED);
        let failure = table.take(0).unwrap().failure().unwrap();
        assert_eq!(failure.raw_os_error(), Some(libc::EPIPE));
    }

    #[test]
    fn single_sqe_chain() {
        let mut table = SendChainTable::new(16);
        table.start(0, 1);
        assert!(table.is_active(0));

        let event = table.on_operation_cqe(0, 100);
        assert_eq!(
            event,
            ChainEvent::Complete {
                bytes_sent: 100,
                error: None
            }
        );

        // Chain should still be present until take()
        let state = table.take(0);
        assert!(state.is_some());
        assert!(!table.is_active(0));
    }

    #[test]
    fn multi_sqe_chain_success() {
        let mut table = SendChainTable::new(16);
        table.start(0, 3);

        let event = table.on_operation_cqe(0, 100);
        assert_eq!(event, ChainEvent::Pending);

        let event = table.on_operation_cqe(0, 100);
        assert_eq!(event, ChainEvent::Pending);

        let event = table.on_operation_cqe(0, 100);
        assert_eq!(
            event,
            ChainEvent::Complete {
                bytes_sent: 300,
                error: None
            }
        );
    }

    #[test]
    fn chain_with_error_and_cancel() {
        let mut table = SendChainTable::new(16);
        table.start(0, 3);

        // First SQE succeeds
        let event = table.on_operation_cqe(0, 100);
        assert_eq!(event, ChainEvent::Pending);

        // Second SQE fails (partial write)
        let event = table.on_operation_cqe(0, -libc::EIO);
        assert_eq!(event, ChainEvent::Pending);

        // Third SQE cancelled (IO_LINK chain broken)
        let event = table.on_operation_cqe(0, -libc::ECANCELED);
        assert_eq!(
            event,
            ChainEvent::Complete {
                bytes_sent: 100,
                error: Some(-libc::EIO)
            }
        );
    }

    #[test]
    fn chain_with_zc_notifs() {
        let mut table = SendChainTable::new(16);
        table.start(0, 2);

        // First SQE op CQE + ZC notif pending
        table.inc_zc_notif(0);
        let event = table.on_operation_cqe(0, 100);
        assert_eq!(event, ChainEvent::Pending);

        // Second SQE op CQE (no ZC)
        let event = table.on_operation_cqe(0, 100);
        assert_eq!(event, ChainEvent::AllOpsComplete);

        // ZC notification arrives
        let event = table.on_notif_cqe(0);
        assert_eq!(
            event,
            ChainEvent::Complete {
                bytes_sent: 200,
                error: None
            }
        );
    }

    #[test]
    fn cancel_active_chain() {
        let mut table = SendChainTable::new(16);
        table.start(0, 5);
        assert!(table.is_active(0));

        assert_eq!(table.cancel(0), None, "an unawaited chain carries no id");
        assert!(!table.is_active(0));
    }

    #[test]
    fn cancel_no_chain() {
        let mut table = SendChainTable::new(16);
        assert_eq!(table.cancel(0), None);
    }

    #[test]
    fn inactive_connection() {
        let table = SendChainTable::new(16);
        assert!(!table.is_active(0));
        assert!(!table.is_active(15));
    }
}
