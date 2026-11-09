//! The bounded channels that carry a connection to the worker that serves
//! it: an accepted fd from the acceptor thread or, in merged accept mode,
//! from the worker that accepted it, and a parked connection from the worker
//! that parked it.
//!
//! These are `std::sync::mpsc` channels rather than crossbeam ones because of
//! what happens to a message queued when the receiver drops. A worker that
//! stops drains its receiver and drops it. A message a sender queues between
//! the drain and the drop is dropped with a `std` receiver, which closes the
//! fd it carries, and the sender's next `try_send` fails with `Disconnected`.
//! A crossbeam receiver keeps that message until the last sender drops too,
//! which for a worker's channel is when the acceptor thread or the last other
//! worker exits; until then the connection's fd stays open and its peer
//! waits (#780). `a_queued_message_drops_with_the_receiver` pins the
//! property.

pub(crate) use std::sync::mpsc::{Receiver, SyncSender as Sender, TrySendError};

/// A bounded channel holding at most `capacity` messages.
pub(crate) fn bounded<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    std::sync::mpsc::sync_channel(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A message queued when the receiver drops is dropped with it while a
    /// sender still exists, and that sender's next send fails. A connection
    /// handed to a worker that has stopped closes, instead of staying open
    /// until the sending thread exits (#780).
    #[test]
    fn a_queued_message_drops_with_the_receiver() {
        let (tx, rx) = bounded::<Arc<()>>(4);
        let probe = Arc::new(());
        tx.try_send(Arc::clone(&probe)).unwrap();
        drop(rx);
        assert_eq!(
            Arc::strong_count(&probe),
            1,
            "the queued message outlived the receiver"
        );
        assert!(matches!(
            tx.try_send(Arc::clone(&probe)),
            Err(TrySendError::Disconnected(_))
        ));
    }
}
