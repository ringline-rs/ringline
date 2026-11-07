use std::future::Future;
use std::pin::Pin;

use crate::runtime::io::{Connection, UdpSocket};

/// Trait for async connection handlers.
///
/// Consumers implement this trait to handle connections using `async fn` code
/// instead of push-based
/// callbacks. Each accepted connection gets a long-lived async task that runs
/// for the connection's lifetime.
///
/// # Example
///
/// ```no_run
/// use std::future::Future;
/// use ringline::{AsyncEventHandler, Connection, ParseResult};
///
/// struct EchoHandler;
///
/// impl AsyncEventHandler for EchoHandler {
///     fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
///         async move {
///             let (mut tx, mut rx) = conn.split();
///             loop {
///                 let n = rx.with_data(|data| {
///                     // Echo back everything received.
///                     tx.send_nowait(data).ok();
///                     ringline::ParseResult::Consumed(data.len())
///                 }).await;
///                 if n == 0 {
///                     break;
///                 }
///             }
///         }
///     }
///
///     fn create_for_worker(worker_id: usize) -> Self {
///         EchoHandler
///     }
/// }
/// ```
pub trait AsyncEventHandler: Send + 'static {
    /// Handle an accepted connection. When the returned future completes, the
    /// connection is closed, even if a half moved to a spawned task.
    ///
    /// Dropping the [`Connection`] also closes it, and the task then ends when
    /// the close completes. An unused `_conn` parameter is not captured by an
    /// `async move` block, so it drops when this method returns. To keep the
    /// connection open for the task's life, bind it inside the block:
    /// `let _conn = conn;`.
    ///
    /// The handler is given an owned [`Connection`], not a `Copy` handle: one
    /// task owns one connection, and the read side cannot be aliased. Call
    /// [`Connection::split`] when a send has to happen while a read borrow is
    /// live (an echo writing from inside its own `with_data` closure).
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static;

    /// Adopt a connection parked from another worker (tier 3, #443).
    ///
    /// Park moves an established connection to a less loaded worker. The
    /// future returned by [`Self::on_accept`] is `!Send` and cannot travel,
    /// so it is dropped on the old worker and this is called on the new one
    /// to make a fresh one.
    ///
    /// `state` is whatever the handler deposited with
    /// [`Connection::offer_for_park`] at the moment it allowed the park, or
    /// `None` if it deposited nothing.
    ///
    /// **A connection is only ever parked if the handler offered it**, so
    /// doing nothing here is safe: a handler that never calls
    /// `offer_for_park` never sees this.
    ///
    /// The default treats the connection as freshly accepted, which is
    /// correct for any handler that keeps no per-connection state — most of
    /// them. Override it when there is state to restore.
    ///
    /// Returns a boxed future rather than `impl Future` for the same reason
    /// [`Self::on_udp_bind`] does: a defaulted method cannot return an opaque
    /// type.
    #[cfg(any(feature = "unstable-accept", test))]
    fn on_adopt(
        &self,
        conn: Connection,
        state: Option<crate::park::ParkState>,
    ) -> Pin<Box<dyn Future<Output = ()> + 'static>> {
        // Depositing state and not overriding this loses it silently, which
        // would present as a connection that mysteriously forgot its session.
        debug_assert!(
            state.is_none(),
            "park state was deposited as `{}` but this handler does not \
             override `on_adopt`, so it would be dropped",
            state.as_ref().map(|s| s.deposited_as()).unwrap_or(""),
        );
        let _ = state;
        Box::pin(self.on_accept(conn))
    }

    /// Periodic tick (synchronous). Called on each event loop iteration.
    ///
    /// Runs on the worker, so the free functions such as
    /// [`spawn`](crate::spawn) and [`request_shutdown`](crate::request_shutdown)
    /// work here. It does not run in a task, so a future made here has to go to
    /// [`spawn`](crate::spawn) to be polled.
    fn on_tick(&mut self) {}

    /// Handle a bound UDP socket. Called once per UDP socket during startup.
    ///
    /// Return `Some(future)` to spawn a standalone task that handles datagrams
    /// for this socket. The future typically loops on [`UdpSocket::recv_from()`].
    /// Return `None` to ignore this UDP socket.
    fn on_udp_bind(&self, _udp: UdpSocket) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        None
    }

    /// Called after the worker's wake fd fires on io_uring (a
    /// [`WakeHandle::wake`](crate::WakeHandle::wake), a service-pool response,
    /// or a runtime `Waker` woken on another thread); on mio, every loop
    /// iteration. Synchronous, and has the same rules as [`Self::on_tick`].
    fn on_notify(&mut self) {}

    /// Async entry point called once during worker startup.
    ///
    /// Return `Some(future)` to spawn a standalone task on this worker. This
    /// is useful for client-only applications (no `.bind()`) that need to
    /// initiate outbound connections via [`connect()`](crate::connect).
    ///
    /// The task is spawned before the event loop's first iteration and then
    /// runs concurrently with everything else on the worker, including
    /// accepting connections. It is not a readiness gate: a listener that was
    /// not deferred starts serving as soon as `launch()` reaches it, whether or
    /// not this future has finished. To hold a port until the server can
    /// serve, bind it with
    /// [`RinglineBuilder::defer_listen`](crate::RinglineBuilder::defer_listen)
    /// and call [`begin_listening()`](crate::begin_listening) from here.
    ///
    /// The future can call [`request_shutdown()`](crate::request_shutdown) to
    /// stop the worker when done. Return `None` (the default) to skip.
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        None
    }

    /// Create per-worker instance.
    fn create_for_worker(worker_id: usize) -> Self
    where
        Self: Sized;
}
