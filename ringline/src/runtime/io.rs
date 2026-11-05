use std::cell::{Cell, RefCell};
use std::fmt;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::backend::Driver;
#[cfg(has_io_uring)]
use crate::completion::{OpTag, UserData};
use crate::error::TimerExhausted;
use crate::handler::ConnToken;
#[cfg(has_io_uring)]
use crate::runtime::TimerSlotPool;
use crate::runtime::send_completion::SendId;
use crate::runtime::task::TaskId;
use crate::runtime::waker::STANDALONE_BIT;
use crate::runtime::{CURRENT_TASK_ID, Executor, IoResult};

/// Result of a parse closure passed to [`Connection::with_data`] or
/// [`Connection::with_bytes`].
///
/// When the closure returns `NeedMore` or `Consumed(0)`, the future parks and
/// retries when more data arrives. `Consumed(0)` on a non-empty buffer is
/// treated identically to `NeedMore`. At end of stream the closure is shown
/// what is buffered; if it consumes nothing, the future resolves with `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseResult {
    /// The closure consumed `n` bytes from the buffer.
    ///
    /// `Consumed(0)` on non-empty data is treated as "need more data" — the
    /// future will park and retry when additional bytes arrive.
    Consumed(usize),
    /// The closure needs more data before it can make progress.
    NeedMore,
    /// The closure needs at least `additional` more bytes beyond what it
    /// was shown (e.g. a length-prefixed protocol that has parsed its
    /// header). Parks exactly like [`NeedMore`](Self::NeedMore), but the
    /// runtime reserves recv-accumulator capacity for the announced
    /// remainder up front — one right-sized allocation instead of the
    /// doubling-regrowth cascade (~2× the payload in extra memcpy for a
    /// multi-MB message arriving in chunks).
    ///
    /// `with_data` and `with_bytes` only reserve with `additional`, so an
    /// `additional` that is too large costs memory.
    NeedAtLeast(usize),
}

/// Driver + executor state pointer, set before polling each task.
///
/// Using `NonNull` instead of raw pointers provides better type safety:
/// 1. **Non-null guarantee**: `NonNull` is guaranteed non-null at runtime
///    (enforced in debug builds), catching bugs earlier
/// 2. **Zero overhead**: Same performance as raw pointers
/// 3. **Clear ownership**: The pointer is set before poll and cleared after,
///    in a single-threaded context (no concurrent access)
pub(crate) struct DriverState {
    pub(crate) driver: NonNull<Driver>,
    pub(crate) executor: NonNull<Executor>,
}

thread_local! {
    /// Thread-local storage for the current driver state.
    ///
    /// # Safety
    ///
    /// This is safe because:
    /// 1. Single-threaded: each worker thread has its own driver/executor.
    /// 2. Scoped: set before poll, cleared after poll. The pointer is only
    ///    dereferenced within a Future::poll call.
    /// 3. The pointed-to data lives on the worker thread's stack (in AsyncEventLoop::run).
    pub(crate) static CURRENT_DRIVER: Cell<Option<NonNull<DriverState>>> =
        const { Cell::new(None) };
}

/// Set the thread-local driver pointer before polling a task.
///
/// # Safety
///
/// The caller must ensure `state` points to valid `DriverState` on the
/// current thread's stack.
pub(crate) unsafe fn set_driver_state(state: &mut DriverState) {
    CURRENT_DRIVER.with(|c| c.set(Some(NonNull::from(state))));
}

/// Clear the thread-local driver pointer after polling a task.
pub(crate) fn clear_driver_state() {
    CURRENT_DRIVER.with(|c| c.set(None));
}

/// RAII guard returned by [`set_driver_state_guarded`]. Clears the
/// thread-local driver pointer on drop — including during panic unwind.
/// Without this, a panic between set and clear leaves `CURRENT_DRIVER`
/// pointing into a popped stack frame, and futures' `Drop` impls
/// (`SendFuture`, `SleepFuture`, ...) dereference it while the executor's
/// slabs unwind — a use-after-free.
pub(crate) struct DriverStateGuard(());

impl Drop for DriverStateGuard {
    fn drop(&mut self) {
        clear_driver_state();
    }
}

// The connection whose reader callback is running on this thread, if any.
//
// `offer_for_park` declines an offer made from inside the connection's own
// reader callback, while it is the innermost one running. `with_bytes` takes
// the request out of the driver before its callback runs. A
// `forward_recv_buf` that sends the whole accumulator takes it out during the
// callback. `holds_unread` returns false
// for a request taken out either way (#669).
#[cfg(has_io_uring)]
thread_local! {
    static READER_CALLBACK_CONN: std::cell::Cell<Option<u32>> =
        const { std::cell::Cell::new(None) };
}

/// Marks `conn_index`'s reader callback as running until dropped, then
/// restores the previous value. Only the innermost running callback is
/// recorded, so while a nested callback on another connection runs, the
/// outer connection is not detected.
#[cfg(has_io_uring)]
struct ReaderCallback(Option<u32>);

#[cfg(has_io_uring)]
impl ReaderCallback {
    fn enter(conn_index: u32) -> Self {
        ReaderCallback(READER_CALLBACK_CONN.with(|c| c.replace(Some(conn_index))))
    }
}

#[cfg(has_io_uring)]
impl Drop for ReaderCallback {
    fn drop(&mut self) {
        READER_CALLBACK_CONN.with(|c| c.set(self.0));
    }
}

/// Whether the innermost reader callback running on this thread is
/// `conn_index`'s.
#[cfg(has_io_uring)]
pub(crate) fn in_reader_callback(conn_index: u32) -> bool {
    READER_CALLBACK_CONN.with(|c| c.get() == Some(conn_index))
}

/// Set the thread-local driver pointer, returning a guard that clears it
/// when dropped (normally or during unwind).
///
/// # Safety
///
/// Same contract as [`set_driver_state`]: `state` must point to valid
/// `DriverState` on the current thread's stack for the guard's lifetime.
pub(crate) unsafe fn set_driver_state_guarded(state: &mut DriverState) -> DriverStateGuard {
    unsafe { set_driver_state(state) };
    DriverStateGuard(())
}

/// Access the thread-local driver state. Panics if called outside the executor.
///
/// # Safety
///
/// This function is safe to call because:
/// 1. The pointer is always set before polling and cleared after
/// 2. Single-threaded execution means no concurrent access
/// 3. NonNull provides a runtime non-null check in debug builds
pub(crate) fn with_state<R>(f: impl FnOnce(&mut Driver, &mut Executor) -> R) -> R {
    let opt_non_null = CURRENT_DRIVER.with(|c| c.get());
    let mut non_null = opt_non_null.expect("called outside executor");

    let state = unsafe { non_null.as_mut() };
    let driver = unsafe { &mut *state.driver.as_mut() };
    let executor = unsafe { &mut *state.executor.as_mut() };
    f(driver, executor)
}

/// Access the thread-local driver state, returning `None` if called outside the executor.
pub(crate) fn try_with_state<R>(f: impl FnOnce(&mut Driver, &mut Executor) -> R) -> Option<R> {
    let opt_non_null = CURRENT_DRIVER.with(|c| c.get());
    let mut non_null = opt_non_null?;

    let state = unsafe { non_null.as_mut() };
    let driver = unsafe { &mut *state.driver.as_mut() };
    let executor = unsafe { &mut *state.executor.as_mut() };
    Some(f(driver, executor))
}

/// Spawn a standalone async task on the current worker thread.
///
/// Unlike connection tasks (which are 1:1 with connections), standalone tasks
/// are not bound to any connection. They run on the same single-threaded
/// executor, can use [`sleep()`](crate::sleep) and [`timeout()`](crate::timeout),
/// and can open and use connections with [`connect`](crate::connect). `on_tick`
/// and `on_notify` run inside the executor, so they can call `spawn`.
///
/// Returns `Err` if called outside the ringline async executor or if the
/// standalone task slab is full.
pub fn spawn(future: impl Future<Output = ()> + 'static) -> io::Result<TaskId> {
    try_with_state(
        |_driver, executor| match executor.standalone_slab.spawn(Box::pin(future)) {
            Some(idx) => {
                executor.ready_queue.push_back(idx | STANDALONE_BIT);
                Ok(TaskId(idx))
            }
            None => Err(io::Error::other("standalone task slab exhausted")),
        },
    )
    .unwrap_or_else(|| Err(io::Error::other("called outside executor")))
}

impl TaskId {
    /// Cancel a standalone task. Drops the future immediately, freeing
    /// the slab slot.
    ///
    /// A `TaskId` carries no generation: once the task has completed, its
    /// slot can be reused, and cancelling the old id cancels whatever task
    /// now holds the slot. Call this only while the task is known to be
    /// running; [`JoinHandle::abort`] checks for you.
    ///
    /// Must be called from within the ringline executor (i.e., from a
    /// connection task or standalone task). Panics otherwise.
    ///
    /// Any pending timers owned by the dropped future are cancelled
    /// via their `Drop` impl. Stale entries in the ready queue are
    /// silently skipped when the executor encounters them.
    pub fn cancel(self) {
        with_state(|_driver, executor| {
            executor.standalone_slab.remove(self.0);
        });
    }
}

// ── JoinHandle ──────────────────────────────────────────────────────

/// Shared state between a spawned wrapper future and its [`JoinHandle`].
struct JoinState<T> {
    /// The task's outcome, written by the wrapper when it completes or panics.
    result: Option<Result<T, crate::JoinError>>,
    /// Raw task ID of the task awaiting this handle (includes `STANDALONE_BIT`
    /// for standalone tasks). Set by `JoinHandle::poll` when it returns `Pending`.
    waiter: Option<u32>,
    /// True once the outcome is decided: completed, panicked or cancelled.
    finished: bool,
}

impl<T> JoinState<T> {
    /// Record the outcome, if none is recorded yet, and return the waiter to
    /// wake.
    fn finish(&mut self, result: Result<T, crate::JoinError>) -> Option<u32> {
        if self.finished {
            return None;
        }
        self.finished = true;
        self.result = Some(result);
        self.waiter.take()
    }
}

/// Owned by a `spawn_with_handle` task. Dropping the task before it finished
/// (abort, `TaskId::cancel`, worker shutdown) resolves the handle as cancelled
/// and wakes its waiter.
struct CancelOnDrop<T> {
    state: Rc<RefCell<JoinState<T>>>,
}

impl<T> Drop for CancelOnDrop<T> {
    fn drop(&mut self) {
        let Ok(mut s) = self.state.try_borrow_mut() else {
            return;
        };
        let waiter = s.finish(Err(crate::JoinError::cancelled()));
        drop(s);
        if let Some(waiter_id) = waiter {
            // `None` outside the executor (worker teardown), where there is no
            // task left to wake.
            let _ = try_with_state(|_driver, executor| {
                executor.wake_task(waiter_id);
            });
        }
    }
}

/// Handle to a spawned task's return value.
///
/// Obtained from [`spawn_with_handle()`]. Implements [`Future`]: awaiting it
/// yields `Ok` with the task's return value once the task completes, or `Err`
/// with a [`JoinError`](crate::JoinError) if the task panicked or was
/// aborted.
///
/// # Drop semantics
///
/// Dropping a `JoinHandle` without awaiting it **detaches** the task: the
/// task continues running but its result is discarded. This matches tokio's
/// semantics.
///
/// # Abort
///
/// [`abort()`](Self::abort) cancels the spawned task. The handle then resolves
/// to a [`JoinError`](crate::JoinError) for which
/// [`is_cancelled`](crate::JoinError::is_cancelled) is true.
pub struct JoinHandle<T> {
    state: Rc<RefCell<JoinState<T>>>,
    task_id: TaskId,
}

impl<T> JoinHandle<T> {
    /// Get the underlying [`TaskId`].
    pub fn id(&self) -> TaskId {
        self.task_id
    }

    /// Cancel the spawned task.
    ///
    /// The future is dropped immediately and its slab slot is freed. Awaiting
    /// the handle then resolves to a cancelled [`JoinError`](crate::JoinError).
    /// If the task has already finished, this does nothing and the handle
    /// keeps its outcome.
    pub fn abort(&self) {
        if self.state.borrow().finished {
            return;
        }
        self.task_id.cancel();
    }
}

impl<T: 'static> Future for JoinHandle<T> {
    type Output = Result<T, crate::JoinError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut s = self.state.borrow_mut();
        if let Some(result) = s.result.take() {
            return Poll::Ready(result);
        }
        // Register this task as the waiter so the child can wake us.
        s.waiter = Some(CURRENT_TASK_ID.with(|c| c.get()));
        Poll::Pending
    }
}

pin_project_lite::pin_project! {
    /// Polls `inner`, and resolves to `Err` with the payload if a poll panics.
    struct CatchUnwind<F> {
        #[pin]
        inner: F,
    }
}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = Result<F::Output, Box<dyn std::any::Any + Send>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.project().inner;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx))) {
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

/// Spawn a standalone async task and return a handle to await its result.
///
/// Like [`spawn()`], the future runs on the current worker's single-threaded
/// executor. The returned [`JoinHandle<T>`] is a future: awaiting it yields
/// `Ok` with the task's return value once it completes, or a
/// [`JoinError`](crate::JoinError).
///
/// # Detach semantics
///
/// Dropping the handle without awaiting it detaches the task: the task keeps
/// running but its result is silently discarded.
///
/// # Errors
///
/// Returns `Err` if called outside the ringline executor or if the standalone
/// task slab is exhausted.
///
/// # Panics in the spawned task
///
/// A panic in the spawned future resolves the handle to a
/// [`JoinError`](crate::JoinError) whose `is_panic` is true, and is handled
/// under the runtime's [`TaskPanicPolicy`](crate::TaskPanicPolicy).
pub fn spawn_with_handle<T: 'static>(
    future: impl Future<Output = T> + 'static,
) -> io::Result<JoinHandle<T>> {
    let state = Rc::new(RefCell::new(JoinState {
        result: None,
        waiter: None,
        finished: false,
    }));
    let state_for_wrapper = Rc::clone(&state);
    // Created outside the async block so that dropping the task before its
    // first poll still drops the guard.
    let cancel_guard = CancelOnDrop {
        state: Rc::clone(&state),
    };

    let wrapper = async move {
        let _cancel_guard = cancel_guard;
        let result = match (CatchUnwind { inner: future }).await {
            Ok(value) => Ok(value),
            Err(payload) => {
                with_state(|driver, _executor| {
                    driver
                        .panic_reporter
                        .report("spawn_with_handle task", &*payload);
                });
                Err(crate::JoinError::panicked(payload))
            }
        };
        let waiter = state_for_wrapper.borrow_mut().finish(result);
        // The borrow is released before calling with_state, which guards
        // against a re-entrant borrow in the wakeup path.
        if let Some(waiter_id) = waiter {
            with_state(|_driver, executor| {
                executor.wake_task(waiter_id);
            });
        }
    };

    try_with_state(
        |_driver, executor| match executor.standalone_slab.spawn(Box::pin(wrapper)) {
            Some(idx) => {
                executor.ready_queue.push_back(idx | STANDALONE_BIT);
                Ok(JoinHandle {
                    state: Rc::clone(&state),
                    task_id: TaskId(idx),
                })
            }
            None => Err(io::Error::other("standalone task slab exhausted")),
        },
    )
    .unwrap_or_else(|| Err(io::Error::other("called outside executor")))
}

/// Offload a blocking closure to the dedicated blocking thread pool.
///
/// The closure runs on a low-priority background thread (`SCHED_IDLE`),
/// keeping the io_uring event loop unblocked. Returns a future that resolves
/// to `Ok` with the closure's return value, or to `Err` with a
/// [`JoinError`](crate::JoinError) if the closure panicked. A panic does not
/// end the pool thread, and is handled under the runtime's
/// [`TaskPanicPolicy`](crate::TaskPanicPolicy).
///
/// # Errors
///
/// Returns `Err` if called outside the ringline executor or if the blocking
/// pool is not configured (`blocking_threads = 0`).
pub fn spawn_blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> io::Result<BlockingJoinHandle<T>> {
    try_with_state(|driver, executor| {
        let pool = driver
            .blocking_pool
            .as_ref()
            .ok_or_else(|| io::Error::other("blocking pool not configured"))?;
        let blocking_tx = driver
            .blocking_tx
            .as_ref()
            .ok_or_else(|| io::Error::other("blocking pool not configured"))?;

        let request_id = executor.next_blocking_id;
        executor.next_blocking_id += 1;

        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor
            .pending_blocking
            .insert(request_id, (task_id, None));

        let work = Box::new(move || -> Box<dyn std::any::Any + Send> { Box::new(f()) });

        if pool
            .request_tx
            .send(crate::blocking::BlockingRequest {
                work,
                request_id,
                response_tx: blocking_tx.clone(),
                wake_handle: driver.wake_handle,
            })
            .is_err()
        {
            executor.pending_blocking.remove(&request_id);
            return Err(io::Error::other("blocking pool shut down"));
        }

        Ok(BlockingJoinHandle {
            request_id,
            owner: crate::runtime::waker::current_worker(),
            _phantom: std::marker::PhantomData,
        })
    })
    .unwrap_or_else(|| Err(io::Error::other("called outside executor")))
}

/// Future returned by [`spawn_blocking()`]. Resolves to the closure's return
/// value, or to a [`JoinError`](crate::JoinError) if the closure panicked.
///
/// Dropping the handle does not stop the closure. Dropped on the worker that
/// created it, the handle releases the closure's result: at once if it has
/// arrived, otherwise when it arrives. Dropped on another thread, the result
/// is held until that worker exits.
pub struct BlockingJoinHandle<T> {
    request_id: u64,
    /// The worker whose executor holds the `pending_blocking` entry.
    owner: u32,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Drop for BlockingJoinHandle<T> {
    fn drop(&mut self) {
        // Only the owning worker's executor holds the entry. Dropped
        // elsewhere (the handle is `Send`), it stays there.
        if crate::runtime::waker::current_worker() != self.owner {
            return;
        }
        // A result that arrives after the entry is removed is dropped on
        // delivery. One that already arrived is dropped here, after the
        // executor borrow ends, since its destructor is user code.
        let removed =
            try_with_state(|_driver, executor| executor.pending_blocking.remove(&self.request_id));
        match removed {
            Some(entry) => drop(entry),
            // Outside a task poll (a connection's task dropped at teardown).
            None => {
                crate::runtime::defer_release(crate::runtime::Orphan::Blocking(self.request_id))
            }
        }
    }
}

impl<T: 'static> Future for BlockingJoinHandle<T> {
    type Output = Result<T, crate::JoinError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|_driver, executor| {
            if let Some((_, slot)) = executor.pending_blocking.get_mut(&self.request_id)
                && let Some(boxed) = slot.take()
            {
                executor.pending_blocking.remove(&self.request_id);
                return Poll::Ready(match boxed {
                    Ok(value) => Ok(*value
                        .downcast::<T>()
                        .expect("type mismatch in BlockingJoinHandle")),
                    Err(payload) => Err(crate::JoinError::panicked(payload)),
                });
            }
            Poll::Pending
        })
    }
}

/// Begin an outbound TCP connection.
///
/// Returns a builder. Nothing is submitted until the builder is awaited;
/// [`BackpressuredSendFuture`] has the same contract. Awaiting resolves to an
/// owned [`Connection`], the same type that `on_accept` receives.
///
/// ```ignore
/// let conn = connect(addr).await?;
/// let conn = connect(addr).timeout(Duration::from_millis(500)).await?;
/// let conn = connect(addr).tls("example.com").await?;
/// let conn = connect(addr).tls("example.com").timeout(d).await?;
/// ```
///
/// Callable from a connection task, a task spawned with [`spawn()`], or an
/// [`on_start`](crate::AsyncEventHandler::on_start) future.
///
/// # Receiving
///
/// On io_uring a plaintext connection, from this function, from
/// [`connect_unix`] or accepted on a plaintext listener, receives directly
/// into its own accumulator. When a read
/// parks (`with_data`, `with_bytes`, `recv_ready`, or a
/// [`ConnStream`](crate::ConnStream) read), the runtime submits a one-shot
/// receive whose destination is the free space of the connection's
/// accumulator, so the received bytes are not copied out of a ring buffer.
/// The receive asks for all the free space. With nothing buffered, the
/// connection receives into its own buffer of
/// [`ConfigBuilder::recv_direct_region`](crate::ConfigBuilder::recv_direct_region)
/// bytes, or of the initial accumulator capacity if that is larger and at
/// most twice the region. With part of a message buffered, the buffer grows
/// when less than the parser's [`ParseResult::NeedAtLeast`] value, or less
/// than half of `recv_direct_region`, is free: to hold the rest of the
/// message when that value is at least `recv_direct_region`, and otherwise to
/// the larger of the receive size and the buffered bytes plus
/// `recv_direct_region`. The receive size is `recv_direct_region`, or for a
/// connection whose largest [`ParseResult::Consumed`] value from `with_data`
/// or `with_bytes` so far is `m`, the larger of `recv_direct_region` and
/// `min(4m, m + 4 * recv_direct_region)`. A buffer larger than the
/// connection's own is borrowed from the worker's free buffers
/// ([`ConfigBuilder::recv_direct_pool_max`](crate::ConfigBuilder::recv_direct_pool_max)).
///
/// `try_with_data` does not park or arm a receive. While a receive is in
/// flight, for example after a parked read was dropped, the buffered bytes
/// are in that receive's buffer and `try_with_data` returns `None`.
///
/// `forward_to_conn` sends from the accumulator (see
/// [`RecvHalf::forward_to_conn`]).
///
/// A receive into the accumulator is armed only when a read parks.
/// A poll for `POLLRDHUP`, armed when the connection opens, completes on a
/// FIN, a reset or a socket error from the peer, and not on data. If no
/// receive is in flight then, a one-byte `MSG_PEEK` receive checks the
/// socket. When no bytes are queued in the socket and none are buffered in
/// the accumulator, the connection closes as it would under a parked read,
/// and [`Connection::is_alive`] returns `false`. Otherwise the connection stays
/// open, and the bytes reach the next reads in order. Once they have been
/// read, the end of the stream closes the connection, whether or not a read
/// parks again, and a reset is reported to the read as an error. If the poll,
/// or the peek it triggers, cannot be submitted (counted in
/// `ring::RECV_ARM_FAILURES`), it is submitted again before the worker next
/// waits for completions. Until then, a receive that a parked read arms also
/// sees the end.
///
/// TCP does not tell a half-close from a close: a FIN closes the connection
/// even when the task only sends, and sends made once the Close is submitted
/// (after queued sends drain) fail with `NotConnected`.
///
/// A TLS connection receives ciphertext directly too, up to
/// `recv_direct_region` bytes per receive. With the default engine the
/// destination is the buffer rustls processes records in, so no copy is made
/// before decryption; with the `tls-buffered` feature it is a buffer rustls
/// copies the ciphertext from. Decrypted plaintext goes to the accumulator.
/// During the handshake a receive is re-armed after each completion. After
/// it, a receive is armed when a read parks, as on a plaintext connection.
/// When the `POLLRDHUP` poll fires because the peer sent a FIN or reset while
/// nothing reads, the runtime arms one and re-arms it after each completion
/// until the receive reads the close_notify, returns 0 at the FIN, or fails.
/// The poll does not fire on a close_notify sent without a FIN; the alert is
/// read when a receive next completes. On mio every connection reads into its
/// accumulator.
///
/// # Concurrency
///
/// Submission happens on the first poll, so two builders awaited one after the
/// other run serially:
///
/// ```ignore
/// let a = connect(x);            // nothing submitted
/// let b = connect(y);            // nothing submitted
/// let (ca, cb) = (a.await?, b.await?);   // serial: A then B
/// ```
///
/// To run two connects concurrently, pass both builders to [`join`](crate::join).
/// `join` polls each builder once, which submits both, and then waits for both:
///
/// ```ignore
/// let (a, b) = join(connect(x), connect(y)).await;
/// let (ca, cb) = (a?, b?);
/// ```
///
/// [`join`](crate::join) and [`join3`](crate::join3) take two and three
/// futures. For more, spawn each connect with
/// [`spawn_with_handle`](crate::spawn_with_handle) and await the handles.
///
/// # Panics
///
/// Awaiting outside the ringline async executor panics.
pub fn connect(addr: SocketAddr) -> TcpConnect {
    TcpConnect {
        addr,
        server_name: None,
        timeout: None,
    }
}

/// Begin an outbound Unix-domain connection.
///
/// See [`connect`] for the submission and concurrency contract; it is the same
/// here. This builder has no `tls` method: the driver terminates TLS on
/// `SocketAddr` connections only, so TLS over a Unix socket cannot be
/// expressed.
///
/// ```ignore
/// let conn = connect_unix(path).await?;
/// let conn = connect_unix(path).timeout(Duration::from_millis(500)).await?;
/// ```
///
/// # Panics
///
/// Awaiting outside the ringline async executor panics.
pub fn connect_unix(path: impl AsRef<std::path::Path>) -> UnixConnect {
    UnixConnect {
        path: path.as_ref().to_path_buf(),
        timeout: None,
    }
}

/// Builder for an outbound TCP connection, from [`connect`].
///
/// Nothing is submitted until the builder is awaited. The transport is fixed by
/// the function that produced the builder; TLS and the timeout are set by
/// methods on it (#528).
#[must_use = "a connect builder does nothing until awaited"]
pub struct TcpConnect {
    addr: SocketAddr,
    server_name: Option<String>,
    timeout: Option<Duration>,
}

impl TcpConnect {
    /// Terminate TLS on this connection, with `server_name` as the SNI hostname.
    ///
    /// Requires a client configuration from
    /// [`ConfigBuilder::tls_client`](crate::ConfigBuilder::tls_client); without
    /// one the connect fails when awaited.
    pub fn tls(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = Some(server_name.into());
        self
    }

    /// Fail the connect if it has not completed within `timeout`.
    ///
    /// On a TLS connection the window covers the TCP connect only, not the
    /// handshake that follows.
    ///
    /// The duration is truncated to whole milliseconds, because both backends
    /// arm in milliseconds. `Duration::ZERO` arms a timeout that fires
    /// immediately rather than meaning "no timeout"; omit the call for that.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// Builder for an outbound Unix-domain connection, from [`connect_unix`].
///
/// Nothing is submitted until the builder is awaited. There is no `tls` method;
/// see [`connect_unix`].
#[must_use = "a connect builder does nothing until awaited"]
pub struct UnixConnect {
    path: std::path::PathBuf,
    timeout: Option<Duration>,
}

impl UnixConnect {
    /// Fail the connect if it has not completed within `timeout`.
    ///
    /// See [`TcpConnect::timeout`] for how the duration is treated.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl std::future::IntoFuture for TcpConnect {
    type Output = io::Result<Connection>;
    type IntoFuture = ConnectFuture;

    fn into_future(self) -> ConnectFuture {
        ConnectFuture {
            state: ConnectState::Unsubmitted {
                target: ConnectTarget::Tcp {
                    addr: self.addr,
                    server_name: self.server_name,
                },
                timeout: self.timeout,
            },
        }
    }
}

impl std::future::IntoFuture for UnixConnect {
    type Output = io::Result<Connection>;
    type IntoFuture = ConnectFuture;

    fn into_future(self) -> ConnectFuture {
        ConnectFuture {
            state: ConnectState::Unsubmitted {
                target: ConnectTarget::Unix { path: self.path },
                timeout: self.timeout,
            },
        }
    }
}

/// What a [`ConnectFuture`] will submit on its first poll.
enum ConnectTarget {
    Tcp {
        addr: SocketAddr,
        server_name: Option<String>,
    },
    Unix {
        path: std::path::PathBuf,
    },
}

// ── DNS Resolution ──────────────────────────────────────────────────

/// Resolve a hostname to a [`SocketAddr`] using the dedicated resolver pool.
///
/// Performs `getaddrinfo` on a background thread, keeping the io_uring event
/// loop unblocked. Returns the first resolved address.
///
/// # Errors
///
/// Returns `Err` if called outside the ringline executor, the resolver pool
/// is not configured (`resolver_threads = 0`), or `getaddrinfo` fails.
pub fn resolve(host: &str, port: u16) -> io::Result<ResolveFuture> {
    let host = host.to_string();
    try_with_state(|driver, executor| {
        let resolver = driver
            .resolver
            .as_ref()
            .ok_or_else(|| io::Error::other("resolver pool not configured"))?;
        let resolve_tx = driver
            .resolve_tx
            .as_ref()
            .ok_or_else(|| io::Error::other("resolver pool not configured"))?;

        let request_id = executor.next_resolve_id;
        executor.next_resolve_id += 1;

        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor
            .pending_resolves
            .insert(request_id, (task_id, None));

        if resolver
            .request_tx
            .send(crate::resolver::ResolveRequest {
                host,
                port,
                request_id,
                response_tx: resolve_tx.clone(),
                wake_handle: driver.wake_handle,
            })
            .is_err()
        {
            executor.pending_resolves.remove(&request_id);
            return Err(io::Error::other("resolver pool shut down"));
        }

        Ok(ResolveFuture {
            request_id,
            owner: crate::runtime::waker::current_worker(),
        })
    })
    .unwrap_or_else(|| Err(io::Error::other("called outside executor")))
}

/// Future returned by [`resolve()`]. Resolves to a [`SocketAddr`].
pub struct ResolveFuture {
    request_id: u64,
    /// The worker whose executor holds the `pending_resolves` entry.
    owner: u32,
}

impl Drop for ResolveFuture {
    fn drop(&mut self) {
        // Only the owning worker's executor holds the entry. Dropped
        // elsewhere (the future is `Send`), it stays there.
        if crate::runtime::waker::current_worker() != self.owner {
            return;
        }
        // A result that arrives after the entry is removed is dropped on
        // delivery.
        let removed =
            try_with_state(|_driver, executor| executor.pending_resolves.remove(&self.request_id));
        match removed {
            Some(entry) => drop(entry),
            // Outside a task poll (a connection's task dropped at teardown).
            None => crate::runtime::defer_release(crate::runtime::Orphan::Resolve(self.request_id)),
        }
    }
}

impl Future for ResolveFuture {
    type Output = io::Result<std::net::SocketAddr>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|_driver, executor| {
            if let Some((_, slot)) = executor.pending_resolves.get_mut(&self.request_id)
                && let Some(result) = slot.take()
            {
                executor.pending_resolves.remove(&self.request_id);
                return Poll::Ready(result);
            }
            Poll::Pending
        })
    }
}

/// Request graceful shutdown of the worker event loop from any async task.
///
/// Callable from any task, from
/// [`AsyncEventHandler::on_start()`](crate::AsyncEventHandler::on_start) futures,
/// and from `on_tick` and `on_notify`.
///
/// Returns `Err` if called outside the ringline async executor.
pub fn request_shutdown() -> io::Result<()> {
    try_with_state(|driver, _| {
        let mut ctx = driver.make_ctx();
        ctx.request_shutdown();
    })
    .ok_or_else(|| io::Error::other("called outside executor"))
}

/// A connection's slot index and generation, for runtime internals.
///
/// `Copy`, and `!Send` for the same reason as [`Connection`]: the index means
/// something only on the worker that owns the connection. Applications hold a
/// [`Connection`] or its halves.
#[derive(Clone, Copy)]
pub(crate) struct ConnCtx {
    pub(crate) conn_index: u32,
    pub(crate) generation: u32,
    /// Pins the handle to its owning worker thread — see [`Connection`].
    /// `PhantomData<*const ()>` is how a type opts out of `Send`/`Sync` on
    /// stable Rust; `impl !Send` is still nightly-only (rust-lang/rust#68318).
    pub(crate) _not_send: PhantomData<*const ()>,
}

/// The connection's `recv_buffered` count at the start of a reporting
/// reader's poll, taken after the generation check
/// (`docs/recv-arrival-times-design.md`).
fn arrival_mark(driver: &Driver, conn_index: u32) -> usize {
    driver.recv_buffered(conn_index)
}

/// Settle a reporting reader's resolving poll in the connection's arrival
/// log. `before` is the poll's [`arrival_mark`]; `report` is false when the
/// call resolved without reporting (nothing buffered for `try_with_data`, end
/// of stream, or a close), which leaves `recv_arrival` at
/// `None`.
fn arrival_settle(driver: &mut Driver, conn_index: u32, before: usize, report: bool) {
    let after = driver.recv_buffered(conn_index);
    driver.arrival[conn_index as usize].settle_read(before, after, report);
}

/// Bytes a zero-copy `forward_recv_buf` detached from the accumulator during
/// the closure that just ran, cleared as it is read.
///
/// The forward already removed them, so the delivery path must advance by what
/// the closure reported consuming *minus* this. Read it unconditionally after
/// every closure call, including the ones that report consuming nothing, or a
/// stale count would shorten a later consume.
#[cfg(has_io_uring)]
#[inline]
fn take_forward_zc_consumed(driver: &mut crate::backend::Driver, conn_index: u32) -> usize {
    std::mem::replace(&mut driver.forward_zc_consumed[conn_index as usize], 0) as usize
}

/// Zero-copy send guard over a detached slice of a connection's receive
/// accumulator.
///
/// `forward_recv_buf` uses this when the bytes it was handed are
/// accumulator-backed rather than a single kernel buffer. Holding the `Bytes`
/// keeps the allocation alive until the kernel posts the ZC notification, so
/// the message reaches the wire without being copied into a send-pool slot.
/// The memory is a plain heap allocation, not a registered region.
#[cfg(has_io_uring)]
struct AccumulatorGuard(bytes::Bytes);

#[cfg(has_io_uring)]
impl crate::guard::SendGuard for AccumulatorGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> crate::buffer::fixed::RegionId {
        crate::buffer::fixed::RegionId::UNREGISTERED
    }
}

impl ConnCtx {
    /// Create a new ConnCtx for the given connection.
    pub(crate) fn new(conn_index: u32, generation: u32) -> Self {
        ConnCtx {
            conn_index,
            generation,
            _not_send: PhantomData,
        }
    }

    /// Returns the connection slot index. Useful for indexing into per-connection arrays.
    pub(crate) fn index(&self) -> usize {
        self.conn_index as usize
    }

    /// See [`Connection::offer_for_park`].
    pub(crate) fn offer_for_park(&self, state: Option<crate::park::ParkState>) {
        let _ = try_with_state(|driver, _| {
            #[cfg(has_io_uring)]
            {
                if driver.connections.generation(self.conn_index) == self.generation {
                    driver.offer_park(self.conn_index, state);
                }
            }
            #[cfg(not(has_io_uring))]
            {
                let _ = (driver, state);
            }
        });
    }

    /// Returns the `ConnToken` for this connection.
    pub(crate) fn token(&self) -> ConnToken {
        ConnToken::new(self.conn_index, self.generation)
    }

    // ── Recv ─────────────────────────────────────────────────────────

    /// See [`Connection::with_data`].
    pub(crate) fn with_data<F: FnMut(&[u8]) -> ParseResult>(&self, f: F) -> WithDataFuture<F> {
        WithDataFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            f: Some(f),
        }
    }

    /// See [`Connection::with_data_result`].
    pub(crate) fn with_data_result<F: FnMut(&[u8]) -> ParseResult>(
        &self,
        f: F,
    ) -> WithDataResultFuture<F> {
        WithDataResultFuture {
            inner: self.with_data(f),
        }
    }

    /// See [`Connection::with_bytes`].
    pub(crate) fn with_bytes<F: FnMut(Bytes) -> ParseResult>(&self, f: F) -> WithBytesFuture<F> {
        WithBytesFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            f: Some(f),
        }
    }

    /// Returns a future that becomes ready when received bytes are buffered
    /// for the connection, or when the connection has finished receiving.
    pub(crate) fn recv_ready(&self) -> RecvReadyFuture {
        RecvReadyFuture {
            conn_index: self.conn_index,
            generation: self.generation,
        }
    }

    /// Crate-internal body of [`Connection::recv_arrival`]; see that method.
    pub(crate) fn recv_arrival(&self) -> Option<crate::RecvArrival> {
        try_with_state(|driver, _| {
            if driver.connections.generation(self.conn_index) != self.generation {
                return None;
            }
            driver.arrival[self.conn_index as usize].latest()
        })
        .flatten()
    }

    /// See [`Connection::try_with_data`].
    pub(crate) fn try_with_data<F: FnOnce(&[u8]) -> ParseResult>(
        &self,
        f: F,
    ) -> Option<ParseResult> {
        with_state(|driver, _executor| {
            // A stale handle must not read the slot's new occupant — this both
            // hands the caller another connection's bytes and advances that
            // connection's accumulator past them. See #429.
            if driver.connections.generation(self.conn_index) != self.generation {
                return None;
            }
            let before = arrival_mark(driver, self.conn_index);
            let data = driver.accumulators.data(self.conn_index);
            if data.is_empty() {
                arrival_settle(driver, self.conn_index, before, false);
                return None;
            }
            let result = {
                #[cfg(has_io_uring)]
                let _cb = ReaderCallback::enter(self.conn_index);
                f(data)
            };
            #[cfg(has_io_uring)]
            let forwarded = take_forward_zc_consumed(driver, self.conn_index);
            #[cfg(not(has_io_uring))]
            let forwarded = 0usize;
            if let ParseResult::Consumed(consumed) = result {
                driver
                    .accumulators
                    .consume(self.conn_index, consumed.saturating_sub(forwarded));
            }
            arrival_settle(driver, self.conn_index, before, true);
            Some(result)
        })
    }

    // ── Send (synchronous / fire-and-forget) ─────────────────────────

    /// See [`SendHalf::send_nowait`].
    pub(crate) fn send_nowait(&self, data: &[u8]) -> io::Result<()> {
        with_state(|driver, _| {
            let mut ctx = driver.make_ctx();
            ctx.send(self.token(), data)
        })
    }

    /// Crate-internal body of [`SendHalf::forward_recv_buf`]; see that method
    /// for behaviour and errors.
    pub(crate) fn forward_recv_buf(&self, data: &[u8]) -> io::Result<()> {
        with_state(|driver, _| {
            #[cfg_attr(not(has_io_uring), allow(unused_variables))]
            let conn_index = self.conn_index;

            // Before the zero-copy branch: it acts on the slot's accumulator,
            // which belongs to whichever connection holds the slot now. The
            // same refusal as the copy path's `send` (#544).
            if driver.connections.generation(conn_index) != self.generation {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "stale connection",
                ));
            }
            // Once the Close is submitted, the copy path's `send` refuses
            // without committing anything; the zero-copy branch would queue
            // a send that is never driven.
            #[cfg(has_io_uring)]
            let closing = driver.send_queues[conn_index as usize].close_submitted;

            // The bytes are in the accumulator. Copying the whole message into
            // a send-pool slot is what made ringline lose to its own mio
            // fallback at 16 KiB (#397) — 93.9% of forwards took this path,
            // averaging 15 KB copied per operation. Detach the accumulator
            // instead (O(1) freeze) and send it under a guard, so the message
            // reaches the wire uncopied.
            //
            // Only when the forward covers the whole accumulator: then the
            // detach is a single `take_frozen` with no remainder to put back,
            // and "forwarded" and "consumed" cannot disagree about which bytes
            // went out. Anything else keeps the copy path.
            #[cfg(has_io_uring)]
            if !closing {
                let whole = {
                    let acc = driver.accumulators.data(conn_index);
                    !acc.is_empty()
                        && acc.len() == data.len()
                        && std::ptr::eq(acc.as_ptr(), data.as_ptr())
                };
                if whole {
                    let frozen = driver.accumulators.take_frozen(conn_index);
                    debug_assert_eq!(frozen.len(), data.len());
                    // The delivery future must not also advance past these
                    // bytes — they are no longer in the accumulator.
                    driver.forward_zc_consumed[conn_index as usize] = frozen.len() as u32;
                    let token = self.token();
                    // A refused send drops the guard; this handle puts the
                    // bytes back, so nothing is committed on `Err`.
                    let keep = frozen.clone();
                    // `guard()` honours `send_zc_threshold`, so a forward below
                    // it still folds into a copy exactly as before.
                    let result = driver
                        .make_ctx()
                        .send_parts(token)
                        .guard(crate::guard::GuardBox::new(AccumulatorGuard(frozen)))
                        .submit();
                    if result.is_err() {
                        driver.accumulators.put_back(conn_index, keep);
                        driver.forward_zc_consumed[conn_index as usize] = 0;
                    }
                    return result;
                }
            }

            // Not the whole accumulator, or mio: copy send.
            let mut ctx = driver.make_ctx();
            ctx.send(self.token(), data)
        })
    }

    /// A forward from this connection to the sink connection that sends from
    /// this connection's accumulator. Refuses, resolving on the first poll: a
    /// forward already running from this connection (`EBUSY`), a stale source
    /// or sink (`EPIPE`) and a TLS sink (`EPROTOTYPE`).
    #[cfg(has_io_uring)]
    pub(crate) fn forward_to<'a>(
        &self,
        sink_index: u32,
        sink_generation: u32,
        len: usize,
    ) -> ForwardFuture<'a> {
        let refusal = with_state(|driver, _| {
            let refusal = if driver.connections.generation(self.conn_index) != self.generation {
                Some(libc::EPIPE)
            } else if driver
                .connections
                .get(self.conn_index)
                .is_some_and(|c| c.direct_forwarding)
            {
                Some(libc::EBUSY)
            } else if driver.connections.generation(sink_index) != sink_generation {
                Some(libc::EPIPE)
            } else if driver.tls_table.as_ref().is_some_and(|t| t.has(sink_index)) {
                Some(libc::EPROTOTYPE)
            } else {
                None
            };
            if refusal.is_none()
                && let Some(cs) = driver.connections.get_mut(self.conn_index)
            {
                cs.direct_forwarding = true;
            }
            refusal
        });
        ForwardFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            refused: refusal,
            direct: refusal.is_none().then_some(DirectForward {
                sink_index,
                sink_generation,
                len: len as u64,
                forwarded: 0,
                in_flight: None,
            }),
            _borrow: PhantomData,
        }
    }

    /// See [`RecvHalf::forward_to_conn`].
    #[cfg(not(has_io_uring))]
    pub(crate) fn forward_to<'a>(
        &self,
        sink_index: u32,
        sink_generation: u32,
        len: usize,
    ) -> ForwardFuture<'a> {
        let source = self.conn_index;
        let generation = self.generation;
        let armed = with_state(|driver, _executor| {
            let src = source as usize;
            if driver.connections.generation(source) != generation
                || driver.connections.generation(sink_index) != sink_generation
            {
                return Err(libc::EPIPE);
            }
            // Returned, not asserted: `EBUSY` is a documented error of this
            // function, and a `debug_assert` here made that documented path
            // unreachable in every debug build — which is every test run and
            // all of CI. A caller matching on EBUSY worked in release and
            // panicked under test.
            if driver.forward_conn[src].is_some() {
                return Err(libc::EBUSY);
            }
            // A forward writes bytes onto the sink as they are — nothing on
            // this path encrypts. Queuing plaintext on a TLS connection would
            // put it on the wire in the clear, so refuse rather than do it.
            if driver.tls_table.as_ref().is_some_and(|t| t.has(sink_index)) {
                return Err(libc::EPROTOTYPE);
            }
            driver.forward_conn[src] = Some(crate::backend::mio::driver::MioForwardState {
                sink_index,
                sink_generation,
                len: len as u64,
                forwarded: 0,
            });
            driver.forward_feeder[sink_index as usize] = Some(source);
            // A forward that ended with its slot's previous occupant may have
            // left a result nobody took; it is not this forward's.
            driver.forward_done[src] = None;

            // Bytes the connection already received but the handler never
            // consumed are part of the forward, as on io_uring, where the
            // forward sends from the accumulator. This
            // also settles a forward that is satisfied on the spot (`len == 0`,
            // or the accumulator already covered it), which must not park for a
            // read that is never coming.
            driver.forward_take_accumulated(source);
            Ok(())
        });
        ForwardFuture {
            conn_index: source,
            generation,
            refused: armed.err(),
            _borrow: PhantomData,
        }
    }

    /// See [`SendHalf::send_parts`].
    #[cfg(has_io_uring)]
    pub(crate) fn send_parts(&self) -> AsyncSendBuilder {
        AsyncSendBuilder {
            token: self.token(),
        }
    }

    // ── Send (awaitable) ─────────────────────────────────────────────

    /// See [`SendHalf::send`].
    pub(crate) fn send(&self, data: &[u8]) -> io::Result<SendFuture> {
        with_state(|driver, executor| {
            let id = executor.register_send(self.conn_index);
            let mut ctx = driver.make_ctx();
            if let Err(e) = ctx.send_awaited(self.token(), data, id) {
                executor.withdraw_send(id);
                return Err(e);
            }
            Ok(SendFuture::pending(self.conn_index, self.generation, id))
        })
    }

    /// See [`SendHalf::send_backpressured`].
    pub(crate) fn send_backpressured<'a>(&self, data: &'a [u8]) -> BackpressuredSendFuture<'a> {
        BackpressuredSendFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            data,
            state: BackpressuredState::Fresh,
        }
    }

    // ── Connect ──────────────────────────────────────────────────────

    // ── Send chain ────────────────────────────────────────────────────

    /// Build an IO_LINK chained send on this connection (fire-and-forget).
    ///
    /// The closure receives a [`SendChainBuilder`](crate::handler::SendChainBuilder) for
    /// constructing linked SQEs. Call `.copy()`, `.parts()...add()` to add SQEs,
    /// then `.finish()` to submit the chain.
    ///
    /// For backpressure-aware chained sending, use `send_chain()`.
    #[cfg(has_io_uring)]
    pub(crate) fn send_chain_nowait<F, R>(&self, f: F) -> R
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> R,
    {
        with_state(|driver, _| {
            let mut ctx = driver.make_ctx();
            let token = ConnToken::new(self.conn_index, self.generation);
            let builder = ctx.send_chain(token);
            f(builder)
        })
    }

    /// Build an IO_LINK chained send and await completion.
    ///
    /// The closure receives a [`SendChainBuilder`](crate::handler::SendChainBuilder) for
    /// constructing linked SQEs. Call `.copy()`, `.parts()...add()` to build the
    /// chain, then `.finish()` to submit it. Returns a [`SendFuture`] that
    /// resolves with the bytes the chain sent, or `Ok(0)` when the closure
    /// submitted nothing.
    ///
    /// For fire-and-forget chained sending, use `send_chain_nowait()`.
    #[cfg(has_io_uring)]
    pub(crate) fn send_chain<F>(&self, f: F) -> io::Result<SendFuture>
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> io::Result<()>,
    {
        with_state(|driver, executor| {
            let id = executor.register_send(self.conn_index);
            let mut ctx = driver.make_ctx();
            let token = ConnToken::new(self.conn_index, self.generation);
            let builder = ctx.send_chain_awaited(token, id);
            if let Err(e) = f(builder) {
                executor.withdraw_send(id);
                return Err(e);
            }
            // A TLS chain is queued as one encrypted send, not through
            // `chain_table`.
            let tls_carried = ctx.tls_chain_carried;
            // A closure that submitted nothing (an empty chain, or no
            // `finish`) sent nothing.
            if !tls_carried && !driver.chain_table.carries(self.conn_index, id) {
                executor.withdraw_send(id);
                return Ok(SendFuture::ready(self.conn_index, self.generation, Ok(0)));
            }
            Ok(SendFuture::pending(self.conn_index, self.generation, id))
        })
    }

    // ── Shutdown / cancel ─────────────────────────────────────────────

    /// Shutdown the write side of the connection (half-close).
    ///
    /// Sends a TCP FIN to the peer. The read side remains open.
    ///
    /// Any `send_backpressured` still waiting for
    /// pool capacity on this connection fails with
    /// [`BrokenPipe`](io::ErrorKind::BrokenPipe) rather than waiting for a
    /// turn it could no longer use. Already-submitted sends are left alone —
    /// their bytes may already be on the way, and the FIN is ordered behind
    /// them. Plain `send` is unaffected either way.
    pub(crate) fn shutdown_write(&self) {
        with_state(|driver, executor| {
            let mut ctx = driver.make_ctx();
            ctx.shutdown_write(self.token());
            executor.fail_waiting_bounded_sends(
                self.conn_index,
                self.generation,
                io::ErrorKind::BrokenPipe,
                "write half is shut down",
            );
        })
    }

    // ── TLS ──────────────────────────────────────────────────────────

    /// See [`Connection::tls_info`].
    pub(crate) fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        with_state(|driver, _| {
            let ctx = driver.make_ctx();
            ctx.tls_info(self.token())
        })
    }

    /// See [`Connection::eof_truncated`].
    pub(crate) fn eof_truncated(&self) -> bool {
        with_state(|driver, _| {
            driver
                .connections
                .get(self.conn_index)
                .filter(|c| c.generation == self.generation)
                .map(|c| matches!(c.read, crate::connection::ReadHalf::Eof { truncated: true }))
                .unwrap_or(false)
        })
    }

    // ── Close / metadata ─────────────────────────────────────────────

    /// See [`SendHalf::close`].
    pub(crate) fn close(&self) {
        let opt_non_null = CURRENT_DRIVER.with(|c| c.get());
        if opt_non_null.is_none() {
            return;
        }
        let mut non_null = opt_non_null.unwrap();
        let state = unsafe { non_null.as_mut() };
        let driver = unsafe { &mut *state.driver.as_mut() };
        if driver.connections.generation(self.conn_index) != self.generation {
            return;
        }
        #[cfg(has_io_uring)]
        driver.close_connection_graceful(self.conn_index);
        #[cfg(not(has_io_uring))]
        driver.close_connection(self.conn_index);
    }

    /// See [`Connection::listener`].
    pub(crate) fn listener(&self) -> Option<crate::ListenerId> {
        with_state(|driver, _| {
            let conn = driver.connections.get(self.conn_index)?;
            if conn.generation != self.generation {
                return None;
            }
            conn.listener
        })
    }

    /// See [`Connection::peer_addr`].
    pub(crate) fn peer_addr(&self) -> Option<crate::connection::PeerAddr> {
        with_state(|driver, _| {
            let conn = driver.connections.get(self.conn_index)?;
            if conn.generation != self.generation {
                return None;
            }
            conn.peer_addr.clone()
        })
    }

    /// See [`Connection::is_outbound`].
    pub(crate) fn is_outbound(&self) -> bool {
        with_state(|driver, _| {
            driver
                .connections
                .get(self.conn_index)
                .map(|cs| cs.generation == self.generation && cs.outbound)
                .unwrap_or(false)
        })
    }

    /// See [`Connection::is_alive`].
    pub(crate) fn is_alive(&self) -> bool {
        // `try_with_state`, not `with_state`: this is reachable from a `Drop`
        // that runs outside a task poll. A connection-bound task is dropped by
        // the teardown path (`remove_connection` on mio, `handle_close` on
        // io_uring), which does not set `CURRENT_DRIVER`, so a panicking
        // accessor there would unwind out of the event loop and kill the
        // worker. `close()` and the half `Drop`s are null-safe for the same
        // reason. Outside the executor the answer is unknowable, and `false`
        // is the safe one: callers use this to decide whether to reuse a
        // connection.
        try_with_state(|driver, _| {
            driver
                .connections
                .get(self.conn_index)
                .map(|cs| cs.generation == self.generation && !cs.close_requested())
                .unwrap_or(false)
        })
        .unwrap_or(false)
    }

    /// See [`Connection::is_recv_direct`].
    pub(crate) fn is_recv_direct(&self) -> bool {
        #[cfg(has_io_uring)]
        {
            try_with_state(|driver, _| {
                driver
                    .connections
                    .get(self.conn_index)
                    .is_some_and(|cs| cs.generation == self.generation && cs.recv_direct)
            })
            .unwrap_or(false)
        }
        #[cfg(not(has_io_uring))]
        {
            false
        }
    }
}

// ── AsyncSendBuilder ─────────────────────────────────────────────────

#[cfg(has_io_uring)]
/// Builder for scatter-gather sends in the async API.
///
/// Wraps `DriverCtx::send_parts()` — call `.copy()` and `.guard()` to add
/// parts, then `.submit()`. This is a synchronous builder; the send is
/// fire-and-forget (no future).
pub struct AsyncSendBuilder {
    token: ConnToken,
}

#[cfg(has_io_uring)]
impl AsyncSendBuilder {
    /// Build and submit the send by calling the provided closure with a
    /// `SendBuilder` from the `DriverCtx`.
    ///
    /// The closure receives the `SendBuilder` and should chain `.copy()` / `.guard()`
    /// calls then call `.submit()`.
    ///
    /// # Example
    /// ```no_run
    /// # fn example(tx: &mut ringline::SendHalf) -> std::io::Result<()> {
    /// tx.send_parts().build(|b| {
    ///     b.copy(b"header").submit()
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build<F>(self, f: F) -> io::Result<()>
    where
        F: FnOnce(crate::handler::SendBuilder<'_, '_>) -> io::Result<()>,
    {
        with_state(|driver, _| {
            let mut ctx = driver.make_ctx();
            let builder = ctx.send_parts(self.token);
            f(builder)
        })
    }

    /// Submit a scatter-gather send from pre-classified `SendPart`s.
    ///
    /// This avoids the lifetime constraints of the closure-based [`build()`](Self::build),
    /// allowing callers to mix copy and guard parts in a single SQE from borrowed data.
    ///
    /// All parts go into a single SQE. If the batch exceeds the internal
    /// iovec or guard limits, the entire batch is rejected with `Err`
    /// (nothing is sent, guard parts are dropped) — the call never consumes
    /// a prefix. On success, returns the number of parts submitted (always
    /// `parts.len()`); callers wanting larger batches should split them
    /// (the protocol clients cap at 4 guards / 9 iovecs per flush).
    pub fn submit_batch(self, parts: Vec<crate::handler::SendPart<'_>>) -> io::Result<usize> {
        use crate::handler::SendPart;
        with_state(|driver, _| {
            let mut ctx = driver.make_ctx();
            let mut builder = ctx.send_parts(self.token);
            let mut consumed = 0usize;
            for part in parts {
                match part {
                    SendPart::Copy(data) => {
                        builder = builder.copy(data);
                    }
                    SendPart::Guard(guard) => {
                        builder = builder.guard(guard);
                    }
                }
                consumed += 1;
            }
            if consumed == 0 {
                return Ok(0);
            }
            builder.submit()?;
            Ok(consumed)
        })
    }

    /// Like [`submit_batch`](Self::submit_batch), but returns a [`SendFuture`]
    /// that resolves when the batch has been sent.
    ///
    /// Use this when the caller needs completion-paced backpressure rather
    /// than fire-and-forget. Awaiting the future parks the task until the
    /// kernel signals the send, which returns control to the event loop so
    /// completions are reaped and send-pool slots recycled. Awaiting
    /// [`yield_now`] is not a substitute: the task resumes without waiting
    /// for the send to complete.
    ///
    /// Batch limits and the all-or-nothing rejection behavior are identical
    /// to [`submit_batch`](Self::submit_batch). A batch that is empty or
    /// carries no bytes is rejected with `InvalidInput`.
    pub fn submit_batch_await(
        self,
        parts: Vec<crate::handler::SendPart<'_>>,
    ) -> io::Result<(usize, SendFuture)> {
        use crate::handler::SendPart;
        with_state(|driver, executor| {
            if total_part_len(&parts) == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "empty send batch",
                ));
            }
            let conn_index = self.token.index;
            let id = executor.register_send(conn_index);
            let mut ctx = driver.make_ctx();
            let mut builder = ctx.send_parts(self.token);
            let mut consumed = 0usize;
            for part in parts {
                match part {
                    SendPart::Copy(data) => {
                        builder = builder.copy(data);
                    }
                    SendPart::Guard(guard) => {
                        builder = builder.guard(guard);
                    }
                }
                consumed += 1;
            }
            if let Err(e) = builder.submit_awaited(id) {
                executor.withdraw_send(id);
                return Err(e);
            }
            Ok((
                consumed,
                SendFuture::pending(conn_index, self.token.generation, id),
            ))
        })
    }
}

/// Total byte length carried by a batch of send parts.
#[cfg(has_io_uring)]
fn total_part_len(parts: &[crate::handler::SendPart<'_>]) -> usize {
    use crate::handler::SendPart;
    parts
        .iter()
        .map(|part| match part {
            SendPart::Copy(data) => data.len(),
            SendPart::Guard(guard) => guard.as_ptr_len().1 as usize,
        })
        .sum()
}

// ── mio AsyncSendBuilder (copy-only fallback) ───────────────────────

#[cfg(not(has_io_uring))]
/// Builder for scatter-gather sends in the async API (mio fallback).
///
/// On the mio backend, all parts are copied into a single buffer and
/// sent as one operation. Zero-copy guards are consumed by copying their
/// data.
pub struct AsyncSendBuilder {
    token: ConnToken,
}

#[cfg(not(has_io_uring))]
impl ConnCtx {
    /// See [`SendHalf::send_parts`].
    pub(crate) fn send_parts(&self) -> AsyncSendBuilder {
        AsyncSendBuilder {
            token: self.token(),
        }
    }
}

#[cfg(not(has_io_uring))]
impl AsyncSendBuilder {
    /// Build and submit the send by concatenating all copy parts.
    pub fn build<F>(self, f: F) -> io::Result<()>
    where
        F: FnOnce(MioSendBuilder<'_>) -> io::Result<()>,
    {
        with_state(|driver, _| {
            let mut buf = Vec::new();
            let builder = MioSendBuilder { buf: &mut buf };
            f(builder)?;
            if !buf.is_empty() {
                let mut ctx = driver.make_ctx();
                ctx.send(self.token, &buf)?;
            }
            Ok(())
        })
    }

    /// Submit a scatter-gather send from pre-classified `SendPart`s.
    ///
    /// On the mio backend, guard data is copied (no kernel zero-copy).
    pub fn submit_batch(self, parts: Vec<crate::handler::SendPart<'_>>) -> io::Result<usize> {
        use crate::handler::SendPart;
        with_state(|driver, _| {
            let mut buf = Vec::new();
            let mut consumed = 0usize;
            for part in &parts {
                match part {
                    SendPart::Copy(data) => buf.extend_from_slice(data),
                    SendPart::Guard(guard) => {
                        let (ptr, len) = guard.as_ptr_len();
                        let data = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
                        buf.extend_from_slice(data);
                    }
                }
                consumed += 1;
            }
            if !buf.is_empty() {
                let mut ctx = driver.make_ctx();
                ctx.send(self.token, &buf)?;
            }
            Ok(consumed)
        })
    }

    /// Like [`submit_batch`](Self::submit_batch), but returns a [`SendFuture`]
    /// that resolves when the batch has been written to the socket.
    ///
    /// A batch that is empty or carries no bytes is rejected with
    /// `InvalidInput`.
    pub fn submit_batch_await(
        self,
        parts: Vec<crate::handler::SendPart<'_>>,
    ) -> io::Result<(usize, SendFuture)> {
        use crate::handler::SendPart;
        with_state(|driver, executor| {
            let mut buf = Vec::new();
            let mut consumed = 0usize;
            for part in &parts {
                match part {
                    SendPart::Copy(data) => buf.extend_from_slice(data),
                    SendPart::Guard(guard) => {
                        let (ptr, len) = guard.as_ptr_len();
                        let data = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
                        buf.extend_from_slice(data);
                    }
                }
                consumed += 1;
            }
            if buf.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "empty send batch",
                ));
            }
            let conn_index = self.token.index;
            let id = executor.register_send(conn_index);
            let mut ctx = driver.make_ctx();
            if let Err(e) = ctx.send_awaited(self.token, &buf, id) {
                executor.withdraw_send(id);
                return Err(e);
            }
            Ok((
                consumed,
                SendFuture::pending(conn_index, self.token.generation, id),
            ))
        })
    }
}

/// Mio send builder — accumulates parts into a single buffer.
#[cfg(not(has_io_uring))]
pub struct MioSendBuilder<'a> {
    buf: &'a mut Vec<u8>,
}

#[cfg(not(has_io_uring))]
impl<'a> MioSendBuilder<'a> {
    /// Add a copy part.
    pub fn copy(self, data: &[u8]) -> Self {
        self.buf.extend_from_slice(data);
        self
    }

    /// Add a guard part (copies the data on mio backend).
    pub fn guard(self, guard: crate::guard::GuardBox) -> Self {
        let (ptr, len) = guard.as_ptr_len();
        let data = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
        self.buf.extend_from_slice(data);
        self
    }

    /// Submit the accumulated send.
    pub fn submit(self) -> io::Result<()> {
        Ok(())
    }
}

// ── WithDataFuture ───────────────────────────────────────────────────

/// Whether `conn_index` receives directly into its accumulator (a plaintext
/// TCP or Unix connection).
#[cfg(has_io_uring)]
fn is_recv_direct(driver: &Driver, conn_index: u32) -> bool {
    driver
        .connections
        .get(conn_index)
        .is_some_and(|cs| cs.recv_direct)
}

/// Register the current task as `conn_index`'s receive waiter and arm the
/// connection's receive, which the caller does only after its parser has seen
/// every buffered byte: a direct receive into the accumulator on a plaintext
/// TCP or Unix connection, into its TLS engine's buffer on a TLS one. `need`
/// is the parser's `NeedAtLeast` value, if it returned one.
pub(crate) fn park_recv(
    #[allow(unused_variables)] driver: &mut Driver,
    executor: &mut Executor,
    conn_index: u32,
    #[allow(unused_variables)] need: Option<usize>,
) {
    executor.owner_task[conn_index as usize] = Some(CURRENT_TASK_ID.with(|c| c.get()));
    executor.recv_waiters[conn_index as usize] = true;
    #[cfg(has_io_uring)]
    {
        if driver.arm_direct_recv_or_close(conn_index, need) {
            // The connection closed instead: poll again to resolve the read.
            executor.wake_recv(conn_index);
        }
    }
}

/// Register the current task as `conn_index`'s receive waiter for a mio
/// `forward_to_conn`, which waits outside [`park_recv`].
#[cfg(not(has_io_uring))]
fn park_forward_waiter(executor: &mut Executor, conn_index: u32) {
    executor.owner_task[conn_index as usize] = Some(CURRENT_TASK_ID.with(|c| c.get()));
    executor.recv_waiters[conn_index as usize] = true;
}

/// Future returned by [`Connection::with_data`].
pub struct WithDataFuture<F> {
    conn_index: u32,
    /// Generation snapshot from `ConnCtx` at construction time. Compared on
    /// poll / drop so a stale future that survived a slot-reuse cycle
    /// doesn't read or wake the *new* connection's state.
    generation: u32,
    f: Option<F>,
}

impl<F: FnMut(&[u8]) -> ParseResult + Unpin> Future for WithDataFuture<F> {
    type Output = usize;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<usize> {
        with_state(|driver, executor| {
            // Reject stale futures that survived a slot-reuse cycle. A
            // standalone task holding a `ConnCtx` whose underlying
            // connection has closed-then-been-reused would otherwise read
            // the new connection's accumulator. Return Poll::Ready(0)
            // (EOF-equivalent) so the caller's read loop terminates
            // gracefully.
            if driver.connections.generation(self.conn_index) != self.generation {
                self.f.take();
                return Poll::Ready(0);
            }
            let before = arrival_mark(driver, self.conn_index);
            let poll = self.poll_current(driver, executor);
            if let Poll::Ready(consumed) = poll {
                arrival_settle(driver, self.conn_index, before, consumed > 0);
            }
            poll
        })
    }
}

impl<F: FnMut(&[u8]) -> ParseResult + Unpin> WithDataFuture<F> {
    /// `poll` for a future whose generation matches the connection's.
    fn poll_current(&mut self, driver: &mut Driver, executor: &mut Executor) -> Poll<usize> {
        let data = driver.accumulators.data(self.conn_index);
        if data.is_empty() {
            // Check if the connection has been closed — return 0 (EOF)
            // so the caller can detect disconnection.
            let is_closed = driver
                .connections
                .get(self.conn_index)
                .map(|c| c.recv_finished())
                .unwrap_or(true); // connection already released
            if is_closed {
                #[cfg(has_io_uring)]
                let cb_conn = self.conn_index;
                let f = self.f.as_mut().expect("WithDataFuture polled after Ready");
                let result = {
                    #[cfg(has_io_uring)]
                    let _cb = ReaderCallback::enter(cb_conn);
                    f(&[])
                };
                self.f.take();
                return Poll::Ready(match result {
                    ParseResult::Consumed(n) => n,
                    ParseResult::NeedMore | ParseResult::NeedAtLeast(_) => 0,
                });
            }

            // No data available — register as recv waiter and park.
            driver
                .accumulators
                .compact_at_message_start(self.conn_index);
            park_recv(driver, executor, self.conn_index, None);
            return Poll::Pending;
        }

        // Data available — call closure immediately (zero-overhead hot path).
        #[cfg(has_io_uring)]
        let cb_conn = self.conn_index;
        let f = self.f.as_mut().expect("WithDataFuture polled after Ready");
        let result = {
            #[cfg(has_io_uring)]
            let _cb = ReaderCallback::enter(cb_conn);
            f(data)
        };
        #[cfg(has_io_uring)]
        let forwarded = take_forward_zc_consumed(driver, self.conn_index);
        #[cfg(not(has_io_uring))]
        let forwarded = 0usize;
        match result {
            ParseResult::Consumed(consumed) if consumed > 0 => {
                driver
                    .accumulators
                    .consume(self.conn_index, consumed.saturating_sub(forwarded));
                #[cfg(has_io_uring)]
                driver.accumulators.note_consumed(self.conn_index, consumed);
                self.f.take();
                return Poll::Ready(consumed);
            }
            _ => {}
        }
        // A length-prefixed parser announced the remainder — reserve
        // once so the arriving chunks append without regrowth.
        if let ParseResult::NeedAtLeast(additional) = result {
            driver.accumulators.reserve(self.conn_index, additional);
        }
        driver
            .accumulators
            .compact_at_message_start(self.conn_index);

        // NeedMore or Consumed(0) on non-empty data: incomplete parse.
        // Check if the connection is closed (EOF with leftover partial data).
        let is_closed = driver
            .connections
            .get(self.conn_index)
            .map(|c| c.recv_finished())
            .unwrap_or(true);
        if is_closed {
            self.f.take();
            return Poll::Ready(0);
        }

        // Connection still open — wait for more data before retrying.
        let need = match result {
            ParseResult::NeedAtLeast(additional) => Some(additional),
            _ => None,
        };
        park_recv(driver, executor, self.conn_index, need);
        Poll::Pending
    }
}

// ── WithDataResultFuture ─────────────────────────────────────────────

/// Future returned by [`Connection::with_data_result`].
///
/// Wraps [`WithDataFuture`] and adds one thing: when the inner future
/// reports `0`, this one checks the executor's per-connection recv error
/// slot (written by the backends at every real socket-read failure) and
/// returns `Err(e)` if an error was recorded for this connection generation,
/// `Ok(0)` otherwise. Data already buffered is delivered first, so a peer
/// that sent bytes and then reset still gets its bytes parsed before the
/// reset is reported.
///
/// The generation used for the lookup is the one captured at construction;
/// `Executor::recv_errors` documents why that is what makes a post-teardown
/// poll still see the cause.
///
/// Dropping the future before it resolves is inert: it registers no state
/// beyond what `WithDataFuture` registers, and the error slot stays readable,
/// until taken, by a later `with_data_result` on the same connection.
pub struct WithDataResultFuture<F> {
    inner: WithDataFuture<F>,
}

impl<F: FnMut(&[u8]) -> ParseResult + Unpin> Future for WithDataResultFuture<F> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let conn_index = self.inner.conn_index;
        let generation = self.inner.generation;
        match Pin::new(&mut self.inner).poll(cx) {
            Poll::Ready(0) => {
                let error = with_state(|_driver, executor| {
                    executor.take_recv_error(conn_index, generation)
                });
                match error {
                    Some(error) => Poll::Ready(Err(error)),
                    None => Poll::Ready(Ok(0)),
                }
            }
            Poll::Ready(consumed) => Poll::Ready(Ok(consumed)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── WithBytesFuture ──────────────────────────────────────────────────

/// Future returned by [`Connection::with_bytes`].
pub struct WithBytesFuture<F> {
    conn_index: u32,
    /// See `WithDataFuture` for the role of `generation`.
    generation: u32,
    f: Option<F>,
}

impl<F: FnMut(Bytes) -> ParseResult + Unpin> Future for WithBytesFuture<F> {
    type Output = usize;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<usize> {
        with_state(|driver, executor| {
            // Single connection-table lookup: extract generation + closed
            // state together so the rest of poll needs no further accesses.
            // `get()` returns None when the slot is inactive (connection
            // already released), which we treat the same as a stale token.
            let (conn_generation, is_closed) = match driver.connections.get(self.conn_index) {
                None => {
                    // Slot is inactive — definitely stale.
                    self.f.take();
                    return Poll::Ready(0);
                }
                Some(conn) => (conn.generation, conn.recv_finished()),
            };
            if conn_generation != self.generation {
                // Slot was recycled for a different connection.
                self.f.take();
                return Poll::Ready(0);
            }
            let before = arrival_mark(driver, self.conn_index);
            let poll = self.poll_current(driver, executor, is_closed);
            if let Poll::Ready(consumed) = poll {
                arrival_settle(driver, self.conn_index, before, consumed > 0);
            }
            poll
        })
    }
}

impl<F: FnMut(Bytes) -> ParseResult + Unpin> WithBytesFuture<F> {
    /// `poll` for a future whose generation matches the connection's.
    /// `is_closed` is the connection's `recv_finished()`.
    fn poll_current(
        &mut self,
        driver: &mut Driver,
        executor: &mut Executor,
        is_closed: bool,
    ) -> Poll<usize> {
        let data = driver.accumulators.data(self.conn_index);
        if data.is_empty() {
            // No data yet — check closed state from the lookup above.
            if is_closed {
                #[cfg(has_io_uring)]
                let cb_conn = self.conn_index;
                let f = self.f.as_mut().expect("WithBytesFuture polled after Ready");
                let result = {
                    #[cfg(has_io_uring)]
                    let _cb = ReaderCallback::enter(cb_conn);
                    f(Bytes::new())
                };
                self.f.take();
                return Poll::Ready(match result {
                    ParseResult::Consumed(n) => n,
                    ParseResult::NeedMore | ParseResult::NeedAtLeast(_) => 0,
                });
            }

            park_recv(driver, executor, self.conn_index, None);
            return Poll::Pending;
        }

        // Detach accumulator as frozen Bytes (O(1), tail capacity retained).
        let frozen = driver.accumulators.take_frozen(self.conn_index);
        let len = frozen.len();

        #[cfg(has_io_uring)]
        let cb_conn = self.conn_index;
        let f = self.f.as_mut().expect("WithBytesFuture polled after Ready");
        // clone is an O(1) Bytes refcount bump; the original `frozen` is retained for the prepend calls below.
        let result = {
            #[cfg(has_io_uring)]
            let _cb = ReaderCallback::enter(cb_conn);
            f(frozen.clone())
        };

        match result {
            ParseResult::Consumed(consumed) if consumed > 0 => {
                // Put back the unconsumed remainder (if any) as a
                // refcounted slice handoff.
                if consumed < len {
                    driver
                        .accumulators
                        .put_back(self.conn_index, frozen.slice(consumed..));
                } else {
                    // A direct connection's next receive reuses this
                    // allocation if no slice of it is alive by then.
                    #[cfg(has_io_uring)]
                    if driver
                        .connections
                        .get(self.conn_index)
                        .is_some_and(|cs| cs.recv_direct)
                    {
                        driver.accumulators.keep_spent(self.conn_index, frozen);
                    }
                }
                #[cfg(has_io_uring)]
                driver.accumulators.note_consumed(self.conn_index, consumed);
                self.f.take();
                return Poll::Ready(consumed);
            }
            _ => {}
        }

        // NeedMore or Consumed(0) on non-empty data: incomplete parse.
        // Put everything back and use closed state from the lookup above.
        driver.accumulators.put_back(self.conn_index, frozen);
        // A length-prefixed parser announced the remainder — record the
        // reserve target so the unfreeze merge allocates once at full
        // size when the next chunks arrive.
        if let ParseResult::NeedAtLeast(additional) = result {
            driver.accumulators.reserve(self.conn_index, additional);
        }

        if is_closed {
            self.f.take();
            return Poll::Ready(0);
        }

        let need = match result {
            ParseResult::NeedAtLeast(additional) => Some(additional),
            _ => None,
        };
        park_recv(driver, executor, self.conn_index, need);
        Poll::Pending
    }
}

// ── RecvHalf — the exclusive read side of a connection ───────────────

/// The exclusive read side of a connection.
///
/// Obtained from [`Connection::split`]. Neither `Copy` nor `Clone`, and every
/// read method takes `&mut self`.
///
/// `&mut self` prevents a second call only while the return value carries the
/// borrow. [`forward_to_conn`](Self::forward_to_conn) returns
/// `ForwardFuture<'_>`, so a read during a forward is a compile error:
///
/// ```compile_fail
/// # use ringline::{ParseResult, RecvHalf, SendHalf};
/// # async fn f(mut rx: RecvHalf, mut sink: SendHalf) {
/// let forward = rx.forward_to_conn(&mut sink, 16);
/// rx.with_data(|_| ParseResult::Consumed(0)).await;
/// drop(forward);
/// # }
/// ```
///
/// A second forward from one source is refused the same way:
///
/// ```compile_fail
/// # use ringline::{RecvHalf, SendHalf};
/// # async fn f(mut rx: RecvHalf, mut a: SendHalf, mut b: SendHalf) {
/// let first = rx.forward_to_conn(&mut a, 16);
/// let second = rx.forward_to_conn(&mut b, 16);
/// drop((first, second));
/// # }
/// ```
///
/// `with_data`, `with_data_result`, `with_bytes` and `recv_ready` return futures
/// with no lifetime parameter, so the borrow ends with the call and two of them
/// can be held at once. Those rely on runtime checks.
///
/// Available on both backends.
pub struct RecvHalf {
    conn: ConnCtx,
    /// Pinned to its owning worker thread; see [`Connection`].
    _not_send: PhantomData<*const ()>,
}

impl RecvHalf {
    /// See [`Connection::with_data`].
    pub fn with_data<F: FnMut(&[u8]) -> ParseResult>(&mut self, f: F) -> WithDataFuture<F> {
        self.conn.with_data(f)
    }

    /// See [`Connection::with_data_result`].
    pub fn with_data_result<F: FnMut(&[u8]) -> ParseResult>(
        &mut self,
        f: F,
    ) -> WithDataResultFuture<F> {
        self.conn.with_data_result(f)
    }

    /// See [`Connection::with_bytes`].
    pub fn with_bytes<F: FnMut(Bytes) -> ParseResult>(&mut self, f: F) -> WithBytesFuture<F> {
        self.conn.with_bytes(f)
    }

    /// Offer this connection for rebalancing. See
    /// [`Connection::offer_for_park`].
    pub fn offer_for_park(&self, state: Option<crate::park::ParkState>) {
        self.conn.offer_for_park(state);
    }

    /// See [`Connection::token`].
    pub fn token(&self) -> ConnToken {
        self.conn.token()
    }

    /// See [`Connection::is_alive`].
    pub fn is_alive(&self) -> bool {
        self.conn.is_alive()
    }

    /// See [`Connection::is_recv_direct`].
    pub fn is_recv_direct(&self) -> bool {
        self.conn.is_recv_direct()
    }

    /// The connection's slot index and generation.
    pub(crate) fn as_conn_ref(&self) -> ConnCtx {
        self.conn
    }

    /// See [`Connection::eof_truncated`].
    pub fn eof_truncated(&self) -> bool {
        self.conn.eof_truncated()
    }

    /// See [`Connection::recv_arrival`].
    pub fn recv_arrival(&self) -> Option<crate::RecvArrival> {
        self.conn.recv_arrival()
    }

    /// See [`Connection::try_with_data`].
    pub fn try_with_data<F: FnOnce(&[u8]) -> ParseResult>(&mut self, f: F) -> Option<ParseResult> {
        self.conn.try_with_data(f)
    }

    /// See [`Connection::recv_ready`].
    pub fn recv_ready(&mut self) -> RecvReadyFuture {
        self.conn.recv_ready()
    }

    /// Forward the next `len` received bytes to another connection on this
    /// worker.
    ///
    /// The sink is its [`SendHalf`], borrowed mutably for as long as the forward
    /// runs, so a bidirectional proxy splits both connections and runs one
    /// forward in each direction.
    ///
    /// ```ignore
    /// let backend = ringline::connect(addr).await?;
    /// let (mut backend_tx, backend_rx) = backend.split();
    /// // client -> backend; a second task forwards backend -> client
    /// client_rx.forward_to_conn(&mut backend_tx, len).await?;
    /// ```
    ///
    /// A result `< len` means the peer sent FIN first.
    ///
    /// # Thread affinity
    ///
    /// Both connections belong to this worker, because [`SendHalf`] is `!Send`
    /// and a half from another worker cannot reach this call.
    ///
    /// # TLS
    ///
    /// The source may be a TLS connection: rustls' plaintext is collected and
    /// forwarded, which is what makes a TLS-terminating proxy work. The sink may
    /// not, because the forward sends bytes as they are, with nothing on the path
    /// to encrypt them. A TLS sink is refused with `EPROTOTYPE`.
    ///
    /// # Errors
    ///
    /// Refused at the call, resolving on the first poll without having installed
    /// anything: `EBUSY` if a forward is already running on this connection,
    /// `EPIPE` if the source or sink slot is already stale, and `EPROTOTYPE` if
    /// the sink is a TLS connection.
    ///
    /// Resolves `Err(EPIPE)` if the sink connection closes mid-forward. Its slot
    /// may be reused, and writing to a recycled index would deliver this stream
    /// to a different peer, so the sink's generation is checked before every
    /// write.
    ///
    /// # The source on io_uring
    ///
    /// A plaintext source receives directly into its accumulator, and a TLS
    /// source's decrypted plaintext lands there too. The forward takes the
    /// bytes the accumulator holds, up to what is left of `len`, and sends
    /// them on the sink through the sink's send queue under a guard: zero-copy
    /// at or above `send_zc_threshold`, copied into a pool slot below it. One
    /// send is in flight at a time, and the source receives the next chunk
    /// while it is. Because the sends go through the sink's queue, they are
    /// ordered with other sends on the sink. A send the runtime cannot submit,
    /// for example with the worker's send slab
    /// ([`ConfigBuilder::send_slab_slots`](crate::ConfigBuilder::send_slab_slots))
    /// full, resolves the forward with that error and leaves the chunk
    /// buffered on the source. Dropping the future lets a chunk already
    /// submitted go out and leaves the rest buffered.
    ///
    /// # The source on mio
    ///
    /// Bytes are read into a queued send on the sink and copied on the way.
    /// This path exists so that a proxy built on ringline runs without io_uring.
    /// The source stops reading once it holds the hold cap of entries awaiting
    /// the sink (`forward_hold_cap`), which closes the source's TCP window rather
    /// than growing the queue without bound, and resumes when the sink drains.
    pub fn forward_to_conn<'h, 's: 'h>(
        &'h mut self,
        sink: &'s mut SendHalf,
        len: usize,
    ) -> ForwardFuture<'h> {
        self.conn
            .forward_to(sink.conn.conn_index, sink.conn.generation, len)
    }
}

/// An owned connection: its two halves.
///
/// Delivered to
/// [`AsyncEventHandler::on_accept`](crate::AsyncEventHandler::on_accept) for
/// accepted connections, and resolved from [`connect`](crate::connect) and
/// [`connect_unix`](crate::connect_unix) for outbound ones.
///
/// Not `Copy`, not `Clone`, and `!Send`, so one task owns one connection. A
/// `Copy` handle would let two readers interleave on one connection and
/// desynchronise the protocol (#423, #425, #429).
///
/// Most handlers can use this directly: the read and write methods are the
/// same ones on [`SendHalf`] and [`RecvHalf`].
///
/// ```ignore
/// async move {
///     loop {
///         let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
///         if n == 0 { break; }
///     }
/// }
/// ```
///
/// Sending while a read is in flight — an echo writing from inside its own
/// `with_data` closure — needs the two halves to be separately borrowable, so
/// call [`split`](Self::split):
///
/// ```ignore
/// let (mut tx, mut rx) = conn.split();
/// let n = rx.with_data(|d| { let _ = tx.send_nowait(d); ParseResult::Consumed(d.len()) }).await;
/// ```
///
/// Fan-in from several tasks to one connection is an explicit queue
/// (`runtime::channel`) drained by the owning task, not a shared handle. See
/// `docs/connection-handle-ownership-design.md`.
///
/// # Example: Echo Handler
///
/// ```no_run
/// use ringline::{AsyncEventHandler, Connection, ParseResult};
///
/// struct Echo;
///
/// impl AsyncEventHandler for Echo {
///     fn on_accept(&self, mut conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
///         async move {
///             let (mut tx, mut rx) = conn.split();
///             loop {
///                 let n = rx.with_data(|data| {
///                     // Echo back whatever we received
///                     tx.send_nowait(data).ok();
///                     ParseResult::Consumed(data.len())
///                 }).await;
///                 // n == 0 means connection closed (EOF)
///                 if n == 0 { break; }
///             }
///         }
///     }
///     fn create_for_worker(_id: usize) -> Self { Echo }
/// }
/// ```
///
/// # Example: Line-Based Protocol
///
/// ```no_run
/// use ringline::{AsyncEventHandler, Connection, ParseResult};
///
/// struct LineEcho;
///
/// impl AsyncEventHandler for LineEcho {
///     fn on_accept(&self, mut conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
///         async move {
///             let (mut tx, mut rx) = conn.split();
///             loop {
///                 let n = rx.with_data(|data| {
///                     // Find newline
///                     if let Some(pos) = data.iter().position(|&b| b == b'\n') {
///                         let line = &data[..=pos];
///                         tx.send_nowait(line).ok();
///                         ParseResult::Consumed(pos + 1)
///                     } else {
///                         ParseResult::NeedMore
///                     }
///                 }).await;
///                 if n == 0 { break; }
///             }
///         }
///     }
///     fn create_for_worker(_id: usize) -> Self { LineEcho }
/// }
/// ```
///
/// # Example: Zero-Copy with `with_bytes`
///
/// For protocols where you want to avoid copying parsed values, use
/// `with_bytes` which provides `Bytes` handles:
///
/// ```no_run
/// use ringline::{AsyncEventHandler, Connection, ParseResult};
/// use bytes::Bytes;
///
/// struct ZeroCopyHandler;
///
/// impl AsyncEventHandler for ZeroCopyHandler {
///     fn on_accept(&self, mut conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
///         async move {
///             let (mut tx, mut rx) = conn.split();
///             loop {
///                 let n = rx.with_bytes(|bytes| {
///                     // Parse protocol, return Bytes::slice() for the value
///                     // The slice stays valid even after the accumulator advances
///                     if let Some((consumed, value)) = parse_message(&bytes) {
///                         process_value(value); // value: Bytes
///                         ParseResult::Consumed(consumed)
///                     } else {
///                         ParseResult::NeedMore
///                     }
///                 }).await;
///                 if n == 0 { break; }
///             }
///         }
///     }
///     fn create_for_worker(_id: usize) -> Self { ZeroCopyHandler }
/// }
///
/// fn parse_message(data: &[u8]) -> Option<(usize, Bytes)> {
///     // Parse length-prefixed message: 4-byte big-endian length + payload
///     if data.len() < 4 { return None; }
///     let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
///     if data.len() < 4 + len { return None; }
///     let value = Bytes::copy_from_slice(&data[4..4+len]);
///     Some((4 + len, value))
/// }
///
/// fn process_value(_value: Bytes) {
///     // Process the zero-copy value
/// }
/// ```
///
/// # Send Patterns
///
/// ```no_run
/// use ringline::{AsyncEventHandler, Connection, ParseResult};
///
/// struct SendExample;
///
/// impl AsyncEventHandler for SendExample {
///     fn on_accept(&self, mut conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
///         async move {
///             let (mut tx, mut rx) = conn.split();
///             // Fire-and-forget (returns Err if send pool exhausted)
///             tx.send_nowait(b"hello").ok();
///
///             // Await send completion
///             if let Ok(future) = tx.send(b"world") {
///                 future.await.ok();
///             }
///         }
///     }
///     fn create_for_worker(_id: usize) -> Self { SendExample }
/// }
/// ```
///
/// # Thread affinity
///
/// A connection is meaningful only on the worker thread that owns it, so
/// `Connection` and its halves are neither `Send` nor `Sync`:
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<ringline::Connection>();
/// ```
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<ringline::Connection>();
/// ```
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<ringline::SendHalf>();
/// ```
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<ringline::RecvHalf>();
/// ```
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<ringline::SendHalf>();
/// ```
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<ringline::RecvHalf>();
/// ```
///
/// Ringline is thread-per-core: each worker owns its own driver and
/// `ConnectionTable`, and a connection is an `(index, generation)` pair into
/// that worker's table. Used from another worker the index is still in bounds,
/// so the lookup does not fail. It resolves against a different table, and if
/// the generation also matches, I/O lands on an unrelated connection. Capturing
/// a `Connection` in a [`spawn_blocking`] closure is a compile error for the same
/// reason: its pool threads have no driver. [`spawn`] is unaffected, because it
/// requires only `'static`.
pub struct Connection {
    tx: SendHalf,
    rx: RecvHalf,
}

impl Connection {
    /// The connection handed to `on_accept`.
    ///
    /// `spawn_accept_task` runs outside a task poll, so the event loop sets the
    /// claim itself while it owns `&mut Driver`. The slot is freshly accepted, so
    /// the claim is always free.
    pub(crate) fn for_accept(conn: ConnCtx) -> Self {
        Self::from_claimed(conn)
    }

    /// Build the pair from a slot whose halves the caller has already marked
    /// claimed.
    ///
    /// Two callers use this. `spawn_accept_task` runs outside a task poll, and
    /// the event loop sets the claim while it owns `&mut Driver`.
    /// `ConnectFuture::poll` runs inside `with_state` and sets the claim there.
    pub(crate) fn from_claimed(conn: ConnCtx) -> Self {
        Self {
            tx: SendHalf {
                conn,
                _not_send: PhantomData,
            },
            rx: RecvHalf {
                conn,
                _not_send: PhantomData,
            },
        }
    }

    /// A dangling pair for in-memory unit tests.
    ///
    /// The halves are unclaimed and the connection does not exist. The result is only safe on buffered paths (encoders,
    /// write buffers, pending queues) that never reach the wire. Gated on the
    /// `testing` feature because calling an I/O method on it is undefined.
    #[cfg(feature = "testing")]
    #[doc(hidden)]
    pub fn for_test(conn_index: u32, generation: u32) -> Self {
        Self::from_claimed(ConnCtx::new(conn_index, generation))
    }

    /// The connection's slot index and generation.
    pub(crate) fn ctx(&self) -> ConnCtx {
        self.tx.conn
    }

    /// Split into the independently borrowable write and read halves.
    ///
    /// Needed whenever a send has to happen while a read borrow is live.
    pub fn split(self) -> (SendHalf, RecvHalf) {
        (self.tx, self.rx)
    }

    /// The write half alone, borrowed.
    pub fn send_half(&mut self) -> &mut SendHalf {
        &mut self.tx
    }

    /// The read half alone, borrowed.
    pub fn recv_half(&mut self) -> &mut RecvHalf {
        &mut self.rx
    }

    // ── recv ────────────────────────────────────────────────────────────

    /// Wait until recv data is available, then process it.
    ///
    /// The closure receives accumulated bytes and returns a [`ParseResult`]:
    /// - `ParseResult::Consumed(n)` — `n` bytes were consumed from the buffer.
    /// - `ParseResult::NeedMore` — the closure needs more data before making progress.
    ///
    /// Resolves immediately when data is already buffered (cache-hit hot path).
    ///
    /// If the closure returns `NeedMore` or `Consumed(0)` on non-empty data
    /// (incomplete parse), the future parks and retries when more data arrives.
    /// The closure must therefore be safe to call multiple times (`FnMut`).
    pub fn with_data<F: FnMut(&[u8]) -> ParseResult>(&mut self, f: F) -> WithDataFuture<F> {
        self.rx.with_data(f)
    }

    /// Like `with_data`, but the future distinguishes a
    /// clean peer close from a transport failure.
    ///
    /// Resolves to:
    /// - `Ok(n)` with `n > 0` — the closure consumed `n` bytes;
    /// - `Ok(0)` — the peer closed cleanly (or this future is stale: the
    ///   connection slot has been closed and reused) and no error was
    ///   recorded;
    /// - `Err(e)` — the socket read failed with a non-`WouldBlock` error
    ///   (`ConnectionReset` after an RST, for example). Buffered bytes are
    ///   always delivered before the error is surfaced.
    ///
    /// The error is reported once: a later `with_data_result` on the same
    /// connection resolves to `Ok(0)`. And `Ok(n)` echoes whatever the
    /// closure returned, including from the empty-slice call made once the
    /// connection is closed — a closure that returns `Consumed(n > 0)` for
    /// empty input will see `Ok(n)` there and the recorded error only on the
    /// following call.
    ///
    /// Only a failed socket read is reported this way. A TLS record-layer
    /// error (a bad record, a failed decrypt) still closes the connection
    /// through the EOF path and resolves to `Ok(0)`, indistinguishable from a
    /// clean close, exactly as with `with_data`.
    ///
    /// `with_data` keeps returning `0` for both cases; nothing about it
    /// changes. Use this variant when a protocol handler must tell "the peer
    /// hung up" from "the transport broke". Check
    /// `eof_truncated` after `Ok(0)` on TLS
    /// connections, exactly as with `with_data`.
    pub fn with_data_result<F: FnMut(&[u8]) -> ParseResult>(
        &mut self,
        f: F,
    ) -> WithDataResultFuture<F> {
        self.rx.with_data_result(f)
    }

    /// Wait until recv data is available, then provide it as zero-copy `Bytes`.
    ///
    /// Like [`with_data()`](Self::with_data), but the closure receives a `Bytes`
    /// handle that can be sliced (O(1), refcounted) instead of copied. The
    /// closure returns a [`ParseResult`] indicating bytes consumed.
    ///
    /// This enables zero-copy RESP parsing: the parser can call `bytes.slice()`
    /// to extract sub-ranges without allocating.
    pub fn with_bytes<F: FnMut(Bytes) -> ParseResult>(&mut self, f: F) -> WithBytesFuture<F> {
        self.rx.with_bytes(f)
    }

    /// Returns a future that resolves when received bytes are buffered for
    /// the connection, or when the connection has finished receiving.
    ///
    /// The future consumes nothing and does not borrow the connection, so a
    /// reader started after it resolves sees the same bytes, and dropping it
    /// loses none. Polling it registers the polling task, and an arrival
    /// wakes that task by id; the [`Context`]'s waker is not used. A combinator that
    /// re-polls only the child whose own waker fired, such as
    /// `FuturesUnordered`, never re-polls it.
    pub fn recv_ready(&mut self) -> RecvReadyFuture {
        self.rx.recv_ready()
    }

    /// See [`RecvHalf::forward_to_conn`].
    pub fn forward_to_conn<'h, 's: 'h>(
        &'h mut self,
        sink: &'s mut SendHalf,
        len: usize,
    ) -> ForwardFuture<'h> {
        self.rx.forward_to_conn(sink, len)
    }

    // ── send ────────────────────────────────────────────────────────────

    /// See [`SendHalf::send`].
    pub fn send(&mut self, data: &[u8]) -> io::Result<SendFuture> {
        self.tx.send(data)
    }

    /// See [`SendHalf::send_nowait`].
    pub fn send_nowait(&mut self, data: &[u8]) -> io::Result<()> {
        self.tx.send_nowait(data)
    }

    /// See [`SendHalf::send_parts`].
    pub fn send_parts(&mut self) -> AsyncSendBuilder {
        self.tx.send_parts()
    }

    /// See [`SendHalf::send_backpressured`].
    pub fn send_backpressured<'a>(&mut self, data: &'a [u8]) -> BackpressuredSendFuture<'a> {
        self.tx.send_backpressured(data)
    }

    // ── lifecycle and identity ──────────────────────────────────────────

    /// See [`SendHalf::close`].
    pub fn close(&mut self) {
        self.tx.close();
    }

    /// Offer this connection for rebalancing onto a less loaded worker
    /// (#443), carrying `state` across.
    ///
    /// Call it at a point where the handler holds nothing it cannot rebuild —
    /// after finishing a response, not mid-request. Park drops the future and
    /// makes a fresh one on the new worker via
    /// [`AsyncEventHandler::on_adopt`](crate::AsyncEventHandler::on_adopt),
    /// so `state` is the only thing that survives.
    ///
    /// Once the connection is parked, sends on this handle, from the handler,
    /// a spawned task or `on_tick`, return `NotConnected` until the future is
    /// dropped.
    ///
    /// A connection is parked only if its handler calls this, whatever the load
    /// imbalance.
    ///
    /// The offer is cleared when more data arrives, since that means a new
    /// request started and the boundary is gone. So a handler offers once per
    /// idle point and never has to revoke.
    ///
    /// Call it outside any reader callback, after the response to every
    /// request read so far has been queued. An offer is ignored when it
    /// is made from inside one of the connection's reader callbacks
    /// (`with_data`, `with_bytes`, `try_with_data`), or
    /// while the runtime holds received bytes for the connection, such as
    /// the next request. Offer again at the next idle point.
    /// A connection whose next request has always arrived by the time the
    /// handler offers is therefore never parked. Only the innermost
    /// running callback is detected. An offer for connection A made from
    /// inside a callback on connection B, itself inside A's callback, is
    /// declined only while the runtime still holds A's bytes. It does not
    /// hold them in a `with_bytes` callback, or after a `forward_recv_buf`
    /// that sent the whole accumulator.
    /// `metrics::park_diag::OFFER_DECLINED` counts offers ignored because of
    /// a running reader callback or held bytes.
    ///
    /// The runtime does not see bytes the handler has taken into its own
    /// memory, for example a `ConnStream`'s buffered data, `Bytes` kept from
    /// `with_bytes`, or requests the handler has queued. Do not offer while
    /// holding any.
    ///
    /// A TLS connection keeps its TLS session when parked: the session moves
    /// with it, with any ciphertext received but not yet decrypted, so the
    /// peer sees no new handshake.
    ///
    /// Park also requires the io_uring backend and a kernel with
    /// `IORING_OP_FIXED_FD_INSTALL` (mainline 6.8). On mio this does
    /// nothing; on io_uring without that operation the offer is recorded
    /// and never acted on.
    pub fn offer_for_park(&self, state: Option<crate::park::ParkState>) {
        self.tx.offer_for_park(state);
    }

    /// Returns the `ConnToken` for this connection.
    pub fn token(&self) -> ConnToken {
        self.tx.token()
    }

    /// Whether this handle still refers to a live, usable connection.
    ///
    /// Returns `false` if the slot has been released and its generation bumped,
    /// or if the connection is closing, even before the Close CQE has released
    /// the slot. Because `close()` sets `Closing` synchronously, a caller such as
    /// a pool sees a client's close on its next turn.
    ///
    /// A FIN or reset from the peer closes the connection whether or not a
    /// read is parked, so this returns `false` once the runtime has seen it.
    /// On io_uring the runtime detects it on every plaintext or TLS
    /// connection with a `POLLRDHUP` poll. On a plaintext connection, when
    /// bytes the peer sent before it are queued or buffered, the connection
    /// stays open, and this returns `true`, until they have been read (see
    /// [`connect`]). On a TLS connection the close takes effect when the
    /// receive reads the close_notify or the FIN; plaintext already decrypted
    /// stays readable. On io_uring, a close_notify the peer sends without a FIN
    /// is read when a receive next completes (see [`connect`] for when one is
    /// armed), and this returns `true` until then.
    pub fn is_alive(&self) -> bool {
        self.tx.is_alive()
    }

    /// Whether the connection receives directly into its accumulator: on
    /// io_uring, every plaintext connection, accepted or from [`connect`] or
    /// [`connect_unix`]. A TLS connection receives into its TLS engine's
    /// buffer instead, and this returns `false` for it. Always `false` on the
    /// mio backend, outside the executor, and once the runtime has released
    /// the connection's slot after its close completes.
    pub fn is_recv_direct(&self) -> bool {
        self.rx.is_recv_direct()
    }

    /// Access peer address.
    pub fn peer_addr(&self) -> Option<crate::connection::PeerAddr> {
        self.tx.peer_addr()
    }

    /// Which listener accepted this connection, or `None` if it is outbound.
    ///
    /// A runtime can bind several listeners and they all feed the same
    /// `on_accept`; this is how a handler tells them apart. Ids follow
    /// `bind()` call order — see [`ListenerId`](crate::ListenerId).
    pub fn listener(&self) -> Option<crate::ListenerId> {
        self.tx.listener()
    }

    /// Check if this connection is outbound (initiated via connect).
    pub fn is_outbound(&self) -> bool {
        self.tx.is_outbound()
    }

    // ── the rest of the connection surface ─────────────────────────────────

    /// Whether this TLS connection's EOF was a truncation: the peer's TCP
    /// FIN arrived without a preceding close_notify alert. A truncated
    /// stream may be missing data the peer (or an active attacker injecting
    /// the FIN) cut off — length- or delimiter-framed protocols should treat
    /// it as an error rather than a clean end-of-stream.
    ///
    /// Check this when a recv (`with_data`/`with_bytes`) reports EOF. The
    /// flag is readable while the connection slot is still held (the wake
    /// that delivered the EOF and this check run before the slot is
    /// recycled); it returns `false` for plaintext connections, for clean
    /// TLS shutdowns, and once the slot has been reused.
    pub fn eof_truncated(&self) -> bool {
        self.rx.as_conn_ref().eof_truncated()
    }

    /// When the bytes consumed by the most recent reader call on this
    /// connection arrived.
    ///
    /// The reader calls that set it are `with_data`, `with_data_result`,
    /// `with_bytes` and `try_with_data`, on this connection or its
    /// [`RecvHalf`]. The call's bytes are the ones it removed from the
    /// connection, whatever the parser returned.
    /// Forwards and `ConnStream` do not set it.
    ///
    /// Returns `None` until a reader call has consumed a byte, after a call
    /// that consumed none or resolved at end of stream, and once the
    /// connection has been torn down, whether or not its slot is reused.
    ///
    /// Read it before the task's next `.await`. A task that runs two reader
    /// calls on one connection at once, for example with `join!`, cannot tell
    /// which call set it.
    ///
    /// See [`RecvArrival`](crate::RecvArrival) for what an arrival time
    /// measures.
    pub fn recv_arrival(&self) -> Option<crate::RecvArrival> {
        self.rx.recv_arrival()
    }

    /// Non-blocking accumulator access. Calls `f` with buffered data if any,
    /// returning `Some(result)`. Returns `None` if the accumulator is empty.
    pub fn try_with_data<F: FnOnce(&[u8]) -> ParseResult>(&mut self, f: F) -> Option<ParseResult> {
        self.rx.as_conn_ref().try_with_data(f)
    }

    /// See [`SendHalf::forward_recv_buf`].
    pub fn forward_recv_buf(&mut self, data: &[u8]) -> io::Result<()> {
        self.tx.conn.forward_recv_buf(data)
    }

    /// See [`SendHalf::send_chain`].
    #[cfg(has_io_uring)]
    pub fn send_chain<F>(&mut self, f: F) -> io::Result<SendFuture>
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> io::Result<()>,
    {
        self.tx.conn.send_chain(f)
    }

    /// See [`SendHalf::send_chain_nowait`].
    #[cfg(has_io_uring)]
    pub fn send_chain_nowait<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> R,
    {
        self.tx.conn.send_chain_nowait(f)
    }

    /// See [`SendHalf::shutdown_write`].
    pub fn shutdown_write(&mut self) {
        self.tx.conn.shutdown_write();
    }

    /// Query TLS session info for this connection.
    pub fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.tx.conn.tls_info()
    }

    /// Returns the connection slot index. Useful for indexing into per-connection arrays.
    pub fn index(&self) -> usize {
        self.tx.conn.index()
    }
}

/// The write side of a connection, from [`Connection::split`].
///
/// Not `Copy` and not `Clone`, so one task owns the writes. Several producers
/// feeding one connection is an explicit queue — `runtime::channel`'s
/// `Sender`/`Receiver` — with the owning task draining it, rather than a shared
/// handle. That is deliberate: the per-connection send queue provides
/// *non-corruption* (one `send`'s bytes reach the wire contiguously, TLS
/// records do not interleave) but it cannot provide *ordering*, because which
/// task's message goes first is whichever the executor polled. Message order is
/// a protocol property and only the application knows the intended order, so a
/// shared send handle would advertise a guarantee the transport cannot keep.
///
/// Unlike [`RecvHalf`], this does not borrow the read side: sending while a
/// reader is live is ordinary (an echo does exactly that), so the two halves
/// are independent.
///
/// Available on both backends.
pub struct SendHalf {
    conn: ConnCtx,
    _not_send: PhantomData<*const ()>,
}

impl SendHalf {
    /// Send data and await completion. Copies data into the send pool, submits
    /// the SQE eagerly, then returns a future that resolves with `data.len()`
    /// once this send's last byte has gone to the socket, or with the error
    /// that ended it. Under TLS that is the plaintext length, not the
    /// ciphertext's. Each future resolves with its own send's result, so
    /// several may be awaited at once.
    ///
    /// Use this when you need backpressure or send completion notification.
    /// For fire-and-forget sending, use `send_nowait()`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the send copy pool cannot admit the whole buffer
    /// (`Other`, retryable once in-flight sends complete) or if the buffer
    /// is wider than the entire pool (`InvalidInput`). Nothing was queued or
    /// transmitted on `Err`, so the same buffer may be sent again later. On a
    /// TLS connection the pool is checked against the ciphertext bound
    /// before anything is encrypted, which is what keeps that true there.
    /// Submission-queue pressure is not an error: the send is queued
    /// and retried. Persistent submission-queue starvation is reported like
    /// a write error: the awaited `SendFuture` resolves `Err` and the
    /// connection is closed.
    pub fn send(&mut self, data: &[u8]) -> io::Result<SendFuture> {
        self.conn.send(data)
    }

    /// Fire-and-forget send: copies data into the send pool and submits the SQE.
    /// One copy, no heap allocation, no future.
    ///
    /// This is the hot-path send for cache responses. The CQE is handled
    /// internally by the executor (resource cleanup + send queue advancement).
    ///
    /// # Errors
    ///
    /// Same error contract as `send()`: pool admission errors
    /// only (`Other` when the pool cannot admit the whole buffer,
    /// `InvalidInput` when it never could), nothing committed on `Err`,
    /// submission-queue pressure absorbed by the queue. With no future to resolve, persistent
    /// submission-queue starvation surfaces only as the connection closing.
    ///
    /// For backpressure-aware sending, use `send()` instead.
    pub fn send_nowait(&mut self, data: &[u8]) -> io::Result<()> {
        self.conn.send_nowait(data)
    }

    /// Begin building a scatter-gather send with mixed copy and zero-copy guard
    /// parts.
    ///
    /// [`build`](AsyncSendBuilder::build) takes a closure that chains
    /// `.copy(data)` and `.guard(guard)` and ends with `.submit()`.
    /// [`submit_batch`](AsyncSendBuilder::submit_batch) takes pre-classified
    /// `SendPart`s. Both are fire-and-forget;
    /// [`submit_batch_await`](AsyncSendBuilder::submit_batch_await) also returns
    /// a [`SendFuture`]. On the mio backend every part is copied.
    pub fn send_parts(&mut self) -> AsyncSendBuilder {
        self.conn.send_parts()
    }

    /// Send `data`, waiting for send-pool capacity instead of failing when
    /// the pool is full.
    ///
    /// The counterpart to `send`, which fails immediately when
    /// the copy pool is exhausted. Reach for this when the peer should set
    /// the pace rather than the pool — forwarding a fast source to a slow
    /// sink, for instance — and for `send` when a full pool means you would
    /// rather drop the message than wait.
    ///
    /// Nothing is submitted, and no queue is joined, until the returned
    /// future is polled; dropping one you never awaited does nothing. See
    /// [`BackpressuredSendFuture`] for admission order, cancellation
    /// semantics and the error kinds.
    ///
    /// `data` is borrowed until the future resolves, so it is read at
    /// submission time rather than copied up front.
    ///
    /// ```no_run
    /// # async fn f(tx: &mut ringline::SendHalf, body: &[u8]) -> std::io::Result<()> {
    /// let sent = tx.send_backpressured(body).await?;
    /// assert_eq!(sent as usize, body.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_backpressured<'a>(&mut self, data: &'a [u8]) -> BackpressuredSendFuture<'a> {
        self.conn.send_backpressured(data)
    }

    /// Close this connection.
    ///
    /// Queued sends drain first, then, on a TLS connection, a close_notify
    /// alert, then the FIN. The drain has no time bound: a peer that stops
    /// reading holds the connection until it reads, resets, or the worker
    /// exits. On io_uring, if a close is already pending, for example because
    /// the peer closed first, this sends no alert; mio writes the alert at
    /// teardown regardless. No alert follows a write shutdown
    /// (`shutdown_write`).
    ///
    /// On io_uring a TLS send made after `close()` returns `NotConnected`,
    /// because it would follow the alert. On mio it is queued and sent ahead of
    /// the alert, which mio writes once the queue drains.
    ///
    /// Does nothing if the connection has already been released (its slot may
    /// now hold another connection), or when called outside the worker's
    /// executor.
    pub fn close(&mut self) {
        self.conn.close();
    }

    /// Send `data`, the bytes a `with_data` closure was handed, without
    /// copying them when possible.
    ///
    /// On io_uring, if `data` is exactly the connection's whole recv
    /// accumulator, the accumulator is detached and sent under a guard
    /// (copied into the send pool below `send_zc_threshold`). Otherwise
    /// `data` is copied as by [`send_nowait`](Self::send_nowait).
    ///
    /// On mio, `data` is always copied as by `send_nowait`. On a TLS
    /// connection it is always encrypted into the send pool; when `data` is
    /// the whole accumulator, the accumulator is detached first and gathered
    /// into a temporary buffer.
    ///
    /// # Errors
    ///
    /// `NotConnected` if this handle is stale: its connection closed and the
    /// slot now holds another. Otherwise the errors of
    /// [`send_nowait`](Self::send_nowait), and, when `data` is the whole
    /// accumulator, `Other` if the zero-copy send slab is full. Nothing is
    /// sent or consumed on `Err`.
    pub fn forward_recv_buf(&mut self, data: &[u8]) -> io::Result<()> {
        self.conn.forward_recv_buf(data)
    }

    /// Shut down the write side of the connection (half-close).
    ///
    /// Sends a TCP FIN to the peer. The read side remains open.
    ///
    /// Any `send_backpressured` still waiting for pool capacity on this
    /// connection fails with [`BrokenPipe`](io::ErrorKind::BrokenPipe) rather
    /// than waiting for a turn it could no longer use. Already-submitted
    /// sends are left alone: their bytes may already be on the way, and the
    /// FIN is ordered behind them. Plain `send` is unaffected either way.
    ///
    /// On io_uring the shutdown runs on the worker's io-wq pool, and a close
    /// issued before it finishes waits for it; see
    /// [the `fs` module docs](crate::fs#blocking-file-io-and-connection-closes-io_uring).
    pub fn shutdown_write(&mut self) {
        self.conn.shutdown_write();
    }

    /// See [`Connection::index`].
    pub fn index(&self) -> usize {
        self.conn.index()
    }

    /// See [`Connection::tls_info`].
    pub fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.conn.tls_info()
    }

    /// Build an IO_LINK chained send and await completion.
    ///
    /// The closure receives a [`SendChainBuilder`](crate::handler::SendChainBuilder)
    /// for constructing linked SQEs. Call `.copy()`, `.parts()...add()` to build
    /// the chain, then `.finish()` to submit it. Returns a [`SendFuture`] that
    /// resolves with the bytes the chain sent, or `Ok(0)` when the closure
    /// submitted nothing.
    ///
    /// On a plaintext connection, `finish` returns `WouldBlock` while a send on
    /// the connection is in flight or queued, or another chain is active, since
    /// a linked chain would overtake them; retry once they complete. On a TLS
    /// connection the parts are not linked SQEs: `copy` and `add` gather them,
    /// guard parts included, and `finish` encrypts them as one send and queues
    /// it behind the connection's other sends, so it does not refuse while
    /// earlier sends are in flight.
    ///
    /// For fire-and-forget chained sending, use `send_chain_nowait()`.
    #[cfg(has_io_uring)]
    pub fn send_chain<F>(&mut self, f: F) -> io::Result<SendFuture>
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> io::Result<()>,
    {
        self.conn.send_chain(f)
    }

    /// Build an IO_LINK chained send on this connection (fire-and-forget).
    ///
    /// The closure receives a [`SendChainBuilder`](crate::handler::SendChainBuilder)
    /// for constructing linked SQEs. Call `.copy()`, `.parts()...add()` to add
    /// SQEs, then `.finish()` to submit the chain. On a TLS connection the
    /// chain is encrypted and queued as one send; see
    /// [`send_chain`](Self::send_chain).
    ///
    /// For backpressure-aware chained sending, use `send_chain()`.
    #[cfg(has_io_uring)]
    pub fn send_chain_nowait<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> R,
    {
        self.conn.send_chain_nowait(f)
    }

    /// Offer this connection for rebalancing. See
    /// [`Connection::offer_for_park`].
    pub fn offer_for_park(&self, state: Option<crate::park::ParkState>) {
        self.conn.offer_for_park(state);
    }

    /// See [`Connection::token`].
    pub fn token(&self) -> ConnToken {
        self.conn.token()
    }

    /// See [`Connection::is_alive`].
    pub fn is_alive(&self) -> bool {
        self.conn.is_alive()
    }

    /// See [`Connection::peer_addr`].
    pub fn peer_addr(&self) -> Option<crate::connection::PeerAddr> {
        self.conn.peer_addr()
    }

    /// See [`Connection::listener`].
    pub fn listener(&self) -> Option<crate::ListenerId> {
        self.conn.listener()
    }

    /// See [`Connection::is_outbound`].
    pub fn is_outbound(&self) -> bool {
        self.conn.is_outbound()
    }
}

impl Drop for SendHalf {
    /// Clear this half's flag if the slot still holds this connection. A half
    /// can outlive its connection inside a standalone task, and the slot's new
    /// occupant has its own flag.
    fn drop(&mut self) {
        let _ = try_with_state(|driver, _executor| {
            if driver.connections.generation(self.conn.conn_index) != self.conn.generation {
                return;
            }
            if let Some(taken) = driver
                .send_half_taken
                .get_mut(self.conn.conn_index as usize)
            {
                *taken = false;
            }
        });
    }
}

impl Drop for RecvHalf {
    /// See [`SendHalf`]'s `drop`. `Driver::clear_conn_claims` at the recycle
    /// point starts each slot with both flags clear.
    fn drop(&mut self) {
        let _ = try_with_state(|driver, _executor| {
            if driver.connections.generation(self.conn.conn_index) != self.conn.generation {
                return;
            }
            if let Some(taken) = driver
                .recv_half_taken
                .get_mut(self.conn.conn_index as usize)
            {
                *taken = false;
            }
        });
    }
}

// ── Forwarding to a connection ───────────────────────────────────────

/// Future returned by [`RecvHalf::forward_to_conn`].
///
/// Parks on the source's recv waiter slot; the event loop resolves it by writing
/// into `Driver::forward_done` and calling `wake_recv`. Borrows the source and
/// sink halves for its lifetime.
#[cfg(not(has_io_uring))]
pub struct ForwardFuture<'a> {
    conn_index: u32,
    generation: u32,
    /// Set when the forward could not be installed at all (stale handle, or a
    /// forward already running); reported on the first poll.
    refused: Option<i32>,
    _borrow: PhantomData<&'a ()>,
}

#[cfg(not(has_io_uring))]
impl Future for ForwardFuture<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        if let Some(errno) = me.refused {
            return Poll::Ready(Err(io::Error::from_raw_os_error(errno)));
        }
        with_state(|driver, executor| {
            let idx = me.conn_index as usize;
            // The terminal result wins over a stale-handle check: the loop
            // records it before teardown releases the slot.
            if let Some(res) = driver.forward_done[idx].take() {
                return Poll::Ready(match res {
                    Ok(n) => Ok(n as usize),
                    Err(errno) => Err(io::Error::from_raw_os_error(errno)),
                });
            }
            if driver.connections.generation(me.conn_index) != me.generation {
                let forwarded = driver.forward_conn[idx].take().map_or(0, |st| st.forwarded);
                return Poll::Ready(Ok(forwarded as usize));
            }
            park_forward_waiter(executor, idx as u32);
            Poll::Pending
        })
    }
}

#[cfg(not(has_io_uring))]
impl Drop for ForwardFuture<'_> {
    /// Cancel a forward that is dropped before it resolves.
    ///
    /// This matters more here than on io_uring, where writes only happen while
    /// the future is being polled. On mio the event loop relays autonomously
    /// once the forward is installed, so a `select!` or `timeout` that drops
    /// the future would otherwise leave bytes flowing to the sink with nobody
    /// waiting for the result. Whatever was already queued on the sink stays
    /// queued — it is on its way and cannot be recalled — but no further bytes
    /// are taken from the source.
    fn drop(&mut self) {
        // A refused future installed nothing, and a forward running on this
        // source belongs to another future.
        if self.refused.is_some() {
            return;
        }
        let _ = try_with_state(|driver, _executor| {
            let idx = self.conn_index as usize;
            if driver.connections.generation(self.conn_index) != self.generation {
                return;
            }
            if let Some(st) = driver.forward_conn[idx].take() {
                driver.forward_feeder[st.sink_index as usize] = None;
            }
            driver.forward_done[idx] = None;
        });
    }
}

/// Future returned by [`RecvHalf::forward_to_conn`]. Borrows the source and sink
/// halves for its lifetime.
#[cfg(has_io_uring)]
pub struct ForwardFuture<'a> {
    conn_index: u32,
    generation: u32,
    /// Set when the forward could not be installed at all — a forward already
    /// running (`EBUSY`), a stale source or sink slot (`EPIPE`), or a TLS sink
    /// (`EPROTOTYPE`). Reported on the first poll; nothing was mutated.
    refused: Option<i32>,
    /// The running forward; `None` once it resolved or if it was refused.
    direct: Option<DirectForward>,
    /// Ties the future to the source and sink the caller borrowed.
    _borrow: PhantomData<&'a ()>,
}

/// State of a [`ForwardFuture`] that sends from its source's accumulator.
///
/// Each step takes the bytes the accumulator holds, up to what is left of
/// `len`, and sends them on the sink through its send queue under a guard:
/// zero-copy at or above `send_zc_threshold`, copied into a pool slot below
/// it. One send is in flight at a time. While it is, the source receives
/// into an empty accumulator, so at most one more chunk is buffered and the
/// source's TCP window closes when the sink falls behind.
#[cfg(has_io_uring)]
struct DirectForward {
    sink_index: u32,
    sink_generation: u32,
    len: u64,
    forwarded: u64,
    /// The send in flight and the chunk it carries.
    in_flight: Option<(SendFuture, Bytes)>,
}

/// Mark the direct forward from `source` ended, so another may start.
#[cfg(has_io_uring)]
fn end_direct_forward(source: u32, generation: u32) {
    let _ = try_with_state(|driver, _| {
        if let Some(cs) = driver.connections.get_mut(source)
            && cs.generation == generation
        {
            cs.direct_forwarding = false;
        }
    });
}

/// One step of a direct forward, decided under the driver borrow.
#[cfg(has_io_uring)]
enum DirectStep {
    /// The source closed or finished receiving: resolve with the count.
    Done,
    /// Nothing buffered; a receive is armed.
    Park,
    /// A chunk went to the sink.
    Sent(SendFuture, Bytes),
    Fail(io::Error),
}

#[cfg(has_io_uring)]
impl DirectForward {
    fn poll(
        &mut self,
        source: u32,
        generation: u32,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        loop {
            if let Some((send, chunk)) = self.in_flight.as_mut() {
                match Pin::new(send).poll(cx) {
                    Poll::Pending => {
                        // Receive the next chunk while this one is sent.
                        with_state(|driver, executor| {
                            if driver
                                .connections
                                .get(source)
                                .is_some_and(|c| c.generation == generation && !c.recv_finished())
                                && driver.accumulators.is_empty(source)
                            {
                                park_recv(driver, executor, source, None);
                            }
                        });
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => {
                        let sink_gone = with_state(|driver, _| {
                            driver.connections.generation(self.sink_index) != self.sink_generation
                        });
                        self.in_flight = None;
                        return Poll::Ready(Err(if sink_gone {
                            io::Error::from_raw_os_error(libc::EPIPE)
                        } else {
                            e
                        }));
                    }
                    Poll::Ready(Ok(_)) => {
                        let chunk = chunk.clone();
                        self.forwarded += chunk.len() as u64;
                        self.in_flight = None;
                        // The next direct receive reuses the chunk's
                        // allocation if the guard has released it by then.
                        with_state(|driver, _| {
                            if driver.connections.generation(source) == generation
                                && is_recv_direct(driver, source)
                            {
                                driver.accumulators.keep_spent(source, chunk);
                            }
                        });
                    }
                }
            }
            if self.forwarded >= self.len {
                return Poll::Ready(Ok(self.forwarded as usize));
            }
            let step = with_state(|driver, executor| {
                match driver.connections.get(source) {
                    Some(c) if c.generation == generation => {}
                    _ => return DirectStep::Done,
                }
                if driver.connections.generation(self.sink_index) != self.sink_generation {
                    return DirectStep::Fail(io::Error::from_raw_os_error(libc::EPIPE));
                }
                if driver.accumulators.is_empty(source) {
                    if driver
                        .connections
                        .get(source)
                        .is_none_or(|c| c.recv_finished())
                    {
                        return DirectStep::Done;
                    }
                    park_recv(driver, executor, source, None);
                    return DirectStep::Park;
                }
                let frozen = driver.accumulators.take_frozen(source);
                let take = (frozen.len() as u64).min(self.len - self.forwarded) as usize;
                let chunk = frozen.slice(..take);
                if take < frozen.len() {
                    driver.accumulators.put_back(source, frozen.slice(take..));
                }
                driver.accumulators.note_consumed(source, take);
                let id = executor.register_send(self.sink_index);
                let token = ConnToken::new(self.sink_index, self.sink_generation);
                let submitted = driver
                    .make_ctx()
                    .send_parts(token)
                    .guard(crate::guard::GuardBox::new(AccumulatorGuard(chunk.clone())))
                    .submit_awaited(id);
                match submitted {
                    Ok(()) => DirectStep::Sent(
                        SendFuture::pending(self.sink_index, self.sink_generation, id),
                        chunk,
                    ),
                    Err(e) => {
                        // Nothing was sent: the chunk goes back in front of
                        // whatever the accumulator still holds.
                        executor.withdraw_send(id);
                        driver.accumulators.prepend(source, &chunk);
                        DirectStep::Fail(e)
                    }
                }
            });
            match step {
                DirectStep::Done => return Poll::Ready(Ok(self.forwarded as usize)),
                DirectStep::Park => return Poll::Pending,
                DirectStep::Fail(e) => return Poll::Ready(Err(e)),
                DirectStep::Sent(send, chunk) => self.in_flight = Some((send, chunk)),
            }
        }
    }
}

#[cfg(has_io_uring)]
impl Drop for ForwardFuture<'_> {
    /// A chunk already submitted to the sink goes out; the rest stays
    /// buffered on the source.
    fn drop(&mut self) {
        if self.direct.is_some() {
            end_direct_forward(self.conn_index, self.generation);
        }
    }
}

#[cfg(has_io_uring)]
impl Future for ForwardFuture<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        let Some(direct) = me.direct.as_mut() else {
            // Refused at the call, or polled again after resolving.
            let errno = me.refused.unwrap_or(libc::EPIPE);
            return Poll::Ready(Err(io::Error::from_raw_os_error(errno)));
        };
        let poll = direct.poll(me.conn_index, me.generation, cx);
        if poll.is_ready() {
            me.direct = None;
            end_direct_forward(me.conn_index, me.generation);
        }
        poll
    }
}

// ── RecvReadyFuture ──────────────────────────────────────────────────

/// Future returned by [`Connection::recv_ready`]. Resolves when:
/// 1. The driver holds received bytes for the connection in its
///    accumulator, OR
/// 2. The connection has finished receiving.
pub struct RecvReadyFuture {
    conn_index: u32,
    /// See `WithDataFuture` for the role of `generation`.
    generation: u32,
}

impl Future for RecvReadyFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        with_state(|driver, executor| {
            // Stale future from a reused slot — synthesize "ready" so the
            // caller's loop sees the closure and terminates.
            if driver.connections.generation(self.conn_index) != self.generation {
                return Poll::Ready(());
            }
            // Bytes the driver holds for the connection: the accumulator, and
            // on io_uring the bytes a direct receive holds (`recv_direct_held`).
            if driver.recv_buffered(self.conn_index) > 0 {
                return Poll::Ready(());
            }

            // Check if the connection is closed.
            let is_closed = driver
                .connections
                .get(self.conn_index)
                .map(|c| c.recv_finished())
                .unwrap_or(true);
            if is_closed {
                return Poll::Ready(());
            }

            // Not ready — register as recv waiter and park.
            park_recv(driver, executor, self.conn_index, None);
            Poll::Pending
        })
    }
}

// ── BackpressuredSendFuture ──────────────────────────────────────────

/// Where a [`BackpressuredSendFuture`] is in the admission handshake.
enum BackpressuredState {
    /// Nothing has touched runtime state yet. Dropping here is inert, which
    /// is what makes construction lazy.
    Fresh,
    /// Enqueued on the worker's send-capacity FIFO, waiting for its turn.
    Waiting(SendId),
    /// `send_bounded` has run; waiting for the backend to settle the id.
    Submitted(SendId),
    /// Resolved (or refused). Drop has nothing to undo.
    Done,
}

/// Future returned by [`SendHalf::send_backpressured`]: a send that **waits**
/// for send-pool capacity instead of failing when the pool is full.
///
/// # How it differs from [`SendHalf::send`]
///
/// `send` submits immediately and returns `Err` if the copy pool is
/// exhausted. This parks instead, in a per-worker FIFO, and submits when its
/// turn comes. Use it when the peer, not the pool, should set the pace —
/// a proxy forwarding a fast source to a slow sink, say. Use `send` when a
/// full pool means you would rather shed the message than wait.
///
/// # Admission
///
/// Nothing happens until the first poll: building the future touches no
/// runtime state, so dropping one you never awaited is a no-op. On the first
/// poll the message's worst-case pool cost is computed and the future joins
/// the FIFO; it is released when it reaches the head *and* the pool can cover
/// that cost. Admission is strictly first-come-first-served per worker, so a
/// large message cannot be starved by a stream of small ones.
///
/// A message that could never fit the pool — even empty — is rejected with
/// [`io::ErrorKind::InvalidInput`] before it joins the queue, because no
/// amount of waiting would help. On a TLS connection the cost is the
/// *ciphertext* bound, which is larger than `data.len()`.
///
/// # Cancellation
///
/// Dropping while waiting removes the entry and hands the queue to the next
/// waiter. Dropping after submission abandons the result: the write may or
/// may not have reached the wire, exactly as for any cancelled write. The
/// future never submits twice.
///
/// # Errors
///
/// - [`InvalidInput`](io::ErrorKind::InvalidInput) — the message can never
///   fit this connection's send pool.
/// - [`BrokenPipe`](io::ErrorKind::BrokenPipe) — the write half is shut down,
///   or was shut down while this send was waiting.
/// - [`ConnectionAborted`](io::ErrorKind::ConnectionAborted) — the connection
///   closed while waiting or in flight.
/// - [`NotConnected`](io::ErrorKind::NotConnected) — on io_uring, the
///   connection is TLS and its close_notify is already queued (`close()`, a
///   handler return or `DriverCtx::close`); or the connection's close was
///   *committed* while this send waited for capacity. A waiter in the admission
///   FIFO is neither in flight nor in the per-connection send queue, so it does
///   not hold off `try_finalize_close`; if the close is finalized while it
///   waits, winning capacity finds the Close already submitted and the send is
///   refused rather than written. Which of this and `ConnectionAborted` you see
///   is a race between the capacity wake and teardown — treat both as "the
///   connection went away", and expect either on a peer that closed.
/// - Anything the underlying send reports, including `BrokenPipe` (`EPIPE`) from
///   the socket itself when the peer has reset.
///
/// On success it resolves to the number of bytes **you passed in**, not the
/// bytes on the wire; under TLS those differ.
#[must_use = "a send_backpressured future does nothing until polled"]
pub struct BackpressuredSendFuture<'a> {
    conn_index: u32,
    /// See `WithDataFuture` for the role of `generation`.
    generation: u32,
    data: &'a [u8],
    state: BackpressuredState,
}

impl BackpressuredSendFuture<'_> {
    /// Resolve and mark done in one step, so no error path forgets the
    /// transition and leaves `Drop` trying to cancel an id that never was.
    fn finish(&mut self, result: io::Result<u32>) -> Poll<io::Result<u32>> {
        self.state = BackpressuredState::Done;
        Poll::Ready(result)
    }

    /// Give up on `id` with `ConnectionAborted`, taking it off the queue on
    /// the way out. Used when the connection slot has been recycled and no
    /// result was parked: without the `cancel` the entry would sit in the
    /// queue forever, scanned by every later operation, and if it were the
    /// head it would stall every bounded send on the worker.
    fn abandon(&mut self, executor: &mut Executor, id: SendId) -> Poll<io::Result<u32>> {
        executor.cancel_send(id);
        self.finish(Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "connection closed",
        )))
    }
}

impl Future for BackpressuredSendFuture<'_> {
    type Output = io::Result<u32>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u32>> {
        let this = self.get_mut();
        with_state(|driver, executor| {
            let task_id = CURRENT_TASK_ID.with(|c| c.get());

            match this.state {
                BackpressuredState::Done => {
                    panic!("BackpressuredSendFuture polled after completion")
                }

                BackpressuredState::Fresh => {
                    // Slot-reuse safety, as every other connection future
                    // does: a recycled index is a different connection.
                    //
                    // This check belongs *only* here. Once an id exists it
                    // identifies the operation on its own — an id's slot
                    // generation changes when the slot is freed, so it stops
                    // matching once its operation is freed — and the queue is the
                    // authority on its outcome. Checking the generation in
                    // the other states would throw away the result teardown
                    // parked for this id, which on mio can be a real
                    // `Ok(len)` that the final flush produced *after* the
                    // provisional abort (departure 4), and would leave the
                    // entry on the queue with nobody left to take it.
                    if driver.connections.generation(this.conn_index) != this.generation {
                        return this.finish(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "connection closed",
                        )));
                    }
                    // Waiting for capacity in order to write to a half-closed
                    // socket is never useful, and a doomed entry at the head
                    // of a shared FIFO delays every other connection on this
                    // worker. `WriteHalf`'s docs leave this policy open for
                    // plain sends; bounded sends decide it here.
                    if let Some(conn) = driver.connections.get(this.conn_index)
                        && conn.write != crate::connection::WriteHalf::Open
                    {
                        return this.finish(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "write half is shut down",
                        )));
                    }
                    // Likewise a TLS connection whose close_notify is queued:
                    // the send would be refused once it won capacity.
                    #[cfg(has_io_uring)]
                    if driver
                        .tls_table
                        .as_ref()
                        .is_some_and(|t| t.close_notify_sent(this.conn_index))
                    {
                        return this.finish(Err(crate::handler::close_notify_sent_error()));
                    }
                    let needed = {
                        let ctx = driver.make_ctx();
                        crate::handler::bounded_send_slots(
                            ctx.send_copy_pool,
                            ctx.tls_table,
                            this.conn_index,
                            this.data.len(),
                        )
                    };
                    let needed = match needed {
                        Ok(n) => n,
                        // Permanent: no amount of waiting grows the pool.
                        Err(e) => return this.finish(Err(e)),
                    };
                    let id = executor.enqueue_send_capacity(
                        this.conn_index,
                        this.generation,
                        needed,
                        task_id,
                    );
                    this.state = BackpressuredState::Waiting(id);
                    // Fall through: the pool is usually free, and costing the
                    // common case a wake-up round-trip would be a poor
                    // default for the API reached for under load.
                    this.poll_waiting(driver, executor, id)
                }

                BackpressuredState::Waiting(id) => {
                    // Before anything else: a future can be polled from a
                    // different task than the one that enqueued it (moved
                    // into a `join!`, handed to a spawned task). The queue
                    // wakes owners by task id, and a stale owner on the head
                    // stalls the whole FIFO, not just this send.
                    executor.set_send_owner(id, task_id);
                    // Teardown takes waiting entries out of the FIFO with a
                    // result, so consult the queue before asking for a turn.
                    if let Some(result) = executor.take_send_result(id) {
                        return this.finish(result);
                    }
                    if driver.connections.generation(this.conn_index) != this.generation {
                        return this.abandon(executor, id);
                    }
                    this.poll_waiting(driver, executor, id)
                }

                BackpressuredState::Submitted(id) => {
                    executor.set_send_owner(id, task_id);
                    match executor.take_send_result(id) {
                        Some(result) => this.finish(result),
                        // A recycled slot means teardown ran but left no
                        // result for this id — take the entry off the queue
                        // rather than leaving it for nobody.
                        None if driver.connections.generation(this.conn_index)
                            != this.generation =>
                        {
                            this.abandon(executor, id)
                        }
                        None => Poll::Pending,
                    }
                }
            }
        })
    }
}

impl BackpressuredSendFuture<'_> {
    /// The waiting half of `poll`, shared by the first poll and later ones.
    fn poll_waiting(
        &mut self,
        driver: &mut Driver,
        executor: &mut Executor,
        id: SendId,
    ) -> Poll<io::Result<u32>> {
        let free = driver.send_copy_pool.free_count();
        if !executor.send_capacity_turn(id, free) {
            return Poll::Pending;
        }
        let token = ConnToken::new(self.conn_index, self.generation);
        let submit = {
            let mut ctx = driver.make_ctx();
            ctx.send_bounded(token, self.data, id)
        };
        match submit {
            Ok(()) => {
                // Promotes this id to `submitted` and wakes the new head.
                executor.mark_send_submitted(id);
                self.state = BackpressuredState::Submitted(id);
                // A synchronous settle (an empty message, or a mio send
                // that needed no socket write) lands on the *driver's*
                // completion queue, not the executor's, so this never sees
                // it. What stops such a send hanging is that both run loops
                // drain that queue every iteration. Kept as a cheap
                // belt-and-braces read rather than an assumption about which
                // side settled.
                match executor.take_send_result(id) {
                    Some(result) => self.finish(result),
                    None => Poll::Pending,
                }
            }
            Err(e) => {
                // Nothing was queued and no completion is coming, so the id
                // has to leave the queue or it holds the head forever.
                executor.cancel_send(id);
                self.finish(Err(e))
            }
        }
    }
}

impl Drop for BackpressuredSendFuture<'_> {
    fn drop(&mut self) {
        let id = match self.state {
            BackpressuredState::Waiting(id) | BackpressuredState::Submitted(id) => id,
            // Never polled, or already resolved: nothing was left behind.
            BackpressuredState::Fresh | BackpressuredState::Done => return,
        };
        // Drop runs outside a poll, so the thread-local may be gone (worker
        // teardown). Same guard as `SendFuture::drop`.
        let Some(mut non_null) = CURRENT_DRIVER.with(|c| c.get()) else {
            return;
        };
        let state = unsafe { non_null.as_mut() };
        let executor = unsafe { &mut *state.executor.as_mut() };
        // Waiting: removed, and the next waiter takes the head. Submitted:
        // marked abandoned, so the completion that is still coming removes
        // it rather than parking a result nobody will take.
        executor.cancel_send(id);
    }
}

// ── SendFuture ───────────────────────────────────────────────────────

/// Future that awaits one send's completion. The send was submitted when the
/// future was created; the future resolves with that send's own result, the
/// length its caller passed or the error that ended it, and with no other
/// send's. No allocation.
///
/// Dropping it does not cancel the send: the bytes still go out, and the
/// result is discarded.
pub struct SendFuture {
    conn_index: u32,
    /// See `WithDataFuture` for the role of `generation`.
    generation: u32,
    state: SendFutureState,
}

enum SendFutureState {
    /// The send's entry in the executor's completion table.
    Pending(SendId),
    /// A result known when the future was created; taken by the first poll.
    Ready(Option<io::Result<u32>>),
}

impl SendFuture {
    /// A future for the send `id` names, which the caller has submitted.
    fn pending(conn_index: u32, generation: u32, id: SendId) -> Self {
        SendFuture {
            conn_index,
            generation,
            state: SendFutureState::Pending(id),
        }
    }

    /// A future that resolves with `result` on its first poll.
    #[cfg(has_io_uring)]
    fn ready(conn_index: u32, generation: u32, result: io::Result<u32>) -> Self {
        SendFuture {
            conn_index,
            generation,
            state: SendFutureState::Ready(Some(result)),
        }
    }
}

impl Future for SendFuture {
    type Output = io::Result<u32>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u32>> {
        let this = self.get_mut();
        let id = match &mut this.state {
            SendFutureState::Ready(result) => {
                return Poll::Ready(result.take().expect("SendFuture polled after completion"));
            }
            SendFutureState::Pending(id) => *id,
        };
        with_state(|driver, executor| {
            // A future polled from another task than the one that submitted
            // (moved into a `join!`, handed to a spawned task) is woken where
            // it now lives.
            executor.set_send_owner(id, CURRENT_TASK_ID.with(|c| c.get()));
            match executor.take_send_result(id) {
                Some(result) => {
                    this.state = SendFutureState::Ready(None);
                    Poll::Ready(result)
                }
                // A recycled slot means teardown ran and left no result for
                // this id: take the entry off the table and report the
                // close.
                None if driver.connections.generation(this.conn_index) != this.generation => {
                    executor.cancel_send(id);
                    this.state = SendFutureState::Ready(None);
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    )))
                }
                None => Poll::Pending,
            }
        })
    }
}

impl Drop for SendFuture {
    fn drop(&mut self) {
        let SendFutureState::Pending(id) = self.state else {
            return;
        };
        // Drop runs outside a poll, so the thread-local may be gone (worker
        // teardown), and the table with it.
        let Some(mut non_null) = CURRENT_DRIVER.with(|c| c.get()) else {
            return;
        };
        let state = unsafe { non_null.as_mut() };
        let executor = unsafe { &mut *state.executor.as_mut() };
        // In flight: marked abandoned, so the completion still coming frees
        // the entry. Already resolved: freed now.
        executor.cancel_send(id);
    }
}

// ── ConnectFuture ────────────────────────────────────────────────────

/// Future for an outbound connection, from awaiting [`TcpConnect`] or
/// [`UnixConnect`].
///
/// Submits the connect on its first poll, waits for the completion, and
/// resolves to an owned [`Connection`]. A future that is never polled allocates
/// no socket and no connection slot.
///
/// Two of these futures awaited one after the other run serially. See
/// [`connect`] for running them concurrently.
#[must_use = "a connect future does nothing until polled"]
pub struct ConnectFuture {
    state: ConnectState,
}

enum ConnectState {
    /// Nothing submitted yet.
    Unsubmitted {
        target: ConnectTarget,
        timeout: Option<Duration>,
    },
    /// The connect is in the kernel; waiting for its completion.
    Waiting {
        conn_index: u32,
        generation: u32,
        /// The worker whose connection table holds `conn_index`.
        owner: u32,
    },
    /// Resolved, or failed before submitting. Holds no slot.
    Done,
}

impl ConnectFuture {
    /// Submit the connect described by `target` and arm a timeout if one was
    /// set.
    ///
    /// The driver call is chosen by transport and by whether a server name was
    /// given. The timeout is armed afterwards by connection index;
    /// `arm_connect_timeout` does not depend on the transport on either
    /// backend.
    fn submit(
        target: &ConnectTarget,
        timeout: Option<Duration>,
        driver: &mut crate::backend::Driver,
        executor: &mut crate::runtime::Executor,
    ) -> io::Result<(u32, u32)> {
        let mut ctx = driver.make_ctx();
        let token = match target {
            ConnectTarget::Tcp {
                addr,
                server_name: Some(name),
                ..
            } => ctx.start_connect_tls(*addr, name),
            ConnectTarget::Tcp {
                addr,
                server_name: None,
                ..
            } => ctx.start_connect(*addr),
            ConnectTarget::Unix { path } => ctx.start_connect_unix(path.as_path()),
        }
        .map_err(io::Error::other::<crate::error::Error>)?;
        if let Some(timeout) = timeout {
            let ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
            ctx.arm_connect_timeout(token.index, ms);
        }
        // A plaintext connection receives directly into its accumulator. A
        // TLS connection receives into its TLS engine's buffer.
        #[cfg(has_io_uring)]
        if !matches!(
            target,
            ConnectTarget::Tcp {
                server_name: Some(_),
                ..
            }
        ) && let Some(cs) = driver.connections.get_mut(token.index)
        {
            cs.recv_direct = true;
        }
        let calling_task = CURRENT_TASK_ID.with(|c| c.get());
        executor.owner_task[token.index as usize] = Some(calling_task);
        executor.connect_waiters[token.index as usize] = true;
        Ok((token.index, token.generation))
    }
}

impl Future for ConnectFuture {
    type Output = io::Result<Connection>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<Connection>> {
        let this = self.get_mut();
        with_state(|driver, executor| {
            // First poll: submit. A submission failure holds no slot, so the
            // state moves to `Done` and `Drop` has nothing to release.
            let (conn_index, generation) = match &this.state {
                ConnectState::Unsubmitted { target, timeout } => {
                    match Self::submit(target, *timeout, driver, executor) {
                        Ok(pair) => {
                            this.state = ConnectState::Waiting {
                                conn_index: pair.0,
                                generation: pair.1,
                                owner: crate::runtime::waker::current_worker(),
                            };
                            pair
                        }
                        Err(e) => {
                            this.state = ConnectState::Done;
                            return Poll::Ready(Err(e));
                        }
                    }
                }
                ConnectState::Waiting {
                    conn_index,
                    generation,
                    ..
                } => (*conn_index, *generation),
                ConnectState::Done => {
                    return Poll::Ready(Err(io::Error::other(
                        "connect future polled after completion",
                    )));
                }
            };

            // Slot-reuse safety.
            if driver.connections.generation(conn_index) != generation {
                this.state = ConnectState::Done;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "connection closed",
                )));
            }
            match executor.io_results[conn_index as usize].take() {
                Some(IoResult::Connect(result)) => {
                    this.state = ConnectState::Done;
                    match result {
                        Ok(()) => {
                            // Claim both halves. A freshly connected slot has
                            // no half outstanding, and `Connection` is not
                            // `Copy`, so no other handle can claim them (#528).
                            let idx = conn_index as usize;
                            driver.recv_half_taken[idx] = true;
                            driver.send_half_taken[idx] = true;
                            Poll::Ready(Ok(Connection::from_claimed(ConnCtx::new(
                                conn_index, generation,
                            ))))
                        }
                        Err(e) => Poll::Ready(Err(e)),
                    }
                }
                _ => {
                    // Not ready yet — re-register waiter.
                    executor.connect_waiters[conn_index as usize] = true;
                    Poll::Pending
                }
            }
        })
    }
}

impl Drop for ConnectFuture {
    fn drop(&mut self) {
        // `Unsubmitted` and `Done` hold no slot: an unpolled future never
        // reached the driver, and a resolved future has either handed its slot
        // to the `Connection` or failed without one.
        let (conn_index, generation, owner) = match self.state {
            ConnectState::Waiting {
                conn_index,
                generation,
                owner,
            } => (conn_index, generation, owner),
            _ => return,
        };
        // Only the owning worker's table holds the slot. Dropped elsewhere
        // (the future is `Send`), the connection stays there.
        if crate::runtime::waker::current_worker() != owner {
            return;
        }
        match CURRENT_DRIVER.with(|c| c.get()) {
            Some(mut non_null) => {
                let state = unsafe { non_null.as_mut() };
                let driver = unsafe { &mut *state.driver.as_mut() };
                let executor = unsafe { &mut *state.executor.as_mut() };
                release_connect(driver, executor, conn_index, generation);
            }
            // Outside a task poll (a connection's task dropped at teardown).
            None => crate::runtime::defer_release(crate::runtime::Orphan::Connect {
                conn_index,
                generation,
            }),
        }
    }
}

/// Give up an outbound connection whose `ConnectFuture` was dropped before it
/// resolved. Still connecting: clear the waiter, and the completion handler
/// closes the connection when the connect completes. Already connected (the
/// future had not been polled since): close it now, since no task will.
pub(crate) fn release_connect(
    driver: &mut crate::backend::Driver,
    executor: &mut crate::runtime::Executor,
    conn_index: u32,
    generation: u32,
) {
    // The slot may already hold another connection.
    if driver.connections.generation(conn_index) != generation {
        return;
    }
    let idx = conn_index as usize;
    executor.connect_waiters[idx] = false;
    executor.io_results[idx] = None;
    let open = driver
        .connections
        .get(conn_index)
        .is_some_and(|c| c.lifecycle == crate::connection::Lifecycle::Open);
    if open {
        driver.close_connection(conn_index);
    }
}

// ── Yield ────────────────────────────────────────────────────────────

/// Return control to the worker's event loop once.
///
/// A task runs until it awaits a future that is not ready. Until then no
/// other task on its worker is polled, and no I/O completion, readiness event
/// or timer is processed. A task that does a long stretch of work without such
/// an await, such as many `send_nowait` calls in a row, can await
/// `yield_now()` between parts of it.
///
/// The first poll wakes the task and returns `Pending`; the second returns
/// `Ready`. Tasks already in the worker's ready queue are polled before the
/// second poll. Tasks woken by the completions, readiness events or timers
/// that the event loop processes before the second poll, and tasks woken
/// from other threads, may be polled after it. The event loop does not block
/// while a task is runnable.
///
/// The second poll can come later in the same loop iteration. On io_uring it
/// follows the loop's flush of queued SQEs and its dispatch of the
/// completions the kernel has posted. On mio it follows the write of queued
/// sends, when that write completes an awaited send.
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

/// Future returned by [`yield_now`].
#[must_use = "futures do nothing unless awaited"]
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod yield_now_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    struct CountWakes(AtomicUsize);

    impl Wake for CountWakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The first poll wakes the task once and returns `Pending`; the second
    /// returns `Ready` without waking it. No executor is involved.
    #[test]
    fn yield_now_is_pending_once_then_ready() {
        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut fut = yield_now();
        assert!(Pin::new(&mut fut).poll(&mut cx).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(Pin::new(&mut fut).poll(&mut cx).is_ready());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    }
}

// ── Sleep ────────────────────────────────────────────────────────────

/// Create a future that completes after the given duration.
///
/// On io_uring, uses a timeout SQE internally — no busy-waiting, no timer
/// thread. The timer fires on the same worker thread as the calling task.
///
/// # Panics
///
/// Panics if all 65536 of the worker's timer slots are held (a slot is held
/// from a timer's creation until its future is dropped), or if called outside
/// the ringline async executor.
pub fn sleep(duration: Duration) -> SleepFuture {
    SleepFuture {
        duration,
        timer_slot: None,
        owner: 0,
        generation: 0,
        absolute: None,
    }
}

/// Future returned by [`sleep()`] or [`sleep_until()`]. Completes after
/// the configured duration or at the given deadline.
pub struct SleepFuture {
    duration: Duration,
    /// None until first poll, then Some(slot_index).
    timer_slot: Option<u32>,
    /// Generation when the slot was allocated.
    generation: u16,
    /// If Some, this is an absolute timer (sleep_until).
    absolute: Option<Deadline>,
    /// The worker whose timer pool holds `timer_slot`.
    owner: u32,
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        with_state(|driver, executor| {
            let _ = driver; // used only on io_uring path
            if let Some(slot) = self.timer_slot {
                // Already submitted — check if fired.
                if executor.timer_pool.is_fired(slot) {
                    executor.timer_pool.release(slot);
                    self.timer_slot = None;
                    return Poll::Ready(());
                }
                return Poll::Pending;
            }

            // First poll — allocate slot, fill timespec, submit SQE.
            let waker_id = CURRENT_TASK_ID.with(|c| c.get());
            let (slot, generation) = match executor.timer_pool.allocate(waker_id) {
                Some(pair) => pair,
                None => {
                    // Documented contract: the infallible variants panic on
                    // pool exhaustion (try_sleep/try_timeout are the fallible
                    // API). Completing immediately instead was far worse than
                    // the panic: every timeout() fired a spurious
                    // zero-duration Elapsed that cancelled healthy I/O, and a
                    // sleep() loop became a busy-spin keeping the pool
                    // exhausted.
                    panic!(
                        "timer slot pool exhausted ({} slots) — use try_sleep()/try_timeout() to handle it",
                        executor.timer_pool.capacity()
                    );
                }
            };

            #[cfg(has_io_uring)]
            {
                let payload = TimerSlotPool::encode_payload(slot, generation);
                let ud = UserData::encode(OpTag::Timer, 0, payload);

                let submit_result = if let Some(deadline) = self.absolute {
                    let ts_ptr =
                        executor
                            .timer_pool
                            .set_absolute(slot, deadline.secs, deadline.nsecs);
                    driver.ring.submit_timeout_abs(ts_ptr, ud)
                } else {
                    let ts_ptr = executor.timer_pool.set_relative(slot, self.duration);
                    driver.ring.submit_timeout(ts_ptr, ud)
                };

                if let Err(e) = submit_result {
                    executor.timer_pool.release(slot);
                    // SQ full at timer-arm time. Completing immediately would
                    // fire a spurious zero-duration timeout; panicking matches
                    // the documented infallible contract.
                    panic!(
                        "timer SQE submission failed: {e} — use try_sleep()/try_timeout() for fallible arming"
                    );
                }
            }

            #[cfg(not(has_io_uring))]
            {
                // Mio backend: store deadline; the event loop polls timer expiry.
                if let Some(deadline) = self.absolute {
                    executor
                        .timer_pool
                        .set_absolute(slot, deadline.secs, deadline.nsecs);
                } else {
                    executor.timer_pool.set_relative(slot, self.duration);
                }
            }

            self.timer_slot = Some(slot);
            self.generation = generation;
            self.owner = crate::runtime::waker::current_worker();
            Poll::Pending
        })
    }
}

impl Drop for SleepFuture {
    fn drop(&mut self) {
        let Some(slot) = self.timer_slot else { return };
        // Only the owning worker's pool holds the slot. Dropped elsewhere
        // (the future is `Send`), the slot stays allocated there.
        if crate::runtime::waker::current_worker() != self.owner {
            return;
        }
        match CURRENT_DRIVER.with(|c| c.get()) {
            Some(mut non_null) => {
                let state = unsafe { non_null.as_mut() };
                let driver = unsafe { &mut *state.driver.as_mut() };
                let executor = unsafe { &mut *state.executor.as_mut() };
                release_timer_slot(driver, executor, slot, self.generation);
            }
            // Outside a task poll (a connection's task dropped at teardown).
            None => crate::runtime::defer_release(crate::runtime::Orphan::TimerSlot {
                slot,
                generation: self.generation,
            }),
        }
    }
}

/// Release a sleep's timer slot. On io_uring, cancels the timer first if it
/// has not fired; a timer CQE that arrives after the release is
/// rejected by its generation. On mio, releasing clears the deadline.
#[cfg_attr(not(has_io_uring), allow(unused_variables))]
pub(crate) fn release_timer_slot(
    driver: &mut crate::backend::Driver,
    executor: &mut crate::runtime::Executor,
    slot: u32,
    generation: u16,
) {
    if !executor.timer_pool.is_fired(slot) {
        #[cfg(has_io_uring)]
        {
            let payload = TimerSlotPool::encode_payload(slot, generation);
            let target_ud = UserData::encode(OpTag::Timer, 0, payload);
            // Best effort cancel; timer fires harmlessly if already expired.
            let _ = driver.ring.submit_async_cancel(target_ud.raw(), 0);
        }
    }
    executor.timer_pool.release(slot);
}

/// Create a sleep future, returning an error if the timer pool is exhausted.
///
/// Unlike [`sleep()`] which panics on pool exhaustion, this returns
/// `Err(TimerExhausted)` so callers can handle capacity limits gracefully.
///
/// The timer slot is allocated eagerly (at call time, not on first poll).
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn try_sleep(duration: Duration) -> Result<SleepFuture, TimerExhausted> {
    with_state(|driver, executor| {
        let _ = driver; // used only on io_uring path
        let waker_id = CURRENT_TASK_ID.with(|c| c.get());
        let (slot, generation) = executor.timer_pool.allocate(waker_id).ok_or_else(|| {
            crate::metrics::POOL.increment(crate::metrics::pool::TIMER_EXHAUSTED);
            TimerExhausted
        })?;

        #[cfg(has_io_uring)]
        {
            let payload = TimerSlotPool::encode_payload(slot, generation);
            let ud = UserData::encode(OpTag::Timer, 0, payload);
            let ts_ptr = executor.timer_pool.set_relative(slot, duration);

            if let Err(_e) = driver.ring.submit_timeout(ts_ptr, ud) {
                executor.timer_pool.release(slot);
                // SQE submission failure — complete immediately (`sleep()`
                // panics instead).
                return Ok(SleepFuture {
                    duration,
                    timer_slot: None,
                    owner: 0,
                    generation: 0,
                    absolute: None,
                });
            }
        }

        #[cfg(not(has_io_uring))]
        {
            executor.timer_pool.set_relative(slot, duration);
        }

        Ok(SleepFuture {
            duration,
            timer_slot: Some(slot),
            owner: crate::runtime::waker::current_worker(),
            generation,
            absolute: None,
        })
    })
}

// ── Deadline (absolute timer support) ─────────────────────────────────

/// A monotonic clock deadline for use with absolute timers.
///
/// Created via [`Deadline::after()`] or [`Deadline::now()`].
/// Uses `CLOCK_MONOTONIC` to match io_uring's default clock.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline {
    pub(crate) secs: u64,
    pub(crate) nsecs: u32,
}

impl Deadline {
    /// Capture the current monotonic time.
    pub fn now() -> Self {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // Safety: clock_gettime with CLOCK_MONOTONIC is safe.
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        }
        Deadline {
            secs: ts.tv_sec as u64,
            nsecs: ts.tv_nsec as u32,
        }
    }

    /// Create a deadline `duration` from now.
    pub fn after(duration: Duration) -> Self {
        let now = Self::now();
        let mut secs = now.secs + duration.as_secs();
        let mut nsecs = now.nsecs + duration.subsec_nanos();
        if nsecs >= 1_000_000_000 {
            nsecs -= 1_000_000_000;
            secs += 1;
        }
        Deadline { secs, nsecs }
    }

    /// Duration remaining until this deadline (saturates at zero).
    pub fn remaining(&self) -> Duration {
        let now = Self::now();
        if now.secs > self.secs || (now.secs == self.secs && now.nsecs >= self.nsecs) {
            return Duration::ZERO;
        }
        let mut secs = self.secs - now.secs;
        let nsecs = if self.nsecs >= now.nsecs {
            self.nsecs - now.nsecs
        } else {
            secs -= 1;
            1_000_000_000 + self.nsecs - now.nsecs
        };
        Duration::new(secs, nsecs)
    }
}

/// Create a future that completes at the given absolute deadline.
///
/// Uses io_uring's `TIMEOUT_ABS` flag with `CLOCK_MONOTONIC` for
/// precise deadline-based timing without accumulated drift.
///
/// # Panics
///
/// Panics if the timer slot pool is exhausted, or if called outside the
/// ringline async executor.
pub fn sleep_until(deadline: Deadline) -> SleepFuture {
    SleepFuture {
        duration: Duration::ZERO, // unused for absolute timers
        timer_slot: None,
        owner: 0,
        generation: 0,
        absolute: Some(deadline),
    }
}

/// Create an absolute-deadline sleep, returning an error if the timer pool is exhausted.
///
/// Unlike [`sleep_until()`] which panics on pool exhaustion, this returns
/// `Err(TimerExhausted)` so callers can handle capacity limits gracefully.
///
/// The timer slot is allocated eagerly (at call time, not on first poll).
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn try_sleep_until(deadline: Deadline) -> Result<SleepFuture, TimerExhausted> {
    with_state(|driver, executor| {
        let _ = driver; // used only on io_uring path
        let waker_id = CURRENT_TASK_ID.with(|c| c.get());
        let (slot, generation) = executor.timer_pool.allocate(waker_id).ok_or_else(|| {
            crate::metrics::POOL.increment(crate::metrics::pool::TIMER_EXHAUSTED);
            TimerExhausted
        })?;

        #[cfg(has_io_uring)]
        {
            let payload = TimerSlotPool::encode_payload(slot, generation);
            let ud = UserData::encode(OpTag::Timer, 0, payload);
            let ts_ptr = executor
                .timer_pool
                .set_absolute(slot, deadline.secs, deadline.nsecs);

            if let Err(_e) = driver.ring.submit_timeout_abs(ts_ptr, ud) {
                executor.timer_pool.release(slot);
                return Ok(SleepFuture {
                    duration: Duration::ZERO,
                    timer_slot: None,
                    owner: 0,
                    generation: 0,
                    absolute: Some(deadline),
                });
            }
        }

        #[cfg(not(has_io_uring))]
        {
            executor
                .timer_pool
                .set_absolute(slot, deadline.secs, deadline.nsecs);
        }

        Ok(SleepFuture {
            duration: Duration::ZERO,
            timer_slot: Some(slot),
            owner: crate::runtime::waker::current_worker(),
            generation,
            absolute: Some(deadline),
        })
    })
}

// ── Timeout ──────────────────────────────────────────────────────────

/// Error returned when a [`timeout()`] deadline expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elapsed;

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("deadline has elapsed")
    }
}

impl std::error::Error for Elapsed {}

/// Wrap a future with a deadline. If the future does not complete within
/// `duration`, returns `Err(Elapsed)`.
///
/// # Panics
///
/// Panics on first poll if the timer pool is exhausted, or if polled outside
/// the ringline async executor. [`try_timeout`] returns an error for an
/// exhausted pool instead.
///
/// # Example
///
/// ```no_run
/// # async fn example() {
/// use std::time::Duration;
/// match ringline::timeout(Duration::from_secs(1), async { 42 }).await {
///     Ok(value) => { /* completed in time */ }
///     Err(_elapsed) => { /* timed out */ }
/// }
/// # }
/// ```
pub fn timeout<F: Future>(duration: Duration, future: F) -> TimeoutFuture<F> {
    TimeoutFuture {
        future,
        sleep: sleep(duration),
    }
}

/// Wrap a future with a deadline, returning an error if the timer pool is full.
///
/// Unlike [`timeout()`] which panics on pool exhaustion, this returns
/// `Err(TimerExhausted)` so callers can handle capacity limits gracefully.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn try_timeout<F: Future>(
    duration: Duration,
    future: F,
) -> Result<TimeoutFuture<F>, TimerExhausted> {
    let sleep = try_sleep(duration)?;
    Ok(TimeoutFuture { future, sleep })
}

/// Wrap a future with an absolute deadline. If the future does not complete
/// before `deadline`, returns `Err(Elapsed)`.
///
/// Uses io_uring's `TIMEOUT_ABS` flag with `CLOCK_MONOTONIC`.
///
/// # Panics
///
/// Panics if the timer slot pool is exhausted.
pub fn timeout_at<F: Future>(deadline: Deadline, future: F) -> TimeoutFuture<F> {
    TimeoutFuture {
        future,
        sleep: sleep_until(deadline),
    }
}

/// Wrap a future with an absolute deadline, returning an error if the timer pool is full.
///
/// Unlike [`timeout_at()`] which panics on pool exhaustion, this returns
/// `Err(TimerExhausted)` so callers can handle capacity limits gracefully.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn try_timeout_at<F: Future>(
    deadline: Deadline,
    future: F,
) -> Result<TimeoutFuture<F>, TimerExhausted> {
    let sleep = try_sleep_until(deadline)?;
    Ok(TimeoutFuture { future, sleep })
}

pin_project_lite::pin_project! {
    /// Future returned by [`timeout()`] or [`timeout_at()`].
    pub struct TimeoutFuture<F> {
        #[pin]
        future: F,
        #[pin]
        sleep: SleepFuture,
    }
}

impl<F: Future> Future for TimeoutFuture<F> {
    type Output = Result<F::Output, Elapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        // Poll the inner future first.
        if let Poll::Ready(output) = this.future.poll(cx) {
            return Poll::Ready(Ok(output));
        }

        // Poll the sleep timer.
        if let Poll::Ready(()) = this.sleep.poll(cx) {
            return Poll::Ready(Err(Elapsed));
        }

        Poll::Pending
    }
}

// ── Disk I/O async API ──────────────────────────────────────────────

/// Future that awaits a disk-I/O completion: `fs::read`, `fs::write`,
/// `fs::fsync`, `fs::rename`, `fs::remove`, `fs::mkdir`, NVMe and direct
/// I/O. The operation was submitted before this future was created;
/// its completion stores the result and wakes the task.
pub struct DiskIoFuture {
    pub(crate) seq: u32,
    /// Set once `poll` has returned `Ready`: the result has been taken.
    done: bool,
    /// The worker whose executor holds `seq`.
    owner: u32,
}

impl DiskIoFuture {
    pub(crate) fn new(seq: u32) -> Self {
        DiskIoFuture {
            seq,
            done: false,
            owner: crate::runtime::waker::current_worker(),
        }
    }
}

impl Future for DiskIoFuture {
    type Output = io::Result<i32>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<i32>> {
        assert!(!self.done, "DiskIoFuture polled after completion");
        let poll = with_state(|_driver, executor| {
            match executor.take_disk_io_result(self.seq) {
                Some(result) if result < 0 => {
                    Poll::Ready(Err(io::Error::from_raw_os_error(-result)))
                }
                Some(result) => Poll::Ready(Ok(result)),
                None => {
                    // Re-register waiter (polled before CQE arrived or after spurious wake).
                    let task_id = CURRENT_TASK_ID.with(|c| c.get());
                    executor.wait_disk_io(self.seq, task_id);
                    Poll::Pending
                }
            }
        });
        if poll.is_ready() {
            self.done = true;
        }
        poll
    }
}

impl Drop for DiskIoFuture {
    fn drop(&mut self) {
        // Only the owning worker's executor holds the key. Dropped elsewhere
        // (the future is `Send`), the key stays held there (#575).
        if !self.done && crate::runtime::waker::current_worker() == self.owner {
            crate::fs::abandon_disk_io_key(self.seq);
        }
    }
}

/// Open a Direct I/O file from any async task.
///
/// Returns a [`DirectIoFile`](crate::direct_io::DirectIoFile) handle
/// for use with [`direct_io_read()`].
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn open_direct_io_file(path: &str) -> io::Result<crate::direct_io::DirectIoFile> {
    with_state(|driver, _| {
        let mut ctx = driver.make_ctx();
        ctx.open_direct_io_file(path)
    })
}

/// Open a Direct I/O file from any async task with `options` added to the
/// flags [`open_direct_io_file()`] uses.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn open_direct_io_file_with(
    path: &str,
    options: crate::direct_io::DirectIoOpenOptions,
) -> io::Result<crate::direct_io::DirectIoFile> {
    with_state(|driver, _| {
        let mut ctx = driver.make_ctx();
        ctx.open_direct_io_file_with(path, options)
    })
}

/// Open an NVMe device from any async task.
///
/// Returns an [`NvmeDevice`](crate::nvme::NvmeDevice) handle
/// for use with [`nvme_read()`], [`nvme_write()`], and [`nvme_flush()`].
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn open_nvme_device(path: &str, nsid: u32) -> io::Result<crate::nvme::NvmeDevice> {
    with_state(|driver, _| {
        let mut ctx = driver.make_ctx();
        ctx.open_nvme_device(path, nsid)
    })
}

/// Submit a Direct I/O read and return a future for the result.
///
/// Reads `len` bytes from `offset` into the buffer at `buf`.
/// The returned future completes when the io_uring CQE arrives.
///
/// # Safety
///
/// `buf` must point to aligned, writable memory of at least `len` bytes
/// that remains valid until the future completes.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub unsafe fn direct_io_read(
    file: crate::direct_io::DirectIoFile,
    offset: u64,
    buf: *mut u8,
    len: u32,
) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        // Safety: the outer `direct_io_read()` is already unsafe, and the
        // caller guarantees the buffer invariants.
        #[allow(unused_unsafe)]
        let seq = unsafe { ctx.direct_io_read(file, offset, buf, len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

/// Submit an NVMe read and return a future for the result.
///
/// Reads `num_blocks` logical blocks starting at `lba` into the buffer
/// at `buf_addr` with length `buf_len`. The returned future completes
/// when the io_uring CQE arrives.
///
/// # Safety
///
/// `buf_addr` must point to valid, aligned memory of at least `buf_len`
/// bytes that remains valid until the returned future completes.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub unsafe fn nvme_read(
    device: crate::nvme::NvmeDevice,
    lba: u64,
    num_blocks: u16,
    buf_addr: u64,
    buf_len: u32,
) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        // SAFETY: forwarded contract — the caller of the (unsafe) public
        // wrapper guarantees buf_addr/buf_len validity and lifetime.
        let seq = unsafe { ctx.nvme_read(device, lba, num_blocks, buf_addr, buf_len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

/// Submit a Direct I/O write and return a future for the result.
///
/// Writes `len` bytes from the buffer at `buf` to `offset` in the file.
/// The returned future completes when the io_uring CQE arrives.
///
/// # Safety
///
/// `buf` must point to aligned, readable memory of at least `len` bytes
/// that remains valid until the future completes.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub unsafe fn direct_io_write(
    file: crate::direct_io::DirectIoFile,
    offset: u64,
    buf: *const u8,
    len: u32,
) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        // Safety: the outer `direct_io_write()` is already unsafe, and the
        // caller guarantees the buffer invariants.
        #[allow(unused_unsafe)]
        let seq = unsafe { ctx.direct_io_write(file, offset, buf, len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

/// Submit an fsync of a Direct I/O file and return a future for the result.
///
/// The future resolves to `Ok(0)` once every write to `file` that completed
/// before the call is on stable storage. On a Linux block device this sends
/// the device a cache flush, which persists everything in its volatile write
/// cache and not only this file's writes; the kernel skips the flush when the
/// device reports a write-through cache. To make individual writes durable
/// without flushing the whole cache, open the file with
/// [`DirectIoOpenOptions::dsync`](crate::direct_io::DirectIoOpenOptions::dsync).
///
/// On io_uring the kernel runs an fsync on an io-wq worker thread.
/// On mio it is `fsync(2)` on the disk I/O pool; on macOS that call does not
/// flush the drive's own cache.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn direct_io_fsync(file: crate::direct_io::DirectIoFile) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.direct_io_fsync(file)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

/// Submit an NVMe flush and return a future for the result.
///
/// Flushes volatile write caches on the device, ensuring all previously
/// written data is persisted to non-volatile storage. The returned future
/// completes when the io_uring CQE arrives.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn nvme_flush(device: crate::nvme::NvmeDevice) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.nvme_flush(device)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

/// Submit an NVMe write and return a future for the result.
///
/// Writes `num_blocks` logical blocks starting at `lba` from the buffer
/// at `buf_addr` with length `buf_len`. The returned future completes
/// when the io_uring CQE arrives.
///
/// # Safety
///
/// `buf_addr` must point to valid, aligned memory of at least `buf_len`
/// bytes that remains valid until the returned future completes.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub unsafe fn nvme_write(
    device: crate::nvme::NvmeDevice,
    lba: u64,
    num_blocks: u16,
    buf_addr: u64,
    buf_len: u32,
) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        // SAFETY: forwarded contract — see nvme_read above.
        let seq = unsafe { ctx.nvme_write(device, lba, num_blocks, buf_addr, buf_len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

// ── UDP async API ───────────────────────────────────────────────────

/// Async context for a UDP socket.
///
/// Passed to [`AsyncEventHandler::on_udp_bind()`](crate::AsyncEventHandler::on_udp_bind)
/// for each bound UDP socket. Provides async recv and fire-and-forget send.
#[derive(Clone, Copy)]
pub struct UdpCtx {
    pub(crate) udp_index: u32,
}

impl UdpCtx {
    /// Returns the UDP socket index within this worker.
    pub fn index(&self) -> usize {
        self.udp_index as usize
    }

    /// Receive a datagram, returning the payload and source address.
    ///
    /// Suspends until a datagram is available. Each call returns exactly one
    /// datagram. The payload is copied into a `Vec<u8>` (datagrams are
    /// typically small, so this is acceptable for the initial implementation).
    ///
    /// Only one task should await this per socket at a time; a second waiter
    /// overwrites the first, which is then leaked (it must still be driven
    /// from another wake source). If you need fan-out to multiple consumers,
    /// run a single recv loop and forward the payloads through your own
    /// channel.
    pub fn recv_from(&self) -> UdpRecvFuture {
        UdpRecvFuture {
            udp_index: self.udp_index,
        }
    }

    /// Receive the next datagram and invoke `f(payload, peer)` zero-copy.
    ///
    /// Unlike [`recv_from()`](Self::recv_from), this does not allocate a `Vec`
    /// for the payload. On the io_uring backend the callback runs over the
    /// kernel-provided buffer directly; on the mio backend it runs over the
    /// per-socket recv buffer. Either way, the buffer is released as soon as
    /// the callback returns, so any data the caller wants to keep must be
    /// copied out inside `f`.
    ///
    /// Same single-consumer semantics as [`recv_from()`](Self::recv_from).
    pub fn with_datagram<F, R>(&self, f: F) -> UdpWithDatagramFuture<F, R>
    where
        F: FnMut(&[u8], SocketAddr) -> R + Unpin,
    {
        UdpWithDatagramFuture {
            udp_index: self.udp_index,
            f: Some(f),
            _marker: std::marker::PhantomData,
        }
    }

    /// Timestamped counterpart of
    /// [`recv_batch`](Self::recv_batch) — each invocation of `f`
    /// receives a third argument: the [`Instant`] the driver first
    /// observed the datagram in user space (in the io_uring CQE
    /// handler on the io_uring backend, or in the `recv_from` poll
    /// on the mio backend). Use this to feed protocol drivers that
    /// measure RTT (like quinn-proto's `handle_datagram(now, ...)`)
    /// without including executor wake + task poll latency in the
    /// measurement — that latency would otherwise be charged to the
    /// network path and trigger spurious loss / congestion signals
    /// at high pps.
    ///
    /// All other semantics — single-consumer, zero-copy borrow,
    /// `max` trade-off — match [`recv_batch`](Self::recv_batch).
    pub fn recv_batch_timed<F>(&self, max: usize, f: F) -> UdpRecvBatchTimedFuture<F>
    where
        F: FnMut(&[u8], SocketAddr, Instant) + Unpin,
    {
        debug_assert!(max > 0, "recv_batch_timed max must be at least 1");
        UdpRecvBatchTimedFuture {
            udp_index: self.udp_index,
            max,
            f: Some(f),
        }
    }

    /// Drain up to `max` currently-queued datagrams in a single poll.
    ///
    /// Resolves once at least one datagram is available. On poll-Ready,
    /// the callback is invoked up to `max` times — once per queued
    /// datagram — before the future returns the count drained. This
    /// collapses what would otherwise be N task wake-cycles into one
    /// and is the high-throughput counterpart to
    /// [`with_datagram()`](Self::with_datagram).
    ///
    /// **Pick `max` carefully.** A larger value reduces executor
    /// overhead at high pps but delays the next trip through your
    /// recv→handle→send loop, which on protocol drivers like QUIC
    /// translates into delayed ACK / `MAX_STREAM_DATA` emission and
    /// can stall the peer's congestion window. As a rule of thumb,
    /// 4–16 is a reasonable starting point: enough to amortise the
    /// per-poll overhead at thousands of pps without buffering more
    /// than a few millisecond's worth of inbound traffic before the
    /// next send-side flush. `max = 0` is invalid and panics in debug
    /// builds.
    ///
    /// io_uring multishot recv keeps writing CQEs into our recv queue
    /// between event-loop iterations, so by the time a task is polled
    /// the queue may already hold several datagrams. Draining several
    /// at once avoids the per-packet executor wake/poll overhead that
    /// becomes the bottleneck at packet rates approaching the upper
    /// end of what a single core can process (5K+ pps).
    ///
    /// Same zero-copy semantics as [`with_datagram()`](Self::with_datagram):
    /// each invocation of `f` borrows directly from the kernel-provided
    /// buffer; the buffer is released back to the kernel after `f`
    /// returns and before the next datagram is dispatched.
    ///
    /// Same single-consumer semantics as [`recv_from()`](Self::recv_from).
    pub fn recv_batch<F>(&self, max: usize, f: F) -> UdpRecvBatchFuture<F>
    where
        F: FnMut(&[u8], SocketAddr) + Unpin,
    {
        debug_assert!(max > 0, "recv_batch max must be at least 1");
        UdpRecvBatchFuture {
            udp_index: self.udp_index,
            max,
            f: Some(f),
        }
    }

    /// Resolve when at least one UDP send slot is available on this socket.
    ///
    /// Use this to back off when [`UdpCtx::send_to`] returns
    /// [`crate::error::UdpSendError::PoolExhausted`], rather than busy-looping.
    /// On the io_uring backend the future suspends until a completion frees
    /// a slot. On the mio backend sends are synchronous and this future is
    /// always immediately ready — callers can still use it to stay
    /// backend-agnostic.
    ///
    /// Only one task should await this per socket at a time; a second waiter
    /// overwrites the first, which is then leaked (it must still be driven
    /// from another wake source).
    pub fn send_ready(&self) -> UdpSendReadyFuture {
        UdpSendReadyFuture {
            udp_index: self.udp_index,
            #[cfg(not(has_io_uring))]
            yielded: false,
        }
    }

    /// Send a datagram to the given peer (fire-and-forget, copying).
    ///
    /// Copies `data` into the send pool and submits a send SQE; up to
    /// [`udp_send_slots`](crate::ConfigBuilder::udp_send_slots) sends can be in
    /// flight per socket.
    #[cfg(has_io_uring)]
    pub fn send_to(&self, peer: SocketAddr, data: &[u8]) -> Result<(), crate::error::UdpSendError> {
        with_state(|driver, _executor| driver.udp_send_to(self.udp_index, peer, data, None))
    }

    /// Send a datagram to the given peer (mio backend — synchronous non-blocking send).
    ///
    /// `WouldBlock` is surfaced as [`crate::error::UdpSendError::PoolExhausted`] so callers
    /// have a single "try again later" branch that matches the io_uring backend.
    #[cfg(not(has_io_uring))]
    pub fn send_to(&self, peer: SocketAddr, data: &[u8]) -> Result<(), crate::error::UdpSendError> {
        with_state(|driver, _executor| {
            let idx = self.udp_index as usize;
            if idx >= driver.udp_sockets.len() {
                return Err(crate::error::UdpSendError::Io(io::Error::other(
                    "invalid UDP socket index",
                )));
            }
            // A connected socket sends to its peer with `send`: macOS refuses
            // `sendto` with an address on a connected socket (EISCONN).
            let sent = if driver.udp_connected_peers[idx] == Some(peer) {
                match driver.udp_sockets[idx].send(data) {
                    // A connected socket reports an earlier ICMP
                    // port-unreachable once, on the next send, which then
                    // sends nothing. The error is cleared, so send again.
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                        driver.udp_sockets[idx].send(data)
                    }
                    other => other,
                }
            } else {
                driver.udp_sockets[idx].send_to(data, peer)
            };
            match sent {
                Ok(_) => {
                    crate::metrics::UDP.increment(crate::metrics::udp::DATAGRAMS_SENT);
                    Ok(())
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    Err(crate::error::UdpSendError::PoolExhausted)
                }
                Err(e) => Err(crate::error::UdpSendError::Io(e)),
            }
        })
    }

    /// Send `data` segmented into back-to-back `segment_size`-byte UDP
    /// datagrams in a *single* `sendmsg` syscall, using Linux GSO
    /// (`UDP_SEGMENT`).
    ///
    /// `data.len()` must be a positive multiple of `segment_size`, except
    /// the final packet may be shorter — the kernel splits the buffer
    /// at every `segment_size` boundary and sends a smaller trailing
    /// packet for any remainder.
    ///
    /// On the io_uring backend this attaches the cmsg to the existing
    /// per-slot `msghdr` and submits one SQE — at high packet rates
    /// this is several times faster than calling `send_to` per
    /// datagram. On the mio backend (which doesn't have a built-in
    /// place to bolt on cmsgs), this falls back to calling the
    /// underlying `send_to` once per `segment_size` chunk; the
    /// observable behavior is identical to applications, just without
    /// the syscall savings.
    ///
    /// Errors:
    /// - `Io(InvalidInput)` if `data` is too large for the send pool
    ///   slot, or if `segment_size` is zero or larger than `data`.
    /// - `PoolExhausted` if no free slot is currently available — wait
    ///   on [`send_ready`](Self::send_ready) and retry.
    #[cfg(has_io_uring)]
    pub fn send_to_gso(
        &self,
        peer: SocketAddr,
        data: &[u8],
        segment_size: u16,
    ) -> Result<(), crate::error::UdpSendError> {
        with_state(|driver, _executor| {
            driver.udp_send_to(self.udp_index, peer, data, Some(segment_size))
        })
    }

    /// mio fallback for [`send_to_gso`](Self::send_to_gso): emits
    /// per-segment `send_to` calls. Same observable result, no syscall
    /// batching benefit.
    #[cfg(not(has_io_uring))]
    pub fn send_to_gso(
        &self,
        peer: SocketAddr,
        data: &[u8],
        segment_size: u16,
    ) -> Result<(), crate::error::UdpSendError> {
        if segment_size == 0 || (segment_size as usize) > data.len() {
            return Err(crate::error::UdpSendError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GSO segment_size invalid for data length",
            )));
        }
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + segment_size as usize).min(data.len());
            self.send_to(peer, &data[offset..end])?;
            offset = end;
        }
        Ok(())
    }
}

/// Future returned by [`UdpCtx::recv_from()`].
pub struct UdpRecvFuture {
    udp_index: u32,
}

impl Future for UdpRecvFuture {
    type Output = (Vec<u8>, SocketAddr);

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|driver, executor| {
            let idx = self.udp_index as usize;
            if idx < executor.udp_recv_queues.len()
                && let Some(mut entry) = executor.udp_recv_queues[idx].pop_front()
            {
                // GRO-coalesced entry: hand out ONE datagram per call (the
                // docs promise "the next datagram"). Returning the whole
                // coalesced blob concatenated N datagrams into one.
                if entry.segment_size != 0 {
                    let (start, end) = entry.next_segment_range();
                    let peer = entry.peer;
                    let seg = entry.data()[start..end].to_vec();
                    entry.consumed = end as u32;
                    if entry.exhausted() {
                        let bid = entry.bid_to_release();
                        #[cfg(has_io_uring)]
                        if let Some(bid) = bid {
                            driver.udp_pending_replenish.push(bid);
                        }
                        #[cfg(not(has_io_uring))]
                        let _ = bid;
                    } else {
                        executor.udp_recv_queues[idx].push_front(entry);
                    }
                    let _ = &driver;
                    return Poll::Ready((seg, peer));
                }
                let bid = entry.bid_to_release();
                let owned = entry.into_owned();
                #[cfg(has_io_uring)]
                if let Some(bid) = bid {
                    driver.udp_pending_replenish.push(bid);
                }
                #[cfg(not(has_io_uring))]
                let _ = (bid, driver);
                return Poll::Ready(owned);
            }
            // Register as waiter so the CQE handler wakes us. There is
            // only one waiter slot per socket; if a different task
            // already registered, we'd silently overwrite and the prior
            // task would get stuck forever. That's documented as
            // "single-consumer" semantics on `recv_from`, but it's an
            // easy mistake — fail loud in debug builds.
            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            if idx < executor.udp_recv_waiters.len() {
                debug_assert!(
                    executor.udp_recv_waiters[idx].is_none_or(|t| t == task_id),
                    "two distinct tasks awaiting recv_from on UdpCtx index {idx}; \
                     UdpCtx::recv_from supports a single consumer per socket"
                );
                executor.udp_recv_waiters[idx] = Some(task_id);
            }
            Poll::Pending
        })
    }
}

/// Future returned by [`UdpCtx::with_datagram()`].
///
/// Zero-copy alternative to [`UdpCtx::recv_from()`]: the callback is invoked
/// over a borrowed slice into the kernel-provided buffer (io_uring) or the
/// owned recv buffer (mio), without ever allocating a `Vec` for the payload.
/// The buffer is released back to the kernel once the callback returns.
pub struct UdpWithDatagramFuture<F, R>
where
    F: FnMut(&[u8], SocketAddr) -> R + Unpin,
{
    udp_index: u32,
    f: Option<F>,
    _marker: std::marker::PhantomData<fn() -> R>,
}

impl<F, R> Future for UdpWithDatagramFuture<F, R>
where
    F: FnMut(&[u8], SocketAddr) -> R + Unpin,
{
    type Output = R;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<R> {
        let this = self.get_mut();
        with_state(|driver, executor| {
            let idx = this.udp_index as usize;
            if idx < executor.udp_recv_queues.len()
                && let Some(mut entry) = executor.udp_recv_queues[idx].pop_front()
            {
                let f = this
                    .f
                    .as_mut()
                    .expect("UdpWithDatagramFuture polled after Ready");
                // One datagram per call: for a GRO-coalesced entry, run the
                // callback on the next segment and keep the remainder queued.
                let (start, end) = entry.next_segment_range();
                let r = f(&entry.data()[start..end], entry.peer);
                this.f.take();
                entry.consumed = end as u32;
                if entry.exhausted() {
                    let bid = entry.bid_to_release();
                    drop(entry);
                    #[cfg(has_io_uring)]
                    if let Some(bid) = bid {
                        driver.udp_pending_replenish.push(bid);
                    }
                    #[cfg(not(has_io_uring))]
                    let _ = (bid, driver);
                } else {
                    executor.udp_recv_queues[idx].push_front(entry);
                }
                return Poll::Ready(r);
            }
            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            if idx < executor.udp_recv_waiters.len() {
                debug_assert!(
                    executor.udp_recv_waiters[idx].is_none_or(|t| t == task_id),
                    "two distinct tasks awaiting recv on UdpCtx index {idx}; \
                     UdpCtx::with_datagram supports a single consumer per socket"
                );
                executor.udp_recv_waiters[idx] = Some(task_id);
            }
            Poll::Pending
        })
    }
}

/// Future returned by [`UdpCtx::recv_batch()`].
///
/// Drains up to `max` queued datagrams on the first poll where at
/// least one is available. Returns the count of datagrams drained
/// (between 1 and `max`). See [`UdpCtx::recv_batch`] for the rationale
/// on choosing `max`.
pub struct UdpRecvBatchFuture<F>
where
    F: FnMut(&[u8], SocketAddr) + Unpin,
{
    udp_index: u32,
    max: usize,
    f: Option<F>,
}

impl<F> Future for UdpRecvBatchFuture<F>
where
    F: FnMut(&[u8], SocketAddr) + Unpin,
{
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<usize> {
        let this = self.get_mut();
        with_state(|driver, executor| {
            let idx = this.udp_index as usize;
            if idx >= executor.udp_recv_queues.len() || executor.udp_recv_queues[idx].is_empty() {
                let task_id = CURRENT_TASK_ID.with(|c| c.get());
                if idx < executor.udp_recv_waiters.len() {
                    debug_assert!(
                        executor.udp_recv_waiters[idx].is_none_or(|t| t == task_id),
                        "two distinct tasks awaiting recv on UdpCtx index {idx}; \
                         UdpCtx::recv_batch supports a single consumer per socket"
                    );
                    executor.udp_recv_waiters[idx] = Some(task_id);
                }
                return Poll::Pending;
            }

            let f = this
                .f
                .as_mut()
                .expect("UdpRecvBatchFuture polled after Ready");

            let mut drained: usize = 0;
            while drained < this.max
                && let Some(entry) = executor.udp_recv_queues[idx].pop_front()
            {
                let bid = entry.bid_to_release();
                let peer = entry.peer;
                // One callback per datagram: GRO-coalesced entries fan out
                // into per-segment slices here. `drained` counts entries
                // (kernel recv completions), so the bid lifetime stays simple
                // — released once after the whole entry is consumed.
                entry.for_each_segment(|seg| f(seg, peer));
                drop(entry);
                #[cfg(has_io_uring)]
                if let Some(bid) = bid {
                    driver.udp_pending_replenish.push(bid);
                }
                // On mio the bid is always `None` (no kernel buf ring) and
                // `driver` is borrowed but never read inside the loop. Keep
                // `let _ = bid;` here to silence the per-iteration unused
                // warning without moving `driver` (which the loop will
                // touch again on the next iteration).
                #[cfg(not(has_io_uring))]
                let _ = bid;
                drained += 1;
            }
            this.f.take();
            #[cfg(not(has_io_uring))]
            let _ = driver;
            Poll::Ready(drained)
        })
    }
}

/// Future returned by [`UdpCtx::recv_batch_timed()`].
///
/// Identical to [`UdpRecvBatchFuture`] except the callback receives
/// the driver-captured arrival timestamp as a third argument.
pub struct UdpRecvBatchTimedFuture<F>
where
    F: FnMut(&[u8], SocketAddr, Instant) + Unpin,
{
    udp_index: u32,
    max: usize,
    f: Option<F>,
}

impl<F> Future for UdpRecvBatchTimedFuture<F>
where
    F: FnMut(&[u8], SocketAddr, Instant) + Unpin,
{
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<usize> {
        let this = self.get_mut();
        with_state(|driver, executor| {
            let idx = this.udp_index as usize;
            if idx >= executor.udp_recv_queues.len() || executor.udp_recv_queues[idx].is_empty() {
                let task_id = CURRENT_TASK_ID.with(|c| c.get());
                if idx < executor.udp_recv_waiters.len() {
                    debug_assert!(
                        executor.udp_recv_waiters[idx].is_none_or(|t| t == task_id),
                        "two distinct tasks awaiting recv on UdpCtx index {idx}; \
                         UdpCtx::recv_batch_timed supports a single consumer per socket"
                    );
                    executor.udp_recv_waiters[idx] = Some(task_id);
                }
                return Poll::Pending;
            }

            let f = this
                .f
                .as_mut()
                .expect("UdpRecvBatchTimedFuture polled after Ready");

            let mut drained: usize = 0;
            while drained < this.max
                && let Some(entry) = executor.udp_recv_queues[idx].pop_front()
            {
                let bid = entry.bid_to_release();
                let recv_at = entry.recv_at;
                let peer = entry.peer;
                // One callback per datagram; GRO-coalesced entries fan out
                // into per-segment slices, all sharing this entry's arrival
                // timestamp. `drained` counts entries, not segments.
                entry.for_each_segment(|seg| f(seg, peer, recv_at));
                drop(entry);
                #[cfg(has_io_uring)]
                if let Some(bid) = bid {
                    driver.udp_pending_replenish.push(bid);
                }
                #[cfg(not(has_io_uring))]
                let _ = bid;
                drained += 1;
            }
            this.f.take();
            #[cfg(not(has_io_uring))]
            let _ = driver;
            Poll::Ready(drained)
        })
    }
}

/// Future returned by [`UdpCtx::send_ready()`].
pub struct UdpSendReadyFuture {
    /// Mio: whether this future has yielded once (cooperative backoff).
    #[cfg(not(has_io_uring))]
    yielded: bool,
    /// Never read on the mio backend — the future resolves immediately
    /// without looking at any per-socket state.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    udp_index: u32,
}

impl Future for UdpSendReadyFuture {
    type Output = ();

    #[cfg(has_io_uring)]
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        with_state(|driver, executor| {
            let idx = self.udp_index as usize;
            if idx < driver.udp_sockets.len() && !driver.udp_sockets[idx].send_freelist.is_empty() {
                return Poll::Ready(());
            }
            // Same single-consumer story as `recv_from` — if another
            // task is already awaiting `send_ready`, overwriting their
            // wakeup leaks them forever.
            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            if idx < executor.udp_send_ready_waiters.len() {
                debug_assert!(
                    executor.udp_send_ready_waiters[idx].is_none_or(|t| t == task_id),
                    "two distinct tasks awaiting send_ready on UdpCtx index {idx}; \
                     UdpCtx::send_ready supports a single consumer per socket"
                );
                executor.udp_send_ready_waiters[idx] = Some(task_id);
            }
            Poll::Pending
        })
    }

    /// Mio backend: sends are synchronous `send_to` calls that never queue.
    /// Yield once before resolving: the documented retry pattern
    /// (`PoolExhausted`/`WouldBlock` → `send_ready().await` → retry) would
    /// otherwise be a hard busy-loop inside a single task poll,
    /// monopolizing the worker until the kernel drains the socket buffer.
    #[cfg(not(has_io_uring))]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if !self.yielded {
            self.yielded = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(())
    }
}
