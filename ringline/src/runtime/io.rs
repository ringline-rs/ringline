use std::cell::{Cell, RefCell};
use std::fmt;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
#[cfg(has_io_uring)]
use std::ops::Deref;
#[cfg(has_io_uring)]
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
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

/// Result of a parse closure passed to [`Connection::with_data`],
/// [`Connection::with_bytes`] or [`Connection::with_bytes_segments`].
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
    /// `additional` that is too large costs memory. `with_bytes_segments`
    /// does not call the parser again until `additional` more bytes are
    /// buffered, so an `additional` that is too large stalls it. On io_uring
    /// it stalls until the hold reaches the receive throttle's cap or the
    /// receive side finishes. On mio it stalls until end of stream, or until
    /// the accumulator reaches `recv_accumulator_max` and the connection is
    /// closed.
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
// the request out of the driver before its callback runs, and so does
// `with_bytes_segments` for accumulator bytes a hold-cap copy left there. A
// `forward_recv_buf` that sends the whole lent buffer or the whole
// accumulator takes it out during the callback. `holds_unread` returns false
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
/// executor and can use [`sleep()`](crate::sleep) and [`timeout()`](crate::timeout),
/// but cannot perform connection I/O directly.
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
/// owned [`Connection`] with both halves claimed, the same type that
/// `on_accept` receives.
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
/// This is the free-function equivalent of [`ConnCtx::request_shutdown()`] —
/// it can be called from standalone tasks or [`AsyncEventHandler::on_start()`](crate::AsyncEventHandler::on_start)
/// futures where no `ConnCtx` is available.
///
/// Returns `Err` if called outside the ringline async executor.
pub fn request_shutdown() -> io::Result<()> {
    try_with_state(|driver, _| {
        let mut ctx = driver.make_ctx();
        ctx.request_shutdown();
    })
    .ok_or_else(|| io::Error::other("called outside executor"))
}

/// Async connection context providing send, recv, and connect operations.
///
/// # `ConnCtx` is a token, not a capability
///
/// As of step 4 and the write-claim work it grants no I/O of its own. The read
/// entry points are crate-private (below) and so are the write ones — `send`,
/// `send_nowait`, `send_parts`, `send_backpressured`, `send_chain`,
/// `send_chain_nowait`, `forward_recv_buf`, `shutdown_write`. Reading goes
/// through [`RecvHalf`], writing through [`SendHalf`], and neither is `Copy`.
///
/// `ConnCtx` is `Copy` because it carries no I/O capability. A copyable handle
/// that did carry one allowed two tasks to write to a single socket, which for
/// a forward sink means interleaved SQEs on the wire, because a forward submits
/// its own SQE rather than going through the connection's send queue (Domain
/// Invariant 2).
///
/// A `ConnCtx` identifies a connection (`token`, `index`, `peer_addr`,
/// `is_outbound`, `is_alive`, `tls_info`), manages its lifecycle (`close`,
/// `cancel`, `request_shutdown`), and names a forward sink. It can also mint the
/// halves with [`take_recv`](Self::take_recv), [`take_send`](Self::take_send)
/// and [`split`](Self::split); each is exclusive and fails if the half is
/// already held. Connections delivered as a [`Connection`] already own their
/// halves, so those methods are for the cases that start from a bare handle.
///
/// # The read entry points are crate-private
///
/// `with_data`, `with_bytes`, `segments`, `recv_owned_segment`, `end_segments`
/// and friends are `pub(crate)` as of step 4b: reading a connection goes
/// through [`Connection`] or [`RecvHalf`], which are not `Copy`, so the read
/// side cannot be aliased. A `ConnCtx` is now a send/identity/lifecycle handle
/// plus a way to *obtain* the read side ([`take_recv`](Self::take_recv),
/// [`split`](Self::split)).
///
/// The forwarding entry points (`forward_to`, `forward_to_conn`,
/// `forward_held`, `enable_recv_forward`, `run_direct_echo`) stay public on
/// purpose: they move bytes kernel-side from source to sink and never surface
/// them to the caller, so they cannot be used to observe a stream someone else
/// is reading. Their own "one forward at a time" rule is refused at runtime by
/// the driver, and that refusal stays reachable — and therefore testable —
/// only through this handle, because `&mut RecvHalf` turns a second concurrent
/// forward into a compile error.
///
/// Both accepted and outbound connections are delivered as a [`Connection`]:
/// accepted ones in
/// [`AsyncEventHandler::on_accept`](crate::AsyncEventHandler::on_accept),
/// outbound ones from [`connect`](crate::connect) and
/// [`connect_unix`](crate::connect_unix) (#528).
///
/// A `ConnCtx` is valid for the lifetime of the connection's async task.
/// When the connection is closed, the task is dropped along with the `ConnCtx`.
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
/// # Thread affinity
///
/// A `ConnCtx` is meaningful only on the worker thread that owns the
/// connection, so it is deliberately **neither `Send` nor `Sync`**:
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<ringline::ConnCtx>();
/// ```
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<ringline::ConnCtx>();
/// ```
///
/// Ringline is thread-per-core: each worker owns its own driver and
/// `ConnectionTable`, and a `ConnCtx` is just an `(index, generation)` pair
/// into *that* worker's table. Used from another worker the index is still in
/// bounds, so the lookup does not fail — it resolves against a different
/// table, and if the generation happens to match too, I/O lands on an
/// unrelated connection. That is a silent wrong-socket write rather than a
/// crash, so the type system rules it out instead. This also makes capturing a
/// `ConnCtx` in a [`spawn_blocking`] closure a compile error, which is correct:
/// its pool threads have no driver. [`spawn`] is unaffected — it requires only
/// `'static`, not `Send`.
#[derive(Clone, Copy)]
pub struct ConnCtx {
    pub(crate) conn_index: u32,
    pub(crate) generation: u32,
    /// Pins the handle to its owning worker thread — see "Thread affinity".
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
/// of stream, a close, or a hold overflow), which leaves `recv_arrival` at
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

/// Which route is entering the segmented domain.
///
/// The `RecvHalf` claim must block the `ConnCtx` route and *not* the half's own
/// route — the half holds the claim by construction, so treating it like any
/// other caller made `RecvHalf::segments()` permanently `EBUSY`.
#[cfg(has_io_uring)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegmentedEntry {
    /// Through `ConnCtx`. Refused while a `RecvHalf` owns the read side.
    ViaConn,
    /// Through the `RecvHalf` that already owns the read side.
    ViaHalf,
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

    /// Construct a `ConnCtx` with arbitrary index/generation for use in
    /// downstream-crate unit tests that exercise buffering / encoding logic
    /// without a live io_uring driver.
    ///
    /// The returned handle does **not** refer to any real connection. Any I/O
    /// method (`with_data`, `send`, `flush`, …) will index into a driver table
    /// that has no slot for it and is therefore undefined to call. It is only
    /// safe to use in tests that touch in-memory client state (write buffers,
    /// pending queues, encoders) and never reach the wire.
    #[cfg(feature = "testing")]
    #[doc(hidden)]
    pub fn for_test(conn_index: u32, generation: u32) -> Self {
        ConnCtx::new(conn_index, generation)
    }

    /// Returns the connection slot index. Useful for indexing into per-connection arrays.
    pub fn index(&self) -> usize {
        self.conn_index as usize
    }

    /// Offer this connection for rebalancing onto a less loaded worker
    /// (tier 3, #443), carrying `state` across.
    ///
    /// Call it at a point where the handler holds nothing it cannot rebuild —
    /// after finishing a response, not mid-request. Park drops the future and
    /// makes a fresh one on the new worker via
    /// [`AsyncEventHandler::on_adopt`](crate::AsyncEventHandler::on_adopt),
    /// so `state` is the only thing that survives.
    ///
    /// **This is the opt-in.** A connection whose handler never calls this is
    /// never parked, whatever the load imbalance.
    ///
    /// The offer is cleared when more data arrives, since that means a new
    /// request started and the boundary is gone. So a handler offers once per
    /// idle point and never has to revoke.
    ///
    /// Call it outside any reader callback, after the response to every
    /// request read so far has been queued. An offer is ignored when it
    /// is made from inside one of the connection's reader callbacks
    /// (`with_data`, `with_bytes`, `with_segments`, `with_bytes_segments`,
    /// `try_with_data`), or
    /// while the runtime holds received bytes for the connection, such as
    /// the next request. Offer again at the next idle point.
    /// A connection whose next request has always arrived by the time the
    /// handler offers is therefore never parked. Only the innermost
    /// running callback is detected. An offer for connection A made from
    /// inside a callback on connection B, itself inside A's callback, is
    /// declined only while the runtime still holds A's bytes. It does not
    /// hold them in a `with_bytes` callback, in a `with_bytes_segments`
    /// callback shown only bytes a hold-cap copy left in the accumulator,
    /// or after a `forward_recv_buf` that sent the whole lent buffer or the
    /// whole accumulator.
    /// `metrics::park_diag::OFFER_DECLINED` counts offers ignored because of
    /// a running reader callback or held bytes.
    ///
    /// The runtime does not see bytes the handler has taken into its own
    /// memory, for example a `ConnStream`'s buffered data, a recv sink,
    /// `Bytes` kept from `with_bytes`, or requests the handler has queued. Do
    /// not offer while holding any.
    ///
    /// Park also requires the io_uring backend and a kernel with
    /// `IORING_OP_FIXED_FD_INSTALL` (mainline 6.8). On mio this does
    /// nothing; on io_uring without that operation the offer is recorded
    /// and never acted on.
    pub fn offer_for_park(&self, state: Option<crate::park::ParkState>) {
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
    pub fn token(&self) -> ConnToken {
        ConnToken::new(self.conn_index, self.generation)
    }

    // ── Recv ─────────────────────────────────────────────────────────

    /// Take this connection's exclusive **recv half**.
    ///
    /// The recv side of a connection is exclusive: ten entry points
    /// (`with_data`, `with_bytes`, `segments`, `recv_owned_segment`,
    /// `with_segments`, `with_bytes_segments`, `forward_to`,
    /// `forward_to_conn`, `recv_ready` and `with_data_result`) all drive one
    /// stream and none of them may run
    /// concurrently with another. `ConnCtx` is `Copy`, so that exclusivity
    /// cannot be owned — every rule has to be re-checked at run time, and the
    /// ones that are missed are silent hangs (#423) or interleaved wire bytes.
    ///
    /// [`RecvHalf`] is neither `Copy` nor `Clone`, and its methods take
    /// `&mut self`, so the borrow checker enforces what those checks
    /// approximate. A second `segments()` while a reader is live stops being an
    /// `EBUSY` you must remember to handle and becomes a compile error.
    ///
    /// Step 2 of `docs/connection-handle-ownership-design.md`: additive. The
    /// equivalent `ConnCtx` methods still exist and still work, so nothing has
    /// to migrate at once — but a connection whose half is out refuses the
    /// segmented entry points on the `ConnCtx` path, so the two cannot be mixed
    /// where that is checkable.
    ///
    /// # Errors
    ///
    /// - `EBUSY` — the half is already out for this connection.
    /// - `EPIPE` — this handle is stale; the slot was closed and recycled.
    ///
    /// io_uring only, for now: the mio backend shares the recv entry points but
    /// not the driver-side claim.
    /// Split this connection into its write and read halves.
    ///
    /// The read side is exclusive and the write side is single-owner; see
    /// [`SendHalf`] and [`RecvHalf`]. Fan-in to one connection is an explicit
    /// queue with the owning task draining it, not a shared handle.
    ///
    /// # Errors
    ///
    /// Same as [`take_recv`](Self::take_recv): `EBUSY` if the read side is
    /// already out, `EPIPE` if this handle is stale.
    pub fn split(&self) -> io::Result<(SendHalf, RecvHalf)> {
        let rx = self.take_recv()?;
        // If the write side is already out, the read claim must not be left
        // stuck: `rx` drops on the `?` and its `Drop` releases it.
        let tx = self.take_send()?;
        Ok((tx, rx))
    }

    /// Take the connection's **write side**, exclusively.
    ///
    /// The twin of [`take_recv`](Self::take_recv). One owner of the writes is
    /// now a claim rather than a convention: several producers feeding one
    /// connection is an explicit queue drained by the owning task.
    ///
    /// It is also what lets a forward refuse a sink somebody else is already
    /// writing to. A forward submits its own SQE straight to the ring instead
    /// of going through the per-connection send queue, so a concurrent send to
    /// that socket interleaves with it — and io_uring does not order
    /// independent SQEs (Domain Invariant 2).
    ///
    /// # Errors
    ///
    /// `EBUSY` if the write side is already out, `EPIPE` if this handle is
    /// stale.
    pub fn take_send(&self) -> io::Result<SendHalf> {
        with_state(|driver, _executor| {
            if driver.connections.generation(self.conn_index) != self.generation {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }
            let idx = self.conn_index as usize;
            if driver.send_half_taken[idx] {
                return Err(io::Error::from_raw_os_error(libc::EBUSY));
            }
            driver.send_half_taken[idx] = true;
            Ok(())
        })?;
        Ok(SendHalf {
            conn: *self,
            _not_send: PhantomData,
        })
    }

    /// [`split`](Self::split) without the driver.
    ///
    /// `split` records the read claim in the driver, so it cannot run outside
    /// a worker. This hands back unclaimed halves for the same narrow case
    /// [`for_test`](Self::for_test) exists for: tests that exercise in-memory
    /// client state (encoders, write buffers, pending queues) and never reach
    /// the wire. Calling any I/O method on the result is undefined, exactly as
    /// it is for a `for_test` handle.
    #[cfg(feature = "testing")]
    #[doc(hidden)]
    pub fn split_for_test(&self) -> (SendHalf, RecvHalf) {
        (
            SendHalf {
                conn: *self,
                _not_send: PhantomData,
            },
            RecvHalf {
                conn: *self,
                _not_send: PhantomData,
            },
        )
    }

    pub fn take_recv(&self) -> io::Result<RecvHalf> {
        with_state(|driver, _executor| {
            if driver.connections.generation(self.conn_index) != self.generation {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }
            let idx = self.conn_index as usize;
            if driver.recv_half_taken[idx] {
                return Err(io::Error::from_raw_os_error(libc::EBUSY));
            }
            driver.recv_half_taken[idx] = true;
            Ok(())
        })?;
        Ok(RecvHalf {
            conn: *self,
            _not_send: PhantomData,
        })
    }

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
    pub(crate) fn with_data<F: FnMut(&[u8]) -> ParseResult>(&self, f: F) -> WithDataFuture<F> {
        WithDataFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            f: Some(f),
        }
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
    pub(crate) fn with_data_result<F: FnMut(&[u8]) -> ParseResult>(
        &self,
        f: F,
    ) -> WithDataResultFuture<F> {
        WithDataResultFuture {
            inner: self.with_data(f),
        }
    }

    /// Wait until recv data is available, then provide it as zero-copy `Bytes`.
    ///
    /// Like [`with_data()`](Self::with_data), but the closure receives a `Bytes`
    /// handle that can be sliced (O(1), refcounted) instead of copied. The
    /// closure returns a [`ParseResult`] indicating bytes consumed.
    ///
    /// This enables zero-copy RESP parsing: the parser can call `bytes.slice()`
    /// to extract sub-ranges without allocating.
    pub(crate) fn with_bytes<F: FnMut(Bytes) -> ParseResult>(&self, f: F) -> WithBytesFuture<F> {
        WithBytesFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            f: Some(f),
        }
    }

    /// Enter the segmented recv domain, **adopting bytes that already arrived**.
    ///
    /// Flipping `recv_domain` is not enough. Anything received before the
    /// reader was installed is already in the `RecvAccumulator` (or pinned as
    /// the zero-copy `pending_recv_bufs` slot), and a segmented reader only
    /// ever looks at `segment_hold` — so without this those bytes are
    /// invisible forever: the reader parks, the data sits in the accumulator,
    /// and every health signal reads normal (ring full, multishot live, no
    /// errors). That is #423.
    ///
    /// The race is easy to lose and hard to see. A handler installs its reader
    /// on the task's first poll, which is strictly after `on_accept`; under TLS
    /// the handshake round-trip all but guarantees application data is already
    /// in flight by then. How much is stranded depends purely on timing, which
    /// is why the symptom was an intermittent hang at a varying offset.
    ///
    /// `arm_forward_source` (Mode A) has always done this; Modes B and C did
    /// not. Ordering matches it: accumulator bytes are the oldest and go to the
    /// front, the pinned buffer is the newest and goes to the back.
    #[cfg(has_io_uring)]
    fn enter_segmented_domain(&self, exclusive: bool, via: SegmentedEntry) -> io::Result<()> {
        with_state(|driver, _executor| {
            enter_segmented(driver, self.conn_index, self.generation, exclusive, via)
        })
    }

    /// Borrow a segmented-recv reader (Mode B "Borrow", the sound lending-iterator
    /// face — see `docs/segmented-recv-design.md`).
    ///
    /// Opts this connection into *segmented* delivery: arriving provided buffers
    /// are held in-place (no copy into the accumulator, bid not replenished) and
    /// surfaced one at a time as zero-copy [`RecvSegment`]s via
    /// [`SegmentReader::next`]. A segment is `!Send`, `!Clone`, and borrows the
    /// reader exclusively (`&mut`), so it cannot escape the runtime or outlive the
    /// buffer's pin — the "holdable ⇒ copied" invariant is enforced structurally.
    ///
    /// Call this **before** the connection starts receiving: it flips the delivery
    /// domain but does not retroactively segment bytes already gathered into the
    /// accumulator under the default `with_data`/`with_bytes` path.
    ///
    /// # Errors
    ///
    /// Refused before any reader exists, so a conflict is reported where it is
    /// caused rather than one poll later:
    ///
    /// - `EBUSY` — a [`SegmentReader`] is already live on this connection, or a
    ///   Mode A forward is running (the forward owns the hold).
    /// - `EPIPE` — this handle is stale: the slot was closed and recycled for a
    ///   different connection.
    ///
    /// io_uring only — segmented delivery is backed by the provided-buffer ring.
    ///
    /// Crate-private since step 4b. It is the only constructor of
    /// [`SegmentedEntry::ViaConn`], whose `EBUSY` gate ("refuse when a half is
    /// already out") is exercised by the driver's own unit tests — so it has no
    /// caller in the library target and is kept for those tests rather than
    /// deleted, which would take the gate's coverage with it.
    #[cfg(has_io_uring)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn segments(&self) -> io::Result<SegmentReader<'_>> {
        self.segments_via(SegmentedEntry::ViaConn)
    }

    #[cfg(has_io_uring)]
    pub(crate) fn segments_via(&self, via: SegmentedEntry) -> io::Result<SegmentReader<'_>> {
        self.enter_segmented_domain(true, via)?;
        Ok(SegmentReader {
            conn_index: self.conn_index,
            generation: self.generation,
            _borrow: PhantomData,
            _not_send: PhantomData,
        })
    }

    /// Await the next received segment as an owned, freely holdable [`Bytes`]
    /// (Mode C — "Own", copy-at-delivery; see `docs/segmented-recv-design.md`).
    ///
    /// Opts this connection into *segmented* delivery (like `segments`),
    /// then, for each arriving provided buffer, **copies** its bytes into an owned
    /// heap `Bytes` and replenishes the bid **immediately at delivery** — the copy
    /// *is* the release, so this path never pins the ring and cannot deplete it by
    /// holding (unlike a [`RecvSegment`], which pins until dropped). The returned
    /// `Bytes` is `Send`, `Clone`, and retainable indefinitely.
    ///
    /// Resolves to:
    /// - `Ok(Some(bytes))` — one received buffer, copied and owned.
    /// - `Ok(None)` — end of stream: the recv side is closed (peer FIN) with no
    ///   held buffers remaining, or the connection slot was reused (stale handle).
    ///
    /// Parks when no buffer is held and the connection is still open, resuming
    /// when the recv completion handler holds a buffer and calls `wake_recv` (the
    /// same waiter mechanism as `segments` / `with_data`).
    ///
    /// # Errors
    ///
    /// Refused before any reader exists, so a conflict is reported where it is
    /// caused rather than one poll later:
    ///
    /// - `EBUSY` — a [`SegmentReader`] is already live on this connection, or a
    ///   Mode A forward is running (the forward owns the hold).
    /// - `EPIPE` — this handle is stale: the slot was closed and recycled for a
    ///   different connection.
    ///
    /// io_uring only — segmented delivery is backed by the provided-buffer ring.
    ///
    /// Crate-private since step 4b. It is the only constructor of
    /// [`SegmentedEntry::ViaConn`], whose `EBUSY` gate ("refuse when a half is
    /// already out") is exercised by the driver's own unit tests — so it has no
    /// caller in the library target and is kept for those tests rather than
    /// deleted, which would take the gate's coverage with it.
    #[cfg(has_io_uring)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn recv_owned_segment(&self) -> io::Result<RecvOwnedSegment> {
        self.recv_owned_segment_via(SegmentedEntry::ViaConn)
    }

    #[cfg(has_io_uring)]
    pub(crate) fn recv_owned_segment_via(
        &self,
        via: SegmentedEntry,
    ) -> io::Result<RecvOwnedSegment> {
        self.enter_segmented_domain(false, via)?;
        Ok(RecvOwnedSegment {
            conn_index: self.conn_index,
            generation: self.generation,
        })
    }

    /// End segmented-recv delivery on this connection and restore the default
    /// `with_data` / `with_bytes` path.
    ///
    /// `segments` and `recv_owned_segment`
    /// leave the connection in the *segmented* domain: arriving buffers are held
    /// for the segment reader instead of being gathered into the accumulator. A
    /// consumer that has finished pulling its segments **must** call this before
    /// issuing an ordinary `with_data`/`with_bytes` read — otherwise that read
    /// would never observe further data (it keeps getting held as segments).
    ///
    /// Any buffers still held (bytes received *past* what the consumer pulled) are
    /// appended, in arrival order, behind any bytes already in the accumulator,
    /// and the next read sees them in that order.
    ///
    /// Returns an error (and closes the connection) if gathering the leftover
    /// segments overflows the recv accumulator bound (`recv_accumulator_max`).
    ///
    /// io_uring only — segmented delivery is backed by the provided-buffer ring.
    #[cfg(has_io_uring)]
    pub(crate) fn end_segments(&self) -> io::Result<()> {
        // `settle_forward_end` is the shared "drain held segments into the
        // accumulator, reset the delivery domain to default" routine (named for
        // its first caller, the Mode A `forward_to` completion). Reused here for
        // the streaming-value read side, which needs the identical settle.
        let ok = with_state(|driver, _executor| {
            // A stale handle must not settle the slot's new occupant: that
            // drains someone else's hold into their accumulator and resets
            // their delivery domain underneath them. See #429.
            if driver.connections.generation(self.conn_index) != self.generation {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }
            Ok(driver.settle_forward_end(self.conn_index))
        })?;
        if ok {
            Ok(())
        } else {
            self.close();
            Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "recv accumulator overflow while ending segmented recv",
            ))
        }
    }

    /// Process the connection's buffered recv data as an **ordered chain of
    /// borrowed segments** via a callback (Mode B "Borrow", the B1 callback face
    /// — see `docs/segmented-recv-design.md`).
    ///
    /// Opts this connection into *segmented* delivery, then hands the callback a
    /// [`SegChain`] presenting, **in order**:
    /// 1. the current accumulator contents (if any) as the leading segment, then
    /// 2. each held provided buffer, in arrival order.
    ///
    /// The callback borrows those slices for the call only (they cannot escape,
    /// like `with_data`) and returns a [`SegConsumed`] — the
    /// number of bytes it consumed **from the front** of that concatenation.
    ///
    /// After the callback returns, the runtime settles state so that all
    /// un-consumed bytes end up contiguously at the **front of the accumulator**,
    /// in order:
    /// - fully-consumed accumulator bytes are dropped from the front;
    /// - each held buffer wholly consumed by the callback is replenished to the
    ///   ring;
    /// - any remainder — a partially-consumed buffer, plus buffers the callback
    ///   did not reach (under-drain) — is **copied into the accumulator** and its
    ///   bids replenished.
    ///
    /// So the fully-draining consumer (h2/grpc: extend-each + consume-all) pays
    /// **zero** ringline copies, while an under-draining or whole-frame consumer
    /// degrades to the `with_data` copy — never a deadlock or a
    /// bid leak. The next `with_segments` / `with_data` / `with_bytes` call sees
    /// the carried-over bytes first, in order.
    ///
    /// Resolves to `Ok(n)` = total bytes consumed this call. A callback that
    /// returns [`SegConsumed(0)`](SegConsumed) (it needs a bigger frame than is
    /// buffered) gathers everything to the accumulator and **parks** for more
    /// data — the `NeedMore` idiom, bounded by `recv_accumulator_max` (an
    /// over-run closes the connection). Resolves to `Ok(0)` at EOF (recv side
    /// closed with nothing to present) or for a stale handle (slot reused).
    ///
    /// This deliberately does **not** reuse [`ParseResult`]: its `NeedMore` grows
    /// the heap accumulator by ring depth, which is the wrong bound here.
    ///
    /// Call this **before** the connection starts receiving; it flips the delivery
    /// domain but does not retroactively segment bytes already gathered into the
    /// accumulator.
    ///
    /// io_uring only — segmented delivery is backed by the provided-buffer ring.
    #[cfg(has_io_uring)]
    pub(crate) fn with_segments<F>(&self, f: F) -> WithSegmentsFuture<F>
    where
        F: FnMut(&SegChain<'_>) -> SegConsumed,
    {
        // The domain flip happens on the first poll, not here.
        //
        // Flipping at call time skipped the generation check every other
        // segmented entry performs, so a *stale* handle — one whose slot was
        // closed and recycled — could put a different connection into the
        // segmented domain. That connection's own `with_data` reader never
        // looks at `segment_hold`, so its bytes are stranded and it hangs with
        // every health signal normal: #423 inflicted on an innocent third
        // party. See #429.
        WithSegmentsFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            f: Some(f),
            entered: false,
        }
    }

    /// See [`Connection::with_bytes_segments`].
    pub(crate) fn with_bytes_segments<F>(&self, f: F) -> WithBytesSegmentsFuture<F>
    where
        F: FnMut(&[Bytes]) -> ParseResult,
    {
        WithBytesSegmentsFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            f: Some(f),
            entered: false,
            #[cfg(has_io_uring)]
            epoch: 0,
            consumed: 0,
            call_at: None,
        }
    }

    /// The mio backend has no segmented domain, so there is nothing to leave.
    /// Returns `Ok(())`, for a stale handle too.
    #[cfg(not(has_io_uring))]
    pub(crate) fn end_segments(&self) -> io::Result<()> {
        Ok(())
    }

    /// Put this connection into the Mode A forwarding state: switch delivery to
    /// the segmented domain, mark it a forwarder, and move anything already
    /// buffered into the hold.
    ///
    /// That last step is what makes a proxy expressible. The length a forward
    /// needs comes from a header, and reading a header means `with_data`,
    /// which leaves the rest of the segment sitting in the accumulator. Those
    /// bytes are the front of the forward; leaving them behind would strand
    /// them and shift the stream by however much arrived with the header.
    #[cfg(has_io_uring)]
    /// Install a Mode A forward on this connection, or refuse it.
    ///
    /// The refusals mirror the mio sibling's, which stated the contract for
    /// both backends while only one enforced it: a forward already running is
    /// `EBUSY`, a stale source or sink slot is `EPIPE`, and a TLS sink is
    /// `EPROTOTYPE`. That last one matters most — a forward writes bytes to
    /// the sink as they are, with nothing on the path to encrypt them, so
    /// forwarding into a TLS connection would put plaintext on the wire.
    ///
    /// Every check happens **before** any state is touched, so a refusal
    /// leaves an in-progress forward and the recv domain exactly as they were.
    /// `sink_owned` says the caller presented the sink's [`SendHalf`] by
    /// mutable borrow, which *is* the permission to write to it and, for as
    /// long as the forward future lives, the proof nobody else can. When the
    /// sink is named by a bare `ConnCtx` instead, there is no such proof, so
    /// the claim is checked below.
    fn arm_forward_source(
        &self,
        target: crate::backend::uring::driver::SinkTarget,
        len: u64,
        sink_owned: bool,
    ) -> Result<u32, i32> {
        with_state(|driver, _executor| {
            let idx = self.conn_index as usize;
            // A stale source owns nothing worth settling — its slot has already
            // been recycled, and touching it would reach a different connection.
            // Teardown released its buffers when the slot was cleared.
            if driver.connections.generation(self.conn_index) != self.generation {
                return Err(libc::EPIPE);
            }
            // Arming over a running forward would strand its held bids and
            // hand its caller a result belonging to someone else. The running
            // forward owns this connection's hold, so leave it strictly alone.
            if driver.forward_progress[idx].is_some() {
                return Err(libc::EBUSY);
            }
            // Sink-side refusals: the source is live and no forward owns its
            // hold, so anything already held would be stranded — the provided
            // buffer leaked per attempt that
            // `forward_to_conn_refuses_a_recycled_sink_slot` exists to catch.
            // Before these checks moved to arm time the write path refused and
            // released the backing on the way out; settling here is what keeps
            // that true. `settle_forward_end` returns the bytes to the
            // accumulator, replenishes the bids, and resets the delivery
            // domain, which is what a connection that is not forwarding wants.
            if let crate::backend::uring::driver::SinkTarget::Conn { index, generation } = target {
                let refusal = if driver.connections.generation(index) != generation {
                    Some(libc::EPIPE)
                } else if driver.tls_table.as_ref().is_some_and(|t| t.has(index)) {
                    Some(libc::EPROTOTYPE)
                } else if !sink_owned && driver.send_half_taken[index as usize] {
                    // Somebody else owns this sink's writes. A forward submits
                    // its own SQE straight to the ring rather than going
                    // through the sink's send queue, so their sends and these
                    // writes would interleave on one socket — and io_uring
                    // does not order independent SQEs (Domain Invariant 2).
                    // This is the "forward *or* send, not both" rule, enforced
                    // for the first time.
                    Some(libc::EBUSY)
                } else {
                    None
                };
                if let Some(errno) = refusal {
                    if !driver.settle_forward_end(self.conn_index) {
                        driver.close_connection(self.conn_index);
                    }
                    return Err(errno);
                }
            }
            // The driver owns the forward from here: it submits each write from
            // the completion handler, so the task is woken once at the end
            // rather than once per provided buffer.
            let epoch = driver.forward_epoch[idx].wrapping_add(1);
            driver.forward_epoch[idx] = epoch;
            driver.forward_progress[idx] = Some(crate::backend::uring::driver::ForwardProgress {
                target,
                len,
                forwarded: 0,
                epoch,
            });
            // A result left by the slot's previous occupant is not this
            // forward's.
            driver.forward_done[idx] = None;
            driver.recv_domain[idx] = crate::recv::domain::RecvDomain::Segmented;
            driver.forward_recv_active[idx] = true;
            if !driver.accumulators.is_empty(self.conn_index) {
                let buffered = driver.accumulators.take_frozen(self.conn_index);
                driver.segment_hold[idx].push_front(crate::backend::HeldRecvBuf::Owned(buffered));
            }
            // The plaintext path holds the most recent provided buffer in
            // place rather than copying it (the zero-copy `with_data` read),
            // so buffered bytes can be sitting *behind* an empty accumulator.
            // They are the newest, hence the back of the hold. Missing them
            // stranded the buffer for good: a forward never reads this slot,
            // and the bid it pins is only replenished when the slot is
            // cleared, so the ring lost an entry too.
            if let Some(pending) = driver.pending_recv_bufs[idx].take() {
                // SAFETY: the slot owns an unreplenished provided buffer with
                // `len` bytes received into it; taking the slot transfers that
                // ownership here, and the bid goes back at the same moment the
                // copy is made.
                let data = unsafe { std::slice::from_raw_parts(pending.ptr, pending.len as usize) };
                driver.segment_hold[idx].push_back(crate::backend::HeldRecvBuf::Owned(
                    Bytes::copy_from_slice(data),
                ));
                crate::accumulator::note_copied(data.len());
                driver.pending_replenish.push(pending.bid);
            }
            Ok(epoch)
        })
    }

    /// Forward the next `len` received bytes straight to `sink` (Mode A —
    /// "Forward", zero userspace copy; see `docs/segmented-recv-design.md`).
    ///
    /// Opts this connection into *segmented* delivery, then interleaves recv and
    /// write: arriving provided buffers are held driver-side and written directly
    /// to `sink` — a **socket** (zero-copy proxy, `send` with `MSG_WAITALL`) or a
    /// **buffered file** (`pwrite` at an advancing offset starting at 0). No
    /// intermediate copy into the accumulator or a user buffer. Each held buffer's
    /// bid is released back to the provided ring on **its own write completion**.
    ///
    /// Writes to `sink` are strictly serialized — one in flight at a time — so the
    /// byte stream cannot be reordered (io_uring does not order independent SQEs);
    /// a large `len` therefore becomes a sequence of serialized buffer-sized
    /// writes. Shared-ring safety under fan-in is provided by the low-water
    /// reserve (`recv_segment_reserve`): when the ring runs low, arriving buffers
    /// are force-copied and their bids returned immediately, so a slow sink cannot
    /// deplete the shared ring and starve other connections.
    ///
    /// Bytes already buffered on this connection when the forward starts — the
    /// remainder of the segment that carried the length header, typically — are
    /// the front of the forward and are moved into the hold, not left behind in
    /// the accumulator.
    ///
    /// # Size the provided buffers for forwarding, not for echo
    ///
    /// This path pays its per-completion cost **once per provided buffer**: a
    /// CQE, a push to the hold, a task wake, a future poll, one write SQE, one
    /// write CQE, one bid replenish — about 6,600 instructions, measured. One
    /// write is in flight per connection at a time, so the buffer size sets
    /// how many bytes that cycle covers.
    ///
    /// Relaying a byte stream between two 40 GbE hosts, moving
    /// `recv_buffer(256, 16384)` to `recv_buffer(64, 65536)` — the same 4 MiB
    /// of provided-buffer memory, a quarter as many buffers, four times the
    /// size — took the proxy from 11.2 to 14.0 Gbit/s at the same CPU, and
    /// from 1.26 to 0.96 instructions per byte. The fixed cost falls from 32%
    /// of all work to 10%; the remaining ~0.86 instructions/byte is the
    /// kernel's copy and TCP work, which no buffer size touches.
    ///
    /// A geometry sweep (#416) put a number on how much the default costs a
    /// forwarding workload: **34% at 64 connections, 18% at 1024**. It is the
    /// only workload measured where the default is systematically far from
    /// best — for request/response it is within ~6%.
    ///
    /// # Sizing
    ///
    /// **The default is fine.** A forward write gathers up to 16 held buffers
    /// into one `sendmsg`, so the payload per completion follows what the
    /// socket had queued rather than what one buffer holds. Measured on two
    /// 40 GbE hosts at the same 4 MiB/worker budget: 14.60 Gbit/s at the
    /// default `recv_buffer(256, 16384)`, 15.13 at `recv_buffer(64, 65536)`,
    /// 14.22 at `recv_buffer(16, 262144)`. A few percent, either way.
    ///
    /// This used to matter a great deal. Before gathering, one write carried
    /// one buffer, so buffer size *was* payload per completion: the same
    /// default measured 11.23 Gbit/s against 14.29 at 64 KiB, and #416 found
    /// forwarding 34% behind the best geometry — the one workload where
    /// ringline's default was badly wrong. Gathering removed the cause, and
    /// with it the need to tune.
    ///
    /// Going *larger* is now mildly counterproductive: at 256 KiB a
    /// sixteen-buffer batch would be 4 MiB of iovec against a socket that
    /// rarely has more than ~100 KB queued, so batches stay short while the
    /// ring gets shallower — and ring depth is what bounds concurrent arrivals
    /// at high fan-in, where a 4-deep ring measured a 1.03-second p99.
    ///
    /// Resolves to `Ok(bytes_forwarded)`. `bytes_forwarded == len` on success; a
    /// value `< len` means the peer closed (FIN) before `len` bytes arrived — the
    /// forward is truncated (any received-but-unwritten tail is dropped as the
    /// connection unwinds). After the forward the delivery domain is reset to the
    /// default, and any bytes received *past* `len` are preserved at the front of
    /// the accumulator for the next `with_data`/`with_bytes` read.
    ///
    /// # Sink ownership
    ///
    /// [`SinkFd`] borrows the target descriptor for the forward's lifetime (it is
    /// **not** a bare `RawFd` the caller can close mid-forward — that would be a
    /// use-after-close, since an in-flight write would land on a recycled fd). The
    /// returned future borrows the `SinkFd`, so the borrow checker keeps the fd
    /// open until the forward resolves.
    ///
    /// # NVMe / `O_DIRECT`
    ///
    /// Not supported for zero-copy: provided buffers are mid-ring, unaligned, and
    /// unregistered, so `O_DIRECT`'s alignment contract cannot be met without an
    /// intermediate aligned copy (which defeats the purpose). [`SinkFd::file`]
    /// **rejects** an `O_DIRECT` descriptor with [`io::ErrorKind::InvalidInput`].
    ///
    /// io_uring only — Mode A is backed by the provided-buffer ring.
    ///
    /// # Errors
    ///
    /// Refused at the call, resolving on the first poll without having
    /// installed anything: `EBUSY` if a forward is already running on this
    /// connection, `EPIPE` if this connection's slot is already stale. (The
    /// sink is a borrowed descriptor, so the sink-side `EPIPE`/`EPROTOTYPE`
    /// of [`forward_to_conn`](Self::forward_to_conn) do not apply.)
    #[cfg(has_io_uring)]
    pub fn forward_to<'a>(&self, sink: &'a SinkFd<'a>, len: usize) -> ForwardToFuture<'a> {
        let target = crate::backend::uring::driver::SinkTarget::Fd {
            fd: sink.fd,
            is_file: sink.is_file,
        };
        // An fd sink is not a connection, so it carries no send claim to check.
        let armed = self.arm_forward_source(target, len as u64, true);
        ForwardToFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            epoch: armed.unwrap_or(0),
            refused: armed.err(),
            _borrow: PhantomData,
        }
    }

    /// Install a recv sink so that CQE data is written directly to the
    /// target buffer instead of the per-connection accumulator.
    ///
    /// Does nothing if the handle is stale (its connection has been
    /// released); `recv_ready` then resolves immediately and
    /// `take_recv_sink` returns 0.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `target` points to writable memory of at
    /// least `len` bytes, and that the memory remains valid until
    /// `take_recv_sink()` is called. In practice this
    /// is guaranteed because ringline is single-threaded: the task sets the sink,
    /// yields, and the CQE handler (same thread) writes to it before the task
    /// resumes and clears the sink.
    pub unsafe fn set_recv_sink(&self, target: *mut u8, len: usize) {
        with_state(|driver, executor| {
            if driver.connections.generation(self.conn_index) != self.generation {
                return;
            }
            executor.recv_sinks[self.conn_index as usize] = Some(crate::runtime::RecvSink {
                ptr: target,
                cap: len,
                pos: 0,
            });
        });
    }

    /// Remove the recv sink and return the number of bytes written to it.
    /// Returns 0 if no sink was active, or if the handle is stale.
    pub(crate) fn take_recv_sink(&self) -> usize {
        with_state(|driver, executor| {
            if driver.connections.generation(self.conn_index) != self.generation {
                return 0;
            }
            match executor.recv_sinks[self.conn_index as usize].take() {
                Some(sink) => sink.pos,
                None => 0,
            }
        })
    }

    /// Returns a future that becomes ready when received bytes are buffered
    /// for the connection, when a recv sink has received data, or when the
    /// connection has finished receiving.
    ///
    /// Use this with [`set_recv_sink()`](Self::set_recv_sink) to wait for
    /// direct-to-buffer writes without processing accumulator data.
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

    /// Non-blocking accumulator access. Calls `f` with buffered data if any,
    /// returning `Some(result)`. Returns `None` if the accumulator is empty.
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

            // Before either zero-copy branch: both act on the slot's pending
            // recv buffer or accumulator, which belong to whichever
            // connection holds the slot now. The same refusal as the copy
            // path's `send` (#544).
            if driver.connections.generation(conn_index) != self.generation {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "stale connection",
                ));
            }
            // Once the Close is submitted, the copy path's `send` refuses
            // without committing anything; the zero-copy branches would queue
            // a send that is never driven.
            #[cfg(has_io_uring)]
            let closing = driver.send_queues[conn_index as usize].close_submitted;

            #[cfg(has_io_uring)]
            if !closing {
                // Check for pending recv buffer.
                if let Some(pending) = driver.pending_recv_bufs[conn_index as usize].take() {
                    // Verify the data pointer matches the pending buffer (sanity check).
                    let pending_ptr = pending.ptr;
                    let data_ptr = data.as_ptr();
                    if data_ptr == pending_ptr && data.len() == pending.len as usize {
                        // Submit send SQE from the recv buffer. The bid is replenished
                        // on send completion via handle_send_recv_buf.
                        // Payload: bid only (low 16 bits). The remaining byte count is
                        // tracked in driver.send_recv_buf_remaining[conn_index] so that
                        // buffer sizes > u16::MAX (e.g. 65536 B) are supported without
                        // truncation in the CQE user_data payload.
                        let payload = pending.bid as u32;
                        let user_data = crate::completion::UserData::encode(
                            crate::completion::OpTag::SendRecvBuf,
                            conn_index,
                            payload,
                        );
                        let entry = crate::backend::uring::sqe::Sqe::stream_send(
                            conn_index,
                            pending_ptr,
                            pending.len,
                            user_data.raw(),
                        );

                        let built = crate::handler::BuiltSend {
                            entry,
                            pool_slot: u16::MAX,
                            #[cfg(has_io_uring)]
                            slab_idx: u16::MAX,
                            total_len: pending.len,
                        };

                        // Infallible: under SQ pressure the entry is parked in
                        // the connection's queue and keeps its bid exactly as
                        // a queued entry does; `handle_send_recv_buf`
                        // replenishes it on completion.
                        driver.send_held_recv[conn_index as usize] += 1;
                        driver.submit_or_queue_send(conn_index, built);
                        return Ok(());
                    }

                    // Pointer mismatch �� put it back and fall through to copy path.
                    driver.pending_recv_bufs[conn_index as usize] = Some(pending);
                }
            }

            // The bytes are accumulator-backed: either they arrived across
            // several recv completions, or a previous parse left a remainder.
            // Copying the whole message into a send-pool slot is what made
            // ringline lose to its own mio fallback at 16 KiB (#397) — 93.9%
            // of forwards took this path, averaging 15 KB copied per
            // operation. Detach the accumulator instead (O(1) freeze) and send
            // it under a guard, so the message reaches the wire uncopied.
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

            // No pending recv buffer (or mio backend) — fall back to copy send.
            let mut ctx = driver.make_ctx();
            ctx.send(self.token(), data)
        })
    }

    /// Run a direct-echo event loop for this connection (io_uring only).
    ///
    /// Instead of the standard task-driven approach where each recv CQE wakes
    /// the owning task, which then calls `with_data` → `forward_recv_buf`, this
    /// mode sets a flag on the connection that tells `handle_recv_multi` to
    /// submit the echo SQE directly from the CQE handler — bypassing the
    /// `collect_wakeups` → `poll_ready_tasks` roundtrip entirely.
    ///
    /// The returned future resolves once the peer has closed its write side
    /// (or the read failed) and every byte received before that has been
    /// submitted for echo. The connection then closes, after the last send
    /// completes. Any data buffered before the flag was set is drained on the
    /// first poll.
    ///
    /// Available only on io_uring; on mio, use a `with_data` /
    /// `forward_recv_buf` loop.
    #[cfg(has_io_uring)]
    pub fn run_direct_echo(&self) -> DirectEchoFuture {
        DirectEchoFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            armed: false,
        }
    }

    /// Forward the next `len` received bytes to **another connection on this
    /// worker**, with no copy through user space.
    ///
    /// The proxy form of `forward_to`. Where `forward_to`
    /// names its sink as a borrowed descriptor, this names it as a
    /// [`ConnCtx`] — which is what makes a *bidirectional* proxy expressible:
    /// the return direction needs the client named as a sink, and a
    /// connection's descriptor is deliberately not public.
    ///
    /// ```ignore
    /// let backend = ringline::connect(addr)?.await?;
    /// // client -> backend; a second task forwards backend -> client
    /// conn.forward_to_conn(&backend, len).await?;
    /// ```
    ///
    /// Same mechanics and same truncation semantics as `forward_to`: arriving
    /// provided buffers are held driver-side and written straight to the sink,
    /// one serialized write at a time, each bid released on its own write
    /// completion; a result `< len` means the peer sent FIN first.
    ///
    /// # Thread affinity
    ///
    /// Both connections must belong to this worker. That is not a rule you can
    /// break: [`ConnCtx`] is `!Send`, so a handle from another worker cannot
    /// reach this call. A sink obtained from [`connect`](crate::connect) inside
    /// the handler is always on the right worker.
    ///
    /// # Do not send on the sink concurrently
    ///
    /// The forward writes to the sink directly rather than through its send
    /// queue, so a `send` on the sink from elsewhere while a forward is running
    /// is not ordered against it and will interleave on the wire. io_uring does
    /// not order independent SQEs. Forward *or* send on a given connection, not
    /// both at once.
    ///
    /// # TLS
    ///
    /// The **source** may be a TLS connection: rustls' plaintext is collected
    /// and forwarded, which is what makes a TLS-terminating proxy work. The
    /// **sink** may not — the forward writes bytes as they are, with nothing
    /// on the path to encrypt them — and a TLS sink is refused with
    /// `EPROTOTYPE` rather than put plaintext on the wire.
    ///
    /// # Errors
    ///
    /// Refused at the call, resolving on the first poll without having
    /// installed anything: `EBUSY` if a forward is already running on this
    /// connection, `EPIPE` if the source or sink slot is already stale, and
    /// `EPROTOTYPE` if the sink is a TLS connection.
    ///
    /// Resolves `Err(EPIPE)` if the sink connection closes *mid*-forward — its
    /// slot may be reused, and writing to a recycled index would deliver this
    /// stream to a different peer. The sink's generation is checked before
    /// every write.
    ///
    /// The mio backend exposes the same signature, but as a copy path — see
    /// the `not(has_io_uring)` sibling below. Both backends refuse the same
    /// three conditions with the same errnos.
    #[cfg(has_io_uring)]
    pub fn forward_to_conn<'a>(&self, sink: &'a ConnCtx, len: usize) -> ForwardToFuture<'a> {
        let target = crate::backend::uring::driver::SinkTarget::Conn {
            index: sink.conn_index,
            generation: sink.generation,
        };
        let armed = self.arm_forward_source(target, len as u64, false);
        ForwardToFuture {
            conn_index: self.conn_index,
            generation: self.generation,
            epoch: armed.unwrap_or(0),
            refused: armed.err(),
            _borrow: PhantomData,
        }
    }

    /// Forward the next `len` received bytes to another connection on this
    /// worker.
    ///
    /// The mio counterpart of the io_uring `forward_to_conn`, with the same
    /// signature, the same truncation semantics — a result `< len` means the
    /// peer sent FIN first — and the same thread affinity, which [`ConnCtx`]
    /// being `!Send` enforces for free.
    ///
    /// # This is a copy path
    ///
    /// The io_uring version holds provided recv buffers and writes them
    /// straight to the sink, touching the bytes zero times in user space. mio
    /// has no provided-buffer ring, so bytes are read into a queued send on
    /// the sink and copied on the way. It exists so that a proxy built on
    /// ringline runs at all without io_uring.
    ///
    /// It is not, however, automatically the slower of the two. Measured on
    /// two 40 GbE hosts relaying a byte stream (64 connections, one proxy
    /// worker pair, medians of three interleaved runs): this path moved
    /// **12.8 Gbit/s at 1.12 instructions per byte**, against **11.2 Gbit/s
    /// at 1.26** for the io_uring path using 16 KiB provided buffers — the
    /// copy path ahead by 14%. Raising the io_uring side to 64 KiB provided
    /// buffers put it back in front at **14.0 Gbit/s and 0.96
    /// instructions/byte**. The bookkeeping io_uring adds per buffer (hold,
    /// bid lifecycle, task wake, one serialized write per buffer — about
    /// 6,600 instructions a completion) costs more than the copy it removes,
    /// until the buffer is large enough to amortize it. `forward_to`, which
    /// exists only on the io_uring backend, carries the sizing guidance.
    ///
    /// # Backpressure
    ///
    /// The source stops reading once it holds the hold cap of entries
    /// awaiting the sink (`forward_hold_cap`; on io_uring without
    /// `recv_incremental`, at most a quarter of the receive ring), which closes
    /// the source's TCP window rather than growing the queue without bound,
    /// and resumes when the sink drains.
    ///
    /// # TLS
    ///
    /// The **source** may be a TLS connection: rustls' plaintext is collected
    /// and forwarded, which is what makes a TLS-terminating proxy work. The
    /// **sink** may not — the forward queues bytes as they are, with nothing
    /// on the path to encrypt them — and a TLS sink is refused with
    /// `EPROTOTYPE` rather than put plaintext on the wire.
    ///
    /// # Errors
    ///
    /// `EPIPE` if the sink closes or its slot is recycled mid-forward;
    /// `EPROTOTYPE` if the sink is a TLS connection; `EBUSY` if a forward is
    /// already running on this connection.
    #[cfg(not(has_io_uring))]
    pub fn forward_to_conn<'a>(&self, sink: &'a ConnCtx, len: usize) -> ForwardToConnFuture<'a> {
        let (sink_index, sink_generation) = (sink.conn_index, sink.generation);
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
            // consumed are part of the forward — the same bytes the io_uring
            // path picks up out of the accumulator when the domain flips. This
            // also settles a forward that is satisfied on the spot (`len == 0`,
            // or the accumulator already covered it), which must not park for a
            // read that is never coming.
            driver.forward_take_accumulated(source);
            Ok(())
        });
        ForwardToConnFuture {
            conn_index: source,
            generation,
            refused: armed.err(),
            _borrow: PhantomData,
        }
    }

    /// Enable the zero-copy recv-forward path for this connection.
    ///
    /// Once enabled, incoming provided recv buffers are *held in place* (not
    /// copied into the accumulator) and can be echoed back zero-copy via
    /// [`forward_held`](Self::forward_held), which gathers up to 32 held
    /// buffers into one scatter-gather `sendmsg`. Intended for byte-pipe workloads (echo,
    /// proxy) where the handler does not parse the stream. While enabled,
    /// `with_data` / `with_bytes` will not
    /// observe data (it never reaches the accumulator).
    ///
    /// Backpressure is automatic: held buffer ids are not returned to the
    /// provided-buffer ring until their forward completes, so a slow peer
    /// naturally throttles recv (`ENOBUFS`) rather than growing memory.
    #[cfg(has_io_uring)]
    /// A stale handle is a no-op: this returns `()` and so has no way to
    /// report a refusal, and flipping the flag on a recycled slot would make a
    /// *different* connection start holding its recv buffers. See #429.
    pub fn enable_recv_forward(&self) {
        with_state(|driver, _| {
            if driver.connections.generation(self.conn_index) != self.generation {
                return;
            }
            driver.recv_forward[self.conn_index as usize] = true;
            // Recv-forward holds its buffers past the completion, so it
            // receives one buffer per arm (`Driver::recv_single`).
            driver.cancel_recv_for_single(self.conn_index);
        });
    }

    /// Forward the held recv buffers back to the peer in one zero-copy
    /// scatter-gather `sendmsg`, returning a [`SendFuture`] that resolves with
    /// the bytes sent. A call forwards at most 32 buffers. While the
    /// connection is open, buffers beyond that stay held for the next call,
    /// and `recv_ready` is ready at once. When the peer closes, held buffers
    /// that were not forwarded are discarded.
    /// Requires [`enable_recv_forward`](Self::enable_recv_forward).
    ///
    /// Gate calls on `recv_ready`, which becomes ready when the connection
    /// holds received bytes or has closed. When the hold is empty (e.g. the
    /// connection closed), the returned future resolves to `0`. `recv_ready`
    /// is also ready for bytes outside the hold, for which `forward_held`
    /// returns 0: bytes received before `enable_recv_forward`, and every byte
    /// on a TLS connection, which decrypts into the accumulator.
    ///
    /// One forward is in flight per connection at a time (await the returned
    /// future before calling again); buffers received during the send accumulate
    /// in the hold and are picked up by the next call. The same holds for any
    /// other send on the connection: while one is queued or in flight, or a
    /// send chain is active, this returns `WouldBlock` rather than let the
    /// forward overtake it, and the held buffers stay in the hold.
    #[cfg(has_io_uring)]
    pub fn forward_held(&self) -> io::Result<SendFuture> {
        with_state(|driver, executor| {
            let conn_index = self.conn_index;
            if driver.connections.generation(conn_index) != self.generation {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "stale connection",
                ));
            }

            let n = driver.recv_hold[conn_index as usize]
                .len()
                .min(crate::buffer::FORWARD_HELD_MAX_BUFFERS);

            // Nothing held (connection closed or spurious wake) — resolve to 0.
            if n == 0 {
                return Ok(SendFuture::ready(conn_index, self.generation, Ok(0)));
            }

            // Earlier sends queued, in flight or parked, or a chain active: the
            // forward is its own SQE and io_uring does not order independent
            // SQEs, so pushing it now would let the echoed bytes overtake them.
            // Refuse before allocating anything; the hold stays put and the
            // next call forwards the same bytes. Await the earlier send first.
            let state = &driver.send_queues[conn_index as usize];
            if state.in_flight
                || !state.queue.is_empty()
                || driver.chain_table.is_active(conn_index)
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "earlier sends are still in flight on this connection",
                ));
            }

            // Gather iovecs over the held provided-buffer memory (PendingRecvBuf
            // is Copy, so each index read releases the recv_hold borrow).
            let mut iovecs = [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; crate::buffer::send_slab::MAX_IOVECS];
            let mut bids = [0u16; crate::buffer::send_slab::MAX_IOVECS];
            let mut total: u32 = 0;
            for i in 0..n {
                let p = driver.recv_hold[conn_index as usize][i];
                iovecs[i] = libc::iovec {
                    iov_base: p.ptr as *mut libc::c_void,
                    iov_len: p.len as usize,
                };
                bids[i] = p.bid;
                total += p.len;
            }

            let generation = driver.connections.generation(conn_index);
            let (slab_idx, msg_ptr) = driver
                .send_slab
                .allocate_recv_forward(conn_index, generation, &iovecs[..n], &bids[..n], total)
                .ok_or_else(|| io::Error::other("send slab exhausted"))?;

            let id = executor.register_send(conn_index);
            driver.send_slab.set_send_id(slab_idx, id, total);
            match driver
                .ring
                .submit_send_recv_bufs_coalesced(conn_index, msg_ptr, slab_idx)
            {
                Ok(()) => {
                    // Buffers are now owned by the slab entry (bids replenished on
                    // completion) — remove them from the hold.
                    for _ in 0..n {
                        driver.recv_hold[conn_index as usize].pop_front();
                    }
                    driver.send_held_recv[conn_index as usize] += n as u32;
                    driver.send_queues[conn_index as usize].in_flight = true;
                    Ok(SendFuture::pending(conn_index, self.generation, id))
                }
                Err(e) => {
                    // Submission failed — release the slab entry; buffers stay in
                    // the hold (bids un-replenished, still valid) for a later retry.
                    driver.send_slab.release(slab_idx);
                    executor.withdraw_send(id);
                    Err(e)
                }
            }
        })
    }

    /// Enable the recv-forward path for this connection.
    ///
    /// mio fallback: no-op. There is no provided-buffer ring to hold, so recv
    /// data flows through the accumulator as usual and
    /// [`forward_held`](Self::forward_held) copy-sends it, at most 32
    /// receive buffers' worth per call (no zero-copy). Keeps the API portable across backends.
    #[cfg(not(has_io_uring))]
    pub fn enable_recv_forward(&self) {}

    /// Forward currently-buffered recv data back to the peer.
    ///
    /// mio fallback: copy-sends the start of the accumulator and consumes it,
    /// returning a [`SendFuture`] that resolves with the bytes sent (`0` when
    /// empty). A call forwards at most 32 receive buffers' worth of bytes
    /// (`ConfigBuilder::recv_buffer`'s `buffer_size` each), the most one
    /// io_uring call forwards. The rest stays buffered for the next call,
    /// and `recv_ready` is ready at once. After the peer closes, the rest
    /// survives only while each call follows the previous one's completion
    /// directly: the connection's teardown discards it once nothing is
    /// queued to send. Gate calls on `recv_ready` as on the io_uring
    /// backend.
    #[cfg(not(has_io_uring))]
    pub fn forward_held(&self) -> io::Result<SendFuture> {
        with_state(|driver, executor| {
            let conn_index = self.conn_index;
            if driver.connections.generation(conn_index) != self.generation {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "stale connection",
                ));
            }
            // Copy out the accumulated bytes (releases the accumulator borrow so
            // we can take a DriverCtx), then consume them once the send is queued.
            let held = driver.accumulators.data(conn_index);
            let data = held[..held.len().min(driver.forward_held_max_bytes)].to_vec();
            if data.is_empty() {
                return Ok(SendFuture::ready(conn_index, self.generation, Ok(0)));
            }
            let id = executor.register_send(conn_index);
            let mut ctx = driver.make_ctx();
            if let Err(e) = ctx.send_awaited(self.token(), &data, id) {
                executor.withdraw_send(id);
                return Err(e);
            }
            driver.accumulators.consume(conn_index, data.len());
            Ok(SendFuture::pending(conn_index, self.generation, id))
        })
    }

    /// Begin building a scatter-gather send with mixed copy + zero-copy guard parts.
    ///
    /// This mirrors `DriverCtx::send_parts()` — use `.copy(data)` for copied parts
    /// and `.guard(guard)` for zero-copy parts backed by `SendGuard`. Call `.submit()`
    /// to submit the SQE. Fire-and-forget: no future returned.
    #[cfg(has_io_uring)]
    pub(crate) fn send_parts(&self) -> AsyncSendBuilder {
        AsyncSendBuilder {
            token: self.token(),
        }
    }

    // ── Send (awaitable) ─────────────────────────────────────────────

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
    /// TLS connection the pool is checked against the *ciphertext* bound
    /// before anything is encrypted, which is what keeps that true there.
    /// The one exception is the unbuffered TLS engine with a
    /// `send_copy_slot_size` too small to hold one whole record, where no
    /// bound exists: a shortfall found mid-encryption closes the connection
    /// and returns `Err`. Submission-queue pressure is not an error: the send is queued
    /// and retried. Persistent submission-queue starvation is reported like
    /// a write error: the awaited `SendFuture` resolves `Err` and the
    /// connection is closed.
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
            // A closure that submitted nothing (an empty chain, or no
            // `finish`) sent nothing.
            if !driver.chain_table.carries(self.conn_index, id) {
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

    /// Cancel pending I/O operations on this connection.
    pub fn cancel(&self) -> io::Result<()> {
        with_state(|driver, _| {
            let mut ctx = driver.make_ctx();
            ctx.cancel(self.token())
        })
    }

    /// Request graceful shutdown of the worker event loop.
    pub fn request_shutdown(&self) {
        with_state(|driver, _| {
            let mut ctx = driver.make_ctx();
            ctx.request_shutdown();
        })
    }

    // ── TLS ──────────────────────────────────────────────────────────

    /// Query TLS session info for this connection.
    pub fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        with_state(|driver, _| {
            let ctx = driver.make_ctx();
            ctx.tls_info(self.token())
        })
    }

    /// Whether this TLS connection's EOF was a truncation: the peer's TCP
    /// FIN arrived *without* a preceding close_notify alert. A truncated
    /// stream may be missing data the peer (or an active attacker injecting
    /// the FIN) cut off — length- or delimiter-framed protocols should treat
    /// it as an error rather than a clean end-of-stream.
    ///
    /// Check this when a recv (`with_data`/`with_bytes`) reports EOF. The
    /// flag is readable while the connection slot is still held (the wake
    /// that delivered the EOF and this check run before the slot is
    /// recycled); it returns `false` for plaintext connections, for clean
    /// TLS shutdowns, and once the slot has been reused.
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

    /// Close this connection.
    ///
    /// Does nothing if the connection has already been released (its slot may
    /// now hold another connection), or when called outside the worker's
    /// executor.
    pub fn close(&self) {
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
        driver.close_connection(self.conn_index);
    }

    /// Which listener accepted this connection, or `None` if it is outbound.
    ///
    /// A runtime can bind several listeners and they all feed the same
    /// `on_accept`; this is how a handler tells them apart. Ids follow
    /// `bind()` call order — see [`ListenerId`](crate::ListenerId).
    pub fn listener(&self) -> Option<crate::ListenerId> {
        with_state(|driver, _| {
            let conn = driver.connections.get(self.conn_index)?;
            if conn.generation != self.generation {
                return None;
            }
            conn.listener
        })
    }

    /// Access peer address.
    pub fn peer_addr(&self) -> Option<crate::connection::PeerAddr> {
        with_state(|driver, _| {
            let conn = driver.connections.get(self.conn_index)?;
            if conn.generation != self.generation {
                return None;
            }
            conn.peer_addr.clone()
        })
    }

    /// Check if this connection is outbound (initiated via connect).
    pub fn is_outbound(&self) -> bool {
        with_state(|driver, _| {
            driver
                .connections
                .get(self.conn_index)
                .map(|cs| cs.generation == self.generation && cs.outbound)
                .unwrap_or(false)
        })
    }

    /// Whether this handle still refers to a live, usable connection.
    ///
    /// Returns `false` if the slot has been released and its generation bumped
    /// (a stale handle after slot reuse) **or** if the connection is closing
    /// (`close()` was called — `lifecycle` is `Closing` — even before the Close
    /// CQE has released the slot). Because a proactive `close()` flips the state
    /// synchronously, this is a *deterministic* poison probe: a caller that owns
    /// a `ConnCtx` copy (e.g. a connection pool) can detect an
    /// undrained-`ValueStream` poison on the very next turn, without waiting for
    /// the Close CQE to bump the generation.
    ///
    /// A clean, fully-drained streaming read (which restores the default read
    /// path via `end_segments`) leaves the connection `Multi`/armed, so this
    /// returns `true` and the connection stays reusable.
    pub fn is_alive(&self) -> bool {
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
    /// completions are reaped and send-pool slots recycled. Yielding to the
    /// executor is *not* a substitute: a self-wake is re-polled within the
    /// same ready-queue drain pass, before the loop revisits the ring.
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
    /// Begin building a scatter-gather send.
    ///
    /// On the mio backend, this degrades to copy-only sends.
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
        // Zero-copy fast path: check pending recv buffer before accumulator.
        // Only available on io_uring where kernel-provided buffers are used.
        #[cfg(has_io_uring)]
        if driver.pending_recv_bufs[self.conn_index as usize].is_some() {
            // Non-merging emptiness check — `data()` would merge a held
            // frozen remainder just to answer a boolean.
            let acc_empty = driver.accumulators.is_empty(self.conn_index);
            if acc_empty {
                // Borrow the kernel buffer in-place — no copy.
                let pending = driver.pending_recv_bufs[self.conn_index as usize].unwrap();
                let data = unsafe { std::slice::from_raw_parts(pending.ptr, pending.len as usize) };
                #[cfg(has_io_uring)]
                let cb_conn = self.conn_index;
                let f = self.f.as_mut().expect("WithDataFuture polled after Ready");
                let result = {
                    #[cfg(has_io_uring)]
                    let _cb = ReaderCallback::enter(cb_conn);
                    f(data)
                };
                match result {
                    ParseResult::Consumed(consumed) if consumed > 0 => {
                        // The closure may have called forward_recv_buf(), which
                        // takes the pending slot. Only replenish if still present.
                        if let Some(pending) =
                            driver.pending_recv_bufs[self.conn_index as usize].take()
                        {
                            if consumed < pending.len as usize {
                                // Partial consume: copy remainder to accumulator.
                                let remainder = unsafe {
                                    std::slice::from_raw_parts(
                                        pending.ptr.add(consumed),
                                        pending.len as usize - consumed,
                                    )
                                };
                                driver.accumulators.append(self.conn_index, remainder);
                            }
                            driver.pending_replenish.push(pending.bid);
                        }
                        self.f.take();
                        return Poll::Ready(consumed);
                    }
                    _ => {
                        // NeedMore / Consumed(0): flush pending to accumulator
                        // and fall through to the existing accumulator path.
                        if let Some(pending) =
                            driver.pending_recv_bufs[self.conn_index as usize].take()
                        {
                            let pending_data = unsafe {
                                std::slice::from_raw_parts(pending.ptr, pending.len as usize)
                            };
                            driver.accumulators.append(self.conn_index, pending_data);
                            driver.pending_replenish.push(pending.bid);
                        }
                        // Fall through to accumulator path below.
                    }
                }
            } else {
                // Accumulator has data AND there's a pending buffer.
                // Flush pending to accumulator (prepend — it arrived first).
                let pending = driver.pending_recv_bufs[self.conn_index as usize]
                    .take()
                    .unwrap();
                let pending_data =
                    unsafe { std::slice::from_raw_parts(pending.ptr, pending.len as usize) };
                driver.accumulators.prepend(self.conn_index, pending_data);
                driver.pending_replenish.push(pending.bid);
                // Fall through to accumulator path below.
            }
        }

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
            executor.owner_task[self.conn_index as usize] = Some(CURRENT_TASK_ID.with(|c| c.get()));
            executor.recv_waiters[self.conn_index as usize] = true;
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
        executor.owner_task[self.conn_index as usize] = Some(CURRENT_TASK_ID.with(|c| c.get()));
        executor.recv_waiters[self.conn_index as usize] = true;
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
        // Flush any pending zero-copy recv buffer to accumulator so
        // take_frozen() will include it (io_uring only).
        #[cfg(has_io_uring)]
        if let Some(pending) = driver.pending_recv_bufs[self.conn_index as usize].take() {
            let pending_data =
                unsafe { std::slice::from_raw_parts(pending.ptr, pending.len as usize) };
            driver.accumulators.append(self.conn_index, pending_data);
            driver.pending_replenish.push(pending.bid);
        }

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

            executor.owner_task[self.conn_index as usize] = Some(CURRENT_TASK_ID.with(|c| c.get()));
            executor.recv_waiters[self.conn_index as usize] = true;
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
                }
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

        executor.owner_task[self.conn_index as usize] = Some(CURRENT_TASK_ID.with(|c| c.get()));
        executor.recv_waiters[self.conn_index as usize] = true;
        Poll::Pending
    }
}

// ── RecvHalf — the exclusive read side of a connection ───────────────

/// The exclusive **read side** of a connection.
///
/// Obtained from [`ConnCtx::take_recv`]. Neither `Copy` nor `Clone`, and every
/// method takes `&mut self`.
///
/// # How much the compiler actually enforces
///
/// `&mut self` only prevents a second call while the **return value carries the
/// borrow**. Three methods do that, and for them the conflict is a compile
/// error rather than a runtime refusal:
///
/// - `segments` — returns `SegmentReader<'_>`
/// - `forward_to` / [`forward_to_conn`](Self::forward_to_conn)
///   — return `ForwardToFuture<'_>`
///
/// The rest — `with_data`, `with_data_result`, `with_bytes`, `with_segments`,
/// `with_bytes_segments`, `recv_ready`, `recv_owned_segment` — return futures
/// built from
/// `conn_index`/`generation` by value, with no lifetime parameter, so the
/// borrow ends at the end of the call expression and two of them can be held at
/// once. Those still rely on the runtime checks. Giving them a borrow-carrying
/// wrapper is what would make the type enforce the whole rule; until then this
/// section is the honest statement of what it buys.
///
/// The three that are enforced:
///
/// ```ignore
/// let mut rx = conn.take_recv()?;
/// let mut a = rx.segments()?;
/// let mut b = rx.segments()?;   // compile error: `rx` is already borrowed
/// ```
///
/// ```ignore
/// let mut rx = conn.take_recv()?;
/// let mut r = rx.segments()?;
/// rx.with_data(|_| ParseResult::Consumed(0)).await;  // compile error
/// ```
///
/// Dropping the half releases the claim, so a connection can be handed on.
///
/// Sends stay on [`ConnCtx`], which is still `Copy` — that half has its own
/// exclusivity rule ("forward *or* send, not both") that this step does not yet
/// enforce. See `docs/connection-handle-ownership-design.md`.
///
/// Available on both backends. `segments`, `recv_owned_segment`,
/// `with_segments` and `forward_to` are io_uring only, as they are on
/// [`ConnCtx`]. `with_bytes_segments` and `end_segments` are on both; mio
/// has no segmented recv domain, so there `with_bytes_segments` presents the
/// accumulator and `end_segments` returns `Ok(())`.
pub struct RecvHalf {
    conn: ConnCtx,
    /// Same reason as [`ConnCtx`]: pinned to its owning worker thread.
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

    /// See [`Connection::segments`]. The returned reader borrows this half, so a
    /// second one is a compile error rather than an `EBUSY`.
    #[cfg(has_io_uring)]
    pub fn segments(&mut self) -> io::Result<SegmentReader<'_>> {
        self.conn.segments_via(SegmentedEntry::ViaHalf)
    }

    /// See [`Connection::recv_owned_segment`].
    #[cfg(has_io_uring)]
    pub fn recv_owned_segment(&mut self) -> io::Result<RecvOwnedSegment> {
        self.conn.recv_owned_segment_via(SegmentedEntry::ViaHalf)
    }

    /// See [`Connection::with_segments`].
    #[cfg(has_io_uring)]
    pub fn with_segments<F>(&mut self, f: F) -> WithSegmentsFuture<F>
    where
        F: FnMut(&SegChain<'_>) -> SegConsumed,
    {
        self.conn.with_segments(f)
    }

    /// See [`Connection::with_bytes_segments`].
    pub fn with_bytes_segments<F>(&mut self, f: F) -> WithBytesSegmentsFuture<F>
    where
        F: FnMut(&[Bytes]) -> ParseResult,
    {
        self.conn.with_bytes_segments(f)
    }

    /// See [`Connection::end_segments`]. Leaves the segmented domain and restores
    /// the default read path; the half stays valid and can read again.
    pub fn end_segments(&mut self) -> io::Result<()> {
        self.conn.end_segments()
    }

    /// Offer this connection for rebalancing. See
    /// [`ConnCtx::offer_for_park`].
    pub fn offer_for_park(&self, state: Option<crate::park::ParkState>) {
        self.conn.offer_for_park(state);
    }

    /// See [`ConnCtx::token`].
    pub fn token(&self) -> ConnToken {
        self.conn.token()
    }

    /// See [`ConnCtx::is_alive`].
    pub fn is_alive(&self) -> bool {
        self.conn.is_alive()
    }

    /// The underlying handle, for the read-side APIs that are still only on
    /// `ConnCtx`. Crate-internal: it hands back the full surface.
    pub(crate) fn as_conn_ref(&self) -> ConnCtx {
        self.conn
    }

    /// See [`ConnCtx::enable_recv_forward`].
    pub fn enable_recv_forward(&mut self) {
        self.conn.enable_recv_forward();
    }

    /// See [`ConnCtx::forward_held`].
    pub fn forward_held(&mut self) -> io::Result<SendFuture> {
        self.conn.forward_held()
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

    /// See [`Connection::take_recv_sink`].
    pub fn take_recv_sink(&mut self) -> usize {
        self.conn.take_recv_sink()
    }

    /// See [`Connection::recv_ready`].
    pub fn recv_ready(&mut self) -> RecvReadyFuture {
        self.conn.recv_ready()
    }

    /// See [`ConnCtx::forward_to`].
    #[cfg(has_io_uring)]
    pub fn forward_to<'h, 's: 'h>(
        &'h mut self,
        sink: &'s SinkFd<'s>,
        len: usize,
    ) -> ForwardToFuture<'h> {
        self.conn.forward_to(sink, len)
    }

    /// Forward the next `len` received bytes into another connection.
    ///
    /// The sink is its [`SendHalf`], borrowed mutably for as long as the
    /// forward runs. That borrow is the point: a forward submits its own SQE
    /// straight to the ring rather than through the sink's send queue, so a
    /// concurrent `send` to the same socket would interleave with it — and
    /// io_uring does not order independent SQEs (Domain Invariant 2). Holding
    /// the half is both the permission to write and the proof that nobody else
    /// is; the borrow checker now says so instead of a comment.
    #[cfg(has_io_uring)]
    pub fn forward_to_conn<'h, 's: 'h>(
        &'h mut self,
        sink: &'s mut SendHalf,
        len: usize,
    ) -> ForwardToFuture<'h> {
        let target = crate::backend::uring::driver::SinkTarget::Conn {
            index: sink.conn.conn_index,
            generation: sink.conn.generation,
        };
        let armed = self.conn.arm_forward_source(target, len as u64, true);
        ForwardToFuture {
            conn_index: self.conn.conn_index,
            generation: self.conn.generation,
            epoch: armed.unwrap_or(0),
            refused: armed.err(),
            _borrow: PhantomData,
        }
    }

    /// Forward the next `len` received bytes into another connection.
    ///
    /// The sink is its [`SendHalf`], borrowed mutably for as long as the
    /// forward runs. That borrow is the point: a forward submits its own SQE
    /// straight to the ring rather than through the sink's send queue, so a
    /// concurrent `send` to the same socket would interleave with it — and
    /// io_uring does not order independent SQEs (Domain Invariant 2). Holding
    /// the half is both the permission to write and the proof that nobody else
    /// is; the borrow checker now says so instead of a comment.
    ///
    /// The two backends return different futures (io_uring forwards from the
    /// held provided buffers; mio pumps through the accumulator), so this is
    /// two signatures rather than one.
    #[cfg(not(has_io_uring))]
    pub fn forward_to_conn<'h, 's: 'h>(
        &'h mut self,
        sink: &'s mut SendHalf,
        len: usize,
    ) -> ForwardToConnFuture<'s> {
        self.conn.forward_to_conn(&sink.conn, len)
    }
}

/// An owned connection: the pair of claimed halves.
///
/// Delivered to
/// [`AsyncEventHandler::on_accept`](crate::AsyncEventHandler::on_accept) for
/// accepted connections, and resolved from [`connect`](crate::connect) and
/// [`connect_unix`](crate::connect_unix) for outbound ones.
///
/// Not `Copy`, not `Clone`, and `!Send`, so one task owns one connection. A
/// `Copy` handle carrying the read surface allowed two readers to interleave on
/// one connection and desynchronise the protocol (#423, #425, #429).
///
/// Most handlers can use this directly: the read and write methods are the
/// same ones `ConnCtx` used to carry.
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
pub struct Connection {
    tx: SendHalf,
    rx: RecvHalf,
}

impl Connection {
    /// The connection handed to `on_accept`, built without going through
    /// [`ConnCtx::split`].
    ///
    /// `split` records the read claim via `with_state`, but `spawn_accept_task`
    /// runs *outside* a task poll, so there is no `CURRENT_DRIVER` to reach.
    /// The event loop owns `&mut Driver` at that point and sets the claim
    /// itself; the slot is freshly accepted, so the claim is always free.
    pub(crate) fn for_accept(conn: ConnCtx) -> Self {
        Self::from_claimed(conn)
    }

    /// Build the pair from a slot whose halves the caller has already marked
    /// claimed.
    ///
    /// Two callers use this. `spawn_accept_task` runs outside a task poll, and
    /// the event loop sets the claim while it owns `&mut Driver`.
    /// `ConnectFuture::poll` runs inside `with_state` and sets the claim there.
    /// Neither goes through [`ConnCtx::split`].
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
    /// Mirrors `ConnCtx::for_test`: the halves are unclaimed and the connection
    /// does not exist. The result is only safe on buffered paths (encoders,
    /// write buffers, pending queues) that never reach the wire. Gated on the
    /// `testing` feature for the same reason as `ConnCtx::for_test`.
    #[cfg(feature = "testing")]
    #[doc(hidden)]
    pub fn for_test(conn_index: u32, generation: u32) -> Self {
        Self::from_claimed(ConnCtx::new(conn_index, generation))
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

    /// See [`Connection::with_data`].
    pub fn with_data<F: FnMut(&[u8]) -> ParseResult>(&mut self, f: F) -> WithDataFuture<F> {
        self.rx.with_data(f)
    }

    /// See [`Connection::with_data_result`].
    pub fn with_data_result<F: FnMut(&[u8]) -> ParseResult>(
        &mut self,
        f: F,
    ) -> WithDataResultFuture<F> {
        self.rx.with_data_result(f)
    }

    /// See [`Connection::with_bytes`].
    pub fn with_bytes<F: FnMut(Bytes) -> ParseResult>(&mut self, f: F) -> WithBytesFuture<F> {
        self.rx.with_bytes(f)
    }

    /// Returns a future that resolves when received bytes are buffered for
    /// the connection, when a recv sink has received data, or when the
    /// connection has finished receiving.
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

    /// See [`Connection::segments`].
    #[cfg(has_io_uring)]
    pub fn segments(&mut self) -> io::Result<SegmentReader<'_>> {
        self.rx.segments()
    }

    /// See [`Connection::recv_owned_segment`].
    #[cfg(has_io_uring)]
    pub fn recv_owned_segment(&mut self) -> io::Result<RecvOwnedSegment> {
        self.rx.recv_owned_segment()
    }

    /// See [`Connection::with_segments`].
    #[cfg(has_io_uring)]
    pub fn with_segments<F>(&mut self, f: F) -> WithSegmentsFuture<F>
    where
        F: FnMut(&SegChain<'_>) -> SegConsumed,
    {
        self.rx.with_segments(f)
    }

    /// Wait until received data is available, then hand the parser the
    /// connection's buffered bytes as an ordered list of `Bytes` pieces.
    ///
    /// For a segment parser: one that parses a message split across pieces
    /// and returns a value inside one piece as a slice of it. The parser
    /// returns a [`ParseResult`] for the bytes consumed from the front of the
    /// pieces, as a [`with_bytes`](Self::with_bytes) parser does for its one
    /// `Bytes`.
    ///
    /// On io_uring the call puts the connection in the segmented receive
    /// domain, where each completion's buffer is held in place. Each held
    /// buffer is presented as a `Bytes` view of the ring buffer's memory, so
    /// a value the parser slices out of one piece is not copied. A view keeps
    /// its whole ring buffer from being reused until the view and every
    /// clone and slice of it have dropped. A completion the runtime copied
    /// instead (lend refused, the ring at its reserve, or a TLS connection's
    /// decrypted plaintext) is presented as a heap `Bytes`. Bytes the
    /// runtime copied into the accumulator come first, as one piece.
    ///
    /// On mio the pieces are the accumulator, as one piece.
    ///
    /// After `Consumed(k)` the first `k` bytes are removed and the rest stay
    /// held, uncopied. After `NeedAtLeast(n)` the parser is not called again
    /// until `n` more bytes are buffered, the receive side finishes, or, on
    /// io_uring, the hold reaches the receive throttle's cap. At the cap an
    /// incomplete parse copies the held bytes into the accumulator, so a
    /// message longer than the cap still completes.
    ///
    /// The connection stays in the segmented domain after the future
    /// resolves. Call [`end_segments`](Self::end_segments) before reading
    /// with `with_data`, `with_bytes`, `recv_ready`, a `ConnStream` or a recv
    /// sink. On io_uring, until it runs, those see only bytes a hold-cap copy
    /// left in the accumulator, and none that arrive later.
    ///
    /// Resolves to:
    ///
    /// - `Ok(k)` for `k` bytes consumed;
    /// - `Ok(0)` at end of stream, for a stale handle, or after the
    ///   connection is closed because the buffered bytes exceed
    ///   `recv_accumulator_max`;
    /// - `Err(EBUSY)` when, since the future last parked, another reader
    ///   consumed bytes or the connection left the segmented domain
    ///   (`end_segments`, a forward ending, a `SegmentReader` dropping); call
    ///   again to read with the connection's current state;
    /// - `Err(EBUSY)` while a forward runs or a `SegmentReader` is live. A
    ///   new call also resolves to `Err(EBUSY)`, without waiting, until the
    ///   forward ends or the reader drops;
    /// - `Err(EBUSY)` on io_uring for a call first polled after
    ///   [`enable_recv_forward`](RecvHalf::enable_recv_forward) was called on
    ///   the connection, until the connection starts closing. On mio
    ///   `enable_recv_forward` does nothing and this call reads normally.
    pub fn with_bytes_segments<F>(&mut self, f: F) -> WithBytesSegmentsFuture<F>
    where
        F: FnMut(&[Bytes]) -> ParseResult,
    {
        self.rx.with_bytes_segments(f)
    }

    /// Return the connection to the default receive domain, after
    /// [`with_bytes_segments`](Self::with_bytes_segments) or another
    /// segmented reader.
    ///
    /// On io_uring the held bytes no reader has consumed are appended, in
    /// order, behind any bytes already in the accumulator, and the next
    /// `with_data` or `with_bytes` call reads them in that order. If that
    /// copy would exceed `recv_accumulator_max`, the connection is closed and
    /// an `OutOfMemory` error returned; for a stale handle the error is
    /// `EPIPE`.
    ///
    /// On mio, which has no segmented domain, it returns `Ok(())`.
    pub fn end_segments(&mut self) -> io::Result<()> {
        self.rx.end_segments()
    }

    /// See [`ConnCtx::forward_to`].
    #[cfg(has_io_uring)]
    pub fn forward_to<'h, 's: 'h>(
        &'h mut self,
        sink: &'s SinkFd<'s>,
        len: usize,
    ) -> ForwardToFuture<'h> {
        self.rx.forward_to(sink, len)
    }

    /// See [`ConnCtx::forward_to_conn`].
    #[cfg(has_io_uring)]
    pub fn forward_to_conn<'h, 's: 'h>(
        &'h mut self,
        sink: &'s mut SendHalf,
        len: usize,
    ) -> ForwardToFuture<'h> {
        self.rx.forward_to_conn(sink, len)
    }

    /// See [`ConnCtx::forward_to_conn`].
    #[cfg(not(has_io_uring))]
    pub fn forward_to_conn<'h, 's: 'h>(
        &'h mut self,
        sink: &'s mut SendHalf,
        len: usize,
    ) -> ForwardToConnFuture<'s> {
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

    /// See [`ConnCtx::close`].
    pub fn close(&mut self) {
        self.tx.close();
    }

    /// Offer this connection for rebalancing. See
    /// [`ConnCtx::offer_for_park`].
    pub fn offer_for_park(&self, state: Option<crate::park::ParkState>) {
        self.tx.offer_for_park(state);
    }

    /// See [`ConnCtx::token`].
    pub fn token(&self) -> ConnToken {
        self.tx.token()
    }

    /// See [`ConnCtx::is_alive`].
    pub fn is_alive(&self) -> bool {
        self.tx.is_alive()
    }

    /// See [`ConnCtx::peer_addr`].
    pub fn peer_addr(&self) -> Option<crate::connection::PeerAddr> {
        self.tx.peer_addr()
    }

    /// See [`ConnCtx::listener`].
    pub fn listener(&self) -> Option<crate::ListenerId> {
        self.tx.listener()
    }

    /// See [`ConnCtx::is_outbound`].
    pub fn is_outbound(&self) -> bool {
        self.tx.is_outbound()
    }

    /// The underlying `ConnCtx`, for the APIs that still take one — most
    /// notably as a `forward_to_conn` sink. See [`SendHalf::as_conn`].
    pub fn as_conn(&self) -> ConnCtx {
        self.tx.as_conn()
    }

    // ── the rest of the ConnCtx surface ─────────────────────────────────

    /// See [`Connection::eof_truncated`].
    pub fn eof_truncated(&self) -> bool {
        self.rx.as_conn_ref().eof_truncated()
    }

    /// When the bytes consumed by the most recent reader call on this
    /// connection arrived.
    ///
    /// The reader calls that set it are `with_data`, `with_data_result`,
    /// `with_bytes`, `with_bytes_segments`, `try_with_data` and, on io_uring,
    /// `with_segments`, on this connection or its [`RecvHalf`]. The call's
    /// bytes are the ones it removed from the connection, whatever the parser
    /// returned.
    /// Forwards, recv sinks, `ConnStream` and segment readers do not set it.
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

    /// See [`Connection::try_with_data`].
    pub fn try_with_data<F: FnOnce(&[u8]) -> ParseResult>(&mut self, f: F) -> Option<ParseResult> {
        self.rx.as_conn_ref().try_with_data(f)
    }

    /// See [`Connection::take_recv_sink`].
    pub fn take_recv_sink(&mut self) -> usize {
        self.rx.as_conn_ref().take_recv_sink()
    }

    /// See [`ConnCtx::enable_recv_forward`].
    pub fn enable_recv_forward(&mut self) {
        self.rx.enable_recv_forward();
    }

    /// See [`ConnCtx::forward_held`].
    pub fn forward_held(&mut self) -> io::Result<SendFuture> {
        self.rx.forward_held()
    }

    /// See [`SendHalf::forward_recv_buf`].
    pub fn forward_recv_buf(&mut self, data: &[u8]) -> io::Result<()> {
        self.tx.as_conn().forward_recv_buf(data)
    }

    /// See [`ConnCtx::run_direct_echo`].
    #[cfg(has_io_uring)]
    pub fn run_direct_echo(&mut self) -> DirectEchoFuture {
        self.tx.as_conn().run_direct_echo()
    }

    /// See [`SendHalf::send_chain`].
    #[cfg(has_io_uring)]
    pub fn send_chain<F>(&mut self, f: F) -> io::Result<SendFuture>
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> io::Result<()>,
    {
        self.tx.as_conn().send_chain(f)
    }

    /// See [`SendHalf::send_chain_nowait`].
    #[cfg(has_io_uring)]
    pub fn send_chain_nowait<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> R,
    {
        self.tx.as_conn().send_chain_nowait(f)
    }

    /// See [`SendHalf::shutdown_write`].
    pub fn shutdown_write(&mut self) {
        self.tx.as_conn().shutdown_write();
    }

    /// See [`ConnCtx::cancel`].
    pub fn cancel(self) {
        let _ = self.tx.as_conn().cancel();
    }

    /// See [`ConnCtx::tls_info`].
    pub fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.tx.as_conn().tls_info()
    }

    /// See [`ConnCtx::index`].
    pub fn index(&self) -> usize {
        self.tx.as_conn().index()
    }

    /// See [`ConnCtx::request_shutdown`].
    pub fn request_shutdown(&self) {
        self.tx.as_conn().request_shutdown();
    }
}

/// The **write side** of a connection, from [`ConnCtx::split`].
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
/// Note the write side has an exclusivity rule of its own that is **not yet
/// enforced** — a connection that is the sink of a `forward_to_conn` must not
/// be sent to concurrently. See `docs/connection-handle-ownership-design.md`.
///
/// Available on both backends.
pub struct SendHalf {
    conn: ConnCtx,
    _not_send: PhantomData<*const ()>,
}

impl SendHalf {
    /// See [`SendHalf::send`].
    pub fn send(&mut self, data: &[u8]) -> io::Result<SendFuture> {
        self.conn.send(data)
    }

    /// See [`SendHalf::send_nowait`].
    pub fn send_nowait(&mut self, data: &[u8]) -> io::Result<()> {
        self.conn.send_nowait(data)
    }

    /// See [`SendHalf::send_parts`].
    pub fn send_parts(&mut self) -> AsyncSendBuilder {
        self.conn.send_parts()
    }

    /// See [`SendHalf::send_backpressured`].
    pub fn send_backpressured<'a>(&mut self, data: &'a [u8]) -> BackpressuredSendFuture<'a> {
        self.conn.send_backpressured(data)
    }

    /// See [`ConnCtx::close`].
    pub fn close(&mut self) {
        self.conn.close();
    }

    /// Send `data`, the bytes a `with_data` closure was handed, without
    /// copying them when possible.
    ///
    /// On io_uring, if `data` is exactly the connection's pending recv buffer,
    /// that buffer is sent as is and replenished when the send completes. If
    /// `data` is exactly the connection's whole recv accumulator, the
    /// accumulator is detached and sent under a guard (copied into the send
    /// pool below `send_zc_threshold`). Otherwise `data` is copied as by
    /// [`send_nowait`](Self::send_nowait).
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

    /// See [`ConnCtx::index`].
    pub fn index(&self) -> usize {
        self.conn.index()
    }

    /// See [`ConnCtx::tls_info`].
    pub fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.conn.tls_info()
    }

    /// See [`ConnCtx::request_shutdown`].
    pub fn request_shutdown(&self) {
        self.conn.request_shutdown();
    }

    /// See [`SendHalf::send_chain`].
    #[cfg(has_io_uring)]
    pub fn send_chain<F>(&mut self, f: F) -> io::Result<SendFuture>
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> io::Result<()>,
    {
        self.conn.send_chain(f)
    }

    /// See [`SendHalf::send_chain_nowait`].
    #[cfg(has_io_uring)]
    pub fn send_chain_nowait<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> R,
    {
        self.conn.send_chain_nowait(f)
    }

    /// Offer this connection for rebalancing. See
    /// [`ConnCtx::offer_for_park`].
    pub fn offer_for_park(&self, state: Option<crate::park::ParkState>) {
        self.conn.offer_for_park(state);
    }

    /// See [`ConnCtx::token`].
    pub fn token(&self) -> ConnToken {
        self.conn.token()
    }

    /// See [`ConnCtx::is_alive`].
    pub fn is_alive(&self) -> bool {
        self.conn.is_alive()
    }

    /// See [`ConnCtx::peer_addr`].
    pub fn peer_addr(&self) -> Option<crate::connection::PeerAddr> {
        self.conn.peer_addr()
    }

    /// See [`ConnCtx::listener`].
    pub fn listener(&self) -> Option<crate::ListenerId> {
        self.conn.listener()
    }

    /// See [`ConnCtx::is_outbound`].
    pub fn is_outbound(&self) -> bool {
        self.conn.is_outbound()
    }

    /// The underlying handle, for the APIs that still take a `ConnCtx` — most
    /// notably as a `forward_to_conn` sink.
    ///
    /// This is an escape hatch, and it hands back the full `Copy` surface: the
    /// ownership model is only advisory until step 4 takes the recv methods off
    /// `ConnCtx` entirely. Do not use it to read.
    pub fn as_conn(&self) -> ConnCtx {
        self.conn
    }
}

impl Drop for SendHalf {
    /// Release the write claim, **if it is still ours**.
    ///
    /// Generation-gated for the same reason as [`RecvHalf`]'s: the claim is per
    /// *slot*, and a half can outlive its connection inside a standalone task,
    /// so clearing unconditionally would steal the claim of whoever owns the
    /// slot now.
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
    /// Release the claim, **if it is still ours**.
    ///
    /// The claim is per *slot*, and a half can outlive its connection:
    /// [`spawn`] requires only `'static`, not `Send`, so a standalone task can
    /// hold one past teardown. If the slot has since been recycled and its new
    /// occupant has taken its own half, clearing unconditionally would steal
    /// that claim and permit a second `RecvHalf` on a live connection.
    ///
    /// `Driver::clear_conn_claims` at the recycle point is what guarantees a
    /// fresh slot starts clean; this only releases a claim of our own
    /// generation.
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

// ── Segmented recv (Mode B — Borrow) ─────────────────────────────────

/// An async **lending iterator** over a connection's received provided buffers,
/// obtained from [`Connection::segments`] (io_uring only).
///
/// Each [`next`](Self::next) yields one zero-copy [`RecvSegment`] borrowing the
/// reader exclusively (`&mut self`). Because the segment holds that `&mut`
/// borrow, calling `next` again while a segment is alive is a **compile error** —
/// so "drop the previous segment before pulling the next" and "the segment cannot
/// escape the runtime" are enforced by the borrow checker, not by convention.
/// This is why it cannot be a `futures::Stream`/`for` loop (inherent to lending
/// iterators). Typical use:
///
/// ```ignore
/// let mut r = conn.segments()?;
/// while let Some(seg) = r.next().await? {
///     process(&seg);        // seg: Deref<Target = [u8]>, held across the await below
///     downstream.send(&seg).await?;
/// }                          // loop ends at EOF (peer FIN, hold drained)
/// ```
///
/// The reader is itself `!Send`/`!Clone`/non-`Copy`: it is bound to the worker
/// thread's driver and to the connection it was created for.
#[cfg(has_io_uring)]
pub struct SegmentReader<'a> {
    conn_index: u32,
    /// Generation snapshot from the originating `ConnCtx`; a stale reader (slot
    /// reused) resolves `next` to `Ok(None)` (EOF) rather than reading the new
    /// occupant's buffers.
    generation: u32,
    /// Ties the reader to the `ConnCtx` borrow it came from.
    _borrow: PhantomData<&'a ()>,
    /// `!Send` + `!Sync`: a provided buffer is thread-affine and driver-released.
    _not_send: PhantomData<*const ()>,
}

#[cfg(has_io_uring)]
impl SegmentReader<'_> {
    /// Await the next received segment.
    ///
    /// Resolves to:
    /// - `Ok(Some(seg))` — a held provided buffer, handed out as a zero-copy
    ///   [`RecvSegment`] pinned until it is dropped.
    /// - `Ok(None)` — end of stream: the recv side is closed (peer FIN) and no
    ///   held buffers remain, or the connection slot was reused (stale reader).
    ///
    /// Parks when no buffer is held and the connection is still open, resuming
    /// when the recv completion handler holds a buffer and calls `wake_recv`
    /// (the same waiter mechanism as [`Connection::with_data`]).
    // This is a *lending* iterator: `next` borrows `&mut self` and yields a
    // segment tied to that borrow, which `std::iter::Iterator` cannot express.
    // The name is deliberate (it reads as an iterator to callers); it genuinely
    // cannot implement the trait.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> SegmentNext<'_> {
        SegmentNext {
            conn_index: self.conn_index,
            generation: self.generation,
            _borrow: PhantomData,
        }
    }
}

#[cfg(has_io_uring)]
impl Drop for SegmentReader<'_> {
    fn drop(&mut self) {
        // Release the exclusivity claim before the settle below, which has
        // early returns. Generation-gated for the same reason as
        // `RecvHalf::drop`: the flag is per slot, a reader can outlive its
        // connection inside a standalone task, and clearing after the slot was
        // recycled would steal the new occupant's claim.
        let _ = try_with_state(|driver, _executor| {
            if driver.connections.generation(self.conn_index) != self.generation {
                return;
            }
            if let Some(live) = driver.segment_reader_live.get_mut(self.conn_index as usize) {
                *live = false;
            }
        });

        // Auto-settle on drop: if the reader is dropped while the connection is
        // still in the segmented domain (i.e. `end_segments()` was not called —
        // the common pattern drops the reader first, then calls `end_segments`),
        // drain any still-held segments into the accumulator and restore the
        // default `with_data`/`with_bytes` read path. Without this, held bytes
        // would be stranded and a subsequent ordinary read would hang (arriving
        // buffers keep being held as segments). A live `RecvSegment` borrows the
        // reader `&mut`, so by here the pin slot is empty (the segment dropped
        // first) — only the hold needs draining.
        //
        // `try_with_state`: a reader owned by a parked task can be dropped in the
        // *unguarded* `drain_completions` during teardown (`CURRENT_DRIVER` is
        // `None`), where there is nothing to settle — the connection is closing
        // and `handle_close` reclaims the held bids. On accumulator overflow while
        // settling, poison (close) the connection.
        try_with_state(|driver, _executor| {
            if driver.connections.generation(self.conn_index) != self.generation {
                return; // slot reused — nothing of ours to settle.
            }
            if driver.recv_domain[self.conn_index as usize]
                != crate::recv::domain::RecvDomain::Segmented
            {
                return; // already settled (end_segments() was called).
            }
            if !driver.settle_forward_end(self.conn_index) {
                driver.close_connection(self.conn_index);
            }
        });
    }
}

/// Deliver bytes a segmented reader would otherwise never see (#423).
///
/// A segmented reader consumes only `segment_hold`; the `RecvAccumulator` is
/// invisible to it. Reaching a poll with a non-empty accumulator therefore
/// means those bytes are stranded, and the connection hangs with every other
/// signal healthy — provided ring full, multishot armed and live, no ENOBUFS,
/// no errors. That combination is invisible to every other counter here, which
/// is what made #423 cost months to find.
///
/// Called at the **top** of the poll, before the hold is examined, so adopted
/// bytes are returned by that same poll. Adopting after the park decision
/// instead would be useless: `Executor::wake_recv` is gated on the waiter flag
/// the caller has not set yet, so the wake would be a silent no-op and the
/// reader would still hang.
///
/// This is a recovery path, not an assertion. The accumulator can legitimately
/// be non-empty here — `SegmentReader::drop` settles the hold into it, and
/// `with_segments` leaves its un-consumed remainder there — and in every such
/// case adopting is simply the correct answer. (`SegmentNext::poll` already
/// treats a second concurrent reader as a recoverable misuse rather than a
/// panic; asserting here would contradict that.)
///
/// `enter_segmented_domain` adopts on entry, so a non-zero
/// `SEGMENT_STRANDED_ADOPTED` means bytes reached the accumulator *after*
/// entry. The known ways are a `RecvOwnedSegment` future created before one
/// of these and polled after it: a `with_bytes_segments` hold-cap copy, or a
/// `with_segments` under-drain. Any other is a path that strands bytes, and
/// this adoption is the only reason the connection kept working.
#[cfg(has_io_uring)]
fn adopt_stranded_accumulator(driver: &mut Driver, conn: u32) {
    if driver.accumulators.is_empty(conn) {
        return;
    }
    let idx = conn as usize;
    let buffered = driver.accumulators.take_frozen(conn);
    driver.segment_hold[idx].push_front(crate::backend::HeldRecvBuf::Owned(buffered));
    crate::metrics::POOL.increment(crate::metrics::pool::SEGMENT_STRANDED_ADOPTED);
}

/// The body of [`ConnCtx::enter_segmented_domain`], for a caller that already
/// holds the driver.
#[cfg(has_io_uring)]
fn enter_segmented(
    driver: &mut Driver,
    conn_index: u32,
    generation: u32,
    exclusive: bool,
    via: SegmentedEntry,
) -> io::Result<()> {
    let idx = conn_index as usize;
    // A stale handle must not touch the slot's new occupant. Without
    // this, a recycled connection has its accumulator drained into a
    // hold its own `with_data` reader never looks at — #423 inflicted
    // on an innocent third party. `arm_forward_source` refuses the same
    // way (EPIPE); the caller's own poll then resolves to EOF.
    if driver.connections.generation(conn_index) != generation {
        return Err(io::Error::from_raw_os_error(libc::EPIPE));
    }
    // A running Mode A forward owns this connection's hold, and its
    // `advance_forward` gathers whatever is in front. Adopting the
    // accumulator here would push post-`len` overshoot into the
    // forward's next write and corrupt the relayed stream, so leave a
    // forwarding connection strictly alone — exactly as
    // `arm_forward_source` refuses a second forward with EBUSY.
    if driver.forward_progress[idx].is_some() {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    // A live `SegmentReader` owns the delivery discipline until it
    // drops (its `Drop` settles the hold back into the accumulator), so
    // a second reader or an owned-segment read alongside it conflicts.
    if driver.segment_reader_live[idx] {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    // The recv half owns this connection's read side. Entering the
    // segmented domain through the `ConnCtx` path behind its back is
    // the mixing this design exists to stop, so refuse it wherever the
    // signature can say so. (`with_data` and friends still cannot
    // report it; step 4 of `docs/connection-handle-ownership-design.md`
    // removes that.)
    //
    // `ViaHalf` is exempt: the half holds this claim by construction,
    // so treating it like any other caller made it refuse itself.
    if via == SegmentedEntry::ViaConn && driver.recv_half_taken[idx] {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    if exclusive {
        driver.segment_reader_live[idx] = true;
    }
    driver.recv_domain[idx] = crate::recv::domain::RecvDomain::Segmented;
    if !driver.accumulators.is_empty(conn_index) {
        let buffered = driver.accumulators.take_frozen(conn_index);
        driver.segment_hold[idx].push_front(crate::backend::HeldRecvBuf::Owned(buffered));
    }
    if let Some(pending) = driver.pending_recv_bufs[idx].take() {
        // The lend's buffer hold becomes the entry's, so nothing is
        // copied or released. A lend's data starts inside its buffer,
        // so the offset is its distance from the buffer's start.
        let start = driver.provided_bufs.data_ptr(pending.bid, 0);
        let off = (pending.ptr as usize - start as usize) as u32;
        driver.segment_hold[idx].push_back(crate::backend::HeldRecvBuf::Pinned {
            bid: pending.bid,
            off,
            len: pending.len,
        });
    }
    Ok(())
}

#[cfg(has_io_uring)]
pub struct SegmentNext<'a> {
    conn_index: u32,
    generation: u32,
    _borrow: PhantomData<&'a mut ()>,
}

#[cfg(has_io_uring)]
impl<'a> Future for SegmentNext<'a> {
    type Output = io::Result<Option<RecvSegment<'a>>>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|driver, executor| {
            let conn = self.conn_index;
            let idx = conn as usize;

            // Stale reader (slot closed-then-reused for a different connection):
            // surface EOF so the caller's `while let Some` loop terminates rather
            // than reading the new occupant's held buffers.
            if driver.connections.generation(conn) != self.generation {
                return Poll::Ready(Ok(None));
            }

            // Before anything else: bytes stranded in the accumulator are
            // invisible to this reader. Adopt them so this poll can return them.
            adopt_stranded_accumulator(driver, conn);

            // One live pinned segment per connection at a time. A *single* reader
            // is kept sound by `&mut self` (a live `RecvSegment` borrows the reader
            // exclusively, so `next` cannot be called again). But `segments()`
            // takes `&self`, so a second concurrent `SegmentReader` on the same
            // connection could reach here with the pin slot already occupied —
            // overwriting it would orphan the first segment's bid (a ring leak).
            // Refuse rather than leak: surface the misuse as an error instead of
            // handing out a second pinned segment.
            if driver.segment_pinned[idx].is_some() {
                return Poll::Ready(Err(io::Error::other(
                    "a segmented-recv segment is already checked out — only one \
                     SegmentReader/RecvSegment may be live per connection at a time",
                )));
            }

            // A held buffer is available: hand it to a `RecvSegment`.
            if let Some(held) = driver.segment_hold[idx].pop_front() {
                match held {
                    crate::backend::HeldRecvBuf::Pinned { bid, off, len } => {
                        // Zero-copy: check the bid out into the (guaranteed-empty)
                        // pin slot; the segment's Drop / into_owned releases it
                        // exactly once.
                        driver.segment_pinned[idx] =
                            Some(crate::backend::HeldRecvBuf::Pinned { bid, off, len });
                        return Poll::Ready(Ok(Some(RecvSegment {
                            conn_index: conn,
                            generation: self.generation,
                            backing: SegBacking::Pinned { bid, off, len },
                            _borrow: PhantomData,
                            _not_send: PhantomData,
                        })));
                    }
                    crate::backend::HeldRecvBuf::Owned(bytes) => {
                        // Force-copied at delivery: no pin slot involved; the
                        // owned segment's Drop is a no-op.
                        return Poll::Ready(Ok(Some(RecvSegment {
                            conn_index: conn,
                            generation: self.generation,
                            backing: SegBacking::Owned(bytes),
                            _borrow: PhantomData,
                            _not_send: PhantomData,
                        })));
                    }
                }
            }

            // Hold empty. If the recv side is closed (peer FIN), this is EOF.
            let is_closed = driver
                .connections
                .get(conn)
                .map(|c| c.recv_finished())
                .unwrap_or(true);
            if is_closed {
                return Poll::Ready(Ok(None));
            }

            // Open and nothing held yet — park as a recv waiter. `handle_recv_multi`
            // pushes into `segment_hold` and calls `wake_recv` on the next arrival.
            executor.owner_task[idx] = Some(CURRENT_TASK_ID.with(|c| c.get()));
            executor.recv_waiters[idx] = true;
            Poll::Pending
        })
    }
}

/// A single received provided buffer, borrowed zero-copy from the ring.
///
/// Yielded by [`SegmentReader::next`]. Derefs to the received bytes (`&[u8]`).
/// The backing buffer stays pinned in the provided-buffer ring for the segment's
/// whole lifetime — its bid is **not** replenished until the segment is dropped
/// (or the connection closes). By construction it is:
///
/// - **`!Send` / `!Sync`** (`PhantomData<*const ()>`): a provided buffer is
///   thread-affine and released only by its owning worker's driver.
/// - **`!Clone` / non-`Copy`**: exactly one release per bid; a clone would
///   double-replenish or leak.
/// - **borrow-scoped** (`&'a mut` the reader): it cannot escape the async scope,
///   so the "holdable ⇒ copied-at-delivery" invariant holds structurally. To
///   *keep* the bytes past the scope, [`into_owned()`](Self::into_owned) copies
///   (Mode C); there is no zero-copy retain.
///
/// # Drop / release soundness
///
/// A segment's `Drop` does **not** always run inside an executor poll: a parked
/// task holding a segment can be dropped by a close/EOF CQE handled in the
/// *unguarded* `drain_completions` (where `CURRENT_DRIVER` is `None`). So `Drop`
/// uses [`try_with_state`]: when the driver is reachable it replenishes the bid
/// and clears the driver's pin slot; when it is not, it no-ops and
/// `close_connection` reclaims the pinned bid instead. The driver pin slot
/// (`segment_pinned[conn]`) is the single-release discriminant — whoever `take()`s
/// it first replenishes, so the bid is returned exactly once across the
/// drop/close race and any slot-reuse.
#[cfg(has_io_uring)]
pub struct RecvSegment<'a> {
    conn_index: u32,
    generation: u32,
    /// Where this segment's bytes live: a pinned provided buffer (zero-copy,
    /// released via the driver pin slot on drop/`into_owned`) or an owned copy
    /// (force-copied at delivery under ring pressure; its bid was already
    /// replenished, so drop/`into_owned` touch no ring state).
    backing: SegBacking,
    _borrow: PhantomData<&'a mut ()>,
    _not_send: PhantomData<*const ()>,
}

/// Backing store for a [`RecvSegment`] — one of the two segmented-recv
/// deliveries (see `docs/segmented-recv-design.md`, "Backpressure and ring
/// safety").
#[cfg(has_io_uring)]
enum SegBacking {
    /// A provided buffer pinned in the ring. The bid is released exactly once via
    /// the driver pin slot (`segment_pinned[conn]`) on drop or `into_owned`.
    Pinned { bid: u16, off: u32, len: u32 },
    /// An owned copy of the received bytes. The bid was replenished at delivery,
    /// so this segment pins nothing: drop is a no-op and `into_owned` just hands
    /// back the bytes.
    Owned(Bytes),
}

#[cfg(has_io_uring)]
impl RecvSegment<'_> {
    /// The number of received bytes in this segment.
    pub fn len(&self) -> usize {
        match &self.backing {
            SegBacking::Pinned { len, .. } => *len as usize,
            SegBacking::Owned(b) => b.len(),
        }
    }

    /// Whether this segment carries no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copy this segment's bytes into an owned heap [`Bytes`] and release the
    /// pinned provided buffer (Mode C — "Own"; see `docs/segmented-recv-design.md`).
    /// Consumes the segment.
    ///
    /// This is a **real copy**, not an alias: the returned `Bytes` owns freshly
    /// allocated heap memory with no release-on-drop tie to the ring, so it is
    /// freely `Send`, `Clone`, and holdable past the connection's lifetime —
    /// unlike the borrowed [`RecvSegment`], which cannot escape the runtime. This
    /// is the same single copy the accumulator path pays today. (Deliberately
    /// *not* `Bytes::from_owner` over the provided buffer — that would keep the
    /// bid pinned, which Mode C exists to avoid.)
    ///
    /// # Release-exactly-once
    ///
    /// The copy is taken first (INC ordering: copy-before-replenish, no await
    /// between), then this method `take()`s the driver pin slot
    /// (`segment_pinned[conn]`, the single-release discriminant — the **same**
    /// guard as [`RecvSegment::drop`]) and queues the bid for replenish. Because
    /// `self` is consumed by value, its `Drop` runs at the end of this method and
    /// finds the pin slot already `None` (or holding a different bid, after a
    /// slot reuse) → it no-ops. So the bid is replenished **exactly once**: here.
    // Consumes `self` by design: the conversion *is* the release (it `take()`s the
    // pin slot), so a `&self` signature would be unsound — the borrow would leave
    // the bid pinned and let `Drop` also try to release it. Named `into_owned`
    // (not `to_owned`) because it consumes: `into_*` is the by-value convention.
    pub fn into_owned(self) -> Bytes {
        match &self.backing {
            SegBacking::Owned(b) => {
                // Already owned (force-copied at delivery): no pin to release. The
                // clone is an O(1) refcount bump; `self`'s `Drop` no-ops for Owned.
                b.clone()
            }
            SegBacking::Pinned { bid, off, len } => {
                let (bid, off, len) = (*bid, *off, *len);
                // Copy before replenish (INC template), no await between.
                let owned = with_state(|driver, _executor| {
                    let ptr = driver.provided_bufs.data_ptr(bid, off);
                    // SAFETY: the bid is pinned (not yet replenished) and `len`
                    // bytes were received into it at `off`.
                    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
                    Bytes::copy_from_slice(slice)
                });
                // Release the pin — identical guard to `Drop`; `take()` is the
                // single release. Uses `try_with_state` for the same reason `Drop`
                // does (this normally runs in-poll, but staying symmetric keeps it
                // panic-free).
                try_with_state(|driver, _executor| {
                    if driver.connections.generation(self.conn_index) != self.generation {
                        return;
                    }
                    match driver.segment_pinned[self.conn_index as usize] {
                        Some(crate::backend::HeldRecvBuf::Pinned {
                            bid: pinned_bid, ..
                        }) if pinned_bid == bid => {
                            driver.segment_pinned[self.conn_index as usize] = None;
                            driver.pending_replenish.push(bid);
                        }
                        _ => {}
                    }
                });
                owned
            }
        }
        // `self` drops here: for Pinned the pin slot is now `None` (or holds a
        // different bid after a slot reuse) → `Drop` no-ops; for Owned, `Drop` is
        // inherently a no-op. Exactly one replenish either way.
    }
}

#[cfg(has_io_uring)]
impl Deref for RecvSegment<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match &self.backing {
            // Owned bytes (force-copied at delivery) — borrow them directly.
            SegBacking::Owned(b) => &b[..],
            SegBacking::Pinned { bid, off, len } => {
                // The buffer is pinned in the ring (bid not replenished) for this
                // segment's lifetime, so the pointer is valid and `len <= buf cap`.
                let ptr = with_state(|driver, _executor| driver.provided_bufs.data_ptr(*bid, *off));
                // SAFETY: `ptr` points into the provided-buffer backing for `bid`,
                // which stays pinned until this segment drops; `len` bytes were
                // received into it. The returned slice borrows `self`, so it
                // cannot outlive the pin.
                unsafe { std::slice::from_raw_parts(ptr, *len as usize) }
            }
        }
    }
}

#[cfg(has_io_uring)]
impl Drop for RecvSegment<'_> {
    fn drop(&mut self) {
        // Owned segments (force-copied at delivery) pin nothing: the bid was
        // already replenished, so there is nothing to release — just drop the
        // owned `Bytes`. Only the pinned backing touches the ring.
        let bid = match &self.backing {
            SegBacking::Pinned { bid, .. } => *bid,
            SegBacking::Owned(_) => return,
        };
        // May run inside a poll (driver reachable) or in the unguarded
        // `drain_completions` while a parked task is torn down (driver == None).
        try_with_state(|driver, _executor| {
            // Slot recycled to a new connection: the bid was already replenished
            // by the old occupant's `close_connection`. Do nothing.
            if driver.connections.generation(self.conn_index) != self.generation {
                return;
            }
            // Reclaim only if the pin slot still holds *this* segment's buffer.
            // If `close_connection` already drained it (None), or it somehow holds
            // a different bid, do not replenish — that avoids the drop/close
            // double-replenish. `take()` makes this the single release.
            match driver.segment_pinned[self.conn_index as usize] {
                Some(crate::backend::HeldRecvBuf::Pinned {
                    bid: pinned_bid, ..
                }) if pinned_bid == bid => {
                    driver.segment_pinned[self.conn_index as usize] = None;
                    driver.pending_replenish.push(bid);
                }
                _ => {}
            }
        });
        // When `try_with_state` returned `None` (unguarded drop), the bid stays
        // pinned and `close_connection` replenishes it — still exactly once.
    }
}

// ── Segmented recv (Mode C — Own, copy-at-delivery) ──────────────────

/// Future returned by [`Connection::recv_owned_segment`]. Copies each arriving
/// provided buffer into an owned [`Bytes`] and replenishes its bid at delivery,
/// so it never pins the ring (the ring-safe owned-delivery path).
#[cfg(has_io_uring)]
pub struct RecvOwnedSegment {
    conn_index: u32,
    generation: u32,
}

#[cfg(has_io_uring)]
impl Future for RecvOwnedSegment {
    type Output = io::Result<Option<Bytes>>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|driver, executor| {
            let conn = self.conn_index;
            let idx = conn as usize;

            // Stale handle (slot closed-then-reused): surface EOF rather than
            // reading the new occupant's held buffers.
            if driver.connections.generation(conn) != self.generation {
                return Poll::Ready(Ok(None));
            }

            // Before anything else: bytes stranded in the accumulator are
            // invisible to this reader. Adopt them so this poll can return them.
            adopt_stranded_accumulator(driver, conn);

            // A held buffer is available: COPY it into an owned `Bytes` and
            // replenish the bid immediately. The copy is the release — this path
            // never touches `segment_pinned`, so it can never deplete the ring by
            // holding. (INC ordering: copy-before-replenish, no await between.)
            if let Some(held) = driver.segment_hold[idx].pop_front() {
                match held {
                    crate::backend::HeldRecvBuf::Pinned { bid, off, len } => {
                        let ptr = driver.provided_bufs.data_ptr(bid, off);
                        // SAFETY: `bid` is held (not yet replenished), and `len`
                        // bytes were received into it at `off`. The slice is
                        // consumed by the copy below before `driver` is mutated.
                        let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
                        let owned = Bytes::copy_from_slice(slice);
                        driver.pending_replenish.push(bid);
                        return Poll::Ready(Ok(Some(owned)));
                    }
                    crate::backend::HeldRecvBuf::Owned(bytes) => {
                        // Already owned (force-copied at delivery): its bid was
                        // replenished at delivery, so just hand back the bytes.
                        return Poll::Ready(Ok(Some(bytes)));
                    }
                }
            }

            // Hold empty. If the recv side is closed (peer FIN), this is EOF.
            let is_closed = driver
                .connections
                .get(conn)
                .map(|c| c.recv_finished())
                .unwrap_or(true);
            if is_closed {
                return Poll::Ready(Ok(None));
            }

            // Open and nothing held yet — park as a recv waiter, resumed by
            // `handle_recv_multi`'s `wake_recv` on the next arrival.
            executor.owner_task[idx] = Some(CURRENT_TASK_ID.with(|c| c.get()));
            executor.recv_waiters[idx] = true;
            Poll::Pending
        })
    }
}

// ── Segmented recv (Mode A — Forward to an fd) ───────────────────────

/// A non-raw sink descriptor for [`ConnCtx::forward_to`] (Mode A — "Forward";
/// see `docs/segmented-recv-design.md`).
///
/// Wraps a [`BorrowedFd`] so the descriptor is guaranteed open for the forward's
/// lifetime — deliberately **not** a bare [`RawFd`] the caller could close
/// mid-forward, which would be a use-after-close (an in-flight write landing on a
/// recycled fd; generation guards ring *slots*, not caller fds). The
/// [`forward_to`](ConnCtx::forward_to) future borrows the `SinkFd`, so the borrow
/// checker keeps the fd alive until the forward resolves.
///
/// Two sink kinds are supported for **zero userspace copy**:
/// - [`socket`](Self::socket): a stream socket (zero-copy proxy).
/// - [`file`](Self::file): a **buffered** regular file (`pwrite` at offset).
///
/// `O_DIRECT` / NVMe sinks are **not** supported for zero-copy (provided buffers
/// are unaligned) and are rejected by [`file`](Self::file).
#[cfg(has_io_uring)]
#[derive(Debug)]
pub struct SinkFd<'a> {
    fd: RawFd,
    /// Seekable buffered file (`pwrite` at an advancing offset) vs. stream socket
    /// (`send` with `MSG_WAITALL`, no offset).
    is_file: bool,
    /// Ties this handle to the borrowed descriptor's lifetime.
    _borrow: PhantomData<BorrowedFd<'a>>,
}

#[cfg(has_io_uring)]
impl<'a> SinkFd<'a> {
    /// A **socket** sink (zero-copy proxy). Forwarded bytes are written with
    /// `send`(`MSG_WAITALL`), so the kernel retries short stream sends in place.
    pub fn socket(fd: BorrowedFd<'a>) -> Self {
        SinkFd {
            fd: fd.as_raw_fd(),
            is_file: false,
            _borrow: PhantomData,
        }
    }

    /// A **buffered file** sink. Forwarded bytes are written with `pwrite` at an
    /// offset that advances from 0 as bytes are forwarded; short writes resubmit
    /// the remainder at the advanced offset.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the descriptor was opened with
    /// `O_DIRECT`: zero-copy forwarding requires buffered I/O because provided
    /// recv buffers are mid-ring, unaligned, and unregistered — `O_DIRECT`'s
    /// alignment contract cannot be met without an intermediate aligned copy,
    /// which defeats the purpose. Use a buffered file (or copy the bytes out via
    /// Mode C).
    pub fn file(fd: BorrowedFd<'a>) -> io::Result<Self> {
        let raw = fd.as_raw_fd();
        // Reject O_DIRECT: unaligned provided buffers cannot be its source.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_DIRECT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "O_DIRECT sink is not supported for zero-copy forward (provided \
                 buffers are unaligned); use a buffered file",
            ));
        }
        Ok(SinkFd {
            fd: raw,
            is_file: true,
            _borrow: PhantomData,
        })
    }
}

/// Future returned by the mio [`ConnCtx::forward_to_conn`]. Parks on the
/// source's recv waiter slot; the event loop resolves it by writing into
/// `Driver::forward_done` and calling `wake_recv`. Borrows the sink `ConnCtx`
/// (`'a`) so it cannot be dropped mid-forward.
#[cfg(not(has_io_uring))]
pub struct ForwardToConnFuture<'a> {
    conn_index: u32,
    generation: u32,
    /// Set when the forward could not be installed at all (stale handle, or a
    /// forward already running); reported on the first poll.
    refused: Option<i32>,
    _borrow: PhantomData<&'a ()>,
}

#[cfg(not(has_io_uring))]
impl Future for ForwardToConnFuture<'_> {
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
            executor.owner_task[idx] = Some(CURRENT_TASK_ID.with(|c| c.get()));
            executor.recv_waiters[idx] = true;
            Poll::Pending
        })
    }
}

#[cfg(not(has_io_uring))]
impl Drop for ForwardToConnFuture<'_> {
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

/// Future returned by [`ConnCtx::forward_to`]. Drives the recv/write interleave
/// that forwards `len` received bytes to the sink, one serialized write at a
/// time. Borrows the [`SinkFd`] (`'a`) so the sink descriptor stays open for the
/// whole forward.
#[cfg(has_io_uring)]
pub struct ForwardToFuture<'a> {
    conn_index: u32,
    generation: u32,
    /// Which forward on this connection this future owns; see
    /// [`ForwardProgress::epoch`]. Drop cancels only its own. Meaningless
    /// when `refused` is set, which is why Drop checks that first.
    epoch: u32,
    /// Set when the forward could not be installed at all — a forward already
    /// running (`EBUSY`), a stale source or sink slot (`EPIPE`), or a TLS sink
    /// (`EPROTOTYPE`). Reported on the first poll; nothing was mutated.
    refused: Option<i32>,
    /// Ties the future to whatever the caller borrowed — a `SinkFd`, or the
    /// sink `ConnCtx` — so the sink cannot be dropped mid-forward.
    _borrow: PhantomData<&'a ()>,
}

#[cfg(has_io_uring)]
impl Drop for ForwardToFuture<'_> {
    /// Cancel a forward that is dropped before it resolves.
    ///
    /// Gathering moved submission out of `poll` and into
    /// `handle_forward_write`, so the driver now advances a forward on its own
    /// once armed. Before that, dropping this future stopped the relay for
    /// free: nothing popped the hold unless someone polled. Now a `select!`
    /// that loses, or a `timeout` that fires, would otherwise leave bytes
    /// streaming to a sink with nobody waiting on the result — and leave the
    /// connection in the segmented recv domain, so the caller's next
    /// `with_data` would park while its bytes went to the sink.
    ///
    /// The in-flight write is deliberately *not* touched: its backing buffers
    /// are being read by the kernel, and returning those bids to the provided
    /// ring here would let an arriving packet overwrite a `sendmsg` in
    /// progress. Its CQE releases them exactly once, and with the progress
    /// cleared `advance_forward` submits no successor — so what is already
    /// queued completes, and no further bytes are taken from the source. That
    /// is the same contract the mio sibling documents.
    ///
    /// Held-but-not-yet-written bytes go to the accumulator rather than being
    /// dropped, via the same `settle_forward_end` the normal end of a forward
    /// uses — so a cancel loses no data the peer already sent.
    fn drop(&mut self) {
        // A refused forward installed nothing — in particular it may have been
        // refused *because* another forward is running, which this must not
        // cancel.
        if self.refused.is_some() {
            return;
        }
        let _ = try_with_state(|driver, _executor| {
            let idx = self.conn_index as usize;
            if driver.connections.generation(self.conn_index) != self.generation {
                return;
            }
            // Only cancel *this* forward. A future dropped after its own
            // forward resolved must not settle a later one that armed on the
            // same connection in between.
            let mine = driver.forward_progress[idx].is_some_and(|p| p.epoch == self.epoch);
            if !mine {
                return;
            }
            driver.forward_progress[idx] = None;
            driver.forward_done[idx] = None;
            if !driver.settle_forward_end(self.conn_index) {
                // Accumulator overflow settling the tail: the bytes have
                // nowhere to go, so the connection cannot continue.
                driver.close_connection(self.conn_index);
            }
        });
    }
}

#[cfg(has_io_uring)]
impl Future for ForwardToFuture<'_> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        if let Some(errno) = me.refused {
            return Poll::Ready(Err(io::Error::from_raw_os_error(errno)));
        }
        with_state(|driver, executor| {
            let conn = me.conn_index;
            let idx = conn as usize;

            // The terminal result wins over a stale-handle check: a forward
            // that ended as its connection closed still owes its caller the
            // count.
            if let Some(res) = driver.forward_done[idx].take() {
                driver.forward_progress[idx] = None;
                return Poll::Ready(match res {
                    Ok(n) => Ok(n as usize),
                    Err(errno) => Err(io::Error::from_raw_os_error(errno)),
                });
            }

            // Stale handle (slot closed/reused): the driver already released any
            // held or in-flight backing on close.
            if driver.connections.generation(conn) != me.generation {
                let forwarded = driver.forward_progress[idx]
                    .take()
                    .map_or(0, |p| p.forwarded);
                return Poll::Ready(Ok(forwarded as usize));
            }

            // Drive it on every poll, not just the first. The completion
            // handlers submit each write themselves, so in the common path this
            // finds a write already in flight and simply parks — but *any* other
            // wake has to be able to finish the forward. A peer FIN is the case
            // that matters: `handle_recv_multi` notes EOF and wakes, and if this
            // only parked, a forward ending in a truncation would park forever.
            // (It did: 47 of 60 proxy runs hung before this line looked like
            // this.)
            if let Some(res) = driver.advance_forward(conn) {
                driver.forward_progress[idx] = None;
                return Poll::Ready(res.map(|n| n as usize));
            }

            executor.owner_task[idx] = Some(CURRENT_TASK_ID.with(|c| c.get()));
            executor.recv_waiters[idx] = true;
            Poll::Pending
        })
    }
}

// ── Segmented recv (Mode B — Borrow, B1 callback face) ───────────────

/// Bytes a [`with_segments`](ConnCtx::with_segments) callback consumed from the
/// **front** of the presented [`SegChain`].
///
/// This is deliberately *not* [`ParseResult`]: `with_segments` re-presents
/// carried-over bytes bounded by ring depth, so the only signal it needs is
/// "how many front bytes did you take". `SegConsumed(0)` is the "need a bigger
/// frame" case (the runtime gathers the chain to the accumulator and parks).
#[cfg(has_io_uring)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegConsumed(pub usize);

/// An ordered, borrowed view of a connection's buffered recv data, handed to a
/// [`with_segments`](ConnCtx::with_segments) callback.
///
/// The chain presents, **in order**, the accumulator remainder (if any) as the
/// leading segment followed by each held provided buffer in arrival order — so a
/// consumer walking [`iter`](Self::iter) never sees a later byte before an
/// earlier one. The slices borrow driver-internal memory for the callback's
/// duration only; they cannot escape (lifetime `'a`, like `with_data`).
#[cfg(has_io_uring)]
pub struct SegChain<'a> {
    /// Ordered borrowed segments: accumulator-first, then held buffers.
    segs: &'a [&'a [u8]],
}

#[cfg(has_io_uring)]
impl<'a> SegChain<'a> {
    /// Iterate the segments in order (accumulator remainder first, then held
    /// provided buffers in arrival order).
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.segs.iter().copied()
    }

    /// Total number of bytes across all segments.
    pub fn total_len(&self) -> usize {
        self.segs.iter().map(|s| s.len()).sum()
    }
}

/// By-value record of a held segment, captured during gather so the settle step
/// can run after the borrowed [`SegChain`] slices are released. `Pinned` carries
/// the bid+len so the remainder can be re-read from the (still-pinned) provided
/// buffer and the bid replenished; `Owned` carries the bytes themselves (an O(1)
/// refcount clone of the held copy), which keep the remainder alive after the
/// hold is cleared and need no replenish.
#[cfg(has_io_uring)]
enum SegSettle {
    Pinned { bid: u16, off: u32, len: usize },
    Owned(Bytes),
}

/// Future returned by [`Connection::with_segments`]. Resolves to the total bytes
/// the callback consumed this call (`Ok(0)` at EOF / on a stale handle).
#[cfg(has_io_uring)]
pub struct WithSegmentsFuture<F> {
    conn_index: u32,
    /// See `WithDataFuture` for the role of `generation`.
    generation: u32,
    f: Option<F>,
    /// Has this future put the connection into the segmented domain yet?
    ///
    /// The flip is deferred to the first poll so it happens behind the
    /// generation and claim checks; see [`ConnCtx::with_segments`] and #429.
    entered: bool,
}

#[cfg(has_io_uring)]
impl<F: FnMut(&SegChain<'_>) -> SegConsumed + Unpin> Future for WithSegmentsFuture<F> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|driver, executor| {
            // Stale future (slot closed-then-reused): surface EOF so the caller's
            // read loop terminates rather than reading the new occupant's data.
            if driver.connections.generation(self.conn_index) != self.generation {
                self.f.take();
                return Poll::Ready(Ok(0));
            }
            let before = arrival_mark(driver, self.conn_index);
            let poll = self.poll_current(driver, executor);
            if let Poll::Ready(ref result) = poll {
                let report = matches!(result, Ok(consumed) if *consumed > 0);
                arrival_settle(driver, self.conn_index, before, report);
            }
            poll
        })
    }
}

#[cfg(has_io_uring)]
impl<F: FnMut(&SegChain<'_>) -> SegConsumed + Unpin> WithSegmentsFuture<F> {
    /// `poll` for a future whose generation matches the connection's.
    fn poll_current(
        &mut self,
        driver: &mut Driver,
        executor: &mut Executor,
    ) -> Poll<io::Result<usize>> {
        let conn = self.conn_index;
        let idx = conn as usize;

        if !self.entered {
            // A live `SegmentReader` owns the hold; handing the same
            // buffers to a second consumer would double-deliver them.
            if driver.segment_reader_live[idx] {
                self.f.take();
                return Poll::Ready(Err(io::Error::from_raw_os_error(libc::EBUSY)));
            }
            driver.recv_domain[idx] = crate::recv::domain::RecvDomain::Segmented;
            self.entered = true;
        }

        // Flush a leftover single-buffer zero-copy recv (from a pre-`segments`
        // `with_data` cycle on this slot) into the accumulator so it is
        // presented accumulator-first, in order, ahead of any held buffers.
        if let Some(pending) = driver.pending_recv_bufs[idx].take() {
            let pending_data =
                unsafe { std::slice::from_raw_parts(pending.ptr, pending.len as usize) };
            // Intermediate buffer shuffle: on breach the authoritative cap
            // check below (during settle) closes the connection.
            let _ = driver.accumulators.append(conn, pending_data);
            driver.pending_replenish.push(pending.bid);
        }

        // Nothing to present yet?
        let acc_empty = driver.accumulators.is_empty(conn);
        let hold_empty = driver.segment_hold[idx].is_empty();
        if acc_empty && hold_empty {
            let is_closed = driver
                .connections
                .get(conn)
                .map(|c| c.recv_finished())
                .unwrap_or(true);
            if is_closed {
                self.f.take();
                return Poll::Ready(Ok(0));
            }
            // Open + nothing buffered → park; `handle_recv_multi` holds a
            // buffer and calls `wake_recv` on the next arrival.
            executor.owner_task[idx] = Some(CURRENT_TASK_ID.with(|c| c.get()));
            executor.recv_waiters[idx] = true;
            return Poll::Pending;
        }

        // Gather the ordered borrowed view: accumulator remainder first, then
        // each held provided buffer. `held_meta` records (bid, len) by value so
        // the settle below can run after the borrows are released.
        let hold_len = driver.segment_hold[idx].len();
        let mut slices: Vec<&[u8]> = Vec::with_capacity(1 + hold_len);
        let mut held_meta: Vec<SegSettle> = Vec::with_capacity(hold_len);
        let acc = driver.accumulators.data(conn);
        let acc_len = acc.len();
        if !acc.is_empty() {
            slices.push(acc);
        }
        for held in &driver.segment_hold[idx] {
            match held {
                crate::backend::HeldRecvBuf::Pinned { bid, off, len } => {
                    // `data_ptr` returns a raw pointer (no borrow tie), so the
                    // held slice does not alias the `provided_bufs` field borrow.
                    let ptr = driver.provided_bufs.data_ptr(*bid, *off);
                    let s = unsafe { std::slice::from_raw_parts(ptr, *len as usize) };
                    slices.push(s);
                    held_meta.push(SegSettle::Pinned {
                        bid: *bid,
                        off: *off,
                        len: *len as usize,
                    });
                }
                crate::backend::HeldRecvBuf::Owned(b) => {
                    // Borrow the owned bytes for the chain; keep an O(1)
                    // refcount clone in `held_meta` so the remainder survives
                    // the `segment_hold.clear()` below (which drops the
                    // original).
                    slices.push(&b[..]);
                    held_meta.push(SegSettle::Owned(b.clone()));
                }
            }
        }

        // Present to the callback; clamp its answer to what we actually showed.
        let consumed = {
            let chain = SegChain { segs: &slices };
            let total = chain.total_len();
            #[cfg(has_io_uring)]
            let cb_conn = self.conn_index;
            let f = self
                .f
                .as_mut()
                .expect("WithSegmentsFuture polled after Ready");
            let SegConsumed(c) = {
                #[cfg(has_io_uring)]
                let _cb = ReaderCallback::enter(cb_conn);
                f(&chain)
            };
            c.min(total)
        };
        // Release the accumulator/provided-buffer borrows before mutating.
        drop(slices);

        // ── Settle ──────────────────────────────────────────────────────
        // All held buffers are being resolved this call, so drain the hold up
        // front; each bid is either replenished (consumed) or gathered +
        // replenished (remainder). Net: hold empties, un-consumed bytes live
        // contiguously at the accumulator front, in order.
        driver.segment_hold[idx].clear();

        let mut rem_n = consumed;
        // (1) Consume from the accumulator front (O(1) advance). If only part
        // of the accumulator was consumed, `rem_n` is now 0 and every held
        // buffer is untouched → gathered behind the accumulator remainder.
        let acc_consumed = rem_n.min(acc_len);
        driver.accumulators.consume(conn, acc_consumed);
        rem_n -= acc_consumed;

        // (2) Walk the held buffers in order.
        let mut overflowed = false;
        for meta in held_meta {
            match meta {
                SegSettle::Pinned { bid, off, len } => {
                    if rem_n >= len {
                        // Wholly consumed by the callback — just replenish.
                        rem_n -= len;
                        driver.pending_replenish.push(bid);
                    } else {
                        // Partially consumed (or untouched, when rem_n == 0):
                        // copy the unconsumed remainder [rem_n..len] into the
                        // accumulator, in order, then replenish. Push the bid
                        // even on breach so it is never leaked.
                        if !overflowed {
                            let ptr = driver.provided_bufs.data_ptr(bid, off);
                            let remainder =
                                unsafe { std::slice::from_raw_parts(ptr.add(rem_n), len - rem_n) };
                            if !driver.accumulators.append(conn, remainder) {
                                overflowed = true;
                            }
                        }
                        rem_n = 0;
                        driver.pending_replenish.push(bid);
                    }
                }
                SegSettle::Owned(bytes) => {
                    let len = bytes.len();
                    if rem_n >= len {
                        // Wholly consumed; the bid was replenished at delivery,
                        // so there is nothing to return to the ring here.
                        rem_n -= len;
                    } else {
                        // Copy the unconsumed remainder into the accumulator,
                        // in order. No replenish (owned copy holds no bid).
                        if !overflowed && !driver.accumulators.append(conn, &bytes[rem_n..]) {
                            overflowed = true;
                        }
                        rem_n = 0;
                    }
                }
            }
        }

        if overflowed {
            // The under-drain gather streamed past `recv_accumulator_max`
            // (a misbehaving whole-frame consumer). Close rather than OOM;
            // held bids were already queued for replenish above.
            self.f.take();
            driver.close_connection(conn);
            return Poll::Ready(Ok(0));
        }

        if consumed > 0 {
            // Progress made — return it. Any carried-over remainder now sits at
            // the accumulator front and is re-presented next call.
            self.f.take();
            return Poll::Ready(Ok(consumed));
        }

        // consumed == 0 (need a bigger frame): everything is gathered to the
        // accumulator. Park for more data (bounded by recv_accumulator_max),
        // or surface EOF if the recv side already closed. This mirrors
        // `with_data`'s NeedMore idiom — never a busy loop.
        let is_closed = driver
            .connections
            .get(conn)
            .map(|c| c.recv_finished())
            .unwrap_or(true);
        if is_closed {
            self.f.take();
            return Poll::Ready(Ok(0));
        }
        executor.owner_task[idx] = Some(CURRENT_TASK_ID.with(|c| c.get()));
        executor.recv_waiters[idx] = true;
        Poll::Pending
    }
}

// ── Receive view threshold ───────────────────────────────────────────

/// The calling worker's receive view threshold
/// ([`ConfigBuilder::recv_zc_threshold`](crate::ConfigBuilder::recv_zc_threshold)),
/// or the default, 4096, when called anywhere other than a worker's tasks
/// and its `on_tick` and `on_notify` callbacks.
///
/// A client passes it to [`copy_small_view`] when it has no threshold of its
/// own.
pub fn recv_zc_threshold() -> u32 {
    try_with_state(|driver, _| driver.recv_zc_threshold)
        .unwrap_or(crate::config::DEFAULT_RECV_ZC_THRESHOLD)
}

/// Return an owned copy of `value` if it is a receive view shorter than
/// `threshold` bytes; otherwise return `value` unchanged.
///
/// On io_uring, [`Connection::with_bytes_segments`] presents held receive
/// buffers as views of the ring's memory, and a value sliced from one is a
/// view too. A view keeps its whole ring buffer from being reused until it
/// drops, whatever its length. Ring buffers are 16 KiB by default;
/// [`ConfigBuilder::recv_incremental`](crate::ConfigBuilder::recv_incremental)
/// and [`ConfigBuilder::recv_buffer`](crate::ConfigBuilder::recv_buffer)
/// give other sizes. A client that keeps parsed values calls this on each
/// one, so a small kept value holds a heap copy instead of a ring buffer.
/// When `value` is copied it is dropped here; the view's hold on its buffer
/// is released once no clone or slice of the view remains.
///
/// A view is recognised by its data pointer lying in the calling worker's
/// ring memory. On io_uring, called anywhere other than a worker's tasks and
/// its `on_tick` and `on_notify` callbacks, every `Bytes` is treated as a
/// view. A view made on one worker and passed
/// here on another is not recognised and is returned unchanged. On mio
/// nothing is a view, and a non-empty `value` is returned unchanged.
///
/// An empty `value` is returned as an empty `Bytes` that holds nothing. A
/// `threshold` of 0 never copies. Copies count in
/// `metrics::recv_ring::THRESHOLD_COPIED` and `BYTES_COPIED`.
pub fn copy_small_view(value: Bytes, threshold: u32) -> Bytes {
    // An empty slice of a view can still hold the view's buffer.
    if value.is_empty() {
        return Bytes::new();
    }
    if value.len() >= threshold as usize || !is_recv_view(&value) {
        return value;
    }
    let copy = Bytes::copy_from_slice(&value);
    crate::metrics::RECV_RING.increment(crate::metrics::recv_ring::THRESHOLD_COPIED);
    #[cfg(test)]
    TEST_THRESHOLD_COPIED.with(|c| c.set(c.get() + 1));
    crate::accumulator::note_copied(copy.len());
    copy
}

#[cfg(test)]
thread_local! {
    /// This thread's `THRESHOLD_COPIED` total, for tests: the process-wide
    /// metric is also moved by concurrent tests in one process.
    pub(crate) static TEST_THRESHOLD_COPIED: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

/// Whether `value`'s data lies in the calling worker's TCP receive ring
/// memory; `true` where no worker's driver is current.
#[cfg(has_io_uring)]
fn is_recv_view(value: &Bytes) -> bool {
    try_with_state(|driver, _| {
        let memory = driver.provided_bufs.memory();
        let start = memory.as_ptr() as usize;
        let at = value.as_ptr() as usize;
        at >= start && at < start + memory.len()
    })
    .unwrap_or(true)
}

#[cfg(not(has_io_uring))]
fn is_recv_view(_value: &Bytes) -> bool {
    false
}

// ── WithBytesSegmentsFuture ──────────────────────────────────────────

/// Future returned by [`Connection::with_bytes_segments`]. Resolves to the
/// bytes the parser consumed, `Ok(0)` at end of stream, for a stale handle or
/// after a close, and `Err(EBUSY)` when another reader owns or used the
/// connection.
pub struct WithBytesSegmentsFuture<F> {
    conn_index: u32,
    /// See `WithDataFuture` for the role of `generation`.
    generation: u32,
    f: Option<F>,
    /// Whether a poll has run. On io_uring the first poll enters the
    /// segmented domain.
    entered: bool,
    /// The connection's `segment_epoch` at the end of the previous poll.
    #[cfg(has_io_uring)]
    epoch: u32,
    /// The connection's `recv_consumed` at the end of the previous poll.
    consumed: u64,
    /// After `NeedAtLeast(n)`, the buffered byte count at which the parser
    /// is called again: the bytes it was shown plus `n`.
    call_at: Option<usize>,
}

impl<F: FnMut(&[Bytes]) -> ParseResult + Unpin> Future for WithBytesSegmentsFuture<F> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|driver, executor| {
            // `get` is `None` once the slot is released, which is stale too.
            let current = driver
                .connections
                .get(self.conn_index)
                .is_some_and(|c| c.generation == self.generation);
            if !current {
                self.f.take();
                return Poll::Ready(Ok(0));
            }
            let before = arrival_mark(driver, self.conn_index);
            let poll = self.poll_current(driver, executor);
            if let Poll::Ready(ref result) = poll {
                let report = matches!(result, Ok(consumed) if *consumed > 0);
                arrival_settle(driver, self.conn_index, before, report);
            }
            poll
        })
    }
}

impl<F: FnMut(&[Bytes]) -> ParseResult + Unpin> WithBytesSegmentsFuture<F> {
    fn resolve(&mut self, result: io::Result<usize>) -> Poll<io::Result<usize>> {
        self.f.take();
        Poll::Ready(result)
    }

    fn busy(&mut self) -> Poll<io::Result<usize>> {
        self.resolve(Err(io::Error::from_raw_os_error(libc::EBUSY)))
    }

    /// Record the connection's state for the next poll's checks and wait
    /// for the next receive.
    fn park(&mut self, driver: &Driver, executor: &mut Executor) -> Poll<io::Result<usize>> {
        let idx = self.conn_index as usize;
        #[cfg(has_io_uring)]
        {
            self.epoch = driver.segment_epoch[idx];
        }
        self.consumed = driver.recv_consumed(self.conn_index);
        executor.owner_task[idx] = Some(CURRENT_TASK_ID.with(|c| c.get()));
        executor.recv_waiters[idx] = true;
        Poll::Pending
    }

    /// `poll` for a future whose generation matches the connection's.
    #[cfg(has_io_uring)]
    fn poll_current(
        &mut self,
        driver: &mut Driver,
        executor: &mut Executor,
    ) -> Poll<io::Result<usize>> {
        let conn = self.conn_index;
        let idx = conn as usize;

        if !self.entered {
            // On a plaintext recv-forward connection in the default domain,
            // received bytes go to `recv_hold`, the hold `forward_held` sends
            // from, which this reader does not read; entering would present
            // later bytes ahead of them.
            if driver.recv_forward[idx] {
                return self.busy();
            }
            match enter_segmented(
                driver,
                conn,
                self.generation,
                false,
                SegmentedEntry::ViaHalf,
            ) {
                Ok(()) => self.entered = true,
                Err(e) if e.raw_os_error() == Some(libc::EPIPE) => return self.resolve(Ok(0)),
                Err(e) => return self.resolve(Err(e)),
            }
        } else if driver.forward_progress[idx].is_some()
            || driver.segment_reader_live[idx]
            || driver.segment_epoch[idx] != self.epoch
            || driver.recv_consumed(conn) != self.consumed
        {
            // A forward or a `SegmentReader` owns the hold, or another reader
            // consumed bytes or returned the connection to the default domain
            // since the previous poll.
            return self.busy();
        }

        let finished = |driver: &Driver| {
            driver
                .connections
                .get(conn)
                .is_none_or(|c| c.recv_finished())
        };
        let acc_len = driver.accumulators.len(conn);
        let total = acc_len
            + driver.segment_hold[idx]
                .iter()
                .map(crate::backend::HeldRecvBuf::len)
                .sum::<usize>();
        if total == 0 {
            if finished(driver) {
                return self.resolve(Ok(0));
            }
            return self.park(driver, executor);
        }
        // The skip does not apply at the hold cap: there a plaintext
        // connection's receive is throttled, so no more bytes arrive until the
        // hold drains, and a TLS connection's later chunks would only grow
        // the hold.
        if let Some(call_at) = self.call_at
            && total < call_at
            && !finished(driver)
            && !driver.segment_at_hold_cap(conn)
        {
            return self.park(driver, executor);
        }

        // The accumulator holds bytes older than anything held: those the
        // hold-cap copy moved there.
        let frozen = (acc_len > 0).then(|| driver.accumulators.take_frozen(conn));
        let mut pieces: Vec<Bytes> = Vec::with_capacity(1 + driver.segment_hold[idx].len());
        if let Some(frozen) = &frozen {
            pieces.push(frozen.clone());
        }
        for i in 0..driver.segment_hold[idx].len() {
            let piece = match &driver.segment_hold[idx][i] {
                crate::backend::HeldRecvBuf::Owned(b) => Ok(b.clone()),
                crate::backend::HeldRecvBuf::Pinned { bid, off, len } => Err((*bid, *off, *len)),
            };
            let piece = match piece {
                Ok(b) => b,
                Err((_, _, 0)) => continue,
                Err((bid, off, len)) => driver.recv_view(bid, off, len),
            };
            if !piece.is_empty() {
                pieces.push(piece);
            }
        }

        let result = {
            let f = self
                .f
                .as_mut()
                .expect("WithBytesSegmentsFuture polled after Ready");
            let _cb = ReaderCallback::enter(conn);
            f(&pieces)
        };
        // Drop the presented clones before the put-back, so the accumulator's
        // remainder is the only reference to its allocation when nothing kept
        // a slice of it.
        drop(pieces);

        if let ParseResult::Consumed(k) = result
            && k > 0
        {
            let k = k.min(total);
            let mut rem = k;
            if let Some(frozen) = frozen {
                let from_acc = rem.min(frozen.len());
                if from_acc < frozen.len() {
                    driver.accumulators.put_back(conn, frozen.slice(from_acc..));
                }
                rem -= from_acc;
            }
            consume_hold(driver, idx, rem);
            return self.resolve(Ok(k));
        }

        if let Some(frozen) = frozen {
            driver.accumulators.put_back(conn, frozen);
        }
        let need = match result {
            ParseResult::NeedAtLeast(n) => n,
            _ => 0,
        };
        self.call_at = match result {
            ParseResult::NeedAtLeast(n) => Some(total.saturating_add(n)),
            _ => None,
        };
        // At end of stream no more bytes can complete the message, so the
        // hold is left for teardown rather than copied.
        if finished(driver) {
            return self.resolve(Ok(0));
        }
        if driver.segment_at_hold_cap(conn)
            && !driver.segment_hold[idx].is_empty()
            && !copy_hold_to_accumulator(driver, conn, need)
        {
            driver.close_connection(conn);
            return self.resolve(Ok(0));
        }
        self.park(driver, executor)
    }

    /// `poll` for a future whose generation matches the connection's. Mio
    /// has no segmented domain; the parser is shown the accumulator as one
    /// piece.
    #[cfg(not(has_io_uring))]
    fn poll_current(
        &mut self,
        driver: &mut Driver,
        executor: &mut Executor,
    ) -> Poll<io::Result<usize>> {
        let conn = self.conn_index;
        let idx = conn as usize;
        if driver.forward_conn[idx].is_some()
            || (self.entered && driver.recv_consumed(conn) != self.consumed)
        {
            return self.busy();
        }
        self.entered = true;

        let finished = driver
            .connections
            .get(conn)
            .is_none_or(|c| c.recv_finished());
        let total = driver.accumulators.len(conn);
        if total == 0 {
            if finished {
                return self.resolve(Ok(0));
            }
            return self.park(driver, executor);
        }
        if let Some(call_at) = self.call_at
            && total < call_at
            && !finished
        {
            return self.park(driver, executor);
        }

        let frozen = driver.accumulators.take_frozen(conn);
        let pieces = [frozen.clone()];
        let result = {
            let f = self
                .f
                .as_mut()
                .expect("WithBytesSegmentsFuture polled after Ready");
            f(&pieces)
        };
        drop(pieces);

        if let ParseResult::Consumed(k) = result
            && k > 0
        {
            let k = k.min(total);
            if k < total {
                driver.accumulators.put_back(conn, frozen.slice(k..));
            }
            return self.resolve(Ok(k));
        }
        driver.accumulators.put_back(conn, frozen);
        self.call_at = match result {
            ParseResult::NeedAtLeast(n) => {
                driver.accumulators.reserve(conn, n);
                Some(total.saturating_add(n))
            }
            _ => None,
        };
        if finished {
            return self.resolve(Ok(0));
        }
        self.park(driver, executor)
    }
}

/// Remove the first `n` bytes of the connection's `segment_hold`: pop each
/// entry wholly inside them, queueing the release of its buffer hold, and
/// advance an entry partly inside them. Nothing is copied.
#[cfg(has_io_uring)]
fn consume_hold(driver: &mut Driver, idx: usize, mut n: usize) {
    while let Some(front) = driver.segment_hold[idx].front_mut() {
        let len = front.len();
        if len <= n {
            if let Some(crate::backend::HeldRecvBuf::Pinned { bid, .. }) =
                driver.segment_hold[idx].pop_front()
            {
                driver.pending_replenish.push(bid);
            }
            n -= len;
            continue;
        }
        if n > 0 {
            match front {
                crate::backend::HeldRecvBuf::Pinned { off, len, .. } => {
                    *off += n as u32;
                    *len -= n as u32;
                }
                crate::backend::HeldRecvBuf::Owned(b) => {
                    use bytes::Buf;
                    b.advance(n);
                }
            }
        }
        break;
    }
}

/// Copy every `segment_hold` entry into the accumulator, behind what it holds,
/// and queue the release of each entry's buffer hold. Reserves room for the
/// held bytes plus `need` first, so the accumulator grows once. Returns
/// `false` if the accumulator bound (`recv_accumulator_max`) was reached; the
/// caller closes the connection. Every buffer hold is released either way.
#[cfg(has_io_uring)]
fn copy_hold_to_accumulator(driver: &mut Driver, conn: u32, need: usize) -> bool {
    let idx = conn as usize;
    let held: usize = driver.segment_hold[idx]
        .iter()
        .map(crate::backend::HeldRecvBuf::len)
        .sum();
    driver.accumulators.reserve(conn, held.saturating_add(need));
    driver.accumulators.reclaim(conn);
    let mut ok = true;
    let mut copied = 0u64;
    while let Some(entry) = driver.segment_hold[idx].pop_front() {
        match entry {
            crate::backend::HeldRecvBuf::Pinned { bid, off, len } => {
                if ok {
                    // SAFETY: the entry holds buffer `bid`, which has `len`
                    // completed bytes at `off`; the slice is copied before the
                    // hold's release is queued.
                    let data = unsafe {
                        std::slice::from_raw_parts(
                            driver.provided_bufs.data_ptr(bid, off),
                            len as usize,
                        )
                    };
                    ok = driver.accumulators.append(conn, data);
                    copied += u64::from(ok);
                }
                driver.pending_replenish.push(bid);
            }
            crate::backend::HeldRecvBuf::Owned(bytes) => {
                if ok {
                    ok = driver.accumulators.append(conn, &bytes);
                    copied += u64::from(ok);
                }
            }
        }
    }
    crate::metrics::RECV_RING.add(crate::metrics::recv_ring::HOLD_CAP_COPIED, copied);
    #[cfg(test)]
    TEST_HOLD_CAP_COPIED.with(|c| c.set(c.get() + copied));
    ok
}

#[cfg(all(test, has_io_uring))]
thread_local! {
    /// This thread's `HOLD_CAP_COPIED` total, for tests: the process-wide
    /// metric is also moved by concurrent tests in one process.
    pub(crate) static TEST_HOLD_CAP_COPIED: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

// ── RecvReadyFuture ──────────────────────────────────────────────────

/// Future returned by [`Connection::recv_ready`]. Resolves when:
/// 1. The recv sink has received data (`pos > 0`), OR
/// 2. The driver holds received bytes for the connection: in the
///    accumulator, or on io_uring in a lent buffer, the segment hold or the
///    recv-forward hold, OR
/// 3. The connection has finished receiving.
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
            // Check recv sink.
            if let Some(sink) = &executor.recv_sinks[self.conn_index as usize]
                && sink.pos > 0
            {
                return Poll::Ready(());
            }

            // Bytes the driver holds for the connection: the accumulator, and
            // on io_uring a lent buffer, the segment hold and the
            // recv-forward hold.
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
            executor.owner_task[self.conn_index as usize] = Some(CURRENT_TASK_ID.with(|c| c.get()));
            executor.recv_waiters[self.conn_index as usize] = true;
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
/// - [`NotConnected`](io::ErrorKind::NotConnected) — the connection's close was
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

// ── DirectEchoFuture ─────────────────────────────────────────────────

/// Future that drives a connection in direct-echo mode (io_uring only).
///
/// On first poll it sets `ConnectionState::direct_echo = true` so that all
/// subsequent recv CQEs are echoed directly from `handle_recv_multi` without
/// waking this task — eliminating the `collect_wakeups` → `poll_ready_tasks`
/// roundtrip on the hot path. Any data buffered before the flag was set is
/// drained on the first poll. The future resolves once the peer has closed
/// its write side (or the read failed) and every byte received before that
/// has been submitted for echo.
///
/// Created by [`ConnCtx::run_direct_echo`].
#[cfg(has_io_uring)]
pub struct DirectEchoFuture {
    conn_index: u32,
    generation: u32,
    armed: bool,
}

#[cfg(has_io_uring)]
impl Future for DirectEchoFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        with_state(|driver, executor| {
            // Generation check: the slot was reused while we were parked.
            if driver.connections.generation(self.conn_index) != self.generation {
                return Poll::Ready(());
            }

            if !self.armed {
                // Arm direct-echo mode on the connection.
                if let Some(cs) = driver.connections.get_mut(self.conn_index) {
                    cs.direct_echo = true;
                }
                // Direct echo holds its buffers past the completion, so it
                // receives one buffer per arm (`Driver::recv_single`).
                driver.cancel_recv_for_single(self.conn_index);
                self.armed = true;

                // Drain any buffer that arrived before the flag was set.
                // After this, all new bufs are echoed directly by handle_recv_multi.
                if let Some(pending) = driver.pending_recv_bufs[self.conn_index as usize].take() {
                    // Staged like any other direct-echo arrival; the event
                    // loop's flush pass submits it before the next blocking
                    // wait, gathered with anything that landed alongside it.
                    driver.hold_direct_echo(self.conn_index, pending);
                }
            }

            // Done once the read side has finished and every byte received
            // before it has been submitted for echo; until the hold drains,
            // ending the task would close the connection and drop them
            // (#604).
            let done = driver
                .connections
                .get(self.conn_index)
                .map(|c| c.recv_finished())
                .unwrap_or(true)
                && driver.recv_hold[self.conn_index as usize].is_empty();

            if done {
                return Poll::Ready(());
            }

            // Park until done. handle_recv_multi calls wake_recv on EOF or
            // error, and flush_direct_echoes calls it when the hold of a
            // connection whose read side has finished drains.
            executor.owner_task[self.conn_index as usize] = Some(CURRENT_TASK_ID.with(|c| c.get()));
            executor.recv_waiters[self.conn_index as usize] = true;
            Poll::Pending
        })
    }
}

#[cfg(has_io_uring)]
impl Drop for DirectEchoFuture {
    fn drop(&mut self) {
        let opt_non_null = CURRENT_DRIVER.with(|c| c.get());
        if opt_non_null.is_none() {
            return;
        }
        let mut non_null = opt_non_null.unwrap();
        let state = unsafe { non_null.as_mut() };
        let driver = unsafe { &mut *state.driver.as_mut() };
        // Verify the slot still belongs to this connection before clearing
        // its waiter — a close/reuse cycle gives the slot a new generation.
        if driver.connections.generation(self.conn_index) != self.generation {
            return;
        }
        let executor = unsafe { &mut *state.executor.as_mut() };
        executor.recv_waiters[self.conn_index as usize] = false;
    }
}

// ── ConnectFuture ────────────────────────────────────────────────────

/// Future for an outbound connection, from awaiting [`TcpConnect`] or
/// [`UnixConnect`].
///
/// Submits the connect on its first poll, waits for the completion, and
/// resolves to an owned [`Connection`] with both halves claimed. A future that
/// is never polled allocates no socket and no connection slot.
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
            } => ctx.start_connect_tls(*addr, name),
            ConnectTarget::Tcp {
                addr,
                server_name: None,
            } => ctx.start_connect(*addr),
            ConnectTarget::Unix { path } => ctx.start_connect_unix(path.as_path()),
        }
        .map_err(io::Error::other::<crate::error::Error>)?;
        if let Some(timeout) = timeout {
            let ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
            ctx.arm_connect_timeout(token.index, ms);
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
