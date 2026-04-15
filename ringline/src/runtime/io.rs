use std::cell::{Cell, RefCell};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;

use crate::completion::{OpTag, UserData};
use crate::driver::Driver;
use crate::error::TimerExhausted;
use crate::handler::ConnToken;
use crate::runtime::task::TaskId;
use crate::runtime::waker::STANDALONE_BIT;
use crate::runtime::{CURRENT_TASK_ID, Executor, IoResult, TimerSlotPool};

/// Result of a parse closure passed to [`ConnCtx::with_data`] or [`ConnCtx::with_bytes`].
///
/// When the closure returns `NeedMore` or `Consumed(0)`, the future parks and
/// retries when more data arrives. `Consumed(0)` on a non-empty buffer is
/// treated identically to `NeedMore`. When the connection is closed (EOF),
/// the `with_data`/`with_bytes` future resolves with `0` regardless of the
/// parse result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseResult {
    /// The closure consumed `n` bytes from the buffer.
    ///
    /// `Consumed(0)` on non-empty data is treated as "need more data" — the
    /// future will park and retry when additional bytes arrive.
    Consumed(usize),
    /// The closure needs more data before it can make progress.
    NeedMore,
}

/// Raw pointer to the driver + executor state, set before polling each task.
///
/// # Safety
///
/// This is safe because:
/// 1. Single-threaded: each worker thread has its own driver/executor.
/// 2. Scoped: set before poll, cleared after poll. The pointer is only
///    dereferenced within a Future::poll call.
/// 3. The pointed-to data lives on the worker thread's stack (in AsyncEventLoop::run).
pub(crate) struct DriverState {
    pub(crate) driver: *mut Driver,
    pub(crate) executor: *mut Executor,
}

thread_local! {
    pub(crate) static CURRENT_DRIVER: Cell<*mut DriverState> =
        const { Cell::new(std::ptr::null_mut()) };
}

/// Set the thread-local driver pointer before polling a task.
pub(crate) fn set_driver_state(state: *mut DriverState) {
    CURRENT_DRIVER.with(|c| c.set(state));
}

/// Clear the thread-local driver pointer after polling a task.
pub(crate) fn clear_driver_state() {
    CURRENT_DRIVER.with(|c| c.set(std::ptr::null_mut()));
}

/// Access the thread-local driver state. Panics if called outside the executor.
pub(crate) fn with_state<R>(f: impl FnOnce(&mut Driver, &mut Executor) -> R) -> R {
    let ptr = CURRENT_DRIVER.with(|c| c.get());
    assert!(!ptr.is_null(), "called outside executor");
    let state = unsafe { &mut *ptr };
    let driver = unsafe { &mut *state.driver };
    let executor = unsafe { &mut *state.executor };
    f(driver, executor)
}

/// Access the thread-local driver state, returning `None` if called outside the executor.
pub(crate) fn try_with_state<R>(f: impl FnOnce(&mut Driver, &mut Executor) -> R) -> Option<R> {
    let ptr = CURRENT_DRIVER.with(|c| c.get());
    if ptr.is_null() {
        return None;
    }
    let state = unsafe { &mut *ptr };
    let driver = unsafe { &mut *state.driver };
    let executor = unsafe { &mut *state.executor };
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
    /// the slab slot. No-op if the task already completed.
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
    /// The task's return value, written by the wrapper when it completes.
    result: Option<T>,
    /// Raw task ID of the task awaiting this handle (includes `STANDALONE_BIT`
    /// for standalone tasks). Set by `JoinHandle::poll` when it returns `Pending`.
    waiter: Option<u32>,
    /// True if [`JoinHandle::abort`] was called.
    aborted: bool,
}

/// Handle to a spawned task's return value.
///
/// Obtained from [`spawn_with_handle()`]. Implements [`Future`] — awaiting it
/// yields the task's return value `T` once the task completes.
///
/// # Drop semantics
///
/// Dropping a `JoinHandle` without awaiting it **detaches** the task: the
/// task continues running but its result is discarded. This matches tokio's
/// semantics.
///
/// # Abort
///
/// [`abort()`](Self::abort) cancels the spawned task. A `JoinHandle` that has
/// been aborted will never resolve if polled.
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
    /// The future is dropped immediately and its slab slot is freed.
    /// After this call, awaiting the handle will hang forever — use
    /// [`select()`](crate::select) with a flag if you need to detect
    /// cancellation.
    pub fn abort(&self) {
        self.state.borrow_mut().aborted = true;
        self.task_id.cancel();
    }
}

impl<T: 'static> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<T> {
        let mut s = self.state.borrow_mut();
        if s.aborted {
            return Poll::Pending;
        }
        if let Some(value) = s.result.take() {
            return Poll::Ready(value);
        }
        // Register this task as the waiter so the child can wake us.
        s.waiter = Some(CURRENT_TASK_ID.with(|c| c.get()));
        Poll::Pending
    }
}

/// Spawn a standalone async task and return a handle to await its result.
///
/// Like [`spawn()`], the future runs on the current worker's single-threaded
/// executor. The returned [`JoinHandle<T>`] implements [`Future<Output = T>`] —
/// awaiting it yields the task's return value once it completes.
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
/// A panic in the spawned future unwinds the worker thread (same as [`spawn()`]).
pub fn spawn_with_handle<T: 'static>(
    future: impl Future<Output = T> + 'static,
) -> io::Result<JoinHandle<T>> {
    let state = Rc::new(RefCell::new(JoinState {
        result: None,
        waiter: None,
        aborted: false,
    }));
    let state_for_wrapper = Rc::clone(&state);

    let wrapper = async move {
        let value = future.await;
        let mut s = state_for_wrapper.borrow_mut();
        s.result = Some(value);
        let waiter = s.waiter.take();
        // Drop the borrow before calling with_state — defensive against
        // any re-entrant borrow in the wakeup path.
        drop(s);
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
/// keeping the io_uring event loop unblocked. Returns a future that
/// resolves to the closure's return value.
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

        pool.request_tx
            .send(crate::blocking::BlockingRequest {
                work,
                request_id,
                response_tx: blocking_tx.clone(),
                worker_eventfd: driver.eventfd,
            })
            .map_err(|_| io::Error::other("blocking pool shut down"))?;

        Ok(BlockingJoinHandle {
            request_id,
            _phantom: std::marker::PhantomData,
        })
    })
    .unwrap_or_else(|| Err(io::Error::other("called outside executor")))
}

/// Future returned by [`spawn_blocking()`]. Resolves to the closure's return value.
pub struct BlockingJoinHandle<T> {
    request_id: u64,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: 'static> Future for BlockingJoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<T> {
        with_state(|_driver, executor| {
            if let Some((_, slot)) = executor.pending_blocking.get_mut(&self.request_id)
                && let Some(boxed) = slot.take()
            {
                executor.pending_blocking.remove(&self.request_id);
                let value = *boxed
                    .downcast::<T>()
                    .expect("type mismatch in BlockingJoinHandle");
                return Poll::Ready(value);
            }
            Poll::Pending
        })
    }
}

/// Initiate an outbound TCP connection from any async task (connection or standalone).
///
/// This is the free-function equivalent of [`ConnCtx::connect()`] — it can be
/// called from standalone tasks spawned via [`spawn()`] or from an
/// [`AsyncEventHandler::on_start()`](crate::AsyncEventHandler::on_start) future,
/// where no `ConnCtx` is available.
///
/// Returns a [`ConnectFuture`] that resolves with a [`ConnCtx`] for the new connection.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn connect(addr: SocketAddr) -> io::Result<ConnectFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let token = ctx
            .connect(addr)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let calling_task = CURRENT_TASK_ID.with(|c| c.get());
        executor.owner_task[token.index as usize] = Some(calling_task);
        executor.connect_waiters[token.index as usize] = true;
        Ok(ConnectFuture {
            conn_index: token.index,
            generation: token.generation,
        })
    })
}

/// Initiate an outbound TCP connection with a timeout from any async task.
///
/// Free-function equivalent of [`ConnCtx::connect_with_timeout()`].
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn connect_with_timeout(addr: SocketAddr, timeout_ms: u64) -> io::Result<ConnectFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let token = ctx
            .connect_with_timeout(addr, timeout_ms)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let calling_task = CURRENT_TASK_ID.with(|c| c.get());
        executor.owner_task[token.index as usize] = Some(calling_task);
        executor.connect_waiters[token.index as usize] = true;
        Ok(ConnectFuture {
            conn_index: token.index,
            generation: token.generation,
        })
    })
}

/// Initiate an outbound Unix domain socket connection from any async task.
///
/// Free-function equivalent of [`ConnCtx::connect_unix()`].
///
/// Returns a [`ConnectFuture`] that resolves with a [`ConnCtx`] for the new connection.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn connect_unix(path: impl AsRef<std::path::Path>) -> io::Result<ConnectFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let token = ctx
            .connect_unix(path.as_ref())
            .map_err(|e| io::Error::other(e.to_string()))?;
        let calling_task = CURRENT_TASK_ID.with(|c| c.get());
        executor.owner_task[token.index as usize] = Some(calling_task);
        executor.connect_waiters[token.index as usize] = true;
        Ok(ConnectFuture {
            conn_index: token.index,
            generation: token.generation,
        })
    })
}

/// Initiate an outbound TLS connection from any async task (connection or standalone).
///
/// This is the free-function equivalent of [`ConnCtx::connect_tls()`] — it can be
/// called from standalone tasks spawned via [`spawn()`] or from an
/// [`AsyncEventHandler::on_start()`](crate::AsyncEventHandler::on_start) future,
/// where no `ConnCtx` is available.
///
/// `server_name` is the SNI hostname for the TLS handshake.
///
/// Returns a [`ConnectFuture`] that resolves with a [`ConnCtx`] for the new connection
/// once both the TCP and TLS handshakes complete.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn connect_tls(addr: SocketAddr, server_name: &str) -> io::Result<ConnectFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let token = ctx
            .connect_tls(addr, server_name)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let calling_task = CURRENT_TASK_ID.with(|c| c.get());
        executor.owner_task[token.index as usize] = Some(calling_task);
        executor.connect_waiters[token.index as usize] = true;
        Ok(ConnectFuture {
            conn_index: token.index,
            generation: token.generation,
        })
    })
}

/// Initiate an outbound TLS connection with a timeout from any async task.
///
/// Free-function equivalent of [`ConnCtx::connect_tls_with_timeout()`].
///
/// `server_name` is the SNI hostname for the TLS handshake.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn connect_tls_with_timeout(
    addr: SocketAddr,
    server_name: &str,
    timeout_ms: u64,
) -> io::Result<ConnectFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let token = ctx
            .connect_tls_with_timeout(addr, server_name, timeout_ms)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let calling_task = CURRENT_TASK_ID.with(|c| c.get());
        executor.owner_task[token.index as usize] = Some(calling_task);
        executor.connect_waiters[token.index as usize] = true;
        Ok(ConnectFuture {
            conn_index: token.index,
            generation: token.generation,
        })
    })
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

        resolver
            .request_tx
            .send(crate::resolver::ResolveRequest {
                host,
                port,
                request_id,
                response_tx: resolve_tx.clone(),
                worker_eventfd: driver.eventfd,
            })
            .map_err(|_| io::Error::other("resolver pool shut down"))?;

        Ok(ResolveFuture { request_id })
    })
    .unwrap_or_else(|| Err(io::Error::other("called outside executor")))
}

/// Future returned by [`resolve()`]. Resolves to a [`SocketAddr`].
pub struct ResolveFuture {
    request_id: u64,
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

/// The async equivalent of `ConnToken` + `DriverCtx`. Passed to the
/// connection's async fn, provides I/O methods.
///
/// Async connection context providing send, recv, and connect operations.
///
/// Each accepted connection receives a `ConnCtx` in [`AsyncEventHandler::on_accept`](crate::AsyncEventHandler::on_accept).
/// It exposes an async API for reading data ([`with_data`](Self::with_data),
/// [`with_bytes`](Self::with_bytes)), sending data ([`send`](Self::send),
/// [`send_nowait`](Self::send_nowait)), and initiating outbound connections
/// ([`connect`](Self::connect)).
///
/// A `ConnCtx` is valid for the lifetime of the connection's async task.
/// When the connection is closed, the task is dropped along with the `ConnCtx`.
#[derive(Clone, Copy)]
pub struct ConnCtx {
    pub(crate) conn_index: u32,
    pub(crate) generation: u32,
}

impl ConnCtx {
    /// Create a new ConnCtx for the given connection.
    pub(crate) fn new(conn_index: u32, generation: u32) -> Self {
        ConnCtx {
            conn_index,
            generation,
        }
    }

    /// Returns the connection slot index. Useful for indexing into per-connection arrays.
    pub fn index(&self) -> usize {
        self.conn_index as usize
    }

    /// Returns the `ConnToken` for this connection.
    pub fn token(&self) -> ConnToken {
        ConnToken::new(self.conn_index, self.generation)
    }

    // ── Recv ─────────────────────────────────────────────────────────

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
    pub fn with_data<F: FnMut(&[u8]) -> ParseResult>(&self, f: F) -> WithDataFuture<F> {
        WithDataFuture {
            conn_index: self.conn_index,
            f: Some(f),
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
    pub fn with_bytes<F: FnMut(Bytes) -> ParseResult>(&self, f: F) -> WithBytesFuture<F> {
        WithBytesFuture {
            conn_index: self.conn_index,
            f: Some(f),
        }
    }

    /// Install a recv sink so that CQE data is written directly to the
    /// target buffer instead of the per-connection accumulator.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `target` points to writable memory of at
    /// least `len` bytes, and that the memory remains valid until
    /// [`take_recv_sink()`](Self::take_recv_sink) is called. In practice this
    /// is guaranteed because ringline is single-threaded: the task sets the sink,
    /// yields, and the CQE handler (same thread) writes to it before the task
    /// resumes and clears the sink.
    pub unsafe fn set_recv_sink(&self, target: *mut u8, len: usize) {
        with_state(|_driver, executor| {
            executor.recv_sinks[self.conn_index as usize] = Some(crate::runtime::RecvSink {
                ptr: target,
                cap: len,
                pos: 0,
            });
        });
    }

    /// Remove the recv sink and return the number of bytes written to it.
    /// Returns 0 if no sink was active.
    pub fn take_recv_sink(&self) -> usize {
        with_state(
            |_driver, executor| match executor.recv_sinks[self.conn_index as usize].take() {
                Some(sink) => sink.pos,
                None => 0,
            },
        )
    }

    /// Returns a future that becomes ready when any recv data is available
    /// (in the accumulator, recv sink, or connection is closed).
    ///
    /// Use this with [`set_recv_sink()`](Self::set_recv_sink) to wait for
    /// direct-to-buffer writes without processing accumulator data.
    pub fn recv_ready(&self) -> RecvReadyFuture {
        RecvReadyFuture {
            conn_index: self.conn_index,
        }
    }

    /// Non-blocking accumulator access. Calls `f` with buffered data if any,
    /// returning `Some(result)`. Returns `None` if the accumulator is empty.
    pub fn try_with_data<F: FnOnce(&[u8]) -> ParseResult>(&self, f: F) -> Option<ParseResult> {
        with_state(|driver, _executor| {
            let data = driver.accumulators.data(self.conn_index);
            if data.is_empty() {
                return None;
            }
            let result = f(data);
            if let ParseResult::Consumed(consumed) = result {
                driver.accumulators.consume(self.conn_index, consumed);
            }
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
    /// Returns `Err` if the send copy pool is exhausted or the submission queue is full.
    ///
    /// For backpressure-aware sending, use [`send()`](Self::send) instead.
    pub fn send_nowait(&self, data: &[u8]) -> io::Result<()> {
        with_state(|driver, _| {
            let mut ctx = driver.make_ctx();
            ctx.send(self.token(), data)
        })
    }

    /// Forward the current pending recv buffer as a zero-copy send.
    ///
    /// This is intended for use inside a `with_data` closure. If the connection
    /// has a pending recv buffer (from the zero-copy recv path), it is taken and
    /// used as the send source directly — no copy into the send pool. The recv
    /// buffer is replenished when the send completes.
    ///
    /// Falls back to `send_nowait(data)` if there is no pending recv buffer
    /// (e.g., data came from the accumulator or a TLS connection).
    ///
    /// Only works for plaintext connections; TLS connections always copy.
    pub fn forward_recv_buf(&self, data: &[u8]) -> io::Result<()> {
        with_state(|driver, _| {
            let conn_index = self.conn_index;

            // Check for pending recv buffer.
            if let Some(pending) = driver.pending_recv_bufs[conn_index as usize].take() {
                // Verify the data pointer matches the pending buffer (sanity check).
                let pending_ptr = pending.ptr;
                let data_ptr = data.as_ptr();
                if data_ptr == pending_ptr && data.len() == pending.len as usize {
                    // Submit send SQE from the recv buffer. The bid is replenished
                    // on send completion via handle_send_recv_buf.
                    // Payload: bid in low 16 bits, remaining_len in high 16 bits.
                    debug_assert!(
                        pending.len <= 0xFFFF,
                        "forward_recv_buf: data length {} exceeds 16-bit payload capacity",
                        pending.len,
                    );
                    let payload = (pending.bid as u32) | ((pending.len) << 16);
                    // Store original data length for correct offset on partial sends.
                    driver.send_recv_buf_original_lens[conn_index as usize] = pending.len;
                    let user_data = crate::completion::UserData::encode(
                        crate::completion::OpTag::SendRecvBuf,
                        conn_index,
                        payload,
                    );
                    let entry = io_uring::opcode::Send::new(
                        io_uring::types::Fixed(conn_index),
                        pending_ptr,
                        pending.len,
                    )
                    .build()
                    .user_data(user_data.raw());

                    let built = crate::handler::BuiltSend {
                        entry,
                        pool_slot: u16::MAX,
                        slab_idx: u16::MAX,
                        total_len: pending.len,
                    };

                    let result = driver.submit_or_queue_send(conn_index, built);
                    if result.is_err() {
                        // Submit failed — replenish the recv buffer.
                        driver.pending_replenish.push(pending.bid);
                    }
                    return result;
                }

                // Pointer mismatch — put it back and fall through to copy path.
                driver.pending_recv_bufs[conn_index as usize] = Some(pending);
            }

            // No pending recv buffer — fall back to copy send.
            let mut ctx = driver.make_ctx();
            ctx.send(self.token(), data)
        })
    }

    /// Begin building a scatter-gather send with mixed copy + zero-copy guard parts.
    ///
    /// This mirrors `DriverCtx::send_parts()` — use `.copy(data)` for copied parts
    /// and `.guard(guard)` for zero-copy parts backed by `SendGuard`. Call `.submit()`
    /// to submit the SQE. Fire-and-forget: no future returned.
    pub fn send_parts(&self) -> AsyncSendBuilder {
        AsyncSendBuilder {
            token: self.token(),
        }
    }

    // ── Send (awaitable) ─────────────────────────────────────────────

    /// Send data and await completion. Copies data into the send pool, submits
    /// the SQE eagerly, then returns a future that resolves with the total bytes
    /// sent (or error).
    ///
    /// Use this when you need backpressure or send completion notification.
    /// For fire-and-forget sending, use [`send_nowait()`](Self::send_nowait).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the send copy pool is exhausted or the submission queue is full.
    pub fn send(&self, data: &[u8]) -> io::Result<SendFuture> {
        with_state(|driver, executor| {
            let mut ctx = driver.make_ctx();
            ctx.send(self.token(), data)?;
            executor.send_waiters[self.conn_index as usize] = true;
            Ok(SendFuture {
                conn_index: self.conn_index,
            })
        })
    }

    // ── Connect ──────────────────────────────────────────────────────

    /// Initiate an outbound TCP connection and await the result.
    ///
    /// Returns a new `ConnCtx` for the peer connection on success.
    pub fn connect(&self, addr: SocketAddr) -> io::Result<ConnectFuture> {
        with_state(|driver, executor| {
            let mut ctx = driver.make_ctx();
            let token = ctx
                .connect(addr)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let calling_task = CURRENT_TASK_ID.with(|c| c.get());
            executor.owner_task[token.index as usize] = Some(calling_task);
            executor.connect_waiters[token.index as usize] = true;
            Ok(ConnectFuture {
                conn_index: token.index,
                generation: token.generation,
            })
        })
    }

    /// Initiate an outbound TCP connection with a timeout and await the result.
    pub fn connect_with_timeout(
        &self,
        addr: SocketAddr,
        timeout_ms: u64,
    ) -> io::Result<ConnectFuture> {
        with_state(|driver, executor| {
            let mut ctx = driver.make_ctx();
            let token = ctx
                .connect_with_timeout(addr, timeout_ms)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let calling_task = CURRENT_TASK_ID.with(|c| c.get());
            executor.owner_task[token.index as usize] = Some(calling_task);
            executor.connect_waiters[token.index as usize] = true;
            Ok(ConnectFuture {
                conn_index: token.index,
                generation: token.generation,
            })
        })
    }

    /// Initiate an outbound Unix domain socket connection and await the result.
    ///
    /// Returns a new `ConnCtx` for the peer connection on success.
    pub fn connect_unix(&self, path: impl AsRef<std::path::Path>) -> io::Result<ConnectFuture> {
        with_state(|driver, executor| {
            let mut ctx = driver.make_ctx();
            let token = ctx
                .connect_unix(path.as_ref())
                .map_err(|e| io::Error::other(e.to_string()))?;
            let calling_task = CURRENT_TASK_ID.with(|c| c.get());
            executor.owner_task[token.index as usize] = Some(calling_task);
            executor.connect_waiters[token.index as usize] = true;
            Ok(ConnectFuture {
                conn_index: token.index,
                generation: token.generation,
            })
        })
    }

    // ── Send chain ────────────────────────────────────────────────────

    /// Build an IO_LINK chained send on this connection (fire-and-forget).
    ///
    /// The closure receives a [`SendChainBuilder`](crate::handler::SendChainBuilder) for
    /// constructing linked SQEs. Call `.copy()`, `.parts()...add()` to add SQEs,
    /// then `.finish()` to submit the chain.
    ///
    /// For backpressure-aware chained sending, use [`send_chain()`](Self::send_chain).
    pub fn send_chain_nowait<F, R>(&self, f: F) -> R
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
    /// resolves with total bytes sent.
    ///
    /// For fire-and-forget chained sending, use [`send_chain_nowait()`](Self::send_chain_nowait).
    pub fn send_chain<F>(&self, f: F) -> io::Result<SendFuture>
    where
        F: FnOnce(crate::handler::SendChainBuilder<'_, '_>) -> io::Result<()>,
    {
        with_state(|driver, executor| {
            let mut ctx = driver.make_ctx();
            let token = ConnToken::new(self.conn_index, self.generation);
            let builder = ctx.send_chain(token);
            f(builder)?;
            executor.send_waiters[self.conn_index as usize] = true;
            Ok(SendFuture {
                conn_index: self.conn_index,
            })
        })
    }

    // ── Shutdown / cancel ─────────────────────────────────────────────

    /// Shutdown the write side of the connection (half-close).
    ///
    /// Sends a TCP FIN to the peer. The read side remains open.
    pub fn shutdown_write(&self) {
        with_state(|driver, _| {
            let mut ctx = driver.make_ctx();
            ctx.shutdown_write(self.token());
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

    /// Initiate an outbound TLS connection and await the result.
    pub fn connect_tls(&self, addr: SocketAddr, server_name: &str) -> io::Result<ConnectFuture> {
        with_state(|driver, executor| {
            let mut ctx = driver.make_ctx();
            let token = ctx
                .connect_tls(addr, server_name)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let calling_task = CURRENT_TASK_ID.with(|c| c.get());
            executor.owner_task[token.index as usize] = Some(calling_task);
            executor.connect_waiters[token.index as usize] = true;
            Ok(ConnectFuture {
                conn_index: token.index,
                generation: token.generation,
            })
        })
    }

    /// Initiate an outbound TLS connection with a timeout and await the result.
    pub fn connect_tls_with_timeout(
        &self,
        addr: SocketAddr,
        server_name: &str,
        timeout_ms: u64,
    ) -> io::Result<ConnectFuture> {
        with_state(|driver, executor| {
            let mut ctx = driver.make_ctx();
            let token = ctx
                .connect_tls_with_timeout(addr, server_name, timeout_ms)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let calling_task = CURRENT_TASK_ID.with(|c| c.get());
            executor.owner_task[token.index as usize] = Some(calling_task);
            executor.connect_waiters[token.index as usize] = true;
            Ok(ConnectFuture {
                conn_index: token.index,
                generation: token.generation,
            })
        })
    }

    // ── Timestamps ─────────────────────────────────────────────────

    /// Returns the most recent kernel RX software timestamp as nanoseconds
    /// since epoch (`CLOCK_REALTIME`), or 0 if no timestamp has been received.
    ///
    /// Updated each time a `RecvMsgMulti` completion delivers an
    /// `SCM_TIMESTAMPING` cmsg. Only available when the `timestamps` feature
    /// is enabled and `Config::timestamps(true)` is set.
    #[cfg(feature = "timestamps")]
    pub fn recv_timestamp(&self) -> u64 {
        with_state(|driver, _| {
            driver
                .connections
                .get(self.conn_index)
                .map(|cs| cs.recv_timestamp_ns)
                .unwrap_or(0)
        })
    }

    // ── Close / metadata ─────────────────────────────────────────────

    /// Close this connection.
    pub fn close(&self) {
        let ptr = CURRENT_DRIVER.with(|c| c.get());
        if ptr.is_null() {
            return;
        }
        let state = unsafe { &mut *ptr };
        let driver = unsafe { &mut *state.driver };
        driver.close_connection(self.conn_index);
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
}

// ── AsyncSendBuilder ─────────────────────────────────────────────────

/// Builder for scatter-gather sends in the async API.
///
/// Wraps `DriverCtx::send_parts()` — call `.copy()` and `.guard()` to add
/// parts, then `.submit()`. This is a synchronous builder; the send is
/// fire-and-forget (no future).
pub struct AsyncSendBuilder {
    token: ConnToken,
}

impl AsyncSendBuilder {
    /// Build and submit the send by calling the provided closure with a
    /// `SendBuilder` from the `DriverCtx`.
    ///
    /// The closure receives the `SendBuilder` and should chain `.copy()` / `.guard()`
    /// calls then call `.submit()`.
    ///
    /// # Example
    /// ```no_run
    /// # fn example(conn: ringline::ConnCtx) -> std::io::Result<()> {
    /// conn.send_parts().build(|b| {
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

    /// Build and submit a scatter-gather send, then await completion.
    ///
    /// Like [`build()`](Self::build) but returns a [`SendFuture`] that resolves
    /// with the total bytes sent (or error). Use this when you need backpressure
    /// or send completion notification.
    pub fn build_await<F>(self, f: F) -> io::Result<SendFuture>
    where
        F: FnOnce(crate::handler::SendBuilder<'_, '_>) -> io::Result<()>,
    {
        with_state(|driver, executor| {
            let mut ctx = driver.make_ctx();
            let builder = ctx.send_parts(self.token);
            f(builder)?;
            let conn_index = self.token.index;
            executor.send_waiters[conn_index as usize] = true;
            Ok(SendFuture { conn_index })
        })
    }

    /// Submit a scatter-gather send from pre-classified `SendPart`s.
    ///
    /// This avoids the lifetime constraints of the closure-based [`build()`](Self::build),
    /// allowing callers to mix copy and guard parts in a single SQE from borrowed data.
    /// Parts are consumed in order up to `MAX_IOVECS` total or `MAX_GUARDS` guards.
    ///
    /// Returns the number of parts consumed on success.
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

    /// Like [`submit_batch`](Self::submit_batch) but returns a [`SendFuture`]
    /// for backpressure / yield.
    pub fn submit_batch_await(
        self,
        parts: Vec<crate::handler::SendPart<'_>>,
    ) -> io::Result<(usize, SendFuture)> {
        use crate::handler::SendPart;
        with_state(|driver, executor| {
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
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty batch"));
            }
            builder.submit()?;
            let conn_index = self.token.index;
            executor.send_waiters[conn_index as usize] = true;
            Ok((consumed, SendFuture { conn_index }))
        })
    }
}

// ── WithDataFuture ───────────────────────────────────────────────────

/// Future returned by [`ConnCtx::with_data`].
pub struct WithDataFuture<F> {
    conn_index: u32,
    f: Option<F>,
}

impl<F: FnMut(&[u8]) -> ParseResult + Unpin> Future for WithDataFuture<F> {
    type Output = usize;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<usize> {
        with_state(|driver, executor| {
            // Zero-copy fast path: check pending recv buffer before accumulator.
            if driver.pending_recv_bufs[self.conn_index as usize].is_some() {
                let acc_empty = driver.accumulators.data(self.conn_index).is_empty();
                if acc_empty {
                    // Borrow the kernel buffer in-place — no copy.
                    let pending = driver.pending_recv_bufs[self.conn_index as usize].unwrap();
                    let data =
                        unsafe { std::slice::from_raw_parts(pending.ptr, pending.len as usize) };
                    let f = self.f.as_mut().expect("WithDataFuture polled after Ready");
                    let result = f(data);
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
                    .map(|c| matches!(c.recv_mode, crate::connection::RecvMode::Closed))
                    .unwrap_or(true); // connection already released
                if is_closed {
                    let f = self.f.as_mut().expect("WithDataFuture polled after Ready");
                    let result = f(&[]);
                    self.f.take();
                    return Poll::Ready(match result {
                        ParseResult::Consumed(n) => n,
                        ParseResult::NeedMore => 0,
                    });
                }

                // No data available — register as recv waiter and park.
                executor.recv_waiters[self.conn_index as usize] = true;
                return Poll::Pending;
            }

            // Data available — call closure immediately (zero-overhead hot path).
            let f = self.f.as_mut().expect("WithDataFuture polled after Ready");
            let result = f(data);
            match result {
                ParseResult::Consumed(consumed) if consumed > 0 => {
                    driver.accumulators.consume(self.conn_index, consumed);
                    self.f.take();
                    return Poll::Ready(consumed);
                }
                _ => {}
            }

            // NeedMore or Consumed(0) on non-empty data: incomplete parse.
            // Check if the connection is closed (EOF with leftover partial data).
            let is_closed = driver
                .connections
                .get(self.conn_index)
                .map(|c| matches!(c.recv_mode, crate::connection::RecvMode::Closed))
                .unwrap_or(true);
            if is_closed {
                self.f.take();
                return Poll::Ready(0);
            }

            // Connection still open — wait for more data before retrying.
            executor.recv_waiters[self.conn_index as usize] = true;
            Poll::Pending
        })
    }
}

// ── WithBytesFuture ──────────────────────────────────────────────────

/// Future returned by [`ConnCtx::with_bytes`].
pub struct WithBytesFuture<F> {
    conn_index: u32,
    f: Option<F>,
}

impl<F: FnMut(Bytes) -> ParseResult + Unpin> Future for WithBytesFuture<F> {
    type Output = usize;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<usize> {
        with_state(|driver, executor| {
            // Flush any pending zero-copy recv buffer to accumulator so
            // take_frozen() will include it.
            if let Some(pending) = driver.pending_recv_bufs[self.conn_index as usize].take() {
                let pending_data =
                    unsafe { std::slice::from_raw_parts(pending.ptr, pending.len as usize) };
                driver.accumulators.append(self.conn_index, pending_data);
                driver.pending_replenish.push(pending.bid);
            }

            let data = driver.accumulators.data(self.conn_index);
            if data.is_empty() {
                // Check if the connection has been closed — return 0 (EOF).
                let is_closed = driver
                    .connections
                    .get(self.conn_index)
                    .map(|c| matches!(c.recv_mode, crate::connection::RecvMode::Closed))
                    .unwrap_or(true);
                if is_closed {
                    let f = self.f.as_mut().expect("WithBytesFuture polled after Ready");
                    let result = f(Bytes::new());
                    self.f.take();
                    return Poll::Ready(match result {
                        ParseResult::Consumed(n) => n,
                        ParseResult::NeedMore => 0,
                    });
                }

                executor.recv_waiters[self.conn_index as usize] = true;
                return Poll::Pending;
            }

            // Detach accumulator as frozen Bytes (O(1)).
            let frozen = driver.accumulators.take_frozen(self.conn_index);
            let len = frozen.len();

            let f = self.f.as_mut().expect("WithBytesFuture polled after Ready");
            let result = f(frozen.clone());

            match result {
                ParseResult::Consumed(consumed) if consumed > 0 => {
                    // Put back unconsumed remainder (if any).
                    if consumed < len {
                        driver
                            .accumulators
                            .prepend(self.conn_index, &frozen[consumed..]);
                    }
                    self.f.take();
                    return Poll::Ready(consumed);
                }
                _ => {}
            }

            // NeedMore or Consumed(0) on non-empty data: incomplete parse.
            // Put everything back.
            driver.accumulators.prepend(self.conn_index, &frozen[..]);

            let is_closed = driver
                .connections
                .get(self.conn_index)
                .map(|c| matches!(c.recv_mode, crate::connection::RecvMode::Closed))
                .unwrap_or(true);
            if is_closed {
                self.f.take();
                return Poll::Ready(0);
            }

            executor.recv_waiters[self.conn_index as usize] = true;
            Poll::Pending
        })
    }
}

// ── RecvReadyFuture ──────────────────────────────────────────────────

/// Future returned by [`ConnCtx::recv_ready`]. Resolves when:
/// 1. The recv sink has received data (`pos > 0`), OR
/// 2. The accumulator has data, OR
/// 3. The connection is closed.
pub struct RecvReadyFuture {
    conn_index: u32,
}

impl Future for RecvReadyFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        with_state(|driver, executor| {
            // Check recv sink.
            if let Some(sink) = &executor.recv_sinks[self.conn_index as usize]
                && sink.pos > 0
            {
                return Poll::Ready(());
            }

            // Check accumulator.
            if !driver.accumulators.data(self.conn_index).is_empty() {
                return Poll::Ready(());
            }

            // Check if the connection is closed.
            let is_closed = driver
                .connections
                .get(self.conn_index)
                .map(|c| matches!(c.recv_mode, crate::connection::RecvMode::Closed))
                .unwrap_or(true);
            if is_closed {
                return Poll::Ready(());
            }

            // Not ready — register as recv waiter and park.
            executor.recv_waiters[self.conn_index as usize] = true;
            Poll::Pending
        })
    }
}

// ── SendFuture ───────────────────────────────────────────────────────

/// Future that awaits send completion. The SQE was already submitted eagerly
/// by [`ConnCtx::send`] — this future only waits for the CQE result.
/// No data stored in the future. No allocation.
pub struct SendFuture {
    conn_index: u32,
}

impl Future for SendFuture {
    type Output = io::Result<u32>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u32>> {
        with_state(|_driver, executor| {
            match executor.io_results[self.conn_index as usize].take() {
                Some(IoResult::Send(result)) => Poll::Ready(result),
                _ => {
                    // Not ready yet — re-register waiter.
                    executor.send_waiters[self.conn_index as usize] = true;
                    Poll::Pending
                }
            }
        })
    }
}

impl Drop for SendFuture {
    fn drop(&mut self) {
        let ptr = CURRENT_DRIVER.with(|c| c.get());
        if ptr.is_null() {
            return;
        }
        let state = unsafe { &mut *ptr };
        let executor = unsafe { &mut *state.executor };
        executor.send_waiters[self.conn_index as usize] = false;
    }
}

// ── ConnectFuture ────────────────────────────────────────────────────

/// Future that awaits an outbound TCP connection. The connect SQE was submitted
/// eagerly by [`ConnCtx::connect`] — this future waits for the CQE result.
pub struct ConnectFuture {
    conn_index: u32,
    generation: u32,
}

impl Future for ConnectFuture {
    type Output = io::Result<ConnCtx>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<ConnCtx>> {
        with_state(|_driver, executor| {
            match executor.io_results[self.conn_index as usize].take() {
                Some(IoResult::Connect(result)) => match result {
                    Ok(()) => Poll::Ready(Ok(ConnCtx::new(self.conn_index, self.generation))),
                    Err(e) => Poll::Ready(Err(e)),
                },
                _ => {
                    // Not ready yet — re-register waiter.
                    executor.connect_waiters[self.conn_index as usize] = true;
                    Poll::Pending
                }
            }
        })
    }
}

impl Drop for ConnectFuture {
    fn drop(&mut self) {
        let ptr = CURRENT_DRIVER.with(|c| c.get());
        if ptr.is_null() {
            return;
        }
        let state = unsafe { &mut *ptr };
        let executor = unsafe { &mut *state.executor };
        executor.connect_waiters[self.conn_index as usize] = false;
    }
}

// ── Sleep ────────────────────────────────────────────────────────────

/// Create a future that completes after the given duration.
///
/// Uses an io_uring timeout SQE internally — no busy-waiting, no timer
/// thread. The timer fires on the same worker thread as the calling task.
///
/// # Panics
///
/// Panics if the timer slot pool is exhausted, or if called outside the
/// ringline async executor.
pub fn sleep(duration: Duration) -> SleepFuture {
    SleepFuture {
        duration,
        timer_slot: None,
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
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        with_state(|driver, executor| {
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
                    // Pool exhausted — complete immediately rather than panic.
                    // Callers needing explicit error handling should use try_sleep().
                    return Poll::Ready(());
                }
            };

            let is_absolute = self.absolute.is_some();
            if let Some(deadline) = self.absolute {
                executor.timer_pool.timespecs[slot as usize] = io_uring::types::Timespec::new()
                    .sec(deadline.secs)
                    .nsec(deadline.nsecs);
            } else {
                let secs = self.duration.as_secs();
                let nsecs = self.duration.subsec_nanos();
                executor.timer_pool.timespecs[slot as usize] =
                    io_uring::types::Timespec::new().sec(secs).nsec(nsecs);
            }

            let payload = TimerSlotPool::encode_payload(slot, generation);
            let ud = UserData::encode(OpTag::Timer, 0, payload);
            let ts_ptr =
                &executor.timer_pool.timespecs[slot as usize] as *const io_uring::types::Timespec;

            let submit_result = if is_absolute {
                driver.ring.submit_timeout_abs(ts_ptr, ud)
            } else {
                driver.ring.submit_timeout(ts_ptr, ud)
            };

            if let Err(_e) = submit_result {
                executor.timer_pool.release(slot);
                // On SQE submission failure, complete immediately rather than hang.
                return Poll::Ready(());
            }

            self.timer_slot = Some(slot);
            self.generation = generation;
            Poll::Pending
        })
    }
}

impl Drop for SleepFuture {
    fn drop(&mut self) {
        if let Some(slot) = self.timer_slot {
            // Timer was submitted but not yet fired — try to cancel it.
            let ptr = CURRENT_DRIVER.with(|c| c.get());
            if ptr.is_null() {
                return;
            }
            let state = unsafe { &mut *ptr };
            let driver = unsafe { &mut *state.driver };
            let executor = unsafe { &mut *state.executor };

            if !executor.timer_pool.is_fired(slot) {
                let payload = TimerSlotPool::encode_payload(slot, self.generation);
                let target_ud = UserData::encode(OpTag::Timer, 0, payload);
                // Best effort cancel; timer fires harmlessly if already expired.
                let _ = driver.ring.submit_async_cancel(target_ud.raw(), 0);
            }
            // Slot released regardless — stale timer CQE detected via generation.
            executor.timer_pool.release(slot);
        }
    }
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
        let waker_id = CURRENT_TASK_ID.with(|c| c.get());
        let (slot, generation) = executor.timer_pool.allocate(waker_id).ok_or_else(|| {
            crate::metrics::TIMER_POOL_EXHAUSTED.increment();
            TimerExhausted
        })?;

        let secs = duration.as_secs();
        let nsecs = duration.subsec_nanos();
        executor.timer_pool.timespecs[slot as usize] =
            io_uring::types::Timespec::new().sec(secs).nsec(nsecs);

        let payload = TimerSlotPool::encode_payload(slot, generation);
        let ud = UserData::encode(OpTag::Timer, 0, payload);
        let ts_ptr =
            &executor.timer_pool.timespecs[slot as usize] as *const io_uring::types::Timespec;

        if let Err(_e) = driver.ring.submit_timeout(ts_ptr, ud) {
            executor.timer_pool.release(slot);
            // SQE submission failure — complete immediately (same as sleep()).
            return Ok(SleepFuture {
                duration,
                timer_slot: None,
                generation: 0,
                absolute: None,
            });
        }

        Ok(SleepFuture {
            duration,
            timer_slot: Some(slot),
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
        let waker_id = CURRENT_TASK_ID.with(|c| c.get());
        let (slot, generation) = executor.timer_pool.allocate(waker_id).ok_or_else(|| {
            crate::metrics::TIMER_POOL_EXHAUSTED.increment();
            TimerExhausted
        })?;

        executor.timer_pool.timespecs[slot as usize] = io_uring::types::Timespec::new()
            .sec(deadline.secs)
            .nsec(deadline.nsecs);

        let payload = TimerSlotPool::encode_payload(slot, generation);
        let ud = UserData::encode(OpTag::Timer, 0, payload);
        let ts_ptr =
            &executor.timer_pool.timespecs[slot as usize] as *const io_uring::types::Timespec;

        if let Err(_e) = driver.ring.submit_timeout_abs(ts_ptr, ud) {
            executor.timer_pool.release(slot);
            return Ok(SleepFuture {
                duration: Duration::ZERO,
                timer_slot: None,
                generation: 0,
                absolute: Some(deadline),
            });
        }

        Ok(SleepFuture {
            duration: Duration::ZERO,
            timer_slot: Some(slot),
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

/// Future that awaits a disk I/O completion (NVMe or Direct I/O).
///
/// The io_uring SQE was submitted before this future was created.
/// On completion, the CQE handler stores the result and wakes the task.
pub struct DiskIoFuture {
    pub(crate) seq: u32,
}

impl Future for DiskIoFuture {
    type Output = io::Result<i32>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<i32>> {
        with_state(|_driver, executor| {
            match executor.disk_io_results.remove(&self.seq) {
                Some(result) if result < 0 => {
                    Poll::Ready(Err(io::Error::from_raw_os_error(-result)))
                }
                Some(result) => Poll::Ready(Ok(result)),
                None => {
                    // Re-register waiter (polled before CQE arrived or after spurious wake).
                    let task_id = CURRENT_TASK_ID.with(|c| c.get());
                    executor.disk_io_waiters.insert(self.seq, task_id);
                    Poll::Pending
                }
            }
        })
    }
}

impl Drop for DiskIoFuture {
    fn drop(&mut self) {
        let ptr = CURRENT_DRIVER.with(|c| c.get());
        if ptr.is_null() {
            return;
        }
        let state = unsafe { &mut *ptr };
        let executor = unsafe { &mut *state.executor };
        executor.disk_io_waiters.remove(&self.seq);
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
        let seq = unsafe { ctx.direct_io_read(file, offset, buf, len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
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
pub fn nvme_read(
    device: crate::nvme::NvmeDevice,
    lba: u64,
    num_blocks: u16,
    buf_addr: u64,
    buf_len: u32,
) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.nvme_read(device, lba, num_blocks, buf_addr, buf_len)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
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
        let seq = unsafe { ctx.direct_io_write(file, offset, buf, len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
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
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
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
pub fn nvme_write(
    device: crate::nvme::NvmeDevice,
    lba: u64,
    num_blocks: u16,
    buf_addr: u64,
    buf_len: u32,
) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.nvme_write(device, lba, num_blocks, buf_addr, buf_len)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
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
    pub fn recv_from(&self) -> UdpRecvFuture {
        UdpRecvFuture {
            udp_index: self.udp_index,
        }
    }

    /// Send a datagram to the given peer (fire-and-forget, copying).
    ///
    /// Copies `data` into the send pool and submits a `sendmsg` SQE.
    /// Only one send can be in-flight per UDP socket at a time.
    pub fn send_to(&self, peer: SocketAddr, data: &[u8]) -> Result<(), crate::error::UdpSendError> {
        with_state(|driver, _executor| driver.udp_send_to(self.udp_index, peer, data))
    }
}

/// Future returned by [`UdpCtx::recv_from()`].
pub struct UdpRecvFuture {
    udp_index: u32,
}

impl Future for UdpRecvFuture {
    type Output = (Vec<u8>, SocketAddr);

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        with_state(|_driver, executor| {
            let idx = self.udp_index as usize;
            if idx < executor.udp_recv_queues.len()
                && let Some(datagram) = executor.udp_recv_queues[idx].pop_front()
            {
                return Poll::Ready(datagram);
            }
            // Register as waiter so the CQE handler wakes us.
            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            if idx < executor.udp_recv_waiters.len() {
                executor.udp_recv_waiters[idx] = Some(task_id);
            }
            Poll::Pending
        })
    }
}
