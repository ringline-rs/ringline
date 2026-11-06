//! What happens when a task panics.
//!
//! A panic in user code that the runtime polls or calls on a worker is caught:
//! connection tasks; standalone tasks from `spawn` and `spawn_with_handle`;
//! the futures returned by `on_start` and `on_udp_bind`, and the calls that
//! build them; building the `on_accept` (or `on_adopt`) future; `on_tick`;
//! `on_notify`; and, on the blocking pool, `spawn_blocking` closures.
//!
//! A future's `Drop` is caught wherever the runtime drops a task: after `Ready`,
//! after a panic in its poll, on cancellation, when its connection closes, and
//! when the worker exits. So is a [`SendGuard`](crate::SendGuard)'s `Drop` on a
//! worker's thread, and that of a `spawn_blocking` result whose future was
//! dropped, on the worker or on the blocking pool.
//!
//! Not covered: the handler's own `Drop` at worker exit, which is reported by
//! the worker's join handle; the `Drop` of a [`ParkState`](crate::ParkState),
//! which stops the worker; `create_for_worker`, whose panic fails `launch()`;
//! and the `wake` of a waker kept for a combinator, whose panic goes to the
//! panic hook only, under either policy.
//!
//! By default ([`TaskPanicPolicy::Contain`]) a caught panic is contained: the
//! task is dropped, a connection task's connection is closed, the worker keeps
//! running, and a handle awaiting the task resolves to a [`JoinError`]. With
//! [`TaskPanicPolicy::Shutdown`] a panic also shuts the runtime down.

use std::any::Any;
use std::fmt;
use std::io::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// What the runtime does when a task panics. Set with
/// [`ConfigBuilder::task_panic_policy`](crate::ConfigBuilder::task_panic_policy).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskPanicPolicy {
    /// Catch the panic and keep running. The task is dropped, a connection
    /// task's connection is closed, and a handle awaiting the task resolves to
    /// a [`JoinError`]. The panic message is printed to stderr.
    #[default]
    Contain,
    /// Catch the panic, then shut the runtime down as
    /// [`Runtime::shutdown`](crate::Runtime::shutdown) does: the listeners
    /// close, every worker drains and exits, and
    /// [`Runtime::wait_on_signal`](crate::Runtime::wait_on_signal) returns
    /// [`Signal::TaskPanic`](crate::signal::Signal::TaskPanic). Each worker on
    /// which a task panicked before it stopped returns
    /// [`Error::TaskPanicked`](crate::Error::TaskPanicked) carrying that
    /// worker's first panic; workers that only drained return `Ok(())`.
    Shutdown,
}

/// Why a task's handle did not produce a value.
///
/// Returned by awaiting a [`JoinHandle`](crate::JoinHandle) or a
/// [`BlockingJoinHandle`](crate::BlockingJoinHandle), and carried by
/// [`Error::TaskPanicked`](crate::Error::TaskPanicked).
pub struct JoinError {
    repr: Repr,
}

enum Repr {
    Cancelled,
    // A `Mutex` so `JoinError` is `Sync`; the payload is `Send` only.
    Panicked {
        message: Option<String>,
        payload: Mutex<Option<Box<dyn Any + Send>>>,
    },
}

impl JoinError {
    pub(crate) fn cancelled() -> Self {
        JoinError {
            repr: Repr::Cancelled,
        }
    }

    pub(crate) fn panicked(payload: Box<dyn Any + Send>) -> Self {
        JoinError {
            repr: Repr::Panicked {
                message: panic_message(&*payload),
                payload: Mutex::new(Some(payload)),
            },
        }
    }

    /// A panic known only by its message, carried as a `String` payload.
    fn panicked_with_message(message: Option<String>) -> Self {
        let payload: Box<dyn Any + Send> = Box::new(
            message
                .clone()
                .unwrap_or_else(|| NON_STRING_PAYLOAD.to_string()),
        );
        JoinError {
            repr: Repr::Panicked {
                message,
                payload: Mutex::new(Some(payload)),
            },
        }
    }

    /// Whether the task panicked.
    pub fn is_panic(&self) -> bool {
        matches!(self.repr, Repr::Panicked { .. })
    }

    /// Whether the task was cancelled with
    /// [`JoinHandle::abort`](crate::JoinHandle::abort) or
    /// [`TaskId::cancel`](crate::TaskId::cancel).
    pub fn is_cancelled(&self) -> bool {
        matches!(self.repr, Repr::Cancelled)
    }

    /// The panic message, if the task panicked with a `&str` or `String`
    /// payload. `None` for any other payload, and for a cancelled task.
    pub fn panic_message(&self) -> Option<&str> {
        match &self.repr {
            Repr::Panicked { message, .. } => message.as_deref(),
            Repr::Cancelled => None,
        }
    }

    /// The panic payload, to re-raise with [`std::panic::resume_unwind`].
    ///
    /// # Panics
    ///
    /// Panics if the task did not panic; check [`is_panic`](Self::is_panic).
    pub fn into_panic(self) -> Box<dyn Any + Send> {
        self.try_into_panic()
            .unwrap_or_else(|_| panic!("JoinError::into_panic on a task that did not panic"))
    }

    /// The panic payload, or `self` back if the task did not panic.
    pub fn try_into_panic(self) -> Result<Box<dyn Any + Send>, JoinError> {
        match self.repr {
            Repr::Panicked { message, payload } => {
                let payload = payload
                    .into_inner()
                    .unwrap_or_else(|e| e.into_inner())
                    .unwrap_or_else(|| {
                        Box::new(message.unwrap_or_else(|| NON_STRING_PAYLOAD.to_string()))
                    });
                Ok(payload)
            }
            repr @ Repr::Cancelled => Err(JoinError { repr }),
        }
    }
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repr {
            Repr::Cancelled => f.write_str("task was cancelled"),
            Repr::Panicked {
                message: Some(message),
                ..
            } => write!(f, "task panicked: {message}"),
            Repr::Panicked { message: None, .. } => f.write_str("task panicked"),
        }
    }
}

impl fmt::Debug for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repr {
            Repr::Cancelled => f.write_str("JoinError::Cancelled"),
            Repr::Panicked { message, .. } => {
                f.debug_tuple("JoinError::Panicked").field(message).finish()
            }
        }
    }
}

impl std::error::Error for JoinError {}

impl From<JoinError> for std::io::Error {
    fn from(err: JoinError) -> Self {
        std::io::Error::other(err)
    }
}

/// Stands in for the message of a panic whose payload is not a string.
const NON_STRING_PAYLOAD: &str = "non-string panic payload";

/// The message of a panic payload that is a `&str` or a `String`.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> Option<String> {
    if let Some(s) = payload.downcast_ref::<&str>() {
        Some((*s).to_string())
    } else {
        payload.downcast_ref::<String>().cloned()
    }
}

/// What `catch_unwind` returns for a panic.
pub(crate) type PanicPayload = Box<dyn Any + Send>;

thread_local! {
    /// Panics caught on this thread in a [`GuardBox`](crate::GuardBox)'s drop,
    /// for its event loop to report.
    static GUARD_DROP_PANICS: std::cell::RefCell<Vec<PanicPayload>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Record a panic caught in a guard's `Drop`.
pub(crate) fn note_guard_drop_panic(payload: PanicPayload) {
    let _ = GUARD_DROP_PANICS.try_with(|p| p.borrow_mut().push(payload));
}

/// Take the panics caught on this thread in guards' `Drop`.
pub(crate) fn take_guard_drop_panics() -> Vec<PanicPayload> {
    GUARD_DROP_PANICS.with(|p| std::mem::take(&mut *p.borrow_mut()))
}

/// Drop `value`, returning the payload of a panic in its `Drop`.
pub(crate) fn drop_caught<T>(value: T) -> Option<PanicPayload> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(value))).err()
}

/// A worker's handling of caught task panics, under its runtime's policy.
pub(crate) struct PanicReporter {
    policy: TaskPanicPolicy,
    /// This worker's shutdown flag; set directly where there is no
    /// `runtime_shutdown` (event loops built in unit tests).
    shutdown_flag: std::sync::Arc<AtomicBool>,
    /// The runtime's shutdown, run on the first panic under `Shutdown`.
    runtime_shutdown: Option<std::sync::Arc<crate::worker::RuntimeShutdown>>,
    /// The first panic on this worker under `Shutdown`.
    first: Option<JoinError>,
}

impl PanicReporter {
    pub(crate) fn new(
        policy: TaskPanicPolicy,
        shutdown_flag: std::sync::Arc<AtomicBool>,
        runtime_shutdown: Option<std::sync::Arc<crate::worker::RuntimeShutdown>>,
    ) -> Self {
        PanicReporter {
            policy,
            shutdown_flag,
            runtime_shutdown,
            first: None,
        }
    }

    /// Handle a panic caught at `site`. The payload stays with the caller,
    /// which may hand it to a waiting handle.
    pub(crate) fn report(&mut self, site: &str, payload: &(dyn Any + Send)) {
        let message = panic_message(payload);
        let shown = message.as_deref().unwrap_or(NON_STRING_PAYLOAD);
        match self.policy {
            TaskPanicPolicy::Contain => {
                eprintln!("ringline: {site} panicked: {shown}; continuing");
            }
            TaskPanicPolicy::Shutdown => {
                eprintln!("ringline: {site} panicked: {shown}; shutting down");
                if self.first.is_none() {
                    self.first = Some(JoinError::panicked_with_message(message));
                }
                match &self.runtime_shutdown {
                    Some(shutdown) => shutdown.shutdown_for_panic(),
                    None => self.shutdown_flag.store(true, Ordering::Release),
                }
            }
        }
    }

    /// Report that worker `worker` stopped for `cause`, a panic in the runtime
    /// or an error from its ring or poll. Wakes
    /// [`Runtime::wait_on_signal`](crate::Runtime::wait_on_signal), and under
    /// `Shutdown` shuts the runtime down. A `Contain` runtime keeps serving on
    /// its other workers.
    pub(crate) fn report_worker_exit(&self, worker: usize, cause: &str) {
        let shutdown = self.policy == TaskPanicPolicy::Shutdown;
        let outcome = if shutdown {
            "shutting down"
        } else {
            "other workers continue until shutdown"
        };
        // Not `eprintln!`, which panics if stderr fails, and the worker's drain
        // comes next.
        let _ = writeln!(
            std::io::stderr(),
            "ringline: worker {worker} exited: {cause}; {outcome}"
        );
        match &self.runtime_shutdown {
            Some(runtime) => runtime.worker_exited(worker, shutdown),
            None if shutdown => self.shutdown_flag.store(true, Ordering::Release),
            None => {}
        }
    }

    /// Close what reached `worker`'s sockets during its drain.
    pub(crate) fn report_worker_drained(&self, worker: usize) {
        if let Some(runtime) = &self.runtime_shutdown {
            runtime.worker_drained(worker);
        }
    }

    /// The first panic recorded under `Shutdown`, for the worker to return.
    pub(crate) fn take(&mut self) -> Option<JoinError> {
        self.first.take()
    }
}
