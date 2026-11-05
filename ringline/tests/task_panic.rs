//! Task panics: handles resolve to a `JoinError`, and `TaskPanicPolicy`
//! decides whether the runtime keeps running or shuts down.

#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, RinglineBuilder, TaskPanicPolicy,
};

fn config(workers: usize, policy: TaskPanicPolicy) -> Config {
    ConfigBuilder::new()
        .workers(workers)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(1)
        .resolver_threads(0)
        .spawner_threads(0)
        .task_panic_policy(policy)
        .build()
        .expect("valid config")
}

/// Join every worker within `within`, or fail rather than hang.
fn join_all(
    handles: Vec<JoinHandle<Result<(), ringline::Error>>>,
    within: Duration,
) -> Vec<Result<(), ringline::Error>> {
    let joiner = std::thread::spawn(move || {
        handles
            .into_iter()
            .map(|h| h.join().expect("worker thread panicked"))
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + within;
    while !joiner.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        joiner.is_finished(),
        "workers did not exit within {within:?}"
    );
    joiner.join().expect("joiner panicked")
}

// ── spawn_blocking ─────────────────────────────────────────────────────

static BLOCKING_PANIC_MESSAGE: Mutex<Option<String>> = Mutex::new(None);
static BLOCKING_AFTER_PANIC: AtomicU32 = AtomicU32::new(0);
static BLOCKING_DONE: AtomicBool = AtomicBool::new(false);

struct BlockingPanics;

impl AsyncEventHandler for BlockingPanics {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let err = ringline::spawn_blocking(|| -> u32 { panic!("boom in blocking") })
                .expect("spawn_blocking")
                .await
                .expect_err("the closure panicked");
            assert!(err.is_panic() && !err.is_cancelled());
            assert_eq!(err.panic_message(), Some("boom in blocking"));
            let payload = err.into_panic();
            *BLOCKING_PANIC_MESSAGE.lock().unwrap() =
                payload.downcast_ref::<&str>().map(|s| s.to_string());

            // The only pool thread survived the panic and runs the next one.
            let value = ringline::spawn_blocking(|| 7u32)
                .expect("spawn_blocking")
                .await
                .expect("the closure returned");
            BLOCKING_AFTER_PANIC.store(value, Ordering::SeqCst);
            BLOCKING_DONE.store(true, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        BlockingPanics
    }
}

/// A panicking `spawn_blocking` closure resolves its handle to a `JoinError`
/// that carries the payload, and the pool thread keeps running.
#[test]
fn a_blocking_panic_resolves_to_a_join_error_and_the_pool_survives() {
    let (_runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<BlockingPanics>()
        .expect("launch");
    let results = join_all(handles, Duration::from_secs(10));
    assert!(
        results.iter().all(|r| r.is_ok()),
        "Contain does not fail a worker"
    );
    assert!(
        BLOCKING_DONE.load(Ordering::SeqCst),
        "on_start did not finish"
    );
    assert_eq!(
        BLOCKING_PANIC_MESSAGE.lock().unwrap().as_deref(),
        Some("boom in blocking"),
        "into_panic returns the original payload"
    );
    assert_eq!(BLOCKING_AFTER_PANIC.load(Ordering::SeqCst), 7);
}

// ── spawn_with_handle ──────────────────────────────────────────────────

static HANDLE_PANICKED: AtomicBool = AtomicBool::new(false);
static HANDLE_CANCELLED: AtomicBool = AtomicBool::new(false);
static HANDLE_AFTER: AtomicBool = AtomicBool::new(false);

struct HandlePanics;

impl AsyncEventHandler for HandlePanics {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let panicking = ringline::spawn_with_handle(async {
                let _ = ringline::sleep(Duration::from_millis(1)).await;
                panic!("boom in task");
            })
            .expect("spawn_with_handle");
            let err = panicking.await.expect_err("the task panicked");
            HANDLE_PANICKED.store(
                err.is_panic() && err.panic_message() == Some("boom in task"),
                Ordering::SeqCst,
            );

            let endless = ringline::spawn_with_handle(std::future::pending::<u32>())
                .expect("spawn_with_handle");
            endless.abort();
            let err = endless.await.expect_err("the task was aborted");
            HANDLE_CANCELLED.store(err.is_cancelled() && !err.is_panic(), Ordering::SeqCst);

            // The worker is still running after the panic.
            let _ = ringline::sleep(Duration::from_millis(10)).await;
            HANDLE_AFTER.store(true, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        HandlePanics
    }
}

/// A `JoinHandle` resolves to a panicked `JoinError` when its task panics, and
/// to a cancelled one after `abort`.
#[test]
fn a_join_handle_reports_panics_and_aborts() {
    let (_runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<HandlePanics>()
        .expect("launch");
    let results = join_all(handles, Duration::from_secs(10));
    assert!(
        results.iter().all(|r| r.is_ok()),
        "Contain does not fail a worker"
    );
    assert!(
        HANDLE_PANICKED.load(Ordering::SeqCst),
        "panic not reported as JoinError"
    );
    assert!(
        HANDLE_CANCELLED.load(Ordering::SeqCst),
        "abort not reported as cancelled"
    );
    assert!(
        HANDLE_AFTER.load(Ordering::SeqCst),
        "the worker stopped after the panic"
    );
}

// ── TaskPanicPolicy ────────────────────────────────────────────────────

static CONTAIN_ALIVE: AtomicBool = AtomicBool::new(false);

struct ContainedPanic;

impl AsyncEventHandler for ContainedPanic {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            ringline::spawn(async { panic!("boom contained") }).expect("spawn");
            let _ = ringline::sleep(Duration::from_millis(50)).await;
            CONTAIN_ALIVE.store(true, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        ContainedPanic
    }
}

/// Under `Contain`, a task panic leaves the worker running.
#[test]
fn contain_keeps_the_runtime_running() {
    let (_runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<ContainedPanic>()
        .expect("launch");
    let results = join_all(handles, Duration::from_secs(10));
    assert!(results.iter().all(|r| r.is_ok()));
    assert!(
        CONTAIN_ALIVE.load(Ordering::SeqCst),
        "the worker stopped after the panic"
    );
}

/// Panics in a spawned task on worker 0 only; worker 1 idles.
struct PanicOnWorkerZero {
    id: usize,
}

impl AsyncEventHandler for PanicOnWorkerZero {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        if self.id != 0 {
            return None;
        }
        Some(Box::pin(async {
            let _ = ringline::sleep(Duration::from_millis(20)).await;
            ringline::spawn(async { panic!("boom shutdown") }).expect("spawn");
        }))
    }

    fn create_for_worker(id: usize) -> Self {
        PanicOnWorkerZero { id }
    }
}

/// Under `Shutdown`, a task panic stops every worker without
/// `Runtime::shutdown`, and only the panicking worker returns the panic.
#[test]
fn shutdown_stops_every_worker_and_reports_the_panic() {
    let (_runtime, handles) = RinglineBuilder::new(config(2, TaskPanicPolicy::Shutdown))
        .launch::<PanicOnWorkerZero>()
        .expect("launch");
    let mut results = join_all(handles, Duration::from_secs(10));
    let worker_one = results.pop().expect("two workers");
    let worker_zero = results.pop().expect("two workers");
    assert!(
        worker_one.is_ok(),
        "the other worker drains and exits cleanly"
    );
    match worker_zero {
        Err(ringline::Error::TaskPanicked(err)) => {
            assert!(err.is_panic());
            assert_eq!(err.panic_message(), Some("boom shutdown"));
            let payload = err.into_panic();
            assert_eq!(
                payload.downcast_ref::<String>().map(String::as_str),
                Some("boom shutdown"),
                "the payload is the panic message, to re-raise"
            );
        }
        other => panic!("worker 0 should return TaskPanicked, got {other:?}"),
    }
}

struct BlockingPanicShutdown;

impl AsyncEventHandler for BlockingPanicShutdown {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let _ = ringline::spawn_blocking(|| -> u32 { panic!("boom blocking shutdown") })
                .expect("spawn_blocking")
                .await;
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        BlockingPanicShutdown
    }
}

/// Under `Shutdown`, a `spawn_blocking` panic also stops the runtime.
#[test]
fn shutdown_covers_blocking_panics() {
    let (_runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Shutdown))
        .launch::<BlockingPanicShutdown>()
        .expect("launch");
    let results = join_all(handles, Duration::from_secs(10));
    match &results[0] {
        Err(ringline::Error::TaskPanicked(err)) => {
            assert_eq!(err.panic_message(), Some("boom blocking shutdown"));
        }
        other => panic!("the worker should return TaskPanicked, got {other:?}"),
    }
}

// ── JoinHandle cancellation ────────────────────────────────────────────

static FINISHED_ABORT_OTHER_RAN: AtomicBool = AtomicBool::new(false);
static FINISHED_ABORT_RESULT: Mutex<Option<u32>> = Mutex::new(None);

struct AbortAfterFinish;

impl AsyncEventHandler for AbortAfterFinish {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let mut handle = ringline::spawn_with_handle(async { 1u32 }).expect("spawn");
            // The task finishes and its slot is freed.
            let _ = ringline::sleep(Duration::from_millis(5)).await;
            // An unrelated task can reuse the slot.
            ringline::spawn(async {
                let _ = ringline::sleep(Duration::from_millis(5)).await;
                FINISHED_ABORT_OTHER_RAN.store(true, Ordering::SeqCst);
            })
            .expect("spawn");
            handle.abort();
            *FINISHED_ABORT_RESULT.lock().unwrap() = (&mut handle).await.ok();
            let _ = ringline::sleep(Duration::from_millis(30)).await;
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        AbortAfterFinish
    }
}

/// `abort` on a handle whose task already finished keeps the result and does
/// not cancel a task that reused the slot.
#[test]
fn abort_after_the_task_finished_cancels_nothing() {
    let (_runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<AbortAfterFinish>()
        .expect("launch");
    join_all(handles, Duration::from_secs(10));
    assert_eq!(*FINISHED_ABORT_RESULT.lock().unwrap(), Some(1));
    assert!(
        FINISHED_ABORT_OTHER_RAN.load(Ordering::SeqCst),
        "abort of a finished handle cancelled an unrelated task"
    );
}

static ID_CANCEL_RESOLVED: AtomicBool = AtomicBool::new(false);
static OTHER_ABORT_CANCELLED: AtomicBool = AtomicBool::new(false);

struct CancelPaths;

impl AsyncEventHandler for CancelPaths {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            // Cancelled through the TaskId.
            let handle = ringline::spawn_with_handle(std::future::pending::<u32>()).expect("spawn");
            handle.id().cancel();
            let resolved = ringline::timeout(Duration::from_millis(500), handle).await;
            ID_CANCEL_RESOLVED.store(
                matches!(resolved, Ok(Err(ref e)) if e.is_cancelled()),
                Ordering::SeqCst,
            );

            // Aborted by another task while this one awaits the handle.
            let handle = std::rc::Rc::new(std::cell::RefCell::new(
                ringline::spawn_with_handle(std::future::pending::<u32>()).expect("spawn"),
            ));
            let aborter = handle.clone();
            ringline::spawn(async move {
                let _ = ringline::sleep(Duration::from_millis(20)).await;
                aborter.borrow().abort();
            })
            .expect("spawn");
            let awaited = std::future::poll_fn(|cx| Pin::new(&mut *handle.borrow_mut()).poll(cx));
            let resolved = ringline::timeout(Duration::from_millis(500), awaited).await;
            OTHER_ABORT_CANCELLED.store(
                matches!(resolved, Ok(Err(ref e)) if e.is_cancelled()),
                Ordering::SeqCst,
            );
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        CancelPaths
    }
}

/// Cancelling through `JoinHandle::id().cancel()`, or aborting from another
/// task while one awaits, resolves the handle as cancelled.
#[test]
fn every_cancellation_resolves_the_handle() {
    let (_runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<CancelPaths>()
        .expect("launch");
    join_all(handles, Duration::from_secs(10));
    assert!(
        ID_CANCEL_RESOLVED.load(Ordering::SeqCst),
        "TaskId::cancel left the handle pending"
    );
    assert!(
        OTHER_ABORT_CANCELLED.load(Ordering::SeqCst),
        "abort from another task did not wake the awaiter"
    );
}

// ── Panics in handler calls ────────────────────────────────────────────

struct OnStartCallPanics;

impl AsyncEventHandler for OnStartCallPanics {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        panic!("boom in on_start call")
    }

    fn create_for_worker(_id: usize) -> Self {
        OnStartCallPanics
    }
}

/// A panic in the `on_start` call itself, before it returns a future, is a
/// task panic: contained under `Contain`, a shutdown under `Shutdown`.
#[test]
fn a_panic_in_the_on_start_call_follows_the_policy() {
    let (runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<OnStartCallPanics>()
        .expect("launch");
    std::thread::sleep(Duration::from_millis(100));
    drop(runtime);
    let results = join_all(handles, Duration::from_secs(10));
    assert!(results[0].is_ok(), "Contain: the worker survives");

    let (_runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Shutdown))
        .launch::<OnStartCallPanics>()
        .expect("launch");
    let results = join_all(handles, Duration::from_secs(10));
    assert!(
        matches!(&results[0], Err(ringline::Error::TaskPanicked(e)) if e.panic_message() == Some("boom in on_start call")),
        "Shutdown: got {:?}",
        results[0]
    );
}

static ACCEPT_BUILDS: AtomicU32 = AtomicU32::new(0);
static ACCEPT_LOCK: Mutex<()> = Mutex::new(());

/// Panics while building the first connection's future, then serves.
struct AcceptBuildPanics;

impl AsyncEventHandler for AcceptBuildPanics {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        if ACCEPT_BUILDS.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("boom building on_accept");
        }
        async {}
    }

    fn create_for_worker(_id: usize) -> Self {
        AcceptBuildPanics
    }
}

fn run_accept_build_panic(policy: TaskPanicPolicy) -> (Vec<Result<(), ringline::Error>>, u32) {
    ACCEPT_BUILDS.store(0, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config(1, policy))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<AcceptBuildPanics>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let _first = std::net::TcpStream::connect(addr).expect("connect");
    std::thread::sleep(Duration::from_millis(100));
    let _second = std::net::TcpStream::connect(addr);
    std::thread::sleep(Duration::from_millis(100));
    let builds = ACCEPT_BUILDS.load(Ordering::SeqCst);
    drop(runtime);
    (join_all(handles, Duration::from_secs(10)), builds)
}

/// A panic while building the `on_accept` future closes that connection.
/// Under `Contain` the worker serves the next one; under `Shutdown` it
/// returns the panic. Both backends.
#[test]
fn a_panic_building_on_accept_follows_the_policy() {
    let _lock = ACCEPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (results, builds) = run_accept_build_panic(TaskPanicPolicy::Contain);
    assert!(
        results[0].is_ok(),
        "Contain: the worker survives: {:?}",
        results[0]
    );
    assert_eq!(builds, 2, "Contain: the second connection was not served");

    let (results, _) = run_accept_build_panic(TaskPanicPolicy::Shutdown);
    assert!(
        matches!(&results[0], Err(ringline::Error::TaskPanicked(e)) if e.panic_message() == Some("boom building on_accept")),
        "Shutdown: got {:?}",
        results[0]
    );
}

static TICKS: AtomicU32 = AtomicU32::new(0);

struct TickPanics;

impl AsyncEventHandler for TickPanics {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_tick(&mut self) {
        if TICKS.fetch_add(1, Ordering::SeqCst) == 3 {
            panic!("boom in on_tick");
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        TickPanics
    }
}

/// Under `Shutdown`, an `on_tick` panic stops every worker.
#[test]
fn shutdown_covers_on_tick() {
    let (_runtime, handles) = RinglineBuilder::new(config(2, TaskPanicPolicy::Shutdown))
        .launch::<TickPanics>()
        .expect("launch");
    let results = join_all(handles, Duration::from_secs(10));
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(ringline::Error::TaskPanicked(e)) if e.panic_message() == Some("boom in on_tick")))
            .count(),
        1,
        "exactly the worker that ticked into the panic returns it: {results:?}"
    );
}

/// A connection task that panics.
struct ConnectionPanics;

impl AsyncEventHandler for ConnectionPanics {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async { panic!("boom in connection task") }
    }

    fn create_for_worker(_id: usize) -> Self {
        ConnectionPanics
    }
}

/// Under `Shutdown`, a connection-task panic shuts the runtime down as
/// `Runtime::shutdown` does: with the `Runtime` still alive, the listener
/// refuses new connections and `wait_on_signal` returns `Signal::TaskPanic`.
///
/// `wait_on_signal` installs ringline's `SIGINT`/`SIGTERM` handlers, so after
/// this test Ctrl-C no longer stops this test binary.
#[test]
fn shutdown_stops_the_listener_and_wakes_wait_on_signal() {
    let (runtime, handles) = RinglineBuilder::new(config(2, TaskPanicPolicy::Shutdown))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ConnectionPanics>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let _client = std::net::TcpStream::connect(addr).expect("connect");
    let results = join_all(handles, Duration::from_secs(10));
    assert!(
        results
            .iter()
            .any(|r| matches!(r, Err(ringline::Error::TaskPanicked(_)))),
        "{results:?}"
    );

    #[cfg(target_os = "linux")]
    {
        let refused = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500));
        assert!(
            refused.is_err(),
            "the listener still accepts after a panic shut the runtime down"
        );
    }
    assert_eq!(
        runtime.wait_on_signal(),
        ringline::signal::Signal::TaskPanic
    );
}

/// (Display had no message, `panic_message`, payload as `u64`).
type PayloadObservation = (bool, Option<String>, Option<u64>);
static ANY_PAYLOAD: Mutex<Option<PayloadObservation>> = Mutex::new(None);

struct NonStringPanic;

impl AsyncEventHandler for NonStringPanic {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let err = ringline::spawn_with_handle(async { std::panic::panic_any(42u64) })
                .expect("spawn")
                .await
                .expect_err("the task panicked");
            let shown = err.to_string() == "task panicked";
            let message = err.panic_message().map(str::to_string);
            let payload = err.into_panic().downcast_ref::<u64>().copied();
            *ANY_PAYLOAD.lock().unwrap() = Some((shown, message, payload));
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        NonStringPanic
    }
}

/// A non-string panic payload has no message, displays without one, and is
/// returned intact by `into_panic`.
#[test]
fn a_non_string_panic_payload_is_kept_intact() {
    let (_runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<NonStringPanic>()
        .expect("launch");
    join_all(handles, Duration::from_secs(10));
    assert_eq!(
        *ANY_PAYLOAD.lock().unwrap(),
        Some((true, None, Some(42))),
        "(Display without a message, panic_message None, payload 42)"
    );
}

/// Under `Shutdown`, a task panic while `launch()` is still setting up its
/// listeners reports the panic: `launch()` fails with `TaskPanicked`, or
/// returns and the worker does.
#[test]
fn a_panic_during_launch_reports_the_panic() {
    for mode in [ringline::AcceptMode::Pool, ringline::AcceptMode::Merged] {
        for _ in 0..20 {
            let config = ConfigBuilder::new()
                .workers(1)
                .pin_to_core(false)
                .sq_entries(64)
                .max_connections(16)
                .send_pool(16, 16384)
                .blocking_threads(0)
                .resolver_threads(0)
                .spawner_threads(0)
                .accept_mode(mode)
                .task_panic_policy(TaskPanicPolicy::Shutdown)
                .build()
                .expect("valid config");
            let launched = RinglineBuilder::new(config)
                .bind("127.0.0.1:0".parse().unwrap())
                .launch::<OnStartCallPanics>();
            let reported = match launched {
                Err(ringline::Error::TaskPanicked(e)) => e.panic_message().map(str::to_string),
                Err(other) => panic!("{mode:?}: launch lost the panic: {other}"),
                Ok((_runtime, handles)) => {
                    match join_all(handles, Duration::from_secs(10)).remove(0) {
                        Err(ringline::Error::TaskPanicked(e)) => {
                            e.panic_message().map(str::to_string)
                        }
                        other => panic!("{mode:?}: worker lost the panic: {other:?}"),
                    }
                }
            };
            assert_eq!(reported.as_deref(), Some("boom in on_start call"));
        }
    }
}
