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
    type SetMode = fn(ConfigBuilder) -> ConfigBuilder;
    #[cfg(feature = "unstable-accept")]
    let modes: [(&str, SetMode); 2] = [
        ("Pool", |b| b.accept_mode(ringline::AcceptMode::Pool)),
        ("Merged", |b| b.accept_mode(ringline::AcceptMode::Merged)),
    ];
    #[cfg(not(feature = "unstable-accept"))]
    let modes: [(&str, SetMode); 1] = [("Pool", |b| b)];
    for (mode, set_mode) in modes {
        for _ in 0..20 {
            let config = set_mode(
                ConfigBuilder::new()
                    .workers(1)
                    .pin_to_core(false)
                    .sq_entries(64)
                    .max_connections(16)
                    .send_pool(16, 16384)
                    .blocking_threads(0)
                    .resolver_threads(0)
                    .spawner_threads(0),
            )
            .task_panic_policy(TaskPanicPolicy::Shutdown)
            .build()
            .expect("valid config");
            let launched = RinglineBuilder::new(config)
                .bind("127.0.0.1:0".parse().unwrap())
                .launch::<OnStartCallPanics>();
            let reported = match launched {
                Err(ringline::Error::TaskPanicked(e)) => e.panic_message().map(str::to_string),
                Err(other) => panic!("{mode}: launch lost the panic: {other}"),
                Ok((_runtime, handles)) => {
                    match join_all(handles, Duration::from_secs(10)).remove(0) {
                        Err(ringline::Error::TaskPanicked(e)) => {
                            e.panic_message().map(str::to_string)
                        }
                        other => panic!("{mode}: worker lost the panic: {other:?}"),
                    }
                }
            };
            assert_eq!(reported.as_deref(), Some("boom in on_start call"));
        }
    }
}

// ── a panic in a future's Drop ─────────────────────────────────────────

/// A future that panics when dropped, at the point its owner chooses: its poll
/// is `Ready` at once, or `Pending` for ever. An `async` block drops its locals
/// inside its last poll, so only a future like this one runs `Drop` afterwards.
struct PanicsOnDrop {
    ready: bool,
}

impl Future for PanicsOnDrop {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        if self.ready {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }
}

impl Drop for PanicsOnDrop {
    fn drop(&mut self) {
        // A panic while the thread unwinds would abort the process.
        if !std::thread::panicking() {
            panic!("boom in drop");
        }
    }
}

static DROP_ACCEPTS: AtomicU32 = AtomicU32::new(0);
static DROP_LOCK: Mutex<()> = Mutex::new(());

/// The first connection's task panics in `Drop`, `ready` deciding when it
/// drops. Later connections hold their task open until the peer closes.
struct DropPanics<const READY: bool>;

impl<const READY: bool> AsyncEventHandler for DropPanics<READY> {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        let first = DROP_ACCEPTS.fetch_add(1, Ordering::SeqCst) == 0;
        DropTask {
            inner: (!first).then(|| {
                Box::pin(async move {
                    let mut conn = conn;
                    let _ = conn
                        .with_data(|d| ringline::ParseResult::Consumed(d.len()))
                        .await;
                }) as Pin<Box<dyn Future<Output = ()>>>
            }),
            bomb: first.then_some(PanicsOnDrop { ready: READY }),
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        DropPanics
    }
}

struct DropTask {
    inner: Option<Pin<Box<dyn Future<Output = ()>>>>,
    bomb: Option<PanicsOnDrop>,
}

impl Future for DropTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        if let Some(bomb) = &self.bomb {
            return if bomb.ready {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            };
        }
        self.inner.as_mut().unwrap().as_mut().poll(cx)
    }
}

/// A panic in `Drop` costs no worker: the next connection on the same worker is
/// accepted, and the worker exits cleanly.
fn run_drop_panic<H: AsyncEventHandler>(
    policy: TaskPanicPolicy,
    close_first: bool,
) -> (Vec<Result<(), ringline::Error>>, u32) {
    DROP_ACCEPTS.store(0, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config(1, policy))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let first = std::net::TcpStream::connect(addr).expect("connect");
    std::thread::sleep(Duration::from_millis(100));
    if close_first {
        drop(first);
        std::thread::sleep(Duration::from_millis(100));
    } else {
        std::mem::forget(first);
    }
    let second = std::net::TcpStream::connect(addr);
    std::thread::sleep(Duration::from_millis(100));
    let accepts = DROP_ACCEPTS.load(Ordering::SeqCst);
    drop(second);
    if policy == TaskPanicPolicy::Shutdown {
        // The runtime still lives, so only the panic can stop the worker.
        assert!(
            finishes_within(&handles, Duration::from_secs(5)),
            "the panic did not shut the runtime down"
        );
    }
    drop(runtime);
    (join_all(handles, Duration::from_secs(15)), accepts)
}

/// Whether every worker exits within `within`.
fn finishes_within(handles: &[JoinHandle<Result<(), ringline::Error>>], within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while !handles.iter().all(|h| h.is_finished()) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

#[test]
fn a_panic_in_drop_after_ready_costs_no_worker() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (results, accepts) = run_drop_panic::<DropPanics<true>>(TaskPanicPolicy::Contain, false);
    assert!(results[0].is_ok(), "{:?}", results[0]);
    assert_eq!(accepts, 2, "the worker stopped accepting");
}

#[test]
fn a_panic_in_drop_after_ready_follows_the_shutdown_policy() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (results, _) = run_drop_panic::<DropPanics<true>>(TaskPanicPolicy::Shutdown, false);
    assert!(
        matches!(&results[0], Err(ringline::Error::TaskPanicked(e)) if e.panic_message() == Some("boom in drop")),
        "{:?}",
        results[0]
    );
}

/// The peer's close drops the parked task from a completion handler.
#[test]
fn a_panic_in_drop_when_the_connection_closes_costs_no_worker() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (results, accepts) = run_drop_panic::<DropPanics<false>>(TaskPanicPolicy::Contain, true);
    assert!(results[0].is_ok(), "{:?}", results[0]);
    assert_eq!(accepts, 2, "the worker stopped accepting");
}

static EXIT_STARTED: AtomicU32 = AtomicU32::new(0);

/// Two tasks parked for the worker to drop at exit.
struct ParkedBombs;

impl AsyncEventHandler for ParkedBombs {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        std::future::ready(())
    }
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            for _ in 0..2 {
                ringline::spawn(PanicsOnDrop { ready: false }).expect("spawn");
            }
            ringline::sleep(Duration::from_millis(1)).await;
            EXIT_STARTED.fetch_add(1, Ordering::SeqCst);
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        ParkedBombs
    }
}

fn run_exit_panics(policy: TaskPanicPolicy) -> Result<(), ringline::Error> {
    EXIT_STARTED.store(0, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config(1, policy))
        .launch::<ParkedBombs>()
        .expect("launch");
    let deadline = Instant::now() + Duration::from_secs(5);
    while EXIT_STARTED.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        EXIT_STARTED.load(Ordering::SeqCst),
        1,
        "the tasks were not spawned"
    );
    drop(runtime);
    join_all(handles, Duration::from_secs(15)).remove(0)
}

/// An uncaught panic from the first task would unwind through the slab's
/// `Drop`, and the second would abort.
#[test]
fn panics_in_drop_at_worker_exit_are_caught() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let result = run_exit_panics(TaskPanicPolicy::Contain);
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn panics_in_drop_at_worker_exit_follow_the_shutdown_policy() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let result = run_exit_panics(TaskPanicPolicy::Shutdown);
    assert!(
        matches!(&result, Err(ringline::Error::TaskPanicked(e)) if e.panic_message() == Some("boom in drop")),
        "{result:?}"
    );
}

static LATER_TASK_RAN: AtomicBool = AtomicBool::new(false);

/// A task that panics in its poll, and whose `Drop` panics once its poll has.
struct PanicsTwice {
    _bomb: PanicsOnDrop,
}

impl Future for PanicsTwice {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        panic!("boom in poll")
    }
}

/// Which way a standalone task's `Drop` is reached.
#[derive(Clone, Copy)]
enum StandaloneDrop {
    Ready,
    AfterPollPanic,
    Abort,
}

static STANDALONE_DROP: AtomicU32 = AtomicU32::new(0);

struct StandaloneDrops;

impl AsyncEventHandler for StandaloneDrops {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        std::future::ready(())
    }
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            match STANDALONE_DROP.load(Ordering::SeqCst) {
                0 => drop(ringline::spawn(PanicsOnDrop { ready: true })),
                1 => {
                    drop(ringline::spawn(PanicsTwice {
                        _bomb: PanicsOnDrop { ready: true },
                    }));
                }
                _ => {
                    let handle =
                        ringline::spawn_with_handle(PanicsOnDrop { ready: false }).expect("spawn");
                    ringline::sleep(Duration::from_millis(5)).await;
                    handle.abort();
                }
            }
            ringline::sleep(Duration::from_millis(20)).await;
            LATER_TASK_RAN.store(true, Ordering::SeqCst);
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        StandaloneDrops
    }
}

fn run_standalone_drop(
    way: StandaloneDrop,
    policy: TaskPanicPolicy,
) -> Result<(), ringline::Error> {
    LATER_TASK_RAN.store(false, Ordering::SeqCst);
    STANDALONE_DROP.store(way as u32, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config(1, policy))
        .launch::<StandaloneDrops>()
        .expect("launch");
    let deadline = Instant::now() + Duration::from_secs(2);
    if policy == TaskPanicPolicy::Shutdown {
        assert!(
            finishes_within(&handles, Duration::from_secs(5)),
            "the panic did not shut the runtime down"
        );
    }
    while !LATER_TASK_RAN.load(Ordering::SeqCst)
        && !handles[0].is_finished()
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(runtime);
    join_all(handles, Duration::from_secs(15)).remove(0)
}

#[test]
fn a_panic_in_a_standalone_tasks_drop_costs_no_worker() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for way in [
        StandaloneDrop::Ready,
        StandaloneDrop::AfterPollPanic,
        StandaloneDrop::Abort,
    ] {
        let result = run_standalone_drop(way, TaskPanicPolicy::Contain);
        assert!(result.is_ok(), "{result:?}");
        assert!(LATER_TASK_RAN.load(Ordering::SeqCst), "the worker stopped");
    }
}

/// `Shutdown` sees a panic that reaches the event loop by way of the slab.
#[test]
fn a_panic_in_an_aborted_tasks_drop_follows_the_shutdown_policy() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let result = run_standalone_drop(StandaloneDrop::Abort, TaskPanicPolicy::Shutdown);
    assert!(
        matches!(&result, Err(ringline::Error::TaskPanicked(e)) if e.panic_message() == Some("boom in drop")),
        "{result:?}"
    );
}

#[test]
fn a_panic_in_drop_when_the_connection_closes_follows_the_shutdown_policy() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (results, _) = run_drop_panic::<DropPanics<false>>(TaskPanicPolicy::Shutdown, true);
    assert!(
        matches!(&results[0], Err(ringline::Error::TaskPanicked(e)) if e.panic_message() == Some("boom in drop")),
        "{:?}",
        results[0]
    );
}

/// A connection task that panics in its poll and in its `Drop` costs the
/// connection and no worker.
#[test]
fn a_panic_in_drop_after_a_poll_panic_costs_no_worker() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    struct PollAndDrop;
    impl AsyncEventHandler for PollAndDrop {
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            DROP_ACCEPTS.fetch_add(1, Ordering::SeqCst);
            PanicsTwice {
                _bomb: PanicsOnDrop { ready: true },
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            PollAndDrop
        }
    }
    let (results, accepts) = run_drop_panic::<PollAndDrop>(TaskPanicPolicy::Contain, false);
    assert!(results[0].is_ok(), "{:?}", results[0]);
    assert_eq!(accepts, 2, "the worker stopped accepting");
}

/// A guard's `Drop` runs in a completion handler when the kernel finishes with
/// it, outside any task.
#[cfg(has_io_uring)]
#[test]
fn a_panic_in_a_guards_drop_costs_no_worker() {
    use std::io::{Read, Write};

    use ringline::{GuardBox, ParseResult, RegionId, SendGuard};

    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    static PANIC_NEXT: AtomicBool = AtomicBool::new(true);

    struct PanickingGuard(Vec<u8>);
    impl SendGuard for PanickingGuard {
        fn as_ptr_len(&self) -> (*const u8, u32) {
            (self.0.as_ptr(), self.0.len() as u32)
        }
        fn region(&self) -> RegionId {
            RegionId::UNREGISTERED
        }
    }
    impl Drop for PanickingGuard {
        fn drop(&mut self) {
            if PANIC_NEXT.swap(false, Ordering::SeqCst) {
                panic!("boom in guard drop");
            }
        }
    }

    struct GuardEcho;
    impl AsyncEventHandler for GuardEcho {
        fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                while conn.with_data(|d| ParseResult::Consumed(d.len())).await > 0 {
                    let guard = GuardBox::new(PanickingGuard(vec![7; 8192]));
                    conn.send_parts()
                        .build(|b| b.guard(guard).submit())
                        .expect("guard send accepted");
                }
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            GuardEcho
        }
    }

    let (runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<GuardEcho>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    for _ in 0..2 {
        let mut peer = std::net::TcpStream::connect(addr).expect("connect");
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.write_all(b"x").unwrap();
        let mut body = [0u8; 8192];
        peer.read_exact(&mut body).expect("the guard's bytes");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!PANIC_NEXT.load(Ordering::SeqCst), "no guard panicked");
    assert!(
        !handles[0].is_finished(),
        "the guard's panic ended the worker"
    );
    drop(runtime);
    let results = join_all(handles, Duration::from_secs(15));
    assert!(results[0].is_ok(), "{:?}", results[0]);
}

/// A `spawn_blocking` result reaches the event loop after its future was
/// dropped, and the event loop drops it.
#[test]
fn a_panic_in_an_abandoned_blocking_results_drop_costs_no_worker() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    static RESULT_MADE: AtomicBool = AtomicBool::new(false);

    struct PanicsWhenDropped;
    impl Drop for PanicsWhenDropped {
        fn drop(&mut self) {
            panic!("boom in result drop");
        }
    }

    struct AbandonsBlocking;
    impl AsyncEventHandler for AbandonsBlocking {
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            std::future::ready(())
        }
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async {
                let handle = ringline::spawn_blocking(|| {
                    std::thread::sleep(Duration::from_millis(50));
                    RESULT_MADE.store(true, Ordering::SeqCst);
                    PanicsWhenDropped
                })
                .expect("spawn_blocking");
                drop(handle);
            }))
        }
        fn create_for_worker(_id: usize) -> Self {
            AbandonsBlocking
        }
    }

    let (runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<AbandonsBlocking>()
        .expect("launch");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !RESULT_MADE.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(100));
    assert!(!handles[0].is_finished(), "the panic ended the worker");
    drop(runtime);
    let results = join_all(handles, Duration::from_secs(15));
    assert!(results[0].is_ok(), "{:?}", results[0]);
}

static RESULT_DROPPED: AtomicBool = AtomicBool::new(false);

struct PanicsWhenDropped;

impl Drop for PanicsWhenDropped {
    fn drop(&mut self) {
        RESULT_DROPPED.store(true, Ordering::SeqCst);
        panic!("boom in result drop");
    }
}

/// Holds a delivered `spawn_blocking` result in its handle until the runtime
/// drops the task.
async fn hold_a_delivered_result() {
    let _handle = ringline::spawn_blocking(|| PanicsWhenDropped).expect("spawn_blocking");
    ringline::sleep(Duration::from_secs(3600)).await;
}

/// The peer's close drops the task from a completion handler, and the event
/// loop releases the result outside any task.
#[test]
fn a_panic_in_a_delivered_blocking_results_drop_costs_no_worker() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    struct Holds;
    impl AsyncEventHandler for Holds {
        fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let _handle =
                    ringline::spawn_blocking(|| PanicsWhenDropped).expect("spawn_blocking");
                while conn
                    .with_data(|d| ringline::ParseResult::Consumed(d.len()))
                    .await
                    > 0
                {}
                ringline::sleep(Duration::from_secs(3600)).await;
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            Holds
        }
    }
    RESULT_DROPPED.store(false, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Holds>()
        .expect("launch");
    let peer = std::net::TcpStream::connect(runtime.bound_addr().unwrap()).expect("connect");
    std::thread::sleep(Duration::from_millis(100));
    drop(peer);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !RESULT_DROPPED.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        RESULT_DROPPED.load(Ordering::SeqCst),
        "the result was not dropped"
    );
    assert!(!handles[0].is_finished(), "the panic ended the worker");
    drop(runtime);
    let results = join_all(handles, Duration::from_secs(15));
    assert!(results[0].is_ok(), "{:?}", results[0]);
}

/// A delivered result still held at worker exit.
#[test]
fn a_panic_in_a_held_blocking_results_drop_at_worker_exit_is_caught() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    struct HoldsAtExit;
    impl AsyncEventHandler for HoldsAtExit {
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            std::future::ready(())
        }
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(hold_a_delivered_result()))
        }
        fn create_for_worker(_id: usize) -> Self {
            HoldsAtExit
        }
    }
    RESULT_DROPPED.store(false, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<HoldsAtExit>()
        .expect("launch");
    std::thread::sleep(Duration::from_millis(100));
    drop(runtime);
    let results = join_all(handles, Duration::from_secs(15));
    assert!(results[0].is_ok(), "{:?}", results[0]);
    assert!(
        RESULT_DROPPED.load(Ordering::SeqCst),
        "the result was not dropped"
    );
}

/// The pool sends the result while the worker drops its tasks.
#[test]
fn a_panic_in_a_blocking_result_queued_at_worker_exit_is_caught() {
    let _lock = DROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    static RELEASE: AtomicBool = AtomicBool::new(false);

    struct ReleasesWhenDropped;
    impl Drop for ReleasesWhenDropped {
        fn drop(&mut self) {
            RELEASE.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    struct QueuesAtExit;
    impl AsyncEventHandler for QueuesAtExit {
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            std::future::ready(())
        }
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async {
                let _release = ReleasesWhenDropped;
                let _handle = ringline::spawn_blocking(|| {
                    while !RELEASE.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    PanicsWhenDropped
                })
                .expect("spawn_blocking");
                ringline::sleep(Duration::from_secs(3600)).await;
            }))
        }
        fn create_for_worker(_id: usize) -> Self {
            QueuesAtExit
        }
    }

    RELEASE.store(false, Ordering::SeqCst);
    RESULT_DROPPED.store(false, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config(1, TaskPanicPolicy::Contain))
        .launch::<QueuesAtExit>()
        .expect("launch");
    std::thread::sleep(Duration::from_millis(50));
    drop(runtime);
    let results = join_all(handles, Duration::from_secs(15));
    assert!(results[0].is_ok(), "{:?}", results[0]);
    assert!(
        RESULT_DROPPED.load(Ordering::SeqCst),
        "the result was not dropped"
    );
}
