#![allow(clippy::manual_async_fn)]
//! A task that cancels itself mid-poll. Its future is checked out of the slab,
//! so the slot has to stay taken until the poll returns. Freeing it at the
//! cancel let the parked future land in a freed slot, which double-freed the
//! index and could overwrite a task spawned into it.

mod common;

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder, TaskId, TaskPanicPolicy,
};

const LIMIT: Duration = Duration::from_secs(5);

type Body = fn() -> Pin<Box<dyn Future<Output = ()>>>;

fn run(body: Body) {
    static SERIAL: Mutex<()> = Mutex::new(());
    static BODY: Mutex<Option<Body>> = Mutex::new(None);
    static FINISHED: AtomicBool = AtomicBool::new(false);

    struct Handler;
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            async {}
        }
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            let body = BODY.lock().unwrap().expect("set before launch");
            Some(Box::pin(async move {
                body().await;
                FINISHED.store(true, Ordering::SeqCst);
                let _ = ringline::request_shutdown();
            }))
        }
        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    FINISHED.store(false, Ordering::SeqCst);
    *BODY.lock().unwrap_or_else(|e| e.into_inner()) = Some(body);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .standalone_task_capacity(8)
        .task_panic_policy(TaskPanicPolicy::Contain)
        .resolver_threads(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Handler>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    assert!(
        FINISHED.load(Ordering::SeqCst),
        "the on_start task ended early"
    );
}

/// Spawn a task that cancels itself, sleeps, then sets `ran_on`.
fn spawn_self_cancelling(ran_on: Rc<Cell<bool>>) {
    let own_id: Rc<Cell<Option<TaskId>>> = Rc::new(Cell::new(None));
    let id = own_id.clone();
    let task = ringline::spawn(async move {
        id.get().expect("set before the first poll").cancel();
        ringline::sleep(Duration::from_millis(5)).await;
        ran_on.set(true);
    })
    .unwrap();
    own_id.set(Some(task));
}

/// The future is dropped when the poll returns, so nothing runs past the await.
#[test]
fn a_cancelled_task_does_not_run_past_its_await() {
    run(|| {
        Box::pin(async {
            let ran_on = Rc::new(Cell::new(false));
            spawn_self_cancelling(ran_on.clone());
            ringline::sleep(Duration::from_millis(30)).await;
            assert!(!ran_on.get(), "the task ran after cancelling itself");
        })
    });
}

/// The index is freed exactly once: the slab holds its full capacity afterwards,
/// with no id twice.
#[test]
fn a_self_cancelled_slot_is_freed_once() {
    run(|| {
        Box::pin(async {
            let ran_on = Rc::new(Cell::new(false));
            spawn_self_cancelling(ran_on);
            ringline::sleep(Duration::from_millis(30)).await;
            let mut ids = Vec::new();
            while let Ok(id) = ringline::spawn(std::future::pending::<()>()) {
                assert!(!ids.contains(&id), "one slot was handed out twice");
                ids.push(id);
            }
            // Capacity 8, less this on_start task.
            assert_eq!(ids.len(), 7, "the self-cancelled slot was not freed");
            ids.into_iter().for_each(TaskId::cancel);
        })
    });
}

/// A task spawned after a self-cancel, in the same poll, keeps its own slot.
#[test]
fn a_task_spawned_by_a_cancelling_task_runs() {
    run(|| {
        Box::pin(async {
            let ran = Rc::new(Cell::new(false));
            let own_id: Rc<Cell<Option<TaskId>>> = Rc::new(Cell::new(None));
            let id = own_id.clone();
            let flag = ran.clone();
            let task = ringline::spawn(async move {
                id.get().expect("set before the first poll").cancel();
                ringline::spawn(async move { flag.set(true) }).unwrap();
                std::future::pending::<()>().await;
            })
            .unwrap();
            own_id.set(Some(task));
            ringline::sleep(Duration::from_millis(30)).await;
            assert!(ran.get(), "the spawned task was lost");
        })
    });
}

/// A handle on a task that aborts itself resolves as cancelled once the poll
/// returns, with no later spawn needed.
#[test]
fn a_handle_on_a_self_aborted_task_resolves() {
    run(|| {
        Box::pin(async {
            type Shared = Rc<Cell<Option<Rc<ringline::JoinHandle<u32>>>>>;
            let own: Shared = Rc::new(Cell::new(None));
            let in_task = own.clone();
            let handle = Rc::new(
                ringline::spawn_with_handle(async move {
                    in_task.take().expect("set before the first poll").abort();
                    std::future::pending::<u32>().await
                })
                .unwrap(),
            );
            own.set(Some(handle.clone()));
            // The task drops its clone in its first poll.
            ringline::yield_now().await;
            let handle = Rc::into_inner(handle).expect("the task's clone has gone");
            let outcome = ringline::timeout(LIMIT, handle)
                .await
                .expect("the handle never resolved");
            assert!(outcome.expect_err("the task was aborted").is_cancelled());
        })
    });
}

/// A task that aborts itself and returns before it yields keeps its outcome.
#[test]
fn a_self_aborted_task_that_finishes_keeps_its_outcome() {
    run(|| {
        Box::pin(async {
            let own_id: Rc<Cell<Option<TaskId>>> = Rc::new(Cell::new(None));
            let id = own_id.clone();
            let handle = ringline::spawn_with_handle(async move {
                id.get().expect("set before the first poll").cancel();
                7u32
            })
            .unwrap();
            own_id.set(Some(handle.id()));
            let outcome = ringline::timeout(LIMIT, handle)
                .await
                .expect("the handle never resolved");
            assert_eq!(outcome.expect("the task finished"), 7);
        })
    });
}

/// A panic in the `Drop` of a self-cancelled future does not end the worker.
#[test]
fn a_panic_dropping_a_self_cancelled_future_is_contained() {
    run(|| {
        Box::pin(async {
            struct PanicsOnDrop;
            impl Drop for PanicsOnDrop {
                fn drop(&mut self) {
                    panic!("drop of a self-cancelled future");
                }
            }
            let own_id: Rc<Cell<Option<TaskId>>> = Rc::new(Cell::new(None));
            let id = own_id.clone();
            let task = ringline::spawn(async move {
                let _held = PanicsOnDrop;
                id.get().expect("set before the first poll").cancel();
                std::future::pending::<()>().await;
            })
            .unwrap();
            own_id.set(Some(task));
            // This task outlives the panic, so the worker did too.
            ringline::sleep(Duration::from_millis(30)).await;
            let again = ringline::spawn(async {}).unwrap();
            let _ = again;
        })
    });
}
