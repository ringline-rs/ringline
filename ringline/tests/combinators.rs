#![allow(clippy::manual_async_fn)]
//! Ringline's futures inside combinators that poll a child only when the
//! child's own waker fires, such as `FuturesUnordered` and `Shared` (#641).
//!
//! A ringline future's completion wakes the task that polled it, by task id.
//! Each test waits under a `ringline::timeout`, so a child that is never
//! polled again fails the test rather than hanging it.

mod common;

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::Poll;
use std::time::Duration;

use futures_util::future::{FutureExt, LocalBoxFuture, Shared};
use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::{AsyncBufReadExt, AsyncReadExt};
use ringline::{
    AsyncEventHandler, CancellationToken, ConfigBuilder, ConnStream, Connection, ParseResult,
    RinglineBuilder,
};

const LIMIT: Duration = Duration::from_secs(5);

fn config() -> ringline::Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(64, 16384)
        .blocking_threads(1)
        .resolver_threads(1)
        .build()
        .expect("valid config")
}

/// Drain `children` and return how many completed before [`LIMIT`].
async fn completed(children: Vec<LocalBoxFuture<'_, ()>>) -> usize {
    let total = children.len();
    let mut unordered: FuturesUnordered<_> = children.into_iter().collect();
    let done = Rc::new(Cell::new(0));
    let counted = done.clone();
    let _ = ringline::timeout(LIMIT, async move {
        while unordered.next().await.is_some() {
            counted.set(counted.get() + 1);
        }
    })
    .await;
    assert!(done.get() <= total);
    done.get()
}

type Body = fn() -> LocalBoxFuture<'static, ()>;

/// Run `body` as a worker's `on_start` task, and fail if it does not finish.
fn run_on_start(body: Body) {
    // One handler type reads these, so the tests that use them run one at a
    // time under `cargo test`, which shares a process between tests.
    static SERIAL: Mutex<()> = Mutex::new(());
    static FINISHED: AtomicBool = AtomicBool::new(false);
    static BODY: Mutex<Option<Body>> = Mutex::new(None);

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
    let (runtime, handles) = RinglineBuilder::new(config())
        .launch::<Handler>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    assert!(
        FINISHED.load(Ordering::SeqCst),
        "the on_start task ended early"
    );
}

/// The reproduction in #641, with a sequential sleep as the control.
#[test]
fn sleeps_complete_in_futures_unordered() {
    run_on_start(|| {
        Box::pin(async {
            ringline::sleep(Duration::from_millis(5)).await;
            let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                ringline::sleep(Duration::from_millis(20)).boxed_local(),
                ringline::sleep(Duration::from_millis(40)).boxed_local(),
            ];
            assert_eq!(completed(children).await, 2);
        })
    });
}

/// A sleep polled again after it completed runs again, as a new timer.
#[test]
fn a_sleep_polled_after_it_completed_runs_again() {
    run_on_start(|| {
        Box::pin(async {
            let mut sleep = ringline::sleep(Duration::from_millis(5));
            (&mut sleep).await;
            let again = ringline::timeout(LIMIT, poll_fn(|cx| Pin::new(&mut sleep).poll(cx))).await;
            assert!(
                again.is_ok(),
                "a sleep polled after Ready never completed again"
            );
        })
    });
}

/// A sleep or deadline too far out for the clock does not fire and does not
/// panic: `Duration::MAX` overflowed the timespec on io_uring, which the kernel
/// refused, and `Instant` on mio (#836).
#[test]
fn a_sleep_of_duration_max_stays_pending() {
    run_on_start(|| {
        Box::pin(async {
            let short = Duration::from_millis(20);
            assert!(
                ringline::timeout(short, ringline::sleep(Duration::MAX))
                    .await
                    .is_err(),
                "sleep(Duration::MAX) completed"
            );
            let far = ringline::Deadline::after(Duration::MAX);
            assert!(
                ringline::timeout(short, ringline::sleep_until(far))
                    .await
                    .is_err(),
                "sleep_until(after(Duration::MAX)) completed"
            );
            assert_eq!(
                ringline::timeout(Duration::MAX, async { 7 }).await.ok(),
                Some(7)
            );
        })
    });
}

/// A connection task woken during its own poll is polled again: the wake is
/// recorded in its slot, and parking the task queues it.
#[test]
fn a_connection_task_woken_during_its_poll_is_polled_again() {
    static POLLED_AGAIN: AtomicBool = AtomicBool::new(false);

    struct Handler;
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            async {
                let token = CancellationToken::new();
                let mut cancelled = Box::pin(token.cancelled());
                let mut polls = 0;
                poll_fn(|cx| {
                    polls += 1;
                    if polls == 1 {
                        // Registers the task, which `cancel` then wakes by id.
                        assert!(cancelled.as_mut().poll(cx).is_pending());
                        token.cancel();
                        return Poll::Pending;
                    }
                    Poll::Ready(())
                })
                .await;
                POLLED_AGAIN.store(true, Ordering::SeqCst);
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Handler>()
        .expect("launch");
    let _client = TcpStream::connect(runtime.bound_addr().expect("bound")).unwrap();
    let deadline = std::time::Instant::now() + LIMIT;
    while !POLLED_AGAIN.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let polled_again = POLLED_AGAIN.load(Ordering::SeqCst);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    assert!(polled_again, "the connection task was not polled again");
}

/// `join_all` runs every child at once, waits for them all, and keeps their
/// order, whichever finishes first.
#[test]
fn join_all_returns_outputs_in_order() {
    run_on_start(|| {
        Box::pin(async {
            let delays = [30u64, 5, 15];
            let running = Rc::new(Cell::new(0));
            let most = Rc::new(Cell::new(0));
            let children = delays.iter().map(|&ms| {
                let running = running.clone();
                let most = most.clone();
                async move {
                    running.set(running.get() + 1);
                    most.set(most.get().max(running.get()));
                    ringline::sleep(Duration::from_millis(ms)).await;
                    running.set(running.get() - 1);
                    ms
                }
            });
            let outputs = ringline::timeout(LIMIT, ringline::join_all(children))
                .await
                .expect("join_all did not finish");
            assert_eq!(outputs, delays);
            assert_eq!(most.get(), delays.len(), "the children ran one at a time");
            let none = ringline::join_all(std::iter::empty::<std::future::Ready<()>>()).await;
            assert!(none.is_empty());
        })
    });
}

/// `join_all_limited` never has more than its limit running, and runs them all.
#[test]
fn join_all_limited_holds_back_the_rest() {
    run_on_start(|| {
        Box::pin(async {
            let running = Rc::new(Cell::new(0u32));
            let most = Rc::new(Cell::new(0u32));
            let children = (0..8u64).map(|i| {
                let running = running.clone();
                let most = most.clone();
                async move {
                    running.set(running.get() + 1);
                    most.set(most.get().max(running.get()));
                    ringline::sleep(Duration::from_millis(1 + i)).await;
                    running.set(running.get() - 1);
                    i
                }
            });
            let outputs = ringline::timeout(LIMIT, ringline::join_all_limited(children, 3))
                .await
                .expect("join_all_limited did not finish");
            assert_eq!(outputs, (0..8).collect::<Vec<u64>>());
            assert_eq!(most.get(), 3);
        })
    });
}

/// Dropping a `join_all` drops the children that are still pending.
#[test]
fn dropping_join_all_drops_its_children() {
    run_on_start(|| {
        Box::pin(async {
            struct Counted(Rc<Cell<u32>>);
            impl Drop for Counted {
                fn drop(&mut self) {
                    self.0.set(self.0.get() + 1);
                }
            }
            let dropped = Rc::new(Cell::new(0));
            let children = (0..3).map(|_| {
                let counted = Counted(dropped.clone());
                async move {
                    ringline::sleep(Duration::from_secs(60)).await;
                    drop(counted);
                }
            });
            let elapsed =
                ringline::timeout(Duration::from_millis(5), ringline::join_all(children)).await;
            assert!(elapsed.is_err());
            assert_eq!(dropped.get(), 3);
        })
    });
}

/// One sleep finishing must not leave the other unpolled, and a child that is
/// polled for another child's wake must register again.
#[test]
fn a_wake_for_one_child_keeps_the_others_registered() {
    run_on_start(|| {
        Box::pin(async {
            let children: Vec<LocalBoxFuture<'_, ()>> = (1..=5)
                .map(|i| ringline::sleep(Duration::from_millis(10 * i)).boxed_local())
                .collect();
            assert_eq!(completed(children).await, 5);
        })
    });
}

#[test]
fn channels_complete_in_futures_unordered() {
    run_on_start(|| {
        Box::pin(async {
            let (once_tx, once_rx) = ringline::oneshot::channel::<u32>();
            let (bounded_tx, bounded_rx) = ringline::mpsc::channel::<u32>(1);
            let (full_tx, full_rx) = ringline::mpsc::channel::<u32>(1);
            full_tx.try_send(1).unwrap();
            ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(10)).await;
                once_tx.send(1).unwrap();
                bounded_tx.try_send(2).unwrap();
                assert_eq!(full_rx.recv().await, Some(1));
                assert_eq!(full_rx.recv().await, Some(3));
            })
            .unwrap();
            let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                async move { assert_eq!(once_rx.await, Ok(1)) }.boxed_local(),
                async move { assert_eq!(bounded_rx.recv().await, Some(2)) }.boxed_local(),
                async { full_tx.send(3).await.unwrap() }.boxed_local(),
            ];
            assert_eq!(completed(children).await, 3);
        })
    });
}

#[test]
fn tasks_and_cancellation_complete_in_futures_unordered() {
    run_on_start(|| {
        Box::pin(async {
            let token = CancellationToken::new();
            let cancelled = token.cancelled();
            let joined = ringline::spawn_with_handle(async move {
                ringline::sleep(Duration::from_millis(10)).await;
                token.cancel();
                7
            })
            .unwrap();
            let blocking = ringline::spawn_blocking(|| {
                std::thread::sleep(Duration::from_millis(10));
                8
            })
            .unwrap();
            let resolved = ringline::resolve("localhost", 80).unwrap();
            let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                cancelled.boxed_local(),
                async move { assert_eq!(joined.await.unwrap(), 7) }.boxed_local(),
                async move { assert_eq!(blocking.await.unwrap(), 8) }.boxed_local(),
                async move {
                    resolved.await.unwrap();
                }
                .boxed_local(),
            ];
            assert_eq!(completed(children).await, 4);
        })
    });
}

#[test]
fn file_io_completes_in_futures_unordered() {
    run_on_start(|| {
        Box::pin(async {
            let path =
                std::env::temp_dir().join(format!("ringline-combinators-{}", std::process::id()));
            std::fs::write(&path, [7u8; 4096]).unwrap();
            let file = ringline::fs::open(&path, ringline::fs::OpenFlags::READ, 0)
                .unwrap()
                .await
                .unwrap();
            let children: Vec<LocalBoxFuture<'_, ()>> = (0..8)
                .map(|_| {
                    let read =
                        ringline::fs::read_into(file, 0, bytes::BytesMut::with_capacity(4096))
                            .unwrap();
                    async move {
                        let (result, buf) = read.await;
                        assert_eq!(result.unwrap(), 4096);
                        assert_eq!(buf[0], 7);
                    }
                    .boxed_local()
                })
                .collect();
            assert_eq!(completed(children).await, 8);
            let _ = std::fs::remove_file(&path);
        })
    });
}

/// A connection's own task, holding a receive and a send of the connection in
/// one `FuturesUnordered` with a sleep.
#[test]
fn connection_io_completes_in_futures_unordered() {
    static DONE: AtomicU32 = AtomicU32::new(0);

    struct Handler;
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let (mut send, mut recv) = conn.split();
                let sent = send.send(b"hello").unwrap();
                let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                    async {
                        let n = recv
                            .with_data(|data| {
                                if data.len() < 4 {
                                    ParseResult::NeedMore
                                } else {
                                    ParseResult::Consumed(data.len())
                                }
                            })
                            .await;
                        assert_eq!(n, 4);
                    }
                    .boxed_local(),
                    async {
                        sent.await.unwrap();
                    }
                    .boxed_local(),
                    ringline::sleep(Duration::from_millis(30)).boxed_local(),
                ];
                DONE.store(completed(children).await as u32, Ordering::SeqCst);
                let _ = ringline::request_shutdown();
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Handler>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound");
    let mut client = TcpStream::connect(addr).unwrap();
    let mut greeting = [0u8; 5];
    client.read_exact(&mut greeting).unwrap();
    // Sent in two parts, so the receive parks between them.
    client.write_all(b"pi").unwrap();
    client.flush().unwrap();
    std::thread::sleep(Duration::from_millis(10));
    client.write_all(b"ng").unwrap();
    common::join_workers(&runtime, handles);
    assert_eq!(DONE.load(Ordering::SeqCst), 3);
}

/// Firing a combinator's waker must not poll its task again for nothing: the
/// wake it ends in belongs to the poll about to run. A task that kept requeuing
/// itself this way would spin its worker for as long as a child is pending.
#[test]
fn a_pending_child_does_not_spin_the_worker() {
    run_on_start(|| {
        Box::pin(async {
            let polls = Rc::new(Cell::new(0u32));
            let counted = polls.clone();
            let mut sleep = Box::pin(ringline::sleep(Duration::from_millis(100)));
            let child = poll_fn(move |cx| {
                counted.set(counted.get() + 1);
                sleep.as_mut().poll(cx)
            });
            // The ticks wake the task three times while the child is pending.
            let mut ticks = Box::pin(async {
                for _ in 0..3 {
                    ringline::sleep(Duration::from_millis(10)).await;
                }
                std::future::pending::<()>().await
            });
            let children: Vec<LocalBoxFuture<'_, ()>> = vec![child.boxed_local()];
            let mut unordered: FuturesUnordered<_> = children.into_iter().collect();
            let finished = ringline::timeout(
                LIMIT,
                poll_fn(|cx| {
                    let _ = ticks.as_mut().poll(cx);
                    match unordered.poll_next_unpin(cx) {
                        Poll::Ready(_) => Poll::Ready(()),
                        Poll::Pending => Poll::Pending,
                    }
                }),
            )
            .await;
            assert!(finished.is_ok(), "the child did not complete");
            // Five polls: the first, one per tick and the sleep's completion.
            // A spin polls it thousands of times.
            assert!(polls.get() <= 8, "child polled {} times", polls.get());
        })
    });
}

/// Poll `shared` once and let the caller end: the leaf inside it stays
/// registered under the caller.
async fn poll_once(mut shared: Shared<LocalBoxFuture<'static, ()>>) {
    poll_fn(|cx| {
        let _ = shared.poll_unpin(cx);
        Poll::Ready(())
    })
    .await;
}

/// A `Shared` last polled by a standalone task that then ends. The leaf wakes
/// the id of a task that has gone, which still fires the waker it kept for the
/// other waiter.
#[test]
fn shared_survives_the_standalone_task_that_polled_it() {
    run_on_start(|| {
        Box::pin(async {
            let shared = ringline::sleep(Duration::from_millis(30))
                .boxed_local()
                .shared();
            let waits = shared.clone();
            let waiter = ringline::spawn_with_handle(waits).unwrap();
            ringline::spawn(poll_once(shared)).unwrap();
            ringline::timeout(LIMIT, waiter)
                .await
                .expect("the waiting task was not woken")
                .unwrap();
        })
    });
}

/// The same for a connection's task, which a different slab holds.
#[test]
fn shared_survives_the_connection_task_that_polled_it() {
    thread_local! {
        static SHARED: Cell<Option<Shared<LocalBoxFuture<'static, ()>>>> = const { Cell::new(None) };
    }
    static ADDR: Mutex<Option<std::net::SocketAddr>> = Mutex::new(None);
    static FINISHED: AtomicBool = AtomicBool::new(false);

    struct Handler;
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            async {
                poll_once(SHARED.take().expect("set in on_start")).await;
            }
        }
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async {
                let shared = ringline::sleep(Duration::from_millis(100))
                    .boxed_local()
                    .shared();
                let waits = shared.clone();
                SHARED.set(Some(shared));
                let waiter = ringline::spawn_with_handle(waits).unwrap();
                ringline::sleep(Duration::from_millis(1)).await;
                let addr = ADDR.lock().unwrap().expect("set after launch");
                let _client = ringline::spawn_blocking(move || TcpStream::connect(addr)).unwrap();
                ringline::timeout(LIMIT, waiter)
                    .await
                    .expect("the waiting task was not woken")
                    .unwrap();
                FINISHED.store(true, Ordering::SeqCst);
                let _ = ringline::request_shutdown();
            }))
        }
        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    // The worker must not read ADDR before it is set; the lock holds it back.
    let guard = ADDR.lock().unwrap();
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Handler>()
        .expect("launch");
    let mut guard = guard;
    *guard = runtime.bound_addr();
    drop(guard);
    common::join_workers(&runtime, handles);
    assert!(
        FINISHED.load(Ordering::SeqCst),
        "the on_start task ended early"
    );
}

/// Run `body` on two workers, each told its index, with results on `RESULT`.
fn run_on_two_workers(body: fn(usize) -> LocalBoxFuture<'static, ()>) -> &'static str {
    type TwoWorkerBody = fn(usize) -> LocalBoxFuture<'static, ()>;
    static SERIAL: Mutex<()> = Mutex::new(());
    static BODY: Mutex<Option<TwoWorkerBody>> = Mutex::new(None);

    struct Handler(usize);
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            async {}
        }
        fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            let body = BODY.lock().unwrap().expect("set before launch");
            Some(body(self.0))
        }
        fn create_for_worker(id: usize) -> Self {
            Handler(id)
        }
    }

    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    *BODY.lock().unwrap_or_else(|e| e.into_inner()) = Some(body);
    *RESULT.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let config = ConfigBuilder::new()
        .workers(2)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(64, 16384)
        .blocking_threads(2)
        .resolver_threads(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Handler>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    RESULT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .expect("worker 1 reported")
}

static RESULT: Mutex<Option<&'static str>> = Mutex::new(None);

/// A blocking handle polled on another worker must not take over the entry
/// with the same request id on that worker. Request ids start at 0 per worker.
#[test]
fn a_blocking_handle_on_another_worker_leaves_its_owner_alone() {
    static FOREIGN: Mutex<Option<ringline::BlockingJoinHandle<String>>> = Mutex::new(None);
    static DONE: AtomicBool = AtomicBool::new(false);
    let result = run_on_two_workers(|worker| {
        Box::pin(async move {
            if worker == 0 {
                let handle = ringline::spawn_blocking(|| String::from("foreign")).unwrap();
                *FOREIGN.lock().unwrap() = Some(handle);
                while !DONE.load(Ordering::SeqCst) {
                    ringline::sleep(Duration::from_millis(5)).await;
                }
                let _ = ringline::request_shutdown();
                return;
            }
            let foreign = loop {
                if let Some(handle) = FOREIGN.lock().unwrap().take() {
                    break handle;
                }
                ringline::sleep(Duration::from_millis(1)).await;
            };
            let mine = ringline::spawn_blocking(|| {
                std::thread::sleep(Duration::from_millis(100));
                7u32
            })
            .unwrap();
            ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(10)).await;
                let _ = ringline::timeout(Duration::from_millis(200), foreign).await;
            })
            .unwrap();
            let outcome = ringline::timeout(LIMIT, mine).await;
            *RESULT.lock().unwrap() = Some(if matches!(outcome, Ok(Ok(7))) {
                "woken"
            } else {
                "not woken"
            });
            DONE.store(true, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        })
    });
    assert_eq!(result, "woken");
}

/// A sleep polled on another worker must not take over the timer in the same
/// slot of that worker's pool.
#[test]
fn a_sleep_on_another_worker_leaves_its_timer_slot_alone() {
    static FOREIGN: Mutex<Option<ringline::SleepFuture>> = Mutex::new(None);
    static DONE: AtomicBool = AtomicBool::new(false);
    let result = run_on_two_workers(|worker| {
        Box::pin(async move {
            if worker == 0 {
                let mut sleep = ringline::sleep(Duration::from_secs(60));
                poll_fn(|cx| {
                    let _ = Pin::new(&mut sleep).poll(cx);
                    Poll::Ready(())
                })
                .await;
                *FOREIGN.lock().unwrap() = Some(sleep);
                while !DONE.load(Ordering::SeqCst) {
                    ringline::sleep(Duration::from_millis(5)).await;
                }
                let _ = ringline::request_shutdown();
                return;
            }
            let mut foreign = loop {
                if let Some(sleep) = FOREIGN.lock().unwrap().take() {
                    break sleep;
                }
                ringline::sleep(Duration::from_millis(1)).await;
            };
            // The sleep above freed the top slot, which this one takes, and
            // which the foreign sleep names on worker 0.
            let mine = ringline::sleep(Duration::from_millis(100));
            let spawned = ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(10)).await;
                poll_fn(|cx| {
                    let _ = Pin::new(&mut foreign).poll(cx);
                    Poll::Ready(())
                })
                .await;
            });
            spawned.unwrap();
            // The timeout's own wake polls `mine` too, so a lost wake shows as
            // lateness.
            let started = std::time::Instant::now();
            let woken = ringline::timeout(LIMIT, mine).await.is_ok()
                && started.elapsed() < Duration::from_secs(2);
            *RESULT.lock().unwrap() = Some(if woken { "woken" } else { "not woken" });
            DONE.store(true, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        })
    });
    assert_eq!(result, "woken");
}

/// A blocking handle polled on another worker must leave alone a delivered
/// result with the same request id.
#[test]
fn a_blocking_handle_on_another_worker_leaves_a_delivered_result_alone() {
    static FOREIGN: Mutex<Option<ringline::BlockingJoinHandle<String>>> = Mutex::new(None);
    static DONE: AtomicBool = AtomicBool::new(false);
    let result = run_on_two_workers(|worker| {
        Box::pin(async move {
            if worker == 0 {
                let handle = ringline::spawn_blocking(|| String::from("foreign")).unwrap();
                *FOREIGN.lock().unwrap() = Some(handle);
                while !DONE.load(Ordering::SeqCst) {
                    ringline::sleep(Duration::from_millis(5)).await;
                }
                let _ = ringline::request_shutdown();
                return;
            }
            let mut foreign = loop {
                if let Some(handle) = FOREIGN.lock().unwrap().take() {
                    break handle;
                }
                ringline::sleep(Duration::from_millis(1)).await;
            };
            let mine = ringline::spawn_blocking(|| 7u32).unwrap();
            // Long enough for the result to be delivered, unclaimed.
            ringline::sleep(Duration::from_millis(50)).await;
            let stayed_pending = poll_fn(|cx| Poll::Ready(Pin::new(&mut foreign).poll(cx)))
                .await
                .is_pending();
            let outcome = ringline::timeout(LIMIT, mine).await;
            *RESULT.lock().unwrap() = Some(if stayed_pending && matches!(outcome, Ok(Ok(7))) {
                "kept"
            } else {
                "taken"
            });
            DONE.store(true, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        })
    });
    assert_eq!(result, "kept");
}

/// A sleep polled on another worker must not report the timer that fired in the
/// same slot of that worker's pool, or release it.
#[test]
fn a_sleep_on_another_worker_leaves_a_fired_timer_alone() {
    static FOREIGN: Mutex<Option<ringline::SleepFuture>> = Mutex::new(None);
    static DONE: AtomicBool = AtomicBool::new(false);
    let result = run_on_two_workers(|worker| {
        Box::pin(async move {
            if worker == 0 {
                let mut sleep = ringline::sleep(Duration::from_secs(60));
                poll_fn(|cx| {
                    let _ = Pin::new(&mut sleep).poll(cx);
                    Poll::Ready(())
                })
                .await;
                *FOREIGN.lock().unwrap() = Some(sleep);
                while !DONE.load(Ordering::SeqCst) {
                    ringline::sleep(Duration::from_millis(5)).await;
                }
                let _ = ringline::request_shutdown();
                return;
            }
            let mut foreign = loop {
                if let Some(sleep) = FOREIGN.lock().unwrap().take() {
                    break sleep;
                }
                ringline::sleep(Duration::from_millis(1)).await;
            };
            // Takes the slot the sleep above freed, which the foreign sleep names.
            let mut mine = ringline::sleep(Duration::from_millis(5));
            poll_fn(|cx| {
                let _ = Pin::new(&mut mine).poll(cx);
                Poll::Ready(())
            })
            .await;
            ringline::sleep(Duration::from_millis(30)).await;
            let stayed_pending = poll_fn(|cx| Poll::Ready(Pin::new(&mut foreign).poll(cx)))
                .await
                .is_pending();
            let fired = ringline::timeout(LIMIT, mine).await.is_ok();
            *RESULT.lock().unwrap() = Some(if stayed_pending && fired {
                "kept"
            } else {
                "taken"
            });
            DONE.store(true, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        })
    });
    assert_eq!(result, "kept");
}

/// A child wait polled on another worker must not take over the waiter with the
/// same sequence number on that worker. Sequence numbers start at 0 per worker.
#[cfg(has_io_uring)]
#[test]
fn a_wait_on_another_worker_leaves_its_owner_alone() {
    static FOREIGN: Mutex<Option<ringline::process::WaitFuture>> = Mutex::new(None);
    static DONE: AtomicBool = AtomicBool::new(false);
    let result = run_on_two_workers(|worker| {
        Box::pin(async move {
            if worker == 0 {
                let child = ringline::process::Command::new("sleep")
                    .arg("10")
                    .spawn()
                    .unwrap()
                    .await
                    .unwrap();
                *FOREIGN.lock().unwrap() = Some(child.wait().unwrap());
                while !DONE.load(Ordering::SeqCst) {
                    ringline::sleep(Duration::from_millis(5)).await;
                }
                let _ = child.kill();
                let _ = ringline::request_shutdown();
                return;
            }
            let foreign = loop {
                if let Some(wait) = FOREIGN.lock().unwrap().take() {
                    break wait;
                }
                ringline::sleep(Duration::from_millis(1)).await;
            };
            let child = ringline::process::Command::new("sleep")
                .arg("0.2")
                .spawn()
                .unwrap()
                .await
                .unwrap();
            let mine = child.wait().unwrap();
            ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(10)).await;
                let _ = ringline::timeout(Duration::from_millis(100), foreign).await;
            })
            .unwrap();
            let started = std::time::Instant::now();
            let woken = matches!(ringline::timeout(LIMIT, mine).await, Ok(Ok(_)))
                && started.elapsed() < Duration::from_secs(2);
            *RESULT.lock().unwrap() = Some(if woken { "woken" } else { "not woken" });
            DONE.store(true, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        })
    });
    assert_eq!(result, "woken");
}

/// A child wait polled on another worker must leave alone a delivered result
/// with the same sequence number.
#[cfg(has_io_uring)]
#[test]
fn a_wait_on_another_worker_leaves_a_delivered_result_alone() {
    static FOREIGN: Mutex<Option<ringline::process::WaitFuture>> = Mutex::new(None);
    static DONE: AtomicBool = AtomicBool::new(false);
    let result = run_on_two_workers(|worker| {
        Box::pin(async move {
            if worker == 0 {
                // Short, so a foreign poll that takes worker 1's result and
                // calls `waitid` on this child does not block for long.
                let child = ringline::process::Command::new("sleep")
                    .arg("1")
                    .spawn()
                    .unwrap()
                    .await
                    .unwrap();
                *FOREIGN.lock().unwrap() = Some(child.wait().unwrap());
                while !DONE.load(Ordering::SeqCst) {
                    ringline::sleep(Duration::from_millis(5)).await;
                }
                let _ = child.kill();
                let _ = ringline::request_shutdown();
                return;
            }
            let mut foreign = loop {
                if let Some(wait) = FOREIGN.lock().unwrap().take() {
                    break wait;
                }
                ringline::sleep(Duration::from_millis(1)).await;
            };
            let child = ringline::process::Command::new("true")
                .spawn()
                .unwrap()
                .await
                .unwrap();
            let mine = child.wait().unwrap();
            // Long enough for the result to be delivered, unclaimed.
            ringline::sleep(Duration::from_millis(200)).await;
            let stayed_pending = poll_fn(|cx| Poll::Ready(Pin::new(&mut foreign).poll(cx)))
                .await
                .is_pending();
            let outcome = ringline::timeout(LIMIT, mine).await;
            *RESULT.lock().unwrap() = Some(if stayed_pending && matches!(outcome, Ok(Ok(_))) {
                "kept"
            } else {
                "taken"
            });
            DONE.store(true, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        })
    });
    assert_eq!(result, "kept");
}

type SendFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Worker 0 starts a disk-I/O operation with `start` and hands its future to
/// worker 1. Worker 1 starts the same operation after the same history, so the
/// two share a key, lets its result arrive, polls worker 0's future, and then
/// awaits its own. Records "kept" if worker 0's future stayed pending and
/// worker 1's resolved and passed `ok`.
async fn disk_result_kept<Fut>(
    worker: usize,
    foreign: &'static Mutex<Option<SendFuture>>,
    done: &'static AtomicBool,
    start: fn(ringline::fs::File, &std::path::Path) -> std::io::Result<Fut>,
    ok: fn(&Fut::Output) -> bool,
) where
    Fut: Future + Send + 'static,
{
    let path = std::env::temp_dir().join(format!(
        "ringline-combinators-foreign-{}-{worker}",
        std::process::id()
    ));
    let flags = ringline::fs::OpenFlags::READ_WRITE
        | ringline::fs::OpenFlags::CREATE
        | ringline::fs::OpenFlags::TRUNCATE;
    let file = ringline::fs::open(&path, flags, 0o644)
        .unwrap()
        .await
        .unwrap();
    if worker == 0 {
        let theirs = start(file, &path).unwrap();
        *foreign.lock().unwrap() = Some(Box::pin(async move {
            let _ = theirs.await;
        }));
        while !done.load(Ordering::SeqCst) {
            ringline::sleep(Duration::from_millis(5)).await;
        }
        let _ = std::fs::remove_file(&path);
        let _ = ringline::request_shutdown();
        return;
    }
    let mut theirs = loop {
        if let Some(theirs) = foreign.lock().unwrap().take() {
            break theirs;
        }
        ringline::sleep(Duration::from_millis(1)).await;
    };
    let mut mine = Box::pin(start(file, &path).unwrap());
    // Polled once, so this task is the operation's waiter when it completes.
    let first = poll_fn(|cx| Poll::Ready(mine.as_mut().poll(cx))).await;
    let kept = if first.is_ready() {
        // Completed before a foreign poll could interfere: nothing tested.
        "completed on the first poll"
    } else {
        // Long enough for the result to be delivered, unclaimed. An operation
        // slower than this leaves no result to take, and the test passes
        // whether or not the foreign poll is guarded.
        ringline::sleep(Duration::from_millis(200)).await;
        let stayed_pending = poll_fn(|cx| Poll::Ready(theirs.as_mut().poll(cx)))
            .await
            .is_pending();
        let outcome = ringline::timeout(LIMIT, mine).await;
        if stayed_pending && outcome.as_ref().is_ok_and(ok) {
            "kept"
        } else {
            "taken"
        }
    };
    *RESULT.lock().unwrap() = Some(kept);
    done.store(true, Ordering::SeqCst);
    let _ = std::fs::remove_file(&path);
    let _ = ringline::request_shutdown();
}

/// Generates a test that a disk-I/O future polled on another worker leaves
/// alone a delivered result with the same key there.
macro_rules! disk_result_kept_test {
    ($name:ident, $start:expr, $ok:expr) => {
        #[test]
        fn $name() {
            static FOREIGN: Mutex<Option<SendFuture>> = Mutex::new(None);
            static DONE: AtomicBool = AtomicBool::new(false);
            let result = run_on_two_workers(|worker| {
                Box::pin(disk_result_kept(worker, &FOREIGN, &DONE, $start, $ok))
            });
            assert_eq!(result, "kept");
        }
    };
}

disk_result_kept_test!(
    an_open_on_another_worker_leaves_a_delivered_result_alone,
    |_, path| ringline::fs::open(path, ringline::fs::OpenFlags::READ, 0),
    |result| result.is_ok()
);
disk_result_kept_test!(
    a_stat_on_another_worker_leaves_a_delivered_result_alone,
    |_, path| ringline::fs::stat(path),
    |result| result.is_ok()
);
disk_result_kept_test!(
    an_fsync_on_another_worker_leaves_a_delivered_result_alone,
    |file, _| ringline::fs::fsync(file),
    |result| result.is_ok()
);
disk_result_kept_test!(
    a_read_into_on_another_worker_leaves_a_delivered_result_alone,
    |file, _| ringline::fs::read_into(file, 0, bytes::BytesMut::with_capacity(16)),
    |(result, _)| result.is_ok()
);
disk_result_kept_test!(
    a_write_from_on_another_worker_leaves_a_delivered_result_alone,
    |file, _| ringline::fs::write_from(file, 0, bytes::BytesMut::from(&b"ping"[..])),
    |(result, _)| result.is_ok()
);

/// A task woken for another reason takes a slot while its entry is queued. The
/// entry must leave with it, or the next receive spends its wake on it and the
/// other senders hang.
#[test]
fn a_send_that_ends_without_its_wake_leaves_no_entry() {
    run_on_start(|| {
        Box::pin(async {
            let (tx, rx) = ringline::mpsc::channel::<u32>(1);
            tx.try_send(0).unwrap();
            let (nudge, nudged) = ringline::oneshot::channel::<()>();
            // First in line, so it is polled second after the receive below
            // and loses the slot to the woken select.
            let first = tx.clone();
            let queued_first = ringline::spawn_with_handle(async move {
                first.send(1).await.unwrap();
            })
            .unwrap();
            ringline::sleep(Duration::from_millis(2)).await;
            let middle = tx.clone();
            let selects = ringline::spawn_with_handle(async move {
                let _ = ringline::select(middle.send(2), nudged).await;
            })
            .unwrap();
            ringline::sleep(Duration::from_millis(2)).await;
            let last = tx.clone();
            let queued_last = ringline::spawn_with_handle(async move {
                last.send(3).await.unwrap();
            })
            .unwrap();
            ringline::sleep(Duration::from_millis(2)).await;

            nudge.send(()).unwrap();
            let mut received = vec![rx.recv().await.unwrap()];
            let finish = ringline::timeout(LIMIT, async {
                let _ = selects.await;
                while received.len() < 3 {
                    received.push(rx.recv().await.unwrap());
                }
                queued_first.await.unwrap();
                queued_last.await.unwrap();
            })
            .await;
            assert!(finish.is_ok(), "a sender was stranded");
        })
    });
}

/// Two sends in one task. The first is woken for a slot and dropped, after
/// another sender has taken the slot. The second must keep its entry, and be
/// woken for the next slot.
#[test]
fn dropping_a_send_leaves_its_siblings_entry() {
    run_on_start(|| {
        Box::pin(async {
            let (tx, rx) = ringline::mpsc::channel::<u32>(1);
            tx.try_send(0).unwrap();
            let barger = tx.clone();
            let (go, wait_for_go) = ringline::oneshot::channel::<()>();
            let sends = ringline::spawn_with_handle(async move {
                let mut dropped = Box::pin(tx.send(2));
                let mut keeps = Box::pin(tx.send(1));
                poll_fn(|cx| {
                    let _ = dropped.as_mut().poll(cx);
                    let _ = keeps.as_mut().poll(cx);
                    Poll::Ready(())
                })
                .await;
                let _ = wait_for_go.await;
                drop(dropped);
                keeps.await.unwrap();
            })
            .unwrap();
            ringline::sleep(Duration::from_millis(5)).await;

            assert_eq!(rx.recv().await, Some(0));
            barger.try_send(9).unwrap();
            go.send(()).unwrap();
            ringline::sleep(Duration::from_millis(5)).await;
            assert_eq!(rx.recv().await, Some(9));
            let received = ringline::timeout(LIMIT, rx.recv()).await;
            assert_eq!(received.ok().flatten(), Some(1), "the send was stranded");
            sends.await.unwrap();
        })
    });
}

/// A send woken for a slot and dropped before it can take the slot passes the
/// wake to the next sender.
#[test]
fn a_dropped_send_passes_its_wake_on() {
    run_on_start(|| {
        Box::pin(async {
            let (tx, rx) = ringline::mpsc::channel::<u32>(1);
            tx.try_send(0).unwrap();
            let (nudge, nudged) = ringline::oneshot::channel::<()>();
            let first = tx.clone();
            // `select` polls the oneshot first, so the woken task drops the
            // send without polling it.
            let dropped = ringline::spawn_with_handle(async move {
                let _ = ringline::select(nudged, first.send(1)).await;
            })
            .unwrap();
            ringline::sleep(Duration::from_millis(2)).await;
            let next = ringline::spawn_with_handle(async move {
                tx.send(2).await.unwrap();
            })
            .unwrap();
            ringline::sleep(Duration::from_millis(2)).await;

            nudge.send(()).unwrap();
            assert_eq!(rx.recv().await, Some(0));
            let received = ringline::timeout(LIMIT, rx.recv()).await;
            assert_eq!(
                received.ok().flatten(),
                Some(2),
                "the next sender was not woken"
            );
            dropped.await.unwrap();
            next.await.unwrap();
        })
    });
}

/// `Shared` passing `leaf` from a task that stops polling it to a second task.
/// The first task stays alive, and an unrelated wake has fired the waker it
/// kept, so the leaf has to wake the second task itself.
async fn shared_leaf_follows_the_task_polling_it(leaf: LocalBoxFuture<'static, ()>) {
    let shared = leaf.shared();
    let first = shared.clone();
    let stays_alive = ringline::spawn_with_handle(async move {
        let _ = ringline::timeout(Duration::from_millis(5), first).await;
        ringline::sleep(Duration::from_millis(1)).await;
        ringline::sleep(Duration::from_millis(100)).await;
    })
    .unwrap();
    ringline::sleep(Duration::from_millis(1)).await;
    let takes_over = ringline::spawn_with_handle(async move {
        let _ = ringline::timeout(Duration::from_millis(10), shared.clone()).await;
        shared.await;
    })
    .unwrap();
    ringline::timeout(LIMIT, async {
        takes_over.await.unwrap();
        stays_alive.await.unwrap();
    })
    .await
    .expect("the second task was not woken");
}

#[test]
fn shared_timer_follows_the_task_polling_it() {
    run_on_start(|| {
        Box::pin(shared_leaf_follows_the_task_polling_it(
            ringline::sleep(Duration::from_millis(40)).boxed_local(),
        ))
    });
}

#[test]
fn shared_cancellation_follows_the_task_polling_it() {
    run_on_start(|| {
        Box::pin(async {
            let token = CancellationToken::new();
            let cancelled = token.cancelled();
            ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(40)).await;
                token.cancel();
            })
            .unwrap();
            shared_leaf_follows_the_task_polling_it(cancelled.boxed_local()).await;
        })
    });
}

#[test]
fn shared_channel_send_follows_the_task_polling_it() {
    run_on_start(|| {
        Box::pin(async {
            let (tx, rx) = ringline::mpsc::channel::<u32>(1);
            tx.try_send(1).unwrap();
            ringline::spawn(async move {
                ringline::sleep(Duration::from_millis(40)).await;
                assert_eq!(rx.recv().await, Some(1));
                assert_eq!(rx.recv().await, Some(2));
            })
            .unwrap();
            shared_leaf_follows_the_task_polling_it(
                async move { tx.send(2).await.unwrap() }.boxed_local(),
            )
            .await;
        })
    });
}

/// A sender woken for a slot that a `try_send` took first waits again.
#[test]
fn a_sender_that_lost_its_slot_is_woken_for_the_next() {
    run_on_start(|| {
        Box::pin(async {
            let (tx, rx) = ringline::mpsc::channel::<u32>(1);
            tx.try_send(1).unwrap();
            let waiting = tx.clone();
            let sender = ringline::spawn_with_handle(async move {
                waiting.send(3).await.unwrap();
            })
            .unwrap();
            ringline::sleep(Duration::from_millis(5)).await;
            // The receive wakes the sender, and this task fills the slot first.
            assert_eq!(rx.recv().await, Some(1));
            tx.try_send(2).unwrap();
            ringline::sleep(Duration::from_millis(5)).await;
            assert_eq!(rx.recv().await, Some(2));
            assert_eq!(
                ringline::timeout(LIMIT, rx.recv())
                    .await
                    .expect("the sender was stranded"),
                Some(3)
            );
            sender.await.unwrap();
        })
    });
}

#[test]
fn shared_blocking_call_follows_the_task_polling_it() {
    run_on_start(|| {
        Box::pin(async {
            let blocking = ringline::spawn_blocking(|| {
                std::thread::sleep(Duration::from_millis(40));
            })
            .unwrap();
            shared_leaf_follows_the_task_polling_it(
                async move { blocking.await.unwrap() }.boxed_local(),
            )
            .await;
        })
    });
}

const READ_WITH_DATA: u8 = 0;
const READ_WITH_BYTES: u8 = 1;
const READ_WITH_DATA_RESULT: u8 = 2;
const READ_READY: u8 = 3;
const READ_STREAM: u8 = 4;
const READ_FILL_BUF: u8 = 5;

/// Accepts one connection and reads from it in a `FuturesUnordered`.
struct ReadHandler<const KIND: u8>;

static READS_DONE: [AtomicU32; 6] = [const { AtomicU32::new(0) }; 6];

impl<const KIND: u8> AsyncEventHandler for ReadHandler<KIND> {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let need = |data: &[u8]| {
                if data.len() < 4 {
                    ParseResult::NeedMore
                } else {
                    ParseResult::Consumed(data.len())
                }
            };
            // The halves outlive the children: dropping the last of them closes
            // the connection, which ends this task.
            match KIND {
                READ_STREAM | READ_FILL_BUF => {
                    let mut stream = ConnStream::new(conn);
                    finish_read::<KIND>(
                        async {
                            if KIND == READ_STREAM {
                                let mut buf = [0u8; 4];
                                stream.read_exact(&mut buf).await.unwrap();
                            } else {
                                let n = stream.fill_buf().await.unwrap().len();
                                assert!(n > 0);
                            }
                        }
                        .boxed_local(),
                    )
                    .await;
                }
                _ => {
                    let (_send, mut recv) = conn.split();
                    finish_read::<KIND>(
                        async {
                            match KIND {
                                READ_WITH_DATA => assert_eq!(recv.with_data(need).await, 4),
                                READ_WITH_BYTES => {
                                    let n = recv.with_bytes(|data| need(&data)).await;
                                    assert_eq!(n, 4);
                                }
                                READ_WITH_DATA_RESULT => {
                                    assert_eq!(recv.with_data_result(need).await.unwrap(), 4);
                                }
                                _ => recv.recv_ready().await,
                            }
                        }
                        .boxed_local(),
                    )
                    .await;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ReadHandler
    }
}

async fn finish_read<const KIND: u8>(child: LocalBoxFuture<'_, ()>) {
    let children = vec![
        child,
        ringline::sleep(Duration::from_millis(30)).boxed_local(),
    ];
    READS_DONE[KIND as usize].store(completed(children).await as u32, Ordering::SeqCst);
    let _ = ringline::request_shutdown();
}

fn read_in_unordered<const KIND: u8>() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ReadHandler<KIND>>()
        .expect("launch");
    let mut client = TcpStream::connect(runtime.bound_addr().expect("bound")).unwrap();
    // Sent in two parts, so the read parks between them.
    std::thread::sleep(Duration::from_millis(5));
    client.write_all(b"pi").unwrap();
    std::thread::sleep(Duration::from_millis(5));
    client.write_all(b"ng").unwrap();
    common::join_workers(&runtime, handles);
    assert_eq!(READS_DONE[KIND as usize].load(Ordering::SeqCst), 2);
}

#[test]
fn with_data_completes_in_futures_unordered() {
    read_in_unordered::<READ_WITH_DATA>();
}

#[test]
fn with_bytes_completes_in_futures_unordered() {
    read_in_unordered::<READ_WITH_BYTES>();
}

#[test]
fn with_data_result_completes_in_futures_unordered() {
    read_in_unordered::<READ_WITH_DATA_RESULT>();
}

#[test]
fn recv_ready_completes_in_futures_unordered() {
    read_in_unordered::<READ_READY>();
}

#[test]
fn stream_read_completes_in_futures_unordered() {
    read_in_unordered::<READ_STREAM>();
}

#[test]
fn stream_fill_buf_completes_in_futures_unordered() {
    read_in_unordered::<READ_FILL_BUF>();
}

const UDP_RECV_FROM: u8 = 0;
const UDP_WITH_DATAGRAM: u8 = 1;
const UDP_RECV_BATCH: u8 = 2;
const UDP_RECV_BATCH_TIMED: u8 = 3;

/// Receives one datagram in a `FuturesUnordered`.
struct UdpHandler<const KIND: u8>;

static UDP_DONE: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];

impl<const KIND: u8> AsyncEventHandler for UdpHandler<KIND> {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn on_udp_bind(
        &self,
        mut udp: ringline::UdpSocket,
    ) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async move {
            let child = async {
                let n = match KIND {
                    UDP_RECV_FROM => udp.recv_from().await.0.len(),
                    UDP_WITH_DATAGRAM => udp.with_datagram(|data, _| data.len()).await,
                    UDP_RECV_BATCH => {
                        let mut len = 0;
                        udp.recv_batch(8, |data, _| len = data.len()).await;
                        len
                    }
                    _ => {
                        let mut len = 0;
                        udp.recv_batch_timed(8, |data, _, _| len = data.len()).await;
                        len
                    }
                };
                assert_eq!(n, 4);
            }
            .boxed_local();
            let children = vec![
                child,
                ringline::sleep(Duration::from_millis(30)).boxed_local(),
            ];
            UDP_DONE[KIND as usize].store(completed(children).await as u32, Ordering::SeqCst);
            let _ = ringline::request_shutdown();
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        UdpHandler
    }
}

fn udp_in_unordered<const KIND: u8>() {
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind_udp("127.0.0.1:0".parse().unwrap())
        .launch::<UdpHandler<KIND>>()
        .expect("launch");
    let addr = runtime.bound_udp_addr().expect("bound");
    // After the receive parks.
    std::thread::sleep(Duration::from_millis(10));
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(b"ping", addr).unwrap();
    common::join_workers(&runtime, handles);
    assert_eq!(UDP_DONE[KIND as usize].load(Ordering::SeqCst), 2);
}

#[test]
fn udp_recv_from_completes_in_futures_unordered() {
    udp_in_unordered::<UDP_RECV_FROM>();
}

#[test]
fn udp_with_datagram_completes_in_futures_unordered() {
    udp_in_unordered::<UDP_WITH_DATAGRAM>();
}

#[test]
fn udp_recv_batch_completes_in_futures_unordered() {
    udp_in_unordered::<UDP_RECV_BATCH>();
}

#[test]
fn udp_recv_batch_timed_completes_in_futures_unordered() {
    udp_in_unordered::<UDP_RECV_BATCH_TIMED>();
}

// `Child::wait` is io_uring only.
#[cfg(has_io_uring)]
#[test]
fn process_spawn_and_wait_complete_in_futures_unordered() {
    run_on_start(|| {
        Box::pin(async {
            let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                async {
                    let child = ringline::process::Command::new("true")
                        .spawn()
                        .unwrap()
                        .await
                        .unwrap();
                    assert!(child.wait().unwrap().await.unwrap().success());
                }
                .boxed_local(),
                ringline::sleep(Duration::from_millis(30)).boxed_local(),
            ];
            assert_eq!(completed(children).await, 2);
        })
    });
}

#[test]
fn file_open_stat_and_write_complete_in_futures_unordered() {
    run_on_start(|| {
        Box::pin(async {
            let path = std::env::temp_dir()
                .join(format!("ringline-combinators-write-{}", std::process::id()));
            let write_path = path.clone();
            let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                async {
                    let file = ringline::fs::create(&write_path).unwrap().await.unwrap();
                    let mut buf = bytes::BytesMut::with_capacity(4);
                    buf.extend_from_slice(b"ping");
                    let (result, _) = ringline::fs::write_from(file, 0, buf).unwrap().await;
                    assert_eq!(result.unwrap(), 4);
                    let metadata = ringline::fs::stat(&write_path).unwrap().await.unwrap();
                    assert_eq!(metadata.size, 4);
                    ringline::fs::fsync(file).unwrap().await.unwrap();
                }
                .boxed_local(),
                ringline::sleep(Duration::from_millis(30)).boxed_local(),
            ];
            assert_eq!(completed(children).await, 2);
            let _ = std::fs::remove_file(&path);
        })
    });
}

#[test]
fn connect_completes_in_futures_unordered() {
    static PEER: Mutex<Option<std::net::SocketAddr>> = Mutex::new(None);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    *PEER.lock().unwrap() = Some(listener.local_addr().unwrap());
    run_on_start(|| {
        Box::pin(async {
            let addr = PEER.lock().unwrap().expect("set before launch");
            let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                async move {
                    ringline::connect(addr).await.unwrap();
                }
                .boxed_local(),
                ringline::sleep(Duration::from_millis(30)).boxed_local(),
            ];
            assert_eq!(completed(children).await, 2);
        })
    });
    drop(listener);
}

/// A bounded send waiting for the pool's one slot, then waiting for its
/// completion.
#[test]
fn backpressured_send_completes_in_futures_unordered() {
    static DONE: AtomicU32 = AtomicU32::new(0);

    struct Handler;
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let (mut send, _recv) = conn.split();
                let held = [b'H'; 4096];
                let waits = [b'W'; 4096];
                let first = send.send_backpressured(&held);
                let second = send.send_backpressured(&waits);
                let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                    async { assert_eq!(first.await.unwrap(), 4096) }.boxed_local(),
                    async { assert_eq!(second.await.unwrap(), 4096) }.boxed_local(),
                ];
                DONE.store(completed(children).await as u32, Ordering::SeqCst);
                let _ = ringline::request_shutdown();
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(1, 4096)
        .resolver_threads(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Handler>()
        .expect("launch");
    let mut client = TcpStream::connect(runtime.bound_addr().expect("bound")).unwrap();
    let mut received = [0u8; 8192];
    client.read_exact(&mut received).unwrap();
    common::join_workers(&runtime, handles);
    assert_eq!(DONE.load(Ordering::SeqCst), 2);
}

/// A forward parked for bytes from its source.
#[test]
fn forward_completes_in_futures_unordered() {
    static SINK: Mutex<Option<std::net::SocketAddr>> = Mutex::new(None);
    static DONE: AtomicU32 = AtomicU32::new(0);

    struct Handler;
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let addr = SINK.lock().unwrap().expect("set before launch");
                let sink = ringline::connect(addr).await.unwrap();
                let (mut sink_send, _sink_recv) = sink.split();
                let (_send, mut recv) = conn.split();
                let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                    async {
                        let n = recv.forward_to_conn(&mut sink_send, 4).await.unwrap();
                        assert_eq!(n, 4);
                    }
                    .boxed_local(),
                    ringline::sleep(Duration::from_millis(30)).boxed_local(),
                ];
                DONE.store(completed(children).await as u32, Ordering::SeqCst);
                let _ = ringline::request_shutdown();
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    let sink = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    *SINK.lock().unwrap() = Some(sink.local_addr().unwrap());
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Handler>()
        .expect("launch");
    let mut client = TcpStream::connect(runtime.bound_addr().expect("bound")).unwrap();
    let (mut sink_side, _) = sink.accept().unwrap();
    // Sent in two parts, so the forward parks between them.
    std::thread::sleep(Duration::from_millis(5));
    client.write_all(b"pi").unwrap();
    std::thread::sleep(Duration::from_millis(5));
    client.write_all(b"ng").unwrap();
    let mut forwarded = [0u8; 4];
    sink_side.read_exact(&mut forwarded).unwrap();
    assert_eq!(&forwarded, b"ping");
    common::join_workers(&runtime, handles);
    assert_eq!(DONE.load(Ordering::SeqCst), 2);
}

/// A bounded send that is submitted and still in flight when a sibling's wake
/// polls it, which it has to register for again.
#[test]
fn a_submitted_backpressured_send_survives_a_sibling_wake() {
    const LEN: usize = 4 << 20;
    static DONE: AtomicU32 = AtomicU32::new(0);

    struct Handler;
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let (mut send, _recv) = conn.split();
                let body = vec![b'B'; LEN];
                let sent = send.send_backpressured(&body);
                let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                    async { assert_eq!(sent.await.unwrap() as usize, LEN) }.boxed_local(),
                    ringline::sleep(Duration::from_millis(10)).boxed_local(),
                ];
                DONE.store(completed(children).await as u32, Ordering::SeqCst);
                let _ = ringline::request_shutdown();
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(512, 16384)
        .resolver_threads(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Handler>()
        .expect("launch");
    let mut client = TcpStream::connect(runtime.bound_addr().expect("bound")).unwrap();
    // Not reading keeps the send in flight past the sibling's wake.
    std::thread::sleep(Duration::from_millis(100));
    let mut received = vec![0u8; LEN];
    client.read_exact(&mut received).unwrap();
    common::join_workers(&runtime, handles);
    assert_eq!(DONE.load(Ordering::SeqCst), 2);
}

/// `send_ready` after the send pool runs out. On mio a UDP send does not take
/// the pool.
#[cfg(has_io_uring)]
#[test]
fn udp_send_ready_completes_in_futures_unordered() {
    static DONE: AtomicU32 = AtomicU32::new(0);

    struct Handler;
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
            async {}
        }
        fn on_udp_bind(
            &self,
            udp: ringline::UdpSocket,
        ) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
            Some(Box::pin(async move {
                let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                let addr = peer.local_addr().unwrap();
                let (mut send, _recv) = udp.split();
                while send.send_to(addr, b"ping").is_ok() {}
                let children: Vec<LocalBoxFuture<'_, ()>> = vec![
                    send.send_ready().boxed_local(),
                    ringline::sleep(Duration::from_millis(30)).boxed_local(),
                ];
                DONE.store(completed(children).await as u32, Ordering::SeqCst);
                let _ = ringline::request_shutdown();
            }))
        }
        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    let (runtime, handles) = RinglineBuilder::new(config())
        .bind_udp("127.0.0.1:0".parse().unwrap())
        .launch::<Handler>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    assert_eq!(DONE.load(Ordering::SeqCst), 2);
}
