#![allow(clippy::manual_async_fn)]
//! A full standalone task slab is reported as `WouldBlock` and counted (#481).
//!
//! Its own test binary, because it reads a process-wide counter.

mod common;

use std::future::{Future, pending};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};

use ringline::metrics::{POOL, pool};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

static REFUSED: AtomicU32 = AtomicU32::new(0);

struct Handler;

impl AsyncEventHandler for Handler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            // This task holds the first of the two slots.
            ringline::spawn(pending::<()>()).expect("the second slot");
            for result in [
                ringline::spawn(async {}).map(|_| ()),
                ringline::spawn_with_handle(async {}).map(|_| ()),
            ] {
                let error = result.expect_err("the slab is full");
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                assert!(error.to_string().contains("standalone_task_capacity"));
                REFUSED.fetch_add(1, Ordering::SeqCst);
            }
            let _ = ringline::request_shutdown();
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        Handler
    }
}

#[test]
fn a_full_slab_is_reported_and_counted() {
    let before = POOL.value(pool::STANDALONE_TASKS_EXHAUSTED).unwrap_or(0);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .standalone_task_capacity(2)
        .resolver_threads(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Handler>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    assert_eq!(REFUSED.load(Ordering::SeqCst), 2);
    assert_eq!(
        POOL.value(pool::STANDALONE_TASKS_EXHAUSTED).unwrap_or(0) - before,
        2
    );
}
