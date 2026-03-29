#![allow(clippy::manual_async_fn)]
//! Integration tests for spawn_blocking.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};

use ringline::{AsyncEventHandler, Config, ConnCtx, RinglineBuilder};

fn test_config() -> Config {
    let mut config = Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 64;
    config.recv_buffer.ring_size = 64;
    config.recv_buffer.buffer_size = 4096;
    config.max_connections = 64;
    config.send_copy_count = 64;
    config.resolver_threads = 0;
    config.spawner_threads = 0;
    config
}

// ── Basic: returns a value ──────────────────────────────────────────

static BLOCKING_RESULT: AtomicU32 = AtomicU32::new(0);

struct BlockingBasicHandler;

impl AsyncEventHandler for BlockingBasicHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let val = ringline::spawn_blocking(|| 42u32).unwrap().await;
            BLOCKING_RESULT.store(val, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingBasicHandler
    }
}

#[test]
fn spawn_blocking_returns_value() {
    BLOCKING_RESULT.store(0, Ordering::SeqCst);

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<BlockingBasicHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(BLOCKING_RESULT.load(Ordering::SeqCst), 42);
}

// ── Blocking work doesn't stall the worker ──────────────────────────

static BLOCKING_CONCURRENT: AtomicU32 = AtomicU32::new(0);

struct BlockingConcurrentHandler;

impl AsyncEventHandler for BlockingConcurrentHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            // Spawn a blocking task that sleeps.
            let handle = ringline::spawn_blocking(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                10u32
            })
            .unwrap();

            // Meanwhile, do async work (a timer) — this should not be blocked.
            ringline::sleep(std::time::Duration::from_millis(10)).await;

            // Now await the blocking result.
            let val = handle.await;
            BLOCKING_CONCURRENT.store(val, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingConcurrentHandler
    }
}

#[test]
fn spawn_blocking_doesnt_stall_worker() {
    BLOCKING_CONCURRENT.store(0, Ordering::SeqCst);

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<BlockingConcurrentHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(BLOCKING_CONCURRENT.load(Ordering::SeqCst), 10);
}

// ── Multiple concurrent blocking tasks ──────────────────────────────

static BLOCKING_MULTI: AtomicU32 = AtomicU32::new(0);

struct BlockingMultiHandler;

impl AsyncEventHandler for BlockingMultiHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let h1 = ringline::spawn_blocking(|| 10u32).unwrap();
            let h2 = ringline::spawn_blocking(|| 20u32).unwrap();
            let h3 = ringline::spawn_blocking(|| 30u32).unwrap();

            let (a, b) = ringline::join(h1, h2).await;
            let c = h3.await;
            BLOCKING_MULTI.store(a + b + c, Ordering::SeqCst);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingMultiHandler
    }
}

#[test]
fn spawn_blocking_multiple_concurrent() {
    BLOCKING_MULTI.store(0, Ordering::SeqCst);

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<BlockingMultiHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(BLOCKING_MULTI.load(Ordering::SeqCst), 60);
}

// ── Pool disabled ───────────────────────────────────────────────────

static BLOCKING_DISABLED: AtomicU32 = AtomicU32::new(0);

struct BlockingDisabledHandler;

impl AsyncEventHandler for BlockingDisabledHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            match ringline::spawn_blocking(|| 42u32) {
                Err(_) => BLOCKING_DISABLED.store(1, Ordering::SeqCst),
                Ok(_) => BLOCKING_DISABLED.store(99, Ordering::SeqCst),
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingDisabledHandler
    }
}

#[test]
fn spawn_blocking_disabled() {
    BLOCKING_DISABLED.store(0, Ordering::SeqCst);

    let mut config = test_config();
    config.blocking_threads = 0;

    let (_shutdown, handles) = RinglineBuilder::new(config)
        .launch::<BlockingDisabledHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(BLOCKING_DISABLED.load(Ordering::SeqCst), 1);
}

// ── String return type (non-Copy) ───────────────────────────────────

static BLOCKING_STRING: AtomicU32 = AtomicU32::new(0);

struct BlockingStringHandler;

impl AsyncEventHandler for BlockingStringHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let val = ringline::spawn_blocking(|| "hello blocking".to_string())
                .unwrap()
                .await;
            if val == "hello blocking" {
                BLOCKING_STRING.store(1, Ordering::SeqCst);
            }
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BlockingStringHandler
    }
}

#[test]
fn spawn_blocking_non_copy_type() {
    BLOCKING_STRING.store(0, Ordering::SeqCst);

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<BlockingStringHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(BLOCKING_STRING.load(Ordering::SeqCst), 1);
}
