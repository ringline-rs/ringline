//! A `core_offset` that puts a worker beyond the CPUs the process may run on
//! fails `launch()` with `InvalidInput` before any worker starts.
//!
//! Its own test binary: a pin past what an affinity mask can name aborts the
//! process (`pin_to_core`'s own check is a unit test in `worker.rs`).
//! Linux only: pinning is a no-op elsewhere.

#![cfg(target_os = "linux")]
#![allow(clippy::manual_async_fn)]

use std::future::Future;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn create_for_worker(_id: usize) -> Self {
        Idle
    }
}

#[test]
fn a_core_offset_beyond_the_affinity_mask_fails_launch() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(true)
        .core_offset(100_000)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .build()
        .expect("valid config");
    match RinglineBuilder::new(config).launch::<Idle>() {
        Ok(_) => panic!("launch pinned a worker to CPU 100000"),
        Err(ringline::Error::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}
