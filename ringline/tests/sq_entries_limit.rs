//! The largest `sq_entries` that `ConfigBuilder::build` accepts is one the
//! kernel accepts: the completion queue is 4 × `sq_entries`, and Linux
//! refuses more than 65536 completion queue entries (#835).

#![allow(clippy::manual_async_fn)]

use std::future::Future;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {}
    }

    fn create_for_worker(_worker_id: usize) -> Self {
        Idle
    }
}

fn config(sq_entries: u32) -> Result<ringline::Config, ringline::Error> {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(sq_entries)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
}

#[test]
fn the_largest_accepted_sq_entries_sets_up_a_ring() {
    let config = config(16384).expect("16384 is accepted");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Idle>()
        .expect("launch with sq_entries 16384");
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
}

#[test]
fn sq_entries_past_the_kernel_limit_is_refused_by_build() {
    let Err(err) = config(32768) else {
        panic!("build accepted sq_entries 32768, a CQ of 131072 entries");
    };
    assert!(err.to_string().contains("at most 16384"), "{err}");
}
