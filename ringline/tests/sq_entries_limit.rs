//! The largest queues `ConfigBuilder::build` accepts are ones the kernel
//! accepts: Linux refuses an SQ of more than 32768 entries and a CQ of more
//! than 65536 (#835, #831).

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

fn config(sq_entries: u32, cq_entries: u32) -> Result<ringline::Config, ringline::Error> {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(sq_entries)
        .cq_entries(cq_entries)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
}

#[test]
fn the_largest_accepted_queues_set_up_a_ring() {
    let config = config(32768, 65536).expect("32768 and 65536 are accepted");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Idle>()
        .expect("launch with sq_entries 32768 and cq_entries 65536");
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker error");
    }
}

#[test]
fn queues_past_the_kernel_limits_are_refused_by_build() {
    let Err(err) = config(65536, 65536) else {
        panic!("build accepted sq_entries 65536");
    };
    assert!(err.to_string().contains("at most 32768"), "{err}");
    let Err(err) = config(4096, 131072) else {
        panic!("build accepted cq_entries 131072");
    };
    assert!(err.to_string().contains("at most 65536"), "{err}");
}
