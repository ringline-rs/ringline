#![allow(clippy::manual_async_fn)]
//! A launch whose `sqpoll_cpus` list does not match the worker count, or whose
//! `sqpoll_cpu` the kernel refuses, fails with an error naming the knob
//! (#834). Kept out of `sqpoll_cpu.rs`: when the kernel refuses the CPU, ring
//! setup sets the ring up again without it to name the cause. That ring's SQ
//! thread is named after this runtime's `rl-work-0`, which `sqpoll_cpu.rs`
//! would take for its own worker 0 (#941).
#![cfg(has_io_uring)]

use std::future::Future;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, Error, RinglineBuilder};

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {}
    }
    fn create_for_worker(_id: usize) -> Self {
        Idle
    }
}

fn builder(workers: usize) -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(workers)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(64, 16384)
        .sqpoll(true)
}

fn launch_error(config: ringline::Config) -> Error {
    match RinglineBuilder::new(config).launch::<Idle>() {
        Ok((runtime, handles)) => {
            runtime.shutdown();
            for h in handles {
                let _ = h.join();
            }
            panic!("launch succeeded");
        }
        Err(e) => e,
    }
}

#[test]
fn a_sqpoll_cpus_list_shorter_than_the_workers_fails_launch() {
    let err = launch_error(builder(2).sqpoll_cpus(&[0]).build().expect("config"));
    let text = err.to_string();
    assert!(matches!(err, Error::RingSetup(_)), "{err:?}");
    assert!(text.contains("sqpoll_cpus has 1 entries"), "{text}");
}

#[test]
fn an_sq_cpu_past_the_machine_fails_launch_naming_the_knob() {
    // Far beyond any machine's CPU count, so the kernel refuses it with EINVAL.
    let err = launch_error(builder(1).sqpoll_cpu(1 << 20).build().expect("config"));
    let text = err.to_string();
    assert!(matches!(err, Error::RingSetup(_)), "{err:?}");
    assert!(text.contains("sqpoll_cpu 1048576 + worker 0"), "{text}");
}

/// With the default `pin_to_core(true)` the ring is set up on a worker pinned
/// to one core; a refused SQ CPU is still named.
#[test]
fn an_sq_cpu_past_the_machine_is_named_from_a_pinned_worker() {
    let config = builder(1)
        .pin_to_core(true)
        .sqpoll_cpu(1 << 20)
        .build()
        .expect("config");
    let err = launch_error(config);
    let text = err.to_string();
    assert!(matches!(err, Error::RingSetup(_)), "{err:?}");
    assert!(text.contains("SQPOLL thread on CPU 1048576"), "{text}");
}
