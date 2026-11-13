#![allow(clippy::manual_async_fn)]
//! A refused SQPOLL CPU is named under an `RLIMIT_MEMLOCK` with less than a
//! ring of headroom. On Linux 6.14+ the refused ring's memlock charge can
//! still be held when ring setup retries without the CPU, and the retry at
//! the ring's own sizes then fails with ENOMEM. In its own binary because it
//! lowers this process's hard limit, which cannot be raised again. Below
//! 6.14 rings are not charged, and with `CAP_IPC_LOCK` nothing is, so there
//! the test passes without reaching the smaller retry.
#![cfg(has_io_uring)]

use std::future::Future;
use std::time::Duration;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {}
    }
    fn create_for_worker(_id: usize) -> Self {
        Idle
    }
}

/// The launch error for one worker whose SQ CPU is far beyond the machine,
/// at the default ring sizes (about 2.5 MiB of memlock).
fn launch_error() -> String {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(64)
        .send_pool(64, 16384)
        .sqpoll(true)
        .sqpoll_cpu(1 << 20)
        .build()
        .expect("config");
    match RinglineBuilder::new(config).launch::<Idle>() {
        Ok((runtime, handles)) => {
            runtime.shutdown();
            for h in handles {
                let _ = h.join();
            }
            panic!("launch succeeded");
        }
        Err(e) => e.to_string(),
    }
}

#[test]
fn a_refused_sq_cpu_is_named_under_a_tight_memlock_limit() {
    let limit = libc::rlimit {
        rlim_cur: 3 << 20,
        rlim_max: 3 << 20,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) },
        0,
        "lower RLIMIT_MEMLOCK"
    );
    // The charge is per user, so another process's rings can leave too
    // little for even the first ring for a moment (#589); wait that out.
    let mut text = launch_error();
    for _ in 0..50 {
        if !text.contains("(ENOMEM)") && !text.contains("failed with ENOMEM") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        text = launch_error();
    }
    assert!(text.contains("SQPOLL thread on CPU 1048576"), "{text}");
}
