//! `RLIMIT_MEMLOCK` governs how much memory io_uring lets an unprivileged
//! process register as fixed buffers. Distros default it to 8 MiB or 64 MiB,
//! so a `registered_regions` config of a few hundred MiB used to fail with a
//! bare `Cannot allocate memory`. Two paths must name the limit instead:
//! `launch` before it spawns anything, and `Runtime::register_region`
//! at run time.
//!
//! One test, sequential: lowering the hard limit is irreversible for the
//! process, so the order in which the two scenarios run must be fixed.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

use std::future::Future;

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, Error, MemoryRegion, RinglineBuilder,
};

struct Idle;

impl AsyncEventHandler for Idle {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        Idle
    }
}

fn builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .max_registered_regions(4)
}

fn memlock() -> (u64, u64) {
    let mut r: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r) }, 0);
    (r.rlim_cur, r.rlim_max)
}

/// Lower both soft and hard to `bytes`. Unprivileged processes may lower the
/// hard limit; they may never raise it again, which is why this file holds a
/// single test.
fn cap_memlock(bytes: u64) {
    let r = libc::rlimit {
        rlim_cur: bytes,
        rlim_max: bytes,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &r) },
        0,
        "setrlimit: {}",
        std::io::Error::last_os_error()
    );
}

const CAP: u64 = 64 * 1024;
const REGION: usize = 4 * 1024 * 1024;

#[test]
fn memlock_shortfall_is_named_at_launch_and_at_register_region() {
    // A root or CAP_IPC_LOCK process is exempt from the limit; the assertions
    // below would then be testing nothing.
    assert_ne!(unsafe { libc::geteuid() }, 0, "run this test unprivileged");

    // --- run time: launch with no regions, then register one that exceeds
    // the limit. This also verifies the kernel really enforces the limit on
    // this host, which the launch-time preflight relies on.
    let (shutdown, handles) = RinglineBuilder::new(builder().build().unwrap())
        .launch::<Idle>()
        .expect("launch without regions");

    cap_memlock(CAP);
    assert_eq!(memlock(), (CAP, CAP));

    let mut backing = vec![0u8; REGION];
    let region = unsafe { MemoryRegion::new(backing.as_mut_ptr(), REGION) };
    let err = shutdown
        .register_region(region)
        .expect_err("registering 4 MiB under a 64 KiB memlock limit must fail");
    let text = err.to_string();
    assert!(text.contains("RLIMIT_MEMLOCK"), "{text}");
    assert!(text.contains("ulimit -l"), "{text}");
    assert!(text.contains("CAP_IPC_LOCK"), "{text}");
    // The registrar adds what the worker rings already hold and need.
    assert!(text.contains("registered region(s)"), "{text}");
    assert!(text.contains("the rings need"), "{text}");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }

    // --- launch time: a config that needs more than the hard limit must be
    // refused before any worker thread exists, with the same guidance.
    let mut backing2 = vec![0u8; REGION];
    let region2 = unsafe { MemoryRegion::new(backing2.as_mut_ptr(), REGION) };
    let config = builder().registered_regions(vec![region2]).build().unwrap();
    let err = RinglineBuilder::new(config)
        .launch::<Idle>()
        .err()
        .expect("launch must refuse a config that exceeds the memlock hard limit");
    assert!(
        matches!(err, Error::ResourceLimit(_)),
        "expected ResourceLimit, got {err:?}"
    );
    let text = err.to_string();
    assert!(text.contains("RLIMIT_MEMLOCK"), "{text}");
    assert!(text.contains("ulimit -l"), "{text}");
    assert!(text.contains("CAP_IPC_LOCK"), "{text}");
}
