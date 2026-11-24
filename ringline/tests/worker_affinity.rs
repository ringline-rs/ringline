#![allow(clippy::manual_async_fn)]
//! The default worker count and worker pinning use only the CPUs the process
//! may run on (#976).
//!
//! The test restricts its own thread to one CPU, as `taskset` would, then
//! launches with the default worker count and pinning on. Workers inherit the
//! launching thread's mask, so each worker reads its own mask in `on_start`.
#![cfg(target_os = "linux")]

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

/// Each worker's affinity mask, read on the worker thread.
static MASKS: Mutex<Vec<Vec<usize>>> = Mutex::new(Vec::new());

struct Recorder;

impl AsyncEventHandler for Recorder {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        MASKS.lock().unwrap().push(affinity());
        None
    }

    fn create_for_worker(_id: usize) -> Self {
        Recorder
    }
}

/// The calling thread's affinity mask, ascending.
fn affinity() -> Vec<usize> {
    // SAFETY: a zeroed `cpu_set_t` and its own size.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let ret =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    assert_eq!(
        ret,
        0,
        "sched_getaffinity: {}",
        std::io::Error::last_os_error()
    );
    let capacity = 8 * std::mem::size_of::<libc::cpu_set_t>();
    (0..capacity)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .collect()
}

/// Restrict the calling thread to `cpu`.
fn restrict_to(cpu: usize) {
    // SAFETY: a zeroed `cpu_set_t`, `cpu` below its capacity, and its own size.
    let ret = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
    };
    assert_eq!(
        ret,
        0,
        "sched_setaffinity: {}",
        std::io::Error::last_os_error()
    );
}

#[test]
fn default_workers_are_pinned_inside_the_affinity_mask() {
    let allowed = affinity();
    // The highest allowed CPU, so that a pin computed from the online CPUs
    // (CPU 0 first) lands outside the mask.
    let Some(&cpu) = allowed.last().filter(|_| allowed.len() > 1) else {
        eprintln!("skipped: the process may run on only {allowed:?}");
        return;
    };
    restrict_to(cpu);
    assert_eq!(ringline::physical_core_count(), 1);

    let config = ConfigBuilder::new()
        .sq_entries(64)
        .max_connections(16)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Recorder>()
        .expect("launch");
    let workers = runtime.worker_count();
    let start = Instant::now();
    while MASKS.lock().unwrap().len() < workers && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(1));
    }
    runtime.shutdown();
    for h in handles {
        let _ = h.join();
    }

    assert_eq!(workers, 1, "one worker for the one allowed core");
    let masks = MASKS.lock().unwrap();
    assert_eq!(*masks, vec![vec![cpu]], "each worker pinned to CPU {cpu}");
}
