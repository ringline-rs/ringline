#![allow(clippy::manual_async_fn)]
//! The default worker count and worker pinning use only the CPUs the process
//! may run on (#976).
//!
//! Each test restricts the process's main thread to some CPUs, as
//! `taskset <command>` would, then launches with pinning on. ringline reads the
//! main thread's mask; each worker reads its own mask in `on_start`.
#![cfg(target_os = "linux")]

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

/// The tests change the main thread's mask, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());
/// Each worker's affinity mask, read on the worker thread.
static MASKS: Mutex<Vec<Vec<usize>>> = Mutex::new(Vec::new());

struct Recorder;

impl AsyncEventHandler for Recorder {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        MASKS.lock().unwrap().push(affinity(0));
        None
    }

    fn create_for_worker(_id: usize) -> Self {
        Recorder
    }
}

/// The affinity mask of thread `tid` (0: the calling thread), ascending.
fn affinity(tid: libc::pid_t) -> Vec<usize> {
    // SAFETY: a zeroed `cpu_set_t` and its own size.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let ret =
        unsafe { libc::sched_getaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
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

/// Set the main thread's mask to `cpus`.
fn restrict_main_thread(cpus: &[usize]) {
    // SAFETY: a zeroed `cpu_set_t`, every CPU below its capacity (they came
    // from `affinity`), and its own size.
    let ret = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for &cpu in cpus {
            libc::CPU_SET(cpu, &mut set);
        }
        libc::sched_setaffinity(libc::getpid(), std::mem::size_of::<libc::cpu_set_t>(), &set)
    };
    assert_eq!(
        ret,
        0,
        "sched_setaffinity: {}",
        std::io::Error::last_os_error()
    );
}

/// Restores the main thread's mask when dropped.
struct Restore(Vec<usize>);

impl Drop for Restore {
    fn drop(&mut self) {
        restrict_main_thread(&self.0);
    }
}

fn config(workers: usize) -> ringline::Config {
    ConfigBuilder::new()
        .workers(workers)
        .sq_entries(64)
        .max_connections(16)
        .build()
        .expect("valid config")
}

#[test]
fn default_workers_are_pinned_inside_the_affinity_mask() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let allowed = affinity(unsafe { libc::getpid() });
    // The highest allowed CPU, so that a pin computed from the online CPUs
    // (CPU 0 first) lands outside the mask.
    let Some(&cpu) = allowed.last().filter(|_| allowed.len() > 1) else {
        eprintln!("skipped: the process may run on only {allowed:?}");
        return;
    };
    let _restore = Restore(allowed.clone());
    restrict_main_thread(&[cpu]);
    // The count does not depend on the calling thread's mask.
    assert_eq!(ringline::physical_core_count(), 1);
    MASKS.lock().unwrap().clear();

    let (runtime, handles) = RinglineBuilder::new(config(0))
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

#[test]
fn more_workers_than_allowed_cpus_fails_launch() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let allowed = affinity(unsafe { libc::getpid() });
    if allowed.len() < 3 {
        eprintln!("skipped: the process may run on only {allowed:?}");
        return;
    }
    let _restore = Restore(allowed.clone());
    let two = &allowed[allowed.len() - 2..];
    restrict_main_thread(two);

    // Three workers do not fit two allowed CPUs. Pinning the third to CPU 2,
    // its index, would put it on a CPU outside the mask or beside another
    // worker.
    match RinglineBuilder::new(config(3)).launch::<Recorder>() {
        Ok((runtime, handles)) => {
            runtime.shutdown();
            for h in handles {
                let _ = h.join();
            }
            panic!("launched 3 pinned workers on the 2 CPUs {two:?}");
        }
        Err(ringline::Error::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}
