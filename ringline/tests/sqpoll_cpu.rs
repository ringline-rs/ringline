#![allow(clippy::manual_async_fn)]
//! `ConfigBuilder::sqpoll_cpu` and `sqpoll_cpus` pin each worker's SQPOLL
//! thread to its own CPU (#834).
//!
//! The tests read every SQ thread in the process and key it by its owner's
//! name, `rl-work-<i>`, which every runtime shares. So this binary holds only
//! tests that launch through `launch_and_read`, which runs one runtime at a
//! time. When the kernel refuses an SQ CPU, ring setup sets the ring up again
//! without it to name the cause, and that ring has an SQ thread, so those
//! tests are in `sqpoll_cpu_refused.rs` (#941).
#![cfg(has_io_uring)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

fn builder(workers: usize) -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(workers)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(64, 16384)
        .sqpoll(true)
}

/// Whether every CPU in `cpus` is in this process's affinity mask. The test
/// process is not pinned, so this stands in for the cpuset the kernel checks
/// an SQ thread CPU against.
fn all_allowed(cpus: &[u32]) -> bool {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return false;
        }
        cpus.iter().all(|&c| libc::CPU_ISSET(c as usize, &set))
    }
}

fn read(path: std::path::PathBuf) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Each SQ thread's `Cpus_allowed_list`, keyed by the worker that created it.
/// The kernel names an SQ thread `iou-sqp-<tid>` after the thread that set up
/// its ring, which is the worker thread `rl-work-<i>`.
fn sq_cpus_by_worker() -> HashMap<usize, String> {
    let mut workers: HashMap<String, usize> = HashMap::new();
    let mut sq: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir("/proc/self/task").unwrap() {
        let dir = entry.unwrap().path();
        let tid = dir.file_name().unwrap().to_string_lossy().into_owned();
        let Some(comm) = read(dir.join("comm")) else {
            continue;
        };
        let comm = comm.trim();
        if let Some(i) = comm.strip_prefix("rl-work-") {
            workers.insert(tid, i.parse().unwrap());
        } else if let Some(owner) = comm.strip_prefix("iou-sqp-") {
            let Some(status) = read(dir.join("status")) else {
                continue;
            };
            if let Some(list) = status
                .lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
            {
                sq.push((owner.to_owned(), list.trim().to_owned()));
            }
        }
    }
    sq.into_iter()
        .filter_map(|(owner, list)| workers.get(&owner).map(|&i| (i, list)))
        .collect()
}

/// Launches `config`'s runtime, waits until every worker's SQ thread is
/// pinned to one CPU, and returns each worker's SQ thread CPU list.
fn launch_and_read(config: ringline::Config, workers: usize) -> HashMap<usize, String> {
    // Every runtime names its workers rl-work-0, rl-work-1, ..., so under
    // `cargo test`, which runs this file's tests on threads of one process,
    // two runtimes at once would mix their SQ threads.
    static ONE_RUNTIME: Mutex<()> = Mutex::new(());
    let _one = ONE_RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Idle>()
        .expect("launch");
    // The SQ thread sets its own affinity when it first runs.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut lists;
    loop {
        lists = sq_cpus_by_worker();
        let pinned = lists.len() == workers && lists.values().all(|l| l.parse::<usize>().is_ok());
        if pinned || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    runtime.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
    eprintln!("SQ thread Cpus_allowed_list by worker: {lists:?}");
    lists
}

fn expected(cpus: &[u32]) -> HashMap<usize, String> {
    cpus.iter()
        .enumerate()
        .map(|(i, c)| (i, c.to_string()))
        .collect()
}

#[test]
fn sqpoll_cpu_pins_worker_i_to_base_plus_i() {
    if !all_allowed(&[0, 1]) {
        eprintln!("skipping: CPUs 0 and 1 are not both in this process's affinity mask");
        return;
    }
    let config = builder(2).sqpoll_cpu(0).build().expect("config");
    assert_eq!(launch_and_read(config, 2), expected(&[0, 1]));
}

#[test]
fn sqpoll_cpus_pins_worker_i_to_entry_i() {
    if !all_allowed(&[0, 1]) {
        eprintln!("skipping: CPUs 0 and 1 are not both in this process's affinity mask");
        return;
    }
    let config = builder(2).sqpoll_cpus(&[1, 0]).build().expect("config");
    assert_eq!(launch_and_read(config, 2), expected(&[1, 0]));
}

#[test]
fn sqpoll_cpus_may_put_every_sq_thread_on_one_cpu() {
    if !all_allowed(&[1]) {
        eprintln!("skipping: CPU 1 is not in this process's affinity mask");
        return;
    }
    let config = builder(2).sqpoll_cpus(&[1, 1]).build().expect("config");
    assert_eq!(launch_and_read(config, 2), expected(&[1, 1]));
}
