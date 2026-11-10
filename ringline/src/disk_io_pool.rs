//! Dedicated disk I/O thread pool for the mio backend.
//!
//! Offloads blocking filesystem syscalls (pread, pwrite, fsync, stat, rename,
//! unlink, mkdir) from the mio event loop to a pool of background threads.
//! Each thread executes one blocking call at a time and sends the result back
//! via a per-worker crossbeam channel + `WakeFd`, matching the pattern used
//! by [`BlockingPool`](crate::blocking::BlockingPool).
//!
//! Unlike the blocking pool, these threads do NOT use `SCHED_IDLE` — disk I/O
//! is latency-sensitive and should not be deprioritized.

use std::thread;

use crossbeam_channel::{Receiver, Sender};

/// A request from a worker to the disk I/O pool.
pub(crate) struct DiskIoRequest {
    /// The blocking syscall to execute. Returns a [`DiskIoResult`].
    /// The i32 follows io_uring CQE convention: >= 0 for success/bytes,
    /// < 0 for -errno.
    pub(crate) work: Box<dyn FnOnce() -> DiskIoResult + Send>,
    /// Sequence number for correlating request → response.
    pub(crate) seq: u32,
    /// Per-worker response channel.
    pub(crate) response_tx: Sender<DiskIoResponse>,
    /// Wake handle — used to wake the worker after sending the response.
    pub(crate) wake_handle: crate::wakeup::WakeFd,
}

/// Result from a disk I/O worker thread.
pub(crate) struct DiskIoResult {
    /// io_uring-compatible result: >= 0 for success, < 0 for -errno.
    pub(crate) result: i32,
    /// Optional metadata (populated only for stat operations).
    pub(crate) metadata: Option<crate::fs::Metadata>,
    /// The fd a successful open produced. Owned, so a result that reaches no
    /// worker closes it.
    pub(crate) opened: Option<std::os::fd::OwnedFd>,
}

/// A response from the disk I/O pool to a worker.
pub(crate) struct DiskIoResponse {
    /// Sequence number matching the original request.
    pub(crate) seq: u32,
    /// io_uring-compatible result.
    pub(crate) result: i32,
    /// Optional metadata (populated only for stat operations).
    pub(crate) metadata: Option<crate::fs::Metadata>,
    /// The fd a successful open produced; see [`DiskIoResult::opened`].
    pub(crate) opened: Option<std::os::fd::OwnedFd>,
}

/// Which requests the pool's threads are running, and whether the worker has
/// exited.
#[derive(Default)]
pub(crate) struct PoolState {
    /// Set when the worker exits: a request not yet started is answered
    /// `-ECANCELED` without running, so it uses no memory after exit (#856).
    pub(crate) abandon: bool,
    /// The sequence numbers of the requests a thread has started and not
    /// finished. A thread adds one only while `abandon` is false, under the
    /// same lock, so the set the exit drain reads after setting `abandon` is
    /// every request that can still run.
    pub(crate) running: std::collections::HashSet<u32>,
}

/// A pool of threads that perform blocking disk I/O.
///
/// Each mio worker starts its own pool, in `AsyncEventLoop::new`. Shutdown is
/// driven by dropping the request sender, which causes all pool threads to
/// exit.
pub(crate) struct DiskIoPool {
    pub(crate) request_tx: Sender<DiskIoRequest>,
    pub(crate) state: std::sync::Arc<std::sync::Mutex<PoolState>>,
    _threads: Vec<thread::JoinHandle<()>>,
}

impl DiskIoPool {
    /// Create the channel pair and spawn disk I/O threads.
    pub(crate) fn start(
        num_threads: usize,
        wake_keep_alive: crate::wakeup::WakeKeepAlive,
        #[cfg(test)] fault: Option<std::sync::Arc<crate::config::TestFault>>,
    ) -> Self {
        let (request_tx, request_rx) = crossbeam_channel::unbounded::<DiskIoRequest>();
        let state = std::sync::Arc::new(std::sync::Mutex::new(PoolState::default()));
        let mut threads = Vec::with_capacity(num_threads);

        for i in 0..num_threads {
            let rx = request_rx.clone();
            let state = std::sync::Arc::clone(&state);
            #[cfg(test)]
            let fault = fault.clone();
            let keep_alive = std::sync::Arc::clone(&wake_keep_alive);
            let handle = thread::Builder::new()
                .name(format!("ringline-disk-io-{i}"))
                .spawn(move || {
                    // Holds every worker's wake fd open while this thread
                    // can still wake one.
                    let _keep_alive = keep_alive;
                    disk_io_thread(
                        rx,
                        &state,
                        #[cfg(test)]
                        fault.as_deref(),
                    );
                })
                .expect("failed to spawn disk I/O thread");
            threads.push(handle);
        }

        DiskIoPool {
            request_tx,
            state,
            _threads: threads,
        }
    }
}

/// Main loop for a disk I/O thread.
fn disk_io_thread(
    rx: Receiver<DiskIoRequest>,
    state: &std::sync::Mutex<PoolState>,
    #[cfg(test)] fault: Option<&crate::config::TestFault>,
) {
    while let Ok(req) = rx.recv() {
        let start = {
            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
            if !state.abandon {
                state.running.insert(req.seq);
            }
            !state.abandon
        };
        let result = if start {
            #[cfg(test)]
            if let Some(fault) = fault {
                while fault
                    .hold_disk_io
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    fault
                        .disk_io_held
                        .store(true, std::sync::atomic::Ordering::Release);
                    thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            let result = (req.work)();
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .running
                .remove(&req.seq);
            result
        } else {
            #[cfg(test)]
            if let Some(fault) = fault {
                fault
                    .disk_io_skipped
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }
            DiskIoResult {
                result: -libc::ECANCELED,
                metadata: None,
                opened: None,
            }
        };
        let _ = req.response_tx.send(DiskIoResponse {
            seq: req.seq,
            result: result.result,
            metadata: result.metadata,
            opened: result.opened,
        });
        // Wake the requesting worker so it drains the response channel.
        req.wake_handle.wake();
    }
    // Channel closed — pool is shutting down.
}
