//! User-facing blocking thread pool.
//!
//! Offloads blocking or CPU-bound work from io_uring worker threads.
//! On Linux the threads run at `SCHED_BATCH`: they get the same CPU share as
//! other threads, and a pool thread that wakes does not preempt the thread
//! running on its CPU, such as a worker's event loop.

use std::any::Any;
use std::thread;

use crossbeam_channel::{Receiver, Sender};

/// A request from a worker to the blocking pool.
pub(crate) struct BlockingRequest {
    pub(crate) work: Box<dyn FnOnce() -> Box<dyn Any + Send> + Send>,
    pub(crate) request_id: u64,
    /// Per-worker response channel.
    pub(crate) response_tx: Sender<BlockingResponse>,
    /// Wake handle — used to wake the worker after sending the response.
    pub(crate) wake_handle: crate::wakeup::WakeFd,
}

/// A response from the blocking pool to a worker.
pub(crate) struct BlockingResponse {
    pub(crate) request_id: u64,
    pub(crate) result: BlockingResult,
}

/// A blocking closure's value, or its panic payload.
pub(crate) type BlockingResult = Result<Box<dyn Any + Send>, Box<dyn Any + Send>>;

/// A pool of threads that perform blocking work.
///
/// Created once in [`launch_inner`](crate::worker) and shared (via `Arc`)
/// across all workers. Shutdown is driven by dropping the request sender,
/// which causes all pool threads to exit.
pub(crate) struct BlockingPool {
    pub(crate) request_tx: Sender<BlockingRequest>,
    _threads: Vec<thread::JoinHandle<()>>,
}

impl BlockingPool {
    /// Create the channel pair and spawn blocking threads.
    pub(crate) fn start(num_threads: usize, wake_keep_alive: crate::wakeup::WakeKeepAlive) -> Self {
        let (request_tx, request_rx) = crossbeam_channel::unbounded::<BlockingRequest>();
        let mut threads = Vec::with_capacity(num_threads);

        for i in 0..num_threads {
            let rx = request_rx.clone();
            let keep_alive = std::sync::Arc::clone(&wake_keep_alive);
            let handle = thread::Builder::new()
                .name(format!("rl-blok-{i}"))
                .spawn(move || {
                    // Not SCHED_IDLE: on a busy host a SCHED_IDLE thread gets
                    // almost no CPU, and it cannot leave that policy without
                    // CAP_SYS_NICE or an RLIMIT_NICE of at least 20 (the
                    // default is 0). When such a thread is the last of the
                    // process to exit, it unmaps the address space and closes
                    // the files at that priority, which can take seconds.
                    #[cfg(target_os = "linux")]
                    {
                        // SAFETY: an all-zero `sched_param` (priority 0) is
                        // the value SCHED_BATCH requires.
                        let param: libc::sched_param = unsafe { std::mem::zeroed() };
                        // SAFETY: sets this thread's policy; `param` outlives
                        // the call.
                        unsafe {
                            libc::sched_setscheduler(0, libc::SCHED_BATCH, &param);
                        }
                    }
                    // Holds every worker's wake fd open while this thread
                    // can still wake one.
                    let _keep_alive = keep_alive;
                    blocking_thread(rx);
                })
                .expect("failed to spawn blocking thread");
            threads.push(handle);
        }

        BlockingPool {
            request_tx,
            _threads: threads,
        }
    }
}

/// Main loop for a blocking thread.
fn blocking_thread(rx: Receiver<BlockingRequest>) {
    while let Ok(req) = rx.recv() {
        // A panicking closure must not take the pool thread with it; the
        // payload goes back to the requesting worker instead.
        let work = req.work;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
        // A send to a stopped worker returns the response here, and a panic in
        // its `Drop` must not take the pool thread either.
        let _ = crate::task_panic::drop_caught(req.response_tx.send(BlockingResponse {
            request_id: req.request_id,
            result,
        }));
        // Wake the requesting worker so it drains the response channel.
        req.wake_handle.wake();
    }
    // Channel closed — pool is shutting down.
}
