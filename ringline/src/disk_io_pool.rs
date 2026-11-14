//! Dedicated disk I/O thread pool for the mio backend.
//!
//! Offloads blocking filesystem syscalls (open, pread, pwrite, fsync, stat,
//! lstat, rename, unlink, mkdir) from the mio event loop to a pool of
//! background threads. Each thread executes one blocking call at a time and
//! sends the result back via a per-worker crossbeam channel + `WakeFd`,
//! matching the pattern used by [`BlockingPool`](crate::blocking::BlockingPool).
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
    /// The worker's wake handle, written after a response when `wake_pending`
    /// was clear ([`wake_coalesced`]).
    pub(crate) wake_handle: crate::wakeup::WakeFd,
    /// Set by a pool thread that wrote the worker's wake pipe, cleared by the
    /// worker in `drain_channels`; see [`wake_coalesced`].
    pub(crate) wake_pending: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Wake a worker unless a pool thread has written its wake pipe since the
/// worker last cleared `pending` in `drain_channels`.
///
/// The worker clears `pending` (a swap) before it reads the response
/// channel, so a response queued after the clear writes again and none is
/// missed, while a burst of responses costs one write.
pub(crate) fn wake_coalesced(
    pending: &std::sync::atomic::AtomicBool,
    wake: &crate::wakeup::WakeFd,
) {
    if !pending.swap(true, std::sync::atomic::Ordering::AcqRel) {
        wake.wake();
    }
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

/// The subsystem a pool request counts against, with its own
/// `max_commands_in_flight` (`FsConfig`). fs is the only one: NVMe does not
/// run on mio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PoolSubsystem {
    Fs = 0,
}

/// A pool request held in the worker, not yet sent: its key and its work.
/// An fsync waits like this for the writes submitted before it (#905).
pub(crate) type HeldRequest = (u32, Box<dyn FnOnce() -> DiskIoResult + Send>);

/// Send `work` under key `seq` to `pool`, with the worker's response channel
/// and wake handle.
pub(crate) fn send_request(
    pool: &DiskIoPool,
    response_tx: &Sender<DiskIoResponse>,
    wake_handle: crate::wakeup::WakeFd,
    wake_pending: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    seq: u32,
    work: Box<dyn FnOnce() -> DiskIoResult + Send>,
) -> std::io::Result<()> {
    pool.request_tx
        .send(DiskIoRequest {
            work,
            seq,
            response_tx: response_tx.clone(),
            wake_handle,
            wake_pending: std::sync::Arc::clone(wake_pending),
        })
        .map_err(|_| std::io::Error::other("disk I/O pool shut down"))
}

impl PoolSubsystem {
    /// The error a submit past the subsystem's bound returns: the io_uring
    /// backend's kind and text for a full command slab.
    pub(crate) fn exhausted(self) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            match self {
                PoolSubsystem::Fs => "filesystem command slab exhausted",
            },
        )
    }

    /// The error a submit for an unconfigured subsystem returns: the io_uring
    /// backend's text.
    pub(crate) fn not_configured(self) -> std::io::Error {
        std::io::Error::other(match self {
            PoolSubsystem::Fs => "filesystem I/O not configured",
        })
    }
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
    /// Create the channel pair and spawn disk I/O threads, named
    /// `rl-disk-<worker>-<thread>`.
    pub(crate) fn start(
        worker_index: usize,
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
                .name(format!("rl-disk-{worker_index}-{i}"))
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
        wake_coalesced(&req.wake_pending, &req.wake_handle);
    }
    // Channel closed — pool is shutting down.
}

#[cfg(all(test, not(has_io_uring)))]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::wake_coalesced;

    /// Bytes waiting in the non-blocking read end `fd`, drained.
    fn drain(fd: std::os::fd::RawFd) -> usize {
        let mut total = 0;
        let mut buf = [0u8; 64];
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return total;
            }
            total += n as usize;
        }
    }

    /// A burst of completions writes the wake pipe once; after the worker
    /// clears the flag, the next completion writes again.
    #[test]
    fn a_burst_of_completions_writes_the_wake_pipe_once() {
        let (read_fd, handle) = crate::wakeup::create_wake_fd().expect("wake fd");
        let wake = handle.as_wake_fd();
        let pending = AtomicBool::new(false);
        for _ in 0..5 {
            wake_coalesced(&pending, &wake);
        }
        assert_eq!(drain(read_fd), 1, "five completions, one write");
        wake_coalesced(&pending, &wake);
        assert_eq!(drain(read_fd), 0, "the flag is still set: no write");
        pending.store(false, Ordering::Release);
        wake_coalesced(&pending, &wake);
        assert_eq!(drain(read_fd), 1, "a completion after the clear writes");
    }
}
