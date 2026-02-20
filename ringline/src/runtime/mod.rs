//! Async runtime for ringline: task executor, waker, and I/O primitives.
//!
//! # Portability boundary
//!
//! This module is designed so that the core async machinery is portable
//! across I/O backends (io_uring, mio/epoll, kqueue):
//!
//! - **Portable** (no io_uring dependency):
//!   - `task` — `TaskSlab`, `TaskSlot` (slab of per-connection futures)
//!   - `waker` — `conn_waker()`, thread-local `READY_QUEUE`
//!   - `mod.rs` — `Executor`, `IoResult` (waiter flags, ready queue, result storage)
//!   - `handler` — `AsyncEventHandler` trait (references `DriverCtx` by borrowed ref only)
//!
//! - **Backend-specific** (tied to the concrete `Driver` type):
//!   - `io` — `ConnCtx`, futures (`WithDataFuture`, `SendFuture`, `ConnectFuture`)
//!     accesses `Driver` via thread-local pointer
//!
//! A mio backend would provide an alternative `driver.rs`, `async_event_loop.rs`,
//! and `runtime/io.rs` while reusing everything else unchanged.

pub(crate) mod handler;
pub(crate) mod io;
pub(crate) mod join;
pub(crate) mod select;
pub(crate) mod task;
pub(crate) mod waker;

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::io as stdio;

use self::task::{StandaloneTaskSlab, TaskSlab};
use self::waker::drain_ready_queue;

/// I/O result stored per-connection for async task wakeup.
#[allow(dead_code)]
pub(crate) enum IoResult {
    /// Send completed with total bytes or error.
    Send(stdio::Result<u32>),
    /// Connect completed with success or error.
    Connect(stdio::Result<()>),
}

/// A recv sink that allows CQE data to be written directly to a target buffer,
/// bypassing the per-connection accumulator.
///
/// # Safety
///
/// The pointer is set by the async task before yielding and cleared after wakeup.
/// ringline is single-threaded per worker — CQE processing and task polling never
/// interleave — so the raw pointer is safe to dereference during CQE processing.
pub(crate) struct RecvSink {
    pub(crate) ptr: *mut u8,
    pub(crate) cap: usize,
    pub(crate) pos: usize,
}

thread_local! {
    /// The current task ID being polled. Set by the executor before each poll.
    /// Connection tasks: conn_index (bits 0..23).
    /// Standalone tasks: task_idx | STANDALONE_BIT.
    /// Used by SleepFuture to know which task to wake on timer completion.
    pub(crate) static CURRENT_TASK_ID: Cell<u32> = const { Cell::new(0) };
}

/// Pool of timer slots for io_uring timeout SQEs.
///
/// Each `sleep()` call allocates a slot that holds the `Timespec` (stable
/// memory for io_uring) and metadata. Generation counters prevent stale
/// CQEs from waking the wrong task after slot reuse.
pub(crate) struct TimerSlotPool {
    /// Timespec values — must remain at stable addresses for io_uring.
    pub(crate) timespecs: Vec<io_uring::types::Timespec>,
    /// Which task (with STANDALONE_BIT encoding) to wake when this timer fires.
    pub(crate) waker_ids: Vec<u32>,
    /// Whether the CQE has arrived for this timer.
    pub(crate) fired: Vec<bool>,
    /// Generation counter per slot to prevent stale CQE races.
    pub(crate) generations: Vec<u16>,
    /// Free slot indices for O(1) allocation.
    free_list: Vec<u32>,
}

impl TimerSlotPool {
    /// Create a new pool with the given capacity.
    pub(crate) fn new(capacity: u32) -> Self {
        let cap = capacity as usize;
        let mut free_list = Vec::with_capacity(cap);
        for i in 0..capacity {
            free_list.push(i);
        }
        TimerSlotPool {
            timespecs: vec![io_uring::types::Timespec::new(); cap],
            waker_ids: vec![0; cap],
            fired: vec![false; cap],
            generations: vec![0; cap],
            free_list,
        }
    }

    /// Allocate a timer slot. Returns `(slot_index, generation)` or None if full.
    pub(crate) fn allocate(&mut self, waker_id: u32) -> Option<(u32, u16)> {
        let slot = self.free_list.pop()?;
        let idx = slot as usize;
        self.waker_ids[idx] = waker_id;
        self.fired[idx] = false;
        let generation = self.generations[idx];
        Some((slot, generation))
    }

    /// Release a timer slot back to the free list.
    pub(crate) fn release(&mut self, slot: u32) {
        let idx = slot as usize;
        if idx < self.generations.len() {
            self.generations[idx] = self.generations[idx].wrapping_add(1);
            self.free_list.push(slot);
        }
    }

    /// Mark a timer as fired. Returns the waker_id if generation matches.
    pub(crate) fn fire(&mut self, slot: u32, generation: u16) -> Option<u32> {
        let idx = slot as usize;
        if idx >= self.generations.len() || self.generations[idx] != generation {
            return None; // stale CQE
        }
        self.fired[idx] = true;
        Some(self.waker_ids[idx])
    }

    /// Check if a timer slot has fired.
    pub(crate) fn is_fired(&self, slot: u32) -> bool {
        self.fired.get(slot as usize).copied().unwrap_or(false)
    }

    /// Encode `(slot_index, generation)` into a 32-bit payload for UserData.
    pub(crate) fn encode_payload(slot: u32, generation: u16) -> u32 {
        (slot & 0xFFFF) | ((generation as u32) << 16)
    }

    /// Decode payload back to `(slot_index, generation)`.
    pub(crate) fn decode_payload(payload: u32) -> (u32, u16) {
        let slot = payload & 0xFFFF;
        let generation = (payload >> 16) as u16;
        (slot, generation)
    }
}

/// Per-worker async executor. Owns the task slab and coordinates
/// CQE-driven wakeups with future polling.
pub(crate) struct Executor {
    pub(crate) task_slab: TaskSlab,
    /// Standalone tasks not bound to any connection.
    pub(crate) standalone_slab: StandaloneTaskSlab,
    /// Timer slot pool for sleep/timeout.
    pub(crate) timer_pool: TimerSlotPool,
    /// Connection indices (and standalone task indices with STANDALONE_BIT) ready to poll.
    pub(crate) ready_queue: VecDeque<u32>,
    /// Per-connection: task is awaiting recv data.
    pub(crate) recv_waiters: Vec<bool>,
    /// Per-connection: task is awaiting send completion.
    pub(crate) send_waiters: Vec<bool>,
    /// Per-connection: task is awaiting connect result.
    pub(crate) connect_waiters: Vec<bool>,
    /// Per-connection: CQE result storage for send/connect.
    pub(crate) io_results: Vec<Option<IoResult>>,
    /// Maps conn_index → owning task ID. For accepted connections, `owner_task[i] = Some(i)`
    /// (self-owned). For outbound connections created via `ConnCtx::connect()`,
    /// `owner_task[i] = Some(calling_task_id)` where `calling_task_id` is the task
    /// that initiated the connect. This indirection allows `wake_recv`/`wake_send`/
    /// `wake_connect` to wake the correct task even when the connection index differs
    /// from the task index.
    pub(crate) owner_task: Vec<Option<u32>>,
    /// Per-connection recv sink for direct-to-buffer writes.
    pub(crate) recv_sinks: Vec<Option<RecvSink>>,
    /// Per-UDP-socket datagram recv queue for async tasks.
    pub(crate) udp_recv_queues: Vec<VecDeque<(Vec<u8>, std::net::SocketAddr)>>,
    /// Per-UDP-socket: task ID waiting for recv_from (None = no waiter).
    pub(crate) udp_recv_waiters: Vec<Option<u32>>,
    /// Disk I/O: maps command slab_idx → task_id to wake on completion.
    pub(crate) disk_io_waiters: HashMap<u32, u32>,
    /// Disk I/O: maps command slab_idx → i32 result from CQE.
    pub(crate) disk_io_results: HashMap<u32, i32>,
}

impl Executor {
    /// Create a new executor with the given capacities.
    pub(crate) fn new(
        max_connections: u32,
        standalone_capacity: u32,
        timer_slots: u32,
        udp_count: u32,
    ) -> Self {
        let cap = max_connections as usize;
        let udp = udp_count as usize;
        Executor {
            task_slab: TaskSlab::new(max_connections),
            standalone_slab: StandaloneTaskSlab::new(standalone_capacity),
            timer_pool: TimerSlotPool::new(timer_slots),
            ready_queue: VecDeque::with_capacity(64),
            recv_waiters: vec![false; cap],
            send_waiters: vec![false; cap],
            connect_waiters: vec![false; cap],
            io_results: {
                let mut v = Vec::with_capacity(cap);
                for _ in 0..cap {
                    v.push(None);
                }
                v
            },
            owner_task: vec![None; cap],
            recv_sinks: {
                let mut v = Vec::with_capacity(cap);
                for _ in 0..cap {
                    v.push(None);
                }
                v
            },
            udp_recv_queues: (0..udp).map(|_| VecDeque::new()).collect(),
            udp_recv_waiters: vec![None; udp],
            disk_io_waiters: HashMap::new(),
            disk_io_results: HashMap::new(),
        }
    }

    /// Drain the thread-local waker queue into our ready_queue,
    /// then wake corresponding tasks in the slab.
    pub(crate) fn collect_wakeups(&mut self) {
        drain_ready_queue(&mut self.ready_queue);
    }

    /// Reset all per-connection state for a connection that was closed.
    pub(crate) fn remove_connection(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        // Clear recv sink before removing the task — the task owns the memory
        // the sink points to, so the sink must be invalidated first.
        if idx < self.recv_sinks.len() {
            self.recv_sinks[idx] = None;
        }
        self.task_slab.remove(conn_index);
        if idx < self.recv_waiters.len() {
            self.recv_waiters[idx] = false;
            self.send_waiters[idx] = false;
            self.connect_waiters[idx] = false;
            self.io_results[idx] = None;
            self.owner_task[idx] = None;
        }
    }

    /// Wake a task by its ID (connection task or standalone task).
    ///
    /// Handles both connection tasks (plain index) and standalone tasks
    /// (index | STANDALONE_BIT). Returns true if the task was parked and
    /// is now ready.
    pub(crate) fn wake_task(&mut self, task_id: u32) -> bool {
        if task_id & waker::STANDALONE_BIT != 0 {
            let idx = task_id & !waker::STANDALONE_BIT;
            if self.standalone_slab.wake(idx) {
                self.ready_queue.push_back(task_id);
                return true;
            }
        } else if self.task_slab.wake(task_id) {
            self.ready_queue.push_back(task_id);
            return true;
        }
        false
    }

    /// Wake a task that was waiting for recv data.
    ///
    /// Resolves through `owner_task` so that outbound connections correctly
    /// wake the task that owns them (which may differ from the conn_index).
    pub(crate) fn wake_recv(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        if idx < self.recv_waiters.len() && self.recv_waiters[idx] {
            self.recv_waiters[idx] = false;
            let task_id = self.owner_task[idx].unwrap_or(conn_index);
            self.wake_task(task_id);
        }
    }

    /// Wake a task that was waiting for send completion.
    pub(crate) fn wake_send(&mut self, conn_index: u32, result: stdio::Result<u32>) {
        let idx = conn_index as usize;
        if idx < self.send_waiters.len() && self.send_waiters[idx] {
            self.send_waiters[idx] = false;
            self.io_results[idx] = Some(IoResult::Send(result));
            let task_id = self.owner_task[idx].unwrap_or(conn_index);
            self.wake_task(task_id);
        }
    }

    /// Wake a task that was waiting for a UDP datagram.
    pub(crate) fn wake_udp_recv(&mut self, udp_index: u32) {
        let idx = udp_index as usize;
        if idx < self.udp_recv_waiters.len()
            && let Some(task_id) = self.udp_recv_waiters[idx].take()
        {
            self.wake_task(task_id);
        }
    }

    /// Wake a task that was waiting for connect completion.
    pub(crate) fn wake_connect(&mut self, conn_index: u32, result: stdio::Result<()>) {
        let idx = conn_index as usize;
        if idx < self.connect_waiters.len() && self.connect_waiters[idx] {
            self.connect_waiters[idx] = false;
            self.io_results[idx] = Some(IoResult::Connect(result));
            let task_id = self.owner_task[idx].unwrap_or(conn_index);
            self.wake_task(task_id);
        }
    }

    /// Wake a task that was waiting for a disk I/O completion.
    ///
    /// Stores the CQE result and wakes the task if one is registered.
    /// Disk I/O waiters are keyed by slab_idx (not conn_index), so
    /// `remove_connection()` does not need to clear them — the task
    /// holds the `DiskIoFuture` and will consume the result.
    pub(crate) fn wake_disk_io(&mut self, seq: u32, result: i32) {
        self.disk_io_results.insert(seq, result);
        if let Some(task_id) = self.disk_io_waiters.remove(&seq) {
            self.wake_task(task_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_new() {
        let exec = Executor::new(16, 8, 8, 0);
        assert!(exec.ready_queue.is_empty());
        assert_eq!(exec.recv_waiters.len(), 16);
        assert_eq!(exec.send_waiters.len(), 16);
        assert_eq!(exec.connect_waiters.len(), 16);
        assert_eq!(exec.io_results.len(), 16);
        assert_eq!(exec.owner_task.len(), 16);
    }

    #[test]
    fn remove_connection_clears_state() {
        let mut exec = Executor::new(4, 4, 4, 0);
        exec.recv_waiters[1] = true;
        exec.send_waiters[1] = true;
        exec.connect_waiters[1] = true;
        exec.io_results[1] = Some(IoResult::Send(Ok(42)));
        exec.owner_task[1] = Some(0);

        exec.remove_connection(1);
        assert!(!exec.recv_waiters[1]);
        assert!(!exec.send_waiters[1]);
        assert!(!exec.connect_waiters[1]);
        assert!(exec.io_results[1].is_none());
        assert!(exec.owner_task[1].is_none());
    }

    #[test]
    fn wake_task_connection_task() {
        let mut exec = Executor::new(4, 4, 4, 0);
        // Spawn a task at index 1 (simulated by setting it up as Ready then parking).
        exec.task_slab
            .spawn(1, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(1).unwrap();
        exec.task_slab.park(1, fut);

        assert!(exec.wake_task(1));
        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 1);
    }

    #[test]
    fn wake_task_standalone_task() {
        let mut exec = Executor::new(4, 4, 4, 0);
        let idx = exec
            .standalone_slab
            .spawn(Box::pin(std::future::pending::<()>()))
            .unwrap();
        let fut = exec.standalone_slab.take_ready(idx).unwrap();
        exec.standalone_slab.park(idx, fut);

        let task_id = idx | waker::STANDALONE_BIT;
        assert!(exec.wake_task(task_id));
        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], task_id);
    }

    #[test]
    fn owner_task_routes_recv_wakeup() {
        let mut exec = Executor::new(16, 4, 4, 0);

        // Task at index 5 owns connection 12 (outbound connect scenario).
        exec.task_slab
            .spawn(5, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(5).unwrap();
        exec.task_slab.park(5, fut);

        exec.owner_task[12] = Some(5);
        exec.recv_waiters[12] = true;

        exec.wake_recv(12);

        // The task at index 5 should be woken, not index 12.
        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 5);
        assert!(!exec.recv_waiters[12]);
    }

    #[test]
    fn owner_task_routes_send_wakeup() {
        let mut exec = Executor::new(16, 4, 4, 0);

        exec.task_slab
            .spawn(3, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(3).unwrap();
        exec.task_slab.park(3, fut);

        exec.owner_task[10] = Some(3);
        exec.send_waiters[10] = true;

        exec.wake_send(10, Ok(42));

        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 3);
        assert!(!exec.send_waiters[10]);
        assert!(matches!(exec.io_results[10], Some(IoResult::Send(Ok(42)))));
    }

    #[test]
    fn owner_task_routes_connect_wakeup() {
        let mut exec = Executor::new(16, 4, 4, 0);

        exec.task_slab
            .spawn(2, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(2).unwrap();
        exec.task_slab.park(2, fut);

        exec.owner_task[8] = Some(2);
        exec.connect_waiters[8] = true;

        exec.wake_connect(8, Ok(()));

        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 2);
        assert!(!exec.connect_waiters[8]);
    }

    #[test]
    fn owner_task_none_falls_back_to_conn_index() {
        let mut exec = Executor::new(4, 4, 4, 0);

        // owner_task is None — should fall back to using conn_index directly.
        exec.task_slab
            .spawn(1, Box::pin(std::future::pending::<()>()));
        let fut = exec.task_slab.take_ready(1).unwrap();
        exec.task_slab.park(1, fut);

        exec.recv_waiters[1] = true;
        exec.wake_recv(1);

        assert_eq!(exec.ready_queue.len(), 1);
        assert_eq!(exec.ready_queue[0], 1);
    }
}
