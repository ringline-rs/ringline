use std::future::Future;
use std::pin::Pin;

pub(crate) type BoxFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;

/// Opaque handle for a standalone task spawned via [`spawn()`](crate::spawn).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskId(pub(crate) u32);

/// State of a single task slot.
enum TaskSlot {
    /// Slot is empty (no task).
    Empty,
    /// The future is out of the slab, being polled. Distinct from `Empty`
    /// because `StandaloneTaskSlab::remove` has to tell "this task just
    /// finished, reclaim its index" from "there was never a task here, do
    /// not push a duplicate onto the free list".
    ///
    /// `wake` cannot transition this state — there is no future here to mark
    /// ready — which is why a task that wakes during its own poll is recorded
    /// in `Executor::woken_while_polling` and re-queued after parking instead.
    Polling,
    /// Task is parked (waiting for a wakeup).
    Parked(BoxFuture),
    /// Task is ready to be polled.
    Ready(BoxFuture),
}

/// Slab of per-connection async tasks, indexed by connection index.
///
/// One long-lived task per connection. Spawned on accept/connect,
/// dropped on close. O(1) lookup by `ConnToken::index()`.
pub(crate) struct TaskSlab {
    tasks: Vec<TaskSlot>,
}

impl TaskSlab {
    /// Create a new task slab with capacity for `max_connections` tasks.
    pub(crate) fn new(max_connections: u32) -> Self {
        let mut tasks = Vec::with_capacity(max_connections as usize);
        for _ in 0..max_connections {
            tasks.push(TaskSlot::Empty);
        }
        TaskSlab { tasks }
    }

    /// Spawn a new task for the given connection index.
    /// The task is immediately marked as Ready for its first poll.
    pub(crate) fn spawn(&mut self, conn_index: u32, future: BoxFuture) {
        let idx = conn_index as usize;
        debug_assert!(idx < self.tasks.len(), "conn_index out of range");
        debug_assert!(
            matches!(self.tasks[idx], TaskSlot::Empty),
            "task already exists for conn_index {conn_index}"
        );
        self.tasks[idx] = TaskSlot::Ready(future);
    }

    /// Take a Ready task out for polling. Returns None if the slot is
    /// not in the Ready state.
    pub(crate) fn take_ready(&mut self, conn_index: u32) -> Option<BoxFuture> {
        let idx = conn_index as usize;
        if idx >= self.tasks.len() {
            return None;
        }
        match std::mem::replace(&mut self.tasks[idx], TaskSlot::Polling) {
            TaskSlot::Ready(fut) => Some(fut),
            other => {
                // Put it back — was not Ready.
                self.tasks[idx] = other;
                None
            }
        }
    }

    /// Park a task back after it returned Poll::Pending.
    pub(crate) fn park(&mut self, conn_index: u32, future: BoxFuture) {
        let idx = conn_index as usize;
        debug_assert!(idx < self.tasks.len());
        self.tasks[idx] = TaskSlot::Parked(future);
    }

    /// Mark a Parked task as Ready (called when the waker fires).
    /// Returns true if the task was parked and is now ready.
    pub(crate) fn wake(&mut self, conn_index: u32) -> bool {
        let idx = conn_index as usize;
        if idx >= self.tasks.len() {
            return false;
        }
        match std::mem::replace(&mut self.tasks[idx], TaskSlot::Empty) {
            TaskSlot::Parked(fut) => {
                self.tasks[idx] = TaskSlot::Ready(fut);
                true
            }
            TaskSlot::Ready(fut) => {
                // Already ready — put it back.
                self.tasks[idx] = TaskSlot::Ready(fut);
                false // already queued
            }
            TaskSlot::Polling => {
                self.tasks[idx] = TaskSlot::Polling;
                false
            }
            TaskSlot::Empty => false,
        }
    }

    /// Remove a task (connection closed or future completed).
    pub(crate) fn remove(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        if idx < self.tasks.len() {
            self.tasks[idx] = TaskSlot::Empty;
        }
    }

    /// Check if a task exists for the given connection index.
    #[cfg(test)]
    pub(crate) fn has_task(&self, conn_index: u32) -> bool {
        let idx = conn_index as usize;
        idx < self.tasks.len() && !matches!(self.tasks[idx], TaskSlot::Empty)
    }
}

/// Slab of standalone async tasks (not bound to connections).
///
/// Uses a free list for O(1) allocate/deallocate. Task indices are independent
/// of connection indices — the executor distinguishes them via `STANDALONE_BIT`.
pub(crate) struct StandaloneTaskSlab {
    tasks: Vec<TaskSlot>,
    free_list: Vec<u32>,
}

impl StandaloneTaskSlab {
    /// Create a new standalone task slab with the given capacity.
    pub(crate) fn new(capacity: u32) -> Self {
        let mut tasks = Vec::with_capacity(capacity as usize);
        let mut free_list = Vec::with_capacity(capacity as usize);
        for i in 0..capacity {
            tasks.push(TaskSlot::Empty);
            free_list.push(i);
        }
        StandaloneTaskSlab { tasks, free_list }
    }

    /// Spawn a task. Returns the slot index, or None if the slab is full.
    pub(crate) fn spawn(&mut self, future: BoxFuture) -> Option<u32> {
        let idx = self.free_list.pop()?;
        self.tasks[idx as usize] = TaskSlot::Ready(future);
        Some(idx)
    }

    /// Take a Ready task out for polling.
    pub(crate) fn take_ready(&mut self, task_idx: u32) -> Option<BoxFuture> {
        let idx = task_idx as usize;
        if idx >= self.tasks.len() {
            return None;
        }
        match std::mem::replace(&mut self.tasks[idx], TaskSlot::Polling) {
            TaskSlot::Ready(fut) => Some(fut),
            other => {
                self.tasks[idx] = other;
                None
            }
        }
    }

    /// Park a task back after Poll::Pending.
    pub(crate) fn park(&mut self, task_idx: u32, future: BoxFuture) {
        let idx = task_idx as usize;
        debug_assert!(idx < self.tasks.len());
        self.tasks[idx] = TaskSlot::Parked(future);
    }

    /// Mark a Parked task as Ready. Returns true if it was parked.
    pub(crate) fn wake(&mut self, task_idx: u32) -> bool {
        let idx = task_idx as usize;
        if idx >= self.tasks.len() {
            return false;
        }
        match std::mem::replace(&mut self.tasks[idx], TaskSlot::Empty) {
            TaskSlot::Parked(fut) => {
                self.tasks[idx] = TaskSlot::Ready(fut);
                true
            }
            TaskSlot::Ready(fut) => {
                self.tasks[idx] = TaskSlot::Ready(fut);
                false
            }
            TaskSlot::Polling => {
                self.tasks[idx] = TaskSlot::Polling;
                false
            }
            TaskSlot::Empty => false,
        }
    }

    /// Remove a completed or cancelled task, returning its slot to the free
    /// list. Idempotent: a second call on an already-Empty slot is a no-op
    /// (the slot's index is *not* pushed onto the free list again, which
    /// would otherwise allow two future spawns to collide on the same slot
    /// and silently drop one of the two futures).
    pub(crate) fn remove(&mut self, task_idx: u32) {
        let idx = task_idx as usize;
        if idx >= self.tasks.len() {
            return;
        }
        let prev = std::mem::replace(&mut self.tasks[idx], TaskSlot::Empty);
        if !matches!(prev, TaskSlot::Empty) {
            self.free_list.push(task_idx);
        }
    }

    /// Check if a task exists at the given index.
    #[cfg(test)]
    pub(crate) fn has_task(&self, task_idx: u32) -> bool {
        let idx = task_idx as usize;
        idx < self.tasks.len() && !matches!(self.tasks[idx], TaskSlot::Empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Poll};

    /// A simple future that resolves after being polled N times.
    struct CountdownFuture(u32);

    impl Future for CountdownFuture {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 == 0 {
                Poll::Ready(())
            } else {
                self.0 -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    /// A completed standalone task must give its slot back. The slab is the
    /// only bound on how many standalone tasks can ever be spawned, so one
    /// slot lost per completion means a runtime that stops accepting spawns
    /// for good, `standalone_task_capacity` spawns after it starts. Measured
    /// in a server that spawns one task per buffer flush: of 4,866 flushes,
    /// the first 4,095 spawned and the remaining 771 could not, every one of
    /// them falling back to running inline on the event loop.
    #[test]
    fn completed_standalone_task_frees_its_slot() {
        let mut slab = StandaloneTaskSlab::new(1);
        for round in 0..10 {
            let idx = slab
                .spawn(Box::pin(async {}))
                .unwrap_or_else(|| panic!("slab full on round {round}"));
            // What the event loop does: take the future out, poll it to
            // completion, then remove it.
            let fut = slab.take_ready(idx).expect("ready after spawn");
            drop(fut);
            slab.remove(idx);
            assert!(!slab.has_task(idx));
        }
    }

    /// `remove` stays idempotent: a second call must not hand the same index
    /// out twice, or two spawns collide on one slot and one future is lost.
    #[test]
    fn removing_twice_does_not_double_free() {
        let mut slab = StandaloneTaskSlab::new(2);
        let a = slab.spawn(Box::pin(async {})).unwrap();
        let fut = slab.take_ready(a).unwrap();
        drop(fut);
        slab.remove(a);
        slab.remove(a);
        let x = slab.spawn(Box::pin(async {})).unwrap();
        let y = slab.spawn(Box::pin(async {})).unwrap();
        assert_ne!(x, y, "two spawns landed on the same slot");
        assert!(slab.spawn(Box::pin(async {})).is_none(), "capacity is 2");
    }

    #[test]
    fn spawn_and_take_ready() {
        let mut slab = TaskSlab::new(4);
        assert!(!slab.has_task(0));

        slab.spawn(0, Box::pin(CountdownFuture(2)));
        assert!(slab.has_task(0));

        // Should be Ready immediately after spawn.
        let fut = slab.take_ready(0);
        assert!(fut.is_some());

        // The future is out being polled, so the slot is not Ready and cannot
        // be taken again -- but it is still occupied, and only `remove` frees
        // it. A slot that read Empty here is what leaked standalone task
        // indices, because `remove` cannot distinguish Empty from finished.
        assert!(slab.take_ready(0).is_none());
        assert!(slab.has_task(0));
        slab.remove(0);
        assert!(!slab.has_task(0));
    }

    #[test]
    fn park_and_wake() {
        let mut slab = TaskSlab::new(4);
        slab.spawn(1, Box::pin(CountdownFuture(1)));

        let fut = slab.take_ready(1).unwrap();

        // Park the future.
        slab.park(1, fut);
        assert!(slab.has_task(1));

        // Not ready yet.
        assert!(slab.take_ready(1).is_none());

        // Wake it.
        assert!(slab.wake(1));

        // Now it's ready.
        assert!(slab.take_ready(1).is_some());
    }

    #[test]
    fn remove_task() {
        let mut slab = TaskSlab::new(4);
        slab.spawn(2, Box::pin(CountdownFuture(0)));
        assert!(slab.has_task(2));

        slab.remove(2);
        assert!(!slab.has_task(2));
    }

    #[test]
    fn wake_empty_slot() {
        let mut slab = TaskSlab::new(4);
        assert!(!slab.wake(3));
    }

    #[test]
    fn wake_already_ready() {
        let mut slab = TaskSlab::new(4);
        slab.spawn(0, Box::pin(CountdownFuture(0)));

        // Already ready — wake should return false (already queued).
        assert!(!slab.wake(0));
    }

    // ── StandaloneTaskSlab tests ──────────────────────────────────────

    #[test]
    fn standalone_spawn_and_take() {
        let mut slab = StandaloneTaskSlab::new(4);
        let idx = slab.spawn(Box::pin(CountdownFuture(2))).unwrap();
        assert!(slab.has_task(idx));
        let fut = slab.take_ready(idx);
        assert!(fut.is_some());
        // Out for polling: still occupied, not takeable, freed by `remove`.
        assert!(slab.take_ready(idx).is_none());
        assert!(slab.has_task(idx));
        slab.remove(idx);
        assert!(!slab.has_task(idx));
    }

    #[test]
    fn standalone_park_and_wake() {
        let mut slab = StandaloneTaskSlab::new(4);
        let idx = slab.spawn(Box::pin(CountdownFuture(1))).unwrap();
        let fut = slab.take_ready(idx).unwrap();
        slab.park(idx, fut);
        assert!(slab.take_ready(idx).is_none());
        assert!(slab.wake(idx));
        assert!(slab.take_ready(idx).is_some());
    }

    #[test]
    fn standalone_remove_returns_to_free_list() {
        let mut slab = StandaloneTaskSlab::new(2);
        let a = slab.spawn(Box::pin(CountdownFuture(0))).unwrap();
        let b = slab.spawn(Box::pin(CountdownFuture(0))).unwrap();
        // Slab is full.
        assert!(slab.spawn(Box::pin(CountdownFuture(0))).is_none());
        // Remove one — slot is reusable.
        slab.remove(a);
        assert!(slab.spawn(Box::pin(CountdownFuture(0))).is_some());
        slab.remove(b);
    }

    #[test]
    fn standalone_full_slab() {
        let mut slab = StandaloneTaskSlab::new(1);
        assert!(slab.spawn(Box::pin(CountdownFuture(0))).is_some());
        assert!(slab.spawn(Box::pin(CountdownFuture(0))).is_none());
    }

    #[test]
    fn standalone_remove_is_idempotent() {
        // Regression: removing an already-Empty slot must not push its index
        // onto the free list a second time, or two subsequent spawns will
        // return the same slot and silently overwrite the first future.
        let mut slab = StandaloneTaskSlab::new(2);
        let a = slab.spawn(Box::pin(CountdownFuture(0))).unwrap();
        slab.remove(a);
        slab.remove(a); // second remove is a no-op
        let b = slab.spawn(Box::pin(CountdownFuture(0))).unwrap();
        let c = slab.spawn(Box::pin(CountdownFuture(0))).unwrap();
        assert_ne!(
            b, c,
            "spawn must hand out distinct slots after redundant remove"
        );
        // Slab is now full — a 3rd spawn must fail.
        assert!(slab.spawn(Box::pin(CountdownFuture(0))).is_none());
    }
}
