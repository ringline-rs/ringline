use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use super::CURRENT_TASK_ID;

// The waker's data is a `usize`: the task id in the low 32 bits and the
// owning worker's id in the high 32.
const _: () = assert!(
    std::mem::size_of::<usize>() >= 8,
    "ringline wakers need a 64-bit usize"
);

thread_local! {
    // Thread-local queue of connection indices whose tasks are ready to poll.
    // Wakers on the owning worker's thread push to this queue; the executor
    // drains it after each CQE batch.
    pub(crate) static READY_QUEUE: std::cell::RefCell<VecDeque<u32>> =
        const { std::cell::RefCell::new(VecDeque::new()) };
    // Wakers that are not their task's own, by task id, then by what the waker
    // would wake, so polling a leaf again with one waker keeps one entry. A
    // leaf's completion wakes its task by id, so these fire when a leaf of that
    // task completes and when the task ends.
    static KEPT_WAKERS: std::cell::RefCell<BTreeMap<(u32, usize, usize), Waker>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
    // Whether `KEPT_WAKERS` may hold a waker. A worker with none pays for
    // reading this on each wake.
    static WAKERS_KEPT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    // The id of the worker whose executor runs on this thread, or 0.
    static CURRENT_WORKER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// The id of the worker whose executor runs on this thread, or 0.
pub(crate) fn current_worker() -> u32 {
    CURRENT_WORKER.with(|c| c.get())
}

/// Bit flag that distinguishes standalone tasks from connection tasks
/// in the ready queue. Connection indices use bits 0..23 (max 16M),
/// so bit 31 is always free for connection tasks.
pub(crate) const STANDALONE_BIT: u32 = 1 << 31;

/// Where a waker woken off its worker's thread delivers the task id. One per
/// executor, registered in `INBOXES` under the worker's id while the executor
/// lives.
pub(crate) struct Inbox {
    ids: Mutex<Vec<u32>>,
    /// Set after an id is pushed, so the executor takes the lock only after a
    /// wake has set it.
    nonempty: AtomicBool,
    /// The worker's wake fd, written by the push that sets `nonempty`, so a
    /// worker blocked in its event loop wakes. Unset for an executor with no event loop (unit
    /// tests).
    wake: OnceLock<crate::wakeup::WakeHandle>,
}

/// Inboxes of live executors, by worker id.
fn inboxes() -> &'static RwLock<HashMap<u32, Arc<Inbox>>> {
    static INBOXES: OnceLock<RwLock<HashMap<u32, Arc<Inbox>>>> = OnceLock::new();
    INBOXES.get_or_init(|| RwLock::new(HashMap::new()))
}

/// A worker's registration: its id, process-unique and never reused, and its
/// inbox. Registering makes the calling thread the worker's thread; dropping
/// the registration removes the inbox, so a later wake for this worker is
/// dropped.
pub(crate) struct WorkerWakes {
    id: u32,
    inbox: Arc<Inbox>,
}

impl WorkerWakes {
    pub(crate) fn register() -> Self {
        static NEXT_ID: AtomicU32 = AtomicU32::new(1);
        // Stops at the maximum rather than wrapping, so an id is never handed
        // out twice.
        let mut id = NEXT_ID.load(Ordering::Relaxed);
        loop {
            let next = id.checked_add(1).expect("worker ids exhausted");
            match NEXT_ID.compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(current) => id = current,
            }
        }
        let inbox = Arc::new(Inbox {
            ids: Mutex::new(Vec::new()),
            nonempty: AtomicBool::new(false),
            wake: OnceLock::new(),
        });
        inboxes()
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&inbox));
        CURRENT_WORKER.with(|c| c.set(id));
        WorkerWakes { id, inbox }
    }

    pub(crate) fn id(&self) -> u32 {
        self.id
    }

    /// Give the inbox the worker's wake handle, so a cross-thread wake also
    /// wakes the event loop.
    pub(crate) fn set_wake_handle(&self, wake: crate::wakeup::WakeHandle) {
        let _ = self.inbox.wake.set(wake);
    }

    /// Move ids woken from other threads into `buf`.
    pub(crate) fn drain_into(&self, buf: &mut VecDeque<u32>) {
        // A plain load first, so a worker that never receives cross-thread
        // wakes pays no read-modify-write per call.
        if self.inbox.nonempty.load(Ordering::Relaxed)
            && self.inbox.nonempty.swap(false, Ordering::Acquire)
        {
            let mut ids = self.inbox.ids.lock().unwrap_or_else(|e| e.into_inner());
            buf.extend(ids.drain(..));
        }
    }
}

impl Drop for WorkerWakes {
    fn drop(&mut self) {
        inboxes()
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
        CURRENT_WORKER.with(|c| {
            if c.get() == self.id {
                c.set(0);
            }
        });
    }
}

/// Create a [`Waker`] for the given connection index on worker `owner`.
///
/// Zero allocation: the index and the worker id are packed into the raw
/// pointer. Woken on the owner's thread, it pushes the index onto the
/// thread-local `READY_QUEUE`; woken on any other thread, it delivers the
/// index to the owner's inbox and wakes the owner's event loop.
pub(crate) fn conn_waker(owner: u32, conn_index: u32) -> Waker {
    debug_assert!(
        conn_index & STANDALONE_BIT == 0,
        "conn_index has standalone bit set"
    );
    make_waker(owner, conn_index)
}

/// Create a [`Waker`] for a standalone task (not bound to a connection).
///
/// The `task_idx` is OR'd with `STANDALONE_BIT` so the executor can
/// distinguish it from connection wakeups.
pub(crate) fn standalone_waker(owner: u32, task_idx: u32) -> Waker {
    debug_assert!(
        task_idx & STANDALONE_BIT == 0,
        "task_idx already has standalone bit"
    );
    make_waker(owner, task_idx | STANDALONE_BIT)
}

fn waker_data(owner: u32, task_id: u32) -> *const () {
    (((owner as usize) << 32) | task_id as usize) as *const ()
}

fn make_waker(owner: u32, task_id: u32) -> Waker {
    let data = waker_data(owner, task_id);
    // SAFETY: The vtable functions below follow the RawWaker contract.
    // The "data" is just a usize cast to a pointer — no heap allocation, no
    // lifetime concerns.
    unsafe { Waker::from_raw(RawWaker::new(data, &VTABLE)) }
}

// A `static`, not a `const`: `pending` compares its address, and each use of a
// `const` may have its own.
static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_fn, wake_fn, wake_by_ref_fn, drop_fn);

unsafe fn clone_fn(data: *const ()) -> RawWaker {
    RawWaker::new(data, &VTABLE)
}

unsafe fn wake_fn(data: *const ()) {
    // SAFETY: wake_by_ref_fn is safe to call with data from our vtable.
    unsafe { wake_by_ref_fn(data) };
}

unsafe fn wake_by_ref_fn(data: *const ()) {
    let data = data as usize;
    let task_id = data as u32;
    let owner = (data >> 32) as u32;
    if CURRENT_WORKER.with(|c| c.get()) == owner {
        READY_QUEUE.with(|q| {
            q.borrow_mut().push_back(task_id);
        });
    } else {
        wake_remote(owner, task_id);
    }
}

/// Deliver a wake from a thread other than the owning worker's. A worker that
/// has exited has no inbox, and the wake is dropped: its tasks are gone.
#[cold]
fn wake_remote(owner: u32, task_id: u32) {
    let inbox = inboxes()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&owner)
        .cloned();
    let Some(inbox) = inbox else {
        return;
    };
    inbox
        .ids
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(task_id);
    // After the push, so the executor that sees the flag finds the id. Only
    // the wake that sets the flag writes the fd: a flag already set means an
    // earlier wake has written it, or is about to, and the executor drains
    // the inbox only after clearing the flag.
    if !inbox.nonempty.swap(true, Ordering::AcqRel)
        && let Some(wake) = inbox.wake.get()
    {
        wake.wake();
    }
}

unsafe fn drop_fn(_data: *const ()) {
    // No resources to free — data is just a usize.
}

/// What a leaf future returns once it has registered to be woken by task id.
///
/// A leaf's completion wakes the task that polled it, whatever waker the leaf
/// was polled with. If `cx` holds another waker, something other than the
/// executor polled the leaf, usually a combinator that polls a child only when
/// the child's own waker fires, so `cx`'s waker is kept for
/// [`wake_combinators`].
#[inline]
pub(crate) fn pending<T>(cx: &Context<'_>) -> Poll<T> {
    let task_id = CURRENT_TASK_ID.with(|c| c.get());
    let own = waker_data(current_worker(), task_id);
    let waker = cx.waker();
    if waker.data() != own || !std::ptr::eq(waker.vtable(), &VTABLE) {
        keep_waker(task_id, waker);
    }
    Poll::Pending
}

#[cold]
fn keep_waker(task_id: u32, waker: &Waker) {
    let key = (
        task_id,
        waker.data() as usize,
        std::ptr::from_ref(waker.vtable()) as usize,
    );
    // The clone is outside the borrow: a custom waker's clone is arbitrary code.
    if !KEPT_WAKERS.with_borrow(|wakers| wakers.contains_key(&key)) {
        let waker = waker.clone();
        KEPT_WAKERS.with_borrow_mut(|wakers| wakers.insert(key, waker));
    }
    WAKERS_KEPT.set(true);
}

/// Fire the wakers [`pending`] kept for `task_id`. Called when a leaf of the
/// task completes, and when the task ends, so no waker outlives its task. Until
/// then a waker stays kept, whether or not the leaf it was kept for has been
/// dropped.
///
/// The completion does not say which leaf it was for, so every leaf in those
/// combinators is polled again, and those not done register again. Calling
/// this for a wake through a task's own waker would spin the worker:
/// `FuturesUnordered` wakes its task when it yields after a poll budget, which
/// would poll all its children again.
#[inline]
pub(crate) fn wake_combinators(task_id: u32) {
    if WAKERS_KEPT.get() {
        wake_kept_wakers(task_id);
    }
}

/// A kept waker runs where the completion runs: in the completion loop, or
/// inside another task's poll, under `with_state`, when a channel send, a cancel
/// or a task's end wakes the waiter. It must not call into ringline. The standard
/// combinators' wakers touch only atomics, the ready queue and, for `Shared`, its
/// own `Mutex` and the wakers it holds, which can reach another worker's inbox.
/// A panic in one goes to the panic hook and goes no further, under either
/// `TaskPanicPolicy`.
#[cold]
fn wake_kept_wakers(task_id: u32) {
    // `try_with`: a future dropped during thread exit can land here after the
    // map is gone.
    let wakers = KEPT_WAKERS.try_with(|wakers| {
        let mut wakers = wakers.borrow_mut();
        let range = (task_id, 0, 0)..=(task_id, usize::MAX, usize::MAX);
        let keys: Vec<_> = wakers.range(range).map(|(key, _)| *key).collect();
        let taken: Vec<_> = keys.iter().filter_map(|key| wakers.remove(key)).collect();
        WAKERS_KEPT.set(!wakers.is_empty());
        taken
    });
    for waker in wakers.into_iter().flatten() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()));
    }
}

/// Drain the thread-local ready queue into the provided buffer.
pub(crate) fn drain_ready_queue(buf: &mut VecDeque<u32>) {
    READY_QUEUE.with(|q| {
        buf.append(&mut q.borrow_mut());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waker_pushes_to_ready_queue() {
        // Clear any leftover state.
        READY_QUEUE.with(|q| q.borrow_mut().clear());

        let wakes = WorkerWakes::register();
        let waker = conn_waker(wakes.id(), 42);
        waker.wake_by_ref();
        waker.wake_by_ref();

        let mut buf = VecDeque::new();
        drain_ready_queue(&mut buf);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], 42);
        assert_eq!(buf[1], 42);
    }

    #[test]
    fn waker_clone_works() {
        READY_QUEUE.with(|q| q.borrow_mut().clear());

        let wakes = WorkerWakes::register();
        let waker = conn_waker(wakes.id(), 7);
        let cloned = waker.clone();

        waker.wake_by_ref();
        cloned.wake();

        let mut buf = VecDeque::new();
        drain_ready_queue(&mut buf);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], 7);
        assert_eq!(buf[1], 7);
    }

    fn kept_wakers() -> usize {
        KEPT_WAKERS.with_borrow(|wakers| wakers.len())
    }

    #[test]
    fn a_tasks_own_waker_is_not_kept() {
        let wakes = WorkerWakes::register();
        CURRENT_TASK_ID.with(|c| c.set(5));
        let conn = conn_waker(wakes.id(), 5);
        assert!(pending::<()>(&Context::from_waker(&conn)).is_pending());
        CURRENT_TASK_ID.with(|c| c.set(6 | STANDALONE_BIT));
        let standalone = standalone_waker(wakes.id(), 6);
        assert!(pending::<()>(&Context::from_waker(&standalone)).is_pending());
        assert_eq!(kept_wakers(), 0);
        assert!(!WAKERS_KEPT.get());
    }

    #[test]
    fn another_waker_is_kept_once_and_fired_once() {
        struct Count(std::sync::atomic::AtomicU32);
        impl std::task::Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let wakes = WorkerWakes::register();
        CURRENT_TASK_ID.with(|c| c.set(5));
        let count = Arc::new(Count(AtomicU32::new(0)));
        let waker = Waker::from(Arc::clone(&count));
        for _ in 0..3 {
            assert!(pending::<()>(&Context::from_waker(&waker)).is_pending());
        }
        assert_eq!(kept_wakers(), 1);

        // Another task's wakers stay. A wake of this task fires its own once.
        wake_combinators(6);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        wake_combinators(5);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(kept_wakers(), 0);
        assert!(!WAKERS_KEPT.get());
        drop(wakes);
    }

    /// The end of a task fires what it kept, on both slabs, for wakers whose
    /// leaf will never complete.
    #[test]
    fn the_end_of_a_task_fires_its_kept_wakers() {
        use crate::runtime::task::{StandaloneTaskSlab, TaskSlab};

        let wakes = WorkerWakes::register();
        let keep_for = |task_id: u32| {
            CURRENT_TASK_ID.with(|c| c.set(task_id));
            let waker = std::task::Waker::noop();
            assert!(pending::<()>(&Context::from_waker(waker)).is_pending());
            assert_eq!(kept_wakers(), 1);
        };

        let mut tasks = TaskSlab::new(4);
        tasks.spawn(2, Box::pin(async {}));
        keep_for(2);
        tasks.remove(2);
        assert_eq!(kept_wakers(), 0);

        let mut standalone = StandaloneTaskSlab::new(4);
        let idx = standalone.spawn(Box::pin(async {})).expect("a slot");
        keep_for(idx | STANDALONE_BIT);
        standalone.remove(idx);
        assert_eq!(kept_wakers(), 0);
        drop(wakes);
    }

    #[test]
    fn a_panicking_waker_does_not_stop_the_others() {
        struct Panics;
        impl std::task::Wake for Panics {
            fn wake(self: Arc<Self>) {
                panic!("a waker panicked");
            }
        }
        struct Flag(AtomicBool);
        impl std::task::Wake for Flag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let _wakes = WorkerWakes::register();
        CURRENT_TASK_ID.with(|c| c.set(5));
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let wakers = [
            Waker::from(Arc::new(Panics)),
            Waker::from(Arc::clone(&flag)),
        ];
        let wakers = if wakers[0].data() < wakers[1].data() {
            wakers
        } else {
            let [a, b] = wakers;
            [b, a]
        };
        for waker in &wakers {
            assert!(pending::<()>(&Context::from_waker(waker)).is_pending());
        }
        wake_combinators(5);
        assert!(flag.0.load(Ordering::SeqCst));
    }

    #[test]
    fn drain_empty_queue() {
        READY_QUEUE.with(|q| q.borrow_mut().clear());

        let mut buf = VecDeque::new();
        drain_ready_queue(&mut buf);
        assert!(buf.is_empty());
    }
}
