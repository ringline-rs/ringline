//! Per-worker completion table for awaited sends, and the admission FIFO
//! for bounded sends.
//!
//! Every send through `SendHalf` (`send`, `forward_recv_buf`, `send_parts`'
//! `build` and `submit_batch`, `send_admitted`,
//! `send_backpressured`) holds an entry here, named by the
//! [`SendId`] its future keeps. The driver settles the entry when that send
//! completes, and the future resolves with the result of that one send. A
//! bounded send (`SendHalf::send_admitted`, `send_backpressured`) is also
//! admission-controlled: it reserves copy-pool slots once it is the
//! *oldest* waiter on the worker and the pool can admit its whole message,
//! or, under [`SendAdmissionOrder::Budget`], once it may pass an older
//! waiter that does not fit (see "Admission orders" below).
//!
//! The table is plain worker-local state owned by the [`Executor`]. Every
//! entry holds a slot indexed by its id, and is also listed under its target
//! connection and, when a connection task owns it, under that task; waiting
//! bounded sends are listed in arrival order. `register`, `set_owner`,
//! `complete`, `take_result`, `mark_submitted` and `cancel` are index
//! lookups; `remove_connection`, `fail_waiting` and `abort_connection`
//! visit the entries listed under their connection. An entry that leaves the
//! waiting state leaves its id in the waiting list, and the reads of the head
//! pop the ids at the front that no longer name a waiting entry, so each id is
//! pushed once and leaves once, popped at the front or dropped by `compact`.
//! Design:
//! `docs/send-completion-slots-design.md`, `docs/send-admission-design.md`
//! (section 2).
//!
//! Lifecycle of one entry:
//!
//! ```text
//! enqueue ─▶ waiting ─mark_submitted─▶ InFlight ─complete─▶ Done ─take_result─▶ gone
//!              │                          │                       ▲
//!              │ cancel ─▶ gone           │ cancel ─▶ Abandoned   │ complete
//!              │                          │             └complete─▶ gone
//!              │ remove_connection        │ remove_connection     │
//!              ▼                          ▼                       │
//!           Aborted ◀───────────────── Aborted ───────────────────┘
//!              └─ take_result ─▶ gone
//! ```
//!
//! **An entry leaves the table through its future, never through its
//! owner.** The future's `Drop` cancels the entry (`cancel`): a waiting one
//! goes, an in-flight one becomes `Abandoned` and its completion frees it,
//! a resolved one goes with its result. The owning task's death changes no
//! entry's state. A connection task is dropped with the driver state
//! installed, in its task-exit arm and at its connection's release
//! ([`Executor::remove_connection`] runs under `with_driver_state`), so
//! every future that died with it cancels its entry; `cancel` finds the
//! entry by id, so it does not matter that the `Ready` arms drop the future
//! after `remove_task` ran. An entry still owned by the dead task is
//! therefore held by a future the task handed to another task that has not
//! polled it yet: it is re-owned to [`NO_OWNER`] and kept, resolved or in
//! flight, and that task's first poll (`set_owner`) claims it.
//!
//! **A connection task's exit and its connection's release are separate
//! steps.** When a connection task returns or panics, the backend's
//! task-exit arm calls [`Executor::remove_connection_task`], which re-owns
//! the entries the task owned (`remove_task`); the connection is then
//! closing, and the driver delivers or fails every queued send on it, waking
//! the live owners through [`complete`](SendCompletions::complete), before
//! the slot is released. `remove_connection` runs at the release
//! ([`Executor::remove_connection`], from io_uring's `handle_close` and
//! mio's `drain_pending_closes`) and aborts whatever is still outstanding on
//! the connection.
//!
//! **A synthetic teardown abort is provisional.** `remove_connection`
//! records `Aborted`, not `Done`, and `complete` overwrites it with the
//! driver's result: a message that was fully delivered must never be
//! reported to its caller as aborted. In the current run loops no driver
//! result reaches `complete` after the release: mio finalizes a close only
//! once `pending_sends` is empty, io_uring commits the Close only once the
//! queue is empty and nothing is in flight, and a CQE that outlives the slot
//! goes to `forget`. The rule has no effect today and stays so that
//! `remove_connection` is correct from any call site. An `Aborted` that
//! nothing overwrites still
//! resolves the future ([`take_result`](SendCompletions::take_result) takes
//! it), so a genuinely torn-down send does not hang. "First result wins"
//! survives only between two *driver* results for one id.
//!
//! Every entry records the task id that owns it. The owner is refreshed on
//! each poll of its future (`set_owner`), and the `Executor` wrappers call `wake_task` immediately on
//! whatever id the queue returns — no deferred wake list. Between a
//! completion and the next poll no poll runs, so the owner resolved at
//! completion time is the owner that will be polled.
//!
//! Admission design: `docs/send-capacity-fifo-design.md`.
//!
//! **Admission orders.** The worker's [`SendAdmissionOrder`] is set once,
//! when the event loop creates the executor. Under `Strict` only the head
//! is admitted, through [`turn`](SendCompletions::turn) and
//! [`head_ready`](SendCompletions::head_ready). The entry points `Budget`
//! shares with it (`Executor::wake_send_capacity_in`,
//! `Executor::send_scan_due`, `set_order`, `order`) test the order or a flag
//! only `Budget` sets and take the `Strict` path; the rest of what this
//! paragraph describes does not run under `Strict`. Under `Budget`, while
//! the head does not fit, a waiter behind it is also admitted
//! ([`admit`](SendCompletions::admit)). A waiter admitted that way leaves its
//! id in `waiting`, as a cancelled waiter does, so the rule above still
//! holds: each id is pushed once and leaves once. A waiter can become able to
//! pass without its own poll noticing: when capacity comes back, when the
//! head changes, when an earlier waiter on its connection leaves, or when its
//! connection goes idle. The first is the release hook's wake; for the
//! others the queue sets `scan_due`, or the driver sets `capacity_released`,
//! and the event loop's end-of-iteration capacity wake then runs
//! [`scan`](SendCompletions::scan), which wakes the waiters behind the head
//! that could pass. Those polls check again with `admit`. A poll whose
//! `admit` says wait also sets `scan_due`, so a scan that woke a waiter which
//! then could not pass (the pool changed in between) is followed by another.

use std::collections::VecDeque;
use std::io;

use super::Executor;
use crate::buffer::send_copy::SendCopyPool;

/// The order in which a worker admits bounded sends
/// ([`SendHalf::send_admitted`](crate::SendHalf::send_admitted),
/// [`send_backpressured`](crate::SendHalf::send_backpressured)) to its send
/// copy pool. Set with
/// [`ConfigBuilder::send_admission_order`](crate::ConfigBuilder::send_admission_order).
///
/// Bounded sends that do not fit the pool's free slots wait in one FIFO per
/// worker. In both orders the FIFO's head is admitted when the free slots
/// cover its whole message, and a send is admitted only once no earlier
/// bounded send on its own connection still waits, so the sends on one
/// connection keep their order. The orders differ in what happens while the
/// head does not fit.
///
/// The default is `Budget { slots: 32 }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendAdmissionOrder {
    /// Only the head is admitted. A send that fits waits behind a head that
    /// does not, however small it is.
    Strict,
    /// A waiter behind a head that does not fit is also admitted, ahead of
    /// the head (it passes the head), when three conditions hold:
    ///
    /// - its message fits in the free slots;
    /// - the slots held by sends that passed a head, plus its own, are at
    ///   most L = min(`slots`, P - H), where P is the pool's slot count and H
    ///   the slots the head needs;
    /// - its connection has no send queued or in flight, and the
    ///   connection's last settled send did not wait for room in the socket.
    ///
    /// The second condition bounds how long the head waits on passing
    /// sends. Passing sends never hold more than `slots`, and when `slots` is
    /// at most P - H, the head fits once the sends that did not pass hold at
    /// most P - H - `slots` slots, whatever the passing sends hold. A head
    /// that needs more than P - `slots` can also wait for slots that sends
    /// passing an earlier head still hold. The third keeps a send
    /// from passing onto a connection whose peer is not reading, where its
    /// slots could stay held until the peer reads. Waiters that may pass are
    /// admitted oldest first. A `slots` above the pool's slot count admits as
    /// the pool's slot count does.
    Budget {
        /// The most slots sends that passed a head may hold at once. At
        /// least 1; `ConfigBuilder::build` refuses 0.
        slots: u16,
    },
}

impl Default for SendAdmissionOrder {
    fn default() -> Self {
        SendAdmissionOrder::Budget { slots: 32 }
    }
}

impl SendAdmissionOrder {
    /// Whether the order lets a waiter pass a head that does not fit: so the
    /// pool keeps the passing marks B counts, and the drivers keep each
    /// connection's room-wait flags (`track_room_waits`).
    pub(crate) fn lets_pass(self) -> bool {
        !matches!(self, SendAdmissionOrder::Strict)
    }
}

/// The copy-pool figures `Budget` reads, taken from the pool when an
/// admission check or a wake scan runs. Terms, as in
/// `docs/send-admission-design.md`, section 4: P is the pool's slots, F the
/// free slots, H the slots the head needs, and B the slots held by sends that
/// passed a head, counted until each slot returns to the pool, across changes
/// of head.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PoolView {
    /// Slots available to a new allocation (F).
    pub(crate) free: usize,
    /// Slots held by sends that passed a head (B).
    pub(crate) passing: usize,
    /// Slots in the pool (P).
    pub(crate) slots: usize,
}

impl PoolView {
    /// The figures of `pool` now.
    pub(crate) fn of(pool: &SendCopyPool) -> Self {
        PoolView {
            free: pool.free_count(),
            passing: pool.passing_held(),
            slots: pool.slot_count(),
        }
    }
}

/// What [`SendCompletions::admit`] decided for one waiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admit {
    /// Not now; the future parks.
    Wait,
    /// The waiter is the head and fits.
    Head,
    /// The waiter passes the head, which does not fit. `slots` is the
    /// waiter's `required_slots`.
    Pass { slots: usize },
}

/// What admission did on one worker. Read with
/// [`send_admission_counters`]. Every count starts at zero when the worker
/// starts and only grows, except `passing_held`, `main_free` and
/// `unowned_held`, which are figures of now; under `Strict` the passing and
/// scan counts stay zero.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendAdmissionCounters {
    /// Sends admitted past a waiting head.
    pub passing_admissions: u64,
    /// The copy-pool slots those sends were admitted against (each one's
    /// worst-case cost, as the FIFO counts it), summed.
    pub passing_slots: u64,
    /// The slots sends that passed a head hold now (B).
    pub passing_held: u64,
    /// The largest `passing_held` has been.
    pub passing_held_max: u64,
    /// Wake scans that looked behind a head that did not fit.
    pub wake_scans: u64,
    /// The waiters those scans woke.
    pub scan_wakes: u64,
    /// Slots of the copy pool free now.
    pub main_free: u64,
    /// The most copy-pool slots one connection has held at once
    /// (`SendHalf::send_pool_held`).
    pub conn_held_max: u64,
    /// Copy-pool slots held now by sends that belong to no connection (UDP).
    pub unowned_held: u64,
}

/// The admission counters of the worker this runs on: see
/// [`SendAdmissionCounters`].
///
/// # Panics
///
/// Outside a task or handler callback on a ringline worker.
#[doc(hidden)]
pub fn send_admission_counters() -> SendAdmissionCounters {
    super::io::with_state(|driver, executor| {
        executor.send_admission_counters(&driver.send_copy_pool)
    })
}

/// Whether arrival number `a` came before `b`. Arrival numbers wrap; the
/// waiters in the FIFO at any one time span far fewer than 2^31 of them.
fn arrived_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Identity of one send operation on its worker: a slot in
/// [`SendCompletions`]'s table and that slot's generation.
///
/// A slot's generation advances each time the slot is freed, so an id that
/// outlives its operation never matches the slot's next occupant: every
/// method treats it as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SendId {
    index: u32,
    generation: u32,
}

/// The owner of an entry whose owning task is gone while the future that
/// holds it is alive, handed to a task that has not polled it yet. A wake
/// for it reaches no task ([`Executor::wake_task`] finds no slot); the next
/// poll records the polling task as the owner. Also the owner of an
/// `Abandoned` entry, whose future is gone (`cancel`).
pub(crate) const NO_OWNER: u32 = u32::MAX;

/// Where one operation stands.
enum Completion {
    /// Waiting for admission, in the FIFO. `generation` is the target
    /// connection's generation, which `fail_waiting` matches; the slot's own
    /// generation is unrelated.
    Waiting {
        generation: u32,
        /// Copy-pool slots the whole message needs; `turn` admits the head
        /// only when at least this many are free.
        required_slots: usize,
        /// Arrival number, which orders the waiters of one connection: under
        /// `Budget` a waiter passes only if no waiter on its connection
        /// arrived before it. 0 under `Strict`, which never reads it.
        seq: u32,
        /// The scan (`scan_epoch`) that last woke this waiter to pass, if it
        /// has not polled since; 0 if none. A waiter woken and not polled by
        /// the next scan loses its claim on the room it was woken for.
        woken_in: u32,
    },
    /// Submitted to the driver; no completion yet.
    InFlight,
    /// The driver reported; the result waits for `take_result`. Final — a
    /// second driver result for the same id is ignored.
    Done(io::Result<u32>),
    /// Teardown recorded this before the driver reported. Provisional: a
    /// real driver result overwrites it (`complete`), and if none ever
    /// arrives `take_result` hands this error to the future. See the module
    /// docs for the provisional-abort rule.
    Aborted(io::Error),
    /// The future was dropped while the operation was in flight. The driver
    /// still owns the operation; its completion frees the slot. Nothing
    /// polls a dropped future, so nothing leaves this state but that
    /// completion.
    Abandoned,
}

/// A live operation.
struct Entry {
    /// The connection the send targets.
    conn_index: u32,
    /// Task to wake on admission or completion.
    task_id: u32,
    state: Completion,
    /// A write on the connection found the socket full while this send was
    /// in flight ([`mark_waited_for_room`](SendCompletions::mark_waited_for_room)).
    waited_for_room: bool,
}

/// One slot of the table: its current generation and, while an operation
/// holds it, that operation.
struct Slot {
    generation: u32,
    entry: Option<Entry>,
}

/// Completion table for awaited sends, and admission FIFO for bounded
/// sends, on one worker.
///
/// Owned by [`Executor::send_completions`]; the `Executor` methods further down
/// in this file are the only intended entry points outside tests, because
/// they pair every returned task id with `wake_task`.
#[derive(Default)]
pub(crate) struct SendCompletions {
    /// Every operation, waiting or admitted, indexed by
    /// `SendId::index`.
    slots: Vec<Slot>,
    /// Indices of the slots no operation holds.
    free: Vec<u32>,
    /// Waiting operations in arrival order. Under `Strict` only the head may
    /// be admitted; `Budget` also admits waiters behind it. Also
    /// holds ids that no longer name a waiting entry, which
    /// [`front`](Self::front) pops when they reach the head and
    /// [`compact`](Self::compact) drops when they number more than the live
    /// ones plus 64.
    waiting: VecDeque<SendId>,
    /// How many ids in `waiting` name a waiting entry.
    waiting_live: usize,
    /// Ids of `waiting` examined, for the tests that bound it.
    #[cfg(test)]
    visited: usize,
    /// Slot indices of the live operations targeting each connection,
    /// indexed by connection index, in the order they were added.
    by_conn: Vec<VecDeque<u32>>,
    /// Slot indices of the live operations owned by each connection task,
    /// indexed by task id, in the order they were added. Standalone tasks and
    /// [`NO_OWNER`] are not indexed: [`remove_task`](Self::remove_task) and
    /// [`remove_connection`](Self::remove_connection) never look them up.
    by_task: Vec<VecDeque<u32>>,
    /// The worker's admission order, set when the executor is created.
    order: SendAdmissionOrder,
    /// The arrival number the next waiter gets, under `Budget`.
    next_seq: u32,
    /// The number of the latest scan that looked behind the head, under
    /// `Budget`; 0 until the first such scan, and never 0 after it,
    /// since `woken_in` uses 0 for none.
    scan_epoch: u32,
    /// A [`scan`](Self::scan) is due at the end of the event-loop iteration.
    /// Set only under `Budget`: when a waiter leaves the
    /// waiting state, when a later poll of a waiter is told to wait, when any
    /// poll is told to wait because an older waiter takes the room
    /// ([`admit`](Self::admit)), and by a scan that woke passers, for the
    /// scan after it.
    scan_due: bool,
    /// The task ids a scan wakes, kept between scans by
    /// [`Executor::wake_send_capacity_in`] so that a scan allocates only
    /// when it wakes more tasks than any scan before it.
    wake_scratch: Vec<u32>,
    /// The counts the FIFO keeps; `passing_held` and `passing_held_max`
    /// stay zero here and are read from the pool
    /// ([`Executor::send_admission_counters`]).
    counters: SendAdmissionCounters,
}

// List entries `index_remove` compared, for the tests that bound it. Per
// thread, so tests running in parallel do not share it.
#[cfg(test)]
thread_local! {
    static INDEX_SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Record `index` under `key`, at the back of its list.
fn index_add(lists: &mut Vec<VecDeque<u32>>, key: u32, index: u32) {
    let key = key as usize;
    if lists.len() <= key {
        lists.resize_with(key + 1, VecDeque::new);
    }
    lists[key].push_back(index);
}

/// Forget `index` under `key`, keeping the rest of the list in order.
///
/// The sends on one connection mostly settle in the order they were
/// registered, so in a connection's list the index is mostly the front. A
/// task's list spans its connections; an abandoned entry leaves it when its
/// future is dropped ([`cancel`](SendCompletions::cancel)), which for a
/// send whose completion is dropped at once is the back. Both leave in at
/// most two comparisons. Any other index is found by a scan. A list that
/// kept no order would put the next index to settle anywhere, and settling
/// N queued sends would cost about N^2/2 comparisons.
fn index_remove(lists: &mut [VecDeque<u32>], key: u32, index: u32) {
    let Some(list) = lists.get_mut(key as usize) else {
        return;
    };
    if list.front() == Some(&index) {
        #[cfg(test)]
        INDEX_SCANNED.with(|c| c.set(c.get() + 1));
        list.pop_front();
        return;
    }
    if list.back() == Some(&index) {
        #[cfg(test)]
        INDEX_SCANNED.with(|c| c.set(c.get() + 2));
        list.pop_back();
        return;
    }
    let found = list.iter().position(|&i| i == index);
    #[cfg(test)]
    INDEX_SCANNED.with(|c| c.set(c.get() + 2 + found.map_or(list.len(), |pos| pos + 1)));
    if let Some(pos) = found {
        list.remove(pos);
    }
}

/// Whether `task_id` is a connection task, the only kind `by_task` indexes.
fn is_connection_task(task_id: u32) -> bool {
    task_id & crate::runtime::waker::STANDALONE_BIT == 0
}

impl SendCompletions {
    /// Empty queue, in the `Strict` order. Called once per worker from
    /// `Executor::new`; the event loops then set the configured order
    /// ([`set_order`](Self::set_order)).
    pub(crate) fn new() -> Self {
        Self {
            order: SendAdmissionOrder::Strict,
            ..Self::default()
        }
    }

    /// Empty queue in `order`.
    #[cfg(test)]
    fn with_order(order: SendAdmissionOrder) -> Self {
        let mut q = Self::new();
        q.set_order(order);
        q
    }

    /// Set the admission order. Called once, before any waiter is enqueued,
    /// by [`Executor::set_send_admission_order`].
    pub(crate) fn set_order(&mut self, order: SendAdmissionOrder) {
        debug_assert_eq!(self.waiting_live, 0, "the order changed under waiters");
        self.order = order;
    }

    /// The admission order.
    pub(crate) fn order(&self) -> SendAdmissionOrder {
        self.order
    }

    /// Put `entry` in a free slot and return its id.
    fn insert(&mut self, entry: Entry) -> SendId {
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                let index = u32::try_from(self.slots.len()).expect("send id space exhausted");
                self.slots.push(Slot {
                    generation: 0,
                    entry: None,
                });
                index
            }
        };
        index_add(&mut self.by_conn, entry.conn_index, index);
        if is_connection_task(entry.task_id) {
            index_add(&mut self.by_task, entry.task_id, index);
        }
        let slot = &mut self.slots[index as usize];
        slot.entry = Some(entry);
        SendId {
            index,
            generation: slot.generation,
        }
    }

    /// The live operation `id` names, or `None` for a stale or unknown id.
    fn entry(&self, id: SendId) -> Option<&Entry> {
        self.slots
            .get(id.index as usize)
            .filter(|slot| slot.generation == id.generation)
            .and_then(|slot| slot.entry.as_ref())
    }

    /// Mutable form of [`entry`](Self::entry).
    fn entry_mut(&mut self, id: SendId) -> Option<&mut Entry> {
        self.slots
            .get_mut(id.index as usize)
            .filter(|slot| slot.generation == id.generation)
            .and_then(|slot| slot.entry.as_mut())
    }

    /// Free the slot `id` names and return its operation. The slot's
    /// generation advances, so `id` and every copy of it go stale.
    fn remove(&mut self, id: SendId) -> Option<Entry> {
        if self.slots.get(id.index as usize)?.generation != id.generation {
            return None;
        }
        self.free_index(id.index)
    }

    /// Free slot `index`, whatever its generation, and return its operation.
    fn free_index(&mut self, index: u32) -> Option<Entry> {
        let slot = &mut self.slots[index as usize];
        let entry = slot.entry.take()?;
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(index);
        index_remove(&mut self.by_conn, entry.conn_index, index);
        if is_connection_task(entry.task_id) {
            index_remove(&mut self.by_task, entry.task_id, index);
        }
        Some(entry)
    }

    /// Whether `id` names a waiting entry.
    fn is_waiting(&self, id: SendId) -> bool {
        matches!(
            self.entry(id),
            Some(Entry {
                state: Completion::Waiting { .. },
                ..
            })
        )
    }

    /// The FIFO's head: pops the ids at the front that no longer name a
    /// waiting entry, and returns the first that does.
    fn front(&mut self) -> Option<SendId> {
        while let Some(&id) = self.waiting.front() {
            #[cfg(test)]
            {
                self.visited += 1;
            }
            if self.is_waiting(id) {
                return Some(id);
            }
            self.waiting.pop_front();
        }
        None
    }

    /// An entry left the waiting state without leaving `waiting`. Drops the
    /// stale ids once they number more than the live ones plus 64, so that a
    /// head that waits for a long time does not leave the list growing with
    /// every waiter behind it that times out. The `retain` visits every id;
    /// when it runs the stale ids are more than half of them, and each went
    /// stale after the previous `retain`, so its cost is less than two visits
    /// per entry that left the waiting state.
    fn left_waiting(&mut self) {
        self.waiting_live -= 1;
        self.waiter_left();
        self.compact_if_mostly_stale();
    }

    /// [`compact`](Self::compact) once the stale ids in `waiting` number
    /// more than the live ones plus 64.
    fn compact_if_mostly_stale(&mut self) {
        if self.waiting.len() > 2 * self.waiting_live + 64 {
            self.compact();
        }
    }

    /// A waiter left the waiting state. Under `Budget`
    /// that can let a waiter behind the head pass: the head may have changed,
    /// or the waiter that left was the earliest of its connection. The scan
    /// at the end of the iteration wakes whoever can.
    fn waiter_left(&mut self) {
        if self.order != SendAdmissionOrder::Strict {
            self.scan_due = true;
        }
    }

    /// Drop every id in `waiting` that no longer names a waiting entry.
    fn compact(&mut self) {
        let slots = &self.slots;
        #[cfg(test)]
        {
            self.visited += self.waiting.len();
        }
        self.waiting.retain(|&id| {
            let slot = &slots[id.index as usize];
            slot.generation == id.generation
                && matches!(
                    slot.entry,
                    Some(Entry {
                        state: Completion::Waiting { .. },
                        ..
                    })
                )
        });
    }

    /// The task owning the FIFO's head, if any.
    fn head_task(&mut self) -> Option<u32> {
        let id = self.front()?;
        self.entry(id).map(|e| e.task_id)
    }

    /// Append a waiter and return its id.
    ///
    /// Called by `Admission` on its first poll, with the
    /// connection it targets, the number of copy-pool slots its message
    /// needs, and the polling task's id.
    pub(crate) fn enqueue(
        &mut self,
        conn_index: u32,
        generation: u32,
        required_slots: usize,
        task_id: u32,
    ) -> SendId {
        let seq = if self.order == SendAdmissionOrder::Strict {
            0
        } else {
            let seq = self.next_seq;
            self.next_seq = seq.wrapping_add(1);
            seq
        };
        let id = self.insert(Entry {
            conn_index,
            task_id,
            state: Completion::Waiting {
                generation,
                required_slots,
                seq,
                woken_in: 0,
            },
            waited_for_room: false,
        });
        self.waiting.push_back(id);
        self.waiting_live += 1;
        id
    }

    /// Register an awaited send that needs no admission, already `InFlight`,
    /// and return its id.
    ///
    /// Called by the awaiting send APIs (`SendHalf::send`,
    /// `forward_recv_buf`, `build`, `submit_batch`) before they
    /// submit. A submission that fails must [`withdraw`](Self::withdraw) the id
    /// it registered.
    pub(crate) fn register(&mut self, conn_index: u32, task_id: u32) -> SendId {
        self.insert(Entry {
            conn_index,
            task_id,
            state: Completion::InFlight,
            waited_for_room: false,
        })
    }

    /// Mark every send in flight on `conn_index` as having waited for room
    /// in the socket. A send in flight has been submitted and has not
    /// settled: its bytes, or bytes queued ahead of it on the connection,
    /// are not all in the socket.
    ///
    /// Called by the io_uring event loop at every call of `wait_for_room`;
    /// mio marks sends by id instead
    /// ([`mark_send_waited_for_room`](Self::mark_send_waited_for_room)).
    /// Visits the entries indexed under the connection.
    pub(crate) fn mark_waited_for_room(&mut self, conn_index: u32) {
        let Some(list) = self.by_conn.get(conn_index as usize) else {
            return;
        };
        for &index in list {
            if let Some(e) = self.slots[index as usize].entry.as_mut()
                && matches!(e.state, Completion::InFlight)
            {
                e.waited_for_room = true;
            }
        }
    }

    /// Mark the send `id` names as having waited for room, if it is in
    /// flight, or settled with its result not yet taken. mio marks the sends
    /// a `writev` that returned `WouldBlock` carried one by one, by the ids
    /// their queued entries carry.
    #[cfg_attr(has_io_uring, allow(dead_code))]
    pub(crate) fn mark_send_waited_for_room(&mut self, id: SendId) {
        if let Some(e) = self.entry_mut(id)
            && matches!(e.state, Completion::InFlight | Completion::Done(_))
        {
            e.waited_for_room = true;
        }
    }

    /// Whether the send `id` names has waited for room: see
    /// [`mark_waited_for_room`](Self::mark_waited_for_room). False for an
    /// unknown id.
    pub(crate) fn waited_for_room(&self, id: SendId) -> bool {
        self.entry(id).is_some_and(|e| e.waited_for_room)
    }

    /// Record the task that currently owns `id`, whether it is waiting or
    /// submitted. A no-op for an unknown id.
    ///
    /// Called by the send futures on every poll after the first, so that a
    /// future moved between tasks (or polled from a different task than the
    /// one that enqueued it) is woken where it now lives, and so that an
    /// entry its creator's exit left with [`NO_OWNER`] has one again.
    pub(crate) fn set_owner(&mut self, id: SendId, task_id: u32) {
        let Some(e) = self.entry_mut(id) else {
            return;
        };
        let old = std::mem::replace(&mut e.task_id, task_id);
        if old != task_id {
            if is_connection_task(old) {
                index_remove(&mut self.by_task, old, id.index);
            }
            if is_connection_task(task_id) {
                index_add(&mut self.by_task, task_id, id.index);
            }
        }
    }

    /// Remove `id`, which no submission took: its send was refused or
    /// queued nothing, so no completion will ever arrive for it. Unlike
    /// [`cancel`](Self::cancel), which leaves an in-flight entry for its
    /// completion to free, this frees it now.
    ///
    /// Called by the awaited send APIs when their submission fails.
    pub(crate) fn withdraw(&mut self, id: SendId) {
        if matches!(self.entry(id).map(|e| &e.state), Some(Completion::InFlight)) {
            self.remove(id);
        }
    }

    /// A completion for `id` arrived that must not settle it, because its
    /// connection has been torn down: teardown already recorded the abort,
    /// and a driver result would override it. An `Abandoned` entry waits
    /// for exactly this completion, so it is freed; any other state is left
    /// for its future to take.
    ///
    /// Called by the completion handlers' stale-generation branches.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) fn forget(&mut self, id: SendId) {
        if matches!(
            self.entry(id).map(|e| &e.state),
            Some(Completion::Abandoned)
        ) {
            self.remove(id);
        }
    }

    /// Whether `id` may reserve slots now: it must be the head of the queue
    /// *and* `free_slots` must cover its `required_slots`.
    ///
    /// Called by `Admission` on each poll while waiting; a `false` parks
    /// the future until [`head_ready`](Self::head_ready) or a promotion
    /// wakes it.
    pub(crate) fn turn(&mut self, id: SendId, free_slots: usize) -> bool {
        self.front() == Some(id) && self.head_ready(free_slots).is_some()
    }

    /// Move `id` from waiting to submitted (`InFlight`).
    ///
    /// Returns the new head's task id, so the caller can wake it (it
    /// re-checks [`turn`](Self::turn) on its next poll). Returns `None` if
    /// `id` is not the head, which under `Strict` [`turn`](Self::turn) has
    /// just checked it is and under `Budget` means it passed the
    /// head ([`admit`](Self::admit)), or if there is no new head. A waiter
    /// that passed leaves its id in `waiting`, for `front` or `compact` to
    /// drop.
    ///
    /// Called by `Admission` right after it reserved its slots and submitted
    /// the send.
    pub(crate) fn mark_submitted(&mut self, id: SendId) -> Option<u32> {
        if !self.is_waiting(id) {
            return None;
        }
        let at_front = self.front() == Some(id);
        self.entry_mut(id)?.state = Completion::InFlight;
        if at_front {
            self.waiting.pop_front();
            self.waiting_live -= 1;
            self.waiter_left();
            // Under `Budget`, waiters behind this head can have left
            // already, and the scan's cost rests on `waiting` holding at most
            // twice the live ids plus 64. `Strict` never scans, and keeps the
            // pop it always had.
            if self.order != SendAdmissionOrder::Strict {
                self.compact_if_mostly_stale();
            }
            self.head_task()
        } else {
            self.left_waiting();
            None
        }
    }

    /// Deliver the driver's completion of `id` — the authoritative result.
    ///
    /// `InFlight` becomes `Done(result)` and the owner's task id is returned
    /// for waking. `Aborted` does the same: a teardown abort is provisional,
    /// and a driver result that arrives after it is authoritative (module
    /// docs). `Abandoned` entries are removed and `result` is
    /// discarded (the future is gone). An entry that is already `Done` keeps
    /// its result — between two *driver* results for one id the first wins.
    /// A waiting entry is not in flight and ignores it. An unknown id is
    /// ignored: it is a stale completion for an entry that
    /// [`remove_connection`](Self::remove_connection) already resolved and
    /// the future already collected.
    ///
    /// Called by the backends' send-completion handlers.
    pub(crate) fn complete(&mut self, id: SendId, result: io::Result<u32>) -> Option<u32> {
        let e = self.entry_mut(id)?;
        match e.state {
            Completion::InFlight | Completion::Aborted(_) => {
                e.state = Completion::Done(result);
                Some(e.task_id)
            }
            Completion::Abandoned => {
                self.remove(id);
                None
            }
            Completion::Done(_) | Completion::Waiting { .. } => None,
        }
    }

    /// Take the result of `id` if it has one — a driver result (`Done`) or
    /// a teardown abort no driver result overwrote (`Aborted`) — removing
    /// the entry. Anything else (waiting, in flight, abandoned, unknown) is
    /// `None`.
    ///
    /// `Aborted` resolves here too, and must: a send whose connection really
    /// was torn down before the driver ever reported has no other way to
    /// finish, and would park forever.
    ///
    /// Called by the send futures on each poll after submission; `None`
    /// parks it until [`complete`](Self::complete) wakes it.
    pub(crate) fn take_result(&mut self, id: SendId) -> Option<io::Result<u32>> {
        if !matches!(
            self.entry(id)?.state,
            Completion::Done(_) | Completion::Aborted(_)
        ) {
            return None;
        }
        match self.remove(id)?.state {
            Completion::Done(result) => Some(result),
            Completion::Aborted(err) => Some(Err(err)),
            _ => unreachable!("checked above"),
        }
    }

    /// The future for `id` was dropped.
    ///
    /// Waiting: removed; if it was the head, the new head's task id is
    /// returned for waking. `InFlight`: becomes `Abandoned` (the driver
    /// still owns the operation; its completion removes the entry), owned
    /// by [`NO_OWNER`] and no longer listed under its task: no future is
    /// left to wake, so nothing reads its owner again. `Done`
    /// or `Aborted`: removed, result discarded (a driver result that arrives
    /// afterwards finds no entry and is ignored). Unknown: ignored.
    ///
    /// Called from `SendCompletion`'s and `Admission`'s `Drop`. A
    /// connection task is dropped with the driver state installed, at its
    /// exit and at its connection's release (`with_driver_state`), so its
    /// futures reach this. A drop outside the executor (on another thread,
    /// or in the synchronous body of `on_accept`) skips it and leaves the
    /// entry in the table for the life of the worker.
    pub(crate) fn cancel(&mut self, id: SendId) -> Option<u32> {
        let e = self.entry_mut(id)?;
        match e.state {
            Completion::Waiting { .. } => {
                let was_head = self.front() == Some(id);
                self.remove(id);
                self.left_waiting();
                if was_head {
                    return self.head_task();
                }
            }
            Completion::InFlight => {
                e.state = Completion::Abandoned;
                // Leave the task's list now rather than at the completion.
                // A task's list spans its connections, and one connection's
                // abandoned entries left there would sit ahead of another's
                // that settle first.
                let owner = std::mem::replace(&mut e.task_id, NO_OWNER);
                if is_connection_task(owner) {
                    index_remove(&mut self.by_task, owner, id.index);
                }
            }
            Completion::Done(_) | Completion::Aborted(_) => {
                self.remove(id);
            }
            Completion::Abandoned => {}
        }
        None
    }

    /// The head's task id if `free_slots` covers its `required_slots`.
    ///
    /// The driver's slot-release hook calls this through
    /// [`Executor::wake_send_capacity`] after every pool release, so the
    /// head is woken only when it can now fit rather than on every release.
    pub(crate) fn head_ready(&mut self, free_slots: usize) -> Option<u32> {
        let head = self.front()?;
        let e = self.entry(head)?;
        match e.state {
            Completion::Waiting { required_slots, .. } if free_slots >= required_slots => {
                Some(e.task_id)
            }
            _ => None,
        }
    }

    /// Under `Budget`, whether `id` may reserve slots
    /// now: as the head, when `pool.free` covers its `required_slots`, or
    /// past a head that does not fit, when the order lets it
    /// ([`may_pass`](Self::may_pass)) with what is left once the older
    /// waiters that could pass have taken their room
    /// ([`left_after_older_passers`](Self::left_after_older_passers)), so
    /// passers go oldest first whichever polls first. An older waiter that a
    /// scan woke keeps that claim only until the next scan; one its task does
    /// not poll then stops holding the newer ones back
    /// ([`could_pass`](Self::could_pass)). `idle` says, for a
    /// connection index, whether the connection has no send queued or in
    /// flight and its most recent send did not wait for room; it is called
    /// for `id` once it passes every other test, and for the older waiters.
    ///
    /// An answer of wait on any poll but the first sets `scan_due`: the
    /// poll may have come from a scan that counted on this waiter's slots,
    /// or the head may have stopped fitting because a send outside the FIFO
    /// took slots, and either way another waiter may now be able to pass.
    /// So does a wait because an older waiter takes the room, on any poll,
    /// so that the scan wakes the older one.
    ///
    /// Cost, for a waiter that would pass on its own: one visit per id ahead
    /// of it in `waiting`, and the operations of each older waiter's
    /// connection that fits. A rejection on its own test costs nothing more.
    ///
    /// Called by `Admission` on each poll while waiting, in place of
    /// [`turn`](Self::turn).
    pub(crate) fn admit(
        &mut self,
        id: SendId,
        pool: PoolView,
        first_poll: bool,
        idle: impl Fn(u32) -> bool,
    ) -> Admit {
        debug_assert_ne!(self.order, SendAdmissionOrder::Strict);
        // This is the poll a scan's wake asked for, if one did.
        if let Some(Entry {
            state: Completion::Waiting { woken_in, .. },
            ..
        }) = self.entry_mut(id)
        {
            *woken_in = 0;
        }
        let admit = self.admit_inner(id, pool, idle);
        if admit == Admit::Wait && !first_poll {
            self.scan_due = true;
        }
        admit
    }

    /// [`admit`](Self::admit) without its effect on `scan_due`.
    fn admit_inner(&mut self, id: SendId, pool: PoolView, idle: impl Fn(u32) -> bool) -> Admit {
        let Some((head, head_needs)) = self.head_and_need() else {
            return Admit::Wait;
        };
        if pool.free >= head_needs {
            return if head == id { Admit::Head } else { Admit::Wait };
        }
        if head == id {
            return Admit::Wait;
        }
        let Some(Entry {
            conn_index,
            state:
                Completion::Waiting {
                    required_slots,
                    seq,
                    ..
                },
            ..
        }) = self.entry(id)
        else {
            return Admit::Wait;
        };
        let (conn_index, required_slots, seq) = (*conn_index, *required_slots, *seq);
        if !self.may_pass(head_needs, conn_index, required_slots, seq, pool) {
            return Admit::Wait;
        }
        if !idle(conn_index) {
            return Admit::Wait;
        }
        // Passers go oldest first, as the scan wakes them: an older waiter
        // that could pass takes its room before this one, even when this
        // poll comes first (a new waiter's first poll, in the same iteration
        // as the release that made the room). If what is left does not cover
        // this waiter, the scan at the end of the iteration wakes the older
        // one.
        let left = self.left_after_older_passers(head_needs, id, pool, &idle);
        if !self.may_pass(head_needs, conn_index, required_slots, seq, left) {
            self.scan_due = true;
            return Admit::Wait;
        }
        Admit::Pass {
            slots: required_slots,
        }
    }

    /// `pool` less what the waiters between the head and `id` that could
    /// pass take, oldest first, each counted against the free slots and B as
    /// [`scan`](Self::scan) counts the waiters it wakes.
    ///
    /// Cost: one visit per id in `waiting` ahead of `id`, stale ones
    /// included, and for each waiter that fits, the operations of its
    /// connection. It runs only for a waiter that would pass on its own.
    ///
    /// So within one iteration it is quadratic in the waiters that pass: each
    /// walks the ones ahead of it, including those that passed already and
    /// left their ids.
    fn left_after_older_passers(
        &self,
        head_needs: usize,
        id: SendId,
        pool: PoolView,
        idle: &impl Fn(u32) -> bool,
    ) -> PoolView {
        let mut left = pool;
        for &older in self.waiting.iter().skip(1) {
            if older == id {
                break;
            }
            if let Some((required_slots, _)) = self.could_pass(older, head_needs, left, idle) {
                left.free -= required_slots;
                left.passing += required_slots;
            }
        }
        left
    }

    /// If `id` is a waiter with an owner that could pass a head of
    /// `head_needs` with `left`, its `required_slots` and owner. The test the scan applies to
    /// each waiter it might wake, and that an admission applies to the
    /// waiters older than itself. A waiter with no owner ([`NO_OWNER`]) is
    /// left out: no task would poll it, and its holder's first poll checks
    /// it.
    ///
    /// So is a waiter a scan before the latest one woke that has not polled
    /// since. An admission still counts one the latest scan woke, which
    /// gives it the iteration that wake is polled in, and not after: a waiter
    /// its task does not poll would otherwise hold its room, and every newer
    /// waiter behind it, for as long as the task does not poll it. A scan
    /// raises `scan_epoch` before it walks, so it leaves out every waiter an
    /// earlier scan woke, rather than wake the same task again; that task was
    /// woken, and polls it whenever it next awaits it.
    fn could_pass(
        &self,
        id: SendId,
        head_needs: usize,
        left: PoolView,
        idle: &impl Fn(u32) -> bool,
    ) -> Option<(usize, u32)> {
        let Some(Entry {
            conn_index,
            task_id,
            state:
                Completion::Waiting {
                    required_slots,
                    seq,
                    woken_in,
                    ..
                },
            ..
        }) = self.entry(id)
        else {
            return None;
        };
        let woken_earlier = *woken_in != 0 && *woken_in != self.scan_epoch;
        let passes = *task_id != NO_OWNER
            && !woken_earlier
            && self.may_pass(head_needs, *conn_index, *required_slots, *seq, left)
            && idle(*conn_index);
        passes.then_some((*required_slots, *task_id))
    }

    /// The FIFO's head and the slots it needs.
    fn head_and_need(&mut self) -> Option<(SendId, usize)> {
        let head = self.front()?;
        match self.entry(head)?.state {
            Completion::Waiting { required_slots, .. } => Some((head, required_slots)),
            _ => None,
        }
    }

    /// Whether a waiter behind the head, which needs `head_needs` slots and
    /// does not fit, may pass it: its `required_slots` fit in `pool.free`, no
    /// waiter on `conn_index` arrived before it (`seq`), and the order allows
    /// it ([`order_allows`](Self::order_allows)). `pool.passing` is B as the
    /// caller counts it, which a scan raises by the waiters it has woken.
    fn may_pass(
        &self,
        head_needs: usize,
        conn_index: u32,
        required_slots: usize,
        seq: u32,
        pool: PoolView,
    ) -> bool {
        required_slots <= pool.free
            && !self.has_earlier_waiter(conn_index, seq)
            && self.order_allows(head_needs, required_slots, pool)
    }

    /// The order's own condition for a waiter of `required_slots` to pass a
    /// head of `head_needs`: under `Budget`, B plus its slots is at most
    /// min(`slots`, P - H).
    fn order_allows(&self, head_needs: usize, required_slots: usize, pool: PoolView) -> bool {
        match self.order {
            SendAdmissionOrder::Strict => false,
            SendAdmissionOrder::Budget { slots } => {
                let others = pool.slots.saturating_sub(head_needs);
                pool.passing + required_slots <= usize::from(slots).min(others)
            }
        }
    }

    /// Whether a waiter on `conn_index` that arrived before `seq` is still
    /// waiting. Visits the operations indexed under the connection, which
    /// are few.
    fn has_earlier_waiter(&self, conn_index: u32, seq: u32) -> bool {
        let Some(list) = self.by_conn.get(conn_index as usize) else {
            return false;
        };
        list.iter().any(|&index| {
            matches!(
                self.slots[index as usize].entry,
                Some(Entry {
                    state: Completion::Waiting { seq: earlier, .. },
                    ..
                }) if arrived_before(earlier, seq)
            )
        })
    }

    /// Whether a [`scan`](Self::scan) is due: the event loop runs its
    /// capacity wake at the end of the iteration when this is set, as it
    /// does when slots came back.
    pub(crate) fn scan_due(&self) -> bool {
        self.scan_due
    }

    /// The capacity wake under `Budget`, and the scan
    /// [`scan_due`](Self::scan_due) asks for: push onto `wakes` the head's
    /// task if the head fits, and otherwise the tasks of the waiters behind
    /// it that could pass, oldest first. Clears `scan_due`, and sets it again
    /// if it woke a passer, so that the next scan runs.
    ///
    /// Each waiter woken is counted against the free slots and the budget as
    /// if it had passed, so that the waiters woken together fit together. It
    /// reads `idle` for the waiter's connection. A waiter with no owner ([`NO_OWNER`]) is skipped
    /// and not counted: no task would poll it, and its holder's first poll
    /// checks it. The wakes may still be more than can pass, when the pool
    /// changes before the woken tasks poll; each poll checks again
    /// ([`admit`](Self::admit)).
    ///
    /// Cost: once the head does not fit, it visits every id in `waiting`, stale ones included (at most twice the
    /// live ones plus 64, see [`left_waiting`](Self::left_waiting)), and for
    /// each waiter that fits, the operations of its connection. It runs at
    /// most once per event-loop iteration. It keeps visiting after the free
    /// slots are used up, because a waiter that needs no slots (an empty
    /// message) can still pass. Stale ids are skipped, not popped: only
    /// `front` and `compact` remove ids.
    pub(crate) fn scan(
        &mut self,
        pool: PoolView,
        idle: impl Fn(u32) -> bool,
        wakes: &mut Vec<u32>,
    ) {
        debug_assert_ne!(self.order, SendAdmissionOrder::Strict);
        self.scan_due = false;
        let Some((head, head_needs)) = self.head_and_need() else {
            return;
        };
        if pool.free >= head_needs {
            if let Some(e) = self.entry(head) {
                wakes.push(e.task_id);
            }
            return;
        }
        self.counters.wake_scans += 1;
        self.scan_epoch = self.scan_epoch.wrapping_add(1).max(1);
        let woken_before = wakes.len();
        let mut left = pool;
        // `front` left the head at the front of `waiting`.
        for position in 1..self.waiting.len() {
            let id = self.waiting[position];
            if let Some((required_slots, task_id)) = self.could_pass(id, head_needs, left, &idle) {
                wakes.push(task_id);
                left.free -= required_slots;
                left.passing += required_slots;
                let epoch = self.scan_epoch;
                if let Some(Entry {
                    state: Completion::Waiting { woken_in, .. },
                    ..
                }) = self.entry_mut(id)
                {
                    *woken_in = epoch;
                }
            }
        }
        let woken = wakes.len() - woken_before;
        self.counters.scan_wakes += woken as u64;
        // A waiter woken here that does not poll before the next scan loses
        // its claim then, and the waiters it held back get their turn; the
        // next scan has to run for that even if nothing else asks for it.
        if woken > 0 {
            self.scan_due = true;
        }
    }

    /// `id`, a waiter [`admit`](Self::admit) let pass the head with
    /// `slots`, was submitted: count the pass, then
    /// [`mark_submitted`](Self::mark_submitted).
    pub(crate) fn mark_passed(&mut self, id: SendId, slots: usize) -> Option<u32> {
        self.counters.passing_admissions += 1;
        self.counters.passing_slots += slots as u64;
        self.mark_submitted(id)
    }

    /// The connection at `conn_index` is released (any generation): the
    /// backend has closed its socket and is about to free the slot.
    ///
    /// Every waiting and in-flight entry for the connection becomes
    /// `Aborted(ConnectionAborted)` (a waiting one's id leaves the FIFO when it
    /// reaches the head, or at the next `compact`) and its
    /// owner's task id is in the returned list — the owner may be a
    /// standalone task, or a connection task on another index, that
    /// outlives this connection. A resolved entry keeps its result for the
    /// future that holds it. Abandoned entries are removed. If the head was
    /// removed, the new head's task id is appended as well.
    ///
    /// `Aborted` rather than `Done` because this abort is *provisional*: a
    /// driver's `Ok(n)` that arrives after it wins over the abort recorded
    /// here. See the module docs. (An entry still waiting was never
    /// submitted, so no driver result can arrive for it; it is recorded the
    /// same way so teardown has one rule, and `take_result` resolves both
    /// alike.)
    ///
    /// The connection's own task dies here too, if it was still alive, and
    /// so does its ownership of entries on any connection: `Executor::remove_connection`
    /// drops the task with the driver state installed, so the futures that
    /// died with it have already cancelled their entries, and an entry
    /// still owned by the task is held by a future the task handed off. It
    /// is re-owned to [`NO_OWNER`] and otherwise treated as any other entry.
    ///
    /// Visits the entries indexed under `conn_index`, and allocates the
    /// returned `Vec` and a list of those entries; this is the teardown path.
    /// An entry that leaves the waiting state can trigger a `compact`, which
    /// visits every id in the FIFO.
    pub(crate) fn remove_connection(&mut self, conn_index: u32) -> Vec<u32> {
        let mut wakes = Vec::new();
        let old_head = self.front();

        // Every entry this touches is indexed under `conn_index`, as its
        // target or as its connection-task owner.
        let mut candidates: Vec<u32> = Vec::new();
        for lists in [&self.by_conn, &self.by_task] {
            if let Some(list) = lists.get(conn_index as usize) {
                candidates.extend(list.iter().copied());
            }
        }
        candidates.sort_unstable();
        candidates.dedup();

        for index in candidates {
            if self.owned_by_connection_task(index, conn_index) {
                self.disown(index);
            }
            let Some(e) = self.slots[index as usize].entry.as_mut() else {
                continue;
            };
            if e.conn_index != conn_index {
                continue;
            }
            let was_waiting = matches!(e.state, Completion::Waiting { .. });
            let keep = match e.state {
                Completion::Waiting { .. } | Completion::InFlight => {
                    e.state = Completion::Aborted(connection_aborted());
                    if e.task_id != NO_OWNER {
                        wakes.push(e.task_id);
                    }
                    true
                }
                // Resolved, by the driver or by an earlier teardown of the
                // same slot: the future that holds it takes it.
                Completion::Done(_) | Completion::Aborted(_) => true,
                Completion::Abandoned => false,
            };
            if !keep {
                self.free_index(index);
            }
            if was_waiting {
                self.left_waiting();
            }
        }
        self.wake_new_head(old_head, &mut wakes);
        wakes
    }

    /// Whether slot `index` holds an entry owned by connection task
    /// `conn_index`.
    fn owned_by_connection_task(&self, index: u32, conn_index: u32) -> bool {
        self.slots[index as usize]
            .entry
            .as_ref()
            .is_some_and(|e| is_connection_task(e.task_id) && e.task_id == conn_index)
    }

    /// Re-own the entry in slot `index` to [`NO_OWNER`]: its owning
    /// connection task is gone and the future that holds it has not been
    /// polled since.
    fn disown(&mut self, index: u32) {
        let Some(e) = self.slots[index as usize].entry.as_mut() else {
            return;
        };
        let old = std::mem::replace(&mut e.task_id, NO_OWNER);
        if is_connection_task(old) {
            index_remove(&mut self.by_task, old, index);
        }
    }

    /// The connection task `conn_index` returned or panicked while its
    /// connection is still being closed. The task's own futures cancelled
    /// their entries when the task was dropped, so an entry it still owns,
    /// whichever connection it targets, is held by a future the task handed
    /// to another task that has not polled it yet: it is re-owned to
    /// [`NO_OWNER`] and left in its state, waiting, in flight or resolved,
    /// for that poll. Entries other tasks own on this connection are left
    /// as they are: the close is deferred behind the queued sends, so the
    /// driver delivers or fails each of them before
    /// [`remove_connection`](Self::remove_connection) runs at the slot's
    /// release. Returns nothing to wake: no entry changes state.
    ///
    /// Called from [`Executor::remove_connection_task`], the task-exit arms
    /// of both backends' `poll_ready_tasks`.
    pub(crate) fn remove_task(&mut self, conn_index: u32) -> Vec<u32> {
        let candidates: Vec<u32> = self
            .by_task
            .get(conn_index as usize)
            .map(|list| list.iter().copied().collect())
            .unwrap_or_default();
        for index in candidates {
            if self.owned_by_connection_task(index, conn_index) {
                self.disown(index);
            }
        }
        Vec::new()
    }

    /// If the head changed from `old_head`, push the new head's task onto
    /// `wakes`.
    fn wake_new_head(&mut self, old_head: Option<SendId>, wakes: &mut Vec<u32>) {
        if self.front() != old_head
            && let Some(next) = self.head_task()
        {
            wakes.push(next);
        }
    }

    /// Fail every *waiting* entry for exactly (`conn_index`, `generation`)
    /// with `io::Error::new(kind, msg)`; in-flight entries are left alone.
    /// Returns the owners' task ids for waking, plus the new head's task id
    /// if the head was among the failed.
    ///
    /// `SendHalf::shutdown_write` calls this with `BrokenPipe` so that bounded
    /// sends queued behind a write shutdown fail instead of waiting forever.
    ///
    /// Records `Done`, not the provisional `Aborted`
    /// [`remove_connection`](Self::remove_connection) uses: these entries
    /// were never submitted, so no driver result is coming to overwrite
    /// them.
    ///
    /// Allocates the returned `Vec` and one boxed error per failed entry.
    pub(crate) fn fail_waiting(
        &mut self,
        conn_index: u32,
        generation: u32,
        kind: io::ErrorKind,
        msg: &'static str,
    ) -> Vec<u32> {
        let mut wakes = Vec::new();
        let old_head = self.front();
        let candidates: Vec<u32> = self
            .by_conn
            .get(conn_index as usize)
            .map(|list| list.iter().copied().collect())
            .unwrap_or_default();
        for index in candidates {
            let Some(e) = self.slots[index as usize].entry.as_mut() else {
                continue;
            };
            let matches = e.conn_index == conn_index
                && matches!(e.state, Completion::Waiting { generation: g, .. } if g == generation);
            if !matches {
                continue;
            }
            e.state = Completion::Done(Err(io::Error::new(kind, msg)));
            wakes.push(e.task_id);
            self.left_waiting();
        }
        self.wake_new_head(old_head, &mut wakes);
        wakes
    }

    /// `abort` on `conn_index`: every entry on it that is waiting for
    /// admission (for `generation`) or in flight records
    /// `Done(Err(ConnectionAborted))`, and its owner's task id is returned for
    /// waking; if the FIFO head left, the new head's task id is appended.
    ///
    /// `Done`, not the provisional `Aborted`: the caller asked for these
    /// sends to fail, so a driver result that arrives later is ignored, as
    /// any second result is. An entry already `Done` keeps its result, an
    /// `Aborted` one is a torn-down earlier occupant's, and an `Abandoned`
    /// one has no future. An entry in flight on `conn_index` belongs to the
    /// current occupant: `remove_connection` aborts every one at the slot's
    /// release.
    ///
    /// Allocates the returned `Vec` and one boxed error per failed entry.
    pub(crate) fn abort_connection(&mut self, conn_index: u32, generation: u32) -> Vec<u32> {
        let mut wakes = Vec::new();
        let old_head = self.front();
        let candidates: Vec<u32> = self
            .by_conn
            .get(conn_index as usize)
            .map(|list| list.iter().copied().collect())
            .unwrap_or_default();
        for index in candidates {
            let Some(e) = self.slots[index as usize].entry.as_mut() else {
                continue;
            };
            if e.conn_index != conn_index {
                continue;
            }
            let was_waiting = match e.state {
                Completion::Waiting { generation: g, .. } if g == generation => true,
                Completion::InFlight => false,
                _ => continue,
            };
            e.state = Completion::Done(Err(crate::handler::aborted_error()));
            if e.task_id != NO_OWNER {
                wakes.push(e.task_id);
            }
            if was_waiting {
                self.left_waiting();
            }
        }
        self.wake_new_head(old_head, &mut wakes);
        wakes
    }

    #[cfg(test)]
    fn waiting_len(&self) -> usize {
        self.waiting_live
    }

    /// Operations holding a slot, waiting or admitted.
    #[cfg(test)]
    pub(crate) fn live(&self) -> usize {
        self.slots.iter().filter(|s| s.entry.is_some()).count()
    }

    #[cfg(test)]
    fn submitted_len(&self) -> usize {
        let live = self.slots.iter().filter(|s| s.entry.is_some()).count();
        live - self.waiting_live
    }
}

fn connection_aborted() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")
}

/// Thin wrappers that pair every task id the queue returns with
/// [`Executor::wake_task`]. These are the entry points the rest of the crate
/// uses; the `wake_task` bool is ignored (a task that is not parked does not
/// need waking).
impl Executor {
    /// [`SendCompletions::enqueue`]. `Admission`, first poll.
    pub(crate) fn enqueue_send_capacity(
        &mut self,
        conn_index: u32,
        generation: u32,
        required_slots: usize,
        task_id: u32,
    ) -> SendId {
        self.send_completions
            .enqueue(conn_index, generation, required_slots, task_id)
    }

    /// [`SendCompletions::register`], owned by the polling task. The
    /// awaiting send APIs, before they submit.
    pub(crate) fn register_send(&mut self, conn_index: u32) -> SendId {
        let task_id = super::CURRENT_TASK_ID.with(|c| c.get());
        self.send_completions.register(conn_index, task_id)
    }

    /// [`SendCompletions::withdraw`]. The awaited send APIs, when their
    /// submission fails.
    pub(crate) fn withdraw_send(&mut self, id: SendId) {
        self.send_completions.withdraw(id);
    }

    /// [`SendCompletions::forget`]. The completion handlers' stale-generation
    /// branches.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) fn forget_send(&mut self, id: SendId) {
        self.send_completions.forget(id);
    }

    /// [`SendCompletions::set_owner`]. The send futures, every later poll.
    pub(crate) fn set_send_owner(&mut self, id: SendId, task_id: u32) {
        self.send_completions.set_owner(id, task_id);
    }

    /// [`SendCompletions::turn`]. `Admission`, each poll while
    /// waiting.
    pub(crate) fn send_capacity_turn(&mut self, id: SendId, free_slots: usize) -> bool {
        self.send_completions.turn(id, free_slots)
    }

    /// [`SendCompletions::mark_submitted`] plus a wake of the new head.
    /// `Admission`, after the reserve-copy-submit step.
    pub(crate) fn mark_send_submitted(&mut self, id: SendId) {
        if let Some(next) = self.send_completions.mark_submitted(id) {
            let _ = self.wake_task(next);
        }
    }

    /// [`SendCompletions::complete`] plus a wake of the owner. Backends'
    /// send-completion handlers.
    pub(crate) fn complete_send(&mut self, id: SendId, result: io::Result<u32>) {
        if let Some(owner) = self.send_completions.complete(id, result) {
            let _ = self.wake_task(owner);
        }
    }

    /// [`SendCompletions::take_result`]. The send futures, each poll after
    /// submission.
    pub(crate) fn take_send_result(&mut self, id: SendId) -> Option<io::Result<u32>> {
        self.send_completions.take_result(id)
    }

    /// [`SendCompletions::mark_waited_for_room`]. The io_uring event loop's
    /// `wait_for_room`.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) fn mark_sends_waited_for_room(&mut self, conn_index: u32) {
        self.send_completions.mark_waited_for_room(conn_index);
    }

    /// [`SendCompletions::waited_for_room`]. `SendCompletion::waited_for_room`,
    /// and its poll before it takes the result.
    pub(crate) fn send_waited_for_room(&self, id: SendId) -> bool {
        self.send_completions.waited_for_room(id)
    }

    /// [`SendCompletions::cancel`] plus a wake of the new head. The send
    /// futures' `Drop`.
    pub(crate) fn cancel_send(&mut self, id: SendId) {
        if let Some(next) = self.send_completions.cancel(id) {
            let _ = self.wake_task(next);
        }
    }

    /// [`SendCompletions::head_ready`] plus a wake of the head. The
    /// driver's copy-pool slot-release hook, with the number of
    /// slots now free.
    ///
    /// Counted under `cfg(test)` in [`Executor::send_capacity_wakes`]: the
    /// mio loop's "one capacity wake per iteration" is otherwise invisible,
    /// since waking an already-Ready head pushes nothing.
    pub(crate) fn wake_send_capacity(&mut self, free_slots: usize) {
        if let Some(head) = self.send_completions.head_ready(free_slots) {
            #[cfg(test)]
            {
                self.send_capacity_wakes += 1;
            }
            let _ = self.wake_task(head);
        }
    }

    /// [`SendCompletions::set_order`]. The event loops, right after
    /// `Executor::new`, with `Config::send_admission_order`.
    pub(crate) fn set_send_admission_order(&mut self, order: SendAdmissionOrder) {
        self.send_completions.set_order(order);
    }

    /// The worker's admission order. `Admission`, each poll while waiting,
    /// to choose between [`send_capacity_turn`](Self::send_capacity_turn)
    /// and [`send_capacity_admit`](Self::send_capacity_admit).
    pub(crate) fn send_admission_order(&self) -> SendAdmissionOrder {
        self.send_completions.order()
    }

    /// [`SendCompletions::admit`]. `Admission`, each poll while waiting,
    /// under `Budget`.
    pub(crate) fn send_capacity_admit(
        &mut self,
        id: SendId,
        pool: PoolView,
        first_poll: bool,
        idle: impl Fn(u32) -> bool,
    ) -> Admit {
        self.send_completions.admit(id, pool, first_poll, idle)
    }

    /// [`SendCompletions::mark_passed`]. `Admission`, after submitting a
    /// send that passed the head. `id` was behind the head, so the head does
    /// not change and nothing is woken.
    pub(crate) fn mark_send_passed(&mut self, id: SendId, slots: usize) {
        let next = self.send_completions.mark_passed(id, slots);
        debug_assert!(next.is_none(), "a send that passed was the head");
    }

    /// The worker's [`SendAdmissionCounters`]: the FIFO's counts, with B and
    /// its largest value from `pool`.
    pub(crate) fn send_admission_counters(&self, pool: &SendCopyPool) -> SendAdmissionCounters {
        SendAdmissionCounters {
            passing_held: pool.passing_held() as u64,
            passing_held_max: pool.passing_peak() as u64,
            main_free: pool.free_count() as u64,
            conn_held_max: pool.held_peak() as u64,
            unowned_held: pool.unowned_held() as u64,
            ..self.send_completions.counters
        }
    }

    /// [`SendCompletions::scan_due`]. The event loops' end-of-iteration
    /// capacity wake runs when this is set or slots came back.
    pub(crate) fn send_scan_due(&self) -> bool {
        self.send_completions.scan_due()
    }

    /// The event loops' end-of-iteration capacity wake, with the worker's
    /// copy pool. Under `Strict`,
    /// [`wake_send_capacity`](Self::wake_send_capacity) with the free count.
    /// Under `Budget`, [`SendCompletions::scan`] plus a wake of every task it
    /// returns; `idle` answers, for a connection index, whether the
    /// connection has no send queued or in flight and its last settled send
    /// did not wait for room (`Driver::send_idle`). Either way each wake is
    /// counted under `cfg(test)` in [`Executor::send_capacity_wakes`].
    pub(crate) fn wake_send_capacity_in(
        &mut self,
        pool: &SendCopyPool,
        idle: impl Fn(u32) -> bool,
    ) {
        if self.send_completions.order() == SendAdmissionOrder::Strict {
            self.wake_send_capacity(pool.free_count());
            return;
        }
        let mut wakes = std::mem::take(&mut self.send_completions.wake_scratch);
        let view = PoolView::of(pool);
        self.send_completions.scan(view, idle, &mut wakes);
        #[cfg(test)]
        {
            self.send_capacity_wakes += wakes.len() as u32;
        }
        for task_id in wakes.drain(..) {
            let _ = self.wake_task(task_id);
        }
        self.send_completions.wake_scratch = wakes;
    }

    /// [`SendCompletions::abort_connection`] plus a wake of every returned
    /// task. `ConnCtx::abort`.
    pub(crate) fn abort_sends(&mut self, conn_index: u32, generation: u32) {
        for task_id in self
            .send_completions
            .abort_connection(conn_index, generation)
        {
            let _ = self.wake_task(task_id);
        }
    }

    /// [`SendCompletions::fail_waiting`] plus a wake of every returned
    /// task. `SendHalf::shutdown_write`, with `BrokenPipe`.
    pub(crate) fn fail_waiting_bounded_sends(
        &mut self,
        conn_index: u32,
        generation: u32,
        kind: io::ErrorKind,
        msg: &'static str,
    ) {
        for task_id in self
            .send_completions
            .fail_waiting(conn_index, generation, kind, msg)
        {
            let _ = self.wake_task(task_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::waker::STANDALONE_BIT;

    // Task ids in these tests carry STANDALONE_BIT so they never collide
    // with a connection index (see `remove_connection`'s dead-owner rule).
    const fn task(n: u32) -> u32 {
        n | STANDALONE_BIT
    }

    fn kind_of(r: Option<io::Result<u32>>) -> io::ErrorKind {
        r.expect("result present")
            .expect_err("result is an error")
            .kind()
    }

    #[test]
    fn fifo_admits_only_the_head_and_only_with_capacity() {
        let mut q = SendCompletions::new();
        let first = q.enqueue(1, 0, 3, task(1));
        let second = q.enqueue(2, 0, 1, task(2));

        assert!(!q.turn(second, 8), "second must wait behind the head");
        assert!(!q.turn(first, 2), "head must wait for its 3 slots");
        assert!(q.turn(first, 3), "head with capacity is admitted");
        assert!(q.turn(first, 100));
    }

    #[test]
    fn mark_submitted_promotes_and_reports_the_next_head() {
        let mut q = SendCompletions::new();
        let a = q.enqueue(1, 0, 1, task(10));
        let b = q.enqueue(1, 0, 1, task(11));
        let c = q.enqueue(2, 0, 1, task(12));

        assert!(!q.turn(b, 8));
        assert_eq!(q.mark_submitted(a), Some(task(11)), "b is the new head");
        assert!(q.turn(b, 8));
        assert_eq!(q.waiting_len(), 2);
        assert_eq!(q.submitted_len(), 1);

        // Submitting from behind the head promotes nobody.
        assert_eq!(q.mark_submitted(c), None);
        assert!(q.turn(b, 8));

        // The last waiter leaves no head to report.
        assert_eq!(q.mark_submitted(b), None);
        assert_eq!(q.waiting_len(), 0);
        assert_eq!(q.submitted_len(), 3);

        // Already submitted: nothing to do.
        assert_eq!(q.mark_submitted(a), None);
        assert_eq!(q.submitted_len(), 3);
    }

    #[test]
    fn cancel_at_head_promotes_next_but_cancel_behind_head_wakes_nobody() {
        let mut q = SendCompletions::new();
        let a = q.enqueue(1, 0, 1, task(1));
        let b = q.enqueue(1, 0, 1, task(2));
        let c = q.enqueue(1, 0, 1, task(3));

        assert_eq!(q.cancel(b), None, "b was not the head");
        assert!(q.turn(a, 1), "a is still the head");
        assert_eq!(q.cancel(a), Some(task(3)), "c is promoted past the gone b");
        assert!(q.turn(c, 1));
        assert_eq!(q.cancel(c), None, "nobody left to promote");
        assert_eq!(q.waiting_len(), 0);
        assert_eq!(q.cancel(c), None, "cancelling an unknown id is ignored");
    }

    #[test]
    fn abandoned_operation_discards_its_late_completion() {
        let mut q = SendCompletions::new();
        let id = q.enqueue(1, 0, 1, task(1));
        assert_eq!(q.mark_submitted(id), None);
        assert_eq!(q.cancel(id), None, "in flight: nothing to promote");
        assert_eq!(
            q.submitted_len(),
            1,
            "abandoned entry stays until completion"
        );

        assert_eq!(q.complete(id, Ok(5)), None, "no owner to wake");
        assert_eq!(q.submitted_len(), 0, "completion removed the entry");
        assert!(q.take_result(id).is_none());
        assert_eq!(q.complete(id, Ok(5)), None, "second completion is ignored");
    }

    #[test]
    fn take_result_returns_exactly_once() {
        let mut q = SendCompletions::new();
        let id = q.enqueue(1, 0, 1, task(1));
        assert!(q.take_result(id).is_none(), "waiting: no result");
        q.mark_submitted(id);
        assert!(q.take_result(id).is_none(), "in flight: no result");

        assert_eq!(q.complete(id, Ok(42)), Some(task(1)));
        assert_eq!(q.take_result(id).unwrap().unwrap(), 42);
        assert!(q.take_result(id).is_none(), "second take is None");
        assert_eq!(q.submitted_len(), 0);
    }

    #[test]
    fn remove_connection_fails_waiting_and_in_flight_and_wakes_unrelated_head() {
        const A: u32 = 1;
        const B: u32 = 2;
        let mut q = SendCompletions::new();
        let a_abandoned = q.enqueue(A, 0, 1, task(10));
        q.mark_submitted(a_abandoned);
        q.cancel(a_abandoned);
        let a_in_flight = q.enqueue(A, 0, 1, task(11));
        q.mark_submitted(a_in_flight);
        let a_waiting = q.enqueue(A, 0, 1, task(12));
        let b_waiting = q.enqueue(B, 0, 1, task(20));
        assert!(q.turn(a_waiting, 8));

        let wakes = q.remove_connection(A);

        assert!(wakes.contains(&task(11)), "in-flight owner woken");
        assert!(wakes.contains(&task(12)), "waiting owner woken");
        assert!(wakes.contains(&task(20)), "B is the new head and woken");
        assert!(!wakes.contains(&task(10)), "abandoned entry wakes nobody");
        assert_eq!(wakes.len(), 3);

        assert_eq!(
            kind_of(q.take_result(a_in_flight)),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            kind_of(q.take_result(a_waiting)),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(q.submitted_len(), 0, "abandoned entry removed");
        assert_eq!(q.complete(a_abandoned, Ok(1)), None);
        assert!(q.take_result(a_abandoned).is_none());

        assert!(q.turn(b_waiting, 1), "B is the head");
        assert_eq!(q.waiting_len(), 1);

        // A later completion for A's in-flight op is stale and ignored.
        assert_eq!(q.complete(a_in_flight, Ok(1)), None);
        assert_eq!(q.submitted_len(), 0);
    }

    /// Entries on A that A's own task owns at A's release are held by
    /// futures the task handed off (its own cancelled themselves when it was
    /// dropped). The release treats them as any other entry on A: the open
    /// ones record the provisional abort and a resolved one keeps its
    /// result; none is woken, since the owner is gone and the holder has
    /// not polled.
    #[test]
    fn remove_connection_keeps_entries_the_dead_task_handed_off() {
        const A: u32 = 3;
        let mut q = SendCompletions::new();
        let in_flight = q.enqueue(A, 0, 1, A);
        q.mark_submitted(in_flight);
        let done = q.enqueue(A, 0, 1, A);
        q.mark_submitted(done);
        assert_eq!(q.complete(done, Ok(1)), Some(A));
        let waiting = q.enqueue(A, 0, 1, A);
        let other = q.enqueue(4, 0, 1, task(40));

        let wakes = q.remove_connection(A);
        assert_eq!(wakes, vec![task(40)], "only the new head is woken");
        assert_eq!(q.waiting_len(), 1, "A's waiter left the FIFO");
        assert_eq!(q.submitted_len(), 3, "all three of A's entries are kept");
        assert_eq!(
            kind_of(q.take_result(waiting)),
            io::ErrorKind::ConnectionAborted,
            "never submitted: the abort stands"
        );
        assert_eq!(
            q.take_result(done).expect("kept").expect("ok"),
            1,
            "a delivered send keeps its result"
        );
        assert_eq!(q.complete(in_flight, Ok(1)), Some(NO_OWNER));
        assert_eq!(q.take_result(in_flight).expect("resolved").expect("ok"), 1);
        assert_eq!(q.submitted_len(), 0);
        assert!(q.turn(other, 1));
    }

    #[test]
    fn a_real_result_overwrites_a_teardown_abort_but_not_another_result() {
        // A teardown abort is provisional: a driver result that follows it
        // is the authoritative one, whatever order a run loop produces.
        const A: u32 = 7;
        let mut q = SendCompletions::new();
        let id = q.enqueue(A, 0, 1, task(1));
        q.mark_submitted(id);

        assert_eq!(
            q.remove_connection(A),
            vec![task(1)],
            "teardown aborts the in-flight entry and wakes its owner"
        );

        assert_eq!(
            q.complete(id, Ok(200)),
            Some(task(1)),
            "the driver's result must land, and wake the owner again"
        );
        assert_eq!(
            q.take_result(id).expect("resolved").expect("delivered"),
            200,
            "a fully delivered message is not ConnectionAborted"
        );
        assert_eq!(q.submitted_len(), 0);

        // Two driver results for one id: the first still wins.
        let id = q.enqueue(A, 0, 1, task(2));
        q.mark_submitted(id);
        assert_eq!(q.complete(id, Ok(1)), Some(task(2)));
        assert_eq!(q.complete(id, Ok(2)), None, "second driver result ignored");
        assert_eq!(q.take_result(id).expect("resolved").expect("ok"), 1);
    }

    #[test]
    fn a_teardown_abort_nothing_overwrites_still_resolves() {
        // The other half of the provisional-abort rule: if no driver result
        // ever arrives, `take_result` must still hand the abort to the
        // future, or the send parks forever.
        const A: u32 = 8;
        let mut q = SendCompletions::new();
        let in_flight = q.enqueue(A, 0, 1, task(1));
        q.mark_submitted(in_flight);
        let waiting = q.enqueue(A, 0, 1, task(2));

        q.remove_connection(A);

        assert_eq!(
            kind_of(q.take_result(in_flight)),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            kind_of(q.take_result(waiting)),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(q.submitted_len(), 0, "both entries removed by the take");
    }

    #[test]
    fn cancelling_an_aborted_entry_drops_it_and_its_late_result() {
        // The future was dropped after teardown aborted its entry: nothing
        // can take a result, so the entry goes and the driver's later
        // completion finds no id.
        const A: u32 = 9;
        let mut q = SendCompletions::new();
        let id = q.enqueue(A, 0, 1, task(1));
        q.mark_submitted(id);
        q.remove_connection(A);

        assert_eq!(q.cancel(id), None);
        assert_eq!(q.submitted_len(), 0, "the aborted entry is gone");
        assert_eq!(q.complete(id, Ok(4)), None, "a late result has no owner");
        assert!(q.take_result(id).is_none());
    }

    #[test]
    fn fail_waiting_leaves_in_flight_alone_and_uses_the_given_kind() {
        let mut q = SendCompletions::new();
        let in_flight = q.enqueue(1, 5, 1, task(1));
        q.mark_submitted(in_flight);
        let same_gen = q.enqueue(1, 5, 1, task(2));
        let other_gen = q.enqueue(1, 6, 1, task(3));
        let other_conn = q.enqueue(2, 5, 1, task(4));

        // `shutdown_write` passes BrokenPipe; an arbitrary kind here proves the kind
        // is plumbed through rather than hardcoded.
        let wakes = q.fail_waiting(1, 5, io::ErrorKind::TimedOut, "write side shut down");

        assert_eq!(
            wakes,
            vec![task(2), task(3)],
            "failed owner, then the promoted head"
        );
        assert_eq!(kind_of(q.take_result(same_gen)), io::ErrorKind::TimedOut);
        assert!(q.take_result(in_flight).is_none(), "in flight untouched");
        assert_eq!(q.complete(in_flight, Ok(9)), Some(task(1)));
        assert_eq!(q.take_result(in_flight).unwrap().unwrap(), 9);
        assert!(q.turn(other_gen, 1), "other generation is now the head");
        assert_eq!(q.cancel(other_gen), Some(task(4)));
        assert!(q.turn(other_conn, 1));
    }

    /// `abort_connection` fails the connection's waiting entries of its
    /// generation and its in-flight ones with `ConnectionAborted`, and a
    /// driver result that arrives afterwards does not replace that. A
    /// resolved entry, another generation's waiter and another connection's
    /// entries keep their state.
    #[test]
    fn abort_connection_fails_waiting_and_in_flight_entries() {
        let mut q = SendCompletions::new();
        let in_flight = q.enqueue(1, 5, 1, task(1));
        q.mark_submitted(in_flight);
        let done = q.enqueue(1, 5, 1, task(2));
        q.mark_submitted(done);
        q.complete(done, Ok(4));
        let waiting = q.enqueue(1, 5, 1, task(3));
        let other_gen = q.enqueue(1, 6, 1, task(4));
        let other_conn = q.enqueue(2, 5, 1, task(5));
        let other_conn_in_flight = q.enqueue(2, 5, 1, task(6));
        q.mark_submitted(other_conn_in_flight);

        let wakes = q.abort_connection(1, 5);

        assert_eq!(
            wakes,
            vec![task(1), task(3), task(4)],
            "the failed owners, then the promoted head"
        );
        assert_eq!(
            q.complete(in_flight, Ok(9)),
            None,
            "a driver result after the abort is ignored"
        );
        let err = q.take_result(in_flight).unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(err.to_string(), "connection aborted");
        assert_eq!(
            kind_of(q.take_result(waiting)),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(q.take_result(done).unwrap().unwrap(), 4, "resolved before");
        assert!(
            q.take_result(other_gen).is_none(),
            "another generation waits"
        );
        assert!(q.turn(other_gen, 1), "and is now the head");
        assert_eq!(q.cancel(other_gen), Some(task(5)));
        assert!(q.take_result(other_conn).is_none());
        assert!(q.take_result(other_conn_in_flight).is_none());
        assert_eq!(q.waiting_len(), 1, "only the other connection's waiter");
    }

    /// `withdraw` frees an entry no submission took, and leaves alone one
    /// that has moved on.
    #[test]
    fn withdraw_frees_only_an_unsubmitted_entry() {
        let mut q = SendCompletions::new();
        for _ in 0..100 {
            let id = q.register(1, task(1));
            q.withdraw(id);
        }
        assert_eq!(q.live(), 0, "every withdrawn entry is freed");

        let done = q.register(1, task(1));
        q.complete(done, Ok(3));
        q.withdraw(done);
        assert_eq!(q.take_result(done).unwrap().unwrap(), 3, "a result is kept");
    }

    /// `forget` frees an abandoned entry, whose completion is the one it was
    /// waiting for, and leaves a teardown abort for its future to take.
    #[test]
    fn forget_frees_only_an_abandoned_entry() {
        const A: u32 = 3;
        let mut q = SendCompletions::new();
        let abandoned = q.register(A, task(1));
        q.cancel(abandoned);
        q.forget(abandoned);
        assert_eq!(q.live(), 0, "the abandoned entry is freed");

        let aborted = q.register(A, task(2));
        q.forget(aborted);
        assert_eq!(q.live(), 1, "an in-flight entry is kept");
        q.remove_connection(A);
        q.forget(aborted);
        assert_eq!(q.live(), 1, "an aborted entry is kept");
        assert_eq!(
            kind_of(q.take_result(aborted)),
            io::ErrorKind::ConnectionAborted
        );
    }

    /// `remove_connection` finds an entry through its current owner: after
    /// `set_owner` moves it to connection task `C`, tearing `C` down drops
    /// it, and tearing down its first owner does not.
    /// An entry on D that C's task owns is left in flight when C is
    /// released: C's own futures cancelled themselves when C's task was
    /// dropped, so an entry still owned by C is held by a future handed to
    /// a task that has not polled it yet. The entry has no owner to wake
    /// until that poll.
    #[test]
    fn remove_connection_leaves_an_entry_its_dead_task_handed_off_in_flight() {
        const B: u32 = 2;
        const C: u32 = 3;
        const D: u32 = 7;
        let mut q = SendCompletions::new();
        let id = q.register(D, B);
        q.set_owner(id, C);

        assert!(q.remove_connection(B).is_empty(), "B no longer owns it");
        assert_eq!(q.live(), 1);
        assert!(q.remove_connection(C).is_empty(), "nobody to wake yet");
        assert_eq!(q.live(), 1, "kept for the future that holds it");
        assert_eq!(
            q.complete(id, Ok(1)),
            Some(NO_OWNER),
            "the driver's result lands with no owner to wake"
        );
        assert_eq!(q.take_result(id).expect("resolved").expect("ok"), 1);
        assert_eq!(q.live(), 0);
    }

    /// A slot freed by one operation is reused by the next, and an id the
    /// first operation left behind is stale: it reaches nothing.
    #[test]
    fn a_stale_id_never_reaches_the_slot_s_next_occupant() {
        let mut q = SendCompletions::new();
        let old = q.enqueue(1, 0, 1, task(1));
        q.mark_submitted(old);
        q.complete(old, Ok(3));
        assert_eq!(q.take_result(old).unwrap().unwrap(), 3);

        let new = q.enqueue(2, 0, 1, task(2));
        assert_eq!(new.index, old.index, "the freed slot is reused");
        q.mark_submitted(new);

        assert_eq!(q.complete(old, Ok(99)), None, "stale completion ignored");
        assert!(q.take_result(old).is_none());
        q.set_owner(old, task(9));
        assert_eq!(q.cancel(old), None);
        assert_eq!(
            q.complete(new, Ok(7)),
            Some(task(2)),
            "the new operation is still in flight under its own owner"
        );
        assert_eq!(q.take_result(new).unwrap().unwrap(), 7);
    }

    #[test]
    fn head_ready_respects_required_slots() {
        let mut q = SendCompletions::new();
        assert_eq!(q.head_ready(usize::MAX), None, "empty queue");
        q.enqueue(1, 0, 4, task(1));
        q.enqueue(1, 0, 1, task(2));
        assert_eq!(q.head_ready(3), None, "head needs 4");
        assert_eq!(q.head_ready(4), Some(task(1)));
        assert_eq!(q.head_ready(9), Some(task(1)), "never the second waiter");
    }

    #[test]
    fn set_owner_redirects_the_wake() {
        let mut q = SendCompletions::new();
        let id = q.enqueue(1, 0, 1, task(1));
        q.set_owner(id, task(2));
        assert_eq!(q.head_ready(1), Some(task(2)));

        let behind = q.enqueue(1, 0, 1, task(5));
        q.set_owner(behind, task(6));
        assert_eq!(
            q.mark_submitted(id),
            Some(task(6)),
            "promotion uses the new owner"
        );

        q.set_owner(id, task(3));
        assert_eq!(
            q.complete(id, Ok(0)),
            Some(task(3)),
            "completion uses the new owner"
        );

        // Unknown id: ignored.
        q.set_owner(
            SendId {
                index: u32::MAX,
                generation: 0,
            },
            task(9),
        );
        assert_eq!(q.head_ready(1), Some(task(6)));
    }
    /// A proxy task on connection C with a bounded send waiting on
    /// connection D, handed with its `SendHalf` to a task that has not
    /// polled it when C is released. The entry keeps its place in the FIFO:
    /// a waiting entry leaves the FIFO only through its future's drop
    /// (`cancel`), and the future is alive. Its wake goes to no task until
    /// that poll records an owner.
    #[test]
    fn removing_a_connection_keeps_a_waiting_entry_its_task_handed_off_at_the_head() {
        let mut q = SendCompletions::new();
        const C: u32 = 3;
        const D: u32 = 7;

        let handed_off = q.enqueue(D, 1, 1, C);
        let behind = q.enqueue(D, 1, 1, 9 | STANDALONE_BIT);

        assert!(q.remove_connection(C).is_empty(), "the head did not move");

        assert!(q.turn(handed_off, 1), "still the head");
        assert!(!q.turn(behind, 1));
        assert_eq!(
            q.head_ready(1),
            Some(NO_OWNER),
            "a wake for it reaches nobody"
        );
        assert_eq!(q.waiting_len(), 2);

        // The holder polls it: it owns the head and admission proceeds.
        q.set_owner(handed_off, task(5));
        assert_eq!(q.head_ready(1), Some(task(5)));
        assert_eq!(q.mark_submitted(handed_off), Some(9 | STANDALONE_BIT));
        assert_eq!(q.complete(handed_off, Ok(1)), Some(task(5)));
        assert_eq!(q.take_result(handed_off).expect("resolved").expect("ok"), 1);
    }

    /// The result of a send whose creator task returned, and whose
    /// connection was then released, is still there for the future the task
    /// handed off: the send completed before the release (a close finalizes
    /// only once the connection's sends have drained), and the release
    /// keeps a resolved entry.
    #[test]
    fn a_result_that_landed_before_the_release_waits_for_the_handed_off_future() {
        const N: u32 = 3;
        let mut q = SendCompletions::new();
        let id = q.register(N, N);
        assert!(q.remove_task(N).is_empty(), "the task returned");
        assert_eq!(
            q.complete(id, Ok(5)),
            Some(NO_OWNER),
            "delivered, nobody to wake"
        );
        assert!(q.remove_connection(N).is_empty(), "released");
        assert_eq!(q.live(), 1, "the result waits for the future");

        // The task the future was handed to polls it.
        q.set_owner(id, task(5));
        assert_eq!(q.take_result(id).expect("resolved").expect("ok"), 5);
        assert_eq!(q.live(), 0);
    }

    /// An entry still in flight when its creator task returns stays in
    /// flight: the task's own futures cancelled themselves when the task was
    /// dropped, so this one is held by a future handed to another task. The
    /// completion, landing before that task's first poll, is kept for it.
    #[test]
    fn remove_task_leaves_an_in_flight_entry_for_the_future_that_holds_it() {
        const N: u32 = 3;
        let mut q = SendCompletions::new();
        let id = q.register(N, N);
        assert!(q.remove_task(N).is_empty());
        assert_eq!(q.live(), 1, "kept, not abandoned");
        assert_eq!(
            q.complete(id, Ok(5)),
            Some(NO_OWNER),
            "the result is recorded; the wake reaches nobody"
        );
        q.set_owner(id, task(5));
        assert_eq!(q.take_result(id).expect("resolved").expect("ok"), 5);
        assert_eq!(q.live(), 0);
    }

    /// `remove_task` changes no entry's state. The entries the dead task
    /// owned are held by futures it handed off and lose their owner until
    /// polled; entries other tasks own are untouched.
    #[test]
    fn remove_task_leaves_every_entry_where_it_is() {
        const A: u32 = 3;
        let mut q = SendCompletions::new();
        // Entries A's task owned, now held elsewhere.
        let own_in_flight = q.enqueue(A, 0, 1, A);
        q.mark_submitted(own_in_flight);
        let own_done = q.enqueue(A, 0, 1, A);
        q.mark_submitted(own_done);
        assert_eq!(q.complete(own_done, Ok(1)), Some(A));
        let own_waiting = q.enqueue(A, 0, 1, A);
        // Entries on A owned by a standalone task and by connection task 4.
        let other_in_flight = q.register(A, task(40));
        let other_waiting = q.enqueue(A, 0, 1, 4);

        assert!(q.remove_task(A).is_empty(), "the head did not move");
        assert_eq!(q.waiting_len(), 2);
        assert_eq!(q.live(), 5);
        assert!(
            q.turn(own_waiting, 1),
            "still the head, for its holder's poll"
        );
        assert_eq!(q.head_ready(1), Some(NO_OWNER));
        assert_eq!(q.take_result(own_done).expect("kept").expect("ok"), 1);
        assert_eq!(q.complete(own_in_flight, Ok(1)), Some(NO_OWNER));
        assert_eq!(
            q.take_result(own_in_flight).expect("resolved").expect("ok"),
            1
        );

        assert!(q.take_result(other_in_flight).is_none(), "still in flight");
        assert_eq!(
            q.complete(other_in_flight, Ok(5)),
            Some(task(40)),
            "the driver's result reaches the live owner"
        );
        assert_eq!(q.take_result(other_in_flight).unwrap().unwrap(), 5);
        assert!(!q.turn(other_waiting, 1), "behind the handed-off waiter");
        assert_eq!(q.live(), 2);
    }

    /// A connection task's entries on *another* connection (a proxy's
    /// bounded send to upstream) are kept the same way.
    #[test]
    fn remove_task_keeps_the_task_s_entries_on_other_connections() {
        const C: u32 = 3;
        const D: u32 = 7;
        let mut q = SendCompletions::new();
        let waiting = q.enqueue(D, 0, 1, C);
        let in_flight = q.register(D, C);
        let unrelated = q.enqueue(D, 0, 1, task(9));

        assert!(q.remove_task(C).is_empty());
        assert!(q.turn(waiting, 1), "still the head");
        assert_eq!(q.complete(in_flight, Ok(1)), Some(NO_OWNER));
        assert_eq!(q.take_result(in_flight).expect("resolved").expect("ok"), 1);
        assert!(!q.turn(unrelated, 1));
        assert_eq!(q.live(), 2);
    }

    /// Cancelling waiters behind the head leaves their ids in place, and the
    /// head's next reads pop them once each: no cancel searches the FIFO.
    /// Cancelling from the back is the order in which a search costs most.
    #[test]
    fn cancelling_waiters_behind_the_head_does_not_search_the_fifo() {
        const A: u32 = 4;
        let mut q = SendCompletions::new();
        let head = q.enqueue(A, 0, 1, task(1));
        let behind: Vec<SendId> = (0..64).map(|i| q.enqueue(A, 0, 1, task(2 + i))).collect();
        q.visited = 0;
        for &id in behind.iter().rev() {
            assert_eq!(q.cancel(id), None, "not the head: nobody to wake");
        }
        assert_eq!(
            q.waiting.len(),
            65,
            "the cancelled ids stay until they reach the head"
        );
        assert_eq!(q.waiting_len(), 1);
        // Each cancel reads the head once.
        assert_eq!(q.visited, 64);

        assert_eq!(q.mark_submitted(head), None, "no waiter left to wake");
        assert!(q.waiting.is_empty(), "the stale ids were popped");
        // The head read once, then the 64 stale ids popped once each.
        assert_eq!(q.visited, 64 + 1 + 64);
    }

    /// A head that waits while the waiters behind it come and go does not
    /// leave the FIFO growing: the stale ids are dropped once they outnumber
    /// the live ones.
    #[test]
    fn stale_ids_behind_a_waiting_head_are_dropped() {
        const A: u32 = 5;
        let mut q = SendCompletions::new();
        let head = q.enqueue(A, 0, 4, task(1));
        for i in 0..1000 {
            let id = q.enqueue(A, 0, 1, task(2 + i));
            q.cancel(id);
            assert!(q.waiting.len() <= 2 * q.waiting_len() + 64 + 1);
        }
        assert_eq!(q.waiting_len(), 1);
        assert!(q.turn(head, 4), "the head kept its place");
    }

    /// An aborted head left by a released connection is skipped by the next
    /// read of the head, whatever the free count, and its id leaves the FIFO.
    #[test]
    fn a_released_connection_s_waiter_does_not_hold_the_head() {
        const A: u32 = 6;
        const B: u32 = 7;
        let mut q = SendCompletions::new();
        let a = q.enqueue(A, 0, 1, task(1));
        let b = q.enqueue(B, 0, 1, task(2));
        q.remove_connection(A);
        assert_eq!(q.head_ready(1), Some(task(2)), "B is admitted with A gone");
        assert!(q.turn(b, 1));
        assert_eq!(q.mark_submitted(b), None);
        assert!(q.waiting.is_empty());
        assert_eq!(
            kind_of(q.take_result(a)),
            io::ErrorKind::ConnectionAborted,
            "A's future still collects its abort"
        );
    }

    /// The slot indices `lists` holds under `key`, front first.
    fn listed(lists: &[VecDeque<u32>], key: u32) -> Vec<u32> {
        lists
            .get(key as usize)
            .map(|list| list.iter().copied().collect())
            .unwrap_or_default()
    }

    /// A connection task's id is its connection index, so it is indexed in
    /// `by_task` as well as `by_conn`.
    const CONN: u32 = 3;
    const OTHER_CONN: u32 = 5;

    /// Sends settle in the order they were registered, and each leaves the
    /// front of its lists, which keep the rest in registration order. A send
    /// whose future was dropped has already left its task's list; one whose
    /// future takes the result leaves both lists then.
    #[test]
    fn settling_in_order_keeps_the_lists_in_registration_order() {
        let mut q = SendCompletions::new();
        let ids: Vec<SendId> = (0..64).map(|_| q.register(CONN, CONN)).collect();
        for &id in &ids {
            assert_eq!(q.cancel(id), None, "in flight: nothing to promote");
        }
        assert_eq!(listed(&q.by_task, CONN), Vec::<u32>::new());
        for (n, &id) in ids.iter().enumerate() {
            assert_eq!(
                q.complete(id, Ok(1)),
                None,
                "an abandoned send wakes nobody"
            );
            let rest: Vec<u32> = ids[n + 1..].iter().map(|id| id.index).collect();
            assert_eq!(listed(&q.by_conn, CONN), rest, "by_conn after {n}");
        }
        assert_eq!(q.live(), 0);

        let ids: Vec<SendId> = (0..64).map(|_| q.register(CONN, CONN)).collect();
        for (n, &id) in ids.iter().enumerate() {
            assert_eq!(q.complete(id, Ok(1)), Some(CONN));
            assert!(q.take_result(id).is_some());
            let rest: Vec<u32> = ids[n + 1..].iter().map(|id| id.index).collect();
            assert_eq!(listed(&q.by_conn, CONN), rest, "by_conn after {n}");
            assert_eq!(listed(&q.by_task, CONN), rest, "by_task after {n}");
        }
        assert_eq!(q.live(), 0);
    }

    /// Entries that leave out of order, through every path that removes an
    /// index (a taken result, a re-owning poll, an abandoned completion),
    /// leave the others listed in the order they were added.
    #[test]
    fn settling_out_of_order_keeps_the_lists_consistent() {
        let mut q = SendCompletions::new();
        // One task sending on two connections, alternately.
        let ids: Vec<SendId> = (0..8)
            .map(|n| q.register(if n % 2 == 0 { CONN } else { OTHER_CONN }, CONN))
            .collect();
        let index = |n: usize| ids[n].index;

        // The other connection's sends settle first, newest first, and
        // their futures take the results.
        for n in [7, 5, 3, 1] {
            assert_eq!(q.complete(ids[n], Ok(1)), Some(CONN));
            assert!(q.take_result(ids[n]).is_some());
        }
        assert_eq!(listed(&q.by_conn, OTHER_CONN), Vec::<u32>::new());
        let on_conn: Vec<u32> = [0, 2, 4, 6].map(index).to_vec();
        assert_eq!(listed(&q.by_conn, CONN), on_conn);
        assert_eq!(listed(&q.by_task, CONN), on_conn);

        // A future moved to another connection task leaves the middle of
        // the first task's list and joins the back of the second's.
        q.set_owner(ids[2], OTHER_CONN);
        assert_eq!(listed(&q.by_task, CONN), [0, 4, 6].map(index).to_vec());
        assert_eq!(listed(&q.by_task, OTHER_CONN), vec![index(2)]);
        assert_eq!(listed(&q.by_conn, CONN), on_conn, "by_conn is unchanged");

        // The rest settle from the middle, then the back, then the front.
        for (n, conn_rest, task_rest) in [
            (4, vec![0, 2, 6], vec![0, 6]),
            (6, vec![0, 2], vec![0]),
            (0, vec![2], vec![]),
        ] {
            assert_eq!(q.cancel(ids[n]), None);
            assert_eq!(q.complete(ids[n], Ok(1)), None);
            let conn_rest: Vec<u32> = conn_rest.into_iter().map(index).collect();
            let task_rest: Vec<u32> = task_rest.into_iter().map(index).collect();
            assert_eq!(listed(&q.by_conn, CONN), conn_rest, "by_conn after {n}");
            assert_eq!(listed(&q.by_task, CONN), task_rest, "by_task after {n}");
        }
        assert_eq!(q.complete(ids[2], Ok(1)), Some(OTHER_CONN));
        assert!(q.take_result(ids[2]).is_some());
        assert_eq!(listed(&q.by_conn, CONN), Vec::<u32>::new());
        assert_eq!(listed(&q.by_task, OTHER_CONN), Vec::<u32>::new());
        assert_eq!(q.live(), 0);
    }

    /// The comparisons `index_remove` makes while `f` runs.
    fn comparisons(f: impl FnOnce()) -> usize {
        INDEX_SCANNED.with(|c| c.set(0));
        f();
        INDEX_SCANNED.with(|c| c.get())
    }

    /// Settling N queued sends whose futures were dropped costs one
    /// comparison per list per send: the task's list when the future is
    /// dropped, the connection's when the send settles. That holds too when
    /// one task sends on two connections and the second one's sends settle
    /// while the first one's wait. A list that does not keep registration
    /// order costs about N^2/2 per list, 200 million at this N, and so does
    /// keeping abandoned entries in the task's list in the two-connection
    /// case.
    #[test]
    fn settling_in_order_compares_once_per_list_per_send() {
        const N: usize = 20_000;

        let mut q = SendCompletions::new();
        let scanned = comparisons(|| {
            let ids: Vec<SendId> = (0..N).map(|_| q.register(CONN, CONN)).collect();
            for &id in &ids {
                q.cancel(id);
            }
            for &id in &ids {
                q.complete(id, Ok(1));
            }
        });
        assert_eq!(scanned, 2 * N, "one connection");
        assert_eq!(q.live(), 0);

        // One task, two connections, each future dropped as soon as its send
        // is made (`let _ = tx.send(..)`); the second connection's sends
        // settle first.
        let mut q = SendCompletions::new();
        let scanned = comparisons(|| {
            let mut first = Vec::new();
            let mut second = Vec::new();
            for _ in 0..N {
                for (conn, ids) in [(CONN, &mut first), (OTHER_CONN, &mut second)] {
                    let id = q.register(conn, CONN);
                    q.cancel(id);
                    ids.push(id);
                }
            }
            for &id in second.iter().chain(&first) {
                q.complete(id, Ok(1));
            }
        });
        assert_eq!(scanned, 2 * 2 * N, "two connections");
        assert_eq!(q.live(), 0);
    }

    /// A send whose future is dropped at once leaves its task's list from
    /// the back, so the sends a task makes behind awaited ones it still
    /// holds cost the same few comparisons however many it holds.
    #[test]
    fn a_dropped_send_leaves_its_tasks_list_from_the_back() {
        const N: usize = 20_000;
        const HELD: usize = 16;
        let mut q = SendCompletions::new();
        let held: Vec<SendId> = (0..HELD).map(|_| q.register(OTHER_CONN, CONN)).collect();
        let scanned = comparisons(|| {
            for _ in 0..N {
                let id = q.register(CONN, CONN);
                q.cancel(id);
                q.complete(id, Ok(1));
            }
        });
        // Dropping compares the front (a held send) and then the back;
        // settling compares the front of the connection's list.
        assert_eq!(scanned, 3 * N);
        let held_indices: Vec<u32> = held.iter().map(|id| id.index).collect();
        assert_eq!(listed(&q.by_task, CONN), held_indices);
        for &id in &held {
            assert_eq!(q.complete(id, Ok(1)), Some(CONN));
            assert!(q.take_result(id).is_some());
        }
        assert_eq!(q.live(), 0);
    }

    // ── The Budget order ────────────────────────────────────────────────

    /// `Budget` with a budget that never binds, for the tests that are not
    /// about it.
    const UNBOUNDED: SendAdmissionOrder = SendAdmissionOrder::Budget { slots: u16::MAX };

    fn pool(free: usize, passing: usize, slots: usize) -> PoolView {
        PoolView {
            free,
            passing,
            slots,
        }
    }

    fn idle(_conn_index: u32) -> bool {
        true
    }

    /// The task ids `scan` wakes for `view`, every connection idle.
    fn scanned(q: &mut SendCompletions, view: PoolView) -> Vec<u32> {
        let mut wakes = Vec::new();
        q.scan(view, |_| true, &mut wakes);
        wakes
    }

    /// Under `Strict` the queue keeps no arrival numbers and asks for no
    /// scan, whatever leaves the FIFO: none of `Budget`'s work runs.
    #[test]
    fn strict_keeps_no_arrival_numbers_and_asks_for_no_scan() {
        let mut q = SendCompletions::new();
        let head = q.enqueue(1, 0, 6, task(1));
        let behind = q.enqueue(2, 0, 1, task(2));
        let gone = q.enqueue(3, 0, 1, task(3));
        assert_eq!(q.next_seq, 0);
        assert!(!q.turn(behind, 4), "nothing passes the head");
        q.cancel(gone);
        q.mark_submitted(head);
        q.remove_connection(2);
        assert!(!q.scan_due());
        assert_eq!(q.counters, SendAdmissionCounters::default());
    }

    /// A waiter that fits passes a head that does not, and once the head
    /// fits the head is admitted, not the waiter.
    #[test]
    fn a_waiter_that_fits_passes_a_head_that_does_not() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        let head = q.enqueue(1, 0, 6, task(1));
        let small = q.enqueue(2, 0, 1, task(2));
        assert_eq!(q.admit(head, pool(4, 0, 8), true, idle), Admit::Wait);
        assert_eq!(
            q.admit(small, pool(4, 0, 8), true, idle),
            Admit::Pass { slots: 1 }
        );
        assert_eq!(
            q.admit(small, pool(6, 0, 8), true, idle),
            Admit::Wait,
            "the head fits and goes first"
        );
        assert_eq!(q.admit(head, pool(6, 0, 8), true, idle), Admit::Head);
        assert_eq!(
            q.admit(small, pool(0, 0, 8), true, idle),
            Admit::Wait,
            "a waiter that does not fit waits"
        );
    }

    /// No waiter passes while an earlier waiter on its own connection
    /// waits, the head's connection included; once the earlier one leaves,
    /// it may.
    #[test]
    fn a_waiter_whose_connection_has_an_earlier_waiter_does_not_pass() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        let head = q.enqueue(1, 0, 6, task(1));
        let behind_head = q.enqueue(1, 0, 1, task(2));
        let large = q.enqueue(2, 0, 5, task(3));
        let small = q.enqueue(2, 0, 1, task(4));
        let view = pool(4, 0, 8);
        assert_eq!(q.admit(behind_head, view, true, idle), Admit::Wait);
        assert_eq!(q.admit(large, view, true, idle), Admit::Wait);
        assert_eq!(q.admit(small, view, true, idle), Admit::Wait);
        q.cancel(large);
        assert_eq!(q.admit(small, view, true, idle), Admit::Pass { slots: 1 });
        q.mark_submitted(head);
        assert_eq!(
            q.admit(behind_head, view, true, idle),
            Admit::Head,
            "the next on the head's connection is the new head"
        );
    }

    /// B plus a passing send's slots stays within min(slots, P - H), with B
    /// counted by a real pool as the passing sends take slots.
    #[test]
    fn budget_never_lets_passing_sends_hold_more_than_the_budget() {
        // (budget, P, H, slots each waiter needs): the budget binds, then
        // P - H binds.
        let cases = [(3u16, 16u16, 10, 1), (10, 16, 14, 1), (4, 16, 10, 3)];
        for (budget, slots, head_needs, each) in cases {
            budget_case(budget, slots, head_needs, each);
        }
    }

    /// One case of the test above: a budget of `budget`, a pool of `slots`,
    /// a head of `head_needs` and waiters of `each` slots.
    fn budget_case(budget: u16, slots: u16, head_needs: usize, each: usize) {
        let mut q = SendCompletions::with_order(SendAdmissionOrder::Budget { slots: budget });
        let mut copy_pool = SendCopyPool::new(slots, 8);
        copy_pool.track_passing();
        // Sends outside the FIFO hold all but 8 slots, so the head waits.
        let held: Vec<u16> = (0..slots - 8)
            .map(|_| {
                copy_pool
                    .copy_in(crate::buffer::send_copy::SlotOwner::NONE, b"x")
                    .unwrap()
                    .0
            })
            .collect();
        q.enqueue(1, 0, head_needs, task(1));
        let limit = usize::from(budget).min(usize::from(slots) - head_needs);
        let mut passed = 0;
        for conn in 2..20 {
            let id = q.enqueue(conn, 0, each, task(conn));
            match q.admit(id, PoolView::of(&copy_pool), true, idle) {
                Admit::Pass { slots } => {
                    copy_pool.begin_passing();
                    for _ in 0..slots {
                        copy_pool
                            .copy_in(crate::buffer::send_copy::SlotOwner::NONE, b"p")
                            .unwrap();
                    }
                    copy_pool.end_passing();
                    q.mark_submitted(id);
                    passed += slots;
                }
                Admit::Wait => {
                    q.cancel(id);
                }
                Admit::Head => panic!("not the head"),
            }
            assert!(copy_pool.passing_held() <= limit, "B within min(R, P - H)");
        }
        assert_eq!(copy_pool.passing_held(), passed);
        assert!(
            passed + each > limit,
            "budget {budget}: stopped only at the limit, at {passed}"
        );
        for slot in held {
            copy_pool.release(slot);
        }
    }

    /// A budget above the pool's slot count admits as one of P - H does.
    #[test]
    fn a_budget_above_the_pool_admits_as_the_pool_does() {
        let mut q = SendCompletions::with_order(SendAdmissionOrder::Budget { slots: 1000 });
        q.enqueue(1, 0, 6, task(1));
        let fits = q.enqueue(2, 0, 2, task(2));
        let over = q.enqueue(3, 0, 1, task(3));
        assert_eq!(
            q.admit(fits, pool(4, 0, 8), true, idle),
            Admit::Pass { slots: 2 }
        );
        q.mark_passed(fits, 2);
        assert_eq!(
            q.admit(over, pool(2, 2, 8), true, idle),
            Admit::Wait,
            "B = 2 = P - H"
        );
    }

    /// No waiter passes while its connection has a send queued or in
    /// flight, or its last settled send waited for room; the scan reads the
    /// same test.
    #[test]
    fn a_waiter_whose_connection_is_busy_does_not_pass() {
        let mut q = SendCompletions::with_order(SendAdmissionOrder::Budget { slots: 8 });
        q.enqueue(1, 0, 6, task(1));
        let w = q.enqueue(2, 0, 1, task(2));
        assert_eq!(q.admit(w, pool(4, 0, 8), true, |_| false), Admit::Wait);
        let mut wakes = Vec::new();
        q.scan(pool(4, 0, 8), |conn| conn != 2, &mut wakes);
        assert!(wakes.is_empty(), "the scan reads the same test");
        q.scan(pool(4, 0, 8), |_| true, &mut wakes);
        assert_eq!(wakes, vec![task(2)]);
        assert_eq!(
            q.admit(w, pool(4, 0, 8), true, idle),
            Admit::Pass { slots: 1 }
        );
    }

    /// A waiter admitted past the head leaves its id in `waiting`, like a
    /// cancelled one: `front` pops it once it reaches the front, and the
    /// live count drops at once.
    #[test]
    fn a_waiter_that_passed_leaves_its_id_for_front_to_pop() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        let head = q.enqueue(1, 0, 6, task(1));
        let w = q.enqueue(2, 0, 1, task(2));
        assert_eq!(
            q.admit(w, pool(4, 0, 8), true, idle),
            Admit::Pass { slots: 1 }
        );
        assert_eq!(q.mark_submitted(w), None, "passing promotes nobody");
        assert_eq!(q.waiting_len(), 1);
        assert_eq!(
            q.waiting.len(),
            2,
            "the id stays until it reaches the front"
        );
        assert_eq!(q.mark_submitted(head), None, "no waiter left");
        assert!(q.waiting.is_empty(), "popped behind the head");
        assert_eq!(q.complete(w, Ok(1)), Some(task(2)));
        assert_eq!(q.take_result(w).unwrap().unwrap(), 1);
    }

    /// The scan wakes the head alone when it fits, and otherwise the oldest
    /// waiters that could pass, counting each against the free slots,
    /// skipping one behind an earlier waiter on its connection, a stale id
    /// and a waiter with no owner. A waiter that needs no slots is woken
    /// after the free slots run out. Having woken passers, it asks for the
    /// next scan, which does not wake them again before they poll.
    #[test]
    fn scan_wakes_the_waiters_that_could_pass_oldest_first() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        let head = q.enqueue(1, 0, 10, task(1));
        q.enqueue(2, 0, 2, task(2));
        let gone = q.enqueue(3, 0, 1, task(3));
        q.enqueue(4, 0, 3, task(4));
        q.enqueue(2, 0, 1, task(5));
        q.enqueue(5, 0, 1, NO_OWNER);
        q.enqueue(6, 0, 1, task(6));
        q.enqueue(7, 0, 5, task(7));
        q.enqueue(8, 0, 0, task(8));
        q.cancel(gone);
        assert!(q.scan_due());

        assert_eq!(
            scanned(&mut q, pool(10, 0, 16)),
            vec![task(1)],
            "the head fits"
        );
        assert_eq!(
            scanned(&mut q, pool(6, 0, 16)),
            vec![task(2), task(4), task(6), task(8)],
            "2 + 3 + 1 slots, then the empty message"
        );
        assert!(q.scan_due(), "a scan that woke passers asks for the next");
        assert_eq!(q.front(), Some(head), "the scan pops nothing");
        let again = scanned(&mut q, pool(6, 0, 16));
        assert!(
            [task(2), task(4), task(6), task(8)]
                .iter()
                .all(|woken| !again.contains(woken)),
            "the next scan does not wake them again before they poll: {again:?}"
        );
    }

    /// The scan counts the waiters it wakes against the budget as if they
    /// had passed.
    #[test]
    fn scan_counts_woken_waiters_against_the_budget() {
        let mut q = SendCompletions::with_order(SendAdmissionOrder::Budget { slots: 3 });
        q.enqueue(1, 0, 10, task(1));
        for conn in 2..8 {
            q.enqueue(conn, 0, 1, task(conn));
        }
        assert_eq!(
            scanned(&mut q, pool(6, 1, 16)),
            vec![task(2), task(3)],
            "B = 1, so two more fit the budget of 3"
        );
    }

    /// Under `Budget`, `scan_due` is set whenever a waiter leaves the
    /// waiting state, whatever the way, and by a later poll told to wait; a
    /// first poll told to wait does not set it.
    #[test]
    fn scan_due_follows_every_way_a_waiter_leaves() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        let head = q.enqueue(1, 0, 6, task(1));
        let w = q.enqueue(1, 0, 1, task(2));
        assert_eq!(q.admit(w, pool(4, 0, 8), true, idle), Admit::Wait);
        assert!(!q.scan_due(), "a first poll that waits");
        assert_eq!(q.admit(w, pool(4, 0, 8), false, idle), Admit::Wait);
        assert!(q.scan_due(), "a later poll that waits");

        let leave: [fn(&mut SendCompletions, SendId); 5] = [
            |q, id| {
                q.cancel(id);
            },
            |q, id| {
                q.mark_submitted(id);
            },
            |q, _| {
                q.remove_connection(3);
            },
            |q, _| {
                q.fail_waiting(3, 0, io::ErrorKind::BrokenPipe, "shut down");
            },
            |q, _| {
                q.abort_connection(3, 0);
            },
        ];
        for (n, leave) in leave.iter().enumerate() {
            let id = q.enqueue(3, 0, 1, task(10));
            q.scan(pool(0, 0, 8), |_| true, &mut Vec::new());
            assert!(!q.scan_due());
            leave(&mut q, id);
            assert!(q.scan_due(), "way {n}");
        }
        q.scan(pool(0, 0, 8), |_| true, &mut Vec::new());
        q.mark_submitted(head);
        assert!(q.scan_due(), "the head was admitted");
    }

    /// The FIFO's counts: a pass and its slots, and a scan that looks behind
    /// the head, with the waiters it wakes. A scan that stops at a head that
    /// fits is not counted.
    #[test]
    fn counters_record_passes_and_scans() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        let head = q.enqueue(1, 0, 6, task(1));
        let a = q.enqueue(2, 0, 2, task(2));
        q.enqueue(3, 0, 1, task(3));
        assert_eq!(
            q.admit(a, pool(4, 0, 8), true, idle),
            Admit::Pass { slots: 2 }
        );
        assert_eq!(q.mark_passed(a, 2), None);
        assert_eq!(
            scanned(&mut q, pool(2, 2, 8)),
            Vec::<u32>::new(),
            "B = P - H"
        );
        assert_eq!(scanned(&mut q, pool(2, 0, 8)), vec![task(3)]);
        assert_eq!(
            q.counters,
            SendAdmissionCounters {
                passing_admissions: 1,
                passing_slots: 2,
                wake_scans: 2,
                scan_wakes: 1,
                ..SendAdmissionCounters::default()
            }
        );

        q.cancel(head);
        assert_eq!(scanned(&mut q, pool(6, 0, 8)), vec![task(3)], "it fits");
        assert_eq!(q.counters.wake_scans, 2, "a scan of a head that fits");
    }

    /// The executor's counters take B and its largest value from the pool.
    #[test]
    fn executor_counters_take_passing_slots_from_the_pool() {
        let mut exec = Executor::new(8, 8, 8, 0, 0);
        exec.set_send_admission_order(UNBOUNDED);
        let mut copy_pool = SendCopyPool::new(8, 8);
        copy_pool.track_passing();
        copy_pool.begin_passing();
        let (first, _p, _l) = copy_pool
            .copy_in(crate::buffer::send_copy::SlotOwner::NONE, b"p")
            .unwrap();
        copy_pool
            .copy_in(crate::buffer::send_copy::SlotOwner::NONE, b"q")
            .unwrap();
        copy_pool.end_passing();
        copy_pool.release(first);
        let counters = exec.send_admission_counters(&copy_pool);
        assert_eq!((counters.passing_held, counters.passing_held_max), (1, 2));
        assert_eq!(counters.main_free, 7);
    }

    /// Heads admitted at the front keep the stale ids that passers left
    /// behind them within twice the live ids plus 64, the bound the scan's
    /// cost rests on.
    #[test]
    fn heads_admitted_at_the_front_keep_stale_ids_bounded() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        let heads: Vec<SendId> = (0..65).map(|i| q.enqueue(i, 0, 6, task(i))).collect();
        for i in 0..100 {
            let passer = q.enqueue(100 + i, 0, 1, task(100 + i));
            assert_eq!(
                q.admit(passer, pool(4, 0, 8), true, idle),
                Admit::Pass { slots: 1 }
            );
            q.mark_submitted(passer);
        }
        for head in heads {
            q.mark_submitted(head);
            assert!(
                q.waiting.len() <= 2 * q.waiting_len() + 64,
                "{} ids for {} live",
                q.waiting.len(),
                q.waiting_len()
            );
        }
    }

    /// A waiter's first poll does not take the room an older parked waiter
    /// could pass with: the older one is counted first, as the scan that
    /// wakes it counts it. One slot coming back, and then a budget of 2 with
    /// B falling from 2 to 1.
    #[test]
    fn an_older_waiter_that_could_pass_goes_before_a_newer_one() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        q.enqueue(1, 0, 6, task(1));
        let older = q.enqueue(2, 0, 1, task(2));
        assert_eq!(q.admit(older, pool(0, 0, 8), true, idle), Admit::Wait);
        let newer = q.enqueue(3, 0, 1, task(3));
        assert_eq!(
            q.admit(newer, pool(1, 0, 8), true, idle),
            Admit::Wait,
            "the slot is the older waiter's"
        );
        assert!(q.scan_due(), "the older waiter is woken");
        assert_eq!(scanned(&mut q, pool(1, 0, 8)), vec![task(2)]);
        assert_eq!(
            q.admit(older, pool(1, 0, 8), false, idle),
            Admit::Pass { slots: 1 }
        );

        let mut q = SendCompletions::with_order(SendAdmissionOrder::Budget { slots: 2 });
        q.enqueue(1, 0, 10, task(1));
        let older = q.enqueue(2, 0, 1, task(2));
        let budget = |passing| pool(4, passing, 16);
        assert_eq!(q.admit(older, budget(2), true, idle), Admit::Wait);
        let newer = q.enqueue(3, 0, 1, task(3));
        assert_eq!(q.admit(newer, budget(1), true, idle), Admit::Wait);
        assert_eq!(
            q.admit(older, budget(1), false, idle),
            Admit::Pass { slots: 1 }
        );
    }

    /// An older waiter that a scan woke and that does not poll keeps its
    /// claim on the room only until the next scan: then a newer waiter that
    /// fits is woken and passes.
    #[test]
    fn an_older_waiter_that_does_not_poll_loses_its_claim_at_the_next_scan() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        q.enqueue(1, 0, 6, task(1));
        let older = q.enqueue(2, 0, 1, task(2));
        assert_eq!(q.admit(older, pool(0, 0, 8), true, idle), Admit::Wait);
        assert_eq!(scanned(&mut q, pool(1, 0, 8)), vec![task(2)]);
        let newer = q.enqueue(3, 0, 1, task(3));
        assert_eq!(
            q.admit(newer, pool(1, 0, 8), true, idle),
            Admit::Wait,
            "the older one was woken for that slot this iteration"
        );
        assert!(q.scan_due());
        assert_eq!(
            scanned(&mut q, pool(1, 0, 8)),
            vec![task(3)],
            "the older one did not poll: the newer one is woken"
        );
        assert_eq!(
            q.admit(newer, pool(1, 0, 8), false, idle),
            Admit::Pass { slots: 1 }
        );

        // Once the older one polls, it competes again.
        assert_eq!(q.admit(older, pool(0, 0, 8), false, idle), Admit::Wait);
        assert_eq!(scanned(&mut q, pool(1, 0, 8)), vec![task(2)]);
    }

    /// Two waiters of one task, the task polling only the newer: the
    /// newer is admitted within two scans, and then the scans stop, instead
    /// of each poll asking for a scan that wakes the same task again.
    #[test]
    fn a_task_that_polls_only_its_newer_waiter_does_not_spin() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        q.enqueue(1, 0, 6, task(1));
        let older = q.enqueue(2, 0, 1, task(9));
        let newer = q.enqueue(3, 0, 1, task(9));
        assert_eq!(q.admit(older, pool(0, 0, 8), true, idle), Admit::Wait);
        assert_eq!(q.admit(newer, pool(0, 0, 8), true, idle), Admit::Wait);
        let mut scans = 0;
        let mut admitted = false;
        while q.scan_due() || scans == 0 {
            scans += 1;
            assert!(scans <= 4, "still scanning after {scans} scans");
            if !scanned(&mut q, pool(1, 0, 8)).is_empty()
                && !admitted
                && q.admit(newer, pool(1, 0, 8), false, idle) == (Admit::Pass { slots: 1 })
            {
                q.mark_passed(newer, 1);
                admitted = true;
            }
        }
        assert!(admitted, "the newer waiter passed");
    }

    /// A scan that wakes passers asks for the next: here both waiters parked
    /// before the slot came back, so nothing else would ask, and only the
    /// next scan finds the older one's claim gone and wakes the newer one.
    #[test]
    fn a_scan_that_woke_passers_asks_for_the_next() {
        let mut q = SendCompletions::with_order(UNBOUNDED);
        q.enqueue(1, 0, 6, task(1));
        let older = q.enqueue(2, 0, 1, task(2));
        let newer = q.enqueue(3, 0, 1, task(3));
        assert_eq!(q.admit(older, pool(0, 0, 8), true, idle), Admit::Wait);
        assert_eq!(q.admit(newer, pool(0, 0, 8), true, idle), Admit::Wait);
        assert!(!q.scan_due(), "first polls ask for nothing");
        assert_eq!(scanned(&mut q, pool(1, 0, 8)), vec![task(2)]);
        assert!(q.scan_due(), "the next scan is due");
        assert_eq!(scanned(&mut q, pool(1, 0, 8)), vec![task(3)]);
    }
}
