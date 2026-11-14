//! Per-worker completion table for awaited sends, and the admission FIFO
//! for bounded sends.
//!
//! Every awaited send (`SendHalf::send`, `submit_batch_await`, `send_chain`,
//! `send_admitted`, `send_backpressured`) holds an entry here, named by the
//! [`SendId`] its future keeps. The driver settles the entry when that send
//! completes, and the future resolves with the result of that one send. A
//! bounded send (`SendHalf::send_admitted`, `send_backpressured`) is also
//! admission-controlled: it may only reserve copy-pool slots once it is the
//! *oldest* waiter on the worker and the pool can admit its whole message.
//!
//! The table is plain worker-local state owned by the [`Executor`]. Every
//! entry holds a slot indexed by its id, and is also listed under its target
//! connection and, when a connection task owns it, under that task; waiting
//! bounded sends are listed in arrival order. `register`, `set_owner`,
//! `complete`, `take_result`, `mark_submitted` and `cancel` are index
//! lookups; `remove_connection` and `fail_waiting` visit the entries listed
//! under their connection. An entry that leaves the waiting state leaves its
//! id in the waiting list, and the reads of the head pop the ids at the front
//! that no longer name a waiting entry, so each id is pushed once and leaves
//! once, popped at the front or dropped by `compact`. Design:
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

use std::collections::VecDeque;
use std::io;

use super::Executor;

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
/// poll records the polling task as the owner.
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
    /// Waiting operations in arrival order. Only the head may be admitted.
    /// Also holds ids that no longer name a waiting entry, which
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
    /// indexed by connection index.
    by_conn: Vec<Vec<u32>>,
    /// Slot indices of the live operations owned by each connection task,
    /// indexed by task id. Standalone tasks and [`NO_OWNER`] are not indexed:
    /// [`remove_task`](Self::remove_task) and
    /// [`remove_connection`](Self::remove_connection) never look them up.
    by_task: Vec<Vec<u32>>,
}

/// Record `index` under `key`.
fn index_add(lists: &mut Vec<Vec<u32>>, key: u32, index: u32) {
    let key = key as usize;
    if lists.len() <= key {
        lists.resize_with(key + 1, Vec::new);
    }
    lists[key].push(index);
}

/// Forget `index` under `key`. A list holds the few operations of one
/// connection or task, so the search is short.
fn index_remove(lists: &mut [Vec<u32>], key: u32, index: u32) {
    if let Some(list) = lists.get_mut(key as usize)
        && let Some(pos) = list.iter().position(|&i| i == index)
    {
        list.swap_remove(pos);
    }
}

/// Whether `task_id` is a connection task, the only kind `by_task` indexes.
fn is_connection_task(task_id: u32) -> bool {
    task_id & crate::runtime::waker::STANDALONE_BIT == 0
}

impl SendCompletions {
    /// Empty queue. Called once per worker from `Executor::new`.
    pub(crate) fn new() -> Self {
        Self::default()
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
        if self.waiting.len() > 2 * self.waiting_live + 64 {
            self.compact();
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
        let id = self.insert(Entry {
            conn_index,
            task_id,
            state: Completion::Waiting {
                generation,
                required_slots,
            },
        });
        self.waiting.push_back(id);
        self.waiting_live += 1;
        id
    }

    /// Register an awaited send that needs no admission, already `InFlight`,
    /// and return its id.
    ///
    /// Called by the awaiting send APIs (`SendHalf::send`,
    /// `submit_batch_await`, `send_chain`) before they
    /// submit. A submission that fails must [`withdraw`](Self::withdraw) the id
    /// it registered.
    pub(crate) fn register(&mut self, conn_index: u32, task_id: u32) -> SendId {
        self.insert(Entry {
            conn_index,
            task_id,
            state: Completion::InFlight,
        })
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
    /// `id` is not the head, which [`turn`](Self::turn) has just checked it
    /// is, or if there is no new head.
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
    /// still owns the operation; its completion removes the entry). `Done`
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
            Completion::InFlight => e.state = Completion::Abandoned,
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
                candidates.extend_from_slice(list);
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
            .cloned()
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
            .cloned()
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
}
