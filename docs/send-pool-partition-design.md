# Send pool: per-connection tickets, a round-robin worker queue, and a cap

Status: proposal. Nothing here is implemented.

Terms from `docs/send-admission-design.md`: the admission FIFO is the
worker's queue of sends waiting for send-pool slots; `Strict` and
`Budget { slots }` are its admission orders; `F` is the plaintext of one TLS
record (16,384 bytes by default).

## The problem

Each worker has one send copy pool (`SendCopyPool`, `buffer/send_copy.rs`):
`send_copy_count` slots of one size in one allocation, with a LIFO free list.
The pool keeps no account of which connection holds which slot (`release`
takes only a slot index), so one connection can hold any number of slots.
`docs/send-admission-design.md` lists one connection's share as a non-goal
and leaves it to the caller, who can await each reply's `SendCompletion`
before admitting the next, or wait for `writable()` before each send.

The cache server this design is for gates its long replies that way (pieces
of at most 128 KiB, each sent after `writable()`), but not its whole replies
of up to 128 KiB or its pipelined small replies. While a reply waits for
slots it sends every reply through `send_admitted`. It measured what that
leaves (plaintext, loopback, kernel 6.12, one worker, 8,192 slots of 16,448
bytes, three runs per cell, closed-loop probes):

- A client that pipelines 4,000 GETs of 64 KiB values and reads at 1 MB/s
  keeps the pool full. Every reply on the worker, including a 1 KiB reply on
  an idle connection, then waited about 1 s (four such clients) to 2 s (one),
  under `Strict` and under `Budget { slots: 32 }` alike.
- With those readers and 120 KiB replies waiting for slots, `Strict` held a
  1 KiB reply for 1-2 s at p99 in every run, where `Budget` admitted it in
  under a millisecond in seven of nine runs.

Two related gaps are in the TLS paths:

- TLS output produced while receiving (handshake flights, session tickets,
  alerts) is written into a heap buffer by `unbuffered::drive` and then
  copied into slots by `ciphertext_to_sends` (`tls/backend_uring.rs`). If the
  pool is short the connection is failed ("send pool exhausted during TLS
  output flush"; on the connect path "send pool exhausted during TLS flush",
  `backend/uring/event_loop.rs`). With the buffered engine, `PoolWriter` has
  already taken the bytes out of rustls when it runs short, and they are
  released (`tls/buffered.rs`).
- Nothing orders TLS output produced on the receive path against the
  connection's later sends except that both enter the same send queue at the
  time they are made. Any change that holds such output back has to keep it
  ahead of later records.

## Goal and criterion

A connection holds a bounded share of its worker's send pool, a slow
receiver's backpressure reaches the application on that connection, a
connection's sends go out in the order they were made, and no TLS connection
is failed because the pool was short.

Success, measured with the cache server's cells (below):

- in every run of the `slow` and `mixed` cells, under each admission order,
  the 1 KiB probe's p99 is at most 10 ms, measured by an open-loop probe at a
  fixed rate in which a request that times out counts as a sample at the
  timeout;
- the slow readers are still served: their throughput is within 10% of the
  same readers on the unchanged pool, and no connection is closed by the
  runtime;
- a client that pipelines small replies, and a client that reads 1 MiB
  replies at full speed, each lose at most 10% of their throughput against
  the unchanged pool, or no more than the A/A spread of the same cell if
  that is larger;
- in the TLS cell, no connection is failed for want of pool slots.

## Design

### 1. A ticket queue per connection

Every operation on a connection that needs send-pool slots takes a ticket in
that connection's queue, in the order the operations are made: bounded sends
(`send_admitted`, `send_backpressured`, `submit_batch_admitted`), direct
sends (`send`, `submit_batch`, `build`, a send chain), TLS application data,
and TLS output produced on the receive path. Slots are given to a
connection's tickets in ticket order, so a connection's bytes go out in the
order its operations were made, whichever kind they are.

TLS output produced on the receive path takes a ticket when rustls produces
it. If the pool is short, the ticket waits at the front of the queue with
its bytes, and the application's later sends wait behind it. This is the
ordering that session tickets need: they are produced at handshake
completion, and the application's first reply, encrypted under later
sequence numbers, is made right after.

A ticket that can be served at once (its connection has no earlier ticket
waiting, and slots are free) is served in the call that made it, as a send
is today; the queue costs nothing on the uncontended path.

### 2. The worker queue is round-robin over connections

The worker's admission queue holds at most one entry per connection: the
front ticket of each connection that has a ticket waiting for slots. When a
connection's front ticket is served, its next waiting ticket, if any, joins
the back of the worker queue. A connection with many waiting tickets
therefore takes one turn and then waits behind every other connection that
has a ticket waiting.

`Strict` serves the worker queue's head only; `Budget { slots }` also serves
a later entry that fits ahead of a head that does not, within its limit, as
today. Both keep their meaning across connections. Under either order the
arrival order across connections is replaced by turn order: a connection's
second ticket queues behind tickets that arrived after it but belong to other
connections. The documentation of `SendAdmissionOrder`
(`runtime/send_completion.rs`) changes accordingly.

Turns are per ticket, not per slot: a connection whose tickets need eight
slots takes more of the pool per turn than one whose tickets need one. The
cap (section 4) bounds what any connection holds. Turns weighted by slots
(deficit round-robin) are the next step if the experiment shows per-ticket
turns are too coarse under the cap.

### 3. Slots are taken, used, and the excess returned

A ticket being served pops the slots its operation can need off the free
list, owns them while it fills them, and pushes back the ones it did not use.
The connection's held count rises when slots are popped and falls when they
are pushed back or released after their send completes, so each slot is
counted once and no slot is hidden from the free list by a count.

- A copy send pops `ceil(len / slot_size)` slots and uses all of them.
- TLS application data pops its ciphertext bound (`ciphertext_capacity`,
  `tls/mod.rs`): `ceil(len / F) + 1` slots for the unbuffered engine, which
  writes whole records into each slot, and the byte bound in slots for the
  buffered engine. Encryption writes into the popped slots (a new
  `encrypt_to_sends` variant that takes them instead of calling `alloc_raw`)
  and the unused slots are pushed back, usually the one slack record's. The
  operation cannot run out of slots after rustls has sealed a record, by
  construction rather than by the check before it (`encrypt_tls_send`,
  `handler.rs`).
- TLS output produced on the receive path pops the slots its bytes need,
  which are known before it is copied.

The extra record in the TLS bound covers records rustls has queued (a TLS 1.3
`key_update`, an alert), which it writes into the front of the same buffer,
and the plaintext a slot gives up when it carries them (`slots_unbuffered`,
`tls/mod.rs`). It is not dropped when `wants_write()` is false:
`wants_write()` checks only `sendable_tls`, and rustls moves a pending key
update into `sendable_tls` inside the write call (ringline-tls 0.1.2,
`common_state.rs`; read, not tested).

The free list stays a `Vec<u16>` owned by the worker: only the worker's
thread touches its pool, and principle 3 asks that shared written state be
demonstrated before it is paid for.

### 4. A cap on the slots one connection holds

The pool records the connection index and generation that popped each slot
and keeps a held count per connection, as the send slab does for its entries
(`InFlightSendSlab::held_by`, `buffer/send_slab.rs`). A release from an
earlier generation of the index does not decrement the current one, so slots
a closed connection's sends still hold do not count against the next
occupant of its index.

A connection with `held >= M` is at the cap. The rule is the one
`zero_copy_hold_cap` uses (`zero_copy_over_cap`), so an operation of any
size is served while its connection is under the cap; nothing is refused for
its size.

- A bounded send's ticket at the front of a capped connection's queue leaves
  the worker queue and rejoins it at the back when the connection's held
  count drops below `M`. The worker queue's head therefore never belongs to
  a capped connection, and neither order scans past ineligible entries.
- A direct send on a capped connection is refused at once with
  `io::ErrorKind::WouldBlock` and a message naming the cap: the
  backpressure a direct send can carry. `WouldBlock` is already what
  `submit_batch_admitted` returns at the zero-copy cap and for a full slab.
  A new public method, beside `zero_copy_capped`, says whether the
  connection is at the cap, so a caller can choose a bounded send instead.
- TLS output produced on the receive path is exempt: its ticket is served
  in order whatever the held count. It is bounded by what rustls can produce
  without an application write: handshake flights, session tickets and
  alerts. A `key_update` response is queued inside rustls and goes out with
  the next application write (`queued_key_update_message`, ringline-tls
  `common_state.rs`), and rustls refuses more than 32 key update requests
  between application records.
- `close_notify` is exempt as well.

Whether the cap applies always or only once the pool is more than half used,
as `zero_copy_hold_cap` does, is decided by the experiment.

The refusal changes `send` and `submit_batch`, which
`docs/send-admission-design.md` lists as unchanged. The in-tree callers that
make direct sends change with it: ringline-redis and ringline-memcache
(their `flush`, which is synchronous, and their direct `send` calls), and the
copy fallback of `forward_to_conn`, which resolves the refusal as an error
for its caller today.

### 5. Dedicated slots (built only if the experiment needs them)

The cap bounds what one connection takes, but `N` slow connections at the cap
still hold at least `N × M` slots. Once that approaches the pool, small
replies wait again, under any `M`. A dedicated slot per connection removes
that case for replies that fit one slot.

- Dedicated slots form their own pool of `max_connections + k` slots of size
  `D`. A connection takes one when it is accepted or connected and keeps it
  while it lives. A connection's front ticket uses its dedicated slot when
  the slot is free and the operation fits it, without entering the worker
  queue.
- The slot belongs to the connection, not to its index. At close, a slot
  with a send in flight is retired and returns to the pool when that send
  completes. A connection that reuses the index takes any free dedicated
  slot; if none is free, because more than `k` are retired, it uses the
  shared pool until one returns.
- `D` = 20,480 bytes holds one worst-case TLS record (16,384 plaintext bytes
  and 29 of overhead) and 4,067 bytes of queued records. A one-record TLS
  reply is charged against `D` in bytes, one record plus the slack, not the
  two-record bound `ciphertext_capacity` gives for shared slots today.
- Shared slots keep indices `0..send_copy_count`; dedicated slots take the
  indices after them, in the same `SendCopyPool` object with a second
  backing. The completion payload carries a 16-bit slot index with
  `u16::MAX` as "no slot" (`completion.rs`, `BuiltSend` in `handler.rs`), so
  `send_copy_count + max_connections + k` is at most 65,535, which `build()`
  checks. Coalesced `sendmsg` runs read each slot's address and length from
  the pool object (`submit_coalesced_run`, `backend/uring/driver.rs`).
- The dedicated pool is `(max_connections + k) × D`: 312.5 MiB per worker at
  ringline's default 16,000 connections with `k` = 0, 80 MiB at 4,096. It is
  off unless configured, `build()` refuses it with the default
  `max_connections`, and it is not created on mio.

## mio

On mio the pool is an admission budget: `send_bounded` reserves slots, and
plain sends copy into a heap buffer and use no pool slots (`handler.rs`,
`docs/mio-bounded-send-design.md`). The ticket queue, the round-robin worker
queue and the cap apply on mio as on io_uring, with a direct send's queued
heap bytes counted against the cap in slot-sized units, so a slow receiver's
direct sends are refused on mio as they are on io_uring (principle 5). TLS on
mio already reserves, encrypts and shrinks; it takes its slots through the
same ticket rule.

## Teardown and parking

- At close, a connection's waiting tickets are failed, as waiting sends are
  today; its worker queue entry is removed, and TLS output waiting in its
  queue is dropped.
- A connection with tickets waiting is not parked onto another worker until
  they are served or failed; waiting tickets are a park blocker
  (`park_blocker`, `backend/uring/driver.rs`).

## Counters

Per worker, as `SendAdmissionCounters` fields: tickets that waited, turns
taken, waits at the cap, direct sends refused at the cap, the largest held
count, TLS receive-path output that waited for slots, and, if section 5 is
built, dedicated-slot sends and retired dedicated slots.

## Experiment

The cache server's admission-order cells (described in its research note on
admission order) are rerun in stages, so each answers one question before
more is built:

1. After sections 1 to 4: the `slow` cells (readers pipelining 4,000 GETs of
   64 KiB values at 1 MB/s) with 1, 4 and 16 readers, and with enough
   readers that `N × M` reaches the pool; the `mixed` cells (those readers
   with clients requesting 120 KiB values); a `slow` cell whose slow replies
   are direct sends, to exercise the refusal; the `idle` cell (a client that
   pipelines small replies) and a cell with a client reading 1 MiB replies
   at full speed, each with its own A/A runs first. `M` at 16 and 64, an
   always-on cap and one above half occupancy, under `Strict` and `Budget`,
   against the unchanged pool.
2. A TLS cell with slow readers and the pool held near full, counting
   connections failed and receive-path output that waited.
3. Only if stage 1 calls for it: section 5, with the shared pool at its
   original and at its halved size.

Each stage's prediction and decision rule are committed before its runs. In
each cell `passing_admissions` shows whether `Budget` had anything to do, and
the cap counters whether the cap bound.

Section 5 is needed if no `M` meets the criterion in the `slow` and `mixed`
cells and in both throughput cells at a slow-reader count below `S / M` (the
pool's slots over the cap) that a deployment expects. At `S / M` readers or
more the pool is full by construction, so those counts measure section 5,
not the cap.

NO-GO for an always-on cap: no `M` meets the criterion in the `slow` cells
and both throughput cells. The cap then applies only above an occupancy.

## Non-goals

- Making `Strict` the default. Stage 1 says whether it meets the criterion;
  the default is a separate decision.
- A cap on UDP sends, which have no connection.
- The send slab. Nothing here takes slab entries.

## Open questions

1. Defaults for `M` and, if section 5 is built, `k` and `D`.
2. Whether the cap applies always or above an occupancy.
3. How large the output rustls produces without an application write can be
   (handshake flights, session tickets), which bounds what a connection's
   exempt tickets hold and sets `D`.
4. Configuration names for `M`, `k` and `D`, and the name of the method that
   reports the cap. They are public and hard to change once released.
5. Whether per-ticket turns are fair enough, or turns weighted by slots are
   needed.

## Alternatives

- Do nothing, and require callers to gate every send on settlement or
  `writable()`. This is the current non-goal; the measured cells are what a
  caller that gates only its long replies gets.
- A cap on bounded sends only, without the refusal of direct sends. A slow
  receiver's direct sends would then hold slots up to the pool, which the cap
  exists to prevent.
- Overflow buffers: send a copy that the cap keeps out of the pool from a
  heap buffer. It moves unbounded memory from the pool to the heap, needs a
  worker-wide limit of its own, takes send slab entries if sent zero-copy,
  and gives the application no backpressure.
- A count-only reservation instead of taking slots: it hides slots from the
  free list while the operation runs, and counting both the reservation and
  the slots filled from it invites counting a slot twice.
- Refuse a send that needs more than `M` slots. It rejects any reply larger
  than `M` slots (263 KB at `M` = 16); the `held >= M` rule does not.
- A reserved count per connection instead of dedicated slots: the same
  guarantee for small replies, with accounting on every allocation.
- Two pools by reply size (O5 in `docs/send-admission-design.md`): bounds the
  slots a large reply takes, but not one connection's share.

## Order of work

1. The held count per connection, keyed by generation, with tests and no
   behaviour change.
2. Taking slots for an operation and returning the excess, for copy sends,
   TLS application data and receive-path TLS output (section 3).
3. The per-connection ticket queue and the round-robin worker queue
   (sections 1 and 2), with receive-path TLS output waiting in order instead
   of failing the connection.
4. The cap, the refusal of direct sends with `WouldBlock`, the method that
   reports the cap, mio, and the in-tree callers (section 4).
5. Experiment stages 1 and 2.
6. If stage 1 calls for it, the dedicated pool (section 5) and stage 3.
