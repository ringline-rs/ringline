# Send pool: a per-connection cap, overflow buffers, and dedicated slots

Status: proposal. Nothing here is implemented.

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
of up to 128 KiB or its pipelined small replies, and it measured what that
leaves (plaintext, loopback, kernel 6.12, one worker, 8,192 slots of 16,448
bytes, three runs per cell):

- A client that pipelines 4,000 GETs of 64 KiB values and reads at 1 MB/s
  keeps the pool full. Every reply on the worker, including a 1 KiB reply on
  an idle connection, then waited about 1 s (four such clients) to 2 s (one),
  under `Strict` and under `Budget { slots: 32 }` alike.
- With those readers and 120 KiB replies waiting for slots, `Strict` held a
  1 KiB reply for 1-2 s at p99 in every run, where `Budget` admitted it in
  under a millisecond in seven of nine runs.

A runtime that serves many clients cannot rely on every caller gating every
send, so ringline bounds a connection's share of the pool itself.

## Goal and criterion

A client that stops reading or reads slowly holds a bounded share of its
worker's send memory, and a small reply on another connection is not delayed
by it, under either admission order.

Success, measured with the cache server's cells (below): the 1 KiB probe's
p99 is at most 10 ms in every run of the `slow` and `mixed` cells under
`Strict`, and a client that pipelines small replies on an otherwise idle
server loses at most 10% of its throughput against the unchanged pool.

## Design

### 1. A cap on the shared slots one connection holds

The pool records, for each slot in use, the connection index and generation
that took it, and keeps a held count per connection that `release`
decrements. The send slab keeps the same count for its entries
(`InFlightSendSlab::held_by`, `buffer/send_slab.rs`).

A connection that holds `M` or more slots takes no more pool slots: its next
copy send goes to an overflow buffer (section 2) instead. The rule is
`held >= M`, as `zero_copy_hold_cap` uses (`zero_copy_over_cap`,
`buffer/send_slab.rs`), so a send of any size is allowed while the
connection is under the cap; it is not refused for its size. Whether the
cap applies always or only once the pool is more than half used, as
`zero_copy_hold_cap` does, is decided by the experiment (the `idle` cell
measures what an always-on cap costs a fast client).

In the admission FIFO (`SendCompletions`, `runtime/send_completion.rs`) a
bounded send whose connection is at the cap does not wait for pool slots: it
is admitted against the overflow limit instead (section 2), so it never holds
the head. UDP sends (`Driver::udp_send_to`) have no connection and are not
capped.

### 2. Overflow buffers

A copy send that the cap or an empty pool keeps out of the pool is copied
into a buffer allocated for it, and that buffer is sent: zero-copy under a
guard at or above `send_zc_threshold`, or with a plain send below it. ringline
already sends zero-copy from unregistered heap memory under a guard (the
guard path of `SendBuilder`, `handler.rs`); a plain send from an owned buffer
holds the buffer until its CQE, as a pool slot is held today. A large copy
send costs one copy either way, into pool slots or into the buffer.

Overflow memory is not bounded by the pool, so it has its own limit: `O`
bytes in flight per connection (held until the send's CQE, or its
zero-copy notification). A zero-copy overflow send also takes a send slab
entry and is subject to `zero_copy_hold_cap`.

- A bounded send (`send_admitted`, `send_backpressured`,
  `submit_batch_admitted`) on a connection at `O` waits for that connection's
  own overflow bytes to return. The wait is on the connection, not in the
  FIFO, so it does not hold the head.
- A direct send (`send`, `submit_batch`, `build`, a send chain) on a
  connection at `O` is refused with `Other`, as an exhausted pool refuses it
  today. With the cap and overflow in place, a direct send is refused only
  when its connection has `M` slots and `O` bytes in flight.

A worker's overflow memory is at most `O` times its connections. Whether a
worker-wide overflow limit is needed as well is open (question 2).

### 3. TLS

The bound for a bounded TLS send stays `ceil(len / F) + 1` records
(`ciphertext_capacity`, `tls/mod.rs`). The extra record covers records
rustls has queued (a TLS 1.3 `key_update`, an alert), which `write_plaintext`
drains into the front of the same buffer, and the plaintext a slot gives up
when it carries them (`tls/mod.rs`, `slots_unbuffered`). It cannot be
dropped when `wants_write()` is false: `wants_write()` checks only
`sendable_tls`, and rustls moves a pending key update into `sendable_tls`
inside the write call itself (ringline-tls 0.1.2, `common_state.rs`; read,
not tested).

A TLS send that the cap or an empty pool keeps out of the pool is encrypted
into an overflow buffer sized to the ciphertext bound (`encrypt_chunk` takes
any destination slice, `tls/unbuffered/mod.rs`) and sent from it. Today, if
`alloc_raw` returns no slot partway through, the connection is closed after
rustls has sealed records (`encrypt_to_sends`, `tls/backend_uring.rs`;
`handler.rs`). With overflow buffers there is somewhere to put those records,
and encryption cannot fail for want of memory below `O`.

Handshake output, `key_update` replies and alerts are exempt from the cap and
from `O`: refusing them closes the connection, and they are small.
`close_notify` keeps its retained retry (`close_notify_pending`,
`backend/uring/driver.rs`).

### 4. Dedicated slots (built only if the experiment needs them)

The cap bounds what one connection takes from the shared pool, but `N` slow
connections at the cap still hold `N × M` slots. Once that approaches the
pool, small replies wait again. A dedicated slot per connection removes that
case for replies that fit one slot.

- Dedicated slots form their own pool of `max_connections + k` slots of size
  `D`. A connection takes one when it is accepted or connected, and keeps it
  for its life. A reply that fits it, sent while it is free and while the
  connection has no earlier send waiting, uses it without entering the FIFO.
  The ordering rules (`Strict`, `Budget`) then govern the shared pool only,
  and their documentation says so.
- The slot belongs to the connection, not to its index. At close, a slot
  with a send in flight is retired and returns to the pool when that send
  completes. A connection that reuses the index takes any free dedicated
  slot. If more than `k` slots are retired at once, a new connection gets
  none and uses the shared pool and overflow buffers until one returns. `k`
  bounds how many aborted connections can be draining at once.
- `D` = 20,480 bytes holds one worst-case TLS record (16,384 plaintext bytes
  and 29 of overhead) and 4,067 bytes of queued records, so a one-record TLS
  reply takes exactly its dedicated slot. If queued records leave too little
  room, the reply is encrypted into an overflow buffer instead (section 3).
  With the buffered TLS engine (`tls-buffered`), whose bound for one record
  is larger than `D` (`slots_buffered`, `tls/mod.rs`), TLS replies do not use
  dedicated slots.
- Shared slots keep indices `0..send_copy_count`; dedicated slots take the
  indices after them. The completion payload carries a 16-bit slot index with
  `u16::MAX` as "no slot" (`completion.rs`, `BuiltSend` in `handler.rs`), so
  `send_copy_count + max_connections + k` must be at most 65,535, which
  `build()` checks. Each pool has its own backing; coalesced `sendmsg` runs
  read every slot's address and length from the pool and need no change
  (`submit_coalesced_run`, `backend/uring/driver.rs`).
- The dedicated pool is `(max_connections + k) × D`: 312.5 MiB per worker at
  ringline's default 16,000 connections, 80 MiB at 4,096. It is off unless
  configured, and `build()` refuses it with the default `max_connections`.
- On mio the pool is an admission budget and sends use no slot memory
  (`send_bounded`, `handler.rs`), but its backing is still allocated
  (`backend/mio/driver.rs`). The dedicated pool is not created on mio.

## Admission FIFO changes

- A waiter is only ever waiting for shared slots: a send at the cap goes to
  overflow (section 1), and a send that fits its free dedicated slot does not
  enter the FIFO (section 4). The head therefore never belongs to a
  connection at the cap, and `Strict` needs no scan past ineligible waiters.
- A connection's sends stay in order: a send that could use the dedicated
  slot or overflow waits behind an earlier send of the same connection that
  is in the FIFO.
- `Budget`'s limit `min(slots, P - H)` counts shared slots.

## Counters

Per worker, exported as `SendAdmissionCounters` fields: sends that used a
dedicated slot, sends and bytes sent from overflow buffers, overflow bytes in
flight, waits at `O`, direct sends refused at `O`, and retired dedicated
slots.

## Experiment

The cache server's admission-order cells, rerun after sections 1-3 are built
and before section 4 is:

- `slow` cells with the number of slow readers at 1, 4, 16, 64 and 128, so
  the readers' total `N × M` runs from well under the pool to over it, and
  `mixed` cells (the same readers with clients requesting 120 KiB values),
  with the 1 KiB and 64 KiB probes;
- `M` at 16, 64 and 256, and `O` at 4 MiB and 16 MiB, under `Strict` and
  `Budget`;
- controls: the unchanged pool at 8,192 slots, and the cap with 8,192 and
  with 4,096 slots, the second being the shared pool's size if section 4 is
  built at the same memory;
- an `idle` cell with a client that pipelines small replies;
- three A/A runs of one cell first, for the noise floor.

The prediction and decision rule are committed before the runs, and in each
cell `passing_admissions` shows whether `Budget` had anything to do and the
overflow counters whether the cap bound.

NO-GO for section 4: the cap and overflow meet the criterion at every reader
count up to `S / M` (the pool's slots over the cap). Section 4 is reopened if
a case above `S / M` that a deployment expects fails it.

NO-GO for an always-on cap: no `M` meets the criterion in both the `slow`
cells and the `idle` cell. The fallback is a cap that applies only above an
occupancy, as `zero_copy_hold_cap` does.

## Non-goals

- Making `Strict` the default. The experiment says whether it is viable; the
  default is a separate decision.
- A cap on UDP sends.
- The send slab's own sizing; `zero_copy_hold_cap` bounds it.

## Open questions

1. Defaults for `M`, `O` and, if section 4 is built, `k` and `D`. The
   experiment sets `M` and `O`.
2. Whether a worker-wide limit on overflow memory is needed in addition to
   the per-connection `O`, and what a send does when it is reached.
3. Whether the cap applies always or above an occupancy (section 1).
4. How large the output rustls queues ahead of application data can be
   (post-handshake messages such as session tickets), which sets `D` and
   decides how often a one-record TLS reply overflows. With overflow
   buffers this no longer decides correctness.
5. Configuration names for `M`, `O`, `k` and `D`. They are public and hard to
   change once released.

## Alternatives

- Do nothing, and require callers to gate every send on settlement or
  `writable()`. This is the current non-goal; the measured cells are what a
  caller that gates only its long replies gets.
- Refuse a send that needs more than `M` slots, instead of overflow. Simpler,
  and it rejects any reply larger than `M` slots (263 KB at `M` = 16).
- A reserved count per connection instead of dedicated slots: the same
  guarantee for small replies, with accounting on every allocation.
- Two pools by reply size (O5 in `docs/send-admission-design.md`): bounds the
  slots a large reply takes, but not one connection's share.

## Order of work

1. The per-connection held count for pool slots, with tests and no behaviour
   change.
2. Overflow buffers for copy and TLS sends, with the per-connection limit `O`,
   replacing the close on TLS encryption failure.
3. The cap `M`, sending at-cap copy sends to overflow.
4. The experiment above.
5. If the experiment calls for it, the dedicated pool.
