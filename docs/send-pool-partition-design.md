# Send pool: a per-connection cap, reserved TLS encryption, and dedicated slots

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
of up to 128 KiB or its pipelined small replies. It measured what that
leaves (plaintext, loopback, kernel 6.12, one worker, 8,192 slots of 16,448
bytes, three runs per cell):

- A client that pipelines 4,000 GETs of 64 KiB values and reads at 1 MB/s
  keeps the pool full. Every reply on the worker, including a 1 KiB reply on
  an idle connection, then waited about 1 s (four such clients) to 2 s (one),
  under `Strict` and under `Budget { slots: 32 }` alike.
- With those readers and 120 KiB replies waiting for slots, `Strict` held a
  1 KiB reply for 1-2 s at p99 in every run, where `Budget` admitted it in
  under a millisecond in seven of nine runs.

A second, smaller problem is in the TLS paths. A TLS send checks that enough
slots are free, then encrypts and takes slots one at a time (`encrypt_tls_send`,
`handler.rs`); if the pool runs out partway, records rustls has sealed are
lost and the connection is closed. TLS output produced while receiving
(handshake records, `key_update` responses, alerts) is copied into slots
after rustls has produced it, and the connection is failed if the pool is
short (`ciphertext_to_sends`, `tls/backend_uring.rs`).

## Goal and criterion

A connection holds a bounded share of its worker's send pool, a slow
receiver's backpressure reaches the application on that connection, and no
TLS connection is closed because the pool was short.

Success, measured with the cache server's cells (below):

- in every run of the `slow` and `mixed` cells, under `Strict` and under
  `Budget`, the 1 KiB probe's p99 is at most 10 ms (Experiment D's bound for
  small replies), from at least 1,000 probe samples per run;
- a client that pipelines small replies, and a client that reads large
  replies at full speed, each lose at most 10% of their throughput against
  the unchanged pool, measured against an A/A noise floor of the same cell;
- no `send pool exhausted during TLS output flush` and no close on TLS
  encryption in a TLS cell.

## Design

### 1. A held count per connection

The pool records, for each slot in use and each reservation, the connection
index and generation that took it, and keeps a count per connection that
`release` and the end of a reservation decrement. The send slab keeps the
same count for its entries (`InFlightSendSlab::held_by`,
`buffer/send_slab.rs`). UDP sends (`Driver::udp_send_to`) have no connection
and are not counted.

### 2. A cap, with one waiter per connection in the FIFO

A connection that holds `M` or more slots takes no more. The rule is
`held >= M`, as `zero_copy_hold_cap` uses (`zero_copy_over_cap`,
`buffer/send_slab.rs`), so a send of any size is allowed while its
connection is under the cap; a send larger than `M` slots is not refused for
its size.

Bounded sends (`send_admitted`, `send_backpressured`, `submit_batch_admitted`)
wait. Each connection keeps its own queue of waiting bounded sends, and only
the oldest of them is in the worker's admission FIFO (`SendCompletions`,
`runtime/send_completion.rs`), and only while its connection is under the
cap. The cap is checked when that send reaches the front, not when it was
enqueued. When the connection's held count drops below `M`, its next waiting
send enters the FIFO. So:

- a connection's bounded sends are admitted in the order they were made;
- the FIFO holds at most one waiter per connection, and its head never
  belongs to a connection at the cap, so `Strict` needs no scan past
  ineligible waiters;
- a slow receiver's sends wait on its own connection, which is the
  backpressure the application awaits, and do not hold the head.

Direct sends (`send`, `submit_batch`, `build`, a send chain) cannot wait. A
direct send on a connection at the cap is refused, with the same kinds as a
refusal for an exhausted pool today (`Other` from `send` and `submit`), and a
message that names the cap. This changes `send` and `submit_batch`, which
`docs/send-admission-design.md` lists as unchanged; it is the per-connection
form of the refusal they already make when the pool is empty. The in-tree
clients that make direct sends (ringline-redis, ringline-memcache) check for
the cap first, as they do for `zero_copy_hold_cap`.

Whether the cap applies always or only once the pool is more than half used,
as `zero_copy_hold_cap` does, is decided by the experiment.

### 3. TLS application data: reserve, then encrypt

`encrypt_tls_send` reserves the ciphertext bound before it encrypts, and
encryption takes its slots from that reservation:

1. Reserve `ceil(len / F) + 1` slots (`ciphertext_capacity`, `tls/mod.rs`).
   The extra record covers records rustls has queued (a TLS 1.3
   `key_update`, an alert), which `write_plaintext` drains into the front of
   the same buffer, and the plaintext a slot gives up when it carries them.
   The reservation counts against the connection's held count, so the cap is
   checked before any record is sealed.
2. `encrypt_to_sends` takes each slot from the reservation, through a new
   `alloc_reserved` beside `alloc_raw`, as copy sends take theirs with
   `copy_in_reserved`.
3. The rest of the reservation is released.

Today the reservation is not held across encryption, because an outstanding
reservation hides its slots from `alloc_raw` (the comment above `send_inner`,
`handler.rs`); this is the change that removes that reason. The bound is an
upper bound on the slots encryption takes, which the existing tripwire checks
(`encrypt_tls_send`, `debug_assert`), so encryption cannot run out of slots
partway. The close on encryption failure stays for the failures the pool does
not cause, such as exhausted traffic keys.

The `+ 1` cannot be dropped when `wants_write()` is false: `wants_write()`
checks only `sendable_tls`, and rustls moves a pending key update into
`sendable_tls` inside the write call itself (ringline-tls 0.1.2,
`common_state.rs`; read, not tested).

### 4. TLS output produced while receiving: retained until slots return

On the receive path the unbuffered engine writes rustls's output into a heap
buffer first (`unbuffered::drive` into `scratch`, `tls/backend_uring.rs`),
then copies it into slots (`ciphertext_to_sends`). When the pool is short
the bytes are kept instead of failing the connection:

- the connection keeps the produced bytes in a pending buffer, ahead of
  anything it sends later, as `close_notify_pending` keeps a `close_notify`
  today (`backend/uring/driver.rs`);
- a release of pool slots retries the pending buffer before the
  connection's queued sends are submitted, so records stay in sequence;
- this output is exempt from the cap, so a connection at its cap can still
  answer a `key_update` or finish a handshake;
- a handshake that cannot get slots waits under `tls_handshake_timeout`.

With the buffered engine (`tls-buffered`) the same applies to
`take_tls_output_sends` (`tls/buffered.rs`).

### 5. Dedicated slots (built only if the experiment needs them)

The cap bounds what one connection takes, but `N` slow connections at the cap
still hold `N × M` slots. Once that approaches the pool, small replies wait
again. A dedicated slot per connection removes that case for replies that fit
one slot.

- Dedicated slots form their own pool of `max_connections + k` slots of size
  `D`. A connection takes one when it is accepted or connected, and keeps it
  while it lives. A reply that fits it, sent while it is free and while the
  connection has no earlier send waiting, uses it without entering the FIFO.
  The ordering rules (`Strict`, `Budget`) then govern the shared pool only,
  and their documentation says so.
- The slot belongs to the connection, not to its index. At close, a slot
  with a send in flight is retired and returns to the pool when that send
  completes. A connection that reuses the index takes any free dedicated
  slot. If more than `k` slots are retired at once, a new connection gets
  none and uses the shared pool until one returns; `k` is how many draining
  slots the pool absorbs before that happens.
- `D` = 20,480 bytes holds one worst-case TLS record (16,384 plaintext bytes
  and 29 of overhead) and 4,067 bytes of queued records, so a one-record TLS
  reply is reserved and encrypted into exactly its dedicated slot. A reply
  whose bound does not fit `D` takes shared slots. With the buffered engine,
  whose one-record bound is larger than `D` (`slots_buffered`, `tls/mod.rs`),
  TLS replies use shared slots.
- Shared slots keep indices `0..send_copy_count`; dedicated slots take the
  indices after them. The completion payload carries a 16-bit slot index with
  `u16::MAX` as "no slot" (`completion.rs`, `BuiltSend` in `handler.rs`), so
  `send_copy_count + max_connections + k` must be at most 65,535, which
  `build()` checks. Dedicated slots live in the same `SendCopyPool` object
  with a second backing, so coalesced `sendmsg` runs, which read each slot's
  address and length from that object (`submit_coalesced_run`,
  `backend/uring/driver.rs`), need no change.
- The dedicated pool is `(max_connections + k) × D`: 312.5 MiB per worker at
  ringline's default 16,000 connections with `k` = 0, 80 MiB at 4,096. It is
  off unless configured, and `build()` refuses it with the default
  `max_connections`. A connection parked onto another worker gives up its
  dedicated slot and takes one on the new worker.
- It is not created on mio, where sends use no slot memory.

## mio

On mio the pool is an admission budget: `send_bounded` reserves slots and
holds the reservation, and plain sends copy into a heap buffer and never use
the pool (`handler.rs`, `docs/mio-bounded-send-design.md`). Sections 1 and 2
apply to that budget, so bounded sends on mio wait at the cap as on io_uring.
Direct sends on mio are not refused at the cap, since they take no pool
slots; this difference is documented on `send`. Section 3 is already how mio
works (reserve, encrypt, shrink), and section 4 does not arise there.

## Teardown

- A connection's waiting bounded sends are failed at close, as waiters are
  today, and its queue and its FIFO entry are removed.
- A retained TLS output buffer is dropped at close.
- Held counts are keyed by generation, so slots a closed connection still
  holds do not count against the next occupant of its index, and are
  released by their CQEs as today.

## Counters

Per worker, as `SendAdmissionCounters` fields: waits at the cap, direct sends
refused at the cap, the largest held count seen, TLS output retained and
retried, and, if section 5 is built, dedicated-slot sends and retired
dedicated slots.

## Experiment

Run in stages, so each answers one question before more is built.

1. After sections 1 and 2: the `slow` cells with 1, 4, 16, 64 and 128 slow
   readers and the `mixed` cells, `M` at 16 and 64, under `Strict` and
   `Budget`, against the unchanged pool. Add the `idle` cell (a client that
   pipelines small replies) and a cell with a client reading 1 MiB replies at
   full speed, each with its own A/A runs first. This sets `M` and decides
   whether the cap applies always or above an occupancy.
2. After sections 3 and 4: a TLS cell with slow readers and the pool held
   near full, counting closes and retained output.
3. Only if stage 1 fails the criterion at a reader count a deployment can
   reach: section 5, and the same cells with the shared pool at its original
   and at its halved size, so the dedicated region's memory is not confused
   with its effect.

Each stage's prediction and decision rule are committed before its runs. In
each cell `passing_admissions` shows whether `Budget` had anything to do, and
the cap counters whether the cap bound.

NO-GO for section 5: stage 1 meets the criterion at every reader count up to
`S / M` at the chosen `M` (the pool's slots over the cap). It is reopened by
a measured case above `S / M` that fails.

NO-GO for an always-on cap: no `M` meets the criterion in the `slow` cells
and in both throughput cells. The fallback is a cap that applies only above
an occupancy, as `zero_copy_hold_cap` does.

## Non-goals

- Making `Strict` the default. Stage 1 says whether it meets the criterion;
  the default is a separate decision.
- A cap on UDP sends.
- The send slab. Nothing here takes slab entries.

## Open questions

1. Defaults for `M` and, if section 5 is built, `k` and `D`.
2. Whether the cap applies always or above an occupancy (section 2).
3. How large the output rustls queues ahead of application data can be
   (post-handshake messages such as session tickets), which sets `D`.
4. Configuration names for `M`, `k` and `D`, and the message of the cap
   refusal. They are public and hard to change once released.

## Alternatives

- Do nothing, and require callers to gate every send on settlement or
  `writable()`. This is the current non-goal; the measured cells are what a
  caller that gates only its long replies gets.
- Overflow buffers: send a copy that the cap keeps out of the pool from a
  heap buffer. It removes the refusal of direct sends, but moves unbounded
  memory from the pool to the heap, needs a worker-wide limit of its own, and
  takes send slab entries if the buffers are sent zero-copy. Refusing at the
  cap gives the application the backpressure instead.
- Refuse a send that needs more than `M` slots. It rejects any reply larger
  than `M` slots (263 KB at `M` = 16); the `held >= M` rule does not.
- A reserved count per connection instead of dedicated slots: the same
  guarantee for small replies, with accounting on every allocation.
- Two pools by reply size (O5 in `docs/send-admission-design.md`): bounds the
  slots a large reply takes, but not one connection's share.

## Order of work

1. The held count per connection, with tests and no behaviour change.
2. Reserve-then-encrypt for TLS application data (section 3).
3. Retained TLS output on the receive path (section 4).
4. The cap, with one waiter per connection in the FIFO, and the refusal of
   direct sends at the cap; the in-tree clients updated (section 2).
5. Experiment stages 1 and 2.
6. If stage 1 calls for it, the dedicated pool (section 5) and stage 3.
