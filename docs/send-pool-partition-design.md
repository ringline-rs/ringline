# Send pool: per-connection tickets, a round-robin worker queue, and a cap

Status: proposal. Nothing here is implemented.

Terms from `docs/send-admission-design.md`: the admission FIFO is the
worker's queue of sends waiting for send-pool slots; `Strict` and
`Budget { slots }` are its admission orders; `F` is the plaintext of one TLS
record (16,384 bytes by default). A bounded send is one that can wait for
slots (`send_admitted`, `send_backpressured`, `submit_batch_admitted`). A
direct send is one that cannot (`send`, `submit_batch`, `build`, a send
chain): it is sent in the call or refused.

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
  ahead of every record sealed after it.

## Goal and criterion

A connection holds a bounded share of its worker's send pool, a slow
receiver's backpressure reaches the application on that connection, a
connection's sends that take pool slots go out in the order they were made,
and no TLS connection is failed because the pool was short.

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
- a client that writes a batch of requests before reading any reply is
  served to completion;
- in the TLS cell, no connection is failed for want of pool slots.

## Design

### 1. A ticket queue per connection

Each connection has one queue of tickets, and every operation on it that
takes send-pool slots goes through that queue. Slots are given to a
connection's tickets in queue order.

- A bounded send takes a ticket. If it cannot be served when it is made, the
  ticket waits.
- A direct send is served in the call if its connection has no ticket
  waiting, is under the cap (section 4), and slots are free. Otherwise it is
  refused (section 6). It never waits, so it never overtakes a waiting
  ticket and is never overtaken.
- TLS output produced on the receive path takes a ticket when rustls
  produces it. Its bytes are sealed by then, so the ticket goes ahead of
  every waiting ticket whose bytes are not yet sealed, and behind any that
  are. TLS application data from a bounded send is sealed when its ticket
  is served (section 3), so every record goes on the wire in sequence-number
  order. The peer fails a connection whose records arrive out of order
  (`bad_record_mac`).
- `close_notify` takes a ticket after the connection's other tickets.

A ticket waits only when it cannot be served: its connection has an earlier
ticket waiting, the connection is at the cap, the pool cannot hold it, or the
admission order puts another connection's ticket first (section 2). A direct
send is therefore refused for a waiting ticket only while the worker is
contended, which is also when it is most likely to find the pool short. One
case is refused that today's code serves: a one-slot direct send while the
pool has room for it but not for the larger ticket waiting ahead of it. A
counter records each refusal of this kind, and the experiment decides
whether it is rare enough (stage 1's decision rule).

The rule covers sends that take pool slots. A send with no copied parts
(only zero-copy or guard parts) takes no slots and no ticket, and is ordered
against the connection's tickets only as it is today (open question 6).

Cancelling a bounded send whose ticket is waiting removes the ticket. If it
was the connection's front ticket, the connection's next ticket takes its
place in the worker queue (section 2). A ticket is served in one call that
pops, fills and submits, so a ticket is never cancelled partway through.
Receive-path tickets and `close_notify` are not cancelled; they are dropped
at close (Teardown).

The uncontended path adds one check per send: whether the connection has a
ticket waiting or is at the cap. The held count is updated when slots are
popped, pushed back and released.

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
(`runtime/send_completion.rs`) changes accordingly. This is a change to
documented behaviour, so the experiment measures round-robin on its own
(stage 0's round-robin arm) before it replaces arrival order.

Turns are per ticket, not per slot: a connection whose tickets need eight
slots takes more of the pool per turn than one whose tickets need one. The
cap (section 4) bounds what any connection holds. Turns weighted by slots
(deficit round-robin) are the next step if the experiment shows per-ticket
turns are too coarse under the cap.

Slots that a ticket admitted ahead of the head pops are marked passing as
today (`mark_if_passing`, `buffer/send_copy.rs`). Slots it pushes back are
unmarked, so `passing_held` counts only slots in use.

### 3. Slots are taken, used, and the excess returned

A ticket being served pops the slots its operation can need off the free
list, owns them while it fills them, and pushes back the ones it did not use.
The connection's held count rises when slots are popped and falls when they
are pushed back or released after their send completes, so each slot is
counted once and no slot is hidden from the free list by a count. Today a
copy send that waits reserves a count of slots (`reserve_slots`,
`SlotReservation`); this replaces that count on io_uring.

- A copy send pops `ceil(len / slot_size)` slots and uses all of them.
- TLS application data pops its ciphertext bound (`ciphertext_capacity`,
  `tls/mod.rs`): `ceil(len / F) + 1` slots for the unbuffered engine, which
  writes whole records into each slot, and the byte bound in slots for the
  buffered engine. Encryption writes into the popped slots (a new
  `encrypt_to_sends` variant that takes them instead of calling `alloc_raw`)
  and the unused slots are pushed back, usually the one slack record's. The
  operation then cannot run out of slots after rustls has sealed a record
  because its slots are already held. Today the check before encryption
  (`encrypt_tls_send`, `handler.rs`) gives the same result because nothing
  runs between the check and the allocation.
- TLS output produced on the receive path pops the slots its bytes need,
  which are known before it is copied.

The extra record in the TLS bound covers records rustls has queued (a TLS 1.3
`key_update` response, an alert), which it writes into the front of the same
buffer, and the plaintext a slot gives up when it carries them
(`slots_unbuffered`, `tls/mod.rs`). It is not dropped when `wants_write()` is
false: `wants_write()` checks only `sendable_tls`, and rustls moves a pending
key update into `sendable_tls` inside the write call (ringline-tls 0.1.2,
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
  the worker queue. `SendCopyPool::release`, which every completion and
  disposal path goes through, detects the held count dropping below `M` and
  puts the ticket back at the back of the worker queue. The worker queue's
  head therefore never belongs to a capped connection, and neither order
  scans past ineligible entries.
- A direct send on a capped connection is refused (section 6).
- TLS output produced on the receive path and `close_notify` are exempt:
  their tickets are served in order whatever the held count. Receive-path
  output is bounded by what rustls produces without an application write:
  handshake flights, session tickets and alerts. A `key_update` response is
  not receive-path output here: rustls queues it (`queued_key_update_message`,
  ringline-tls `common_state.rs`) and writes it with the next application
  write, under that write's ticket, so it is subject to the cap. rustls
  refuses more than 32 key update requests between application records.

The cap can deadlock against a peer that writes a batch of requests before
it reads any reply. If the batch's replies need more than `M` slots plus
what the socket buffers take, the server's bounded send waits at the cap;
a handler that awaits it stops reading, the peer's writes block, and the
peer never reads the replies that would release the slots. The send slab's
caps apply only above half occupancy for this reason. Whether this cap
applies always or only above an occupancy is decided by the experiment, and
the batch-writer cell is part of that decision.

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

### 6. Refusals

A direct send is refused in three cases: the pool has too few free slots, as
today; its connection is at the cap; or its connection has a ticket waiting.
Each is an `io::Error` of kind `Other`, the kind pool exhaustion returns
today, carrying a `ringline::SendRefused` as its inner error.
`SendRefused::reason()` returns a `#[non_exhaustive]` enum with one variant
per case, so a caller tells them apart with `get_ref()` and `downcast_ref`
instead of matching the message. Kind `WouldBlock` is not used: `send` would
then return `Other` for an empty pool and `WouldBlock` at the cap, and send
chains already use `WouldBlock` with another meaning.

A new public method, beside `zero_copy_capped`, says whether a direct send
on the connection would be refused for the cap or a waiting ticket. A caller
refused for either reason makes a bounded send instead, which waits in the
connection's queue. No new wake-up is needed for that: `writable()` reports
socket space, not pool space, and is unchanged.

## mio

On mio the pool is an admission budget: `send_bounded` reserves a count of
slots, and plain sends copy into a heap buffer and use no pool slots
(`handler.rs`, `docs/mio-bounded-send-design.md`). There is no slot memory to
take, so mio keeps count permits; section 3 applies to io_uring only. The
ticket queue, the round-robin worker queue and the cap apply on mio as on
io_uring. A connection's held count on mio is its permits plus its queued
heap bytes in slot-sized units, so a slow receiver's direct sends are refused
on mio as they are on io_uring (principle 5).

## Teardown and parking

- At close, a connection's waiting tickets are failed, as waiting sends are
  today, and its worker queue entry is removed.
- Receive-path output that is sealed and still waiting at close is dropped.
  `close_notify` is then not sent, because the peer would find the dropped
  records' sequence numbers missing and report a MAC failure; the connection
  ends with a bare FIN, as it does today when `close_notify` itself finds the
  pool short (`place_retained_close_notify`, `backend/uring/driver.rs`).
- A connection with tickets waiting is not parked onto another worker until
  they are served or failed; waiting tickets are a park blocker
  (`park_blocker`, `backend/uring/driver.rs`).

## Counters

Per worker, as `SendAdmissionCounters` fields: tickets that waited, turns
taken, waits at the cap, direct sends refused at the cap, direct sends
refused for a waiting ticket, the largest held count, TLS receive-path
output that waited for slots, connections closed with a bare FIN because
sealed output was waiting, and, if section 5 is built, dedicated-slot sends
and retired dedicated slots.

## Experiment

The cache server's admission-order cells (described in its research note on
admission order) are rerun in stages, so each answers one question before
more is built. The cells:

- `slow`: readers pipelining 4,000 GETs of 64 KiB values at 1 MB/s, with 1,
  4 and 16 readers, and with enough readers that `N × M` reaches the pool;
- `mixed`: those readers with clients requesting 120 KiB values;
- `direct`: a `slow` cell whose slow replies are direct sends;
- `batch`: a client that writes 64 requests for 64 KiB values (256 slots)
  before it reads any reply;
- `idle`: a client that pipelines small replies;
- `bulk`: a client reading 1 MiB replies at full speed.

`idle` and `bulk` get their own A/A runs first.

0. A prototype in ringline-bench's `admission-server`, which has an
   open-loop small-request probe and slow readers (`admission-load`): the
   cap on today's FIFO, with the scan skipping capped connections; and
   round-robin on its own, with no cap. Arms: unchanged, cap only (`M` = 16
   and 64), round-robin only, both. Cells `slow`, `mixed`, `batch`, `idle`,
   `bulk`. The prototype also counts direct sends made while their
   connection has a send in the FIFO, which section 1 would refuse.
   This stage decides whether the cap meets the criterion before tickets,
   the TLS ordering or mio are built, and whether round-robin earns its
   change to documented behaviour.
1. After sections 1 to 4 and 6: every cell, `M` at the values stage 0
   chose, an always-on cap and one above half occupancy, under `Strict` and
   `Budget`, against the unchanged pool.
2. A TLS cell with slow readers and the pool held near full, counting
   connections failed, receive-path output that waited, and bare-FIN closes.
3. Only if stage 1 calls for it: section 5, with the shared pool at its
   original and at its halved size.

Each stage's prediction and decision rule are committed before its runs. In
each cell `passing_admissions` shows whether `Budget` had anything to do, and
the cap counters whether the cap bound. A cell in which a mechanism's
counter reads zero did not test that mechanism.

Stage 1's decision rule includes the refusals for a waiting ticket: if they
exceed 1% of direct sends in any `mixed` or `direct` run, the refusal rule is
reopened. The alternative then is a per-connection send buffer
(Alternatives).

Section 5 is needed if no `M` meets the criterion in the `slow` and `mixed`
cells and in both throughput cells at a slow-reader count below `S / M` (the
pool's slots over the cap) that a deployment expects. At `S / M` readers or
more the pool is full by construction, so those counts measure section 5,
not the cap.

NO-GO for an always-on cap: no `M` meets the criterion in the `slow` cells
and both throughput cells, or the `batch` client is not served to completion
under it. The cap then applies only above an occupancy.

NO-GO for round-robin: stage 0's round-robin arm, with and without the cap,
does not improve the 1 KiB probe's p99 over the cap alone in the `slow` or
`mixed` cells. The worker queue then keeps arrival order, with one entry per
connection.

## Prior art

Each mechanism here has a precedent. The sources were read on 2026-11-18;
where only part of a claim could be checked, the entry says so.

- Per-socket send buffers in Linux TCP. A socket's queued bytes are limited
  by `sk_sndbuf` (`SO_SNDBUF`, `net.ipv4.tcp_wmem`), and `tcp_mem` limits
  all TCP sockets together. A socket at its limit is not reported writable
  again until its free space is at least half its queued bytes
  (`__sk_stream_is_writeable`, `sk_stream_min_wspace`,
  `include/net/sock.h`), so it becomes writable at about two thirds of
  `sk_sndbuf`, not at the first free byte. The cap here is the per-socket
  limit applied to the send pool, and open question 3 asks whether to copy
  the gap between the limit and the point at which a connection resumes.
- Netty's `WriteBufferWaterMark`. A channel becomes unwritable when its
  outbound buffer's pending bytes exceed the high mark (64 KiB by default)
  and writable again when they fall below the low mark (32 KiB), and the
  application is told through `channelWritabilityChanged`
  (`ChannelOutboundBuffer`). Writes are not refused while the channel is
  unwritable; the buffer keeps growing. This design refuses direct sends at
  the cap so that the bound holds when the application does not check.
- Envoy's per-connection buffer limits. `per_connection_buffer_limit_bytes`
  (1 MiB by default) sets a high mark, and the low mark is half of it
  (`watermark_buffer.cc`). When a connection's write buffer passes the high
  mark, the TCP proxy stops reading from the paired connection
  (`readDisableUpstream`, `tcp_proxy.cc`) and starts again below the low
  mark. That is backpressure on the connection that caused it (principle
  12), applied by stopping reads; here a bounded send waits instead.
- Redis's `client-output-buffer-limit`. A client whose output buffer passes
  the hard limit, or stays above the soft limit for the soft period, is
  disconnected (`checkClientOutputBufferLimits`). The defaults are 256 MB
  and 64 MB for 60 s for replicas, 32 MB and 8 MB for 60 s for pub/sub
  clients, and no limit for normal clients. It bounds one client's output
  memory by closing the client; this design waits or refuses and leaves the
  close to the application.
- Round-robin over per-source queues, from Nagle (RFC 970, one queue per
  source host and one packet per non-empty queue per cycle), and deficit
  round-robin (Shreedhar and Varghese, SIGCOMM 1995), which gives each flow
  a quantum per round so flows with large packets do not get more than
  their share. DRR is O(1) per packet when the quantum is at least the
  largest packet. Section 2's per-ticket turns are Nagle's scheme; turns
  weighted by slots would be DRR. Linux's `fq` qdisc combines both with a
  per-flow limit: per-flow queues served round-robin with a quantum of two
  MTUs, and a packet dropped once its flow holds 100 (`flow_limit`,
  `net/sched/sch_fq.c`). The per-flow limit there is the cap here, with a
  refusal or a wait in place of a drop.
- EASY backfilling (Lifka, "The ANL/IBM SP Scheduling System", 1995;
  Mu'alem and Feitelson, IEEE TPDS 2001). A later job may start ahead of
  the queue's head if that does not delay the head. `Budget { slots }` is a
  version of this with a slot budget in place of a time reservation. The
  definition was checked against summaries of the papers, not their text.
- HTTP/2 flow control (RFC 9113, sections 5.2 and 6.9). A sender is limited
  by a window per stream and one per connection, and the h2 crate's
  `SendStream::reserve_capacity` and `poll_capacity` let it ask for capacity
  and wait until some is assigned. Per-stream windows are the per-stream
  version of the cap, and `poll_capacity` is the shape of a bounded send.

## Non-goals

- Making `Strict` the default. Stage 1 says whether it meets the criterion;
  the default is a separate decision.
- A cap on UDP sends, which have no connection.
- The send slab. Nothing here takes slab entries.

## Open questions

1. Defaults for `M` and, if section 5 is built, `k` and `D`.
2. Whether the cap applies always or above an occupancy.
3. Whether a capped connection rejoins at `held < M` or only below a lower
   mark `L`, as Netty's and Envoy's watermarks do (Prior art). A lower mark
   gives a capped connection fewer, larger turns.
4. How large the output rustls produces without an application write can be
   (handshake flights, session tickets), which bounds what a connection's
   exempt tickets hold and sets `D`.
5. Configuration names for `M`, `k`, `D` and `L`, the name of the method that
   reports a refusal in advance, and the names of `SendRefused` and its
   reasons. They are public and hard to change once released.
6. Whether sends with no copied parts join the ticket order. Refusing them
   while a ticket waits would order them, but `forward_to_conn` would then
   see a refusal that copying does not resolve.
7. Whether per-ticket turns are fair enough, or turns weighted by slots are
   needed.

## Alternatives

- Do nothing, and require callers to gate every send on settlement or
  `writable()`. This is the current non-goal; the measured cells are what a
  caller that gates only its long replies gets.
- A cap on bounded sends only, without the refusal of direct sends. A slow
  receiver's direct sends would then hold slots up to the pool, which the cap
  exists to prevent.
- Direct sends that overtake waiting tickets, with a rule that keeps sealed
  TLS output ahead of unsealed operations. It refuses fewer direct sends, but
  a connection's bytes then follow two orders, and a caller that mixes
  direct and bounded sends can see its replies reordered.
- A direct send behind a waiting ticket copies into free slots and waits
  behind the ticket. Its slots are held but not in flight; if every held
  slot is held that way, nothing completes. The rule that prevents it allows
  this only when the waiting ticket could be served, which is the case
  section 1 already serves.
- A per-connection send buffer, as `SO_SNDBUF` is for a socket: a direct
  send copies into the connection's queue and is refused only past a byte
  limit. Every send is ordered and nothing is refused for a waiting ticket,
  but the queued bytes are outside the pool, up to `max_connections` times
  the limit. This is the fallback if stage 1 finds refusals for a waiting
  ticket common.
- Remove direct sends, so that every send is bounded. One order and no
  refusal for a waiting ticket, at the cost of the API: `send(&[u8])` in
  `handler.rs` and `runtime/io.rs`, its callers in ringline-redis,
  ringline-memcache and ringline-bench, and synchronous handler callbacks,
  which cannot await.
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

1. The prototype and experiment stage 0, in ringline-bench.
2. The held count per connection, keyed by generation, with tests and no
   behaviour change.
3. Taking slots for an operation and returning the excess, for copy sends,
   TLS application data and receive-path TLS output (section 3).
4. The per-connection ticket queue and the worker queue (sections 1 and 2,
   round-robin only if stage 0 keeps it), with receive-path TLS output
   waiting in order instead of failing the connection.
5. The cap, the refusals and `SendRefused`, the method that reports a
   refusal in advance, mio, and the in-tree callers (sections 4 and 6).
6. Experiment stages 1 and 2.
7. If stage 1 calls for it, the dedicated pool (section 5) and stage 3.
