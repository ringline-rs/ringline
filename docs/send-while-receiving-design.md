# Sending while a reply is pending on the redis and memcache clients

Status: proposal. Nothing implemented.

Related: `docs/connection-handle-ownership-design.md` (the runtime's
`SendHalf`/`RecvHalf`, and the decision against a shared send handle).

Line numbers are pinned to `cca4a94`. R is `ringline-redis/src/lib.rs`, M is
`ringline-memcache/src/lib.rs`, io is `ringline/src/runtime/io.rs`.

## Goal

A caller of the fire/recv API cannot send while it waits for a reply. `fire_*`
and `recv` both take `&mut self` on one `Client`, so while a `recv` future is
pending nothing can be fired on that connection. A pipelined connection waiting
for its oldest reply cannot send a request that became ready in the meantime,
even when its pipeline has room.

The wait shows up as latency in any load generator that measures from when a
request was ready rather than when it was sent. cachecannon's routed mode does
this (cachecannon#242). Against a server answering every request after 2 ms,
with one connection, pipeline depth 32 and 2000 requests a second, routed
requests waited 1.20 ms at p50 before being sent (measured on mio).

This document proposes two ways to let one task send while a reply is pending,
and recommends starting with the smaller one.

## What exists

The runtime supports sending while receiving. `Connection::split()` returns a
`SendHalf` and a `RecvHalf`, and `SendHalf` does not borrow `RecvHalf`:
"sending while a reader is live is ordinary" (io:4182-4184). The futures
`RecvHalf::with_bytes` and `with_segments` return do not borrow the half
(io:3533-3540).

Both clients already hold the halves (`tx`, `rx`; R:685-723, M:572-607). What
keeps them behind one `&mut self` is state that both paths touch:

| field | send path | receive path |
|---|---|---|
| `pending` | `push_back` in every `fire_*`; length checked against `max_in_flight` (R:925); `truncate` on a flush error (R:1002) | `pop_front` (R:1275, 1409, 1755); `clear()` on error (R:1288, 1585, 1733, 1810) |
| `flushed_count` | set by direct sends and `flush` (R:1014) | decremented on pop (R:1276, 1415, 1756); zeroed on error |
| `write_buf`, `write_guards`, `buffered_ops` | `fire_*`, `flush` | through `flush()`, which every `recv` calls first (R:1273, 1408, 1754; M:1005) |
| `tx` | sends | `tx.close()` on a protocol error or desync (R:796-798, 1584, 1732; M:1188-1190); `read_value_from` takes `&mut tx` for the whole read (R:733-736, called at R:1872) |
| `on_result`, `metrics` | `is_instrumented` decides whether a fire stamps a start time (R:867-876) | `record()` (R:880-888) |

"Poison" below means what the clients do on a protocol error or desync: close
`tx` and clear `pending`.

`recv` flushes before it pops, so the op it waits on is on the wire. Any change
must keep that rule: a receiver that popped an op still in `write_buf` would
wait for a reply to a request never sent.

## Why not make `recv` cancel-safe

A cancel-safe `recv` would let a caller select between `recv` and "a request is
ready", drop the `recv` when a request wins, fire, and start a new `recv`. Every
receive entry point pops its op before its first `.await` (R:1275, 1409, 1755;
M:1007), so dropping one loses the op and every later reply is matched to the
wrong request.

For the single-read paths (redis `recv` and `recv_meta_simple`, memcache
`recv`) the pop could move after the await: `WithBytesFuture` consumes bytes
only when it completes and has no `Drop` (io:3480-3512), so a dropped read
leaves the accumulator untouched. The GET paths cannot be made cancel-safe this
way. `run_get_state_machine` (R:1417, 1471-1531) and `run_get_drain_mio`
(R:1627-1702) consume bytes on each loop iteration and keep the parse state in
the future, so a drop partway through a large value leaves the stream mid-reply
and, on io_uring, the connection in the segmented domain without
`end_segments`. cachecannon receives every RESP GET through `recv_meta` unless
`workload.read_values` is set.

## Option A: wait for reply bytes, then receive

`RecvHalf::recv_ready()` (io:3681) returns a `RecvReadyFuture` that holds only
the connection index and generation (io:6002-6006). It resolves when the recv
sink or the accumulator holds bytes, when the zero-copy forward hold is
non-empty, or when the connection has finished receiving (io:6008-6044), and it
consumes nothing.

A client method that flushes and then forwards it:

```rust
impl Client {
    /// Send any buffered requests, then return a future that resolves when
    /// bytes for the next reply have arrived or the connection has closed.
    /// The future consumes nothing and is safe to drop. A `recv` started after
    /// it resolves waits only for the rest of a reply that has started
    /// arriving.
    pub fn recv_ready(&mut self) -> Result<RecvReadyFuture, Error>;
}
```

The flush is required. `recv` flushes before it pops (R:1273) because a reply
cannot arrive for a request still in `write_buf`. A caller that fires below
`max_batch_size` and then waits on `recv_ready` without a flush would wait for
a reply to a request never sent, until its request timeout or forever. `flush`
is synchronous, so `recv_ready` does it before building the future.

A caller waits on `recv_ready` and on its own "request ready" signal, fires on
`&mut Client` when a request is ready (and calls `recv_ready` again, which
flushes it), and calls `recv` when `recv_ready` resolves. The task is inside
`recv` only while a reply that has started arriving is still coming in.

A caller that keeps a pending `recv_ready` across fires, instead of calling it
again, must call `flush` itself, or its buffered requests wait for the next
`recv_ready` or `recv`; with nothing else in flight, until the request
timeout.

After the flush, `recv_ready` returns `Err(Error::NoPending)` when nothing is
in flight, the same contract as `recv`, so it never waits for bytes no request
asked for.

### Required runtime change

`RecvReadyFuture::poll` does not see every place the io_uring backend holds
received bytes. When a reply arrives on a connection with an empty accumulator
and no buffer already lent, the receive completion does not copy it into the
accumulator: it lends the kernel buffer in `pending_recv_bufs`
(`ringline/src/backend/uring/event_loop.rs:1926-1943`) and wakes the task. The
poll checks the accumulator, finds it empty, and parks again, until a second
completion moves the lent buffer into the accumulator or the connection
closes. That is the normal state between replies, so as written `recv_ready`
would not resolve for most replies on io_uring with plain TCP. The segmented
domain's `segment_hold` (`event_loop.rs:1819-1837`) is missed the same way.

The poll uses `driver.recv_buffered(conn_index) > 0`, which both drivers
define (io_uring: accumulator, `pending_recv_bufs`, `segment_hold`,
`recv_hold`, `ringline/src/backend/uring/driver.rs:2452-2465`; mio: the
accumulator, `ringline/src/backend/mio/driver.rs:314-316`), in place of the
accumulator and `recv_hold` checks. The generation, sink and closed checks
stay. Bytes in `segment_hold` now resolve `recv_ready`, including bytes held
during a `forward_to_conn` (`event_loop.rs:1844`); no current caller waits on
`recv_ready` during a forward. None of the existing `recv_ready` callers
exercise copy mode with an empty accumulator; they use a recv sink or recv
forwarding (`ringline/tests/recv_arrival.rs:177`, `recv_lend_cap.rs:24`,
`echo.rs:125`, `forward_held_cap.rs`).

### Waking

`RecvReadyFuture::poll` ignores its `Context` (io:6011). It registers the
current task in `owner_task` and `recv_waiters` (io:6046-6047), and an arrival
wakes that task by id. A task that waits on `recv_ready` together with a timer
and a queue in one `poll_fn`, or a `select!` that polls every branch on each
wake, works: each wake re-polls `recv_ready`, which registers again. A
combinator that re-polls only the child whose own waker fired, such as
`FuturesUnordered`, never re-polls it and hangs. Every ringline recv future
behaves this way (io:3283, 3461, 3510); this is the first design that asks
callers to combine one with other futures, so the client method documents it.

A `RecvReadyFuture` dropped while pending leaves its registration in place, and
the wake is one-shot. The next arrival wakes the task once with nothing to
read; no wakeup is lost.

### TLS

Decrypted bytes go into the accumulator, or into `segment_hold` in the
segmented domain (`event_loop.rs:1690-1710`; mio `tls/backend_mio.rs:39`).
Ciphertext that does not yet complete a record wakes the task with nothing
added, and the poll parks again. `recv_ready` does not resolve on ciphertext
alone, so a `recv` started after it does not block waiting for a record to
complete.

### Limits

- While a reply is arriving, the task is inside `recv` and cannot send. If the
  whole reply arrived in one completion, `recv` returns without suspending;
  otherwise it waits at most until the next receive completion for a small
  reply, and for the transfer time of the value for a large one.
- Bytes of the next reply already buffered when a `recv` returns make
  `recv_ready` resolve at once, and the next `recv` waits for the rest of that
  reply. The next `recv` consumes those bytes, so `recv_ready` does not keep
  resolving with nothing new.

Size: one method in each client crate, the `recv_buffered` check in
`RecvReadyFuture::poll`, tests. No change to `Client`'s structure or to the
channels-only decision.

## Option B: split the client into a sender and a receiver

```rust
impl Client {
    pub fn into_split(self) -> (Sender, Receiver);
}
```

Both halves are `!Send`, like the runtime halves, and neither is `Clone`: one
sender and one receiver per connection, so the order requests are fired in is
the order their replies are received in. This option removes the limit Option A
keeps: the sender can fire while the receiver is partway through a large reply.

### State

- Shared by both halves (`Shared`): `tx`, `write_buf`, `write_guards`,
  `buffered_ops`, `pending`, `flushed_count`, `max_in_flight`,
  `max_batch_size`, `zc_threshold`, `encode_buf`, `command_names`, the binary
  flag, and an `instrumented: bool` fixed when the client is built.
- `Receiver` only: `rx`, `on_result`, `metrics`. `record()` runs the user's
  callback; running it inside a borrow of `Shared` would panic if the callback
  reaches the sender, and `metrics()` returns `&ClientMetrics`, which a
  `RefCell` cannot hand out.
- `Shared` also gains `in_read: bool`, set when the receiver pops an op and
  cleared when its read completes. `pending_count()` and the `max_in_flight`
  check (R:925) count it. Without it the op being read is in neither place, and
  a caller filling its pipeline to `pending_count() < depth` puts depth + 1
  requests on the wire.

`Client` holds `Shared` by value, and the fire and receive logic becomes
functions over `&mut Shared` and `&mut RecvHalf`: a synchronous step before the
read, the read on `rx`, a synchronous step after it. `Client` calls them with
`&mut self.shared`; the halves call them inside short `borrow_mut()` sections
on an `Rc<RefCell<Shared>>`. The unsplit path takes no `RefCell`.

No `RefCell` borrow may span an await. Two functions need a new signature for
that: `read_value_from` (R:733-736) and memcache `read_reply` (M:1146-1190)
take or use `tx` across the read to close it on a protocol error. They return a
"close the connection" outcome instead, and the caller closes `tx` in the
synchronous step after the read. `Pipeline::execute` calls `read_value_from`
too (R:3883, 3899) and changes with it.

### The flush rule

`Receiver::recv` flushes `write_buf` before popping, as `recv` does today. A
request fired while a `recv` is already pending is sent when the next
`Receiver::recv` call starts, when the batch reaches `max_batch_size`, or when
the caller calls `Sender::flush`; the pending `recv` does not send it. Callers
that fire while a `recv` is pending flush after their fire loop. Each `fire_*`
documents this.

### No pending op

The receiver keeps `Error::NoPending` (CLAUDE.md, "Design Notes"). A caller
that wants to wait for the sender tracks `Sender::pending_count()` and starts a
`recv` only when it is non-zero.

### Errors

A receive error poisons the connection in the synchronous step after the read:
close `tx`, clear `pending`, zero `flushed_count`, and also clear `write_buf`,
`write_guards` and `buffered_ops`, which can now hold requests the sender
buffered during the read. After that, `pending_count()` is 0, `is_alive()` is
false, and the next send attempt fails. A batched `fire_*` that only appends to
`write_buf` (R:1035-1038) does not attempt a send, so the split halves' batched
branch checks `tx.is_alive()` first and returns the connection-closed error.
The check is a driver lookup (io:2851-2858); it is not added to the unsplit
`Client`'s fire path.

A flush error on the sender truncates `pending` to `flushed_count`
(R:993-1003), as today. A receiver suspended on an op already flushed is
unaffected.

`Receiver::recv` is not cancel-safe, for the reasons above. A caller that drops
a pending `recv` (on a request timeout, for example) must close the connection.

### Drop

Neither half closes the connection on drop, as dropping a `Client` does not
today (`ringline-redis/src/pool.rs:181-195`; the runtime halves only release
their claims, io:4340-4387). The read claim is released with the `Receiver`,
the write claim when both halves are gone. A `Receiver` dropped while the
`Sender` keeps firing leaves `pending` growing until `max_in_flight`.

### Relation to the channels-only decision

`connection-handle-ownership-design.md` decided against a shared send handle
("channels only, no blessed `Rc<SendHalf>`") because two writers on one
connection cannot know which reply is theirs. `Sender` and `Receiver` are one
writer and one reader, and `pending` records which reply belongs to which
request. The prescribed alternative, a channel feeding the task that owns the
`Client`, does not help here: that task is inside `recv` and cannot drain the
channel until the reply arrives. The `Rc` is private. The ownership design's
description of redis pipelining as "already single-owner + queue"
(`connection-handle-ownership-design.md:203-205`, `:219`) needs a note if this
option lands.

### What stays on `Client`

`into_split` is additive. The request/response API (`get`, `set`, `execute*`
from R:1883; `cmd` at R:2916), the streaming API (`set_stream`, `get_stream`,
`ValueStream`, R:3138-3566), and `Pipeline` stay on `Client` and are not on the
halves: they send and read in one call on an idle connection, and the
request/response calls do not check `pending` (mixing them with in-flight
`fire_*` desyncs today). `ShardedClient`, `ClusterClient` and the pools are
untouched: they send and read one request at a time and never call `fire_*` or
`recv` (redis `sharded.rs:212-213`, `cluster.rs:361-362`; memcache
`sharded.rs:212-225`, which reads with `read_response`).

The receiver methods follow each crate: redis `recv`, `recv_meta`,
`recv_get_discard` and `recv_get_segments` (the last two io_uring only);
memcache `recv`. `BinaryClient` (M:2401-2403) splits into the same types, with
the binary flag in `Shared`.

Size: every request/response method, `Pipeline` and `ValueStream` use
`self.tx` and `self.rx` around awaits (R:1883-3566), so moving `Client` onto
`Shared` touches most of each crate's `lib.rs`, plus `read_value_from`'s
callers.

## Recommendation

Option A first. It is small, it leaves `Client` and the ownership decision
alone, and it removes the wait cachecannon measured, which is a connection
waiting for a reply that has not started arriving. Option B is worth its size
only if the remaining wait, a send held while a large reply is read, matters
for a real workload. Option A's measurements below show whether it does.

## Measurements

- Option A, in cachecannon routed mode against a server with fixed latency, at
  pipeline 32, with the batch size stated and a flush after each fire loop:
  `routed_queue_wait` with one `Client` today and with `recv_ready`, at small
  and large values, on io_uring and mio.
- Option B only: fire/recv throughput and client CPU per request at batch 1 and
  16, on io_uring and mio, before and after the restructure, not split. The
  unsplit path should not change. `ringline-benchmarks` does not call `fire_*`
  (its redis and memcache cases use `get`), so this needs a fire/recv case
  added there, or a cachecannon run pinned to each ringline revision.

## Tests

Option A:

- `recv_ready` resolves when a reply's first bytes arrive and not before, on
  both backends; a `recv` started then returns the reply. On io_uring, in copy
  mode with an empty accumulator and the default lend cap.
- Fire one request at batch 16, await `recv_ready` without a separate flush,
  and the reply arrives.
- TLS: `recv_ready` resolves on a decrypted record, not on a partial one.
- Fire on `&mut Client` while a `recv_ready` future is pending, at batch 1,
  and at batch 16 followed by `flush`; the request reaches the server; replies
  arrive in fire order.
- `recv_ready` with nothing in flight returns `NoPending`.
- A dropped pending `recv_ready` loses no bytes and causes no missed wakeup.
- `recv_ready` wakes for bytes in `segment_hold` and in `pending_recv_bufs`
  (io_uring).
- `recv_ready` resolves when the peer closes.

Option B:

- Fire on the sender while a `recv` is pending, both backends: the request
  reaches the server before the pending reply arrives, after `Sender::flush`.
- With depth N and a `recv` pending, `pending_count()` counts the op being
  read, and fire N + 1 returns `TooManyInFlight`.
- A receiver never waits on an unflushed op.
- A desync on the receiver at batch 1 and batch 16: `pending_count()` is 0,
  `write_buf` is empty, `is_alive()` is false, the next `fire_*` fails.
- A flush error on the sender while the receiver is suspended leaves the
  receiver's op intact.
- A RESP GET through `recv_meta` on io_uring with a value spanning several
  buffers, while the sender fires and flushes between segments.
- An `on_result` callback that holds the sender and fires does not panic.
- `NoPending` from a receiver with nothing in flight. Memcache ASCII and binary.

## Steps

1. Option A: `Client::recv_ready` in both crates, the `recv_buffered` check in
   `RecvReadyFuture::poll`, tests. Measure through cachecannon.
2. Independent fix: `recv_get_segments` pops a non-GET op and returns
   `UnexpectedResponse` without reading its reply or poisoning the connection
   (R:1409-1414), so every later reply is matched to the wrong request. Check
   `pending.front()`'s kind before popping and return the error with the op
   still queued.
3. Option B, if step 1's measurements call for it: the `Shared` restructure
   with no API change, measured; then `into_split`, `Sender`, `Receiver`.
4. CHANGELOG and the fire/recv section of `CLAUDE.md` for whichever lands.

## How cachecannon would use it

Option A: each connection task waits on `recv_ready` (when anything is in
flight), its node queue (when the pipeline has room), and the request-timeout
timer it already keeps. A queued request is fired and flushed at once; when
`recv_ready` resolves, the task calls `recv_meta` or `recv`. Pinned mode gains
the same: a connection holding rate-limit tokens no longer waits for its oldest
reply before sending them.

Option B: the same loop, with a pinned `recv` future kept across iterations in
place of `recv_ready`. cachecannon's `recv_with_timeout` assumes the in-flight
list does not change while a `recv` is pending (worker.rs:4312); with sends
during a pending `recv`, that assumption no longer holds and the timer logic
must change.
