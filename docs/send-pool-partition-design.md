# Send pool: bounded sends, per-connection tickets, and a cap

Status: proposal. Experiment stage 0 has run
(`docs/journal/2026-11-send-pool-stage0.md`); nothing in the runtime is
implemented.

Terms: the worker queue is the worker's queue of sends waiting for
send-pool slots, which `docs/send-admission-design.md` calls the FIFO
(`SendCompletions::waiting`); `Strict` and `Budget { slots }` are its
admission orders. `F` is the plaintext of one TLS record (16,384 bytes), as
in `docs/tls-premutation-bound-design.md`; `docs/send-admission-design.md`
uses `F` for free slots. A bounded send waits for send-pool slots
when the pool cannot serve it. A non-waiting send is either served in the
call or refused.

## The problem

Each worker has one send copy pool (`SendCopyPool`, `buffer/send_copy.rs`):
`send_copy_count` slots of one size in one allocation, with a LIFO free list.
The pool keeps no account of which connection holds which slot (`release`
takes only a slot index), so one connection can hold any number of slots.
`docs/send-admission-design.md` lists one connection's share as a non-goal
and leaves it to the caller, who can await each reply's `SendCompletion`
before admitting the next. A caller can also wait for `writable()` before
each send.

The cache server this design is for gates its long replies that way (pieces of
at most 128 KiB, each sent after `writable()`), but not its whole replies of up
to 128 KiB or its pipelined small replies. While one of its replies waits for
slots, the server sends its later replies through `send_admitted`. Measurements
on that server show what that leaves (plaintext, loopback, kernel 6.12, one
worker, 8,192 slots of 16,448 bytes, three runs per cell, closed-loop probes).
The runs are recorded in that server's repository, not in this one:

- A client that pipelines 4,000 GETs of 64 KiB values and reads at 1 MB/s
  keeps the pool full. Every reply on the worker, including a 1 KiB reply on
  an idle connection, then waited about 1 s (four such clients) to 2 s (one),
  under `Strict` and under `Budget { slots: 32 }` alike.
- With those readers and 120 KiB replies waiting for slots, `Strict` held a
  1 KiB reply for 1-2 s at p99 in every run, where `Budget` admitted it in
  under a millisecond in seven of nine runs.

The default send does not wait. `SendHalf::send` (`runtime/io.rs`) copies
into the pool in the call and fails with `Other` when the pool is short, and
`submit_batch`, `send_parts(..).build(..)` and `send_chain` do the same.
Waiting is opt-in (`send_admitted`, `send_backpressured`,
`submit_batch_admitted`). A limit on one connection's share would therefore
reach most callers as a refusal, which they handle as an error:

- ringline-redis and ringline-memcache write a streamed SET as a header, the
  value's chunks and a `\r\n` trailer, each a separate `send`
  (`write_set_frame_and_read`). A refusal after the header leaves a partial
  frame on the wire.
- ringline-http's HTTP/2 connection takes frames out of the h2 state
  (`take_pending_send`, `h2_conn.rs`) before `send`, so a refusal loses
  frames that the HPACK state has already counted.

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
  connection's later sends except that both are queued on the connection in the
  order they are made. Any change that holds such output back has to keep it
  ahead of every record sealed after it.

## Goal and criterion

- A connection holds a bounded share of its worker's send pool.
- A slow receiver makes the task that sends on that connection wait.
- A connection's sends that take pool slots go out in the order their
  futures were first polled.
- No TLS connection is failed because the pool was short.

Success, measured with the cache server's cells (below):

- in every run of the `slow` and `mixed` cells, under each admission order, at
  most 1% of an open-loop 1 KiB probe's requests are not answered within 10 ms,
  counting a lost or unanswered request as not answered. This applies at
  slow-reader counts below `S / M` (the pool's slots over the cap);
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

### 1. Sends wait by default

Every send that takes pool slots is bounded unless the caller asks for one
that does not wait. A send resolves once its bytes are copied into the pool,
when the caller's buffer is free again; waiting for the bytes to reach the
kernel is a separate call. tokio's `AsyncWriteExt::write_all` and `flush`
have the same split.

- `send(data)` waits for slots and resolves with `io::Result<()>` once the
  send is admitted and queued. It replaces `send_admitted`, whose
  `SendCompletion` result is gone.
- `flush()` waits until every send made earlier on the connection has
  settled, and returns the first error among them. A connection's sends
  settle in order, so `flush` right after a send waits for that send. A
  caller can no longer wait for one send's settlement while it keeps
  sending; `flush` also waits for the later sends.
- `try_send(data)` does not wait. It is served in the call or refused
  (section 6), and returns `io::Result<()>`.
- `submit_batch` waits, as `submit_batch_admitted` does today, and
  `try_submit_batch` does not; both resolve at admission as `send` does.
  `send_parts(..).build(..)` calls `submit` inside a synchronous closure
  (`runtime/io.rs`, `handler.rs`), so it cannot wait; it stays non-waiting
  under the name `try_build`, and `submit_batch` is the waiting form for
  parts.
- `forward_recv_buf` is synchronous and, on TLS, takes pool slots. It stays
  non-waiting and is refused like `try_send` (its name is open question 5).
- `send_backpressured` is removed: `send(..).await?` followed by
  `flush().await?` does what it does. Its one production caller is the redis
  client's `AUTH`.
- `send_chain` is removed. Its IO_LINK send path and `SendChainBuilder` go with
  it, along with `ConfigBuilder::max_chain_length` and the tests that exercise
  chains (`chain_short_send.rs`, `zc_chain_enomem.rs` and the chain cases in
  seven other test files and in `backend/uring/event_loop.rs`). No crate in this
  workspace other than `ringline` calls it, and a waiting form would need the
  chain's slot count before its closure builds it. IO_LINK chains for other
  operations, such as `abort`'s linked operations and disk ordering, stay.

Zero-copy sends still hold their guards until the kernel releases the
pages; that release is internal and does not need a per-send result.

A bounded send borrows its data until it is admitted, as `send_admitted`
does. A caller that reuses its buffer before awaiting does not compile. The
send futures are `#[must_use]`, so a caller that drops one without awaiting
it gets a warning and sends nothing. Today's `tx.send(x)?` does not compile
against the new signature, but `let _ = tx.send(x);` does, and then sends
nothing. There are about 165 such statements in the workspace, most in
tests. `clippy::let_underscore_future` flags them, and CI runs clippy with
`-D warnings`; rustdoc examples are not linted and are fixed by hand.

`with_data` stays the way to parse received bytes: its closure borrows them
in place, as a tokio-util `Decoder` or `httparse` does. A send made inside
the closure cannot await, because the closure is synchronous. The documented
echo pattern does this (the `split` docs and `with_data` examples in
`runtime/io.rs`, `examples/echo_async_server.rs`,
`examples/echo_tls_server.rs`, ringline-bench's echo servers). Such a caller
uses `with_bytes`, keeps the `Bytes` slice it wants to send (a
reference-counted handle, not a copy), and sends it with `send(..).await`
after the closure returns. `with_bytes` freezes the receive buffer, and a
slice kept alive stops the next receive from reusing that allocation, so
`with_data` stays the default for parsing. A closure that would rather drop
a reply than wait uses `try_send`.

A task that sends on several connections waits on the first one that cannot
be served. Such a task should use `try_send` or one task per connection.

A bounded send's wait has no limit. A peer that never reads makes the task
wait until the connection fails or the task gives up, as `writable()` does
today; the examples on `send` show a timeout around it. Whether ringline
offers a configured default limit is open question 7.

Slab conditions are unchanged: a send that needs a send slab entry is still
refused at `zero_copy_hold_cap` or when the slab is full, with `WouldBlock`
from a waiting batch and with `Other` from a non-waiting send, as today.
`SendRefused` is carried only by pool, cap and ticket refusals.

### 2. A ticket queue per connection

Each connection has one queue of tickets, and every operation on it that
takes send-pool slots goes through that queue. Slots are given to a
connection's tickets in queue order.

- A bounded send takes a ticket. If it cannot be served when it is made, the
  ticket waits.
- A non-waiting send is served in the call if its connection has no ticket
  waiting, is under the cap (section 5), and slots are free. Otherwise it is
  refused. It never waits, so it never overtakes a waiting ticket and is
  never overtaken.
- TLS output produced on the receive path takes a ticket when rustls
  produces it. Its bytes are sealed by then, so the ticket goes ahead of
  every waiting ticket whose bytes are not yet sealed, and behind any that
  are. TLS application data from a bounded send is sealed when its ticket
  is served (section 4), so every record goes on the wire in sequence-number
  order. The peer fails a connection whose records arrive out of order
  (`bad_record_mac`). A connection has at most one receive-path ticket:
  output produced while one waits joins it. With the unbuffered engine the
  ticket owns the bytes `unbuffered::drive` wrote into its scratch buffer
  (`tls/backend_uring.rs`). With the buffered engine the bytes stay in
  rustls's `sendable_tls`, which any later `write_tls` drains in full
  (`tls/buffered.rs`), so the ticket records only that output is pending,
  and its size is read from rustls when it is served.
- `close_notify` takes a ticket after the connection's other tickets.

When a ticket is placed ahead of a connection's front ticket, it takes that
ticket's place in the worker queue (section 3).

A ticket waits only when it cannot be served: its connection has an earlier
ticket waiting, the connection is at the cap, the pool cannot hold it, or the
admission order puts another connection's ticket first (section 3).

A guarded send below `send_zc_threshold` that fits one slot is copied into
it (`submit_small_gather`, `handler.rs`), and it takes a ticket like a copy
send; `forward_to_conn` sends this way. Behind a waiting ticket it waits; it
does not fall through to the slab. A send of zero-copy or guard parts
that takes a slab entry and no slot takes no ticket, and is ordered against
the connection's tickets only as it is today (open question 6).

Cancelling a bounded send whose ticket is waiting removes the ticket. If it
was the connection's front ticket, the connection's next ticket takes its
place in the worker queue. A ticket is served in one call that pops, fills
and submits, so a ticket is never cancelled partway through. Receive-path
tickets and `close_notify` are not cancelled; they are dropped at teardown.

The uncontended path adds one check per send: whether the connection has a
ticket waiting or is at the cap. A bounded send that can be served at once
is served on its first poll, which adds one `with_state` call per send.
The held count is updated when slots are popped, pushed back and released.

### 3. The worker queue holds one entry per connection

The worker queue holds at most one entry per connection: the
front ticket of each connection that has a ticket waiting for slots. When a
connection's front ticket is served, its next waiting ticket, if any, takes
its place. `Strict` serves the worker queue's head only; `Budget { slots }`
also serves a later entry that fits ahead of a head that does not, within
its limit, as today.

The worker queue keeps arrival order across connections. Round-robin, in
which a connection's next waiting ticket joins the back of the worker queue
instead of taking its predecessor's place, is not built: stage 0 found, by
reading the code, that the cache server and `admission-server` send each
reply on a connection only after the one before it is admitted, so at most
one bounded send waits per connection and turn order would reorder nothing.
Reopen if a server sends on one connection from more than one task, or joins
or selects over several sends on one connection.

Slots that a ticket admitted ahead of the head pops are marked passing as
today (`mark_if_passing`, `buffer/send_copy.rs`). Slots it pushes back are
unmarked, so `passing_held` counts only slots in use.

### 4. Slots are taken, used, and the excess returned

A ticket being served pops the slots its operation can need off the free
list, owns them while it fills them, and pushes back the ones it did not use.
The connection's held count rises when slots are popped and falls when they
are pushed back or released after their send completes, so each slot is
counted once and no slot is hidden from the free list by a count. Today
every copy send on io_uring reserves its slots and fills them in one call
(`handler.rs`, `buffer/send_copy.rs`), and a mio bounded send holds its
reservation until its entry is written. Taking slots ahead of the work is
new only for TLS application data on io_uring.

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
- TLS output produced on the receive path pops the slots its bytes need:
  the length of the unbuffered engine's scratch bytes, or the buffered
  engine's pending bytes read from rustls when the ticket is served.

The extra record in the TLS bound covers records rustls has queued (a TLS 1.3
`key_update` response, an alert), which it writes into the front of the same
buffer, and the plaintext a slot gives up when it carries them
(`slots_unbuffered`, `tls/mod.rs`). It is not dropped when `wants_write()` is
false: `wants_write()` checks only `sendable_tls`, and rustls moves a pending
key update into `sendable_tls` inside the write call (ringline-tls 0.1.2,
`common_state.rs`; read, not tested).

The free list stays a `Vec<u16>` owned by the worker: only the worker's
thread touches its pool (principle 3).

### 5. A cap on the slots one connection holds

The pool records the connection index and generation that popped each slot
and keeps a held count per connection, as the send slab does for its entries
(`InFlightSendSlab::held_by`, `buffer/send_slab.rs`). A release from an
earlier generation of the index does not decrement the current one, so slots
a closed connection's sends still hold do not count against the next
occupant of its index.

A connection with `held >= M` is at the cap. `M` defaults to 64: in stage 0
an application-level bound of 64 slots removed the slow-reader stalls (0 of
60,000 probe requests over 10 ms in every run, against 32-100% unbounded)
and cost no measured throughput to connections with up to 256 replies
outstanding (at most 2% in a cell with 64 outstanding 16 KiB replies, which
had no A/A runs), where 16 slots cost idle connections a third of their
replies. At 96 slow readers, below `S / M` = 128, 64 did not meet the probe
bar (open question 8).
The rule is the one
`zero_copy_hold_cap` uses (`zero_copy_over_cap`), so an operation of any
size is served while its connection is under the cap; nothing is refused for
its size.

- A bounded send's ticket at the front of a capped connection's queue leaves
  the worker queue. When the held count drops below `M`, the ticket goes
  back at the back of the worker queue. The drop is detected where held
  falls: in `SendCopyPool::release`, which every completion and disposal
  path goes through; in the push-back of a ticket's unused slots, after the
  push-back and not between pop and push-back; and on mio in
  `release_reservation`, which returns permits. A capped connection is in
  the worker queue only when its front ticket is exempt (below).
- A non-waiting send on a capped connection is refused (section 6).
- TLS output produced on the receive path and `close_notify` are exempt:
  their tickets are served in order whatever the held count. Receive-path
  output is bounded by what rustls produces without an application write:
  handshake flights, session tickets and alerts. A `key_update` response is
  not receive-path output here: rustls queues at most one
  (`queued_key_update_message`, ringline-tls `common_state.rs`) and moves it
  into `sendable_tls` with the next application write or the next other TLS
  message, so it goes out under that operation's ticket.

The cap can deadlock against a peer that writes a batch of requests before
it reads any reply. If the batch's replies need more than `M` slots plus
what the socket buffers take, the server's send waits at the cap; a handler
that awaits it stops reading, the peer's writes block, and the peer never
reads the replies that would release the slots. Stage 0 measured it with the
server's socket buffers held small: a client writing 2,000 requests before
reading deadlocked under a 16-slot bound and finished unbounded. With the
image's default buffers no batch of up to 10,000 requests stalled. So the
cap applies only while the pool is more than half used, as the send slab's
caps do; below that a connection may hold any number of slots. Stage 1
measures the threshold.

### 6. Refusals

Only a non-waiting send is refused for want of slots. It is refused in
three cases: the pool has too few free slots, as today; its connection is at
the cap; or its connection has a ticket waiting. Each is an `io::Error` of
kind `Other`, the kind pool exhaustion returns today, carrying a
`ringline::SendRefused` as its inner error. `SendRefused::reason()` returns a
`#[non_exhaustive]` enum with one variant per case, so a caller tells them
apart with `get_ref()` and `downcast_ref` instead of matching the message.
Kind `WouldBlock` is not used: pool exhaustion returns `Other` today, and
the three reasons share one kind so that a caller that handles pool
exhaustion handles the other two.

Pool exhaustion and the cap clear as in-flight sends complete; a waiting
ticket clears when the connection's own ticket is served. The documentation
of the error kinds (`runtime/io.rs`) says so.

A new public method, beside `zero_copy_capped`, says whether a non-waiting
send on the connection would be refused for the cap or a waiting ticket.

### 7. Dedicated slots (built only if stage 1's rule requires them)

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

## In-tree callers

Each caller of a non-waiting send moves to the waiting form unless it has a
reason not to wait.

The redis and memcache clients split into halves, as tokio's `TcpStream`
does with `split`:

- The send half has two methods, `send(command, user_data)` and `flush`. They
  replace `fire_*` (six methods in the redis client, four in each memcache
  client, `Client` and `BinaryClient`). A command is a value: each client
  defines a `Command<'a>` enum with borrowed fields (`Command::get(key)`,
  `Command::set(key, value).ex(60)`, `Command::del(key)` and the others `fire_*`
  covers today). Each variant encodes through the client's existing encoders
  (the redis client's `encode_*_into`, which honour its renamed commands; the
  memcache clients' `append_get`, `append_set` and `append_delete`, which call
  `encode_request_into` for the text protocol and `BinaryRequest::encode_*` for
  the binary one) and gives the reply kind the receive half needs to classify
  the reply. A guarded SET holds its guard as a `GuardBox`, one allocation per
  guarded SET. `resp_proto::Request` is not used for this: it allocates a `Vec`
  per command and carries no reply kind. `send` encodes the command into the
  client's write buffer. The buffer is sent when it holds `max_batch_size`
  commands or a guard that would pass the scatter-gather limit, and by `flush`.
  A call that sends resolves when the send is admitted, as ringline's `send`
  does. With the default `max_batch_size` of 1, each command is sent by its own
  call, as `fire_*` documents today.
- The receive half has `recv` and `recv_meta`, which return each reply with
  its `user_data`. The halves share the client's state on the worker's
  thread, so `recv` sends any buffered commands first, as it does today.
- `recv_ready` is removed from both memcache clients and the redis client. Its
  future does not borrow the client so that a caller can fire while waiting for
  a reply; with halves, one half sends while the other waits.
- The unsplit client keeps its request-response methods (`get().await`
  returns the value). `Command::get` builds a command, `client.get` runs a
  request, and `tx.send` sends a command without waiting for its reply.
- `write_set_frame_and_read` sends the header, each chunk and the trailer
  with `send(..).await?`, and calls `flush().await?` after each chunk where
  it awaits the chunk's `SendCompletion` today. The number of sends is
  unchanged. A piece that cannot be served waits, so a frame is never cut
  short by the pool or the cap; it fails only if the connection fails, which
  already poisons the client.
- `send_raw` is `pub(crate)`: the sharded and cluster routers send one
  encoded command through a pooled `Client` with it. It becomes async, with
  no public change.
- A load generator built on these clients uses `fire_*` and `recv_ready` in
  its open-loop path, and changes to the halves.

ringline-http changes the same way: the HTTP/2 `fire_request` becomes
async, `from_conn` awaits its preface send, and `flush_pending_send` takes
frames from h2 and sends them with `send(..).await`, so no frames are lost.
The HTTP/1 connection (`h1_conn.rs`) sends with `send(..).await`.

- `forward_to_conn`'s copy fallback waits for slots; it runs inside
  `ForwardFuture::poll`, so the forward pauses instead of failing. Its
  rustdoc's "`Other` when the pool has no free slots" changes.
- ringline-ping, ringline-bench, ringline-benchmarks, the examples and the test
  call sites change mechanically. `admission-server`'s outside probe keeps
  `try_send`, since it counts refusals.

`docs/send-admission-design.md` lists `send` and `submit_batch` as
unchanged; it changes to point here. The renames and removals are batched
into one breaking release of ringline and its client crates (principle 9).

## mio

On mio the pool is an admission budget: `send_bounded` reserves a count of
slots, and today's plain sends copy into a heap buffer and use no pool slots
(`handler.rs`, `docs/mio-bounded-send-design.md`). There is no slot memory to
take, so mio keeps count permits; section 4 applies to io_uring only. With
sends bounded by default, every mio send takes permits. The ticket queue,
the worker queue and the cap apply on mio as on io_uring. A connection's
held count on mio is its permits plus, in slot-sized units, the bytes of its
queued entries that carry no permit (receive-path TLS output and
`close_notify`), so a slow receiver waits on mio as it does on io_uring
(principle 5). On mio, `try_send` is refused when permits are short, which
today's `send` never is.

## Teardown and parking

A close request is the application's `close`; teardown is the release of
the connection's state that follows once its sends have drained or failed.

- At a close request, the connection's waiting bounded-send tickets are
  failed, as waiting sends are today, and `close_notify` takes its ticket.
  A waiting receive-path ticket stays, so the records it holds still go
  ahead of `close_notify`.
- `close_notify` keeps today's fallback: if it finds no slot once the
  connection's other sends have drained, it is dropped and the connection
  ends with a bare FIN (`place_retained_close_notify`,
  `backend/uring/driver.rs`). A closing connection therefore never waits on
  slots for `close_notify` beyond that point.
- At teardown, a receive-path ticket still waiting is dropped and its worker
  queue entry removed. `close_notify` is then not sent, because the peer
  would find the dropped records' sequence numbers missing and report a MAC
  failure; the connection ends with a bare FIN.
- A connection with tickets waiting is not parked onto another worker until
  they are served or failed; waiting tickets are a park blocker
  (`park_blocker`, `backend/uring/driver.rs`).

## Counters

Per worker, as `SendAdmissionCounters` fields: tickets that waited, the
largest number of tickets waiting on one connection at once, waits at the
cap, non-waiting sends refused for each reason, the largest held count, TLS
receive-path output that waited for slots, connections closed with a bare
FIN because sealed output was waiting, and, if built, dedicated-slot sends
and retired dedicated slots (section 7).

## Experiment

The cells are those the cache server used to measure admission order, plus
four more, run in stages so each answers one question before more is built.
The cells:

- `slow`: readers pipelining 4,000 GETs of 64 KiB values at 1 MB/s, with 1,
  4 and 16 readers, and with enough readers that `N × M` reaches the pool;
- `mixed`: those readers with clients requesting 120 KiB values;
- `batch`: a client that writes requests totalling more than the server's
  receive buffer plus its own send buffer, whose replies need more than `M`
  slots, before it reads any reply;
- `idle`: a client that pipelines small replies;
- `bulk`: a client reading 1 MiB replies at full speed.

`idle` and `bulk` get their own A/A runs first. The cost of the waiting
`send` on the uncontended path is measured with a criterion benchmark of
`send(..).await` against `try_send` (`ringline/benches/echo.rs`).

0. Done, with no runtime change (`docs/journal/2026-11-send-pool-stage0.md`):
   `admission-server --conn-slot-cap M`, an application-level bound on the
   slots a connection's unsettled replies hold, in these cells and deeper
   pipelining cells, 226 runs. `M` = 64 met the decision rules under both
   orders; `M` = 16 cost idle connections a third of their replies. NO-GO
   for an always-on cap (the `batch` cell with small server socket buffers)
   and for round-robin (section 3). At `M` = 64 the 8,192-slot pool held the
   probe bar with 16 slow readers and missed it at 96, below `S / M` = 128,
   with about 1,500 to 2,300 slots in use that the application's count did
   not cover (open question 8). Under the criterion that is a miss below
   `S / M`, the rule for section 7 below; whether it counts as one waits on
   what holds those slots.
1. After sections 1 to 6: every cell, `M` at 32 and 64, the cap above half
   occupancy and above three quarters, under `Strict` and `Budget`, against
   the unchanged pool; `slow-N` at 64, 96 and 128 readers, with the runtime's
   held count, to find what holds the slots stage 0 could not account for;
   and the `batch` cell with small server socket buffers, which the
   occupancy threshold must let finish.
2. A TLS cell with slow readers and the pool held near full, counting
   connections failed, receive-path output that waited, and bare-FIN closes.
3. Only if stage 1's rule for section 7 is met (below): section 7, with the
   shared pool at its original and at its halved size.

Each stage's prediction and decision rule are committed before its runs. In
each cell `passing_admissions` shows whether `Budget` had anything to do, and
the cap counters whether the cap bound. A cell in which a mechanism's
counter reads zero did not test that mechanism.

Section 7 is needed if no `M` meets the criterion in the `slow` and `mixed`
cells and in both throughput cells at a slow-reader count below `S / M` (the
pool's slots over the cap) that a deployment expects. At `S / M` readers or
more the pool is full by construction, so those counts measure section 7,
not the cap.

Stage 0 met the NO-GO for an always-on cap (the `batch` client deadlocked
under the bound) and the NO-GO for round-robin (by reading the code, at most
one bounded send waits per connection; section 3), so neither is built.

## Prior art

Most mechanisms here have a precedent; none is listed for the TLS ordering.
The sources were read on 2026-11-18; where only part of a claim could be
checked, the entry says so.

- Per-socket send buffers in Linux TCP. A socket's queued bytes are limited
  by `sk_sndbuf` (`SO_SNDBUF`, `net.ipv4.tcp_wmem`), and `tcp_mem` limits
  all TCP sockets together. A socket at its limit is not reported writable
  again until its free space is at least half its queued bytes
  (`__sk_stream_is_writeable`, `sk_stream_min_wspace`,
  `include/net/sock.h`), so it becomes writable again once its queued bytes
  fall to about two thirds of `sk_sndbuf`. The cap here is the per-socket
  limit applied to the send pool, and open question 3 asks whether to copy
  the gap between the limit and the point at which a connection resumes.
- Netty's `WriteBufferWaterMark`. A channel becomes unwritable when its
  outbound buffer's pending bytes exceed the high mark (64 KiB by default)
  and writable again when they fall below the low mark (32 KiB), and the
  application is told through `channelWritabilityChanged`
  (`ChannelOutboundBuffer`). Writes are not refused while the channel is
  unwritable; the buffer keeps growing. Here a send waits at the cap and
  `try_send` is refused, so the bound holds whether or not the application
  checks.
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
- Round-robin over per-source queues, from Nagle (RFC 970, one queue per source
  host and one packet per non-empty queue per cycle), and deficit round-robin
  (Shreedhar and Varghese, SIGCOMM 1995), which gives each flow a quantum per
  round so flows with large packets do not get more than their share. DRR is
  O(1) per packet when the quantum is at least the largest packet. Round-robin
  over connections (section 3, not built) would be Nagle's scheme, and turns
  weighted by slots DRR. Linux's `fq` qdisc combines both with a per-flow limit:
  per-flow queues served round-robin with a quantum of two MTUs, and a packet
  dropped once its flow holds 100 (`flow_limit`, `net/sched/sch_fq.c`). The
  per-flow limit there is the cap here, with a refusal or a wait in place of a
  drop.
- EASY backfilling (Lifka, "The ANL/IBM SP Scheduling System", 1995;
  Mu'alem and Feitelson, IEEE TPDS 2001). A later job may start ahead of
  the queue's head if that does not delay the head. `Budget { slots }` is a
  version of this with a slot budget in place of a time reservation. The
  definition was checked against summaries of the papers, not their text.
- HTTP/2 flow control (RFC 9113, sections 5.2 and 6.9). A sender is limited
  by a window per stream and one per connection, and the h2 crate's
  `SendStream::reserve_capacity` and `poll_capacity` let it ask for capacity
  and wait until some is assigned. The windows are credit the receiver
  grants, where the cap is a limit the sender sets, but both bound one
  stream's share; `poll_capacity` waits for capacity as a bounded send waits
  for slots.
- Request values with one verb: hyper's and h2's `send_request(req)` and
  tower's `Service::call(req)`. The clients' send halves take a `Command`
  the same way.
- Tokio's bounded channels (`tokio::sync::mpsc::Sender`). `send` waits for
  capacity and `try_send` returns an error at once when the channel is full.
  Section 1 gives sends the same pair of forms.

## Non-goals

- Making `Strict` the default. Stage 1 says whether it meets the criterion;
  the default is a separate decision.
- A cap on UDP sends, which have no connection.
- The send slab. Nothing here takes slab entries, and slab refusals are
  unchanged.

## Open questions

1. Defaults for `k` and `D`, if section 7 is built. `M` defaults to 64 from
   stage 0; stage 1 confirms it against the runtime's own count.
2. The occupancy above which the cap applies: half, as the send slab's caps,
   unless stage 1 shows another threshold serves the `batch` cell and the
   slow readers better.
3. Whether a capped connection rejoins at `held < M` or only below a lower
   mark `L`, as Netty's and Envoy's watermarks do (Prior art). A lower mark
   gives a capped connection fewer, larger turns.
4. How large the output rustls produces without an application write can be
   (handshake flights, session tickets), which bounds what a connection's
   exempt tickets hold and sets `D`.
5. Names: the configuration for `M`, `k`, `D` and `L`; `try_send`,
   `try_submit_batch`, `try_build` and the name of `forward_recv_buf`; the
   method that reports a refusal in advance; `SendRefused` and its reasons. They
   are public and hard to change once released.
6. Whether sends that take a slab entry and no slot join the ticket order.
7. Whether ringline offers a configured default limit on a bounded send's
   wait, and what a send that reaches it returns.
8. What holds the 1,500 to 2,300 pool slots that stage 0's application-level
   count did not cover with 96 to 160 slow readers. It decides how many slow
   readers a pool of a given size protects, and so the pool's size.

## Alternatives

- Do nothing, and require callers to gate every send on settlement or
  `writable()`. This is the current non-goal; the measured cells are what a
  caller that gates only its long replies gets. Stage 0 did not measure
  it.
- Keep non-waiting sends as the default and add the cap, refusing a non-waiting
  send at the cap or behind a waiting ticket. The API stays as it is, but every
  caller meets the refusal: redis and memcache leave partial frames, and HTTP/2
  loses frames, unless each caller adds its own handling.
- Non-waiting sends that overtake waiting tickets, with a rule that keeps
  sealed TLS output ahead of unsealed operations. A connection's bytes then
  follow two orders, and a caller that mixes the two kinds of send can see
  its replies reordered.
- A per-connection send buffer, as `SO_SNDBUF` is for a socket: a send
  copies into the connection's queue and is refused only past a byte limit.
  The queued bytes are outside the pool, up to `max_connections` times the
  limit.
- A reservation handle, `reserve(bytes)`, that takes slots off the free list
  at once and lets later non-waiting sends fill them without refusal. It
  makes a multi-piece frame safe without an await, at the cost of slots
  that sit idle until filled, so it suits small frames. No in-tree caller
  sends a multi-piece frame without an await; it is built when one does.
- Overflow buffers: send a copy that the cap keeps out of the pool from a
  heap buffer. It moves unbounded memory from the pool to the heap, needs a
  worker-wide limit of its own, takes send slab entries if sent zero-copy,
  and gives the application no backpressure.
- A count-only reservation instead of taking slots: it hides slots from the
  free list while the operation runs, and code that counts both the
  reservation and the slots filled from it can count a slot twice.
- Refuse a send that needs more than `M` slots. It rejects any reply larger
  than `M` slots (263 KB at `M` = 16); the `held >= M` rule does not.
- A reserved count per connection instead of dedicated slots: the same
  guarantee for small replies, with accounting on every allocation.
- Two pools by reply size (O5 in `docs/send-admission-design.md`): bounds the
  slots a large reply takes, but not one connection's share.

## Order of work

1. Experiment stage 0 (done).
2. The held count per connection, keyed by generation, with tests and no
   behaviour change.
3. Taking slots for an operation and returning the excess, for copy sends,
   TLS application data and receive-path TLS output (section 4).
4. In one breaking release: the per-connection ticket queue and the worker
   queue (sections 2 and 3), with
   receive-path TLS output waiting in order instead of failing the
   connection; bounded sends by default, the `try_` forms, `SendRefused` and
   the method that reports a refusal in advance; the removal of `send_chain`;
   and the in-tree callers (sections 1, 2 and 6, In-tree callers).
5. The cap above half occupancy, `M` = 64 by default (section 5), and its
   mio account (the mio section).
6. Experiment stages 1 and 2.
7. If stage 1's rule for section 7 is met, the dedicated pool (section 7)
   and stage 3.
