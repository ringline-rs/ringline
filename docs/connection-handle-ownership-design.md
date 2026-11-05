# Connection handle ownership

Note (2026-11-04): `ConnCtx` is `pub(crate)` and `as_conn` is gone; see
`docs/public-context-types-design.md`. References to it below are historical.

Note (2026-10-25): the segment readers (`segments`, `recv_owned_segment`,
`with_segments`, `end_segments`) and `SegmentReader` were removed.

Note (2026-10-25): `forward_to` and `SinkFd` were removed; on io_uring
`forward_to_conn` sends through the sink's send queue.

- **Status:** proposal — intent only, nothing implemented
- **Motivated by:** #423, and four sibling defects found reviewing its fix

## The problem in one sentence

`ConnCtx` is `Copy`, and it is a handle to state that is exclusive — so every
exclusivity rule in the runtime has to be re-derived at run time, and the ones
we miss are silent hangs or wire corruption rather than compile errors.

## Evidence

`ConnCtx` derives `Clone, Copy`. It exposes **nine** recv entry points, all
`&self`, all mutually exclusive in practice:

`with_data`, `with_data_result`, `with_bytes`, `segments`,
`recv_owned_segment`, `with_segments`, `forward_to`, `forward_to_conn`,
`recv_ready`

Any two of them live at once is a bug. Nothing prevents any pairing, because a
second handle costs a `let`. Five compositions are known to be reachable, and
each one has already cost something:

| composition | consequence | how it is handled today |
|---|---|---|
| two `SegmentReader`s | one drops, settles the hold into the accumulator, the other strands | runtime check → `Err` |
| `with_segments` + live reader | remainder left in the accumulator, domain still segmented | nothing — latent |
| `with_data` then `segments()` | bytes stranded in the accumulator, connection hangs | **#423** — the adoption fix |
| `segments()` during a Mode A forward | adoption injects post-`len` overshoot into the forward's write | runtime refusal, added in #425 |
| stale `ConnCtx` after slot recycle | drains a *different* connection's accumulator | runtime generation check |

The send side is not exempt, which is the part that makes this a handle problem
rather than a recv problem. `forward_to_conn`'s own documentation states:

> The forward writes to the sink directly rather than through its send queue,
> so a `send` on the sink from elsewhere while a forward is running is not
> ordered against it and will interleave on the wire. **Forward *or* send on a
> given connection, not both at once.**

That rule is enforced by that sentence and nothing else.

## Why "the send queue already serialises sends" is not an answer

The per-connection send queue provides **non-corruption**: one `send()`'s bytes
reach the wire contiguously, and TLS records do not interleave. It says nothing
about the **order** two tasks' messages arrive in — that is whichever task the
executor polled first.

For a protocol, message order *is* the correctness property. A shared send
handle therefore advertises a guarantee the transport cannot supply. Ordering
is an application decision and needs an application-visible place to live.

## Proposal

**One owner per connection, for both directions.**

- Split `ConnCtx` into a send half and a recv half; make **both** non-`Copy`
  and non-`Clone`. Methods take `&mut self`.
- Fan-in (several tasks producing for one connection) becomes an explicit
  queue, using the `Sender`/`Receiver` already in `runtime/channel.rs`: many
  producers, one owning task, ordering decided by the queue's owner.
- `forward_to_conn` takes the sink's send half by `&mut`, so "forward or send,
  not both" becomes a borrow error.

What this converts from runtime to compile time:

| composition | after |
|---|---|
| two `SegmentReader`s | compile error |
| `with_segments` + live reader | compile error |
| `with_data` then `segments()` | compile error |
| `segments()` during a forward | compile error |
| send while the connection is a forward sink | compile error |

## What it does not fix

**Staleness.** A handle can outlive its connection, slots recycle, and handler
futures are `'static`, so a lifetime cannot bind a handle to a connection. The
generation check stays, permanently, and every entry point still needs a way to
*report* a stale handle — which several (`segments()`, `recv_owned_segment()`)
currently lack.

## Staging

This changes `AsyncEventHandler::on_accept`'s signature, so it reaches every
handler, example and test plus the six client crates. It does not have to be a
flag day:

1. **Make mode entry fallible** — `segments()` / `recv_owned_segment()` return
   `io::Result<_>`, refusing `EBUSY` on a live reader or forward and `EPIPE` on
   a stale generation. This is needed regardless of the rest: #425 had to refuse
   silently only because the signature has no error channel.
2. Add `ConnCtx::split()` (or `take_recv()`) additively, returning the halves.
   Both forms coexist; the old methods delegate.
3. Migrate the client crates and examples onto the halves.
4. Deprecate the direct methods; remove them in the next breaking release,
   flipping `on_accept` to hand out the halves directly.

### Step 4, split in two

Step 4 turned out to be two independent breaking axes, and they land as two
PRs rather than one:

**4a — `on_accept` hands out an owned `Connection`.** Not the two halves
directly, which is what this doc originally said. Measured across the 214
handler bodies in the tree:

| shape | count |
|---|---|
| ignores the connection entirely | 98 |
| recv only | 62 |
| send inside a recv closure (needs two handles) | 32 |
| send only | 16 |
| both, but sequential | 6 |

Two parameters would have churned every signature *and* every body. A single
owned, non-`Copy`, `!Send` `Connection` that delegates both sides — with
`split()` for the minority that need independently borrowable halves — leaves
most bodies untouched and gives the identical guarantee: the handler cannot
alias its own read side, because it never holds a `Copy` handle. In the event
only 16 bodies needed `split()`.

The ownership claim is recorded by the event loop at accept time
(`Connection::for_accept` plus `driver.recv_half_taken[idx] = true`), because
`spawn_accept_task` runs outside a task poll and cannot reach `CURRENT_DRIVER`.

**4b — demote `ConnCtx`'s recv methods to `pub(crate)`.** *(landed)*

The read entry points — `with_data`, `with_data_result`, `with_bytes`,
`recv_ready`, `segments`, `recv_owned_segment`, `with_segments`,
`end_segments`, `try_with_data`, `eof_truncated` — are crate-private.
Reading goes through `Connection` or `RecvHalf`, neither of which is `Copy`,
so the read side cannot be aliased.
`ConnCtx` is now a send/identity/lifecycle handle plus a way to *obtain* the
read side (`take_recv`, `split`).

The **forwarding** entry points stay public on purpose: `forward_to` and
`forward_to_conn` move bytes from source to sink and never surface them to the
caller, so they cannot be used to observe a stream another reader owns. Their
own "one forward at a time" rule is refused at runtime by the driver — and with
the read methods private, that refusal is now reachable *only* through
`ConnCtx`, because `&mut RecvHalf` turns a second concurrent forward into a
compile error. Keeping them public is what keeps that runtime check testable.

Original sketch of this step:
 This is what makes
the model *enforced* rather than advisory, and it is a separate change with its
own call sites: outbound connections from `connect()`, which take their read
half with `take_recv()`. Roughly 21 sites, all in tests, examples and the
bench crates. Until 4b lands, `Connection::as_conn()` and `SendHalf::as_conn()`
remain reachable escape hatches.

Step 1 is independently valuable and cheap. Steps 2–4 are the real fix.

### Step 2, as actually landed

Step 2 shipped in two parts, because the first half had a hole.

`take_recv()` + `RecvHalf` landed first (#430). The adversarial review then
found that `RecvHalf::conn()` returned a `Copy` `ConnCtx` carrying the **full
recv surface** — so the "exclusive" read side could be reached around by the
task that held it, and every migrated consumer in step 3 would have had to call
`.conn()` for its sends, cementing the hole into all six client crates before
anyone noticed.

So `conn()` is gone and `ConnCtx::split() -> io::Result<(SendHalf, RecvHalf)>`
replaces it. Two consequences worth recording, because both were arrived at by
being wrong first:

- **`SendHalf` does not borrow `RecvHalf`.** The obvious design — a send handle
  borrowed from the read side — makes the write side unreachable for as long as
  a reader is live. That is not an edge case: an echo sends from *inside* its
  `with_data` closure, while the recv future holds the read half `&mut`. The
  halves are therefore independent, and
  `split_halves_echo_round_trip` in `tests/echo.rs` is the executable form of
  that argument — it would not compile under a borrowing design.
- **`SendHalf::as_conn()` is a deliberate remaining escape hatch**, not an
  oversight. `forward_to_conn` takes a `&ConnCtx` sink, so without it a proxy
  holding halves for its backend could not forward into that backend. It hands
  back the full surface, so the model stays *advisory* until step 4 takes the
  recv methods off `ConnCtx` — but it sits on the write side, where a consumer
  reaches for it once (to name a sink) rather than on every send.

`SendHalf` carries no claim flag of its own yet: `ConnCtx` is still `Copy` and
can still send, so refusing a second sender would be enforcement the additive
phase cannot deliver. Single-ownership of the write side is expressed by the
type (not `Copy`, not `Clone`) and becomes enforced in step 4.

`RecvHalf::end_segments()` was also added here: redis and memcache call
`end_segments` on the handle they hold, so step 3 is blocked without it.

## Decided: channels only, no blessed `Rc<SendHalf>`

Fan-out send has no surviving use case, and the two hardest many-to-one users
in this tree already chose the queue design without being asked to:

- **HTTP/2** — the canonical many-streams-to-one-connection case — is a pump
  loop wrapping `H2Connection` and *one* `ConnCtx` (`ringline-http/src/h2_conn.rs`).
  Streams feed the pump; the pump owns the socket.
- **Redis pipelining** — `Client` owns the `ConnCtx` and tracks a `VecDeque` of
  pending ops bounded by `max_in_flight`. Callers share the `Client`, never the
  handle.

Neither reached for a shared handle, because both need response-order
correspondence and a shared handle cannot provide it.

The candidates that fold on inspection:

| case | why it does not need a shared handle |
|---|---|
| pub/sub broadcast | fan-out *across* connections; each is still single-writer |
| keepalive `PING` from a timer task | a PING landing mid-response corrupts framing — needs ordering |
| supervisor sending `GOAWAY`/shutdown | must follow in-flight responses — needs ordering |
| `on_tick` flushing batched data | same ordering question |
| HTTP/2 multiplexing | already a pump loop |
| Redis pipelining | already single-owner + queue |

The keepalive row is the important one: it is the case a developer would reach
for sharing, and it is exactly the case that would silently interleave.

**Cost, stated plainly:** double queueing — a userspace channel in front of the
runtime's per-connection send queue. The runtime's queue cannot absorb the job,
because there is no order for it to be deterministic *about*; only the
application knows the intended order. The channel is `!Send` and
`Rc<RefCell<...>>` (`runtime/channel.rs`), so the marginal cost is a push and a
task wake, not an atomic. Worth measuring if anyone objects on latency grounds.

Users can still wrap their own type in `Rc`. The question is what the API
*endorses*: blessing `Rc<SendHalf>` would advertise an unsound pattern as
supported.

## Open questions
- Should the recv half be a single type with `&mut self` methods, or a typestate
  (`RecvHalf<Default>` / `RecvHalf<Segmented>`) so a mode switch is visible in
  the type? Typestate is stricter but interacts badly with `'static` futures.
- `forward_to` takes a `SinkFd`, not a connection; does it need the same
  treatment, or is the borrow of the `SinkFd` already sufficient?

## Why this is worth doing

Three separate bugs in one day traced to the same shape: a rule that was known,
written down in one place, and unenforced everywhere else — Mode A's
`arm_forward_source` had the adoption, the generation check and the `EBUSY`
refusal, and Modes B and C, written later against the same driver state,
inherited none of them. Divergent siblings against shared mutable state is the
recurring defect. Ownership is the mechanism that makes divergence impossible
rather than merely discouraged.

## The end state

Both sides are now capabilities you must hold, and `ConnCtx` is a token.

| | read | write |
|---|---|---|
| capability type | `RecvHalf` | `SendHalf` |
| `Copy`/`Clone` | neither | neither |
| claim | `recv_half_taken` | `send_half_taken` |
| taken by | `take_recv` / `split` | `take_send` / `split` |
| released by | `Drop` (generation-gated) | `Drop` (generation-gated) |
| recycle-point reset | `clear_conn_claims` | `clear_conn_claims` |

`ConnCtx` keeps identity (`token`, `index`, `peer_addr`, `is_outbound`,
`is_alive`, `tls_info`), lifecycle (`close`, `cancel`, `request_shutdown`),
outbound connects, the forwarding entry points, and the three that mint the
halves. It grants no read or write of its own — which is what makes it being
`Copy` fine. **Copying a name is harmless; copying a capability was the bug.**

### Why forwarding stayed on the token

`forward_to` and `forward_to_conn` move bytes from source to sink and never
surface them to the caller, so they cannot be used to observe a stream another
reader owns. With the read *and* write methods private they also cannot be
paired with an external operation on the same connection. Their own
exclusivity is enforced two ways:
`RecvHalf::forward_to_conn` takes the sink's `&mut SendHalf` (compile time),
and the token-named form refuses `EBUSY` when the sink's write half is out
(run time). Keeping the latter reachable is what keeps that runtime refusal
testable.

### Fan-in is a queue, and the tests now show it

With no `Clone` on either half and no capability on the token, several
producers feeding one connection *has* to be an explicit queue drained by the
owning task. `SleepEchoHandler` and `TimeoutTestHandler` in `tests/echo.rs`
were rewritten onto `mpsc::channel` for exactly this reason — they had been
using `as_conn()` to hand a spawned task a second writer, which is the thing
this whole arc exists to prevent.

Single *ownership* is not the same as one operation at a time: `send` and
`send_backpressured` return owned futures, so the `&mut` ends at the call and
two sends can still be in flight from one half. `JoinHandler` and
`OwnerMoveHandler` demonstrate that.
