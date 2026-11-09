# Listeners and the accept path

Note (2026-10-25): `SegmentReader` was removed.

Note (2026-10-25): `forward_to` was removed, with the segment hold
(`segment_hold`) and Mode A forward writes.

Note (2026-10-25): the TCP provided-buffer ring was removed, with the
fallback receive and the `pool/recv_parked` and `pool/recv_fallback`
counters.

- **Status:** listener list and Pool are on main; merged accept, steering and
  park are implemented behind the `unstable-accept` feature; steps 6 and 7 of
  Staging are not implemented
- **Motivated by:** the single-listener limit found while reviewing whether
  `Connection` should split per transport

## The problem in one sentence

A ringline process can listen on exactly one socket, and the code that accepts
on it is the only part of an io_uring runtime that never touches the ring.

## Evidence

**One listener, last call wins.** `bind_addr` is a single `Option<BindAddr>`
(`worker.rs:474`); `bind()` (`:488`) and `bind_unix()` (`:497`) each *assign*
it. Calling both silently discards the first. Three methods away in the same
builder, `bind_udp()` (`:506`) pushes onto a `Vec` — the right pattern already
exists, in the other half of the API.

**Everything per-connection is therefore process-global, with the transport
difference papered over at run time:**

| what | today | consequence |
|---|---|---|
| TLS | `config.tls: Option<TlsConfig>` (`config.rs:203`) | cannot serve plaintext on 8080 and TLS on 8443 |
| `TCP_NODELAY` | `tcp_nodelay: if is_unix { false } else { … }` (`worker.rs:980`) | `ConfigBuilder::tcp_nodelay(true)` is accepted, documented, and silently ignored under `bind_unix` |
| bound address | `getsockname_v4_v6` → `Option`, `None` for Unix (`worker.rs:962`) | one address for one listener |
| peer address | acceptor sends a fabricated `0.0.0.0:0` for Unix (`acceptor.rs:104`) | the channel payload is `Sender<(RawFd, SocketAddr)>` — TCP-shaped |

**Accepts never enter the ring.** There is no accept opcode anywhere in
`backend/uring/`. The path is a dedicated thread blocking in `accept4`
(`acceptor.rs:33`), then a crossbeam send plus an eventfd write to wake the
target worker — a cross-thread handoff per connection, in a runtime whose
entire premise is that nothing crosses threads. The thread is also unpinned,
which is the hazard class behind the single-core funnel we root-caused
(i40e Flow-Director ATR plus unpinned threads under `isolcpus`).

**The crate's own architecture diagram describes a design we do not have.**
`lib.rs:53` reads *"Acceptors Thread (accept4() with SO_REUSEPORT)"*. There is
one acceptor thread, one socket, and `create_listener` is explicitly documented
*"without SO_REUSEPORT (just SO_REUSEADDR)"* (`worker.rs:1169`) with no
recorded reason.

**TLS handshakes run on the worker event loop**, inline in the completion path:
*"TLS path: defer accept until handshake completes"* (`backend/uring/event_loop.rs:1882`).
`on_accept` is not called until the handshake finishes, so a TLS connect storm
puts all of the asymmetric crypto on the workers before any user task exists.

## Design

### 1. A listener list

`bind()` and `bind_unix()` push rather than assign, matching `bind_udp`. Any
mix of TCP and Unix listeners, any number of each. This is the piece everything
else follows from, and it settles a question raised separately: because one
`on_accept` now receives every transport, `Connection` **stays transport-erased**.
A `TcpConnection` / `UnixConnection` split — which std and tokio do, and which
is defensible under the one-listener limit — stops working the moment a process
can serve both, and ringline has no `AsyncRead`/`AsyncWrite` to re-converge on.

### 2. Per-listener configuration

TLS, `TCP_NODELAY`, backlog and bound address move from `Config` onto the
listener entry. The `if is_unix` branch at `worker.rs:980` then does not need
another arm — a Unix listener simply has no `tcp_nodelay` to set. Process-wide
`ConfigBuilder::tls()` stays as the default for listeners that do not override
it, so existing single-listener code is unaffected.

### 3. `ListenerId` on `Connection`

A handler serving plaintext, TLS and a Unix admin socket cannot dispatch
without knowing which listener a connection arrived on. `Connection::listener()
-> ListenerId` (opaque, bind order) alongside the existing `peer_addr()`. The
`AsyncEventHandler` signature is unchanged — that RPITIT is the most delicate
declaration in the crate and this does not need to touch it.

The acceptor channel payload becomes `(RawFd, ListenerId, PeerAddr)`, which
also retires the fabricated `0.0.0.0:0`.

### 4. Two accept modes, configurable

**Pool** — N acceptor threads, one per listener, each blocking in `accept4`,
all feeding the existing per-worker channels. Keeps explicit round-robin
placement and the existing full/dead-worker fallback. Unix listeners need this
mode or the shared-fd variant, since `SO_REUSEPORT` does not apply to them.

**Merged** — each worker binds its own listener with `SO_REUSEPORT` and arms a
multishot accept on its own ring. No thread, no channel, no wake fd, no
handoff. Kernel ≥6.0 is already required, so multishot accept is available.
This mirrors what the UDP path does today (`backend/uring/driver.rs:2291`).

For a listener that cannot use `SO_REUSEPORT` (Unix), the merged mode degrades
to every worker arming multishot accept on one **shared** listen fd; the kernel
hands each connection to exactly one waiter.

mio has no multishot accept. It keeps the pool, or registers the shared
listener per worker with `EPOLLEXCLUSIVE`. Correct and non-pathological is the
bar there, not optimal.

### 5. Placement, and why it is not a detail

The pool mode's real advantage over the merged mode is *placement*: explicit
round-robin versus the kernel's 4-tuple hash. That difference is much larger
than it sounds, because of the topology every real client uses.

**A pooled client is the adversarial case for hashing.** N connections from one
client to one host vary only in source port, so `SO_REUSEPORT` spreads them
approximately uniformly at random. That is balls-in-bins: at N = W — the
canonical "one connection per server core" pool — the expected fraction of
*empty* workers is (1 - 1/W)^W → 1/e ≈ **37%**. Eight connections across eight
workers typically leaves three workers idle and stacks three on one. Round-robin
gives exactly one each, deterministically.

A third of the machine dark on the most common client pattern is not a marginal
distribution difference, and it is the topology all of our load generators use.
So **BPF steering is a prerequisite for the merged mode, not a refinement of
it** — without explicit placement the merged mode cannot be the default.

`SO_REUSEPORT` groups accept a BPF program that chooses the target socket:

- `SO_ATTACH_REUSEPORT_CBPF` — classic BPF returning an index into the group.
  Unprivileged. Cannot read a map, so changing policy means re-attaching a new
  program via `setsockopt`. Coarse, but enough for "exclude worker 3".
- `SO_ATTACH_REUSEPORT_EBPF` — `BPF_PROG_TYPE_SK_REUSEPORT` with a
  `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` and `bpf_sk_select_reuseport()`. Userspace
  updates the map at run time, so a worker leaves the rotation with no
  `setsockopt` and no socket close. Needs BPF load privileges.

**Measured, 2026-09-22** — Debian 13, kernel 6.12.63, four listeners in one
reuseport group, 40 connections, `experiments/reuseport-steering-spike.toml`:

| case | Recv-Q across the four listeners | accepted |
|---|---|---|
| CBPF selects index 0 | `0, 0, 0, 40` | `40, 0, 0, 0` |
| CBPF selects index 2 | `0, 40, 0, 0` | `0, 0, 40, 0` |
| no BPF (kernel hash) | `12, 10, 8, 10` | `10, 8, 10, 12` |

**A socket the selection program never picks accrues nothing** — zero pending
backlog, zero accepted. "Not selected" and "not queued on" are the same thing,
so tier 2 works: a worker leaves the rotation without closing its listener, and
nothing is sitting there to be reset. The no-BPF row is what makes that
trustworthy — the same measurement reports non-zero backlogs on all four
sockets, so the zeros are a result rather than an instrument that can only
print zero.

Re-attaching a different program moves the target, so **unprivileged CBPF is
enough to take a worker out of the rotation** — no BPF load privileges needed.
CBPF cannot read a userspace map, so a policy change re-attaches a program
mapping to the remaining set; eBPF with a `REUSEPORT_SOCKARRAY` stays the
option if per-connection policy is ever wanted, at the cost of those
privileges.

**The index source decides whether exclusion funnels (measured 2026-09-23).**
Excluding a socket is only half of what the program must do; the other half is
spreading over the ones that remain. Two ancillary loads were tried, same
program shape otherwise (`idx = <source> % live_count`, then a jump chain to
the live socket's group index), 40 connections over 4 listeners,
`experiments/reuseport-exclude-spike.toml`:

| index source | excluded socket | live set |
|---|---|---|
| `SKF_AD_CPU` | 0 | `0, 40, 0` |
| `SKF_AD_RANDOM` | 0 | `12, 12, 16` |
| `SKF_AD_RANDOM` (different exclusion) | 0 | `16, 10, 14` |

Exclusion is absolute under both — the excluded socket accepts nothing. But
`SKF_AD_CPU` is the *receiving* CPU, which is constant for a loopback client, so
every connection funnels onto one live socket. Tier 1's handoff would then
redistribute nearly every connection at a channel hop each, which is the
single-core funnel shape this project has already root-caused once.

So tier 2 attaches **`SKF_AD_RANDOM % live_count`**, unprivileged CBPF, with a
jump chain mapping the result to the live socket's index. No packet parsing, no
map, no privileges.

Not yet measured, and decisive before tier 2 ships: what happens to
connections **already queued** on a socket when it leaves the rotation. They
stay where they landed, so exclusion stops new arrivals but does not empty the
queue — taking a worker out still needs a drain before its listener closes.

Recorded hazard: closing a `SO_REUSEPORT` listener **resets** connections still
queued on it. Graceful shutdown in merged mode must stop accepting, drain, then
close.

### 5a. Spread versus pack

Spreading a client's pool across workers is not unconditionally right, and the
codebase already contains the opposing argument. `conn_chunk_size`
(`config.rs:148`) exists to do the opposite:

> Higher values pack connections onto fewer workers at low connection counts,
> keeping each active worker's CQE density high enough for io_uring batching to
> pay off. Rule of thumb: set to the minimum connections-per-worker at which
> your workload sees good batching (typically 16-64).

Follow that rule of thumb and a 16-64 connection client pool lands **entirely on
one worker**. The knob's own caveat — no effect once total connections exceed
`conn_chunk_size * num_workers` — covers the many-client case and is exactly
wrong for the single pooled client.

The tension is real, not an oversight. Packing buys CQE batching density;
spreading buys parallelism and tail latency. Both regimes have been measured
here: the throughput work where batching paid, and the server-latency finding
where ringline lost ~28% to tokio in the idle-CPU, latency-bound case — which is
precisely where packing hurts.

This does not resolve to a single default. It resolves to **placement policy as
the configured thing**, with `conn_chunk_size` as one point in that space, and
documentation that names the regime each setting serves rather than a rule of
thumb that is hostile to pooled clients.

### 6. Rebalancing, in four tiers

Live migration of a running connection is impossible and is not proposed. The
`ConnectionTable` slot, `RecvAccumulator`, send queue and task-slab entry are
thread-local, and `Connection`, `SendHalf`, `RecvHalf` and `ConnCtx` are
`!Send` via `PhantomData<*const ()>`.

But the *connection* is not what blocks a move — the *task* is. Cheapest first:

**Tier 1 - prevent.** Place at accept time, before the connection has any
state. In pool mode that is the existing round-robin. In merged mode, a worker
accepting while over its share forwards the **raw fd** to the least-loaded
worker over the existing channel; at that point nothing exists but an integer.
One mechanism, two policies.

**Tier 2 - steer.** Take an overloaded worker out of the accept rotation via
§5. No closes, no handshakes, reversible.

**Tier 3 - park and adopt.** Move the connection to another worker without the
client noticing.

> Park starts far more moves than it completes — 94% of attempts are abandoned
> on a withdrawn offer rather than on the connection's state, and only when the
> parking worker is CPU-saturated. Measured in
> [park-abandonment-design.md](park-abandonment-design.md), which also collects
> what park structurally cannot do and the case for de-emphasising the tier.

Everything the connection *is* can move. Inside one process an fd is an integer,
so there is no `SCM_RIGHTS` dance; the accumulator is `BytesMut`; the TLS state
is a `rustls::ServerConnection`. What cannot move is the future `on_accept`
returned — it is `!Send` and `'static` and lives in worker A's `TaskSlab`.
Making it `Send` would put `Send` bounds across the whole user-facing API, which
is the thread-per-core design's entire benefit. So the future is **dropped on A
and recreated on B**, which makes park a cooperative operation at a point where
the handler holds no state it cannot hand over.

The quiesce this needs already exists. Deferred teardown is implemented and
tested — `ctx_close_defers_behind_in_flight_send`,
`close_defers_while_chain_active`, `close_while_segment_pinned_defers_bid_release`
— because Domain Invariant 1 requires waiting for in-flight sends, active chains
and pinned segments before releasing a slot. Park is that path stopped one step
early: quiesce, then hand the fd over instead of closing it. Fd movement between
workers is likewise already supported —
`register_files_update(fd_index, &[fd])` (`backend/uring/driver.rs:2380`) is how
an fd enters a worker's fixed-file table.

The gate is not new either — it is `try_finalize_close`'s predicate
(`backend/uring/driver.rs:1670`), which is already the definition of "this
connection is quiescent":

```rust
!in_flight && queue.is_empty() && forward_write.is_none() && !chain_table.is_active()
```

with the terms close does not need.

An earlier draft of this section had park *carry* held buffers: convert every
`Pinned` bid to `Owned` at move time, on the grounds that waiting for a slow
reader could make a connection permanently unparkable. **That was wrong, and
the adversarial review of the API found why.** Unconsumed bytes mean the
quiescent point the handler offered at has already passed, so carrying them
ships handler state deposited *before* a request that is now in flight — the
adopting worker gets a stale session next to a partial message. Nothing
becomes permanently unparkable either: the handler re-offers at its next idle
point and the park happens then. Park is best-effort by construction.

So the gate refuses while anything is unconsumed — accumulator, the buffer a
direct receive holds, a lent buffer in `pending_recv_bufs`, `segment_hold` or
`segment_pinned` (`ParkBlocker::DataPending`). Stating it as a property of *state* rather than
as a withdraw hook on each delivery path is deliberate: the review found two
recv paths that delivered bytes without withdrawing the offer, and a
state-based gate means the next one added fails closed instead. The refusals
are the states where the handler or the kernel is mid-operation, and the gate
names each one (`ParkBlocker`): not open or still handshaking; teardown
already requested, or a hangup error kept for the reader; queued or in-flight sends; an in-flight Mode A forward
write; an active send chain; a live `SegmentReader`; an in-flight fallback
recv.

One non-obvious exclusion. `recv_half_taken` / `send_half_taken` look like
blockers and are not: since #427 the halves are the normal API and a typical
handler holds both for the connection's whole life, so gating on them would
refuse essentially every park. They are owned by the future, which park drops
as part of the move.

Sequence: quiesce on the predicate above (a hangup peek in flight also
defers the start) → cancel the direct receive, if one is in flight, and
the hangup poll → wait until no receive, hangup poll or hangup peek is
armed and the connection is still parkable (bytes that arrived during the
cancel withdraw the offer, and the handler must offer again) → install the
fd → when the install completes, abandon the park if the install failed,
the slot now holds another connection (generation check), the gate
(`park_blocker`) refuses, or a receive, hangup poll or hangup peek is
armed; every abandon except the recycled slot gives the connection its
receive or hangup poll back → take the leftover accumulator bytes and
handler payload → close A's fixed-file slot without a shutdown → send
`(OwnedFd, leftover bytes, ListenerId, PeerAddr, handler payload, TLS state)`, all
`Send`, over the park channel (`peer_park`) → B allocates a slot,
registers the fd, seeds the accumulator, arms the hangup poll, and calls
`on_adopt`; the new task's first parked read arms a receive.

A TLS connection's session moves with it: `handle_park_install` takes its
`TlsConn` (the rustls session, and with the unbuffered engine the ciphertext
buffer with any partial record) out of A's TLS table into the `ParkedFd`, and
B installs it in its own table, marks the connection established and calls
`on_adopt` without a handshake. The drain has already ended A's receive, so
nothing is writing into the ciphertext buffer that moves.

**Park is opt-in** (owner decision, 2026-09-23). The future is dropped and
recreated, so a handler that kept anything — negotiated protocol,
authenticated identity, subscriptions — has to hand it over or rebuild it. Most
handlers keep nothing (echo, plain RESP) and would park safely by default, but
the ones that do keep state would break silently rather than loudly, and a
runtime that silently discards handler state is not a trade a default should
make. So `on_adopt` stays off the mandatory `AsyncEventHandler` surface and
only connections whose handler opts in are ever parked; everything else falls
through to tier 4 (shed) or is simply left where it is.

`on_adopt` is **optional**, and the handler payload is the new public surface:
since the future dies, anything the handler kept — negotiated protocol,
authenticated identity, subscriptions — is rebuilt or carried as an opaque
`Box<dyn Any + Send>` returned at park and handed back at adopt.

Viability is not cache-versus-web, it is **request/response versus multiplexed**:

| shape | quiescent point | payload | verdict |
|---|---|---|---|
| RESP, memcache | after every response | empty, or a DB index / auth flag | easy |
| HTTP/1.1 keep-alive | after every response | near none | easy |
| HTTP/2 | zero open streams | `H2Connection` is plain data (`ringline-h2/src/connection.rs:190`) — sans-IO, so it moves | idle connections yes, saturated no |
| HTTP/3 | — | rides `UdpSocket`, not the connection table; QUIC migrates at the protocol level | out of scope |

The h2 gate predicate is already written and public: `H2Conn::pending_count()`
(`ringline-http/src/h2_conn.rs:457`). `pending_count() == 0` is the park gate.

The requirement is also less restrictive than it first appears, because **you
park idle connections, not busy ones**. Rebalancing targets long-lived
connections, and long-lived connections are idle between bursts.

**Tier 4 - shed.** For handlers that cannot park, hang up slowly so clients
reconnect elsewhere. A hint, not an action: "graceful" is protocol-specific —
H2 has GOAWAY, H1 has `Connection: close`, raw TCP has only FIN, and a request
may be in flight. The runtime knows the load; only the handler knows what a
polite goodbye looks like.

Shed is last because it is expensive and imprecise. Each shed connection costs a
reconnect plus a full TLS handshake — the expense §7 exists to reduce — and
under an unsteered hash the replacement lands uniformly, so with 8 workers it
has a 1-in-8 chance of returning to the same worker. Park has neither problem:
nothing is client-visible, and placement is **exact** because you choose the
target worker. That is also why park, not steering, is what makes rebalance
converge.

Guardrails for tiers 3 and 4: rate limit, hysteresis so it does not oscillate,
prefer idle connections, floor on per-worker count.

**Non-goal, stated so it is not filed as a bug later.** If a worker is hot
because of *one* saturated connection, none of this helps. Park cannot — there
is no quiescent point. Shed cannot — it relocates the load and charges a
handshake for it. Rebalancing addresses **count** imbalance, not **load**
imbalance from a single heavy connection. That is inherent to thread-per-core
without work stealing.

### 7. Handshake offload as its own knob

Where handshake crypto runs is orthogonal to how connections are accepted, and
should be configured separately rather than bundled into "pool mode".

A handshake is ~2 RTT of latency plus a burst of CPU (ECDHE and a signature).
Those want opposite treatment. A pool that blocks across the RTTs needs roughly
a thread per in-flight handshake — a 1000-connection storm is 1000 threads. A
pool that goes async to avoid that is an event loop, i.e. a worker. So the
offloadable part is the CPU burst, and the tool already exists:
`blocking_threads` (default 4, `config.rs:308`) with `spawn_blocking`.
`rustls::ServerConnection` is `Send`, so moving `process_new_packets` off the
event loop and back is mechanically possible.

Two handoffs per handshake is not obviously a win. This needs a prototype and a
measurement before it is more than a knob.

## Open questions

1. ~~Does a `SO_REUSEPORT` socket excluded by a BPF selection program still
   accrue a backlog?~~ **Answered 2026-09-22: no** — zero Recv-Q, zero
   accepted (§5). Tier 2 works.
2. ~~Is unprivileged steering practical, or does useful steering need BPF
   privileges?~~ **Answered: unprivileged CBPF suffices** to exclude a worker;
   re-attach moves the target.
3. What happens to connections **already queued** on a socket when it leaves
   the rotation? They stay, so tier 2 needs a drain before any close. Not
   measured.
4. ~~Does the `tls-unbuffered` engine hold partial-record state that complicates
   moving a `ServerConnection` between workers?~~ **Answered 2026-09-23: it holds
   the state, and it moves anyway.** `UnbufferedConn`
   (`tls/unbuffered/mod.rs:133`) keeps `incoming: CiphertextBuf` — received
   ciphertext awaiting `process_tls_records`, i.e. exactly the partial records
   this asked about — plus `pending_plaintext: VecDeque<Vec<u8>>`. Both are
   plain owned data: `CiphertextBuf` is a `Vec<u8>` and three `usize`
   (`tls/ciphertext.rs:80`). The two cache fields
   (`max_plaintext_per_chunk`, `chunk_basis`) are keyed on the `SendCopyPool`
   slot size, which is uniform for every slot today, so they stay valid on the
   target worker. Verified by compiling a `Send` bound over `UnbufferedConn`,
   `CiphertextBuf` and `RecvAccumulator`, and by then adding an `Rc<u8>` to
   confirm the assertion could fail. **Tier 3 therefore needs no
   engine-specific path** — move the whole `UnbufferedConn` as one value
   rather than reconstructing it. Revisit only if TLS ever gets its own slot
   class, which would invalidate the chunk cache across workers; that is
   already flagged at the field.
5. ~~Can a `Bytes` handed out by `with_bytes` still be alive at a park
   point?~~ **Answered 2026-09-23: it can, and it is not the hazard.** The
   accumulator copies into its own `BytesMut` (`accumulator.rs:73`), so a
   `Bytes` from `with_bytes` is a refcounted slice of owned memory — `Send`,
   and dropped with the future that park discards regardless. The blocker is
   one level down: `segment_pinned[conn]` can hold
   `HeldRecvBuf::Pinned { bid, len }`, a bid index into **this worker's**
   `ProvidedBufRing`, which means nothing on the target.
   `HeldRecvBuf::Owned(Bytes)` moves fine. See the gate in §6.
6. Does any client crate need to be generic over transport (redis and memcached
   both speak Unix sockets)? Decides whether §1's transport erasure is also
   needed on the outbound side.
7. Is per-listener TLS reachable without restructuring the handshake path, or
   does `TlsConfig` need to become per-connection state?

## Measurement

**Run 2026-09-23.** Two X710 guests, one client host opening a pool against an
8-worker server, `experiments/accept-mode-ab.toml`. Distribution read as
per-core busy time from `/proc/stat` diffed across the measured window —
workers are pinned, so on *these guests* core *N* is worker *N*.

> **That mapping is environment-specific, not a property of the runtime.**
> `topology::physical_core_first_cpus()` takes the first logical CPU per
> `(package, core_id)`, so on a host that enumerates SMT siblings adjacently
> worker *W* lands on cpu *2W*. The tier-3 run below hit exactly that (a 24-vCPU
> anvil guest) and initially sampled the wrong half of the machine. Verify the
> mapping per environment, or use a statistic that does not depend on it.

### At 64 connections over 8 workers: no difference, and no information

| | throughput | worker cores busy |
|---|---|---|
| pool | 294,321 ops/s | 8/8, 71.5–81.8% |
| merged | 294,447 ops/s | 8/8, 71.6–82.2% |

That looks like a clean pass and is worth nothing. At N=64 over W=8 the
kernel's hash leaves a worker idle with probability about 0.2%, so this run
cannot distinguish placement working from placement doing nothing. It is the
"measured from N independent clients" mistake in another form: the topology was
right, the *scale* was not.

### At 8 connections over 8 workers: merged leaves workers idle

Worker-core busy %, three interleaved reps each:

| rep | pool | merged |
|---|---|---|
| a | 31.9 42.9 32.1 32.0 30.9 30.1 31.7 29.6 | 31.6 42.6 35.6 32.3 **4.8** 30.6 **4.0** 39.1 |
| b | 35.0 32.6 30.1 30.4 32.0 49.2 29.1 27.4 | 39.5 **2.5** 27.1 26.5 35.6 38.9 34.6 **8.1** |
| c | 30.5 28.3 23.9 24.7 30.6 29.5 29.8 37.0 | 40.0 37.9 **4.1** 35.7 29.4 39.2 39.4 **4.3** |

**Pool leaves no worker idle, 3/3. Merged leaves exactly two idle, 3/3** — a
different pair each time, so it is the hash rather than a fixed bug. Two of
eight is what (1-1/W)^W predicts.

### After the fix (2026-09-23)

`HANDOFF_MARGIN` drops to 1 when the quietest worker is idle (#457). Nine
interleaved reps per arm, same harness, same N=W=8. The idle threshold was
fixed at 10% busy *before* the data was read, justified by the pre-fix numbers
— idle cores sat at 2.5–8.1% against 24–49% busy, so the line falls in a wide
empty gap rather than being a knob to turn afterwards.

| arm | reps | min | max | median | median spread | idle (<10%) |
|---|---|---|---|---|---|---|
| pool | 9 | 24.6 | 53.3 | 30.6 | 13.5 | **0** |
| merged | 9 | 23.2 | 63.8 | 30.8 | 13.1 | **0** |

**Merged now leaves no worker idle, 9 of 9**, against 2 idle in 3 of 3 before.
Spread and median match pool's within noise. Both arms throw the occasional
high outlier (pool 53.3, merged 63.8), so that is the rig, not the mode.

This clears the distribution half of the default-mode decision. Connect rate was
unmeasured at this point; see "Connect rate (2026-11-06)".

### Tier 3 park: converges a standing imbalance, ~free when balanced (2026-09-25)

`experiments/park-imbalance.toml` and `experiments/park-balanced.toml`. Anvil
guests, 8 workers, 256 held connections, 64 B closed loop at depth 1, n=3 per
arm. Full write-up and the harness faults that had to be fixed first:
[docs/journal/2026-09-tier3-park.md](journal/2026-09-tier3-park.md).

The imbalance is manufactured, because tier 1 leaves nothing for tier 3 to do in
a healthy fleet: steer workers 4–7 out of the accept rotation, establish all 256
connections on workers 0–3, readmit with no new arrivals.

| | park off | park on |
|---|---|---|
| loaded cores, before → after readmit | 4 → 4 | 4 → **8** |
| converges? | **never**, 66 s observed | **yes, 11 / 18 / 18 s** |
| steady ops (t=60–90) | 377,958 ±1.1% | 592,446 ±2.6% — **+56.7%** |
| `park_completed` = `adopted` | 0 | 264 / 310 / 191 |

The control carries the result: workers 4–7 stay at 13–15% busy for the full 66 s
after readmit, so the imbalance does not self-repair. Rezolus per-vCPU at 1 s
resolution gives the curve — readmit at t=30, idle half 0.15 → 0.49 → 0.97 by
t=42, pinned at 1.00 after, with the originally-hot half at 1.00 throughout.
Park *adds* capacity rather than shuffling it.

With no imbalance (`--park-imbalance-ms 0`), park costs nothing resolvable:

| | park off | park on | on − off |
|---|---|---|---|
| steady ops | 592,739 ±3.6% | 585,640 ±2.3% | −1.2% |
| p50 | 420.7 µs ±3.1% | 422.3 µs ±3.4% | +0.4% |
| p99 | 753.8 µs ±4.9% | 764.0 µs ±7.0% | +1.3% |

Pooled spread across the six balanced runs is 4.1%, so this bounds the penalty
below ~4% rather than showing zero. The balanced 8-worker ceiling (592,739) and
converged park (592,446) agree within 0.05%: park recovers the full headroom.

Two caveats on reading these numbers. Closed loop at fixed concurrency means
`ops = 256/latency` (holds to <2% on all twelve runs), so throughput and latency
are one measurement and no throughput ceiling exists independent of latency.
And because all 256 connections were identical saturating echoes, connection
count and worker busyness were the same signal — this run cannot distinguish the
count-based policy from a busyness-based one. See the journal entry's open
questions.

### Spreading a fixed load costs per-operation efficiency (2026-09-28)

`experiments/coalesce-sweep.toml`. 600k offered in open loop, 256 connections held,
park off, no manufactured imbalance — **worker count is the only variable**, and
every run serves the same 600k ops/s.

| workers | conns/worker | CQE/op | CPU (cores) | p50 | p99 | p999 |
|---|---|---|---|---|---|---|
| 2 | 128 | **0.44** | 4.83 | 3206.9 | 6093.5 | 6707.4 |
| 4 | 64 | **0.86** | 7.73 | 1530.8 | **2601.9** | 6950.1 |
| 8 | 32 | **1.78** | 12.88 | 767.4 | 18945.9 | 58455.1 |
| 16 | 16 | 1.76 | 18.04 | **734.6** | 14210.8 | 67657.6 |

> **CQE/op was overstated by 5.6% in every earlier revision of this section, and
> the figures above are corrected.** `ring.cqe_processed` is a server counter
> covering warmup *and* run; `total_ops` is a client counter covering the run
> only. With `--warmup 5 --duration 90` the windows differ by 95/90 = 1.0556, and
> the measured ratio of server messages (`bytes.received / msg_size`) to client
> ops is 1.0557–1.0558 in all nine cells checked — the warmup, to four digits.
> The corrected denominator is server-side (`bytes.received / msg_size`), so
> numerator and denominator cover the same window.
>
> The bias is a uniform multiplicative factor, so **no relative comparison in this
> section changes** — the separations, the CVs and the 30/30 result all stand.
> What changes is the reading of the ceiling: the largest value yet measured,
> `(300k, w4)`, corrects from 2.12 to **2.008**, landing *on* the predicted 2.0
> rather than impossibly above it. That is independent support for the ceiling
> being exactly one recv plus one send completion per echo.
>
> Earlier revisions quoted 0.47 / 0.91 / 1.88 / 1.86 for this table and 1.64–1.95
> for the 8-worker replicates; multiply any CQE/op figure elsewhere in the session
> record by 1/1.0556 to compare.

> **`w16` oversubscribes this guest and its row is confounded.** The guest has 24
> logical CPUs on **12 physical cores** (adjacent SMT siblings), and ringline pins
> SMT-aware — one worker per *physical* core. Sixteen workers therefore place four
> pairs on shared physical cores. The Rezolus per-vCPU recording confirms it: at
> `(600k, w16)` sixteen logical CPUs are busy at 0.98–1.00 where only twelve
> physical cores exist. So that row measures *spreading plus SMT contention*, not
> spreading, and its tail is the contention: p99 is 11,912us at 600k against
> 1,250us at 300k on the same sixteen workers, where the lower rate leaves slack
> to absorb it. **Read `w2`/`w4`/`w8` as the clean series and treat `w16` as
> indicative only** — in particular, "CQE/op flattens against the ceiling above
> `w8`" rests partly on this point and is not established by it.
>
> The same recording corrects a second thing. At 600k **every** arm has all of its
> workers pinned at 1.00 — `w2` two cores, `w4` four, `w8` eight, `w16` sixteen —
> so the CPU cost of spreading is close to *linear in worker count*, not merely
> the 4x that CQE/op shows. And per-worker CPU barely responds to load: halving the
> rate takes a `w4` worker from 1.00 to ~0.94 and a `w16` worker from ~0.99 to
> ~0.82. A worker burns most of a core almost regardless of how much work it has,
> which means fixed per-loop cost — not per-operation cost — dominates what
> spreading actually charges.
>
> (This also kills an inference made while reading the matrix: that 37.5k ops/s per
> worker at `w16` meant low utilisation. Those workers were saturated. Per-worker
> *rate* does not imply per-worker *utilisation* when both the per-operation cost
> and the fixed loop cost move with worker count.)

> **And a pinned worker is not a worker at capacity.** Holding the worker count at
> 2 and sweeping offered load gives, per worker, 150k / 300k / 600k ops per second
> at **1.00 CPU in every case**:
>
> | offered | ops/s/worker | worker CPU | ops per worker-CPU-sec | CQE/op | p50 | p99 |
> |---|---|---|---|---|---|---|
> | 300k | 150,000 | 1.00 | 150,436 | 1.04 | 2535us | 5772us |
> | 600k | 300,000 | 1.00 | 300,034 | 0.46 | 3095us | 6304us |
> | 1.2M | 600,000 | 1.00 | 600,114 | 0.17 | 5730us | 111,739us |
>
> Four times the work per CPU-second, on the same two cores, at the same
> utilisation — because coalescing cuts completions per operation from 1.04 to
> 0.17 (one completion carrying ~12 requests at the top). Two claims made earlier
> in this session are wrong as a result: that `w2` at 600k was "right at the edge"
> of capacity (it had 2x headroom), and that a worker has a fixed completion
> budget from which ops-per-CPU-second follows. **Utilisation says nothing about
> headroom here**, because the efficiency is itself a function of load.
>
> The cost is the tail, and it is not gentle: p50 grows 1.8x across that range
> while p99 grows **19x**, almost all of it in the final doubling. That is the
> same trade the worker-count series shows, driven from the other axis — and it is
> why "read the shape, not the row" applies to the offered rate as much as to the
> worker count. A `w4` knee at 600k is a `w8` knee at 1.2M.
>
> Softirq is worth noting alongside it: non-worker CPU on the same host goes 2.08
> → 2.83 → 4.84 cores across those three rates, so by 1.2M the kernel network path
> costs more than the runtime's own workers do. Any per-operation accounting that
> stops at the worker threads is missing the larger half.

Completions per operation **halve with every halving of the worker count**, then
flatten against a ceiling of ~2.0 — one recv and one send completion per echo
request, which is what "no batching at all" costs. At 128 connections per worker
multishot recv is carrying more than four requests per completion.

CPU tracks it: **two workers serve the same throughput on a quarter of the CPU of
sixteen.**

### Why that is the sizing

The batching is a *consequence of queueing*, which is why the two move together.
Per-connection arrival rate is identical across the sweep (256 connections, fixed
600k) — what changes is per-worker service rate. A worker carrying 300k ops/s
returns to each connection less often, so more requests accumulate between visits,
so more arrive in one TCP segment and one completion carries several requests. A
worker carrying 37k ops/s reaches each arrival immediately and pays a completion
for each.

So the knee is not a property of "64 connections". It is where per-worker load
stops producing accumulation, and it moves with per-connection request rate,
pipelining depth and per-request cost. **Do not read `w4` as an optimum to
configure for**; read the shape.

#### A competing explanation this sweep cannot rule out

The paragraphs above name per-worker service rate as the cause. There is a
second candidate that fits the same four points at least as well, and the sweep
is confounded with respect to it: **provided recv buffers per connection.**

`recv_ring_size` is *per worker* and was fixed at 256 for every arm, so changing
the worker count changed buffers-per-connection by the same factor it changed
connections-per-worker:

| workers | conns/worker | buffers/conn | CQE/op | `min(buffers_per_conn / 4, 1.88)` |
|---|---|---|---|---|
| 2 | 128 | 2.0 | 0.47 | 0.50 |
| 4 | 64 | 4.0 | 0.91 | 1.00 |
| 8 | 32 | 8.0 | 1.88 | 1.88 |
| 16 | 16 | 16.0 | 1.86 | 1.88 |

The mechanism would be the buffer ring rather than the clock: a recv CQE checks
out a provided buffer and the *application* returns it, so when buffers per
connection get low the ring dries, `ENOBUFS` parks the multishot recv, bytes
accumulate in the socket buffer, and the recv that follows replenishment carries
several requests. That is the same observable coalescing, from a cause that has
nothing to do with how busy the worker is.

The two are perfectly correlated here — fewer workers means both more load per
worker *and* fewer buffers per connection — so **this sweep does not distinguish
them, and the mechanism paragraphs above should be read as one of two candidate
explanations, not as established.** The fitted column is four points against a
post-hoc formula; it is offered as motivation for the test, not as a result.

##### Refuted, by counters already in the artifacts (2026-09-28)

The buffer-ring explanation above is **wrong**, and the runs that were going to
test it were not needed: the existing artifacts already carry the counter that
settles it. `pool.recv_parked` counts exactly the event the mechanism requires —
a multishot recv completing `ENOBUFS` because the provided ring is empty — and
`pool.buffer_ring_empty` counts the ring running dry:

| workers | buffers/conn | CQE/op | `recv_parked` | `buffer_ring_empty` |
|---|---|---|---|---|
| 2 | 2.0 | 0.47 | 71 | 71 |
| 4 | 4.0 | 0.91 | **0** | **0** |
| 8 | 8.0 | 1.88 | 0 | 0 |
| 16 | 16.0 | 1.86 | 0 | 0 |

The `w4` arm coalesces heavily — 0.91 means a completion carries more than one
request — with the ring **never once** running dry. And `w2`'s 71 park events
span a 90-second run carrying ~54 million operations, which cannot move an
aggregate ratio at all. So ring exhaustion is not the mechanism at any arm; the
numeric fit in the table above was four points against a formula chosen after
seeing them, and it was coincidence.

**Per-worker load survives as the explanation**, which is what the section said
before the detour. The correct reading of that is *unwelcome*: it means the
batching cannot be bought at full spread by sizing the ring, and concentration
really does appear to be required to get it.

##### And refuted again by direct experiment, with the reason (2026-09-28)

One arm of the ring sweep was kept as a positive control — `recv_parked = 0`
everywhere is also exactly what a dead counter looks like — and it settles the
question outright. 8 workers, 32 connections per worker, `recv_ring_size` cut 8x
from 256 to **32**, i.e. 1.0 provided buffer per connection:

| | b32 | baseline (b256) |
|---|---|---|
| ops/s | 600,007 | 599,978 |
| CQE/op | **1.71** | 1.64 |
| p50 | 1058.7us | 920.5us |
| `recv_parked` | 285 | 0 |
| `buffer_ring_empty` | 285 | 0 |
| `recv_fallback` | **35,949,657** | 0 |

The control passes: the ring genuinely dries and the counter genuinely responds,
so the zeros above are real zeros. And an **8x smaller ring bought no coalescing
whatsoever**: 1.71 sits *inside* the baseline configuration's own run-to-run
range of 1.64–1.95 (see the noise floor below), so there is no detectable effect
at all. Throughput is unaffected (600,007 ops/s), so the arm is not
memory-starved and the comparison is valid; buffers-per-connection simply is not
the lever.

The p50 difference (1058.7us against 920.5us) is **not** a result — it is inside
a 32.8% latency floor and is withdrawn.

`recv_fallback` explains why it never could be. ~36M fallback recvs against ~54M
operations means two thirds of operations took the graceful-degradation path:
**when the provided ring is dry, ringline submits a one-shot recv to keep
draining the socket** rather than leaving the connection parked. Socket-buffer
accumulation — the thing the hypothesis needed — is precisely what that path
exists to prevent. The mechanism was not merely unsupported by the data, it is
excluded by the design, and the counter says so by name.

The same applies to `min_complete`, tested at 1/2/4/8 on this configuration:
CQE/op 1.64, 1.65, —, 1.79 with `recv_parked` and `buffer_ring_empty` at 0
throughout. That span is 8.8%, less than half the 18.6% floor, so the correct
statement is **indistinguishable from flat**, not measured flat. Blocking the
reaper for a few completions checks out a handful of buffers against 256 and
never approaches the ring, so there was nothing for it to induce. **Both
candidate ways of buying batching without concentration are dead**, and
per-worker load stands as the explanation.

##### The noise floor, and which comparisons survive it

**Five** runs of one configuration — 8 workers, 256-buffer ring, `min_complete`
1, same binary, landing as arms of three different sweeps:

**Six** runs of one configuration — 8 workers, 256-buffer ring, `min_complete`
1, same binary, landing as arms of three different sweeps:

| replicate | CQE/op | p50 | p99 |
|---|---|---|---|
| A | 1.64 | 920.5us | 10,154us |
| B | 1.81 | 767.8us | **46,162us** |
| C | 1.86 | 777.3us | 10,888us |
| D | 1.93 | 707.2us | 9,208us |
| E | 1.94 | 695.4us | 27,131us |
| F | 1.95 | 693.1us | 16,967us |

| metric | min | max | mean | stdev | CV | spread |
|---|---|---|---|---|---|---|
| ops/s | 599,978 | 600,005 | — | — | — | 0.005% |
| CQE/op | 1.64 | 1.95 | 1.86 | 0.116 | 6.3% | **18.6%** |
| p50 | 693.1us | 920.5us | 760.2us | 86.6 | 11.4% | **32.8%** |
| p99 | 9,208us | 46,162us | 20,085us | 14,428 | 71.8% | **401.3%** |

Offered load is reproduced to five figures; everything derived from timing is
not. **Read the CV column, not the spread column.** Spread is `(max-min)/min`,
which can only grow as samples accumulate — it is monotonically non-decreasing by
construction, so its growth across sample sizes says nothing about the underlying
distribution. An earlier revision of this section made exactly that mistake,
quoting p99 spread going 67% → 84% → 195% → 401% as evidence of a heavy tail and
concluding that "no number of runs" could make the comparison safe. Both halves
were wrong: the growth was an artifact of the statistic, and more runs is
precisely the remedy. For the record the p99 CV over the same accumulation ran
35.5% → 35.0% → 29.7% → 50.4% → 71.8% — declining until the last two draws.

What the numbers do support: CQE/op is stable (CV 6.3%), p50 is moderately noisy
(CV 11.4%), and p99 is very noisy (CV 71.8%, 9.2ms to 46.2ms across identical
runs). Single-run comparisons are safe for the first, marginal for the second and
unsafe for the third — but "unsafe single-run" means *take replicates*, not
"unusable".

This has to be applied to every claim in this section:

- **Survives.** The worker-count shape in CQE/op and CPU: 0.47 / 0.91 / 1.88 /
  1.86 spans 4x against an 18.6% floor, and CPU 4.83 → 18.04 cores spans 3.7x.
  These are the results this section rests on.
- **Survives.** The p50 trend, 3206.9 → 1530.8 → 767.4us across `w2` → `w4` →
  `w8`: 2x steps against a 32.8% floor.
- **ESTABLISHED: the p99 advantage at `w4`.** Five `w4` replicates against six
  `w8` replicates, same binary, same 600k offered rate:

  | | CQE/op | p50 | p99 |
  |---|---|---|---|
  | `w4`, n=5 | 0.86 0.87 0.87 0.88 0.94 | 1470 1560 1575 1584 1590us | 2511 2582 2673 2731 2797us |
  | `w8`, n=6 | 1.64 1.81 1.86 1.93 1.94 1.95 | 693 695 707 768 777 921us | 9208 10154 10889 16967 27131 46162us |

  **Complete separation on all three**: `w4` below `w8` in 30/30 cross pairs on
  CQE/op and on p99, and above in 30/30 on p50. Exact two-sample probability of
  complete separation under a null of no difference is 1/C(11,5) = **0.0022**.

  So the trade is real and both directions of it are established: spreading a
  fixed load buys p50 (1556us → 760us) and pays for it in per-operation cost
  (CQE/op 0.88 → 1.85), CPU, and the tail (p99 2659us → 20085us).

##### The variance is a property of the configuration, not the rig

The more useful finding from those replicates is that **the two configurations
are not equally reproducible**:

| metric | `w4` CV (n=5) | `w8` CV (n=6) | ratio |
|---|---|---|---|
| CQE/op | 3.6% | 6.4% | 1.8x |
| p50 | 3.2% | 11.4% | 3.6x |
| p99 | **4.3%** | **71.8%** | **16.7x** |

`w4`'s tail is tight — p99 2511–2797us across five runs — while `w8`'s ranges
from 9.2ms to 46.2ms. The distribution shapes differ accordingly: mean p99/p50 is
**1.71 at `w4` and 26.4 at `w8`**.

Two consequences. First, an earlier revision of this section derived a noise floor
from `w8` replicates alone and stated it as a rig-wide rule ("a single-run CQE/op
difference under ~15% is not a result"). That was an over-generalisation from one
operating point: `w4` reproduces CQE/op to 3.6%. A floor has to be quoted with the
configuration it was measured at.

Second, and more substantively: the heavy tail is not measurement noise to be
averaged away, it *is* the `w8` result. Spreading the load does not merely raise
p99, it makes p99 **unpredictable** — which is a worse property for anything with
a latency objective than a higher but stable tail would be.
- **Survives**, because it is categorical rather than a magnitude: every
  `recv_parked` / `buffer_ring_empty` / `recv_fallback` comparison. Zero versus
  285, and zero versus 36 million, are not noise.
- **Does not survive.** `w8` versus `w16` on p99 (14210.8 vs 18945.9, 33%) and
  on p50 (734.6 vs 767.4, 4%). The `w16` row cannot be said to differ from `w8`
  on latency at all, so "p50 is best at full spread" rests on the 2x steps below
  `w8`, not on that last row.
- **Does not survive.** Anything at all from the `min_complete` sweep, and the
  b32 p50. The completed sweep is:

  | `min_complete` | ops/s | CQE/op | p50 | p99 | `recv_parked` |
  |---|---|---|---|---|---|
  | 1 | 599,978 | 1.64 | 920.5us | 10,154us | 0 |
  | 2 | 600,005 | 1.65 | 933.6us | 6,035us | 0 |
  | 4 | 600,002 | 1.78 | 804.4us | 24,727us | 0 |
  | 8 | 600,004 | 1.79 | 824.1us | 11,935us | 0 |

  Every arm falls inside the baseline's own 1.64–1.95 range, and the whole span
  is 8.8% against a 0.128 standard deviation — about one sigma.

  **`min_complete` is not exposed in the tree.** It was measured with an
  unmerged experimental patch adding a `wait_min_complete` config knob, kept off
  `main` precisely because the result was NO-GO: there is no flag to look for, and
  nothing to tune. The syscall counters later explained why it could not have
  worked — `w8` was already reaping ~23 completions per `io_uring_enter` unaided,
  so asking it to wait for 8 was asking for a third of the batch the loop already
  achieved. One oddity worth
  recording rather than interpreting: CQE/op is monotone increasing across the
  four arms, which has a ~4% chance under random ordering. But the values pair up
  (1.64, 1.65) and (1.78, 1.79) more like two machine states than a trend, the
  magnitude is inside the floor, and the *direction is opposite* to any mechanism
  — more blocking producing **less** batching is not something to explain. It is
  noted so the next person does not rediscover it and read it as signal.

`b256`'s 1.95 also lands on the original 1.88 reference, so the two sweeps are
mutually comparable — an earlier note claiming the `n=1` arm failed to replicate
was reading an 18.6% floor as a 13% discrepancy.

The practical rule, on this rig and this workload, stated in CVs because those
are the sample-size-independent numbers: CQE/op CV 6.3%, p50 CV 11.4%, p99 CV
71.8%. So a single-run CQE/op difference under ~15% is not a result, a p50
difference under ~25% is not a result, and a p99 difference wants replicates on
both sides at any magnitude under ~3x. Where only one side has been replicated,
say so and give the one-sided reading rather than either asserting or withdrawing
the claim.

##### Separated, by splitting the completion counter (2026-09-28)

`experiments/tag-split.toml`, on a build carrying `ringline/cqe_by_tag` (the
completion counter split by `OpTag`). The question below — whether the coalescing
is recv-side, send-side or both — is answered: **both, by the same factor.**

| arm | CQE/op | recv/op | send/op | other/op |
|---|---|---|---|---|
| `w4` rep1 | 0.828 | 0.418 | 0.408 | 0.003 |
| `w4` rep2 | 0.798 | 0.401 | 0.394 | 0.003 |
| `w8` rep1 | 1.759 | 0.899 | 0.850 | 0.010 |
| `w8` rep2 | 1.633 | 0.842 | 0.783 | 0.009 |
| **`w4` mean** | **0.813** | **0.409** | **0.401** | 0.003 |
| **`w8` mean** | **1.696** | **0.871** | **0.817** | 0.010 |
| **ratio** | **2.09x** | **2.13x** | **2.04x** | — |

Both halves roughly double from `w4` to `w8`, and within each arm recv/op and
send/op are nearly equal. That pins the mechanism exactly: the forward echo path
sends each received buffer back as **one** `send_recv_buf`, so a buffer carrying
*k* pipelined requests costs one recv completion and one send completion —
`CQE/op = 2/k`, with `recv/op = send/op = 1/k`. The 2.0 ceiling is *k*=1, and
everything below it is queue depth. It was never recv batching *or* send
coalescing; it is one buffer, one recv, one send, *k* requests.

Only seven tags are non-zero, and three of them settle other questions:

| tag | `w4` /op | `w8` /op |
|---|---|---|
| `recv_multi` | 0.4178 | 0.8419 |
| `send_recv_buf` | 0.3980 | 0.7242 |
| `send` | 0.0097 | 0.0586 |
| `tick_timeout` | 0.0026 | 0.0088 |
| `accept_multi`, `close`, `event_fd_read` | ~0 | ~0 |

- **`recv_fallback` is absent**, so recv is entirely multishot. That corroborates
  `recv_parked = 0` from an independent counter, and the ring-exhaustion refutation
  above now rests on two measurements rather than one.
- **Sends are slightly fewer than recvs** (0.398 against 0.418). In `forward` mode
  a recv delivering a partial message waits for more before echoing, so two recvs
  occasionally feed one send. The plain `send` fallback grows 6x at `w8` and is
  still only 0.06/op.
- **`tick_timeout` is negligible and fires *less* than configured** — 145,928
  firings against the 360,000 that 1000/s/worker over 90 s on 4 workers would give,
  because the loop is almost always woken by a real completion first. A third,
  measured confirmation that `tick_timeout_us` was never the batching lever.

All four arms pass the partition check exactly (`sum(cqe_by_tag) +
cqe_unknown_tag == cqe_processed`, zero unknown in every arm), so the split is
arithmetic rather than inference. Two replicates per worker count, and the two
halves scale by 2.13x and 2.04x — indistinguishable from each other given the
3.6% within-config CV, and both indistinguishable from the 2.09x that CQE/op
itself moves.

##### What was not separated before this

`CQE/op` conflates two completions — one recv and one send per echo, which is
where the ~2.0 ceiling comes from — and the arms are consistent with *both*
halves falling together (0.91 ≈ 0.5 + 0.5, 0.47 ≈ 0.25 + 0.25). A busier worker
would plausibly do both: carry more requests per recv completion *and* coalesce
more queued sends per loop iteration. Those are different levers with different
fixes, and this measurement cannot tell them apart.

It cannot be told apart from the current artifacts either, because there is no
per-`OpTag` completion counter — `ring.cqe_processed` is a single total. Adding
recv-completions and send-completions as separate counters is the prerequisite
for any further work here, and is cheap: `dispatch_cqe` already has the `OpTag`
in hand. Until then, "spreading costs per-operation efficiency" is the solid
claim and every statement about *why* is underdetermined.

This is already known on the client side of the same repo. `bench-client`'s
`--conn-chunk-size` exists precisely to pack connections onto fewer workers,
"keeping per-worker CQE density high enough for io_uring batching to pay off".
Tier 1 placement does the opposite on the server side, by design.

### The coalescing is the queue (2026-09-28)

`experiments/rate-workers.toml`. The section above swept worker count at one
offered rate. Sweeping *both* — 300k / 600k / 1.2M against 2 / 4 / 8 / 16 workers,
256 connections throughout — collapses the whole picture onto one variable, and it
is not the one the section above was looking for.

| offered | wkrs | worker CPU | total CPU | softirq | CQE/op | p50 | p99 | in flight per conn |
|---|---|---|---|---|---|---|---|---|
| 300k | 2 | **1.00** | 4.08 | 2.08 | 1.04 | 2535us | 5772us | 3.0 |
| 300k | 4 | 0.94 | 6.70 | 2.93 | 2.01 | 620us | 1255us | 0.7 |
| 300k | 8 | 0.83 | 9.42 | 2.81 | 2.03 | 525us | 1201us | 0.6 |
| 300k | 16 | 0.76 | 13.64 | 1.50 | 2.05 | 578us | 1250us | 0.7 |
| 600k | 2 | **1.00** | 4.83 | 2.83 | 0.46 | 3095us | 6304us | 7.3 |
| 600k | 4 | **1.00** | 7.73 | 3.73 | 0.84 | 1556us | 2659us | 3.6 |
| 600k | 8 | **1.00** | 12.88 | 4.89 | 1.78 | 760us | 20085us | 1.8 |
| 600k | 16 | 0.96 | 17.71 | 2.34 | 1.70 | 727us | 11912us | 1.7 |
| 1.2M | 2 | **1.00** | 6.84 | 4.84 | 0.17 | 5730us | 111739us | 26.9 |
| 600k | 4 | **1.00** | 7.73 | 3.73 | 0.87 | 1508us | 2524us | 3.5 |
| 1.2M | 4 | **1.00** | 9.67 | 5.67 | 0.30 | 4455us | 556500us | 20.9 |
| 1.2M | 8 | **1.00** | 14.94 | 6.95 | 0.54 | 150288us | 1051204us | 704 |
| 1.2M | 16 | **1.00** | 19.87 | 3.89 | 0.95 | 1290515us | 28749460us | 3900 |

`in flight per conn` is Little's law — `offered_rate x p50 / connections`.

**Worker CPU is the predictor, and coalescing is queue depth.** Every arm with a
worker below 1.00 sits at the ~2.0 ceiling with *under one* request in flight per
connection: no queue, so nothing to batch. Every arm at 1.00 has a queue, and
CQE/op falls in step with how deep it is — 0.7 → 3.0 → 3.6 → 7.3 → 26.9 in
flight against 2.01 → 1.04 → 0.84 → 0.46 → 0.17 completions per operation.

That correspondence is mechanically necessary rather than fitted: if a connection
has *k* requests waiting, one `recv` completion delivers all *k*, so completions
per operation go as 1/*k*. **The per-operation efficiency and the latency are two
views of the same queue.** The efficiency is not a win that spreading forfeits —
it is what a saturated worker does instead of keeping up, and it cannot be bought
without buying the latency.

#### It is not cache topology

The obvious hardware story — Zen 1 groups cores into 4-wide CCXs sharing an L3, so
4 workers fit one CCX while 8 straddle two — is wrong, and the 300k row rules it
out: `w4`, `w8` and `w16` are indistinguishable there (CQE/op 2.01 / 2.03 / 2.05,
p99 1255 / 1201 / 1250us). A CCX penalty would appear at every rate. This one
appears at no rate; what appears at 600k is a queue.

What does bite is **total CPU demand against the physical core count**. The guest
is 24 logical on **12 physical** cores, and demand is roughly
`workers x 1.0 + softirq(rate)` — with softirq the growing term: 2.08 → 4.89 →
6.95 cores as offered rate rises, so by 1.2M the kernel network path costs more
than the runtime's own workers. At 600k, `w4` needs 7.73 cores and fits; `w8`
needs 12.88 and `w16` needs 17.71, so both spill onto shared SMT siblings. That is
the leading explanation for `w4` being the p99 optimum at 600k — **not** a hardware
sweet spot, but the largest worker count that still fits the machine while being
saturated enough to coalesce.

Offered as the leading explanation rather than a proven one, because it needs two
conditions and not one: `(300k, w16)` also exceeds 12 cores (13.64) with no tail
penalty, since its workers have slack to absorb the contention.

#### The 12-core boundary, measured

The 1.2M row is not a trade at all, and it locates the boundary precisely. The
guest has **12 physical cores**; every worker is pinned at 1.00 in all four arms:

| 1.2M offered | achieved | worker CPU | softirq | **total** | fits 12? | p50 | p99 |
|---|---|---|---|---|---|---|---|
| `w2` | 100% | 1.00 | 4.84 | **6.84** | yes | 5730us | 111,739us |
| `w4` | 100% | 1.00 | 5.67 | **9.67** | yes | **4455us** | 556,500us |
| `w8` | 99.8% | 1.00 | 6.95 | **14.94** | no | 150,288us | 1,051,204us |
| `w16` | **90.5%** | 1.00 | 3.89 | **19.87** | no | 1,290,515us | 28,749,460us |

**p50 jumps 34x exactly where total demand crosses the physical core count** —
9.67 cores fits and costs 4.5 ms; 14.94 does not and costs 150 ms. Nothing else in
the row changes discontinuously there.

The effect is **graded, not a step**, which is what makes it credible: at 600k,
`w8` needs 12.88 cores — barely over — and its p50 is still healthy at 825us while
its p99 is already blown at 35,568us. Crossing the boundary damages the tail first
and reaches the median only well past it, which is how occasional contention should
behave. (At 600k, `w8` and `w16` cannot be ordered against each other on p99: the
`w8` figure sits inside the 9,208–46,162us range its own six replicates span.)

**Two workers beat sixteen by 226x on p50, and sixteen cannot serve the load at
all.** Concentration is not merely cheaper here; spreading is the thing that
breaks. Tier 1/2/3 exist to spread connections across workers, and in this regime
that is the harmful direction — worth stating plainly in the design doc that
proposes them.

Note what this makes of worker-count advice: the useful limit is not a worker count
but `workers + softirq(rate) <= physical_cores`, and **softirq is the term that
moves** — 4.84 to 6.95 cores across this row alone, exceeding the runtime's own
workers at every arm below `w8`. A recommendation phrased in worker counts is
implicitly a recommendation about packet rate.

#### A methodological correction

`(1.2M, w8)` served **99.8%** of its offered rate while running a 150 ms p50 with
~704 requests in flight per connection. An earlier version of the spec gated
validity on achieved rate at >=95%, and that arm passed it while being nowhere near
a usable operating point. **In open loop, meeting the offered rate does not mean
unsaturated** — a saturated server grows a queue instead of missing the target. The
gate is now queue depth from Little's law, read alongside worker CPU, since a
worker below 1.00 cannot be the cause of a queue.

### The trade, and whether placement should compensate

The latency shape is monotone with a knee, and it is the opposite of what
"balanced is better" predicts:

- **p50 improves all the way**: 3207 → 1531 → 767 → 735 µs
- **p99 improves to 4 workers** (6094 → 2602), then collapses (→ 18946)
- **p999 is flat to 4 workers** (6707, 6950), then explodes (→ 58455)

Past the knee you buy ~30 µs of p50 for a 7x worse p99 and an 8x worse p999.
Saturated-and-queued gives a worse median and a much tighter tail; fully spread
gives the best median and a far worse tail.

Three responses, none of them yet measured:

1. **Pack rather than spread** — fill workers toward a target utilisation and
   leave the rest idle, recruiting more only as load rises. Maximises batching,
   minimises CPU, and on this data gives better tails. The risk is that a worker
   near saturation has no headroom for a burst, so the tail it protects in steady
   state is the tail it would wreck on arrival spikes. It also contradicts the
   thread-per-core premise of using every core.
2. **Decouple batching from queueing** — keep spreading, but let a lightly loaded
   worker accumulate arrivals deliberately. This is the only option that might get
   the batching benefit without the queueing cost, and it is the one worth
   measuring first.

   The lever is **`min_complete`**, not `tick_timeout_us`. An earlier draft of
   this section named the latter, wrongly: `tick_timeout_us` bounds how long
   `submit_and_wait` blocks *when there is nothing to do*, so it never delays a
   completion that has already arrived and cannot affect batching. The loop always
   calls `submit_and_wait(1)`, returning on the first CQE; waiting for N
   completions or a timeout (`IORING_ENTER_EXT_ARG`) is the interrupt-coalescing
   shape that would actually accumulate arrivals. Multishot recv delivers whatever
   is in the socket buffer when it fires, so not reading for a while genuinely does
   put more requests in each completion — the same mechanism as the queueing
   above, induced on purpose.

   Note what the sweep cannot separate: batching there arrived *bundled with*
   load, so "delay causes batching" and "load causes both" are not distinguished
   by it. A fixed `min_complete` sweep at 8 workers is the test — if CQE/op falls
   toward 0.9 while p50 stays under the 4-worker figure, the premise holds and an
   adaptive version is worth designing. If it only adds latency, the premise is
   wrong and no controller would help.
3. **Document and let the operator choose** worker count for the statistic they
   serve. The minimum, and what this section does.

### What this does not establish

The CQE/op and CPU columns repeat to within ~4–10% across runs of an identical
configuration and can be relied on. **The tail columns cannot, single-run**: two
runs of the 8-worker configuration gave p99 9,041 µs and 18,945 µs, a factor of
two. So the 4-vs-8 comparison (7x on p99) is far outside that spread and worth
believing; 8-vs-16 is inside it and means nothing here. A dedicated noise-floor
measurement is the prerequisite for any finer tail claim, and several tail deltas
quoted earlier in this effort were made without one.

One workload, one box: 256 connections, 64 B echo, open loop at a fixed rate, on a
24-vCPU guest with 12 physical cores. The 16-worker point also oversubscribes the
physical cores, which is a second effect confounded with the first — note that
CQE/op is flat from 8 to 16 while CPU still climbs 40%, so that CPU is contention
and scheduling rather than completions.

### Conclusion

**Merged accept mode stays behind its flag** — though the distribution defect
below was fixed in #457; see "After the fix" above. As first measured, tier 1's
accept-time handoff did not fix the case it was built for. The mechanism is visible in its own
constants: a worker sheds only when it is `HANDOFF_MARGIN` (2) ahead of the
quietest, but at N≈W most workers hold 0 or 1 connection, so a worker holding 2
sheds only if it *sees* a zero — and the whole population arrives within
microseconds, before any worker has published a load update. The optimistic
claim added for bursts spreads work across many connections; it has nothing to
work with when there are only eight.

Connect rate is measured in the next section, with `connect-bench`.
`bench-client` opens its pool once and holds it, so it cannot produce a connect
storm.

### Connect rate (2026-11-06)

Pool and merged accept, one request per connection, no reuse: `connect-bench`
with 32 threads on hv01 against an 8-worker `bench-server --echo-mode copy` on
hv02, Linux 6.12, X710 LAG. Five runs per cell, 0 connect or I/O errors. Nineteen
ran in random order. The fifth merged TLS run was the smoke run of the same spec,
just before them, and dropping it leaves that cell at -5.9%. Medians, with CPU
taken from a recording scoped inside the client's measured window.

| | Pool conns/s | Merged conns/s | Merged rate | Pool CPU/conn | Merged CPU/conn |
|---|---|---|---|---|---|
| no TLS | 32,945 | 33,194 | +0.8% | 232 µs | 198 µs |
| TLS | 18,940 | 17,818 | -5.9% | 509 µs | 492 µs |

The rule set before the run was a median win of at least 10%, outside the arms'
spread, with and without TLS, and p99 no worse. Merged does not meet it, so Pool
stays the default. `connect-bench` reports no p99, so that clause was not
checked; the rate clause already fails.

CPU did not bound the no-TLS rate: workers ran at about 0.65 of a core and the
client peaked at 17.5 cores. Connection latency was about 950 µs in both modes,
and what sets it is not known. So this cell does not give merged mode's maximum
rate. With TLS, workers ran at about 0.98 of a core in Pool and 0.93 in merged.
Why merged is slower there while using less CPU is not known.

Merged accept, steering and park moved behind the `unstable-accept` feature
after this run. Park runs only in merged mode, so the feature holds both until
the policy work in `docs/journal/2026-09-two-phase-park.md` is finished.

## Staging

1. Listener list + per-listener config (TLS, nodelay, backlog, bound address)
   + `ListenerId` on `Connection` (breaking builder change).
2. Acceptor payload `(RawFd, ListenerId, PeerAddr)`; retire the fake peer addr.
3. Merged accept mode behind config, io_uring multishot; mio keeps the pool.
4. BPF steering → tier 1 and tier 2 placement. The kernel-behaviour spike is
   done (§5); what remains is wiring it into the runtime.
5. Park and adopt (tier 3): quiesce reuse, fd handover, `on_adopt`.
6. Shed hint (tier 4).
7. Handshake offload knob, gated on its prototype measuring well.

Fix the stale `lib.rs:53` diagram in step 1 — it is the crate's front page and
it currently describes `SO_REUSEPORT` that does not exist.

Placement policy documentation (§5a) belongs with step 3 or 4, whichever lands
the second placement mechanism: the existing `conn_chunk_size` rule of thumb is
actively wrong for pooled clients and should not survive this work unqualified.

This is a breaking builder change, so it batches with the naming work already
queued for the next release: `connect() -> Connection`, `UdpCtx -> UdpSocket`,
`ConnToken -> ConnId`.
