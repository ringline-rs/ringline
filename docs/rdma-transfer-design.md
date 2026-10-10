# RDMA value transfer for cache clients

Status: proposal. Nothing here is built.

This note covers how a ringline client could move cache values with RDMA
(libfabric, on EFA or a verbs NIC) while the request and reply stay on an
ordinary ringline TCP connection. It starts from the existing implementation,
cachecannon/cachecannon#201, which adds an RDMA path to the cachecannon load
generator, and says what ringline would need to support the same design as a
library feature.

Everything about #201 below was read at its head `ae75869`; line references
are to that head. Bare file names from #201 are in `src/dma/`, except
`endpoint.rs`, `buffer.rs`, `handle.rs`, `config.rs` and `progress.rs`, which
are in `src/dma/fabric/`, and `worker.rs` and `config/mod.rs`, which are in
`src/`. The server side of #201 is not in that PR, so claims about server
behaviour are inferences and are marked as such.

## The client as a passive RMA target

In #201 the client never posts an RDMA operation. For each transfer it sends
a RESP command on its TCP connection that names a window of its own
registered memory, and the server performs the RDMA. There are two command
dialects (`command.rs:11-14`, `144-222`):

| Operation | Client sends | Server does (inferred) | Expected reply (`command.rs:9-13`, `31`, `41`, `70-71`, `114`) |
|---|---|---|---|
| `DMA.GET` | `<addr> <rkey> <raddr> <capacity> <key> [crc-flag]` | RDMA write of the value into the window | `Integer(n)`, `[n, crc]`, or `Null` on a miss |
| `DMA.SET` | `<addr> <rkey> <raddr> <len> <key> [crc]` | RDMA read of the value from the window | the byte count, which must equal `len` |
| `BLOB.GET` | `<key> <rkey> <raddr> <capacity>` | RDMA write of the value into the window | `[n, crc]` |
| `BLOB.SET` | `<key> <len> <rkey> <raddr> <len>` | RDMA read of the value from the window | `OK` |

The client accepts `Null`, `n` or `[n, crc]` for either GET, and `OK`, or `n`
or `[n, crc]` with `n` equal to `len`, for either SET (`command.rs:47-89`).
Not known: the `BLOB.GET` reply on a miss; the client treats `Null` as a miss
for either GET (`command.rs:49`). `BLOB.*`, the large-object dialect, is the
default. It sends the client's fabric address once, in `BLOB.HELLO <hex
addr>`; `DMA.*` sends it as `<addr>` in every command. The PR description
still calls the large-object commands `LO.*`; the code uses `BLOB.*`.

`<addr>` is the client's fabric address in hex. `<rkey>` and `<raddr>` are the
registration's remote key and remote address in decimal: the virtual address
on EFA, 0 on the tcp provider, which addresses by offset
(`advertisement.rs:17-26`, `handle.rs:161-172`). `DMA.HELLO` or `BLOB.HELLO`
at connect returns the server's fabric addresses, which the client inserts
into its address vector (`client.rs:44-46`, `178-207`).

#201 treats the RESP reply as meaning the RDMA transfer has finished. That
holds only if the server replies after a delivery-complete completion for its
write. Not checked: the server is not in the PR. With checksums on, a CRC-32c
is the only end-to-end check.

With this design the RDMA completion is observed as a socket read, which
wakes the task the same way any RESP reply does. On a provider that needs no
progress from the target, the event loop needs no RDMA completion handling.
This is the design to keep.

## How #201 is built

- One fabric endpoint and address vector per worker, in a `thread_local!`
  (`connection.rs:27-35`), opened from `on_start` (`worker.rs:767-775`). A
  worker uses NIC `worker_id % interfaces` (`connection.rs:107`). This matches
  ringline's thread-per-core model.
- GET destination: one `vec![0; capacity]` per connection, registered with
  `fi_mr_reg` at connect time (`client.rs:47`) and held until the connection
  drops.
- SET source: the load generator's shared value pool, registered read-only
  once per worker (`connection.rs:117-130`, `endpoint.rs:440`). A SET names a
  window into the pool (`buffer.rs:121-138`), so there is no staging copy.
- One transfer per connection: every GET names the whole buffer at offset 0
  (`client.rs:72-78`), `pipeline_depth` must be 1 (`config/mod.rs:859-864`),
  and the transfer uses `ringline_redis::Client::cmd`, which is one request
  and one reply at a time.
- Providers: `tcp`, and the `efa` provider with the `efa-direct` fabric
  (`config.rs:2-24`). Progress: none on efa-direct, where
  `needs_manual_progress()` is false (`config.rs:32-34`, `handle.rs:36-39`). A
  comment in #201 (`progress.rs:100-102`) says the provider's other fabric,
  `efa` (rxr), which #201 does not select, emulates RMA and advances only
  while the target polls. On tcp, one `std::thread` per worker calls
  `fi_cq_read` in a loop without sleeping while any transfer is in flight,
  discards what it reads, and parks on a `Condvar` when idle
  (`progress.rs:44`, `103-113`). The completion queue has no wait object
  (`endpoint.rs:273-274`).
- Drop order: a `Registration` holds a clone of the domain, so the domain
  outlives every memory region (`endpoint.rs:34-40`), and `DmaBuffer` closes
  its memory region before it frees the memory (field order,
  `buffer.rs:50-58`).
- Build: `ofi-libfabric-sys` 0.2.0, which generates bindings with bindgen and
  probes libfabric through pkg-config with no minimum version (its
  `build.rs:190-192` panics unless pkg-config reports exactly one include path
  and one link path), and `crc-fast`; both are behind the `dma` cargo feature,
  which is off by default. CI does not enable `dma`, so none of the RDMA code
  is built or tested in CI. The tests that exist need a host libfabric with
  the tcp provider and cover open, register and drop; there is no transfer
  test against a server.

## Defects in #201 that a ringline design must avoid

Each item was confirmed by reading the code unless it says otherwise.

1. On a reply timeout, `recv_with_timeout` closes the socket and the
   connection, with its registered GET buffer, goes out of scope
   (`connection.rs:225-244`), while the server may still hold the rkey. The
   memory region is closed before the memory is freed, so on a hardware
   provider a late write fails at the server (inferred). On the tcp provider
   the write into client memory is performed by the client's progress
   thread, which reads the CQ without the endpoint lock (defect 4), so it can
   race the close and the free (plausible, as defect 4). The progress thread
   runs only while some transfer on the worker is in flight
   (`progress.rs:83-91`), so the late write lands only if another connection
   keeps it running. This is the RDMA form of Domain Invariant 1
   in ringline's CLAUDE.md: memory an operation references must outlive it.
2. `BLOB.GET` CRCs are discarded. Config validation forbids `checksum` in the
   large-object mode (`config/mod.rs:875-880`) and `verify` returns early when
   it is off (`client.rs:137`), although the server sends a CRC on every
   `BLOB.GET`. The throughput figures in the #201 description were measured
   in the large-object mode, so no CRC was verified in them.
3. `fi_mr_reg` runs on the worker thread inside the async connect
   (`client.rs:47`) and again on every reconnect. On a hardware provider,
   pinning `capacity` bytes stalls every other connection on that worker for
   the duration (inferred).
4. The progress thread reads the CQ without the endpoint mutex
   (`progress.rs:107`), while `fi_mr_reg`, `fi_close` and `fi_av_insert` run
   under it on the worker thread. The SAFETY comment at `endpoint.rs:109-111`
   acknowledges the unlocked CQ read but gives no reason it is safe. No
   `threading` level is requested in the hints, so whether this is safe
   depends on the provider's default (plausible, tcp provider only).
5. CQ errors are never read. The drain stops on `read <= 0`
   (`progress.rs:109`) and `fi_cq_readerr` is never called. Plausible: one
   error entry makes every later read return `-FI_EAVAIL`, and the errors are
   lost.
6. The progress thread spins without sleeping and is not pinned. Inferred:
   about one core per worker on tcp-provider runs, competing with the pinned
   workers.
7. Address-vector entries are inserted again on every connect
   (`client.rs:44-46`) and never removed. Plausible: a duplicate insert
   returns the existing entry on efa-direct and tcp. Not checked.
8. A worker whose fabric open fails spawns no tasks but is still counted as
   started (`worker.rs:767-782`), so the run continues with fewer connections
   and only a log line says so.

## What ringline would need

### Where it lives

A separate crate, `ringline-fabric`, with the libfabric dependency, and RDMA
commands in `ringline-redis` behind a cargo feature. The core runtime needs
no libfabric code. It needs two additions, both described below: a
per-worker memlock input for `launch`, and a way for a helper thread to wake
the worker it serves.

### Registered memory

A per-worker `FabricRegion`: one large allocation, registered with `fi_mr_reg`
once at worker start, before the worker accepts or connects. Registration
never runs on the event loop after startup. The region is divided into
fixed-size slots.

`launch` checks `RLIMIT_MEMLOCK` before it spawns workers
(`ensure_memlock_limit` and `memlock_required` in `ringline/src/worker.rs`),
on io_uring builds only and not for a process with `CAP_IPC_LOCK`, and counts
`registered_regions` and, from Linux 6.14, the ring and provided buffer
rings. A region registered by another crate is not counted. Making `launch`
fail with `Error::ResourceLimit` when the fabric region does not fit needs a
new `Config` input: the region's bytes per worker. The two charges add up:
io_uring checks registered buffers against `user->locked_vm` and also adds
them to `mm->pinned_vm`, and a verbs or EFA registration (`ib_umem_get`)
adds to `mm->pinned_vm` and checks that against `RLIMIT_MEMLOCK` (Linux
6.12 source). How the 6.14 ring charge is accounted was not checked. The tcp
provider pins nothing.

A GET leases a slot. The slot is released when the reply has been consumed,
or when the transfer is known to be finished. On a timeout the transfer is not
known to be finished: closing the TCP connection does not stop a server that
already holds the rkey. A slot can be reused safely only after its rkey is
revoked. Two ways to get that:

- Register each slot as its own memory region at startup. A timed-out slot's
  region is closed, which revokes its rkey, and the slot is re-registered
  later, never on the event loop. This costs one registration per slot, and
  some providers limit the number of memory regions. Not known: whether verbs
  or EFA can hand a revoked rkey value to the next registration of the same
  address, which would let a late write land in the reused slot.
- Quarantine the slot. Slots that time out stay unusable until the region is
  re-registered. Re-registering closes the region's memory region, which
  revokes the rkey of every slot, so every transfer on the worker must finish
  or fail first. Two regions used alternately avoid that pause.

Either way, re-registration runs on a `ringline::spawn_blocking` thread,
which is a fabric caller like the worker, so the domain needs
`FI_THREAD_SAFE` or a lock shared with the worker. The blocking pool runs at
`SCHED_IDLE`, so a busy core can delay the re-registration.

Not known: the per-region cost, the region-count limit on EFA, and whether an
rkey value can be reused (above). The choice depends on them.

A SET source is a window into memory the caller registered, the RDMA
counterpart of a `.guard()` part in `send_parts`. The memory must stay valid
until the server's RDMA read completes, which the client learns from the
reply. A zero-copy send's guard is instead held until its notification CQE.
The lease holds the caller's guard until the reply arrives. On a timeout
ringline cannot revoke the rkey, because the caller owns the registration,
and with a shared pool as in #201 revoking it would revoke every in-flight
SET. The lease therefore returns the guard to the caller marked as possibly
still being read, and the caller must not reuse or free that memory until
it has revoked the registration or the server is known to have stopped.

### Depth above one per connection

`ringline-redis` already pipelines arbitrary commands with `Pipeline::cmd`
and `execute` (`ringline-redis/src/lib.rs`), which gives depth above one in
batches. Streaming depth, where a new transfer starts as each reply arrives,
needs `fire_cmd` and a generic `recv`; fire/recv exists only for the typed
commands. RESP replies arrive in request order, so slots can be leased from a
ring and released in order as replies are consumed.

### Progress

The passive-target design needs progress only on providers that require
target-side progress, such as tcp. The options:

1. Poll the CQ from `on_tick`. The io_uring loop arms a tick timeout before
   it blocks, so `on_tick` runs at least every `tick_timeout_us` (default
   1 ms; 0 blocks until a completion arrives). On the mio backend `on_tick`
   runs at least every 10 ms, a fixed interval that `tick_timeout_us` does
   not change. On tcp the target reads the socket only when it polls, so a
   value larger than the TCP receive window costs up to one tick period per
   window, not one per transfer. Lowering the period wakes every worker
   that often whether or not a transfer is outstanding. It needs no new
   ringline API, but `on_tick` belongs to the application's
   `AsyncEventHandler`, so every application has to call the fabric crate's
   poll from its own `on_tick`.
2. Open the CQ with `FI_WAIT_FD`, get its fd with `fi_control(FI_GETWAIT)`,
   and watch it with a multishot `PollAdd`. After each poll CQE the worker
   drains the CQ and calls `fi_trywait`, and drains again on `-FI_EAGAIN`,
   as fi_poll(3) requires before waiting on a native wait object. Ringline
   has no public API that waits for readiness on an arbitrary fd; this would
   add one. Only providers that need target progress use this option, so
   efa-direct does not. Not known: whether the tcp provider's wait fd becomes
   readable when incoming RMA needs progress; a passive target without
   `FI_RMA_EVENT` gets no CQ entries for incoming writes unless the server
   sends remote CQ data, which is not known.
3. A helper thread per worker that waits in `fi_cq_sread` with a timeout, on
   a CQ opened with a wait object, and reports CQ errors (`fi_cq_readerr`)
   to the worker. The domain must be opened with `FI_THREAD_SAFE`: a lock
   held across a blocking `fi_cq_sread` would stall every other fabric call
   on the worker. The thread wakes the worker through a task's
   `std::task::Waker`, which ringline accepts from any thread. A
   `WakeHandle` would also work, but a worker cannot obtain its own today:
   `Runtime::worker_wake_handle` is available only after `launch` returns.
   Not known: whether the tcp provider makes progress on incoming RMA while
   a thread waits in `fi_cq_sread`. A passive target that has not requested
   `FI_RMA_EVENT` gets no CQ entries for incoming writes unless the server
   sends remote CQ data, which is not known, so this option relies on the
   wait itself driving progress.

Option 1 is the smallest change and costs up to one tick period per receive
window of each value; option 3 replaces #201's spinning thread without that
cost if the tcp provider progresses inside `fi_cq_sread`.

### Testing

The tcp provider runs without RDMA hardware, so CI can build the feature and
run a transfer test against an in-process server: register, GET into a slot,
SET from a window, and a timed-out GET whose slot is not reused while the test
server still writes to it. A test of a CQ error reaching the caller needs a
way to make the provider post one; a passive target without `FI_RMA_EVENT`
gets no CQ entries for incoming writes unless the server sends remote CQ data,
and how to inject an error is not known. Each test should be checked by
mutation (for example, releasing a timed-out slot at once must fail the
timeout test). EFA testing needs an EFA host, and none is registered in
SystemsLab.

## Open questions

- Does the server reply only after its RDMA write is delivery-complete? The
  client's correctness depends on it, and #201 does not include the server.
- Does the tcp provider's wait fd become readable when incoming RMA needs
  progress?
- Does the tcp provider progress incoming RMA while a thread waits in
  `fi_cq_sread`?
- What does a memory region cost on EFA, and how many can a domain hold?
  That decides between per-slot regions and quarantine.
- Does the server send remote CQ data with its RDMA writes?
- Can verbs or EFA give a new registration of the same address a revoked
  rkey value?
- Should a value larger than one slot span several slots, or should the slot
  size be the maximum value size?
