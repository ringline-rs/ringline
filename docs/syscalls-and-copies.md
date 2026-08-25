# Syscalls and copies, counted

[Why consider io_uring?](io-uring-primer.md) presents an analytical model of
application syscall crossings — `2R + ceil(R/B)` for level-triggered epoll,
`3R + ceil(R/B)` for an edge-triggered drain, `ceil(R/B)` for batched io_uring
with multishot receive — and is careful to label it a model, not a performance
result. This page grounds that model in ringline specifically: it walks the two
backends' event loops and counts what actually crosses the kernel boundary per
request, counts the data copies on the same paths, and closes with a measured
data point.

Every count below is tied to the code that produces it, so it can be re-checked
when the code changes. What the counts deliberately ignore: kernel-side CPU
(io_uring moves work into task_work and ring processing rather than
eliminating it), page faults, and cache/TLB effects. Fewer syscalls is a
mechanism, not a verdict — the measured section is what connects the counts to
throughput.

## At a glance: one request-response exchange

What each backend pays in kernel crossings to serve a single request, counted
from the event loops (details and code references in the two sections that
follow):

| Step | epoll loop (mio backend) | io_uring loop |
|---|---|---|
| Learn the request arrived | share of one `epoll_wait` | share of one `io_uring_enter` — the CQE is already in the completion ring when it returns |
| Read the request bytes | 1 `read()` — **plus 1 more** `read()` returning `EAGAIN` to finish the edge-triggered drain | **0** — the multishot-recv CQE *delivers a filled buffer*; no read call exists |
| Send the response | 1 `writev()` | **0 dedicated** — a send SQE rides the iteration's shared enter |
| Confirm the send completed | (return value of `writev`) | **0** — send CQE, drained in the same iteration |
| Arm/fire a timeout | folded into the `epoll_wait` timeout | **0** — timeout SQE/CQE |
| **Total, idle connection** | **~3–4 syscalls, every request** | **~2 enters** |
| **Total, under load** | ~2–3 per request — the reads and writes never amortize, only the `epoll_wait` does | **(1–3 enters) ÷ requests in the batch** — *every* step amortizes |

That last row is the whole argument. In the epoll loop, only the wait is
shared; each request still owns its `read` and `writev`, so the floor is ~2
syscalls per request no matter the load. In the io_uring loop *no step owns a
syscall* — requests ride the ring as SQEs and CQEs, and the per-iteration
enters divide across everything serviced that iteration. Load makes the
io_uring loop *cheaper* per request while the epoll loop stays flat:

| Pipeline depth (measured, sweep below) | io_uring client syscalls/req | epoll client syscalls/req |
|--:|--:|--:|
| 1 | 0.80 | 6.62 |
| 8 | 0.035 | 1.23 |
| 32 | 0.021 | 0.72 |

## Syscalls per request: io_uring backend

The worker loop is `AsyncEventLoop::run()` in
`ringline/src/backend/uring/event_loop.rs`. The ring is created with
`coop_taskrun`, `single_issuer`, and (unless SQPOLL is enabled)
`defer_taskrun`, with registered file descriptors — connections are referenced
as `Fixed(conn_index)` slots, so no per-operation fd table lookups
(`ring.rs`).

One loop iteration makes **one to three `io_uring_enter` calls, total,
regardless of how many connections or requests it services**:

1. `submit_and_wait(min_complete)` — the blocking entry. `min_complete` is 0
   when tasks are already runnable (so it only submits and returns) and 1
   otherwise (block until a CQE arrives).
2. `Ring::flush()` after the task-poll pass — a single merged
   `enter(sq_len, 0, GETEVENTS)` that both submits the SQEs the tasks just
   queued and forces `DEFER_TASKRUN` task_work delivery, so send/recv CQEs are
   drained in the same iteration instead of costing a wake-up of their own.
   **Skipped entirely when no SQEs are pending** — the syscall is not made for
   an idle flush.
3. A second `flush()` only if draining those CQEs woke more tasks whose sends
   should land before the loop blocks again.

Everything a request needs rides inside those batched enters as SQEs and CQEs:

| Operation | Syscalls per event | Mechanism |
|---|---:|---|
| Receive a message | **0** | Multishot recv (`opcode::RecvMulti` + provided buffers) is armed once per connection; the kernel keeps posting CQEs with filled buffers indefinitely. Re-arm happens only after `ENOBUFS` parking or cancellation, and is itself an SQE. |
| Send a response | **0 dedicated** | `send()`/`send_nowait()` push an `opcode::Send` SQE (`MSG_WAITALL`, so the kernel retries short sends in place); coalesced sends are one `opcode::SendMsg` SQE gathering several queued sends; zero-copy sends are `opcode::SendMsgZc`. All are submitted by the iteration's shared enter. |
| Zero-copy notification | **0** | The "DMA done, guard can drop" signal is a second CQE on the same SQE, not a syscall. |
| Timer arm/fire | **0** | Timeout SQE / timeout CQE. |
| Outbound connect | **0 dedicated** | Connect SQE, optionally `IO_LINK`ed with a timeout SQE. |
| Accept | 1 per connection | The dedicated acceptor thread runs blocking `accept4()` and hands the fd to a worker over a channel, waking it via eventfd write. The worker's side of that wake is an eventfd-read *SQE* — no syscall on the worker. This is one-time per connection, not per request. |

So in steady state:

```
syscalls/request ≈ enters_per_iteration (1–3) / requests_serviced_per_iteration
```

which is the primer's `ceil(R/B)` with `B` = requests per loop iteration. The
worst case is an idle server receiving one request at a time: the request's
CQE ends one `submit_and_wait`, the task queues a send, `flush()` submits it,
and the loop re-enters `submit_and_wait` — about 2 enters per request. Under
load, `B` grows naturally (every CQE that arrived while tasks were running is
drained in the same iteration) and the ratio falls toward zero. The measured
sweep below shows 0.80 syscalls/request at pipeline depth 1 falling to 0.02 at
depth 32.

With SQPOLL enabled a kernel thread consumes the SQ, so even the submission
enters disappear while it is active — paid for with a polling thread that
burns CPU including when idle. Ringline supports it but the defaults do not
enable it; none of the numbers here use it.

## Syscalls per request: mio backend

The fallback loop (`ringline/src/backend/mio/event_loop.rs`) is the
epoll-shaped design the primer models, with the mitigations a careful epoll
loop can apply:

| Step | Syscalls | Mechanism |
|---|---:|---|
| Wait | 1 per iteration | `poll.poll()` (`epoll_wait`/`kevent`) with a timer-heap-derived timeout. Amortizes over every ready connection in the batch. |
| Drain a readable connection | N+1 per wake | mio registrations are edge-triggered: `handle_readable` calls `read()` until `WouldBlock`, so N successful reads plus one terminal `EAGAIN`. Pipelined requests arriving together share one read. |
| Flush sends | ≥1 per dirty connection per pass | `Driver::flush_sends` gathers the connection's whole pending queue into one `writev()` (up to 1024 iovecs), looping only if the queue didn't fit or until `WouldBlock`. |
| Accept | 1 per connection | Same acceptor thread; the wake pipe's read end is registered in the poll, so the worker pays a `read()` to drain it per wake (coalescing any number of pending accepts). |

A request-response exchange on an otherwise idle connection therefore costs
about 3–4 syscalls (read, EAGAIN read, writev, plus a share of the
`epoll_wait`) — the primer's `3R + ceil(R/B)` shape. Batching helps here too
(one read can carry many pipelined requests, one writev many responses), but
the floor is different: every drain ends in a wasted `EAGAIN` read and every
flush is at least one syscall, whereas the io_uring loop's floor is the one
blocking enter per iteration.

## Measured: pipeline sweep, June 2026

Cross-client corroboration from a SystemsLab run (ctx `pipeline-sweep
019ead4c`, 2026-06-09): `valkey-lab` (a ringline-based load generator, io_uring
backend) vs `valkey-benchmark` (epoll, per-op recv/send) driving the same
16-shard Valkey cluster on uniform c8g.8xlarge instances — GET workload, 8
threads, 128 connections, pipeline depth P swept 1→32. Per-op metrics from
per-variant rezolus captures.

| P | ringline lab Mreq/s | lab cyc/req | lab **syscall/req** | lab IPC | valkey-benchmark Mreq/s | bench cyc/req | bench **syscall/req** | bench IPC |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 1 | 1.10 | 22977 | **0.80** | 1.59 | 0.78 | 31901 | **6.62** | 1.50 |
| 2 | 1.80 | 13905 | 0.37 | 1.63 | 1.50 | 16778 | 3.45 | 1.49 |
| 4 | 2.80 | 8879 | 0.16 | 1.69 | 2.93 | 8546 | 1.62 | 1.40 |
| 8 | 3.90 | 6203 | 0.035 | 1.87 | 4.28 | 6223 | 1.23 | 1.29 |
| 16 | 4.70 | 5137 | 0.027 | 1.91 | 5.21 | 4262 | 0.83 | 1.22 |
| 32 | 4.90 | 4804 | **0.021** | 1.96 | 5.99 | 3400 | 0.72 | 1.21 |

What the numbers say about the counting above:

- **The syscall column matches the models.** At P=1 the epoll client pays
  6.62 syscalls/request (per-op recv and send, readiness bookkeeping, no
  coalescing); the io_uring client pays 0.80 — already below 1 because 128
  connections across 8 workers give each loop iteration a natural batch even
  without pipelining. Deeper pipelines amortize both, but the io_uring curve
  drops to ~0.02 — thirty-plus requests riding each `io_uring_enter`.
- **IPC diverges in opposite directions.** The io_uring client's IPC *rises*
  with load (1.59 → 1.96) as the loop spends more time in straight-line
  userspace batch processing; the epoll client's *falls* (1.50 → 1.21) as
  syscall entry/exit and readiness churn pollute the pipeline.
- **Syscall count is not the whole story.** At P=32 the epoll client is
  leaner per request in cycles (3400 vs 4804 cyc/req) and pushes more
  requests/s at this thread count — its per-op path is simply shorter once
  syscalls amortize, and the lab client carries cluster slot-routing and
  fire/recv accounting the benchmark doesn't. Fewer syscalls buys the most at
  low pipeline depth and high connection counts, which is exactly what the
  primer's model predicts.

**Caveat:** this is two different codebases, not a controlled backend A/B — it
corroborates the counting but doesn't isolate io_uring-vs-epoll. The
controlled experiment exists in-tree: `ringline-benchmarks` has a `force-mio`
feature so the same client code can run on either backend on one machine.

## Copies per request

The same discipline applied to data movement. Kernel-internal copies
(skb-to-buffer on receive, buffer-to-skb on plain sends) are outside the
count; zero-copy send is the exception the ZC rows note.

### Receive path

| Step | Copies | Mechanism |
|---|---:|---|
| Kernel → provided buffer | 0 | Multishot recv fills `ProvidedBufRing` buffers selected at completion time (io_uring). On mio, `read()` into a scratch buffer instead. |
| Provided buffer → `RecvAccumulator` | 1 | `extend_from_slice` into the per-connection contiguous accumulator. This is the one mandatory receive copy on the ordinary path. |
| Accumulator → `with_data(\|&[u8]\|)` | 0 borrowed | The parser sees a borrowed slice and must copy anything it keeps. |
| Accumulator → `with_bytes(\|Bytes\|)` | 0 | `BytesMut::freeze()` and `Bytes::slice()` are O(1) refcount operations; parsed values are refcounted sub-slices that stay valid after the accumulator advances. |
| TLS receive | +1 | rustls must decrypt; plaintext is drained into the accumulator through `BufRead` with no intermediate scratch buffer. |

`with_data` vs `with_bytes` is the single biggest receive-side copy decision a
client makes: `with_bytes` plus a `Bytes`-aware parser makes value extraction
fully zero-copy.

### Send path

| Method | Copies | Mechanism |
|---|---:|---|
| `send()` / `send_nowait()` | 1 | User data → pre-allocated `SendCopyPool` slot. The pool exists because SQE-referenced memory must outlive the operation; the runtime owns the slot until the CQE. |
| `send_parts()` with `.copy()` parts | 1 | All copy parts gathered into one pool slot. |
| `send_parts()` with `.guard()` parts | 0 | `SendMsgZc` iovecs point at the caller's memory; the `SendGuard` is held in `InFlightSendSlab` until the kernel's notification CQE confirms the DMA. Routed through the copy path below `send_zc_threshold` (default 4096 — measured crossover is 1–4 KiB). |
| Mixed `.copy()` + `.guard()` | 1 (copy parts only) | Copy parts → pool slot; guard parts zero-copy via iovec. |
| Any send under TLS | 2 | Encryption must read plaintext and write ciphertext, so guard zero-copy is impossible — but rustls encrypts *directly into the pool slot* (an `io::Write` adapter over the slot in `tls.rs`), so TLS caps at one extra copy, and records are serialized through the per-connection send queue for ordering. |
| Any send on the mio backend | 1 | Zero-copy degrades: guards are consumed by copying. NVMe is unsupported and fs/direct I/O move to a thread pool. |

### Protocol clients

The client crates (`ringline-redis`, `ringline-memcache`) compose these
primitives; their READMEs carry the full per-path tables. The shape:

- **Receive is fully zero-copy.** Both use `with_bytes` with `Bytes`-based
  parsers (`resp-proto`, `memcache-proto`); returned values are refcounted
  slices into the accumulator.
- **The command envelope always costs one copy.** Commands are encoded into a
  *reused* scratch buffer (no per-op allocation) and copied into the send
  pool — as are all fired commands coalesced into a batch
  (`max_batch_size` > 1) and all `Pipeline` batches (one buffer, one send).
- **Large values can skip the copy.** `set_with_guard()` /
  `fire_set_with_guard()` keep the value in place via `SendGuard` when it is
  at or above the client `zc_threshold` (default 4096, matching the runtime);
  smaller guarded values fold into the coalescing buffer because the copy is
  cheaper than ZC bookkeeping at that size.

## Reading the two counts together

The two backends make opposite trades. The mio loop copies little but crosses
the kernel boundary per event; the io_uring loop crosses per *batch* but pays
for it in machinery — provided-buffer rings, send pools, in-flight slabs,
generation-checked completions ([PRINCIPLES.md](principles/PRINCIPLES.md)
covers why ringline accepts that complexity on Linux and not elsewhere). The
sweep is one workload on one machine class, but it shows the mechanism doing
what the counting says it should: syscalls per request driven to noise, and
IPC improving as the loop turns into straight-line batch processing.
