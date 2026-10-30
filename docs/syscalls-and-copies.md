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
| Read the request bytes | 1 `read()` — **plus 1 more** `read()` returning `EAGAIN` to finish the edge-triggered drain | **0** — the recv CQE *delivers a filled buffer*; no read call exists |
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
`single_issuer` and, unless SQPOLL is enabled, `coop_taskrun` and
`defer_taskrun`, with registered file descriptors — connections are referenced
as `Fixed(conn_index)` slots, so no per-operation fd table lookups
(`engine/uring.rs`).

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
| Receive a message | **0** | A plaintext connection submits a one-shot `RECV` into its accumulator when a read parks (`docs/recv-direct-design.md`): 1 SQE per completion, plus one `POLL_ADD(POLLRDHUP)` per connection, armed when it opens. When the poll fires with no receive in flight, a `MSG_PEEK` recv checks for bytes queued ahead of the end. A TLS connection submits the same one-shot `RECV`, into its TLS engine's ciphertext buffer, 1 SQE per completion, submitted by the iteration's shared enter. During the handshake it is re-armed when it completes; after it, when a read parks. It arms the same `POLL_ADD(POLLRDHUP)`, and when the poll fires a receive reads the rest of the stream; there is no peek. |
| Send a response | **0 dedicated** | `send()`/`send_nowait()` push an `opcode::Send` SQE (`MSG_WAITALL`, so the kernel retries short sends in place), and a send wider than one send-pool slot goes out as `opcode::SendMsg` SQEs of up to 32 slots each (per-slot `opcode::Send`s if the send slab is full); coalesced sends are one `opcode::SendMsg` SQE gathering several queued sends; zero-copy sends are `opcode::SendMsgZc`. All are submitted by the iteration's shared enter. |
| Zero-copy notification | **0** | The "DMA done, guard can drop" signal is a second CQE on the same SQE, not a syscall. |
| Timer arm/fire | **0** | Timeout SQE / timeout CQE. |
| Outbound connect | **0 dedicated** | Connect SQE, optionally `IO_LINK`ed with a timeout SQE. A plaintext connection then arms one `POLL_ADD(POLLRDHUP)` SQE (`docs/recv-direct-design.md`). |
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
| Kernel → TLS engine buffer (TLS, io_uring) | 0 | A one-shot `RECV` of ciphertext, armed when a read parks: into the unbuffered engine's `CiphertextBuf`, or with `tls-buffered` into a worker buffer that `read_tls` reads (the TLS receive rows). |
| Kernel → read buffer (TLS, mio) | 0 | `read()` into the per-worker 8192-byte buffer; the ciphertext goes to rustls (the TLS receive rows). |
| Read buffer → `RecvAccumulator` (mio) | 1 | `read()` into a per-worker buffer, then `extend_from_slice` into the per-connection contiguous accumulator. |
| Kernel → `RecvAccumulator` (plaintext, io_uring) | 0 | A one-shot `RECV` into the accumulator's free space, armed when a read parks. Growing the accumulator for a longer message can copy the part already received (`docs/recv-direct-design.md`). |
| Accumulator → `with_data(\|&[u8]\|)` | 0 borrowed | The parser sees a borrowed slice and must copy anything it keeps. |
| Accumulator → `with_bytes(\|Bytes\|)` | 0 | `BytesMut::freeze()` and `Bytes::slice()` are O(1) refcount operations; parsed values are refcounted sub-slices that stay valid after the accumulator advances. |
| TLS receive, unbuffered engine (default) | +1 on io_uring, +2 on mio | On io_uring the receive writes ciphertext into `CiphertextBuf`; on mio `append` copies it there from the read buffer. rustls decrypts in place there, and `ReadTraffic::next_record` lends the record from `CiphertextBuf` (ringline-tls 0.1.1, either TLS version); ringline copies it into the accumulator. `CiphertextBuf::compact` moves ciphertext too: measured 0.94× the payload at 16 KiB records arriving in 16 KiB buffers, 0.02–0.04× at 1 KiB, before TLS received directly (receives are now up to `recv_direct_region`, 32 KiB by default; not remeasured). |
| TLS receive, buffered engine (`tls-buffered`) | +3 | Ciphertext is copied into rustls' deframer buffer (`read_tls`); rustls decrypts in place and copies each record's plaintext into a new `Vec` (`take_received_plaintext`, one allocation per record); `drain_tls_plaintext` copies it into the accumulator. `DeframerVecBuffer::discard` also memmoves the ciphertext behind each processed record: measured 0.12× the payload at 16 KiB records, 2.3× at 1 KiB. |

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
| Any send under TLS (buffered engine, `tls-buffered`) | 2; 3 through `send_parts`/`send_chain` | Encryption must read plaintext and write ciphertext, so guard zero-copy is impossible. rustls seals each record in a per-record `PrefixedPayload`, and `write_tls` copies it into pool slots through `PoolWriter`, an `io::Write` adapter over the slot in `tls/buffered.rs` (no scratch `Vec`), on io_uring, or into the queued `Vec` on mio (`encrypt_for_send_mio_buffered`). `send_parts` and `send_chain` first gather their parts, guard parts included, into a `Vec` (`SendBuilder::submit_tls` for `send_parts` and `SendChainBuilder::copy` / `ChainPartsBuilder::add` for `send_chain` on io_uring; `AsyncSendBuilder` on mio), one more copy. Records are serialized through the per-connection send queue for ordering. |
| Application-data send under TLS (unbuffered engine, the default; both backends) | 1 (TLS 1.3, ring or aws-lc-rs), 2 otherwise; `send_parts`/`send_chain` +1 | With ringline-tls 0.1.1 and the ring or aws-lc-rs provider, `WriteTraffic::encrypt` → `write_fragments` → `MessageEncrypter::encrypt_into` copies a TLS 1.3 record's plaintext into the pool slot (io_uring) or the queued `Vec` (mio) and seals it there. A TLS 1.2 record, or one from another provider, is sealed in a per-record buffer and then copied into the destination. `send_parts` and `send_chain` first gather their parts, guard parts included, into a `Vec` (`SendBuilder::submit_tls` for `send_parts` and `SendChainBuilder::copy` / `ChainPartsBuilder::add` for `send_chain` on io_uring; `AsyncSendBuilder` on mio), one more copy. See the correction below. |
| TLS handshake output under the unbuffered engine, io_uring only | 2 | `EncodeTlsData::encode` needs one contiguous output buffer that can exceed a `send_copy_slot_size` slot, and takes no `io::Write`. Handshake ciphertext goes rustls → a scratch `Vec` → pool slot — one copy more than the buffered engine's direct `PoolWriter`. Handshake-only: application data does not go through that scratch `Vec`; it costs what the row above says. On mio there is no pool-slot step, so handshake output stays 1 copy on both engines. |
| Any send on the mio backend | 1; 2 through `send_parts` (gathered into a `Vec`, then copied into the queued `Vec`); TLS sends cost what the TLS rows say | Zero-copy degrades: guards are consumed by copying. NVMe is unsupported and fs/direct I/O move to a thread pool. |

> **Correction (2026-09-04).** The `tls-unbuffered` feature was merged (#350)
> claiming it took application-data sends from 2 copies to 1. **With upstream
> rustls it does not** (see the 2026-10-30 note at the end of this block).
>
> Two things in rustls 0.23.41 falsify the claim, both readable in the source:
>
> - **The copy the feature was meant to remove does not happen on an
>   established connection.** `CommonState::send_plain` (`src/common_state.rs`)
>   appends to `sendable_plaintext` only while `!may_send_application_data` —
>   that is, before the handshake completes, so that plaintext written early can
>   be flushed once it may be sent. Every application-data write on an
>   established connection falls through to `send_plain_non_buffering`, which
>   fragments and encrypts immediately. There was no buffering copy to remove.
> - **The unbuffered API does not encrypt into the caller's destination
>   either.** `WriteTraffic::encrypt` → `write_plaintext` →
>   `CommonState::write_fragments` calls `record_layer.encrypt_outgoing(m)` per
>   fragment; `Tls13MessageEncrypter::encrypt` (`src/crypto/ring/tls13.rs`)
>   allocates a `PrefixedPayload`, copies the plaintext into it, seals in place,
>   and `write_fragments` then `copy_from_slice`s the finished record into
>   `outgoing_tls`. Two passes over the plaintext — the same two the buffered
>   engine pays.
>
> Measurement agrees. An allocation counter inside the measured call reports
> 263,976 bytes/op buffered against 264,000 unbuffered at a 256 KiB payload
> (io_uring, hv01, Linux 6.12, rustc 1.98.1); a path that encrypted into the
> destination would allocate ~0. In an isolated send-path microbenchmark
> (medians of 4 interleaved rounds, under 1% spread within an arm) the arms
> differ by −3.1% at 1 KiB, **+5.7% at 16 KiB**, −0.7% at 64 KiB, −2.2% at
> 256 KiB and −1.8% at 1 MiB. Making the copy 4.5× more expensive by running the
> payload cold left the delta unchanged (−2.2% hot vs −2.1% cold at 256 KiB),
> which a removed copy would not have done.
>
> **What the feature actually buys:** a small (~1–2%) send-side *bookkeeping*
> win at ≥64 KiB (not data movement), a 4–8% win on the isolated recv path (weaker
> numbers — 10–20% spread, treat as ±2%), and a systematic extra TLS record
> whenever the payload is a multiple of `send_copy_slot_size`, at a
> `send_copy_slot_size` of 16384, which the unbuffered engine now rejects; at
> any accepted slot size both engines emit `ceil(len / F)` records. At a 16 KiB
> payload the buffered path emits one 16406-byte record and lets `PoolWriter`
> straddle it across two slots; the unbuffered path must fit a whole record
> inside one slot, so `encrypt_chunk` shrinks and emits two (17 records vs 16 at
> 256 KiB, 65 vs 64 at 1 MiB). The extra record is ~245 ns, which is the whole
> +5.7%. It also remains the prerequisite for kTLS —
> `dangerous_into_kernel_connection` is public only on the unbuffered
> connection types.
>
> Reaching the originally-claimed 1 copy required rustls to encrypt in
> place into `outgoing_tls`, which upstream's `write_fragments` does not do.
> ringline-tls 0.1.1, ringline's fork of rustls, does it for TLS 1.3 with the
> ring and aws-lc-rs providers (`MessageEncrypter::encrypt_into`), so the
> application-data row above is 1 copy for TLS 1.3 (2026-10-30). See
> [`tls-unbuffered-design.md`](tls-unbuffered-design.md),
> [`rustls-quinn-forks-design.md`](rustls-quinn-forks-design.md) and
> [`journal/2026-09-unbuffered-tls.md`](journal/2026-09-unbuffered-tls.md).

With `tls-buffered`, TLS receive costs 3 copies on either backend:
ciphertext into rustls' deframer buffer, decrypted plaintext into a per-record
`Vec` (`CommonState::take_received_plaintext` → `Payload::into_vec`, one heap
allocation per record), and that `Vec` into the accumulator. The unbuffered
engine with ringline-tls 0.1.1 makes no copy inside rustls:
`take_received_plaintext` lends the in-place plaintext instead of copying it,
on unbuffered connections only. A TLS receive then costs 1 copy on io_uring,
where the receive writes the ciphertext into `CiphertextBuf`, and 2 on mio,
where `append` copies it there (from the code; ringline-tls's copy-count test
measures 0.00 bytes copied per plaintext byte inside rustls on a TLS 1.3
client connection with the ring provider; the server side, TLS 1.2 and
aws-lc-rs are from the code). `note_copied` counts only ringline's own copy.

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
for it in machinery — send pools, in-flight slabs, direct-receive buffers,
generation-checked completions ([PRINCIPLES.md](principles/PRINCIPLES.md)
covers why ringline accepts that complexity on Linux and not elsewhere). The
sweep is one workload on one machine class, but it shows the mechanism doing
what the counting says it should: syscalls per request driven to noise, and
IPC improving as the loop turns into straight-line batch processing.
