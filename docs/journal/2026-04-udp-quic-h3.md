# Maturing the UDP/QUIC/HTTP-3 stack: from pipelined sends to closing the 32 KiB gap

- **Status:** shipped (retrospective entry, reconstructed 2026-07-06 from commit history)
- **Span:** 2026-04-20 – 2026-05-22 · PRs #115–#198 · releases v0.1.1 (`6ceee65`, #121) and v0.1.2 (`9dd390a`, #127)

## Goal

Make the datagram stack — `UdpCtx` in the runtime, `ringline-quic` (sans-IO wrapper
around quinn-proto), and `ringline-h3` on top — a real, benchmarkable HTTP/3 path.
There was no single up-front design; the work proceeded as iterative gap-closing,
where each correctness or perf finding in the QUIC/H3 layer drove a new primitive in
the runtime's UDP layer.

## What happened

**UDP transport foundation (late April, shipped in v0.1.1).** UDP sends were pipelined
on io_uring — up to `Config::udp_send_slots` datagrams in flight per socket (`83ceb4d`,
#115) — with `UdpCtx::send_ready()` added for event-driven backpressure instead of
retry loops (`c3d368f`, #116). Recv moved to multishot `recvmsg` with a dedicated
provided buffer ring (`c3a5c7e`, #118), eliminating per-datagram SQE resubmission.
Shortly after v0.1.2, the per-socket recv queue was capped (`f09efcf`, #133).

**QUIC event-surface fill-in (April 27, one burst).** Wrapping quinn-proto exposed a
series of missing events and hazards: `StreamReadable` emitted alongside `StreamOpened`
(`935cfd8`, #117); task-panic catching plus `StreamStopped` (`97bd1ef`, #132);
`StreamsAvailable` and unreliable datagrams (`3d08de5`, #134); 0-RTT (`03adf84`, #137);
peer-address change events on path migration (`98e9670`, #138); close/oversize edge
cases and integration tests (`824c55b`, #130).

**H3 correctness.** `send_data` had been silently dropping bytes past the flow-control
window — quinn-proto's `SendStream::write` returns the accepted count and the code
ignored it; the fix queues the remainder per-stream and drives retries off
`StreamWritable` (`98000bf`, #119). Zero-copy `send_data_bytes` via `Bytes` chunks
followed (`88ec32c`, #120), and the receive path went Bytes-throughout in May
(`888c441`, #192). A mid-May audit pass hardened both crates — state cleanup on
close/reset, GOAWAY gating, 0-RTT reject, frame-size bounds (#158–#166).

**GSO/GRO.** `13f3b6f` (#141) batched quinn-proto's `poll_transmit` and split
GSO-segmented buffers. The runtime then grew native `UDP_SEGMENT` support —
`UdpCtx::send_to_gso(peer, data, segment_size)`, one `sendmsg` for many back-to-back
datagrams (`ba2dbc5`, #145) — and QUIC passed its `segment_size` straight through
(`9da42bd`, #146). `b391c3e` (#190) stopped draining transmits inline on every stream
operation (which had emitted ~3N small sendmsg syscalls for N opens) in favor of
batch-scoped coalescing; profiling at 50 c × 512 B had shown ringline-quic trailing
quinn by ~15% with 29% of CPU in `submit_and_wait`.

**Runtime recv APIs driven by bench findings (mid-May).** Zero-copy
`UdpCtx::with_datagram` plus a connected-socket fast path replaced per-datagram
`Vec<u8>` allocation (`497631f`, #165). `recv_batch` added drain-style consumption
(`31817f6`, #193), and `recv_batch_timed` threaded the driver-captured rx timestamp
(taken in the CQE handler, before user-space dispatch) to protocol drivers
(`af9e41c`, #195). QUIC exposed `connection_stats` and `next_timer_deadline`
(`5d57aed`, #194) so benches could see CWND/RTT state.

**The 32 KiB capstone (`8fc33c3`, #198).** The H3 bench (`ad595fb`, #191) showed 32 KiB
cells trailing tokio by 31–49%. Profiling overturned the standing "RTT jitter pins
CWND" theory — smoothed RTT was identical to tokio, and raising the recv buffer made
ringline *slower* (the drops were load-shedding). The real cause was CPU: the bench ran
`poll_transmit` once per received datagram, emitting 3–4-segment GSO buffers and ~10x
the sendmsg syscalls of quinn's batched path. Two fixes: (1) hold one
`QuicEndpoint::batch()` across each loop iteration's whole recv→process→send phase, so
one `poll_transmit` pass coalesces the backlog into max-size GSO super-packets
(segments-per-sendmsg 3.4 → 6.6; 200 c × 32 KiB: 4.4k → 7.0k, +59%, p99 ~340 ms →
~55 ms); (2) opt-in `Config::udp_gro` — parse the `UDP_GRO` cmsg and fan the coalesced
payload back out per-datagram at drain time, so `recv_batch` consumers see no change
(10 c × 32 KiB: −15% vs tokio → +1%, a tie; 200 c: −38% → −25%). GRO stayed opt-in
because forcing it on globally cost ~20% on 64–512 B high-concurrency cells.

Alongside, `ddd1e7e` (#197) fixed a bench self-DoS — clients topped up to
`num_clients` in-flight streams per loop tick, dumping 1.6 MiB (50 × 32 KiB) into
quinn-proto's send buffer before any ACK could grow CWND — and recorded a negative
result in BENCHMARKS.md: kernel-accurate `SO_TIMESTAMPING` rx timestamps were built,
A/B'd (−8/−9% at 32 KiB), and reverted, because quinn-proto's `ack_delay` accounting
*wants* the kernel→drain latency included in the timestamp delta.

## Outcome

Everything above is in tree today: UDP APIs in `ringline/src/runtime/io.rs`
(`recv_batch`, `recv_batch_timed`, `send_to_gso`), shared GRO cmsg parsing in
`ringline/src/backend/udp_gro.rs` (both backends), `udp_gro` in
`ringline/src/config.rs` (default false, recv-buffer size validated at startup), the
event set in `ringline-quic/src/event.rs`, `batch()`/`connection_stats`/
`next_timer_deadline`/0-RTT accessors in `ringline-quic/src/endpoint.rs`, and the
Bytes-based H3 paths in `ringline-h3/src/connection.rs`. At 32 KiB the H3 gap to
tokio closed to a tie at 10 c and −25% at 200 c (per #198), with ≤512 B cells
improved +4–14% and no regressions.

## Lessons / open questions

- A sans-IO protocol layer is only as fast as the runtime primitives it drives. Each
  bench finding (syscall counts, per-datagram CQE cost) became a new runtime API — GSO
  passthrough, `recv_batch`, GRO — rather than a protocol-layer workaround.
- Plausible theories die to profiling: "RTT jitter" and "packet loss" were both wrong
  at 32 KiB; the drops were load-shedding a CPU-bound worker.
- Batching scope matters more than batching existence: #141 batched transmits, but the
  wins in #190/#198 came from widening the batch window to the whole loop iteration.
- Open (per #198): the residual 200 c × 32 KiB gap is attributed to per-iteration
  syscall overhead vs quinn's recvmmsg/sendmmsg batching — left unresolved in this arc.
- GRO's latency-vs-throughput tradeoff is workload-dependent (the H3 bench enables it
  only for msg_size ≥ 4 KiB); no adaptive heuristic exists.
