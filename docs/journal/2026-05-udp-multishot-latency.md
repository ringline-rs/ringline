# UDP multishot recv latency: the kernel-side EAGAIN peek

- **Status:** closed — finding recorded, proposed single-shot mode deferred (migrated
  2026-08-18 from issue [#167], filed 2026-05-16)
- **Span:** 2026-05-16 · bpftrace investigation on Linux 6.12.63 (Debian 13), loopback

## Goal

Explain the ~10µs per-RTT latency penalty of ringline UDP echo over ringline TCP at
single-client load (`ringline-benchmarks`, 1 client × 64B, 1 worker per side,
loopback): TCP 43µs p50 vs UDP 53µs p50, despite the connected-socket work (#165)
already having moved the client onto the same lightweight `IORING_OP_RECV`/
`IORING_OP_SEND` opcodes TCP uses.

## What happened

Kernel profiling with bpftrace (kprobe/kretprobe latency histograms over ~12s
windows; full script and procedure preserved in [#167]) localized ~6µs of the gap
to `io_recv` itself: ~3µs p50 per invocation under TCP vs ~6µs under UDP, with
`udp_recvmsg` firing **~2× per `io_recv` invocation** (650k vs 320k calls over the
trace window) while `tcp_recvmsg` fires ~1×. The raw protocol paths point the other
way — `udp_recvmsg` (~1µs) and `__udp4_lib_rcv` (~3µs) are *faster* than their TCP
counterparts (~1.5µs, ~6µs) — so the overhead is in the io_uring multishot wrapper,
not UDP proper. `io_send` cost was identical (~12µs) on both runs.

**Mechanism.** The kernel's multishot `IORING_OP_RECV` loops inside each invocation:
receive a datagram, post a CQE with `IORING_CQE_F_MORE`, then call `udp_recvmsg`
*again* to check for another queued datagram, exiting on `-EAGAIN`. TCP doesn't pay
this because one `tcp_recvmsg` drains everything available in the stream. At
single-client load there is never a second datagram, so the peek is ~1µs of pure
waste per CQE — two recv sides per RTT plus the extra `io_recv` wrapping ≈ 6µs of
the 10µs gap. The remaining ~4µs is userspace bookkeeping, wake/scheduling, and
measurement noise. This is kernel behavior, not a ringline bug; it bounds what
userspace optimization can recover.

**Why the current design stays.** The peek amortizes: at high concurrency the
second `udp_recvmsg` returns a real datagram and the loop body is productive work —
matching the benchmark suite, where UDP out-scales TCP at 50–200 clients. Multishot
is the right default for throughput-oriented users.

## Verdict: single-shot recv mode deferred

An opt-in single-shot mode (one `IORING_OP_RECV` SQE per datagram, via a config
knob or per-socket setter) would trade per-datagram SQE submission for skipping the
peek — an estimated ~4–6µs per RTT for latency-sensitive single-client workloads
(RPC clients, DNS resolvers, probes), and a regression at high concurrency.
Deferred as NO-GO for now: the win is real but bounded (~5µs of a ~50µs RTT), it
adds API surface that deserves design discussion, and the throughput levers
(zero-copy, connected sockets, #165) matter more to most UDP users.

**Reopen if:** a latency-sensitive single-client UDP consumer materializes, or the
upstream io_uring recv path changes the peek cost — the numbers are tied to Linux
6.12 and must be re-measured before any build decision.

## Lessons / open questions

- Opcode parity isn't cost parity: after #165 both protocols submit the same
  recv/send opcodes, yet the multishot *re-arm discipline* differs per protocol
  semantics. Profiling the kernel side (not just userspace) was what surfaced it.
- Call-count ratios (`udp_recvmsg` per `io_recv`) were the decisive signal, more
  than the latency histograms alone.

[#167]: https://github.com/ringline-rs/ringline/issues/167
