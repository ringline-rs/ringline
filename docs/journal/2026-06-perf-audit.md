# The June perf audit: copies, allocations, and a two-day burst

- **Status:** shipped (retrospective entry, reconstructed 2026-07-06 from commit history)
- **Span:** 2026-06-12 → 2026-06-13 · PRs #212–#227 · v0.2.1 (ringline 0.2.1, ringline-redis 0.4.0, ringline-memcache 0.4.0)

## Goal

A systematic performance pass over the hot paths: send, recv, the event loop,
and the protocol clients. The organizing question was where copies, heap
allocations, and syscalls hide per operation — not micro-tuning, but removing
whole categories of per-request work. Everything landed in a two-day burst
(fifteen commits, f3797ad through 37aa3b4) and shipped as the coordinated
v0.2.1 release (a6974f8, #224), which CHANGELOG.md labels "Coordinated release
of the 2026-06 performance audit."

## What happened

**zc-threshold: zero-copy is not free below a size floor.**
f3797ad (#212) added `Config::send_zc_threshold` (default 4096): guard sends
below it are gathered into the send copy pool and submitted as plain `Send`
instead of `SendMsgZc`. Per the CHANGELOG, small guard sends had been paying
zero-copy bookkeeping — an in-flight slab entry plus a ZC notification CQE per
send — and the memcpy is cheaper than the two-completion lifecycle; this
removed a small-value SET throughput plateau observed in benchmarks. 32c7f70
(#222) extended the idea into the clients: `ClientBuilder::zc_threshold`
(default 4096) folds small `fire_set_with_guard` values into the coalescing
send buffer, recovering ~17% throughput on small pipelined SET workloads
(CHANGELOG.md, 0.2.1). The 4096 default was validated by a parameter sweep on
the bench rig — crossover measured at 1–4 KiB — as recorded in CLAUDE.md's
Copy Semantics section.

**Allocation and copy elimination.**
3295b96 (#214) removed per-request encode allocations in redis/memcache —
reusable per-client encode buffers, in-place guard-SET prefixes, `itoa` for
integers, with the wire format golden-tested byte-identical. 2aa3786 (#215)
made `take_frozen()` detach via `split_to` so the stashed remainder reuses
tail capacity instead of allocating, and dropped two redundant table lookups
per `WithBytesFuture` poll. a81f776 (#223) rewired TLS recv to drain rustls
plaintext straight into the accumulator via `BufRead`, deleting the per-worker
16 KiB scratch buffer and one copy of every received plaintext byte. adfa0c8
(#219) did the mio-side equivalent for sends — encrypt into the owned send
buffer rather than encrypt-then-clone — and wired the `send_exhausted` pool
metric so send-pool exhaustion is visible instead of silent.

**Event-loop cost.**
8f006c8 (#216) made `CancellationToken` futures register as a waiter once
(O(1) vs O(n) rescans) and de-duplicated ready-queue entries per poll batch.
7ce44ea (#217) trimmed memory traffic: no unused 16-byte `big_cqe` payload per
drained CQE, swap-buffer reuse in the send-retry drains, and same-iteration
recv-buffer replenish. feea437 (#221) skipped the `flush()` `io_uring_enter`
syscall when no SQEs are queued. fe0899f (#213) made stall timing opt-in via
`RINGLINE_LOOP_DIAG`, removing ~4 clock reads per iteration by default.

**Write coalescing.**
0574576 (#220) gave the memcache client the fire_* write-coalescing layer
(`ClientBuilder::max_batch_size`, default 1 — no behavior change unless opted
in), matching redis. CLAUDE.md records the measured payoff: ~10x GET
throughput at batch 16 vs batch 1 against memcached.

**Housekeeping.**
7fa3b0b (#218) removed an unused client crate (acaccaa #226 dropped its stale
CI and release-workflow jobs the day after), and 37aa3b4 (#227) closed out
with the dev bump to 0.2.2.

## Outcome

Fifteen commits, one coordinated release, and no API breakage beyond the
clients' minor bumps. The recurring shape of the wins: a copy, an allocation,
or a syscall that ran per-request or per-iteration, removed by reusing a
buffer or checking a cheap condition first. Both new thresholds
(`send_zc_threshold`, client `zc_threshold`) defaulted to 4096 on the strength
of the same sweep.

## Lessons / open questions

- Zero-copy has a floor. Below a few KiB, ZC bookkeeping (slab entry +
  notification CQE) costs more than the memcpy it avoids — measure the
  crossover, don't assume. The sweep-validated 1–4 KiB range is in CLAUDE.md.
- Instrumentation isn't free either: #213's always-on stall timing was itself
  a hot-path cost worth removing.
- The audit was perf-scoped, not exhaustive. TLS sends still carried an extra
  scratch-buffer copy after 0.2.1; that fell later, in 9be1809 (#254, v0.4.0).
  And a separate July correctness audit (~35 fixes, PRs #236–#244, per
  CLAUDE.md) found real bugs this pass did not look for — a perf sweep and a
  correctness sweep are different lenses over the same code.
