# Release comparison campaign: ringline vs tokio, io_uring vs mio

- **Status:** phase 1 complete (192 arms, 189 gated in). Phases 2-4 open.
- **Span:** 2026-09-13 → · PRs TBD · pre-release (post-0.6.4)

Opened **before** the work, per this journal's "land intent before building"
rule. The previous two entries both had to record the opposite
([2026-09-unbuffered-tls.md](2026-09-unbuffered-tls.md),
[2026-09-backpressured-sends.md](2026-09-backpressured-sends.md)); this is the
correction.

## Goal

Refresh the runtime comparison before cutting a release, on the two-guest X710
rig with rezolus instrumentation, so the claims in
[`BENCHMARKS.md`](../../BENCHMARKS.md) and
[`docs/syscalls-and-copies.md`](../syscalls-and-copies.md) are measured on
current `main` rather than inherited.

Three comparisons, not one:

1. **ringline vs tokio** — the published claim.
2. **io_uring vs mio within ringline** — never published; `CLAUDE.md` asserts
   mio should be "correct and non-pathological, not optimal", which is an
   untested claim about how large the gap is.
3. **ringline default vs `--recv-forward`** — the zero-copy recv path, which a
   prior bare-metal run found was the entire difference at 256 B.

## Why this is not just a re-run

Two recorded findings make a naive re-run misleading, and both are the reason
the axes below are what they are.

**The connection-scaled latency penalty is unresolved.** On this rig, in the
latency-bound regime with idle CPUs, ringline's *server* is 25–38% slower than
tokio, and the added latency scales with connection count (~2.5 µs × N): 1
conn identical, 64 conns +0.15 ms, 512 conns +1.3 ms. It is a property of the
server event loop — a runtime-cross 2×2 showed the client runtime is
irrelevant. Two fix hypotheses (incremental flush, `tick_timeout_us` sweep) are
already refuted by clean A/Bs. The working model is
`latency ≈ (conns_per_worker / CQEs_per_iter) × iteration_latency`.

`BENCHMARKS.md` fixes connections at 128 and therefore cannot see this. A
campaign that does the same would publish a flattering number over a known
weakness. **Connection count is a first-class axis here for that reason**, and
rezolus can test the model directly (CQEs per iteration, syscalls per op) rather
than inferring it.

Nothing has re-measured this since the send-path series (#369–#389) landed,
which changed the send path substantially.

**The harness is not currently fair.** Three gaps, all of which must be fixed
before any number is trusted:

| Gap | Where | Consequence |
|---|---|---|
| tokio server uses `read_exact(msg_size)` — one read syscall per message | `ringline-bench/src/bin/server.rs:285` | Previously manufactured a spurious ~9.6× ringline "win". Fixed on the segcache benchmark branch, which never landed on `main`. |
| client hardcodes `send_pool(32768, …)` | `ringline-bench/src/client.rs:578` | At 4096 connections that is 8 slots/conn; the client collapses to 33k ops/s and the arm measures a client limit, not the server. |
| no closed-loop pipeline depth | `ringline-bench/src/bin/client.rs` | `--max-inflight` covers open loop only, so the syscall-amortization claim cannot be tested in closed loop. |

With the fairness fix applied, the previously measured fair 256 B single-core
picture was tokio 2.08M, ringline io_uring 1.67M, ringline mio 1.41M, ringline
io_uring `--recv-forward` 2.04M — i.e. **fair tokio beat ringline-default by
~20%**, and ringline only drew level using zero-copy recv-forward. That is the
number this campaign has to either reproduce or overturn.

## Rig hazards to gate on

An entire previous bare-metal campaign on these hosts was invalidated after the
fact: IRQ and wakeup locality funnelled all work onto one core, capping every
arm at ~208k ops/s regardless of runtime, connection count or loop mode. "All
runtimes are equal" was the *artifact*, not the result.

Every arm is therefore gated before its numbers are used:

- **Per-core utilization** — no single core saturated while siblings idle.
- **Host quiet** — the `check_quiet.sh` guard from the send-path A/B, which
  rejects arms whose host block I/O was not near idle.
- **Little's law** — in closed loop `N = X·R` must hold. If measured
  p50 × throughput ≉ connections, the arm is discarded: that inequality is the
  fingerprint of coordinated omission, a client-side bottleneck, or a stalled
  arm, which is the class of error that produced the withdrawn 2026-05 numbers.

## Plan

Phased, because each phase's output is the next phase's input.

- **Phase 0 — harness + rig validation.** The three fairness gaps above, then a
  validation run whose only job is to show the gates fire: deliberately
  oversubscribe one core and confirm the per-core gate rejects it.
- **Phase 1 — closed-loop peak throughput.** size × connections × server
  config. Produces the saturation point each Phase 2 rate is expressed against.
- **Phase 2 — open-loop latency vs load.** Rates at 10/50/80/95% of Phase 1
  saturation. This is the chart that decides whether "better latency at a given
  load" is true, and the instrument for the connection-scaled penalty.
- **Phase 3 — worker count and pipeline depth.** Tests whether
  connections-per-worker is the real parameter, and whether syscalls/op falls
  with depth as the copy/syscall doc claims.
- **Phase 4 (separate effort) — segcache.** Revive the segcache benchmark
  branch (28k lines, vendors segcache + cache-core, predates the series) so
  `BENCHMARKS.md`'s own workload can be refreshed. Deliberately after the echo
  campaign: echo answers the scaling questions more cheaply, and the revival is
  a substantial job that should not block them.

## What would change our mind

Stated now so the analysis cannot be steered later:

- If the connection-scaled latency penalty reproduces, `BENCHMARKS.md` gains a
  section saying so. A published comparison that omits a known regime where we
  lose is not an honest baseline.
- If fair tokio still beats ringline-default at small messages, that is the
  headline, and the recv-forward path's status (currently opt-in) becomes a
  design question rather than a footnote.
- If measured syscalls/op or copies/op disagree with
  `docs/syscalls-and-copies.md`, that document is corrected — it makes counted
  claims, and counted claims are falsifiable.
- If the per-core or Little's-law gates reject a large fraction of arms, the
  campaign stops and the rig is fixed first. Measuring harder against a broken
  rig is what produced the last withdrawal.

## Outcome — phase 1

192 arms, 4 configs x 4 connection counts x 4 message sizes x 3 reps, one size
per arm. **189 passed the gates; 3 were rejected**, and all three are the same
cell in all three reps (tokio at 2048 connections x 16 KiB, Little's law 18%
out), so that corner is systematically unmeasurable on this rig rather than
noisy. A 1.6% rejection rate is well inside the "stop and fix the rig" bar set
above.

### The connection-scaled latency penalty has inverted

This was the reason connection count became a first-class axis, and the finding
this campaign most needed to re-test. It does not reproduce. Mean latency,
ringline io_uring against tokio:

| conns | 256 B | | | 4 KiB | | |
|---|---|---|---|---|---|---|
| | uring | tokio | delta | uring | tokio | delta |
| 1 | 0.152 ms | 0.165 ms | −8.2% | 0.196 ms | 0.200 ms | −1.9% |
| 64 | 0.225 | 0.370 | **−39.1%** | 0.323 | 0.504 | **−35.8%** |
| 512 | 0.829 | 1.193 | **−30.5%** | 1.604 | 2.160 | **−25.8%** |
| 2048 | 3.948 | 5.024 | −21.4% | 7.183 | 8.945 | −19.7% |

The prior measurement had ringline 25-38% *slower*, worsening with connection
count (+0.15 ms at 64, +1.3 ms at 512). It is now 20-39% faster at those same
points. `BENCHMARKS.md` would have had to carry a disclosure section for that
regime; on current `main` it does not.

Not attributed to any single change — the send-path series (#369-#389) reworked
much of this path between the two measurements, and nothing isolated the cause.
Recorded as "does not reproduce", not as "fixed by X".

### Throughput: io_uring wins everywhere except 16 KiB

Median ops/s, n=3:

| conns | 256 B uring | tokio | mio | 4 KiB uring | tokio | mio |
|---|---|---|---|---|---|---|
| 64 | 285,133 | 173,721 | 265,479 | 198,679 | 127,555 | 183,599 |
| 512 | 621,570 | 431,515 | 450,541 | 322,848 | 238,755 | 260,061 |
| 2048 | 531,199 | 420,798 | 437,845 | 300,284 | 234,501 | 232,425 |

CPU efficiency at 512 connections (ops per server core-second, from
`cpu_usage`): 256 B — uring 47,261, mio 38,477, tokio 37,320. So the throughput
lead is not bought with CPU.

At **16 KiB the default io_uring path loses to its own mio fallback** (118k vs
152k at 64 connections) and to `--recv-forward` by 25-41%. Root-caused and
filed as #397. The root cause in that issue was wrong twice over and has been
re-derived: the benchmark never ran `run_direct_echo` at all (`ringline-bench`
had no `build.rs`, so `has_io_uring` was never set for it and every
`#[cfg(has_io_uring)]` block was dead — #402), and the defect on the path it did
run is a **lost zero-copy** rather than a lost coalesce. `forward_recv_buf`
sends without copying only when the `with_data` slice is the single buffer in
`pending_recv_bufs`; a message arriving in several partial completions goes to
the accumulator instead, and 93.9% of forwards then copy the whole message into
a send-pool slot, at 27% more CPU per operation. Transmit packets per operation at 512 connections are
identical across all three configurations at 256 B (1.99), 1 KiB (1.99) and
4 KiB (3.97) and separate only at 16 KiB: 6.29 for io_uring against 4.65 for
recv-forward and 4.26 for mio — 35% more packets for the same work, at exactly
the size where a message stops fitting one completion.

### Syscall amortization confirmed

0.032 `event` syscalls per operation at 512 connections and 256 B — about 31
operations submitted and reaped per `io_uring_enter` — against tokio's 1.04
reads plus 1.04 writes and mio's 1.99 reads plus 1.00 writes. mio's second read
is edge-triggered epoll reading until `EAGAIN`.

### recv-forward cannot be the default, and this is not a tuning question

Worth recording because the measurements make it tempting. `--recv-forward`
wins at 16 KiB and is roughly neutral below it, which looks like an argument for
making it opt-out. It is not: while enabled, **`with_data` / `with_bytes` never
observe the data** — buffers are held for forwarding and never reach the
accumulator. It turns the connection into a byte pipe.

So it is not a performance knob with a tradeoff; it is a different mode that
disables the primary recv API. Every handler that parses its input — every
protocol client in this workspace — would break. The path to a competitive
default at 16 KiB is #397, not flipping this flag.

## Lessons / open questions

**Four instrumentation errors, each of which produced a plausible wrong
number.** Recorded because the pattern matters more than any of them.

1. A hand-rolled `/proc/stat` sampler counted **iowait as busy**. A worker
   blocked in io_uring's `submit_and_wait` is accounted as iowait, not idle, so
   an idle io_uring server read as **806% busy against tokio's 33%** — about to
   be reported as "24x the CPU for 7% more throughput". True figure ~22% of one
   core. The error does not add noise evenly: epoll runtimes have no such
   accounting quirk, so it biased the comparison against the runtime under
   test. rezolus `cpu_usage` is BPF-derived on-CPU time with only `user`/`system`
   states and is structurally incapable of the mistake.
2. Per-op syscall rates taken as the **mean over a whole recording** rather than
   the loaded window. That gave 0.83 reads/op for an echo server, which is
   impossible — it must read every request it echoes. The loaded-window figure
   is 1.27. A per-op count below the floor the protocol demands means the window
   is wrong.
3. The funnel gate was written **twice wrong**, both caught only by real arms.
   hottest-vs-median rejected every healthy arm (a thread-per-core runtime is
   supposed to saturate its worker count and idle the rest); busy-cores-vs-worker
   -count rejected every lightly loaded arm and did so for the correctly-idle
   runtimes while passing the anomalous one.

4. The packets-per-operation and syscalls-per-operation figures in the first
   version of this entry were **wrong in absolute terms** — published as "1.00
   flat below 4 KiB, 1.97 at 16 KiB" and "0.08 `io_uring_enter` per op", against
   real values of 1.99/3.97/6.29 and 0.032. They were derived ad hoc during the
   analysis rather than by the procedure used for every other number here, and
   nobody re-derived them before they were written down. The *comparison* they
   supported survived re-derivation intact — identical across configurations up
   to 4 KiB, io_uring 35% worse at 16 KiB — which is exactly why the error was
   invisible: the conclusion was right, so the numbers looked right. Corrected
   against the recordings, with one script over every arm.

The common thread: each produced a number that was wrong in a way that flattered
or damned the thing under test, and each would have survived review by anyone
reading only the conclusion. The habit worth keeping is not "use rezolus" but
**ask what floor the work imposes and check the measurement can clear it** —
and, from the fourth, that a figure quoted in a conclusion has to come from the
same re-runnable procedure as the rest, not from a one-off query nobody repeats.

**A negative result is only evidence once the setup could have produced a
positive.** A probe built to show recording dilution produced "both recordings
agree" — because `mode = "stop"` had truncated the long recording and there was
no dilution to detect. It read as a clean null and was an unarmed experiment.

**Open:** phases 2 (open-loop latency vs load), 3 (workers, pipeline depth) and
4 (segcache). The 2048-connection column is the weakest part of this grid —
Little's law errors climb to 6-8% even where they pass — and should be treated
as directional rather than quotable. #397 is the one actionable defect found.
