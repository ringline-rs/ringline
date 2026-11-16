# 2026-09 — Tier 3 park: does it repair a standing imbalance?

- **Status:** shipped — mechanism validated; policy metric measured as count-based (2026-09-26)
- **Span:** Sep 2026 · PRs #464–#469 (mechanism), #470 (rig +
  measurement)

## Goal

Tiers 1 and 2 of the accept work are measured in
[listeners-and-accept-design.md](../listeners-and-accept-design.md), "Measurement".
Tier 3 — park and adopt, moving an *established* connection to another worker —
shipped across #464–#469 with unit coverage but no behavioural measurement. The
question this effort answers is the one the unit tests cannot: given a real
standing imbalance, does park actually converge it, and what does it cost when
there is nothing to repair?

The hypothesis and the scoring were fixed before any run:

| off arm | on arm | conclusion |
|---|---|---|
| stays split | converges | tier 3 works |
| stays split | stays split, `started>0`, `completed≈0` | mechanism abandons every attempt |
| stays split | stays split, `started==0` | policy never fires — `PARK_MARGIN` too wide |
| converges | (any) | experiment invalid — something else is rebalancing |

The control is the load-bearing arm. A healthy merged-mode fleet is balanced at
accept by tier 1, so measuring there produces a confident null that says tier 1
works, not that tier 3 does. So the imbalance is manufactured (#470): steer
the upper half of the workers out of the accept rotation, let the client
establish every connection on the lower half, readmit with no new arrivals.
Tier 1 cannot touch that, because tier 1 only acts at accept time.

## What happened

Rig: `experiments/park-imbalance.toml` and `experiments/park-balanced.toml`, both
checked in. Anvil ephemeral guests — server `z1.c` on hv02, client `z2.c` on
hv01, debian-13, kernel `6.12.63+deb13-amd64`, 24 vCPU guest. 8 workers, 256
connections held for the run, 64 B messages, closed loop at depth 1, 5 s warmup
+ 90 s measured. Numbers come from an off-repo SystemsLab rig and are not
checked in; the contexts are named below so they can be re-read.

### Three harness faults, recorded because each one produced a readable lie

**1. No load at all, reported as success.** The first six runs
(`01a0d727-9d12-7054-4cf9-b42b5d1f5bd8`, renamed `INVALID`) had `bench-client`
missing its required `--runtime`, so it exited rc=2 before opening a connection
— and the step `exit 0`'d anyway. Both completed runs reported **success** with
`park_started = 0`, which scores as row 3 of the table above: "policy never
fires, `PARK_MARGIN` too wide". It would have sent the next person tuning a
constant to fix a missing CLI flag.

The tell was `connections/accepted = 1` — the shell reachability probe alone.
The metrics were not broken; `runtime_metrics.rs` sums metriken's per-thread
shards on read, so `accepted = 1` was truthful and was the evidence. The spec
now propagates the client's exit code and asserts `accepted >= clients` before
any counter is read, so an absent workload cannot be reportable again.

**2. The measured half excluded the answer.** The first instrumentation sampled
`cpu0..cpu7` on the premise, taken from this repo's own accept measurement, that
"workers are pinned, so core *N* is worker *N*". In the anvil guest that is
false: `nproc` = 24 with adjacent SMT siblings, so
`topology::physical_core_first_cpus()` yields `[0,2,4,6,…]` and worker *W* lands
on cpu *2W*. Workers 4–7 — the readmitted half, whose convergence is the entire
question — were on cpu8/10/12/14, outside the window. The `systeminfo.json`
artifact describes the *host* (hv02, 32 CPUs), not the guest, which is how the
wrong mapping was adopted in the first place. The claim in
`listeners-and-accept-design.md` is now qualified as environment-specific.

The fix was to stop depending on the mapping: sample every CPU and count cores
above 50% busy. That statistic is immune to enumeration order, and it correctly
excludes the 22–36% softirq/virtio cores that would otherwise inflate it.

**3. Two coarse windows where a time series already existed.** Every run
uploads a `metrics.rez` Rezolus recording — per-vCPU at 1 s resolution, taken
*inside* the guest (endpoint `127.0.0.1:4246`, 24 CPUs × {user, system}). The
hand-rolled `/proc/stat` diff was a worse instrument for data already collected.
Reading it gave the convergence *curve* rather than two endpoints, which is
where the time constant below comes from. The `.rez` segments are standalone
Parquet blobs in a SQLite container, readable directly, or via
`rezolus mcp query <file> '<promql>'`.

### Result 1 — park converges a standing imbalance

Context `01a0d74b-26ff-70b6-a516-0b30dc9c7f0c`, n=3 per arm.

| | park off | park on |
|---|---|---|
| loaded cores, before → after readmit | 4 → 4 | 4 → **8** |
| converges? | **never**, 66 s observed | **yes, 11 / 18 / 18 s** |
| steady ops (t=60–90) | 377,958 ±1.1% | 592,446 ±2.6% — **+56.7%** |
| `park_started` | 0 | 31,409 / 35,219 / 71,295 |
| `park_completed` = `adopted` | 0 | 264 / 310 / 191 |

The control is unambiguous: three runs with workers 4–7 flat at 13–15% busy for
the full 66 s after readmit. The imbalance does not self-repair, so row 4 —
something else rebalancing — is excluded, and the `on` arm effect is park's.
Effect size is ~34× the control's run-to-run spread.

The Rezolus curve, `on` arm: readmit at t=30, then the idle half's mean busy
goes 0.15 → 0.26 → 0.49 → 0.97 by t=42 and pins at 1.00. **The originally-hot
half stays at 1.00 throughout** — park adds capacity rather than shuffling it.

### Result 2 — no measurable cost when the fleet is balanced

Context `01a0d8f7-cac6-70d3-f2da-348312b9efe4`, `--park-imbalance-ms 0`, n=3.

| | park off | park on | on − off |
|---|---|---|---|
| steady ops | 592,739 ±3.6% | 585,640 ±2.3% | **−1.2%** |
| p50 | 420.7 µs ±3.1% | 422.3 µs ±3.4% | **+0.4%** |
| p99 | 753.8 µs ±4.9% | 764.0 µs ±7.0% | **+1.3%** |

Every difference is inside the spread; pooled across all six balanced runs it is
4.1%. The honest claim is a bound, not zero: **any penalty is below ~4%, which
is this setup's resolution.** All six arms sat at 0.996–0.999 mean worker busy,
so they were equally CPU-saturated.

A second penalty control came free from the imbalance runs: in the pre-readmit
window (t=15–28) the `on` arm has park active but every peer steered out, so
`choose_park_target` filters them and the policy evaluates each tick without
ever firing. 386,981 vs 382,169 off — the per-tick evaluation is free.

**Park recovers the full headroom.** The balanced 8-worker ceiling is 592,739
steady ops; converged park reached 592,446, within 0.05%.

### Prediction refuted

Predicted `park_started ≈ 0` when balanced: 256 connections over 8 workers is 32
each, and `PARK_MARGIN = 8` needs an 8-connection spread. Wrong — `started` was
72 / 933 / 57 and `completed` 72 / 60 / 57. A balanced fleet does throw
transient spread past the margin, and ~60–70 connections relocate per 90 s run.

Completion rates differ sharply by regime, and the direction is the informative
part: **balanced** runs completed 72/72, 57/57 (100%) with 60/933 the outlier,
while **imbalanced** runs abandoned ~99% (264/31,409). That matches
`PARK_COMPLETED`'s doc comment — a park is abandoned when quiesce breaks across
the fd-recovery round trip — because a saturated imbalanced worker has no
connection that will hold still. Attempt counts vary 16× while completions
barely move.

## Outcome

Tier 3 park is validated on the criterion set before the runs: it converges a
standing post-accept imbalance in 11–18 s, recovers the full 8-worker headroom,
and costs nothing measurable above a ~4% resolution when idle. Row 1 of the
table.

Shipped in this PR: the two experiment specs, and this entry. The mechanism
itself was already on `main` (#464–#469); nothing in `ringline/` changed as a
result of the measurement.

## Lessons / open questions

**The policy is connection counts, not busyness — measured, not inferred.**
`publish_load()` stores `connections.active_count()`, and `choose_park_target`
compares those counts against `PARK_MARGIN = 8` / `PARK_FLOOR = 4`. The run
above could not tell the two signals apart: all 256 connections were identical
saturating echoes, so 32 connections/worker *was* 0.999 busy/worker.

`experiments/park-heterogeneous.toml` separates them, by making a small number
of connections expensive instead of making many connections cheap. Twenty-four
connections at `--depth 64`, six per active worker: the CPU gap against the
readmitted half is roughly ninefold, while the *count* gap is 6 — below the
margin of 8. Context `01a0dae3-665e-7002-ab1a-4ea7b9dea8cb`, n=3 per arm:

| | conns/worker | busy vs idle workers | parks started | outcome |
|---|---|---|---|---|
| the run above | 64 | 100% vs 13% | **31,409** | converges 4 → 8 in 11–18 s |
| heterogeneous | **6** | **82.5% vs 7.7%** | **0** | imbalance stands |

Zero in all three `park on` runs, across a 58-second window, with four workers
idle the whole time. The `on` arm is indistinguishable from the `off` control
because `6 >= 0 + 8` never holds, so `choose_park_target` returns `None` every
tick. Same mechanism and same manufactured imbalance as the 256-connection run —
only the count differs, which is what isolates the metric rather than the
mechanism.

The consequence in one line: **a worker saturated by a few expensive connections
will never shed, however idle its peers are.** The cases this predicts, none of
them measured yet, are heterogeneous connections (idle keepalives outnumbering
saturating streams, so counts pick the wrong worker to shed *and* the wrong
target), a single hot connection (`PARK_FLOOR = 4` pins it, and a worker at 1
connection looks like the most attractive target), and varying per-op cost at
equal counts.

Two caveats on that table. The busy workers ran at 76–90%, not pegged — the
prediction said "saturate" and the honest word is "heavily loaded"; it does not
affect the conclusion, since a ninefold gap is exactly what a busyness-based
policy exists to close. And throughput across the six runs spans 5.33–6.18M
ops/s, a 14.6% spread against the 1.1% floor of the depth-1 runs, so **no
performance delta should be read out of this matrix** — the result rests on
`park_started` and the core counts, which were unanimous.

Whether tier 3 *should* read busyness is still a design question rather than a
measurement one. A count is the only thing tier 1 can use, since it places a
connection that does not exist yet, and tier 3 inherits that table;
`publish_load` is one function away from publishing busy time instead.

**The policy constants are not caller-tunable.** `PARK_MARGIN`, `PARK_FLOOR` and
`PARK_PER_TICK` are private consts in `backend/uring/event_loop.rs`. The caller
opts in per connection via `offer_for_park` and can decline, but cannot retune
the margin. Deliberate for now; revisit if a workload wants a different
aggressiveness.

**Throughput and latency are one measurement here, not two.** Closed loop at 256
connections and depth 1 means `ops = 256/latency` — it holds to under 2% on all
twelve runs (e.g. 671 µs → 381,520 predicted vs 375,132 measured). 4→8 workers
is 1.53×, not 2×, because latency only improved 1.58×. Any statement of the form
"park recovered X% of the ideal throughput" is meaningless in this rig; there is
no throughput ceiling independent of the latency the server delivers. Absolute
ops/s figures here are a function of the chosen concurrency; the on-vs-off
comparisons are what transfer.

**`connections/accepted` counts adoptions.** `accepted = 258 + adopted` exactly
across all twelve runs. Worth knowing before reading `accepted` as an arrival
count. (258 rather than 257: 256 client connections plus the shell reachability
probe, with one connection unaccounted for and not chased.)

**Reopen conditions.** Revisit the count-vs-busyness choice if a heterogeneous
workload shows misdirected parks. Revisit the ~4% penalty bound on a rig with a
tighter noise floor — the saturated 8-worker regime here was 3.6% run-to-run
against the 4-worker regime's 1.1%, so a smaller cost is not excluded, only
unresolved.
