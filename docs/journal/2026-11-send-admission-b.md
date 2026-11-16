# Experiment B: what send_admitted costs, and what FIFO order costs

- **Status:** closed. Both conditions of section 4's decision rule held, the
  first with a floor that cannot tell a cost of 1 to 2% from none. The latency
  cost in the contended case, which the rule does not count, is for the owner
  to weigh.
- **Span:** Nov 2026 · follows #930 (`send_admitted`) and #939 (`abort`) ·
  SystemsLab context `send-admission-expB` (`01a1ddd8-a0ba`)

## Goal

Section 4 of `docs/send-admission-design.md` asks whether a server can send
every plain reply with `send_admitted`. Two costs decide it: the CPU a
`send_admitted` call adds when the pool is free, and the replies that wait
behind the FIFO's head while slots are free.

## Method

Binaries: `experiments/send-admission-b-build.toml`, io_uring builds of two
versions of B's tools. The first (artifact `01a1ddd9-1448`) ran the two floor
runs, echo runs 1 and 2, and the four contended pilots. The second (artifact
`01a1de0c-432a`) adds `bytes-admitted-await` and ran echo runs 3 and 4 and the
24 contended runs. #945's `ringline-bench` differs from the second only in two
doc comments in `ringline-bench/src/bin/server.rs`. Its `ringline/src` also
carries #946 to #949, which landed on main between the build and the merge,
so building #945 does not build the same library.

Uncontended: `bench-server` with one worker, pinned to CPU 0, in a guest on
hv02 (z1, 24 vCPU); `bench-client` in a guest on hv01 (z2, 56 vCPU), across the
X710 LAG. 256 B messages, 256 connections. Arms, `--echo-mode`:

| arm | after `with_bytes` returns |
| --- | --- |
| `bytes-nowait` | `send_nowait` |
| `bytes-admitted` | `send_admitted`, the `SendCompletion` dropped |
| `bytes-admitted-timeout` | `send_admitted` under a 1 s `timeout`, then the `SendCompletion` under a 1 s `timeout` |
| `bytes-admitted-await` (control) | `send_admitted`, then the `SendCompletion` awaited with no timeout |
| `bytes-nowait-defer` (control) | `send_nowait`, with `--defer-recv-arm` |

Each cell runs its own server and two windows: a closed-loop window, which
saturates the worker, and an open-loop window at 55,000 requests/s, about half
the closed-loop rate. The primary statistic is the worker thread's CPU time
(`/proc/<pid>/task/<tid>/schedstat`) over the closed window, divided by the
client's operations in it. The secondary is the open window's p99, measured
from each request's scheduled send time.

Two single-arm `bytes-nowait` experiments ran first, each in its own pair of
guests (`experiments/send-admission-b-echo-single.toml`; `01a1dddb-0388`,
`01a1dddb-03c0`). They measured 8.87 and 9.22 us of worker CPU per operation,
at 111,786 and 108,620 operations/s: 4.0% apart between boots, as large as the
effect being measured. So the arms are compared within one boot instead, as
the November echo rerun on this rig did (`BENCHMARKS.md`, run `01a1bc9d`).
`experiments/send-admission-b-echo-gen.py` writes one experiment with a
discarded warm-up cell and four rounds of the arms, the order rotated each
round: `send-admission-b-echo.toml` with the first three arms, and
`send-admission-b-echo-controls.toml` with all five. Each ran twice, in two
boots.

Contended: `experiments/send-admission-b-contended.toml`, one guest on hv03.
`admission-server` (one worker, pinned to CPU 0) and `admission-load` (CPUs 2
and up) over loopback, with `net.ipv4.tcp_wmem` capped at 1 MiB so that a
stalled reply stays in the send pool. Every 4 s, three peers that never read
each ask for a 3 MiB reply from a 512 x 16 KiB pool, and 200 ms later one
7 MiB reply waits at the head of the FIFO. 8-byte requests for 256 B replies
arrive at 2,000/s on 16 connections throughout. `settle_limit` is 1 s and
`admit_limit` is 0.5, 1 or 2 s. Small replies are sent with `send_admitted`
or with `send`; large ones always with `send_admitted`. Four repetitions of
each of the six cells.

Four pilots at a ratio of 1 with `send_admitted` chose the cap:

| pilot | `tcp_wmem` cap | stalled replies | large reply |
| --- | --- | --- | --- |
| `01a1dddb-03eb` | 4 MiB (default) | 2 MiB | 2 to 5 ms; no stalled reply aborted: not contended |
| `01a1dde4-9da6` | 64 KiB | 2 MiB | admitted after the abort, then not drained within `settle_limit` and aborted, in all 10 episodes |
| `01a1de0a-1dae` | 1 MiB | 3 MiB | 807 to 810 ms in all 10 episodes |
| `01a1de0a-1de2` | 256 KiB | 2.5 MiB | 814 to 818 ms in all 10 episodes |

## Prediction

The predictions were written before the first rack run was submitted, and are
as first committed with the second version, after echo runs 1 and 2 had
finished; the note after them was added with the results. The contended part
was revised before the first rack submission, after a local smoke run on mio
(macOS), which showed the large-reply timeout at a ratio of 0.5 and seven small
replies just past the limit.

Uncontended, closed loop:

- `bytes-admitted` adds a completion-table entry, a FIFO enqueue and pop, and
  a dropped `SendCompletion` per reply. The design predicts CPU per operation
  within the `bytes-nowait` floor. I expect it 1 to 4% above, which may be
  outside a floor under 1%.
- `bytes-admitted-timeout` also arms and cancels two timers and wakes the task
  when the send completes. I expect 5 to 15% above `bytes-nowait`, outside the
  floor.
- Refuted if `bytes-admitted` is within the floor (the design's prediction
  holds), or if `bytes-admitted-timeout` is too.

Uncontended, open loop: p99 within the spread for `bytes-admitted`, and higher
for `bytes-admitted-timeout` only if its CPU cost is large enough to queue
replies at the fixed rate.

Contended:

- The large reply is delivered after about 800 ms (the stalled peers' abort at
  `settle_limit`, less the 200 ms delay) at ratios 1 and 2, in both arms. At
  0.5 it times out at `admit_limit` in both arms. If it is delivered in
  milliseconds the pool was not contended and the run measures nothing.
- `send`: every small reply within `admit_limit` at every ratio, p99 of a few
  milliseconds.
- `send_admitted` at ratios 1 and 2: every small reply within `admit_limit`,
  since each waits only until the head is admitted after the abort. p99 near
  the wait behind the head, up to about 800 ms.
- `send_admitted` at 0.5: a few late, those scheduled just before the head
  arrived and read after it, which wait the head's whole `admit_limit`. In a
  FIFO where every wait has the same bound, the waiters ahead of a reply leave
  by their own deadlines, which come before its deadline. So "fewer below a
  ratio of 1" holds only by that margin.
- The design's decision rule then holds for the contended case: at ratios of
  1 or more `send_admitted` delivers no fewer small replies than `send`. Its
  cost there is latency, which the rule does not count.

Two phrases in the 0.5 bullet are imprecise as written: it is the head that
waits the whole `admit_limit`, and the replies behind it wait less; "that
margin" means those few late replies.

## Results

Linux 6.12.116, `debian-13-6.12` guests. No server refused or closed a
connection in the two floor runs or in any of the 136 windows of echo runs 1
to 4, and the worker was 99.6 to 99.8% busy in every measured closed window.

### Uncontended

Worker CPU per operation, closed loop, in microseconds. Each run is one boot of
the two guests; each figure is the median of its four cells, with the change
against `bytes-nowait` in the same run. Runs 1 and 2 are
`send-admission-b-echo.toml` (`01a1dde5-8bb4`, `01a1dde5-8c01`), runs 3 and 4
`send-admission-b-echo-controls.toml` (`01a1de0c-50d4`, `01a1de0c-510d`).

| arm | run 1 | run 2 | run 3 | run 4 | all cells |
| --- | --- | --- | --- | --- | --- |
| `bytes-nowait` | 8.95 | 9.06 | 9.02 | 9.09 | 9.00 [8.63-9.33], n=16 |
| `bytes-admitted` | 9.20 (+2.8%) | 9.04 (-0.3%) | 8.90 (-1.4%) | 9.09 (-0.1%) | 9.09 [8.77-9.39], n=16 |
| `bytes-admitted-timeout` | 7.72 (-13.7%) | 7.61 (-16.1%) | 7.71 (-14.6%) | 7.80 (-14.2%) | 7.67 [7.50-8.15], n=16 |
| `bytes-admitted-await` | | | 7.73 (-14.3%) | 7.70 (-15.3%) | 7.71 [7.59-8.40], n=8 |
| `bytes-nowait-defer` | | | 7.91 (-12.3%) | 7.80 (-14.2%) | 7.80 [7.63-8.42], n=8 |

- **The floor.** Within a boot, consecutive `bytes-nowait` cells differ by a
  median of 2.0% (12 pairs, up to 6.1%); its run medians spread 1.6% across
  the four boots.
- **`bytes-admitted`.** Paired by round, it was higher than `bytes-nowait` in
  12 of 16 rounds (a two-sided sign test gives p = 0.08), by a median of 1.7%
  (mean 0.9%, range -5.1% to +4.1%). In run 1 it was higher in all four
  rounds. The difference is inside the floor, taken here as the difference
  between consecutive `bytes-nowait` cells; the sign test is what says the
  experiment cannot tell a cost of 1 to 2% from none. The design's prediction
  (within the floor) holds with that floor. By the refutation condition
  above, mine (1 to 4% more) is refuted, although the paired data are
  consistent with a 1 to 2% cost.
- **`bytes-admitted-timeout`** is 14 to 16% cheaper, in every run, and its
  closed-loop throughput is 16 to 19% higher (about 129,000 against 110,000
  operations/s). My prediction (5 to 15% more) is refuted. The two controls,
  added after runs 1 and 2, separate what it changes:
  - `bytes-admitted-await` awaits the same settlement with no timers, and is
    as cheap: paired against it, `bytes-admitted-timeout` differs by a median
    of -0.3%. The timers cost nothing measurable.
  - `bytes-nowait` with `--defer-recv-arm` is 12 to 14% cheaper than
    `bytes-nowait` (paired median 11.7%), with `send_nowait` and no wait.
    Awaiting settlement before the next `with_bytes` also arms the next
    receive after the reply's send completes. I infer the saving is that
    deferral, the effect `BENCHMARKS.md` records for
    `ConfigBuilder::defer_recv_arm` (21.11 to 19.10 us per operation at 8
    workers); syscalls and completions per operation were not counted.
- **Open loop**, 55,000 requests/s: every arm's median worker CPU per
  operation is within 15.13 +/- 0.25 us (cell range 14.28 to 15.65), and the
  median p99 is 385 to 395 us (cell range 369 to 491). Nothing separates the
  arms.

### Contended

24 runs in a rotated order, four per cell. "Not within" counts small replies
whose latency from their scheduled send time exceeded `admit_limit`, late or
lost, of about 80,000 offered in each run's 40 s window.

| ratio | small replies | not within, per run | small p99 | large replies delivered |
| --- | --- | --- | --- | --- |
| 0.5 | `send_admitted` | 124, 200, 186, 176 | 470 ms | 0 of 40 (admission timeout) |
| 0.5 | `send` | 0, 0, 0, 0 | 11.5 ms | 0 of 40 (admission timeout) |
| 1 | `send_admitted` | 0, 0, 0, 0 | 771 ms | 40 of 40, after 808 ms |
| 1 | `send` | 0, 0, 0, 0 | 11.5 ms | 40 of 40, after 805 ms |
| 2 | `send_admitted` | 0, 0, 0, 0 | 770 ms | 40 of 40, after 808 ms |
| 2 | `send` | 0, 4, 0, 0 | 11.4 ms | 40 of 40, after 806 ms |

Runs, by cell and repetition 1 to 4 (all `01a1de11-`): `send_admitted` 0.5
`afaa b0e3 b216 b390`, `send` 0.5 `afdd b0b7 b23f b365`, `send_admitted` 1
`b00a b192 b26b b33d`, `send` 1 `b036 b169 b295 b311`, `send_admitted` 2
`b05f b13a b1be b2ea`, `send` 2 `b08b b10f b1eb b2c2`.

- Every run was contended. In each episode the large reply either waited
  about 808 ms for the stalled peers' abort, or timed out in admission (10 of
  10 at 0.5, by the server's count). All 30 stalled replies per run were
  aborted at `settle_limit`.
- `send_admitted` delivered every small reply within the limit at ratios 1
  and 2. At 0.5 it missed 0.16 to 0.25% of them: all delivered late and none
  lost, at most 514 ms after their scheduled send, and no small reply's
  admission timed out. I infer these are the requests scheduled just before
  the head arrived and read after it, admitted when the head's admission
  timed out. The prediction held.
- `send` missed 4 small replies in one run at ratio 2, the prediction's one
  failure. Its sends were refused 4 times in that run, and 8 times in one run
  at 0.5 that missed none in the window. A refusal means no slot was free,
  and the server aborts the connection; when each happened, and which
  admission took the last slots, was not recorded.
- The cost of FIFO order is latency: small replies sent with `send_admitted`
  wait behind the head until it is admitted or times out, p99 about 770 ms.
  `send`'s 11.5 ms is this setup's floor on loopback: the uncontended first
  pilot had a small-reply p50 of 5.9 ms and a maximum of 15.0 ms.
  Correction (2026-11-15, Experiment C): the floor was the load generator.
  Its small connections waited for their next send in a blocking read under
  `SO_RCVTIMEO`, which the kernel rounds up to a timer tick, so each request
  was written up to a tick late and its latency, measured from the scheduled
  time, carried that. With the wait moved to `ppoll`, the same server's
  delay from scheduled time to admission under `send` was 0.4 ms at p99 in
  this case (`2026-11-send-admission-c.md`, C0). Both arms ran the same
  load generator, so both carried the lateness.

## Outcome

Section 4's decision rule holds on both conditions:

- uncontended, `send_admitted`'s CPU per operation is within the floor of
  `send_nowait`'s, a floor that cannot tell a cost of 1 to 2% from none;
- contended, at `admit_limit` of `settle_limit` or more, `send_admitted`
  delivered no fewer small replies within the limit than `send`: none missed,
  against 4 missed by `send` in one run at ratio 2.

By the rule, the specification for section 4 covers only guarded batches,
and a server sends every plain reply with `send_admitted`, with `admit_limit`
at or above `settle_limit`.

The rule does not count latency. While a head waits for stalled peers to be
aborted, every reply on the worker waits behind it, up to `settle_limit`,
with slots free: here a p99 of 770 ms. A server that cannot accept that needs
tries, as the section's constraints describe. Whether it can is for the
owner.

## Not covered

- One message size (256 B), one rig (a z1 server guest, one worker) and one
  kernel (6.12). A larger reply, which needs several slots, was not measured
  uncontended.
- No arm sent TLS, guarded batches, or zero-copy replies.
- The contended case ran on loopback with the kernel's send buffer capped at
  1 MiB.
- One `large_delay_ms` (200 ms). At ratio 1 the margin between the longest
  small-reply latency (812 to 817 ms) and `admit_limit` is about that delay.
  A head that arrived as the stalled replies were admitted would make small
  replies scheduled before it reach the peer more than `settle_limit` after
  their scheduled send, and arrive late.
- The first contended episode starts at the start of the measured window, so
  refusals or waits at its onset fall on requests scheduled before the
  window, and are not counted. That can only lower the counts.
- Syscalls and completions per operation were not read from the recordings,
  so the receive-arming explanation rests on the two controls.
- The design asked for an A-against-A pair before the comparison. The pair
  ran in separate boots and gave 4.0%; the comparison then ran within one
  boot, where consecutive cells of one arm are the A-against-A pairs.
