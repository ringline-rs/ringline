# A Shutdown SQE half-closing the slot's next occupant

- **Status:** **shipped** — and one hypothesis **refuted after being merged**
- **Span:** 2026-09-29 (one day) · issue #518 · PRs #522, #523, #525 · backport #524 ·
  unreleased (0.7.0) and `release/0.6.x`

A single CI failure that looked like data loss in a brand-new public API turned out
to be a lifecycle bug three layers away from where everyone looked, including me.
The first explanation was wrong, was merged with a confident claim attached, and
was refuted by its own control an hour later. That sequence is the most useful
part of this entry, so it is written in the order it happened rather than
back-to-front from the answer.

## Goal

`backpressured_send_waits_for_pool_capacity_without_duplication`
(`ringline/tests/echo.rs`) failed once in CI —
[run 36524008903](https://github.com/ringline-rs/ringline/actions/runs/36524008903),
job `Test` (io_uring, debug), on a commit of #489,
2026-09-29 04:58Z — with 12288 of 32768 bytes arriving:

```
thread 'ringline-worker-0' panicked at ringline/tests/echo.rs:2862:31:
backpressured send failed: connection closing
ringline: connection task panicked; connection 0 closed
...
assertion `left == right` failed: every byte arrives exactly once: no duplication, no loss
  left: 12288
 right: 32768
```

Filed as #518 **without** classifying it as flaky, on the grounds that the failing
assertion is the invariant `ConnCtx::send_backpressured` exists to hold and the API
ships in 0.7.0. That call was right for the wrong reason: it was not a flake, but
it also was not the API's invariant failing.

The branch it appeared on touched only `ringline-bench/` and `experiments/`, so the
`ringline` crate under test was identical to `main`'s at the merge base — recorded
in the issue at the time, and it held up.

## What happened

### Hypothesis 1 — the readiness probe. Merged, then refuted.

#518 described connection 0 as *"a connection the client had not closed; it was
sleeping, then reading to FIN."* That premise is false, and it is what made the
failure unexplainable.

`wait_for_server` (`ringline/tests/echo.rs:195`) proves the server is up by
connecting and **discarding** the stream. The server accepts that probe like any
other client, so it becomes connection 0 with its peer already gone — and
`BackpressuredEchoHandler` sends *unprompted* on accept. Connection 0 was never
one of the test's sixteen readers.

This was verified, not argued: a handler on the discarded probe completes send 1
and fails send 2 with `Broken pipe (os error 32)` — the same second error in
#518's log — and holding the same probe open makes the same handler complete 8 of
8. `wait_for_server_probe_reaches_a_send_on_accept_handler` asserts both halves and
fails under that mutation.

PR #522 (`60ff17f`) added `connect_retry`, which waits for the server *and* returns
the connection that proved it, so nothing discarded reaches a handler. It predicted
the failure would go to 0/100 and said so in the PR body.

**The control refuted it** (context `01a0eed9`, 100 iterations per arm at 2 CPUs):

| arm | mode | failed | predicted |
|---|---|---|---|
| before | alone | 0/100 | ~2/100 |
| before | suite | 3/100 | ~7/100 |
| after | alone | **2/100** | 0/100 |
| after | suite | **10/100** | 0/100 |

The fix made it **more** frequent. Per-failure attribution said why:

- `before` — all 3 failures carried **both** `connection 0: connection closing`
  **and** `connection 1: Broken pipe (os error 32)`.
- `after` — 14 `Broken pipe` across connection 0 (8) and connection 1 (6), and
  **zero** `connection closing`.

So hypothesis 1 was right about the *string* it explained — `connection closing`
exists only where a discarded probe does, and vanishes with it — and wrong about
the cause. **The probe was shielding connection slot 0 by occupying it.** Removing
it exposed two real client connections instead of one, which is what 3/100 → 10/100
looks like. `after/alone` at 2/100 also ruled out suite contention.

`connect_retry` and the `NotConnected` documentation correction from #522 stand on
their own; the claim attached to them did not. The PR body and #518 were corrected
in place rather than quietly, because the false premise was the whole obstacle.

### Instrumenting instead of deducing again

Deducing a mechanism from panic text had now failed twice, so the next step
recorded what happened instead. `repro518_instrumented` (`#[ignore]`d,
environment-parameterized) logs per connection: which accept it was, how many sends
completed, the raw `errno`, whether the handler reached `shutdown_write`, and what
the client on the other end saw. It asserts nothing.

Mutation-verified before use — capped at three sends it reports `anomalous=2/2` with
each reader's 12288 bytes — so a clean arm means clean rather than blind.

A 2×2 over the two conditions the test deliberately creates (context `01a0eeee`,
400 rounds per arm):

| arm | stall | pool | anomalous |
|---|---|---|---|
| baseline | 300 ms | 8 | 8/400 |
| **nostall** | **0** | 8 | **21/400** |
| bigpool | 300 ms | 64 | 6/400 |
| nostall-bigpool | 0 | 64 | 4/400 |
| calibration (unmodified test) | — | — | 2/200 |

It fails in **all four**. Neither the 300 ms stall nor a pool small enough to force
parking is required, so the **send-capacity admission FIFO is exonerated** — and
`nostall` is the *worst* arm, the opposite of a backpressure story.

Two facts from the per-round records reframed the issue:

1. **Zero reader errors, and `sends_ok × 4096 == bytes received` in 79 of 79
   accept/reader pairs.** Nothing was lost or duplicated: the client saw a **clean
   FIN** after exactly the bytes that succeeded. This was never data loss — it was
   the server truncating the stream early, which both #518 and the test's own
   `"no duplication, no loss"` message misdescribed.
2. In **33 of 38** anomalous rounds every failing connection shared *one*
   `sends_ok` value, in contiguous accept-order groups. They were half-closed
   *together*, on a single event-loop iteration — not in independent races.

A clean FIN followed by `EPIPE` is the signature of `shutdown(SHUT_WR)`, and every
handler in this test calls `shutdown_write()` when it finishes its eight sends.

### Isolating the operation

Three arms at the strongest-signal configuration (context `01a0eefd`, 400 rounds
each), with a positive control:

| arm | conns | `shutdown_write()` | anomalous |
|---|---|---|---|
| withshutdown (control) | 16 | yes | **49/400** |
| noshutdown | 16 | **no** | **0/400** |
| conns1 | 1 | yes | **0/400** |

The `Shutdown` SQE is necessary, and a *concurrent* second connection is necessary.
`RL518_SHUTDOWN=0` removes every `Shutdown` SQE while changing nothing else the
test measures — the task ending still closes the connection and still FINs, so the
client still sees EOF.

### The bug

`Ring::submit_shutdown` (`ringline/src/backend/uring/ring.rs`) built
`Shutdown::new(Fixed(conn_index), SHUT_WR)`: the socket is named as the
**registered-file slot**, not as an fd. Nothing pinned that slot for the
operation's lifetime.

- A `Shutdown` is not a queued send, so `try_finalize_close`'s drained check
  (`!in_flight && queue.is_empty()`, plus forward-write and chain) could not see it.
- Its completion was discarded outright — `OpTag::Shutdown => {}`.
- Its `user_data` payload was a bare `0`, carrying no generation, so a stale one
  could not be detected afterwards either (domain invariant 3).

io_uring does not order independent SQEs (domain invariant 2). So the `Close` that
frees the slot could be submitted and complete first, the next accept could register
the slot, and the kernel could then execute the FIN **against that new connection**
— a live peer, cleanly half-closed, whose next send fails `EPIPE`.

Every observation follows: the clean early FIN, the victims dying in groups on one
iteration, and `conns1` clean because there is no later connect to inherit the slot.

## Outcome

**Fixed in #523 (`8c5deb0`), backported to `release/0.6.x` in #524.**

`ConnSendState::shutdown_inflight` sits with the other close sub-states. It is set
on **both** submission paths — the immediate one in `DriverCtx::shutdown_write` and
the deferred one in `submit_next_queued` — and `try_finalize_close` requires it
clear before submitting the `Close`. `handle_shutdown` clears it and re-drives the
finalize. The SQE carries its generation, so a completion that outlived its slot is
rejected and counted as `ringline/ring` `shutdown_stale`. `reset_send_state` clears
it defensively, as it does `close_submitted`.

Verified on Linux, both arms in one run (context `01a0ef0a`, 2 CPUs):

| arm | io_uring clippy / build | regression tests | instrumented | original test |
|---|---|---|---|---|
| unfixed | 0 / 0 | — | **46/400** | **2/200** |
| fixed | 0 / 0 | **2 passed** | **0/400** | **0/200** |

The gate's coverage was checked by enumerating every `submit_close` site rather
than assumed: one is inside `try_finalize_close`; `drain_close_retries` only retries
a `Close` whose submission already passed the gate; and `run_shutdown` closes every
slot at worker teardown, where no slot is reused afterwards.
`force_finalize_close` ends by calling `try_finalize_close`, so it goes through the
gate rather than around it.

**Backport adaptation worth knowing.** Both `submit_shutdown` call sites on
`release/0.6.x` discard the result (`let _ = submit_shutdown(..)`), where `main`
records success through `WriteHalf::Shutdown`. The flag there is therefore set only
inside an `is_ok()` guard: setting it for an SQE that was never accepted would hold
the close forever and **leak the fd and slot**, turning a half-close bug into a
worse one. That line is the only part of the backport that is not a transcription.
The instrumented reproducer was dropped from the backport because
`send_backpressured` does not exist on that line.

**Not a regression from anything recent.** #515 (`1be7049`, park-drain slot
scanning) was a natural suspect given the contiguous-slot signature, but it merged
at 17:42Z and the failure occurred at 04:58Z the same day. The bug is older than
every commit landed that day.

**Reproducers committed in #525**, with `experiments/REPRODUCERS.md` as an index.
`bpsend-shutdown-fix-verify.toml` builds both arms from `main` and makes the
`unfixed` arm by **reverting the fix commit**, which is durable as branches age out
and asserts something stronger: putting the bug back must bring the failure back.
Smoke-tested in its committed form before landing — 6/60 unfixed versus 0/60 fixed.

### Not measured

`shutdown_stale` was predicted to be 0 and **never read** — the experiment payload
does not collect the metric. What exists instead is an argument from code:
`close_submitted` is set only after the `Shutdown` CQE clears the flag, and
`reset_send_state` runs only at reactivation, which requires the `Close` to have
completed, so a stale `Shutdown` CQE has no reachable path. That is weaker than a
measurement and should be read as such.

### Risk this introduces

The close now waits on a CQE it did not wait on before, so a `Shutdown` completion
that never arrived would hold the close and leak the slot. io_uring posts a
completion for every SQE unless `IOSQE_CQE_SKIP_SUCCESS` is set, which this op does
not set — but that is the symptom to look for if slots are ever seen leaking.

## Lessons / open questions

**A clean arm with no positive control cannot be told from a blind instrument.**
This is the expensive one. Hypothesis 1's control would have been unreadable
without its `before` arm, and every sweep afterwards carried one. A 2%-per-run
failure is absent from 100 runs 13% of the time.

**State the prediction, including what refutes it, in the spec before running.**
Both live specs do. It is what stopped the all-four-arms result from being
retrofitted into a backpressure story — the spec had already written down that
failing in all four arms means "look at accept and slot allocation, not sends".

**A merged claim needs correcting where the claim lives.** #522's body and #518
both asserted the probe was the cause. Both were corrected in place, with the
earlier reading kept and labelled rather than deleted, because it is right about
the string and wrong about the cause and that distinction is the useful part.

**Deduction from panic text failed twice; instrumentation settled it in one run.**
The two false starts (the probe, and a stale `Shutdown` across *rounds* rather than
within one) both came from reasoning about a log. `conns1` killed the second one
immediately.

**"Data loss" was the wrong frame, and the test said so in its assertion message.**
`sends_ok × 4096 == bytes received` in 79/79 pairs. Naming the statistic that would
actually distinguish loss from truncation — which the instrument did by recording
both sides — reframed the search.

**Harvesters fail silently, and both of today's did.** One treated only
`completed`/`failed` as terminal when the server reports `success`, so finished arms
read as forever-pending. The other used `grep "verify.log"`, where `.` is a regex
wildcard that matched the artifact row `verify logs.json` and downloaded the wrong
file — which printed "no RESULT line", indistinguishable from a failed arm. Both
looked like "nothing has happened yet". Use `grep -F` for literal names, and
enumerate terminal states from what the server actually emits.

### Open

- `shutdown_stale` unmeasured, as above.
- The two sibling specs (`bpsend-shutdown-sqe`, `bpsend-epipe-diagnose`) are now
  regression detectors that should report 0. Nobody runs them on a schedule; they
  are submitted by hand.
- Five send-on-accept tests in the `send_backpressured` cluster `.expect()` on a
  resolved send. They were latent versions of hypothesis 1's failure and escaped
  only because their sends never park long enough. #522 moved them to
  `connect_retry`, which removes the exposure, but the pattern is worth watching in
  new tests.
