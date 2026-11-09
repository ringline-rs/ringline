# 2026-11: Audit of the connection lifecycle and close path

- **Status:** closed — 14 findings recorded, every one fixed: F1 (#771), F2 and F3 (#767), F4 and F5 (#774), F6 (#769), F7 (#776), F8 (#779), F9 (#768), F10 (#791), F11 (#792), F12 (#793), F13 (#794) and F14 (#798); the design limitations L1 to L6 stand, L2 and L3 stated on `SendHalf::close` by #803, and L7 was changed in #807; checked against 5b92399a
- **Span:** 2026-11-07 → 2026-11-08 · tree a2e28073 (`main`) · PRs: F2 and F3 #767, F9 #768, F6 #769, F1 #771, F4 and F5 #774, F7 #776, F8 #779, F10 #791, F11 #792, F12 #793, F13 #794, F14 #798

## Goal

Audit the code that takes a connection from a close request to slot reuse, on
both backends, against a written list of invariants. No diff was under
review; the question was whether the code as it stands holds what its docs,
comments and tests say it holds. Four questions: correctness against the
invariants, ordering across slot reuse (stale completions), error paths and
partial failure, and whether the docs state current behaviour.

Method (`cs:audit`): scope and invariants written first and agreed with the
owner; a state map; five fresh read-only reviewer agents, one per concern, in
parallel; every finding re-checked by the auditor by reading the quoted path,
and run on a clean worktree where the mio backend allows it on macOS. The
io_uring path cannot be compiled on the development host, so every io_uring
finding below is a trace, not a run; the status line says which.

A first pass ran against f19c31e8, which turned out to be 228 commits behind
upstream (#537–#763). Its record was discarded; its findings went into this
pass as seeds to re-establish or drop, and the per-seed outcome is listed
under "Seeds from the stale pass".

## Scope

- `ringline/src/connection.rs`: `ConnectionState` (`read`, `lifecycle`,
  `write`, `generation`, `established`, `socket_handed_off`, `recv_direct*`,
  the hangup flags), `ConnectionTable`.
- `ringline/src/handler.rs`: `ConnSendState` close fields; `DriverCtx::close`
  and `shutdown_write` on both backends.
- io_uring: `driver.rs` `arm_hangup_poll`, `reset_send_state`,
  `close_connection`, `close_connection_graceful`, `close_lead`,
  `try_finalize_close`, `submit_committed_close`, `force_finalize_close`;
  `event_loop.rs` run-loop order, `poll_ready_tasks` exit arms,
  `handle_hangup_poll`/`handle_hangup_peek`, the direct-recv EOF/error arms,
  `handle_shutdown`, `handle_connect`, `handle_timeout`, `handle_close`,
  `handle_park_install`, `drain_close_retries`, `check_close_notify_deadlines`,
  the `close_submitted` guards in the send handlers; `ring.rs` `CloseLead`,
  `submit_close`.
- mio: `driver.rs` `close_connection`, `finish_close`, `clear_pending_sends`;
  `event_loop.rs` run-loop order, `handle_readable` EOF/error sites,
  `handle_writable` connect arm, `fail_connection_on_send_error`,
  `drain_pending_closes`, the connect-deadline scan.
- `runtime/mod.rs` `Executor::remove_connection`, `defer_release`/`Orphan`;
  `runtime/io.rs` `ConnCtx::close`, `release_half`, `drop_half`, the public
  `close`/`shutdown_write`/`with_data_result` docs; `runtime/send_completion.rs`.
- Docs: `CLAUDE.md` Connection Lifecycle and Domain Invariants 3/8/9;
  `docs/connection-state-model-design.md`, `docs/mio-close-lifecycle-design.md`,
  `docs/write-half-design.md`, `docs/half-closed-send-wait-design.md`,
  `docs/recv-direct-design.md` (Close and hangup sections),
  `docs/recv-multi-identity-design.md`; `config.rs`, `metrics.rs`,
  `CHANGELOG.md` Unreleased.

Out of scope: `submit_next_queued` and coalescing except where they re-drive
the close; park/adopt beyond the `Closing` blocker, `socket_handed_off` and
`handle_park_install`'s identity check; forward beyond its close hooks; UDP;
TLS record handling; disk-I/O teardown.

## Invariants

D = from docs, comments or tests; I = inferred by the auditor. Agreed with the
owner before the reviewers were sent (1–18 before the first pass; 19 and 20
added for this tree).

1. D Only `Driver::close_connection` (directly or via
   `close_connection_graceful`) and `DriverCtx::close` set
   `Lifecycle::Closing`, on both backends.
2. D A second close request after `Closing` is a no-op.
3. D+I A connection that reaches `Closing` releases its slot and fd exactly
   once, unless a queued send never drains and the peer never errors
   (documented unbounded deferral).
4. D The fd close is not committed while any SQE naming the slot may still
   complete; the hard-linked `CloseLead` ends the connection's own requests
   before the Close runs (Domain Invariant 8).
5. D The task gets one poll window between the close request and the Close
   commit; a send queued in that poll drains first (#371). Same on mio.
6. D After `close_submitted`, no CQE handler pushes a new SQE for that
   connection.
7. D Every completion that can arrive after slot release checks the generation
   before touching connection state (Domain Invariant 3).
8. D Slot reuse starts clean.
9. D `Executor::remove_connection` runs before the slot is released.
10. D Peer FIN: `read = Eof{..}` recorded and the recv waiter woken before
    `close_connection`; `truncated` never downgraded; buffered bytes stay
    readable.
11. D Read error: `read = Error` and `fail_recv(generation, err)` before close;
    `with_data_result` observes the error only for that generation.
12. D Bytes queued before close reach the wire; an awaited send that cannot
    complete is failed, never left pending or delivered to a dropped task.
13. D `shutdown_write` after a close is requested (mio) / committed (uring) is
    a no-op; a Shutdown SQE never lands on the slot's next occupant.
14. D Connect failure wakes the connect waiter with the error, then closes;
    timeout bookkeeping stays balanced; the slot does not leak.
15. D+I `CONNECTIONS_ACTIVE` decrements iff it incremented; `conn::CLOSED`
    increments once per teardown and means the same thing on both backends.
16. D A `ConnId`/handle for a previous generation cannot act on the slot's new
    occupant.
17. I The close-path lists hold no duplicates or released indices.
18. I `force_finalize_close` abandons only what its comment says.
19. I Dropping the last half closes the connection exactly once, inside or
    outside a task poll; a stale half closes nothing.
20. I The hangup poll closes a connection only when the stream has ended and
    nothing is buffered or in flight; a poll/peek CQE for a recycled slot
    changes nothing.

## Verdict per invariant

| # | io_uring | mio |
|---|---|---|
| 1 | holds (`uring/driver.rs:1342`, `handler.rs:1119`) | holds (`mio/driver.rs:614`, `handler.rs:2882`) |
| 2 | holds | holds |
| 3 | holds (unbounded deferral documented on `SendHalf::close`) | holds (same) |
| 4 | holds with caveat (F7) | n/a |
| 5 | **broken** (F1); caveats: FIN-policy and close-then-await (L1, L2) | holds for the step-4 and awaited-send paths; **plausible break** for unawaited sends (F9); L2 |
| 6 | holds | n/a |
| 7 | **broken** (F4); F10 touch-before-check | holds |
| 8 | holds with caveat (F10: `park_in_flight` never reset) | holds |
| 9 | holds | holds |
| 10 | holds | holds |
| 11 | holds with caveat (F6) | holds with caveat (F6) |
| 12 | holds | holds with caveats (F9; L3) |
| 13 | holds with caveat (F7, F12) | holds |
| 14 | **broken** (F4); F5 benign | holds |
| 15 | **broken** (F2, F3, F8) | **broken** (F2, F3, F8) |
| 16 | holds | holds |
| 17 | holds | holds |
| 18 | holds with caveat (F11) | n/a |
| 19 | holds | holds |
| 20 | holds | n/a |

## Findings

Status: **confirmed** = reproduced by a run, or every step of the path traced
and quoted with no trigger assumption; **plausible** = the path is real, the
trigger was not shown. All dispositions are "open" at the time of writing.

### F1 — io_uring commits the Close inside `drain_completions` when the FIN and the last gating CQE land in one batch (invariant 5). Confirmed by trace.

`close_connection`'s in-flight arm (`uring/driver.rs:1396-1401`) returns
without registering the connection on `pending_finalize_closes`; it relies on
the in-flight send's CQE. That CQE is handled inside `drain_completions`:
`handle_send` (`uring/event_loop.rs:2735-2736`) → `submit_next_queued` →
empty arm (`driver.rs:1838`) → `try_finalize_close`, which sets
`close_submitted` and pushes the lead+Close pair before `poll_ready_tasks`
(loop order L504 vs L568). The end-of-iteration drain added by #371 (L656)
covers only connections pushed onto the list. When the FIN-woken task is
polled its `send()` is refused at `handler.rs:541-546`. Same shape through
`handle_shutdown` (L2549), `fire_chain_complete` (L3878),
`drain_conn_send_queue` (`driver.rs:1959`) and the ZC/coalesced success arms.

`parked_send_defers_a_requested_close` (`uring/event_loop.rs:7669`) asserts
`close_submitted` straight out of `drain_completions`, so the test pins the
bug for the parked arm. `batch_recv_eof_then_stale_send_cqe` (L11056)
injects the exact batch but asserts only `close_requested()`; its "stale" send
encodes generation 0 against a fresh table, so it is live.

Fix: push onto `pending_finalize_closes` in all three arms of
`close_connection` and have `try_finalize_close` return early while the index
is on the list (the drain `mem::take`s it first); `handle_park_install`'s
immediate commit needs an explicit bypass. Flip the parked test's last
assertion; add `!close_submitted` to the batch test and rename it. Needs a
Linux run.

Disposition: fixed in #771, by a narrower change than proposed: the
completion handlers call `defer_finalize_close`, which registers the
connection on `pending_finalize_closes`, and only the end-of-iteration drain
(`finalize_pending_closes`), `force_finalize_close` and the park install call
`try_finalize_close`. Verified in a SystemsLab anvil VM (Linux 6.12,
`experiments/close-commit-drain-verify.toml`): at the tests-only commit the
five pinning tests fail, among them
`a_fin_batched_with_the_last_send_cqe_leaves_the_close_to_the_drain`, whose
task reads the FIN and has its reply refused; at the fix they pass, with the
full io_uring suite.

### F2 — `CONNECTIONS_ACTIVE` never incremented for outbound connections on io_uring, or for TLS outbound on mio (invariant 15). Confirmed (mio run; io_uring read).

`established = true` without an increment: `uring/event_loop.rs:3642-3646`
(plaintext connect success), `uring/event_loop.rs:1222-1225` and
`mio/event_loop.rs:915-920` (TLS outbound `HandshakeJustCompleted`). Both
backends decrement on teardown when `established` (`uring:3714-3723`,
`mio/driver.rs:702-705`). Every such connection nets −1; `Gauge` is an
`AtomicI64`. Reproduction (mio): plaintext outbound `delta_open=2
delta_after_close=0`; TLS outbound `delta_open=1 delta_after_close=-1`.

Fix: increment at the three sites, or set `established` and the gauge in one
helper.

Disposition: fixed in #767. `ringline/tests/connection_metrics.rs`
(`outbound_plaintext_connection_balances_the_active_gauge`,
`outbound_tls_connection_balances_the_active_gauge`) was red on a2e28073 for
TLS (`open = 1`, expected 2) and is green with the increments at the three
sites. The plaintext case passes on mio before and after; it fails on io_uring
before the fix, which Linux CI checks.

### F3 — `conn::CLOSED` means different things per backend (invariant 15). Confirmed (mio run).

mio `finish_close` (`mio/driver.rs:699`) increments unconditionally; io_uring
`handle_close` (`uring/event_loop.rs:3720-3721`) only when `established`. A
refused mio connect: `closed_delta=1 accepted_delta=0`. `metrics.rs:75` has
no doc for `CLOSED`.

Fix: gate mio on `was_established`; document `CLOSED` and `ACCEPTED`.

Disposition: fixed in #767 (one change with F2: both counters now follow
`established` on both backends). `refused_connect_is_not_counted_as_a_close`
was red on a2e28073 (`closed = 1`) and is green with the gate.

### F4 — `handle_connect` has no generation check and the Connect SQE carries none (invariants 7, 14, 4). Plausible.

`ring.rs:560` encodes the Connect payload as 0; `handle_connect`
(`uring/event_loop.rs:3489-3494`) checks only `connections.get(i).is_none()`.
`try_finalize_close` has no term for an in-flight Connect, so a close on a
`Connecting` slot (timeout, or the application) commits the Close while the
Connect is still in the kernel; `handle_close` releases the slot; LIFO reuse
hands it to the next accept (which happens inside `drain_completions`); the
old Connect CQE then runs an arm against the new occupant — the ECANCELED arm
closes it, the errno arm drops its TLS state and closes it, the success arm
resets its accumulator and closes it (accepted occupant) or marks it
connected and wakes its waiter before its own connect completed (`Connecting`
occupant). Trigger needs the Connect CQE dispatched after the Close CQE
(cancel push failed, or `DEFER_TASKRUN` task_work posting the cancelled
CQE after the inline Close CQE); not shown on a kernel.

Fix: carry the generation in the Connect payload and check it first; build the
cancel targets with the same payload; add a `connect_inflight` gate to
`try_finalize_close` mirroring `shutdown_inflight`.

Disposition: fixed in #774, by the identity check
alone: `submit_connect` encodes the slot's generation, `handle_connect` returns
on a mismatch before touching the slot, and the cancel targets carry the same
payload. The proposed `connect_inflight` gate was added and then removed on
review: a late CQE fails the generation check, and, read from the kernel source
and not tested, the kernel holds the Connect's own file reference so
re-registering the slot does not redirect it, and the Close's lead ends a
Connect still in the kernel (from Linux 6.13 an `ASYNC_CANCEL` of the fixed
file, which cancels a poll-armed Connect; before 6.13 a `shutdown(SHUT_RDWR)`,
which disconnects a `SYN_SENT` socket and wakes the poll); with the gate, a
cancel push refused by a full SQ left the slot `Closing` until the kernel's own
connect timeout (about 127 s at the default `tcp_syn_retries`). Verified by
`experiments/connect-identity-verify.toml` (SystemsLab experiment
`01a1bc34-4f45-7153-842b-ffa04d3156c4`, Debian 13, Linux 6.12): at the
tests-only commit 7b719b82 the four pinning tests that exist there fail (4
passed; 4 failed), among them
`a_stale_connect_cqe_leaves_the_reused_slot_alone`, whose stale success CQE
opens the new occupant; at 173cb83a ten pass, and the uring gate (fmt, clippy
on three builds, rustdoc, `cargo test --all`) passes. The trigger itself (a
Connect CQE dispatched after the Close CQE) was not reproduced on a kernel.

### F5 — connect-timeout cancels never match (invariant 14). Confirmed by reading; benign.

`arm_connect_timeout` (`handler.rs:2531-2535`) encodes the generation; the
cancel targets at `uring/event_loop.rs:3526` and `3568` use 0. Every cancel
is `-ENOENT`; the Timeout stays armed for its full duration and is then
rejected by `handle_timeout`'s generation/flag checks. One root cause with F4
(user_data identity on the connect/timeout pair).

Disposition: fixed in #774, with F4: the cancels of
the Timeout in `handle_connect` name the generation `arm_connect_timeout`
encoded, and the cancel of the Connect in `handle_timeout` names the
generation the Connect now carries. The heading's "never match" holds for
every occupant after a slot's first: a fresh slot's generation is 0, which
the payload-0 cancel matched. Pinned by
`a_completed_connect_cancels_its_timeout_by_its_generation`,
`a_failed_connect_cancels_its_timeout_by_its_generation` and
`the_connect_timeout_cancels_the_connect_by_its_generation`.

### F6 — local aborts are reported by `with_data_result` as a clean peer close (invariant 11). Confirmed (mio run 10/10 vs control 10/10; io_uring read).

Sites that `wake_recv` + `close_connection` with `read` left `Open` and no
`fail_recv`: mio `fail_connection_on_send_error` (`mio/event_loop.rs:1184-1193`),
mio accumulator cap (`1040-1047`) and `append_or_close` (`721-729`), mio TLS
record error (`964-977`); io_uring `arm_direct_recv_or_close` cap/no-room
arms (`uring/driver.rs:205-220`) and push failure (`232-248`), TLS record
error (`uring/event_loop.rs:1296-1311`). Reproduction (mio): handler queues
8 MiB with `send_nowait`, parks on `with_data_result`, peer resets → `Ok(0)`
10/10; control with nothing queued → `Err(ConnectionReset)` 10/10;
accumulator cap → `Ok(0)`. The doc at `runtime/io.rs:2706-2709` says `Ok(0)`
means the peer closed cleanly; only the TLS record-layer case is listed as an
exception.

Fix: `read = Error` + `fail_recv` with a descriptive error at each site (the
write error; `InvalidData`/`OutOfMemory` for the cap), or extend the doc.
Owner's call which; the auditor recommends the code change.

Disposition: fixed in #769, by the code change: each site records
`read = Error` and fails the parked read first (mio: the write's error; the
plaintext cap: `QuotaExceeded`; io_uring: a receive that could not be
armed), so `with_data_result` resolves `Err`. A TLS record-layer error still
resolves `Ok(0)`, as documented. Pinned by
`ringline/tests/local_abort_errors.rs`; its write-error case runs on mio
only: on io_uring a failed plaintext send does not close the connection
(F13), and the send and the receive race for the socket's pending error, so
the case was intermittent there (3 of 6 CI jobs).

### F7 — `force_finalize_close` sets `write = Open` under an in-flight Shutdown, and the io_uring `shutdown_write` lacks the `close_requested()` guard mio has (invariants 13, 4). Plausible, narrow.

`uring/driver.rs:1728-1732` resets `write` without touching
`shutdown_inflight`; `try_finalize_close` stays gated, so a repeat
`shutdown_write` (`handler.rs:1165-1196`, checks `write == Open` and
`close_submitted` only) submits a second Shutdown; the first Shutdown CQE
clears the flag and commits the Close with the second in the kernel — the
#518 shape. Trigger: a TLS `DriverCtx::close` (reachable only from the
encrypt-failure paths), the 5 s `CLOSE_NOTIFY_TIMEOUT` firing while a
Shutdown is in flight, and a repeat `shutdown_write` in that window.

Fix: reset only `ShutdownPending` to `Open`; add `|| cs.close_requested()`
to the io_uring guard, matching mio (`handler.rs:2915`).

Disposition: fixed in #776, as proposed:
`force_finalize_close` resets the write half to `Open` only from
`ShutdownPending`, whose queued sends it released, and the io_uring
`shutdown_write` returns when `close_requested()`, as the mio one does. Pinned
by `a_forced_close_keeps_an_in_flight_shutdown_recorded` and
`shutdown_write_after_a_requested_close_submits_nothing`; verified by
`experiments/force-close-write-half-verify.toml` (SystemsLab experiment
`01a1bc3b-0b66-7125-1396-0547f875c73f`, Debian 13, Linux 6.12): at the
tests-only commit 0bea7c16 both fail (1 passed; 2 failed), at the branch head
8fd4e34d (the fix b8883058 plus the spec and the alpha bump) three pass, and the uring gate (fmt, clippy on three builds, rustdoc, `cargo test
--all`, lib 780 passed) passes. The trigger (a repeat `shutdown_write` in the
window between the deadline and the Shutdown CQE) was not reproduced from
outside the event loop.

### F8 — worker exit leaves `CONNECTIONS_ACTIVE` inflated and abandons mio closing connections (invariants 15, 3). Traced.

The `OpTag::Close` arm of io_uring's `handle_shutdown_cqe`
(`uring/driver.rs:2605-2610`), which `run_shutdown` runs for each CQE of its
drain, releases
TLS state, claims and the slot without decrementing the gauge. mio `run()`
returns; `worker.rs:1235-1245` drops tasks and the event loop, so streams
close on drop: no `finish_close`, no `CLOSED`, no decrement, queued bytes
lost, no close_notify, awaited sends unsettled. Under
`TaskPanicPolicy::Contain` the process-wide gauge then over-reports for the
rest of the run. Not stated in CHANGELOG or the mio close design.

Fix: decrement per established connection on both exit paths; document the
mio abandonment or run one bounded `drain_pending_closes` pass before
returning.

Disposition: fixed in #779: the `OpTag::Close` arm of io_uring's
`handle_shutdown_cqe` and a mio `count_out_open_connections`, run at `run`'s shutdown
return and in `drain_after_failure`, count each established connection into
`CLOSED` and out of `CONNECTIONS_ACTIVE`, as `handle_close` and `finish_close`
do. The mio abandonment is documented rather than replaced by a drain pass:
`docs/mio-close-lifecycle-design.md`, "Worker exit", and the `metrics.rs` docs
no longer list worker exit as an exception. Pinned by
`worker_exit_counts_open_connections_out` in
`ringline/tests/connection_metrics.rs`: on mio it fails at the tests-only
commit 0ef26fb2 (gauge 3, expected 0) and passes at the fix; on io_uring,
verified by `experiments/exit-closes-count-down-verify.toml` (SystemsLab
experiment `01a1bc48-5b3e-718d-e469-71f2b93528e2`, Debian 13, Linux 6.12): 0
passed, 1 failed at 0ef26fb2, 1 passed at the branch head 4ba14ccf, and the
uring gate (fmt, clippy on three builds, rustdoc, `cargo test --all`) passes. A
connection whose Close has not completed when `run_shutdown`'s 10 s bound
runs out is not counted out: one holding a zero-copy entry whose
notification does not arrive (#607), or one whose Close the ring refused on
every pass (#787).

### F9 — mio: a close raised inside the step-6a/8 flush or `drain_forward_resumes` with only unawaited sends queued drops the task unpolled (invariant 5). Plausible.

`drain_send_completions` (`mio/event_loop.rs:1428-1445`) re-polls only when
it delivered a settled send; `clear_pending_sends_into` pushes one only for
entries with a `SendId`, and `send_nowait`/forward/TLS-handshake output have
none. So `fail_connection_on_send_error` from the 6a flush wakes the task
onto `ready_queue` and `drain_pending_closes` (6b) removes it before the next
poll. The f19c31e8 bug (S2) is fixed for awaited sends by #619; this is its
residue for unawaited ones. Trigger (reset landing between step 3's poll and
6a) not reproduced.

Fix: after a flush that requested a close, run `collect_wakeups` +
`poll_ready_tasks` before `drain_pending_closes`, or retain the entry one
pass while its task is on `ready_queue`.

Disposition: fixed in #768. In an iteration with a close pending, the mio
finalize step polls the ready tasks first (`finalize_closes`). The F6 work
made the trigger observable: its write-error test hung 1 run in 3 until #768.

### F10 — `handle_park_install` takes `park_in_flight[i]` and runs `abandon_park_drain(i)` before its generation check; `park_in_flight` is never reset at close or reuse (invariants 7, 8). Plausible, low.

`uring/event_loop.rs:2063-2071` vs the check at ~L2103. A stale install CQE
for occupant N while N+1 has its own install in flight takes N+1's entry and
abandons N+1's park. The trace could not construct a stale install CQE
(install completes inline before any Close for the slot).

Fix: generation check first; clear `park_in_flight[i]` in `close_connection`.

Disposition: fixed in #791, as proposed but
for where the clear runs: `handle_park_install` compares the CQE's
generation with the slot's before it reads `park_in_flight` or the drain,
and a CQE for a previous occupant closes the fd it carries and nothing
else; `clear_conn_claims`, which `handle_close` and `run_shutdown` run
before they release a slot, clears `park_in_flight` (the other release
sites free a slot allocated in the same call, which no park has reached).
A clear in `close_connection` would have sent the install
CQE of a connection closed mid-park down the stray path, losing the
`PARK_ABANDONED` count for it. Three tests pin the fix:
`a_stale_install_leaves_the_next_occupants_park_in_flight` and
`a_stale_install_leaves_the_next_occupants_park_drain_alone` inject the
stale CQE over the next occupant's park, and
`a_recycled_slot_does_not_inherit_a_park_in_flight` recycles a slot with an
install in flight. The stale CQE was still not constructed on a kernel:
`FixedFdInstall` completes inline at submit, so its CQE is in the ring
ahead of any Close CQE for the slot. Found by the review of #791, outside
the change: `run_shutdown`'s CQE drain has no `ParkInstall` arm, so an
install CQE drained at worker exit falls through and its fd stays open
for the rest of the process.

### F11 — `check_close_notify_deadlines` re-runs `force_finalize_close` every tick while the finalize is blocked; `fail_send_ids` sets `capacity_released` unconditionally (invariant 18). Traced, low.

`uring/event_loop.rs:4753-4790`, `uring/driver.rs:2020-2034`. One spurious
`wake_send_capacity` per tick until the Shutdown CQE lands (the force
cancels a chain, so only a Shutdown holds the commit).

Fix: skip the force while `shutdown_inflight` or a chain is active; clear
the deadline in `force_finalize_close`; set `capacity_released` only when
`ids` is non-empty.

Disposition: fixed in #792, by the
deadline clear alone: `force_finalize_close` disarms the deadline before
it calls `try_finalize_close`, so it runs once per close, and
`handle_shutdown`'s `defer_finalize_close` commits the Close when the
Shutdown CQE lands (`drain_shutdown_retries` keeps a parked Shutdown
until its push succeeds, so the CQE comes). No skip is needed: with the
deadline disarmed there is no second call to skip. The `capacity_released`
part as proposed would have been wrong: an unawaited send holds a pool
slot and carries no `SendId`, so an empty `ids` does not mean nothing was
released. `fail_send_ids` now takes whether the drained queue had
entries, from each caller. Tests:
`a_forced_close_blocked_on_a_shutdown_runs_once` (the deadline is
disarmed by the force, a second tick reports no capacity, the Shutdown
CQE commits the Close), `resetting_an_empty_send_queue_releases_no_capacity`,
and the control `a_forced_close_abandoning_an_unawaited_send_releases_capacity`,
which passes before and after.

### F12 — `handle_shutdown` ignores the Shutdown result; `WriteHalf::Shutdown` doc says "Our FIN has been issued" (invariant 13, docs). Traced, low.

`uring/event_loop.rs:2538-2550` clears `shutdown_inflight` on any result.
After `-ENOTCONN` the write half still reads `Shutdown`. Doc fix ("requested")
or record the failure.

Disposition: fixed in #793, by both changes the
finding offered: the
`WriteHalf::Shutdown` doc says the FIN has been requested, and a
`shutdown(SHUT_WR)` the socket refuses is counted in
`connections{op="shutdown_failed"}` on both backends (`handle_shutdown`
now takes the CQE result; mio's two `shutdown(Write)` calls check theirs).
The write half stays `Shutdown`: the refusal means the socket is already
closed, so sends fail at the socket either way, and on io_uring the Close
the Shutdown held goes ahead. `a_failed_shutdown_is_counted_and_releases_the_close`
dispatches a Shutdown CQE with `-ENOTCONN`; `a_refused_shutdown_is_counted`
(mio) calls `shutdown_write` on a socket that was never connected, which
`shutdown(2)` refuses with `ENOTCONN` on Linux and macOS.

### F13 — `handle_send`'s terminal error arm drains the queue and fails the awaited send but does not close the connection or record a read error (invariants 11, 12). Confirmed by reading; consequence unassessed.

`uring/event_loop.rs:2775-2782`: `release_pool_slot`,
`drain_conn_send_queue` (releases every queued `send_nowait` without
submitting it), `defer_finalize_close`, `settle_send(Err)`. No
`close_connection`, unlike `handle_tls_send` (L3830-3832). The connection
stays `Open` until the hangup poll reports the socket error. A caller of
`send_nowait` is not told its bytes were dropped (fire-and-forget by
contract), but a reader parked on the connection waits for the hangup poll
rather than being failed now.

`handle_send_msg_coalesced`'s terminal error arm (L3197-3212) has the same
shape: it closes only a TLS run (`close_on_error`), so a plaintext run that
fails leaves the connection `Open` too.

Fix: decide whether a terminal plaintext send error should close (as TLS
does) and set `read = Error`, in both arms; or document the asymmetry.

Consequence, observed in #769's CI through the coalesced arm (an 8 MiB
`send_nowait` goes out as coalesced runs of up to 32 pool slots): a peer that
resets the connection while that unawaited response is draining is reported
to the parked reader as an `Err` the test accepts in 3 of 6 io_uring jobs and
as `Ok(0)` in the other 3; the test records no kind on a pass, so
`ConnectionReset` is the kind the mechanism predicts, not one observed. The
reading of the mechanism is that the failed send takes the socket's pending
error and its CQE reports it, and the receive that follows then reports a
plain EOF; not traced in a run. #769 runs its write-error test on mio only.

Disposition: fixed in #794. Every send-failure arm on io_uring
(`handle_send`, `handle_send_msg_zc`, `handle_send_msg_coalesced` for a
plaintext or TLS run, `handle_tls_send`, `fire_chain_complete`, and the
three retry give-up arms) runs `AsyncEventLoop::abort_connection`, the
backend's counterpart of mio's: `read = Error`, `fail_recv` with the send's
error, `close_connection`. A connection whose close is already requested is
left alone, so a send the close's lead cancelled does not mark the read
half. The slab's `close_on_error` flag went with the TLS/plaintext
distinction. Pinned by six io_uring unit tests
(`*_send_error_aborts_the_connection`,
`a_send_error_after_a_requested_close_does_not_mark_the_read_as_an_error`)
and by `write_error_teardown_is_reported_to_the_reader`, run on both
backends from this change. Red-then-green on an anvil VM
(`experiments/send-error-abort-verify.toml`, Debian 13, kernel 6.12): on the
tests-only commit the five arm tests fail; the integration test passed 10 of
10 there, so the reader got an error in every run, which by the mechanism
above is the receive taking the socket's error ahead of the send (not
traced; #769's CI saw the other order in 3 of 6 jobs), so on io_uring the
unit tests are the evidence. That run also failed two existing tests that
encoded the old behaviour (`plaintext_run_error_does_not_close` and the
mixed-operations CQE proptest, which armed a receive on the connection a
failed send had closed); both were updated. On the fix all pass, 10 of 10.

### F14 — docs and comments false or unresolvable at a2e28073. Confirmed by quote and grep.

False claims:

- `handler.rs:55-59`: `close_send_count` "Each CQE decrements this; when it
  reaches zero, `try_finalize_close` fires." Written once to 0, never read.
  Delete the field.
- `connection.rs:97-98`: "`on_close` is only fired when `established ==
  true`." No `on_close` exists. `established` gates the teardown metrics.
- `docs/recv-direct-design.md:574-576`: "`try_finalize_close` cancels a
  multishot receive by its user data, gated on `recv_multishot_armed`" —
  neither exists.
- `docs/mio-close-lifecycle-design.md` Tests: "no `#[cfg(test)]` module in
  `backend/mio/`" — there are two (`mio/driver.rs:1108`,
  `mio/event_loop.rs:1689`). Same doc item 5: the mio `DriverCtx` "cannot
  reach the TLS table" — it holds `tls_table` (`handler.rs:2890-2897`).
- `CLAUDE.md` Connection Lifecycle: "with a `shutdown` hard-linked ahead of
  it" — the lead is `Shutdown` before 6.13, `CancelAll` from 6.13, nothing
  for a handed-off socket, as the same file's Domain Invariant 8 says.
- `uring/event_loop.rs:559-560`: "force-close connections where close_notify
  was sent but the close CQE never arrived" — the set is `close_pending`
  connections whose drain has not finished; a committed Close is never in it.
- `uring/event_loop.rs:4738-4740`: `check_close_notify_deadlines` "by calling
  `try_finalize_close`" — it calls `force_finalize_close`.
- "the flush pass registers writable interest": `handler.rs:2922-2924`,
  `mio/event_loop.rs:1343-1346`, `docs/write-half-design.md` Transitions.
  Interest is fixed `READABLE|WRITABLE` since #395.
- `CHANGELOG.md` Unreleased L736-741: "(io_uring itself commits the Close
  before the task can respond … tracked as #371.)" contradicts the Fixed
  entry at L1465; "`RecvMode::Closed` is now set only by …" and "three
  explicit fields (`recv_arm`, `read`, `lifecycle`)" name removed items;
  L1460-1463 "Interest is WRITABLE-only once the receive side is closed" is
  false.
- `connection.rs:65-67`: `WriteHalf::Shutdown` "does not refuse later sends"
  — `BackpressuredSendFuture` (`runtime/io.rs:3811-3818`) refuses with
  `BrokenPipe`; plain sends are not refused.
- `docs/connection-state-model-design.md:3-5`: the 2026-10-25 note omits
  that `ReadHalf::Cancelled`, `DriverCtx::cancel` and `shutdown_pending` are
  gone and the `recv_multishot_armed` follow-up is moot.
- `on_send_complete` named at `handler.rs:11-15`, `config.rs:280-282`,
  `uring/ring.rs:444-445`, `chain.rs:5-6`; no such function.
- `handler.rs:2870`: mio `DriverCtx::close` "Marks it Closed" (`Closing`);
  the method has no mio caller (`cfg_attr(allow(dead_code))`).
- `uring/ring.rs:493-506`: `submit_close` doc "for a direct file descriptor"
  (it is `Fd::Fixed` with a lead); comment names `push_sqe_pair` (the trait
  method is `Engine::push_pair`).
- `mio/driver.rs:949-951`: a truncated sentence ("…re-adding READABLE would
  just") left in `flush_sends`.
- `metrics.rs:75`: `conn::CLOSED` undocumented (see F3).

Unresolvable: `docs/recv-multi-identity-design.md` describes
`OpTag::RecvMulti`/`handle_recv_multi`/`submit_async_cancel` in
`try_finalize_close`, none of which exist; needs a superseded status line.

History displacing behaviour in doc comments: `uring/driver.rs:1337`
`close_connection` (no `///` at all; ~30 lines of history in the body),
`handler.rs:64-77` (`shutdown_inflight`'s removed `=> {}` arm),
`handler.rs:1100-1106`, `uring/driver.rs:1243-1250`, `mio/driver.rs:636-638`,
`uring/event_loop.rs:4745-4751`.

Style: "load-bearing" at `uring/driver.rs:376`, `mio/event_loop.rs:1112`
(plus `docs/listeners-and-accept-design.md`, `recv-buffer-geometry-sweep-
design.md`, `ktls-design.md`, three journal entries); personification at
`handler.rs:68`.

Disposition: fixed in #798, checked item by
item against ad2c6b23. Already fixed before it: `close_send_count`, the
`CLAUDE.md` lead sentence, the deadline check's `try_finalize_close`,
`WriteHalf::Shutdown`'s "does not refuse later sends", the four
`on_send_complete` comments and the io_uring `DriverCtx::close` history
(#788); `conn::CLOSED`'s doc (#767). Still false and corrected there: the
`on_close` sentence; the multishot cancel in `docs/recv-direct-design.md`;
the mio design's test and TLS-table claims; the deadline check's call-site
comment; the three "registers writable interest" sites; the four CHANGELOG
sentences; the state-model note; "Marks it Closed"; `push_sqe_pair`; the
truncated `flush_sends` sentence. `docs/recv-multi-identity-design.md`
carries a superseded line. The five history paragraphs are rewritten as
behaviour; `close_connection` gains a doc comment. "load-bearing" is
replaced at the two code sites and in the three design docs; the dated
journal entries keep it as records. Three of this finding's own citations
were imprecise: the `mio/driver.rs` history is `finish_close`'s doc, nine
lines above the cited ones; four journal entries carry "load-bearing", not
three; and "direct file descriptor" is io_uring's own name for a fixed-file
entry, so only the `push_sqe_pair` half of that item was false. The mio
`DriverCtx::close` gained callers in #781, so "no mio caller" no longer
holds. Also corrected: F8's disposition named `run_shutdown` for the arm in
`handle_shutdown_cqe`, the gauge doc named #607 alone for a connection
uncounted at the exit bound (#787's refused Close reaches the same state),
and this entry's span line named a branch.

## Design limitations (questions for the owner, not fixes)

- **L1** A peer FIN tears the connection down unless a send is in flight, so
  a task awaiting an upstream reply or a timer at that moment is dropped once
  the Close commits. Stated on the `recv_direct` module doc,
  `docs/recv-direct-design.md:380-381` and `docs/connection-state-model-
  design.md` Follow-ups ("Half-close policy"); not on `with_data`,
  `with_data_result` or `Connection::close`. A proxy author will hit it.
- **L2** `close()` followed by any `.await` drops the task at the same
  iteration's finalize: code after `close()` runs only to its next await
  (mio run: `ran_after=0 dropped=1`; io_uring same shape). Matches the Drop
  contract; stated on `SendHalf::close` since #803. A `close()` from another
  task or `on_tick` against a parked task gives it no poll at all.
- **L3** "Reach the wire" means the socket: closing with unread inbound bytes
  makes the kernel RST, and a peer that kept sending lost 1.07 MiB of an
  8 MiB response in one run. TCP behaviour; stated on `SendHalf::close`
  since #803.
- **L4** The close deferral has no time bound on either backend for
  `Connection::close`; `CLOSE_NOTIFY_TIMEOUT` (5 s) applies only to the
  io_uring `DriverCtx::close`, reachable from the TLS encrypt-failure paths.
  Documented on `SendHalf::close`.
- **L5** `pending_close_retries` has no retry cap; a permanently full SQ
  holds the slot. By design (a cap would leak the fd).
- **L6** `Send`/`TlsSend` CQEs carry a 16-bit truncated generation
  (`completion.rs:287-300`). Every other per-connection op carries 32 bits
  (`SendPollOut` included, so the earlier 15-bit concern is moot). A
  `MSG_DONTWAIT` send never sits in the kernel, so no Send CQE is long-lived.
- **L7** TLS record-layer errors resolve `Ok(0)` by documented choice
  (`runtime/io.rs:2719-2722` at a2e28073). Changed in #807 on the owner's
  decision: a record the engine cannot process is `Err(InvalidData)` to
  `with_data_result`, and a TLS overflow `Err(QuotaExceeded)`, on both
  backends.

## Seeds from the stale pass (f19c31e8), re-established or dropped

| Seed | Outcome on a2e28073 |
|---|---|
| S1 Close committed in `drain_completions` | still present → F1 |
| S2 mio task dropped before seeing a write error | fixed by #619 for awaited sends (10/10 see `Err(BrokenPipe)`); residue for unawaited sends → F9 |
| S3 gauge never incremented for outbound | still present → F2; `CLOSED` asymmetry → F3 |
| S4 `handle_connect` no identity | still present → F4 |
| S5 timeout cancel payload 0 | still present → F5 |
| S6 `cancel` mutates before submit | moot: `ReadHalf::Cancelled` and `DriverCtx::cancel` removed |
| S7 `handle_tls_send` never wakes the waiter | fixed by #618/#619 (settled through `send_completion`) |
| S8 dropped multishot cancel in `try_finalize_close` | moot: multishot gone; `submit_committed_close` error paths consistent |
| S9 `timestamps` re-arm | moot: feature removed (#667) |
| S10 `force_finalize_close` `write = Open` | still present, narrowed → F7 |
| S11 `ConnCtx::close` no generation | fixed by #540 |
| S12 mio `peer_addr`/`is_outbound` no generation | moot: accessors moved to `ConnCtx`, generation-checked |
| S13 `take_recv_sink` | moot: removed |
| S14 local aborts read as clean close | still present, both backends → F6 |
| S15 docs | partly fixed (`try_finalize_close` doc rewritten; mio `close_connection` doc reattached; `runtime/mod.rs` RecvMulti paragraph gone); rest → F14 |
| D1 mio deferral undocumented | fixed: `SendHalf::close` states it |
| D2 bare FIN on TLS `Connection::close` | fixed by #706 |
| D3 worker exit abandons closing connections | still present → F8 |
| D4 `on_tick` close gives no poll window | reframed → L2 |
| D7 truncated generations | narrowed → L6 |

## What the audit did not cover

- Nothing on the io_uring path was executed; F1, F4, F5, F7, F10, F11, F12,
  F13 and the io_uring half of F2/F6/F8 are traces. The 283 io_uring unit
  tests were not run. Reproducing F1 and F4 needs a Linux anvil VM.
- Kernel-behaviour claims in comments were not verified: the CQE order between
  an inline Close and a cancelled request's task_work CQE (F4's trigger;
  `force_finalize_close`'s "usually land before the Close CQE"), the
  `shutdown` lead running on the bounded io-wq pool, the 6.13 and 6.7
  boundaries.
- `docs/half-closed-send-wait-design.md` steps 1–5 were not checked against
  `wait_for_room`/`handle_send_pollout`/`handle_send_backstop`.
- F9's trigger and F6's TLS record-error arm were traced, not run.
- `drain_forward_resumes` beyond its close hooks; park beyond F10 and
  `socket_handed_off`; `run_shutdown` beyond F8; UDP; disk I/O.
- Rustdoc under `cfg(has_io_uring)` was read, not rendered (`-D warnings`
  clean under the mio cfg and `--all-features`).
- `run_shutdown`'s CQE drain has no `ParkInstall` arm, so an install CQE
  drained at worker exit leaves its fd open (found by the review of #791,
  recorded under F10); open at 5b92399a, issue #800.

## Reproductions

The reproductions were scratch drafts, never checked in: an integration test
on mio for F6, L2, L3 and the D1 slot hold with a no-spin check; a gauge
reproduction for F2 and F3; a unit-test patch for F6. They were discarded on
2026-11-08 after the last fix merged. Each code fix (F1 to F13) landed with
a test that failed before it; F14 is documentation.
