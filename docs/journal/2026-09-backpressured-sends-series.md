# Result-aware receives and backpressured sends, landed as a series

- **Status:** shipped (`docs/journal/2026-09-backpressured-sends.md`); the
  follow-ups below are closed except (d), per
  `docs/journal/2026-11-send-path-audit.md` X4
- **Span:** 2026-09-10 → · PRs #367 (design), PR 1 of 9 (this PR) · unreleased (post-0.6.3)

## Goal

Land the work in ringline-rs/ringline#318 (@thinkingfish): a receive that
distinguishes EOF from transport error, and a FIFO-admitted, copy-once
bounded send, plus the internal guarantees underneath them. #318 stalled 41
commits behind `main` with a blocking finding (a bounded TLS send could
advance rustls state, discard the ciphertext, and retry — `bad_record_mac`
at the peer). The design is accepted; the branch is not. The decomposition
and the six deliberate departures from #318 are in
[`docs/backpressured-sends-series-design.md`](../backpressured-sends-series-design.md).

GO criterion for the series: PR 9 lands `send_backpressured` with the
end-to-end regression for the blocking finding (forced push failure after
TLS encryption fails the operation, closes the connection, peer sees no
record gap) green on both backends.

## What happened

- **Hardware A/B of #376 + #377 (2026-09-12).** Owner mandate: every
  send-path PR is verified on Linux with the real X710 ports for both
  backends, not only the single-guest clippy/test job. Harness landed as
  #379 (`experiments/send-path-ab-build.toml`, `experiments/send-path-ab.toml`):
  build once on the validation host, one arm per experiment, server guest
  on hv02 (z1.c, 4×10G LAG), client guest on hv01 (z2.c), rezolus on both
  sides, arms interleaved. Baseline c419d05 vs main 7ecc3fb; ringline echo
  server with 8 workers, 64 closed-loop connections, 256 B and 64 KiB
  phases, 20 s windows. io_uring arms n=6 each, mio arms n=3 each, plus a
  discarded warm-up. Backend proven per arm from the server's syscall mix
  (io_uring: only `io_uring_enter`, ~0.5/req at 256 B; mio: 2.35 poll +
  2.0 read + 1.0 write per request).

  Verdict: **within the run-to-run noise floor on every metric, both
  backends.** Medians (min–max): 256 B ops/s io_uring 287k [274–301k] →
  294k [285–300k], mio 275k [273–278k] → 279k [272–280k]; 256 B p99
  io_uring 404 µs [360–427] → 383 [372–444], mio 420 [405–458] → 411
  [401–430]; server CPU per request io_uring 16.5 → 17.3 µs (spread
  15.8–18.2), mio 25.3 → 25.1 µs. 64 KiB is latency-bound at 64 in flight
  (~42k ops/s ≈ 22 Gbps per direction, unchanged); its io_uring p99 is
  bimodal on both sides (runs cluster at ~2.7–2.9 ms and ~3.6–3.9 ms:
  before 3 low / 3 high, after 1 low / 5 high, medians 3.26 → 3.61 ms,
  ranges overlapping, p999 10.4 → 10.5 ms). Not resolvable at n=6; each
  later PR's A/B will show whether the slow mode's share keeps moving.
  An initial n=3 read had shown a disjoint +4.4 % throughput win for
  io_uring at 256 B that three more runs erased — three runs are not
  enough on this LAG.

  Measurement findings (now in infra `docs/guides/vm-jobs.md`): noise
  floor ±3 % throughput, ±5 % cores, ±4–8 % p99 at 256 B, one-in-twelve
  outlier reps; guest `network_bytes` double-counts bond0 plus its members
  (tx/expected = 2.00 in all 24 windows); `tcp_retransmit` runs 10–30/s at
  22 Gbps per direction on every arm, backend-independent. Per-window CSV:
  systemslab artifact 01a09643-7742-733a-1c04-9b7a0f0e8d6c. anvil-vm
  `upload = true` with a directory artifact failed at curl and cancelled the
  server through the barrier; fixed upstream in anvil 0.8.3, the spec tars
  its results meanwhile.
- **PR 4 — transactional copied sends.** io_uring `DriverCtx::send` copied
  a multi-slot buffer chunk by chunk, so pool exhaustion on chunk *k* left
  chunks 1..k-1 queued behind the `Err` and a retry duplicated them. It now
  reserves every slot as a count before the first copy (`reserve_slots`, no
  allocation, departure 3); wider than the pool is `InvalidInput` up front.
  Designing it found a second hole: a queued send whose SQE could not be
  pushed (SQ still full after `submit()`) was released with everything
  queued behind it — no wake, no close, the `SendFuture` hung; the same
  condition on a first TLS entry returned `Err` after rustls had advanced,
  and three `let _ =` callers dropped handshake output and close_notify.
  Fix: park the built SQE at its queue head and re-push it next iteration,
  with `drain_copy_retries`' two-attempt cap and terminal close; departure 1
  refined to "nothing re-runs a logical send", not "nothing parks". Lesson:
  the io_uring lib build flagged `remaining`/`slot_count`/
  `force_push_failures` as dead until they had non-test callers, invisible
  on the mio host where `buffer` is `allow(dead_code)`. Design:
  `docs/copied-send-reservation-design.md`.
- **Prerequisite — #368, mio close lifecycle.** PR 1's adversarial review
  found that mio never tore down a peer-first-closed or read-errored
  connection (`Closed` set directly at the read sites; `close_connection`
  early-returned on it). Fixed by unifying on io_uring's model rather than
  adding a mio-only flag: `Closed` has one setter, `close_pending` marks
  teardown requested, and mio's `finish_close` is now deferred until
  `pending_sends` drain. CI then showed io_uring does *not* give that
  window when the queue was empty at the FIN (`try_finalize_close` runs
  synchronously and commits the Close before the task polls; a post-EOF
  response is never delivered) — #371, to be fixed with PR 7's handler
  rework. **Closed the same day (#371 PR):** `close_connection`'s
  empty-queue branch now defers to the event loop's `pending_finalize_closes`
  drain instead of finalizing synchronously — a three-line change plus an
  io_uring unit test — and the two post-FIN-send tests run on both backends.
  Review also caught that the deferral test's 4 MiB send would exhaust the
  default 64-slot test copy pool on io_uring (one slot per 16 KiB chunk,
  taken synchronously) — the test now uses an 8 MiB pool and asserts the
  send outcome. Design: `docs/mio-close-lifecycle-design.md`. PR 3 (mio
  `shutdown_write` deferral) and PR 6 build on this.
- **Prerequisite — connection state model.** After #368/#371 the owner
  asked whether the state names matched TCP. They did not: `RecvMode::Closed`
  meant "read half finished", "close requested", and "nothing armed" at once.
  Split into `recv_arm` / `read: ReadHalf` / `lifecycle` with `recv_finished()`
  and `close_requested()` helpers, behaviour-preserving, verified on io_uring
  in an anvil VM on the validation host before the PR. Design:
  `docs/connection-state-model-design.md`. Follow-ups recorded there:
  half-close policy (should a peer FIN request teardown at all?), `WriteHalf`
  with PR 3, folding `active`/`recv_multishot_armed` after PR 7.
- **PR 3 — mio `shutdown_write` deferral + `WriteHalf`.** Done out of
  series order because it sits on the close machinery #368/#371/#373 just
  settled. mio's `shutdown_write` truncated any response larger than the
  socket buffer (nonblocking `write_all`, remainder dropped on
  `WouldBlock`, FIN sent). It now defers the FIN until `flush_sends`
  drains the queue, as io_uring's `submit_next_queued` already did, and
  both backends record the write half as `ConnectionState::write`
  (`Open`/`ShutdownPending`/`Shutdown`) instead of a flag. The regression
  test had to make the client wait for the half-close before reading: a
  fast loopback reader can keep the socket buffer from filling and let the
  old code get away with it. Design: `docs/write-half-design.md`.
- **PR 2 — worker startup errors.** #318's version sent a `String` over
  the startup channel; after #360/#361 made setup failures typed and
  actionable that would have flattened them, so the channel now carries
  `crate::error::Error`. The failing worker's own error reaches `launch()`
  (before: the first joined thread's, in handle order), and a startup panic
  is caught and reported with its payload and worker id (before: a
  disconnected channel and "worker setup failed"). Design:
  `docs/worker-startup-errors-design.md`.
- **PR 1 — `with_data_result`.** `Executor` gains a generation-tagged
  `recv_errors` slot written by `fail_recv` at the five real socket-read
  failure sites (mio: TLS and plaintext read errors in
  `backend/mio/event_loop.rs`; io_uring: the fallback-recv `result < 0`
  branch, the multishot-recv errno branch, and the multishot-recvmsg errno
  branch under the `timestamps` feature in `backend/uring/event_loop.rs`).
  `WithDataResultFuture` wraps `WithDataFuture` and consults the slot, with
  the generation captured at construction, only when the inner future
  reports `0`. Departures 7 and 8 in the design doc: no pre-poll check of the
  slot (redundant — every `fail_recv` site sets `RecvMode::Closed` or calls
  `close_connection`, so the inner future reports `0` on the same poll), and
  the slot is not cleared on teardown (the generation tag makes that safe,
  and a poll that lands after teardown still learns the cause). Tests:
  four executor unit tests; `with_data_result_returns_ok_zero_on_clean_close`
  and `with_data_result_surfaces_tcp_reset` (client sets `SO_LINGER 0` so
  `close()` sends RST) in `ringline/tests/echo.rs`, both gated on the
  handler having actually accepted so they cannot race the acceptor thread.

## Outcome

Open.

## Lessons / open questions

- **PR 4 follow-ups (adversarial review, 2026-09-12).** Closed since, except
  (d): (a) by the removal of the recv-buffer ring, (b) by `send_inner`
  settling `Ok(0)`, (c) by
  `bounded_tls_send_parks_and_then_fails_rather_than_re_encrypting`, (e) by
  `SendChainBuilder::finish` refusing while a send is in flight and
  `submit_or_queue` queueing behind a chain. (a)
  `handle_send_recv_buf`'s partial-resubmit push failure still drops the
  remainder of a recv-buffer forward on an open connection — a pre-existing
  silent hole that the new Invariant 7 wording now contradicts; route it
  through a retry list. (b) `ConnCtx::send(&[])` on io_uring returns a
  `SendFuture` that never resolves (nothing is queued, so nothing writes
  `io_results`); seed `Ok(0)` as `forward_to` already does. (c) No TLS-level
  test of parking exists (the event-loop test module has no TLS harness);
  `queue_built_sends_parks_under_sq_pressure` covers the mechanism only.
  (d) `drain_send_retries` wakes the recv side on give-up while
  `drain_copy_retries` does not; harmless asymmetry, pick one. (e) Send
  chains (`send_chain`) bypass the per-connection queue and can push while
  a queued send is in flight — pre-existing; the `parked` flag keeps the
  retry drain out of that race but does not fix the chain path itself.

- **PR 8/9 follow-up (adversarial review, 2026-09-12): a TLS bounded send
  reports two different lengths depending on which branch it takes.** Closed
  by #617: both branches report `data.len()`.
  `DriverCtx::send_bounded`'s empty-ciphertext early return completes the id
  with `Ok(plaintext_len)`, while a queued TLS entry completes with
  `Ok(ciphertext_len)` from `flush_sends` — two branches of one function
  disagreeing about what the number means. It mirrors a pre-existing
  `send().await` quirk on mio (the completion is the queued buffer's length),
  so it is inherited rather than introduced; decide the contract once when
  PR 8 lands TLS admission and PR 9 gives the caller something to read.

- The io_uring sites cannot be type-checked on the macOS development host;
  Linux CI is the authority for those three edits.
- **Pre-existing hazard, found in review, not introduced here:** the
  `RecvMulti` user_data carries no generation, and `handle_recv_multi`
  validates a CQE only with `connections.get(conn_index).is_none()`.
  Ordinarily that is safe: `close_connection` submits `async_cancel` and
  `Close` together, `DEFER_TASKRUN` runs the cancel at submit, and the recv's
  terminal CQE after that is `ECANCELED`, which the handler returns on. The
  escape is `close_connection`'s `let _ = self.ring.submit_async_cancel(..)`
  failing on a full SQ (`backend/uring/driver.rs`): the uncancelled recv
  outlives the fixed-file close and a later `-ECONNRESET` could reach the
  error branch under a reused slot — before this PR that path did
  `wake_recv` + `close_connection` on the new occupant; now it would also
  store an error under the new occupant's generation. Fix candidates:
  encode the generation in `RecvMulti` user_data, or check
  `recv_multishot_armed` before the error branch. Tracked for a later PR in
  this series (PR 7 touches the same handlers).
