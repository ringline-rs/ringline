# March 2026 Hardening Blitz: Correctness Wave, Fault-Injection Harness, Runtime Surface

- **Status:** shipped (retrospective entry, reconstructed 2026-07-06 from commit history)
- **Span:** 2026-03-25 → 2026-04-09 · eafce3a..8ffbf1b, PRs #4–#84 · releases v0.0.3 (+ same-day v0.0.4/v0.0.5 follow-ups)

## Goal

Inferred from the commit sequence — there was no journal at the time. Three interleaved
threads: (1) an audit-style correctness pass over the young runtime and client crates,
(2) building test infrastructure that could exercise io_uring completion paths without a
kernel, and (3) filling out the runtime's public surface toward general-purpose async
usability. Roughly 80 PRs landed in this window, the bulk of them March 25–31.

## What happened

**Correctness wave (Mar 25–27, PRs #14–#63 interleaved with tests).** The opening fix set
the tone: 6e90929 (#14) made the redis/memcache/ping parse callbacks return
`Consumed(len)` on fatal parse errors instead of hanging the connection task forever.
TLS error paths followed — wake waiters before close on recv error (e90e9b0 #15), close
on intermediate send failure (ce2f6e9 #16), propagate pool exhaustion during output flush
(eb2d468 #18), and return errors from TLS connection creation instead of panicking
(85ed4b2 #37). A soundness cluster fixed a Stacked Borrows violation in
`poll_ready_tasks` (c4baf0a #20), a Pin violation when overwriting `MaybeDone` (a751eab
#21), and unaligned `cmsghdr`/`timespec` reads (8bb23d2 #22). Resource-lifecycle fixes
covered ZC chain and copy send leaks (86e13ca #40, eb5c614 #41, 75f0f08 #42), recv-buffer
replenish on stale-connection CQEs (24cae2d #43), waiter-flag cleanup when
`SendFuture`/`ConnectFuture` are dropped (d2d4187 #35), accept retry on
ECONNABORTED/ECONNRESET/EPERM (45733a6 #33), and a generation check on send-retry
resubmission (771d2bb #54). A March 31 tail hardened the send path further: partial-send
offset correction (4500c3a #77), surfacing SQE submission failures instead of silently
discarding (7b72d77 #78), and chunking oversized copy sends (74358e3 #82).

**Test-infrastructure buildout (Mar 26–28, PRs #44–#63).** 8da90e6 (#44) added a
synthetic CQE dispatch harness — a test-only hook exposing `dispatch_cqe` so completion
handling could be driven with fabricated CQEs, no kernel involved — and fe58783 (#45)
expanded it to 22 tests the same day. On top of it came io_uring NOP error injection with
real ring plumbing (ebcf0f4 #56), retry-drain fault injection (98a2ef5 #57), linked-SQE
chain error propagation (a00281f #58), timer cancel injection (b07a7d1 #59), buffer-ring
exhaustion stress (3f91e37 #60), and property-based CQE dispatch invariants via proptest
(7e98a5e #62, a3ba00e #63). Conventional integration tests landed alongside: TLS
end-to-end echo (6aeab55 #25), peer-close EOF detection (08e0c5b #27), pool exhaustion
and scatter-gather sends (95b0974 #28), connect timeout (1d5d912 #61), and
ConnectionTable/TimerSlotPool unit tests (898b3cf #80).

**Runtime surface expansion (Mar 28–30, PRs #64–#76).** In three days: `ConnStream` with
AsyncRead/AsyncWrite/AsyncBufRead (0cf547b #64), `JoinHandle` (0e822a2 #65), oneshot and
mpsc channels (0d0ce20 #66), signal handling (d374c02 #67), a DNS resolver pool (fa5cca9
#68), Unix domain sockets (9c5168d #69), async fs on io_uring (7f9dfa1 #70),
`CancellationToken` (3fe99d9 #71), process spawning (b782eee #72), `spawn_blocking`
(0dfdefb #73), HTTP and gRPC compression (05fd691 #74, 6e373ef #75), and zero-copy
recv/send plus the `ringline-bench` binaries (bd08001 #76). All of these survive in
today's tree: `ringline/src/runtime/{stream,join,channel,cancellation}.rs`,
`ringline/src/{signal,resolver,fs,process,blocking}.rs`, `connect_unix` and
`spawn_blocking` re-exports in `ringline/src/lib.rs`, `compress.rs` in both
`ringline-http` and `ringline-grpc`, and the `ringline-bench` crate.

**Release.** After a quiet week (nothing landed Apr 1–8), 23eec50 (#83) audited
`#[allow(dead_code)]` annotations and 8ffbf1b (#84) shipped v0.0.3 on Apr 9. Two
follow-up releases went out the same day: v0.0.4 (333e708 #85 treating empty
`MOMENTO_ENDPOINT`/`MOMENTO_REGION` as unset, fadb0e7 #86 fixing the tag-release version
bump) and v0.0.5 (5d8460d #88 skipping Momento integration when secrets are missing).
The `ringline-momento` crate those fixes served was later removed entirely (7fa3b0b
#218, 2026-06-12).

## Outcome

- v0.0.3's changelog carries the whole arc: the fs/process/channels/signal/DNS/UDS/
  cancellation surface, compression, zero-copy paths, and the test buildout.
- The synthetic-CQE harness proved durable. It lived in-module in
  `async_event_loop.rs`; the backend extraction (853510a #94, Apr 15) carried it into
  `ringline/src/backend/uring/event_loop.rs`, where it still sits today with 80 `#[test]`
  functions plus a `proptest_cqe` module. The July 2026 audit-fix PRs added their
  regression tests directly into it: 5173baa (#237, +1 test), fa71711 (#238, +5),
  ca55c0d (#239, +3), 061997d (#240, +1). The May audit fixes (53cdde0 #156, 686a739
  #168) modified the same file but I found no test additions there.
- Several fixes hardened patterns that are now written down as invariants (generation
  checks on stale CQEs, send-queue ordering, SQE lifetime) — though the July 2026 audit
  still found ~35 further violations of the same families, so this pass was a first
  installment, not a completion.

## Lessons / open questions

- **Not every "graceful" fix survived.** 63bde40 (#36) replaced the timer-pool-exhaustion
  panic with complete-immediately. 7844ca6 (#242, July audit) reverted that to a
  documented panic: completing a `timeout()` in zero time fired spurious `Elapsed` errors
  that cancelled healthy I/O, and a `sleep()` loop became a busy-spin. Silently degrading
  behavior can be worse than crashing; the `try_*` variants are the real answer.
- **The harness paid for itself.** Building synthetic CQE dispatch in March meant later
  audit fixes (July, PRs #237–#240) could ship kernel-free regression tests in the same
  file. Keeping the tests in-module made them travel through the #94 backend refactor
  for free.
- The fix and test threads were deliberately interleaved (fix PRs #46–#55 landed between
  harness PRs #45 and #56) — whether tests were finding the bugs or bugs motivating the
  tests isn't recoverable from the log.
- Why the Apr 1–8 gap before release is not recorded anywhere I could find.
