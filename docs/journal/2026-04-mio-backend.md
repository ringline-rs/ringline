# The backend split: extracting uring, adding mio

- **Status:** shipped (retrospective entry, reconstructed 2026-07-06 from commit history)
- **Span:** 2026-04-15 → 2026-04-18 · PRs #94–#103 (#105 release; #136 follow-through 2026-04-27) · v0.1.0

## Goal

Make ringline buildable and testable off Linux. Until April 2026 the crate was
io_uring-only: development on macOS meant no local compile, no local tests, and
protocol client crates that could only be exercised on a Linux box. The plan was
to (1) carve the io_uring code into a backend module, (2) put a compile-time
switch in front of it, and (3) grow a mio-based fallback behind that switch to
functional completeness — correctness and portability, not performance parity.

## What happened

Three foundational commits, then a fill-in sprint:

- **853510a (#94, 2026-04-15)** — mechanical extraction. `ring.rs`, `driver.rs`,
  the event loop, and `buffer/provided.rs` moved into `ringline/src/backend/uring/`
  with re-exports from `backend/mod.rs`. Zero behavior change; the point was the seam.
- **2708c73 (#95, 2026-04-15)** — cfg-gating. First pass gated the backend behind a
  `cfg(feature = "io-uring")`, then the same PR replaced that with `cfg(has_io_uring)`
  emitted by `build.rs`, plus a `Backend` enum / `ringline::backend()` for runtime
  introspection. This PR also introduced the `WakeHandle` abstraction (eventfd on
  io_uring, pipe on mio) and made the `io-uring` dependency target-conditional so it
  never compiles on macOS.
- **0f4b0fd (#96, 2026-04-16)** — the mio backend skeleton in
  `ringline/src/backend/mio/` (`driver.rs`, `event_loop.rs`, `mod.rs`), with shared
  sockaddr helpers hoisted to `backend/sockaddr.rs`. The first commit in the PR
  deliberately did not compile; the second cfg-gated shared modules until the full
  workspace built on macOS with stub I/O.

Then two days of making the stub real, one capability per PR:

- **074fbd1 (#97)** — outbound connect, `shutdown_write`, send wakeup; protocol
  clients now worked cross-platform.
- **26f5558 (#98)** — TLS (rustls) for inbound and outbound.
- **6d6016e (#99)** — UDP bind/recv_from/send_to on dedicated poll tokens.
- **e7d99b3 (#100)** — connect failure detection via `SO_ERROR` (`take_error()`
  instead of `peer_addr()`) and connect timeouts.
- **58076b1 (#101)** — `connect_tls_with_timeout`; ungated the outbound-EOF test
  (64/68 echo tests then ran on mio; 4 remained io_uring-specific).
- **0887d30 (#102)** — disk I/O via a dedicated blocking thread pool
  (`ringline/src/disk_io_pool.rs`, default 2 threads), since mio has no async file I/O.
- **e127533 (#103)** — send coalescing with `writev()`: pipelined `send_nowait()`
  calls that previously produced N `write()` syscalls / N TCP segments now flush
  as one scatter-gather write.

**ed34547 (#105, 2026-04-18)** shipped all of it as v0.1.0. The follow-through
landed later: **ff9c7a2 (#136, 2026-04-27)** added `clippy-macos` and `test-macos`
CI jobs, after an unguarded `libc::SOCK_CLOEXEC` use (#130, fixed in #135) showed
that an all-Linux CI matrix let mio-only regressions through.

## Outcome

The design as it stands today (verified against the current tree):

- Backend selection is **compile-time only**. `ringline/build.rs` emits
  `has_io_uring` when target is Linux AND the `force-mio` feature is off AND
  `/proc/sys/kernel/osrelease` reports kernel ≥ 6.0 (optimistic when `/proc` is
  unreadable, e.g. cross-compiling — runtime fails fast instead). Note the knob
  evolved: #95's `io-uring` default feature became today's `force-mio` opt-out.
- Runtime backend selection was never on the table — per CLAUDE.md, it would
  fight the `CURRENT_DRIVER` raw-pointer thread-local design.
- On mio, zero-copy sends degrade to copies (guards consumed by copying), NVMe
  is unsupported, and fs/direct I/O run on the `disk_io_pool.rs` thread pool
  rather than the ring. The io_uring backend remains the performance target;
  mio's job is correctness and macOS development.
- Both backends live where #94/#96 put them: `ringline/src/backend/uring/` and
  `ringline/src/backend/mio/`.

## Lessons / open questions

- The extraction-first sequencing (#94 as a zero-behavior-change move) made every
  subsequent PR reviewable as pure addition. Cheap discipline, large payoff.
- A cfg emitted by `build.rs` beat a cargo feature for platform detection: features
  are additive across the dependency graph, while `has_io_uring` encodes a fact
  about the target that no downstream crate should be able to toggle.
- Shipping the backend (#94–#103) ten days before its CI (#136) left a window where
  mio-only breakage could merge — #130 landed in exactly that gap. Platform support
  is not real until it is continuously tested.
- Open at the time and still true: some behavior-sensitive tests only make sense on
  one backend and stay gated on `has_io_uring`; and mio send coalescing (#103) is a
  syscall-count fix, not a claim of parity — no benchmark of mio-vs-uring overhead
  was recorded in this arc.
