# Fuzzing the wire-facing parsers

- **Status:** open
- **Span:** started 2026-07-06

## Goal

Stand up coverage-guided fuzzing (cargo-fuzz/libFuzzer) for the components that
parse or frame untrusted wire data, and run the targets continuously in CI. The
May 2026 conformance audit's closing lesson
([2026-05-conformance-audit.md](2026-05-conformance-audit.md)): the bug class it
kept finding by hand — request smuggling, varint-split buffering (f619303),
frame-size edge cases, decompression bombs — is exactly what fuzzers find
cheaply and forever. Both prior audits were expensive manual passes; this is the
first investment that lowers the cost of the next one.

## Scope

Fuzz where untrusted bytes meet in-tree parsing:

- **ringline-h2** — HTTP/2 frame decoding and HPACK.
- **ringline-h3** — H3 frame/varint parsing and QPACK, with *chunked* delivery
  (split the input at fuzzer-chosen boundaries) so the f619303 class —
  state carried across partial reads — stays covered.
- **ringline-http** — HTTP/1.1 response parsing: headers, chunked transfer
  encoding, trailers, the smuggling defenses from e289c8c.
- **ringline-grpc** — length-prefixed message reassembly, decompression
  bounds, trailer/status parsing.

Deliberately out of scope, with reasons:

- **ringline-quic** — the state machine is quinn-proto's; upstream fuzzes it.
  Our thin event-mapping layer is exercised via the h3 targets.
- **redis/memcache/ping wire parsing** — lives in the external published proto
  crates (`resp-proto`, `memcache-proto`, `ping-proto`), not this workspace.
- **TLS** — rustls fuzzes upstream.
- **Core runtime** — not byte-parsing; CQE dispatch already has proptest
  coverage in `backend/uring/event_loop.rs`. Structured fuzzing of
  `RecvAccumulator` op-sequences would be valuable but needs internals exposed
  to an out-of-workspace crate; deferred (open question below).

## GO / NO-GO criteria

- GO if each target builds on nightly, runs clean for a bounded local burn-in,
  and the harness reaches real parsing code (non-trivial coverage, verified by
  seed corpus behavior — a target that never gets past construction is worse
  than none).
- CI: a scheduled (cron + manual dispatch) workflow running each target for a
  bounded time with crash artifacts uploaded. Not on the PR path — fuzzing is
  nightly-toolchain and open-ended; PR CI stays fast and stable.
- The fuzz workspace must not perturb the root workspace: excluded from
  `[workspace]`, own committed lockfile, no impact on `--locked` CI.

## Plan

1. Map the sans-IO seams (which public APIs accept raw bytes; what a harness
   needs to construct).
2. One `fuzz/` cargo-fuzz workspace at the repo root with per-component
   targets and small seed corpora.
3. `.github/workflows/fuzz.yml`: nightly cron + workflow_dispatch, bounded
   `-max_total_time` per target, crash artifacts uploaded.
4. Burn in locally; fix anything found (as separate PRs if non-trivial); close
   out this entry in the implementing PR.

## Outcome

_(open)_

## Lessons / open questions

- Open: structured fuzzing of `RecvAccumulator` (append/advance/take/put-back
  sequences) — needs a `pub` seam or an in-crate fuzz setup; revisit if the
  accumulator grows more state transitions.
- Open: seed corpora from real traffic captures would raise coverage; start
  with hand-written minimal seeds.
