# Fuzzing the wire-facing parsers

- **Status:** shipped
- **Span:** 2026-07-06

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

Eight cargo-fuzz targets in a root `fuzz/` workspace (excluded from the main
workspace, own committed lockfile — root `Cargo.lock` untouched):

- `h2_frame`, `h2_hpack`, `h2_connection` — the last opens a real request
  stream and delivers input in fuzzer-chosen chunk sizes.
- `h3_frame` (varint + frame decode incl. the zero-copy `decode_frame_in`),
  `h3_qpack`.
- `grpc_message` (direct decode + `MessageBuffer` reassembly with chunked
  delivery), `grpc_connection` (full gRPC-over-h2 stack behind a real
  `send_unary`).
- `http1_response` — reaches the crate-private h1 parsers via two
  `#[doc(hidden)]` wrappers behind a new off-by-default `fuzzing` feature in
  ringline-http (`fuzz_parse_response_headers`, `fuzz_decode_chunk`); the
  internal types stay private.

GO criteria verified locally (nightly, libFuzzer/ASan): all targets build; a
20 s/target burn-in produced **no findings**; coverage confirms real parsing
depth (`h2_connection` cov 1422 edges, corpus 2 seeds → 657 entries in 8 s;
`http1_response` cov 566; `grpc_connection` cov 736; `h3_frame` cov 233).
Main-workspace gates unperturbed: `cargo metadata --locked` clean, clippy
`-D warnings` on both backends and with `--features fuzzing`, ringline-http
tests green.

CI: `.github/workflows/fuzz.yml` — daily cron + `workflow_dispatch`, 8-target
matrix, 300 s/target (dispatch-tunable), crash artifacts uploaded on failure.
Seed corpora committed under `fuzz/corpus/<target>/`.

The `H3Connection` state machine remains unfuzzed as scoped: its only byte
ingress is `handle_quic_event(&mut QuicEndpoint, ...)`, which requires a live
quinn-proto endpoint — no sans-IO seam exists.

## Lessons / open questions

- The seam survey found the h1 parsers were the only in-scope code not
  publicly reachable; the `fuzzing`-feature wrapper pattern (doc-hidden fns
  that consume results internally, no type exposure) kept the API surface
  policy intact and is the template for future private seams.
- Open: structured fuzzing of `RecvAccumulator` (append/advance/take/put-back
  sequences) — needs a `pub` seam or an in-crate fuzz setup; revisit if the
  accumulator grows more state transitions.
- Open: seed corpora from real traffic captures would raise coverage; start
  with hand-written minimal seeds.
- Open: a periodic corpus-persistence scheme (cache or artifact round-trip in
  CI) would let coverage accumulate across runs instead of restarting from
  seeds daily.
