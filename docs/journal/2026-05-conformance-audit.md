# 2026-05 — Protocol conformance & resource-bounds audit

- **Status:** shipped (retrospective entry, reconstructed 2026-07-06 from commit history)
- **Span:** 2026-05-15 → 2026-05-16 · PRs #158–#180 (d955d85 → 9be79e6)

## Goal

After the feature buildout (runtime, mio backend, UDP/QUIC/H3 stack, protocol
clients), take a systematic adversarial pass over every crate — each protocol
crate against its RFC, everything against resource-exhaustion attacks and
error-path state consistency — and land the findings crate-by-crate.

The audit report itself is not in-repo: commit messages cite finding lists
("Thirteen findings from the ringline core audit" in 686a739, "F1/F3/F5/F9"
numbering), but only the fixes landed. This entry reconstructs the audit from
them.

## What happened

Twenty-two commits landed in roughly 36 hours across 2026-05-15/16 — 84 files,
~10,900 insertions (`git diff --shortstat d955d85~1 9be79e6`). Two (a6c860c
#162, 497631f #165) were interleaved UDP feature work belonging to that arc;
the other twenty were audit findings, grouped per crate:

**h3/quic state machines** (first wave):
- d955d85 (#158) — clean up H3 per-connection state on connection close.
- f619303 (#159) — buffer partial uni-stream type varints split across QUIC
  packets (bytes consumed from quinn-proto were being discarded); guard against
  double `ConnectionClosed` delivery.
- ef145d8 (#161) — clean up per-stream state on reset/stop; bound frame size.
- 3d52558 (#163) — GOAWAY gating, 0-RTT reject, backpressure.
- 10869a2 (#164) — the big h3 sweep: protocol conformance, resource bounds,
  HTTP message validation (+860 lines incl. a new `stream_lifecycle.rs` test).
- ca988e9 (#166) — quic connection lifecycle, typed errors, dropped events.

**Runtime** (`ringline` core):
- ae300cc (#160) — update `owner_task` when parking recv/send waiters, so a
  `ConnCtx` handed to a second spawned task wakes the task that actually parked.
- 686a739 (#168) — thirteen findings: generation checks in every I/O future's
  `poll` *and* `Drop` (stale futures after slot reuse), `handle_connect` closing
  the slot when the `ConnectFuture` lost a `select!` race, opt-in
  `recv_accumulator_max`, bounded accept channels with connection-refused
  fallback, idempotent `StandaloneTaskSlab::remove`.

**h2**: a6e4231 (#169) RFC 9113 conformance + resource bounds; 27cdff9 (#171)
the OOS follow-ups — stream-level WINDOW_UPDATE overflow gets RST_STREAM not
connection teardown, monotonic GOAWAY, refused PUSH, HPACK dynamic-table update
pairs.

**http**: e289c8c (#172) RFC 9112 conformance with request-smuggling defenses
(TE+CL rejection, duplicate Content-Length, unsupported transfer codings,
CR/LF/NUL in header values, outbound CRLF-injection validation) plus size caps
(`set_max_header_section` etc.); 4480765 (#180) h1 header scan, trailer
validation, pool reuse signalling.

**grpc**: f1bc49b (#174) bounded message reassembly, non-silent decompression
failures, correct missing-status default; 6a1e3cf (#176) decompression-bomb
defense + timeout encoding.

**Protocol clients, error-path consistency**: 2525bd2 (#173) shared sweep —
opt-in `max_in_flight` caps on pending queues (`Error::TooManyInFlight`) across
the clients, plus error-path state consistency after transient send
failures; a1b5862 (#175) redis ASK redirect chaining (`AskOutcome` feeding
follow-up redirects back into the routing loop), transient-error retry, ASKING
response validation; 80e8e9a (#177) memcache; 9be79e6 (#179) ping
close-on-parse-error.

**Supply chain**: e0548b1 (#170) pinned `rustls = "0.23.18"` (RUSTSEC-2024-0399)
and `quinn-proto = "0.11.14"` (pulls patched `ring`, RUSTSEC-2025-0009) as
minimum-version floors for downstream resolvers — our own lockfile was already
safe — and tightened `cargo audit` in CI.

## Outcome

- Every protocol crate got an RFC-conformance and resource-bounds pass; the
  fixes are the audit's only durable record.
- Three shapes recurred at every layer from the runtime to the ping client:
  unbounded caller- or peer-driven growth (pending queues, reassembly buffers,
  accumulators, header sections), state not cleaned up on the error/close
  path, and stale-slot/duplicate-event races.
- The resource caps consistently defaulted to *disabled* (`usize::MAX`) — the
  audit's stance was to provide the knob, not to guess a limit that breaks
  legitimate slow consumers (686a739's rationale for `recv_accumulator_max`).
- The RUSTSEC pin convention from #170 persists today as comments in the
  workspace `Cargo.toml` (rustls/quinn-proto pin rationale, lines ~45–58).

## Lessons / open questions

- **Record the audit, not just the fixes.** Commit messages cite finding
  numbers from a report that doesn't exist in-repo; a finding that was deferred
  rather than fixed is invisible today. This journal is a partial answer.
- Concentrated per-crate landings (one PR per crate, one burst) made the sweep
  reviewable and bisectable — the same structure recurred in the July audit
  (#236–#244).
- The audit was static/adversarial, not fuzz-driven: no fuzz harness landed
  with it. Open question whether smuggling-class and varint-split bugs like
  f619303's would be cheaper to keep finding with a fuzzer in CI.
