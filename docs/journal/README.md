# Engineering Journal

An in-repo record of non-trivial efforts: what we set out to do, the decision to
proceed or not, what happened, and what was learned. Issues and PRs are the
*task* layer; this journal is the *narrative and decision* layer — the why, the
dead-ends, and how to continue. Entries land on `main` via PR alongside the work
they describe.

Ground rules:

- **Ground every claim in code.** Real commit SHAs, PR numbers, file paths,
  and measured numbers with their source. If a figure came from an off-repo rig
  and isn't checked in anywhere, say so explicitly.
- **Honest ledger.** NO-GOs, withdrawals, and falsified hypotheses are
  first-class entries — record the mechanism and the condition under which the
  question should be reopened. A well-measured dead-end is the highest-value
  entry; an unrecorded one gets re-paid.
- **Land intent before building.** For new efforts, open the entry (goal,
  GO/NO-GO criteria, plan) via PR to `main` *before* implementing, and close it
  out (outcome, numbers, lessons) in the implementing PR.

## Entry template

```markdown
# <Title>

- **Status:** open | shipped | NO-GO | withdrawn
- **Span:** <dates> · <commit/PR range> · <releases>

## Goal
## What happened
## Outcome
## Lessons / open questions
```

Retrospective entries (reconstructed from history rather than written alongside
the work) say so in their Status line.

## Entries

The first nine entries are a retrospective bootstrap of the journal,
reconstructed from the commit history (2026-02-20 through v0.4.0).

| Entry | Span | Theme |
|---|---|---|
| [2026-02 — Bootstrap: runtime + protocol clients](2026-02-bootstrap.md) | Feb 2026 · v0.0.1–v0.0.2 | Initial io_uring runtime import, protocol client crates, fire/recv pipelining API |
| [2026-03 — Hardening blitz + runtime surface](2026-03-hardening-blitz.md) | Mar–Apr 2026 · PRs #4–#84 · v0.0.3–v0.0.5 | ~50 correctness fixes, CQE fault-injection test harness, fs/process/channels/UDS surface |
| [2026-04 — Backend split: the mio fallback](2026-04-mio-backend.md) | Apr 2026 · PRs #94–#103 · v0.1.0 | Extract `backend/uring/`, cfg-gated cross-platform mio backend |
| [2026-04/05 — UDP, QUIC, and HTTP/3 datagram stack](2026-04-udp-quic-h3.md) | Apr–May 2026 · v0.1.1–v0.1.2 | GSO/GRO, multishot recvmsg, QUIC events, closing the H3 throughput gap |
| [2026-05 — Protocol conformance & resource-bounds audit](2026-05-conformance-audit.md) | May 2026 · PRs #158–#180 | RFC conformance, resource bounds, and error-path consistency across every protocol crate |
| [2026-05/06 — Benchmark infrastructure and the honest numbers](2026-05-benchmarks.md) | Apr–Jun 2026 · PRs #151–#209 · v0.2.0 | Bench suite, BENCHMARKS.md published → withdrawn → re-measured on two machines |
| [2026-06 — Performance audit](2026-06-perf-audit.md) | Jun 2026 · PRs #212–#227 · v0.2.1 | zc-threshold, write coalescing, allocation and syscall elimination |
| [2026-06 — API simplification](2026-06-api-simplification.md) | Jun 2026 · PRs #228–#235 · v0.3.0 | Opaque Config/TLS types, non_exhaustive errors, locked CI |
| [2026-07 — Correctness audit and v0.4.0](2026-07-correctness-audit.md) | Jul 2026 · PRs #236–#255 · v0.4.0 | ~35 audit fixes in stacked PRs, send-completion design doc, perf follow-ups |
| [2026-07 — Fuzzing the wire-facing parsers](2026-07-fuzzing.md) | Jul 2026 | Eight cargo-fuzz targets for h2/h3/http1/grpc parsing + daily fuzz CI |
