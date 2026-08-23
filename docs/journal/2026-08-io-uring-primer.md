# io_uring primer and code-derived Ringline diagrams

- **Status:** open
- **Span:** 2026-08-23 · branch `docs/io-uring-primer`

## Goal

Explain when io_uring merits consideration for a low-latency,
high-concurrency service with bounded requests. Keep that decision separate
from the question of whether Ringline is a good Rust implementation. Document
Ringline's runtime and request lifecycle with diagrams that fail CI when their
source claims drift.

## What happened

The primer starts from workload properties rather than APIs or Rust. It covers
the submission/completion model, batching, registered resources, provided
buffers, multishot operations, deployment constraints, and cases where
readiness-based I/O remains the better choice. A separate final section maps
those concepts to Ringline's Rust-specific choices.

The architecture guide follows the code from startup through accept, worker
dispatch, receive, task wakeup, ordered send, and deferred close. It describes
both the io_uring and Mio event loops and includes adjacent text equivalents for
both diagrams.

The new `doc-diagrams` workspace tool generates the SVGs. Before rendering, it
checks source paths and exact code markers for:

- backend selection;
- worker readiness before listener creation;
- acceptor and worker thread names;
- the bounded accepted-connection channel and wake;
- both backend event loops and connection-task creation;
- receive wake ownership, per-connection send ordering, and TLS gating; and
- the absence of a work-stealing deque dependency.

CI runs the generator in `--check` mode, which fails if a source assertion
breaks or a committed SVG differs from generated output.

## Outcome

The outcome remains open until the pull request lands. The branch contains:

- `docs/io-uring-primer.md`;
- `docs/architecture.md`;
- `docs/diagrams/runtime.svg`;
- `docs/diagrams/request-flow.svg`; and
- `tools/doc-diagrams` plus its CI freshness check.

No runtime behavior changes are in scope.

## Lessons / open questions

- A platform primer and a library architecture guide answer different review
  questions. Combining them makes the technology choice look Rust-specific.
- Source-derived diagrams still require judgment. Code assertions detect
  structural drift; they do not prove that every label is the clearest
  explanation for a new reader.
- The local image-view helper could not initialize its sandbox network
  namespace. XML validation, deterministic generation, viewport-bound checks,
  and independent review replace that unavailable preview step.
- After merge, change this entry to shipped and record the pull request and
  merge commit.

## Skill Feedback

### architecture-diagram and dataflow-diagram (beta)

- **Friction** — The required visual-review step could not use the local image
  viewer because its sandbox failed before loading either SVG. XML validation,
  viewport-bound checks, deterministic hashes, and an independent human review
  cover that step instead.
- **Confirmation** — Requiring exact source claims before rendering exposed
  three incorrect source markers during the first test run. The resulting
  generator now fails at the architecture boundary rather than producing a
  plausible stale chart.

### review-guide (beta)

- **Friction** — None observed. The change has a non-diff reading order, a
  judgment call about separating platform guidance from Rust design, and an
  unavailable raster preview, so it clears the skill's publish test directly.
- **Confirmation** — Ranking the primer before the generator and generated SVGs
  preserves reviewer attention for the claims and their enforcement rather
  than the mechanical artifacts.

## Appendix: Skills Invoked

- `architecture-diagram` (beta) — runtime topology and source assertions.
- `dataflow-diagram` (beta) — connection and request lifecycle.
- `technical-prose` — technology-first wording and terminology.
- `engineering-journal` — durable effort record.
- `review-guide` (beta) — reviewer-oriented pull-request description.
- `sweep-comments` — final documentation and comment staleness pass.
