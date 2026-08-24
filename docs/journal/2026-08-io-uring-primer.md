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

The requested local io_uring-versus-Mio benchmark initially could not proceed on
the 2026-08-24 test host (Intel Core i5-13500H, Ubuntu
6.8.0-138.138-generic). Ringline's `io_uring_setup` call succeeded, but
`IORING_REGISTER_PBUF_RING` returned `EINVAL`. The root cause is Ubuntu
Launchpad bug `#2162843`: downstream commit `cff3ace786c7` inverted the
reserved-field test. The first affected package is `6.8.0-136.136`; upstream
commit `172484907285` is correct. A syscall-only probe confirmed that zeroed
reserved fields fail and an ABI-invalid nonzero field succeeds.

With explicit approval, a local-only copy of `io-uring` 0.7.12 set
`io_uring_buf_reg.resv[0] = 1` solely to bypass that inverted Ubuntu test.
The copy lived under `/tmp`, was selected only by Cargo command-line
configuration, and was never added to the repository.

The completed matrix pinned server workers to P-core logical CPUs `0,2,4,6`
and the Tokio load generator to E-core CPUs `8-15`. It compared 1, 2, and 4
workers at 1, 64, and 512 closed-loop connections, plus 4-worker fixed-rate
20k/s and 500k/s cases. Each configuration used three alternating-order runs,
a two-second warmup, a five-second measurement, and 64-byte messages. Raw CSV
is retained locally at `/tmp/ringline-bench-results.csv`; the primer records
median throughput, latency, aggregate server CPU, and peak RSS.

The result was workload-dependent. Two workers at 64 and 512 connections
delivered about 81% more throughput than Mio. Four workers at 64 connections
converged near 0.5M requests/s, while io_uring used about 275% aggregate CPU
versus Mio's 355%. Four workers at 512 connections delivered 645k/s versus
539k/s. io_uring used roughly 4 MiB, 8 MiB, and 17 MiB more peak RSS at 1, 2,
and 4 workers. One-worker/512-client io_uring had much worse p99 despite higher
throughput, so the evidence is not uniformly favorable.

Source inspection corrected one measurement assumption: Ringline metrics count
CQEs, failures, bytes, pool pressure, and connection lifecycle, but not
`io_uring_enter` or Mio syscalls. A traced diagnostic was discarded because
it distorted throughput. Exact syscall counts remain analytical until native
backend counters are added.

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
- Repeat the local four-P-core benchmark on a fixed Ubuntu or unaffected
  upstream kernel before treating the diagnostic-patch numbers as publishable
  performance evidence. Preserve the failed syscall trace and reserved-field
  probe as provenance for why the local workaround existed.

## Skill Feedback

### architecture-diagram and dataflow-diagram (beta)

- **Friction** — The required visual-review step could not use the local image
  viewer because its sandbox failed before loading either SVG. XML validation,
  viewport-bound checks, deterministic hashes, and an independent human review
  cover that step instead.
- **Friction** — Text placed beside shapes or along arrow paths is often not
  visually balanced: labels can be off-center, too close to borders, or cross
  nearby shapes and connectors even when every element remains inside the SVG
  viewport. The skills should treat label layout as a first-class constraint:
  use explicit anchors, center labels against their intended shape or segment,
  enforce minimum padding from borders and arrow paths, and run collision checks
  between text bounds, shapes, and connectors. Viewport-bound validation alone
  does not catch these presentation defects.
- **Friction** — Connector attachment points are often chosen independently,
  which produces an unbalanced edge when several arrows enter or leave the same
  shape: one arrow remains centered while the others are pushed to one side.
  The skills should lay out connectors per edge as a group. A single connector
  belongs at the midpoint; two should receive equal offsets on either side of
  the midpoint; larger sets should be distributed evenly and symmetrically,
  while preserving corner padding and enough separation for arrowheads and
  labels. This grouped-edge rule should be part of routing and collision checks,
  rather than left to manual coordinate adjustment.
- **Friction** — Nested visual layers are not consistently composed as a
  hierarchy. Parent labels can be interleaved with child labels, and child
  shapes can cross the bounds of their parent container even though every
  individual element is valid. The skills should validate containment and
  non-overlap at each semantic layer: children stay inside the parent content
  area, siblings do not collide, and parent headers occupy a dedicated region
  outside the visual block of their children. Higher-level labels should be
  spatially distinct from lower-level content, rather than mixed into the same
  text rhythm merely because all strings technically fit.

- **Friction** — Multiline labels were positioned one line at a time, so a
  two-line label could be mathematically centered by its first baseline while
  the visible block sat too high or low. The generator now measures the whole
  line group, centers that group in the shape, and then places each baseline
  within it. The skills should treat a multiline label as one layout object
  before aligning its lines.

- **Friction** — Sibling steps with different widths let a connector that was
  correct for the narrow boxes penetrate the wider box. The generator now uses
  one geometry for equivalent steps and tests connector endpoints against the
  actual box borders. The skills should route against resolved shape bounds,
  not against a nominal column coordinate.

- **Friction** — Labels on two parallel arrows were both placed on the same
  side of their lines. In a tight pair, that can put a label closer to the
  neighboring arrow than to the arrow it describes. The generator now places
  the upper label above the upper line and the lower label below the lower line.
  The skills should choose label placement for the connector group: use outward
  placement for a pair, then use collision-aware placement for larger groups.

- **Friction** — The label `wake_recv + poll owner task` placed two meanings of
  “poll” next to each other: Mio readiness polling and runtime task polling. The
  public diagram now says `schedule owner task`; the Rust runtime detail remains
  in prose. The skills should prefer mechanism-neutral lifecycle labels unless
  an implementation detail distinguishes the paths being compared.

- **Friction** — Combining materially different execution variants in one flow
  makes shared lifecycle stages look like shared backend mechanics. When two
  implementations use different operation vocabularies or event paths, the
  skills should prefer separate panels, ordered in a clear comparison axis
  such as top/bottom. Repeating the portable stages is less confusing than
  interleaving backend-specific labels inside one node; shared behavior can be
  explained in adjacent prose rather than compressed into the chart.

- **Confirmation** — Requiring exact source claims before rendering exposed
  three incorrect source markers during the first test run. The resulting
  generator now fails at the architecture boundary rather than producing a
  plausible stale chart.
- **Confirmation** — Converting the user’s visual feedback into generator tests
  made the fixes durable: multiline groups stay centered, equivalent boxes keep
  one width, connector endpoints remain on borders, paired labels face outward,
  and peer boxes remain inside their lanes.

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
