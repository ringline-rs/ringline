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
| [2026-05 — UDP multishot recv latency: the kernel-side EAGAIN peek](2026-05-udp-multishot-latency.md) | May 2026 · issue #167 | bpftrace localizes the single-client UDP-vs-TCP RTT gap to the kernel's multishot peek; single-shot mode deferred |
| [2026-05/06 — Benchmark infrastructure and the honest numbers](2026-05-benchmarks.md) | Apr–Jun 2026 · PRs #151–#209 · v0.2.0 | Bench suite, BENCHMARKS.md published → withdrawn → re-measured on two machines |
| [2026-06 — Performance audit](2026-06-perf-audit.md) | Jun 2026 · PRs #212–#227 · v0.2.1 | zc-threshold, write coalescing, allocation and syscall elimination |
| [2026-06 — API simplification](2026-06-api-simplification.md) | Jun 2026 · PRs #228–#235 · v0.3.0 | Opaque Config/TLS types, non_exhaustive errors, locked CI |
| [2026-07 — Correctness audit and v0.4.0](2026-07-correctness-audit.md) | Jul 2026 · PRs #236–#255 · v0.4.0 | ~35 audit fixes in stacked PRs, send-completion design doc, perf follow-ups |
| [2026-07 — ENOBUFS graceful degradation: fallback one-shot recv](2026-07-enobufs-fallback-recv.md) | Jul 2026 · PR #274 | Park counter + fallback recv into accumulator memory for responses larger than the provided ring |
| [2026-07 — Fuzzing the wire-facing parsers](2026-07-fuzzing.md) | Jul 2026 · PR #263 | Eight cargo-fuzz targets for h2/h3/http1/grpc parsing + daily fuzz CI |
| [2026-08 — io_uring primer and code-derived runtime diagrams](2026-08-io-uring-primer.md) | Aug 2026 · PR #319 | Technology-first io_uring guidance, Ringline architecture, and generated diagram checks |
| [2026-08 — Evaluating the code against its own principles](2026-08-principles-evaluation.md) | Aug 2026 · PRs #322–#325 | Four findings from a PRINCIPLES.md conformance pass: bounded accumulator default, non_exhaustive gaps, a stale asymmetry claim, and send-CQE identity validation |
| [2026-09 — Two-phase park: induce quiescence instead of sampling for it](2026-09-two-phase-park.md) | Sep 2026 · follows #443 | **Open.** Intent landed before building: suppress the ECANCELED re-arm so a cancelled recv creates a real drain window, then give tier 3 a busyness signal. GO/NO-GO numbers fixed; the "no new bytes can arrive" premise was checked and found false first |
| [2026-09 — Tier 3 park: does it repair a standing imbalance?](2026-09-tier3-park.md) | Sep 2026 · PRs #464–#469 | Park converges a manufactured post-accept imbalance in 11–18 s and recovers the full 8-worker headroom; penalty bounded below ~4% when balanced. Prediction that a balanced fleet never trips `PARK_MARGIN` refuted. Policy metric (counts vs busyness) left open |
| [2026-09 — Unbuffered TLS send path](2026-09-unbuffered-tls.md) | Sep 2026 · PRs #338–#350 | **NO-GO on the stated criterion.** The 2 → 1 copy premise was false: rustls only buffers plaintext pre-handshake, and `write_fragments` seals into a per-record buffer then copies out. Engine kept default-off as the kTLS prerequisite; unanticipated 4–8% recv win |
| [2026-09 — Backpressured sends as a nine-PR series](2026-09-backpressured-sends.md) | Sep 2026 · design #367 · PRs #369–#389 | Landing #318 as nine reviewable PRs with eight recorded departures; departure 1 (no re-encrypting retry) and departure 4 (a real result outranks a provisional abort, broken twice); admission cost made structural rather than conventional |
| [2026-09 — Release comparison campaign](2026-09-release-comparison-campaign.md) | Sep 2026 · open | **Intent only.** ringline vs tokio, io_uring vs mio, on the X710 rig with rezolus. Connection count is a first-class axis because of an unresolved connection-scaled latency penalty; three harness-fairness gaps must be fixed first |
| [2026-09 — Result-aware receives and backpressured sends, as a series](2026-09-backpressured-sends-series.md) | Sep 2026 · #367, PR 1 of 9 → | Landing #318 as nine PRs; `with_data_result` first; io_uring `RecvMulti` stale-CQE hazard recorded |
| [2026-09 — Incremental provided-buffer consumption](2026-09-incremental-buffer-consumption.md) | Sep–Oct 2026 · open · follows #415 (282773b), #416 · design #622 | `IOU_PBUF_RING_INC` (Linux 6.12) to break the payload-per-completion vs ring-depth tie. **2026-10-08: owner's decision**: two shared buffer groups go into the implementation for kernels before 6.12. Author's proposals: plain 4096 × 64 KiB plus 256 × 1 MiB before 6.12 (proposed on by default, pending landing step 6), INC 64 × 1 MiB on 6.12+ with an INC 64 × 1 MiB large group off by default pending further measurement; connections promoted when they stream (`SOCK_NONEMPTY` completions of at least 64 KiB) or hold lends, and demoted only after a 1 s quiet period. One group measured on 6.1, 6.12 and 7.1, two groups on 6.1 and 6.12; per-connection receive memory was measured and not chosen |
| [2026-09 — Direct-forward path, and gathering](2026-09-direct-forward-path.md) | Sep 2026 · NO-GO → **shipped** · follows #415, #416 | Submitting from the completion handler bought nothing (instr/byte 1.236 → 1.243), which left the completion count as the only explanation. Gathering ≤16 held buffers per `sendmsg` is **+30%** (1.236 → 0.906 instr/byte, past direct echo) and collapses #416's forwarding exception from −34% to −3.5% |
| [2026-09 — Prefaulting the buffer pools](2026-09-prefault-measurement.md) | Sep 2026 · shipped, default off · PR #419 | Measured: **−32% ramp p999** at an over-provisioned ring, **null at the default**. The lever is fault *cost*, not count — THP backs a large pool, so each fault zeroes ~1.2 MiB. Two page-count predictions failed; the knob was also unreachable from the harness, which is why it shipped unmeasured |
| [2026-09 — A Shutdown SQE half-closing the slot's next occupant](2026-09-shutdown-sqe-half-close.md) | Sep 2026 · issue #518 · PRs #522–#525 | **Shipped, after one hypothesis was refuted post-merge.** A `Shutdown` SQE names its socket as the registered-file *slot*, and nothing pinned the slot for its lifetime, so the `Close` could complete first and the FIN land on the next occupant — a live peer, cleanly half-closed. The probe explanation in #522 was only shielding slot 0; its own control raised the rate from 3/100 to 10/100. Instrumentation, not deduction, isolated it: 49/400 → 0/400 with `shutdown_write()` removed |
| [2026-09 — `connect()` resolves to a `Connection`, behind two builders](2026-09-connect-returns-connection.md) | Sep 2026 · issue #528 · PRs #531, this one | **Shipped.** Collapse 15 connect entry points to 2 `IntoFuture` type-state builders resolving to `Connection`. The argument is not symmetry but that `split()` at construction manufactures a failure the caller did not cause — reachable, since `ConnCtx` is `Copy`. Records the rejection of a generic `Connection<Tcp/Unix/Tls<Tcp>>`: the tag would be unenforceable over a runtime-dispatched slot table, and `on_accept` cannot know the transport at compile time |
| [2026-09 — Deferred listen: a per-listener readiness gate](2026-09-deferred-listen.md) | Sep 2026 · issue #534 · this PR | **Intent only.** Bind reserves the port; `listen()` waits for the handler, so a readiness probe fails honestly instead of a deferred *accept* completing the handshake and passing the probe. Records that merged mode already binds early, defers listen and gates worker arming on a latch — only *who* releases it changes. Rejects awaiting `on_start`: it may legitimately never complete, and the repo's own tests rely on that |
| [2026-10 — Receive starvation at high connection counts](2026-10-receive-starvation.md) | Oct 2026 · open · #657, #658, #660 | **Open.** Unanswered connections at 10,000–16,384 connections are three failures: lost in the listen queue, closed by the acceptor (#658), and receive starvation. Starvation at 256 B tracks ring exhaustion and arbitrary re-arm order (#657); at 64 KiB it does not, which is unexplained. `recv_incremental`'s RSS growth is heap copies above the lend cap, unbounded; #660 releases accumulators at close |
| [2026-11 — Audit of the connection lifecycle and close path](2026-11-connection-close-audit.md) | Nov 2026 · tree a2e28073 · #767 (F2, F3), #768 (F9), #769 (F6), #771 (F1), `fix/uring-connect-identity` (F4, F5) | **Open; F1 to F6 and F9 fixed.** Twenty invariants agreed first, five concerns reviewed in parallel on the current tree after a first pass ran 228 commits stale. 14 findings: io_uring commits the Close inside `drain_completions` when the FIN and last send CQE share a batch (F1); `CONNECTIONS_ACTIVE` goes negative for outbound connections (F2) and `CLOSED` differs per backend (F3); the Connect SQE carries no generation (F4); local aborts read as a clean peer close (F6, reproduced on mio); worker exit skips the gauge and abandons mio closes (F8); plus seven design limitations and what was not covered |
| [2026-11 — Audit of the send path](2026-11-send-path-audit.md) | Nov 2026 · tree 6ea67e6c · #773 (F1), #775 (F2), this PR (F3) | **Open; F1, F2 and F3 fixed.** 23 invariants agreed first, five concerns reviewed in parallel. 14 findings: a `SendFuture` handed to another task after its creator returns never resolves, and a send another task awaits on a connection whose task returns resolves `ConnectionAborted` for delivered bytes (F1, F2, both reproduced on mio); `shutdown_write` pushes the FIN beside an active chain (F3); mio leaves a TLS connection open after an encrypt failure, reachable at TLS 1.2 key exhaustion (F4); close_notify dropped under pool exhaustion and on key exhaustion (F5, F6); a zero-length `send_parts` discards the queue behind it (F7); plus nine design limitations and what was not covered |
