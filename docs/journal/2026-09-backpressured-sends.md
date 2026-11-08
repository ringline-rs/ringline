# Result-aware receives and FIFO backpressured sends (#318, as a nine-PR series)

- **Status:** shipped. **Retrospective** — this journal's own "land intent
  before building" rule says the entry opens with PR 1. It did not; the design
  doc (#367) carried the intent instead, and this was written after #388
  merged. Recording the omission because it is exactly what the rule exists to
  prevent, and it is the second consecutive entry to say so
  ([2026-09-unbuffered-tls.md](2026-09-unbuffered-tls.md)).
- **Span:** 2026-09-10 → 2026-09-13 · design #367 (`046f204`) · PRs #369–#389 ·
  unreleased (post-0.6.4)

## Goal

Land @thinkingfish's #318 — `ConnCtx::with_data_result` and a
`send_backpressured` that waits for send-pool capacity instead of failing —
without importing its design wholesale. #318 arrived as one large change whose
central mechanism was unsound under TLS (see Departure 1). The plan
([`docs/backpressured-sends-series-design.md`](../backpressured-sends-series-design.md))
was nine PRs, each independently reviewable and green, with the eight
disagreements written down as numbered "departures" that each PR cites.

## What happened

| PR | Merge | What |
|---|---|---|
| #369 | `9e5c3b4` | `with_data_result`: EOF vs transport error |
| #370, #372 | `57ab29e`, `c542f25` | Prerequisites found mid-series (#368, #371) |
| #373, #374, #375 | `fd7c8e6`, `f19b6fc`, `c419d05` | `RecvMode` split, mio `shutdown_write` deferral, worker startup errors |
| #376 | `00c69bb` | Transactional copied sends; SQ-pressure parking |
| #377 | `7ecc3fb` | Executor send-capacity FIFO (no callers yet) |
| #379, #380 | `3ab941c`, `82b160a` | Two-guest X710 A/B harness, and the first result |
| #381 | `09ec4d7` | mio bounded path; **departure 4 restored** |
| #382, #384 | `d8b55b6`, `5bbd5d2` | Completion identity, both backends |
| #385 | `f11aeec` | TLS pre-mutation ciphertext bound |
| #387 | `d8d2fdb` | TLS slot-size floor + `send_pool` docs |
| #388 | `763ffb0` | Public `send_backpressured` |
| #389 | `2c0cf59` | Test flakes surfaced by the series (#386) |

### Departure 1, which is why the series exists

#318 made `Ring::push_sqe` return `WouldBlock` so a bounded send would park and
retry. The retry re-runs the *logical* send — including TLS encryption — after
rustls has already advanced its record sequence for ciphertext that was
discarded. The peer sees a sequence gap and fails with `bad_record_mac`.

PR 4 refined the rule rather than simply banning parking: parking a *built*
SQE and re-pushing the same bytes re-runs no encryption and is the model the
ring already uses for partial resubmits. Past a two-attempt cap the operation
fails and the connection closes, rather than silently dropping. `#388`'s
`bounded_tls_send_parks_and_then_fails_rather_than_re_encrypting` is the first
test to pin that end-to-end.

### Departure 4, which was broken twice

On mio, teardown marks bounded operations `ConnectionAborted` before the final
`flush_sends` can report `Ok(len)`, so a handler closing right after a bounded
send cannot tell written from lost. The fix lets a real result overwrite the
provisional one.

It was dropped once in PR 6 on the reasoning that the mio loop is
flush→completions→closes, so nothing could observe the abort. That was wrong:
`Executor::remove_connection` has three callers, two of them in
`poll_ready_tasks`, which runs *before* the flush. Adversarial review caught it
and #381 restored it.

It was then broken again in PR 9, in a different shape: the future's generation
check ran before its state match, so a future on a recycled slot returned
`ConnectionAborted` while **discarding the real `Ok(len)` the queue had already
parked for its id** — defeating departure 4 at the only layer a user can
observe it, and leaking the queue entry permanently. Adversarial review caught
that one too. Two failures on one invariant, neither found by the author.

### The coupling that convention would not have held

#385 computes a bounded TLS send's admission cost from the *ciphertext* bound,
because the plaintext length under-counts and an under-count is what closes
connections. Its design flagged that PR 9 "must compute that number with this
same capacity function" — a rule to be honoured by convention.

PR 9 made it structural instead: `handler::bounded_send_slots` is the single
definition, called by the future *and* both backends' `send_bounded`, so an
inconsistent pair cannot be written. The accompanying test is explicitly
labelled a smoke check, because mutation shows it cannot fail — shrinking the
shared function shrinks both callers together. When the structure is the
guarantee, the test's job is to notice if someone reintroduces a second
computation, and saying so is better than letting it look stronger than it is.

## Outcome

**Correctness.** Eight departures from #318 recorded and cited per-PR. Three
real bugs in #385/#388 found by adversarial review before merge: the departure-4
regression above; a send owned by another connection's task stranding the
admission FIFO (a proxy task on C with a send outstanding on D — the shape the
API's own docs advertise — whose entry survived `remove_connection(C)` with an
unwakeable task id and, at the head, stalled every bounded send on the worker);
and aliasing UB introduced by the `bounded_send_slots` refactor itself.

**Performance.** Measured on two anvil guests across the X710 LAG (hv02 server,
hv01 client), ABAB-interleaved, n=6 per arm, rep0 discarded, every arm
host-quiet-verified:

- #376+#377 (#380): within noise, both backends.
- #384: 256 B +0.2% ops/s, 64 KiB −0.3%, all ranges overlapping.

Rig resolution is ~±4% at 256 B and ~±2% at 64 KiB, so these are "neutral
within resolution", not "free". None of these numbers are checked in; they are
in the PR bodies and the systemslab contexts.

**A finding worth keeping from #385.** The default `send_copy_slot_size`
(16448) clears one whole worst-case TLS record (`F + 29` = 16413) by **35
bytes**, and below that threshold the unbuffered engine's slot bound inverts
from over- to under-estimate. #387 documents the coupling on
`ConfigBuilder::send_pool` and rejects only what cannot work at all — the
broader rejection first proposed would have failed six of this repo's own TLS
tests, which run at 16384, 29 bytes under the line.

## Lessons / open questions

**A bound can be beaten by the thing it bounds.** #385's design asserted that
the unbuffered slot bound "is always safe, whatever the cache does". It was
not: `encrypt_chunk` sized its whole-record hint from *hardcoded default*
constants, so any `max_fragment_size` below ~16382 made the retry loop converge
below one fragment and cache that. Reproduced rather than argued — F=2043 with
a 2072-byte slot caches 2028 — and fixed at the root in #385.

**A test can look like it pins a constant and not.**
`the_bound_covers_real_tls12_records` stayed green when `MAX_RECORD_OVERHEAD`
was mutated 29 → 22, because the bound's slack record is ~16 KiB of headroom
that swallows a 7-byte-per-record error. Pinning it needed a test that measures
one record's overhead directly. Mutation is how this was found, and the same
technique found that two of PR 9's tests passed for the wrong reason.

**A test can encode the developer's machine as a contract.** Two PR 9 tests
asserted *which* of two sends ended up submitted and which parked. That reads
as a claim about the admission queue; it was a claim about socket-buffer drain
speed. Linux's buffer swallows a 4 KiB write that macOS makes wait, and the
assertions inverted. The product was correct throughout.

**Linux caught five defects macOS structurally cannot**, across #385 and #388 —
three of them dead code behind a `cfg` this development machine never takes,
including one in a *test* file. The mitigation that worked was a per-test
`ran=N` count in the VM job: a green suite cannot tell you a test silently
stopped being one, which happened once when a scripted edit landed between a
`#[test]` and its function.

**Flake characterisation needs the failing condition, not the test.** #386's
`async_join3_mixed` passes 30/30 in isolation, because isolation is the
condition under which it cannot fail. An n=30 arm comparison produced a
convincing 3-vs-0 that reversed at n=120. It was finally settled at n=150 per
arm (6/150 → 0/150, #389) with the mechanism reproduced deterministically: the
handler's first `with_data` consumes everything available, so under load one
recv delivers both of the client's writes and the join3's own `with_data` waits
forever.

**Open.** The QUIC `read_until_fin` change in #389 is reasoned, not measured —
that flake is macOS-only and rare and was never reproduced. #386 was closed on
the owner's call with that caveat recorded; reopen from there if
`server should observe FIN` recurs. The series' own follow-up list is closed
except one item: `handle_send_recv_buf` was removed with the recv-buffer
ring, `ConnCtx::send(&[])` settles `Ok(0)`, and `send_chain` refuses while a
send is in flight and plain sends queue behind a chain; `drain_copy_retries`
still does not wake the recv side on give-up where `drain_send_retries`
does, which is harmless (`docs/journal/2026-11-send-path-audit.md`, X4).
