# Unbuffered TLS send path

- **Status:** **NO-GO on the stated GO criterion** (2026-09-04). The engine
  shipped behind a default-off feature (#350) and stays, but the copy reduction
  it was built for does not exist — see "Plan 4 — measurement" below. Interop
  testing still open.
- **Span:** 2026-09-03 → · PRs #338, #341, #345, #350 · unreleased (post-0.6.0)

Written after the foundation landed rather than before it, contrary to this
journal's own "land intent before building" rule. Recording that here because
the omission is the kind of thing the rule exists to prevent.

## Goal

> **Falsified, 2026-09-04.** The copy described as (1) below does not happen on
> an established connection, and the unbuffered API does not remove a copy.
> See "Plan 4 — measurement: NO-GO on the stated criterion". Original text kept.

Remove one of the two copies TLS pays on every send.
[`docs/syscalls-and-copies.md`](../syscalls-and-copies.md) records TLS sends at
2 copies versus 1 for plaintext:

1. user bytes → rustls' internal `sendable_plaintext` buffer (`conn.writer().write`)
2. rustls encrypts out of that buffer into the send-pool slot (`conn.write_tls`)

Copy 2 is intrinsic, and #254 already removed the scratch buffer that used to
sit beside it. **Copy 1 is pure buffering overhead** — the plaintext is already
contiguous in caller memory — and the buffered rustls API has no way to skip it.
rustls' *unbuffered* API does: `WriteTraffic::encrypt(&[u8], &mut [u8])` reads
plaintext from a caller slice and writes ciphertext into a caller buffer.

Secondary payoff: `send_parts().guard()` is refused outright under TLS today.
With `encrypt` taking `&[u8]`, a `SendGuard`'s memory can be the plaintext
source. Not zero-copy to the wire — that needs NIC offload — but it stops the
API refusing a reasonable request.

## Why not kTLS, which was the original question

kTLS was where this started. Two findings moved it to a follow-on:

1. **kTLS is all-or-nothing per connection.** `dangerous_extract_secrets(self)`
   consumes the rustls connection on all three overloads, so there is no "kTLS
   for TX, rustls for RX" — extraction destroys the state machine that would
   decrypt inbound records.
   *(Corrected 2026-09-06: the conclusion holds and is stronger than stated.
   The method named here is `#[deprecated]`; its replacement
   `dangerous_into_kernel_connection` also takes `self`, and the
   `KernelConnection` it returns does no encryption or decryption at all — it
   only computes new traffic secrets on a key update and absorbs session
   tickets. So the RX conversion is on the critical path for any kTLS work,
   not deferrable to a later phase.)* That makes kTLS strictly larger than it looks:
   Linux-only, kernel-cipher-restricted, needing the `RecvMsgMulti` + cmsg path
   to read TLS control records, plus KeyUpdate handling, kernel-version gating,
   and a fallback for every unsupported case.
2. **The unbuffered path gets the same send-side copy count on *both* backends**,
   including macOS, with none of that — and is a prerequisite anyway, since
   `dangerous_extract_secrets` is implemented on `UnbufferedConnectionCommon`.
   *(Corrected 2026-09-04: the first clause was the point of this effort and it
   is false — the unbuffered path does not change the copy count at all. The
   prerequisite clause is the part that survives, and is now the only standing
   justification for the engine.)*
   *(Corrected again 2026-09-06: the prerequisite clause survives, but its
   stated reason never did. `dangerous_extract_secrets` is implemented on the
   buffered types too — `ClientConnection`, `ServerConnection`,
   `ConnectionCommon<Data>`, `Connection` — so it never distinguished the
   engines. What does distinguish them is the replacement,
   `dangerous_into_kernel_connection`, which is public only on
   `UnbufferedClientConnection`/`UnbufferedServerConnection`. The engine's only
   standing justification rested on a citation that did not support it.)*

kTLS remains the only route to `sendfile` and NIC crypto offload, which is where
the *remaining* copy goes. Reopen it once the unbuffered engine is real.

## GO/NO-GO criteria

- **GO** if TLS sends measurably drop to 1 copy with no regression in
  throughput or latency on the rig, on both backends.
- **NO-GO** if driving rustls' 8-state `ConnectionState` machine proves to cost
  more than the copy it saves, or if the ciphertext-buffer management needed by
  `process_tls_records` cannot be made amortized O(1) — see below, where that
  nearly happened.

## What happened

Design: [`docs/tls-unbuffered-design.md`](../tls-unbuffered-design.md). Split
into three plans; **plan 1 (foundation) shipped in PR #338**, behavior-neutral:

- `tls.rs` (1181 lines) split into `tls/mod.rs` + `tls/buffered.rs`,
  verified byte-identical by ordered reconstruction diff.
- `CiphertextBuf`, the incoming-ciphertext buffer the engine will
  drive. Not yet wired up.
- A default-off `tls-unbuffered` cargo feature and its CI job, so the
  second path is linted from the start.

### Three bugs in `CiphertextBuf`, all found by adversarial review

Recorded because the first one shipped behind a test that proved nothing, and
the pattern is worth not repeating.

- **Unguarded second compaction site.** `make_room` had two `compact()` calls;
  only one was gated on "compaction pays for itself". The other fired exactly
  when the first did not (`live > buf.len()/2`), so once the buffer was backed
  up every append memmoved the whole live set — **16383× amplification** at a
  1 MiB cap, remotely triggerable by a peer that outruns the reader. This is the
  O(N·K) shape #279 removed. The original test ran at 0.002% occupancy, the one
  regime where the bound holds regardless of implementation.
- **`WouldBlock` deadlock at the cap floor.** The fix for the above returns
  `WouldBlock` when the buffer is full of live data. `WouldBlock` implies
  `live > (cap − additional)/2`, so safety needs `cap/2` to exceed the largest
  set rustls can leave unprocessed — but rustls joins handshake messages
  spanning records *inside the caller's buffer* up to `MAX_HANDSHAKE_SIZE`
  (0xffff), making the first floor exactly half what was required. Demonstrated:
  `cap=83972 start=20000 live=63972 append(1448)` hangs. Floor is now
  `2·MAX_UNPROCESSABLE + MAX_SINGLE_APPEND` (233,480), verified at 0 refusals
  across 71,829 unprocessable states.
- **Cap was not a hard ceiling.** `make_room` resized from a `needed` computed
  before compaction, so `.max(needed)` defeated the `.min(cap)` clamp.

Every fix carries a regression test **verified to fail against the broken
implementation**. The first replacement test written for the cap bug passed
against both versions and was discarded for a brute-forced case that
discriminates.

### A cfg-gated bug macOS could not catch

`TlsTable::send_close_notify_queued` in `mod.rs` calls `take_tls_output_sends`,
which the split moved to `buffered.rs` as a private fn. A child module sees an
ancestor's privates; the reverse does not hold. The call is
`#[cfg(has_io_uring)]`, so every local check on macOS passed and Linux CI failed
six jobs on one root cause. Fixed with `pub(super)`, which is the scope it had
as a single file. Notably a reviewer *did* flag cross-module visibility as a
risk but named the opposite direction — the one that is actually free.

## Outcome

Foundation only. No copy has been removed yet; the engine is plan 2.
(Superseded — the engine landed. See "Plan 3 — the engine" below.)

### Plan 3 — the engine (2026-09-04)

The engine is real: `drive()` runs rustls' eight-state machine, `encrypt_chunk`
writes application-data ciphertext straight into a pool slot, and close_notify
goes through `WriteTraffic::queue_close_notify`. Both backends build and test
green under `--features tls-unbuffered`.

**The copy win is application data only, and on io_uring it comes with a
handshake-side cost.** *(Corrected 2026-09-04: there is no copy win at all —
`WriteTraffic::encrypt` also costs 2 copies. See "Plan 4 — measurement" below.
The handshake-side cost recorded here is real and stands.)*
`WriteTraffic::encrypt` reads plaintext from caller
memory and writes ciphertext straight into the pool slot (io_uring) or the
queued buffer (mio) — that path is genuinely 1 copy, down from 2, on both
backends. But `EncodeTlsData::encode` — the handshake path — is all-or-nothing
on one contiguous `&mut [u8]` and does not take an `io::Write`, and a full-size
handshake record can exceed the default 16384-byte `send_copy_slot_size`. The
buffered engine's `PoolWriter` wrote handshake output straight into pool slots
(1 copy); the unbuffered engine can't, so handshake output goes rustls →
scratch `Vec` → pool slot (2 copies) — one *more* than buffered, on io_uring
only (mio has no pool-slot step either way, so its handshake output stays 1
copy under both engines). Handshake is once per connection, not the
steady-state path this work targets, but the copy tables now say so explicitly
rather than claiming an unqualified win.

**Recv is unchanged at 1 copy, on both engines.** rustls 0.23.41's
`ReadTraffic::next_record` pops an owned `Vec` out of `received_plaintext`
rather than decrypting in place — the unbuffered API's `_incoming_tls` field is
kept only "for forwards compatibility; to support in-place decryption in the
future" (that's rustls' own comment, not ours). So plaintext still has to be
copied into the `RecvAccumulator`. Nobody should read the send-side win and
assume recv moved too.

**`TlsInfo::sni_hostname()` is always `None` for server connections on this
engine**, and stays that way until follow-on work. rustls has no equivalent of
`ServerConnection::server_name()` on `UnbufferedServerConnection` —
`server_name()` lives only on the handshake-callback `ClientHello` type and on
the buffered `ServerConnection`. Recovering it needs a `ClientHello` callback
on `ServerConfig`. Real, user-visible, in the CHANGELOG.

**A pre-existing io_uring bug, found but not fixed here** (fixed in #706;
see open item 3). `ConnCtx::close()`
(`runtime/io.rs`) calls `Driver::close_connection`, which on io_uring only sets
`recv_mode = Closed` and tears down recv/forward-write state — it never queues
close_notify. The TLS close_notify queueing lives in `DriverCtx::close(conn:
ConnToken)` (`handler.rs`), a different function the `ConnCtx::close()` path
never reaches. So an io_uring TLS server that closes a connection from inside
its own handler (the common case) sends a bare FIN, not a close_notify alert —
the peer can't distinguish that from truncation. This reproduces against the
**buffered** engine too; it predates this effort entirely and isn't caused by
either engine. Filed here rather than fixed, since it's out of scope for a
docs-only task and deserves its own change with its own tests.

Five things the design doc did not anticipate, all found while building
(design-doc `> **Correction**` blocks record the first three in place; the
other two are here because they're more process than design):

- **`process_tls_records` is not callable generically.** rustls implements it
  separately per connection role, and the shared body is private, so
  `ConnectionState<'_, '_, Data>` differs between `UnbufferedClientConnection`
  and `UnbufferedServerConnection` — no single non-generic function can match
  on both. The engine needed a private `UnbufferedEngine` trait with an
  associated `Data` type, dispatched once at the top of `drive()`; the state
  machine body monomorphizes from there.
- **Re-entering `process_tls_records` on a sizing retry is unsound, and it bit
  twice in two different functions before the pattern was recognized.**
  `write_plaintext`'s `perhaps_write_key_update()` and
  `eager_send_close_notify`'s `send_close_notify()` both queue into
  `sendable_tls` *before* the caller ever calls `check_required_size`, and
  `process_tls_records_common` pops `sendable_tls` into the next
  `EncodeTlsData` before `WriteTraffic` is reachable again. A naive
  "try `encrypt`, get `InsufficientSize`, re-enter the state machine and try
  again" retry therefore lands on a *different* state than the one it started
  in. The close_notify case failed silently: the alert got stranded inside
  rustls, `close_notify_sent` was never set, and the connection closed as a
  truncation rather than a clean shutdown — no panic, no error, just a wrong
  answer that only a wire capture would catch. Both call sites now enter the
  state machine once, hold the `WriteTraffic` handle across the whole retry
  loop, and never re-enter for a sizing-only reason.
- **Never drive the machine to "flush" after encrypting or queueing an
  alert.** `write_fragments` drains `sendable_tls` into the *front* of the
  destination buffer, and `check_required_size` reserves room for it — so
  anything already queued (a TLS 1.3 `key_update`, most notably) rides out
  ahead of the fragments about to be encrypted, correctly ordered, as a side
  effect of the same `encrypt`/`queue_close_notify` call. Driving the machine
  again afterwards and emitting that queued output as a *separate* send would
  put it after the already-encrypted records on the wire instead of before —
  the peer would see `bad_record_mac`. This only had to be gotten right once
  because it was caught in review, not in a wire capture, but it's exactly the
  kind of mistake this journal exists to keep someone from making twice.
- **`MAX_SINGLE_APPEND` (64 KiB) is reachable from public config, not just an
  internal assumption.** `ConfigBuilder::recv_buffer` accepts buffers larger
  than that, and the io_uring recv path hands one whole provided buffer to the
  TLS feed in one call. `CiphertextBuf::append`'s `debug_assert` on the 64 KiB
  bound is silent in a release build, so `feed()` chunks its own appends at
  `MAX_SINGLE_APPEND` rather than trusting the caller to stay under it.
- **Dead-code lints are invisible on macOS for this whole module, and that
  cost a red branch once and was rediscovered twice more.** `lib.rs` applies
  `#[cfg_attr(not(has_io_uring), allow(dead_code))]` to all of `tls` (it
  predates this feature — `buffer`, `chain`, `completion`, `fs`, `nvme` etc.
  carry the same attribute), so a clean local `cargo clippy -D warnings` on
  macOS says nothing about unwired unbuffered-engine surface. Only Linux CI
  (or `hv01`) actually lints it.

Still open, deferred to plan 4: interop testing (buffered client ↔ unbuffered
server and the reverse — streams can't be byte-identical, so the assertion is
interoperability, not equality), and the chunk-size rig sweep the design doc's
open question 1 always deferred to measurement.

### Pre-PR adversarial review (2026-09-04)

Four adversarial reviewers went over the whole branch diff before the PR, one
per risk cluster: send-completion contract and pool-slot lifecycle, wire record
ordering, the ciphertext buffer's state machine, and close/EOF semantics.
**21 of 22 focus areas came back safe**, including the three bug classes this
effort had already been bitten by — `discard` applied exactly once on every exit
of all four state-machine entry points, the 16383x compaction site confirmed
gone rather than merely re-guarded (one call site, correctly gated), and sink
overflow fatal on both arms rather than silently consuming.

**The one finding, reached independently by two reviewers from different
directions.** `encrypt_with` and `close_notify_with` funnelled every non-target
`ConnectionState` into a catch-all, which silently swallowed two states that
must not be swallowed:

- `EncodeTlsData` is *destructive on construction* — `process_tls_records_common`
  pops the chunk out of `sendable_tls` and never restores it, so dropping the
  value discards an outgoing record permanently. In `close_notify_with` that
  record can be the alert itself: on TLS 1.2 traffic-key exhaustion
  `write_plaintext` calls `send_close_notify()` before returning
  `EncryptExhausted`, so the catch-all popped the queued alert, dropped it, and
  returned success with `close_notify_sent` false. The peer would see a bare FIN
  instead of a clean shutdown.
- `PeerClosed` is edge-triggered. If a send-path `process()` were the call that
  deframed the peer's close_notify, the edge would be consumed with
  `peer_sent_close_notify` left false, and the next FIN would be reported as a
  *spurious truncation* — a false security signal.

Neither was reachable on the normal path, but only because of an invariant that
lived nowhere in the code. Both now have explicit arms, both tested, and the
`EncodeTlsData` case turned out to be constructible after all (a server holding
the client's first flight staged-but-undriven).

**Also recorded: an accidental interlock.** `submit_next_queued` coalesces
consecutive pool-backed sends into one `SendMsgCoalesced` without inspecting
`OpTag`. Multi-slot TLS sends never coalesce today *only* because `copy_in` and
`alloc_raw` default `slot_end_of_send = true` and the TLS builders never clear
it. Clearing it for intermediates looks like an obvious tidy-up — they are parts
of one blob — and would collapse a multi-slot send into a single wake with the
wrong count. Both call sites now carry a comment saying so.

### Backlog: pre-existing issues found while reviewing, not fixed here

All of these reproduce against the **buffered** engine too, so this effort
neither introduced nor worsened them. Recorded rather than fixed, to keep the
PR scoped.

1. **`SendFuture` reports ciphertext length, not plaintext length**, for TLS
   sends. `handle_tls_send` never adds to `acked_bytes`, so a multi-chunk
   `send().await` resolves with only the final chunk's ciphertext length. This is
   the half of "exactly one waiter wake per logical send, with the right count"
   that is currently wrong on both engines.
2. **`ConnCtx::send(&[])` on a TLS connection never resolves** — the waiter is
   set but no SQE is submitted. Same shape as the plaintext path.
3. **`ConnCtx::close()` on io_uring sends a bare FIN.** (Fixed in #706: both
   `ConnCtx::close()` and a handler return now go through
   `Driver::close_connection_graceful`, which queues the alert.) It routed to
   `Driver::close_connection`, which only sets `close_pending`; close_notify
   queueing lives in `DriverCtx::close(ConnToken)`, which that path never
   reaches. The peer cannot distinguish clean shutdown from truncation.
   `DriverCtx::close` (the on_tick-context close) *is* now covered, by
   `tls_tick_close_sends_close_notify`.
4. **mio `finish_close` can write the alert past queued data.** `flush_sends`
   may return with the FIFO non-empty on `WouldBlock`, after which
   `flush_tls_output_mio_direct` writes the alert straight to the socket and
   `pending_sends.clear()` discards the rest — a record-sequence gap the peer
   reports as `bad_record_mac`.
5. **Suspected mio fd/slot leak when the peer closes first** (unconfirmed). The
   peer-FIN path sets `RecvMode::Closed` without pushing to `pending_closes`, so
   `finish_close` never runs for that connection: no poll deregistration, no
   `TcpStream` drop, no slot release.
6. **`MAX_UNPROCESSABLE` lacks per-record framing headroom.** The constant bounds
   the 0xffff plaintext handshake message but not the on-wire extent of the
   records carrying it, so the no-deadlock derivation is empirically safe rather
   than airtight. The window is *empty* at the default `recv_buffer.buffer_size`
   of 16384 and only opens above ~64 KiB; worst case is one connection killed
   with a clear error, not a hang or corruption. Suspected, not proven.
7. **Buffered io_uring can miss a coalesced close_notify.** `feed_tls_recv`'s
   buffered path returns `HandshakeJustCompleted` before the
   `state.peer_has_closed()` check, so a peer coalescing its last handshake
   flight with a close_notify leaves `peer_sent_close_notify` false. The
   unbuffered engine handles this correctly — do not "fix" it toward parity.
8. **`encrypt_with`'s catch-all also covers `ReadTraffic`**, the third member of
   the swallowed-state family. Decrypted application data surfacing on a
   send-path `process()` would be dropped rather than stashed into
   `pending_plaintext` the way `drive_inner` does it. Same unreachability
   argument as the two that were fixed.

### Plan 4 — measurement: NO-GO on the stated criterion (2026-09-04)

**Verdict: NO-GO.** The GO criterion was *"TLS sends measurably drop to 1 copy
with no regression in throughput or latency on the rig, on both backends."* The
second half holds. The first half does not, and could not have: **there was no
copy to remove.** The whole premise was a claim about rustls that was never
checked against rustls.

Recording this as a negative result because it is the more useful half. The
engine is real, correct, and merged; what is false is the reason it was built,
and that reason survived a design doc, four PRs, an eight-reviewer adversarial
pass and a merge without anyone opening `common_state.rs`.

#### Evidence 1 — rustls source (definitive)

Verified in rustls 0.23.41, the version pinned in `Cargo.lock`.

The design's "Copy 1" was user bytes copied into rustls' `sendable_plaintext` by
`conn.writer().write()`. **That copy does not happen on an established
connection.** `CommonState::send_plain` (`src/common_state.rs`):

```rust
if !self.may_send_application_data {
    // If we haven't completed handshaking, buffer
    // plaintext to send once we do.
    ...
}
self.send_plain_non_buffering(payload, limit)
```

`sendable_plaintext` exists to hold plaintext written *before* the handshake
completes. Every application-data send afterwards goes straight to
`send_plain_non_buffering`, which fragments and encrypts immediately. The
buffered engine was already doing what the unbuffered engine was built to make
it do.

#### Evidence 2 — rustls does not encrypt into the caller's buffer either

`WriteTraffic::encrypt` → `write_plaintext` → `CommonState::write_fragments`:

```rust
for m in fragments {
    let em = self.record_layer.encrypt_outgoing(m).encode();
    let len = em.len();
    outgoing_tls[written..written + len].copy_from_slice(&em);
}
```

and `Tls13MessageEncrypter::encrypt` (`src/crypto/ring/tls13.rs`):

```rust
let total_len = self.encrypted_payload_len(msg.payload.len());
let mut payload = PrefixedPayload::with_capacity(total_len);   // fresh alloc per record
payload.extend_from_chunks(&msg.payload);                      // plaintext copied IN
self.enc_key.seal_in_place_append_tag(nonce, aad, &mut payload)?;
```

So `encrypt(plaintext, dst)` is: plaintext → fresh per-record heap buffer → AEAD
in place → `copy_from_slice` into `dst`. **Two passes**, the same two the
buffered engine pays. `encrypt`'s signature *looks* like in-place encryption
into the destination; its implementation is not. Reading the signature and
inferring the mechanism is exactly the mistake made here.

#### Evidence 3 — measured on Linux/io_uring

hv01, kernel 6.12, rustc 1.98.1. Isolated in-process microbenchmark of the send
path (harness on a local branch, not merged).

An allocation counter inside the measured call, 256 KiB payload: buffered
**263,976** bytes/op, unbuffered **264,000** — 24 bytes apart. If the unbuffered
path encrypted into the destination this would be ~0. That single number is
what turned a suspicion into a conclusion, and it is cheap: it should have been
the first thing measured, before the design was written.

Isolated send path, ns/op, medians of 4 interleaved rounds, under 1% within-arm
spread:

| size | buffered | unbuffered | Δ |
|---|---:|---:|---:|
| 1 KiB | 538.6 | 521.7 | −3.1% |
| 16 KiB | 4302 | 4547 | **+5.7%** |
| 64 KiB | 17741 | 17613 | −0.7% |
| 256 KiB | 71738 | 70196 | −2.2% |
| 1 MiB | 287181 | 282071 | −1.8% |

**A control that mattered:** running the payload cold made the copy ~4.5× more
expensive and left the arm delta *unchanged* (−2.2% hot vs −2.1% cold at
256 KiB). If a copy had been removed, making copies more expensive would have
widened the gap sharply. It did not move. This is the cheap discriminator for
"did a copy actually go away" and is worth reusing.

Isolated **recv** path (mins of 8 reps, 10–20% spread — weaker numbers, treat
as ±2%):

| size | buffered | unbuffered | Δ |
|---|---:|---:|---:|
| 1 KiB | 580 | 544 | −6.2% |
| 16 KiB | 5020 | 4630 | −7.8% |
| 64 KiB | 23400 | 22270 | −4.8% |
| 256 KiB | 91490 | 88580 | −3.2% |

An end-to-end TLS echo comparison (server CPU per op, 4 interleaved runs per
arm) was also run, but **client and server were co-located, so it is a relative
signal only and its absolute figures are not publishable** — the mistake this
project already made once and withdrew `BENCHMARKS.md` for in #205. It agreed
with the microbenchmark: 64 B −0.4% and 1 KiB +0.7% (both noise); 16 KiB −2.5%
and 256 KiB +1.0%, both with non-overlapping runs, the latter in the wrong
direction. No throughput or latency regression anywhere.

#### The 16 KiB send regression is structural

At a payload that is an exact multiple of `send_copy_slot_size` (16384 by
default), the buffered path emits **one** 16406-byte record and lets
`PoolWriter` straddle it across two slots. The unbuffered path must fit a whole
record inside one slot, so `encrypt_chunk` shrinks the chunk and emits **two**
records — 17 vs 16 at 256 KiB, 65 vs 64 at 1 MiB. The extra record costs
~245 ns, which is the entire +5.7%. This is a real, reproducible cost of the
engine at slot-multiple payloads, not measurement noise, and it is the thing to
attack if the engine is ever made default (see the design doc's open question 1
on chunk size, which now has a concrete reason to be answered).

#### What the feature actually delivers

- A small (~1–2%) send-side win at ≥64 KiB. It is **bookkeeping**, not data
  movement: fewer state transitions and no `wants_write()` loop, not a copy.
- A **4–8% recv-side win** — genuine and *unanticipated*. This design explicitly
  scoped recv out ("Recv copy count does not change", which remains true — the
  copy count is the same, the path around it is cheaper). The one real win came
  from the half of the work nobody was measuring.
- A systematic extra TLS record at slot-multiple payloads.
- The prerequisite for kTLS. `dangerous_extract_secrets` is implemented on
  `UnbufferedConnectionCommon`, so this part of the original argument survives
  intact and is now the *only* standing justification for the engine.
  *(Corrected 2026-09-06: survives, but not "intact" — see the correction under
  "Why not kTLS" above. That method is also on the buffered types, so it never
  distinguished the engines; the argument stands on
  `dangerous_into_kernel_connection`, which is unbuffered-only.)*

Reaching the originally-claimed 1 copy would require **rustls** to encrypt in
place into `outgoing_tls`. `write_fragments` does not, and that is not
reachable from ringline — it is an upstream change, if it is anything.

#### Consequences

- Copy tables corrected in `CLAUDE.md`, `docs/syscalls-and-copies.md` and the
  `## [Unreleased]` CHANGELOG entry; the design doc carries a correction block
  at the top rather than being deleted.
- The feature stays, default off, on the kTLS-prerequisite justification alone.
  It should not be made default without first fixing the slot-multiple extra
  record.
- The recv-side win is the interesting thread and was found by accident. Worth
  isolating properly before it is claimed anywhere user-facing.

## Lessons / open questions

- **A performance premise that is a claim about a dependency must be checked
  against that dependency's source before the design is written.** The whole of
  this effort rested on "`writer().write()` copies into `sendable_plaintext`",
  which is true only before the handshake completes — one `if` in
  `common_state.rs`, ~30 lines, readable in a minute. It was instead assumed
  from the shape of the API, restated in a design doc, a journal, four PRs and a
  merged CHANGELOG entry, and never checked. Nothing about the *implementation*
  review would have caught it: the engine does exactly what it was designed to
  do.
- **To test whether a copy was removed, make copies more expensive.** Running
  the payload cold (4.5× the copy cost) and seeing the arm delta not move is a
  cheaper and more direct discriminator than any timing table. An allocation
  counter inside the measured call was cheaper still, and settled it outright.
- **A test that asserts a bound while exercising the wrong regime is worse than
  no test**, because it converts an unexamined assumption into apparent
  evidence. Both amortization bugs here passed a green suite. The cheap
  countermeasure that caught both: require a regression test to *fail against
  the broken implementation* before trusting it.
- **The module split is by file size, not cleanly by engine.** `TlsConnKind`,
  `TlsConn`, `TlsTable` and `drain_tls_plaintext` remain bound to the buffered
  API (`ClientConnection`/`ServerConnection`, `reader()`/`writer()`). Only
  `TlsInfo`, `TlsRecvResult`, `PlaintextSink` and `build_pool_send` are
  genuinely engine-agnostic. Plan 2 must thread an engine dimension through the
  former set — work the original design did not account for.
- **`MAX_SINGLE_APPEND` is a cross-module coupling.** The cap floor's
  no-deadlock argument assumes no single `append` exceeds 64 KiB. `append`
  `debug_assert`s it, but plan 2's recv wiring must size its buffer accordingly.
- Open: chunk-size policy for `encrypt` (fill slots to `slot_size − overhead`,
  or a fixed 16 KiB record with a larger slot?) wants a measurement. This now
  has a concrete target: the extra TLS record emitted at payloads that are exact
  multiples of `send_copy_slot_size`, worth +5.7% at 16 KiB.
- Open: **where does the 4–8% recv-side win come from?** It was not designed for
  and is not a copy — recv copy count is identical on both engines. Isolate it
  before claiming it anywhere user-facing.
- Open: `CiphertextBuf`'s capacity default — reuse `recv_buffer_size`, or a
  dedicated setting? `MIN_CIPHERTEXT_CAP` is the floor.
