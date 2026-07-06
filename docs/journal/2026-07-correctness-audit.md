# 2026-07: Full correctness audit, perf follow-through, and v0.4.0

- **Status:** shipped (retrospective entry, reconstructed 2026-07-06 from commit history)
- **Span:** 2026-07-03 → 2026-07-06 · PRs #236–#256 · v0.4.0

## Goal

Run a full correctness-and-performance audit of the runtime and client crates
against tree state 8d407d5 (the 0.3.1 dev bump), fix everything confirmed,
land the perf findings behind the correctness fixes, and cut a coordinated
release. The audit report itself is **not checked in**; the ordered PR stack
and its detailed commit messages (#236–#244) are the in-repo record.

## What happened

**Preamble: CI had been red since June 28.** PR #235's dev bump to 0.3.1 left
the committed `Cargo.lock` stale, so every `--locked` CI job had been failing.
cbc91d4 (#236) fixed the lockfile before anything else landed.

**The correctness stack (2026-07-03, ~35 confirmed findings, PRs #237–#244,
merged in order).** One thematic batch per PR:

- 5173baa **#237** — acceptor thread exited (permanently closing the
  listener) when all worker queues were momentarily full; config validation;
  a `ChainPartsBuilder::copy` lifetime that let safe code create a
  use-after-free; a stale-CQE `in_use` guard for `handle_tls_send`.
- fa71711 **#238** — uring lifecycle: deferred close never finalized after
  ZC/recv-forward completions (fd + slot leaked forever); retry queues
  dropped entries on backoff ticks; `EINTR` from `submit_and_wait` killed the
  whole worker thread.
- ca55c0d **#239** — executor lost wakes: self-wake during a task's own poll
  was silently dropped (demonstrable permanent deadlock for
  `join(rx.recv(), tx.try_send(v))` in one task); cloned std `Waker`s never
  re-queued parked tasks; FIFO mpsc send-waiters; a `CURRENT_DRIVER` RAII
  guard + `catch_unwind` (a panic in user tick code left futures' `Drop`
  impls dereferencing a dangling stack pointer — use-after-free on unwind).
- 061997d **#240** — TLS: ciphertext serialized through the per-connection
  send queue — io_uring does not order independent SQEs; concurrent TLS sends
  could interleave records on the wire (`bad_record_mac` at the peer). Plus
  >64 KiB sends, `EAGAIN` → POLLOUT, and the new `eof_truncated()`.
- a7801a9 **#241** — mio parity: deferred close runs executor cleanup *before*
  slot release (the old order left a stale recv-sink raw pointer — a
  use-after-free write into the slot's next occupant); honest send
  completions; connect event ordering; TLS output queued, fixing the
  long-standing >16 KiB mio TLS busy-spin (test ungated on both backends).
- 7844ca6 **#242** — disk/udp/timer: disk-IO completion keys sequence-tagged
  (raw slab indices collided across subsystems — results delivered to the
  wrong future; a graveyard buffer freed while the kernel was still writing
  into it); NVMe positive status words are errors, not `Ok(0x281)`;
  **(breaking)** `nvme_read`/`nvme_write` became `unsafe fn` (the safe
  wrappers let safe code corrupt arbitrary memory); GRO splitting;
  `sleep`/`timeout` panic on pool exhaustion as documented.
- 8f28389 **#243** — clients: `flushed_count` desync on direct sends could
  permanently misattribute every subsequent response (silent wrong data);
  close on protocol errors; cluster refresh survives dead nodes; TTFB fixes.
- a5ad2db **#244** — lifecycle: `shutdown(fd, SHUT_RD)` wakes a blocked
  `accept4` at shutdown (prompt relaunches hit `EADDRINUSE`);
  `SpawnFuture`/`WaitFuture` deregister on drop (abandoned spawns leaked an
  open pidfd); NOFILE math; doc contracts.

**Perf follow-ups (2026-07-03 → 07-05, after the correctness stack).**
022f1fa #245 event-driven ENOBUFS re-arm + pre-block replenish (killed a 100%
CPU spin when the provided ring emptied); c2113bf #246 O(1) `with_bytes`
put-back via refcounted remainders (pipelined parse microbenches −43% to −92%
on hv01 — the old path was O(B²) over a pipelined batch); 036ba7c #249
encode-buffer reuse + itoa in sharded/cluster paths; fd16563 #250 UDP queue
clamp + SMT-aware pinning; 89d3f0a #251 guard batch cap 4→8 + folding small
chained guard sends; 9802baf #252 mio dirty-lists + timer heap replacing
per-iteration scans; f34aaae #253 MSG_WAITALL on all 16 stream-send SQE sites
(kernel ≥5.19 retries short sends in-kernel) **and**
`docs/send-completion-design.md` — the durable design artifact of this arc:
why `IOSQE_CQE_SKIP_SUCCESS` is unsound for pool-backed sends (completions
drive slot release; skip silences short writes), plus zero-copy RX scoping;
9be1809 #254 TLS encrypts directly into send-pool slots (3 copies → 2).
(Housekeeping alongside: cee2a67 #247 bench spec, 5b57016 #248 gitlink fix.)

**One more real find: dfc7421 #255.** NVMe passthrough had been *entirely*
non-functional — `NVME_URING_CMD_IO` was defined as `0` instead of the kernel
ioctl encoding `_IOWR('N', 0x80, struct nvme_uring_cmd)` = `0xC048_4E80`, so
every command returned `ENOTTY`. Never caught: no test had ever run the path
against a real device. Verified on hardware (hv01, `/dev/ng0n1`, kernel 6.12);
`examples/nvme_smoke.rs` is the read-only smoke test that found it.

**Release: c1124d3 #256, v0.4.0 (2026-07-06).** Coordinated breaking release
per CHANGELOG.md: ringline 0.3.1→0.4.0 — the major bump driven by `unsafe fn`
`nvme_read`/`nvme_write` and `sleep`/`timeout` panic-on-exhaustion —
redis/memcache →0.6.0, the six other client crates →0.5.0.

## Outcome

- ~35 confirmed findings fixed in nine ordered PRs; severity classes named in
  the commit messages themselves include use-after-free (#237, #239, #241,
  #242), a safe-API soundness hole (#242), and a demonstrable lost-wake
  deadlock (#239).
- Two perf phases with measured wins (criterion on hv01, no end-to-end
  regressions per #245/#246); NVMe passthrough hardware-verified for the
  first time; v0.4.0 shipped across all nine publishable crates.

## Lessons / open questions

- The recurring failure modes (SQE memory lifetime, no ordering across
  independent SQEs, stale CQEs on slot reuse, CQE-skip unsoundness, short
  sends, event-driven ENOBUFS re-arm, EINTR-as-backpressure) are encoded as
  the **Domain Invariants** section of `CLAUDE.md` — check any
  send/recv/lifecycle change against that list.
- `docs/send-completion-design.md` is required reading before send-path
  changes; it also scopes the one remaining recv copy (zero-copy RX, 6.15+).
- A green build is a precondition, not a nicety: `--locked` CI was red for
  days over a one-line lockfile omission — and #255 shows a code path can be
  100% broken while its unit tests stay green, if nothing runs it on hardware.
- The audit report lives outside the repo; the commit messages of #237–#244
  are the durable substitute.
