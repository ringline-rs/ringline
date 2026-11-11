# 2026-11: Audit of the send and receive paradigms

- **Status:** open — 28 confirmed findings (F1 to F28), 10 plausible (PL1 to PL10), 23 documentation findings (D1 to D23) and 18 design limitations put to the owner as questions (L1 to L18); the owner chose F1 then F2, fixed in #849 (merged) and #850 (open), and chose to bound the TLS handshake for L18, in #868 (merged); F27, F28, L18 and PL10 were found while reviewing those fixes; PL10 was then confirmed and fixed in #886 (merged); the invariant list was confirmed by three agents, not agreed line by line with the owner
- **Span:** 2026-11-09 to 2026-11-10 · tree 6851de26 (`main`, 0.7.0-alpha.68) · PRs: #849 (F1), #850 (F2), #868 (L18), #886 (PL10)

## Goal

Audit the public ways to send and receive in the `ringline` crate, taken as a
set, against the contract each one states, on both backends. No diff was
under review. Five questions: correctness, ordering and stale completions,
failure and teardown, resource bounds, and whether the docs state what the
code does. Performance was not a question.

Method (`cs:audit`):

1. Scope and invariants written first. The owner agreed the scope (the
   entry points as a set with each one's stated contract; UDP and Unix
   domain sockets included). The owner did not review the invariant list
   line by line: they accepted the draft on assumption and asked for
   subagents to confirm it. Three fresh agents checked the draft against the
   docs, rustdoc and test names, corrected it, and added the stated
   properties the draft had missed. The list below is their corrected list.
   The long lists they produced (RM, SM, UM, UX, RL, the Q1 and Q2 tables)
   are in [the lists file](2026-11-send-recv-paradigms-audit-lists.md).
2. A state map of the receive and send paths on both backends.
3. Eleven fresh read-only reviewer agents in parallel, one per concern:
   io_uring receive mechanism; readers and the accumulator; TLS receive, the
   mio receive path and `ConnStream`; forwards; send contracts per entry
   point; the 45 commits since the send-path audit against that audit's
   invariants; send and receive together (half-close, close, two tasks);
   UDP; Unix domain sockets; docs against code for receive; docs against
   code for send. No reviewer built or ran ringline. The Unix reviewer ran
   five python socket probes on the audit host for kernel behaviour; where
   any other reviewer's claim depends on kernel behaviour, the reviewer
   recalled it.
4. The auditor then built both backends on one host and wrote a
   reproduction for each finding that claims a failure and can be run: 10
   integration test files (44 tests) and 17 unit tests added to the lib
   test modules, none checked in. Host: Linux 7.2.6 arm64, rustc 1.98.1;
   io_uring is the default build there and mio is `--features force-mio`.
   This is the first audit of these paths in which io_uring findings were
   run; the two 2026-11-07 audits ran on macOS, where io_uring cannot be
   built.
5. Findings that are statements about documentation, or whose trigger the
   auditor could not produce, went to three more fresh agents as second
   readers, each told to check the quoted text and the cited path against
   the tree and to try to refute the finding. A second reader's agreement is
   a second reading, not a run, and the findings say which they rest on.

Unless a finding says otherwise, a reproduction was run once per backend.
The tests are deterministic in structure (fixed peers, fixed sleeps), and
each one that shows a failure has a control that passes; where a result
could depend on timing it was run five times and the finding says so.

## Scope

The `ringline` crate's public send and receive entry points on both backends
(io_uring, and mio with `--features force-mio`):

- TCP and Unix stream connections: `Connection`, `RecvHalf`, `SendHalf`,
  `ConnStream` (`ringline/src/runtime/io.rs`, `ringline/src/runtime/stream.rs`).
  - Receive: `with_data`, `with_data_result`, `with_bytes`, `try_with_data`,
    `recv_ready`, `forward_to_conn`, `ConnStream::poll_read`/`poll_fill_buf`,
    `peer_closed`, `eof_truncated`, `recv_arrival`, `is_recv_direct`.
  - Send: `send`, `send_nowait`, `send_parts` (`build`, `submit_batch`,
    `submit_batch_await`), `send_backpressured`, `send_chain`,
    `send_chain_nowait`, `forward_recv_buf`, `ConnStream::poll_write`/
    `poll_flush`/`poll_close`, `shutdown_write`, and `close` where a reader
    or sender observes it.
- UDP: `UdpSocket`, `UdpRecvHalf`, `UdpSendHalf`: `recv_from`,
  `with_datagram`, `recv_batch`, `recv_batch_timed`, `send_to`,
  `send_to_gso`, `send_ready`.

Receive was audited in full: mechanism and contracts. It had not been
audited since direct receive (#684), half-close (#809) and `defer_recv_arm`
(#814) landed. Send internals were audited on 2026-11-07 at `6ea67e6c`
([send-path audit](2026-11-send-path-audit.md)); here the send side is the
per-entry-point contracts, and the 45 commits since `6ea67e6c` checked
against that record's invariants. The close path was audited the same day
([close audit](2026-11-connection-close-audit.md)).

Out of scope: the close path except where a read or send observes it, the
acceptor, disk I/O, NVMe, QUIC, the protocol client crates' own buffering.

File references below are at `6851de26`. `uring/` and `mio/` mean
`ringline/src/backend/uring/` and `ringline/src/backend/mio/`; `io.rs` is
`ringline/src/runtime/io.rs`; other bare names are under `ringline/src/`.

## Invariants

Source tags: D design doc or CLAUDE.md, C rustdoc or code comment, T a test
asserts it, I inferred by the auditor. The file and line of each source is in
the lists file. RL numbers refer to the recorded limitations there: design
limitations the owner had already accepted before this audit. A reviewer who
met one reported it as recorded, not as a finding, unless the code did
something worse than the record says.

Not agreed line by line with the owner; see Method step 1.

### Receive mechanism, io_uring

- R1a (D). A connection has at most one `RecvDirect` in flight.
- R1b (D). A plaintext receive is armed only from `park_recv`, at once or
  (with `defer_recv_arm`) after the worker's next wait, never at connect or
  at a completion.
- R1c (D). A TLS receive is armed from `park_recv`, and re-armed at each
  completion during the handshake and after `hangup_seen` until the end is
  read.
- R1d (D, C). No receive is armed when `recv_finished()`, while a park is
  pending, or while `forward_recv_over_cap` holds the connection.
- R2 (D). While a plaintext `RecvDirect` is in flight its buffer is owned by
  its `Driver::direct_recvs` entry, the accumulator is empty, and the entry
  is removed only by `handle_recv_direct`. Close and park do not free it. At
  worker exit `run_shutdown` waits for every entry to empty, up to the
  shutdown bound (the bound running out is recorded limitation RL1).
- R3 (D). A `RecvDirect` CQE whose entry generation differs from the slot's
  changes nothing on the slot's occupant; its buffer goes to `recycle_direct`
  (plaintext) or is dropped (TLS) and `STALE` is counted. One for the same
  generation with lifecycle not `Open` clears only that connection's armed
  and held bookkeeping. A `HangupPoll` or `HangupPeek` CQE whose payload
  generation differs changes nothing.
- R4 (I). Bytes reach readers in arrival order, each exactly once, unless
  discarded by `close()` with unread bytes, by the cap, or handed to a
  forward's sink. This holds across detach/attach, `with_bytes` take and
  put-back, `keep_spent` reuse, pool borrow, compaction, the
  `forward_recv_buf` whole-accumulator take, `prepend` after a failed forward
  submit, the mio/TLS `append` path with the frozen-remainder merge, TLS
  plaintext stashed during the handshake, bytes past a forward's `len`, and a
  park hand-off.
- R5a (D, io_uring plaintext). Each receive length is at most
  `recv_accumulator_max` minus the bytes buffered.
- R5b (D, both backends, plaintext and TLS). When buffered bytes would pass
  the cap the connection closes, `with_data_result` returns `QuotaExceeded`
  after the buffered bytes, and `with_data` returns `0`.
- R6 (D). (a) A FIN or close_notify sets `ReadHalf::Eof`, wakes the reader and
  requests no close. (b) A reset or socket error sets `ReadHalf::Error`,
  reports to the reader and closes. (c) Buffered bytes are delivered before
  the `0` or the error. (d) `with_data_result` reports the error once, then
  `Ok(0)`; `with_data` returns `0` in both cases.
- R7a (D, io_uring). Once the hangup poll is armed, a FIN, reset or socket
  error is recorded on the read half without a read parking, after any
  buffered bytes are read.
- R7b (D). Readers receive every byte that arrived before the end before `0`
  or the error.
- R7c (I, from D parts). A parked reader has a receive in flight, a recorded
  end, or one of the documented holds, each with a wake: a deferred arm
  queued, a pending park (`rearm_direct_after_park`), or the
  `forward_hold_cap` hold (`resume_forward_recvs`). Exception: a reader
  displaced by another task's `recv_ready` (RL3).
- R8 (D). A hangup poll that cannot be pushed is retried from
  `hangup_poll_retries`, and a peek from `hangup_rechecks`. A receive that
  cannot be pushed closes the connection, wakes the reader, and
  `with_data_result` returns the error. All three count
  `ring::RECV_ARM_FAILURES`.
- R9 (D). `DirectPool` holds at most `recv_direct_pool_max` free bytes and
  never keeps a buffer larger than that. A borrowed buffer goes back through
  `DirectPool::put` when its connection has nothing buffered and no `Bytes`
  from it is alive, at `release` on close, or through `recycle_direct` from a
  stale completion.

### Receive, TLS and mio

- R10a (D). The memory a TLS receive writes into is not freed or moved until
  its CQE, including at close.
- R10b (C). A record the engine cannot process closes the connection and
  `with_data_result` returns `InvalidData`.
- R10c (C). close_notify gives `Ok(0)` with `eof_truncated() == false`.
- R10d (C). A FIN without close_notify gives `Ok(0)` with
  `eof_truncated() == true`.
- R10e (C). A TLS engine with no room for ciphertext closes with
  `QuotaExceeded`.
- R11a (D). mio `handle_readable` reads until `WouldBlock` or `0`, except
  that on Linux TCP, for an event that reports neither a closed read side nor
  urgent data, a read that leaves the buffer unfilled ends the drain.
- R11b (C). An append past `recv_accumulator_max` closes with
  `QuotaExceeded`.
- R11c (C). A `forward_to_conn` source stops reading while the sink has
  `forward_hold_cap` sends queued and resumes when the sink drains.
- R11d (D). Once `recv_finished()`, a readable event reads nothing.

### Reader contracts

- P1a (C). Each parser call sees every byte buffered for the connection.
- P1b (C). `Consumed(n)` with `0 < n <= len` removes exactly `n` bytes. (No
  source says what `n > len` does; report what the code does.)
- P1c (C). `NeedMore`, `Consumed(0)` on non-empty data and `NeedAtLeast` park
  when the read half is open.
- P1d (C). Once the read half has finished, the parser is called with what is
  buffered, possibly nothing; the call resolves with what the parser
  consumed, `0` if nothing, and never parks. (The `with_bytes` rustdoc has no
  end-of-stream text.)
- P2 (I). For one byte stream and a parser whose output does not depend on
  chunking, the concatenation of consumed bytes and the terminal result (`0`
  or the error kind) are equal across `with_data` and `with_bytes`, both
  backends, plaintext and TLS.
- P3 (D). `try_with_data` never parks or arms. It returns `None` while a
  receive holds the buffer and on a stale handle.
- P4 (C). `recv_ready` consumes nothing and resolves when bytes are buffered
  (including `recv_direct_held`) or the read half has finished; a stale
  future resolves.
- P5 (C, I for plain `with_data`). Dropping a pending `with_data`,
  `with_data_result`, `with_bytes`, `recv_ready` or `forward_to_conn` future
  removes no bytes from the connection, except a forward chunk already
  submitted, and the next reader sees them. On io_uring the dropped read's
  receive stays in flight and `try_with_data` returns `None` until it
  completes.
- P6 (code only; question for the owner). `ConnStream::poll_read` and
  `poll_fill_buf` deliver buffered bytes, then `Ok(0)` once `recv_finished()`
  or on a stale handle; a read error is reported as `Ok(0)`. No doc states
  the last clause.
- P7 (C). `forward_to_conn`: (a) forwards `min(len, bytes before FIN)` in
  order, result `< len` means FIN first; (b) `EBUSY` if a forward is running
  on the source, `EPIPE` if source or sink is stale, `EPROTOTYPE` for a TLS
  sink, with nothing installed; (c) the sink's generation is checked before
  every write, `EPIPE` mid-forward; (d) io_uring: a drop lets a submitted
  chunk go out and leaves the rest buffered, a failed submit resolves the
  forward with the error and leaves the chunk buffered; mio: queued bytes
  stay queued and no further bytes are taken; (e) bytes past `len` stay for
  the next reader. (No source says what a forward returns when the source
  read fails.)
- P8 (C). `recv_arrival` is when the bytes consumed by the most recent reader
  call arrived. `with_data`, `with_data_result`, `with_bytes` and
  `try_with_data` set it; forwards and `ConnStream` do not. `None` until a
  reader call has consumed a byte, after a call that consumed none or
  resolved at end of stream, and once the connection is torn down.
- RM1–RM71. Further stated properties, listed with sources in
  [the lists file](2026-11-send-recv-paradigms-audit-lists.md), grouped: reader callbacks and
  re-entrancy; `NeedAtLeast`; after close, abort or on a stale handle;
  arming limits; hangup detection; metrics; accumulator and buffers; arrival
  log; `ConnStream`; backend and TLS differences; forward and wake.

### Send contracts

- Q1 (D). The S, O, C, T, W and F invariants of
  `docs/journal/2026-11-send-path-audit.md`, in the wording of the Q1 table
  in the lists file, and that record's close_notify row, hold at `6851de26`.
- Q2 (C). Each claim in the Q2 contract table (the lists file) holds on both backends, or on the backend the row names.
- Q3a (D). Bytes of `send`, `send_nowait`, the three `send_parts` submits,
  `forward_recv_buf` and a TLS `send_chain` on one connection reach the wire
  in call order. One call's bytes are contiguous; TLS records neither
  interleave nor gap.
- Q3b (D). A `send_backpressured` takes its place at the poll that submits
  it; a plain send made while it waits goes ahead of it.
- Q3c (D, C). A plaintext `send_chain` whose `finish` finds a send queued, in
  flight or parked, or another chain active, returns `WouldBlock` and submits
  nothing; a send made while a chain is active goes out after it.
- Q3d (D, io_uring). `forward_to_conn` chunks are ordered with other sends on
  the sink. (The mio doc has no ordering sentence.)
- Q3e (D). The FIN of `shutdown_write` follows every send queued or in
  flight, and every part of a chain active, at the call; a send made after
  the call has no promised order against the FIN.
- Q3f (D). Between two tasks the order is the order their calls ran.
- Q4 (D, PRINCIPLES.md:83). Every observable difference between io_uring and
  mio in a send or receive entry point (availability, error kinds, limits,
  order, what a drop does, copy count) is stated in that entry point's
  rustdoc or a document it links.
- SM1–SM20. Further stated properties, in the lists file.

### Across send and receive

- A1a (D, T). A send can be submitted and can complete while a read on the
  same connection is parked, and a read can park and resolve while a send
  waits for room or capacity, with the halves in one task or in two tasks on
  the worker.
- A1b (C, D). A send completion wakes the task that last polled that send's
  future. A receive completion, EOF or read error wakes the one task that
  last parked a read or `recv_ready` on the connection. No wake goes to the
  other task or is lost (except RL3).
- A2a (D, T). After the peer's FIN or close_notify: `is_alive()` stays true,
  `peer_closed()` is true, sends go to the wire; a peer that only shut its
  write side reads the reply; to a fully closed peer the next send reports
  the reset, the connection aborts with that error, and a reader on
  `with_data_result` sees it.
- A2b (D). After `shutdown_write`: reads continue; a waiting or new
  `send_backpressured` resolves `BrokenPipe`; `send`, `send_nowait` and
  `send_parts` are accepted, and after an accepted Shutdown fail `EPIPE`,
  which closes the connection and reports to a reader on `with_data_result`,
  on both backends.
- A2c (D). After `close()`: queued sends drain, then close_notify on TLS
  unless a write shutdown preceded, then the FIN; the calling task runs to
  its next `.await`; the connection's task parked elsewhere is dropped
  unpolled; a read polled before the close completes resolves `0` without
  parking; a `SendFuture` held by another task resolves with its own result;
  a waiting `send_backpressured` resolves `ConnectionAborted` or
  `NotConnected`; a new send returns `NotConnected` on io_uring once the
  Close is submitted (or on TLS once close_notify is queued), and on mio is
  queued and flushed or discarded with the connection.
- A2d (D, C). Stale handle: `send` returns `NotConnected`; a read resolves
  `Ok(0)`; `close` does nothing; a pending `SendFuture` resolves
  `ConnectionAborted`.
- A2e (D, T). Runtime abort on a write error: `with_data_result` reports the
  write's error once, then `Ok(0)`.
- A3 (D). One check per document or entry point: the CLAUDE.md copy tables
  and Domain Invariants, `docs/syscalls-and-copies.md`,
  `recv-direct-design.md`, `half-close-design.md`,
  `recv-arrival-times-design.md`, `connection-state-model-design.md`,
  `send-while-receiving-design.md`, `send-completion-design.md`,
  `write-half-design.md`, `half-closed-send-wait-design.md`,
  `send-backpressured-design.md`, `send-capacity-fifo-design.md`,
  `send-completion-slots-design.md`, `copied-send-reservation-design.md`,
  `connection-handle-ownership-design.md`, the `stream.rs` module doc, and
  the rustdoc on the entry points and on `WriteHalf`, `SendFuture`,
  `BackpressuredSendFuture`, `AsyncSendBuilder`, `SendChainBuilder`,
  `ChainPartsBuilder`, `SendGuard` state what the code does.

### UDP

- U1a (D). When a UDP multishot (`RecvMsgUdp` or `RecvUdp`) ends with
  `-ENOBUFS`, the handler submits nothing and records the socket in
  `udp_awaiting_buffers`; `return_udp_buffers` re-arms it only when that
  socket's ring has a free buffer.
- U1b (C). A re-arm whose submit fails leaves the socket in
  `udp_awaiting_buffers`, and `may_block` does not block while
  `udp_rearm_due()` is true.
- U1c (C). `-ECANCELED` ends the multishot with no re-arm.
- U1d (code). Every other end of the multishot re-arms at once. (No bound on
  repeats is stated.)
- U2a (C). Each UDP recv CQE that selected a buffer calls `on_handout` once,
  and its bid reaches `udp_pending_replenish` exactly once: at once on a
  parse failure, a truncated name or payload, or a full queue; otherwise when
  the consumer finishes the queue entry.
- U2b (C, T). A GRO entry's bid is returned once, after its last segment is
  consumed or a panicking callback drops the entry.
- U2c (C). No receive future stores a bid between polls.
- U2d (D). A bid of a datagram left in the queue is held until worker exit.
- U3a (C, T; order is I). A queued datagram is handed to the consumer at most
  once, with the source address the kernel reported (unconnected) or the
  connected peer (connected), in arrival order per socket.
- U3b (D). A datagram is dropped only by a full queue (counted), a truncated
  name or payload on io_uring (not counted), or the kernel receive buffer
  (not counted).
- U3c (D). Under GRO, `recv_from` and `with_datagram` return one segment per
  call, batch callbacks run once per segment, and every segment is
  `segment_size` bytes except the last.
- U3d (C, T). `send_to_gso(peer, data, seg)` puts `data` on the wire split at
  every `seg` boundary with a shorter final datagram.
- U4a (D). Each accepted `send_to` or `send_to_gso` on io_uring holds one
  per-socket `UdpSendSlot` and one `SendCopyPool` slot from submit to its
  CQE, and the send handler releases each exactly once whatever the result.
- U4b (C). Every `Err` return of `udp_send_to` leaves `send_freelist` and the
  copy pool as they were.
- U4c (C, T). Each send CQE that returns a send slot wakes the socket's one
  `send_ready` waiter.
- UM1–UM43. Further stated properties, in the lists file.

### Unix domain stream sockets

- UX1–UX19, in the lists file. In short: UX1–UX3 a waiting
  send against a Unix peer's `SHUT_WR`, full shutdown and `SHUT_RD`; UX4
  zero-copy guarded sends deliver their bytes (I, unverified); UX5 no
  `TCP_NODELAY`; UX6 reset semantics (I); UX7 direct receive; UX8 hangup poll
  and peek (I); UX9 mio reads to `WouldBlock`; UX10 `PeerAddr::Unix`; UX11
  acceptor thread; UX12 TLS (none on `connect_unix`; terminated on a
  `bind_unix` listener when process-wide TLS is set); UX13 connect timeout;
  UX14 `connect_unix` fails on mio; UX15 park; UX16 `bound_addr` is `None`;
  UX17 unlink before bind; UX18 full backlog is `EAGAIN`; UX19 path
  truncation.
- UXdoc (D, PRINCIPLES.md:83). Each of UX3 (the up-to-1 s delay), UX4, UX5,
  UX12 (accepted side), UX14 and UX19 is stated on the doc comment of the
  public item it affects.

## Verdict per invariant

"holds" is a reviewer's reading unless a finding number is given; the
reviewers' confidence levels and the lines they read are in the working
reports (see Reproductions). A finding number in a cell means the auditor
ran it or a second reader checked it, as that finding says. "n/a" means the
invariant is about the other backend.

| Invariant | io_uring | mio |
|---|---|---|
| R1a, R1b, R1d | holds | n/a |
| R1c | holds (TLS arm bodies not read) | n/a |
| R2 | holds; a comment misstates the drop order (F26) | n/a |
| R3 | holds as worded; the same-generation `Closing` branch is the cause of F3 | n/a |
| R4 | **broken** (F3 loses bytes; F2 frees them under a live slice) | **broken** (F13) |
| R5a | holds | n/a |
| R5b | holds | holds for the stated sequence; the cap is reached with no reader (L5) |
| R6a | **broken** before the TLS handshake completes (F1); holds once established | same (F1) |
| R6b | holds | holds |
| R6c | **broken** (F3) | not held for a task parked on something other than a read (L4) |
| R6d | holds | **broken** (F7) |
| R7a | holds for the triggers shown; one return leaves nothing armed (PL1) | n/a |
| R7b | **broken** (F3) | see L4 |
| R7c | **broken** (F15) | **broken** for the forward hold (F13) |
| R8 | holds | n/a |
| R9 | **broken** (F16) | n/a |
| R10a, R10b, R10c | holds | holds |
| R10d | **broken** before the handshake completes (F1) | same (F1) |
| R10e | holds | see PL8 |
| R11a, R11b, R11d | n/a | holds |
| R11c | n/a | **broken** (F12) |
| P1a | holds; a reader that finds the buffer detached parks without calling the parser (F20) | holds |
| P1b | holds for `0 < n <= len`; `n > len` is in D12 | same |
| P1c, P1d | **broken** for `with_bytes` in one sequence (F21) | same (F21) |
| P2 | **broken** (F21) | **broken** (F21; L5) |
| P3 | holds | holds |
| P4 | holds as written; F20 | holds as written; L3 |
| P5 | holds; F20 is the io_uring clause's consequence | **broken** for a dropped forward (F13) |
| P6 | holds as written; whether it should is L1 | same |
| P7a | holds for a FIN; a failed read gives the same result (L2) | holds for a FIN; on a reset the task is dropped (L2, L4) |
| P7b, P7e | holds | holds |
| P7c | generation check holds; the error kind is D17 | holds |
| P7d | holds | **broken** (F13) |
| P8 | holds | holds |
| Q1 | S1–S3, O1–O5, C1–C4, W1–W3, F3, F4 and the close_notify row hold; F1 and F2 (that record's numbering) **broken** by this record's F14; S4, S5, T3 not checked; T1 and T2 hold for `send`, `send_bounded` and `SendBuilder::submit` only | F1 (that record's) **broken** by this record's F7; the rest as io_uring where it applies |
| Q2 | **broken** for the rows in F5, F22 and D4 | **broken** for the rows in F5, F22 and D4 |
| Q3a–Q3f | hold | hold (Q3d has no mio statement) |
| Q4 | **broken** (F8, F9, F22, F23 and the documentation group) | same |
| A1a, A1b | hold | hold |
| A2a | holds | **broken** in "reported once" (F7); depends on SIGPIPE disposition (F6) |
| A2b | a `send` after `shutdown_write` reached the peer in 5 of 5 runs (L6) | fails `EPIPE` as stated, and raises SIGPIPE (F6) |
| A2c | holds | holds except after a flush error (F7) |
| A2d | holds | holds |
| A2e | holds | **broken** (F7) |
| A3 | **broken** (documentation findings D1–D23) | same |
| U1a, U1b, U1c | hold | n/a |
| U1d | holds; no bound on repeats (L9) | n/a |
| U2a | holds for `RecvUdp`; `RecvMsgUdp` see PL2 | holds |
| U2b, U2c, U2d | hold | hold |
| U3a | **broken** (F11; F9 for connected sockets) | **broken** (F11) |
| U3b | **broken** for connected sockets (F9) | holds |
| U3c | **broken** (F11; F9 for connected sockets) | **broken** (F11) |
| U3d | holds | holds on success; error path differs (D20) |
| U4a | holds while the worker runs; worker exit see PL3 | n/a |
| U4b | holds | holds |
| U4c | holds as worded; not sufficient for the documented loop (F10) | holds |
| UX1 | holds | n/a |
| UX2, UX3 | hold | the mio counterpart does not hold (F19) |
| UX4 | **broken** (F8) | holds |
| UX5–UX16, UX18 | hold | hold (UX14: `connect_unix` fails on mio, as recorded) |
| UX17, UX19 | **broken** (F17, F18) | **broken** (F17, F18) |
| UXdoc | **broken** (D23) | **broken** (D23) |

Long lists:

- RM1–RM71: no item found broken as worded except RM62's third clause on
  mio (PL7). Not checked by any reviewer: RM4, RM5, RM15, RM36, RM37, RM38,
  RM55, RM56, RM59, RM60; RM51 only for the push path; RM31 only against
  the SQE definitions, not the kernel.
- SM1–SM20: SM1 broken for a guard that points into its own storage (F4);
  SM5 broken across workers (F5); SM8 broken on mio (F7); SM20 extends to
  every `SendHalf` entry point (F24). SM10 not checked on io_uring; SM11 not
  checked.
- UM1–UM43: UM11, UM17 and UM19 broken for connected sockets on io_uring
  (F9); UM14 broken after a segment-wise read (F11). Not checked: UM7, UM10,
  UM27, UM40, UM41, UM42; UM28 and UM43 only at one site each. UM30 holds on
  io_uring only (D20).

## Findings

Status: **confirmed** = a test or measurement at `6851de26` shows it, with
the backend and the number of runs given, or (where marked "by reading") the
quoted text is the whole finding; **plausible** = the code path is real and
the trigger was not produced. F1 and PL10 are fixed; F2's fix is open;
every other finding is open. Findings are ordered by
consequence as the auditor judges it; the owner ranks.

### F1 — A peer FIN before the TLS handshake completes leaves the connection with no task; an outbound `connect().tls()` never resolves (R6a, R10d). Confirmed (run, both backends).

`uring/event_loop.rs:1350–1365` and `mio/event_loop.rs:861–878` handle a
FIN on a TLS connection by calling `note_eof` and `wake_recv`. Neither
checks `established`. Before #809 (`90d81de6`, 2026-11-09) both arms called
`close_connection`; #809 removed that so an established connection survives
a half-close, and the not-yet-established case went with it. `git tag
--contains 90d81de6` is empty, so no release has this.

- Inbound: with `max_connections(1)`, a plain TCP client connects and
  closes; 500 ms later a TLS client's echo fails with `ConnectionReset`
  because the slot is still held. Control: an established TLS connection closed with close_notify after
  one echo frees the slot and the second echo passes. Both
  backends, one run each (`audit_tls_fin_before_handshake.rs`).
- Outbound: `connect(addr).tls("localhost")` to a peer that accepts and
  closes was unresolved after 3 s on both backends, one run each
  (`audit_tls_connect.rs`).

Consequence: any peer that connects to a TLS listener and closes without
sending a ClientHello (a TCP health check, a port scan) holds a connection
slot until the process exits. No `on_accept` task exists for it, so no
handler timeout can release it.

Proposed fix: at both arms, when the connection is not established, treat
the FIN as a failed handshake: wake the connect waiter with an error and
close. io_uring's error arm beside the FIN arm does both
(`uring/event_loop.rs:1375–1389`). mio's read-error arm beside the FIN arm
(`mio/event_loop.rs:887–896`) calls `fail_recv` and `close_connection` and
has no `wake_connect`; the mio arm that wakes the connect waiter with an
error is the TLS feed-error arm (`:984–997`).

Fixed in #849, merged as f73022d0. At both FIN arms, a connection that is not
established wakes the connect waiter with `UnexpectedEof` and is closed.
Tests: two unit tests per backend and `ringline/tests/tls_handshake_fin.rs`,
red without the check on both backends, green with it and with both TLS
engines. Reviewed by a fresh agent twice (first verdict "fix first", for
two false comments; second "merge"). The review settled the `Closed`
question left open under "What the audit did not cover": ringline-tls
0.1.2 records a close_notify only once `may_receive_application_data` is
set, so no close_notify produces `TlsRecvResult::Closed` before the
handshake completes. It also measured L18.

### F2 — `forward_recv_buf` frees the bytes its caller's slice points to (io_uring; R4, RM7). Confirmed (unit test and public-API run).

`io.rs:1244–1258`: on io_uring, when the accumulator is a frozen remainder,
the forwarded slice is the whole accumulator and no close is pending
(`io.rs:1227–1235`), `forward_recv_buf` takes it into an `AccumulatorGuard` and sends it. Below
`send_zc_threshold` the send copies and the guard is dropped before
`forward_recv_buf` returns, while the `with_data` closure that called it
still holds `data: &[u8]` into that memory.

- Unit test with a `Bytes::from_owner` drop flag: a 99-byte forward frees
  the owner before the call returns; a 5000-byte forward (zero-copy path,
  control) does not.
- Public API only: `with_bytes` consumes 1 of 100 bytes, then
  `with_data(|d| tx.forward_recv_buf(d))`, with a test allocator that fills
  freed blocks with `0xEE`. After `forward_recv_buf` returned `Ok`, the
  closure's slice read `0xEE`. Control (first read through `with_data`, so
  the accumulator is not a frozen remainder): unchanged. mio: unchanged in
  both. One run each.

Consequence: safe code reads freed memory. The sequence needs a `with_bytes`
read that leaves a remainder, followed by a `forward_recv_buf` of fewer than
4096 bytes from a `with_data` closure.

Proposed fix: keep the taken remainder alive until the reader callback
returns. The reviewer's suggestion is a per-connection driver field next to
`forward_zc_consumed`, cleared where `take_forward_zc_consumed` runs and in
`close_connection`.

Fixed in #850 (open).
The driver holds the detached bytes in `forward_zc_held` until a delivery
path reads a non-zero forwarded count after the closure returns, or until
`handle_close` releases the slot. It is not cleared in `close_connection`,
as proposed above, because a closure can call `close()` after the forward
and still hold the slice; a test checks that. A TLS forward had the same
defect at any size, because encryption consumes the guard (unit test, red
without the fix). Tests: four unit tests and
`ringline/tests/forward_recv_buf_slice.rs`. Reviewed by a fresh agent
twice (verdict merge both times); its test and wording findings were
applied, and F27 and F28 are its pre-existing findings.

### F3 — A failed send discards received bytes the reader has not seen (io_uring; R6c, R7b, R4). Confirmed (unit tests; one live run with a control).

`handle_recv_direct` treats a receive CQE as live only when the generation
matches and the lifecycle is `Open` (`uring/event_loop.rs:1161–1163`), and
recycles the buffer otherwise (`:1191–1200`). A failed send calls
`abort_connection` (`:3128–3139`), which moves the connection to `Closing`
in the same generation. A receive that completes after that, with bytes,
is recycled.

- Unit tests: receive CQE handled first (control), the closure sees
  `[4, 8]`. Failed-send CQE first, receive result 4: the closure sees
  `[4, 0]` and the read returns `Err(BrokenPipe)`. Failed-send first,
  receive `-ECANCELED` with 4 bytes held: `[4, 0]`.
- Live: the peer sends a 4-byte message and resets while the handler
  sleeps. With no send before the read: "closure saw [4]; read Ok(4)".
  With `send_nowait(b"reply")` before the read: "send Ok(()); closure saw
  [0]; read Err(ConnectionReset)". One run each.

Consequence: a handler that writes before it reads (any pipelined or
proxying handler) loses the peer's last message when the peer has reset.
`with_data_result`'s rustdoc says "Buffered bytes are always delivered
before the error is surfaced" (`io.rs:2800`).

Proposed fix: discard only when the generation differs. For the same
generation in `Closing`, attach the bytes and wake the reader without
re-arming. This needs a check that the accumulator of a `Closing`
connection is not released before the reader's next poll.

### F4 — `SendGuard` is a safe trait, and the zero-copy path sends from a pointer taken before the guard is moved (io_uring; SM1). Confirmed (run).

`SendGuard` (`guard.rs:5–14`) is a safe trait. `build_with_guards` reads
`g.as_ptr_len()` (`handler.rs:3983`) and then moves the guard into the slab
(`handler.rs:4003–4004`); `GuardBox` stores the guard inline
(`guard.rs:26`). A guard whose bytes live inside the guard value therefore
hands the kernel the address of the value's old location.

`audit_guard_send.rs`: a guard holding a 48-byte array, total length above
`send_zc_threshold`, io_uring plaintext. The peer received 48 bytes of
`0xCD`, which the test had written over the dead stack frame; the guard's
address at `as_ptr_len` differed from its address at drop. Controls: the
same guard below the threshold, and on mio, pass. One run.

Not run, by reading only: the length is read twice on one path, and a guard
returning a null pointer with length 0 reaches `from_raw_parts`.

Consequence: a safe implementation of a safe trait sends memory it does not
own. Guards that point at heap memory (`Bytes`, `Vec`, `Arc<[u8]>`) are not
affected.

Proposed fix: this is a question (L10). Either declare `pub unsafe trait
SendGuard` with the obligation written down (the pointer is non-null, valid
for `len` until drop, the same on every call, unchanged by a move), or read
the pointer after the guard is in its final location.

### F5 — `SendFuture` is `Send`, and polled on another worker it resolves with that worker's send result (both backends; SM5, Q2). Confirmed (run).

`SendFuture` (`io.rs:4131–4147`) holds two `u32`s and a state, is `Send`,
and has no worker check. `BackpressuredSendFuture` (`io.rs:3912–3918`) holds
the same two ids plus a borrowed `&'a [u8]`. `RecvReadyFuture` carries `PhantomData<*const ()>`
(`io.rs:3799–3800`).

`audit_guard_send.rs`: a future created on worker A and polled on worker B
resolved `Ok(8)`, the length of a send B had made on its own connection;
B's own future had not resolved 2 s later. Both backends, one run each.

Consequence: one task gets another connection's result and the other waits
forever. The send-path audit's F1 fixed the same hand-off between tasks on
one worker; across workers the completion table is a different table.

Proposed fix: add the `!Send` marker to both futures, as `RecvReadyFuture`
has, with `compile_fail` doctests. This removes an auto trait from two
public types, so it belongs in the next breaking release.

### F6 — The mio flush uses `writev`, so a write to a shut-down socket raises SIGPIPE (mio on Linux; A2a, A2b, SM7). Confirmed (run).

`mio/driver.rs:917` calls `libc::writev`, which cannot carry
`MSG_NOSIGNAL`. `audit_sigpipe.rs` sets SIGPIPE to `SIG_DFL`, and the
handler calls `shutdown_write()` then `send(b"x")`. mio: nextest reports
"test aborted with signal 13: SIGPIPE". io_uring: passes. One run.

Not run: the reset-then-send path, macOS, and the other write sites
`finish_close` reaches.

Consequence: a mio process that has not ignored SIGPIPE is killed by a
sequence the docs describe as returning `EPIPE`. Rust binaries ignore
SIGPIPE by default; a `cdylib`, or a binary that restores the default, does
not.

Proposed fix: `sendmsg` with `MSG_NOSIGNAL` over the same iovecs; on macOS,
`SO_NOSIGPIPE` at accept and connect.

### F7 — mio's `abort_connection` has no `close_requested()` guard, so a flush error after a local close is reported to the reader (mio; A2e, R6d, SM8). Confirmed (unit test and run).

io_uring's `abort_connection` returns early when a close is already
requested (`uring/event_loop.rs:3127–3140`). mio's does not.

- mio unit test: after `close_connection` and an `EPIPE` flush, the read
  half is `Error` and a receive error is recorded.
- mio integration (`audit_interplay.rs`): "s1 awaited Err(BrokenPipe); r1
  Err(BrokenPipe); s2 awaited Err(BrokenPipe); r2 Err(BrokenPipe)", where
  `io.rs:2803–2804` says the second `with_data_result` is `Ok(0)`. This test calls
  `shutdown_write()` and then sends twice; it never calls `close`, so the
  local-close case in the title rests on the unit test. One run of this
  version of the test (`repro-interplay2-mio.log`).

Consequence: on mio a read error can be reported more than once, and a
reader sees an error for a connection its own task closed.

Proposed fix: the same early return in mio's `abort_connection`.

### F8 — A zero-copy guarded send on a Unix connection fails with `EOPNOTSUPP` (io_uring; UX4). Confirmed (run, Linux 7.2.6).

A guarded batch goes to `SendMsgZc` when its total is at or above
`send_zc_threshold` (default 4096; 0 sends every guarded batch zero-copy),
and below it when `submit_small_gather` finds no free pool slot or the
gather does not fit one (`handler.rs:3868–3874`, `4117`). Nothing in the
choice looks at the socket family. The only fallback from a failed `SendMsgZc` is the
`-ENOMEM` arm (`uring/event_loop.rs:3510–3512`).

`audit_unix.rs`: a 64 KiB `SendPart::Guard` through `submit_batch_await` on
a `bind_unix` connection resolved
`Err(Os { code: 95, kind: Unsupported, message: "Operation not supported" })`
and the peer read 0 bytes. Control over TCP: `Ok(65536)`. mio on Unix:
passes. One run.

Not run: `forward_recv_buf` above the threshold, `forward_to_conn` to a Unix
sink, and `send_chain` with a guard on a Unix connection. By reading they
build the same SQE.

Consequence: every guarded send at or above `send_zc_threshold` on a Unix
connection, and a smaller one that falls through to the zero-copy path,
fails and aborts the connection. `ringline-redis` and `ringline-memcache`
`set_with_guard` over a Unix socket would hit it; neither was run.

Proposed fix: decide at submission. Mark a connection whose socket is
`AF_UNIX` at accept and in `connect_unix`, and route its guards through the
copy path, in `send_parts` and in the chain builder.

### F9 — A connected UDP socket on io_uring coalesces GRO segments, delivers a truncated datagram as a whole one, and drops empty datagrams (io_uring; U3a, U3b, U3c, UM11, UM17, UM19). Confirmed (run).

One mechanism: a connected socket is armed with multishot `recv`
(`uring/driver.rs:1236–1240`, `2605–2607`), not `recvmsg`. With `udp_gro`
enabled, `UDP_GRO` is set on every socket, connected or not
(`uring/driver.rs:2277–2293`), a plain `recv` has no cmsg to
carry the segment size (`uring/event_loop.rs:4257–4259` writes
`segment_size: 0`), `handle_recv_udp` has no truncation check
(`:4190–4274`), and it returns on `result <= 0` (`:4200–4217`).
`config.rs:346–348` says GRO "has no effect" on connected io_uring sockets.

`audit_udp.rs`, each with a control on an unconnected socket that passes,
one run each:

- GRO: the peer sends 3000 bytes with `UDP_SEGMENT` 1000. `recv_from`
  lengths `[3000]`; unconnected `[1000, 1000, 1000]`.
- Truncation: `udp_recv_buffer(16, 256)`, the peer sends 1500 bytes then
  10. Lengths `[256, 10]`. The unconnected control passes; its assertion
  accepts `[10]` or `[1500, 10]`, and `[10]` is in the working log only
  (the saved log does not print it).
- Empty datagram: the peer sends 0 bytes then 5. Lengths `[5]`;
  unconnected `[0, 5]`.

mio passes all three connected.

Proposed fix: one of two. Skip the `UDP_GRO` setsockopt for a connected
socket (which makes `config.rs` true) and separately handle truncation and
empty datagrams in `handle_recv_udp`; or arm connected sockets with
multishot `recvmsg`, which fixes all three and costs the per-datagram
header parse the connected path was built to avoid. Which is a question for
the owner (L11).

### F10 — `send_ready` resolves while `send_to` still returns `PoolExhausted`, so the documented loop spins without yielding (io_uring; U4c). Confirmed (run).

`UdpSendReadyFuture::poll` checks only the socket's `send_freelist`
(`io.rs:6026`). `send_to` also needs a `SendCopyPool` slot and returns
`PoolExhausted` after giving the send slot back (`uring/driver.rs:2465–2468`).
The rustdoc at `io.rs:5610–5613` tells the caller to await `send_ready` when
`send_to` returns `PoolExhausted`, "rather than busy-looping".

`audit_udp.rs`, `send_pool(16, 16384)` with the default 64
`udp_send_slots`: 16 datagrams sent, then `send_ready` resolved 100 000
times in a row with `send_to` returning `PoolExhausted` or
`SubmissionQueueFull` each time (the test's bound; its match arm takes
either and does not record which. By reading it is `PoolExhausted`: the
pool has 16 slots and the SQ has 64 entries). The task never returns `Pending`, so the worker never
handles the send CQEs that would free a slot. Control (`udp_send_slots(4)`):
2000 sent. mio passes. One run.

Consequence: with fewer copy-pool slots than UDP send slots, the documented
loop hangs the worker.

Proposed fix: `send_ready` is ready only when the freelist is not empty and
the copy pool has a free slot; wake `send_ready` waiters when the pool
releases.

### F11 — `for_each_segment` ignores `consumed`, so a datagram already returned by `recv_from` is delivered again by `recv_batch` (both backends; U3a, U3c, UM14). Confirmed (unit test).

`runtime/mod.rs:117` chunks the payload from offset 0. `recv_from` and
`with_datagram` take one segment, set `entry.consumed` and push the entry
back (`io.rs:5759–5770`); `recv_batch` then calls `for_each_segment` on it
(`io.rs:5940`).

Unit test: an entry of 2500 bytes with `segment_size` 1000 and `consumed`
1000 yields `[1000, 1000, 500]`; expected `[1000, 500]`. Both backends.
The callers were read, not run together.

Proposed fix: start the chunking at `consumed`.

### F12 — mio reads a forward source whose sink is at `forward_hold_cap` (mio; R11c). Confirmed (unit test).

`handle_readable` reads before it checks `forward_sink_full`
(`mio/event_loop.rs:1031`, `1047–1059`). Unit test with
`forward_hold_cap = 1`: the sink's queue goes from 1 to 2 entries on a
readable event; the control below the cap passes.

Consequence: each readable event on a held source adds one read to the
sink's queue, so the cap bounds nothing when the source keeps sending.

Proposed fix: test the hold before reading.

### F13 — After a `forward_to_conn` is dropped while held, the source connection is never read again (mio; P5, P7d, R7c). Confirmed (run).

`drain_forward_resumes` skips a source that no longer has a forward and
clears its resume flag (`mio/event_loop.rs:765–768`).
`audit_forward.rs`, `forward_hold_cap(1)`, a sink that never reads, the
forward under a 500 ms `timeout`: the handler logged "forward Err(Elapsed)"
and the `with_data` after it returned nothing in 5 s with 5 291 520 bytes
written by the peer. io_uring passes. Two mio runs of two versions of the
test; the quoted line is from the second (`repro-forward2-mio.log`).

Proposed fix: when the source has no forward, clear the flag and still run
`handle_readable` for it.

### F14 — `drain_send_retries` gives up on a send without `abort_connection`, so the reader is not told (io_uring; the send-path record's F1 and F2). Confirmed (unit test).

`uring/event_loop.rs:4763–4765` calls `drain_conn_send_queue`, `wake_recv`
and `close_connection`. The other three give-up arms (`drain_zc_retries`
`:4523–4535`, `drain_coalesced_retries` `:4602–4618`, `drain_copy_retries`
`:4673–4687`) call `abort_connection`. #794's message names "the three retry give-up
arms"; `drain_send_retries` is a fourth, and #794 has no hunk in it.

Unit test with three forced push failures: the read half is `Open` and no
receive error is recorded; expected `Error` and a recorded error.

Consequence: `with_data_result` returns `Ok(0)` for a connection the
runtime closed after dropping a send. CLAUDE.md Domain Invariant 7 says a
parked send is "never dropped" (D1).

Proposed fix: call `abort_connection` there, as the other three do.

### F15 — `may_block` ignores the send retry lists and a pending park drain (io_uring; R7c, RM24, liveness of O4 and O5). Confirmed for the state (unit tests); the live sequence was not produced.

`may_block` (`uring/event_loop.rs:1101–1109`) checks the ready queue,
`pending_finalize_closes`, `deferred_recv_arms`, `udp_rearm_due()` and
shutdown. It does not check the four send retry lists or
`park_drain_pending`. `drive_park_drains` (`:1920–1925`) counts loop
iterations, and `tick_timeout_us = 0` means the wait has no timeout
(`config.rs:1093–1094`).

Unit tests: with one send parked after a refused push, `may_block()` is
true (at the default `tick_timeout_us` of 1000); with a park drain pending,
a reader parked and nothing armed, `may_block()` is true (with
`tick_timeout_us = 0`). Each test first asserts that an idle worker may
block; there is no separate control test.

Not shown: a refused push on a live ring, and the race that leaves a park
drain pending (a receive CQE with bytes arriving ahead of the cancel during
`begin_park`, under `AcceptMode::Merged`). With a nonzero tick the wait is
bounded by the tick, so the cost is latency, not a hang.

Proposed fix: `may_block` returns false while any retry list or
`park_drain_pending` is non-empty.

### F16 — `DirectPool` keeps a buffer larger than `recv_direct_pool_max` (io_uring; R9). Confirmed (unit test).

`AccumulatorTable::release` puts `acc.buf` into the pool whenever the
connection holds a borrowed buffer (`acc.own.is_some()`,
`accumulator.rs:557–566`, io_uring only; `DirectPool::put` at `:434–440`).
`spent` is not tested there. When `spent` is also set, `acc.buf` is a tail
of a larger shared allocation, and the pool counts the tail's capacity.
Unit test: a 1000-byte first receive, then a message of 3 MiB + 1 byte,
2 MiB pool cap: "4194304 allocated, 1048575 counted in the pool". Control (1 MiB
message) passes. `config.rs:985` says "A buffer larger than this is never
kept".

Proposed fix: in `release`, clear `frozen`, recover the buffer from `spent`
as `detach_for_recv` does, and pool that or nothing.

### F17 — A Unix path longer than 107 bytes is truncated without an error (both backends; UX17, UX19). Confirmed (run).

`unix_path_to_sockaddr` copies `min(len, 107)` bytes and returns no error
(`backend/sockaddr.rs:88–89`). `audit_unix.rs`: `bind_unix` with a 120-byte
file name: `launch` returned `Ok`, nothing exists at the path given, and the
directory holds one entry with an 87-byte name. Both backends, one run each.
By reading, `connect_unix` truncates the same way, and at the next launch
the unlink targets the full path while the bind hits the stale truncated
one.

Proposed fix: return `InvalidInput` for a path that does not fit, from
`launch` and from the `connect_unix` future.

### F18 — `bind_unix` deletes a regular file at the path (both backends; UX17). Confirmed (run).

`worker.rs:2399–2400` runs `remove_file(path)` unconditionally; the rustdoc
(`worker.rs:968`) says "Any existing socket file at the given path is
unlinked before binding." `audit_unix.rs`: a regular file at the path is
gone after `launch`. Both backends, one run each. By reading, the socket
file is not removed at shutdown, and no doc says so.

Proposed fix: unlink only when the path is a socket; otherwise let `bind`
fail. Whether that is wanted is L12.

### F19 — On mio a send waiting on a Unix peer is not failed when the peer shuts down (mio; counterpart of UX2 and UX3). Confirmed (run).

`mio/event_loop.rs:329–334` calls `handle_writable` for an established
connection only on a writable event. `audit_unix.rs`: an 8 MiB send stalled
on a Unix connection did not fail within 3 s of the peer's
`shutdown(Both)`, nor of `shutdown(Read)`. io_uring fails both with
`BrokenPipe` (0.3 s and 1.0 s). One run.

Proposed fix: run the flush once when the event reports a closed side and
sends are queued; for `SHUT_RD`, add the periodic retry io_uring has, or
state the difference.

### F20 — After a dropped read, `recv_ready` resolves while no reader can see the bytes it counted (io_uring; P4, P5, RL17). Confirmed (run).

`recv_ready` counts `recv_direct_held` (`io.rs:3813–3817`,
`uring/driver.rs:1488–1494`). After a parked `with_data` is dropped by a
timeout with part of a message received, `audit_forward.rs` logged: "first
Err(Elapsed); recv_ready resolved true; try_with_data None; with_data
Some(Err(Elapsed))" with 100 bytes received and the peer idle. mio: the test passes;
`Consumed(100)` is in the working log only (the saved log prints nothing,
and the assertion accepts two outcomes). One run.

RL17 records that `try_with_data` returns `None` in this state. It does not
record that `with_data` does not resolve (it had not after 1 s here; the
peer never sent again, so what a later send does was not run), or that
`recv_ready` says otherwise. The `recv_ready` rustdoc (`io.rs:2843–2845`)
says "a reader started after it resolves sees the same bytes". By reading,
this is plaintext only: a TLS receive does not detach the accumulator
(`uring/event_loop.rs:1171`). The TLS case was not run.
`tests/recv_direct.rs:546` shows the `recv_ready` result is intended.

Proposed fix: a question (L3). Either `recv_ready` does not count held bytes
while the receive that holds them is in flight, or a reader that parks with
held bytes and no room requirement is given them.

### F21 — `with_bytes` parks where `with_data` resolves `0` when the callback closes the connection (both backends; P1c, P1d, P2). Confirmed (run).

`with_data` reads `recv_finished()` after the callback (`io.rs:2074–2082`);
`with_bytes` uses the value from before it (`io.rs:2157–2167`,
`2269–2272`). `audit_forward.rs`: the callback calls `tx.close()` and
returns `NeedMore`. `with_data` resolved `0`; under `with_bytes` the
task was dropped before the read resolved (a `Drop` marker fired). Both
backends, one run each. The `close` rustdoc allows code after `close()` to
stop at its next `.await`, so `with_bytes` is inside that contract; the
finding is that the two differ.

Proposed fix: read `recv_finished()` again after the callback in
`WithBytesFuture::poll_current`.

### F22 — `send_parts` behaves differently by backend in two unstated ways (Q2, Q4). Confirmed (run).

`audit_contracts.rs`, one run each:

- 33 parts through `submit_batch`: io_uring `Err(InvalidInput)`, 0 bytes;
  mio `Ok(33)`, 33 bytes. The rustdoc (`io.rs:3195–3196`) gives the limit
  with no backend.
- A `build` closure that does not call `.submit()`: io_uring `Ok`, 0 bytes
  on the wire; mio `Ok`, 1 byte on the wire. On mio `build` sends what the
  closure accumulated (`io.rs:1795–1799`) and `MioSendBuilder::submit`
  returns `Ok(())` (`io.rs:1899–1901`).

Also, by reading: `SendHalf` says "Available on both backends."
(`io.rs:3118`) and `send_chain`/`send_chain_nowait` are
`#[cfg(has_io_uring)]`.

Proposed fix: state the limits and the `build` difference per backend, or
make `MioSendBuilder::submit` set a flag `build` requires. Correct line
3118.

### F23 — The error a reset during an outbound TLS handshake resolves differs by backend and by when the reset lands (Q4). Confirmed (run, both backends, two reset timings).

`audit_tls_connect.rs`, a peer that accepts and resets: io_uring
`Err(ConnectionAborted)` 5 of 5, mio `Err(ConnectionReset)` 5 of 5. The
counts are from the working log; one run per backend was saved
(`repro-tlsconnect-uring.log`, `repro-tlsconnect-mio.log`). The reviewer who raised this predicted the opposite direction from reading the
mio arm; see Refuted. The io_uring path that produces `ConnectionAborted`
was not traced.

Proposed fix: give the connect waiter the socket's error on both backends:
add `wake_connect` to mio's TLS read-error arm, and trace the io_uring arm
that produces `ConnectionAborted`.

The F1 fix's reviewer measured the backends the other way round with the
reset at a later point: a peer that leaves the ClientHello unread and
closes, or reads it and closes with `SO_LINGER 0`, gives `ConnectionReset`
on io_uring and `ConnectionAborted` on mio, 5 of 5 per backend in each
form. Rerun of `control_tls_connect_to_a_peer_that_resets` at `6851de26`
(accept, then reset at once): io_uring `ConnectionAborted` 5 of 5, mio
`ConnectionReset` 5 of 5. Both results hold. Which error a connect sees
depends on the backend and on when the reset lands, and neither backend
gives the socket's error in both cases. The mio TLS read-error arm
(`mio/event_loop.rs:887–896` at `6851de26`) calls `close_connection` with no
`wake_connect`, which accounts for mio's `ConnectionAborted` in both of the
reviewer's forms (by reading; the wake path was not traced).

### F24 — A value whose `Drop` calls `send`, `send_nowait` or `shutdown_write` panics when the worker drops its tasks at exit (both backends; SM16, SM20). Confirmed (run for `send_nowait`; `send` and `shutdown_write` by reading).

`drop_tasks` runs with no driver state installed, and `with_state` expects
it (`io.rs:208–210`). `audit_interplay.rs`: a task-held value whose `Drop`
calls `send_nowait`, alive at `shutdown()`. The worker prints "ringline:
task drop panicked: called outside executor". Under the default policy the
join returns `Ok`; under `TaskPanicPolicy::Shutdown` it returns
`Err(task panicked: called outside executor)`. Both backends, one run each.
SM20 recorded this for `shutdown_write` only.

Proposed fix: the `SendHalf` entry points check for driver state first and
return `Err(NotConnected)` when there is none. `close` already checks
(`io.rs:1531–1536`) and returns without acting.

### F25 — Two UDP unit tests assert nothing (tests). Confirmed (mutation).

`handle_send_msg_udp_error_releases_pool_slot` and
`handle_send_msg_udp_wakes_send_ready_waiter`
(`uring/event_loop.rs:11726–11728`, `11759–11761`) return early when the
test loop has no UDP socket, and `make_test_loop` configures none.
Replacing each `return` with a panic makes both fail with the panic's
message. No test asserts on the handling of a failed UDP send CQE;
`tests/udp.rs:2772` may produce one on io_uring and asserts only
`send_to`'s return.

Proposed fix: build both loops with a UDP bind and remove the early
returns.

### F26 — Small items confirmed by reading

- `uring/driver.rs:405` and `:3128–3129` say `ring` drops last. It is the
  first field and drops first; the test at `:3176` asserts that order. The
  same wording is in five more places (D19). A corrected comment should say
  only what the code shows: the ring drops first, and `run_shutdown` waits
  for or leaks the memory in-flight operations reference. One reviewer's
  replacement sentence described how the kernel tears a ring down, which
  nobody verified.
- `self.total_len += len` (`handler.rs:3787`) is an unchecked `u32` add: a
  debug build panics on overflow and a release build wraps. Reaching it
  needs parts (copy and guard) that total 4 GiB. The same unchecked add is
  at `handler.rs:3756`, `4266`, `4483`, `4515` and `4849`. Not run. Proposed fix:
  `checked_add` with `InvalidInput`.

### F27 — A forward followed by `close()` in the same closure makes the delivery path consume past the end of the accumulator (io_uring). Confirmed (run, by the F2 fix's reviewer, at `6851de26` and on the fix).

In a `with_data` or `try_with_data` closure: `forward_recv_buf(data)` of
the whole accumulator, then `close()`, then return
`ParseResult::Consumed(data.len())`. `close_connection` zeroes
`forward_zc_consumed` (`uring/driver.rs:1418`), so the delivery path calls
`accumulators.consume(conn, len)` on the empty accumulator. A debug build
panics, `consume(99) exceeds buffer length 0` (`accumulator.rs:281`); a
release build clamps the consume to the accumulator's length (0). From
#403, in no release.

Proposed fix: zero the count in `handle_close`, next to the
`forward_zc_held` clear, not in `close_connection`. The reviewer ran this
change against the lib tests (840 passed), not the full suite. The F2
fix's close test returns `NeedMore` to avoid this.

### F28 — A whole-accumulator forward made outside a reader closure leaves a forwarded count the next read subtracts (io_uring). Mechanism confirmed (run against crate internals, by the F2 fix's reviewer); the public-API sequence was traced, not run.

The zero-copy branch of `forward_recv_buf` (`io.rs:1227–1260`) recognises
the whole accumulator by pointer and length only. A parser that keeps
`rest = b.slice(1..)` from a `with_bytes` callback returning `Consumed(1)`
holds a slice with the same range `put_back` stores. Calling
`tx.forward_recv_buf(&rest)` after the `.await`, outside any closure,
detaches the accumulator and sets `forward_zc_consumed` to 99, and no
delivery path reads it. The next `with_data` returning `Consumed(6)`
consumes `6.saturating_sub(99) = 0`, and those 6 bytes are delivered again.
From #403, in no release. Since the F2 fix the 99 bytes are also held until
that read.

Proposed fix: take the zero-copy branch only inside a reader callback for
the same connection (`READER_CALLBACK_CONN == conn_index`).

## Plausible findings

The code path is real; the trigger was not produced.

- **PL1** `handle_hangup_peek` returns on `ECANCELED`, `EAGAIN` or `EINTR`
  (`uring/event_loop.rs:1535–1541`) with no poll, recheck or retry left. A
  unit test that dispatches a `HangupPeek` CQE of `-EAGAIN` on an open
  connection shows nothing armed afterwards. Whether the kernel returns
  `-EAGAIN` for a peek that follows a poll completion was not shown. If it
  does, the connection's FIN or reset is not seen until a reader parks
  (R7a).
- **PL2** `handle_recv_msg_udp` returns on `result <= 0`
  (`uring/event_loop.rs:4040–4047`) without returning a selected buffer. A
  unit test dispatching `-EINVAL` with `IORING_CQE_F_BUFFER` and bid 3
  leaves `udp_pending_replenish` empty; the same CQE under `RecvUdp` queues
  `(0, 3)`. Whether the kernel posts an error CQE that carries a buffer for
  a multishot `recvmsg` was not shown. If it does, each one leaks a buffer
  from the socket's ring (U2a).
- **PL3** At worker exit `run_shutdown` does not cancel or wait for UDP
  sends: `handle_shutdown_cqe` has no arm for the UDP tags
  (`uring/driver.rs:2788`), the exit condition does not count them
  (`:2933–2935`), and the leak of the slab and the copy pool, where UDP
  send payloads live, runs only when the send slab has entries in flight
  (`:2961–2964`), so a UDP send in flight alone does not trigger it. Whether a UDP send can still be in flight when the
  driver's memory is freed was not shown; a UDP send to a local socket
  completes inline (U4a, CLAUDE.md Domain Invariant 1). A second reader
  agreed with the path: UDP sockets are fixed files at
  `max_connections + udp_idx` (`uring/driver.rs:1068`) and are not covered
  by the per-connection cancel, and the UDP multishot receive is not
  cancelled either while its buffer ring is unregistered at
  `uring/driver.rs:2966–2973`. Proposed fix: count UDP sends in flight in
  the exit condition and give `handle_shutdown_cqe` arms for `SendUdp` and
  `SendMsgUdp`; without the arms the wait runs to the shutdown bound every
  time.
- **PL4** mio stops draining a UDP socket on any error other than
  `ECONNREFUSED` (`mio/event_loop.rs:1265`, `1303–1304`). With an
  edge-triggered registration, a datagram queued behind an ICMP error other
  than port-unreachable would wait for the next edge. The ICMP error was
  not produced.
- **PL5** After an ICMP port-unreachable, a connected `send_to` is retried
  once on mio (`io.rs:5651–5658`) and on io_uring fails in its CQE with the
  caller already holding `Ok(())` (`uring/event_loop.rs:4171–4173`). Which
  operation the kernel gives the error to was not shown.
- **PL6** A zero-copy send CQE with result 0 is settled as `WriteZero`,
  counted, and followed by the next queued send
  (`uring/event_loop.rs:3560–3573`, `3587–3593`). A TLS-chunk send CQE with
  result 0 is followed by the next queued send with nothing settled or
  counted (`:3943–3944`, `3952–3954`). Neither aborts the connection;
  `handle_send` aborts on 0 (`:2850–2856`). If the kernel ever completes
  one of these sends with 0, the bytes behind the failed send go out after
  a gap in the stream. No trigger was found: a stream send of a non-empty
  buffer is not expected to return 0. Proposed fix: treat `result <= 0` as
  the failure at `:3587`, `:3943` and `:3952`.
- **PL7** On mio a forward keeps reading its source into a sink whose
  write has failed until the close is processed at the end of the loop pass
  (`mio/driver.rs:767–771`; order at `mio/event_loop.rs:374–382`), so bytes
  are taken from the source after the forward has in effect ended (RM62,
  third clause). A second reader agreed by reading. It was not run, and it
  needs the second write to a reset socket to fail, which is kernel
  behaviour. Proposed fix: `forward_push` refuses a sink for which
  `close_requested()` is true, and `forward_take_accumulated`
  (`mio/driver.rs:792–812`) tests the sink before it consumes.
- **PL8** When the mio unbuffered TLS engine has no room for a record it
  reports `InvalidData` (`tls/unbuffered/mod.rs:684–689`,
  `tls/backend_mio.rs:71–72`). io_uring reports the same condition
  (`tls_recv_arm` returns `None`) as `QuotaExceeded`
  (`uring/driver.rs:195–203`). Whether the mio branch can be reached with
  a valid peer was not shown (R10e).
- **PL9** A parser that panics inside `with_bytes` drops every buffered
  byte: the buffer is taken before the call (`io.rs:2218`) and put back
  after it (`:2238`, `:2261`), with no guard for the unwind. For a
  connection task the panic closes the connection
  (`uring/event_loop.rs:967`), so nothing reads again. A standalone task
  that panics is dropped without a `close_connection`
  (`uring/event_loop.rs:908–920`), so another holder of the handle would
  read with the bytes gone. That sequence was not traced or run. Proposed
  fix: a guard that calls `put_back` on unwind.
- **PL10** On both backends, a TLS connection closed before its handshake
  completes (#849's FIN arm, the feed-error arms, and the
  `tls_handshake_timeout` expiry) is not torn down while handshake
  ciphertext is unsent. On io_uring, `try_finalize_close` returns while
  `in_flight` is set (`uring/driver.rs:1712`), and the close deadline is
  armed only by the `DriverCtx` close path (`handler.rs:1155`). On mio,
  `drain_pending_closes` defers `finish_close` while `pending_sends` is
  non-empty (`mio/event_loop.rs:1423–1428`). This is the pre-handshake
  case of the connection-close audit's L4, the unbounded close deferral;
  it matters here because these closes exist to free a stalled peer's
  slot. A server flight larger than the client's receive buffer and the
  server's send buffer together, sent to a client that never reads, would
  hold the slot until a write fails. Found while reviewing the L18 change,
  by reading; no such client was run. Proposed fix, on both backends: arm
  a close deadline on these paths, or call `force_finalize_close` on
  io_uring and, on mio, let `drain_pending_closes` tear these connections
  down without waiting for `pending_sends`.

  Confirmed after the audit, on both backends, and fixed in #886, merged as
  4cf6d4bb. A one-slot server with a flight of about 2 MB and a peer with a
  minimal receive buffer that stopped reading after its ClientHello: the
  slot stayed held after a handshake timeout and after the peer's FIN. On
  loopback a 0.5 MB flight was taken in full and a 1 MB one was not. A
  first fix tore the connection down at once; on io_uring a peer that was
  still reading then lost most of the flight and the alert, and the owner
  required the alert be delivered. The merged fix keeps the drain and
  bounds it: `close_connection` sets the close deadline
  (`CLOSE_NOTIFY_TIMEOUT`, 5 s) on a connection that is not established, on
  both backends, and mio's `finish_close` writes no close_notify while
  sends remain queued. Open: on io_uring with `tick_timeout_us(0)` the
  deadline is checked only when a worker timer wakes the loop; a stall with
  no send waiting for room was not shown.

## Documentation findings

Each item compares a sentence in the rustdoc, a design doc, `CLAUDE.md`,
`CHANGELOG.md` or a comment with the code at `6851de26`. A reviewer read
each one, and a second reader, told to refute it, read it again. None was
run unless the item cites a run. Where the second reader corrected the
reviewer, the corrected form is given here and the correction is listed
under Refuted and corrected. Every item is open. Together they are the
breaks of A3 and most of the breaks of Q4.

Send:

- **D1** `CLAUDE.md:238` (Domain Invariant 7) says a queued send whose SQE
  cannot be pushed is "never dropped". `drain_send_retries` gives up after
  two retries, drains the queue and closes (`uring/event_loop.rs:4752–4766`).
  `docs/send-completion-design.md:152–155`, `uring/driver.rs:1848–1853` and
  `io.rs:3156–3159` state the give-up. Fix: reword the invariant to "retried
  twice, then the send fails and the connection closes". F14 is the code
  half.
- **D2** `io.rs:3313` says of `shutdown_write`: "Plain `send` is unaffected
  either way." `connection.rs:75–83` says such a send fails with `EPIPE`.
  Measured, 5 runs per backend: on io_uring a `send(b"x")` issued after
  `shutdown_write()` resolved `Ok(1)` and the peer read `x` then EOF; on mio
  it resolved `Err(BrokenPipe)` and the peer read nothing before EOF. In
  one run of a different handler mio also aborted the connection. By
  reading, with no send queued io_uring submits the Shutdown SQE unlinked
  (`handler.rs:1205–1217`) and the later send is an independent Send SQE;
  with sends queued the shutdown is deferred (`handler.rs:1199–1204`).
  Neither sentence describes both backends. The replacement depends on the
  answer to L6.
- **D3** The `ConnStream` module doc (`stream.rs:1–23`, `34–46`) names no
  error behaviour.
  - Read side: with nothing buffered, `poll_read` and `poll_fill_buf`
    return `Ok(0)` or an empty slice when `recv_finished()` is true
    (`stream.rs:87–92`, `136–137`, `171–173`), which includes a failed read
    and the accumulator cap, and when the handle is stale (`:125–127`,
    `:163–165`).
    Measured on both backends: after a peer reset `with_data_result`
    returns `Err(ConnectionReset)` and `ConnStream::read` returns `Ok(0)`.
    The error value cannot be reached through `ConnStream`;
    `send_half().is_alive()` tells a connection closed by an error from a
    FIN.
  - Write side (`stream.rs:203–241`), by reading: `poll_write` never
    returns `Pending`. It writes at most one slot (`:217`) and returns
    `send_nowait`'s result, which with a full pool is
    `Other("send copy pool exhausted")` on io_uring (`handler.rs:587`) and
    an unbounded queue on mio (`handler.rs:2697`, `2712`). `poll_flush`
    always returns `Ready(Ok(()))`. `poll_write` after `poll_close` returns
    `Ready(Ok(n))`.
  Fix: state these in the module doc. Whether to change them is L1.
- **D4** A stale handle gives different results by entry point and
  backend. Zero-byte batch, with the Close committed or the slot released:
  io_uring `build(|b| b.submit())` returns `NotConnected`, io_uring
  `submit_batch(vec![])` returns `Ok(0)`, mio `build` returns `Ok(())`, mio
  `submit_batch` returns `Ok(parts.len())` (`handler.rs:3820–3848`,
  `io.rs:1691–1693`, `1796`, `1823`). `send_backpressured` resolves
  `ConnectionAborted` when the slot was released (`io.rs:3969–3974`), where
  `send` returns `NotConnected` (`handler.rs:541–546`). Rustdoc states the
  io_uring `NotConnected` results (`handler.rs:3812–3814`,
  `io.rs:3189–3191`, `3202`) and `ConnectionAborted` for
  `send_backpressured` (`io.rs:3894–3895`). No rustdoc states the mio
  results, or that io_uring `submit_batch(vec![])` returns `Ok(0)`. Fix:
  return `NotConnected` from each zero-byte batch, or state the results
  per entry point.
- **D5** The `ConfigBuilder` rustdoc for `send_pool` (`config.rs:1043–1046`),
  `send_zc_threshold` (`:1065`), `send_slab_slots` (`:1071`) and
  `max_chain_length` (`:1107`) names no backend. On mio the pool bounds
  only `send_backpressured` admission (`handler.rs:2717–2726`, `2782`);
  `send`, `send_nowait` and `send_parts` queue a `Vec` with no slot. The
  slot size also caps one `ConnStream::poll_write` (`stream.rs:217`).
  `send_slab_slots` is validated (`config.rs:561`) and otherwise unused on
  mio, and `send_zc_threshold` and `max_chain_length` have no effect there.
  Also `config.rs:169–170` (a `pub(crate)` field doc) says a `send()` must
  fit one slot, and `send` takes one slot per chunk (`handler.rs:583–584`,
  `613`). Fix: add the backend scope to each knob; correct the field doc.
- **D6** The `send` rustdoc (`io.rs:3125–3159`):
  - "On mio a plaintext send never fails for pool reasons"
    (`:3149–3150`) leaves mio TLS unstated; a mio TLS `send` uses no pool
    either (`tls/backend_mio.rs:151–168`). A replacement must be scoped to
    `send` and `send_nowait`, because mio `send_backpressured` does use
    pool admission.
  - An empty `send` resolves `Ok(0)` (`handler.rs:614–619`, `2702–2705`).
    Not stated.
  - `SendFuture` and `BackpressuredSendFuture` panic when polled after
    completion (`io.rs:4184`, `3952`). `CHANGELOG.md:633–634` records it
    for `SendFuture` only; the rustdoc does not.
- **D7** The `send_chain` rustdoc (`io.rs:3332–3368`) omits two errors
  `finish` returns: the submit-queue errors
  (`uring/engine/uring.rs:255–274`, `284–301`, `805–832`; `handler.rs:4359`,
  `4366`) and `NotConnected` (`handler.rs:4325–4339`). By reading, not run:
  `Config::validate` (`config.rs:586`) does not relate `sq_entries` to
  `max_chain_length` (default 16, `config.rs:448`), so with `sq_entries(8)`
  a 9-part chain would fail "SQ too small for chain" on every call. Fix:
  list the errors; reject `sq_entries < max_chain_length` in `validate`.
- **D8** `CLAUDE.md:269` gives 1 copy for `send_parts` with copy parts, and
  the note at `:306` says only that on mio "all of these degrade to copy
  sends". On mio `send_parts` pays 2: the gather (`io.rs:1886`) and the copy
  into the queued `Vec` (`handler.rs:2697`).
  `docs/syscalls-and-copies.md:202` already says so; only `CLAUDE.md` needs
  the correction.
- **D9** Stale lines in send design docs:
  - `docs/half-closed-send-wait-design.md:236–238` says "The FIN closes
    each connection when its send finishes"; the test it describes
    (`tests/half_closed_send_wait.rs:271–313`) asserts the peer reads the
    whole payload.
  - `docs/public-context-types-design.md:62–64` describes, as "Today", the
    types `ForwardToFuture` and `ForwardToConnFuture`, which do not exist.
  - `docs/copied-send-reservation-design.md:319` and
    `docs/send-backpressured-design.md:156` name tests that do not exist
    (`send_retry_cap_fails_the_waiter_and_closes`,
    `mio_half_close_completes_submitted_send_and_cancels_capacity_waiter`);
    the rename list at `docs/send-completion-slots-design.md:133–142` does
    not cover them. `docs/backpressured-sends-series-design.md:246` has
    the same kind of reference.

Receive:

- **D10** Three sentences in `CHANGELOG.md` `Unreleased` (`:526–528`,
  `:545–548`, `:551–552`) say a FIN closes the connection. The entry at
  `:275–290` and the code say it does not (`uring/event_loop.rs:1233–1241`,
  `1573–1587`; `mio/event_loop.rs:1032–1040`). These would ship in the
  0.7.0 notes.
- **D11** The `HANGUP` metric rustdoc (`metrics.rs:346–347`) and
  `docs/recv-direct-design.md:669–671` call it a count of closed
  connections. It is incremented at `uring/event_loop.rs:1572`, before the
  branch on the peek result; the FIN branch closes nothing.
- **D12** `Consumed(n)` with `n > len`, and the call at end of stream. Both
  readers call the closure once with empty input when the read half is
  finished and nothing is buffered, and return its `n`; only the
  `with_data_result` rustdoc says so (`io.rs:2804–2808`). For `n > len` on
  buffered data both readers return the unclamped `n`, and on io_uring
  both record it as `largest_message` (`io.rs:2057`, `2252`;
  `accumulator.rs:832–836`); `with_data` reaches a `debug_assert!` in
  `consume` first in a debug build (`accumulator.rs:266–271`). By reading,
  on io_uring the next receive armed with bytes buffered and less than
  half a region spare then requests a buffer of up to
  `recv_accumulator_max` (`accumulator.rs:773–787`). mio does not record
  the value. `ParseResult`, `with_data` and `with_bytes` rustdoc are
  silent; `docs/recv-arrival-times-design.md:153–157` records the clamp
  and the assert in `consume`. Fix: clamp `n` to `len` in both readers
  before it is recorded, and state the rule on `ParseResult`. The clamp
  must exclude the empty-input call, or the `with_data_result` rustdoc
  must change with it.
- **D13** `try_with_data` (`io.rs:3062–3063`) states one of the cases that
  return `None`. Unstated: a stale handle; on io_uring, a plaintext
  receive in flight (the accumulator is detached; a TLS receive does not
  detach it); and that it panics outside the executor. The
  `RecvReadyFuture` rustdoc (`io.rs:3784–3787`) says the bytes are "in its
  accumulator", and `recv_ready` (`io.rs:2840–2845`) says "buffered for the
  connection"; on io_uring the count includes bytes inside a receive in
  flight (`uring/driver.rs:1488–1494`). F20 is the measured consequence.
- **D14** `eof_truncated` panics outside the executor (`io.rs:1505`,
  `210`). Its rustdoc (`io.rs:3003–3013`) has no Panics section, and
  `peer_closed` and `is_recv_direct` beside it return `false` there and
  say so.
- **D15** With unread bytes buffered, `peer_closed` and `is_alive` change
  at different times by backend. io_uring defers the hangup until the task
  has read the buffered bytes (`uring/event_loop.rs:1551–1565`); mio
  records a FIN on the readable event and closes on a read error at once
  (`mio/event_loop.rs:1032–1040`, `1082–1093`). No rustdoc says the
  backends differ. The io_uring half rests on what the kernel returns for
  the peek, which was not verified.
- **D16** `CLAUDE.md:168` describes a receive completion as an accumulator
  append. On io_uring that now holds only for TLS plaintext: a plaintext
  receive goes straight into the detached accumulator buffer
  (`accumulator.rs:722–822`). `CLAUDE.md:252` gives that receive 0 copies
  and omits the copy when the buffer grows or moves
  (`accumulator.rs:794–805`); `:210` and `:256` omit the conditional
  copies in `reclaim` (`accumulator.rs:681–685`) and, on mio, in `unfreeze`
  when a slice is still alive (`accumulator.rs:226–238`).
  `docs/syscalls-and-copies.md:181` has the growth clause and `:183` has
  the same omission as `CLAUDE.md:256`. `CLAUDE.md:244` says the two
  documents are kept in sync.
- **D17** The `forward_to_conn` rustdoc:
  - `io.rs:2423`: "A result `< len` means the peer sent FIN first."
    Measured: after a reset the forward resolved `Ok(10)` on io_uring, the
    same as after a FIN; see L2.
  - `io.rs:2444`: "Resolves `Err(EPIPE)` if the sink connection closes
    mid-forward." By reading (two readers), on io_uring a failed chunk
    send resolves the forward with that send's errno (`io.rs:3664–3673`);
    the generation still matches because the Close is deferred to
    `pending_finalize_closes` (`uring/driver.rs:1454–1463`). mio resolves
    `EPIPE` (`mio/event_loop.rs:1435–1438`). The body of the `SendMsgZc`
    error handler was not read.
  - The mio section (`io.rs:2465–2471`) does not say what dropping the
    future does; a comment at `io.rs:3553–3561` does.
- **D18** Stale receive design docs, comments and test names:
  - `docs/recv-direct-design.md`. Lines 350–352, 434 and 705–706 say the
    end of the stream closes the connection; line 380 of the same document
    says "A FIN closes nothing". Lines 427–429, 444, 572, 595, 835–837 and
    859–860 describe a TCP multishot or provided-ring receive path that the
    header note (`:11–12`) says was removed. Lines 619–621 name `segments`,
    `recv_owned_segment`, `with_segments` and `with_bytes_segments`, which
    name no item in `ringline/src`, and a public `forward_to`; the only
    `forward_to` is crate-private (`io.rs:1273`, `1319`). Lines 636–638 say
    a TLS connection receives through the provided-buffer ring; it receives
    in `handle_tls_recv_direct` (`uring/event_loop.rs:1339`). Line 643
    describes a connection-level `cancel`, which does not exist. Lines
    854–858 name `ForwardToFuture` and `forward_progress`, which have no
    hits. Lines 14–16 and 647–648 are incomplete next to the header note,
    not false.
  - Recorded limitation RL19 (and `docs/recv-direct-design.md:854–858`,
    which it came from) no longer describes the code: a dropped or closed
    forward clears `direct_forwarding` (`uring/event_loop.rs:3842–3848`,
    `io.rs:3617–3625`). `tests/echo.rs:7743–7745` also names
    `forward_progress`.
  - `docs/recv-arrival-times-design.md:80–85` gives the record sites as
    `handle_recv_multi` and `handle_recv_fallback`, which have no hits in
    `ringline/src`. The live sites are `uring/event_loop.rs:1203`, `1398`,
    `1418`, `2353` and `mio/event_loop.rs:902`, `912`, `1044`. Fourteen
    later lines name removed identifiers (`segment_hold`, `segment_pinned`,
    `pending_recv_bufs`, `RecvSegment` and the segment readers). The
    document's header notes say some of these were removed; they do not
    name `segment_pinned` or `pending_recv_bufs`.
  - The comment at `uring/event_loop.rs:1351–1353` says a truncated TLS
    end resolves reads as `UnexpectedEof`. No code constructs that kind;
    the read resolves `0` with `eof_truncated()` true.
  - Two tests in `tests/recv_direct.rs` (`:1378`, `:1466`) have "closes"
    in their names and assert only that the end is seen.
- **D19** Smaller rustdoc and doc faults:
  - The `Connection` type-doc example "Zero-Copy with `with_bytes`"
    (`io.rs:2579–2617`) builds its value with `Bytes::copy_from_slice`,
    which copies; the comment at `:2596` says it returns `Bytes::slice()`.
  - `docs/syscalls-and-copies.md:80` says a plaintext connection arms the
    hangup poll. A TLS connection arms it too
    (`uring/event_loop.rs:3751`, `uring/driver.rs:320–321`).
  - The drop-order wording in F26 appears in five more places:
    `uring/driver.rs:3179`, `3197`, `3202`, the test name
    `ring_drops_after_buffer_pools` (`:3158`), and the doc at `:411`,
    which names a test `driver_field_order` that does not exist.

UDP:

- **D20** The `send_to_gso` rustdoc says that on mio "the observable
  behavior is identical to applications" (`io.rs:5690–5692`, `5712`). By
  reading, four differences. mio sends chunk by chunk and returns at the
  first failure with the earlier chunks already sent (`io.rs:5728–5733`);
  io_uring rejects before sending (`uring/driver.rs:2434–2444`). mio has no
  slot-size limit on the total. A retry after `PoolExhausted` resends the
  chunks already sent. `DATAGRAMS_SENT` moves once per chunk on mio and
  once per call on io_uring.
- **D21** `recv_batch` and `recv_batch_timed` say the callback runs "up to
  `max` times — once per queued datagram" and that they return "the count
  of datagrams drained" (`io.rs:5559–5561`, `5893–5894`). The loop counts
  queue entries (`io.rs:5931–5942`), and with GRO one entry holds several
  datagrams, so the callback runs more than `max` times and the return
  value is smaller than the number of calls. `config.rs:331–339` does not
  say so either.
- **D22** Three more UDP sentences:
  - `io.rs:5584–5588` (`recv_batch`): "the buffer is released back to the
    kernel after `f` returns and before the next datagram is dispatched".
    `with_datagram` (`io.rs:5515–5516`) says "released as soon as the
    callback returns". The release is queued and returned to the ring once
    per loop pass (`uring/event_loop.rs:471`).
  - `io.rs:5512–5515` says the call "does not allocate a `Vec` for the
    payload". mio copies each datagram with `to_vec()`
    (`mio/event_loop.rs:1246`, `1328`).
  - `io.rs:5625–5629` (`send_to`) says "fire-and-forget" and that the call
    submits an SQE. It does not say that `Ok(())` means only that, or that
    a kernel failure appears only in the `SEND_ERRORS` counter; see L13.

Unix domain sockets:

- **D23** The Unix-specific behaviours are not on the rustdoc of the public
  items, and two public statements are wrong:
  1. `connect_unix` always fails on mio, with kind `Other` and the text
     "I/O error: mio connect_unix not yet implemented"
     (`handler.rs:3022–3030`). `CHANGELOG.md:861–862` and
     `docs/ring-emulator-design.md:47–49` say so; the rustdoc
     (`io.rs:741–755`, `800–804`) and `README.md:124` do not.
  2. `README.md:124` says `connect_unix()` has `.tls()` on its builder.
     `impl UnixConnect` (`io.rs:810–818`) has `timeout` only.
  3. `io.rs:744–746` says the driver terminates TLS on `SocketAddr`
     connections only. A connection accepted on a `bind_unix` listener
     takes the process-wide TLS config when one is set
     (`tls/mod.rs:537–545`, `uring/event_loop.rs:2380`,
     `mio/event_loop.rs:561`). A handshake over a Unix socket was not run.
  4. `config.rs:841` says `tcp_nodelay` applies to "all connections"; it is
     skipped for Unix (`worker.rs:1890–1891`).
  5. `config.rs:1065` (`send_zc_threshold`) is silent on Unix, where the
     zero-copy path fails (F8).
  6. A send waiting on a Unix peer that has shut down its read side is
     retried once a second on io_uring
     (`uring/event_loop.rs:3037–3040`). Only
     `docs/half-closed-send-wait-design.md:93–95` says so.
  7. No doc gives the path length limit (F17).

## Design limitations (questions for the owner, not fixes)

In each of these the code does what it was written to do, or no source
says what it should do. The evidence is a run where one is cited and a
reading otherwise.

- **L1** `ConnStream` reports a failed read, the accumulator cap and a
  stale handle as `Ok(0)`, and its write side does not follow what an
  `AsyncWrite` caller expects (D3). Should `poll_read` return the error,
  should `poll_write` return `Pending` on a full pool, and should
  `poll_flush` wait for queued sends?
- **L2** `forward_to_conn` resolves `Ok(n)` with `n < len` for a FIN, a
  failed source read and a local close of the source. Measured: after a
  FIN, both backends, "forward Ok(10); eof_truncated false; next read
  Ok(0)"; after a reset on io_uring, "forward Ok(10); eof_truncated false;
  next read Err(ConnectionReset)"; after a reset on mio the task was
  dropped before it recorded a result, and the run does not show which
  await it was parked on. Should a failed read resolve the forward with
  the error?
- **L3** `recv_ready` resolves when unread bytes exist, including bytes a
  parser has already declined. A loop of `recv_ready().await` then
  `try_with_data`, with a 200-byte message arriving in two writes 200 ms
  apart, ran 1 000 000 iterations without the message on both backends
  (the test's bound). F20 is the io_uring-only case where the bytes are
  inside a receive in flight. Is `recv_ready` meant to be level-triggered
  on "bytes buffered", or to resolve on new bytes?
- **L4** On mio a reset closes the connection and drops its task wherever
  the task is parked, with received bytes unread
  (`mio/event_loop.rs:1082–1092`, `1422–1459`). Measured: the peer sends 4
  bytes and resets while the handler sleeps; on io_uring the handler then
  reads the 4 bytes, and on mio the task was dropped and no reader saw
  them. `with_data_result`'s "Buffered bytes are always delivered before
  the error is surfaced" (`io.rs:2800`) holds on mio only for a task
  parked on a read. Is that the intended mio behaviour, to be documented,
  or should mio defer the close as io_uring does?
- **L5** mio reads a connection whose task is not reading, up to
  `recv_accumulator_max`, and then closes it
  (`mio/event_loop.rs:1025–1031`, `1061–1071`); io_uring arms a receive
  only when a read parks. Measured with a 64 KiB cap, a handler that reads
  one 1 KiB request and sleeps 10 ms, and 200 pipelined requests:
  io_uring "200 requests, then Ok(0)"; mio "1 requests, then the task was
  dropped". The handler saw neither the buffered requests nor
  `QuotaExceeded`. The rustdoc (`io.rs:671`, `704–705`) does not say the
  cap can be reached with no reader. By reading, io_uring TLS after the
  hangup poll fires has the same shape; that was not run. Should mio stop
  reading at the cap and leave the bytes in the socket?
- **L6** What should a `send` do after `shutdown_write`? Measured:
  io_uring delivers it (5 of 5); mio fails it with `EPIPE` (5 of 5). In one
  run each, mio also aborted the connection and raised SIGPIPE with the
  signal at its default disposition (F6). By reading, on io_uring the
  Shutdown SQE is not linked to the later Send SQE when no send is queued;
  that their order in the kernel is a race is inferred, not verified.
  `send_backpressured` refuses in that state.
- **L7** `fail_recv` overwrites a stored receive error that an earlier
  generation's reader has not taken (`runtime/mod.rs:865–871`), and
  `take_recv_error` compares generations (`:876–888`), so a late reader of
  a reset connection whose slot was reused gets `Ok(0)`. By reading, two
  readers. Is a lost error for a handle that outlived its connection
  acceptable?
- **L8** With `recv_accumulator_max(usize::MAX)`, a parser's
  `NeedAtLeast(n)` reaches the allocator unclamped: on io_uring when bytes
  are buffered (`accumulator.rs:770`, `803`, `422`), on mio at
  `accumulator.rs:132–134`. An `n` above `isize::MAX` is expected to panic
  in `Vec` (recalled `std` behaviour, not read); a smaller `n` the
  allocator cannot satisfy aborts the process. On io_uring at the default
  the panic is inside the task poll and, for a connection task, closes the
  connection; with `defer_recv_arm(true)` (`uring/event_loop.rs:1114–1135`)
  and on mio (`mio/event_loop.rs:1061`) it is outside the task poll and
  ends the worker. Should `NeedAtLeast` have a bound when the cap is
  disabled?
- **L9** A UDP multishot receive that ends with any errno other than
  `ECANCELED` or `ENOBUFS` is re-armed with no bound and no counter
  (`uring/driver.rs:2555–2564`, `2595–2618`). Whether any errno repeats
  without a peer action is kernel behaviour and was not checked.
- **L10** `SendGuard` is a safe trait with an obligation the runtime
  depends on (F4). Should it be an `unsafe trait`, which is a breaking
  change, or should the runtime stop depending on the pointer being stable
  across a move?
- **L11** A connected UDP socket on io_uring is armed with `recv`, not
  `recvmsg`, which is the cause of F9. Is the saved header parse worth the
  three differences, or should connected sockets use `recvmsg`?
- **L12** `bind_unix` removes any non-directory file at the path (F18) and
  leaves the socket file at shutdown. Should it refuse a non-socket, and
  should shutdown remove the file?
- **L13** UDP `send_to` returns `Ok(())` at submission. A send the kernel
  then fails moves `SEND_ERRORS` and nothing else
  (`uring/event_loop.rs:4171–4172`); `DATAGRAMS_SENT` was already counted.
  The same holds for a GSO send the kernel rejects. mio returns the error
  from the call. Is the counter the intended report on io_uring?
- **L14** Each UDP `send_to` on io_uring is its own SQE with no
  per-socket queue and no link (`uring/driver.rs:2484–2549`), so the order
  of two sends on the wire is not fixed by ringline. No doc states an
  order. Should one be stated, either way?
- **L15** The `UdpSocket` rustdoc (`io.rs:5346–5347`) recommends `send_to`
  from inside a `with_datagram` closure. That call makes a second
  `&mut Driver` from the thread-local pointer while the first is still in
  use (`io.rs:208–216`, `5834–5835`, `5856`, `5884`).
  `docs/send-writer-design.md:313–317` records the TCP equivalent
  (`send_nowait` inside `with_data`) as "has not been checked". Neither was
  run under Miri here; the docs note Miri cannot set up a ring. Is this
  aliasing accepted, or should `with_state` be made re-entrant-safe?
- **L16** io_uring discards the result of `setsockopt(SO_REUSEPORT)` on a
  UDP socket (`uring/driver.rs:2263–2271`); mio returns the error
  (`mio/driver.rs:1067–1082`). The consequence (a second worker's bind
  failing with `EADDRINUSE`) is kernel behaviour and was not run.
- **L17** Unix connections, four smaller behaviours, by reading:
  - `connect_unix(path).timeout(d)` against a listener with a full backlog
    would resolve `WouldBlock` before `d` if the kernel completes the
    connect with `-EAGAIN` (`uring/event_loop.rs:3609–3661`,
    `config.rs:784–785`). Not run.
  - With `tcp_nodelay` set (the default), mio calls `set_nodelay` on an
    accepted Unix descriptor and ignores the result
    (`mio/event_loop.rs:516–518`).
  - The peer address of an abstract or non-UTF-8 Unix name is
    `PeerAddr::Unix("")` (`backend/sockaddr.rs:34–61`).
  - After a failed send, a reader gets the send's errno
    (`abort_connection`: `uring/event_loop.rs:3128–3139`,
    `mio/event_loop.rs:742–749`): on io_uring only if no close was already
    requested, on mio always.

- **L18** The TLS handshake has no deadline, inbound or outbound
  (`TcpConnect::timeout` covers the TCP connect only). A peer that connects
  and sends nothing holds an inbound connection slot, with no `on_accept`
  task to time it out, and an outbound `connect(..).tls(..)` does not
  resolve. A peer that sends a warning-level close_notify before the
  handshake completes, on a connection that is not TLS 1.3, and keeps the
  socket open has the same effect: ringline-tls 0.1.2 ignores that alert
  (`process_alert`, `common_state.rs:617–638`). Measured by the F1 fix's
  reviewer on both backends: outbound connect unresolved after 3 s, inbound
  slot held after 5 s. Should the runtime bound the handshake, and with what
  default?

  The owner chose a bound of at most 60 s, default 10 s:
  `ConfigBuilder::tls_handshake_timeout`, in #868, merged as 8a33af77. A
  connection whose handshake has not completed within it is closed, and an
  outbound `connect(..).tls(..)` resolves `TimedOut`; inbound, the timeout
  starts when the worker registers the connection, outbound when the TCP
  connect completes. `metrics::conn::TLS_HANDSHAKE_TIMEOUT` counts the
  closes. Tests in `ringline/tests/tls_handshake_timeout.rs`, both backends.
  The first review of the change found that on io_uring a `tick_timeout_us`
  longer than the timeout delayed the close by up to one tick (with a 300 ms
  timeout under a 3 s tick, the reviewer's run counted the close at 2.81 s),
  that the deadline queue was unbounded behind one stalled handshake, and a
  clock read on every loop iteration; all three were fixed in #868. It also
  found PL10.

## Refuted and corrected

Refuted by a run:

- A reviewer read the mio arm and reported that a socket error during an
  outbound TLS handshake resolves `ConnectionAborted` on mio in place of
  the socket error. Measured 5 of 5 per backend for a peer that accepts
  and resets: mio resolves `ConnectionReset` and io_uring resolves
  `ConnectionAborted`. The direction is refuted for that trigger; the
  difference is F23. For a reset after the ClientHello is sent, the F1
  fix's reviewer measured mio `ConnectionAborted`, as the reviewer had read
  it (F23).

Reviewer statements a second reader or a run corrected. The finding
stands in the corrected form given above:

- "A plain send after `shutdown_write` fails with `EPIPE` on both
  backends" (the proposed replacement for `io.rs:3313`). False on
  io_uring by the run in D2.
- "An empty batch returns different results after `close`". The condition
  is a stale handle (D4), not any `close`.
- "`connect_unix` on mio is stated only in the CHANGELOG".
  `docs/ring-emulator-design.md:47–49` states it too (D23).
- "`ConnStream` exposes `eof_truncated` and `is_recv_direct` and not
  `peer_closed` or `with_data_result`". `send_half()` gives `peer_closed`
  and `is_alive` (D3).
- "No document states either" (the two readers' `n > len` behaviour).
  `docs/recv-arrival-times-design.md:153–157` states the clamp and the
  assert in `consume`. That both readers return the unclamped `n` is
  stated nowhere (D12).
- "All five identifiers on `docs/recv-direct-design.md:619–621` have no
  hits". `forward_to` has five, as a crate-private method; the doc line is
  still wrong.
- The mio plaintext reset arm is `mio/event_loop.rs:1082–1092`; the
  reviewer cited the TLS arm at `887–894` (L4).
- A reviewer's figure of 16.8 MiB for the mio queue in a `ConnStream` copy
  loop is 16.06 MiB by the second reader's arithmetic. Neither was
  measured, and the record does not use the figure.

Checked and not a finding (reviewer and second reader agree):

- `docs/syscalls-and-copies.md:5–6` ("`ceil(R/B)` for batched io_uring
  with multishot receive") is attributed by that document to the
  analytical model in `io-uring-primer.md`. It is not a claim about
  ringline.

Proposed fixes a second reader found incomplete:

- PL3: waiting for the UDP send freelist to refill needs `SendUdp` and
  `SendMsgUdp` arms in `handle_shutdown_cqe`; without them the wait always
  runs to the shutdown bound.
- PL7: making `forward_push` refuse a closing sink also makes
  `forward_take_accumulated` (`mio/driver.rs:792–812`) drop the bytes it
  has already consumed; it must test the sink first.
- D12: a clamp must exclude the empty-input end-of-stream call, or the
  `with_data_result` rustdoc (`io.rs:2804–2808`) must change with it.
- D16: `docs/syscalls-and-copies.md:183` needs the same correction as
  `CLAUDE.md`.
- F26: the drop-order wording is in five more places (D19).

## What the audit did not cover

Platforms and kernels:

- macOS. Every mio result is mio on Linux 7.2.6. F6's `SO_NOSIGPIPE` half,
  and any mio behaviour that differs under kqueue, was not looked at.
- Kernels other than 7.2.6. F8 (`SendMsgZc` on `AF_UNIX`), F9 and the
  five-run results in F23 and L6 are measurements on that kernel only.
  CLAUDE.md's Domain Invariant 8 describes different close behaviour before
  6.13; nothing here ran there.
- One architecture (arm64), one host, loopback and Unix sockets only. No
  NIC, so GRO and GSO were exercised only as the loopback path implements
  them.

Not run by the auditor:

- The kernel triggers for PL1–PL9 and the live sequences for F15. PL10's
  trigger was run later, in #886.
- F4's two reading-only parts, F26's overflow, and the io_uring cause of
  F23.
- F6 on the reset-then-send path and at the other write sites `finish_close`
  reaches.
- F8 through `forward_recv_buf`, `forward_to_conn` to a Unix sink, and
  `send_chain` with a guard; the client crates' `set_with_guard` over a Unix
  socket.
- F11 through `recv_from` followed by `recv_batch` on a live socket (the
  unit test calls `for_each_segment` on a constructed entry).
- io_uring TLS receive after the hangup poll, and every TLS variant of the
  reader findings (F20, F21) and of the forward findings (F12, F13; F2's
  TLS variant was tested by its fix only).
- Any reproduction under load, with more than two workers, or repeated
  enough to find an intermittent failure. A single passing run of a control
  is the evidence that a control passes.
- The documentation findings (D1–D23), the limitations L7–L17, and the
  items marked "second reader": those were checked by reading twice, not
  run, apart from the runs D2, D3 and D17 cite. The second readers' own
  lists of what they did not verify are carried into the items: the
  kernel's result for the hangup peek (D15), the body of the `SendMsgZc`
  error handler (D17), `Vec` behaviour above `isize::MAX` (L8), and a TLS
  handshake over a Unix socket (D23).

Code no reviewer read, by the reviewers' own lists:

- The TLS engines: `tls/buffered.rs` send halves, most of
  `tls/unbuffered/mod.rs`, `tls/backend_uring.rs:330–540`,
  `tls/backend_mio.rs`, `tls/ciphertext.rs:500–747`. R1c, R10 and the TLS
  rows of Q2 rest on the arm call sites and the receive feeds only. Whether
  ringline-tls 0.1.2 can record a peer's close_notify before the handshake
  completes was settled after the audit, by the F1 fix's review: it cannot
  (see F1).
- `run_shutdown`'s handling of slab entries and guards at worker exit
  (read for UDP only, PL3).
- `buffer/send_copy.rs`, `buffer/send_slab.rs`, `engine/uring.rs`
  (`push_sqe128`, when a push is refused), `handle_connect`.
- `worker.rs` UDP bind and address code (UM40–UM43).
- `recv/arrival.rs:330–501` (the merge at the 1024-entry cap, RM51, and
  `trim`).
- Most test bodies. Reviewers cited tests by name from the invariant list;
  for one commit only (#804) did a reviewer check that the test fails with
  the fix reverted. Whether the existing tests reach what their names say
  was not audited, apart from F25.
- Of the 45 commits since `6ea67e6c`, four diffs were read (#804 in full,
  #784, #792 and #794 in part). For the rest the reviewer compared the
  commit message with the code at `6851de26`.

Invariants and stated properties left unchecked:

- Q1 rows S4, S5 and T3 of the send-path record; T1 and T2 for the chain
  builders.
- RM4, RM5, RM15, RM36, RM37, RM38, RM55, RM56, RM59, RM60; SM10 on
  io_uring, SM11; UM7, UM10, UM27, UM40, UM41, UM42. RM36–RM38 are the
  receive metrics: no reviewer checked that a counter moves when its event
  happens.
- CLAUDE.md Domain Invariants 1, 2 and 4 against the code; 3 and 6 in part.
- Docs not compared with the code beyond the lines named in the working
  reports: `docs/write-half-design.md`, `docs/half-close-design.md`,
  `docs/half-closed-send-wait-design.md`, `docs/send-backpressured-design.md`,
  `docs/send-capacity-fifo-design.md`, `docs/copied-send-reservation-design.md`,
  `docs/connection-handle-ownership-design.md`,
  `docs/tls-unbuffered-design.md`, `docs/syscalls-and-copies.md` outside the
  receive rows and three send rows, `README.md` and `CHANGELOG.md` outside
  the lines the findings cite. The measured numbers in the docs were not
  checked against anything.
- Q4 across backends for `forward_recv_buf`, `send_backpressured` past its
  first poll, and `submit_batch_await` beyond the empty-batch check.

Out of scope, so not looked at: the close path as such, the acceptor, disk
I/O, NVMe, QUIC, and the client crates' buffering.

The invariant list itself was not reviewed by the owner (Method step 1), so
a property the owner needs and no document states is not in it.

## Reproductions

The audit adds only this record and the lists file to the repository.

- The reproduction tests are a patch against `6851de26`, 14 files: unit
  tests added to the test modules of `ringline/src/accumulator.rs`,
  `ringline/src/backend/mio/event_loop.rs`,
  `ringline/src/backend/uring/event_loop.rs` and
  `ringline/src/runtime/mod.rs`, two existing UDP tests in
  `uring/event_loop.rs` changed for the F25 mutation (each `return` replaced
  by a panic), and ten new files
  `ringline/tests/audit_{contracts,forward,guard_send,interplay,recv_cap,sigpipe,tls_connect,tls_fin_before_handshake,udp,unix}.rs`.
  The audit tests assert the expected behaviour and fail at `6851de26`.
  The controls pass, as do three others:
  `a_forward_ended_by_a_reset_is_told_apart_from_a_fin` and
  `a_send_after_shutdown_write_does_not_report_success`, and
  `a_send_after_shutdown_write_does_not_raise_sigpipe`, which asserts
  nothing and prints what it saw.
- The patch, the run logs and the reviewers' working reports are on the
  auditor's host under `~/.cache/ringline-audit-6851de26/`
  (`audit-repro.patch`, `repro-*.log`, `working/`). They are not in the
  repository. A fix PR for a finding should carry that finding's test.
- Run with `cargo nextest run -p ringline --locked --test <name>
  --no-fail-fast -j 2` for the integration files and `--lib audit_` in place
  of `--test <name>` for the unit tests, adding `--features force-mio` for
  mio. `-j 2` keeps
  the io_uring tests under `RLIMIT_MEMLOCK` on this kernel.
