# 2026-11: Audit of the send and receive paradigms — the long lists

Companion to [the audit record](2026-11-send-recv-paradigms-audit.md). The
record states the short-id invariants (R, P, Q, A, U) in full and cites the
lists below by id. Three agents wrote these lists while confirming the
auditor's draft invariants against the docs, rustdoc and test names; the
auditor edited only the headings and path prefixes. Every `file:line` is at
`6851de26`. Short file names: `io.rs` is `ringline/src/runtime/io.rs`;
`driver.rs` and `event_loop.rs` are under `ringline/src/backend/uring/`
unless prefixed `mio/`; `config.rs`, `handler.rs`, `worker.rs`, `error.rs`,
`metrics.rs`, `connection.rs`, `accumulator.rs` are under `ringline/src/`;
"the record" in the send lists is `2026-11-send-path-audit.md`.

Source tags: D design doc or CLAUDE.md, C rustdoc or code comment, T a test
asserts it, I inferred. "(E)" and "(earlier read)" mark a line the agent
cited from an earlier read without re-opening it.

## RM1–RM71: receive properties stated in the sources

Reader callbacks and re-entrancy
- RM1. A reader closure can be called more than once per call. `io.rs:2772` "The closure must therefore be safe to call multiple times (`FnMut`)." C
- RM2. A second read, or a read during a forward, on one `RecvHalf` does not compile. `io.rs:2314` "`with_data`, `with_data_result` and `with_bytes` hold the borrow the same way, so a second read is a compile error too" C, T (compile_fail doctests `io.rs:2294–2324`)
- RM3. `Connection` is not `Copy`, `Clone` or `Send`. `io.rs:2489` "Not `Copy`, not `Clone`, and `!Send`, so one task owns one connection." (earlier read) C
- RM4. `offer_for_park` is declined from inside the connection's own reader callback or while the runtime holds received bytes, and the decline is counted. `io.rs:2909` "An offer is ignored when it is made from inside one of the connection's reader callbacks (`with_data`, `with_bytes`, `try_with_data`), or while the runtime holds received bytes for the connection"; `io.rs:2921` "`metrics::park_diag::OFFER_DECLINED` counts offers ignored" C, T (`an_offer_from_inside_a_reader_callback_is_declined`)
- RM5. Arriving data clears a park offer. `io.rs:2904` "The offer is cleared when more data arrives" C, T (`arriving_data_withdraws_the_park_offer`)
- RM6. A nested reader callback restores the outer connection's marker on exit. `io.rs:127` "Marks `conn_index`'s reader callback as running until dropped, then restores the previous value." C, T (`a_nested_reader_callback_restores_the_outer_connection`)
- RM7. `forward_recv_buf` sends and consumes nothing on `Err`, and returns `NotConnected` on a stale handle. `io.rs:3295` "`NotConnected` if this handle is stale... Nothing is sent or consumed on `Err`." C, T (`forward_recv_buf_on_a_closing_connection_commits_nothing`)

`NeedAtLeast`
- RM8. `NeedAtLeast(n)` only reserves; a receive that returns fewer bytes still wakes the reader. `io.rs:52` "`with_data` and `with_bytes` only reserve with `additional`, so an `additional` that is too large costs memory."; `driver.rs:148` "A receive that returns less wakes the task like any other, and its parser sees the bytes so far." C, T (`recv_direct.rs:358`)
- RM9. With `need >= recv_direct_region`, a plaintext buffer is grown to hold the rest of the message before the receive. `driver.rs:146` "When it is at least `recv_direct_region`, a plaintext connection's buffer is first grown to hold the rest of the message." C
- RM10. The reserve target is clamped to the cap. `ringline/src/accumulator.rs:295` "Records a high-water total-size target — clamped to `max_size`" C

After close, abort, or on a stale handle
- RM11. `with_data_result` on a stale future is `Ok(0)`. `io.rs:2791` "or this future is stale: the connection slot has been closed and reused." C
- RM12. `recv_ready` on a stale future resolves. `io.rs:3808` "Stale future from a reused slot — synthesize "ready" so the caller's loop sees the closure and terminates." C
- RM13. A stale `ConnStream` read is `Ok(0)` and registers no waiter. `stream.rs:120` "Stale stream: the connection this stream was created for is" ... `:123` "connection's bytes and hijack its recv wakeups. Report EOF," C
- RM14. `eof_truncated` and `peer_closed` are false on a reused slot. `io.rs:3012` "it returns `false` for plaintext connections, for clean TLS shutdowns, and once the slot has been reused."; `io.rs:3033` "Returns `false` outside the executor and once the slot has been released or reused." C
- RM15. A stale reader does not touch the arrival log. `docs/recv-arrival-times-design.md:178` "A reader whose connection generation no longer matches returns without touching the log" D
- RM16. `with_data_result` returns `Err` for a socket read failure, a failed write, the cap, and an arm failure, only for the generation that recorded it; `with_data` returns `0` for all. `io.rs:2795` "the socket read failed with a non-`WouldBlock` error... or the runtime closed the connection on its own account: a write to it failed (the write's error), a message ran past `recv_accumulator_max` (`QuotaExceeded`), or on io_uring a receive could not be armed."; `io.rs:2816` "`with_data` keeps returning `0` for both cases" C, T (`local_abort_errors.rs:138`, `:184`, `:238`)
- RM17. A send after the FIN to a fully closed peer aborts the connection, and the reader sees that error. `docs/half-close-design.md:62` "A peer that fully closed answers with a reset, which the next send reports; the connection then aborts with that error, and a reader on `with_data_result` sees it." D, T (`half_close.rs:189`)
- RM18. No receive is armed after the end of the read half. `docs/half-close-design.md:141` "No receive is armed after the FIN." D
- RM19. A half-open idle connection does not spin the event loop. T (`half_close.rs:256`)
- RM20. `peer_closed()` is true exactly when a read would resolve `0` or an error without parking. `io.rs:3027` "A read made once this is true resolves `0`, or the error, without parking" C
- RM21. `is_alive()` does not turn false at the FIN. `docs/half-close-design.md:49` "It no longer turns false at the peer's FIN, only when a close has been requested." D
- RM22. A close_notify in the same feed as the last handshake flight still spawns the task, which reads what arrived and then `0`. `event_loop.rs:1295` "The peer's close_notify came in the same feed as its last handshake flight. Handle it as the `Closed` arm does: the task reads what arrived, then EOF." C, T (`a_close_notify_with_the_handshake_finishes_the_read_half_and_requests_no_close`)

Arming limits
- RM23. A receive is armed only after the parser has seen every buffered byte. `driver.rs:138` "Called by a receive future that parks, after its parser has seen every buffered byte: the receive detaches the accumulator's buffer, so arming earlier would hide buffered bytes from the parser until more arrive." C
- RM24. No receive is armed while a park is pending; an abandoned park re-arms the hangup poll and wakes the reader. `docs/recv-direct-design.md:592` "`arm_direct_recv_or_close` refuses to arm while a park is pending"; `:597` "An abandoned park arms the hangup poll again and wakes the reader" D, T (`abandoning_a_direct_park_rearms_the_poll_and_allows_a_receive`, `abandoning_a_direct_park_wakes_the_reader`)
- RM25. A park cancels the in-flight receive and the hangup poll, and installs only once neither is armed. `docs/recv-direct-design.md:588` "`begin_park` cancels the direct receive of a parked read, if one is in flight" D, T (`a_direct_park_cancels_the_receive_and_the_poll_before_the_install`, `a_hangup_peek_in_flight_holds_off_the_park`, `a_tls_park_waits_for_the_receive_to_end`)
- RM26. A connection that uses `forward_recv_buf`, holds `forward_hold_cap` slab entries, and sits on a slab over half used arms no receive, and is armed when that changes; TLS is not held. `docs/recv-direct-design.md:633` "arms no receive when a read parks, and arms it when that changes (#733)."; `io.rs:3289` "A TLS connection is not held" D, C
- RM27. With `defer_recv_arm`, the worker does not block while a deferred receive is queued. `config.rs:969` "the worker always defers and does not block while a deferred receive is waiting." C, T (`a_deferred_recv_arm_keeps_the_worker_from_blocking`)
- RM28. A deferred arm is skipped for a recycled slot or a reader no longer parked; entries are armed newest first; an arm that closes wakes the reader. `event_loop.rs:1111` "for connections still in the slot they were deferred in whose reader is still parked. An arm that closes the connection wakes the reader."; `:1119` "Newest first: a reader that parked twice arms with its latest `need`" C
- RM29. `defer_recv_arm` is io_uring only. `config.rs:972` "io_uring only; the mio backend ignores it." C

Hangup detection
- RM30. The hangup poll is armed when a direct or TLS connection opens. `driver.rs:308` "Arm `conn_index`'s hangup poll (`OpTag::HangupPoll`) once it is open, on a direct or a TLS connection." C
- RM31. The poll and peek consume no bytes. `docs/recv-direct-design.md:339` "the hangup poll and peek below take no bytes." D
- RM32. A peek error is kept and reported by whatever later finds the end. `event_loop.rs:1524` "A peek error is kept in `hangup_error`, because the peek cleared the socket's pending error and whatever later finds the end has to report it." C, T (`recv_direct.rs:1300`, `:1631`)
- RM33. A recheck peek runs once nothing is buffered, armed or parking, and before a tickless worker blocks. `event_loop.rs:1628–1633`. C, T (`recv_direct.rs:1533`, `a_recheck_waits_for_a_pending_park`)
- RM34. `-ECANCELED` on the poll changes nothing; on a receive with the connection open it wakes the reader. `event_loop.rs:1457` "`-ECANCELED` comes from the close's cancel lead or worker shutdown and changes nothing."; `:1244` "Cancelled with the connection open: the task re-arms when it parks again." C
- RM35. On TLS, after the poll fires the receive is re-armed after every completion until the end is read. `event_loop.rs:1472` "A TLS connection reads the rest of the stream through its receive: re-armed after every completion from here until it reads the close_notify, returns 0 at the FIN, or fails." C

Metrics
- RM36. `ringline/recv_direct` maintains `ARMED`, `KNOWN_LENGTH`, `BYTES`, `STALE`, `POOL_REUSED`, `POOL_ALLOCATED`, `HANGUP`. `docs/recv-direct-design.md:664–671`. D
- RM37. Copies on a direct connection count in `recv_ring` `BYTES_COPIED`. `docs/recv-direct-design.md:671`. D, T (`recv_direct_copies.rs:136`)
- RM38. `recv_arrival::CLAMPED` counts at most once per reader call. `docs/recv-arrival-times-design.md:189` "a reader call counts at most once" D
- RM39. Every poll, peek or receive push failure counts `ring::RECV_ARM_FAILURES` (`docs/recv-direct-design.md:373`). D

Accumulator and buffers
- RM40. `frozen` is `None` or non-empty. `accumulator.rs:49`. C
- RM41. `append` past the cap leaves the contents intact. `accumulator.rs:95` "`append` rejects data that would push `buf.len()` past `max_size`, leaving the existing contents intact" C
- RM42. `compact_at_message_start` does not allocate and does nothing while a `Bytes` from the allocation is alive or a frozen remainder is held. `accumulator.rs:150` "`try_reclaim` does not allocate, and does nothing while a `Bytes` taken from the allocation (`take_frozen`, a forward's guard) is alive. Returns early while a frozen remainder is held." C
- RM43. A compaction moves at most a quarter of the grown capacity. `CLAUDE.md:255` "at most a quarter of the capacity it has grown to" D
- RM44. A closed connection's accumulator returns to its initial capacity. `accumulator.rs:321` "Discard all data and the allocation, and allocate the initial capacity again. Called when a connection closes" C
- RM45. While a buffer is detached the accumulator is empty, and `detach_for_recv` returns `None` at the cap. `accumulator.rs:694`, `:698`. C
- RM46. `recv_direct_held` is zero with no direct receive in flight. `connection.rs:138–142` (earlier read). C
- RM47. A `with_bytes` view consumed whole gives its allocation back to the next receive when no slice is alive. `docs/recv-direct-design.md:449–453`. D, T (`recv_direct_alloc.rs:158`, `:172`)
- RM48. A pool borrow takes the smallest free buffer that fits, at most twice the size it would allocate. `accumulator.rs:401`. C
- RM49. A `put_back` remainder is copied at most once more. `accumulator.rs:631`. C
- RM50. The arrival is recorded before the bytes are attached. `event_loop.rs:1147` "The arrival is recorded before the bytes are placed, while `recv_direct_held` still counts the bytes the buffer held." C (recorded as untested, limitation 2)

Arrival log
- RM51. A log holds at most 1024 entries; a push at the cap merges the two oldest. `arrival.rs:46` "Entries a log holds before a push merges its two oldest." (earlier read) C, T (`a_full_log_merges_its_two_oldest_entries`)
- RM52. `delivered` does not change during a reader call. `docs/recv-arrival-times-design.md:141`. D
- RM53. A dropped reader future leaves `latest` unchanged. `docs/recv-arrival-times-design.md:180`. D
- RM54. A reused slot starts with an empty log; a log drained without readers is trimmed. T (`a_reused_slot_starts_with_an_empty_arrival_log`, `a_log_drained_without_readers_is_trimmed_at_the_cap`)
- RM55. Reported times are no earlier than the peer's writes. T (`recv_arrival.rs:142`, `:182`)

`ConnStream`
- RM56. `poll_*` panics outside the ringline executor. `stream.rs:15` "via [`with_state`] and will panic if called from an external runtime." C
- RM57. `poll_read` first drains bytes cached by `poll_fill_buf`. `stream.rs:102` "Drain any leftover from a prior poll_fill_buf call first." C
- RM58. The read half is not reachable from a `ConnStream`. `stream.rs:69` "The read half is not" ... `:70` "reachable here, because a read would pass bytes cached by" C
- RM59. `poll_read` costs one copy and `poll_fill_buf` none. `stream.rs:44–45`. C
- RM60. Bytes taken by `poll_fill_buf` count as consumed when taken, and `ConnStream` sets no `recv_arrival`. `docs/recv-arrival-times-design.md:420`; `io.rs:3046`. D, C

Backend and TLS differences
- RM61. mio: after the FIN a readable event reads nothing, and a later reset is seen by the next send. `docs/half-close-design.md:111–115`. D
- RM62. mio forward: bytes past `len` go to the accumulator; already-buffered bytes are part of the forward; a gone sink gives `EPIPE` and the rest goes to the accumulator. `mio/event_loop.rs:680–685`, `:692–694`, `:699–701`; `io.rs:1359`. C
- RM63. TLS: `recv_ready` does not resolve on ciphertext that completes no record. `docs/send-while-receiving-design.md:169`. D, T (`recv_ready.rs:191`)
- RM64. TLS: a receive takes at most `recv_direct_region` bytes of ciphertext. `config.rs:944`. C
- RM65. TLS: a stale completion on a closing connection ends the receive in the TLS state. `event_loop.rs:1174` "A closing connection still has its TLS state: end the receive there (`tls_recv_cancel`) so `release_tls_state` finds none in flight." C
- RM66. TLS: a parked connection keeps its session and undecrypted ciphertext. `io.rs:2929`. C
- RM67. Unix connections receive directly on io_uring and read to `WouldBlock` on mio. T (`recv_direct.rs:711`, `mio_short_read.rs:115`); `mio/event_loop.rs:819`. C
- RM68. mio reads use an 8 KiB buffer. `docs/recv-direct-design.md:639–642`. D

Forward and wake
- RM69. One forward send is in flight at a time and at most one more chunk is buffered. `io.rs:3602`. C
- RM70. A forward's sends are ordered with other sends on the sink. `io.rs:2457`. C
- RM71. A dropped pending `RecvReadyFuture` costs one wake with nothing to read. `docs/send-while-receiving-design.md:160`. D


## RL1–RL28: receive limitations already recorded

A reviewer who met one of these reported it as a recorded limitation, not as
a finding, unless the code did something worse than the record says. Item
`n` is RL`n`. The ids in parentheses are the draft's: X1, X2 and X3 became
A1, A2 and A3, and R1 to R11 and P1 to P8 were split into lettered parts.

1. Worker exit can free a buffer the kernel holds (R2). `docs/recv-direct-design.md:606`; `:861` "Whether a cancelled direct receive can still be in flight when the worker exit bound runs out."; `:608` "I have not checked whether the cancel can still be pending after 10 s."
2. Untested items (R3, P8). `docs/recv-direct-design.md:747` "No test checks the `STALE` counter."; `:755` "Not tested: worker exit with a receive armed; the order of `record_arrival` and `attach_received` in `handle_recv_direct`"
3. `recv_ready` from another task takes the reader's wake (X1, R7). `io.rs:2327`.
4. A reader parked when another task calls `close()` gets no poll (X2). `io.rs:3256`; `docs/journal/2026-11-connection-close-audit.md:614` "A `close()` from another task or `on_tick` against a parked task gives it no poll at all."
5. Closing with unread bytes discards them and sends an RST (R4). `io.rs:3259` "Closing a socket with unread inbound bytes makes the kernel send an RST"
6. mio at the cap has already read the bytes it discards (R4, R5). `mio/event_loop.rs:725` "the bytes are already off the socket, so the stream cannot continue coherently."
7. An `append` comment allows dropped bytes (R4, R5). `accumulator.rs:116` "(or accept that intermediate-flush data is dropped, depending on context)". The wording predates direct receive; ask the owner whether such a path remains.
8. A buffer with no slab entry is leaked on purpose (R9). `driver.rs:298` "No entry to hold it: leak it rather than free memory a receive may write into."
9. A reset after the recorded end is seen by the next send, not by reads (R6, R7). `docs/half-close-design.md:56–58`; `io.rs:3025–3027`.
10. The `Ok(n)` echo can delay the error by one call (R6, P1). `io.rs:2804`.
11. A task that ignores `0` and reads again spins (P1). `docs/half-close-design.md:66–68`.
12. A TLS 1.2 peer may discard data sent after its close_notify (X2). `docs/half-close-design.md:127` "a TLS 1.2 peer may discard it"
13. A half-open connection has no time bound and no knob. `docs/half-close-design.md:142–144`, `:41–42`.
14. The `forward_hold_cap` hold can stall a reader, and stuck peers can fill the slab (R7). `io.rs:3286–3291`; `config.rs:1027–1033` "Guarded sends on that worker then fail with `send slab exhausted`"
15. A reader stays parked with no receive in flight during a pending park (R7). `docs/recv-direct-design.md:592`.
16. Until the hangup poll is armed, an end is seen only by the next receive (R7). `docs/recv-direct-design.md:378`.
17. A dropped parked read leaves a receive in flight, and `try_with_data` returns `None` (R1, P3, P5). `docs/recv-direct-design.md:340` "unless a read that parked was dropped before its receive completed"; `:616`.
18. No `MSG_WAITALL` (P1). `docs/recv-direct-design.md:781` "No `MSG_WAITALL`: a known length grows the buffer, and every completion wakes the reader." Decisions 7, 8, 10, 11, 13 and 15–17 at `:777–828` also bear on R1, R7 and R9.
19. Forward `EBUSY` after a `handle_close` drop (P7). `docs/recv-direct-design.md:854` "cannot clear `direct_forwarding`, so later forwards from its source are refused with `EBUSY` until the source's slot resets." It names `ForwardToFuture`, which has 0 hits; I do not know whether it still applies to `ForwardFuture`.
20. Arrival-time limits (P8). `io.rs:3052–3054` (`join!`); `docs/recv-arrival-times-design.md:190` "the reordering cases under "Limits" return wrong times without it"; `:417–420`; `:181–183`.
21. Only the innermost reader callback is detected (the `offer_for_park` decline). `io.rs:127` "Only the innermost running callback is recorded"; `io.rs:2915–2920`.
22. Close deferral has no time bound and no retry cap. Close audit L4 at `:620`, L5 at `:624`.
23. `defer_recv_arm` has measured costs and defaults to `false`. `config.rs:961–963`.
24. A dropped `recv_ready` costs one spurious wake. `docs/send-while-receiving-design.md:160–162`.
25. The u32 generation can wrap (R3). `connection.rs:99–105` (earlier read, not re-checked).
26. Cost and p99 items under "Not known". `docs/recv-direct-design.md:835–853`.
27. Park requirements are outside semver. `io.rs:2933–2938`.
28. `take_frozen` shrinks the tail capacity. `accumulator.rs:594–598`.


## Q1: the send-path audit's invariants as checked at `6851de26`

"Wording" says whether a commit since `6ea67e6c` changed the invariant
itself.

| Id | Wording | Commits touching the code | Reworded text (where changed) |
|---|---|---|---|
| S1 | same | #794 (slab `close_on_error` removed), #805 | |
| S2 | add exits | #784, #782, #792, #794 | Add: a batch that queues nothing takes nothing; the retained close_notify is placed or dropped once. Keep the caveat that a slot on `pending_copy_retries` at exit is freed with the pool (send-completion-design.md:121-123). |
| S3 | same | #792, #794 | |
| S4 | same | #792, #804 | |
| S5 | same | #787, #813 | |
| O1 | narrow | #777 | "...a plaintext chain is refused while sends are queued, in flight, parked or waiting; a TLS chain is one queued send" (io.rs:3340-3346). |
| O2 | narrow | #784 | Use Q3a and Q3b: order of submission to the queue, which for `send_backpressured` is its admitting poll. |
| O3 | same | none found | |
| O4 | changed | #777, #789, #776, #793 | "The FIN of `shutdown_write` goes out only after every send queued or in flight, and every part of a chain active, at the call has completed. A Shutdown SQE the ring refuses is retried from `pending_shutdown_retries` until pushed or the slot is released. A send made after the call is not ordered against the FIN. After a close is requested `shutdown_write` does nothing on either backend." |
| O5 | changed | #771, #782, #776, #789, #792 | "The Close SQE is submitted only when `!in_flight`, the queue is empty, no chain is active, no Shutdown is in the kernel or on `pending_shutdown_retries`, and no retained close_notify waits to be placed. A completion handler defers the close to `finalize_pending_closes`, which runs after the task poll; only `force_finalize_close` and the park install commit at once. After `close_submitted` no send SQE, resubmit or poll is pushed for the slot." |
| C1 | changed | #773, #775, #797, #784, #794, #804, #805, #809 | Add to the covered cases: a future first polled by another task after its creator returned and the connection closed; an empty `send` and a chain that submits nothing resolve `Ok(0)`. Replace "one on a connection the peer closed" with "one on a connection whose peer sent FIN (the FIN fails nothing) or reset". Accepted losses: worker exit, and a future dropped outside a task on its worker. |
| C2 | same | #794 | |
| C3 | changed | #773, #775, #797 | "A driver result overrides a provisional `Aborted`; between two driver results the first wins; `Abandoned` comes only from a future's drop and is freed by its completion; `remove_task` and `remove_connection` re-own a dead task's entries to `NO_OWNER` and leave their state; an entry is removed only by its future (taking the result or dropping). No growth from closed connections, except an entry whose future was dropped outside a task on its worker." Not checked against `send_completion.rs`. |
| C4 | one clause | #797 | "the head never has an owner that cannot be woken" needs an exception: a handed-off, unpolled future's entry is `NO_OWNER` until its next poll (test name `removing_a_connection_keeps_a_waiting_entry_its_task_handed_off_at_the_head`, `ringline/src/runtime/send_completion.rs:1253`; body unread). |
| T1 | widen | #781, #784, #786 | Add `build`, `forward_recv_buf` and chain `finish` to the "nothing queued" list. "On both backends" became true for mio with #781. A TLS encrypt failure is the exception: the connection closes and the buffer cannot be resent (io.rs:3151-3155). |
| T2 | changed | #786 | "A send wider than the whole pool is `InvalidInput` before anything is taken. On an io_uring plaintext connection so is copy data wider than one slot on any `send_parts` submit, `SendChainBuilder::copy` or a chain part, and a batch over 32 parts or 8 guards. A pool or slab shortfall is `Other` and retryable." |
| T3 | same | #790 | |
| W1 | one clause | #809, #805 | "...the wait ends at close; a peer's FIN does not end it, and a multishot poll can stay armed for the rest of the connection's life" (half-closed-send-wait-design.md:83-85). |
| W2 | same | none found | |
| W3 | same | #805 | |
| F1 | changed | #794, #804, #807, #769 | "A terminal send error aborts the connection on both backends: `read = Error`, the send's error reported once to a reader on `with_data_result`, close requested. A connection whose close was already requested is left as that close left it. Queued awaited sends are failed (mio: the write's error; io_uring: `ConnectionAborted` per the record, unverified after #794)." |
| F2 | scope | #789, #794 | Say "each send retry list". `pending_shutdown_retries` (#789) and `pending_close_retries` (close-audit L5) do not give up. |
| F3 | add | #787, #779, #789, #813 | Add: a Close the ring refuses at exit is retried; `pending_shutdown_retries` is cleared; a copy send on `pending_copy_retries` keeps its slot until the pool drops. |
| F4 | add | #768, #804, #808, #779 | Add: ready tasks are polled before pending closes drain (#768); `finish_close` reports its flush error to sends it leaves queued (#804) and sends close_notify only while the write half is open (#808). |
| close_notify row | new | #782, #790, #806, #808 | "On close of a TLS connection with its write half open, close_notify follows the queued sends and precedes the FIN. None follows `shutdown_write` on either backend. An alert the pool had no slot for is retained and placed by the close drain." |
| X1 | same | #788, #796, #809 (CLAUDE.md) | |
| X2 | same | #788, #789, #797, #798, #809 | The stale passages found are listed in the audit record under the documentation findings. |
| X3 | widen | #770, #777, #781, #784, #786, #788, #803, #807, #809, #814 | Add `shutdown_write`, `close`, `forward_recv_buf`, `forward_to_conn`, `WriteHalf` and `ConnStream`. |
| X4 | same | #799, #812 | |

L1-L10 status (record:1062-1156):
- L1 stands; now stated on `send` (io.rs:3145-3149).
- L2 closed by #794.
- L3 fixed by #805.
- L4 stands.
- L5 fixed by #792.
- L6 stands; now stated at io.rs:3871-3874.
- L7 fixed by #804.
- L8 fixed by #806.
- L9 stands.
- L10 closed by #797.


## Q2: contract table for the send entry points

| Entry point | Claim | Source |
|---|---|---|
| `send` | Copies into the pool and submits at the call | io.rs:3125-3126 |
| | Resolves `data.len()` "once this send's last byte has gone to the socket, or with the error that ended it"; plaintext length under TLS | io.rs:3126-3129 |
| | "Each future resolves with its own send's result, so several may be awaited at once." | io.rs:3129-3130; T `ringline/tests/awaited_send.rs:215-265` |
| | `NotConnected`: stale handle; io_uring once the Close is submitted; TLS once close_notify is queued | io.rs:3137-3140 |
| | mio: a send after `close` "is queued and flushed or discarded with the connection" | io.rs:3140-3141 |
| | io_uring `Other`: pool cannot admit the whole buffer, retryable; `InvalidInput`: wider than the pool; TLS bound checked before encryption, with one record of headroom | io.rs:3141-3149 |
| | mio: "a plaintext send never fails for pool reasons" | io.rs:3149-3150 |
| | On those errors nothing queued or transmitted | io.rs:3150-3151; T echo.rs:4747-4759 |
| | TLS encrypt failure: `Other`, connection closed on both backends, buffer not resendable | io.rs:3151-3155 |
| | SQ pressure: queued and retried; persistent starvation resolves `Err` and closes | io.rs:3156-3159 |
| | Drop: "does not cancel the send: the bytes still go out"; handed to another task it "resolves with the send's own result"; dropped outside a task its entry stays | io.rs:4136-4141 |
| | Parked connection: `NotConnected` | io.rs:2897-2899 |
| | Empty buffer resolves `Ok(0)` | T only, awaited_send.rs:278; not in the rustdoc |
| | Poll after completion panics | code only, io.rs:4184; not in the rustdoc |
| `send_nowait` | Copies and submits; no future | io.rs:3164-3165 |
| | "The errors of [`send`]"; starvation "surfaces only as the connection closing" | io.rs:3172-3174 |
| `send_parts` (all) | "On the mio backend every part is copied." | io.rs:3189 |
| | io_uring plaintext: copy parts of one batch must fit one slot, else `InvalidInput`; 32 parts, 8 guards | io.rs:3192-3196 |
| | Guards below `send_zc_threshold` are gathered into one slot when a slot is free and the gather fits; otherwise zero-copy | io.rs:3196-3200 |
| | `Other` when the pool, or the slab for a zero-copy batch, has no free entry; `NotConnected` as for `send` | io.rs:3200-3202 |
| | TLS batch: gathered, encrypted, "queued in order" | io.rs:3202-3204 |
| `build` | Fire-and-forget; a zero-byte batch queues nothing and returns `Ok(())` on a live connection, `NotConnected` on a stale or closing one | io.rs:3187-3191; handler.rs:3812-3814 |
| | mio: "concatenating all copy parts" | io.rs:1787 |
| `submit_batch` | One SQE; over limits "the entire batch is rejected ... (`InvalidInput`; nothing is sent, guard parts are dropped): the call never consumes a prefix"; returns `parts.len()` | io.rs:1667-1673 |
| | mio: "guard data is copied" | io.rs:1806 |
| `submit_batch_await` | Returns a `SendFuture` "that resolves when the batch has been sent"; limits as `submit_batch`; empty or zero-byte batch `InvalidInput` | io.rs:1699-1711; mio io.rs:1831-1835 |
| | Resolves with the total length of its parts | handler.rs:3791-3792; T awaited_send.rs:224, 233 |
| `send_backpressured` | Lazy: nothing submitted or queued until polled; unpolled drop does nothing | io.rs:3218-3219, 3864-3865; T echo.rs:3197 |
| | Joins a per-worker FIFO on first poll; released at the head when the pool covers its worst-case cost; "strictly first-come-first-served per worker" | io.rs:3865-3869; T echo.rs:2803-2816 |
| | Head submits only when its task polls | io.rs:3871-3874 |
| | `InvalidInput` before joining if it can never fit; TLS cost is the ciphertext bound | io.rs:3876-3879; T echo.rs:3245 |
| | `BrokenPipe`: write half shut down, or shut down while waiting | io.rs:3892-3893 |
| | `ConnectionAborted`: closed while waiting or in flight; `NotConnected` (io_uring): TLS close_notify queued, or the close committed while waiting; either may appear | io.rs:3894-3905; T tls_echo.rs:1270-1273 |
| | Drop while waiting removes the entry and hands on the head; drop after submission abandons the result; "The future never submits twice." | io.rs:3883-3886; T echo.rs:3062 |
| | Resolves the plaintext length passed | io.rs:3909-3910 |
| | A waiter does not hold off a close | io.rs:3899-3901 |
| | Owner refreshed on every poll | C `docs/send-backpressured-design.md:92-96`; T echo.rs:2945, 3004 |
| `send_chain` | io_uring only | `#[cfg(has_io_uring)]` io.rs:3369; not in the doc text |
| | Resolves "with the bytes the chain sent, or `Ok(0)` when the closure submitted nothing" | io.rs:3336-3338; T awaited_send.rs:284 |
| | Plaintext: `finish` returns `WouldBlock` while a send is in flight or queued or another chain is active | io.rs:3340-3342; handler.rs:4290-4291 |
| | TLS: gathered, encrypted as one send, queued behind earlier sends, not refused | io.rs:3342-3346; handler.rs:4190-4192 |
| | Plaintext copy data wider than a slot: `InvalidInput`, "submits nothing" | io.rs:3348-3351 |
| | "A chain that fails closes the connection", including a ZC part failing `ENOMEM` or `EAGAIN` | io.rs:3353-3357; T `ringline/tests/zc_chain_enomem.rs:115` |
| | Partial part then failure: `WriteZero`, "whatever the cause" | io.rs:3361-3363 |
| | "`close` waits for a running chain, and a chain waits for the peer to read." | io.rs:3365-3366 |
| | `NotConnected` if stale or the Close has been submitted | handler.rs:4293-4295 |
| `send_chain_nowait` | Returns the closure's value; TLS as `send_chain`; a failed chain closes | io.rs:3377-3386 |
| `forward_recv_buf` | io_uring: whole accumulator is detached and sent under a guard (copied below the threshold); otherwise copied as `send_nowait` | io.rs:3274-3277 |
| | mio: always copied; TLS encrypted on both | io.rs:3279-3282 |
| | io_uring hold rule at `forward_hold_cap`; TLS not held and fails on pool exhaustion | io.rs:3284-3291 |
| | `NotConnected` stale; errors of `send_nowait`; `Other` if the slab is full; "Nothing is sent or consumed on `Err`." | io.rs:3295-3299 |
| `forward_to_conn` (sink) | Sink borrowed `&mut` for the forward's life | io.rs:2412-2414 |
| | TLS sink refused `EPROTOTYPE`; `EBUSY`; `EPIPE` stale; "without having installed anything" | io.rs:2435, 2439-2442; T tls_echo.rs:2081, echo.rs:7796 |
| | `Err(EPIPE)` if the sink closes mid-forward; "the sink's generation is checked before every write" | io.rs:2444-2447 |
| | io_uring: through the sink's queue, one send in flight, ordered with other sends; a send that cannot be submitted resolves the forward with that error and leaves the chunk buffered | io.rs:2453-2462 |
| | io_uring drop: "lets a chunk already submitted go out and leaves the rest buffered" | io.rs:2462-2463, 3753-3754 |
| | mio: copied into a queued send; source stops reading at `forward_hold_cap` | io.rs:2467-2471 |
| | mio drop: queued bytes stay queued, "no further bytes are taken from the source" | io.rs:3553-3561; T echo.rs:7673 |
| `ConnStream::poll_write` | Copies with `send_nowait`, does not wait for completion | stream.rs:21-23 |
| | Caps at one slot: "oversized writes become partial writes" | comment, stream.rs:215-216 |
| | Never `Pending`; a pool error is `Ready(Err)`; empty buffer `Ok(0)` | code only, stream.rs:209-223 |
| | Panics outside the executor | stream.rs:13-15 |
| `poll_flush` | Always `Ready(Ok(()))` | code and comment only, stream.rs:226-229 |
| `poll_close` | First call runs `shutdown_write`; "The full close happens when this stream drops or the connection task returns." | comment, stream.rs:231-239; T `ringline/tests/stream_echo.rs:300` (body unread) |
| `shutdown_write` | "Sends a TCP FIN to the peer. The read side remains open." | io.rs:3306 |
| | Waiting `send_backpressured` fails `BrokenPipe`; submitted sends and chain parts are left alone, "the FIN is ordered behind them"; "Plain `send` is unaffected either way." | io.rs:3308-3313; T echo.rs:7348-7352, 3333 |
| | io_uring: runs on io-wq; a close issued before it finishes waits | io.rs:3315-3317 |
| | Deferred as `ShutdownPending` while sends or (io_uring) a chain are outstanding | connection.rs:66-68 |
| | A refused socket shutdown is counted and not reported | connection.rs:72-74 |
| | Repeat call is a no-op | `docs/write-half-design.md:56` |
| `close` | Sends drain, then TLS close_notify, then FIN; no time bound | io.rs:3239-3242 |
| | io_uring: no alert if a close is already pending; "mio writes the alert at teardown regardless"; none after `shutdown_write` | io.rs:3242-3245 |
| | TLS send after `close`: io_uring `NotConnected`; mio queued ahead of the alert | io.rs:3247-3249; T tls_echo.rs:1261-1266 |
| | Task dropped when the close completes; code after `close()` runs "only until its next `.await`"; a parked task closed from elsewhere is dropped unpolled | io.rs:3251-3257 |
| | Unread inbound bytes cause an RST and can lose the tail | io.rs:3259-3262 |
| | Nothing if already released or outside the executor | io.rs:3264-3266 |


## SM1–SM20: send properties stated in the sources

Each is promised in the sources and absent from both lists.

- SM1 (D). A zero-copy guard is kept alive until the kernel's notification. `ringline/src/guard.rs:7-8` "The guard keeps registered memory alive until the kernel ZC notification arrives."
- SM2 (D). A guard is dropped when its batch is refused, or gathered on TLS.
  - io.rs:1670 "guard parts are dropped".
  - handler.rs:4488-4490 "its bytes are copied into the chain's plaintext in `add`, and the guard is dropped there."
- SM3 (C). A panic in a guard's `Drop` does not end the worker. guard.rs:82-83 "`Drop` is user code, and a worker can run it from a completion handler, where a panic would end the worker."
- SM4 (D). `GuardBox::new` panics above 64 bytes or 8-byte alignment. guard.rs:36-37.
- SM5 (D, T). A `SendFuture` first polled by another task after its creator returned and the connection closed resolves with the send's own result.
  - io.rs:4137-4139.
  - `ringline/src/backend/mio/event_loop.rs:2842, 2904, 3106`.
- SM6 (D, T). Dropping a `SendFuture` does not cancel the send. io.rs:4136-4137.
- SM7 (D, T). A write failure closes the connection and is reported to the reader, on both backends.
  - connection.rs:78-80 "which closes the connection and reports the error to a reader parked on `with_data_result`, on both backends".
  - local_abort_errors.rs:138.
- SM8 (D). That error is reported once; the next `with_data_result` is `Ok(0)`. io.rs:2803-2804.
- SM9 (T). A task woken by a FIN that arrives in the same batch as its last send's CQE can still send. `ringline/src/backend/uring/event_loop.rs:9589` `a_fin_batched_with_the_last_send_cqe_leaves_the_close_to_the_task` (name only, body unread).
- SM10 (D, T). No close_notify follows a write shutdown on either backend.
  - io.rs:3244-3245.
  - tls_echo.rs:1160-1164.
- SM11 (T). On io_uring a panicked handler sends no close_notify. tls_echo.rs:1483-1488.
- SM12 (D). After the peer's FIN nothing is armed on the socket, so a later reset is seen only by the next send. io.rs:3026-3027 "a reset that arrives then is seen by the next send, not here".
- SM13 (T). A half-open idle connection costs no event-loop iterations. half_close.rs:251-256.
- SM14 (D). The `ConnStream` write rules in the Q2 table: `poll_write` never pends, `poll_flush` is immediate, `poll_close` half-closes once. They have no rustdoc, and the `futures_io::AsyncWrite` contract for flush is not discussed anywhere I read.
- SM15 (D). Sends on a parked connection return `NotConnected` until the future is dropped. io.rs:2897-2899.
- SM16 (D). Once a worker sees a shutdown request, a task awaiting a send is dropped without its result. io.rs:978-979 "a task woken after the worker's last poll pass is dropped without running the code after its `.await`".
- SM17 (D, T). Sends queued before the last half drops arrive ahead of the close.
  - Close-audit invariant 12, `docs/journal/2026-11-connection-close-audit.md:91-92`.
  - `ringline/tests/close_on_drop.rs:277`.
- SM18 (D). Two sends can be in flight from one half. connection-handle-ownership-design.md:300-302 "two sends can still be in flight from one half".
- SM19 (D). Every send's completion is checked against the slot generation. PRINCIPLES.md:24-25. Covered by record C2.
- SM20 (D). A panic on some inputs is stated and a fallible variant exists. PRINCIPLES.md:171-173.
  - `SendFuture` and `BackpressuredSendFuture` panic when polled after completion (io.rs:4184).
  - `shutdown_write` runs `with_state` (io.rs:1481), while `close` returns silently outside the executor (io.rs:1532-1535).
  - Neither panic is in the rustdoc. I did not read `with_state`.


## Send limitations already recorded

- Send-path L1 (io.rs:3145-3149), L4, L6 (io.rs:3871-3874), L9 (record:1062-1116).
- Close-audit L2-L6 (`docs/journal/2026-11-connection-close-audit.md:611-629`):
  - a task is dropped at its first await after `close()`;
  - unread inbound bytes cause an RST;
  - the close drain has no time bound;
  - `pending_close_retries` has no cap;
  - `Send`/`TlsSend` CQEs carry a 16-bit generation.
- A chain part larger than the send buffer's room cannot reach a half-closed peer, and a chain holds an io-wq thread while it waits (io.rs:3357-3359; CLAUDE.md:240).
- A chain's partial failure is always `WriteZero` (io.rs:3361-3363).
- A `SendFuture` dropped outside a task leaves its table entry for the worker's life (io.rs:4139-4141).
- At worker exit a lost result is accepted (record:188).
- Below Linux 6.7 an unreleased zero-copy entry holds exit for 10 s and leaks its guards and the pool (send-completion-design.md:132-135).
- A copy send on `pending_copy_retries` keeps its slot until the pool drops (send-completion-design.md:121-123).
- mio: a send after `close` is "flushed or discarded" (io.rs:3140-3141).
- A send made after `shutdown_write` is "usually", not always, ahead of a parked FIN (connection.rs:80-82).
- `shutdown_write` reports no refusal; a refused socket shutdown is only counted (connection.rs:72-74).
- A TLS 1.2 peer may discard data sent after its close_notify (half-close-design.md:127).
- A task that ignores `0` spins; a task that never ends holds the slot (half-close-design.md:66-68, 142-144).
- One path remains where the alert does not leave after an accumulator overflow: "left as is" (record:724-732).
- L3's case is unreachable today (record:1080-1082).
- Nothing on io_uring was executed by the 11-07 audit (record:1160-1163).


## UM1–UM43: UDP properties stated in the sources

Receive buffers (io_uring):
- UM1. Each bound socket on each worker has its own provided ring; a socket with an empty ring stops reading and the worker's other sockets keep receiving. C `driver.rs:418-420` "one per socket and indexed like `udp_sockets`. A socket that runs out of buffers stops reading, and the others are unaffected." D `io.rs:5352-5353`. T `udp.rs:2876`.
- UM2. A socket out of buffers does not spin the worker, and a late reader receives what waited in the kernel buffer. D `CHANGELOG.md:1355-1356` "a socket out of buffers is re-armed when one returns. Until then its datagrams wait in the kernel receive buffer." T `udp.rs:3054`.
- UM3. A re-arm that cannot be submitted is retried and keeps the worker from blocking. C `driver.rs:2592-2594` "A submission that fails stays in `udp_awaiting_buffers`, for `return_udp_buffers` to retry once the ring has a free buffer." C `event_loop.rs:1093-1095`. T `event_loop.rs:5696` `a_failed_udp_rearm_is_retried`.
- UM4. `return_udp_buffers` runs each pass after tasks are polled and before the wait. C `event_loop.rs:468-470` "The wait below submits any re-arm, so a socket that ran out of buffers receives again without another completion to wake the worker."
- UM5. A bid is never returned twice. C `ringline/src/backend/uring/provided.rs:142-145` (E) "replenishing more buffers than are outstanding means a bid was returned to the ring more than once". T `double_replenish_trips_debug_assert`, same file.
- UM6. A queued datagram's payload pointer stays valid until its bid is replenished. C `event_loop.rs:4115-4118` "The buffer remains valid until `bid` is pushed to `udp_pending_replenish`".
- UM7. With `sqpoll`, returning a buffer never publishes a tail that exposes buffers the application holds. D `CHANGELOG.md:1241-1245`. T `writing_entry_zero_leaves_the_committed_tail` in `provided.rs` (E).
- UM8. The recv `msghdr` template is heap-stable for the life of the multishot, and the parser matches the kernel layout. C `driver.rs:71-75` "Must stay heap-stable for the lifetime of the multishot." T `ringline/src/backend/uring/abi.rs:262`.
- UM9. Worker exit unregisters every UDP ring before its memory is unmapped. C `driver.rs:2966-2968`. T `ring_drops_after_buffer_pools`, `driver.rs:3146` (E).
- UM10. Repeated launch and shutdown with a UDP bind leaks no fd. T `ringline/tests/udp_launch_fds.rs:1-2` (E).

Receive delivery:
- UM11. `recv_from` returns exactly one datagram per call, also under GRO. D `io.rs:5497-5498` "Each call returns exactly one datagram." C `io.rs:5753-5755`. D `CHANGELOG.md:2806-2807`.
- UM12. The buffer given to a `with_datagram` or batch callback is released when the callback returns and before the next datagram is dispatched. D `io.rs:5515-5516`, `5586-5587`.
- UM13. `recv_batch` resolves only with at least one datagram and handles at most `max` queue entries per poll; `max = 0` panics in debug. D `io.rs:5557-5561`; `5574-5575` (E).
- UM14. Under GRO, batch callbacks run once per datagram. D `config.rs:336-339` "callbacks still fire once per datagram."
- UM15. `recv_batch_timed` passes the time the driver first observed the datagram in user space; on io_uring that is one clock read per CQE batch. D `io.rs:5532-5535`. C `driver.rs:667-669`. T `udp.rs:2418`.
- UM16. On io_uring the queue capacity is `min(udp_recv_queue_capacity, ring_size)`; mio keeps the configured depth. C `event_loop.rs:249-257`. D `config.rs:1174-1180`.
- UM17. A datagram larger than the buffer is dropped on io_uring, its bid is returned, and the socket keeps receiving. C `event_loop.rs:4073-4075`. T `udp.rs:981`.
- UM18. A truncated control message (`MSG_CTRUNC`) does not drop the payload; it is delivered as one datagram on both backends. C `event_loop.rs:4103-4106`. C `mio/event_loop.rs:1316-1317`.
- UM19. GRO has no effect on `connect(2)`ed sockets on io_uring. D `config.rs:346-348`. C `event_loop.rs:4257-4258`.
- UM20. A failed `UDP_GRO` setsockopt fails launch on both backends. C `driver.rs:2274-2276` "Opt-in, so a failure is hard rather than silent". C `mio/driver.rs:1105-1107` (E).
- UM21. Config validation rejects bad UDP settings: buffer size outside (0, 262144] or below 160, below 66048 with GRO, a ring size that is not a power of two, a bgid range past `u16`, zero `udp_send_slots`, zero queue capacity. D/T `config.rs:609-668` and tests `1348-1402` (E).
- UM22. A zero-length datagram is delivered on an unconnected socket. T `udp.rs:1178`.
- UM23. A connected bind receives only its peer's datagrams on both backends. D `CHANGELOG.md:1639-1645` (E). T `udp.rs:2591`.
- UM24. A connected socket keeps receiving and sending after an ICMP port-unreachable. C `mio/event_loop.rs:1260-1264`. T `udp.rs:2746`, `2759`, `2772` (E).
- UM25. One receive waiter per socket, enforced at compile time; a half moved after an abandoned receive still receives. D `io.rs:5341-5344`. T compile_fail doctest `io.rs:5355-5367` (E) and `udp.rs:2818`.
- UM26. Dropping a `UdpSocket` or a half closes nothing. D `io.rs:5349-5350`. D `docs/public-context-types-design.md:248-249`.
- UM27. `UdpSocket` and its halves are `!Send`. D `io.rs:5340`; compile_fail doctests `5379-5387`, `5400-5408` (E).
- UM28. `on_udp_bind` runs once per socket per worker; a handler that exits or panics leaves the worker running. D `ringline/src/runtime/handler.rs:140-147` (E). T `udp.rs:1335`, `1470` (E).

Send:
- UM29. At most `udp_send_slots` sends are in flight per socket. D `io.rs:5627-5629`.
- UM30. Data larger than a copy-pool slot returns `Io(InvalidInput)`, never `PoolExhausted`. C `driver.rs:2429-2431`. D `io.rs:5695-5696`. T `udp.rs:875`.
- UM31. A full SQ returns `SubmissionQueueFull` with both slots released. D `error.rs:563-565`. No test.
- UM32. The sockaddr, iovec, msghdr and cmsg of a send live in the boxed slot until its CQE. C `driver.rs:26-28`, `34-37` "Heap-stable so the kernel's view (via `msg_control`) stays valid until the CQE arrives."
- UM33. A UDP send CQE carries `(slot_idx, pool_slot)` and no generation (`driver.rs:47-58` (E)). Inferred: that is sound only while UM26 holds.
- UM34. `send_ready` resolves on io_uring when a send slot is free. D `io.rs:5608`, `5612-5613`.
- UM35. On mio, `WouldBlock` is reported as `PoolExhausted`, and `send_ready` yields once before resolving. D `io.rs:5637-5638`. C `io.rs:6039-6043`.
- UM36. `send_to` on a connected socket to another address is sent on Linux and fails `EISCONN` on macOS. D `config.rs:1130-1132`.
- UM37. `send_to_gso` rejects a zero segment size and one larger than the data, and leaves the socket usable. D `io.rs:5694-5696`. T `udp.rs:2169`.
- UM38. A kernel send failure is counted in `udp::SEND_ERRORS` and is not returned to the caller. C `event_loop.rs:4171-4173`. The doc says only "fire-and-forget" (`io.rs:5625`).
- UM39. Shutdown with sends in flight completes, and a send to an unreachable peer does not stop the worker. T `udp.rs:1565`, `1958` (E).

Sockets and addresses:
- UM40. Each worker has its own socket per bind, and workers share the port through `SO_REUSEPORT`. D `io.rs:5338-5340`. T `udp.rs:1095` (E).
- UM41. An unconnected zero-port bind resolves to one port for all workers; a connected zero-port bind has one port per worker and reports `None`. D `worker.rs:178-181`. T `udp.rs:146`, `347`, `363` (E).
- UM42. `bound_udp_addr` is the first bind's address, or `None`. D `worker.rs:164-165`.
- UM43. `launch` fails on an invalid bind address or a failed `connect(2)`. D `config.rs:1129-1130`. T `udp.rs:2002` (E).

No source states the following, so they should not go on the list as invariants without an owner decision:
- The order of sends on one socket. Each is an independent SQE.
- What `send_to_gso` does when the kernel rejects the segment count or GSO is unavailable. The only visible effect is `SEND_ERRORS`.
- A short UDP send. The handlers do not compare the result to the length.
- That `Ok(())` means "submitted". `DATAGRAMS_SENT` is counted at submit.

Sources that disagree with each other (pick one before the audit, or each shows up as a finding):
- `io.rs:5559-5561` and `5892-5894` say the callback runs up to `max` times and the count is datagrams. `io.rs:5936-5939` says "`drained` counts entries (kernel recv completions)". Under GRO these differ.
- `io.rs:5613-5614` says `send_ready` on mio is "always immediately ready"; `io.rs:6039-6043` yields once.
- `io.rs:5534-5535` says the mio timestamp is taken "in the `recv_from` poll"; the code takes it in `handle_udp_readable` (`mio/event_loop.rs:1251`).
- `io.rs:5690-5691` says mio `send_to_gso` has "identical" observable behaviour. Its loop returns `Err` after earlier chunks were sent (`io.rs:5714-5734` (E)) and skips the slot-size check.
- `error.rs:549` says "per-worker send pools"; send slots are per socket.
- `ringline/src/completion.rs:40` says "Single-shot recvmsg for UDP sockets."; the driver arms it multishot.
- `CHANGELOG.md:2851` says "overload now surfaces as counted drops"; `metrics.rs:423-426` says the counter does not count at ring-size capacity. The newer text is `metrics.rs`.
- io_uring drops a truncated datagram. mio has no `MSG_TRUNC` check on either read path (`mio/event_loop.rs:1221-1338`) and reads into a 65536-byte buffer.
- A zero-length datagram is delivered on the unconnected path (UM22) but not on the connected io_uring path (`event_loop.rs:4200-4216`). No doc says so.
- io_uring ignores the `SO_REUSEPORT` setsockopt result (`driver.rs:2262-2271`); mio returns the error (`mio/driver.rs:1017-1103` (E)).


## UX1–UX19: Unix domain stream sockets

Design doc = `docs/half-closed-send-wait-design.md`. Its poll table is "Measured on Linux 7.2.6." (line 110).

Complete set of Unix-conditional code sites in `ringline/src` (grep for `is_unix`, `PeerAddr::Unix`, `AF_UNIX`):
- `acceptor.rs:143-144`
- `worker.rs:735`, `1891`, `2402`
- `backend/sockaddr.rs:42-58`, `85`
- `handler.rs:1316-1322`
- `backend/mio/event_loop.rs:1023`

No send or receive handler on io_uring branches on the transport.

Send path:
- UX1. A send waiting on a Unix peer that did `SHUT_WR` gets `RDHUP` without `POLLOUT`, moves to the multishot poll, and completes when the peer reads. D design doc 43-44 "Unix stream sockets behave the same way: `POLLRDHUP` on polls, a thread for `MSG_WAITALL`, and `-EAGAIN` for `MSG_DONTWAIT`."; 120 "| Unix peer `SHUT_WR`, full | `RDHUP` | `-EAGAIN` |". No Unix test in the repo for this row.
- UX2. A send waiting when a Unix peer fully shuts down is resubmitted on the multishot `POLLHUP` and fails `EPIPE` without waiting for the timer. C `event_loop.rs:3028-3029`. T `event_loop.rs:11086-11087` "`POLLHUP` without `POLLOUT` on a multishot poll is a Unix peer's full shutdown." D design doc 121.
- UX3. A send waiting when a Unix peer does `SHUT_RD` is reported by no poll and fails `EPIPE` within the 1 s backstop. C `event_loop.rs:3037-3039` "a poll does not report a Unix peer's `SHUT_RD`, where a send fails `EPIPE`." D design doc 93-95, 122, 248. T `ringline/tests/half_closed_send_wait.rs:520-523`.
- UX4. Zero-copy: a guarded send at or above `send_zc_threshold` on a Unix connection delivers its bytes. Inferred, not stated.
  - `SendMsgZc` is chosen by size only, and the only fallback is `-ENOMEM` (`event_loop.rs:3505-3511`).
  - `docs/ktls-design.md:711-712` records that "`io_sendmsg_zc` refuses on that bit" (`SOCK_SUPPORT_ZC`).
  - Whether AF_UNIX stream sockets carry that bit is not stated in the repo. I believe they do not, which would make the send fail `-EOPNOTSUPP` with no fallback. Unverified.
  - No test sends a guard on a Unix connection. This needs a test, then an owner decision.
- UX5. `TCP_NODELAY` is never set on an accepted Unix connection or a `connect_unix` socket. C `acceptor.rs:143-144`. C `worker.rs:1890-1891` (E) "A Unix listener has no TCP_NODELAY to set." D `CHANGELOG.md:788-789`.
- UX6. Resets: no Unix-specific statement exists. The generic one is `io.rs:679-680` "A reset is reported to the read as an error and closes the connection." Proposed check: a Unix peer that closes with unread data produces the same read error and close as a TCP reset. Unverified; no test.

Receive path:
- UX7. A plaintext Unix connection, accepted or from `connect_unix`, receives directly into its accumulator on io_uring. C `ringline/src/connection.rs:127-131` (E). D `docs/recv-direct-design.md:693`. T `ringline/tests/recv_direct.rs:663`, `711`.
- UX8. The hangup poll and `MSG_PEEK` peek have no Unix-specific statement. The generic one is `recv-direct-design.md:345-348`. Proposed check: a Unix peer's `SHUT_WR` or close completes the hangup poll, and `peer_closed()` turns true with no parked read. Design doc rows 120-121 show `RDHUP` and `HUP|RDHUP` for those states. No Unix test.
- UX9. mio reads a Unix connection to `WouldBlock` and does not stop at a short read. C `mio/event_loop.rs:819-820` "A Unix stream read also stops short with bytes behind it, at a message carrying fds, and raises no event for them, so it reads to `WouldBlock`." D `CHANGELOG.md:335`. T `ringline/tests/mio_short_read.rs`.

Identity, accept, connect:
- UX10. An accepted Unix connection reports `PeerAddr::Unix` with an empty path for an unnamed peer; `connect_unix` reports the path. C `acceptor.rs:146-150`. D `connection.rs:9` (E). T `ringline/tests/echo.rs:6205-6213`. C `handler.rs:1316`.
- UX11. A Unix listener always has an acceptor thread, in merged accept mode too. C `worker.rs:1518-1519` (E). D `CHANGELOG.md:771-773` "(`SO_REUSEPORT` does not apply to Unix sockets, which keep their acceptor thread)". `listeners-and-accept-design.md:103-105` describes a shared-fd variant that was not built.
- UX12. TLS:
  - `connect_unix` cannot use TLS, at compile time. D `io.rs:744-746`. D `CHANGELOG.md:699-700`.
  - A connection accepted on a `bind_unix` listener terminates TLS when the process-wide `ConfigBuilder::tls()` is set. D `config.rs:212` "When set, all accepted connections use TLS." C `ringline/src/tls/mod.rs:534-536`. Code `event_loop.rs:2391-2394` selects by listener only, and `worker.rs:972` pushes `tls: None`.
  - This is not on the `bind_unix` doc and has no test.
- UX13. `connect_unix(path).timeout(d)` arms the same connect timeout as TCP. C `handler.rs:2535-2536` "Does not depend on the transport." D `CHANGELOG.md:699`. No test.
- UX14. On mio, `connect_unix` fails with `io::Error::other("mio connect_unix not yet implemented")`. C `handler.rs:3022-3029`. D `CHANGELOG.md:861-862`. No test.
- UX15. Park has no transport condition. An accepted Unix connection the handler offers can be parked and carries its `PeerAddr` (`ringline/src/park.rs:22`). A `connect_unix` connection is refused as `Outbound` (`driver.rs:1624-1634`). I did not search the park unit tests for a Unix case.
- UX16. `bound_addr`, `bound_addr_of` and `bound_addrs` report `None` for a Unix listener. D `worker.rs:134-136`, `148-150`, `157-159` (E). T `echo.rs:6043`.
- UX17. `bind_unix` unlinks an existing socket file before binding. D `worker.rs:968`. Whether the file is removed at shutdown: unverified.
- UX18. On a Unix listener with a full backlog, a non-blocking connect fails `EAGAIN`. D `config.rs:784-785` (E).
- UX19. A path longer than `sun_path` minus one byte is truncated silently by `unix_path_to_sockaddr` (`ringline/src/backend/sockaddr.rs:88-89`). Not stated anywhere; candidate finding.

UXdoc: each of UX3 (the up-to-1 s delay), UX4, UX5, UX12 (accepted side), UX14 and UX19 is stated on the doc comment of the public item it affects. Today UX5, UX12, UX14 and UX19 are not, UX3 is only in an internal comment and the design doc, and UX4 is stated nowhere.

## UDP and Unix limitations already recorded

UDP:
- `io.rs:5349-5351` "Dropping a `UdpSocket` or its `UdpRecvHalf` closes nothing. The socket lives until the worker exits, and arriving datagrams queue up".
- `config.rs:1177-1179` and `metrics.rs:423-426`: at ring-size depth the socket stops reading and kernel drops are not counted.
- `config.rs:346-348`: a datagram larger than the buffer is dropped, and GRO has no effect on connected io_uring sockets.
- `CHANGELOG.md:682-683` "A client that talks to several peers from one unconnected bind has no way to get a port per worker."
- `worker.rs:1061-1063` "a reply can arrive at a worker other than the one that sent the request."
- `docs/journal/2026-05-udp-multishot-latency.md:47` "Deferred as NO-GO for now" (single-shot recv mode; the multishot per-datagram peek cost is accepted).
- `docs/journal/2026-04-udp-quic-h3.md:72-74`: kernel rx timestamps "were built, A/B'd (−8/−9% at 32 KiB), and reverted". Arrival time is user-space observation time by decision.
- `driver.rs:667-669`: one timestamp per CQE batch.
- `config.rs:1130-1132`: `send_to` a non-peer address on a connected socket differs between Linux and macOS.
- `docs/journal/2026-11-send-path-audit.md:103` "UDP sends (`send_to`, GSO, `udp_send_to`, `handle_send_msg_udp`)" under "Out of scope". No earlier audit covered UDP.

Unix:
- Design doc 95 "The interval is a guess, and this retry is unmeasured."
- Design doc 105-106 "`send_chain` still takes a thread in this state" (#734).
- Design doc 39-41: the vectored-send rows are "not settled across kernels".
- Design doc 52-53 "The cause of the difference is not known."
- `handler.rs:3022` and `CHANGELOG.md:861-862`: `connect_unix` on mio.
- `io.rs:744-746`: no TLS on `connect_unix`.
- `2026-11-send-path-audit.md:1189-1190` "Unix-socket TLS on mio: `finish_close`'s TLS path takes a `TcpStream`; what happens for a TLS connection accepted on a Unix listener was not checked."
- `docs/journal/2026-09-deferred-listen.md:398-399` "Still open: `defer_listen()` refuses a deferred Unix listener in merged mode".

