# Half-close: a peer's FIN finishes the read half and nothing else

Connection-close audit design limitation L1
(`docs/journal/2026-11-connection-close-audit.md`), changed in #809. Decided 2026-11-09: no
configuration knob, the accessor is `peer_closed()`, and the multishot
`POLLOUT` poll stays armed for the connection's life.

## Before

Every read EOF requested a close. On io_uring the five EOF sites each ran
`note_eof` and then `close_connection` (`handle_recv_direct` at the FIN,
`apply_tls_recv_result` for `Closed` and for a `HandshakeJustCompleted`
that carried the peer's close_notify, `handle_tls_recv_direct` at the FIN,
`handle_hangup_peek` at the end of the stream). On mio the four sites inside
`handle_readable` did the same. The close was deferred behind queued and
in-flight sends, an active chain, a Shutdown SQE and a retained
close_notify, plus one poll of the task in the FIN's iteration (#371). When
it committed, the task was dropped wherever it was parked.

A task that had read a request, forwarded it upstream and was awaiting the
reply, or was sleeping on a timer, was dropped if the client half-closed
after sending. An HTTP client that calls `shutdown(SHUT_WR)` after its
request is a common shape; a proxy on ringline lost the request.

## Decision

A peer's clean end of stream (a TCP FIN with nothing pending, a TLS
close_notify, a FIN found by the hangup peek) sets `read = ReadHalf::Eof`
and wakes the reader. It requests no close. The connection stays open while
the task holds it, and the task may keep sending.

A connection then closes for the reasons it closed before other than the
FIN: the task returns (`close_connection_graceful`), the last half is
dropped (`release_half`), `close()`, the runtime's own abort on a read
error, a write error or a TLS failure (`abort_connection`,
`DriverCtx::close`), and worker exit.

Read errors are unchanged: a reset or a socket error still sets
`ReadHalf::Error`, reports to the reader and closes.

There is no knob to restore the old policy. 0.7 is a breaking release, and
a handler that wants the old behaviour returns when a read resolves `0`.

## What the application sees

- `with_data`, `with_bytes` and `with_data_result` resolve `0` once the
  read half is finished, as before; buffered bytes are delivered first.
  Nothing in the readers changes: `recv_finished()` already gates them.
- `is_alive()` stays `!close_requested()`. It no longer turns false at the
  peer's FIN, only when a close has been requested. Code that used it to
  detect a departed peer checks `peer_closed()`.
- New: `Connection::peer_closed()`, `RecvHalf::peer_closed()` and
  `SendHalf::peer_closed()`: the peer's FIN or close_notify has arrived, or
  the read failed. True once a read would resolve `0` or an error without
  parking, and while the slot is held by this connection; false before that
  and outside the executor. After the end the runtime arms no receive for
  the socket, so a reset that arrives then is seen by the next send, which
  closes the
  connection. `eof_truncated()` keeps its meaning (a FIN with no
  close_notify on TLS).
- `recv_ready` resolves at the FIN, as before.
- Sends after the FIN go to the wire. A peer that fully closed answers with
  a reset, which the next send reports; the connection then aborts with
  that error, and a reader on `with_data_result` sees it. A peer that only
  shut its write side reads the reply.
- A task that ignores `0` from `with_data` and loops now spins until it
  closes, where before teardown dropped it within the iteration. The reader
  docs say `0` is the end of the stream.
- The client crates' `Client::is_alive()` (ringline-redis, ringline-memcache,
  ringline-ping, ringline-http) is `tx.is_alive() && !rx.peer_closed()`: a
  request/response client whose server has closed its write side cannot get
  a reply, and the pools in those crates reconnect such a slot at checkout
  as they did when the FIN closed the connection.

## Mechanism

io_uring:

1. The five EOF sites keep `note_eof` and `wake_recv` and drop
   `close_connection`. The `HandshakeJustCompleted { peer_closed: true }`
   arm spawns the task and records the EOF; the task reads what arrived,
   then `0`.
2. The hangup poll and peek stay. They record the end, or the error, while
   nothing reads, so `peer_closed()` and `recv_ready` see it and an error
   still closes. `recheck_hangups` and `retry_hangup_polls` already drop
   entries once `recv_finished()`.
3. `arm_direct_recv_or_close` arms nothing once finished (unchanged).
4. The #371 one-poll deferral stays for the closes that remain; nothing
   depends on it for the FIN any more.
5. The multishot `POLLOUT` poll (`docs/half-closed-send-wait-design.md`
   step 6) stays armed until the connection closes, as before. Before, a
   half-closed connection was always closing; now the poll can be armed for
   the rest of the connection's life. A TCP socket wakes `POLLOUT` waiters
   only after a send found no room (`tcp_check_space` runs `sk_write_space`
   only with `SOCK_NOSPACE` set), so an armed poll on a connection whose
   sends fit posts no CQE, and when a send next waits, `wait_for_room` uses
   the armed poll instead of arming another. Cancelling the poll when a
   send finishes was rejected: every poll of a connection has the same
   user_data, so a cancel in flight would also cancel the poll the next
   waiting send arms. The per-edge cost rests on reading `tcp_check_space`
   and on the measurement in the send-wait design, not on a new
   measurement.
6. `close_connection_graceful` after a FIN queues close_notify on a TLS
   connection (no close was requested before), so the task's return sends
   close_notify then the FIN. mio already did.

mio:

1. The four EOF sites in `handle_readable` keep `note_eof`, `wake_recv` and
   `finish_forward_at_eof`, and drop `close_connection`.
2. `handle_readable` already returns early once `recv_finished()`, so a
   readable event after the FIN reads nothing. The registration is
   edge-triggered, so the FIN is reported once; a reset after it raises its
   own event, which the early return also ignores, and the next send
   reports it.
3. A forward whose source hits EOF resolves `Ok(forwarded)` as before.

Both: `Lifecycle` and `WriteHalf` are untouched. `ReadHalf::Eof` with
`Lifecycle::Open` is a steady state instead of a transient one.

## TLS

After the peer's close_notify, the task may still send. ringline-tls's
unbuffered state machine returns `WriteTraffic` after the peer's
close_notify until this side has sent its own (`Closed` needs both), and
the buffered engine's writer does not check for a received close_notify.
TLS 1.3 permits this (RFC 8446 section 6.1); a TLS 1.2 peer may discard it.

`PeerClosed` is an edge rustls reports once, to whichever
`process_tls_records` call deframes the alert. The receive path is that
call in every flow ringline drives, and `encrypt_chunk` and
`queue_close_notify` could be it only for records left undriven behind an
accumulator overflow. Both now call `process` again after `PeerClosed`, so
an encrypt that deframes the alert encrypts, and a close that deframes it
queues this side's alert in reply, as they do when the receive deframed it.

## Resources a half-open connection holds

Everything a live connection holds: the slot, the accumulator (only unread
bytes), the TLS table entry (still needed to encrypt), `CONNECTIONS_ACTIVE`,
the per-connection vectors. No receive is armed after the FIN. The hangup
poll has completed. The connection is released when the task ends. A task
that never ends holds the slot, as a live connection's task does; no new
bound is added, and a server that wants one puts a timeout in its handler.

## Tests changed

Tests that pinned the FIN's close were inverted or retargeted:

- `tests/peer_fin.rs`: the four #581 FIN tests now use a handler that reads
  to `0` and returns, so the close is the task's; a new test pins that a
  FIN does not close a connection whose task does not read.
- `tests/recv_direct.rs`: the hangup tests that waited for `is_alive()` to
  turn false wait for `peer_closed()`.
- `tests/half_closed_send_wait.rs`: the single-slot FIN test asserts the
  whole payload arrives, where before the FIN cut it to a prefix.
- `tests/teardown_drops.rs`: the connection is reset, not half-closed, to
  drop its task.
- `tests/echo.rs`: `response_after_peer_fin_is_delivered`'s doc, and the
  mio handed-off-send unit test, close through the task's return.
- Unit tests at each EOF site assert `read == Eof`, `lifecycle == Open` and
  no pending close; `a_fin_batched_with_the_last_send_cqe_leaves_the_close_to_the_task`
  and `batch_recv_eof_then_send_cqe` are retargeted to the task's close.
- `tls/unbuffered/tests.rs`: an encrypt after the peer's close_notify
  produces a record the peer decrypts, through both the receive-driven and
  the encrypt-driven edge; a close that deframes the peer's alert queues
  this side's.

## New tests, both backends (`tests/half_close.rs`, `tests/tls_echo.rs`)

1. The peer half-closes after its request; the task is awaiting a timer. It
   is not dropped, wakes, sends the reply, reads `0`, returns; the peer
   reads the reply and the FIN.
2. `peer_closed()` is true and `is_alive()` is true after the FIN; the
   connection closes when the task returns.
3. A reset still aborts: `with_data_result` resolves `Err(ConnectionReset)`
   (the existing reset tests in `tests/echo.rs`; a unit test pins the hangup
   peek's error path).
4. TLS: the client sends close_notify; the server sends a reply and
   returns; the client reads the reply, then close_notify, then the FIN.
5. A task that only sends on a connection the peer fully closed gets the
   send error and the connection closes.
6. A half-open idle connection does not spin the event loop: `on_tick`
   counts over 500 ms at the idle rate.

## Docs changed

`runtime/io.rs` module doc and `with_data`, `with_data_result`,
`SendHalf::close`, `Connection::is_alive`;
`docs/recv-direct-design.md`; `docs/connection-state-model-design.md`
(the follow-up is done); `docs/half-closed-send-wait-design.md` step 6;
`docs/mio-close-lifecycle-design.md`; CLAUDE.md Connection Lifecycle; the
client crates' `is_alive` docs; a CHANGELOG `Changed` entry marked
breaking.
