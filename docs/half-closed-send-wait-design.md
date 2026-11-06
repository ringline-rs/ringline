# Waiting for room on a half-closed socket

**Status:** implemented, for #605: `MSG_DONTWAIT` on every stream send, with ringline
doing the waiting. Keeps the Linux 6.1 floor, so #605's raise to 6.8 is
dropped. #607 no longer depends on it.

## Problem

A client that sends a request, half-closes and stops reading holds one kernel
thread per connection for as long as it stalls. The threads come from io-wq's
unbound pool, and they count against `RLIMIT_NPROC` and a cgroup's pids limit.
#605 measured 16 stalled sends holding 16 `iou-wrk` threads on Linux 6.12.

`ConfigBuilder::iowq_max_workers` does not cover this: it sets only the bounded
pool, in the first slot of `IORING_REGISTER_IOWQ_MAX_WORKERS`. The unbound slot is
left at the kernel's default, which measured 63,767 here, the value of
`RLIMIT_NPROC`.

## What the kernel does

Measured on Linux 7.2.6 arm64, TCP over loopback, with a full send buffer. Each send
is 16 MiB, so it cannot fit, and each case ran in its own process. The zero-copy row
needs a send within `RLIMIT_MEMLOCK`: at an 8 MiB limit, 16 MiB returns `-ENOMEM` and
4 MiB reproduces the row. The thread counts
were the same on a ring with ringline's flags (`SINGLE_ISSUER`, `COOP_TASKRUN`,
`DEFER_TASKRUN`).

| Send | `iou-wrk` threads | CQE |
|---|---|---|
| `Send` `MSG_WAITALL`, peer's FIN first | 1 | none in 250 ms |
| `Send` `MSG_WAITALL`, waiting, then the FIN | 0, then 1 | none in 150 ms |
| `Send` no flags, first send | 0 | short, 95,232 bytes |
| `Send` no flags, second send | 1 | none in 200 ms |
| `Send` `MSG_DONTWAIT`, second send | 0 | `-EAGAIN` at once |
| `SendMsg` `MSG_WAITALL`, after the FIN | 1 | none |
| `SendMsgZc`, flags 0 or `MSG_WAITALL`, after the FIN | 1 | none |

The 95,232 bytes are room that appears about 30 ms after the buffer fills, with or
without a FIN. The vectored rows differ from Linux 6.12 and 7.1, where `SendMsg` with
`MSG_WAITALL` and `SendMsgZc` returned `-EAGAIN` after the FIN, so this is not settled
across kernels.

Unix stream sockets behave the same way: `POLLRDHUP` on polls, a thread for
`MSG_WAITALL`, and `-EAGAIN` for `MSG_DONTWAIT`.

In this setup, a 16 MiB send on an already full socket, every plain or vectored send
takes a thread unless it carries `MSG_DONTWAIT`, and a send already waiting takes one
when the FIN arrives. It does not hold for every send: in
`half_closed_send_wait.rs`, a coalesced or guard send with `MSG_WAITALL` held no
thread at the stall point. The cause of the difference is not known.
A one-shot poll cannot replace that wait, because io_uring reports `POLLRDHUP` on
every poll. A multishot poll can: it is edge-triggered, so it posts `POLLRDHUP` once
and then posts `POLLOUT` when room appears.

An epoll fd can replace it, and needs Linux 6.8. A `PollAdd(POLLIN)` on an epoll fd
watching a socket for `EPOLLOUT | EPOLLONESHOT` stayed quiet while the buffer was
full after the FIN, and fired once the peer had read enough, with no thread. The
socket's fd came from `IORING_OP_FIXED_FD_INSTALL`, because connections have no
ordinary fd.

## Design

Stream sends carry `MSG_DONTWAIT`, and `send_chain` keeps `MSG_WAITALL`. A send that
cannot finish waits in ringline:

1. A short send arms `PollAdd(POLLOUT)` for the rest. It does not resubmit first,
   because the resubmit would return `-EAGAIN`.
2. A send that returns `-EAGAIN` arms the same poll. If that send was made on a
   `POLLOUT`, it arms the multishot poll of step 4 instead: a one-shot poll would
   report the same `POLLOUT`, and the two could repeat forever.
3. A poll that completes with `POLLOUT` resubmits the rest.
4. A poll that completes without `POLLOUT` arms a multishot `PollAdd(POLLOUT)`. This
   is a half-closed TCP or Unix peer, or a Unix peer's full shutdown, where the next
   send returns `-EPIPE`.
5. Each multishot CQE with `POLLOUT`, `POLLERR` or `POLLHUP` resubmits the rest. A
   `POLLOUT` that arrives while the resubmit is in flight is recorded, and acts if
   that resubmit returns short or `-EAGAIN`. A multishot poll that ends with the send
   still waiting is armed again.
6. The poll stays armed until the connection closes, when `try_finalize_close`, or
   worker exit, cancels it. A half-closed connection is always closing, and a poll
   armed for step 2 costs one ignored CQE per edge. Cancelling when each send finishes
   would race the next send's arm.
7. A timer resubmits every waiting send once a second, whichever poll it waits on.
   It covers a lost edge, and a Unix peer's `SHUT_RD`, which a send reports as `-EPIPE`
   and a poll does not report. The interval is a guess, and this retry is unmeasured.

A connection has one send outstanding at a time, so the wait is state on
`ConnSendState`. `waiting_send` holds the send's user_data, which names its pool slot
or slab entry and its completion path. A failed wait goes through that path, so each
kind of send fails as it always has. A waiting send has nothing in the kernel, so at
worker exit `run_shutdown` releases it directly, and the `Close` CQE fails one that a
forced close left waiting.

The peer's FIN needs no tracking, because step 4 detects it from the poll's result.
Nothing installs an fd. `send_chain` still takes a thread in this state, because its
parts are linked and a short part would break their order (#734).

### Poll results

Measured on Linux 7.2.6.

| State | Poll result | `MSG_DONTWAIT` send |
|---|---|---|
| Room, no FIN | `OUT` | sends |
| Full, no FIN | waits | `-EAGAIN` |
| FIN, room | `OUT\|RDHUP` | sends |
| FIN, full | `RDHUP` | `-EAGAIN` |
| RST | `OUT\|ERR\|HUP\|RDHUP` | `-ECONNRESET` |
| Own `SHUT_WR` | `OUT` | `-EPIPE` |
| Unix peer `SHUT_WR`, full | `RDHUP` | `-EAGAIN` |
| Unix peer `SHUT_RDWR`, full | `HUP\|RDHUP` | `-EPIPE` |
| Unix peer `SHUT_RD`, full | waits | `-EPIPE` |

### Measured

Raw ring with ringline's flags, Linux 7.2.6 arm64, TCP over loopback, no ringline
code. `PollAdd` and `Send`, `SendMsg`, `SendZc` and `SendMsgZc` with `MSG_DONTWAIT`
took no thread, with the FIN first, during the wait, or absent.

A half-closed peer reading a 64 MiB send on a 64 KiB send buffer, 4 runs each, shows
why the wait is a poll. The timer is a 1 ms retry that does not back off.

| Wait | No stall, MiB/s | After a 400 ms stall, ms | Peak `iou-wrk` |
|---|---|---|---|
| multishot poll | 2,078 to 4,968 | 423 to 438 | 0 |
| timer | 87 to 91 | 1,151 to 1,164 | 0 |

During the stall the multishot poll posted one CQE without `POLLOUT` and no others. A
further 192 combinations of send buffer, read size and reader pause ran with no stall
and every byte intact, and dropping one `POLLOUT` CQE stalled the send.

The cost is the kernel no longer retrying in place. Medians of 4 interleaved runs of
1 MiB sends, steps 1 to 3 against `MSG_WAITALL`:

| Reader | Send buffer | Op | Enters per MiB, `MSG_WAITALL` | Enters per MiB, this design |
|---|---|---|---|---|
| unpaced | default | plain | 1.00 | 1.01 |
| 1 GiB/s | default | plain | 1.00 | 1.98 |
| 200 MiB/s | default | plain | 1.00 | 2.27 |
| 1 GiB/s | 64 KiB | plain | 1.00 | 17.00 |
| 1 GiB/s | 64 KiB | zero-copy | 2.00 | 25.99 |

- A send with room costs the same: io_uring sets `MSG_DONTWAIT` on every first issue.
  `MSG_DONTWAIT` here changes what happens after `-EAGAIN`. 64 KiB sends took about 7%
  more enters when paced.
- Throughput kept the reader's rate.
- Resubmitting on a short send cost about 40% more enters than step 1.
- Linking `PollAdd` ahead of the `Send`, with `IOSQE_CQE_SKIP_SUCCESS` on the poll,
  cut enters by 26% to 47%. CPU showed no clear change, so it is left out.
- CPU differences were at most about 18% and sit inside a run-position effect larger
  than the difference. Measuring CPU needs randomised order on the rig.

### Other kernels

The same raw-ring probe ran in guests on an x86 host. It checks the multishot sequence
on TCP and Unix sockets, each send opcode with `MSG_DONTWAIT`, and 256 runs of steps 1
to 6 against a reader. Those runs covered the default send buffer and 16, 64 and 256
KiB, reads of 4 KiB to 1 MiB, pauses of 0 to 10 ms, and a FIN before and during the
send. A control that drops one `POLLOUT` CQE has to be reported as stuck.

| Kernel | Image | Multishot sequence | Each opcode | 256 runs, stuck or corrupt | Control caught |
| --- | --- | --- | --- | --- | --- |
| 6.1.159 | Amazon Linux 2023 | pass, see below | `-EAGAIN`, 0 threads | 0 | 5 of 5 |
| 6.12.63 | Debian 13 | pass | `-EAGAIN`, 0 threads | 0 | 5 of 5 |

6.12 ran once. 6.1 ran twice, and neither run had a stuck or corrupt transfer.

On 6.1 TCP, the send after the FIN returned 32,768 bytes, where 6.12 and 7.2.6 return
`-EAGAIN`, and the poll stayed silent. `SO_MEMINFO` shows this is the `POLLOUT`
threshold and no lost edge. `wmem_queued` fell from 136,192 to 120,448 after the socket
filled, with `sndbuf` 131,072. `send` needs `wmem_queued < sndbuf`, which held.
`POLLOUT` needs free space of at least `wmem_queued / 2`, which was 10,624 against
60,224 and did not hold. The next send returned `-EAGAIN`, and `POLLOUT` arrived when
the reader drained. What freed the 15,744 bytes was not observed; the FIN's ACK is the
likely source.

So a send can have room while the socket does not poll writable. Step 4 waits in that
state, the room stays unused until the reader frees enough to reach the threshold, and
the wait ends when it does.

## Options not chosen

### Cap the unbound pool, and give a plain close a deadline

Threads stay in use, up to workers × cap. At a full cap, sends that need a thread
queue with no error, and the deadline would cut off half-closing clients still
reading, because a FIN already calls `close_connection`. With a cap of 1 and one
stalled half-closed send, a 256 MiB send to a reading peer stopped at 123 MiB for
12 s, where it took 143 ms uncapped.

### `MSG_DONTWAIT` only after ringline observes the FIN

A cancel sent from the hangup CQE returned `-ENOENT` under `DEFER_TASKRUN`, and the
send moved to a thread, 16 of 16. A cancelled send reports `-EINTR` or `-ECANCELED`,
which every send handler treats as terminal.

### A timed retry

It needs no fd and works on every kernel, and it holds a half-closed reader to one
send buffer per interval, as in the table above.

### Waiting through an epoll fd

It works only from 6.8, costs one fd per stalled connection, and closing the fixed
slot sends no FIN while the installed fd is open.

### Leave it, and document a limit

The threads count against `RLIMIT_NPROC`, and a client controls how many.

## Behaviour that follows

A close with a send waiting behaves as it did, and waits for the peer. Completion
semantics do not change: a short result stays inside its handler, and the send settles
once with its full length. `SEND_EAGAIN` is now a normal backpressure count. A chain part is built with
`Sqe::chain_send` or `Sqe::chain_send_msg_zc`, and `push_sqe_chain` debug-asserts it,
because a chain part with `MSG_DONTWAIT` restores #734.

## Tests

`ringline/tests/half_closed_send_wait.rs` counts `iou-wrk` threads in
`/proc/self/task`.

- 16 half-closed stalled peers hold no thread, for coalesced, guard and TLS sends.
  Every byte arrives when the peers read.
- 16 single-slot sends hold no thread while they wait and after their peers
  half-close. The FIN closes each connection when its send finishes, so a peer sees a
  prefix of the handler's sends, with no gap.
- With `MSG_WAITALL` back on stream sends, the single-slot, TLS and 64 MiB half-closed
  reader tests fail, the first with 16 threads for 16 sends. The coalesced and guard
  tests still pass, because those sends hold no thread at the stall point.
- Nothing tests the `MSG_DONTWAIT` flag on the stream `SendMsgZc` behaviourally:
  `MSG_WAITALL` on that site alone passes every test. Under a small `RLIMIT_MEMLOCK` a
  guard send takes `-ENOMEM` and continues as plain sends.
  `a_zero_copy_send_arrives_intact` checks delivery, and no `-ENOMEM` under a limit of
  at least 64 MiB.
- A half-closed peer reading 64 MiB finishes within a limit the 1 s timer cannot meet.
- A Unix peer's `SHUT_RD` fails the send within the timer's interval.
- A close with a multishot poll armed: the peer sees EOF, and the socket leaves
  `/proc/net/tcp`. Unit tests check the cancel, including with no close lead.
- A control: a chain with a part waiting on a half-closed peer holds a thread.

`a_paced_send_arrives_intact_without_a_fin` passes with `MSG_WAITALL` too. On a 64 KiB
send buffer, a 64 MiB send with `MSG_WAITALL` takes a thread after io_uring's 127 poll
re-arms, and ringline has no way to set that buffer.

## Not known

- Whether a multishot poll behaves this way on a Linux 6.1 older than 6.1.159. No
  earlier 6.1 stable release was run.
- Results on a real NIC. All run-time results are from loopback.
- ringline itself on any kernel but Linux 7.2.6, where its tests ran. The results on
  6.1 and 6.12 are from a raw ring with the same flags.
- CPU cost, per the note under Measured.
- Whether `POLLOUT` and `-EAGAIN` can coincide under TCP memory pressure. It is
  plausible from `tcp.c`, and step 7 bounds it.
