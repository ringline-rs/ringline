# Waiting for room on a half-closed socket

**Status:** chosen by the owner, for #605: option B, `MSG_DONTWAIT` on every stream
send, with ringline doing the waiting. Not implemented. Keeps the Linux 6.1 floor,
so #605's raise to 6.8 is dropped. #607 no longer depends on it.

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
is 16 MiB, so it cannot fit, and each case ran in its own process. The thread counts
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
without a FIN. The vectored rows differ from `docs/send-completion-design.md` §4,
which records `-EAGAIN` for them on Linux 6.12 and 7.1, so this is not settled across
kernels.

Unix stream sockets behave the same way: `POLLRDHUP` on polls, a thread for
`MSG_WAITALL`, and `-EAGAIN` for `MSG_DONTWAIT`.

Every plain or vectored send on a half-closed full socket takes a thread unless it
carries `MSG_DONTWAIT`, and a send already waiting takes one when the FIN arrives.
No poll can replace that wait, because io_uring reports `POLLRDHUP` on every poll.

An epoll fd can replace it, and needs Linux 6.8. A `PollAdd(POLLIN)` on an epoll fd
watching a socket for `EPOLLOUT | EPOLLONESHOT` stayed quiet while the buffer was
full after the FIN, and fired once the peer had read enough, with no thread. The
socket's fd came from `IORING_OP_FIXED_FD_INSTALL`, because connections have no
ordinary fd.

## Design

`STREAM_SEND_FLAGS` becomes `MSG_DONTWAIT`, and `send_chain` keeps `MSG_WAITALL`. A
send that cannot finish waits in ringline:

1. A short send arms `PollAdd(POLLOUT)` for the rest. It does not resubmit first,
   because the resubmit would return `-EAGAIN`.
2. A send that returns `-EAGAIN` arms the same poll.
3. A poll that completes with `POLLOUT` resubmits the rest.
4. A poll that completes without `POLLOUT` means the peer has half-closed. The
   connection joins the worker's retry list, and a timer resubmits the send.
5. A timed resubmit that returns `-EAGAIN` goes back on the list, with a longer
   interval.

The peer's FIN needs no tracking: step 4 detects it from the poll's result. Nothing
installs an fd, so this works on every kernel from 6.1, where the epoll wait needed
6.8 and one fd per stalled connection. One timer serves each worker's list, so a
stalled connection costs a list entry and a resubmit per interval.

The wait has a latency cost only on a half-closed peer: a send resumes up to one
interval after room appears. I propose doubling from 1 ms to 100 ms per connection.
That choice is a guess with no measurement behind it.

`send_chain` still takes a thread in this state. Its parts are linked, so a short
part would break the chain's order (#734).

### Measured

Raw ring with ringline's flags, Linux 7.2.6 arm64, TCP over loopback, no ringline
code. The stall case delayed the reader by 400 ms and retried at 10 ms.

| Stalled send | Delivered | Peak `iou-wrk` | Resubmits |
|---|---|---|---|
| 16 MiB, FIN | all | 0 | 38 |
| 16 MiB, no FIN | all | 0 | 3 |
| 256 MiB, FIN | all | 0 | 38 |
| 256 MiB, no FIN | all | 0 | 3 |

The 256 MiB send with no FIN shows the design also avoids the 127 poll re-arm limit,
which moves a long `MSG_WAITALL` send to io-wq.

The cost is the kernel no longer retrying in place. In the table, `kernel` is
`MSG_WAITALL`, and `design` is steps 1 to 3. Each row is the median of 4 interleaved
runs of 1 MiB sends, and all arms kept the reader's rate.

| Reader | Send buffer | Op | Enters per MiB, kernel | Enters per MiB, design | CPU µs/MiB, kernel | CPU µs/MiB, design |
|---|---|---|---|---|---|---|
| unpaced | default | plain | 1.00 | 1.01 | 55.4 | 44.6 |
| 1 GiB/s | default | plain | 1.00 | 1.98 | 107.1 | 179.4 |
| 200 MiB/s | default | plain | 1.00 | 2.27 | 317.5 | 307.2 |
| 1 GiB/s | 64 KiB | plain | 1.00 | 17.00 | not compared | not compared |
| 1 GiB/s | 64 KiB | zero-copy | 2.00 | 25.99 | not compared | not compared |

- A send with room costs the same, because `MSG_DONTWAIT` changes nothing until the
  socket is full. 64 KiB sends took about 7% more enters when paced, and the same
  number unpaced.
- CPU at 1 GiB/s rose about 68%, spread 89 to 138 against 162 to 212. At 200 MiB/s
  the spreads overlap, so there is no difference yet. Unpaced was faster, for a
  reason I have not found.
- A zero-copy short send also costs a notification. Loopback copies zero-copy sends,
  so that row's counts apply and its CPU does not.
- Resubmitting on a short send cost about 40% more enters than step 1 in the 64 KiB
  buffer rows, which is why step 1 exists.

## Options not chosen

### A. Cap the unbound pool, and give a plain close a deadline

Threads stay in use, up to workers × cap. At a full cap, sends that need a thread
queue with no error, and the deadline would cut off half-closing clients still
reading, because a FIN already calls `close_connection`. With a cap of 1 and one
stalled half-closed send, a 256 MiB send to a reading peer stopped at 123 MiB for
12 s, where it took 143 ms uncapped.

### C. `MSG_DONTWAIT` only after ringline observes the FIN

A cancel sent from the hangup CQE returned `-ENOENT` under `DEFER_TASKRUN`, and the
send moved to a thread, 16 of 16. A cancelled send reports `-EINTR` or `-ECANCELED`,
which every send handler treats as terminal.

### Waiting through an epoll fd

It works only from 6.8, costs one fd per stalled connection, and closing the fixed
slot sends no FIN while the installed fd is open.

### D. Leave it, and document a limit

The threads count against `RLIMIT_NPROC`, and a client controls how many.

## What has to change

- `-EAGAIN` from any send tag goes to steps 1 to 5. `SendPollOut` and the `*Drain`
  tags go away, including `submit_slab_drain`, if nothing else needs them. Domain
  Invariant 9 and `docs/send-completion-design.md` §4 describe them, and change with
  them.
- A waiting send has no SQE in the kernel on the retry list, so
  `force_finalize_close`, `drain_conn_send_queue`, `run_shutdown` and
  `reset_send_state` each release its slot or slab entry.
- A close with a send waiting behaves as it does now: it waits for the peer. A
  poll-armed send is cancelled at worker exit, as #607 cancels sends.
- TLS sends take the same path. Its handler keeps ordering through the
  per-connection queue.
- The in-flight flag stays set across the wait, so the entry stays the one operation
  in flight on the connection, and byte order holds.

## Tests

- 16 half-closed stalled peers: no `iou-wrk` thread in `/proc/self/task`, for plain,
  vectored, zero-copy and TLS sends, and every byte arrives when the peers read.
- A 256 MiB send to a reading peer with no FIN: no thread.
- A half-closed peer that never reads: a stalled send ends at worker exit within
  #607's bound, and costs a bounded number of resubmits per second.
- A control: a chain on a half-closed peer still takes a thread, and the test says so.

## Not known

- Every run-time result above is from 7.2.6, over loopback, on a raw ring. Nothing
  here ran in ringline, on a real NIC, or on 6.1 to 6.12. §4 of the send-completion
  design records different vectored results on 6.12 and 7.1, which is why every send
  tag has to accept `-EAGAIN`.
- The CPU cost on a real network, where a slow peer's rate sets how often the socket
  fills. It needs a rig run.
- Whether step 4's test holds when a poll returns `POLLRDHUP` and `POLLOUT` together.
  It should resubmit, and I have not tested it.
