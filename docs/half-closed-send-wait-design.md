# Waiting for room on a half-closed socket

**Status:** proposed, for #605. Needs an [owner decision](#owner-decisions).
Keeps the Linux 6.1 floor, so #605's raise to 6.8 is dropped. #607 no longer
depends on it.

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

## Options

### A. Cap the unbound pool, and give a plain close a deadline

This is the recommendation. It has two parts, and the first is not safe alone.

**The cap.** Set the second slot of `IORING_REGISTER_IOWQ_MAX_WORKERS`, through a new
`ConfigBuilder` setting. It works on every kernel from 6.1, in about 20 lines. The
limit applies per worker thread, and per NUMA node before Linux 6.4, so the host-wide
bound is workers × cap. Registering above the current limit raises it, so the
setting needs the guard `iowq_max_workers` has.

Measured with a cap of 2 and 8 stalled sends: 2 threads, the other 6 queued, and
those 6 ended with `-ECANCELED` when cancelled. With no cap, 8 threads.

- A client still holds threads, but no more than the cap, so the cost to the host has
  a bound. It does not reach zero threads.
- A send past the cap waits for a thread until the stalled sends' peers read or
  disconnect. A handler's close does not release them on plain TCP:
  `close_connection` waits for the in-flight send, and only TLS has a deadline.
  Worker exit releases them.
- That includes connections with no FIN. The kernel moves a request to io-wq after
  127 poll re-arms, and each partial `MSG_WAITALL` send is one re-arm, so one large
  send can reach the unbound pool. On a default send buffer, a 67 MiB send stayed off
  it and a 1 GiB send did not. With a cap of 1 held by a stalled half-closed send, a
  256 MiB send to a reading peer with no FIN stopped at 123 MiB for 12 s, where it
  took 143 ms uncapped.
- Connections whose send is queued cannot finish a close or send a FIN until a thread
  frees up. No deadlock was found: close leads run on the bounded pool or inline, and
  worker exit took 0.6 to 10 ms at a cap of 1.

So the cap alone replaces a thread cost with starvation of other clients, reachable
with cap × workers stalled connections, that the server cannot clear.

**The close deadline.** A plain TCP close with a send in flight gets a deadline, as a
TLS close has, which drives `force_finalize_close`. A handler can then clear a stalled
connection, and an idle or abusive client releases its thread.

### What uses the unbound pool

From `opdef.c` and `io_prep_async_work` in v6.12: a request counts as unbound when its
op can use it and its file is not a regular file or block device.

| Pool | Ops ringline uses |
|---|---|
| unbound | `Send`, `SendMsg`, `SendMsgZc`, `Recv`, multishot recv, `RecvMsgMulti`, `AcceptMulti`, `Connect`, and `Read`/`Write` on FIFOs and char devices |
| bounded | `Shutdown`, `Close`, `Fsync`, `OpenAt`, `Statx`, `RenameAt`, `UnlinkAt`, `MkDirAt`, `UringCmd`, and `Read`/`Write` on regular or block files |
| not on io-wq in normal operation | `Timeout`, cancels, `FixedFdInstall`, `PollAdd` |

`Connect`, a FIFO read and `Recv` all completed with a cap of 2 full.

### B. `MSG_DONTWAIT` on every stream send, and ringline does the waiting

`STREAM_SEND_FLAGS` becomes `MSG_DONTWAIT`, with a `POLLOUT` poll for a socket with
no FIN and epoll after one, on 6.8+.

- No thread, whatever the order of events, except `send_chain`: its parts need
  `MSG_WAITALL` (#734), so they keep one.
- It gives up the kernel retrying a short send in place. Every short send becomes
  a CQE, a resubmit and another CQE, on the path of a peer slower than the sender.
  That cost is not measured, and it has to be before this is chosen.
- It adds a wait state, below.

### C. `MSG_DONTWAIT` only after ringline observes the FIN

The hot path is unchanged. After a FIN, new sends use `MSG_DONTWAIT`, a send in
flight is cancelled, and `-EAGAIN` takes the epoll wait. I do not recommend this.
Measured against a raw ring, it has these problems:

- A cancel sent from the hangup CQE returned `-ENOENT` under `DEFER_TASKRUN`, and the
  send then moved to a thread. All 16 of 16 sends stayed on threads. It has to be
  resent until the CQE arrives: at a 1 ms retry, all 16 ended within 1.2 to 5 ms.
- Cancelling takes the thread off the send, not out of the process. A worker idles
  for about 5 s, and the ring keeps the last one. The peak still reaches one thread
  per concurrent FIN.
- A cancelled send with nothing sent reports `-EINTR` or `-ECANCELED`, which every
  send handler treats as terminal. Each would have to tell this from a real failure,
  or later sends follow a gap, as in #734.
- Nothing records the FIN today: `read` stays `Open` with a request queued ahead of
  it, and the hangup poll is one-shot. It needs a flag set from every path that can
  observe a FIN.
- A send built before the FIN carries `MSG_WAITALL` in its SQE, so the flag has to
  move from build time to push time.

### D. Leave it, and document a limit

Tell operators to set `TasksMax`. No code. I did not test what happens when that
limit is reached.

## What the wait costs, for B and C

- One epoll fd per worker, and one fd per stalled connection until it closes. A
  client can spend those, so installs need their own limit below `RLIMIT_NOFILE`, and
  past it the send takes a thread.
- With the installed fd open, closing the fixed slot sends no FIN. The fd has to
  close in `handle_close`, after `EPOLL_CTL_DEL`, on every connection that ever
  waited.
- `-EAGAIN` from any send tag goes to the wait, never to `SendPollOut`, which spins
  after a FIN (#603), or to `submit_slab_drain`.
- A waiting send has no CQE, so `force_finalize_close`, `drain_conn_send_queue`,
  `run_shutdown` and `reset_send_state` each release its slot or slab entry.
- None of `ConnSendState`'s fields identifies the waiting send, so that needs new
  fields, set at every push site.

## Tests for A

- 16 half-closed stalled peers with a cap of 4: `iou-wrk` threads in
  `/proc/self/task` stay at 4 or fewer.
- Those stalled sends complete in order when their peers read, or end at worker exit
  within #607's bound.
- A handler's close of a stalled plain connection releases its thread within the
  deadline, and a send queued behind it then proceeds.
- A control: small sends to peers with no FIN are not delayed by stalled half-closed
  peers. A large send behind a full cap stops until a thread frees up, and the test
  states that delay.

## Owner decisions

1. **A, as recommended?** It bounds the cost on every kernel, in a small change, and
   leaves threads in use. Only B removes them, and B needs a measurement first and is
   a larger change to the send path. A does not rule B out later.
2. **The default cap.** I propose 64 per worker thread, which is the bounded pool's
   limit on a 16-vCPU host. It should not ship before the close deadline. A lower cap
   starves sooner, and a higher one costs more threads. I have no measurement that
   picks a number.
3. **The close deadline.** A plain TCP close would now discard unsent data after the
   deadline, where today it waits for the peer indefinitely. What should the deadline
   be, and is it `close_notify_timeout_ms`'s successor? That setting was removed in
   the public context type series.

## Not known

- Every run-time result above is from 7.2.6, over loopback. #605's probe on 6.12 agrees
  with the epoll result. The op list and the 127 re-arm limit are from reading v6.1
  to v6.12 source, and v6.1 has no such limit for partial sends. Nothing here ran on
  6.1 or 6.8.
- On a real network, re-arm counts depend on the send buffer and congestion window.
- Whether a client can hold a zero window indefinitely. Without keepalive or a user
  timeout I expect a stalled send to last as long as the peer acknowledges window
  probes, and that is inferred.
