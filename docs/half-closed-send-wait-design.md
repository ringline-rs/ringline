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
without a FIN. The vectored rows differ from `docs/send-completion-design.md` §4,
which records `-EAGAIN` for them on Linux 6.12 and 7.1, so this is not settled across
kernels.

Unix stream sockets behave the same way: `POLLRDHUP` on polls, a thread for
`MSG_WAITALL`, and `-EAGAIN` for `MSG_DONTWAIT`.

Every plain or vectored send on a half-closed full socket takes a thread unless it
carries `MSG_DONTWAIT`, and a send already waiting takes one when the FIN arrives.
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
2. A send that returns `-EAGAIN` arms the same poll.
3. A poll that completes with `POLLOUT` resubmits the rest.
4. A poll that completes without `POLLOUT` arms a multishot `PollAdd(POLLOUT)`. This
   is a half-closed TCP or Unix peer, or a Unix peer's full shutdown, where the next
   send returns `-EPIPE`.
5. Each multishot CQE with `POLLOUT` resubmits the rest. A CQE that arrives while the
   resubmit is in flight is recorded, and acts if that resubmit returns short or
   `-EAGAIN`.
6. When the send finishes, its multishot poll is cancelled by user_data.
7. A timer retries a waiting send every second. It covers a lost edge, a Unix peer's
   `SHUT_RD`, which a send reports as `-EPIPE` and a poll does not report, and an
   `-EAGAIN` straight after a `POLLOUT`, which could otherwise repeat. The interval is
   a guess, and this retry is unmeasured.

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
review ran 192 further combinations of send buffer, read size and reader pause with
no stall and every byte intact, and confirmed that dropping one `POLLOUT` CQE stalls
the send.

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
  cut enters by 26% to 47% in review. CPU showed no clear change, so it is left out.
- CPU differences were at most about 18% and sit inside a run-position effect larger
  than the difference. Measuring CPU needs randomised order on the rig.

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

### A timed retry

It needs no fd and works on every kernel, and it holds a half-closed reader to one
send buffer per interval, as in the table above.

### Waiting through an epoll fd

It works only from 6.8, costs one fd per stalled connection, and closing the fixed
slot sends no FIN while the installed fd is open.

### D. Leave it, and document a limit

The threads count against `RLIMIT_NPROC`, and a client controls how many.

## What has to change

- A `CHAIN_SEND_FLAGS` constant of `MSG_WAITALL` with separate builders for chains.
  `handler.rs` builds chain parts with `Sqe::stream_send`, so changing
  `STREAM_SEND_FLAGS` alone would silently restore #734.
- `MSG_DONTWAIT` set on the two zero-copy sites, `ring.rs` and `sqe.rs`, which pass
  flags 0 today and would keep their thread.
- `SendPollOut` needs a payload that names a slab entry, because a coalesced or
  zero-copy send waits too. `run_shutdown` and `handle_send_pollout` handle it, or the
  entry is never released and the worker holds exit for the 10 s bound.
- `pending_send_pollout_retries` covers slab entries, and stops closing a connection
  after 3 attempts, because every short send now reaches it.
- `SendMsgCoalescedDrain` goes. `SendMsgZcDrain` and `submit_slab_drain` stay for
  `-ENOMEM` from `SendMsgZc`, carry `MSG_DONTWAIT`, and keep the `plain_send` check.
- A multishot poll keeps the socket open past `Close`, so a close with one armed
  cancels it by user_data, including on the shutdown lead before Linux 6.13.
- Domain Invariants 5 and 9, the comment in `completion.rs`,
  `send-completion-design.md` §2 and §4, `ring-emulator-design.md`,
  `tls-unbuffered-design.md` and `syscalls-and-copies.md`.
- `SEND_EAGAIN` becomes a normal backpressure count.

A close with a send waiting behaves as it does now, and waits for the peer.
Completion semantics do not change: a short result stays inside its handler, and the
send settles once with its full length. Forward writes use `send_parts`, so they need
nothing separate.

## Tests

- 16 half-closed stalled peers: no `iou-wrk` thread in `/proc/self/task`, for plain,
  vectored, zero-copy and TLS sends, and every byte arrives when the peers read.
- A half-closed peer reading 64 MiB on a 64 KiB send buffer: no thread, and it is not
  limited by the backstop timer.
- A 64 MiB send with no FIN on a 64 KiB send buffer, which takes a thread today after
  127 poll re-arms: no thread.
- A half-closed peer that never reads: the send ends at worker exit within #607's
  bound, with no resubmit between backstop intervals.
- A Unix peer's `SHUT_RD`: the send fails within the backstop interval.
- A close with a multishot poll armed: the peer sees EOF, and the socket leaves
  `/proc/net/tcp`.
- A control: a chain on a half-closed peer still takes a thread, and the test says so.

## Not known

- Whether a multishot poll behaves this way below 7.2.6. Linux 6.1's `poll.c` has the
  same `EPOLLET` path, read from source, and nothing has run there. A lost edge would
  leave only the 1 s backstop, so this has to run on 6.1 and 6.12 before implementing.
- Results on a real NIC. All run-time results are from loopback, on a raw ring.
- CPU cost, per the note under Measured.
- Whether `POLLOUT` and `-EAGAIN` can coincide under TCP memory pressure. It is
  plausible from `tcp.c`, and step 7 bounds it.
