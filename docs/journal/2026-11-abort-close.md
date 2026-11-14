# Abort-close of a fixed-file connection, across the 6.13 boundary

- **Status:** closed. The result decides the mechanism of `abort` in
  `docs/send-admission-design.md`, section 3.
- **Span:** Nov 2026 · follows #927 (the design) and #932 (the 6.8 floor) ·
  SystemsLab context `send-admission-expA`

## Goal

`abort` has to close a connection whose peer has stopped reading, and at once
release what its sends hold: queued sends' pool slots, and the slab entry of a
zero-copy send, which is released only when its notification lands. The
question was which io_uring mechanism does that while other connections have
requests pending, on the kernels ringline runs on. Before Linux 6.13 a fixed
file's `Close` does not release the socket while earlier requests on any
connection are in flight (CLAUDE.md, invariant 8), so the answer could differ
either side of 6.13.

A second question came from a server that closes every remaining connection at
once at shutdown: how long that takes before 6.13.

## Method

The probe is `experiments/abort-close-probe.c`, run by
`experiments/abort-close-probe.toml`. It uses raw io_uring syscalls and does not
use ringline. It models ringline's connection handling:

- Each accepted socket is installed in the fixed-file table, and its raw fd is
  closed.
- Each connection has a `POLL_ADD(POLLRDHUP)` pending, standing in for
  ringline's hangup poll.
- `idle` connections (0, 1 or 256) are opened first, so their polls are the
  earlier requests.
- The target connection's client sets a 4 KiB receive buffer and never reads.
- A 512 KiB `SEND_ZC` is sent on the target with `MSG_DONTWAIT`. The kernel
  accepted 176,128 bytes of it on 6.8 and 6.12, and all 524,288 on 7.2. Its
  notification does not land while the peer does not read, and each round
  checks that 300 ms after the send. The check held in all 630 rounds.

The arms close the target in these ways:

| arm | what it does |
| --- | --- |
| `plain` | `Close` of the slot (the control) |
| `linger` | `SO_LINGER {1, 0}` through the setsockopt `URING_CMD`, then `Close` |
| `cancel_linger` | `ASYNC_CANCEL` of every request on the slot, the setsockopt, then `Close`, hard-linked |
| `unspec` | `IORING_OP_CONNECT` with an `AF_UNSPEC` address, then `Close` |
| `cancel_unspec` | the cancel, the connect, then `Close` |
| `batch` | the cancel, setsockopt and `Close` on every connection, idle ones included, submitted together |

"Released" means the notification landed. "At once" means within 100 ms of the
arm's submission. A time below about 0.25 ms means the notification was there
at the first reap after the submission. Each round is one process, and there
were five rounds per kernel, arm and idle count.

When nothing was released within 5 s and there were idle connections, the
round closed the idle clients, which completes their polls, and looked again.

Kernels, from the rack's guest images:

- 6.8.0-142-generic (Ubuntu 24.04.5);
- 6.12.116+deb13-amd64 (Debian 13);
- 7.2.12+deb14-amd64 (Debian 14's image; its os-release reads forky/sid).

This is not the setup the design's Experiment A first described, which put
the test inside ringline with `workers(1)`, queued copy sends and a 4 MiB
guard. The question is how the kernel behaves, and a probe without ringline
answers it without ringline's own close path in the way. That path's drain,
which never commits the `Close` while a send waits for room, is known from the
code (`try_finalize_close`) and was not measured.

The first run used an earlier revision of the probe, which is not checked in.
It differs from the committed one only in how a round ends: it read the
target's client socket before the look after the idle close (see Results).

## Predictions, written before the first run

- `plain`: never released.
- `linger` without the cancel: never released on any kernel, because the
  target's own hangup poll holds the file; still never after the idle clients
  close.
- `cancel_linger`: at once with no idle connections. With idle connections, at
  once on 7.2; on 6.8 and 6.12 not within 5 s, and at once after the idle
  clients close.
- `unspec` and `cancel_unspec`: at once on every kernel and idle count,
  because `tcp_disconnect` resets the socket and purges its write queue
  whatever holds the file.
- `batch`: every connection reset on every kernel, since every pending request
  is cancelled.

What each outcome would have meant, also written before the run:

- `unspec` released at once everywhere: the disconnect works on every kernel
  tested, and `abort` can use one mechanism.
- `cancel_linger` with idle connections not released within 5 s on 6.8 and
  6.12, but released once the idle clients close: the pre-6.13 delay is real
  and caused by other connections' earlier requests. Idle 1 and idle 256
  should then not differ, since any one earlier pending request holds it.
- `cancel_linger` with idle connections released at once on 6.8 and 6.12: the
  pre-6.13 ordering does not apply here, which would refute CLAUDE.md's
  invariant 8 for this case.
- `linger` without the cancel released on any kernel: a connection's own poll
  does not hold the socket.
- `batch` leaving idle clients without an RST on 6.8 or 6.12: closing every
  connection at once is also delayed before 6.13.
- `unspec` not released, or the connect failing on a fixed file: the
  disconnect is out.

## Results

From the first run, all arms (experiments `01a1db23-8105`, `-81c8`, `-8255`).
Each cell counts rounds released within 5 s, out of 5, with the time range:

| arm | idle | 6.8 | 6.12 | 7.2 |
| --- | --- | --- | --- | --- |
| plain | 0, 1, 256 | 0 | 0 | 0 |
| linger | 0, 1, 256 | 0 | 0 | 0 |
| cancel_linger | 0 | 5, 0.06–0.08 ms | 5, 0.06–0.10 ms | 5, 0.07–0.16 ms |
| cancel_linger | 1 | 0 | 0 | 5, 0.07–0.14 ms |
| cancel_linger | 256 | 0 | 0 | 5, 0.10–0.16 ms |
| unspec | 0, 1, 256 | 5 each, 0.03–0.12 ms | 5 each, 0.03–0.07 ms | 5 each, 0.07–0.15 ms |
| cancel_unspec | 0, 1, 256 | 5 each, 0.05–0.20 ms | 5 each, 0.05–0.13 ms | 5 each, 0.07–0.17 ms |
| batch | 0, 1 | 5, 0.06–0.21 ms | 5, 0.06–0.12 ms | 5, 0.07–0.14 ms |
| batch | 256 | 5, 7.36–8.08 ms | 5, 7.24–7.65 ms | 5, 3.19–3.72 ms |

Every released round ended with the target's client reading `ECONNRESET`.
After every `batch` round each idle client read `ECONNRESET` when checked, 256
of 256 at idle 256. A `batch` time is when the target's notification was first
reaped after the batch's 771 SQEs went in through 13 `io_uring_enter` calls:
on 7.2 that is close to the submission time itself, and the idle clients'
resets were read only afterwards.

The first run's look after closing the idle clients was not valid. Before that
look, the round read the target's client socket to report how its read ended.
That read let the server send everything the kernel had accepted (176,128
bytes on 6.8 and 6.12, 524,288 on 7.2), and the ACKs freed the zero-copy
pages, which landed the notification whatever the server side had done. It
reported `plain` and `linger` as released after the idle close on all three
kernels, which contradicted the prediction for the wrong reason.

The probe now reads the client's TCP state with `TCP_INFO`, which consumes
nothing, and reads the socket only at the end. The rerun used the corrected
probe for the idle cases (experiments `01a1db2c-f210`, `-f281`, `-f2f2`):

| arm | idle | 6.8 | 6.12 | 7.2 |
| --- | --- | --- | --- | --- |
| plain, linger | 1, 256 | not released, after the idle close either; client established | same | same |
| cancel_linger | 1 | not in 5 s; released 0.10–0.17 ms after closing the idle client; client reset | not in 5 s; 0.08–0.11 ms after; reset | released within 5 s; reset |
| cancel_linger | 256 | not in 5 s; released 3.64–4.26 ms after starting to close the 256 idle clients; reset | not in 5 s; 2.32–2.44 ms after; reset | released within 5 s; reset |

Closing 256 clients takes about that long on its own: the first run's `plain`
and `linger` rows show the same 2.1–4.2 ms for the loop.

The committed probe and spec were then run as committed, with every arm on all
three kernels (experiments `01a1db3a-1755`, `-17bd`, `-182f`). They matched the
tables above in every arm:

- `unspec` released at once at every idle count: 0.03–0.12 ms on 6.8,
  0.03–0.08 ms on 6.12 and 0.07–0.15 ms on 7.2.
- `cancel_linger` with idle connections was not released within 5 s on 6.8
  and 6.12. After the idle clients closed it was released, 0.08–0.15 ms after
  closing one and 2.35–4.15 ms after starting to close 256. On 7.2 it was
  released at once (0.07–0.20 ms).
- `plain` and `linger` were never released, after the idle close either, and
  the client stayed established.
- `batch` at idle 256 released the target by the first reap 7.14–8.16 ms after
  the batch began on 6.8, 7.32–7.77 ms on 6.12 and 3.21–3.57 ms on 7.2, and
  all 256 idle clients read `ECONNRESET` when checked just after.

## Outcome

- `IORING_OP_CONNECT` with `AF_UNSPEC`, then `Close`, is `abort`'s mechanism on
  every kernel. The disconnect, with or without a cancel ahead of it, was the
  only mechanism that released at once on all three kernels and at every idle
  count.
- Cancel, `SO_LINGER` and `Close` is not used for `abort`. With no other
  connections it released at once on all three kernels. With other
  connections' requests pending it released at once only on 7.2: on 6.8 and
  6.12 it was released only once every earlier request on other connections
  had ended. An idle connection's hangup poll does not end, so on a server
  with idle connections it is not released at all.
- A connection's own pending request holds its socket on every kernel, 7.2
  included. A `Close` alone, or with `SO_LINGER`, released nothing while the
  target's hangup poll was pending.
- Closing every connection at once, each with its requests cancelled,
  released the target within milliseconds on every kernel, and every idle
  client read `ECONNRESET`. Worker exit cancels every
  connection's requests too, but closes a connection that still holds a
  zero-copy entry with the `Abort` lead only after 1 s (`ABORT_AFTER`), so its
  exit takes longer than the batch arm; that is unchanged here.
- Every prediction held. The first run's after-idle numbers were a defect in
  the probe, described above, and were not used.

## Not covered

- Kernels 6.9 to 6.11, 6.13 to 7.1, and aarch64.
- Unix-domain sockets: a disconnect with `AF_UNSPEC` was not tried there.
- TLS, and ringline's own close path.
- A send still in the kernel at the disconnect: the probe had none.
- A close that releases the socket without `SO_LINGER` or a disconnect, which
  is ringline's close from 6.13 (cancel, then `Close`): no arm did it, so how
  long the kernel then keeps the data of a peer that does not read was not
  measured.
- The completions of the target's own hangup poll and of the connect, which
  the probe did not record. In the Linux 6.8 source, `tcp_disconnect` returns 0
  and reports an error on the socket, which should complete the poll; that is
  from reading, not a run.

## Lessons / open questions

- Reading a peer's socket to report how a round ended changes what the
  sender's kernel holds. A probe that measures when a zero-copy notification
  lands must observe the peer without consuming from it (`TCP_INFO` here).
- Reopen this if `abort` has to support a kernel outside 6.8, 6.12 and 7.2
  whose behaviour differs, if ringline adds kTLS (a disconnect on a socket
  with the TLS ULP was not tried), or if a Unix-domain `abort` needs to reset
  its peer.
