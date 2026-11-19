# 2026-11 — Handing a listening socket to the next process

- **Status:** closed — all four PRs merged: the acceptor (#971, GO), `bind_fd` (#972), `stop_accepting` (#982), `next_signal` and `signal::install` (PR_4)
- **Span:** Nov 2026 · tree 911e0497 (`main`) · intent #970 · PR 1 · SystemsLab experiments listed under "What happened"

## Goal

Let a server restart under systemd without refusing a connection or dropping
one from the listening socket's backlog. The old process stores its listening
socket in systemd's fd store (`FDSTORE=1`) and the next process receives it
(`LISTEN_FDS`). While no process accepts, connections wait in the backlog.
Before it exits, the old process stops accepting, serves and ends the
connections it holds, and finishes work that needs its tasks and I/O (a cache
flushing to disk, for example), then shuts the runtime down. Connections still
open when it calls `Runtime::shutdown()` are closed, as today.

The consumer is a cache server whose warm restart this is built for. Every
part below is general: any ringline server run by systemd with
`FileDescriptorStoreMax=` can use it.

## What the code does today (tree 911e0497)

1. Ringline creates every listener itself (`RinglineBuilder::bind`,
   `bind_unix`, `bind_tls`; `create_listener` in `ringline/src/worker.rs`).
   There is no way to pass it a socket another process made.
2. `ListenerSockets::shut_down` (`ringline/src/listener_sockets.rs`) calls
   `shutdown(SHUT_RD)` on every socket of a listener. On Linux that takes the
   socket out of the listening state for every holder of it, including a copy
   systemd stores, and resets the connections in its backlog (read from
   `inet_csk_listen_stop`, not measured). It is called by
   `RuntimeShutdown::shutdown` (runtime shutdown, `Drop for Runtime`, a task
   panic under `TaskPanicPolicy::Shutdown`, a worker exit under that policy),
   by the acceptor thread when
   `run_acceptor` returns (`worker.rs`, the `rl-acpt-` thread), by the launch
   rollback, and, for merged listeners only, by
   `RuntimeShutdown::stop_accepting(worker)` when no worker is left to accept.
3. On Linux the pool-mode acceptor blocks in `accept4` (`accept_nonblock` in
   `ringline/src/acceptor.rs`). `SHUT_RD` is what wakes it at shutdown:
   closing the fd does not, and its accept path does not check the shutdown
   flag until an `accept4` fails. On other platforms it polls the listener
   with a 100 ms timeout and checks the shutdown flag between polls
   (`wait_for_connection`). The acceptor thread is detached: its `JoinHandle`
   is dropped at spawn.
4. On io_uring, a worker that sees the shutdown flag calls `run_shutdown` and
   returns from its event loop in the same iteration
   (`ringline/src/backend/uring/event_loop.rs`, the check after
   `drain_park_ready`). `run_shutdown` polls no task, and
   `close_queued_connections` drops the accept channel, closing what was
   queued but not installed. The mio loop checks the flag at the end of an
   iteration, after polling tasks (`ringline/src/backend/mio/event_loop.rs`),
   and has no `run_shutdown`; its queued connections close when the driver is
   dropped.
5. `Runtime::wait_on_signal` always calls `shutdown()` before it returns.
   `signal::wait_or_ready`, which waits without shutting down, is
   crate-private. It reports a task panic or a worker exit by the readability
   of a pipe it never reads (the panic pipe gets one byte, the exit pipe one
   byte per exit), so a later wait returns at once. The `SIGTERM`/`SIGINT`
   handlers are installed on the first wait, so a `SIGTERM` that arrives
   earlier kills the process with the default action.
6. A worker treats a disconnected accept channel as empty (`try_recv().ok()`),
   so the acceptors exiting does not disturb it.

## Plan

Four PRs in this order, each with tests on both backends and the io_uring run
on Linux through SystemsLab.

### PR 1: the acceptor waits in `poll` and is joined

- One stop fd for the runtime, from `crate::wakeup::create_wake_fd`, written
  by `stop_accepting` (PR 3) and by `Runtime::shutdown()`, and never read.
  Every acceptor polls it. A runtime `stopping` flag, set before the write,
  tells an acceptor to stop; the shutdown flag also tells it to drop a held
  connection.
- The acceptor, on every platform, waits in `poll` on the listening fd and the
  stop fd, and accepts until `EAGAIN`, then polls again. `accept4` has no
  per-call non-blocking flag, so the listener is set `O_NONBLOCK`, as it is on
  macOS today. `EAGAIN` stays a `Retry` in `classify_accept_error` and now
  means "poll again". The acceptor checks the `stopping` flag before each
  `accept`.
- An acceptor holding a connection no worker has room for (`send_when_room`)
  keeps it until a live worker takes it or every worker has exited; on the
  shutdown flag it still drops it, as today.
- The acceptors' `JoinHandle`s are kept in `RuntimeShutdown`, and
  `RuntimeShutdown::shutdown`, which `Runtime::shutdown()` and `Drop` call,
  joins them. It may run on a worker thread
  (`shutdown_for_panic`, `worker_exited`); the join cannot wait on that
  worker, because on the shutdown flag an acceptor leaves `send_when_room`
  within 1 ms and leaves `poll` through the stop fd.
- This replaces the blocking `accept4` on Linux and the 100 ms shutdown poll
  elsewhere, so an acceptor exits at once on shutdown on every platform. It
  changes the accept path of every pool-mode listener, so it is measured
  (below).

### PR 2: a listener from an fd

- `RinglineBuilder::bind_fd(fd: OwnedFd)` adds a listener on a socket the
  caller made or received. `launch()` refuses it unless `SO_TYPE` is
  `SOCK_STREAM`, the family from `getsockname` is `AF_INET`, `AF_INET6` or
  `AF_UNIX`, and an inet socket's port is not 0 (unbound). It may already be
  listening. `create_unix_listener`'s unlink does not apply. TLS falls back to
  the process-wide config, as for `bind`; `TCP_NODELAY` applies when the
  family is not `AF_UNIX`.
- `ListenerSockets` records that the listener came from `bind_fd`, and
  `shut_down` skips `SHUT_RD` for it on every path in fact 2. PR 1's stop fd
  wakes its acceptor. The socket stays listening until every holder closes it.
- `defer_listen()` applies to it. On a socket already listening, the gate
  defers only `accept`: the kernel completes handshakes and queues them, so a
  TCP readiness probe passes before the gate opens. Opening the gate sets
  `SO_REUSEADDR` and calls `listen(2)`, which on a listening socket sets the
  backlog to `Config::backlog` (65535 by default), replacing systemd's
  `Backlog=` (read from `__inet_listen_sk`, not measured; macOS not checked).
- The listener is left `O_NONBLOCK` (PR 1). The flag is on the open file
  description, which systemd's stored copy and the next process share; a
  process given the fd must not assume a blocking socket.
- Refused with `AcceptMode::Merged` on io_uring, which needs one
  `SO_REUSEPORT` socket per worker. Merged mode is ignored on mio.
- `Runtime::shutdown()` alone may still accept connections from the backlog
  and close them: an acceptor that passed its stop check calls `accept`, and
  the worker it hands the connection to closes it in shutdown. A server with a
  `bind_fd` listener calls `stop_accepting` (PR 3) first.

### PR 3: stop accepting without shutting down

- `Runtime::stop_accepting(timeout: Duration) -> io::Result<()>`. It closes
  every listen gate, sets `stopping` and writes the stop fd, waits up to
  `timeout` for each pool acceptor to signal its exit, joins only those that
  have, and returns once every live worker has handled every connection placed
  in its accept channel. The workers' shutdown flag is not set, so the workers
  keep polling tasks and I/O and serve the connections they hold.
  `Runtime::shutdown()` afterwards is the second phase and is unchanged.
- It returns at once if already stopped or if the runtime has shut down. It
  returns an error after `timeout` (a worker blocked in synchronous code never
  drains its channel), and an error if called on a worker thread, where it
  would wait on its own channel. After a timeout, an acceptor still holding a
  connection keeps retrying; `shutdown()` joins it or drops the connection.
- A listener from `bind`, `bind_unix` or `bind_tls` is shut down with
  `SHUT_RD` when its acceptor exits, which resets its backlog. A merged-mode
  listener is stopped with `SHUT_RD`, as today.
- "Handled": a per-worker count of connections placed in its channel,
  incremented at every successful send (by an acceptor, or by a merged-mode
  worker placing a connection on another), and a count the worker increments
  in its accept-channel drain (`handle_eventfd_read` on io_uring,
  `drain_channels` on mio), once per item, after the item is installed or
  closed (after `install_accepted` returns on io_uring; at the end of each
  item in `drain_channels`, including the table-full `continue`, on mio). A
  merged worker's own accepts and park adopts are not counted. A handled
  connection is a task the server can see, or was closed because the
  connection table was full or, on io_uring, the fixed-file update failed. On
  a TLS listener, `on_accept` runs after the handshake, so a handled
  connection may not have reached it yet.
- The event loop changes only by that count. The private
  `RuntimeShutdown::stop_accepting(worker)`, which steers merged listeners
  away from one worker, is renamed `steer_away_from`. A merged listener's
  `SHUT_RD` from `stop_accepting` does not increment `ACCEPTOR_STOPPED`.

### PR 4: a signal wait that does not shut down

- `Runtime::next_signal()`: returns the next `Signal` without calling
  `shutdown()`. Each task panic and each worker exit is reported once: the
  call reads the byte it was woken by. Under `TaskPanicPolicy::Shutdown` the
  runtime has already shut down when `TaskPanic` is returned.
- `signal::install()`: installs the handlers now, so a process can install
  them at start. Idempotent.

## Measurement

PR 1 adds a `poll` each time the backlog empties, on the accept path of every
pool-mode listener. Before merging it, measure the connect rate of one
io_uring worker in pool mode under a connect storm with
`experiments/accept-queue-poll-sweep.toml` (see
[the queue-full poll entry](2026-11-accept-queue-full-poll.md)) at
`caps=1024`. The spec takes one revision, so submit alternately
`rev=<main>` and `rev=<PR 1 head>` with `repo` set to the fork, four
experiments a side, plus two more at `main` for the floor. One experiment
runs `rounds=4`, so that is 16 runs a side. The Linux mio
backend uses the same acceptor and is not measured.

## Decision rules

- PR 1 is GO if the median connect rate at its head is within the spread of
  the A-against-A medians at `main`. If it is lower by more than that spread,
  the `poll` wait is used only for listeners from `bind_fd`, the others keep
  the blocking `accept4` and `SHUT_RD`, and this entry records the measured
  cost. PR 1 then lands the stop fd and the joined acceptors only, and the
  `poll` wait lands in PR 2 for `bind_fd` listeners, and `stop_accepting`
  stops the other pool listeners with `SHUT_RD`.
- PRs 2 to 4 add API. PR 3 adds a counter to the accept drain; the others
  change no path a server without the new calls takes.

## What happened

### PR 1: the acceptor

Built as planned, with two differences from the plan text: there is no
`stopping` flag yet (PR 3 adds it with `stop_accepting`), and `EAGAIN` is
handled in `run_acceptor` before `classify_accept_error`. Review found that a
second `shutdown()` made while the first was joining returned early, because
the first had taken the list of acceptor threads; the lock is now held across
the joins.

Connect rate, one io_uring worker, pool mode, `caps=1024`, 8 client threads,
Linux 6.12.116 x86_64 (`debian-13-6.12`), an 8 vCPU guest, four 10 s rounds
per experiment, submitted alternately, four a side, then two more at `main`,
all on hv01 (measured):

| arm | experiment | median of 4 rounds, conns/s |
| --- | --- | --- |
| main a943cf56 | 01a1e6a8-85b3-714a-cab4-b41394868871 | 19,173 |
| PR 1 e8f77626 | 01a1e6a8-8778-7162-ad4c-ebe26f926b30 | 19,251 |
| main | 01a1e6a8-87f1-7166-d754-a28e9fa6eaa2 | 19,357 |
| PR 1 | 01a1e6a8-886d-71f6-3e6a-11ed52fcc336 | 19,284 |
| main | 01a1e6a8-88e9-7171-0b2e-50385097df4c | 19,472 |
| PR 1 | 01a1e6a8-8972-712e-102d-3ff2391dbe6b | 19,298 |
| main | 01a1e6a8-89f8-71c4-d16f-03e1bd4cfd57 | 19,382 |
| PR 1 | 01a1e6a8-8a75-71fe-2d8c-6c17c33a76a9 | 19,305 |
| main | 01a1e6a8-8af1-71b1-f2b0-4496f6211db9 | 19,421 |
| main | 01a1e6a8-8b69-71f3-cc98-ae7193d3cd30 | 19,270 |

The six `main` medians span 19,173 to 19,472 (300 conns/s); the four PR 1
medians span 19,251 to 19,305. The median of the PR 1 medians, 19,291, is 79
below that of `main`'s, 19,370 (0.4%), inside the `main` spread: GO under the
rule above. Mean connection latency was 397 to 408 µs in every round, and
`accept_queue_full` and connect errors were 0. The two commits after these
runs change the shutdown join, tests, docs and one constant's name, not the
accept path. The mio
backend was not measured.

The rate is lower than the 32,000 conns/s the queue-full poll entry measured
at 4509097c with the same image. That run had a 16 vCPU guest on hv03; these
ran in an 8 vCPU guest on hv01 (`nproc` in each log). They did not test which
difference lowers the rate, and both arms share it.

### PR 2: a listener from an fd

Built as planned. Review added two refusals the plan did not have: a
Unix-domain socket that is not bound, and any connected socket. Both passed
the planned checks and failed later with a bare `EINVAL`, or, with
`defer_listen()`, launched a listener whose gate then failed to open
(measured on macOS for an unbound Unix socket; the rest from kernel and
ringline source). The
merged-mode refusal stays, without the reason the plan gave: a listener from
an fd would take the acceptor path a Unix listener takes there, which is not
tested for a listener from an fd.

`launch()` applies `SO_REUSEADDR` and `listen(Config::backlog)` to every
listener from an fd, not only when a deferred gate opens: an ungated
listener's gate is opened by `launch()` itself. On a socket systemd created,
that replaces its `Backlog=`.

macOS keeps a listener listening after `SHUT_RD`, so there the test that a
listener from an fd still accepts after shutdown passes with or without the
change. `experiments/bind-fd-verify.toml` runs the tests on Linux with
`experiments/bind-fd-verify-shut-rd.patch`, which puts `SHUT_RD` back. In
SystemsLab experiment 01a1e6e8-1c6d-71b6-0573-50fc4794908f (Linux
6.12.116, io_uring, at 4f6bd505) the eight tests passed, the merged-mode
refusal test passed with `unstable-accept`, the patched tree failed
`a_listener_from_an_fd_keeps_listening_after_shutdown`, and the full ringline
suite, fmt, clippy and doc gates passed (measured). An earlier run,
01a1e6db-2a09-71ef-8138-d4b6993fb743 at 260797da, passed every step but the
mutation, whose patch no longer applied after that commit's doc edits; the
patch was regenerated in 4f6bd505.

### PR 3: stop accepting without shutting down

Built as planned, with these differences:

- A second call repeats the wait instead of returning at once, so a call
  that follows a `TimedOut` waits again. It returns at once when nothing has
  been placed since.
- Review found that a worker stopped by `request_shutdown()` returns
  `Ok(())` and is not recorded in `RuntimeShutdown::exited`, so
  `stop_accepting` waited for its channel until the timeout. `AcceptState`
  now records every worker thread that has ended, through a guard dropped
  when the thread ends, and the wait skips those workers.
- Review also found that `Duration::MAX` overflowed the deadline; a timeout
  too long to add to the current time now means no deadline.
- In merged mode, nothing waits for multishot-accept completions already
  queued when the listeners are shut down, so a connection accepted before
  the `SHUT_RD` can reach `on_accept` after the call returns. The doc says
  so.

`experiments/stop-accepting-verify.toml` runs `tests/stop_accepting.rs` on
Linux io_uring three times, with `unstable-accept`, and on mio
(`force-mio`), then with each of four patches that remove one part of the
change, each of which must fail a named test: the wait for the workers'
handled counts, the acceptor's `stopping` check, the merged-mode exemption
from `ACCEPTOR_STOPPED`, and the skip of ended workers. The last runs on mio:
in 01a1f539-3338-7100-a0a4-ce5c82d456fb (at ae3e118e) it passed on io_uring
with the patch applied, because an io_uring worker drains its accept channel
(the acceptor's wake is a completion) in the iteration that sees its
shutdown request, before it checks for that request. There the ended-worker case
needs a connection placed between the worker's last drain and the drop of
its channel, which the test cannot arrange. Every other step of that run
passed. In 01a1f540-cc39-711e-a2f1-15c26812667b (Linux 6.12.116, at 8e5f7f43,
the reviewed code) every step passed: the tests three times on io_uring,
with `unstable-accept` and on mio, each of the four patches failed its test,
and the full ringline suite with and without `unstable-accept`, fmt, clippy
and doc passed (measured). In SystemsLab experiment
01a1f52f-bbe6-7100-8c6c-669ac5076993 (Linux 6.12.116, io_uring, at 124b7bf3,
before the review fixes and the fourth patch) every test passed three times,
the merged-mode test passed, each of the first three patches failed its test,
and the full ringline suite with and without `unstable-accept`, fmt, clippy
and doc passed (measured). The first two submissions failed outside the
tests: 01a1f52c had Linux-only unit tests still calling
`RuntimeShutdown::new` with three arguments, and 01a1f52e cloned before the
fix was on the fork.

The counts add one atomic increment per connection on the sender and one on
the worker, each on its own cache line. The connect rate was not measured
for this PR.

No test here tells `handled` incremented before `install_accepted` from
after it: the gap is a few instructions on the worker thread, so a test would
depend on timing.

### PR 4: a signal wait that does not shut down

Built as planned. `next_signal` uses the poll `wait_on_signal` uses, and reads
one byte from the panic or worker-exit pipe it returns for; another waiter
that took the byte first makes it poll again. `wait_on_signal` still reads
neither pipe, so an event `next_signal` returned is not returned by a later
`wait_on_signal`; one already waiting returns it too.

The planned test that "the next call waits" runs two `next_signal` callers
for one worker stop: one returns, the other is still waiting 300 ms later and
returns for a second stop, after which the exit pipe is not readable. While
it waits, that caller shares the signal pipe with `signal::tests`, which
writes a `SIGTERM` byte and waits for it; the existing
`wait_on_signal_reports_a_worker_exit_and_shuts_down` has the same exposure.
`tests/next_signal.rs`, its own binary with one test, sends real `SIGTERM`s:
one after `install()` and before the runtime exists, which is returned
without shutting the runtime down, and one after a task panic, which the next
call returns in place of the panic. Three patches were seen to fail the tests
on macOS: `next_signal` not reading the byte (both tests), `install()`
doing nothing (the process ends on the first `SIGTERM`), and a caller that
lost the byte to another returning anyway (the unit test, which waits 50 ms
so both callers are in `poll` before the stop).
`experiments/next-signal-verify.toml` runs the tests and the first patch on
Linux io_uring.

## Tests planned

- PR 1: an acceptor exits within a bound after `shutdown()` on both backends,
  with no `SHUT_RD`, and `shutdown()` then joins it.
- PR 2: a listener from `bind_fd` keeps listening after `Runtime::shutdown()`
  and after the runtime is dropped: once the acceptor is joined, a connect
  completes its handshake and a `dup` of the fd accepts it. Each refusal in
  `launch()` (a datagram socket, port 0) has a test.
- PR 2: with `defer_listen()`, a listener from `bind_fd` that was already
  listening accepts nothing until its gate opens, and connections made before
  then are served once it opens.
- PR 3: after `stop_accepting()` returns, a connection queued in a worker's
  channel has reached `on_accept` (plaintext); a connection made afterwards
  waits in the backlog of a `bind_fd` listener; existing connections keep
  being served; the acceptor threads have exited. A second call, a call after
  `shutdown()` return at once; a call from a worker thread returns an error
  at once.
- PR 4: after a worker exit, `next_signal()` returns `WorkerExited` once,
  the other workers keep serving, and the next call waits for a signal.
