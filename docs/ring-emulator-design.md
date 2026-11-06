# One driver: an io_uring engine and a userspace ring emulator

Note (2026-10-25): segmented recv and `forward_to` were removed.

Note (2026-10-25): the TCP provided-buffer ring was removed, with
`OpTag::RecvMulti`, `OpTag::SendRecvBuf`, `OpTag::RecvFallback` and
`recv_incremental`.

Status: proposal. Nothing here is implemented.

## Goal

Ringline has two drivers. The io_uring driver (`backend/uring/`) submits
SQEs and handles CQEs. The mio driver is a second, readiness-based
implementation of the same runtime: `backend/mio/`, the mio `DriverCtx`
(about 1,200 lines of `handler.rs`) and `tls/backend_mio.rs`. It has its
own send queue, recv path, close ordering, timers and teardown. Every
behaviour exists twice, and the two copies drift. Recent examples:

- #617 (fixed in #619) needed fixing on both drivers.
- A TLS `send().await` reported the last record's ciphertext length on
  io_uring and every record's on mio (fixed in #619).
- mio's `forward_held` moved a different amount per call (#620).

This design keeps one driver, the io_uring one, and puts an engine under
it:

- **`UringEngine`** encodes each submission as an SQE and hands it to the
  kernel. This is what runs today.
- **`EmulatedEngine`** executes the same submissions in userspace with
  nonblocking syscalls, mio readiness and the existing disk-I/O thread
  pool, and posts the completions the kernel would have posted.

The driver sees the same completions from either engine. It asks the
engine two capability questions (which close lead to use, and whether
fds can be parked), as it asks the ring today. On macOS, and on a Linux
build with `force-mio`, ringline runs the io_uring driver on the
emulator.

What this gives:

- One implementation of every send, recv, close and teardown rule.
- The io_uring driver builds and runs its tests on macOS. Today it cannot
  be type-checked there.
- The io_uring-only API (`send_chain`, segmented recv, `forward_to`)
  becomes available everywhere.
- The gaps the mio backend has today close: `ConnCtx::cancel`,
  `connect_unix`, `ChildProcess::wait`, NVMe and merged accept are
  unsupported or ignored on mio, and all exist in the io_uring driver.
- A test engine: the emulator can inject short sends, `ENOBUFS`,
  `EAGAIN`, reordered completions and late notifications on demand.
  These are hard to provoke against a real kernel.

## Parity

Every op the driver submits is emulated, and every public API works on
every platform the emulator runs on. There is no "unsupported" outcome.
Where a platform lacks the facility an op uses, the emulator uses that
platform's equivalent and posts a completion of the same shape: the same
result convention, flags and buffer contents the driver parses. The
op-by-op table names the equivalent.

Where the equivalent cannot carry everything the kernel op does, the
difference is listed in that row. These are differences in what the
platform can observe, not missing operations. For example, a macOS
"NVMe" device backed by a file reports errors as errno rather than NVMe
status codes.

Non-goals:

- Matching io_uring's performance on the emulator. The emulated path has
  to be correct and not pathological, the bar CLAUDE.md sets for the mio
  backend today.
- Emulating ops the driver does not use (splice, `LINK_TIMEOUT`, futex,
  `READ_FIXED`, ...).

## Buffers

Every operation already reads from or writes into memory ringline owns:

| Memory | Owner | Used by |
|---|---|---|
| Send-pool slots | `SendCopyPool` | copy sends, TLS records |
| Slab entries (iovecs, guards) | `InFlightSendSlab` | coalesced and zero-copy sends |
| Provided recv buffers | `ProvidedBufRing` | multishot recv, UDP recv, `forward_to` |
| Fallback recv slots | `fallback_recv_pool` (a `SendCopyPool`) | one-shot recv |
| Disk buffers | caller, held by the disk-I/O future | fs, direct I/O |

The engines share these pools, and each buffer's lifetime is the same on
both engines:

- A send borrows its slot or slab entry before it is submitted, and the
  completion handler releases it. A zero-copy entry is released after its
  notification.
- A provided recv buffer is chosen when the recv completes, and goes back
  to the ring when the task has consumed it.

The only difference is who fills or drains the memory:

- **`UringEngine`**: the kernel. A send hands the slot's address to
  `IORING_OP_SEND`; a recv lets the kernel pick a provided buffer.
- **`EmulatedEngine`**: the engine itself. A send `write`s or `writev`s
  from the borrowed memory and posts a CQE when it is done; a recv takes
  a buffer id from the provided ring, `read`s into that buffer and posts
  a CQE that names the id.

The provided buffer ring is ringline memory on both engines.
`ProvidedBufRing` writes entries into a ring and publishes the tail. On
io_uring the ring is mmapped and the kernel consumes from the head. The
emulator reads entries from the same ring between its own head and the
published tail, so `replenish`, `free()` and the `ENOBUFS` accounting are
unchanged.

## The submission type

The driver builds `io_uring::squeue::Entry` values today. The `io_uring`
crate is Linux-only, so the first step is a ringline-owned type:

```rust
pub(crate) struct Sqe {
    pub(crate) op: Op,
    pub(crate) user_data: u64,
    pub(crate) link: Link, // None, Soft (IO_LINK), Hard (IO_HARDLINK)
}

pub(crate) enum Op {
    RecvMulti { fd: Fd, buf_group: u16 },
    Send { fd: Fd, ptr: *const u8, len: u32, flags: i32 },
    SendMsg { fd: Fd, msg: *const libc::msghdr, flags: i32 },
    SendMsgZc { fd: Fd, msg: *const libc::msghdr },
    Close { fd: Fd },
    // ... one variant per opcode in the table below
}

pub(crate) enum Fd { Fixed(u32), Raw(RawFd) }
```

`UringEngine` encodes an `Sqe` into an `squeue::Entry` (or `Entry128`
for NVMe) at push time. `EmulatedEngine` executes it. `Sqe.link`
replaces both conventions in use today: `push_sqe_chain` sets `IO_LINK`
itself on every entry but the last, and `submit_close` sets
`IO_HARDLINK` on the lead before `push_sqe_pair`.

The refactor is bounded by where the driver touches io_uring types today:

| Site | Count |
|---|---|
| `Ring::submit_*` builders in `ring.rs` | 41, two of them test-only |
| `Send` / `SendMsgZc` builders outside `ring.rs` | 15: `handler.rs` ×11, `tls/mod.rs`, `driver.rs`, `runtime/io.rs`, `event_loop.rs` |
| Push choke points (`push_sqe`, `push_sqe128`, `push_sqe_pair`, `push_sqe_chain`) | 4 |
| Stored entries (`BuiltSend.entry`) | 1 field |
| Reads of a stored entry's user_data | 3 sites |
| CQ readers (`ring.completion()`) | 2: `drain_completions` and `run_shutdown` |
| `io_uring::types::Timespec` | 5 files |
| `RecvMsgOut::parse` | 2 sites |
| `cqueue::{more, notif, buffer_select}` | about 20 sites |
| `DestinationSlot` (OPENAT direct install) | 1 site |
| Test-only: `last_pushed` / `last_pushed_opcode`, and `io_uring::` uses in tests | 1 field, 16 uses |

About 100 calls to `Ring::submit_*` keep their signatures. The three
timespec-taking builders and `submit_statx` (which takes a
`*mut libc::statx`) change to ringline types.

Completions need no new type. The event loop already copies each CQE into
`cqe_batch: Vec<(u64, i32, u32)>` and dispatches the tuple
(`dispatch_cqe`). An engine produces tuples.

## The engine interface

The loop uses the ring in three different ways today, and each maps onto
one engine call:

| Today (`event_loop.rs`) | Engine call | Meaning |
|---|---|---|
| `submit_and_wait(1)` when nothing is runnable | `wait(None)` | Start queued work; block until a completion is ready. |
| `submit_and_get_events()` when a task is runnable | `wait(Some(ZERO))` | Start queued work and collect what is ready, without blocking. The emulator polls readiness with a zero timeout here; otherwise it reproduces the worker starvation the comment above that call describes. |
| `flush()` after the poll pass, and mid-batch | `submit()` | Start queued work: each readiness-driven op that is not linked behind an op still in flight (rule 4) makes its first attempt (rule 2; a multishot recv runs one capped pass), disk-pool ops are handed to the pool, cancels, Close, Shutdown and ParkInstall run at once, and timeouts join the deadline heap; `submit` then fires every deadline that has passed (Timeout row). Completions posted by any of these, and disk-pool results already on the channel (rule 5), become visible to the next `reap`. `submit` does not poll readiness and does not resume passes on the cap list. The kernel's `flush()` runs deferred task_work when the SQ is non-empty, including a capped receive's requeue and the recv completions of sockets that became readable. The driver needs neither for correctness: the next `wait` delivers both. |

The loop arms its own wake-up deadline as a TickTimeout SQE, and
`run_shutdown` arms its own, so `wait` needs no timeout of its own.

```rust
pub(crate) trait Engine {
    fn push(&mut self, sqe: Sqe) -> io::Result<()>; // Err: queue full
    fn push_chain(&mut self, sqes: &[Sqe]) -> io::Result<()>;
    fn submit(&mut self) -> io::Result<()>;
    fn wait(&mut self, timeout: Option<Duration>) -> io::Result<()>;
    fn reap(&mut self, out: &mut Vec<(u64, i32, u32)>);

    // Registration.
    fn register_files_sparse(&mut self, n: u32) -> io::Result<()>;
    fn register_files_update(&mut self, slot: u32, fds: &[RawFd]) -> io::Result<()>;
    fn register_buf_ring(&mut self, ring: &ProvidedBufRing, bgid: u16, kind: RingKind) -> io::Result<()>;
    fn unregister_buf_ring(&mut self, bgid: u16) -> io::Result<()>;
    fn register_buffers(&mut self, regions: &[libc::iovec]) -> io::Result<()>;
    fn register_buffers_update_one(&mut self, idx: u32, region: libc::iovec) -> io::Result<()>;

    // Capabilities.
    fn close_lead(&self) -> CloseLead;
    fn supports_park(&self) -> bool;
    fn incremental_buffers(&self) -> bool;

    // Test hooks.
    #[cfg(test)]
    fn inject(&mut self, user_data: u64, result: i32, flags: u32);
    #[cfg(test)]
    fn force_push_failures(&mut self, n: u32);
}
```

`RingKind` is `Plain` or `Incremental` (`IOU_PBUF_RING_INC`); see "Receive
under the shared-ring design". `Ring` becomes `UringEngine`, and both CQ
readers go through `reap`.

The engine is chosen at compile time: `has_io_uring` selects
`UringEngine`, and anything else `EmulatedEngine`. A choice at launch is
open question 2.

## Completion timing

The driver depends on when completions appear, not just on what they say.
The emulator follows these rules, which the driver relies on with
`DEFER_TASKRUN` and does not break under SQPOLL:

1. **A completion is never posted inside `push`.** Work starts in
   `submit` or `wait`, and completions become visible only through
   `reap`. Handlers never run re-entrantly inside a submission.
2. **Every readiness-driven op tries its syscall once when it is
   submitted or re-armed, and waits for a readiness edge only after
   `EAGAIN`.** mio's readiness is edge-triggered. A multishot recv that
   stopped on `ENOBUFS` leaves data in the socket, and no new edge
   arrives for it; the re-arm after a replenish must read at once. The
   same holds for a `POLLOUT` armed after the socket became writable, and
   for an `EventFdRead` re-armed after the wake fd was written. The
   kernel behaves this way: it tries an op at issue and arms a poll only
   on `EAGAIN`.
3. **Independent submissions are not ordered.** The driver must not
   depend on completion order between unrelated SQEs (Domain Invariant
   2), and the emulator does not promise one. Its default order is
   submission order; a test mode shuffles completions to catch code that
   relies on it. The shuffle keeps four orders the kernel guarantees:
   one multishot's CQEs, a zero-copy send's operation CQE before its
   notification, a linked chain, and the CQEs that consume one
   incremental buffer, across connections (the driver derives each
   completion's offset from that order).
4. **Links.** Under `IO_LINK`, an error, or a short result on an op with
   `MSG_WAITALL`, cancels the rest of the chain with `-ECANCELED`. Under
   `IO_HARDLINK` the next op runs whatever the previous result. The close
   lead is hard-linked so that the Close runs even when the lead fails.
5. **Disk-pool results are collected on every `wait` and `submit`.** The
   pool runs on other threads and reports on a channel; the engine drains
   that channel each time, whether or not the wake fd fired, as the mio
   loop does on macOS today to avoid lost kqueue wake-ups. Results that
   change the fixed-file table (OPENAT direct install) are applied on the
   worker thread when they are reaped.

## The fixed-file table

The driver installs an fd into a fixed slot with `register_files_update`
and then closes its own copy at once, because the kernel holds its own
reference to the file. The emulator does the same: on register it takes
a `F_DUPFD_CLOEXEC` copy of the fd and owns it. An update to `-1` (how
fs, direct-I/O and NVMe handles are closed) drops the emulator's copy
once no pending operation names that slot.

Each op resolves its fixed slot to the emulator's fd when it is pushed,
and keeps that fd until it completes. This is what keeps the driver's
close ordering correct:

- The `shutdown_inflight` gate holds a Close until the Shutdown on that
  slot completes; the Shutdown already holds its fd.
- The driver cancels a connection's multishot recv before its Close; the
  cancel finds the recv by user_data and completes it with
  `-ECANCELED`.
- A Close cancels the slot's pending ops (posting `-ECANCELED`) before it
  calls `close(2)`. The kernel's Close does not cancel; the emulator must,
  because once it closes the fd, the number can be reused by the next
  accept.

The engine reports the 6.13 close behaviour (`close_lead()` returns the
cancel lead), because its Close does not wait on other connections'
requests. Today `close_lead_for` reads `KernelVersion::current()`
directly, which exists only on io_uring; it moves behind the engine.

The emulator holds one real fd per connection, as the mio backend does.
`ensure_nofile_limit` and the `RLIMIT_MEMLOCK` checks follow the engine,
not the driver: the emulator needs the mio fd budget and charges nothing
to `RLIMIT_MEMLOCK`.

Fixed buffer registration is a no-op on the emulator: no SQE the driver
builds references `buf_index`.

## Op-by-op

Difficulty: **A** maps directly onto a syscall, **B** needs state in the
emulator, **C** reproduces a kernel rule the driver depends on. **P**
marks a row that needs a platform equivalent off Linux; the equivalent is
named in the row. Rows marked *(verify)* rely on kernel behaviour the
conformance tests confirm against the real ring first.

| OpTag(s) | Opcode | Emulation | |
|---|---|---|---|
| RecvMulti, RecvMultiLarge | RECV multishot, buffer select | Try at arm, then on each readable edge: take buffer space from the arm's group, `read` into it, and repeat until `EAGAIN` or a per-pass cap *(verify the kernel's cap)*, so one fast sender cannot empty a shared group. On a plain group a read takes the head buffer whole and posts `(res, F_BUFFER\|bid<<16\|F_MORE)`. On an incremental group it reads into the head buffer at its current offset, posts `F_BUF_MORE` while the buffer has space left, and moves to the next buffer when it is used up. Each CQE is held until the next read of the same pass returns: if that read returned data, the held CQE gets `IORING_CQE_F_SOCK_NONEMPTY`; if it returned `EAGAIN`, it does not. When the pass stops at the cap, or because the group has no space left, one `ioctl(FIONREAD)` decides the flag. The flag also counts bytes that arrived after the held CQE's read, which the kernel's does not. A pass posts its held CQE before another connection's pass takes space from the same incremental group. A read that returns `0`, `EAGAIN` or an error puts the space back. A `0` or error CQE carries no `F_BUFFER`, and an `EAGAIN` read posts no CQE. A pass that stops at its cap goes on a list the engine keeps, since no new readiness edge arrives for data already queued. A listed pass leaves the list when it is resumed, and when its arm ends (`-ENOBUFS`, EOF, an error, a cancel by user_data or by fixed slot, a Close, or a group move). `wait` resumes each listed pass at most once, before it polls readiness; `submit` does not resume them. After the resumes, `wait(None)` polls readiness with a zero timeout if the list is non-empty or a completion is ready, and blocks otherwise. Resuming listed passes first lets capped connections take buffer space before newly readable ones; each pass is capped, so this bounds the wait of the others *(verify against the kernel's task_work order)*. No buffer: post `-ENOBUFS` without `F_MORE` (the arm ends; the driver re-arms on replenish, Domain Invariant 6). EOF: post `0` without `F_MORE`. Other errors: `-errno` without `F_MORE`. | C |
| RecvMsgUdp | RECVMSG multishot | As RecvMulti, and write the `io_uring_recvmsg_out` header, name and control data into the buffer in the kernel's layout so `RecvMsgOut::parse` (or its replacement) reads it. On Linux the control data is what `recvmsg` returns (`UDP_GRO`). Off Linux there is no GRO, so each completion carries one datagram and no segment-size control message, which the driver already reads as a single datagram. | C, P |
| RecvUdp | RECV multishot | As RecvMulti on a UDP socket. | B |
| RecvFallback | RECV one-shot into a pool slot | Try at submit, then on readable; one CQE. | A |
| Send, TlsSend, *Drain | SEND, `MSG_DONTWAIT`, or `MSG_WAITALL` in a chain | One `write`: post what it took, or `-EAGAIN` or another `-errno`. With `MSG_WAITALL`, `write` until all bytes are sent, waiting for writable in between. Post the total, or, on an error, the bytes written before it if any *(verify)*, otherwise `-errno`. | B |
| SendMsgCoalesced | SENDMSG, `MSG_DONTWAIT` | One `writev` of the iovecs, with the same rule. | B |
| SendMsgZc | SENDMSG_ZC, `MSG_DONTWAIT`, or `MSG_WAITALL` in a chain | One `writev`, posting a short count when that is all the socket took, or `-EAGAIN`. Then post the operation CQE with `F_MORE` and a separate `F_NOTIF` CQE in the same reap. A notification follows exactly when `F_MORE` is set, including on error and zero-length results (#487). The `writev` reads the guard's memory in place; the kernel copies it into the socket buffer, so the send is not zero-copy, but ringline makes no copy of its own. | C |
| SendPollOut | POLL_ADD POLLOUT, one shot or multishot | Check writability at submit; otherwise post on the writable edge. A peer's half-close posts `POLLRDHUP` without `POLLOUT` at once. A multishot poll posts each edge with `F_MORE`, stays armed, and posts `-ECANCELED` without `F_MORE` when cancelled by user_data. | B |
| Connect | CONNECT | Nonblocking `connect`, then `SO_ERROR` on writable, as the mio backend does today. | A |
| Shutdown, CloseShutdown | SHUTDOWN | `shutdown(2)` on the op's fd. | A |
| Close | CLOSE (fixed) | See the fixed-file table: cancel the slot's pending ops, then drop the emulator's fd. | C |
| CloseCancel, Cancel | ASYNC_CANCEL (by user_data; by fixed fd, all) | Exact 64-bit user_data match, or every pending request on the fixed slot. The cancelled request posts `-ECANCELED`; the cancel posts `0` or `-ENOENT`. | B |
| Timeout, TickTimeout, Timer | TIMEOUT (relative, `ABS`) | A min-heap of deadlines, computed from the timespec at push (the caller's timespec need not outlive the push, as with the kernel). Fires post `-ETIME`; a cancel posts `-ECANCELED`. `wait` and `submit` each fire every deadline that has passed. `wait` blocks no later than the earliest deadline. | B |
| EventFdRead | READ on the eventfd | The worker's wake fd (a pipe on macOS). Try at arm, then on readable. | A |
| AcceptMulti | ACCEPT multishot | Try at arm, then on readable: `accept` (with `SOCK_NONBLOCK\|SOCK_CLOEXEC`, or `fcntl` after `accept` where `accept4` is missing) until `EAGAIN`, one CQE per fd with `F_MORE`. | B, P |
| ParkInstall | FIXED_FD_INSTALL | `fcntl(F_DUPFD_CLOEXEC)` on the slot's fd; post the new fd. The kernel installs it close-on-exec, which #460 relies on. | A |
| PidfdPoll | POLL_ADD on a pidfd | On Linux, poll the pidfd for readable. Off Linux there are no pidfds: the engine registers `EVFILT_PROC` / `NOTE_EXIT` for the pid on its kqueue and posts the completion when the child exits. `ChildProcess::wait` then works as on Linux. | A, P |
| SendMsgUdp, SendUdp | SENDMSG (with `UDP_SEGMENT`), SEND | `sendmsg`, with `UDP_SEGMENT` on Linux. Off Linux there is no GSO: the engine sends one datagram per segment and posts one completion with the total. | B, P |
| Fs, DirectIo | OPENAT (direct install), READ, WRITE, FSYNC, STATX, RENAMEAT, UNLINKAT, MKDIRAT | The disk-I/O thread pool (`disk_io_pool.rs`) runs the call. OPENAT installs into the emulated fixed-file table when reaped. Off Linux: STATX is filled from `fstatat` (fields `stat` lacks are left zero and unmarked in the mask), and direct I/O uses `F_NOCACHE` where Linux uses `O_DIRECT`. | B, P |
| NvmeCmd | URING_CMD (SQE128) | The API is `open_nvme_device` plus three commands: read, write, flush. On Linux the disk-I/O pool runs the same command with the synchronous `NVME_IOCTL_IO64_CMD` ioctl on the same `/dev/ngXnY` device and posts its NVMe status word as the result, so `handle_nvme_cmd` is unchanged. Off Linux there is no NVMe passthrough for user processes: the "device" is a raw disk (`/dev/rdiskN`, root only) or a file, read becomes `pread` and write `pwrite` at LBA × block size, and flush becomes `fcntl(F_FULLFSYNC)`. Errors there are errno, not NVMe status codes, and `nsid` is ignored. | B, P |

The ring setup flags have no counterpart in the emulator: `COOP_TASKRUN`,
`SINGLE_ISSUER`, `DEFER_TASKRUN`, SQPOLL and the io-wq worker cap. The
completion-timing rules above are what the driver observes of them.

## Receive under the shared-ring design

`docs/recv-incremental-ring-design.md` (#622) sets how the driver receives
TCP data: one or two shared buffer groups per worker, incremental
consumption (`IOU_PBUF_RING_INC`) where the kernel has it, a bounded
accumulator, and promotion of streaming or holding connections to a group
of 1 MiB buffers. This section maps that onto both engines and counts what
each one costs per request.

### What the driver asks of the engine

| Need | `UringEngine` | `EmulatedEngine` |
|---|---|---|
| Register a group as incremental or plain (`RingKind`) | `IORING_REGISTER_PBUF_RING` with or without `IOU_PBUF_RING_INC`. An `EINVAL` on the incremental form means the kernel lacks it; the engine reports that and the driver registers plain rings. The Ubuntu 6.8 reserved-word retry (#626) stays inside the engine. | Both kinds, in userspace. |
| `incremental_buffers()` | Whether incremental rings are usable: the flag is accepted and, if #622 step 0 keeps a behaviour probe, that probe passes. | `true`. The driver selects the ring kind from this and `recv_incremental`, as #622's ring-kind selection describes, so `recv_incremental(false)` gives the plain row on the emulator too. |
| `F_BUFFER`, `F_MORE`, `F_BUF_MORE` | The kernel's flags. | Posted by the RecvMulti emulation (op-by-op table). |
| `IORING_CQE_F_SOCK_NONEMPTY` (promotion) | The kernel's flag. | Set from the next read of the same pass, or from `FIONREAD` when the pass stops at its cap or the group has no space left. |
| The group a receive was armed on | Its tag: `RecvMulti` or `RecvMultiLarge`. | The same tags; the emulator does not interpret them. |
| Move a connection between groups | `ASYNC_CANCEL` by user_data, then a new arm. | Drop the emulated arm and post `-ECANCELED`, then a new arm, which reads at once (rule 2). |

The driver's buffer-state rules, the lend cap, the bounded accumulator and
promotion are driver code and run unchanged on both engines.

### Copies per request

Copies ringline makes in userspace, not the kernel's copy out of the
socket, as `docs/syscalls-and-copies.md` and CLAUDE.md count them. Both of
those tables count provided buffer → accumulator as one mandatory copy; the
`pending_recv_bufs` path in `handle_recv_multi` makes a completion holding
one whole message 0 today, and both tables should say so.
"Today" is the code at the base of this design; "#622" is the shared-ring
design on either engine.

Receive:

| Case | io_uring today | mio today | #622, io_uring or emulator |
|---|---|---|---|
| A completion holding exactly one whole message, accumulator empty, `with_data` | 0: the buffer is held in `pending_recv_bufs` and parsed in place, one buffer per connection at a time | 1: 8 KiB scratch → accumulator | 0 |
| Several whole messages in one completion, `with_data` | 0 for the first; 1 for the rest (`WithDataFuture` appends the remainder after a partial consume) | 1 | as io_uring today |
| A second completion while one is held | 1: both buffers copied into the accumulator | 1 | 1, as today |
| Bytes already buffered | 1 for the whole completion | 1 | with `NeedAtLeast(n)`: the bytes that complete the message are copied and the rest of the completion is handled as the rows above; with `NeedMore`: 1 for the whole completion |
| A message split across completions | 1 for every byte | 1 | 1 for every byte of the message: the first share is copied when the parser asks for more, the later shares by the bounded copy. Bytes past the message end are not copied by the bound. |
| `with_bytes` | 1: a held buffer is always copied into the accumulator first; `Bytes` views of the accumulator are then free | 1 | 1, unchanged by #622 |
| TLS | 1 (decrypt into the accumulator) | 1 | 1 |
| Above a group's lend cap | — | — | 1 |

Send counts do not change with #622. On the emulator a send writes from the
memory the driver lent it (the send-pool slot, or a guard's memory), so the
counts are io_uring's: 1 copy for `send()` and copy parts, 0 for guard parts
above `send_zc_threshold`. The kernel's copy into the socket buffer, which
replaces io_uring's zero-copy DMA there, is not counted. Today's mio backend
copies every send into a queued `Vec` (`send_inner`, `handler.rs`), so the
emulator removes that copy for guard parts.

### Syscalls per request

| Step | io_uring | Emulator | mio today |
|---|---|---|---|
| Learn the request arrived | share of one `io_uring_enter` | share of one `epoll_wait` (`kevent` on macOS) | share of one `epoll_wait` |
| Read the request | 0 | 1 `read` per completion that carries data, EOF or a read error, plus the `read` returning `EAGAIN` that ends a pass (a readable edge, an arm, a re-arm, or a pass resumed from the cap list); a pass that stops at its cap, for lack of space, at EOF or on an error has none | N `read`s per edge on Linux TCP, plus 1 `EAGAIN` otherwise, into a scratch buffer |
| `SOCK_NONEMPTY` | 0 | 0, except one `ioctl(FIONREAD)` when a pass stops at its cap or the group runs out of space | — |
| Send one response | 0 dedicated | 1 `write`, or 1 `writev` per 32 send-pool slots when the response spans more than one (2 operations when the send slab has no free entry) | share of one `writev` per connection per flush |
| Send N pipelined responses on one connection | 1 + ⌈(N−1)/32⌉ SQEs: the first response, then one `SendMsgCoalesced` per 32 queued behind it (2 measured at depth 2–32), 0 dedicated syscalls | as many `write`/`writev`s as SQEs (derived, not measured) | 1 `writev` |
| Move a connection between groups | 0 dedicated (cancel and arm are SQEs) | 0 dedicated: the arm is a pass, counted above; when nothing is queued that pass is one `read` returning `EAGAIN` | — |
| Re-arm after `ENOBUFS` | 0 dedicated | 0 dedicated: the re-arm's read is the pass's first, counted above (rule 2) | — |

The driver keeps one send in flight per connection. Queued copy sends,
plaintext or TLS ciphertext, coalesce into one `SendMsgCoalesced` of up to
32 iovecs when the in-flight send completes (#628), each awaited send
settling with its own length, so N pipelined responses cost the first
response's operation and one more per 32 queued behind it, and a TLS
response's ciphertext slots go out as `SendMsgCoalesced` operations of up to
32 slots each when nothing is in flight. The emulator
still pays at least one more `write` than mio's single `writev` per flush
for a pipelined batch; the `FIONREAD` when a
pass stops at its cap or for lack of space is the other extra syscall.

### Measuring the counts

One client, one machine pair, through SystemsLab, so the engines are the
only difference:

- Engines: `UringEngine` with incremental rings (6.12+), `UringEngine`
  with plain rings and two groups (6.1), `EmulatedEngine` on Linux, and the
  mio backend while it exists.
- Workloads: request/response at 64 B, 4 KiB, 64 KiB and 1 MiB, pipeline
  depth 1 to 32, and a streaming cell.
- Syscalls per request from rezolus' syscall counters, divided by requests.
  Copies per request from receive counters (bytes lent, bytes copied)
  and a send-pool copy counter, which this measurement adds; neither
  exists today.

The results replace the measured section of `docs/syscalls-and-copies.md`,
which today compares two different programs.

## Tests

Three layers:

1. **Engine conformance tests.** For each op, a test drives it through
   the `Engine` interface against real sockets and files and checks the
   CQEs: result, flags and buffer ids. On Linux the same tests run
   against `UringEngine` and `EmulatedEngine`, so the emulator is checked
   against the kernel rather than against a description of it. The rows
   marked *(verify)* are settled here, before the emulator implements
   them. On macOS the tests run against `EmulatedEngine` with the
   platform equivalents, and assert the differences each **P** row lists,
   so a difference cannot grow unnoticed.
2. **The driver's unit tests.** The io_uring lib tests (756 `#[test]`
   items in `ringline/src`, 23 of them mio-only) run on both engines.
   Tests that inject results through the real ring
   (`IORING_NOP_INJECT_RESULT`) use the engine's `inject` hook instead.
3. **The integration tests** (`tests/*.rs`) run on both engines, on
   Linux in CI and on macOS.

## Landing

Each step is a separate PR. Steps 1–6 keep both backends working.

1. **`Sqe`.** Introduce the ringline-owned submission type and encode it
   in `Ring`. `BuiltSend` stores an `Sqe`. Linux only, no behaviour
   change.
2. **`Engine`.** Turn `Ring` into `UringEngine` behind the `Engine`
   interface, route both CQ readers through `reap`, and move
   `close_lead_for` and the park probe behind it. Replace the remaining
   io_uring types in the driver and its tests (the table above) with
   ringline types. Split the `has_io_uring` cfg in two: one for the
   driver (the io_uring driver, on every platform) and one for the engine
   (`UringEngine` or `EmulatedEngine`). The startup checks
   (`ensure_nofile_limit`, `RLIMIT_MEMLOCK`) follow the engine cfg. There
   are about 184 `cfg(has_io_uring)` sites in 20 files to sort between
   the two. After this the driver compiles without the `io_uring` crate.
3. **First emulated slice.** `EmulatedEngine` on Linux behind a
   `ring-emulator` feature, with RecvMulti on both ring kinds (incremental
   offsets, `F_BUF_MORE` and `SOCK_NONEMPTY` included), Send,
   Connect, Close, the close leads, Cancel, Timeout/TickTimeout/Timer and
   EventFdRead. Acceptance: the conformance tests for those ops pass on
   both engines, and the `tests/echo.rs` tests that use only those ops
   pass on the emulator (the PR names the filter).
4. **The rest of the table**, op group by op group: accept; coalesced,
   zero-copy and forward sends; chains; UDP; fs and direct I/O; park;
   process; NVMe on Linux.
5. **macOS.** Build the io_uring driver on the emulator on macOS and run
   the full suite in CI.
6. **Parity on macOS.** The **P** rows: UDP without GRO/GSO, accept
   without `accept4`, process exit through kqueue, file-backed NVMe,
   `fstatat` and `F_NOCACHE`. Every public API is available on every
   platform, and the `#[cfg(has_io_uring)]` gates on public items are
   removed.
7. **Retire the mio backend** once the emulator passes everything the
   mio backend passes and #628 has landed, so pipelined plaintext and TLS
   sends cost the emulator no more syscalls than mio. `force-mio` becomes
   the switch that selects the emulator on Linux.

## Questions for the owner

1. **Retire the mio backend at step 7, or keep it?** Keeping it keeps
   two drivers, which is the cost this design removes. Retiring it means
   the emulator carries macOS alone.
2. **Engine choice at launch.** Should Linux fall back to the emulator
   when `io_uring_setup` is refused (RHEL 10 ships
   `io_uring_disabled = 2`), instead of requiring a `force-mio` build?
   That needs an enum over the two engines, so every push branches on the
   engine; the driver itself stays non-generic. The fd and
   `RLIMIT_MEMLOCK` checks run before ring setup, so a fallback would
   start under the io_uring limits and must recheck them.
3. **Breaking changes on macOS.** Retiring mio changes the public API
   there: `forward_to_conn` returns a different future type per backend
   today (`ForwardToConnFuture` is exported only without io_uring), and
   `ringline::backend()` returns `Backend::Mio`. Under the release
   process these are breaking changes to batch into a coordinated
   release.

## Notes

- Copy counts use CLAUDE.md's basis: copies ringline makes in userspace,
  not the kernel's copy out of the socket. Where the receive rows differ
  from its table, "Copies per request" says why. "Receive
  under the shared-ring design" above gives the counts per engine.
- kTLS is designed (`docs/ktls-design.md`) but not implemented. Its
  design sends plaintext with `IORING_OP_SEND` with `STREAM_SEND_FLAGS`, which
  the emulator's Send already follows. The kernel TLS
  socket itself is a platform facility the emulator cannot provide off
  Linux; parity there needs the userspace TLS path, as today.

## Found while surveying

- **The connect-timeout cancel never matches.** `arm_connect_timeout`
  (`handler.rs`) arms the timeout with `payload = generation`, but the
  three cancels of it (one in `handler.rs`, two in `event_loop.rs`)
  encode payload 0, and `ASYNC_CANCEL` matches the whole user_data. The
  timeout therefore always runs to `-ETIME`. `handle_timeout` ignores it,
  because it checks the generation and `connect_timeout_armed`. Harmless
  today; the emulator's exact-match cancel must not hide it.
- **A stale comment** in `ring.rs` above `submit_park_recv_cancel`
  describes an `IO_LINK` from the park recv-cancel to the install, which
  the code no longer has. The same block carries `submit_async_cancel`'s
  orphaned summary line.
