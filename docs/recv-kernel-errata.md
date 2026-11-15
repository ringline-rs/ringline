# Kernel errata for io_uring TCP receive

Status: reference, researched 2026-10-14. For each receive mechanism in
`docs/recv-buffering-approaches.md`, this lists the kernel that introduced
it, later changes in behaviour, and fixed bugs, with the fixing commit, the
first mainline release that has it, and the stable releases that got it.

Sources: the stable tree (branches `linux-6.1.y` at 6.1.189, `linux-6.6.y`,
`linux-6.12.y` at 6.12.112, `linux-6.18.y`, `linux-7.1.y` at 7.1.13 and
mainline at 7.3-rc6), the kernel CVE records (`vulns.git`), and Ubuntu's
`noble` kernel git. A stable version is the first stable tag that has the
backport; a dash means none was found. Claims marked "unverified" rest on a
secondary source. The rest were read from the commit, its diff or the source
at the named tag. For two older fixes listed here, 561e4f9451d and
b00c51ef8f7, only the mapping from the mainline commit to its stable
backport was checked. The Debian package versions come from Debian's
security tracker. Commits are at `https://git.kernel.org/torvalds/c/<id>`.

Version numbers do not identify the fix level of a distribution kernel,
which can carry backports or lack them. That is why ringline checks the
behaviour it relies on at startup instead of comparing versions
(`docs/recv-incremental-ring-design.md`, "Selecting the ring kind").

## Distribution kernels

| Distribution | Kernel | Notes |
|---|---|---|
| Debian 12 | 6.1.y (6.1.176, security 6.1.187) | no incremental rings, no bundles |
| Amazon Linux 2023 | 6.1 by default, `kernel6.12` optional (unverified) | |
| Ubuntu 24.04 | Ubuntu's own 6.8 tree | provided-ring registration inverted from 6.8.0-136 (below) |
| Debian 13 | 6.12.y (6.12.107, security 6.12.111) | |
| RHEL / Rocky 10 | 6.12-based | `kernel.io_uring_disabled = 2`: io_uring refused for every process (#355) |

## Provided buffer rings

Introduced in 5.19 (`IORING_REGISTER_PBUF_RING`; the introducing commit,
c7fb19428d67, is named by CVE records and not read here). Kernel-allocated
rings (`IOU_PBUF_RING_MMAP`) arrived in 6.4 (c56e022c0a27), and
`IORING_REGISTER_PBUF_STATUS` in 6.8 (d293b1a89694, not in 6.1.y or 6.6.y).

Registration rules:

| Check | 6.1.y | 6.6.y | 6.12.y | mainline |
|---|---|---|---|---|
| `ring_entries` | power of two, below 65536 (largest 32768) | same | same | same |
| reserved words | must be 0 | must be 0 | must be 0 | must be 0 |
| flags | none | `MMAP` | `MMAP`, `INC` | `MMAP`, `INC` |
| `min_left` | absent | absent | from 6.12.90 | from 7.1 |

The 32768 limit is f9437ac0f851 (5.19-rc3): the ring's 16-bit head and tail
cannot tell a full ring of 65536 from an empty one.

`min_left` (7deba791ad49) takes the low four bytes of what was `resv[0]`.
A nonzero value there on a plain ring returns `EINVAL` on kernels that have
the field, so a workaround that sets `resv[0]` must stay limited to the
kernels that need it (Ubuntu 6.8, below).

Fixes that affect a receive path:

| Commit | Subject | Mainline | Stable | Effect |
|---|---|---|---|---|
| 561e4f9451d | hold io_buffer_list reference over mmap | 6.9 | 6.6.26, 6.8.5 | CVE-2024-35880: use-after-free between mmap and unregister of an `MMAP` ring |
| 8802766324e1 | reallocate buf lists on upgrade | 6.14 | 6.6.79, 6.12.16 | CVE-2025-21836: a ring registered at a bgid used before for legacy buffers reused a live structure |
| c2c185be5c85 | check if target buffer list is still legacy on recycle | 7.0 | 6.1.167, 6.6.130, 6.12.78, 6.18.19 | CVE-2026-43366: legacy-buffer recycle into a list upgraded to a ring |
| 46800585ae04 | validate ring provided buffer addresses with access_ok() | 7.2 | none | an entry with an address outside user space makes single-buffer selection return `-ENOBUFS` without consuming it |
| cd053d788c3f, f1596ba3e6b3 | fix dangling iovec after provided-buffer bundle grow failure; free the replaced iovec after a successful grow | 7.2-rc3, rc4 | none | 46800585ae04 introduced a double free on bundle grow failure (7.2-rc1, rc2); cd053d788c3f's fix introduced a second (7.2-rc3), fixed by f1596ba3e6b3, per the commits' `Fixes:` tags |

From 7.2, a runtime that answers `-ENOBUFS` by re-arming after the next
replenish would re-arm onto the same bad entry. That needs a bad address,
which only a runtime bug produces.

## Multishot receive

`IORING_RECV_MULTISHOT` on `RECV` and `RECVMSG`: 6.0 (b3fdea6ecb55,
9bb66906f23e). `IORING_CQE_F_SOCK_NONEMPTY` and
`IORING_RECVSEND_POLL_FIRST`: 5.19 (liburing man pages; unverified as to
commit). A multishot `RECV` requires buffer select and rejects
`MSG_WAITALL`; before 6.17 it also requires `sqe->len == 0`.

An empty ring ends the arm with `-ENOBUFS` and no `F_MORE` on every kernel
from 6.0 to 7.3-rc6.

A full CQ at a multishot completion:

| Kernels | Behaviour |
|---|---|
| 6.0, 6.1.y | the arm stops; its final result can go to the overflow list, and the kernel comment says ordering can no longer be trusted |
| 6.2 to 6.5.2 | multishot completions go to the overflow list and the arm continues (e2ad599d1ed3) |
| 6.5.3 and later | the arm stops without `F_MORE` (b2e74db55dd9, b6b2bb58a754; CVE-2023-54030) |

How long one multishot receive is served before others:

| Kernels | Behaviour |
|---|---|
| 6.0, 6.1.y | no cap: the receive loops while its socket has data and buffers last |
| 6.6.17 and later, Ubuntu 6.8 | at most 32 inline retries (`MULTISHOT_MAX_RETRY`, 76b367a2d831), then the request goes to the back of the task_work queue |
| 6.17 and later | an optional per-invocation byte cap (below) also requeues |

Fixes:

| Commit | Subject | Mainline | Stable | Effect |
|---|---|---|---|---|
| b00c51ef8f7 | cache provided buffer group value for multishot receives | 6.2 | 6.1.9 | multishot lost its bgid after the first buffer on some paths |
| 8ede3db5061b and two more | multishot recvmsg overflow check, retry setup | 6.9 | 6.1.83/84, 6.6.23/24 | CVE-2024-35827 |
| d63b0e8a628e | fix multishots with selected buffers | 6.14 | 6.1.129, 6.6.78, 6.12.14 | buffer ring state not flushed between iterations |
| 687b2bae0eff | ensure deferred completions are flushed for multishot | 6.15 | 6.12.29; applied to 6.1.139 and 6.6.91, then reverted | without it a multishot completion can be posted before an earlier deferred completion |
| a7d755ed9ce9 | fix overflow resched cqe reordering | 6.15 | 6.1.141, 6.6.93, 6.12.31 | completions reordered while flushing the overflow list |
| 2c7f02321996 | only consider msg_inq if larger than 1 | 6.16 | 6.12.36 | retries need `msg_inq > 1`; `SOCK_NONEMPTY` can be set when only a FIN is pending (from the commit message) |
| a68ed2df7213 | fix multishot recv missing EOF on wakeup race | 7.0 | 6.1.175, 6.6.140, 6.12.86, 6.18.20; Ubuntu 6.8.0-148 | data followed at once by `shutdown()` could leave the arm armed with no EOF completion |

For ringline:

- `SOCK_NONEMPTY` is a hint. The promotion rule in
  `docs/recv-incremental-ring-design.md` reads it on completions of at
  least 64 KiB, where a pending FIN alone does not matter.
- On 6.1 (Debian 12, Amazon Linux 2023) one multishot receive can be served
  for as long as its socket has data. ringline arms one-shot receives by
  default (#647).
- 6.1 before 6.1.175 and 6.12 before 6.12.86 can miss EOF after data and a
  FIN back to back. Debian 12's 6.1.176 and Debian 13's 6.12.107 have the
  fix.

## Incremental buffers (`IOU_PBUF_RING_INC`)

Introduced in 6.12 (ae98dbf43d75). Absent from 6.1.y, 6.6.y and Ubuntu 6.8,
where registration with the flag returns `EINVAL`. 6.12.81 backported the
6.15–6.19 rework of the buffer code (about 25 commits), so 6.12 before and
after 6.12.81 differ in structure as well as in fixes.

| Commit | Subject | Mainline | Stable | Effect |
|---|---|---|---|---|
| ed123c948d06 | use pre-committed buffer address for non-pollable file | 6.13 | 6.12.9 | non-pollable files only: data placed past the start of the buffer, or a spurious `-EFAULT` |
| cf9536e550dd | enable bundles for incrementally consumed buffers | 6.15 | 6.12.81 | before, a bundle on an incremental ring mapped one buffer |
| 98b6fa62c84f | always use READ_ONCE() to read ring provided buffer lengths | 6.17 | part in 6.12.49, all in 6.12.81 | CVE-2025-39816: a user-triggerable `WARN_ON_ONCE`; the full fix stops the commit loop at a zero-length entry |
| 418eab7a6f3c | propagate BUF_MORE through early buffer commit path | 7.0 | 6.12.78, redone in 6.12.81; 6.18.20 | `F_BUF_MORE` never set for non-pollable input or for bundle early commit |
| 3ecd3e03144b | fix missing BUF_MORE for incremental buffers at EOF | 7.0 | 6.12.81, 6.18.20 | a zero-length completion (EOF) reported the buffer as used up although no bytes were used |
| b948f9d5d305 | fix slab-out-of-bounds read in io_bundle_nbufs() | 7.0 | 6.12.81, 6.18.22 | CVE-2026-31774: `sqe->len > INT_MAX` on a bundle; now `EINVAL` |
| 7deba791ad49 | support min length left for incremental buffers | 7.1 | 6.12.90, 6.18.30, 7.0.7 | `min_left`: a buffer with less than this left is finished. Without it, multishot `RECVMSG` can fail with `-EFAULT` when less space is left than its header needs |
| ed46f39c47eb | inherit IORING_CQE_F_BUF_MORE across bundle recv retries | 7.1 | 6.12.94, 6.18.36, 7.0.13 | CVE-2026-53191: incremental ring plus bundle receive dropped `F_BUF_MORE`, so the application moved past a buffer the kernel was still writing |
| 6028b543884f | don't overconsume buffers when using MSG_TRUNC | 7.3 | 6.12.112, 6.18.53, 7.2.7 | CVE-2026-97618: a receive with `MSG_TRUNC` and a datagram larger than the buffer consumed the whole datagram's length from the ring. Datagram sockets; whether it matters for TCP is not established |

These are the fixes the design doc refers to ("non-pollable files, bundles,
zero-length transfers and multishot `RECVMSG` with little space left"):
non-pollable files are ed123c948d06 and 418eab7a6f3c, bundles are
cf9536e550dd, b948f9d5d305, ed46f39c47eb and 70f4886bcbb9, zero-length
transfers are 3ecd3e03144b, and `RECVMSG` with little space left is
7deba791ad49. Debian 13's 6.12.107 and 6.12.111 have every fix through
6.12.94 and lack 6028b543884f. 7.2.6 also lacks 6028b543884f, which is in
7.2.7.

For ringline:

- Detect incremental rings by registering, as the startup preflight does.
- On a kernel without 3ecd3e03144b (6.12.0–6.12.80, 6.18.0–6.18.19), an EOF
  completion on an incremental buffer reports the buffer as used up even
  though no bytes were written. The preflight's step 4 checks EOF on a
  partly used buffer (no `F_BUFFER`, entry left at the used length); a
  kernel that reports it differently fails the preflight and gets a plain
  ring. The exact completion such a kernel posts was not checked here.
- Do not combine incremental rings with bundles on 6.12 before 6.12.94.
- Multishot `RECVMSG` on an incremental ring needs `min_left` of at least
  the header size, which needs 6.12.90 or 7.1. ringline issues `RECVMSG`
  only for UDP, on a plain ring.
- Do not use `MSG_TRUNC` on receives into an incremental ring before
  6.12.112, 6.18.53 or 7.2.7.

## Bundles (`IORING_RECVSEND_BUNDLE`)

Introduced in 6.10 (2f9c9515bdfd), reported by
`IORING_FEAT_RECVSEND_BUNDLE`. Not in 6.1.y, 6.6.y or Ubuntu 6.8. `RECVMSG`
with a bundle returns `EINVAL`. ringline does not use bundles.

| Commit | Subject | Mainline | Stable | Effect |
|---|---|---|---|---|
| 6e92c646f5a4 | don't clear msg_inq before io_recv_buf_select() needs it | 6.10 | in 6.10 | before, a bundle never received more than one buffer |
| 7c71a0af81ba | improve recv bundles | 6.15 | 6.12.36 | a one-shot bundle retries and posts one completion for all available data |
| 3a08988123c8 | only retry recv bundle for a full transfer | 6.15 | 6.12.36 | a short transfer then a retry could leave a gap in the data |
| 178b8ff66ff8 | flag partial buffer mappings | 6.16 | 6.12.36 | a partial mapping could still retry and leave a gap |
| 41b70df5b38b | commit partial buffers on retry | 6.17 | 6.6.103, 6.12.44; Ubuntu 6.8.0-148 | CVE-2025-38730: a short stream receive kept its buffer across a retry, so two sockets sharing a buffer group could receive into the same memory. Applies to plain rings and one-shot receives, not only bundles. The CVE record lists 6.1.y as not affected |
| 70f4886bcbb9 | don't truncate end buffer for bundles | 7.1 | 6.12.94, 6.18.36, 7.0.13 | a shortened last buffer stayed shortened when the transfer then failed |

Detect bundles with `IORING_FEAT_RECVSEND_BUNDLE`. Completion semantics
changed in 6.12.36 and 6.15. Data-gap fixes are in 6.12.36, the
shared-buffer-group corruption fix in 6.12.44 and 6.6.103.

## Byte limits on a multishot receive

Introduced in 6.17, in two forms (verified from the commits and source):

- `sqe->len` on a multishot `RECV` caps the bytes one invocation receives
  before the request is requeued; the arm stays live (6a8afb9fff64).
- `sqe->optlen` sets a total for the arm; when it is used up the arm ends
  without `F_MORE` (0ebc9a7ecf6a).

There is no user-visible flag; `IORING_RECV_MSHOT_LIM` and its siblings are
internal. Before 6.17, `sqe->len != 0` on a multishot `RECV` returns
`EINVAL`, which matches what the benchmark saw on 6.12
(`docs/journal/2026-09-incremental-buffer-consumption.md`). Before 6.17
`sqe->optlen` is not checked and is ignored, so a total cap set there does
nothing. Probe for `len` first and use `optlen` only where that succeeds.

## One-shot receive with buffer select

`IORING_RECVSEND_POLL_FIRST` (5.19) is unchanged through mainline. A one-shot
`RECV` with buffer select and `len == 0` takes its length from the buffer.

- 72bd80252fee (6.8; 6.1.78, 6.6.17): with `MSG_WAITALL` and a short
  receive, the retry computed a huge length and failed with `-EFAULT`.
- 41b70df5b38b (above) applies to one-shot receives on plain rings.
- A one-shot receive on an incremental ring commits through the same path as
  multishot and gets `F_BUF_MORE` the same way (inferred from the 6.12.y and
  mainline source). ringline's preflight checks it on the running kernel.

## Zero-copy receive (zcrx)

Introduced in 6.15 (`IORING_REGISTER_ZCRX_IFQ`, 6f377873cb23;
`IORING_OP_RECV_ZC`, 11ed914bbf94). Not on 6.12.y; whether RHEL 10
backports it is not established. It needs NIC header/data split, flow
steering to a dedicated hardware queue, `IORING_SETUP_DEFER_TASKRUN` with
`CQE32` (or `CQE_MIXED` from 6.18), and `CAP_NET_ADMIN`.

CVE fixes since: CVE-2025-38504 (6.15.7), CVE-2025-40046 (overshooting the
receive limit, 6.17.3), CVE-2026-23263 (6.18.10), CVE-2026-43121 and
CVE-2026-43224 (6.18.16), CVE-2026-43174 (6.19.6), CVE-2026-45995 (7.0.4).
With that many fixes through 7.0, and root-level NIC setup, it is not a
default receive path for a general runtime.

## Ring settings that affect receive

| Item | Kernels | Effect |
|---|---|---|
| `IORING_SETUP_DEFER_TASKRUN` | 6.1 (c0e0d6ba25f1) | task_work, including receive completions, runs only in `io_uring_enter` with `GETEVENTS` |
| Local task_work cap | 6.13 (f46b9cdb22f7, 49c5c63d48eb); not in 6.12.y | at most `max(20, min_events)` items per run; the rest wait for the next. On 6.12 all pending work runs in one pass |
| Ring memory charged to `RLIMIT_MEMLOCK` | 6.14 (8078486e1d53, 81a4058e0cd0, ef62de3c4ad5); not in 6.12.y. Removed in 7.3 (b59cabf9b4ac), 7.2.11 and 6.18.58; 7.0.14 and 7.1.13 still charge | SQ, CQ and provided-ring entry arrays (16 bytes per entry, page-rounded) are charged unless the process has `CAP_IPC_LOCK`; over the limit is `ENOMEM` |
| `kernel.io_uring_disabled` | 6.6 (76d3ccecfa18) | 2 refuses `io_uring_setup` for every process; RHEL and Rocky 10 ship 2 |

The design doc says an `io_uring_enter` makes at most two task_work passes
from 6.13. That was not checked here.

## Ubuntu 6.8: inverted reserved-word check

Ubuntu's `noble` commit cff3ace786c7 backports upstream 172484907285
("io_uring/kbuf: use mem_is_zero()") by replacing `mem_is_zero()` with
`memchr_inv()` and keeping the negation:

```c
if (!memchr_inv(reg.resv, 0, sizeof(reg.resv)))
	return -EINVAL;
```

`memchr_inv` returns NULL when every byte is zero, so registration fails
exactly when the reserved words are zero, the form every other kernel
requires. `IORING_UNREGISTER_PBUF_RING` and `IORING_REGISTER_PBUF_STATUS`
have the same inversion. It is in tags Ubuntu-6.8.0-136 through
Ubuntu-6.8.0-148 and `master-next`, and not in 6.8.0-130. It came with
Launchpad bug 2156956 (the stable patchset of 2026-06-16). No Launchpad bug
for the regression was found, and whether a fix is queued was not
established. Reports from netty (#17636,
on `6.8.0-1064-azure`) suggest the cloud derivatives have it too
(unverified).

ringline retries a registration that failed with `EINVAL` on a 6.8 kernel
with `resv[0]` set, and unregisters the same way after such a registration
(#626, #627, `engine/uring.rs` `retry_with_resv_set`). The retry must stay
limited to 6.8: on a kernel with `min_left`, `resv[0] = 1` sets
`min_left = 1`, which is `EINVAL` on a plain ring.

## Which fixes each kernel has

By base version; a distribution kernel can differ.

| Fix | Debian 12 6.1.176+ | Ubuntu 6.8.0-148 | Debian 13 6.12.107/111 | 7.1.13 | 7.2.6 |
|---|---|---|---|---|---|
| Multishot retry cap (76b367a2d831) | no | yes | yes | yes | yes |
| Multishot EOF race (a68ed2df7213) | yes | yes | yes | yes | yes |
| Deferred-completion ordering (687b2bae0eff) | no (reverted) | yes | yes | yes | yes |
| Partial buffer commit on retry (41b70df5b38b) | not affected per CVE | yes | yes | yes | yes |
| Incremental rings | no | no | yes | yes | yes |
| Incremental fixes through 6.12.94 / 7.1 | n/a | n/a | yes | yes | yes |
| `min_left` | n/a | n/a | yes | yes | yes |
| `MSG_TRUNC` overconsume (6028b543884f) | n/a | n/a | no | no | no |
| Multishot byte caps | no | no | no | yes | yes |
| Local task_work cap | no | no | no | yes | yes |
| Ring `RLIMIT_MEMLOCK` charging | no | no | no | yes | yes |

## Not established

- The commits that introduced provided-buffer rings, `SOCK_NONEMPTY` and
  `POLL_FIRST` in 5.19 predate the history examined.
- Which Ubuntu 6.8 build first reached the updates pocket with the inverted
  check (6.8.0-136 has it in source; reports say 6.8.0-139), whether a fix
  is queued, and which derivative kernels have it.
- Which receive fixes RHEL 10 and Amazon Linux 2023 carry beyond their base
  versions.
- Whether `tcp_inq` reports 1 when only a FIN is pending.
- Whether 6028b543884f matters for TCP.
- Non-LTS stable lines 6.13–6.17 and 6.19 were not examined, except where a
  CVE record names them.
