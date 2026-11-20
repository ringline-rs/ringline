# Fixed-buffer zero-copy sends: kernel behaviour and configuration

Status: reference, written 2026-11-20 (#841, #987, #989, #991). It lists
the kernel behaviour that decides whether a zero-copy send can name a
registered buffer, what ringline does about each, the settings involved, and
the send shapes an application needs to benefit.

Sources: `io_uring/net.c` and `io_uring/rsrc.c` read in the stable tree at
the tags named; the probe's results in the table under "The probe", run in
SystemsLab guests; and the measurements cited. The kernels listed "with the
charge fix" are images patched on 2026-11-17 to charge each segment its
length (`bv_len`), before the fix below was posted. Both remove the
overcharge. The posted fix charges the whole pages a segment touches, so the
patched images charge less for any send that does not start and end on a
page boundary: a 4096-byte send at an offset that is not page-aligned one
page less, a 20-byte guard 20 bytes instead of a page. The probe's send is
one aligned page, which both charge the same. A distribution kernel can
carry any of these changes, or lack them, under any version number, which is
why ringline probes the running kernel instead of reading its version.

## What a fixed-buffer send saves

A zero-copy send from plain iovecs (`SENDMSG_ZC`) makes the kernel look up
and pin the pages of each send (`zerocopy_fill_skb_from_iter`). A send that
names a registered buffer (`IORING_RECVSEND_FIXED_BUF` with `buf_index`)
takes the pages from the buffer, which was pinned when it was registered,
and imports the send against it (`io_import_reg_buf` for `SEND_ZC`,
`io_import_reg_vec` for `SENDMSG_ZC`).

In a cache server's GET replies, perf profiles (one run per arm at 16,000
and 56,000 bytes) showed `zerocopy_fill_skb_from_iter` at 7.4–7.7% inclusive
of the server's samples, and absent with fixed sends. At 56,000 bytes, on a
link-bound 40 Gb/s bond, sending from a registered buffer cut server CPU per
GB sent by 3.4% (four runs a side; a prototype of the path #987 later
added, on a 7.3 kernel patched to charge `bv_len`). At 16,000 bytes the difference was
inside the run-to-run spread.

## Kernel behaviour

### Which sends take the flag

| Opcode | Takes `IORING_RECVSEND_FIXED_BUF` from | ringline uses it for |
|---|---|---|
| `SEND_ZC` | Linux 6.0 (`io_sendzc_prep`) | a send of one guard |
| `SENDMSG_ZC` | Linux 6.15 (6.14 refuses it with `EINVAL`) | a send of several guards |

A fixed `SENDMSG_ZC` takes one `buf_index`, and every iovec must lie inside
that registered buffer: `validate_fixed_range` returns `EFAULT` otherwise
(reached from `io_import_reg_vec` through `io_vec_fill_bvec`). A
send whose parts lie in two regions, or that has a copy part (a copy part
lives in ringline's send pool, which is not registered), cannot name a
buffer.

### The size of one registered buffer

| Kernel | Largest registered buffer |
|---|---|
| up to 7.1 (6.18 LTS, 7.0.y, 7.1.y included) | 1 GiB (`SZ_1G` in `io_uring/rsrc.c`) |
| 7.2 and later | 1 TiB (`SZ_1T`, b4e41050b212 "io_uring/rsrc: raise registered buffer 1GB limit") |

None of 6.1.y (6.1.192), 6.6.y (6.6.162), 6.12.y (6.12.118), 6.18.y
(6.18.64), 7.0.y (7.0.14) or 7.1.y (7.1.13) has the raise. A region larger than 1 GiB is refused before 7.2, so an
application with a larger arena registers it as several regions there, and
a send can name only one of them.

### Folio coalescing and the send-buffer charge

From Linux 6.3 (57bebf807e2a), a registered buffer that lies inside one
large folio (a transparent huge page or a hugetlb page) is stored as one
bvec for the folio; from 6.12 (a8edbb424b13), a buffer spanning several
large folios is stored as one bvec per folio. This makes registering a
buffer on huge pages much cheaper (see below), and it exposes a fault in how
a send from such a buffer is charged to the socket.

`io_sg_from_iter` adds `PAGE_ALIGN(bv_len + bv_offset)` to the skb's
truesize, which TCP charges to `sk_wmem_queued`; for a coalesced bvec,
`bv_offset` is the offset in the folio, not in a page. A 4 KiB send near the end of a 2 MiB page is charged about
2 MiB. The socket's send buffer then fills after a few sends: over 10 GbE,
16 KiB sends from a THP-backed registered region ran at 1.9 Gb/s instead of
9.4. With 4 KiB pages the charge is correct.

| Kernel | One-folio buffer | Buffer over several folios |
|---|---|---|
| 6.1 (Debian) | correct | correct |
| 6.6.13, 6.8.0-142 (Ubuntu), 6.11.10 | overcharged | correct |
| 6.12.116, 6.18.15, 7.1.13, 7.2.12, 7.3.4, 7.4.0-rc2 | overcharged | overcharged |

The report, with a reproducer:
<https://lore.kernel.org/io-uring/CAC+fX10wVVSqGnfCg+aazorsCxB34sUDV-XJiBPd6R3Kuqc-7Q@mail.gmail.com/>.
The fix, which charges `PAGE_ALIGN(bv_len + offset_in_page(bv_offset))` as
the iovec path does, was posted on 2026-11-19 and is not merged as of
2026-11-20:
<https://lore.kernel.org/io-uring/20261119232935.1708458-1-thiery.louis@gmail.com/>.
It is marked for stable.

With the fix, each bvec segment is charged in whole pages, so a 20-byte
header and a 7-byte trailer sent as their own guards are each charged a
page, as the same parts are from plain iovecs.

### Huge pages and registration cost

Registering a buffer on 4 KiB pages stores one entry per page; a buffer on
huge pages, coalesced, stores one per folio. A buffer that mixes page sizes
is not coalesced (`io_check_coalesce_buffer`) and registers one entry per
4 KiB page: 262,144 per GiB, against 512 on 2 MiB pages. An application that registers a
large region should have it entirely on huge pages, or entirely not.

Up to 7.1, the accounting of a huge page (`headpage_already_acct`) scans the
entries already registered on the ring, so each region on huge pages
registers more slowly than the one before. From 7.2 (df0a52537c0f
"io_uring/rsrc: add huge page accounting for registered buffers") the ring
keeps a table of the huge pages it has charged (`hpage_acct_ref`), and the
cost no longer grows with what the ring holds.

### `RLIMIT_MEMLOCK`

A registered buffer's pages are charged to the user's `RLIMIT_MEMLOCK` on
each ring that registers it, unless the process holds `CAP_IPC_LOCK`. A huge
page already charged on that ring is not charged again (`headpage_already_acct`
up to 7.1, `hpage_acct_ref` from 7.2); a 4 KiB page is charged on every
registration (`io_buffer_account_pin`), so registering the same memory twice
over 4 KiB pages doubles its charge. Rings themselves are charged from 6.14
until 7.3 removed it (b59cabf9b4ac), with stable exceptions;
`memlock::kernel_charges_rings` (`ringline/src/memlock.rs`) tests the
running kernel.

## What ringline does

### The probe

`ringline/src/backend/uring/fixed_send.rs` decides, once per process,
whether each kind of fixed send is used. It maps a 2 MiB transparent huge
page, registers it on a ring of its own, and on loopback connections whose
receiver does not read compares the change in `SK_MEMINFO_WMEM_QUEUED`
across a 4 KiB send from the page's last page: from plain iovecs, as a fixed
`SEND_ZC`, and, when that passes, as a fixed `SENDMSG_ZC`. A fixed send that
is charged within a page of the plain one passes; one charged about the
folio's size more is the fault above.

| Result (`FixedBufferSends`) | Meaning | Sends that name the buffer |
|---|---|---|
| `Enabled { multi_guard: true }` | both fixed opcodes are taken and charged correctly | one guard and several guards |
| `Enabled { multi_guard: false }` | `SEND_ZC` passes; `SENDMSG_ZC` is refused (before 6.15) or fails | one guard |
| `Overcharged` | the kernel has the charge fault | none |
| `Unsupported` | the mio backend, or `SEND_ZC` refuses the flag | none |
| `Inconclusive(reason)` | the probe could not decide: for example, no huge page for its buffer, no `RLIMIT_MEMLOCK` room, or measurements that kept failing | none |
| `Disabled` | `ConfigBuilder::fixed_buffer_sends(false)` on io_uring | none |

Measured results:

| Kernel | Result |
|---|---|
| Debian 6.12 | `Overcharged` |
| Debian 6.12 with the charge fix | `Enabled { multi_guard: false }` |
| kernel.org 7.3.4 | `Overcharged` |
| kernel.org 7.3.4 with the charge fix | `Enabled { multi_guard: true }` |

The probe runs at the first launch with `registered_regions`, the first
`Runtime::register_region`, or the first `Runtime::fixed_buffer_sends`,
whichever comes first, and that call blocks while it runs. Its socket and
ring waits are bounded at about 99 s in all; allocating its huge page
(memory compaction) and reading `/proc/self/smaps` are not bounded. Its
duration has not been measured. Until it
has run, each launch raises the soft `RLIMIT_MEMLOCK` to cover it when the
hard limit allows, and otherwise keeps it from running.

When the probe runs it writes one line to stderr saying whether fixed sends
are on, for which sends, and if not why, ending with the result's name (for
example `ringline: fixed-buffer sends off: this kernel does not have the fix
to how they are charged to the socket (Overcharged); …`), and sets the gauge
`ringline/ring/fixed_buffer_sends`: 0 when no fixed send is used (the probe has
not run, or did not pass), 1 for sends of one guard, 2 for sends of one or
several guards. A kernel upgrade that carries the charge fix changes the
result without a code change, and the line and the gauge show it.

### The send path

In `SendBuilder::build_with_guards`, a send whose parts are all guards in one
registered region, when the setting is on and the probe passed that kind of
send, goes out as a fixed `SEND_ZC` (one guard) or a fixed `SENDMSG_ZC`
(several), counted in `ringline/ring` `op=send_fixed_buffer`. Everything
else uses plain iovecs, or for TLS is encrypted into pool slots: a send
with a copy part, guards in several regions or outside any, a send on a
Unix-domain or TLS connection. A guarded send below `send_zc_threshold` is
gathered into one pool slot and copied, unless the pool has no free slot or
the send does not fit one slot; it then goes out zero-copy like any other. A
fixed send that the kernel returns
short or refuses with `EAGAIN` is resent from plain iovecs.

A guard-only send from one region holds that region's slot from the call
that submits it until its completion resolves, including while it waits in
the connection's send queue. `Runtime::unregister_region` before such a send
is submitted makes it fail with `EFAULT` and closes the connection.

### Settings

| Setting | Effect here |
|---|---|
| `ConfigBuilder::fixed_buffer_sends` (default `true`) | turns the probe and fixed sends on; `false` keeps launch from touching `RLIMIT_MEMLOCK` for the probe; the mio backend ignores it |
| `ConfigBuilder::registered_regions`, `max_registered_regions`, `Runtime::register_region` | the regions a guard can name (`SendGuard::region`) |
| `ConfigBuilder::send_zc_threshold` (default 4096) | a guarded send below it is gathered into one pool slot and copied, unless the pool has no free slot or the send does not fit one slot; then it goes out zero-copy |
| `ConfigBuilder::send_slab_slots` (default 512) | each zero-copy send holds an entry until its notification; an application staging per-send memory can size it from this |
| `ConfigBuilder::zero_copy_hold_cap` (default 16) | once the send slab is over half used, a guarded send on a connection holding that many entries is refused, not copied |

## Send shapes that benefit

Only a send whose every part is a guard in one region names a buffer, so an
application lays out what it sends to match:

- Store each reply with its framing beside the value, so the reply is one
  guard (for example a RESP bulk string, `$<len>\r\n<value>\r\n`). A fixed
  `SEND_ZC` takes it from Linux 6.0.
- Copy each reply's header and trailer into staging memory that lies in the
  same region as the value, and send three guards. A fixed `SENDMSG_ZC`
  takes it from 6.15. One way to get the staging memory into the region
  without changing how the value store is allocated: reserve address space
  for the store and the staging area (one `PROT_NONE` mapping), map the
  store's memfd a second time into the front of it with `MAP_FIXED`, map
  the staging area after it, and register that range. The second mapping
  shows the same pages, and a value's guard points into it, since the kernel
  checks addresses against the registered range. Put the staging area on the
  store's page size, or the range is not coalesced. A staging slot is safe to
  reuse when the send's guards drop, which ringline does after the
  notification. This layout has not been measured.
- Before 7.2, keep each region to 1 GiB, with its own staging for the
  values in it.

Every one of these takes effect only where the probe passes, which today
means a kernel carrying the charge fix. The probe tests a huge page and
decides for every region: on a kernel without the fix, a region on 4 KiB
pages, which is charged correctly, gets no fixed sends either, and with
transparent huge pages unavailable the probe is `Inconclusive` and fixed
sends stay off.
