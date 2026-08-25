# Why consider io_uring?

`io_uring` is Linux's completion-oriented asynchronous I/O interface. It is
worth considering for services that keep many independent operations in
flight, especially when each request is small or has a known maximum size.
Those workloads can combine a bounded buffer pool, batched submission, and a
small number of event-loop threads to reduce fixed per-operation overhead
without allowing memory use to grow with demand.

This is a workload argument, not a claim that `io_uring` always beats
`epoll`, synchronous I/O, or a thread pool. Hardware, kernel version, traffic
shape, and application design all matter. The upstream documentation makes
the same recommendation for submission-queue polling: benchmark both modes
under realistic conditions ([`io_uring_sqpoll(7)`]).

## Where it came from

`io_uring` entered mainline Linux in 5.1, released in May 2019. Its original
design goals included broad operation coverage, efficiency, low latency, and
scalability. Earlier Linux AIO interfaces incurred copies and indirections
while passing submissions and completions between user space and the kernel.
`io_uring` instead makes user space the producer of a submission ring and the
consumer of a completion ring, with the kernel on the opposite side of each
ring ([Jens Axboe's design paper], [LWN's history]).

The API has evolved substantially since 5.1. Modern networking features,
multishot operations, provided buffers, and many setup flags arrived later.
Applications need a tested minimum kernel and runtime capability probes;
“Linux 5.1 or newer” alone does not establish support.

## The execution model

`io_uring_setup(2)` creates a ring context and returns a file descriptor.
User space maps a submission queue (SQ), a completion queue (CQ), and an array
of submission queue entries (SQEs) shared with the kernel. It fills SQEs and
publishes them; the kernel later places completion queue entries (CQEs) in the
CQ. Each CQE contains the operation result and the application's `user_data`
value, which identifies the corresponding request
([`io_uring_setup(2)`], [`io_uring(7)`]).

A single `io_uring_enter(2)` can submit multiple operations and optionally
wait for completions. An application can also inspect a non-polled CQ without
entering the kernel. This amortizes system-call and synchronization overhead
across useful work ([`io_uring_enter(2)`]).

Submission-queue polling (SQPOLL) is optional. In that mode a kernel thread
polls the SQ and can submit work without a system call while it remains
active. The trade-off is CPU consumption while polling and possible wake-up
latency after the thread sleeps. I/O polling (IOPOLL) is a separate storage
mode that busy-polls completions; it requires compatible filesystems and
devices, commonly with `O_DIRECT`. Neither option is a generic “go faster”
switch ([`io_uring_setup(2)`], [`io_uring_sqpoll(7)`]).

## Why it can help

### Fewer fixed costs per operation

An application can publish several SQEs together and reap several CQEs
together. This reduces crossings between user and kernel space and makes
small operations less dominated by submission overhead. It does not require
large batches: a latency-sensitive loop can submit promptly while still
combining work already available.

### More operations outstanding at high concurrency

This is not a thread-count advantage over epoll. An epoll event loop can also
manage many connections on one thread; neither design requires a thread per
request ([`epoll(7)`]).

The distinction is where synchronous work sits. epoll reports that a file
descriptor is ready, so the event-loop thread then calls `accept`, `recv`, or
`send` for each ready descriptor. Nonblocking `recv` does not wait for data,
but the call still has to finish its copying, accounting, protocol-stack work,
and error handling before that thread issues the next call. Those costs are
therefore serialized on the event-loop thread across file descriptors.

io_uring lets the loop describe operations for many descriptors first and
consume their results later. The kernel can make progress on those outstanding
operations without requiring the event loop to finish one data syscall before
issuing the next. A CQE identifies the operation and carries its result, while
multishot operations can produce several completions from one submission. This
can reduce control syscalls, readiness bookkeeping, and time spent in
per-descriptor synchronous calls ([`io_uring_multishot(7)`]).

This is not a guarantee that socket operations execute simultaneously. Some
complete inline during submission, some progress in the network stack, and
operations that cannot complete nonblockingly may use kernel worker threads.
epoll can match or beat io_uring when sockets are usually ready, batches are
small, or ring management does not amortize. Connection count alone is not the
reason to switch; request rate, batch size, and time spent inside each data call
determine the opportunity.

### Worked example, not benchmark data

The following model illustrates fixed application syscall crossings. It is not
a performance result. Assume one bounded request and response per transaction,
one ready descriptor and one drain per transaction, one successful `recv` and
`send`, one final `recv` returning `EAGAIN` for an edge-triggered drain,
prearmed multishot receive for io_uring, and one `io_uring_enter` that
publishes available sends and waits for each batch.
Let `R` be requests per second and `B` the average completed batch size.

| Model | Approximate application syscalls | Event-loop CPU path | System-wide CPU trade-off |
| --- | ---: | --- | --- |
| epoll, level-triggered | `2R + ceil(R/B)` | Each `recv` and `send` completes serially on the loop | Low setup cost; repeated entry/exit and readiness bookkeeping |
| epoll, edge-triggered drain | `3R + ceil(R/B)` | Adds the terminal `EAGAIN` call for each drained descriptor | More calls in this model, but fewer readiness notifications can offset them |
| io_uring, batched + multishot receive | `ceil(R/B)` | Publishes SQEs and processes CQEs; no application data syscall per request | Ring processing and operation state replace much of the syscall overhead |
| io_uring with active SQPOLL | potentially zero submission calls while active | Shared-memory publication and CQ processing | A kernel polling thread can consume substantial CPU, including when idle |

The numeric examples use whole batches, rounding `R/B` upward:

| Scenario | Connections | Request rate | Average batch | epoll LT calls/s | epoll ET calls/s | io_uring enters/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Small, sparse | 100 | 1,000/s | 1 | 3,000 | 4,000 | 1,000 |
| Large, sparse | 100,000 | 1,000/s | 1 | 3,000 | 4,000 | 1,000 |
| Small, busy | 100 | 1,000,000/s | 64 | 2,015,625 | 3,015,625 | 15,625 |
| Large, busy | 100,000 | 5,000,000/s | 256 | 10,019,532 | 15,019,532 | 19,532 |

The first two rows deliberately produce the same counts: idle connection count
does not create syscall savings by itself. To show scale rather than predict
hardware, assume each application syscall entry/exit has a fixed 200 ns CPU
cost and exclude payload copying, protocol processing, CQ/SQ processing, and
all other work:

| Scenario | epoll LT fixed cost | epoll ET fixed cost | io_uring fixed cost |
| --- | ---: | ---: | ---: |
| Small, sparse | 0.0006 CPU-seconds/s | 0.0008 CPU-seconds/s | 0.0002 CPU-seconds/s |
| Large, sparse | 0.0006 CPU-seconds/s | 0.0008 CPU-seconds/s | 0.0002 CPU-seconds/s |
| Small, busy | 0.403 CPU-seconds/s | 0.603 CPU-seconds/s | 0.003 CPU-seconds/s |
| Large, busy | 2.004 CPU-seconds/s | 3.004 CPU-seconds/s | 0.004 CPU-seconds/s |

These figures isolate only the assumed crossing cost. They do not say io_uring
uses less total CPU: CQ processing, ring synchronization, cache behavior,
copying, networking, and SQPOLL can erase or reverse the modeled difference.

For this model walked through ringline's own event loops — the counted
syscalls and copies per request on each backend, plus measured
syscalls-per-request from a two-client rig sweep — see
[Syscalls and copies, counted](syscalls-and-copies.md).

### Measured local example

The following is one machine's result, not a portable prediction. Ringline's
64-byte echo server ran on the physical P cores of an Intel Core i5-13500H;
the Tokio load generator ran on separate E cores. Each cell is the median of
three five-second measurements after a two-second warmup. Closed-loop rows
have one outstanding request per connection. CPU is aggregate server CPU, so
400% means four fully occupied cores; HWM is peak resident memory. The host
used Ubuntu 6.8.0-138 and the `powersave` governor.

Ubuntu's kernel has a known inverted reserved-field check in provided-buffer
registration (Launchpad #2162843). To make this local experiment possible,
the benchmark used an uncommitted, ABI-invalid diagnostic patch that sets one
reserved field nonzero; no project source or published result should adopt
that workaround. Treat these numbers as a comparison of Ringline's two paths
on this host, not as results from a supported production kernel.

| Workers | Clients / offered rate | Backend | Throughput | p50 | p99 | Server CPU | HWM |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 1 closed | io_uring | 44.6k/s | 22.3 us | 26.7 us | 34% | 79.8 MiB |
| 1 | 1 closed | Mio | 41.2k/s | 23.8 us | 28.3 us | 40% | 75.6 MiB |
| 1 | 64 closed | io_uring | 183.7k/s | 263 us | 765 us | 99% | 79.8 MiB |
| 1 | 64 closed | Mio | 156.0k/s | 399 us | 780 us | 100% | 75.6 MiB |
| 1 | 512 closed | io_uring | 232.3k/s | 1.24 ms | 24.0 ms | 99% | 79.9 MiB |
| 1 | 512 closed | Mio | 155.0k/s | 3.29 ms | 4.66 ms | 100% | 75.7 MiB |
| 2 | 64 closed | io_uring | 459.3k/s | 131 us | 463 us | 190% | 155.7 MiB |
| 2 | 64 closed | Mio | 254.0k/s | 204 us | 801 us | 169% | 147.4 MiB |
| 2 | 512 closed | io_uring | 450.5k/s | 1.09 ms | 4.42 ms | 189% | 155.8 MiB |
| 2 | 512 closed | Mio | 247.9k/s | 1.71 ms | 5.62 ms | 160% | 147.6 MiB |
| 4 | 64 closed | io_uring | 498.3k/s | 125 us | 253 us | 275% | 307.6 MiB |
| 4 | 64 closed | Mio | 485.9k/s | 122 us | 255 us | 355% | 291.0 MiB |
| 4 | 512 closed | io_uring | 645.5k/s | 732 us | 1.80 ms | 337% | 307.6 MiB |
| 4 | 512 closed | Mio | 539.4k/s | 877 us | 2.31 ms | 383% | 291.4 MiB |
| 4 | 64 @ 20k/s | io_uring | 20.0k/s | 1.42 ms | 2.72 ms | 40% | 307.6 MiB |
| 4 | 64 @ 20k/s | Mio | 20.0k/s | 1.57 ms | 2.83 ms | 72% | 291.0 MiB |
| 4 | 64 @ 500k/s | io_uring | 500.0k/s | 1.14 ms | 2.80 ms | 73% | 307.6 MiB |
| 4 | 64 @ 500k/s | Mio | 500.0k/s | 1.16 ms | 2.90 ms | 93% | 291.3 MiB |

The result is not uniformly favorable. At one worker and 512 connections,
io_uring delivered much more throughput and a lower median, but its p99 was
far worse (24.0 ms versus 4.66 ms). At four workers and 64 connections, both
paths reached about 0.5 million operations/s, while io_uring used about 0.8
fewer CPU cores and about 17 MiB more peak resident memory. The open-loop
latencies include load-generator scheduling lag and are useful only as a
same-run comparison.

Ringline's existing metrics count CQEs, failures, bytes, pool pressure, and
connection lifecycle—not backend syscalls. The syscall table above therefore
remains an analytical model. Exact uninstrumented syscall counts require
dedicated counters around both backends' kernel-entry wrappers; CQE or
event-loop iteration counts are not substitutes.


### Fewer repeated submissions

Multishot accept, receive, read, and poll operations can produce several CQEs
from one SQE. This reduces rearming traffic for busy servers. A multishot
request eventually terminates—for example on an error, cancellation, or
receive-buffer exhaustion—and the application must detect the final CQE and
rearm if appropriate ([`io_uring_multishot(7)`]).

## Complementary application architecture

### Bounded pools are not an io_uring feature

Known request-size limits let a service preallocate I/O buffers and request
objects, bound in-flight work, and define overload behavior. Pelikan has used
that discipline with readiness-based event loops since its earliest versions.
io_uring does not introduce pooling, bounded memory, backpressure, or clear
ownership; epoll and Mio can use exactly the same techniques.

Once an application has a reusable pool, io_uring can integrate it with the
kernel in two distinct ways. Fixed registered buffers pay memory validation,
pinning, and mapping costs at registration rather than on every eligible I/O.
A provided-buffer ring instead registers buffer descriptors so the kernel can
select an available buffer and return its ID in a CQE
([`io_uring_registered_buffers(7)`], [`io_uring_register_buf_ring(3)`]).
Neither mechanism creates the application pool or chooses its capacity.

### Illustrative memory accounting

Consider 100,000 established connections, but only 16,384 simultaneously
active requests; a 4 KiB receive slot and 256-byte request object per active
request; 4,096 readiness/SQ entries; 8,192 CQ entries; and a modeled 16-byte
readiness-event slot. Use standard 64-byte SQEs, 16-byte CQEs, and 16-byte
`io_uring_buf` descriptors. This table shows selected userspace allocations,
not measured RSS:

| Memory component | epoll/Mio | io_uring |
| --- | ---: | ---: |
| Application receive pool | 64 MiB | 64 MiB |
| Request-object pool | 4 MiB | 4 MiB |
| Readiness-event array | about 64 KiB | — |
| SQE array | — | 256 KiB |
| CQE array | — | 128 KiB |
| Provided-buffer descriptors | — | 256 KiB |
| Ring headers and SQ index array | — | tens of KiB |
| Approximate userspace total shown | about 68.1 MiB | about 68.7 MiB |

The dominant pools are shared application architecture. In this example
io_uring adds roughly 0.6 MiB of visible control storage, while extended
128-byte SQEs or 32-byte CQEs double their respective rows
([`io_uring_setup_flags(7)`]). Real totals also include per-operation state,
send buffers, allocator overhead, kernel ring accounting, and socket buffers;
the last category can dominate and exists with either backend.

Registered memory can remain pinned. Kernels before Linux 5.12 charge fixed
registered buffers against `RLIMIT_MEMLOCK`; Linux 5.12 and later with native
io_uring workers use cgroup memory accounting instead
([`io_uring_registered_buffers(7)`]).
Queue depth and outstanding-operation limits therefore require an explicit
memory budget. A thread-per-connection design can additionally consume large
virtual and resident stack space, but epoll/Mio does not require that design
and should not be burdened with that comparison.

### Locality is not an io_uring feature

Thread-per-core ownership, CPU affinity, NUMA placement, and keeping request
state and buffers local are runtime architecture choices. Pelikan already
applies them to its epoll/Mio path.

io_uring maps naturally onto that architecture when each event-loop thread
owns one ring. The ring then has a single submitting owner, avoids
application-side synchronization around shared submission state, and can use
`IORING_SETUP_SINGLE_ISSUER`. That is an io_uring optimization enabled by
local ownership, not the source of locality itself
([`io_uring_setup_flags(7)`]).

## What it does not guarantee

The shared rings avoid copying SQEs and CQEs. Ordinary reads, receives,
writes, and sends can still copy payload data. Registered buffers remove
repeated memory-mapping work; they are not a universal payload zero-copy
mechanism.

Network zero-copy has narrower economics. Linux's documentation notes that
page accounting and completion notification replace the cost of copying and
that `MSG_ZEROCOPY` is generally useful only for writes above roughly 10 KiB.
It is a hint rather than a guarantee and can fall back to copying. The buffer
cannot be reused until a later notification says it is safe
([kernel `MSG_ZEROCOPY` documentation]). `IORING_OP_SEND_ZC` has the same
important lifetime property and usually generates both an operation CQE and
a later reuse notification ([`io_uring_prep_send_zc(3)`]). Small bounded
messages can therefore be faster with ordinary copying.

Current io_uring zero-copy receive is more specialized still. It requires
particular NIC capabilities, queue and flow-steering configuration, special
ring flags, and registered memory. It is an advanced, hardware- and
version-sensitive facility rather than the normal receive path
([kernel zero-copy receive documentation]).

Completion capacity also requires care. If the CQ fills, kernels with
`IORING_FEAT_NODROP` retain overflowed CQEs unless memory is exhausted, but
the overflow path is substantially slower. Older kernels can drop CQEs. A
network workload can produce more completions than submissions, especially
with multishot operations, so the CQ must be sized and drained for bursts
([`io_uring_queue_init_params(3)`]).

Cancellation is asynchronous and inherently racy. The target operation may
complete before its cancellation is processed; the application must accept
either result and account for the cancellation CQE separately
([`io_uring_cancelation(7)`]). Likewise, memory referenced by an operation
must remain valid until the kernel has finished with it. Shutdown is a
protocol: stop admitting work, cancel or drain outstanding operations, and
retain their state and buffers until the final completions arrive.

Finally, `io_uring` does not eliminate device latency, filesystem stalls,
page faults, scheduler interference, interrupt moderation, NUMA effects, or
CPU contention. It reduces interface overhead and gives the application more
control; it does not by itself guarantee tail latency.

## Availability and deployment

`io_uring` is Linux-specific and is not a POSIX interface
([`io_uring(7)`]). Feature support varies with kernel version and vendor
backports. Since Linux 5.6, `IORING_REGISTER_PROBE` can report supported
opcodes, while setup feature bits describe ring-level behavior
([`io_uring_register(2)`], [`io_uring_setup(2)`]). Prefer capability probing
and clear startup errors over release-number checks alone.

Host policy can prohibit the interface. The `kernel.io_uring_disabled`
sysctl can permit all callers, restrict new rings to privileged or selected
group members, or deny all new rings. Container seccomp policy can also deny
the syscalls ([kernel sysctl documentation]). Deployment checks need to cover
the oldest supported kernel, current production kernels, container policy,
and the actual service account.

Other operating systems have different native facilities. Windows I/O
completion ports associate overlapped-I/O handles with a completion queue
and manage worker concurrency ([Microsoft IOCP documentation]). macOS and
FreeBSD provide `kqueue`/`kevent`, a kernel event-notification interface
([Apple `kqueue(2)`], [FreeBSD `kqueue(2)`]). These are useful architectural
counterparts, not ABI- or semantics-compatible implementations of
`io_uring`. Portable software needs separate backends and must account for
differences in readiness versus completion, cancellation, and buffer
ownership.

## Operational checklist

- Benchmark against the real alternative, such as `epoll`, synchronous I/O,
  or a thread pool, using realistic connection counts, request sizes,
  burstiness, idle periods, TLS, and storage or NIC hardware.
- Measure throughput, CPU per request, p50 and tail latency, context switches,
  memory use, CQ occupancy and overflow, `-ENOBUFS`, retries, cancellations,
  and kernel worker activity.
- Size SQ, CQ, buffer pools, accepted work, and outstanding operations
  independently. Define overload behavior before any pool is exhausted.
- Prefer single-owner rings where the application architecture permits it.
  Evaluate CPU affinity and NUMA placement, including contention with sibling
  hardware threads.
- Treat every CQE result as authoritative, including short I/O and negative
  errno values. Submission success is not operation success.
- Benchmark SQPOLL both enabled and disabled. Its CPU cost can be justified
  for a continuously busy, latency-sensitive loop but wasteful for sporadic
  traffic.
- Document and test the minimum kernel, required opcodes and features,
  fallback behavior, security policy, and resource limits.

## Rust and Ringline decisions

The preceding considerations are language-independent. Ringline adds several
implementation choices that are distinct from properties of the Linux API.

Ringline selects one backend at compile time. For a Linux target without
`force-mio`, the build enables `io_uring` when the host reports kernel 6.0
or newer. If the host kernel version is unavailable during cross-compilation,
the build enables it optimistically. Non-Linux targets and `force-mio` builds
use Mio. Mio is a separate readiness implementation, not an emulation of
io_uring completion semantics. If an io_uring build cannot create or prepare
its rings at runtime, `RinglineBuilder::launch` returns an error; Ringline
does not switch a running binary to Mio.

The 6.0 requirement comes from the networking facilities Ringline uses,
including `SendMsgZc`, multishot receive, and provided buffers. It is more
useful to an operator than the historical 5.1 introduction point, but it is
not a complete capability check: vendor kernels, container policy, seccomp,
and the `kernel.io_uring_disabled` sysctl can still prevent startup.

Ringline represents kernel-owned work with generation-tagged connection
slots, fixed buffer pools, send slabs, and guard objects. A stale CQE can
release only the resources encoded in its operation identity; it cannot act
on a connection that later reused the same slot. Zero-copy send guards remain
alive through the notification CQE rather than only through the operation
CQE.

Ringline's thread-per-core model naturally supports a ring per worker and
single-issuer ownership. Its worker documentation warns that placing busy
event loops on both hardware threads of one physical core can create
execution-unit and cache contention ([Ringline `WorkerConfig`]). Treat
physical-core placement as a workload- and topology-sensitive default and
verify it on target machines.

Ringline exposes the capacity decisions io_uring forces into the design:
worker count, SQ and CQ sizing, connection slots, receive buffers, copied-send
slots, zero-copy send slabs, task slots, and timer slots. Configuration
validation rejects zero or structurally invalid capacities. Runtime metrics
report pool pressure and backend events so operators can distinguish a
capacity limit from socket or kernel failure.

[`io_uring(7)`]: https://man7.org/linux/man-pages/man7/io_uring.7.html
[`io_uring_setup(2)`]: https://man7.org/linux/man-pages/man2/io_uring_setup.2.html
[`io_uring_enter(2)`]: https://man7.org/linux/man-pages/man2/io_uring_enter.2.html
[`io_uring_register(2)`]: https://man7.org/linux/man-pages/man2/io_uring_register.2.html
[`io_uring_sqpoll(7)`]: https://man7.org/linux/man-pages/man7/io_uring_sqpoll.7.html
[`io_uring_setup_flags(7)`]: https://man7.org/linux/man-pages/man7/io_uring_setup_flags.7.html
[`io_uring_registered_buffers(7)`]: https://man7.org/linux/man-pages/man7/io_uring_registered_buffers.7.html
[`io_uring_provided_buffers(7)`]: https://man7.org/linux/man-pages/man7/io_uring_provided_buffers.7.html
[`io_uring_multishot(7)`]: https://man7.org/linux/man-pages/man7/io_uring_multishot.7.html
[`io_uring_cancelation(7)`]: https://man7.org/linux/man-pages/man7/io_uring_cancelation.7.html
[`io_uring_queue_init_params(3)`]: https://man7.org/linux/man-pages/man3/io_uring_queue_init_params.3.html
[`io_uring_register_buf_ring(3)`]: https://man7.org/linux/man-pages/man3/io_uring_register_buf_ring.3.html
[`io_uring_prep_send_zc(3)`]: https://man7.org/linux/man-pages/man3/io_uring_prep_send_zc.3.html
[`epoll(7)`]: https://man7.org/linux/man-pages/man7/epoll.7.html
[Jens Axboe's design paper]: https://www.kernel.dk/io_uring.pdf
[LWN's history]: https://lwn.net/Articles/810414/
[kernel `MSG_ZEROCOPY` documentation]: https://www.kernel.org/doc/html/latest/networking/msg_zerocopy.html
[kernel zero-copy receive documentation]: https://www.kernel.org/doc/html/latest/networking/iou-zcrx.html
[kernel sysctl documentation]: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#io-uring-disabled
[Microsoft IOCP documentation]: https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports
[Apple `kqueue(2)`]: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html
[FreeBSD `kqueue(2)`]: https://man.freebsd.org/cgi/man.cgi?query=kqueue&sektion=2
[Ringline `WorkerConfig`]: ../ringline/src/config.rs
