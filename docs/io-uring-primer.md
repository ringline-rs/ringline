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

### Less readiness choreography at high concurrency

This is not a thread-count advantage over epoll. An epoll event loop can also
manage many connections on one thread; neither design requires a thread per
request ([`epoll(7)`]).

The difference is what crosses the kernel boundary. epoll reports that a file
descriptor is ready, after which userspace issues `accept`, `read`, or `write`,
handles partial progress and `EAGAIN`, and maintains or rearms interest state.
io_uring submits the operation itself, and its CQE identifies that operation
and carries the result. Multishot operations can produce several completions
from one submission. For a service doing frequent small, bounded operations,
that can reduce repeated control syscalls and readiness bookkeeping while
batching submission and completion work ([`io_uring_multishot(7)`]).

That advantage is workload-dependent, not a higher connection-count ceiling.
epoll already returns batches of ready descriptors, has mature behavior, and
can match or beat io_uring when sockets are usually ready, batches are small,
or io_uring's setup and completion machinery do not amortize. Some io_uring
operations can also be offloaded to kernel worker threads when they cannot
complete non-blockingly, so io_uring is not threadless. Measure the actual
request mix rather than treating concurrency alone as the reason to switch.

### Kernel integration with reusable buffers

Known request-size limits make buffer ownership and memory use explicit. A
service can choose its maximum number of in-flight requests and preallocate a
corresponding pool, rather than allocate in proportion to an unbounded input
queue. That is an application design technique, not an io_uring feature:
Pelikan has used preallocated I/O and request-object pools with readiness-based
event loops since its earliest versions. The same bounded-pool discipline
applies to epoll, Mio, and io_uring.

What io_uring adds is kernel integration with those reusable buffers.
Registered buffers pin and map application memory once, avoiding repeated
validation, pinning, and mapping for each operation. Upstream documentation
says they are most useful for frequent small I/O that repeatedly uses the
same buffers ([`io_uring_registered_buffers(7)`]).

Provided-buffer rings solve a different receive-side problem. Multiple
pending operations share a pool, and the kernel selects a buffer only when
data arrives. The CQE identifies the selected buffer. If the pool is empty,
the operation reports `-ENOBUFS`; this gives the service an observable point
at which to apply backpressure or shed load
([`io_uring_provided_buffers(7)`]).

These mechanisms do not make capacity automatic. SQ depth limits how many
entries can be submitted in one batch, not the total number of operations
that can remain in flight. The application must separately bound accepted
work, outstanding operations, and buffers
([`io_uring_queue_init_params(3)`]).

### Fewer repeated submissions

Multishot accept, receive, read, and poll operations can produce several
CQEs from one SQE. This reduces rearming traffic for busy servers. A
multishot request eventually terminates—for example on an error,
cancellation, or receive-buffer exhaustion—and the application must detect
the final CQE and rearm if appropriate ([`io_uring_multishot(7)`]).

### Architecture that complements io_uring

Thread-per-core ownership, CPU affinity, NUMA placement, and keeping request
state and buffers local are runtime architecture choices. They are not
io_uring features, and a readiness-based event loop can use the same design.
Pelikan already does so with its epoll/Mio path.

io_uring fits that architecture particularly well when each event-loop thread
owns one ring. The ring then has a single submitting owner, avoids
application-side synchronization around shared submission state, and can use
facilities such as `IORING_SETUP_SINGLE_ISSUER`. Current upstream guidance
describes a ring per thread as the idiomatic arrangement and discourages
sharing a ring between threads because sharing requires synchronization and
prevents those ring-level optimizations ([`io_uring_setup_flags(7)`]).

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
