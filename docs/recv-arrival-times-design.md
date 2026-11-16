# Receive arrival times

Note (2026-10-25): `with_bytes_segments`, `with_segments`,
`SegmentReader`, `RecvSegment` and `recv_owned_segment` were removed; the reporting readers
are `with_data`, `with_data_result`, `with_bytes` and `try_with_data`.

Note (2026-10-25): `forward_to` and the segment hold (`segment_hold`) were
removed.

Note (2026-10-25): the fallback receive was removed with the TCP
provided-buffer ring.

Status: implemented. The cost is measured under "Cost".

A reader on a TCP connection can ask when the first and the last byte it
consumed arrived. The client crates use this to report time to first byte and
time to last byte for each response, pipelined or not.

The arrival time of a byte is a batch time. A batch is one pass over the
completions (io_uring) or readable sockets (mio) that the worker handles
together. The batch time is read at the first record of received bytes in the
batch, so completions ahead of that record in the batch have already been
handled. "What the time measures" says how this differs from when the packet
reached the host.

## Batch time

The driver holds the batch state: a batch sequence number, incremented each
time a batch begins, and an `Option<Instant>` that is `None` until a record in
the batch needs it. The first record with `n > 0` in a batch reads
`Instant::now()` into it, at step 2 of the record. Later records in the same
batch reuse it. A batch with no such record reads no clock.

A batch begins:

- on io_uring, in `drain_completions` after `reap`. It runs twice per loop
  iteration, after `submit_and_wait` and after `flush`, and each run is a
  batch;
- on mio, after `poll` returns, and in `drain_forward_resumes`, which reads
  sockets after tasks have run.

Tests start a batch with a given time through the `#[cfg(test)]`
`BatchClock::begin_at` (`driver.recv_batch.begin_at`) before dispatching a
completion (`test_dispatch_cqe` on io_uring) or calling `handle_readable`
(mio). The tests then control batch boundaries and times.

## The arrival log

Each connection has an arrival log, held in a per-connection `Vec` on the
driver of each backend:

- `delivered: u64`, the stream offset one past the last byte delivered to the
  connection. For TLS the offsets count plaintext.
- `base: u64`, the end offset of the last entry dropped from the log. Offsets
  below it have no entry.
- `entries: VecDeque<(u64, Instant)>`. Each entry is the end offset of a run
  of bytes and the batch time at which the run was delivered. The run starts
  at the previous entry's end, or at `base` for the oldest entry.
- `newest_batch: u64`, the batch sequence number of the newest entry.
- `after_trim: usize`, the entry count after the previous trim.
- `latest: Option<RecvArrival>`, the times of the bytes the most recent
  reporting reader call consumed (see "Which bytes a reader consumed").

Clearing the log sets `delivered`, `base` and `after_trim` to zero, empties
`entries`, and sets `latest` to `None`.

### Where bytes are recorded

A record of 0 bytes does nothing. Except for TLS (below), a record of `n > 0`
bytes runs before those bytes are placed anywhere, and in this order:

1. Trim, if due (see "Bounding the log"), using the current `delivered` and
   `buffered`. The new bytes are in neither yet.
2. Add `n` to `delivered`. If the log is non-empty and its newest entry is
   from this batch, extend that entry. Otherwise, if the log holds 1024
   entries, merge the two oldest, then push a new entry.

The record sites:

- io_uring `handle_recv_multi`, in the non-TLS arm, once per completion that
  passes the stale-slot check. The record runs before the branch on receive
  domain and mode: segment hold, lend, or accumulator.
- io_uring `handle_recv_fallback`, before the segmented or accumulator
  append. `fallback_eligible` excludes TLS connections, so the fallback has
  no TLS arm.
- mio `handle_readable`, once per `read` that returns bytes on a non-TLS
  connection, before the bytes go to a forward or the accumulator.
- TLS on both backends, around the feed of one ciphertext completion or read
  (`feed_tls_recv`, `feed_tls_recv_mio`). Step 1 runs before the feed. Step 2
  runs immediately after the feed and adds the growth of `buffered`, which is
  the plaintext the feed delivered. On mio this is before the `Ok` arm's
  `forward_take_accumulated` moves plaintext to a forward. All plaintext from
  one feed shares one batch, so this gives the same log as recording each
  chunk, without passing the log into the TLS engines. Ciphertext is never
  recorded.
- io_uring `install_accepted_with_pending`: the bytes a park carried, the sum
  of `pending`, are recorded as one entry at the adopting batch's time, after
  the slot is allocated and immediately before they are appended. The adopted
  connection's log starts cleared, so this keeps `delivered >= buffered`.
  `drain_adopted` runs from a completion handler, so the batch is defined.
  The sum is normally zero, because `park_blocker` refuses a connection with
  bytes buffered.

The log is cleared when a slot is set up for a connection: io_uring
`handle_connect` (before its orphaned-future branch) and
`install_accepted_with_pending` (before the record above), and mio accept. It
is cleared at teardown by io_uring `handle_close` and mio `finish_close`,
which also replace the deque with an empty, unallocated one. Mio
`start_connect` reuses a slot that `finish_close` already cleared.

## Which bytes a reader consumed

Bytes leave a connection through readers, forwards, `ConnStream` and close.
`ConnStream`'s `AsyncBufRead::consume` happens outside the driver. Instead of
counting consumption at each of these, the reader derives the first unread
offset from what the connection still holds:

```text
unread = delivered - buffered(conn)
```

`buffered(conn)` is the bytes the connection holds that no consumer has taken:

- io_uring: the accumulator, the buffer a direct receive holds
  (`recv_direct_held`), the lent buffer in `pending_recv_bufs` and
  `segment_hold`;
- mio: the accumulator.

The accumulator term uses a new `AccumulatorTable::len`, which does not merge
the frozen remainder; `data()` merges it.

`segment_pinned` is not counted. It holds a buffer already handed to a
`RecvSegment`, so its bytes are consumed. Bytes inside an in-flight forward
write are not counted either.

`buffered` is one function per backend. `Driver::holds_unread`, which
`park_blocker` and `offer_park` use, becomes
`buffered(conn) > 0 || segment_pinned.is_some()`.

The held bytes are contiguous and end at `delivered`, except in the cases
under "Limits". `delivered` does not change during a reader call: completions
are reaped only in `drain_completions` and at shutdown (io_uring), and sockets
are read only from the event loop (mio), never from inside a task's poll.

### The consumed range

Every poll of a reporting reader future takes `before = buffered(conn)` after
its generation check. The poll that returns `Ready` takes
`after = buffered(conn)` once it has applied the parser's result, and sets
`k = before - after`. `try_with_data` is one synchronous call; it takes
`before` and `after` around its callback.

`k` is the number of bytes the resolving poll removed, whatever the parser
returned. It covers bytes put back, the lent-buffer and `with_bytes` paths
clamping an oversized count, and `forward_recv_buf` taking bytes inside the
callback. (The accumulator's `consume` clamps in release builds and asserts
in debug builds.)

When `k > 0`, the call:

1. Sets `start = delivered - before`.
2. Drops entries whose end is at or below `start`; the front entry then
   covers `start`, and its time is the first time.
3. Drops entries whose end is at or below `start + k - 1`; the front entry
   then covers the last byte, and its time is the last time. Both times are
   stored in `latest`.
4. Drops entries whose end is at or below `start + k`, sets `base` to the end
   of the last one dropped, and sets `after_trim`.

Steps 2 and 3 never drop the newest entry. Each step reads the front of the
deque, so a call costs one pop per entry it drops and no search.

When the resolving poll has `k == 0`, or `try_with_data` returns `None` with a
matching generation, `latest` is set to `None`.

Cases at the edges:

- A reader whose connection generation no longer matches returns without
  touching the log, so it cannot clear the new occupant's `latest`.
- A reader future dropped before it resolves leaves `latest` as it was.
- A `with_data` callback that calls `forward_recv_buf` and returns `NeedMore`
  removes bytes in a poll that does not resolve. Those bytes are not part of
  any call's range; the call's `start` comes from its resolving poll.
- `with_segments` closes the connection when the hold overflows and resolves
  to `Ok(0)` with `k > 0`. It trims by `k` and sets `latest` to `None`.

A range that starts below `base` takes the oldest entry's time for its first
byte, and a range that ends past `delivered` takes the newest entry's time for
its last byte. Both count `metrics::recv_arrival::CLAMPED`, as does a lookup in
an empty log, which returns no time; a reader call counts at most once. The
counter counts only these lookups; the reordering cases under "Limits" return
wrong times without it.

The reporting readers are the public readers on `Connection` and `RecvHalf`:
`with_data`, `with_data_result`, `with_bytes`, `with_bytes_segments`,
`try_with_data`, and, on io_uring, `with_segments`. Forwards, `ConnStream`,
`SegmentReader::next` and `recv_owned_segment` do not set `latest`.

### Bounding the log

Readers trim the log as they consume. A connection whose bytes are consumed
only by non-reporting consumers is trimmed at record time instead. Step 1 of a
record trims when the log holds more than 64 entries and at least
`min(2 * after_trim, 1024)`. The trim drops the entries at or below `unread`,
moves `base`, and sets `after_trim`. Without the `min`, a trim that left more
than 512 live entries would set a threshold the 1024 cap never reaches, and no
record would trim that connection again.

Step 2 merges the two oldest entries before pushing into a full log of 1024.
The merged entry keeps the later end and the earlier time. A response that
starts at the oldest entry keeps its batch time for its first byte; lookups in
the middle of a backlog return an earlier time than the batch that delivered
those bytes.
`metrics::recv_arrival::MERGED` counts merges.

A log holds at most 1024 entries of 24 bytes, 24 KiB. After a trim that
leaves fewer than 64 entries, a deque whose capacity exceeds 256 is shrunk
to 64, so a long-lived connection does not keep a large log after one
backlog.

Both counters go in a new metric group, `recv_arrival`.

## API

```rust
/// When the bytes consumed by the most recent reader call on a connection
/// arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecvArrival { /* first: Instant, last: Instant */ }

impl RecvArrival {
    /// Arrival time of the first byte the call consumed.
    pub fn first(&self) -> Instant;
    /// Arrival time of the last byte the call consumed.
    pub fn last(&self) -> Instant;
}

impl Connection {
    pub fn recv_arrival(&self) -> Option<RecvArrival>;
}

impl RecvHalf {
    pub fn recv_arrival(&self) -> Option<RecvArrival>;
}
```

`RecvArrival` is re-exported at the crate root. It is not `Copy`, so a later
version can hold more than two times (see "Streaming clients"). `ConnCtx`,
whose readers are `pub(crate)`, gets a `pub(crate)` `recv_arrival` that the
`Connection` and `RecvHalf` methods call.

`recv_arrival` returns `None` until a reporting reader call has consumed a
byte, after a call that consumed none, and for a connection whose slot
generation no longer matches.

A reader's return type does not change. The times are read after the call
returns, because `k` is known only once the parser has returned and the call
has applied its result. The executor runs one task at a time, so a call to
`recv_arrival` made before the task's next `.await` sees the times from that
task's last reader call. A task that runs two reader calls on one connection
concurrently, for example with `join!`, cannot tell which call set the
times.

A client that parses one response per reader call, as `ringline-redis`,
`ringline-memcache` and `ringline-ping` do, gets one response's times. A
response read over several calls (redis `run_get_state_machine` and
`run_get_drain_mio`) takes `first` from its first call and `last` from its
last.

## Client crates

`CommandResult` in `ringline-redis`, `ringline-memcache` and `ringline-ping`
becomes `#[non_exhaustive]`, regains `ttfb_ns` (removed in #667) and gains
`ttlb_ns`:

- `ttfb_ns: Option<u64>`: `first` minus the operation's start time;
- `ttlb_ns: Option<u64>`: `last` minus the operation's start time.

Both use `Instant::checked_duration_since`, so a time earlier than the start
gives `None`. That happens when the client reads the reply to an earlier,
abandoned request.

The start time is the `Instant` the client already takes for `latency_ns`.
On the fire/recv path it is taken after `send_nowait` or `flush` returns,
before the worker submits the send. On the sequential path and in ping it is
taken before the send call.

### Carrying the arrival to the record

The response readers return the byte count and the arrival beside the
result, `(Result<T, Error>, u32, Option<RecvArrival>)` (the `Reply<T>` alias
in redis and memcache): redis and memcache `read_reply`, and ping
`read_response`. The arrival is read only on an instrumented client. Redis
`read_value` and memcache `read_response` return the `Result` alone, for the
sharded and cluster clients.

The helpers that feed a `CommandResult` pass the tuple up: redis
`execute_encoded`, `execute_bulk_encoded`, `execute_int_encoded` and
`execute_set`, memcache `execute_encoded`, and ping `execute`. A send error
returns `0` bytes and no arrival. The other helpers (`execute`, `execute_int`,
`execute_ok`, `execute_bulk`) return `Result`, so their callers, and
`Pipeline`, do not change.

Before this change the readers stored the byte count in a per-client cell
(`last_rx_bytes`), and an operation that failed at send reported the previous
operation's count as its `rx_bytes`.

The arrival sits outside the `Result` because an error can follow a read. At
the reader, an unparseable reply is `Err(Error::Protocol)` after consuming its
bytes. In the helpers, an error reply is read as `Ok(Value::Error)` and turned
into `Err(Error::Redis)`, and memcache's `check_error_bytes` returns `Err` for
an error reply. An operation that fails before it reads reports
`rx_bytes = 0` and `None` for both times. This also fixes the stale
`rx_bytes`.

The guarded SET paths (redis `set_with_guard` and `set_ex_with_guard`,
memcache `set_with_guard`) record a `CommandResult` on a send error, a read
error and an error reply, as the other instrumented paths do. Before this
change they recorded none on a send error, the redis ones none on a read
error, and memcache's none on an error reply.

`recv`, `recv_meta`, `recv_meta_simple` and the GET state machines read
through a reader call per response that consumes bytes, and take the arrival
from those calls. The GET state machines (`run_get_state_machine`,
`run_get_drain_mio`) keep the first call's first time and the last call's last
time (`ArrivalSpan`).

Both fields are `None` when the client is not instrumented. `latency_ns`
stays the time from the start to the parsed response, so
`ttfb_ns <= ttlb_ns <= latency_ns` when all three are known.

`CompletedOp` (redis and memcache) and `RespMeta` (redis) do not change.
Callers that need these times use the `on_result` callback, as cachecannon
does.

`CommandResult` keeps its public fields, an existing exception to "no `pub`
fields on public value structs". Nothing outside the client crates constructs
it; cachecannon and cachecannon-pools only read it.

### CHANGELOG

The entries are in `CHANGELOG.md` under `Unreleased`: `Changed` for
`#[non_exhaustive]` and `ttfb_ns`, `Added` for the log and `ttlb_ns`, `Fixed`
for `rx_bytes` and the guarded SET records.

## What the time measures

On io_uring the batch time is later than the receipt of each byte it covers,
by the time from that receipt to the batch's clock read. That delay grows when
the worker is busy with other completions or tasks. On mio the batch time can
be earlier than receipt (below). Neither includes the time from the batch
until the reading task is polled and parses, which `latency_ns` does.

- TLS: plaintext exists only per decrypted record. A TLS response's first byte
  is recorded when the completion that finished the first record is handled.
  A record is up to about 16 KiB.
- mio: the batch time is read at the first record in the batch. Bytes read
  from later sockets in the same batch get that earlier time, including bytes
  that reached their socket while the batch ran.
- The request side is the client's own `Instant` (see "Client crates").

I don't know how large the gap between receipt and batch time is under a
loaded client. Measuring it needs a build used only for the measurement and
a bpftrace script. Neither exists yet; the rest of this section describes them
as proposed.

The build logs, per record, the connection's socket 4-tuple, the batch time
and `delivered` after the record. The batch time is raw `CLOCK_MONOTONIC`
nanoseconds, read with `clock_gettime` next to the `Instant::now()` call. The
log goes into a preallocated in-memory buffer, dumped at exit.

A bpftrace script reads `tcp_sock::bytes_received`, the count of in-order
bytes received, at `fentry:tcp_rcv_established`, keyed by socket. At
`fexit:tcp_rcv_established` it emits a sample only if the count increased: the
4-tuple, `nsecs` (also `CLOCK_MONOTONIC`) and the new count. Pure ACKs, window
updates, out-of-order segments and duplicates do not advance the count, so they
emit nothing. The script filters on the server port, and connections are keyed
by 4-tuple and lifetime, since a 4-tuple can be reused.

The gap for each sample is the time from its `nsecs` to the batch time of the
first record whose `delivered` reaches its count. A FIN adds one to the count
and matches no record. Unmatched samples are counted and reported. On
io_uring every matched gap must be at least zero: the softirq holds the socket
lock through `fexit`, and the receive copy needs that lock, so the clock read
comes later. A negative gap means the join is wrong. Mio has no such check,
since its batch time can precede receipt. The measurement uses plaintext
connections, since TLS offsets count plaintext and `bytes_received` counts
ciphertext. Whether `fexit:tcp_rcv_established` attaches on the rig's guest
kernel is checked with `bpftrace -l` first.

The probe time is when TCP processed the data, which under GRO or the socket
backlog is later than wire arrival. If the median gap under load is more than
10% of the median `ttfb_ns`, the batch time is a poor proxy for receipt, and a
kernel timestamp on the shared receive path is worth designing.

## Streaming clients

This API gives one first/last pair per reader call. A client that takes
several messages from one call cannot time them separately:

- ringline-http's HTTP/1.1 chunked reader (`next_chunk`) reads everything
  available into a leftover buffer and yields several chunks from it;
- its HTTP/2 path (`pump_once`) consumes the whole segment chain per call,
  and the h2 codec buffers partial frames;
- `ConnStream` users do not report at all.

A streaming LLM client needs a time per server-sent event. The extension is a
lookup by offset within the consumed range: the reader call keeps the entries
covering that range, and `RecvArrival::time_at(offset)` answers from them.
The client then needs the byte offset of each event within the consumed range.
For HTTP/2, ringline-h2 would have to report frame offsets. `RecvArrival` is
opaque and not `Copy`, so this can be added later without a breaking change.
It is not part of this design.

## Limits

- Under `tls-unbuffered`, plaintext stashed by a flush with no sink
  (`flush_tls_output` on io_uring, `flush_tls_output_mio_queued` on mio) is
  recorded at the next feed. These flushes run during the handshake.
- Bytes taken by `ConnStream::poll_fill_buf` count as consumed when taken.

## Dependencies

- #670 made `park_blocker` refuse a connection with a lent buffer in
  `pending_recv_bufs`.
- #671 (the fix for #669) added `Driver::holds_unread`, which `park_blocker`
  and `offer_park` share. It is now `recv_buffered(conn) > 0 ||
  segment_pinned.is_some()`.

## Cost

- Per batch with a received byte: one `Instant::now()`.
- Per record: an add, a compare, and a `VecDeque` push when the batch changed.
  When a trim is due, one `buffered` sum. A log held at the 1024 cap (a
  backlog of more than 1024 batches) sums `buffered` on every record.
- Per TLS feed: two `buffered` sums.
- Per poll of a reporting reader: one `buffered` sum, and on the resolving
  poll a second, and pops from the front of the log, one per entry dropped.
  `buffered` is a few lengths plus the entries of `segment_hold`.
- Memory, fixed: about 96 bytes per connection slot (the deque header, four
  `u64`s and `latest`).
- Allocation: the deque allocates at a connection's first record (capacity
  4) and reallocates as it doubles, which happens when more than four
  batches' entries are held at once, for example under a consumer that does
  not report. A trim shrinks a deque above 256 to 64, and teardown frees it.
  The A/B cells use long-lived connections and do not measure the first
  allocation.
- Memory, per worker: about 1.5 MB at the default `max_connections` of
  16,000.
- Cache: per connection, the log (two lines: at a 96-byte stride every slot
  spans two), the front of its deque, and the `segment_hold` header that
  `recv_buffered` reads are touched per record and per read.
- Memory, worst case: a connection whose peer sends more than 1024 small
  segments while its parser returns `NeedMore` holds a 24 KiB log, six times
  the accumulator's default initial capacity of 4 KiB.

The log is always on. The arrival times were judged worth a cost estimated
at about 1–3% of server CPU per request. The estimate comes from
closed-loop runs of an earlier version of the lookup; at 4,096 connections
it appears as lower throughput at about the same server CPU time per second.
In the open-loop 4,096-connection cell, where the closed-loop difference
would have read as about +2%, it measured +0.2%. A profile of the current
lookup attributes 0.33–0.43% of the server's samples to the log's functions.

The cost was measured on hv01 and hv02 through SystemsLab with
`experiments/arrival-log-ab-build.toml` and `experiments/arrival-log-ab.toml`.
The server is `bench-server --echo-mode forward` (`with_data` and
`forward_recv_buf`, so its reads report) with 4 workers; the load generator
is `bench-client --runtime ringline` with 16 threads, whose reads also use
`with_data`. Each arm's client was built from the same commit as its server,
so arm B also adds the log to the load generator. Arm A was built from the
same commit as arm B with `--cfg ringline_no_arrival_log`, since removed,
which compiled out the records, the `buffered` sums and the lookups; the
per-slot logs, their clear at setup and release at teardown, and the batch
counter remained. The build spec now builds arm A from `ref_a`, a commit
without the log, so a rerun measures a different arm A. Client CPU stayed
below 13 of 56 cores in every run. A and B runs alternated (A B A B ...),
and each B run is compared with the A run before it.

Two B builds were measured, both commits on #672 before it was merged. The
first set of runs used the earlier one (B1 below), whose reader calls
binary-searched the log for both ends of the range. The 64:16 repeat and the
profiles used the later one (B2), whose reader calls read the front of the log,
as the code does now.

| Measurement | B build | Runs | Result |
|---|---|---|---|
| Closed loop, 64 and 4,096 connections, depth 1 and 16: throughput and p99, B/A per pair | B1 | 5 pairs per cell | Throughput: median of the pairs +0.9% (64:1), −6.3% (64:16), −2.8% (4,096:1), −2.7% (4,096:16); B below A in 2, 3, 5 and 5 of 5 pairs. The A throughput spread (range over median) was 7.2–9.4%. p99 was lower in B in every 4,096:1 pair and higher in every 4,096:16 pair, and mixed at 64 connections; the A p99 spread was 5.5–18% |
| The same cells: server CPU per request, B/A per pair | B1 | 5 pairs per cell | Median of the pairs +0.3% (+73 ns, 64:1), +2.5% (+63 ns, 64:16), +3.0% (+577 ns, 4,096:1), +1.3% (+28 ns, 4,096:16); B above A in 3, 5, 5 and 5 of 5 pairs |
| The same cells: server CPU time per second, B/A per pair | B1 | 5 pairs per cell | Median of the pairs +0.4% (64:1), −5.2% (64:16), +0.6% (4,096:1), −1.3% (4,096:16) |
| Open loop, 64 conns at 141,038/s and 4,096 at 174,945/s (target rates): server CPU per request, B/A per pair | B1 | 5 pairs | Median of the pairs −2.1% (−619 ns, 64) and +0.2% (+43 ns, 4,096); B above A in 2 and 4 of 5 pairs. The A spread was 1.4% of 30 µs per request at 64 connections and 1.2% of 27 µs at 4,096, about 0.4 µs and 0.3 µs; the B spread was 7.3% and 2.0% |
| Closed loop 64:16, server CPU per request, B/A per pair | B2 | 8 pairs | Median of the pairs +0.4% (+10 ns); B above A in 5 of 8 pairs, which ranged from −4.6% to +6.5% |
| `perf record -a` in the server VM, 10 s at 64:16 | B2 | 1 A, 3 B | The self time of the log's functions (`recv_buffered`, `settle_read`, `add`, `record_arrival`, `arrival_settle`) is 0.33–0.43% of samples, 8–11 ns per request. The server binary's share of samples is 3.01% in A and 3.39–3.58% in B |

The 1–3% estimate rests on the B1 runs at 64:16, 4,096:1 and 4,096:16,
where B used more server CPU per request than the A run before it in every
pair. Server CPU here is rezolus' CPU time summed over all vCPUs of the
server VM, network softirq included. At 4,096 connections B's server used
about as much CPU time per second as A's (medians +0.6% and −1.3%; 6.6–6.9
cores at depth 1 and 7.3–7.9 at depth 16 in both arms), so there the higher
CPU per request comes from B completing fewer requests, and the
CPU-per-request and throughput rows are nearly one result. These runs do not
show whether the server's log or the client's lowered throughput. At 64:16
the server's CPU time per second moved with throughput in each pair, and B
used more CPU per request in all five pairs, including the two where it
completed more requests.

The reader code that ships is B2's. It was measured at 64:16 only: its
paired median, +0.4% or 10 ns per request, agrees with the profile, but its
pairs spread too widely to exclude 2.5%. The 4,096-connection cells were not
measured on it.

The B1 difference in CPU per request is not a fixed time: 63 ns at
64:16, 577 ns at 4,096:1 and 28 ns at 4,096:16. In the open-loop
4,096-connection cell, 577 ns would read as about +2.1%; it measured +0.2%.
In the open-loop 64-connection cell, 63 ns (64:16) to 73 ns (64:1) is about
0.2% of the 30 µs of server CPU per request, and that cell's pairs ranged
from −5.0% to +2.3%, so it could not show a difference that small.

The profile attributes 0.33–0.43% of the server's samples to the log's own
functions. The idle task takes 15–18% of the samples, and almost all of
those are network softirq symbols; the idle-loop symbols take under 1%. If a
halted vCPU is not sampled, the share of samples is the share of busy CPU.
As a consistency check, the samples per request in the profiled runs
(2.37–2.49 µs, at 2.60–2.74 M requests/s) are within 0.02 µs of the range
of CPU per request rezolus measured in the unprofiled B2 runs at 64:16
(2.38–2.63 µs over both arms, at higher throughput). The server binary's
share is 0.38–0.57 points higher in B than in the one A profile, 9–14 ns per
request against the 8–11 ns attributed to the log's functions. With one A
profile the A-to-A variation is unknown. Misses the log causes in kernel
code are not attributed to it. Only 64:16 was profiled. At 4,096
connections each worker holds about 1,024 logs, where misses on
per-connection data are more likely; that case has no profile.

## Tests

Batch times are set through the test hooks, so these do not depend on how the
kernel batches completions. Each test is checked by mutation, named per test
below or, for a test that names none, removing the record or trim it covers.

- Two responses delivered in separate batches report different times; two in
  one batch report the same time.
- A response that spans two batches reports `first` from the first and `last`
  from the second.
- Pipelined responses: the second response's `first` is the time of the batch
  that delivered its first byte.
- Record order: with 65 batches buffered, a new completion at least as large
  as the oldest batch arrives, and the next reader's `first` is the oldest
  batch's time. Mutation: swap steps 1 and 2 of the record.
- Trim recovery: 600 unread batches, a non-reporting consumer drains them,
  then records continue until the log reaches 1024 entries. That record trims
  the log to one entry, so no merge happens. Mutation: drop the `min`; the
  log then merges at 1024 and never trims.
- The offset stays correct after `forward_to` (with overshoot) and a
  consumer that does not report (`accumulators.consume`, standing in for
  `ConnStream`).
- A parser that returns more than it was shown, through `with_bytes` and the
  lent-buffer path.
- Completions recorded while a `RecvSegment` is live, followed by the segment
  reader dropping, leave the next `with_data`'s `first` at the time of the
  first byte after the segments handed out.
- TLS on both backends, segmented reads, the fallback recv path, and mio.
- 1025 unread batches merge entries, count the merge, and leave 1024 entries.
- A read whose range starts below `base` or ends past `delivered`, or that
  reads an empty log, counts `CLAMPED` once. Mutation: count once per
  condition that holds; the empty-log read then counts more than once.
- A park that carries bytes leaves `delivered >= buffered` on the adopting
  worker.
- A slot reused by a new connection starts with an empty log and
  `recv_arrival() == None`; the old connection's handle reads `None`, also
  after the new connection has read (io_uring). Mutation: drop the generation
  check in `recv_arrival`.
- A reader call that consumes nothing leaves `recv_arrival() == None`, and so
  does a `try_with_data` that finds nothing buffered.
- On mio, a forward source re-read by `drain_forward_resumes` gets a batch of
  its own.
- The client crates report `ttfb_ns <= ttlb_ns <= latency_ns`; an operation
  that fails at send reports `ttfb_ns == None` and `rx_bytes == 0`; an error
  reply reports both times, including through the guarded SET paths.
