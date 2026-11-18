# Send pool partition: a slot per connection and a capped shared region

Status: proposal. Nothing here is implemented.

## The problem

Each worker has one send copy pool (`SendCopyPool`, `buffer/send_copy.rs`):
`send_copy_count` slots of one size in one allocation, and a LIFO free list.
The pool keeps no account of which connection holds which slot; `release`
takes only a slot index. One connection can therefore hold any number of
slots, and `docs/send-admission-design.md` lists one connection's share of
the pool as a non-goal.

The cache server this design is for measured what that costs (loopback,
kernel 6.12, one worker, 8,192 slots of 16,448 bytes):

- A client that pipelines 4,000 GETs of 64 KiB values and reads at 1 MB/s
  keeps the pool full. Every reply on the worker, including a 1 KiB reply on
  an idle connection, then waited about 1 s (four such clients) to 2 s (one),
  under `Strict` and under `Budget { slots: 32 }` alike.
- With those readers and 120 KiB replies waiting for slots, `Strict` held a
  1 KiB reply for 1-2 s at p99, where `Budget` admitted it in under a
  millisecond in seven of nine runs. `Budget` helps only while the head of
  the FIFO needs more slots than are free and a smaller send behind it fits.

Neither order bounds a connection's share, so neither prevents the first
case, and `Strict` cannot be the default while the second holds.

## Proposal

Split each worker's pool into two regions.

- A dedicated region of `max_connections` slots. Slot *i* belongs to the
  connection with index *i* and is used by no other connection. Its slot size
  `D` is configured separately from the shared region's.
- A shared region of `send_copy_count` slots of `send_copy_slot_size`, as
  today, with a cap `M` on the shared slots one connection may hold.

A connection always has one slot that no other connection can take, so a
reply that fits one slot never waits on another connection. A connection
that holds `M` shared slots waits for its own slots to return, and does not
hold the head of the FIFO meanwhile.

With the cache server's settings (4,096 connections per worker, `D` = 20 KiB,
the shared region at 4,096 slots of 16,448 bytes) the two regions take 80 MiB
and 64 MiB per worker, against 128 MiB for today's single pool.

### Which region a send uses

- A send whose bytes fit one dedicated slot takes the connection's dedicated
  slot if it is free, and the shared region otherwise. On TLS "fits" means
  the reply's ciphertext, one record of at most `F` plaintext bytes, plus
  what rustls drains ahead of it (below).
- A send that needs more than one slot takes shared slots only. Mixing
  regions within one send would save one shared slot and complicate the
  release path; the design does not do it.
- UDP sends (`Driver::udp_send_to`, `backend/uring/driver.rs`) have no
  connection index and take shared slots, as today.

Every allocation path applies this rule, whether or not it goes through the
admission FIFO: `send_inner` (`send`, `send_awaited`, `send_bounded`),
`SendBuilder` (`build`, `submit_batch`), `SendChainBuilder`, and the TLS
output paths (handshake records, alerts and `close_notify`, in
`tls/backend_uring.rs` and `tls/buffered.rs`). The paths that take slots
directly keep their failure behaviour when neither region has room: they
refuse with `Other("send copy pool exhausted")`, or for TLS output they close
the connection.

### The cap on shared slots

The pool records, for each shared slot in use, the connection index and
generation that took it, and keeps a held count per connection, decremented
on `release`. The send slab already keeps such a count for its entries
(`InFlightSendSlab::held_by`, `buffer/send_slab.rs`); this is the same
accounting for pool slots. Dedicated slots are not counted.

In the admission FIFO (`SendCompletions`, `runtime/send_completion.rs`) a
waiter whose connection would exceed `M` with its own slots is not eligible:
it keeps its place in arrival order, the head is the oldest eligible waiter,
and a release of one of that connection's slots makes it eligible again.
Under `Strict` only the head is admitted; under `Budget` the passing rules
are unchanged and apply among eligible waiters. A send that alone needs more
than `M` slots can never be admitted and is refused with `InvalidInput`, as a
send larger than the pool is today (`bounded_send_slots`, `handler.rs`).

A path that takes slots directly refuses at the cap as it does at
exhaustion. Whether `send` and `submit_batch` should refuse at the cap, or
only bounded sends should observe it, is open (question 2): refusing changes
what existing callers see, as `zero_copy_hold_cap` did for guarded sends.

### TLS slot charge

Today a bounded TLS send is charged `ceil(len / F) + 1` records, one slot
each (`ciphertext_capacity`, `tls/mod.rs`). The extra record is slack for
records rustls has already queued (a TLS 1.3 `key_update`, an alert), which
`write_plaintext` drains into the front of the same buffer; the unbuffered
engine exposes no byte count for them. A one-record reply is therefore
charged two slots and could not use a single dedicated slot.

- The dedicated slot is sized for one worst-case record plus slack:
  `D` = 20,480 bytes holds a record of `F` = 16,384 plaintext bytes and 29
  bytes of overhead (16,413) and 4,067 bytes for drained records. A
  one-record reply is charged exactly the dedicated slot.
- If drained records leave too little room, `encrypt_chunk` writes fewer
  plaintext bytes into the slot than the reply holds (it writes whole records
  and cannot straddle, `tls/unbuffered/mod.rs`), and the remainder takes a
  shared slot in the same loop that fills multi-slot sends today
  (`encrypt_to_sends`). The send then holds one shared slot it was not
  charged for; the cap counts it on allocation.
- In the shared region the charge stays `ceil(len / F) + 1` until it is known
  whether the engine can say that nothing is queued (question 3). If
  `wants_write()` (`tls/mod.rs`) is reliable for the unbuffered engine, the
  `+ 1` is charged only when it is true.
- The unbuffered engine caches the plaintext that fits one slot keyed on the
  destination length (`max_plaintext_per_chunk`, `tls/unbuffered/mod.rs`),
  and its comment notes that a second slot size would defeat the cache. The
  cache keeps one entry per slot size.
- `validate_tls_slot_size` (`config.rs`) checks both slot sizes against one
  worst-case record.

### Slot indices and memory

The completion payload carries a 16-bit slot index, with `u16::MAX` as "no
slot" (`completion.rs`, `BuiltSend::pool_slot`). Dedicated slots take indices
`0..max_connections` and shared slots the indices after them, so
`max_connections + send_copy_count` must be at most 65,535; `build()` checks
it. Each region has its own backing allocation, and a slot's address is its
region's base plus its offset in the region times the region's slot size.
Coalesced `sendmsg` runs (`submit_coalesced_run`, `backend/uring/driver.rs`)
read each slot's address and length from the pool and assume neither
contiguity nor one size, so they need no change.

The dedicated region is `max_connections` × `D`. At ringline's default of
16,000 connections and `D` = 20 KiB that is 312.5 MiB per worker, so the
region is off unless configured (`ConfigBuilder::send_pool_dedicated(slot_size)`,
name to be settled), and an application that enables it sizes
`max_connections` to its real connection count.

### mio

On mio the pool is an admission budget only: `send_bounded` reserves slots
and holds the reservation, and no slot memory is used (`handler.rs`,
`docs/mio-bounded-send-design.md`). The dedicated slot and the cap apply to
that budget in the same way, so a bounded send on mio is admitted under the
same rule as on io_uring.

## Expected effect

- A slow reader holds its dedicated slot and at most `M` shared slots. With
  `M` = 64 and 4,096 shared slots, 64 such connections are needed to fill the
  shared region; one is enough today.
- A reply that fits one slot is sent without waiting on any other connection,
  whatever the shared region holds.
- `Strict` is expected to become usable: its failure in the measurement came
  from a head that could not be admitted while one connection's queued
  replies held the slots it needed. That is a prediction for the experiment
  below, not a result.

## Experiment

The cache server's admission-order cells, rerun with the partition:

- the `slow` cells (readers pipelining 4,000 GETs of 64 KiB values at
  1 MB/s) and the `mixed` cells (the same readers with clients requesting
  120 KiB values), with the 1 KiB and 64 KiB probes;
- `M` at 16, 64 and 256, under `Strict` and `Budget`, against the unpartitioned
  pool as the control;
- an `idle` cell with a client that pipelines small replies, to measure what
  a fast connection loses when it is limited to its dedicated slot and `M`.

The prediction and the decision rule are written before the runs, and
`send_passing_admissions` (the count of sends admitted ahead of the head)
confirms in each cell whether `Budget` had anything to do.

## Open questions

1. `D` and `M` defaults. The experiment sets `M`; `D` depends on the largest
   control output rustls queues ahead of application data. A TLS 1.3
   `key_update` or alert is under 30 bytes; whether session tickets or other
   post-handshake messages can be queued ahead of application data, and how
   large, needs to be read in the TLS library.
2. Whether direct paths (`send`, `submit_batch`, chains) refuse at the cap,
   or only bounded sends observe it.
3. Whether the unbuffered engine's `wants_write()` reports drained records
   reliably, which would remove the `+ 1` record from the shared charge.
4. Whether a connection's waiter that is not eligible should keep its arrival
   position (as above) or rejoin at the back when it becomes eligible.
5. Whether `Budget`'s limit `min(slots, P - H)` should count shared slots
   only, which this design assumes.

## Alternatives

- A reserved count per connection instead of a dedicated region: each
  connection may take its first `min` slots from a reserve sized
  `max_connections` × `min`. The same guarantee, with accounting on every
  allocation and no fixed slot per connection. The dedicated region needs no
  accounting for the common one-slot reply.
- A registered region per connection of several slots (`min` = `max`):
  isolation without sharing, at a memory cost proportional to
  `max_connections` × the largest burst, most of it idle.
- Two pools by reply size (O5 in `docs/send-admission-design.md`): bounds the
  slots a large reply can take, but not one connection's share.

## Order of work

1. The per-connection held count for shared slots and its tests, with no
   behaviour change.
2. The cap in the admission FIFO, for bounded sends.
3. The dedicated region and its backing, behind the configuration switch,
   with the TLS charge for one-record replies.
4. The experiment above, then the defaults.
