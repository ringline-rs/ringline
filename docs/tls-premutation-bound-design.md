# TLS pre-mutation ciphertext bound (series PR 8)

Eighth PR of the series that lands #318
(`docs/backpressured-sends-series-design.md`, "PR 8"). Origin: @thinkingfish
in #318; re-derived on `main` after a survey of both TLS engines. Sits on
#376, #377, #381, #382 and #384. PR 9 consumes it.

No public API. No changelog line.

## The problem

`send_backpressured` must decide admission **before** rustls mutates. Today
both backends size a bounded TLS send's permit by *plaintext* length, and
ciphertext is larger by per-record overhead. Worse, on io_uring the
reservation cannot even be held across encryption, because encryption
allocates from the same pool and an outstanding reservation hides those
slots from it — so the TLS branch returns before reserving at all.

The cost of getting this wrong is asymmetric, and that asymmetry drives
every decision below:

- **A bound that is too large** makes a bounded send wait for capacity it
  did not strictly need. The caller is delayed. Nothing breaks.
- **A bound that is too small** lets the send start encrypting and run out
  of pool mid-record. rustls has already advanced its record sequence, so
  by departure 1 the operation fails *and the connection is closed*. A
  peer that would have seen backpressure instead sees a dead connection.

So every estimate below is deliberately conservative, and a debug tripwire
asserts the bound was never beaten.

## What the bound actually is

Measured against rustls 0.23.41 (`Cargo.lock` at the time; ringline-tls 0.1.2,
the fork ringline uses today, carries the same constants), whose relevant
constants are
all `pub(crate)` and therefore unreachable — ringline already keeps its own
copies and says why (`tls/unbuffered/mod.rs`).

Per record: a 5-byte header plus AEAD expansion. TLS 1.3 adds 17 bytes
(content-type byte + tag); TLS 1.2 GCM adds 24 (explicit nonce + tag). So
**22 bytes per record on TLS 1.3, 29 on TLS 1.2 GCM**.

**The bound uses 29.** The `TlsConfig` and `TlsClientConfig` builders
enable TLS 1.2 next to TLS 1.3 by default (`ringline-tls-config` enables
rustls's `tls12` feature), so a connection can negotiate a TLS 1.2 GCM
suite. This is also why the existing `MAX_RECORD_WIRE_LEN` is the wrong constant to reuse:
it assumes TLS 1.3 and explicitly disclaims correctness dependence.

Fragment size comes from `ClientConfig`/`ServerConfig::max_fragment_size`
(a `pub` field, default `None` → 16389). **It includes the 5-byte header**,
so plaintext per record is `cfg - 5`; rustls' own
`MessageFragmenter::set_max_fragment_size` does the same subtraction. There
is no negotiated per-connection value — the `max_fragment_length` extension
is never negotiated — so the config is the only source. `TlsConn` gains a
`max_plaintext_per_record` field recorded at `create` / `create_client`,
already subtracted, so no call site can repeat the off-by-five.

**Byte bound** (both engines, both backends):
`records = ceil(plaintext / F)`, `bytes = records * (F + 29)`, where `F` is
the plaintext per record.

## Slot bounds diverge, and must not share a constant

**Buffered** packs ciphertext contiguously through `PoolWriter`, letting a
record straddle two slots, so `slots = ceil(bytes / slot_size)` exactly.

**Unbuffered** cannot straddle: `encrypt_chunk` writes whole records into
one slot. The byte formula therefore *under*-estimates it. A worked case:
at `slot_size` 32768 and 49152 bytes of plaintext, the byte formula says 2
slots; the engine takes 3.

The bound below holds while each slot carries at least `F` plaintext, apart
from the last and from calls that also carry records rustls had queued (a
key_update); the slack record (the `+ 1` added under "Slack for
`sendable_tls`" below) covers the plaintext those calls give up.

**Decision: bound the unbuffered slot count at one record per slot**,
`slots = records`. It is safe under the condition above. It over-reserves
when slots are large enough to hold several records, which costs admission
latency and nothing else — the right side of the asymmetry. If a later
measurement shows the waste matters, the fix is a tighter *measured* bound,
not a cleverer formula.

**Slack for `sendable_tls`.** rustls drains anything already queued — a TLS
1.3 `key_update`, an alert — into the front of the same destination, and its
size is not a function of the plaintext. The unbuffered engine exposes no
byte count for it at all (`tls_bytes_to_write` is buffered-only). The bound
therefore adds **one whole record** of headroom unconditionally.

### The unbuffered threshold is tighter than it looks

`slots_unbuffered` can only express a bound when one whole record fits in a
slot, i.e. `slot_size >= F + 29`. In the shipped default that is
`send_copy_slot_size = 16448` against `F + 29 = 16413` — **a margin of 35
bytes**. Any configuration that lowers the slot size a little, or raises the
fragment size, makes the bound inexpressible. On the unbuffered engine
`Config::validate` rejects such a configuration for every configured rustls
config, so the refusal below is reached only by TLS state installed without
validation (unit tests).

What matters is what happens below that threshold, and it is not a progress
failure: the unbuffered engine still encrypts (its shrink loop converges,
and its minimum destination is far smaller), it just emits more records than
`ceil(len / F)`. So `slots = records` stops being an over-estimate and
becomes an **under**-estimate — the connection-closing direction.

Therefore the call site must treat `None` as a refusal, not as a reason to
fall back to the byte formula: a bounded TLS send on a connection whose slot
size cannot hold a whole record is rejected up front with `InvalidInput`,
naming `send_copy_slot_size`, the same shape as the existing
"wider than the whole pool" refusal. Silently proceeding with an
under-estimate is the one outcome this PR exists to prevent.

### The call site does not choose the engine

The two slot formulas above are the tested arithmetic, but a call site that
picks between them can pick wrong, and picking `slots_buffered` for an
unbuffered connection is precisely the silent under-estimate this PR exists
to prevent. `CiphertextCapacity` therefore records which engine drives the
connection it was taken for — read from the connection's own
`TlsConnKind` tag, not from the cargo feature — and exposes
`slots(slot_size)`, which dispatches. That is what admission calls;
`slots_buffered`/`slots_unbuffered` remain as the directly-tested
primitives. The tag and the feature agree today. A call site that assumed
so would be silently wrong on the day they stop agreeing, and nothing would
fail until a connection closed in production.

`min_slot_size()` (`F + 29`) exists so the refusal can name the number the
operator has to clear, rather than saying only that the slot is too small.

### The two refusals are not the same refusal

`None` from `slots` is **unbuffered-only**. The buffered engine straddles
slots, so a slot far smaller than one record still yields a valid bound —
just a large one (a 64-byte slot against a 16 KiB record asks for 513
slots). That request then fails the ordinary pool-capacity check and the
caller gets the existing "needs N slots but the pool has M (raise
Config::send_pool)" error. Both refusals are correct and both are
`InvalidInput`; what must not happen in either engine is a send admitted
against a bound that is too small.

## Where the check goes

**Departure 2 held when this landed.** Both bounded call sites are distinct
functions from their plain twins, so `encrypt_to_sends` and
`encrypt_for_send_mio` were untouched. `encrypt_tls_send` later applied the
same bound to plain TLS sends on io_uring; see the CHANGELOG entry "io_uring:
a TLS `send`, `send_nowait` or `send_parts` that ran out of send pool partway
through encryption corrupted the connection".

**io_uring** (`DriverCtx::send_bounded`, TLS branch): check
`send_copy_pool.free_count() >= capacity_slots` immediately before
`encrypt_to_sends`; on failure return the same `Exhausted` error as the
plaintext path, *before* anything mutates. A plain capacity check is
sufficient here and was verified: the worker is single-threaded, no
reservation is outstanding on this path, and nothing allocates from the pool
between the check and the first allocation inside the call.

**mio** (`DriverCtx::send_bounded`, TLS branch): the reservation is already
taken before the TLS branch; only its *size* is wrong. Size it by
`capacity_slots` instead of the plaintext, then shrink the permit to what
the ciphertext actually needs once `encrypt_for_send_mio` returns.

`SlotReservation` has no partial-release API — it is a bare count, and its
`Drop` debug-asserts the remainder was returned. PR 8 adds
`SendCopyPool::shrink_reservation(&mut SlotReservation, keep: usize)`,
which returns the difference to the pool. Release-then-re-reserve is
rejected: it would need an `expect` that is only sound because nothing runs
in between, and that is exactly the kind of invariant that stops being true
later.

## The tripwire

Bounds that are checked only by the tests that were written for them tend to
drift. Both bounded paths therefore `debug_assert` that the slots actually
consumed did not exceed the bound — io_uring by comparing the pool's free
count before and after `encrypt_to_sends`, mio by comparing the ciphertext
length against the byte bound. If either of the two modelled hazards is
ever beaten (unbuffered record waste, a `sendable_tls` drain into the same
destination), a debug build says so loudly instead of closing a connection
in production. This is the same technique as #384's release
guard, for the same reason.

## Forward coupling with PR 9

`SendCapacityQueue::enqueue` takes `required_slots`, and `turn` compares it
against the pool's free count. PR 9's future **must compute that number with
this same capacity function**, or the FIFO will admit a message the backend
then refuses. The function is therefore public to the crate and documented
as the single source of that number, and PR 9's oversize-rejection test must
use it too.

## Tests

Against real rustls records, using the in-memory handshake harnesses that
already exist (`tls/buffered.rs`'s `test_certs`/`pump`/`handshaked`, and
`tls/unbuffered/tests.rs`'s `conn_pair`/`handshake`). The buffered harness is
currently gated `cfg(all(test, has_io_uring))`, which keeps it off the
development machine for no reason; PR 8 widens that to `cfg(test)`.

- default fragment size: bound ≥ actual, for a plaintext spanning one
  record, exactly one record, and several;
- **fragment-size override** (`max_fragment_size = Some(2048)`): same, and
  the off-by-five is visible here — a bound that forgot the header
  subtraction under-counts records;
- TLS 1.2 (`rustls::version::TLS12`, enabled by default): the
  29-byte worst case is exercised rather than assumed;
- the unbuffered slot bound against a slot size that holds several records,
  which is the case the byte formula under-estimates;
- `shrink_reservation` returns the difference and leaves the remainder
  releasable.

## Verification

Four configurations must be green, per the series doc: default/io_uring,
default/mio, `tls-unbuffered`/io_uring, `tls-unbuffered`/mio. macOS covers
the two mio ones; the io_uring pair runs on a Debian 13 anvil guest.

The two-guest A/B does not apply — this PR changes only admission arithmetic
on a path with no caller until PR 9.
