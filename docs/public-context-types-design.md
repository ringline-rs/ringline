# Removing the public context types

**Status:** approved, 2026-11-04, including both [owner decisions](#owner-decisions).
Series for 0.7.0. Steps 1 to 4 landed in #737, #738, #739 and #740. Follows
`docs/connection-handle-ownership-design.md`, which moved reading and writing
onto `RecvHalf` and `SendHalf` and left `ConnCtx` as a `Copy` token.

## Goal

An application reaches ringline through owned values and free functions:

| need | API |
|---|---|
| a connection | `Connection`, `SendHalf`, `RecvHalf` |
| a UDP socket | `UdpSocket` |
| comparing or indexing connections | `ConnId` |
| anything else on the worker | free functions (`connect`, `spawn`, `sleep`, `request_shutdown`, the disk functions) |

`ConnCtx` and `DriverCtx` become `pub(crate)`. `ConnToken` becomes `ConnId`, and
`UdpCtx` becomes `UdpSocket`.

This is how tokio is built: `runtime::context` and the driver are `pub(crate)`,
`TcpStream` and `Sleep` reach the driver through a thread-local, and
`Builder::on_thread_park` takes a closure with no context argument. Ringline
already has the same mechanism in `CURRENT_DRIVER`, `with_state` and
`try_with_state`, all `pub(crate)`.

## `ConnCtx` becomes `pub(crate)`

The public methods of `ConnCtx`, and what replaces each:

| method | replacement |
|---|---|
| `token`, `peer_addr`, `listener`, `is_outbound`, `is_alive`, `tls_info`, `offer_for_park`, `is_recv_direct` | already on `Connection`; all but `is_recv_direct` on `SendHalf`; `token`, `is_alive`, `offer_for_park` and `is_recv_direct` on `RecvHalf` |
| `close` | `Connection::close`, `SendHalf::close` |
| `cancel` | removed, with `Connection::cancel`; neither has a caller, mio returns `Unsupported`, and a parked read is interrupted by `select` on a `CancellationToken` |
| `request_shutdown` | `ringline::request_shutdown`; the methods on `Connection` and `SendHalf` go too |
| `forward_to_conn` | `RecvHalf::forward_to_conn`, `Connection::forward_to_conn` |
| `split`, `take_send`, `take_recv` | removed; `Connection::split` is the only split |
| `index` | `ConnId::index` |
| `for_test`, `split_for_test` | `Connection::for_test` and `Connection::split` |

`as_conn` on `Connection` and `SendHalf` is removed. The use its doc comment
names is a forward sink, and the `&mut SendHalf` form of `forward_to_conn` covers
that.

### Other public signatures

- `ConnStream::new` takes a `Connection` and owns it. `conn_ctx()` is replaced by
  `send_half(&mut self) -> &mut SendHalf`, because `close` and
  `shutdown_write` take `&mut self`, and a `Connection` accessor would allow a
  read past bytes cached in `fill_buf`. Today a caller writes
  `ConnStream::new(conn.as_conn())` and keeps `conn`, which leaves two values
  that can read one connection. `eof_truncated()` and `is_recv_direct()` are
  added to `ConnStream`, because a caller that gave up the `Connection` needs
  them; a `ConnStream` read does not report `recv_arrival`. `ConnStream` grows by
  8 bytes, so the limit in `conn_stream_size` moves from 48 to 56.
- `mark_disconnected` on the redis, memcache and ping pools takes a `ConnToken`,
  and then a `ConnId` from the rename onward. It only compares the value.
- `RecvHalf::forward_to_conn` and `Connection::forward_to_conn` return one type
  on both backends, `ForwardFuture<'h>`, borrowing the source half and the sink
  half for the same lifetime. Today io_uring returns `ForwardToFuture<'h>` and
  mio returns `ForwardToConnFuture<'s>`. The mio future does not hold the source
  borrow, so a second forward on one source compiles on mio and not on io_uring.

### What goes away

- The `sink_owned` parameter of `direct_forward` and its `EBUSY` refusal. No
  caller can name a sink without holding its `SendHalf`.
- `split_for_test`. `Connection::split` does not touch the driver, so
  `build_for_test` in the redis and memcache clients can call it directly.
- `take_send`, `take_recv` and their unit tests in `uring/event_loop.rs`. No API
  can ask for a second claim.

### Documentation

Public docs link to `ConnCtx` from about 54 lines in `io.rs`, and from `lib.rs`,
`stream.rs`, `config.rs` and the client crates. `cargo doc -D warnings` rejects a
public link to a private item, so step 1 removes every link. Several public
methods say only "See [`ConnCtx::close`]", so the full text moves to the public
method.

The two `compile_fail` doctests on `ConnCtx` assert `!Send` and `!Sync` through
`ringline::ConnCtx`. Once the type is private they keep passing because the name
does not resolve, so they move to `Connection`, `SendHalf` and `RecvHalf`. The
example in `runtime/cancellation.rs` takes a `Connection`.

### Tests

| test | change |
|---|---|
| `stream_echo.rs`, `throughput.rs`, `recv_direct.rs:590`, `echo_stream_server` | pass the `Connection` to `ConnStream::new` |
| `fs_fd_ownership.rs`, `disk_io_stale_results.rs`, `disk_io_teardown_buffers*.rs` | split, and move the `SendHalf` into the task that closes |
| `tls_echo.rs:2118` (`EPROTOTYPE` on a TLS sink) | go through `RecvHalf::forward_to_conn` |
| `echo.rs:7692` (second forward on a source) | the concurrent case becomes a `compile_fail` doctest on `RecvHalf`; the test keeps `EBUSY` through a leaked forward |
| `recv_direct.rs:781` (forward after a dropped forward) | keeps the assertion, using `drop(source.forward_to_conn(&mut tx, 1))` |
| `forward_to_conn_refuses_stale_slots_and_a_claimed_sink` | drops the claimed-sink case and calls `direct_forward` with an in-crate sink |
| `echo.rs:7806` (`take_recv` while claimed) | removed |

## Read futures borrow their half

Before step 2, `WithDataFuture` carried no lifetime, so the borrow ended when the
call returned, and this compiled on both backends:

```rust
let a = rx.with_data(|d| ParseResult::Consumed(d.len()));
let b = rx.with_data(|d| ParseResult::Consumed(d.len()));
```

The ownership design lists two readers as a compile error, and with `ConnCtx`
private the `&mut` on a half is the main compile-time check on reads.
`WithDataFuture`, `WithDataResultFuture` and `WithBytesFuture` gain a lifetime
that holds the half's borrow. `ForwardFuture` already does.

`RecvReadyFuture` stays unborrowed. It consumes nothing, and `Client::recv_ready`
exists so that a caller can fire while it is pending
(`docs/send-while-receiving-design.md`), which a borrow would refuse with E0499.
It was `Send`, holding only a connection index and generation. It gains
`PhantomData<*const ()>`, so it is `!Send`, because a poll on another worker would
index that worker's connection table. A `RecvReadyFuture` moved to another task on
the same worker still compiles, and polling it takes `owner_task` from the reader,
as it does today.

## `DriverCtx` becomes `pub(crate)`

The callbacks become:

```rust
fn on_tick(&mut self) {}
fn on_notify(&mut self) {}
```

Both backends set `CURRENT_DRIVER` around these calls, so the free functions
work inside them. `spawn_from_on_tick_succeeds` in `tests/handler_callbacks.rs`
tests this for `spawn`.

The call sites also change. `handler.on_tick(&mut ctx)` holds a `DriverCtx` built
from `&mut Driver` while `spawn` makes a second `&mut Driver` through
`with_state`, so a tick that uses both has two live mutable references. With no
`ctx` argument there is one.

| `DriverCtx` method | replacement |
|---|---|
| `request_shutdown` | `ringline::request_shutdown` |
| `open_direct_io_file`, `open_direct_io_file_with`, `open_nvme_device` | free functions of the same name |
| `close_direct_io_file`, `close_nvme_device` | new free functions of the same name; no free form exists today, so a task cannot close either handle. `close_nvme_device` needs a mio stub, as `open_nvme_device` has |
| `direct_io_read`, `direct_io_write`, `direct_io_fsync`, `nvme_read`, `nvme_write`, `nvme_flush` | free functions, called from a spawned task |
| `send`, `send_parts`, `send_chain`, `close`, `shutdown_write`, `peer_addr`, `is_outbound`, `tls_info` | no token form; the task that holds the `Connection` or half calls the method, and other code reaches it through `mpsc` or a `CancellationToken` |
| `cancel` | removed, as for `ConnCtx::cancel` |
| `max_chain_length` | the value passed to `ConfigBuilder::max_chain_length` |
| `send_to` | removed, with `UdpToken`; no public API returns a `UdpToken`, so nothing outside the crate can call it |

`SendBuilder` stays public, because `AsyncSendBuilder::build` passes it to the
caller's closure. `SendChainBuilder` and `ChainPartsBuilder` stay public, through
`send_chain`.

A disk method on `DriverCtx` returns a `u32` key, and `DiskIoFuture::new` is
`pub(crate)`, so a caller has no way to get the result. The free functions return
a `DiskIoFuture`, which needs a task to poll it. `on_tick` does not run in a task.

### What a caller loses

Across the series:

- Sending on a connection from `on_tick` by token has no direct replacement. The
  owning task does the send, usually by receiving from an `mpsc::channel`. This
  is the rule the ownership design chose for fan-in, and a tick that sends at an
  arbitrary point in a response stream has the ordering problem that design
  describes. A handler is `Send` and `SendHalf` is not, so a handler cannot keep a
  half in a field.
- A third task can no longer close a connection or check `is_alive` through a
  copied handle. It needs the `SendHalf`, or the owner has to `select` on a
  `CancellationToken`.
- `RecvHalf` has no `close`, so a reader that detects a protocol error signals
  the task holding the `SendHalf`.
- A protocol client exposes `close`, `is_alive` and its id. `peer_addr`,
  `tls_info`, `listener`, `is_outbound` and `is_recv_direct` have to be read from
  the `Connection` before it goes to the client. `offer_for_park` cannot be called
  on a connection held by a client.
- A dropped half cannot be taken again.
- `ConfigBuilder::close_notify_timeout_ms` is removed, and the internal fatal
  closes keep a fixed 5 s bound. An application has no way to bound a TLS close
  against a peer that stops reading. See [Owner decisions](#owner-decisions).
- On a `Connection` a held read future also blocks sends, so that case needs
  `split()`. A read future is not `'static`: to spawn or box one with `'static`,
  move the half into an `async move` block that makes the call.

### Consumers checked

Four crates outside this repository depend on ringline: a load generator, two
cache servers and a proxy. Three have an `on_tick`, and those call only
`request_shutdown` through `ctx`. They pin different ringline versions and were
read at their current checkouts, not compiled against this design. Each has a
path under this design. The largest port is the load generator, which stores a
`ConnCtx` beside each client for closing and logging.

In this repository the uses are `request_shutdown`, `open_direct_io_file` and
`close_direct_io_file`, plus two tests that exist to exercise a `DriverCtx` path:

- `tls_tick_close_sends_close_notify` closes by token. `DriverCtx::close` stays
  in use for the fatal encrypt closes in `handler.rs`, so its deadline becomes a unit
  test in `uring/event_loop.rs`. `tls_server_close_sends_close_notify` and
  `tls_handler_return_sends_close_notify` cover the public close paths.
- `disk_io_stale_results.rs` (`RawThenFuture`) submits a read whose key nothing
  holds. It goes: the disk methods on `DriverCtx` have no other caller than the
  free functions, which hold the key, and the same file covers keys left by
  dropped futures.

## `ConnToken` becomes `ConnId`

With `DriverCtx` gone, the only thing that accepts a token is `mark_disconnected`,
which compares it, so the name no longer describes it. `ConnId` keeps `index()`, gains `Hash`, and is what `id()` returns on
`Connection`, `SendHalf`, `RecvHalf` and the protocol clients, replacing
`token()`. The `index()` methods on `Connection` and `SendHalf` are removed; the
examples that log them use `id().index()`.

`ConnId` is `Send`, and no method on it reaches a driver. An id used on the wrong
worker gives a wrong comparison, and on a pool's `mark_disconnected` that closes
an unrelated connection. A pool cannot cross workers, so this needs an id sent
by hand.

## `UdpCtx` becomes `UdpSocket`

`UdpCtx` is `Copy`, `Send` and `Sync`, and has the problems `ConnCtx` had before
the ownership series. Its doc comment states that a second `recv_from` waiter
overwrites the first and that the first is then leaked, and the type does not
prevent it. It can also be moved to another worker, where `udp_index` resolves
against a different socket table.

`UdpSocket` is not `Copy` or `Clone`, and is `!Send`:

- `recv_from`, `with_datagram`, `recv_batch`, `recv_batch_timed` and `send_ready`
  take `&mut self`, and their futures borrow it for their lifetime. `send_ready`
  has the same second-waiter defect as `recv_from`.
- `send_to`, `send_to_gso` and `index` take `&self`.
- `split(self) -> (UdpSendHalf, UdpRecvHalf)` for a send made while a read borrow
  is live. `UdpRecvHalf` has the four receive methods, taking `&mut self`, and
  `index`. `UdpSendHalf` has `send_ready`, taking `&mut self`, and `send_to`,
  `send_to_gso` and `index`, taking `&self`.
- Dropping a `UdpSocket` releases nothing. The socket lives until the worker
  exits, as it does today when `on_udp_bind` returns `None`.

One call site needs `split`: the fast path in
`ringline-benchmarks/src/protocols/udp.rs`, which sends from inside the
`with_datagram` closure, the zero-allocation path. The QUIC and HTTP/3 loops pass
each datagram to `quinn-proto` and send after the receive future has finished, so
the borrows do not overlap there.

## Owner decisions

### Dropping a connection closes it

Approved 2026-11-04.

`Drop` for `SendHalf` and `RecvHalf` only clears the claim flag, so dropping an
outbound `Connection`, or a client built on one, leaves the socket open and the
slot occupied. An accepted connection is closed when its task ends. An outbound
one is not. Removing `ConnCtx` and `DriverCtx` removes the only ways to close a
dropped outbound connection. One downstream load generator keeps a `ConnCtx` in a
guard to close the connection on every exit from its reconnect loop.

This was not forced: that crate could wrap the client in a type whose `Drop` calls
`Client::close`, but a connection dropped with no `close` would keep leaking its
slot.

Dropping the last half closes the connection, with the same graceful close as
`Connection::close`. Inbound connections keep their second trigger: `on_accept`'s
task ending closes the connection even if a half has moved to a spawned task.

- Dropping a half clears its claim flag. If the other half's flag is also clear,
  the connection closes. `recv_half_taken` and `send_half_taken` stay for this
  purpose.
- A half can be dropped with `CURRENT_DRIVER` unset: at connection teardown, and
  in the synchronous body of `on_accept` or `on_adopt`, which run outside a task
  poll. The drop then queues `Orphan::ConnHalf { index, generation, half }`
  through `defer_release`, as `ConnectFuture` does with `Orphan::Connect`. The
  drain clears that half's flag and closes if the other flag is also clear,
  through the function the driver-set path uses. Without the half in the entry,
  an unset drop would leave a stale flag, and the slot would leak or close while
  the other half was in use. The generation check makes a queued entry for a
  recycled slot do nothing.
- During unwinding (`std::thread::panicking()`) the io_uring drop uses
  `close_connection`, so a panicked handler sends no close_notify, as it does
  today. Step 6 reverses the order in the connection panic arm of
  `poll_ready_tasks` on io_uring, which today calls `drop(fut)` and then
  `close_connection`. It calls `close_connection` first, because a half owned by
  a top-level `Select` is dropped after `catch_unwind` returns, when `panicking()`
  is false. Spawned tasks and outbound connections do not get this: the standalone
  arm has no connection index, `spawn_with_handle` catches the panic inside the
  task, and the connection arm closes only the task's own index. A last half of
  either kind owned by a top-level `Select` therefore closes gracefully, and the
  peer receives close_notify. Mio has one close path, and `finish_close`
  attempts the alert there, as it does today.
- Park sets `socket_handed_off`, closes, and only then drops the task, so the drop
  finds the connection closing, or the generation changed, and does nothing. Mio
  has no park.

A connection task that drops its `Connection` and keeps running ends when the
Close completes, because `remove_connection` drops the task. Today it runs on.

A handler that names its parameter `_conn` and returns a future with a real body
drops the `Connection` when `on_accept` returns, because `async move` does not
capture an unused parameter. Today that connection lives until the task ends.
After the change it closes before the task's first poll. A scan of the tree found
seven handlers that depend on the old behaviour and need `let _conn = conn;`
inside the block: five in `tests/teardown_drops.rs`, `Sleeps` in
`tests/peer_fin.rs` and `ExitingWorker` in `tests/accept_queue_shutdown.rs`.
`peer_fin.rs` would otherwise keep passing without testing FIN detection. The scan
was static, so a run of the full suite on both backends has to confirm the count.

### `close_notify_timeout_ms` is removed

Approved 2026-11-04.

`DriverCtx::close` arms a deadline for a TLS close. `close_connection_graceful`,
behind `Connection::close` and a handler return, arms none, and its drain is
unbounded. With `DriverCtx` private, the public knob applies only to the two
fatal encrypt closes in `handler.rs`, and it is already inert on mio.

Remove `ConfigBuilder::close_notify_timeout_ms` and keep a fixed 5 s bound on
those internal closes. `Connection::close` stays unbounded,
as it is for plaintext. Bounding a close against a peer that stops reading is a
separate change that would apply to TLS and plaintext alike.
`a_slow_reader_gets_the_whole_reply_before_close_notify` stays as a delivery test.
`graceful_close_arms_no_close_notify_deadline` checks that no deadline is armed,
because a 3.5 s drain cannot fail against a 5 s bound.

The rejected alternative was to arm the deadline in `close_connection_graceful`, which keeps
the knob meaningful on io_uring, makes TLS and plaintext closes differ, and cuts
off a TLS peer whose reply takes longer than the timeout to drain.
`a_slow_reader_gets_the_whole_reply_before_close_notify` asserts the opposite and
would be inverted.

## Series

Each step is one PR, and all are breaking.

1. `ConnCtx` becomes `pub(crate)`, `as_conn` and `cancel` go, `ConnStream` owns its
   `Connection`, `ForwardFuture` replaces the two forward futures, and method
   docs move to the public types.
2. Read futures borrow their half, and `RecvReadyFuture` becomes `!Send`.
3. `DriverCtx` becomes `pub(crate)`, the callbacks lose `ctx`,
   `close_direct_io_file` and `close_nvme_device` gain free forms, `UdpToken` goes, and
   `ConfigBuilder::close_notify_timeout_ms` is removed.
4. `ConnToken` becomes `ConnId`.
5. `UdpCtx` becomes `UdpSocket`.
6. Dropping the last half closes the connection.

`README.md`, `ringline/README.md`, the client READMEs, `docs/architecture.md`,
`docs/tls-unbuffered-design.md` and `CLAUDE.md` describe these types. Each step corrects what it removes, and step 1
adds a dated note to `connection-handle-ownership-design.md` pointing here.

No step adds work per send or receive. Step 3 removes one `make_ctx` per loop
iteration on io_uring and two on mio. Step 6 adds a flag check to each half drop, and two `Orphan`
pushes to each teardown that drops a parked task, on both backends. These are per connection, so
step 6 is measured with a connection-churn run.
