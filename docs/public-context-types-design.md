# Removing the public context types

**Status:** proposal, 2026-11-04. Series for 0.7.0. Follows
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
| `token`, `peer_addr`, `listener`, `is_outbound`, `is_alive`, `tls_info`, `offer_for_park`, `is_recv_direct` | already on `Connection`; all but `is_recv_direct` on `SendHalf`; a subset on `RecvHalf` |
| `close` | `Connection::close`, `SendHalf::close` |
| `cancel` | `Connection::cancel` |
| `request_shutdown` | `ringline::request_shutdown` |
| `forward_to_conn` | `RecvHalf::forward_to_conn`, `Connection::forward_to_conn` |
| `split`, `take_send`, `take_recv` | removed; `Connection::split` is the only split |
| `index` | `ConnId::index` |
| `for_test`, `split_for_test` | `Connection::for_test` and `Connection::split` |

`as_conn` on `Connection` and `SendHalf` is removed. Its doc comment gives one
reason for it to exist, naming a forward sink, and the `&mut SendHalf` form of
`forward_to_conn` covers that.

### Other public signatures

- `ConnStream::new` takes a `Connection` and owns it. `conn_ctx()` is replaced by
  `connection(&self) -> &Connection`. Today a caller writes
  `ConnStream::new(conn.as_conn())` and keeps `conn`, which leaves two values
  that can read one connection.
- `mark_disconnected` on the redis, memcache and ping pools takes a `ConnId`.
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

### Tests

| test | change |
|---|---|
| `stream_echo.rs`, `throughput.rs`, `recv_direct.rs:590`, `echo_stream_server` | pass the `Connection` to `ConnStream::new` |
| `fs_fd_ownership.rs`, `disk_io_stale_results.rs`, `disk_io_teardown_buffers*.rs` | split, and move the `SendHalf` into the task that closes |
| `tls_echo.rs:2118` (`EPROTOTYPE` on a TLS sink) | go through `RecvHalf::forward_to_conn` |
| `echo.rs:7692`, `recv_direct.rs:781` (second forward on a source) | replaced by a `compile_fail` doctest on `ForwardFuture`; the driver's `EBUSY` stays and is tested in the event loop's unit tests |
| `echo.rs:7806` (`take_recv` while claimed) | removed; the event loop's unit tests cover `take_recv` |

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
| `close_direct_io_file`, `close_nvme_device` | new free functions of the same name; no free form exists today, so a task cannot close either handle |
| `direct_io_read`, `direct_io_write`, `direct_io_fsync`, `nvme_read`, `nvme_write`, `nvme_flush` | free functions, called from a spawned task |
| `send`, `send_parts`, `send_chain`, `close`, `shutdown_write`, `cancel`, `peer_addr`, `is_outbound`, `tls_info` | no token form; the task that holds the `Connection` or half calls the method, and other code reaches it through `mpsc` or a `CancellationToken` |
| `max_chain_length` | the value passed to `ConfigBuilder::max_chain_length` |
| `send_to` | removed, with `UdpToken`; no public API returns a `UdpToken`, so nothing outside the crate can call it |

A disk method on `DriverCtx` returns a `u32` key, and `DiskIoFuture::new` is
`pub(crate)`, so a caller has no way to get the result. The free functions return
a `DiskIoFuture`, which needs a task to poll it. `on_tick` does not run in a task.

### What a caller loses

Sending on a connection from `on_tick` by token has no direct replacement. The
owning task has to do the send, usually by receiving from an `mpsc::channel`.
This is the rule the ownership design already chose for fan-in, and a tick that
sends at an arbitrary point in a response stream has the ordering problem that
design describes.

A handler is `Send`, and `SendHalf` is not, so a handler cannot keep a half in a
field. A thread-local can hold one. The API does not support this pattern, and
the type system does not rule it out.

### Consumers checked

Four crates outside this repository depend on ringline: two load generators, a
cache server and a proxy. Each `on_tick` found calls only `request_shutdown`
through `ctx`. In this repository the uses are `request_shutdown`,
`open_direct_io_file` and `close_direct_io_file`, plus two tests that exist to
exercise a `DriverCtx` path:

- `tls_echo.rs` (`TlsTickCloseHandler`) closes by token. It goes away; the other
  close_notify tests cover `Connection::close` and a handler return.
- `disk_io_stale_results.rs` (`RawThenFuture`) submits a read whose key nothing
  holds. It moves to a unit test against `Driver`, since a dropped `DiskIoFuture`
  reaches the same state.

## `ConnToken` becomes `ConnId`

With `DriverCtx` gone, nothing accepts a token, so the name no longer describes
it. `ConnId` keeps `index()`, gains `Hash`, and is what `id()` returns on
`Connection`, `SendHalf`, `RecvHalf` and the protocol clients, replacing
`token()`. The `index()` methods on `Connection` and `SendHalf` are removed; the
examples that log them use `id().index()`.

`ConnId` is `Send`, and has no operations that reach a driver, so using one on
the wrong worker can only produce a wrong comparison.

## `UdpCtx` becomes `UdpSocket`

`UdpCtx` is `Copy`, `Send` and `Sync`, and has the problems `ConnCtx` had before
the ownership series. Its doc comment states that a second `recv_from` waiter
overwrites the first and that the first is then leaked, and the type does not
prevent it. It can also be moved to another worker, where `udp_index` resolves
against a different socket table.

`UdpSocket` is not `Copy` or `Clone`, and is `!Send`:

- `recv_from`, `with_datagram`, `recv_batch`, `recv_batch_timed` take `&mut self`.
- `send_to`, `send_to_gso`, `send_ready` take `&self`.
- `split(self) -> (UdpSendHalf, UdpRecvHalf)` for a send made while a read borrow
  is live.

One of the 38 receive call sites needs `split`: the fast path in
`ringline-benchmarks/src/protocols/udp.rs`, which sends from inside the
`with_datagram` closure. The QUIC and HTTP/3 loops receive into a buffer and
send after the receive future has finished, so `&mut self` and `&self` do not
overlap there.

## Dropping a connection closes it (owner decision)

Removing `ConnCtx` exposes a gap. `Drop` for `SendHalf` and `RecvHalf` only
clears the claim flag, so dropping an outbound `Connection`, or a client built on
one, leaves the socket open and the slot occupied. An accepted connection is
closed when its task ends. An outbound one is not. One downstream load generator
keeps a `ConnCtx` in a guard for this reason, to close the connection on every
exit from its reconnect loop.

Without a change, that crate can wrap the client in a type whose `Drop` calls
`Client::close`. The removal does not force a runtime change. A connection
dropped with no `close` still leaks its slot, as it does today, and after this
series no handle can reach it.

The proposal is that dropping the last half closes the connection, with the same
graceful close as `Connection::close`:

- Dropping a half clears its claim flag as it does now. If the other half's flag
  is also clear, the connection closes. `recv_half_taken` and `send_half_taken`
  stay for this purpose.
- A task can be dropped with `CURRENT_DRIVER` unset, during connection teardown.
  The drop then queues `(index, generation)` in a thread-local and the event loop
  drains it, the same arrangement as `abandon_disk_io_key` and `release_orphans`.
  The generation check makes a queued close for a recycled slot do nothing.
- Park calls `close_connection` with `socket_handed_off` set before the task is
  dropped, so the drop finds the connection closing and does nothing.

This changes behaviour for one pattern. A handler that names its parameter
`_conn` and returns a future with a real body drops the `Connection` when
`on_accept` returns, because `async move` does not capture an unused parameter.
Today that connection lives until the task ends. After the change it closes
before the task's first poll. Five handlers in `tests/teardown_drops.rs` have
this shape and need `let _conn = conn;` inside the block. The other `_conn`
handlers return `async {}`, whose connections already close at once.

## Series

Each step is one PR, and all are breaking.

1. `ConnCtx` becomes `pub(crate)`, `as_conn` goes, `ConnStream` owns its
   `Connection`, and `ForwardFuture` replaces the two forward futures.
2. `DriverCtx` becomes `pub(crate)`, the callbacks lose `ctx`,
   `close_direct_io_file` and `close_nvme_device` gain free forms, and `UdpToken`
   goes.
3. `ConnToken` becomes `ConnId`.
4. `UdpCtx` becomes `UdpSocket`.
5. If approved, dropping the last half closes the connection.

`ringline/README.md`, the root `README.md`, the client READMEs, `docs/architecture.md`
and `CLAUDE.md` still teach `ConnCtx`. The first PR corrects them, and
`connection-handle-ownership-design.md` gets a dated note pointing here.

No step changes the hot path. Step 1 removes a branch from `direct_forward`, and
step 2 removes one `make_ctx` per loop iteration. Neither is large enough to
justify a measurement.
