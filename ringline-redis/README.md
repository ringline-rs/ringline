# ringline-redis

**ringline-native Redis client.**

A RESP protocol client built on [`ringline::ConnCtx`](https://docs.rs/ringline) for
use inside the ringline async runtime. Single-threaded, single-connection,
zero-copy recv.

## Quick Start

```rust
use ringline::ConnCtx;
use ringline_redis::Client;

async fn example(conn: ConnCtx) -> Result<(), ringline_redis::Error> {
    let mut client = Client::new(conn);
    client.set("hello", "world").await?;
    let val = client.get("hello").await?;
    assert_eq!(val.as_deref(), Some(&b"world"[..]));
    Ok(())
}
```

## Features

- **Single-key commands**: `get`, `set`, `set_ex`, `del`, `incr`, `decr`, `expire`, `ttl`, etc.
- **Multi-key**: `mget`, `mset`
- **Pipelining**: batch multiple commands into a single write
- **Zero-copy SET**: `set_with_guard` / `set_ex_with_guard` pin value memory via `SendGuard`
- **Connection pooling**: round-robin pool with lazy reconnection
- **Sharded client**: ketama-consistent hashing across multiple Redis instances
- **Cluster client**: `MOVED`/`ASK` redirect handling with slot-map caching
- **Instrumentation**: optional per-command callbacks and built-in histogram metrics

## Copy Semantics

| Path | Copies | Mechanism |
|------|--------|-----------|
| **Recv (values)** | **0** | `with_bytes()` + `Value::parse_bytes()`. Bulk strings are `Bytes::slice()` references into the accumulator -- zero allocation, O(1) refcount. |
| **Send (commands)** | 1 | RESP serialized into `Vec<u8>`, then copied into the send pool. |
| **Send (SET value, standard)** | 1 | All parts gathered into one send-pool slot via `send_parts().copy()`. |
| **Send (SET value, guard)** | 0 (value) | `set_with_guard` / `set_ex_with_guard`: RESP prefix+suffix copied to pool, value stays in-place via `SendGuard`. |
| **Pipeline** | 1 | All commands accumulated into one `Vec<u8>`, single copy to pool. |

TLS connections add encryption copies on the send path regardless of `SendGuard` usage.
