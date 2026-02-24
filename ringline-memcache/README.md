# ringline-memcache

**ringline-native Memcache client.**

A Memcache ASCII protocol client built on [`ringline::ConnCtx`](https://docs.rs/ringline)
for use inside the ringline async runtime. Single-threaded, single-connection,
zero-copy recv.

## Quick Start

```rust
use ringline::ConnCtx;
use ringline_memcache::Client;

async fn example(conn: ConnCtx) -> Result<(), ringline_memcache::Error> {
    let mut client = Client::new(conn);
    client.set("hello", "world").await?;
    let val = client.get("hello").await?;
    assert_eq!(val.unwrap().data.as_ref(), b"world");
    Ok(())
}
```

## Features

- **Storage commands**: `get`, `gets`, `set`, `add`, `replace`, `cas`, `append`, `prepend`
- **Arithmetic**: `incr`, `decr`
- **Other**: `delete`, `flush_all`, `version`
- **Zero-copy SET**: `set_with_guard` pins value memory via `SendGuard`
- **Connection pooling**: round-robin pool with lazy reconnection
- **Sharded client**: ketama-consistent hashing across multiple Memcache instances
- **Instrumentation**: optional per-command callbacks and built-in histogram metrics

## Copy Semantics

| Path | Copies | Mechanism |
|------|--------|-----------|
| **Recv (values)** | **0** | `with_bytes()` + `ResponseBytes::parse()`. Keys and values are `Bytes::slice()` references into the accumulator -- zero allocation, O(1) refcount. |
| **Send (commands)** | 1 | Serialized into `Vec<u8>`, then copied into the send pool. |
| **Send (SET value, guard)** | 0 (value) | `set_with_guard`: prefix+suffix copied to pool, value stays in-place via `SendGuard`. |

TLS connections add encryption copies on the send path regardless of `SendGuard` usage.
