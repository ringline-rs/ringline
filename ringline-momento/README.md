# ringline-momento

**ringline-native Momento cache client.**

A multiplexed Momento protosocket client (length-delimited protobuf over TLS)
built on [`ringline::ConnCtx`](https://docs.rs/ringline) for use inside the
ringline async runtime.

## Quick Start

```rust
use ringline_momento::{Client, Credential};

async fn example() -> Result<(), ringline_momento::Error> {
    let credential = Credential::from_env()?;
    let mut client = Client::connect(&credential).await?;

    // Sequential convenience API
    client.set("my-cache", b"key", b"value", 60_000).await?;
    let value = client.get("my-cache", b"key").await?;

    // Multiplexed fire/recv API
    let id1 = client.fire_get("my-cache", b"key1")?;
    let id2 = client.fire_get("my-cache", b"key2")?;
    let op1 = client.recv().await?;
    let op2 = client.recv().await?;

    Ok(())
}
```

## Features

- **Fully multiplexed**: multiple requests in-flight on a single connection, correlated by message ID
- **Sequential API**: `get`, `set` convenience methods that fire + recv internally
- **Fire/recv API**: `fire_get`, `fire_set` return a message ID; `recv` returns the next completed operation
- **Connection pooling**: round-robin pool with lazy reconnection
- **Instrumentation**: optional per-command callbacks and built-in histogram metrics

## Copy Semantics

| Path | Copies | Mechanism |
|------|--------|-----------|
| **Recv (values)** | **1** | `with_data()` + protobuf decode. `Bytes::copy_from_slice()` for each extracted field. |
| **Send (requests)** | **3-4** | Layered protobuf encoding: each `encode()` layer allocates a new `Vec<u8>` and copies the previous level. Then `send_nowait()` copies into the send pool. |

All Momento connections use TLS, which adds encryption copies on the send path.
