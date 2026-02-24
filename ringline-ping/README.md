# ringline-ping

**ringline-native Ping client.**

A simple PING/PONG protocol client built on [`ringline::ConnCtx`](https://docs.rs/ringline)
for use inside the ringline async runtime. Useful for connection health checks
and latency measurement.

## Quick Start

```rust
use ringline::ConnCtx;
use ringline_ping::Client;

async fn example(conn: ConnCtx) -> Result<(), ringline_ping::Error> {
    let mut client = Client::new(conn);
    client.ping().await?;
    Ok(())
}
```

## Features

- **Single command**: `ping` sends `PING\r\n` and waits for `PONG\r\n`
- **Connection pooling**: round-robin pool with lazy reconnection
- **Instrumentation**: optional per-command callbacks and built-in histogram metrics

## Copy Semantics

| Path | Copies | Mechanism |
|------|--------|-----------|
| **Recv** | **0** | `with_data()` pattern-matches `PONG\r\n` -- no value extraction. |
| **Send** | 1 | 6-byte `PING\r\n` copied into the send pool. |
