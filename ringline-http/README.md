# ringline-http

Async HTTP/1.1 and HTTP/2 client for the ringline io_uring runtime.

## Features

- **HTTP/2** over TLS with multiplexed streams (fire/recv API)
- **HTTP/1.1** over TLS or plaintext with Content-Length and chunked transfer encoding
- **Reqwest-style** builder API (`client.get("/path").header(...).send().await`)
- **Connection pool** with round-robin dispatch and lazy reconnection

## Usage

```rust,ignore
use ringline_http::HttpClient;

// HTTP/2
let mut client = HttpClient::connect_h2(addr, "example.com").await?;
let resp = client.get("/api/data").send().await?;

// HTTP/1.1
let mut client = HttpClient::connect_h1(addr, "example.com").await?;
let resp = client.get("/index.html").send().await?;
```
