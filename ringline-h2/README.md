# ringline-h2

**Sans-IO HTTP/2 client framing layer.**

A pure sans-IO HTTP/2 client framing layer with zero runtime dependencies.
The caller feeds bytes in via `recv()` and pulls bytes out via
`take_pending_send()`.

## Architecture

```text
  TCP + TLS bytes
       |
  +----v----------+
  | ringline-h2   |  HTTP/2 framing + HPACK
  | H2Connection  |  H2Event: Response, Data, Trailers, etc.
  +---------------+
```

## Quick Start

```rust,ignore
use ringline_h2::{H2Connection, H2Event, HeaderField, Settings};

let mut h2 = H2Connection::new(Settings::client_default());

// Send the connection preface to the transport.
let preface = h2.take_pending_send();
transport_send(&preface);

// Send a GET request.
let stream_id = h2.send_request(&[
    HeaderField::new(b":method", b"GET"),
    HeaderField::new(b":path", b"/"),
    HeaderField::new(b":scheme", b"https"),
    HeaderField::new(b":authority", b"example.com"),
], true)?;
transport_send(&h2.take_pending_send());

// Feed received bytes and drain events.
h2.recv(&received_data)?;
while let Some(event) = h2.poll_event() {
    match event {
        H2Event::Response { stream_id, headers, end_stream } => { /* ... */ }
        H2Event::Data { stream_id, data, end_stream } => { /* ... */ }
        _ => {}
    }
}
```

## Features

- HTTP/2 frame encoding/decoding (DATA, HEADERS, SETTINGS, WINDOW_UPDATE, PING, GOAWAY, RST_STREAM)
- HPACK header compression with dynamic table
- Stream multiplexing with per-stream and connection-level flow control
- Zero runtime dependencies -- pure `recv()` / `take_pending_send()` interface
