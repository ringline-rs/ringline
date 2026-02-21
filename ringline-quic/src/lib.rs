//! ringline-quic — QUIC protocol support via quinn-proto.
//!
//! This crate wraps [quinn-proto](https://docs.rs/quinn-proto)'s sans-IO QUIC
//! state machine and exposes an event-based [`QuicEndpoint`] API.
//!
//! # Example
//!
//! ```rust,ignore
//! use ringline_quic::{QuicConfig, QuicEndpoint, QuicEvent};
//!
//! // Feed incoming datagrams:
//! quic.handle_datagram(Instant::now(), data, peer);
//! while let Some(event) = quic.poll_event() {
//!     match event {
//!         QuicEvent::NewConnection(conn) => { /* ... */ }
//!         QuicEvent::StreamReadable { conn, stream } => {
//!             let mut buf = [0u8; 4096];
//!             let (n, fin) = quic.stream_recv(conn, stream, &mut buf)?;
//!             quic.stream_send(conn, stream, &buf[..n])?;
//!         }
//!         _ => {}
//!     }
//! }
//! // Drain outgoing packets:
//! while let Some((dest, data)) = quic.poll_send() {
//!     udp.send_to(dest, &data)?;
//! }
//! ```

pub mod config;
pub mod endpoint;
pub mod error;
pub mod event;

pub use config::QuicConfig;
pub use endpoint::QuicEndpoint;
pub use error::Error;
pub use event::{QuicConnId, QuicEvent};

// Re-export commonly used quinn-proto types for convenience.
pub use quinn_proto::{Dir, StreamId};
