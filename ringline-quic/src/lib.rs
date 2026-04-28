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
//! while let Some(pkt) = quic.poll_send() {
//!     match pkt.segment_size {
//!         Some(seg) => udp.send_to_gso(pkt.destination, &pkt.data, seg)?,
//!         None => udp.send_to(pkt.destination, &pkt.data)?,
//!     }
//! }
//! ```

pub mod config;
pub mod endpoint;
pub mod error;
pub mod event;

pub use config::QuicConfig;
pub use endpoint::{Datagrams, OutgoingPacket, QuicEndpoint};
pub use error::Error;
pub use event::{QuicConnId, QuicEvent};

// Re-export commonly used quinn-proto types for convenience.
pub use quinn_proto::{Dir, StreamId, WriteError};
