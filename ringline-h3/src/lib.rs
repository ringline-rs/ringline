//! HTTP/3 framing layer for ringline-quic.
//!
//! This crate provides a sans-IO, completion-based HTTP/3 framing layer that
//! sits on top of [`ringline_quic::QuicEndpoint`]. It handles:
//!
//! - HTTP/3 frame encoding/decoding (DATA, HEADERS, SETTINGS, GOAWAY)
//! - QPACK header compression (static table only for Phase 1)
//! - Control stream management (SETTINGS exchange)
//! - Mapping QUIC stream events to HTTP request/response events
//!
//! # Architecture
//!
//! ```text
//!   UDP datagrams
//!        │
//!   ┌────▼────────┐
//!   │ringline-quic│  QUIC transport (quinn-proto wrapper)
//!   │QuicEndpoint  │  QuicEvent: StreamReadable, StreamOpened, etc.
//!   └────┬────────┘
//!        │ stream_recv() / stream_send()
//!   ┌────▼────────┐
//!   │ ringline-h3 │  HTTP/3 framing + QPACK
//!   │ H3Connection│  H3Event: Request, Data, etc.
//!   └─────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use ringline_h3::{H3Connection, H3Event, HeaderField, Settings};
//!
//! let mut h3 = H3Connection::new(Settings::default());
//!
//! // After quic.poll_event():
//! h3.handle_quic_event(&mut quic, &event)?;
//!
//! while let Some(h3_event) = h3.poll_event() {
//!     match h3_event {
//!         H3Event::Request { stream_id, headers, end_stream } => {
//!             let response = vec![HeaderField::new(b":status", b"200")];
//!             h3.send_response(&mut quic, stream_id, &response, false)?;
//!             h3.send_data(&mut quic, stream_id, b"hello", true)?;
//!         }
//!         _ => {}
//!     }
//! }
//! ```

pub mod connection;
pub mod error;
pub mod frame;
mod huffman;
pub mod qpack;
pub mod settings;
mod stream;

pub use connection::{H3Connection, H3Event};
pub use error::H3Error;
pub use frame::Frame;
pub use qpack::HeaderField;
pub use settings::Settings;
