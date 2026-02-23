//! Sans-IO HTTP/2 client framing layer.
//!
//! This crate provides a pure sans-IO HTTP/2 client framing layer. It has
//! zero runtime dependencies -- the caller feeds bytes in via `recv()` and
//! pulls bytes out via `take_pending_send()`.
//!
//! # Architecture
//!
//! ```text
//!   TCP + TLS bytes
//!        |
//!   +----v----------+
//!   | ringline-h2   |  HTTP/2 framing + HPACK
//!   | H2Connection  |  H2Event: Response, Data, Trailers, etc.
//!   +---------------+
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use ringline_h2::{H2Connection, H2Event, HeaderField, Settings};
//!
//! let mut h2 = H2Connection::new(Settings::client_default());
//!
//! // Send the connection preface to the transport.
//! let preface = h2.take_pending_send();
//! transport_send(&preface);
//!
//! // Send a GET request.
//! let stream_id = h2.send_request(&[
//!     HeaderField::new(b":method", b"GET"),
//!     HeaderField::new(b":path", b"/"),
//!     HeaderField::new(b":scheme", b"https"),
//!     HeaderField::new(b":authority", b"example.com"),
//! ], true)?;
//! transport_send(&h2.take_pending_send());
//!
//! // Feed received bytes.
//! h2.recv(&received_data)?;
//!
//! // Drain events.
//! while let Some(event) = h2.poll_event() {
//!     match event {
//!         H2Event::Response { stream_id, headers, end_stream } => { /* ... */ }
//!         H2Event::Data { stream_id, data, end_stream } => { /* ... */ }
//!         _ => {}
//!     }
//! }
//! ```

pub mod connection;
pub mod error;
pub mod flowcontrol;
pub mod frame;
pub mod hpack;
mod huffman;
pub mod settings;
mod stream;

pub use connection::{H2Connection, H2Event};
pub use error::{ErrorCode, H2Error};
pub use frame::Frame;
pub use hpack::HeaderField;
pub use settings::Settings;
