//! Streaming response types for incremental body delivery.

use bytes::Bytes;

use crate::error::HttpError;
use crate::h1_conn::H1StreamingResponse;
use crate::h2_conn::H2StreamingResponse;

/// A streaming HTTP response that yields body chunks incrementally.
///
/// Wraps either an HTTP/2 or HTTP/1.1 streaming response. The connection
/// is borrowed exclusively while this type exists — no other requests can
/// be sent until the body is fully consumed or the response is dropped.
///
/// # Example
///
/// ```rust,ignore
/// let mut stream = client.post("/v1/chat/completions")
///     .header("content-type", "application/json")
///     .body(payload)
///     .send_streaming()
///     .await?;
///
/// assert_eq!(stream.status(), 200);
/// while let Some(chunk) = stream.next_chunk().await? {
///     // process each body chunk as it arrives
/// }
/// ```
pub enum StreamingResponse<'a> {
    H2(H2StreamingResponse<'a>),
    H1(H1StreamingResponse<'a>),
}

impl StreamingResponse<'_> {
    /// HTTP status code.
    pub fn status(&self) -> u16 {
        match self {
            Self::H2(s) => s.status(),
            Self::H1(s) => s.status(),
        }
    }

    /// Response headers as (name, value) pairs.
    pub fn headers(&self) -> &[(String, String)] {
        match self {
            Self::H2(s) => s.headers(),
            Self::H1(s) => s.headers(),
        }
    }

    /// Get the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        match self {
            Self::H2(s) => s.header(name),
            Self::H1(s) => s.header(name),
        }
    }

    /// Yield the next body chunk, or `None` when the body is complete.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        match self {
            Self::H2(s) => s.next_chunk().await,
            Self::H1(s) => s.next_chunk().await,
        }
    }
}
