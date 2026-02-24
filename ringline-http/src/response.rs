use bytes::Bytes;

use crate::error::HttpError;

/// HTTP response.
#[derive(Debug)]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
}

impl Response {
    pub(crate) fn new(status: u16, headers: Vec<(String, String)>, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// HTTP status code (e.g. 200, 404).
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Response headers as (name, value) pairs.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Get the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Consume the response and return the body bytes.
    pub fn bytes(self) -> Bytes {
        self.body
    }

    /// Consume the response and return the body as UTF-8 text.
    pub fn text(self) -> Result<String, HttpError> {
        String::from_utf8(self.body.to_vec()).map_err(|_| HttpError::Parse)
    }

    /// Reference to the body bytes without consuming.
    pub fn body(&self) -> &Bytes {
        &self.body
    }
}
