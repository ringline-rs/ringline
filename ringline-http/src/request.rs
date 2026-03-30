//! Request builder for ergonomic HTTP request construction.

use crate::body::Body;
use crate::client::HttpClient;
use crate::error::HttpError;
use crate::response::Response;
use crate::streaming::StreamingResponse;

/// Builder for an HTTP request.
pub struct RequestBuilder<'a> {
    client: &'a mut HttpClient,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Body,
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(client: &'a mut HttpClient, method: &str, path: &str) -> Self {
        Self {
            client,
            method: method.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            body: Body::Empty,
        }
    }

    /// Add a header to the request.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Set the request body.
    pub fn body(mut self, body: impl Into<Body>) -> Self {
        self.body = body.into();
        self
    }

    /// Send the request and return the response.
    pub async fn send(mut self) -> Result<Response, HttpError> {
        self.inject_accept_encoding();

        let extra: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let body_bytes = match &self.body {
            Body::Empty => None,
            Body::Bytes(b) => Some(b.as_ref()),
        };

        self.client
            .send_request(&self.method, &self.path, &extra, body_bytes)
            .await
    }

    /// Send the request and return a streaming response.
    ///
    /// Returns as soon as headers are received. Body chunks are yielded
    /// incrementally via [`StreamingResponse::next_chunk()`].
    ///
    /// **Note:** streaming responses do not automatically decompress the body.
    /// If the server sends a compressed response, chunks will contain raw
    /// compressed bytes. Buffer and decompress manually if needed.
    pub async fn send_streaming(mut self) -> Result<StreamingResponse<'a>, HttpError> {
        self.inject_accept_encoding();

        let extra: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let body_bytes = match &self.body {
            Body::Empty => None,
            Body::Bytes(b) => Some(b.as_ref()),
        };

        self.client
            .send_request_streaming(&self.method, &self.path, &extra, body_bytes)
            .await
    }

    /// Inject `Accept-Encoding` header if compression features are enabled
    /// and the caller has not already set one.
    fn inject_accept_encoding(&mut self) {
        let has_ae = self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"));
        if !has_ae && let Some(ae) = crate::compress::accept_encoding_value() {
            self.headers
                .push(("accept-encoding".to_string(), ae.to_string()));
        }
    }
}
