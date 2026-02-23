//! Momento credential handling.
//!
//! Momento API tokens contain encoded endpoint information.

use crate::error::{Error, Result};

/// Default protosocket port.
const DEFAULT_PORT: u16 = 9004;

/// Momento credential containing API token, endpoint, and TLS configuration.
#[derive(Debug, Clone)]
pub struct Credential {
    /// The API token for authentication.
    token: String,
    /// The cache endpoint (host:port or just host).
    endpoint: String,
    /// Optional SNI hostname for TLS (used when connecting to IP addresses).
    sni_host: Option<String>,
}

impl Credential {
    /// Create a credential from an API token.
    ///
    /// The token is expected to be a Momento API key. The endpoint
    /// can be extracted from the token or provided separately.
    pub fn from_token(token: impl Into<String>) -> Result<Self> {
        let token = token.into();

        // Try to extract endpoint from token
        let endpoint = Self::extract_endpoint(&token)
            .unwrap_or_else(|| "cache.cell-4-us-east-1-1.prod.a.momentohq.com".to_string());

        Ok(Self {
            token,
            endpoint,
            sni_host: None,
        })
    }

    /// Create a credential with explicit endpoint.
    pub fn with_endpoint(token: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            endpoint: endpoint.into(),
            sni_host: None,
        }
    }

    /// Create a credential from environment variables.
    ///
    /// Uses:
    /// - `MOMENTO_API_KEY` or `MOMENTO_AUTH_TOKEN` for the token
    /// - `MOMENTO_ENDPOINT` for explicit endpoint (e.g., "cache.us-west-2.momentohq.com" or IP:port)
    /// - `MOMENTO_REGION` for region-based endpoint (e.g., "us-west-2")
    /// - `MOMENTO_SNI_HOST` for TLS hostname when connecting to IP addresses
    pub fn from_env() -> Result<Self> {
        let token = std::env::var("MOMENTO_API_KEY")
            .or_else(|_| std::env::var("MOMENTO_AUTH_TOKEN"))
            .map_err(|_| Error::Config("MOMENTO_API_KEY environment variable not set".into()))?;

        // Check for SNI hostname (used when connecting to IP addresses)
        let sni_host = std::env::var("MOMENTO_SNI_HOST").ok();

        // Check for explicit endpoint
        if let Ok(endpoint) = std::env::var("MOMENTO_ENDPOINT") {
            // Add "cache." prefix if not already present
            let endpoint = if endpoint.starts_with("cache.") {
                endpoint
            } else {
                format!("cache.{}", endpoint)
            };
            return Ok(Self {
                token,
                endpoint,
                sni_host,
            });
        }

        // Check for region-based endpoint
        if let Ok(region) = std::env::var("MOMENTO_REGION") {
            let endpoint = format!("cache.cell-4-{}-1.prod.a.momentohq.com", region);
            return Ok(Self {
                token,
                endpoint,
                sni_host,
            });
        }

        // Try to extract from token (legacy tokens)
        let mut cred = Self::from_token(token)?;
        cred.sni_host = sni_host;
        Ok(cred)
    }

    /// Set the SNI hostname for TLS connections.
    pub fn with_sni_host(mut self, host: impl Into<String>) -> Self {
        self.sni_host = Some(host.into());
        self
    }

    /// Get the API token.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Get the cache endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Get the host portion of the endpoint.
    pub fn host(&self) -> &str {
        self.endpoint.split(':').next().unwrap_or(&self.endpoint)
    }

    /// Get the TLS hostname for SNI.
    ///
    /// Returns the explicit SNI host if set, otherwise returns the endpoint host.
    pub fn tls_host(&self) -> &str {
        self.sni_host.as_deref().unwrap_or_else(|| self.host())
    }

    /// Get the port (defaults to 9004 for protosocket).
    pub fn port(&self) -> u16 {
        if let Some(port_str) = self.endpoint.split(':').nth(1)
            && let Ok(port) = port_str.parse()
        {
            return port;
        }
        DEFAULT_PORT
    }

    /// Extract endpoint from a Momento token.
    fn extract_endpoint(token: &str) -> Option<String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        let payload = parts[1];
        let decoded = Self::base64url_decode(payload)?;
        let json = String::from_utf8(decoded).ok()?;

        let base_endpoint = Self::extract_json_field(&json, "c")
            .or_else(|| Self::extract_json_field(&json, "endpoint"))
            .or_else(|| Self::extract_json_field(&json, "cp"))?;

        if base_endpoint.starts_with("cache.") {
            Some(base_endpoint)
        } else {
            Some(format!("cache.{}", base_endpoint))
        }
    }

    /// Debug: dump the JWT payload for inspection.
    pub fn debug_jwt_payload(token: &str) -> Option<String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return None;
        }
        let payload = parts[1];
        let decoded = Self::base64url_decode(payload)?;
        String::from_utf8(decoded).ok()
    }

    /// Decode base64url (URL-safe base64 without padding).
    fn base64url_decode(input: &str) -> Option<Vec<u8>> {
        let mut s = input.replace('-', "+").replace('_', "/");
        match s.len() % 4 {
            2 => s.push_str("=="),
            3 => s.push('='),
            _ => {}
        }
        Self::base64_decode(&s)
    }

    /// Simple base64 decoder.
    fn base64_decode(input: &str) -> Option<Vec<u8>> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut output = Vec::with_capacity(input.len() * 3 / 4);
        let mut buffer = 0u32;
        let mut bits = 0;

        for c in input.bytes() {
            if c == b'=' {
                break;
            }

            let value = ALPHABET.iter().position(|&x| x == c)? as u32;
            buffer = (buffer << 6) | value;
            bits += 6;

            if bits >= 8 {
                bits -= 8;
                output.push((buffer >> bits) as u8);
                buffer &= (1 << bits) - 1;
            }
        }

        Some(output)
    }

    /// Extract a string field from JSON (minimal parsing).
    fn extract_json_field(json: &str, field: &str) -> Option<String> {
        let pattern = format!("\"{}\"", field);
        let start = json.find(&pattern)?;
        let rest = &json[start + pattern.len()..];

        let rest = rest.trim_start();
        let rest = rest.strip_prefix(':')?;
        let rest = rest.trim_start();

        let rest = rest.strip_prefix('"')?;
        let end = rest.find('"')?;

        Some(rest[..end].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_credential_with_endpoint() {
        let cred = Credential::with_endpoint("my-token", "cache.example.com:9004");
        assert_eq!(cred.token(), "my-token");
        assert_eq!(cred.endpoint(), "cache.example.com:9004");
        assert_eq!(cred.host(), "cache.example.com");
        assert_eq!(cred.port(), 9004);
    }

    #[test]
    fn test_credential_default_port() {
        let cred = Credential::with_endpoint("token", "cache.example.com");
        assert_eq!(cred.port(), 9004);
    }

    #[test]
    fn test_credential_custom_port() {
        let cred = Credential::with_endpoint("token", "cache.example.com:8080");
        assert_eq!(cred.port(), 8080);
        assert_eq!(cred.host(), "cache.example.com");
    }

    #[test]
    fn test_credential_invalid_port() {
        let cred = Credential::with_endpoint("token", "cache.example.com:notaport");
        assert_eq!(cred.port(), 9004);
    }

    #[test]
    fn test_credential_tls_host_default() {
        let cred = Credential::with_endpoint("token", "cache.example.com");
        assert_eq!(cred.tls_host(), "cache.example.com");
    }

    #[test]
    fn test_credential_tls_host_explicit() {
        let cred =
            Credential::with_endpoint("token", "1.2.3.4:9004").with_sni_host("cache.example.com");
        assert_eq!(cred.tls_host(), "cache.example.com");
        assert_eq!(cred.host(), "1.2.3.4");
    }

    #[test]
    fn test_credential_from_token_simple() {
        let cred = Credential::from_token("simple-api-key").unwrap();
        assert_eq!(cred.token(), "simple-api-key");
        assert!(cred.endpoint().contains("momentohq.com"));
    }

    #[test]
    fn test_credential_from_token_with_jwt() {
        let payload = r#"{"c":"cell-test.example.com"}"#;
        let encoded_payload = base64url_encode(payload.as_bytes());
        let token = format!("header.{}.signature", encoded_payload);

        let cred = Credential::from_token(&token).unwrap();
        assert_eq!(cred.endpoint(), "cache.cell-test.example.com");
    }

    #[test]
    fn test_credential_from_token_with_cache_prefix() {
        let payload = r#"{"c":"cache.already-prefixed.example.com"}"#;
        let encoded_payload = base64url_encode(payload.as_bytes());
        let token = format!("header.{}.signature", encoded_payload);

        let cred = Credential::from_token(&token).unwrap();
        assert_eq!(cred.endpoint(), "cache.already-prefixed.example.com");
    }

    #[test]
    fn test_credential_from_token_with_endpoint_field() {
        let payload = r#"{"endpoint":"cell-endpoint.example.com"}"#;
        let encoded_payload = base64url_encode(payload.as_bytes());
        let token = format!("header.{}.signature", encoded_payload);

        let cred = Credential::from_token(&token).unwrap();
        assert_eq!(cred.endpoint(), "cache.cell-endpoint.example.com");
    }

    #[test]
    fn test_credential_clone() {
        let cred = Credential::with_endpoint("token", "endpoint.com");
        let cloned = cred.clone();
        assert_eq!(cloned.token(), cred.token());
        assert_eq!(cloned.endpoint(), cred.endpoint());
    }

    // Base64 decode tests

    #[test]
    fn test_base64_decode() {
        let decoded = Credential::base64_decode("aGVsbG8=").unwrap();
        assert_eq!(&decoded, b"hello");
    }

    #[test]
    fn test_base64_decode_no_padding() {
        let decoded = Credential::base64_decode("aGk").unwrap();
        assert_eq!(&decoded, b"hi");
    }

    #[test]
    fn test_base64_decode_empty() {
        let decoded = Credential::base64_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_base64_decode_invalid_char() {
        let result = Credential::base64_decode("!!!!");
        assert!(result.is_none());
    }

    #[test]
    fn test_base64_decode_longer_string() {
        let decoded = Credential::base64_decode("SGVsbG8sIFdvcmxkIQ==").unwrap();
        assert_eq!(&decoded, b"Hello, World!");
    }

    // Base64url decode tests

    #[test]
    fn test_base64url_decode_with_url_chars() {
        let input = "dGVzdC1kYXRh";
        let decoded = Credential::base64url_decode(input);
        assert!(decoded.is_some());
    }

    #[test]
    fn test_base64url_decode_padding_2() {
        let decoded = Credential::base64url_decode("YQ").unwrap();
        assert_eq!(&decoded, b"a");
    }

    #[test]
    fn test_base64url_decode_padding_1() {
        let decoded = Credential::base64url_decode("YWI").unwrap();
        assert_eq!(&decoded, b"ab");
    }

    #[test]
    fn test_base64url_decode_no_padding_needed() {
        let decoded = Credential::base64url_decode("YWJj").unwrap();
        assert_eq!(&decoded, b"abc");
    }

    // JSON field extraction tests

    #[test]
    fn test_extract_json_field() {
        let json = r#"{"c":"cache.example.com","other":"value"}"#;
        let endpoint = Credential::extract_json_field(json, "c");
        assert_eq!(endpoint, Some("cache.example.com".to_string()));
    }

    #[test]
    fn test_extract_json_field_with_spaces() {
        let json = r#"{ "c" : "cache.example.com" }"#;
        let endpoint = Credential::extract_json_field(json, "c");
        assert_eq!(endpoint, Some("cache.example.com".to_string()));
    }

    #[test]
    fn test_extract_json_field_not_found() {
        let json = r#"{"other":"value"}"#;
        let result = Credential::extract_json_field(json, "c");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_json_field_empty_value() {
        let json = r#"{"c":""}"#;
        let result = Credential::extract_json_field(json, "c");
        assert_eq!(result, Some(String::new()));
    }

    // Extract endpoint tests

    #[test]
    fn test_extract_endpoint_invalid_jwt() {
        let result = Credential::extract_endpoint("not-a-jwt");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_endpoint_invalid_base64() {
        let result = Credential::extract_endpoint("header.!!!!.signature");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_endpoint_invalid_json() {
        let payload = base64url_encode(b"not json");
        let token = format!("header.{}.signature", payload);
        let result = Credential::extract_endpoint(&token);
        assert!(result.is_none());
    }

    // Debug JWT payload tests

    #[test]
    fn test_debug_jwt_payload() {
        let payload = r#"{"test":"value"}"#;
        let encoded = base64url_encode(payload.as_bytes());
        let token = format!("header.{}.signature", encoded);

        let result = Credential::debug_jwt_payload(&token);
        assert_eq!(result, Some(payload.to_string()));
    }

    #[test]
    fn test_debug_jwt_payload_invalid_token() {
        let result = Credential::debug_jwt_payload("no-dots-here");
        assert!(result.is_none());
    }

    #[test]
    fn test_debug_jwt_payload_invalid_base64() {
        let result = Credential::debug_jwt_payload("header.!!!invalid!!!.sig");
        assert!(result.is_none());
    }

    // Helper function for tests
    fn base64url_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut result = String::new();
        let mut bits = 0u32;
        let mut num_bits = 0;

        for &byte in data {
            bits = (bits << 8) | byte as u32;
            num_bits += 8;

            while num_bits >= 6 {
                num_bits -= 6;
                let index = ((bits >> num_bits) & 0x3F) as usize;
                result.push(ALPHABET[index] as char);
            }
        }

        if num_bits > 0 {
            bits <<= 6 - num_bits;
            let index = (bits & 0x3F) as usize;
            result.push(ALPHABET[index] as char);
        }

        // Convert to base64url
        result.replace('+', "-").replace('/', "_")
    }

    #[test]
    #[serial]
    fn test_from_env_with_explicit_endpoint() {
        let orig_key = std::env::var("MOMENTO_API_KEY").ok();
        let orig_endpoint = std::env::var("MOMENTO_ENDPOINT").ok();
        let orig_region = std::env::var("MOMENTO_REGION").ok();

        // SAFETY: This test runs with --test-threads=1 to avoid data races
        unsafe {
            std::env::set_var("MOMENTO_API_KEY", "test-token");
            std::env::set_var("MOMENTO_ENDPOINT", "cell-test.example.com");
            std::env::remove_var("MOMENTO_REGION");
        }

        let cred = Credential::from_env().expect("from_env should succeed");
        assert_eq!(cred.token(), "test-token");
        assert_eq!(cred.host(), "cache.cell-test.example.com");

        // SAFETY: Restore original values
        unsafe {
            if let Some(val) = orig_key {
                std::env::set_var("MOMENTO_API_KEY", val);
            } else {
                std::env::remove_var("MOMENTO_API_KEY");
            }
            if let Some(val) = orig_endpoint {
                std::env::set_var("MOMENTO_ENDPOINT", val);
            } else {
                std::env::remove_var("MOMENTO_ENDPOINT");
            }
            if let Some(val) = orig_region {
                std::env::set_var("MOMENTO_REGION", val);
            }
        }
    }

    #[test]
    #[serial]
    fn test_from_env_with_cache_prefixed_endpoint() {
        let orig_key = std::env::var("MOMENTO_API_KEY").ok();
        let orig_endpoint = std::env::var("MOMENTO_ENDPOINT").ok();
        let orig_region = std::env::var("MOMENTO_REGION").ok();

        // SAFETY: This test runs with --test-threads=1 to avoid data races
        unsafe {
            std::env::set_var("MOMENTO_API_KEY", "test-token");
            std::env::set_var("MOMENTO_ENDPOINT", "cache.already-prefixed.example.com");
            std::env::remove_var("MOMENTO_REGION");
        }

        let cred = Credential::from_env().expect("from_env should succeed");
        assert_eq!(cred.token(), "test-token");
        assert_eq!(cred.host(), "cache.already-prefixed.example.com");

        // SAFETY: Restore original values
        unsafe {
            if let Some(val) = orig_key {
                std::env::set_var("MOMENTO_API_KEY", val);
            } else {
                std::env::remove_var("MOMENTO_API_KEY");
            }
            if let Some(val) = orig_endpoint {
                std::env::set_var("MOMENTO_ENDPOINT", val);
            } else {
                std::env::remove_var("MOMENTO_ENDPOINT");
            }
            if let Some(val) = orig_region {
                std::env::set_var("MOMENTO_REGION", val);
            }
        }
    }

    #[test]
    #[serial]
    fn test_from_env_with_region() {
        let orig_key = std::env::var("MOMENTO_API_KEY").ok();
        let orig_endpoint = std::env::var("MOMENTO_ENDPOINT").ok();
        let orig_region = std::env::var("MOMENTO_REGION").ok();

        // SAFETY: This test runs with --test-threads=1 to avoid data races
        unsafe {
            std::env::set_var("MOMENTO_API_KEY", "test-token");
            std::env::remove_var("MOMENTO_ENDPOINT");
            std::env::set_var("MOMENTO_REGION", "us-west-2");
        }

        let cred = Credential::from_env().expect("from_env should succeed");
        assert_eq!(cred.token(), "test-token");
        assert!(cred.host().contains("us-west-2"));

        // SAFETY: Restore original values
        unsafe {
            if let Some(val) = orig_key {
                std::env::set_var("MOMENTO_API_KEY", val);
            } else {
                std::env::remove_var("MOMENTO_API_KEY");
            }
            if let Some(val) = orig_endpoint {
                std::env::set_var("MOMENTO_ENDPOINT", val);
            } else {
                std::env::remove_var("MOMENTO_ENDPOINT");
            }
            if let Some(val) = orig_region {
                std::env::set_var("MOMENTO_REGION", val);
            } else {
                std::env::remove_var("MOMENTO_REGION");
            }
        }
    }

    #[test]
    #[serial]
    fn test_from_env_missing_token() {
        let orig_key = std::env::var("MOMENTO_API_KEY").ok();
        let orig_auth = std::env::var("MOMENTO_AUTH_TOKEN").ok();

        // SAFETY: This test runs with --test-threads=1 to avoid data races
        unsafe {
            std::env::remove_var("MOMENTO_API_KEY");
            std::env::remove_var("MOMENTO_AUTH_TOKEN");
        }

        let result = Credential::from_env();
        assert!(result.is_err());

        // SAFETY: Restore original values
        unsafe {
            if let Some(val) = orig_key {
                std::env::set_var("MOMENTO_API_KEY", val);
            }
            if let Some(val) = orig_auth {
                std::env::set_var("MOMENTO_AUTH_TOKEN", val);
            }
        }
    }
}
