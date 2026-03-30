//! HTTP response decompression and request body compression.
//!
//! All functions are `pub(crate)`. Each codec is gated behind its own feature
//! flag (`gzip`, `zstd`, `brotli`). The umbrella `compression` feature enables
//! all three.
//!
//! Streaming decompression is not yet supported -- [`StreamingResponse`] chunks
//! are returned raw. Callers that need streaming decompression should buffer
//! and decompress manually.

use crate::error::HttpError;

/// Decompress a complete body based on the `Content-Encoding` header value.
#[allow(dead_code)]
pub(crate) fn decompress(encoding: &str, data: &[u8]) -> Result<Vec<u8>, HttpError> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        #[cfg(feature = "gzip")]
        "gzip" | "x-gzip" => decompress_gzip(data),
        #[cfg(feature = "zstd")]
        "zstd" => decompress_zstd(data),
        #[cfg(feature = "brotli")]
        "br" => decompress_brotli(data),
        "identity" => Ok(data.to_vec()),
        other => Err(HttpError::Decompress(format!(
            "unsupported encoding: {other}"
        ))),
    }
}

/// Compress data with the specified encoding.
#[allow(dead_code)]
pub(crate) fn compress(encoding: &str, _data: &[u8]) -> Result<Vec<u8>, HttpError> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        #[cfg(feature = "gzip")]
        "gzip" => compress_gzip(_data),
        #[cfg(feature = "zstd")]
        "zstd" => compress_zstd(_data),
        #[cfg(feature = "brotli")]
        "br" => compress_brotli(_data),
        other => Err(HttpError::Decompress(format!(
            "unsupported encoding: {other}"
        ))),
    }
}

/// Build an `Accept-Encoding` header value from enabled compression features.
///
/// Returns `None` when no compression features are enabled.
pub(crate) fn accept_encoding_value() -> Option<&'static str> {
    #[cfg(all(feature = "gzip", feature = "zstd", feature = "brotli"))]
    return Some("gzip, zstd, br");
    #[cfg(all(feature = "gzip", feature = "zstd", not(feature = "brotli")))]
    return Some("gzip, zstd");
    #[cfg(all(feature = "gzip", not(feature = "zstd"), feature = "brotli"))]
    return Some("gzip, br");
    #[cfg(all(not(feature = "gzip"), feature = "zstd", feature = "brotli"))]
    return Some("zstd, br");
    #[cfg(all(feature = "gzip", not(feature = "zstd"), not(feature = "brotli")))]
    return Some("gzip");
    #[cfg(all(not(feature = "gzip"), feature = "zstd", not(feature = "brotli")))]
    return Some("zstd");
    #[cfg(all(not(feature = "gzip"), not(feature = "zstd"), feature = "brotli"))]
    return Some("br");
    #[cfg(not(any(feature = "gzip", feature = "zstd", feature = "brotli")))]
    return None;
}

// ── Gzip ──────────────────────────────────────────────────────────────

#[cfg(feature = "gzip")]
fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, HttpError> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .map_err(|e| HttpError::Decompress(e.to_string()))?;
    Ok(buf)
}

#[cfg(feature = "gzip")]
fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, HttpError> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| HttpError::Decompress(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| HttpError::Decompress(e.to_string()))
}

// ── Zstd ──────────────────────────────────────────────────────────────

#[cfg(feature = "zstd")]
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, HttpError> {
    zstd::decode_all(data).map_err(|e| HttpError::Decompress(e.to_string()))
}

#[cfg(feature = "zstd")]
fn compress_zstd(data: &[u8]) -> Result<Vec<u8>, HttpError> {
    zstd::encode_all(data, 3).map_err(|e| HttpError::Decompress(e.to_string()))
}

// ── Brotli ────────────────────────────────────────────────────────────

#[cfg(feature = "brotli")]
fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>, HttpError> {
    use std::io::Read;
    let mut decoder = brotli::Decompressor::new(data, 4096);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .map_err(|e| HttpError::Decompress(e.to_string()))?;
    Ok(buf)
}

#[cfg(feature = "brotli")]
fn compress_brotli(data: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut buf = Vec::new();
    let params = brotli::enc::BrotliEncoderParams::default();
    brotli::BrotliCompress(&mut &data[..], &mut buf, &params)
        .map_err(|e| HttpError::Decompress(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "gzip")]
    #[test]
    fn roundtrip_gzip() {
        let original = b"Hello, gzip compression roundtrip test data!";
        let compressed = super::compress("gzip", original).unwrap();
        assert_ne!(compressed, original);
        let decompressed = super::decompress("gzip", &compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn roundtrip_gzip_x_gzip() {
        let original = b"x-gzip alias test";
        let compressed = super::compress("gzip", original).unwrap();
        let decompressed = super::decompress("x-gzip", &compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn roundtrip_zstd() {
        let original = b"Hello, zstd compression roundtrip test data!";
        let compressed = super::compress("zstd", original).unwrap();
        assert_ne!(compressed, original);
        let decompressed = super::decompress("zstd", &compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn roundtrip_brotli() {
        let original = b"Hello, brotli compression roundtrip test data!";
        let compressed = super::compress("br", original).unwrap();
        assert_ne!(compressed, original);
        let decompressed = super::decompress("br", &compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn identity_passthrough() {
        let original = b"identity passthrough";
        let result = super::decompress("identity", original).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn unsupported_encoding_returns_error() {
        let result = super::decompress("deflate", b"data");
        assert!(result.is_err());
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn decompress_case_insensitive() {
        let original = b"case insensitive test";
        let compressed = super::compress("gzip", original).unwrap();
        let decompressed = super::decompress("  GZip  ", &compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn decompress_empty() {
        let compressed = super::compress("gzip", b"").unwrap();
        let decompressed = super::decompress("gzip", &compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[cfg(any(feature = "gzip", feature = "zstd", feature = "brotli"))]
    #[test]
    fn accept_encoding_value_is_some() {
        assert!(super::accept_encoding_value().is_some());
    }

    #[cfg(not(any(feature = "gzip", feature = "zstd", feature = "brotli")))]
    #[test]
    fn accept_encoding_value_is_none() {
        assert!(super::accept_encoding_value().is_none());
    }
}
