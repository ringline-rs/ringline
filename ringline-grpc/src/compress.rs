//! Per-message gRPC compression.
//!
//! gRPC supports per-message compression via the `grpc-encoding` header
//! and the compress flag byte in the 5-byte message prefix. Standard
//! algorithms are `gzip` and `deflate`; we also support `zstd` (used by
//! some modern gRPC implementations).

use crate::error::GrpcError;

/// Decompress a gRPC message payload. Output is capped at `max_size` bytes —
/// additional bytes produced by the decoder cause [`GrpcError::MaxSizeExceeded`].
pub(crate) fn decompress(
    encoding: &str,
    data: &[u8],
    max_size: usize,
) -> Result<Vec<u8>, GrpcError> {
    match encoding {
        #[cfg(feature = "gzip")]
        "gzip" => decompress_gzip(data, max_size),
        #[cfg(feature = "zstd")]
        "zstd" => decompress_zstd(data, max_size),
        "identity" => {
            if data.len() > max_size {
                return Err(GrpcError::MaxSizeExceeded(format!(
                    "identity message of {} bytes exceeds cap {max_size}",
                    data.len()
                )));
            }
            Ok(data.to_vec())
        }
        other => Err(GrpcError::InvalidMessage(format!(
            "unsupported grpc-encoding: {other}"
        ))),
    }
}

/// Compress a gRPC message payload.
#[allow(dead_code, unused_variables)]
pub(crate) fn compress(encoding: &str, data: &[u8]) -> Result<Vec<u8>, GrpcError> {
    match encoding {
        #[cfg(feature = "gzip")]
        "gzip" => compress_gzip(data),
        #[cfg(feature = "zstd")]
        "zstd" => compress_zstd(data),
        other => Err(GrpcError::InvalidMessage(format!(
            "unsupported grpc-encoding: {other}"
        ))),
    }
}

/// Build the `grpc-accept-encoding` header value from enabled features.
pub(crate) fn accept_encoding_value() -> Option<&'static str> {
    #[cfg(all(feature = "gzip", feature = "zstd"))]
    return Some("identity,gzip,zstd");
    #[cfg(all(feature = "gzip", not(feature = "zstd")))]
    return Some("identity,gzip");
    #[cfg(all(not(feature = "gzip"), feature = "zstd"))]
    return Some("identity,zstd");
    #[cfg(not(any(feature = "gzip", feature = "zstd")))]
    return None;
}

#[cfg(feature = "gzip")]
fn decompress_gzip(data: &[u8], max_size: usize) -> Result<Vec<u8>, GrpcError> {
    use std::io::Read;
    let decoder = flate2::read::GzDecoder::new(data);
    let mut limited = decoder.take(max_size as u64 + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|e| GrpcError::InvalidMessage(format!("gzip decompress: {e}")))?;
    if buf.len() > max_size {
        return Err(GrpcError::MaxSizeExceeded(format!(
            "gzip decompression exceeds {max_size} bytes"
        )));
    }
    Ok(buf)
}

#[cfg(feature = "gzip")]
fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, GrpcError> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| GrpcError::InvalidMessage(format!("gzip compress: {e}")))?;
    encoder
        .finish()
        .map_err(|e| GrpcError::InvalidMessage(format!("gzip compress: {e}")))
}

#[cfg(feature = "zstd")]
fn decompress_zstd(data: &[u8], max_size: usize) -> Result<Vec<u8>, GrpcError> {
    use std::io::Read;
    let decoder = zstd::Decoder::new(data)
        .map_err(|e| GrpcError::InvalidMessage(format!("zstd decompress: {e}")))?;
    let mut limited = decoder.take(max_size as u64 + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|e| GrpcError::InvalidMessage(format!("zstd decompress: {e}")))?;
    if buf.len() > max_size {
        return Err(GrpcError::MaxSizeExceeded(format!(
            "zstd decompression exceeds {max_size} bytes"
        )));
    }
    Ok(buf)
}

#[cfg(feature = "zstd")]
fn compress_zstd(data: &[u8]) -> Result<Vec<u8>, GrpcError> {
    zstd::encode_all(data, 3).map_err(|e| GrpcError::InvalidMessage(format!("zstd compress: {e}")))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "gzip")]
    #[test]
    fn roundtrip_gzip() {
        let data = b"hello gRPC compression";
        let compressed = super::compress("gzip", data).unwrap();
        let decompressed = super::decompress("gzip", &compressed, usize::MAX).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn roundtrip_zstd() {
        let data = b"hello gRPC zstd";
        let compressed = super::compress("zstd", data).unwrap();
        let decompressed = super::decompress("zstd", &compressed, usize::MAX).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn identity_passthrough() {
        let data = b"no compression";
        let result = super::decompress("identity", data, usize::MAX).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn unsupported_encoding() {
        assert!(super::decompress("snappy", b"data", usize::MAX).is_err());
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn decompression_bomb_rejected_at_cap() {
        // 1 MiB of zeros gzips to a few KiB but expands back to 1 MiB.
        // Cap to 1 KiB → MaxSizeExceeded.
        let original = vec![0u8; 1024 * 1024];
        let compressed = super::compress("gzip", &original).unwrap();
        assert!(compressed.len() < 10_000);
        let result = super::decompress("gzip", &compressed, 1024);
        assert!(matches!(result, Err(crate::GrpcError::MaxSizeExceeded(_))));
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn decompression_bomb_rejected_at_cap_zstd() {
        // 1 MiB of zeros zstd-compresses to ~100 bytes but expands back.
        // Cap to 1 KiB → MaxSizeExceeded.
        let original = vec![0u8; 1024 * 1024];
        let compressed = super::compress("zstd", &original).unwrap();
        assert!(compressed.len() < 10_000);
        let result = super::decompress("zstd", &compressed, 1024);
        assert!(matches!(result, Err(crate::GrpcError::MaxSizeExceeded(_))));
    }

    #[test]
    fn identity_too_large_rejected() {
        let data = vec![0u8; 100];
        assert!(super::decompress("identity", &data, 50).is_err());
    }
}
