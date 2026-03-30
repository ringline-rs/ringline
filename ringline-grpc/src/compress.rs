//! Per-message gRPC compression.
//!
//! gRPC supports per-message compression via the `grpc-encoding` header
//! and the compress flag byte in the 5-byte message prefix. Standard
//! algorithms are `gzip` and `deflate`; we also support `zstd` (used by
//! some modern gRPC implementations).

use crate::error::GrpcError;

/// Decompress a gRPC message payload.
pub(crate) fn decompress(encoding: &str, data: &[u8]) -> Result<Vec<u8>, GrpcError> {
    match encoding {
        #[cfg(feature = "gzip")]
        "gzip" => decompress_gzip(data),
        #[cfg(feature = "zstd")]
        "zstd" => decompress_zstd(data),
        "identity" => Ok(data.to_vec()),
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
fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, GrpcError> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .map_err(|e| GrpcError::InvalidMessage(format!("gzip decompress: {e}")))?;
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
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, GrpcError> {
    zstd::decode_all(data).map_err(|e| GrpcError::InvalidMessage(format!("zstd decompress: {e}")))
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
        let decompressed = super::decompress("gzip", &compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn roundtrip_zstd() {
        let data = b"hello gRPC zstd";
        let compressed = super::compress("zstd", data).unwrap();
        let decompressed = super::decompress("zstd", &compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn identity_passthrough() {
        let data = b"no compression";
        let result = super::decompress("identity", data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn unsupported_encoding() {
        assert!(super::decompress("snappy", b"data").is_err());
    }
}
