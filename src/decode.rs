use crate::types::{DecodedToken, TokenAnalysis};
use anyhow::{Context, Result};
use jsonwebtoken::decode_header;
use serde_json::Value;

/// Decode a JWT token without validating the signature
pub fn decode_token(token: &str) -> Result<DecodedToken> {
    // Split the token into parts
    let parts: Vec<&str> = token.split('.').collect();

    if parts.len() != 3 {
        anyhow::bail!(
            "Malformed JWT: expected 3 parts separated by '.', found {}",
            parts.len()
        );
    }

    // Decode header
    let header = decode_header(token).context("Failed to decode JWT header")?;
    let header_json: Value = serde_json::to_value(&header)?;

    // Extract algorithm
    let algorithm = header_json["alg"].as_str().unwrap_or("unknown").to_string();

    // Decode payload (base64url decode)
    let payload_bytes =
        base64_url_decode(parts[1]).context("Failed to decode payload: invalid base64 encoding")?;

    let payload_json: Value =
        serde_json::from_slice(&payload_bytes).context("Failed to parse payload as JSON")?;

    // Extract standard claims for analysis
    let expires_at = payload_json["exp"].as_i64();
    let not_before = payload_json["nbf"].as_i64();
    let issued_at = payload_json["iat"].as_i64();

    // Check if token has a signature
    let has_signature = !parts[2].is_empty();

    Ok(DecodedToken {
        header: header_json,
        payload: payload_json,
        analysis: TokenAnalysis {
            algorithm,
            has_signature,
            expires_at,
            not_before,
            issued_at,
        },
    })
}

/// Base64 URL decode helper
fn base64_url_decode(input: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    URL_SAFE_NO_PAD
        .decode(input)
        .context("Invalid base64url encoding")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_valid_token() {
        // Sample HS256 JWT token (header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"1234567890","name":"John Doe","iat":1516239022})
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let decoded = decode_token(token).unwrap();
        assert_eq!(decoded.header["alg"], "HS256");
        assert_eq!(decoded.header["typ"], "JWT");
        assert_eq!(decoded.payload["sub"], "1234567890");
        assert_eq!(decoded.payload["name"], "John Doe");
        assert_eq!(decoded.analysis.algorithm, "HS256");
        assert!(decoded.analysis.has_signature);
    }

    #[test]
    fn test_decode_malformed_token() {
        let token = "invalid.token";
        assert!(decode_token(token).is_err());
    }

    #[test]
    fn test_decode_invalid_base64() {
        let token = "eyJhbGciOiJIUzI1NiJ9.!!!invalid!!!.signature";
        assert!(decode_token(token).is_err());
    }

    #[test]
    fn test_decode_extracts_claims() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjJ9.4Adcj0vp8FJn5c6I1Jz4m9m0RmqV3n5vF2c4hLbIrQ4";

        let decoded = decode_token(token).unwrap();
        assert_eq!(decoded.analysis.issued_at, Some(1516239022));
        assert_eq!(decoded.analysis.expires_at, Some(1516242622));
    }
}
