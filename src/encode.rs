use anyhow::{Context, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    #[serde(flatten)]
    data: serde_json::Value,
}

/// Encode and sign a JWT token
pub fn encode_token(
    header: Option<&Value>,
    payload: &Value,
    secret: Option<&str>,
    private_key_pem: Option<&str>,
    algorithm: Option<Algorithm>,
) -> Result<String> {
    // Detect algorithm if not explicitly provided
    let detected_alg = if let Some(alg) = algorithm {
        alg
    } else if secret.is_some() {
        Algorithm::HS256 // Default for HMAC
    } else if let Some(pem) = private_key_pem {
        detect_algorithm_from_key(pem)?
    } else {
        anyhow::bail!("No secret or key provided. Use --secret, --secret-file, or --private-key");
    };

    // Build header
    let mut jwt_header = if let Some(custom_header) = header {
        // Parse custom header into Header struct
        let mut h = Header::new(detected_alg);

        // Merge custom header fields (but always override 'alg' for safety)
        if let Some(typ) = custom_header.get("typ").and_then(|v| v.as_str()) {
            h.typ = Some(typ.to_string());
        }
        if let Some(kid) = custom_header.get("kid").and_then(|v| v.as_str()) {
            h.kid = Some(kid.to_string());
        }
        if let Some(cty) = custom_header.get("cty").and_then(|v| v.as_str()) {
            h.cty = Some(cty.to_string());
        }
        if let Some(jku) = custom_header.get("jku").and_then(|v| v.as_str()) {
            h.jku = Some(jku.to_string());
        }
        if let Some(x5u) = custom_header.get("x5u").and_then(|v| v.as_str()) {
            h.x5u = Some(x5u.to_string());
        }

        h
    } else {
        // Use defaults: alg (detected) and typ = "JWT"
        let mut h = Header::new(detected_alg);
        h.typ = Some("JWT".to_string());
        h
    };

    // Always ensure alg matches the detected/specified algorithm for safety
    jwt_header.alg = detected_alg;

    // Get encoding key
    let encoding_key = if let Some(secret_str) = secret {
        EncodingKey::from_secret(secret_str.as_bytes())
    } else if let Some(pem_content) = private_key_pem {
        match detected_alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => EncodingKey::from_rsa_pem(pem_content.as_bytes())
                .context("Failed to parse RSA private key")?,
            Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(pem_content.as_bytes())
                .context("Failed to parse EC private key")?,
            Algorithm::EdDSA => EncodingKey::from_ed_pem(pem_content.as_bytes())
                .context("Failed to parse EdDSA private key")?,
            _ => {
                anyhow::bail!(
                    "Private key PEM not supported for algorithm {:?}",
                    detected_alg
                );
            }
        }
    } else {
        anyhow::bail!("No secret or key provided");
    };

    // Wrap payload in Claims struct for encoding
    let claims = Claims {
        data: payload.clone(),
    };

    // Encode and sign the token
    let token = encode(&jwt_header, &claims, &encoding_key)
        .context("Failed to encode and sign JWT token")?;

    Ok(token)
}

/// Detect algorithm from private key PEM content
fn detect_algorithm_from_key(pem_content: &str) -> Result<Algorithm> {
    // Try to parse as different key types and detect algorithm
    if pem_content.contains("BEGIN RSA PRIVATE KEY") || pem_content.contains("BEGIN PRIVATE KEY") {
        // For RSA, check key size to determine best algorithm
        // Default to RS256 as the most common
        Ok(Algorithm::RS256)
    } else if pem_content.contains("BEGIN EC PRIVATE KEY") {
        // For EC, default to ES256
        Ok(Algorithm::ES256)
    } else if pem_content.contains("BEGIN OPENSSH PRIVATE KEY") {
        // EdDSA keys often use OpenSSH format
        Ok(Algorithm::EdDSA)
    } else {
        // Try to infer from BEGIN blocks
        if pem_content.contains("EC PRIVATE KEY") {
            Ok(Algorithm::ES256)
        } else if pem_content.contains("PRIVATE KEY") {
            // Generic private key, assume RSA
            Ok(Algorithm::RS256)
        } else {
            anyhow::bail!("Unable to detect algorithm from key format. Use --algorithm to specify explicitly.");
        }
    }
}

/// Parse algorithm string to jsonwebtoken Algorithm enum
pub fn parse_algorithm(alg: &str) -> Result<Algorithm> {
    match alg.to_uppercase().as_str() {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EDDSA" => Ok(Algorithm::EdDSA),
        _ => anyhow::bail!("Unsupported algorithm: {}", alg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_algorithm() {
        assert!(matches!(
            parse_algorithm("HS256").unwrap(),
            Algorithm::HS256
        ));
        assert!(matches!(
            parse_algorithm("hs256").unwrap(),
            Algorithm::HS256
        ));
        assert!(matches!(
            parse_algorithm("RS256").unwrap(),
            Algorithm::RS256
        ));
        assert!(matches!(
            parse_algorithm("ES256").unwrap(),
            Algorithm::ES256
        ));
        assert!(matches!(
            parse_algorithm("EdDSA").unwrap(),
            Algorithm::EdDSA
        ));
        assert!(matches!(
            parse_algorithm("EDDSA").unwrap(),
            Algorithm::EdDSA
        ));
        assert!(parse_algorithm("INVALID").is_err());
    }

    #[test]
    fn test_encode_token_with_hmac() {
        let payload = json!({
            "sub": "1234567890",
            "name": "Test User",
            "iat": 1516239022
        });

        let result = encode_token(None, &payload, Some("secret"), None, None);
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(token.split('.').count() == 3);
        assert!(token.starts_with("eyJ")); // Base64 encoded JWT
    }

    #[test]
    fn test_encode_token_with_custom_header() {
        let header = json!({
            "typ": "JWT",
            "kid": "key-123"
        });
        let payload = json!({
            "sub": "1234567890"
        });

        let result = encode_token(Some(&header), &payload, Some("secret"), None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_encode_token_no_key() {
        let payload = json!({"sub": "test"});
        let result = encode_token(None, &payload, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_algorithm_from_key() {
        let rsa_key = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----";
        assert!(matches!(
            detect_algorithm_from_key(rsa_key).unwrap(),
            Algorithm::RS256
        ));

        let ec_key = "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----";
        assert!(matches!(
            detect_algorithm_from_key(ec_key).unwrap(),
            Algorithm::ES256
        ));
    }
}
