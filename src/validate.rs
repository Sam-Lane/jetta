use crate::decode::decode_token;
use crate::types::ValidationResult;
use anyhow::{Context, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Claims {
    #[serde(flatten)]
    _data: serde_json::Value,
}

/// Validate a JWT token signature
pub fn validate_token(
    token: &str,
    secret: Option<&str>,
    public_key_pem: Option<&str>,
) -> Result<ValidationResult> {
    // First, decode the token to get the algorithm
    let decoded = decode_token(token).context("Failed to decode token")?;
    let algorithm = &decoded.analysis.algorithm;

    let alg = parse_algorithm(algorithm)?;

    // Get the appropriate key
    let key = if let Some(secret_val) = secret {
        DecodingKey::from_secret(secret_val.as_bytes())
    } else if let Some(pem_content) = public_key_pem {
        match alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => DecodingKey::from_rsa_pem(pem_content.as_bytes())
                .context("Failed to parse RSA public key")?,
            Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(pem_content.as_bytes())
                .context("Failed to parse EC public key (ensure it's in PKCS8 format)")?,
            Algorithm::EdDSA => DecodingKey::from_ed_pem(pem_content.as_bytes())
                .context("Failed to parse EdDSA public key")?,
            _ => {
                anyhow::bail!("Public key PEM not supported for algorithm {}", algorithm);
            }
        }
    } else {
        // Check environment variable
        if let Ok(env_secret) = std::env::var("JETTA_SECRET") {
            DecodingKey::from_secret(env_secret.as_bytes())
        } else {
            anyhow::bail!("No secret or key provided. Use --secret, --secret-file, --public-key, or set JETTA_SECRET environment variable");
        }
    };

    // Set up validation
    let mut validation = Validation::new(alg);
    validation.validate_exp = false; // Don't fail on expired tokens, just decode
    validation.validate_nbf = false;
    validation.required_spec_claims = std::collections::HashSet::new(); // Don't require any specific claims

    // Attempt to decode and validate
    match decode::<Claims>(token, &key, &validation) {
        Ok(_) => Ok(ValidationResult {
            valid: true,
            error: None,
            token: decoded,
        }),
        Err(e) => Ok(ValidationResult {
            valid: false,
            error: Some(format!("{}", e)),
            token: decoded,
        }),
    }
}

/// Parse algorithm string to jsonwebtoken Algorithm enum
fn parse_algorithm(alg: &str) -> Result<Algorithm> {
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

    #[test]
    fn test_parse_algorithm() {
        assert!(matches!(
            parse_algorithm("HS256").unwrap(),
            Algorithm::HS256
        ));
        assert!(matches!(
            parse_algorithm("rs256").unwrap(),
            Algorithm::RS256
        ));
        assert!(matches!(
            parse_algorithm("ES384").unwrap(),
            Algorithm::ES384
        ));
        assert!(parse_algorithm("INVALID").is_err());
    }

    #[test]
    fn test_validate_with_correct_secret() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = validate_token(token, Some("your-256-bit-secret"), None).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_validate_with_wrong_secret() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = validate_token(token, Some("wrong-secret"), None).unwrap();
        assert!(!result.valid);
    }
}
