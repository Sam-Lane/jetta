use crate::types::{DecodedToken, OutputFormat, TokenAnalysis, ValidationResult};
use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde_json::Value;
use std::collections::HashMap;

/// Format a decoded JWT token according to the specified output format
pub fn format_decoded_token(token: &DecodedToken, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::HumanReadable => format_decoded_human_readable(token),
        OutputFormat::Json => format_decoded_json(token),
    }
}

/// Format validation results according to the specified output format
pub fn format_validation_result(result: &ValidationResult, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::HumanReadable => format_validation_human_readable(result),
        OutputFormat::Json => format_validation_json(result),
    }
}

/// Format a decoded token in human-readable colorful output
fn format_decoded_human_readable(token: &DecodedToken) -> Result<String> {
    let mut output = String::new();

    // Header section
    output.push_str(&format!("{}\n", "=== JWT Header ===".bold().cyan()));
    output.push_str(&format_header_human_readable(&token.header)?);
    output.push('\n');

    // Payload section
    output.push_str(&format!("{}\n", "=== JWT Payload ===".bold().cyan()));
    output.push_str(&format_payload_human_readable(&token.payload)?);
    output.push('\n');

    // Analysis section
    output.push_str(&format!("{}\n", "=== Token Analysis ===".bold().cyan()));
    output.push_str(&format_analysis_human_readable(&token.analysis)?);

    Ok(output)
}

/// Format the header in human-readable format
fn format_header_human_readable(header: &Value) -> Result<String> {
    let mut output = String::new();

    if let Value::Object(map) = header {
        // Display algorithm prominently
        if let Some(alg) = map.get("alg").and_then(|v| v.as_str()) {
            output.push_str(&format!("  {}: {}\n", "Algorithm".bold(), alg.green()));
        }

        // Display type if present
        if let Some(typ) = map.get("typ").and_then(|v| v.as_str()) {
            output.push_str(&format!("  {}: {}\n", "Type".bold(), typ));
        }

        // Display key ID if present
        if let Some(kid) = map.get("kid").and_then(|v| v.as_str()) {
            output.push_str(&format!("  {}: {}\n", "Key ID".bold(), kid));
        }

        // Display other fields
        for (key, value) in map.iter() {
            if key != "alg" && key != "typ" && key != "kid" {
                output.push_str(&format!("  {}: {}\n", key.bold(), format_json_value(value)));
            }
        }
    }

    Ok(output)
}

/// Format the payload in human-readable format
fn format_payload_human_readable(payload: &Value) -> Result<String> {
    let mut output = String::new();

    if let Value::Object(map) = payload {
        // Standard claims with special formatting
        let standard_claims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

        for &claim in &standard_claims {
            if let Some(value) = map.get(claim) {
                output.push_str(&format_claim_human_readable(claim, value));
            }
        }

        // Custom claims
        let has_custom_claims = map.keys().any(|k| !standard_claims.contains(&k.as_str()));
        if has_custom_claims {
            output.push_str(&format!("\n  {}\n", "Custom Claims:".bold().yellow()));
            for (key, value) in map.iter() {
                if !standard_claims.contains(&key.as_str()) {
                    output.push_str(&format!(
                        "    {}: {}\n",
                        key.bold(),
                        format_json_value(value)
                    ));
                }
            }
        }
    }

    Ok(output)
}

/// Format a single claim in human-readable format
fn format_claim_human_readable(claim: &str, value: &Value) -> String {
    let label = match claim {
        "iss" => "Issuer",
        "sub" => "Subject",
        "aud" => "Audience",
        "exp" => "Expires At",
        "nbf" => "Not Before",
        "iat" => "Issued At",
        "jti" => "JWT ID",
        _ => claim,
    };

    // Format timestamps specially
    if matches!(claim, "exp" | "nbf" | "iat") {
        if let Some(timestamp) = value.as_i64() {
            let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0);
            if let Some(dt) = datetime {
                let formatted = dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                return format!(
                    "  {}: {} ({})\n",
                    label.bold(),
                    timestamp,
                    formatted.bright_black()
                );
            }
        }
    }

    format!("  {}: {}\n", label.bold(), format_json_value(value))
}

/// Format a duration in seconds to a human-readable string with appropriate unit
fn format_duration(seconds: i64) -> String {
    let abs_seconds = seconds.abs();

    let (value, unit) = match abs_seconds {
        s if s < 60 => (s, "second"),
        s if s < 3600 => (s / 60, "minute"),
        s if s < 86400 => (s / 3600, "hour"),
        s if s < 2592000 => (s / 86400, "day"),
        s if s < 31536000 => (s / 2592000, "month"),
        s => (s / 31536000, "year"),
    };

    if value == 1 {
        format!("{} {}", value, unit)
    } else {
        format!("{} {}s", value, unit)
    }
}

/// Format token analysis in human-readable format
fn format_analysis_human_readable(analysis: &TokenAnalysis) -> Result<String> {
    let mut output = String::new();

    // Token validity period
    if let (Some(nbf), Some(exp)) = (analysis.not_before, analysis.expires_at) {
        let nbf_dt = DateTime::<Utc>::from_timestamp(nbf, 0);
        let exp_dt = DateTime::<Utc>::from_timestamp(exp, 0);

        if let (Some(nbf), Some(exp)) = (nbf_dt, exp_dt) {
            output.push_str(&format!(
                "  {}: {} to {}\n",
                "Valid Period".bold(),
                nbf.format("%Y-%m-%d %H:%M:%S UTC"),
                exp.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
    }

    // Expiration status
    if let Some(exp) = analysis.expires_at {
        let now = Utc::now().timestamp();
        if exp < now {
            let diff = now - exp;
            output.push_str(&format!(
                "  {}: {} (expired {} ago)\n",
                "Status".bold(),
                "EXPIRED".red().bold(),
                format_duration(diff)
            ));
        } else {
            let diff = exp - now;
            output.push_str(&format!(
                "  {}: {} (expires in {})\n",
                "Status".bold(),
                "VALID".green().bold(),
                format_duration(diff)
            ));
        }
    }

    // Not before status
    if let Some(nbf) = analysis.not_before {
        let now = Utc::now().timestamp();
        if nbf > now {
            let diff = nbf - now;
            output.push_str(&format!(
                "  {}: {} (not valid for {})\n",
                "Not Before Status".bold(),
                "NOT YET VALID".yellow().bold(),
                format_duration(diff)
            ));
        }
    }

    // Algorithm
    output.push_str(&format!(
        "  {}: {}\n",
        "Algorithm".bold(),
        analysis.algorithm.green()
    ));

    // Has signature
    let sig_status = if analysis.has_signature {
        "YES".green()
    } else {
        "NO".red()
    };
    output.push_str(&format!("  {}: {}\n", "Has Signature".bold(), sig_status));

    Ok(output)
}

/// Format validation result in human-readable format
fn format_validation_human_readable(result: &ValidationResult) -> Result<String> {
    let mut output = String::new();

    // Validation status
    output.push_str(&format!("{}\n", "=== Validation Result ===".bold().cyan()));

    if result.valid {
        output.push_str(&format!(
            "  {}: {}\n\n",
            "Status".bold(),
            "VALID".green().bold()
        ));
    } else {
        output.push_str(&format!(
            "  {}: {}\n",
            "Status".bold(),
            "INVALID".red().bold()
        ));
        if let Some(error) = &result.error {
            output.push_str(&format!("  {}: {}\n\n", "Error".bold(), error.red()));
        } else {
            output.push('\n');
        }
    }

    // Token details
    output.push_str(&format_decoded_human_readable(&result.token)?);

    Ok(output)
}

/// Format a decoded token as JSON
fn format_decoded_json(token: &DecodedToken) -> Result<String> {
    let mut analysis_map = HashMap::new();
    analysis_map.insert(
        "algorithm",
        serde_json::Value::String(token.analysis.algorithm.clone()),
    );
    analysis_map.insert(
        "has_signature",
        serde_json::Value::Bool(token.analysis.has_signature),
    );

    if let Some(exp) = token.analysis.expires_at {
        analysis_map.insert("expires_at", serde_json::Value::Number(exp.into()));
    }

    if let Some(nbf) = token.analysis.not_before {
        analysis_map.insert("not_before", serde_json::Value::Number(nbf.into()));
    }

    if let Some(iat) = token.analysis.issued_at {
        analysis_map.insert("issued_at", serde_json::Value::Number(iat.into()));
    }

    let mut output_map = HashMap::new();
    output_map.insert("header", token.header.clone());
    output_map.insert("payload", token.payload.clone());
    output_map.insert("analysis", serde_json::to_value(analysis_map)?);

    Ok(serde_json::to_string_pretty(&output_map)?)
}

/// Format validation result as JSON
fn format_validation_json(result: &ValidationResult) -> Result<String> {
    let mut map = HashMap::new();
    map.insert("valid", serde_json::Value::Bool(result.valid));

    if let Some(error) = &result.error {
        map.insert("error", serde_json::Value::String(error.clone()));
    }

    // Include token details
    let token_json: Value = serde_json::from_str(&format_decoded_json(&result.token)?)?;
    map.insert("token", token_json);

    Ok(serde_json::to_string_pretty(&map)?)
}

/// Helper function to format JSON values
fn format_json_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Array(arr) => format!(
            "[{}]",
            arr.iter()
                .map(format_json_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(_) => serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string()),
        Value::Null => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_token() -> DecodedToken {
        DecodedToken {
            header: json!({
                "alg": "HS256",
                "typ": "JWT"
            }),
            payload: json!({
                "sub": "1234567890",
                "name": "John Doe",
                "iat": 1516239022,
                "exp": 1516242622
            }),
            analysis: TokenAnalysis {
                algorithm: "HS256".to_string(),
                has_signature: true,
                expires_at: Some(1516242622),
                not_before: None,
                issued_at: Some(1516239022),
            },
        }
    }

    #[test]
    fn test_format_decoded_human_readable() {
        let token = create_test_token();
        let output = format_decoded_human_readable(&token).unwrap();

        assert!(output.contains("JWT Header"));
        assert!(output.contains("JWT Payload"));
        assert!(output.contains("Token Analysis"));
        assert!(output.contains("HS256"));
        assert!(output.contains("John Doe"));
    }

    #[test]
    fn test_format_decoded_json() {
        let token = create_test_token();
        let output = format_decoded_json(&token).unwrap();

        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["header"]["alg"], "HS256");
        assert_eq!(parsed["payload"]["name"], "John Doe");
        assert_eq!(parsed["analysis"]["algorithm"], "HS256");
    }

    #[test]
    fn test_format_validation_human_readable() {
        let token = create_test_token();
        let result = ValidationResult {
            valid: true,
            error: None,
            token,
        };

        let output = format_validation_human_readable(&result).unwrap();
        assert!(output.contains("VALID"));
        assert!(output.contains("JWT Header"));
    }

    #[test]
    fn test_format_validation_human_readable_invalid() {
        let token = create_test_token();
        let result = ValidationResult {
            valid: false,
            error: Some("Invalid signature".to_string()),
            token,
        };

        let output = format_validation_human_readable(&result).unwrap();
        assert!(output.contains("INVALID"));
        assert!(output.contains("Invalid signature"));
    }

    #[test]
    fn test_format_validation_json() {
        let token = create_test_token();
        let result = ValidationResult {
            valid: true,
            error: None,
            token,
        };

        let output = format_validation_json(&result).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["valid"], true);
        assert!(parsed["token"]["header"].is_object());
    }

    #[test]
    fn test_format_validation_json_invalid() {
        let token = create_test_token();
        let result = ValidationResult {
            valid: false,
            error: Some("Signature verification failed".to_string()),
            token,
        };

        let output = format_validation_json(&result).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["valid"], false);
        assert_eq!(parsed["error"], "Signature verification failed");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(30), "30 seconds");
        assert_eq!(format_duration(1), "1 second");
        assert_eq!(format_duration(59), "59 seconds");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(90), "1 minute");
        assert_eq!(format_duration(120), "2 minutes");
        assert_eq!(format_duration(3599), "59 minutes");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3600), "1 hour");
        assert_eq!(format_duration(7200), "2 hours");
        assert_eq!(format_duration(86399), "23 hours");
    }

    #[test]
    fn test_format_duration_days() {
        assert_eq!(format_duration(86400), "1 day");
        assert_eq!(format_duration(172800), "2 days");
        assert_eq!(format_duration(2591999), "29 days");
    }

    #[test]
    fn test_format_duration_months() {
        assert_eq!(format_duration(2592000), "1 month");
        assert_eq!(format_duration(5184000), "2 months");
        assert_eq!(format_duration(31535999), "12 months");
    }

    #[test]
    fn test_format_duration_years() {
        assert_eq!(format_duration(31536000), "1 year");
        assert_eq!(format_duration(63673860), "2 years");
        assert_eq!(format_duration(315360000), "10 years");
    }
}
