use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Represents a decoded JWT token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedToken {
    pub header: Value,
    pub payload: Value,
    pub analysis: TokenAnalysis,
}

/// Token analysis information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAnalysis {
    pub algorithm: String,
    pub has_signature: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
}

/// Represents the result of signature validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub token: DecodedToken,
}

/// Output format enum
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    HumanReadable,
    Json,
    Table,
}
