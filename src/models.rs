use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A key record stored in Supabase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub hwid: String,
    pub key_value: String,
    pub created_at: Option<DateTime<Utc>>,
    pub expires_at: String,
    pub ip_address: Option<String>,
}

/// A used token record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsedToken {
    pub token_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_at: Option<String>,
}

/// JWT claims for session tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub hwid: String,
    pub ip: String,
    pub iat: i64,
    pub exp: i64,
}

/// Request body for starting a session.
#[derive(Debug, Deserialize)]
pub struct StartSessionRequest {
    pub hwid: String,
    pub turnstile_token: String,
}

/// Response for start-session endpoint.
#[derive(Debug, Serialize)]
pub struct StartSessionResponse {
    pub redirect_url: String,
}

/// Response indicating an existing active key.
#[derive(Debug, Serialize)]
pub struct ExistingKeyResponse {
    pub has_key: bool,
    pub key: String,
    pub expires_at: String,
    pub seconds_remaining: i64,
}

/// Query params for the verify endpoint.
#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}

/// Query params for the check endpoint.
#[derive(Debug, Deserialize)]
pub struct CheckKeyQuery {
    pub key: String,
    pub hwid: String,
}

/// Response from the check endpoint (for Roblox Lua scripts).
#[derive(Debug, Serialize)]
pub struct CheckKeyResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Query params for status endpoint.
#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    pub hwid: String,
}
