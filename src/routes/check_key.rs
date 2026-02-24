use std::net::IpAddr;

use axum::{
    extract::{Query, State},
    Json,
};

use crate::error::AppError;
use crate::models::{CheckKeyQuery, CheckKeyResponse};
use crate::AppState;

/// GET /api/check?key=...&hwid=...
///
/// Called by Roblox Lua scripts to validate a key.
pub async fn check_key(
    State(state): State<AppState>,
    Query(query): Query<CheckKeyQuery>,
) -> Result<Json<CheckKeyResponse>, AppError> {
    let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

    // Rate limiting
    if !state.check_limiter.check(client_ip).await {
        return Err(AppError::TooManyRequests);
    }

    // Validate input
    if query.key.is_empty() || query.hwid.is_empty() {
        return Ok(Json(CheckKeyResponse {
            valid: false,
            reason: Some("missing_params".to_string()),
        }));
    }

    // Check key validity
    let (valid, reason) = state
        .db
        .check_key_validity(&query.key, &query.hwid)
        .await
        .map_err(|e| AppError::Internal(e))?;

    Ok(Json(CheckKeyResponse { valid, reason }))
}
