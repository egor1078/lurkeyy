use std::net::IpAddr;

use axum::{extract::State, Json};

use crate::crypto;
use crate::error::AppError;
use crate::models::{ExistingKeyResponse, StartSessionRequest, StartSessionResponse};
use crate::turnstile;
use crate::AppState;

/// POST /api/start-session
pub async fn start_session(
    State(state): State<AppState>,
    Json(body): Json<StartSessionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

    if !state.session_limiter.check(client_ip).await {
        return Err(AppError::TooManyRequests);
    }

    if body.hwid.is_empty() || body.hwid.len() > 128 {
        return Err(AppError::BadRequest("Invalid HWID".to_string()));
    }

    let captcha_valid = turnstile::verify_turnstile(
        &state.config.turnstile_secret,
        &body.turnstile_token,
        Some(&client_ip.to_string()),
    )
    .await
    .map_err(|e| AppError::Internal(format!("Turnstile failed: {}", e)))?;

    if !captcha_valid {
        return Err(AppError::Forbidden("Captcha failed".to_string()));
    }

    match state.db.find_active_key(&body.hwid).await {
        Ok(Some(existing)) => {
            let expires = chrono::DateTime::parse_from_rfc3339(&existing.expires_at)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let seconds_remaining = (expires - chrono::Utc::now()).num_seconds().max(0);
            let response = ExistingKeyResponse {
                has_key: true,
                key: existing.key_value,
                expires_at: existing.expires_at,
                seconds_remaining,
            };
            return Ok(Json(serde_json::to_value(response).unwrap()));
        }
        Ok(None) => {}
        Err(e) => return Err(AppError::Internal(e)),
    }

    let token = crypto::create_session_token(
        &body.hwid,
        &client_ip.to_string(),
        &state.config.hmac_secret,
    )
    .map_err(|e| AppError::Internal(format!("Token gen failed: {}", e)))?;

    let destination = format!(
        "{}/verify?token={}",
        state.config.base_url,
        urlencoding::encode(&token)
    );

    let redirect_url = format!(
        "https://linkvertise.com/{}/lurk-key?o={}",
        state.config.linkvertise_id,
        urlencoding::encode(&destination)
    );

    Ok(Json(
        serde_json::to_value(StartSessionResponse { redirect_url }).unwrap(),
    ))
}
