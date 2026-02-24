use std::net::IpAddr;

use axum::{extract::State, Json};

use crate::crypto;
use crate::db;
use crate::error::AppError;
use crate::models::{ExistingKeyResponse, StartSessionRequest, StartSessionResponse};
use crate::turnstile;
use crate::AppState;

/// Extract client IP from request (simplified; in production use X-Forwarded-For).
fn extract_ip(_state: &AppState) -> IpAddr {
    // In a real deployment behind a reverse proxy, parse X-Forwarded-For.
    // For now, default to loopback.
    "127.0.0.1".parse().unwrap()
}

/// POST /api/start-session
///
/// Flow:
/// 1. Validate Cloudflare Turnstile captcha
/// 2. Rate-limit check
/// 3. Check if HWID already has an active key → return it
/// 4. Generate HMAC-signed JWT session token
/// 5. Build Linkvertise redirect URL
/// 6. Return the redirect URL
pub async fn start_session(
    State(state): State<AppState>,
    Json(body): Json<StartSessionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let client_ip = extract_ip(&state);

    // Rate limiting
    if !state.session_limiter.check(client_ip).await {
        return Err(AppError::TooManyRequests);
    }

    // Validate HWID
    if body.hwid.is_empty() || body.hwid.len() > 128 {
        return Err(AppError::BadRequest("Invalid HWID".to_string()));
    }

    // Verify Turnstile captcha
    let captcha_valid = turnstile::verify_turnstile(
        &state.config.turnstile_secret,
        &body.turnstile_token,
        Some(&client_ip.to_string()),
    )
    .await
    .map_err(|e| AppError::Internal(format!("Turnstile request failed: {}", e)))?;

    if !captcha_valid {
        return Err(AppError::Forbidden(
            "Captcha verification failed".to_string(),
        ));
    }

    // Check if this HWID already has an active key
    if let Some(existing) = db::find_active_key(&state.pool, &body.hwid).await? {
        let seconds_remaining = (existing.expires_at - chrono::Utc::now())
            .num_seconds()
            .max(0);
        let response = ExistingKeyResponse {
            has_key: true,
            key: existing.key_value,
            expires_at: existing.expires_at.to_rfc3339(),
            seconds_remaining,
        };
        return Ok(Json(serde_json::to_value(response).unwrap()));
    }

    // Generate session token
    let token = crypto::create_session_token(
        &body.hwid,
        &client_ip.to_string(),
        &state.config.hmac_secret,
    )
    .map_err(|e| AppError::Internal(format!("Token generation failed: {}", e)))?;

    // Build Linkvertise URL
    // The destination URL is our /verify endpoint with the signed token
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

    let response = StartSessionResponse { redirect_url };

    Ok(Json(serde_json::to_value(response).unwrap()))
}
