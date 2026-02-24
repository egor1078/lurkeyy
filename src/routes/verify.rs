use axum::{
    extract::{Query, State},
    response::Html,
};
use chrono::Utc;

use crate::AppState;
use crate::crypto;
use crate::db;
use crate::error::AppError;
use crate::models::VerifyQuery;

/// GET /verify?token=...
///
/// This is the destination URL that Linkvertise redirects the user to.
///
/// Anti-bypass logic:
/// 1. Verify JWT signature — reject forged tokens
/// 2. Check elapsed time: if (now - iat) < MIN_SECONDS → reject (bypass detected)
/// 3. Check if token was already used → reject (replay attack)
/// 4. Mark token as used
/// 5. Generate key and bind to HWID
/// 6. Return HTML page with the key
pub async fn verify(
    State(state): State<AppState>,
    Query(query): Query<VerifyQuery>,
) -> Result<Html<String>, AppError> {
    // 1. Verify JWT signature and decode claims
    let claims = crypto::verify_session_token(&query.token, &state.config.hmac_secret)
        .map_err(|_| AppError::Unauthorized("Invalid or expired token".to_string()))?;

    // 2. Anti-bypass: check minimum elapsed time
    let now = Utc::now().timestamp();
    let elapsed = now - claims.iat;

    if elapsed < state.config.min_linkvertise_seconds {
        tracing::warn!(
            "Bypass attempt detected for HWID {}: elapsed {}s (min {}s)",
            claims.hwid,
            elapsed,
            state.config.min_linkvertise_seconds
        );
        return Err(AppError::Forbidden(format!(
            "Verification too fast ({}s). Please complete the Linkvertise task properly. Minimum wait: {}s.",
            elapsed, state.config.min_linkvertise_seconds
        )));
    }

    // 3. Check for token replay
    let token_hash = crypto::hash_token(&query.token);
    if db::is_token_used(&state.pool, &token_hash).await? {
        return Err(AppError::Forbidden(
            "This token has already been used. Please start a new session.".to_string(),
        ));
    }

    // 4. Mark token as used (one-time use)
    db::mark_token_used(&state.pool, &token_hash).await?;

    // 5. Check if HWID already has an active key
    if let Some(existing) = db::find_active_key(&state.pool, &claims.hwid).await? {
        let seconds_remaining = (existing.expires_at - Utc::now()).num_seconds().max(0);
        let hours = seconds_remaining / 3600;
        let minutes = (seconds_remaining % 3600) / 60;

        return Ok(Html(render_key_page(
            &existing.key_value,
            &format!("{}h {}m remaining", hours, minutes),
            false,
        )));
    }

    // 6. Generate new key and bind to HWID
    let key_value = crypto::generate_key();
    let record = db::insert_key(
        &state.pool,
        &claims.hwid,
        &key_value,
        state.config.key_ttl_hours,
        Some(&claims.ip),
    )
    .await
    .map_err(|e| {
        // Handle UNIQUE constraint violation (race condition)
        if e.to_string().contains("UNIQUE") || e.to_string().contains("duplicate") {
            AppError::BadRequest("A key already exists for this HWID.".to_string())
        } else {
            AppError::Internal(format!("Failed to insert key: {}", e))
        }
    })?;

    let ttl_display = format!("{}h 0m remaining", state.config.key_ttl_hours);

    tracing::info!(
        "Key generated for HWID {}: {} (expires {})",
        claims.hwid,
        record.key_value,
        record.expires_at
    );

    Ok(Html(render_key_page(&record.key_value, &ttl_display, true)))
}

/// Render a minimal dark-themed HTML page showing the key.
fn render_key_page(key: &str, ttl: &str, is_new: bool) -> String {
    let status = if is_new {
        "✅ Key Generated Successfully!"
    } else {
        "🔑 Your Existing Key"
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LURK — Key System</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-image: radial-gradient(ellipse at 50% 0%, rgba(120, 80, 255, 0.08) 0%, transparent 60%);
        }}
        .card {{
            background: rgba(20, 20, 35, 0.9);
            border: 1px solid rgba(120, 80, 255, 0.2);
            border-radius: 16px;
            padding: 40px;
            max-width: 480px;
            width: 90%;
            text-align: center;
            backdrop-filter: blur(20px);
            box-shadow: 0 0 40px rgba(120, 80, 255, 0.1);
        }}
        .status {{ font-size: 1.3rem; margin-bottom: 24px; }}
        .key-box {{
            background: rgba(120, 80, 255, 0.1);
            border: 1px solid rgba(120, 80, 255, 0.3);
            border-radius: 10px;
            padding: 16px 20px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 1.4rem;
            letter-spacing: 2px;
            color: #a78bfa;
            user-select: all;
            cursor: pointer;
            margin-bottom: 16px;
            transition: all 0.2s;
        }}
        .key-box:hover {{
            background: rgba(120, 80, 255, 0.15);
            border-color: rgba(120, 80, 255, 0.5);
        }}
        .ttl {{
            color: #888;
            font-size: 0.9rem;
            margin-bottom: 24px;
        }}
        .copy-btn {{
            background: linear-gradient(135deg, #7c3aed, #6d28d9);
            color: white;
            border: none;
            padding: 12px 32px;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .copy-btn:hover {{ transform: translateY(-1px); box-shadow: 0 4px 15px rgba(120, 80, 255, 0.3); }}
        .copy-btn:active {{ transform: translateY(0); }}
    </style>
</head>
<body>
    <div class="card">
        <div class="status">{status}</div>
        <div class="key-box" id="key" onclick="copyKey()">{key}</div>
        <div class="ttl">⏱️ {ttl}</div>
        <button class="copy-btn" onclick="copyKey()">📋 Copy Key</button>
    </div>
    <script>
        function copyKey() {{
            navigator.clipboard.writeText('{key}').then(() => {{
                const btn = document.querySelector('.copy-btn');
                btn.textContent = '✅ Copied!';
                setTimeout(() => btn.textContent = '📋 Copy Key', 2000);
            }});
        }}
    </script>
</body>
</html>"#,
        status = status,
        key = key,
        ttl = ttl,
    )
}
