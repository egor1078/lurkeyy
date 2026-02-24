use axum::{
    extract::{Query, State},
    response::Html,
};
use chrono::Utc;

use crate::crypto;
use crate::error::AppError;
use crate::models::VerifyQuery;
use crate::AppState;

/// GET /verify?token=...
pub async fn verify(
    State(state): State<AppState>,
    Query(query): Query<VerifyQuery>,
) -> Result<Html<String>, AppError> {
    let claims = crypto::verify_session_token(&query.token, &state.config.hmac_secret)
        .map_err(|_| AppError::Unauthorized("Invalid or expired token".to_string()))?;

    let now = Utc::now().timestamp();
    let elapsed = now - claims.iat;

    if elapsed < state.config.min_linkvertise_seconds {
        tracing::warn!("Bypass attempt HWID {}: {}s", claims.hwid, elapsed);
        return Err(AppError::Forbidden(format!(
            "Too fast ({}s). Min: {}s.",
            elapsed, state.config.min_linkvertise_seconds
        )));
    }

    let token_hash = crypto::hash_token(&query.token);
    match state.db.is_token_used(&token_hash).await {
        Ok(true) => return Err(AppError::Forbidden("Token already used.".to_string())),
        Ok(false) => {}
        Err(e) => tracing::warn!("Token check error: {}", e),
    }

    if let Err(e) = state.db.mark_token_used(&token_hash).await {
        tracing::warn!("Failed to mark token: {}", e);
    }

    if let Ok(Some(existing)) = state.db.find_active_key(&claims.hwid).await {
        let expires = chrono::DateTime::parse_from_rfc3339(&existing.expires_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let secs = (expires - Utc::now()).num_seconds().max(0);
        return Ok(Html(render_key_page(
            &existing.key_value,
            &format!("{}h {}m remaining", secs / 3600, (secs % 3600) / 60),
            false,
        )));
    }

    let key_value = crypto::generate_key();
    let record = state
        .db
        .insert_key(
            &claims.hwid,
            &key_value,
            state.config.key_ttl_hours,
            Some(&claims.ip),
        )
        .await
        .map_err(|e| {
            if e.contains("duplicate") || e.contains("409") {
                AppError::BadRequest("Key already exists for this HWID.".to_string())
            } else {
                AppError::Internal(format!("Insert failed: {}", e))
            }
        })?;

    tracing::info!(
        "Key generated for HWID {}: {}",
        claims.hwid,
        record.key_value
    );

    Ok(Html(render_key_page(
        &record.key_value,
        &format!("{}h 0m remaining", state.config.key_ttl_hours),
        true,
    )))
}

fn render_key_page(key: &str, ttl: &str, is_new: bool) -> String {
    let status = if is_new {
        "✅ Key Generated!"
    } else {
        "🔑 Your Key"
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LURK Key</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a0f;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;background-image:radial-gradient(ellipse at 50% 0%,rgba(120,80,255,.08) 0%,transparent 60%)}}
.card{{background:rgba(20,20,35,.9);border:1px solid rgba(120,80,255,.2);border-radius:16px;padding:40px;max-width:480px;width:90%;text-align:center;box-shadow:0 0 40px rgba(120,80,255,.1)}}
.status{{font-size:1.3rem;margin-bottom:24px}}
.key-box{{background:rgba(120,80,255,.1);border:1px solid rgba(120,80,255,.3);border-radius:10px;padding:16px 20px;font-family:'JetBrains Mono',monospace;font-size:1.4rem;letter-spacing:2px;color:#a78bfa;user-select:all;cursor:pointer;margin-bottom:16px;transition:all .2s}}
.key-box:hover{{background:rgba(120,80,255,.15);border-color:rgba(120,80,255,.5)}}
.ttl{{color:#888;font-size:.9rem;margin-bottom:24px}}
.copy-btn{{background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;border:none;padding:12px 32px;border-radius:8px;font-size:1rem;cursor:pointer;transition:all .2s}}
.copy-btn:hover{{transform:translateY(-1px);box-shadow:0 4px 15px rgba(120,80,255,.3)}}
</style>
</head>
<body>
<div class="card">
<div class="status">{status}</div>
<div class="key-box" onclick="copyKey()">{key}</div>
<div class="ttl">⏱️ {ttl}</div>
<button class="copy-btn" onclick="copyKey()">📋 Copy Key</button>
</div>
<script>
function copyKey(){{navigator.clipboard.writeText('{key}').then(()=>{{const b=document.querySelector('.copy-btn');b.textContent='✅ Copied!';setTimeout(()=>b.textContent='📋 Copy Key',2000)}})}}
</script>
</body>
</html>"#,
        status = status,
        key = key,
        ttl = ttl
    )
}
