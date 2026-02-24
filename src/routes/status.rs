use axum::{
    extract::{Query, State},
    Json,
};

use crate::error::AppError;
use crate::models::{ExistingKeyResponse, StatusQuery};
use crate::AppState;

/// GET /api/status?hwid=...
///
/// Returns the current active key for a HWID, or null if none exists.
pub async fn key_status(
    State(state): State<AppState>,
    Query(query): Query<StatusQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    if query.hwid.is_empty() {
        return Err(AppError::BadRequest("Missing HWID".to_string()));
    }

    match state.db.find_active_key(&query.hwid).await {
        Ok(Some(record)) => {
            let expires = chrono::DateTime::parse_from_rfc3339(&record.expires_at)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let seconds_remaining = (expires - chrono::Utc::now()).num_seconds().max(0);
            let response = ExistingKeyResponse {
                has_key: true,
                key: record.key_value,
                expires_at: record.expires_at,
                seconds_remaining,
            };
            Ok(Json(serde_json::to_value(response).unwrap()))
        }
        Ok(None) => Ok(Json(serde_json::json!({
            "has_key": false
        }))),
        Err(e) => Err(AppError::Internal(e)),
    }
}
