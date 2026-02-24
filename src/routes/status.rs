use axum::{
    Json,
    extract::{Query, State},
};

use crate::AppState;
use crate::db;
use crate::error::AppError;
use crate::models::{ExistingKeyResponse, StatusQuery};

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

    match db::find_active_key(&state.pool, &query.hwid).await? {
        Some(record) => {
            let seconds_remaining = (record.expires_at - chrono::Utc::now())
                .num_seconds()
                .max(0);
            let response = ExistingKeyResponse {
                has_key: true,
                key: record.key_value,
                expires_at: record.expires_at.to_rfc3339(),
                seconds_remaining,
            };
            Ok(Json(serde_json::to_value(response).unwrap()))
        }
        None => Ok(Json(serde_json::json!({
            "has_key": false
        }))),
    }
}
