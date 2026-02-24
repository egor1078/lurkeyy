use chrono::{DateTime, Duration, Utc};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

use crate::models::KeyRecord;

/// Initialize the PostgreSQL connection pool for Supabase.
///
/// Disables prepared statement caching for PgBouncer compatibility (port 6543).
pub async fn init_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let options: PgConnectOptions = database_url
        .parse::<PgConnectOptions>()?
        .statement_cache_capacity(0);

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    tracing::info!("Connected to Supabase PostgreSQL");
    Ok(pool)
}

/// Run the initial migration to create tables.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    let migration_sql = include_str!("../migrations/001_create_keys.sql");

    sqlx::raw_sql(migration_sql).execute(pool).await?;

    tracing::info!("Database migrations applied");
    Ok(())
}

/// Find an active (non-expired) key for the given HWID.
pub async fn find_active_key(pool: &PgPool, hwid: &str) -> Result<Option<KeyRecord>, sqlx::Error> {
    let record = sqlx::query_as::<_, KeyRecord>(
        "SELECT id, hwid, key_value, created_at, expires_at, ip_address
         FROM keys WHERE hwid = $1 AND expires_at > $2",
    )
    .bind(hwid)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

/// Insert a new key into the database.
pub async fn insert_key(
    pool: &PgPool,
    hwid: &str,
    key_value: &str,
    ttl_hours: i64,
    ip_address: Option<&str>,
) -> Result<KeyRecord, sqlx::Error> {
    let now = Utc::now();
    let expires_at: DateTime<Utc> = now + Duration::hours(ttl_hours);

    // Delete any existing expired key for this HWID first
    sqlx::query("DELETE FROM keys WHERE hwid = $1 AND expires_at <= $2")
        .bind(hwid)
        .bind(now)
        .execute(pool)
        .await?;

    let record = sqlx::query_as::<_, KeyRecord>(
        "INSERT INTO keys (hwid, key_value, created_at, expires_at, ip_address)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, hwid, key_value, created_at, expires_at, ip_address",
    )
    .bind(hwid)
    .bind(key_value)
    .bind(now)
    .bind(expires_at)
    .bind(ip_address)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// Check if a key is valid for the given HWID (used by Roblox Lua scripts).
pub async fn check_key_validity(
    pool: &PgPool,
    key: &str,
    hwid: &str,
) -> Result<(bool, Option<String>), sqlx::Error> {
    let record = sqlx::query_as::<_, KeyRecord>(
        "SELECT id, hwid, key_value, created_at, expires_at, ip_address
         FROM keys WHERE key_value = $1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;

    match record {
        None => Ok((false, Some("invalid_key".to_string()))),
        Some(rec) => {
            if rec.hwid != hwid {
                Ok((false, Some("wrong_hwid".to_string())))
            } else if rec.expires_at <= Utc::now() {
                // Clean up expired key
                sqlx::query("DELETE FROM keys WHERE id = $1")
                    .bind(rec.id)
                    .execute(pool)
                    .await?;
                Ok((false, Some("expired".to_string())))
            } else {
                Ok((true, None))
            }
        }
    }
}

/// Check if a token hash has been used (replay protection).
pub async fn is_token_used(pool: &PgPool, token_hash: &str) -> Result<bool, sqlx::Error> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM used_tokens WHERE token_hash = $1)")
            .bind(token_hash)
            .fetch_one(pool)
            .await?;
    Ok(exists)
}

/// Mark a token hash as used.
pub async fn mark_token_used(pool: &PgPool, token_hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO used_tokens (token_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Clean up expired keys and old used tokens (> 24 hours).
pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    // Use raw_sql to avoid prepared statement issues with PgBouncer
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S%.6f+00").to_string();
    let yesterday = (Utc::now() - Duration::hours(24))
        .format("%Y-%m-%d %H:%M:%S%.6f+00")
        .to_string();

    let keys_result = sqlx::raw_sql(&format!("DELETE FROM keys WHERE expires_at <= '{}'", now))
        .execute(pool)
        .await?;

    let tokens_result = sqlx::raw_sql(&format!(
        "DELETE FROM used_tokens WHERE used_at <= '{}'",
        yesterday
    ))
    .execute(pool)
    .await?;

    let total = keys_result.rows_affected() + tokens_result.rows_affected();

    if total > 0 {
        tracing::info!(
            "Cleanup: {} expired keys, {} old tokens removed",
            keys_result.rows_affected(),
            tokens_result.rows_affected()
        );
    }

    Ok(total)
}
