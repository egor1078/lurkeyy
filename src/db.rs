use chrono::{Duration, Utc};
use reqwest::Client;

use crate::models::KeyRecord;

/// Supabase REST API client wrapper.
#[derive(Clone)]
pub struct SupabaseClient {
    client: Client,
    base_url: String,
    api_key: String,
}

impl SupabaseClient {
    pub fn new(supabase_url: &str, api_key: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: format!("{}/rest/v1", supabase_url.trim_end_matches('/')),
            api_key: api_key.to_string(),
        }
    }

    /// Build a request with Supabase auth headers.
    fn request(&self, method: reqwest::Method, table: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}/{}", self.base_url, table))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
    }

    /// Find an active (non-expired) key for the given HWID.
    pub async fn find_active_key(&self, hwid: &str) -> Result<Option<KeyRecord>, String> {
        let now = Utc::now().to_rfc3339();

        let resp = self
            .request(reqwest::Method::GET, "keys")
            .header("Accept", "application/json")
            .query(&[
                ("hwid", format!("eq.{}", hwid)),
                ("expires_at", format!("gt.{}", now)),
                ("limit", "1".to_string()),
            ])
            .send()
            .await
            .map_err(|e| format!("Supabase request failed: {}", e))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Supabase error: {}", text));
        }

        let records: Vec<KeyRecord> = resp
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        Ok(records.into_iter().next())
    }

    /// Insert a new key into the database.
    pub async fn insert_key(
        &self,
        hwid: &str,
        key_value: &str,
        ttl_hours: i64,
        ip_address: Option<&str>,
    ) -> Result<KeyRecord, String> {
        let now = Utc::now();
        let expires_at = now + Duration::hours(ttl_hours);

        // Delete any existing expired keys for this HWID first
        let _ = self
            .request(reqwest::Method::DELETE, "keys")
            .query(&[
                ("hwid", format!("eq.{}", hwid)),
                ("expires_at", format!("lte.{}", now.to_rfc3339())),
            ])
            .send()
            .await;

        let body = serde_json::json!({
            "hwid": hwid,
            "key_value": key_value,
            "expires_at": expires_at.to_rfc3339(),
            "ip_address": ip_address,
        });

        let resp = self
            .request(reqwest::Method::POST, "keys")
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Prefer", "return=representation")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Supabase insert failed: {}", e))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Supabase insert error: {}", text));
        }

        let records: Vec<KeyRecord> = resp
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        records
            .into_iter()
            .next()
            .ok_or_else(|| "No record returned from insert".to_string())
    }

    /// Check if a key is valid for the given HWID.
    pub async fn check_key_validity(
        &self,
        key: &str,
        hwid: &str,
    ) -> Result<(bool, Option<String>), String> {
        let resp = self
            .request(reqwest::Method::GET, "keys")
            .header("Accept", "application/json")
            .query(&[
                ("key_value", format!("eq.{}", key)),
                ("limit", "1".to_string()),
            ])
            .send()
            .await
            .map_err(|e| format!("Supabase request failed: {}", e))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Supabase error: {}", text));
        }

        let records: Vec<KeyRecord> = resp
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        match records.into_iter().next() {
            None => Ok((false, Some("invalid_key".to_string()))),
            Some(rec) => {
                if rec.hwid != hwid {
                    Ok((false, Some("wrong_hwid".to_string())))
                } else {
                    // Check expiration
                    let expires = chrono::DateTime::parse_from_rfc3339(&rec.expires_at)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());

                    if expires <= Utc::now() {
                        // Delete expired key
                        let _ = self
                            .request(reqwest::Method::DELETE, "keys")
                            .query(&[("key_value", format!("eq.{}", key))])
                            .send()
                            .await;
                        Ok((false, Some("expired".to_string())))
                    } else {
                        Ok((true, None))
                    }
                }
            }
        }
    }

    /// Check if a token hash has been used (replay protection).
    pub async fn is_token_used(&self, token_hash: &str) -> Result<bool, String> {
        let resp = self
            .request(reqwest::Method::GET, "used_tokens")
            .header("Accept", "application/json")
            .query(&[
                ("token_hash", format!("eq.{}", token_hash)),
                ("limit", "1".to_string()),
            ])
            .send()
            .await
            .map_err(|e| format!("Supabase request failed: {}", e))?;

        if !resp.status().is_success() {
            return Ok(false);
        }

        let records: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();
        Ok(!records.is_empty())
    }

    /// Mark a token hash as used.
    pub async fn mark_token_used(&self, token_hash: &str) -> Result<(), String> {
        let body = serde_json::json!({
            "token_hash": token_hash,
        });

        let resp = self
            .request(reqwest::Method::POST, "used_tokens")
            .header("Content-Type", "application/json")
            .header("Prefer", "resolution=ignore-duplicates")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Supabase insert failed: {}", e))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!("Failed to mark token as used: {}", text);
        }

        Ok(())
    }

    /// Clean up expired keys and old used tokens.
    pub async fn cleanup_expired(&self) -> Result<u64, String> {
        let now = Utc::now().to_rfc3339();
        let yesterday = (Utc::now() - Duration::hours(24)).to_rfc3339();

        let _ = self
            .request(reqwest::Method::DELETE, "keys")
            .query(&[("expires_at", format!("lte.{}", now))])
            .send()
            .await;

        let _ = self
            .request(reqwest::Method::DELETE, "used_tokens")
            .query(&[("used_at", format!("lte.{}", yesterday))])
            .send()
            .await;

        Ok(0)
    }
}
