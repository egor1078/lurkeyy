use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::Rng;

use crate::models::SessionClaims;

/// Create an HMAC-SHA256 signed JWT session token.
///
/// The token embeds the HWID, client IP, and timestamps.
/// It expires after 10 minutes (enough time for Linkvertise flow).
pub fn create_session_token(
    hwid: &str,
    ip: &str,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = SessionClaims {
        hwid: hwid.to_string(),
        ip: ip.to_string(),
        iat: now,
        exp: now + 600, // 10 minute expiry
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Verify and decode a session token.
///
/// Returns the claims if the signature is valid and the token hasn't expired.
pub fn verify_session_token(
    token: &str,
    secret: &str,
) -> Result<SessionClaims, jsonwebtoken::errors::Error> {
    let token_data = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

/// Generate a cryptographically random key in format `LURK-XXXX-XXXX-XXXX`.
///
/// Uses alphanumeric uppercase characters for readability.
pub fn generate_key() -> String {
    let mut rng = rand::thread_rng();
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let segment = |rng: &mut rand::rngs::ThreadRng| -> String {
        (0..4)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset[idx] as char
            })
            .collect()
    };

    format!(
        "LURK-{}-{}-{}",
        segment(&mut rng),
        segment(&mut rng),
        segment(&mut rng)
    )
}

/// Hash a token for storage in the `used_tokens` table (replay protection).
///
/// Uses SHA-256 so we never store raw tokens in the database.
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
