use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TurnstileResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

/// Verify a Cloudflare Turnstile captcha token server-side.
///
/// Returns `true` if the token is valid, `false` otherwise.
pub async fn verify_turnstile(
    secret: &str,
    token: &str,
    remote_ip: Option<&str>,
) -> Result<bool, reqwest::Error> {
    let client = Client::new();

    let mut params = vec![("secret", secret), ("response", token)];

    if let Some(ip) = remote_ip {
        params.push(("remoteip", ip));
    }

    let response = client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&params)
        .send()
        .await?
        .json::<TurnstileResponse>()
        .await?;

    if !response.success {
        if let Some(errors) = &response.error_codes {
            tracing::warn!("Turnstile verification failed: {:?}", errors);
        }
    }

    Ok(response.success)
}
