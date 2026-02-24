use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub supabase_url: String,
    pub supabase_key: String,
    pub hmac_secret: String,
    pub turnstile_secret: String,
    pub linkvertise_id: String,
    pub base_url: String,
    pub key_ttl_hours: i64,
    pub min_linkvertise_seconds: i64,
    pub rate_limit_session: u32,
    pub rate_limit_check: u32,
    pub port: u16,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            supabase_url: env::var("SUPABASE_URL").expect("SUPABASE_URL must be set"),
            supabase_key: env::var("SUPABASE_KEY").expect("SUPABASE_KEY must be set"),
            hmac_secret: env::var("HMAC_SECRET").expect("HMAC_SECRET must be set"),
            turnstile_secret: env::var("TURNSTILE_SECRET").expect("TURNSTILE_SECRET must be set"),
            linkvertise_id: env::var("LINKVERTISE_ID").expect("LINKVERTISE_ID must be set"),
            base_url: env::var("BASE_URL").expect("BASE_URL must be set"),
            key_ttl_hours: env::var("KEY_TTL_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .expect("KEY_TTL_HOURS must be a number"),
            min_linkvertise_seconds: env::var("MIN_LINKVERTISE_SECONDS")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .expect("MIN_LINKVERTISE_SECONDS must be a number"),
            rate_limit_session: env::var("RATE_LIMIT_SESSION")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .expect("RATE_LIMIT_SESSION must be a number"),
            rate_limit_check: env::var("RATE_LIMIT_CHECK")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .expect("RATE_LIMIT_CHECK must be a number"),
            port: env::var("PORT")
                .unwrap_or_else(|_| "10000".to_string())
                .parse()
                .expect("PORT must be a number"),
        }
    }
}
