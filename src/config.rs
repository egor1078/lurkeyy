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
        let mut missing = Vec::new();

        let get_env = |key: &str, missing: &mut Vec<String>| -> String {
            match env::var(key) {
                Ok(val) => val,
                Err(_) => {
                    missing.push(key.to_string());
                    String::new()
                }
            }
        };

        let supabase_url = get_env("SUPABASE_URL", &mut missing);
        let supabase_key = get_env("SUPABASE_KEY", &mut missing);
        let hmac_secret = get_env("HMAC_SECRET", &mut missing);
        let turnstile_secret = get_env("TURNSTILE_SECRET", &mut missing);
        let linkvertise_id = get_env("LINKVERTISE_ID", &mut missing);
        let base_url = get_env("BASE_URL", &mut missing);

        if !missing.is_empty() {
            eprintln!("\n❌ CRITICAL STARTUP ERROR:");
            eprintln!("The following required environment variables are missing:");
            for var in missing {
                eprintln!("  - {}", var);
            }
            eprintln!("\nPlease add these variables in your Render Dashboard -> Environment.");
            std::process::exit(1);
        }

        Self {
            supabase_url,
            supabase_key,
            hmac_secret,
            turnstile_secret,
            linkvertise_id,
            base_url,
            key_ttl_hours: env::var("KEY_TTL_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .unwrap_or(24),
            min_linkvertise_seconds: env::var("MIN_LINKVERTISE_SECONDS")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .unwrap_or(15),
            rate_limit_session: env::var("RATE_LIMIT_SESSION")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
            rate_limit_check: env::var("RATE_LIMIT_CHECK")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            port: env::var("PORT")
                .unwrap_or_else(|_| "10000".to_string())
                .parse()
                .unwrap_or(10000),
        }
    }
}
