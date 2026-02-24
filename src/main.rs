mod config;
mod crypto;
mod db;
mod error;
mod models;
mod rate_limit;
mod routes;
mod turnstile;

use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    Router,
    routing::{get, post},
};
use sqlx::PgPool;
use tower_http::cors::{Any, CorsLayer};

use crate::config::AppConfig;
use crate::rate_limit::RateLimiter;

/// Shared application state injected into all handlers.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: AppConfig,
    pub session_limiter: RateLimiter,
    pub check_limiter: RateLimiter,
}

#[tokio::main]
async fn main() {
    // Load .env file (if present)
    dotenvy::dotenv().ok();

    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Load configuration
    let config = AppConfig::from_env();
    let port = config.port;

    tracing::info!("Starting LURK Key System backend...");

    // Initialize database
    let pool = db::init_pool(&config.database_url)
        .await
        .expect("Failed to connect to database");

    // Run migrations
    db::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    // Initialize rate limiters
    let session_limiter = RateLimiter::new(config.rate_limit_session);
    let check_limiter = RateLimiter::new(config.rate_limit_check);

    // Build application state
    let state = AppState {
        pool: pool.clone(),
        config,
        session_limiter: session_limiter.clone(),
        check_limiter: check_limiter.clone(),
    };

    // Spawn background cleanup tasks
    spawn_cleanup_tasks(pool, session_limiter, check_limiter);

    // CORS layer — allow requests from Roblox HTTP service
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build router
    let app = Router::new()
        // Key generation flow
        .route(
            "/api/start-session",
            post(routes::start_session::start_session),
        )
        .route("/verify", get(routes::verify::verify))
        // Roblox API
        .route("/api/check", get(routes::check_key::check_key))
        // Status
        .route("/api/status", get(routes::status::key_status))
        // Health check
        .route("/health", get(|| async { "OK" }))
        .layer(cors)
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("🚀 Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app).await.expect("Server error");
}

/// Spawn background tasks for periodic cleanup.
fn spawn_cleanup_tasks(pool: PgPool, session_limiter: RateLimiter, check_limiter: RateLimiter) {
    // Database cleanup: every 30 minutes, remove expired keys and old tokens
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1800));
        loop {
            interval.tick().await;
            match db::cleanup_expired(&pool).await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("Cleanup removed {} expired records", count);
                    }
                }
                Err(e) => tracing::error!("Cleanup error: {}", e),
            }
        }
    });

    // Rate limiter cleanup: every 5 minutes
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            session_limiter.cleanup().await;
            check_limiter.cleanup().await;
        }
    });
}
