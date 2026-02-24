use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Sliding-window rate limiter keyed by IP address.
///
/// Tracks request timestamps per IP and rejects requests
/// exceeding the configured limit within a 60-second window.
#[derive(Clone)]
pub struct RateLimiter {
    /// Maps IP -> list of request timestamps
    requests: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    /// Maximum requests allowed per window
    max_requests: u32,
    /// Window duration (60 seconds)
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests: max_requests_per_minute,
            window: Duration::from_secs(60),
        }
    }

    /// Check if a request from the given IP is allowed.
    ///
    /// Returns `true` if within limits, `false` if rate-limited.
    /// Automatically cleans up old entries.
    pub async fn check(&self, ip: IpAddr) -> bool {
        let mut map = self.requests.lock().await;
        let now = Instant::now();
        let cutoff = now - self.window;

        let timestamps = map.entry(ip).or_default();

        // Remove timestamps outside the window
        timestamps.retain(|t| *t > cutoff);

        if timestamps.len() >= self.max_requests as usize {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Periodic cleanup of IPs with no recent requests.
    /// Call this from a background task.
    pub async fn cleanup(&self) {
        let mut map = self.requests.lock().await;
        let cutoff = Instant::now() - self.window;
        map.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}
