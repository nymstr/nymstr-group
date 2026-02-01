//! Rate limiting for authentication endpoints.
//!
//! Provides a sliding window rate limiter to prevent brute-force attacks.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Sliding window rate limiter to prevent brute-force attacks on authentication endpoints.
/// Tracks attempts per sender_tag within a configurable time window.
pub struct RateLimiter {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: usize,
    window_secs: u64,
}

impl RateLimiter {
    /// Create a new rate limiter with specified limits.
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window_secs,
        }
    }

    /// Check if a request is allowed and record the attempt.
    /// Returns true if allowed, false if rate limited.
    pub fn check_and_record(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);

        let attempts = self.attempts.entry(key.to_string()).or_default();
        // Remove old attempts outside the window
        attempts.retain(|&t| now.duration_since(t) < window);

        if attempts.len() >= self.max_attempts {
            return false; // Rate limited
        }

        attempts.push(now);
        true // Allowed
    }

    /// Remove empty entries to prevent memory growth.
    pub fn cleanup(&mut self) {
        self.attempts.retain(|_, v| !v.is_empty());
    }
}
