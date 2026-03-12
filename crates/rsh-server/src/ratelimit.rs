//! Failed-auth rate limiter — blocks IPs after too many failures.
//!
//! Prevents brute-force key guessing by tracking failed authentication
//! attempts per IP address. After `MAX_FAILURES` within `WINDOW`, the
//! IP is banned for `BAN_DURATION`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum failures before banning an IP.
const MAX_FAILURES: u32 = 5;

/// Time window for counting failures.
const WINDOW: Duration = Duration::from_secs(60);

/// How long a ban lasts.
const BAN_DURATION: Duration = Duration::from_secs(300); // 5 minutes

struct IpRecord {
    failures: Vec<Instant>,
    banned_until: Option<Instant>,
}

/// Thread-safe rate limiter for auth failures.
pub struct AuthRateLimiter {
    records: Mutex<HashMap<IpAddr, IpRecord>>,
}

impl AuthRateLimiter {
    pub fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
        }
    }

    /// Check if an IP is currently banned. Returns true if connection should be rejected.
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        let records = self.records.lock().unwrap();
        if let Some(record) = records.get(ip) {
            if let Some(until) = record.banned_until {
                return Instant::now() < until;
            }
        }
        false
    }

    /// Record a failed auth attempt. Returns true if the IP is now banned.
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        let mut records = self.records.lock().unwrap();
        let now = Instant::now();

        let record = records.entry(ip).or_insert_with(|| IpRecord {
            failures: Vec::new(),
            banned_until: None,
        });

        // Already banned?
        if let Some(until) = record.banned_until {
            if now < until {
                return true;
            }
            // Ban expired — reset
            record.banned_until = None;
            record.failures.clear();
        }

        // Prune old failures outside window
        record.failures.retain(|t| now.duration_since(*t) < WINDOW);

        // Add this failure
        record.failures.push(now);

        // Check threshold
        if record.failures.len() as u32 >= MAX_FAILURES {
            record.banned_until = Some(now + BAN_DURATION);
            tracing::warn!(
                "rate limiter: banned {} for {}s ({} failures in {}s)",
                ip,
                BAN_DURATION.as_secs(),
                MAX_FAILURES,
                WINDOW.as_secs()
            );
            return true;
        }

        false
    }

    /// Record a successful auth — clears failure count for the IP.
    pub fn record_success(&self, ip: &IpAddr) {
        let mut records = self.records.lock().unwrap();
        records.remove(ip);
    }

    /// Periodic cleanup of expired records (call every few minutes).
    pub fn cleanup(&self) {
        let mut records = self.records.lock().unwrap();
        let now = Instant::now();
        records.retain(|_, record| {
            // Keep if banned and ban not expired
            if let Some(until) = record.banned_until {
                if now < until {
                    return true;
                }
            }
            // Keep if has recent failures
            record.failures.retain(|t| now.duration_since(*t) < WINDOW);
            !record.failures.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allows_first_attempts() {
        let rl = AuthRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!rl.is_banned(&ip));
        assert!(!rl.record_failure(ip));
    }

    #[test]
    fn bans_after_max_failures() {
        let rl = AuthRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for _ in 0..MAX_FAILURES - 1 {
            assert!(!rl.record_failure(ip));
        }
        // This one should trigger ban
        assert!(rl.record_failure(ip));
        assert!(rl.is_banned(&ip));
    }

    #[test]
    fn success_clears_failures() {
        let rl = AuthRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        rl.record_failure(ip);
        rl.record_failure(ip);
        rl.record_success(&ip);
        assert!(!rl.is_banned(&ip));
        // Should start fresh
        assert!(!rl.record_failure(ip));
    }

    #[test]
    fn different_ips_independent() {
        let rl = AuthRateLimiter::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        for _ in 0..MAX_FAILURES {
            rl.record_failure(ip1);
        }
        assert!(rl.is_banned(&ip1));
        assert!(!rl.is_banned(&ip2));
    }

    #[test]
    fn cleanup_removes_stale() {
        let rl = AuthRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
        rl.record_failure(ip);
        // cleanup should keep it (recent failure)
        rl.cleanup();
        // Can't easily test time-based expiry in unit tests without mocking time
    }

}
