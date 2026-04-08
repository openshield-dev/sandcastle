//! Egress control — rate limiting, bandwidth caps, and per-domain accounting.

use std::collections::HashMap;
use std::time::Instant;

use crate::error::NetworkError;

/// Tracks request rate for a single domain.
#[derive(Debug)]
struct RequestCounter {
    /// Total lifetime requests to this domain.
    total: u64,
    /// Requests within the current one-minute window.
    window_count: u32,
    /// Start of the current one-minute window.
    window_start: Instant,
    /// Optional cap: maximum requests per minute.
    max_per_minute: Option<u32>,
}

impl RequestCounter {
    fn new(max_per_minute: Option<u32>) -> Self {
        Self {
            total: 0,
            window_count: 0,
            window_start: Instant::now(),
            max_per_minute,
        }
    }

    /// Record one request and return `Err` if the rate limit is exceeded.
    fn record(&mut self, domain: &str) -> Result<(), NetworkError> {
        // Reset the window if a minute has elapsed.
        if self.window_start.elapsed().as_secs() >= 60 {
            self.window_count = 0;
            self.window_start = Instant::now();
        }

        if let Some(max) = self.max_per_minute {
            if self.window_count >= max {
                return Err(NetworkError::RateLimitExceeded(domain.to_string()));
            }
        }

        self.total += 1;
        self.window_count += 1;

        Ok(())
    }
}

/// Controls outbound network connections with rate limiting and bandwidth caps.
#[derive(Debug)]
pub struct EgressController {
    /// When `true`, connections to domains without explicit rate-limit entries are denied.
    pub default_deny: bool,
    /// Per-domain request tracking.
    request_counts: HashMap<String, RequestCounter>,
    /// Cumulative bytes transferred across all domains.
    total_bytes: u64,
    /// Hard cap on cumulative bytes (data-exfiltration prevention).
    max_total_bytes: Option<u64>,
}

impl EgressController {
    /// Create a new controller with the given default policy.
    pub fn new(default_deny: bool) -> Self {
        Self {
            default_deny,
            request_counts: HashMap::new(),
            total_bytes: 0,
            max_total_bytes: None,
        }
    }

    /// Check whether an outbound connection is permitted, and record the request.
    ///
    /// Returns `Err` if:
    /// - The bandwidth cap would be exceeded.
    /// - The per-domain rate limit would be exceeded.
    /// - `default_deny` is `true` and the domain has no entry.
    pub fn check_egress(
        &mut self,
        domain: &str,
        _port: u16,
        bytes: u64,
    ) -> Result<(), NetworkError> {
        // 1. Global bandwidth cap check.
        if let Some(max) = self.max_total_bytes {
            if self.total_bytes.saturating_add(bytes) > max {
                return Err(NetworkError::BandwidthExceeded);
            }
        }

        // 2. Per-domain rate limit check.
        if self.default_deny && !self.request_counts.contains_key(domain) {
            return Err(NetworkError::EgressDenied {
                protocol: "tcp".into(),
                destination: domain.to_string(),
            });
        }

        let counter = self
            .request_counts
            .entry(domain.to_string())
            .or_insert_with(|| RequestCounter::new(None));

        counter.record(domain)?;

        // Update total_bytes immediately so the accounting is atomic —
        // prevents a gap where concurrent checks could exceed the cap.
        self.total_bytes = self.total_bytes.saturating_add(bytes);

        Ok(())
    }

    /// Record bytes transferred for a domain after a connection completes.
    pub fn record_transfer(&mut self, domain: &str, bytes: u64) -> Result<(), NetworkError> {
        if let Some(max) = self.max_total_bytes {
            if self.total_bytes.saturating_add(bytes) > max {
                return Err(NetworkError::BandwidthExceeded);
            }
        }
        self.total_bytes = self.total_bytes.saturating_add(bytes);

        // Ensure an entry exists so the domain appears in stats.
        self.request_counts
            .entry(domain.to_string())
            .or_insert_with(|| RequestCounter::new(None));

        Ok(())
    }

    /// Configure a per-minute request cap for `domain`.
    pub fn set_rate_limit(&mut self, domain: &str, max_per_minute: u32) {
        let counter = self
            .request_counts
            .entry(domain.to_string())
            .or_insert_with(|| RequestCounter::new(None));
        counter.max_per_minute = Some(max_per_minute);
    }

    /// Set a hard cap on the total bytes this controller will allow.
    pub fn set_bandwidth_limit(&mut self, max_bytes: u64) {
        self.max_total_bytes = Some(max_bytes);
    }

    /// Return a point-in-time snapshot of egress statistics.
    pub fn stats(&self) -> EgressStats {
        let requests_by_domain = self
            .request_counts
            .iter()
            .map(|(domain, counter)| (domain.clone(), counter.total))
            .collect();

        EgressStats {
            total_bytes: self.total_bytes,
            requests_by_domain,
        }
    }
}

/// Snapshot of egress activity.
#[derive(Debug, Clone)]
pub struct EgressStats {
    pub total_bytes: u64,
    pub requests_by_domain: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_limit_enforced() {
        let mut ctrl = EgressController::new(false);
        ctrl.set_bandwidth_limit(100);
        assert!(ctrl.check_egress("example.com", 80, 50).is_ok());
        ctrl.record_transfer("example.com", 50).unwrap();
        assert!(ctrl.check_egress("example.com", 80, 100).is_err());
    }

    #[test]
    fn rate_limit_enforced() {
        let mut ctrl = EgressController::new(false);
        ctrl.set_rate_limit("example.com", 2);
        assert!(ctrl.check_egress("example.com", 80, 0).is_ok());
        assert!(ctrl.check_egress("example.com", 80, 0).is_ok());
        assert!(ctrl.check_egress("example.com", 80, 0).is_err());
    }

    #[test]
    fn default_deny_blocks_unknown() {
        let mut ctrl = EgressController::new(true);
        assert!(ctrl.check_egress("unknown.com", 443, 0).is_err());
        // After adding a rate-limit entry the domain is known.
        ctrl.set_rate_limit("known.com", 100);
        assert!(ctrl.check_egress("known.com", 443, 0).is_ok());
    }
}
