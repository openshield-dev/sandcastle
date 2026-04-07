//! DNS resolution interceptor that enforces domain allowlists.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::error::NetworkError;

/// DNS resolution interceptor that checks domains against an allowlist before resolving.
#[derive(Debug)]
pub struct DnsInterceptor {
    /// Cached DNS resolutions: domain → resolved IPs.
    cache: HashMap<String, Vec<IpAddr>>,
    /// Allowed domains (simple glob patterns, e.g. `*.github.com`).
    allowed_domains: Vec<String>,
    /// Blocked domains — takes precedence over allowed.
    blocked_domains: Vec<String>,
    /// Cache hit counter.
    cache_hits: u64,
    /// Cache miss counter.
    cache_misses: u64,
}

impl DnsInterceptor {
    /// Create a new interceptor with the given allow/block lists.
    pub fn new(allowed: Vec<String>, blocked: Vec<String>) -> Self {
        Self {
            cache: HashMap::new(),
            allowed_domains: allowed,
            blocked_domains: blocked,
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Resolve `domain` to IP addresses, enforcing the allowlist/blocklist.
    ///
    /// Resolution order:
    /// 1. Reject if domain matches the blocklist.
    /// 2. Reject if the allowlist is non-empty and domain does not match it.
    /// 3. Return cached IPs if present.
    /// 4. Perform a stub resolution (loopback) and cache the result.
    pub fn resolve(&mut self, domain: &str) -> Result<Vec<IpAddr>, NetworkError> {
        // 1. Blocked list takes precedence.
        if self.matches_any(domain, &self.blocked_domains.clone()) {
            return Err(NetworkError::DomainBlocked(domain.to_string()));
        }

        // 2. If an allowlist is configured, domain must be on it.
        if !self.allowed_domains.is_empty()
            && !self.matches_any(domain, &self.allowed_domains.clone())
        {
            return Err(NetworkError::DomainBlocked(domain.to_string()));
        }

        // 3. Return cached result.
        if let Some(ips) = self.cache.get(domain) {
            self.cache_hits += 1;
            return Ok(ips.clone());
        }

        // 4. Stub resolution — real async resolution via hickory-resolver would live here.
        self.cache_misses += 1;
        let ips: Vec<IpAddr> = vec![IpAddr::from([127, 0, 0, 1])];
        self.cache.insert(domain.to_string(), ips.clone());
        Ok(ips)
    }

    /// Return `true` if `domain` is allowed without actually resolving it.
    pub fn is_allowed(&self, domain: &str) -> bool {
        if self.matches_any(domain, &self.blocked_domains) {
            return false;
        }
        if self.allowed_domains.is_empty() {
            return true;
        }
        self.matches_any(domain, &self.allowed_domains)
    }

    /// Evict all cached DNS entries.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Return a snapshot of cache statistics.
    pub fn cache_stats(&self) -> DnsCacheStats {
        DnsCacheStats {
            entries: self.cache.len(),
            hits: self.cache_hits,
            misses: self.cache_misses,
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Return `true` if `domain` matches any pattern in `patterns`.
    ///
    /// Supported glob syntax:
    /// - `*` at the start of a pattern (e.g. `*.github.com`) matches any
    ///   single label prefix.
    /// - `*` alone matches every domain.
    fn matches_any(&self, domain: &str, patterns: &[String]) -> bool {
        patterns.iter().any(|p| glob_match(p, domain))
    }
}

/// Match `domain` against a simple glob `pattern`.
///
/// Rules:
/// - `"*"` matches everything.
/// - `"*.example.com"` matches `foo.example.com` but **not** `example.com`
///   itself.
/// - Everything else is an exact case-insensitive comparison.
fn glob_match(pattern: &str, domain: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let pattern_lower = pattern.to_lowercase();
    let domain_lower = domain.to_lowercase();

    if let Some(suffix) = pattern_lower.strip_prefix("*.") {
        // `*.example.com` — domain must end with `.example.com` but NOT be `example.com` itself.
        domain_lower.ends_with(&format!(".{suffix}"))
    } else {
        pattern_lower == domain_lower
    }
}

/// Snapshot of DNS cache activity.
#[derive(Debug, Clone)]
pub struct DnsCacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matches_subdomain() {
        assert!(glob_match("*.github.com", "api.github.com"));
        assert!(glob_match("*.github.com", "raw.github.com"));
        assert!(!glob_match("*.github.com", "github.com"));
        assert!(!glob_match("*.github.com", "notgithub.com"));
    }

    #[test]
    fn star_matches_all() {
        assert!(glob_match("*", "anything.example.com"));
    }

    #[test]
    fn exact_match() {
        assert!(glob_match("crates.io", "crates.io"));
        assert!(!glob_match("crates.io", "api.crates.io"));
    }

    #[test]
    fn blocked_domain_rejected() {
        let mut dns = DnsInterceptor::new(
            vec!["*.example.com".into()],
            vec!["bad.example.com".into()],
        );
        assert!(dns.resolve("bad.example.com").is_err());
        assert!(dns.resolve("good.example.com").is_ok());
    }

    #[test]
    fn allowlist_blocks_unknown_domain() {
        let mut dns =
            DnsInterceptor::new(vec!["api.openai.com".into()], vec![]);
        assert!(dns.resolve("api.openai.com").is_ok());
        assert!(dns.resolve("evil.example.com").is_err());
    }
}
