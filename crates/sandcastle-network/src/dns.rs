//! DNS resolution interceptor that enforces domain allowlists.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};

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
        if matches_any_pattern(domain, &self.blocked_domains) {
            return Err(NetworkError::DomainBlocked(domain.to_string()));
        }

        // 2. If an allowlist is configured, domain must be on it.
        if !self.allowed_domains.is_empty()
            && !matches_any_pattern(domain, &self.allowed_domains)
        {
            return Err(NetworkError::DomainBlocked(domain.to_string()));
        }

        // 3. Return cached result.
        if let Some(ips) = self.cache.get(domain) {
            self.cache_hits += 1;
            return Ok(ips.clone());
        }

        // 4. Stub resolution — real async resolution via hickory-resolver would live here.
        //    Uses a placeholder public IP; a real implementation would call the system
        //    resolver or hickory-resolver and return actual results.
        self.cache_misses += 1;
        let ips: Vec<IpAddr> = vec![IpAddr::from([93, 184, 216, 34])];

        // 5. Reject any resolved IP that falls in a private or reserved range
        //    to prevent SSRF / cloud-metadata attacks.
        for ip in &ips {
            if is_private_or_reserved(ip) {
                return Err(NetworkError::DomainBlocked(format!(
                    "{domain} resolves to private/reserved address {ip}"
                )));
            }
        }

        self.cache.insert(domain.to_string(), ips.clone());
        Ok(ips)
    }

    /// Return `true` if `domain` is allowed without actually resolving it.
    pub fn is_allowed(&self, domain: &str) -> bool {
        if matches_any_pattern(domain, &self.blocked_domains) {
            return false;
        }
        if self.allowed_domains.is_empty() {
            return true;
        }
        matches_any_pattern(domain, &self.allowed_domains)
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

}

/// Check if `domain` matches any of the given glob patterns.
fn matches_any_pattern(domain: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| glob_match(p, domain))
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
        // `*.example.com` — domain must have exactly one more label than the suffix,
        // preventing multi-label subdomain bypass (e.g. `a.b.example.com`).
        let suffix_labels: Vec<&str> = suffix.split('.').collect();
        let domain_labels: Vec<&str> = domain_lower.split('.').collect();

        if domain_labels.len() != suffix_labels.len() + 1 {
            return false;
        }

        let trailing = &domain_labels[domain_labels.len() - suffix_labels.len()..];
        trailing == suffix_labels.as_slice()
    } else {
        pattern_lower == domain_lower
    }
}

/// Check an IPv4 address (as raw octets) against all private/reserved ranges.
fn is_private_or_reserved_v4(octets: &[u8; 4]) -> bool {
    // 0.0.0.0/8 ("this" network)
    octets[0] == 0
    // 10.0.0.0/8
    || octets[0] == 10
    // 172.16.0.0/12
    || (octets[0] == 172 && (octets[1] & 0xf0) == 16)
    // 192.168.0.0/16
    || (octets[0] == 192 && octets[1] == 168)
    // 127.0.0.0/8 (loopback)
    || octets[0] == 127
    // 169.254.0.0/16 (link-local / cloud metadata)
    || (octets[0] == 169 && octets[1] == 254)
    // 224.0.0.0/4 (multicast) + 240.0.0.0/4 (reserved)
    || octets[0] >= 224
}

/// Return `true` if `ip` falls within a private, loopback, link-local, or other
/// reserved range.  Used to block SSRF and cloud-metadata attacks after DNS
/// resolution.
fn is_private_or_reserved(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_or_reserved_v4(&v4.octets()),
        IpAddr::V6(v6) => {
            // ::1 (loopback)
            *v6 == Ipv6Addr::LOCALHOST
            // ::ffff:0.0.0.0/96 (IPv4-mapped — check the mapped address too)
            || matches!(v6.to_ipv4_mapped(), Some(v4) if is_private_or_reserved_v4(&v4.octets()))
            // fe80::/10 (link-local)
            || (v6.segments()[0] & 0xffc0) == 0xfe80
            // fc00::/7 (Unique Local Addresses)
            || (v6.segments()[0] & 0xfe00) == 0xfc00
            // ff00::/8 (multicast)
            || (v6.segments()[0] & 0xff00) == 0xff00
        }
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
