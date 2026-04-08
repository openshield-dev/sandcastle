//! DNS resolution interceptor that enforces domain allowlists.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::error::NetworkError;

/// Time-to-live for DNS cache entries.
const DNS_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// A cached DNS resolution result with an expiration timestamp.
#[derive(Debug, Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    inserted_at: Instant,
}

/// DNS resolution interceptor that checks domains against an allowlist before resolving.
#[derive(Debug)]
pub struct DnsInterceptor {
    /// Cached DNS resolutions: domain → resolved IPs with TTL.
    cache: HashMap<String, CacheEntry>,
    /// Allowed domains (simple glob patterns, e.g. `*.github.com`).
    allowed_domains: Vec<String>,
    /// Blocked domains — takes precedence over allowed.
    blocked_domains: Vec<String>,
    /// Cache hit counter.
    cache_hits: u64,
    /// Cache miss counter.
    cache_misses: u64,
    /// Cache expired counter.
    cache_expired: u64,
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
            cache_expired: 0,
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

        // 3. Return cached result if still valid.
        if let Some(entry) = self.cache.get(domain) {
            if entry.inserted_at.elapsed() < DNS_CACHE_TTL {
                self.cache_hits += 1;
                return Ok(entry.ips.clone());
            }
            // Entry expired — will re-resolve below.
            self.cache_expired += 1;
        }

        // 4. Perform real DNS resolution via hickory-resolver.
        self.cache_misses += 1;

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| NetworkError::DnsResolutionFailed(format!("failed to create runtime: {e}")))?;

        let response = rt.block_on(resolver.lookup_ip(domain))
            .map_err(|e| NetworkError::DnsResolutionFailed(format!("DNS lookup failed for {domain}: {e}")))?;

        let ips: Vec<IpAddr> = response.iter().collect();
        if ips.is_empty() {
            return Err(NetworkError::DnsResolutionFailed(format!(
                "no addresses found for {domain}"
            )));
        }

        // 5. Reject any resolved IP that falls in a private or reserved range
        //    to prevent SSRF / cloud-metadata attacks.
        for ip in &ips {
            if is_private_or_reserved(ip) {
                return Err(NetworkError::DomainBlocked(format!(
                    "{domain} resolves to private/reserved address {ip}"
                )));
            }
        }

        self.cache.insert(domain.to_string(), CacheEntry {
            ips: ips.clone(),
            inserted_at: Instant::now(),
        });
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
            expired: self.cache_expired,
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
    pub expired: u64,
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
        let dns = DnsInterceptor::new(
            vec!["*.example.com".into()],
            vec!["bad.example.com".into()],
        );
        // Use is_allowed() to test blocklist logic without real DNS
        assert!(!dns.is_allowed("bad.example.com"));
        assert!(dns.is_allowed("good.example.com"));
    }

    #[test]
    fn allowlist_blocks_unknown_domain() {
        let dns =
            DnsInterceptor::new(vec!["api.openai.com".into()], vec![]);
        assert!(dns.is_allowed("api.openai.com"));
        assert!(!dns.is_allowed("evil.example.com"));
    }
}
