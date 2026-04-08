//! High-level network filter — orchestrates DNS, allowlist, egress, and TLS checks.

use sandcastle_policy::permission::Permissions;

use crate::{
    allowlist::DomainAllowlist,
    dns::{DnsCacheStats, DnsInterceptor},
    egress::{EgressController, EgressStats},
    error::NetworkError,
    tls::TlsVerifier,
};

/// Orchestrates all network filtering components for a single sandbox.
#[derive(Debug)]
pub struct NetworkFilter {
    pub dns: DnsInterceptor,
    pub allowlist: DomainAllowlist,
    pub egress: EgressController,
    pub tls: TlsVerifier,
    /// Running count of requests blocked by this filter.
    blocked_requests: u64,
    /// Running count of requests allowed by this filter.
    allowed_requests: u64,
}

impl NetworkFilter {
    /// Build a `NetworkFilter` from sandbox [`Permissions`].
    ///
    /// - Allowed/blocked domain lists are taken directly from `NetworkPermissions`.
    /// - `default_deny` is set to `true` when the allowlist is non-empty (allowlist-mode),
    ///   so any domain not on the list is rejected by the egress controller.
    pub fn from_permissions(permissions: &Permissions) -> Self {
        let net = &permissions.network;

        let allowlist = {
            let mut list = DomainAllowlist::new();
            for domain in &net.allow_domains {
                list.add(domain.clone(), None);
            }
            list
        };

        let dns = DnsInterceptor::new(
            net.allow_domains.clone(),
            net.deny_domains.clone(),
        );

        // When an explicit allowlist is configured, unknown domains are denied by default.
        let default_deny = !net.allow_domains.is_empty()
            && !net.allow_domains.iter().any(|d| d == "*");

        let mut egress = EgressController::new(default_deny);

        // Pre-register every allowed domain so the egress controller recognises them
        // even in default-deny mode.  A generous rate limit is used as a starting point;
        // callers can tighten it with `EgressController::set_rate_limit`.
        for domain in &net.allow_domains {
            egress.set_rate_limit(domain, u32::MAX);
        }
        let tls = TlsVerifier::new(true);

        Self {
            dns,
            allowlist,
            egress,
            tls,
            blocked_requests: 0,
            allowed_requests: 0,
        }
    }

    /// Decide whether a network request should be allowed.
    ///
    /// Checks are applied in this order:
    /// 1. Allowlist — domain must match (if a non-wildcard allowlist is configured).
    /// 2. DNS — domain must resolve (also enforces blocklist).
    /// 3. Egress — rate and bandwidth limits are checked.
    /// 4. TLS — SNI verification is performed for port 443.
    pub fn check_request(
        &mut self,
        domain: &str,
        port: u16,
        bytes: u64,
    ) -> Result<(), NetworkError> {
        // 1. Allowlist check.
        if !self.allowlist.is_empty() && self.allowlist.matches(domain).is_none() {
            self.blocked_requests += 1;
            return Err(NetworkError::DomainBlocked(domain.to_string()));
        }

        // 2. DNS check (also enforces the blocklist).
        self.dns.resolve(domain).map_err(|e| {
            self.blocked_requests += 1;
            e
        })?;

        // 3. Egress check.
        self.egress.check_egress(domain, port, bytes).map_err(|e| {
            self.blocked_requests += 1;
            e
        })?;

        // 4. TLS SNI verification for HTTPS connections.
        // NOTE: In a real implementation, `actual_sni` should come from the TLS
        // handshake, not from the `domain` parameter.  Verify on all HTTPS
        // connections regardless of port — HTTPS can run on non-443 ports.
        self.tls.verify_sni(domain, domain).map_err(|e| {
            self.blocked_requests += 1;
            e
        })?;

        // 5. TLS version enforcement (uses the verifier's configured minimum).
        //    In production, the negotiated version would come from the TLS handshake.
        //    Here we enforce TLS 1.2 as the default minimum.
        self.tls
            .check_version(crate::tls::TlsVersion::Tls12)
            .map_err(|e| {
                self.blocked_requests += 1;
                e
            })?;

        self.allowed_requests += 1;
        Ok(())
    }

    /// Return a combined statistics snapshot.
    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            dns_cache: self.dns.cache_stats(),
            egress: self.egress.stats(),
            blocked_requests: self.blocked_requests,
            allowed_requests: self.allowed_requests,
        }
    }
}

/// Combined statistics from all filtering components.
#[derive(Debug)]
pub struct NetworkStats {
    pub dns_cache: DnsCacheStats,
    pub egress: EgressStats,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandcastle_policy::permission::{NetworkPermissions, Permissions};

    fn make_permissions(allow: Vec<String>, deny: Vec<String>) -> Permissions {
        Permissions {
            network: NetworkPermissions {
                allow_domains: allow,
                deny_domains: deny,
                max_bandwidth: None,
            },
            ..Default::default()
        }
    }

    #[test]
    fn allowed_domain_passes() {
        let perms = make_permissions(vec!["api.openai.com".into()], vec![]);
        let mut filter = NetworkFilter::from_permissions(&perms);
        assert!(filter.check_request("api.openai.com", 443, 0).is_ok());
    }

    #[test]
    fn unlisted_domain_blocked() {
        let perms = make_permissions(vec!["api.openai.com".into()], vec![]);
        let mut filter = NetworkFilter::from_permissions(&perms);
        assert!(filter.check_request("evil.example.com", 80, 0).is_err());
    }

    #[test]
    fn empty_allowlist_allows_all() {
        let perms = make_permissions(vec![], vec![]);
        let mut filter = NetworkFilter::from_permissions(&perms);
        assert!(filter.check_request("any.domain.example", 80, 0).is_ok());
    }

    #[test]
    fn stats_tracked() {
        let perms = make_permissions(vec!["ok.com".into()], vec![]);
        let mut filter = NetworkFilter::from_permissions(&perms);
        filter.check_request("ok.com", 80, 0).ok();
        filter.check_request("bad.com", 80, 0).ok();
        let s = filter.stats();
        assert_eq!(s.allowed_requests, 1);
        assert_eq!(s.blocked_requests, 1);
    }
}
