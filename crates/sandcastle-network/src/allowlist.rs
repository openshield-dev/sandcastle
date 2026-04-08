//! Domain allowlist management for network filtering.

use serde::{Deserialize, Serialize};

/// An individual entry in a domain allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    /// Domain pattern — supports simple glob syntax (e.g. `*.github.com`).
    pub pattern: String,
    /// Human-readable description of why this domain is allowed.
    pub description: Option<String>,
    /// Maximum requests per minute allowed to this domain.
    pub max_rate: Option<u32>,
    /// Maximum bytes per second allowed to this domain.
    pub max_bandwidth: Option<u64>,
}

/// Manages a collection of allowed domains for network filtering.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainAllowlist {
    pub domains: Vec<AllowlistEntry>,
}

impl DomainAllowlist {
    /// Create an empty allowlist.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pattern to the allowlist.
    pub fn add(&mut self, pattern: String, description: Option<String>) {
        self.domains.push(AllowlistEntry {
            pattern,
            description,
            max_rate: None,
            max_bandwidth: None,
        });
    }

    /// Remove a pattern from the allowlist.  Returns `true` if an entry was removed.
    pub fn remove(&mut self, pattern: &str) -> bool {
        let before = self.domains.len();
        self.domains.retain(|e| e.pattern != pattern);
        self.domains.len() < before
    }

    /// Return the first [`AllowlistEntry`] whose pattern matches `domain`, or `None`.
    pub fn matches(&self, domain: &str) -> Option<&AllowlistEntry> {
        self.domains.iter().find(|e| glob_match(&e.pattern, domain))
    }

    /// Return `true` when the allowlist contains no entries.
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    // ── Pre-built allowlists ─────────────────────────────────────────────────

    /// Allowlist covering major package registries.
    pub fn package_registries() -> Self {
        let mut list = Self::new();
        for (pattern, desc) in [
            ("registry.npmjs.org", "npm registry"),
            ("*.npmjs.com", "npm CDN"),
            ("pypi.org", "Python Package Index"),
            ("*.pypi.org", "PyPI CDN"),
            ("files.pythonhosted.org", "PyPI file host"),
            ("crates.io", "Rust package registry"),
            ("static.crates.io", "crates.io CDN"),
            ("pkg.go.dev", "Go module proxy"),
            ("sum.golang.org", "Go checksum database"),
        ] {
            list.add(pattern.into(), Some(desc.into()));
        }
        list
    }

    /// Allowlist covering common AI API endpoints.
    pub fn ai_apis() -> Self {
        let mut list = Self::new();
        for (pattern, desc) in [
            ("api.openai.com", "OpenAI API"),
            ("api.anthropic.com", "Anthropic API"),
            ("generativelanguage.googleapis.com", "Google Gemini API"),
            ("api.cohere.com", "Cohere API"),
            ("api.mistral.ai", "Mistral API"),
        ] {
            list.add(pattern.into(), Some(desc.into()));
        }
        list
    }

    /// Allowlist covering common development hosts.
    pub fn development() -> Self {
        let mut list = Self::new();
        for (pattern, desc) in [
            ("github.com", "GitHub"),
            ("*.github.com", "GitHub subdomains"),
            ("*.githubusercontent.com", "GitHub raw content"),
            ("gitlab.com", "GitLab"),
            ("*.gitlab.com", "GitLab subdomains"),
            ("stackoverflow.com", "Stack Overflow"),
            ("*.stackoverflow.com", "Stack Overflow subdomains"),
            ("docs.rs", "Rust documentation"),
            ("doc.rust-lang.org", "Official Rust docs"),
        ] {
            list.add(pattern.into(), Some(desc.into()));
        }
        list
    }
}

/// Match `domain` against a simple glob `pattern`.
///
/// - `"*"` matches any domain.
/// - `"*.example.com"` matches any direct subdomain of `example.com` at the
///   label level — i.e., only domains whose trailing labels exactly equal
///   `example.com`.  This prevents bypass attacks like `evil.com.example.com`
///   matching a pattern for `*.com`.
/// - All other patterns are exact (case-insensitive) comparisons.
fn glob_match(pattern: &str, domain: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let p = pattern.to_lowercase();
    let d = domain.to_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        // Split both into DNS labels and compare at the label level.
        // `*.example.com` has suffix labels ["example", "com"].
        // The domain must have strictly more labels, and its trailing labels
        // must equal the suffix labels exactly — preventing string-suffix
        // tricks like `evil.com.example.com` matching `*.com`.
        let suffix_labels: Vec<&str> = suffix.split('.').collect();
        let domain_labels: Vec<&str> = d.split('.').collect();

        // Domain must have exactly one more label than the suffix so that
        // `*.example.com` matches `api.example.com` but NOT `a.b.example.com`.
        if domain_labels.len() != suffix_labels.len() + 1 {
            return false;
        }

        let trailing = &domain_labels[domain_labels.len() - suffix_labels.len()..];
        trailing == suffix_labels.as_slice()
    } else {
        p == d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_match() {
        let mut list = DomainAllowlist::new();
        list.add("*.example.com".into(), Some("test".into()));
        assert!(list.matches("api.example.com").is_some());
        assert!(list.matches("example.com").is_none());
    }

    #[test]
    fn remove_entry() {
        let mut list = DomainAllowlist::new();
        list.add("crates.io".into(), None);
        assert!(list.remove("crates.io"));
        assert!(list.is_empty());
        assert!(!list.remove("crates.io"));
    }

    #[test]
    fn package_registries_not_empty() {
        assert!(!DomainAllowlist::package_registries().is_empty());
    }
}
