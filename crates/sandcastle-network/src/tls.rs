//! TLS verification — SNI matching and minimum-version enforcement.

use crate::error::NetworkError;

/// Minimum acceptable TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsVersion::Tls12 => write!(f, "TLS 1.2"),
            TlsVersion::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

/// Verifies TLS connections to ensure SNI matches expected domains and that the
/// negotiated protocol version meets the configured minimum.
#[derive(Debug)]
pub struct TlsVerifier {
    /// When `false`, all checks are bypassed (useful for tests or plaintext-only sandboxes).
    pub enabled: bool,
    /// Minimum TLS version that is acceptable.
    pub min_version: TlsVersion,
}

impl TlsVerifier {
    /// Create a new verifier.  Defaults to TLS 1.2 as the minimum version.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            min_version: TlsVersion::Tls12,
        }
    }

    /// Verify that the SNI presented by a connection matches the expected domain.
    ///
    /// The check is case-insensitive.  Returns `Ok(())` when the verifier is
    /// disabled or when the SNI matches.
    pub fn verify_sni(
        &self,
        expected_domain: &str,
        actual_sni: &str,
    ) -> Result<(), NetworkError> {
        if !self.enabled {
            return Ok(());
        }
        if expected_domain.to_lowercase() != actual_sni.to_lowercase() {
            return Err(NetworkError::TlsVerificationFailed {
                domain: expected_domain.to_string(),
                reason: format!(
                    "SNI mismatch: expected `{}`, got `{}`",
                    expected_domain, actual_sni
                ),
            });
        }
        Ok(())
    }

    /// Return `Ok(())` if `version` meets or exceeds [`Self::min_version`].
    pub fn check_version(&self, version: TlsVersion) -> Result<(), NetworkError> {
        if !self.enabled {
            return Ok(());
        }
        if version < self.min_version {
            return Err(NetworkError::TlsVerificationFailed {
                domain: String::new(),
                reason: format!(
                    "TLS version {} is below minimum {}",
                    version, self.min_version
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_match_passes() {
        let v = TlsVerifier::new(true);
        assert!(v.verify_sni("api.example.com", "api.example.com").is_ok());
    }

    #[test]
    fn sni_mismatch_fails() {
        let v = TlsVerifier::new(true);
        assert!(v.verify_sni("api.example.com", "evil.example.com").is_err());
    }

    #[test]
    fn disabled_verifier_always_passes() {
        let v = TlsVerifier::new(false);
        assert!(v.verify_sni("a.com", "b.com").is_ok());
        assert!(v.check_version(TlsVersion::Tls12).is_ok());
    }

    #[test]
    fn version_check_enforced() {
        let mut v = TlsVerifier::new(true);
        v.min_version = TlsVersion::Tls13;
        assert!(v.check_version(TlsVersion::Tls12).is_err());
        assert!(v.check_version(TlsVersion::Tls13).is_ok());
    }
}
