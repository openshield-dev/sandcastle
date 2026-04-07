use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Domain blocked: {0}")]
    DomainBlocked(String),
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),
    #[error("Egress denied: {protocol} to {destination}")]
    EgressDenied { protocol: String, destination: String },
    #[error("TLS verification failed for {domain}: {reason}")]
    TlsVerificationFailed { domain: String, reason: String },
    #[error("Rate limit exceeded for domain: {0}")]
    RateLimitExceeded(String),
    #[error("Bandwidth limit exceeded")]
    BandwidthExceeded,
    #[error("Network filter setup failed: {0}")]
    SetupFailed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
