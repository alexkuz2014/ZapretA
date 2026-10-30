//! Network access policy primitives. No requests or downloads are implemented yet.

use std::{fmt, net::IpAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedHost {
    pub hostname: String,
    pub purpose: NetworkPurpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPurpose {
    Probe,
    CatalogUpdate,
    ListUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameError(pub String);

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HostnameError {}

impl AllowedHost {
    pub fn new(
        hostname: impl Into<String>,
        purpose: NetworkPurpose,
    ) -> Result<Self, HostnameError> {
        let hostname = hostname.into();
        let hostname = hostname
            .strip_suffix('.')
            .unwrap_or(&hostname)
            .to_ascii_lowercase();
        validate_hostname(&hostname)?;
        Ok(Self { hostname, purpose })
    }
}

/// Accepts a DNS hostname only; URLs, IP literals, wildcards, and path fragments
/// are rejected so callers must make network destinations explicit.
pub fn validate_hostname(hostname: &str) -> Result<(), HostnameError> {
    if hostname.is_empty() || hostname.len() > 253 || hostname.parse::<IpAddr>().is_ok() {
        return Err(HostnameError("expected a DNS hostname".into()));
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(HostnameError(format!("invalid DNS hostname: {hostname}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_validates_hostnames() {
        let host = AllowedHost::new("YouTube.COM.", NetworkPurpose::Probe).unwrap();
        assert_eq!(host.hostname, "youtube.com");
    }

    #[test]
    fn rejects_urls_and_ip_literals() {
        for value in ["https://example.com", "127.0.0.1", "*.example.com", "a/b"] {
            assert!(AllowedHost::new(value, NetworkPurpose::Probe).is_err());
        }
    }
}
