//! Network access policy primitives. No requests or downloads are implemented yet.

use serde::Deserialize;
use std::{fmt, net::IpAddr, time::Duration};

const GOOGLE_DOH_URL: &str = "https://dns.google/resolve";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolution {
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetError(pub String);

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NetError {}

#[derive(Debug, Deserialize)]
struct GoogleDnsResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "Answer", default)]
    answers: Vec<GoogleDnsAnswer>,
}

#[derive(Debug, Deserialize)]
struct GoogleDnsAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

pub struct DnsResolver {
    client: reqwest::Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsProbeResult {
    pub hostname: String,
    pub status_code: u16,
    pub elapsed_ms: u128,
    pub bytes_read: usize,
    pub body_limited: bool,
}

pub struct HttpsProber {
    client: reqwest::Client,
}

impl HttpsProber {
    pub fn new(timeout: Duration) -> Result<Self, NetError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .user_agent("ZapretA/0.1")
            .build()
            .map_err(|error| NetError(format!("cannot create HTTPS probe client: {error}")))?;
        Ok(Self { client })
    }

    /// Makes a direct HTTPS GET, reads at most `max_bytes`, and never follows redirects.
    pub async fn get(
        &self,
        destination: &AllowedHost,
        path: &str,
        max_bytes: usize,
    ) -> Result<HttpsProbeResult, NetError> {
        if destination.purpose != NetworkPurpose::Probe {
            return Err(NetError("HTTPS probe requires a Probe host".into()));
        }
        validate_hostname(&destination.hostname).map_err(|error| NetError(error.to_string()))?;
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains('\r')
            || path.contains('\n')
        {
            return Err(NetError("probe path must be a local absolute path".into()));
        }
        if max_bytes == 0 {
            return Err(NetError(
                "probe body limit must be greater than zero".into(),
            ));
        }
        let url = format!("https://{}{path}", destination.hostname);
        let started = std::time::Instant::now();
        let mut response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| NetError(format!("HTTPS probe failed: {error}")))?;
        let status_code = response.status().as_u16();
        let mut bytes_read = 0_usize;
        let mut body_limited = false;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| NetError(format!("reading HTTPS probe response failed: {error}")))?
        {
            let remaining = max_bytes.saturating_sub(bytes_read);
            bytes_read += chunk.len().min(remaining);
            if chunk.len() > remaining {
                body_limited = true;
                break;
            }
            if bytes_read == max_bytes {
                body_limited = true;
                break;
            }
        }
        Ok(HttpsProbeResult {
            hostname: destination.hostname.clone(),
            status_code,
            elapsed_ms: started.elapsed().as_millis(),
            bytes_read,
            body_limited,
        })
    }
}

impl DnsResolver {
    pub fn new(timeout: Duration) -> Result<Self, NetError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .user_agent("ZapretA/0.1")
            .build()
            .map_err(|error| NetError(format!("cannot create DNS client: {error}")))?;
        Ok(Self { client })
    }

    /// Resolves with the configured Windows resolver and returns deduplicated A/AAAA results.
    pub async fn system(&self, hostname: &str) -> Result<DnsResolution, NetError> {
        validate_hostname(hostname).map_err(|error| NetError(error.to_string()))?;
        let results = tokio::net::lookup_host((hostname, 443))
            .await
            .map_err(|error| NetError(format!("system DNS lookup failed: {error}")))?;
        let mut addresses: Vec<IpAddr> = results.map(|item| item.ip()).collect();
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(NetError("system DNS returned no addresses".into()));
        }
        Ok(DnsResolution { addresses })
    }

    /// Queries Google's documented JSON DoH API without sending an EDNS client subnet.
    pub async fn google_doh(&self, hostname: &str) -> Result<DnsResolution, NetError> {
        validate_hostname(hostname).map_err(|error| NetError(error.to_string()))?;
        let mut addresses = Vec::new();
        for record_type in ["A", "AAAA"] {
            let response = self
                .client
                .get(GOOGLE_DOH_URL)
                .query(&[
                    ("name", hostname),
                    ("type", record_type),
                    ("ct", "application/x-javascript"),
                    ("edns_client_subnet", "0.0.0.0/0"),
                ])
                .send()
                .await
                .map_err(|error| NetError(format!("Google DoH request failed: {error}")))?;
            if !response.status().is_success() {
                return Err(NetError(format!(
                    "Google DoH returned HTTP {}",
                    response.status()
                )));
            }
            let response_text = response.text().await.map_err(|error| {
                NetError(format!("reading Google DoH response failed: {error}"))
            })?;
            let wanted_type = if record_type == "A" { 1 } else { 28 };
            addresses.extend(parse_google_dns_json(&response_text, wanted_type)?);
        }
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(NetError("Google DoH returned no A/AAAA addresses".into()));
        }
        Ok(DnsResolution { addresses })
    }
}

fn parse_google_dns_json(input: &str, wanted_type: u16) -> Result<Vec<IpAddr>, NetError> {
    let response: GoogleDnsResponse = serde_json::from_str(input)
        .map_err(|error| NetError(format!("invalid Google DoH JSON: {error}")))?;
    if response.status != 0 {
        return Err(NetError(format!("DNS status {}", response.status)));
    }
    response
        .answers
        .into_iter()
        .filter(|answer| answer.record_type == wanted_type)
        .map(|answer| {
            answer
                .data
                .parse::<IpAddr>()
                .map_err(|_| NetError(format!("invalid IP address in DNS answer: {}", answer.data)))
        })
        .collect()
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

    #[test]
    fn parses_only_requested_dns_record_type() {
        let json = r#"{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":60,"data":"192.0.2.1"},{"name":"example.com.","type":28,"TTL":60,"data":"2001:db8::1"}]}"#;
        assert_eq!(
            parse_google_dns_json(json, 1).unwrap(),
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            parse_google_dns_json(json, 28).unwrap(),
            vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn rejects_dns_errors_and_invalid_addresses() {
        assert!(parse_google_dns_json(r#"{"Status":3}"#, 1).is_err());
        let json = r#"{"Status":0,"Answer":[{"type":1,"data":"not-an-ip"}]}"#;
        assert!(parse_google_dns_json(json, 1).is_err());
    }
}
