//! Network access policy primitives. No requests or downloads are implemented yet.

use serde::Deserialize;
use std::{borrow::Cow, fmt, net::IpAddr, time::Duration};

const GOOGLE_DOH_HOST: &str = "dns.google";
const CLOUDFLARE_DOH_HOST: &str = "cloudflare-dns.com";
const GOOGLE_DOH_URL: &str = "https://dns.google/resolve";
const CLOUDFLARE_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";

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
    /// Provider used (`system`, `Google Public DNS`, or `Cloudflare 1.1.1.1`).
    pub provider: &'static str,
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
struct DnsJsonResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "Answer", default)]
    answers: Vec<DnsJsonAnswer>,
}

#[derive(Debug, Deserialize)]
struct DnsJsonAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

pub struct DnsResolver {
    client: reqwest::Client,
    providers: Vec<DohProvider>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DohProvider {
    name: &'static str,
    url: Cow<'static, str>,
    accept: &'static str,
    bootstrap_host: &'static str,
}

const DOH_PROVIDERS: [DohProvider; 2] = [
    DohProvider {
        name: "Google Public DNS",
        url: Cow::Borrowed(GOOGLE_DOH_URL),
        accept: "application/x-javascript",
        bootstrap_host: GOOGLE_DOH_HOST,
    },
    DohProvider {
        name: "Cloudflare 1.1.1.1",
        url: Cow::Borrowed(CLOUDFLARE_DOH_URL),
        accept: "application/dns-json",
        bootstrap_host: CLOUDFLARE_DOH_HOST,
    },
];

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
    #[cfg(test)]
    test_base_url: Option<String>,
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
        Ok(Self {
            client,
            #[cfg(test)]
            test_base_url: None,
        })
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
        #[cfg(test)]
        let url = match self.test_base_url.as_ref() {
            Some(base) => format!("{base}{path}"),
            None => format!("https://{}{path}", destination.hostname),
        };
        #[cfg(not(test))]
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

#[cfg(test)]
impl HttpsProber {
    fn with_test_base_url(timeout: Duration, base_url: String) -> Result<Self, NetError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|error| NetError(format!("cannot create test HTTPS client: {error}")))?;
        Ok(Self {
            client,
            test_base_url: Some(base_url),
        })
    }
}

impl DnsResolver {
    pub fn new(timeout: Duration) -> Result<Self, NetError> {
        let client = reqwest::Client::builder()
            // Keep the URL hostname for TLS SNI and certificate validation, while
            // resolving the provider hostname only to its published resolver IPs.
            .resolve_to_addrs(
                GOOGLE_DOH_HOST,
                &[
                    "8.8.8.8:0".parse().expect("valid bootstrap socket address"),
                    "8.8.4.4:0".parse().expect("valid bootstrap socket address"),
                ],
            )
            .resolve_to_addrs(
                CLOUDFLARE_DOH_HOST,
                &[
                    "1.1.1.1:0".parse().expect("valid bootstrap socket address"),
                    "1.0.0.1:0".parse().expect("valid bootstrap socket address"),
                ],
            )
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .user_agent("ZapretA/0.1")
            .build()
            .map_err(|error| NetError(format!("cannot create DNS client: {error}")))?;
        Ok(Self {
            client,
            providers: DOH_PROVIDERS
                .iter()
                .map(|provider| DohProvider {
                    url: provider.url.clone(),
                    ..provider.clone()
                })
                .collect(),
        })
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
        Ok(DnsResolution {
            addresses,
            provider: "system",
        })
    }

    /// Queries Google then Cloudflare DoH using pinned resolver IPs as DNS bootstrap.
    /// The provider hostname remains in the URL, preserving TLS SNI and validation.
    pub async fn doh(&self, hostname: &str) -> Result<DnsResolution, NetError> {
        validate_hostname(hostname).map_err(|error| NetError(error.to_string()))?;
        let mut failures = Vec::new();
        for provider in &self.providers {
            match self.query_doh_provider(hostname, provider).await {
                Ok(result) => return Ok(result),
                Err(error) => failures.push(format!("{}: {error}", provider.name)),
            }
        }
        Err(NetError(format!(
            "all DoH providers failed ({})",
            failures.join("; ")
        )))
    }

    async fn query_doh_provider(
        &self,
        hostname: &str,
        provider: &DohProvider,
    ) -> Result<DnsResolution, NetError> {
        let mut addresses = Vec::new();
        for record_type in ["A", "AAAA"] {
            let mut request = self
                .client
                .get(provider.url.as_ref())
                .header(reqwest::header::ACCEPT, provider.accept)
                .query(&[("name", hostname), ("type", record_type)]);
            if provider.name == "Google Public DNS" {
                request = request.query(&[("edns_client_subnet", "0.0.0.0/0")]);
            }
            let response = request
                .send()
                .await
                .map_err(|error| NetError(error.to_string()))?;
            if !response.status().is_success() {
                return Err(NetError(format!("HTTP {}", response.status())));
            }
            let response_text = response
                .text()
                .await
                .map_err(|error| NetError(format!("reading response failed: {error}")))?;
            let wanted_type = if record_type == "A" { 1 } else { 28 };
            addresses.extend(parse_dns_json(&response_text, wanted_type)?);
        }
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(NetError("provider returned no A/AAAA addresses".into()));
        }
        Ok(DnsResolution {
            addresses,
            provider: provider.name,
        })
    }

    #[cfg(test)]
    fn with_test_provider_urls(
        timeout: Duration,
        first_url: String,
        second_url: String,
    ) -> Result<Self, NetError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|error| NetError(format!("cannot create test DNS client: {error}")))?;
        let providers = DOH_PROVIDERS
            .iter()
            .zip([first_url, second_url])
            .map(|(provider, url)| DohProvider {
                url: Cow::Owned(url),
                ..provider.clone()
            })
            .collect();
        Ok(Self { client, providers })
    }
}

fn parse_dns_json(input: &str, wanted_type: u16) -> Result<Vec<IpAddr>, NetError> {
    let response: DnsJsonResponse = serde_json::from_str(input)
        .map_err(|error| NetError(format!("invalid DoH JSON: {error}")))?;
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
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn local_http_server(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let read = stream.read(&mut request).await.unwrap();
                requests.push(String::from_utf8_lossy(&request[..read]).into_owned());
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Service Unavailable"
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/dns-json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (format!("http://{address}/dns-query"), handle)
    }

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
            parse_dns_json(json, 1).unwrap(),
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            parse_dns_json(json, 28).unwrap(),
            vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn rejects_dns_errors_and_invalid_addresses() {
        assert!(parse_dns_json(r#"{"Status":3}"#, 1).is_err());
        let json = r#"{"Status":0,"Answer":[{"type":1,"data":"not-an-ip"}]}"#;
        assert!(parse_dns_json(json, 1).is_err());
    }

    #[test]
    fn doh_providers_have_pinned_bootstrap_hosts_and_ordered_fallback() {
        assert_eq!(DOH_PROVIDERS[0].name, "Google Public DNS");
        assert_eq!(DOH_PROVIDERS[1].name, "Cloudflare 1.1.1.1");
        assert_eq!(DOH_PROVIDERS[0].bootstrap_host, "dns.google");
        assert_eq!(DOH_PROVIDERS[1].bootstrap_host, "cloudflare-dns.com");
        assert!(
            DOH_PROVIDERS
                .iter()
                .all(|provider| provider.url.starts_with("https://"))
        );
    }

    #[tokio::test]
    async fn doh_falls_back_to_second_provider_after_http_failure() {
        let answer = r#"{"Status":0,"Answer":[{"type":1,"data":"192.0.2.40"}]}"#;
        let (first_url, first_server) = local_http_server(vec![(503, "unavailable")]).await;
        let (second_url, second_server) =
            local_http_server(vec![(200, answer), (200, answer)]).await;
        let resolver =
            DnsResolver::with_test_provider_urls(Duration::from_secs(2), first_url, second_url)
                .unwrap();
        let result = resolver.doh("example.test").await.unwrap();
        assert_eq!(result.provider, "Cloudflare 1.1.1.1");
        assert_eq!(
            result.addresses,
            vec!["192.0.2.40".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(first_server.await.unwrap().len(), 1);
        let requests = second_server.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("type=A"));
        assert!(requests[1].contains("type=AAAA"));
    }

    #[tokio::test]
    async fn doh_returns_error_when_both_local_providers_fail() {
        let (first_url, first_server) = local_http_server(vec![(503, "unavailable")]).await;
        let (second_url, second_server) = local_http_server(vec![(503, "unavailable")]).await;
        let resolver =
            DnsResolver::with_test_provider_urls(Duration::from_secs(2), first_url, second_url)
                .unwrap();
        let error = resolver.doh("example.test").await.unwrap_err();
        assert!(error.to_string().contains("all DoH providers failed"));
        assert_eq!(first_server.await.unwrap().len(), 1);
        assert_eq!(second_server.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn doh_falls_back_when_first_provider_returns_malformed_json() {
        let answer = r#"{"Status":0,"Answer":[{"type":1,"data":"192.0.2.41"}]}"#;
        let (first_url, first_server) = local_http_server(vec![(200, "not-json")]).await;
        let (second_url, second_server) =
            local_http_server(vec![(200, answer), (200, answer)]).await;
        let resolver =
            DnsResolver::with_test_provider_urls(Duration::from_secs(2), first_url, second_url)
                .unwrap();
        let result = resolver.doh("example.test").await.unwrap();
        assert_eq!(result.provider, "Cloudflare 1.1.1.1");
        assert_eq!(first_server.await.unwrap().len(), 1);
        assert_eq!(second_server.await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn https_probe_obeys_empty_exact_and_oversized_body_limits() {
        let (url, server) = local_http_server(vec![(200, ""), (200, "1234"), (200, "12345")]).await;
        let prober = HttpsProber::with_test_base_url(Duration::from_secs(2), url).unwrap();
        let host = AllowedHost::new("example.test", NetworkPurpose::Probe).unwrap();

        let empty = prober.get(&host, "/empty", 4).await.unwrap();
        assert_eq!(empty.bytes_read, 0);
        assert!(!empty.body_limited);

        let exact = prober.get(&host, "/exact", 4).await.unwrap();
        assert_eq!(exact.bytes_read, 4);
        assert!(!exact.body_limited);

        let oversized = prober.get(&host, "/large", 4).await.unwrap();
        assert_eq!(oversized.bytes_read, 4);
        assert!(oversized.body_limited);
        assert_eq!(server.await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn https_probe_reports_redirect_without_following_it() {
        let (url, server) = local_http_server(vec![(302, "")]).await;
        let prober = HttpsProber::with_test_base_url(Duration::from_secs(2), url).unwrap();
        let host = AllowedHost::new("example.test", NetworkPurpose::Probe).unwrap();
        let result = prober.get(&host, "/redirect", 16).await.unwrap();
        assert_eq!(result.status_code, 302);
        assert_eq!(server.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn https_probe_surfaces_local_connection_refusal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let prober =
            HttpsProber::with_test_base_url(Duration::from_secs(2), format!("http://{address}"))
                .unwrap();
        let host = AllowedHost::new("example.test", NetworkPurpose::Probe).unwrap();
        assert!(prober.get(&host, "/refused", 16).await.is_err());
    }

    #[tokio::test]
    async fn https_probe_times_out_on_a_stalled_local_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        });
        let prober =
            HttpsProber::with_test_base_url(Duration::from_millis(30), format!("http://{address}"))
                .unwrap();
        let host = AllowedHost::new("example.test", NetworkPurpose::Probe).unwrap();
        assert!(prober.get(&host, "/slow", 16).await.is_err());
        server.await.unwrap();
    }
}
