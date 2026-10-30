//! Validated strategy catalog and probe scoring primitives.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyCatalog {
    pub schema_version: u32,
    pub engine_version: String,
    pub source_revision: String,
    pub strategies: Vec<Strategy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Strategy {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub wire_tcp: Vec<String>,
    #[serde(default)]
    pub wire_udp: Vec<String>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub transport: Transport,
    /// Port numbers and inclusive ranges, such as `443` or `50000-50100`.
    pub ports: Vec<String>,
    #[serde(default)]
    pub l7_protocols: Vec<String>,
    #[serde(default)]
    pub hostlists: Vec<String>,
    #[serde(default)]
    pub hostlist_excludes: Vec<String>,
    #[serde(default)]
    pub ipsets: Vec<String>,
    #[serde(default)]
    pub ipset_excludes: Vec<String>,
    pub desync_methods: Vec<DesyncMethod>,
    pub repeats: Option<u8>,
    pub fooling: Option<Fooling>,
    pub cutoff: Option<String>,
    pub split_position: Option<u16>,
    pub split_sequence_overlap: Option<u16>,
    pub split_pattern: Option<String>,
    pub hostfakesplit_modifier: Option<String>,
    pub badseq_increment: Option<u32>,
    #[serde(default)]
    pub fake_payloads: Vec<FakePayload>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesyncMethod {
    Fake,
    FakeSplit,
    MultiSplit,
    MultiDisorder,
    HostFakeSplit,
    SynData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fooling {
    Ts,
    BadSeq,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakePayload {
    pub kind: FakeKind,
    /// Relative path inside the verified engine bundle.
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FakeKind {
    Tls,
    Http,
    Quic,
    Discord,
    Stun,
    Unknown,
    UnknownUdp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogError(pub String);

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CatalogError {}

impl StrategyCatalog {
    pub fn parse_toml(input: &str) -> Result<Self, CatalogError> {
        let catalog: Self = toml::from_str(input)
            .map_err(|error| CatalogError(format!("invalid strategy catalog: {error}")))?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn load(path: &Path) -> Result<Self, CatalogError> {
        let input = std::fs::read_to_string(path)
            .map_err(|error| CatalogError(format!("cannot read {}: {error}", path.display())))?;
        Self::parse_toml(&input)
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != 1 {
            return Err(CatalogError(format!(
                "unsupported catalog schema version {}",
                self.schema_version
            )));
        }
        if self.engine_version.trim().is_empty() || self.source_revision.trim().is_empty() {
            return Err(CatalogError(
                "engine_version and source_revision must be specified".into(),
            ));
        }
        if self.strategies.is_empty() {
            return Err(CatalogError("catalog has no strategies".into()));
        }

        let mut ids = BTreeSet::new();
        for strategy in &self.strategies {
            if strategy.id.trim().is_empty() || strategy.label.trim().is_empty() {
                return Err(CatalogError("strategy id and label cannot be empty".into()));
            }
            if !ids.insert(&strategy.id) {
                return Err(CatalogError(format!(
                    "duplicate strategy id: {}",
                    strategy.id
                )));
            }
            if strategy.rules.is_empty() {
                return Err(CatalogError(format!(
                    "strategy {} has no rules",
                    strategy.id
                )));
            }
            for port in strategy.wire_tcp.iter().chain(&strategy.wire_udp) {
                validate_port_spec(port)?;
            }
            for rule in &strategy.rules {
                validate_rule(rule)?;
            }
        }
        Ok(())
    }
}

fn validate_rule(rule: &Rule) -> Result<(), CatalogError> {
    if rule.ports.is_empty() {
        return Err(CatalogError("a rule must select at least one port".into()));
    }
    for port in &rule.ports {
        validate_port_spec(port)?;
    }
    if rule.desync_methods.is_empty() {
        return Err(CatalogError("a rule must specify a desync method".into()));
    }
    if let Some(repeats) = rule.repeats {
        if repeats == 0 {
            return Err(CatalogError("repeats must be greater than zero".into()));
        }
    }
    if let Some(path) = &rule.split_pattern {
        validate_relative_path(path)?;
    }
    if let Some(modifier) = &rule.hostfakesplit_modifier {
        if !modifier.starts_with("host=") || modifier.len() <= "host=".len() {
            return Err(CatalogError(
                "hostfakesplit_modifier must use the documented host=<name> form".into(),
            ));
        }
    }
    for list in rule
        .hostlists
        .iter()
        .chain(&rule.hostlist_excludes)
        .chain(&rule.ipsets)
        .chain(&rule.ipset_excludes)
    {
        validate_relative_path(list)?;
    }
    for payload in &rule.fake_payloads {
        validate_relative_path(&payload.path)?;
        if payload.sha256.len() != 64 || !payload.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CatalogError(format!(
                "payload {} must have a 64-character SHA-256 hex digest",
                payload.path
            )));
        }
    }
    Ok(())
}

fn validate_port_spec(value: &str) -> Result<(), CatalogError> {
    let mut split = value.split('-');
    let start = parse_port(split.next().unwrap_or_default())?;
    let end = match split.next() {
        Some(value) => parse_port(value)?,
        None => start,
    };
    if split.next().is_some() || start > end {
        return Err(CatalogError(format!("invalid port or port range: {value}")));
    }
    Ok(())
}

fn parse_port(value: &str) -> Result<u16, CatalogError> {
    let port = value
        .parse::<u16>()
        .map_err(|_| CatalogError(format!("invalid port number: {value}")))?;
    if port == 0 {
        return Err(CatalogError("port zero is not valid here".into()));
    }
    Ok(port)
}

fn validate_relative_path(value: &str) -> Result<(), CatalogError> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(CatalogError(format!("unsafe relative path: {value}")));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeScore {
    pub control_site_ok: bool,
    pub tls_ok: bool,
    pub content_ok: bool,
    pub median_kbps: u32,
    pub successful_runs: u8,
    pub total_runs: u8,
}

impl ProbeScore {
    /// Strategies that fail the control site or the actual content check cannot win.
    pub fn points(self) -> Option<u32> {
        if !self.control_site_ok || !self.tls_ok || !self.content_ok || self.total_runs == 0 {
            return None;
        }
        let reliability = (u32::from(self.successful_runs.min(self.total_runs)) * 100)
            / u32::from(self.total_runs);
        Some(reliability.saturating_mul(10) + self.median_kbps.min(100_000) / 100)
    }
}

/// Builds argument tokens without passing through a shell. Payload files are still
/// verified and resolved by the engine before a process can be launched.
pub fn rule_argv(rule: &Rule) -> Vec<String> {
    let protocol = match rule.transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
    };
    let mut args = vec![format!("--filter-{protocol}={}", rule.ports.join(","))];
    if !rule.l7_protocols.is_empty() {
        args.push(format!("--filter-l7={}", rule.l7_protocols.join(",")));
    }
    for path in &rule.hostlists {
        args.push(format!("--hostlist={path}"));
    }
    for path in &rule.hostlist_excludes {
        args.push(format!("--hostlist-exclude={path}"));
    }
    for path in &rule.ipsets {
        args.push(format!("--ipset={path}"));
    }
    for path in &rule.ipset_excludes {
        args.push(format!("--ipset-exclude={path}"));
    }
    args.push(format!(
        "--dpi-desync={}",
        rule.desync_methods
            .iter()
            .map(|method| match method {
                DesyncMethod::Fake => "fake",
                DesyncMethod::FakeSplit => "fakedsplit",
                DesyncMethod::MultiSplit => "multisplit",
                DesyncMethod::MultiDisorder => "multidisorder",
                DesyncMethod::HostFakeSplit => "hostfakesplit",
                DesyncMethod::SynData => "syndata",
            })
            .collect::<Vec<_>>()
            .join(",")
    ));
    if let Some(repeats) = rule.repeats {
        args.push(format!("--dpi-desync-repeats={repeats}"));
    }
    if let Some(fooling) = rule.fooling {
        let value = match fooling {
            Fooling::Ts => "ts",
            Fooling::BadSeq => "badseq",
        };
        args.push(format!("--dpi-desync-fooling={value}"));
        if fooling == Fooling::BadSeq {
            if let Some(increment) = rule.badseq_increment {
                args.push(format!("--dpi-desync-badseq-increment={increment}"));
            }
        }
    }
    if let Some(cutoff) = &rule.cutoff {
        args.push(format!("--dpi-desync-cutoff={cutoff}"));
    }
    if let Some(position) = rule.split_position {
        args.push(format!("--dpi-desync-split-pos={position}"));
    }
    if let Some(overlap) = rule.split_sequence_overlap {
        args.push(format!("--dpi-desync-split-seqovl={overlap}"));
    }
    if let Some(pattern) = &rule.split_pattern {
        args.push(format!("--dpi-desync-split-seqovl-pattern={pattern}"));
    }
    if let Some(modifier) = &rule.hostfakesplit_modifier {
        args.push(format!("--dpi-desync-hostfakesplit-mod={modifier}"));
    }
    for payload in &rule.fake_payloads {
        let option = match payload.kind {
            FakeKind::Tls => "fake-tls",
            FakeKind::Http => "fake-http",
            FakeKind::Quic => "fake-quic",
            FakeKind::Discord => "fake-discord",
            FakeKind::Stun => "fake-stun",
            FakeKind::Unknown => "fake-unknown",
            FakeKind::UnknownUdp => "fake-unknown-udp",
        };
        args.push(format!("--dpi-desync-{option}={}", payload.path));
    }
    args
}

/// Creates a flat argv vector for the selected profile. `--new` is kept between
/// rules so each filter/desync block retains its own settings.
pub fn strategy_argv(strategy: &Strategy) -> Vec<String> {
    let mut args = Vec::new();
    if !strategy.wire_tcp.is_empty() {
        args.push(format!("--wf-tcp={}", strategy.wire_tcp.join(",")));
    }
    if !strategy.wire_udp.is_empty() {
        args.push(format!("--wf-udp={}", strategy.wire_udp.join(",")));
    }
    for (index, rule) in strategy.rules.iter().enumerate() {
        if index > 0 {
            args.push("--new".into());
        }
        args.extend(rule_argv(rule));
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG: &str = r#"
schema_version = 1
engine_version = "pending-pin"
source_revision = "pending-pin"

[[strategies]]
id = "basic"
label = "Basic"
wire_tcp = ["443"]

[[strategies.rules]]
transport = "tcp"
ports = ["443", "2053-2054"]
desync_methods = ["fake", "multi-split"]
repeats = 6
hostlists = ["lists/general.txt"]
"#;

    #[test]
    fn parses_and_normalizes_strategy_rule() {
        let catalog = StrategyCatalog::parse_toml(CATALOG).unwrap();
        let args = strategy_argv(&catalog.strategies[0]);
        assert_eq!(args[0], "--wf-tcp=443");
        assert_eq!(args[1], "--filter-tcp=443,2053-2054");
        assert!(args.contains(&"--dpi-desync=fake,multisplit".to_string()));
    }

    #[test]
    fn rejects_unknown_fields_and_path_traversal() {
        let unknown = CATALOG.replace("label = \"Basic\"", "label = \"Basic\"\nunknown = true");
        assert!(StrategyCatalog::parse_toml(&unknown).is_err());
        let traversal = CATALOG.replace("lists/general.txt", "../outside.txt");
        assert!(StrategyCatalog::parse_toml(&traversal).is_err());
    }

    #[test]
    fn control_or_content_failure_disqualifies_candidate() {
        let score = ProbeScore {
            control_site_ok: true,
            tls_ok: true,
            content_ok: false,
            median_kbps: 10_000,
            successful_runs: 3,
            total_runs: 3,
        };
        assert_eq!(score.points(), None);
    }

    #[test]
    fn rejects_invalid_port_ranges() {
        let malformed = CATALOG.replace("2053-2054", "2054-2053");
        assert!(StrategyCatalog::parse_toml(&malformed).is_err());
    }
}
