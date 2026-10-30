//! Validated strategy catalog and probe scoring primitives.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

const FLOWSEAL_REPOSITORY: &str = "https://github.com/Flowseal/zapret-discord-youtube";
const FLOWSEAL_COMMIT: &str = "176f56dc3f11ce5915c26abcdde903f93d835b64";
const REFERENCE_ARGUMENTS: &[&str] = &[
    "--wf-tcp",
    "--wf-udp",
    "--filter-tcp",
    "--filter-udp",
    "--filter-l3",
    "--filter-l7",
    "--hostlist",
    "--hostlist-exclude",
    "--hostlist-domains",
    "--hostlist-exclude-domains",
    "--ipset",
    "--ipset-exclude",
    "--ip-id",
    "--dpi-desync",
    "--dpi-desync-repeats",
    "--dpi-desync-any-protocol",
    "--dpi-desync-cutoff",
    "--dpi-desync-fooling",
    "--dpi-desync-badseq-increment",
    "--dpi-desync-split-pos",
    "--dpi-desync-split-seqovl",
    "--dpi-desync-split-seqovl-pattern",
    "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-hostfakesplit-mod",
    "--dpi-desync-fake-tls-mod",
    "--dpi-desync-fake-tls",
    "--dpi-desync-fake-http",
    "--dpi-desync-fake-quic",
    "--dpi-desync-fake-discord",
    "--dpi-desync-fake-stun",
    "--dpi-desync-fake-unknown",
    "--dpi-desync-fake-unknown-udp",
];

/// A source snapshot preserves upstream command-line tokens for audit and golden tests.
/// It is intentionally distinct from executable `Strategy`: these arguments must not
/// be passed to an engine until they have been migrated to the validated typed model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStrategySnapshot {
    pub schema_version: u32,
    pub source_repository: String,
    pub source_commit: String,
    pub profile_id: String,
    pub profile_name: String,
    pub source_file: String,
    pub source_sha256: String,
    pub service_sha256: String,
    pub game_filter_tcp_default: String,
    pub game_filter_udp_default: String,
    pub argv: Vec<String>,
}

impl SourceStrategySnapshot {
    pub fn parse_toml(input: &str) -> Result<Self, CatalogError> {
        let snapshot: Self = toml::from_str(input)
            .map_err(|error| CatalogError(format!("invalid source snapshot: {error}")))?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != 1 {
            return Err(CatalogError("unsupported source snapshot schema".into()));
        }
        if self.source_repository != FLOWSEAL_REPOSITORY {
            return Err(CatalogError("unexpected source repository".into()));
        }
        if !self.profile_name.starts_with("general") || !self.profile_name.ends_with(".bat") {
            return Err(CatalogError(
                "profile_name must identify a general*.bat profile".into(),
            ));
        }
        if self.source_commit != FLOWSEAL_COMMIT {
            return Err(CatalogError(
                "source_commit must match the reviewed Flowseal snapshot".into(),
            ));
        }
        if !self.profile_id.starts_with("flowseal-general-")
            || !self
                .profile_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(CatalogError("invalid Flowseal profile_id".into()));
        }
        validate_relative_path(&self.source_file)?;
        if self.source_sha256.len() != 64
            || !self
                .source_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CatalogError(
                "source_sha256 must be a 64-character hex digest".into(),
            ));
        }
        if self.service_sha256.len() != 64
            || !self
                .service_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CatalogError(
                "service_sha256 must be a 64-character hex digest".into(),
            ));
        }
        for value in [&self.game_filter_tcp_default, &self.game_filter_udp_default] {
            if value != "12" {
                return Err(CatalogError(
                    "only the disabled-by-default Game Filter port 12 snapshot is supported".into(),
                ));
            }
        }
        if self.argv.is_empty() || self.argv.len() > 256 {
            return Err(CatalogError(
                "source argv must contain 1 to 256 tokens".into(),
            ));
        }
        for argument in &self.argv {
            validate_reference_argument(argument)?;
        }
        Ok(())
    }

    pub fn normalized_source_file_hash(&self, bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
}

fn validate_reference_argument(argument: &str) -> Result<(), CatalogError> {
    if argument == "--new" {
        return Ok(());
    }
    let Some((flag, value)) = argument.split_once('=') else {
        return Err(CatalogError(format!(
            "source argv token has no value: {argument}"
        )));
    };
    if !REFERENCE_ARGUMENTS.contains(&flag) {
        return Err(CatalogError(format!("unsupported source argument: {flag}")));
    }
    if value.is_empty()
        || value.len() > 2048
        || value
            .chars()
            .any(|ch| matches!(ch, '\0' | '\r' | '\n' | '"' | '\''))
        || value.contains('%')
    {
        return Err(CatalogError(format!(
            "invalid source argument value: {argument}"
        )));
    }
    let path_option = matches!(
        flag,
        "--hostlist"
            | "--hostlist-exclude"
            | "--ipset"
            | "--ipset-exclude"
            | "--dpi-desync-split-seqovl-pattern"
    );
    let fake_payload = matches!(
        flag,
        "--dpi-desync-fake-tls"
            | "--dpi-desync-fake-http"
            | "--dpi-desync-fake-quic"
            | "--dpi-desync-fake-discord"
            | "--dpi-desync-fake-stun"
            | "--dpi-desync-fake-unknown"
            | "--dpi-desync-fake-unknown-udp"
    );
    if path_option || (fake_payload && (value.contains('/') || value.contains('\\'))) {
        validate_relative_path(value)?;
    } else if value.contains(':') || value.contains('\\') {
        return Err(CatalogError(format!(
            "unsafe source argument value: {argument}"
        )));
    }
    Ok(())
}

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

    #[test]
    fn source_snapshot_rejects_unapproved_flags_and_unsafe_paths() {
        let mut snapshot = SourceStrategySnapshot {
            schema_version: 1,
            source_repository: FLOWSEAL_REPOSITORY.into(),
            source_commit: FLOWSEAL_COMMIT.into(),
            profile_id: "flowseal-general-default".into(),
            profile_name: "general.bat".into(),
            source_file: "tests/fixtures/flowseal/general.bat".into(),
            source_sha256: "b".repeat(64),
            service_sha256: "c".repeat(64),
            game_filter_tcp_default: "12".into(),
            game_filter_udp_default: "12".into(),
            argv: vec!["--wf-tcp=80,443".into()],
        };
        assert!(snapshot.validate().is_ok());
        snapshot.argv[0] = "--unapproved=anything".into();
        assert!(snapshot.validate().is_err());
        snapshot.argv[0] = "--hostlist=../outside.txt".into();
        assert!(snapshot.validate().is_err());
        snapshot.argv[0] = "--wf-tcp=C:\\outside".into();
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn all_flowseal_reference_argv_match_pinned_batch_files() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let catalog_dir = root.join("catalog/flowseal");
        let service_path = root.join("tests/fixtures/flowseal/service.bat");
        let service_bytes = std::fs::read(&service_path).unwrap();
        let service_text = String::from_utf8_lossy(&service_bytes);
        assert!(service_text.contains("set \"GameFilterMode=disabled\""));
        assert!(service_text.contains("set \"GameFilterTCP=12\""));
        assert!(service_text.contains("set \"GameFilterUDP=12\""));
        assert!(service_text.contains("if not exist \"%gameFlagFile%\" exit /b"));

        let mut paths: Vec<_> = std::fs::read_dir(catalog_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "toml")
            })
            .collect();
        paths.sort();
        assert_eq!(paths.len(), 22, "expected all 22 general*.bat profiles");

        let mut profile_ids = BTreeSet::new();
        for path in paths {
            let text = std::fs::read_to_string(&path).unwrap();
            let snapshot = SourceStrategySnapshot::parse_toml(&text).unwrap();
            assert!(profile_ids.insert(snapshot.profile_id.clone()));
            let fixture_path = root.join(&snapshot.source_file);
            let fixture_bytes = std::fs::read(&fixture_path).unwrap();
            assert_eq!(
                snapshot.normalized_source_file_hash(&fixture_bytes),
                snapshot.source_sha256,
                "source hash mismatch for {}",
                snapshot.profile_name
            );
            assert_eq!(
                fixture_path.file_name().unwrap().to_string_lossy(),
                snapshot.profile_name,
                "source filename mismatch for {}",
                snapshot.profile_id
            );
            assert_eq!(
                format!("{:x}", Sha256::digest(&service_bytes)),
                snapshot.service_sha256,
                "service.bat hash mismatch for {}",
                snapshot.profile_name
            );
            let actual = extract_batch_argv(&String::from_utf8_lossy(&fixture_bytes));
            assert_eq!(
                snapshot.argv, actual,
                "argv mismatch for {}",
                snapshot.profile_name
            );
        }
    }

    fn extract_batch_argv(source: &str) -> Vec<String> {
        let lines: Vec<_> = source.lines().collect();
        let marker = "\"%BIN%winws.exe\"";
        let start = lines
            .iter()
            .position(|line| line.contains(marker))
            .expect("profile must start winws.exe");
        let mut command = lines[start][lines[start].find(marker).unwrap() + marker.len()..]
            .trim()
            .to_string();
        let mut index = start;
        loop {
            let trimmed = command.trim_end();
            if !trimmed.ends_with('^') {
                break;
            }
            command = trimmed[..trimmed.len() - 1].to_string();
            index += 1;
            command.push(' ');
            command.push_str(lines[index].trim());
        }

        let mut args = Vec::new();
        let mut token = String::new();
        let mut quoted = false;
        for ch in command.chars() {
            match ch {
                '"' => quoted = !quoted,
                ch if ch.is_whitespace() && !quoted => {
                    if !token.is_empty() {
                        args.push(std::mem::take(&mut token));
                    }
                }
                _ => token.push(ch),
            }
        }
        if !token.is_empty() {
            args.push(token);
        }
        assert!(!quoted, "profile command contains an unmatched quote");
        args.into_iter()
            .map(|arg| {
                arg.replace("%BIN%", "bin/")
                    .replace("%LISTS%", "lists/")
                    .replace("%GameFilterTCP%", "12")
                    .replace("%GameFilterUDP%", "12")
            })
            .collect()
    }
}
