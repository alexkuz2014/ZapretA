//! Glue between the pure selection logic in `zapreta-probe` and the real engine
//! and HTTPS client. Mapping helpers are pure and unit-tested; `LiveTester`
//! itself needs a verified engine binary and is exercised only on Windows.

use crate::devlog;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::runtime::Handle;
use zapreta_engine::{EngineError, EngineProcess, VerifiedEngine};
use zapreta_net::{AllowedHost, HttpsProbeResult, HttpsProber, NetError, NetworkPurpose};
use zapreta_probe::{
    CheckStatus, EndpointResult, ProbeSignal, classify,
    select::{CandidateTester, CheckKind, CheckOutcome, TesterError},
};

/// A runnable candidate parsed from a pinned source snapshot. Coverage comes
/// from literal `--filter-tcp=`/`--filter-udp=` flags in the argv.
pub struct Loaded {
    pub id: String,
    pub label: String,
    pub argv: Vec<String>,
    pub covers_tcp: bool,
    pub covers_udp: bool,
}

pub fn parse_snapshot(input: &str) -> Result<Loaded, String> {
    let snapshot =
        zapreta_core::SourceStrategySnapshot::parse_toml(input).map_err(|e| e.to_string())?;
    let strategy =
        zapreta_core::Strategy::from_source_snapshot(&snapshot).map_err(|e| e.to_string())?;
    let argv = zapreta_core::strategy_argv(&strategy);
    let has = |prefix: &str| argv.iter().any(|token| token.starts_with(prefix));
    Ok(Loaded {
        covers_tcp: has("--filter-tcp="),
        covers_udp: has("--filter-udp="),
        id: strategy.id,
        label: strategy.label,
        argv,
    })
}

/// One HTTPS target of the per-candidate suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub path: String,
    pub max_bytes: usize,
}

impl Target {
    pub fn new(host: &str, path: &str, max_bytes: usize) -> Self {
        Self {
            host: host.to_owned(),
            path: path.to_owned(),
            max_bytes,
        }
    }
}

/// Targets per check. Control passes if any target answers; TLS needs every
/// target to answer; content needs a 2xx from every target and reports the
/// slowest throughput.
#[derive(Debug, Clone)]
pub struct Suite {
    pub control: Vec<Target>,
    pub tls: Vec<Target>,
    pub content: Vec<Target>,
}

impl Default for Suite {
    fn default() -> Self {
        Self {
            control: vec![
                Target::new("example.com", "/", 16 * 1024),
                Target::new("www.microsoft.com", "/", 16 * 1024),
            ],
            tls: vec![
                Target::new("www.youtube.com", "/generate_204", 16 * 1024),
                // Video traffic is served from googlevideo.com; its SNI is the
                // one throttled or dropped when the page itself still loads.
                Target::new(
                    "redirector.googlevideo.com",
                    "/report_mapping?di=no",
                    16 * 1024,
                ),
            ],
            // Bounded reads standing in for a video chunk: the page and a
            // thumbnail from the image CDN. Volume-based throttling shows up as
            // a stall or low throughput here.
            content: vec![
                Target::new("www.youtube.com", "/", 256 * 1024),
                Target::new("i.ytimg.com", "/vi/dQw4w9WgXcQ/hqdefault.jpg", 256 * 1024),
            ],
        }
    }
}

/// Body bytes read from a user site; must exceed the ~16-20 KB stall budget.
pub const SITE_READ_BYTES: usize = 128 * 1024;

/// One independently judged goal of the search: YouTube, or one user site.
#[derive(Debug, Clone)]
pub struct TargetGroup {
    pub name: String,
    /// (target, is_content_check). Transport checks pass on any HTTP answer;
    /// content checks need a 2xx and at least `min_kbps`.
    pub checks: Vec<(Target, bool)>,
}

impl TargetGroup {
    pub fn youtube() -> Self {
        let suite = Suite::default();
        let mut checks: Vec<(Target, bool)> = suite
            .tls
            .into_iter()
            .map(|target| (target, false))
            .collect();
        checks.extend(suite.content.into_iter().map(|target| (target, true)));
        Self {
            name: "YouTube".into(),
            checks,
        }
    }

    /// Reads well past 16 KB: some filters let the handshake and the first
    /// ~16 KB through and then stall the connection, which a short read would
    /// report as a working site. A stalled body fails the read by timeout.
    pub fn site(host: &str) -> Self {
        Self {
            name: host.to_owned(),
            checks: vec![(Target::new(host, "/", SITE_READ_BYTES), false)],
        }
    }
}

/// Any HTTP response proves TCP and TLS completed, so the transport check
/// passes; a network error cannot be localized further and counts as failed.
pub fn transport_outcome(result: &Result<HttpsProbeResult, NetError>) -> CheckOutcome {
    match result {
        Ok(_) => CheckOutcome::passed(),
        Err(_) => CheckOutcome::with_status(CheckStatus::Failed),
    }
}

/// Content passes only with a 2xx status and a measurable throughput in kbit/s.
pub fn content_outcome(result: &Result<HttpsProbeResult, NetError>) -> CheckOutcome {
    match result {
        Ok(response) if (200..300).contains(&response.status_code) => {
            let elapsed_ms = u64::try_from(response.elapsed_ms)
                .unwrap_or(u64::MAX)
                .max(1);
            let kbps = (response.bytes_read as u64).saturating_mul(8) / elapsed_ms;
            CheckOutcome::content(u32::try_from(kbps).unwrap_or(u32::MAX))
        }
        _ => CheckOutcome::with_status(CheckStatus::Failed),
    }
}

/// Combines per-target outcomes: `any` for control, otherwise all must pass.
/// The combined throughput is the slowest target's.
pub fn combine(outcomes: &[CheckOutcome], any: bool) -> CheckOutcome {
    let passed = |o: &CheckOutcome| o.status == CheckStatus::Passed;
    let ok = if any {
        outcomes.iter().any(passed)
    } else {
        !outcomes.is_empty() && outcomes.iter().all(passed)
    };
    if !ok {
        return CheckOutcome::with_status(CheckStatus::Failed);
    }
    let kbps = outcomes.iter().filter_map(|o| o.kbps).min();
    CheckOutcome {
        status: CheckStatus::Passed,
        kbps,
    }
}

/// Baseline without any bypass active. DNS is not compared here, and an HTTPS
/// error cannot be split into TCP vs TLS, so any error is reported as a
/// TCP-level signal; the search plan treats all such signals alike. Content
/// slower than `min_kbps` counts as failed, because throttling is the common
/// failure mode.
pub fn baseline_signal<T: CandidateTester>(tester: &mut T, min_kbps: u32) -> ProbeSignal {
    let control = tester.run_check("", CheckKind::Control).status;
    let tls = tester.run_check("", CheckKind::Tls).status;
    let content = if tls == CheckStatus::Passed {
        match tester.run_check("", CheckKind::Content).kbps {
            Some(kbps) if kbps >= min_kbps => CheckStatus::Passed,
            _ => CheckStatus::Failed,
        }
    } else {
        CheckStatus::NotRun
    };
    let endpoint = |name: &str, transport, content| EndpointResult {
        endpoint: name.to_owned(),
        dns: CheckStatus::NotRun,
        tcp: transport,
        tls: transport,
        content,
    };
    classify(
        &endpoint("control", control, control),
        &endpoint("target", tls, content),
    )
}

pub struct LiveTester {
    handle: Handle,
    prober: HttpsProber,
    timeout: Duration,
    groups: Vec<TargetGroup>,
    min_kbps: u32,
    engine: VerifiedEngine,
    argv: HashMap<String, Vec<String>>,
    suite: Suite,
    warmup: Duration,
    process: Option<EngineProcess>,
    running: Option<String>,
    cancel: Arc<AtomicBool>,
}

impl LiveTester {
    pub fn new(
        handle: Handle,
        engine: VerifiedEngine,
        argv: HashMap<String, Vec<String>>,
        suite: Suite,
    ) -> Result<Self, NetError> {
        Ok(Self {
            handle,
            prober: HttpsProber::new(Duration::from_secs(6))?,
            timeout: Duration::from_secs(6),
            groups: vec![TargetGroup::youtube()],
            min_kbps: 500,
            engine,
            argv,
            suite,
            // Assumption: winws needs about this long to install its filter.
            warmup: Duration::from_millis(1500),
            process: None,
            running: None,
            cancel: Arc::new(AtomicBool::new(false)),
        })
    }

    /// While the flag is set, starts fail and checks report failure, so a
    /// running search drains quickly.
    pub fn set_cancel_flag(&mut self, cancel: Arc<AtomicBool>) {
        self.cancel = cancel;
    }

    pub fn set_groups(&mut self, groups: Vec<TargetGroup>) {
        self.groups = groups;
    }

    pub fn groups(&self) -> &[TargetGroup] {
        &self.groups
    }

    /// Connect to these addresses (e.g. DoH answers) instead of resolving.
    pub fn set_overrides(&mut self, overrides: &[(String, Vec<std::net::IpAddr>)]) {
        if let Ok(prober) = HttpsProber::with_overrides(self.timeout, overrides) {
            self.prober = prober;
        }
    }

    pub fn control_ok(&self) -> bool {
        self.check(&self.suite.control, false, true).status == CheckStatus::Passed
    }

    pub fn group_ok(&self, index: usize) -> bool {
        let Some(group) = self.groups.get(index) else {
            return false;
        };
        group.checks.iter().all(|(target, content)| {
            if self.cancelled() {
                return false;
            }
            let result = self.fetch(target);
            let (passed, kbps) = if *content {
                let kbps = content_outcome(&result).kbps;
                (kbps.is_some_and(|kbps| kbps >= self.min_kbps), kbps)
            } else {
                (
                    transport_outcome(&result).status == CheckStatus::Passed,
                    None,
                )
            };
            self.log_probe(&group.name, target, *content, &result, passed, kbps);
            passed
        })
    }

    /// Starts a candidate for the multi-target search: a spawn error means the
    /// engine cannot run at all; an immediate exit is specific to the candidate.
    pub fn start_for_search(&mut self, id: &str) -> Result<(), crate::search::StartError> {
        use crate::search::StartError;
        if self.cancelled() {
            return Err(StartError::Fatal("cancelled".into()));
        }
        let argv = self
            .argv
            .get(id)
            .ok_or_else(|| StartError::Fatal(format!("unknown strategy {id}")))?;
        let process = self.spawn_engine(id, argv).map_err(|error| {
            self.log_engine_output(id);
            StartError::Fatal(error.to_string())
        })?;
        self.process = Some(process);
        self.running = Some(id.to_owned());
        std::thread::sleep(self.warmup);
        let exited = self.process.as_mut().is_some_and(|p| p.has_exited());
        if exited {
            devlog::event("engine_exited_early", serde_json::json!({ "strategy": id }));
            self.log_engine_output(id);
            let _ = CandidateTester::stop(self, id);
            return Err(StartError::Exited);
        }
        Ok(())
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled()
    }

    pub fn running(&self) -> Option<&str> {
        self.running.as_deref()
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Dev build: one event per probe with the raw result, the verdict and the
    /// strategy that was active (null = no bypass running).
    fn log_probe(
        &self,
        group: &str,
        target: &Target,
        content: bool,
        result: &Result<HttpsProbeResult, NetError>,
        passed: bool,
        kbps: Option<u32>,
    ) {
        if !devlog::ENABLED {
            return;
        }
        let (status, elapsed_ms, bytes, limited, error) = match result {
            Ok(r) => (
                Some(r.status_code),
                Some(r.elapsed_ms as u64),
                Some(r.bytes_read),
                Some(r.body_limited),
                None,
            ),
            Err(error) => (None, None, None, None, Some(error.0.clone())),
        };
        devlog::event(
            "probe",
            serde_json::json!({
                "strategy": &self.running,
                "group": group,
                "host": &target.host,
                "path": &target.path,
                "content_check": content,
                "max_bytes": target.max_bytes,
                "passed": passed,
                "status": status,
                "elapsed_ms": elapsed_ms,
                "bytes": bytes,
                "body_limited": limited,
                "kbps": kbps,
                "min_kbps": self.min_kbps,
                "error": error,
            }),
        );
    }

    /// Dev build only: has the running engine process exited by itself?
    pub fn engine_exited(&mut self) -> Option<bool> {
        self.process.as_mut().map(|process| process.has_exited())
    }

    /// Starts the engine for a candidate. The dev build adds the engine's own
    /// `--debug=@file` log (per-connection hostnames, chosen desync profile)
    /// and keeps its stdout/stderr, where driver errors appear.
    fn spawn_engine(&self, id: &str, argv: &[String]) -> Result<EngineProcess, EngineError> {
        let Some(log) = devlog::engine_log(id) else {
            return self.engine.spawn(argv);
        };
        let mut full = vec![format!("--debug=@{}", log.debug_arg)];
        full.extend(argv.iter().cloned());
        devlog::event(
            "engine_start",
            serde_json::json!({
                "strategy": id,
                "argv": &full,
                "debug_log": log.debug_path.file_name().map(|n| n.to_string_lossy().into_owned()),
                "output_log": log.output_path.file_name().map(|n| n.to_string_lossy().into_owned()),
            }),
        );
        let output = std::fs::File::create(&log.output_path).ok();
        let result = self.engine.spawn_with_output(&full, output);
        match &result {
            Ok(process) => devlog::event(
                "engine_started",
                serde_json::json!({ "strategy": id, "pid": process.process_id() }),
            ),
            Err(error) => devlog::event(
                "engine_start_failed",
                serde_json::json!({ "strategy": id, "error": error.to_string() }),
            ),
        }
        result
    }

    fn log_engine_output(&self, id: &str) {
        if !devlog::ENABLED {
            return;
        }
        let Some(dir) = devlog::dir() else { return };
        let mut outputs: Vec<_> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".out.txt"))
            .collect();
        outputs.sort_by_key(|e| e.file_name());
        if let Some(last) = outputs.last() {
            devlog::event(
                "engine_output",
                serde_json::json!({
                    "strategy": id,
                    "file": last.file_name().to_string_lossy(),
                    "tail": devlog::read_tail(&last.path(), 4000),
                }),
            );
        }
    }

    fn fetch(&self, target: &Target) -> Result<HttpsProbeResult, NetError> {
        let host = AllowedHost::new(&target.host, NetworkPurpose::Probe)
            .map_err(|error| NetError(error.to_string()))?;
        self.handle
            .block_on(self.prober.get(&host, &target.path, target.max_bytes))
    }

    fn check(&self, targets: &[Target], content: bool, any: bool) -> CheckOutcome {
        let mut outcomes = Vec::new();
        for target in targets {
            if self.cancelled() {
                return CheckOutcome::with_status(CheckStatus::Failed);
            }
            let result = self.fetch(target);
            let outcome = if content {
                content_outcome(&result)
            } else {
                transport_outcome(&result)
            };
            let passed = outcome.status == CheckStatus::Passed;
            self.log_probe(
                if any { "control" } else { "suite" },
                target,
                content,
                &result,
                passed,
                outcome.kbps,
            );
            outcomes.push(outcome);
            // Short-circuit: one pass decides `any`, one failure decides `all`.
            if any == passed {
                break;
            }
        }
        combine(&outcomes, any)
    }
}

impl CandidateTester for LiveTester {
    fn start(&mut self, id: &str) -> Result<(), TesterError> {
        if self.cancelled() {
            return Err(TesterError("cancelled".into()));
        }
        let argv = self
            .argv
            .get(id)
            .ok_or_else(|| TesterError(format!("unknown strategy {id}")))?;
        let process = self
            .spawn_engine(id, argv)
            .map_err(|error| TesterError(error.to_string()))?;
        self.process = Some(process);
        self.running = Some(id.to_owned());
        std::thread::sleep(self.warmup);
        Ok(())
    }

    fn run_check(&mut self, _id: &str, kind: CheckKind) -> CheckOutcome {
        match kind {
            CheckKind::Control => self.check(&self.suite.control, false, true),
            CheckKind::Tls => self.check(&self.suite.tls, false, false),
            CheckKind::Content => self.check(&self.suite.content, true, false),
        }
    }

    fn stop(&mut self, _id: &str) -> Result<(), TesterError> {
        let stopped = self.running.take();
        match self.process.take() {
            Some(mut process) => {
                let result = process
                    .stop()
                    .map_err(|error| TesterError(error.to_string()));
                devlog::event(
                    "engine_stop",
                    serde_json::json!({ "strategy": stopped, "ok": result.is_ok(),
                        "error": result.as_ref().err().map(|e| e.0.clone()) }),
                );
                result
            }
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status_code: u16, bytes_read: usize, elapsed_ms: u128) -> HttpsProbeResult {
        HttpsProbeResult {
            hostname: "t.example".into(),
            status_code,
            elapsed_ms,
            bytes_read,
            body_limited: false,
        }
    }

    #[test]
    fn site_check_reads_past_the_16_kb_stall_budget() {
        let group = TargetGroup::site("example.org");
        assert!(group.checks.iter().all(|(t, _)| t.max_bytes >= 64 * 1024));
    }

    #[test]
    fn combine_uses_any_for_control_all_otherwise_and_slowest_speed() {
        let ok = CheckOutcome::passed();
        let fail = CheckOutcome::with_status(CheckStatus::Failed);
        assert_eq!(combine(&[fail, ok], true).status, CheckStatus::Passed);
        assert_eq!(combine(&[ok, fail], false).status, CheckStatus::Failed);
        assert_eq!(combine(&[], false).status, CheckStatus::Failed);
        let speeds = [CheckOutcome::content(900), CheckOutcome::content(300)];
        assert_eq!(combine(&speeds, false).kbps, Some(300));
    }

    #[test]
    fn any_http_status_passes_transport_but_error_fails() {
        assert_eq!(
            transport_outcome(&Ok(response(403, 0, 10))).status,
            CheckStatus::Passed
        );
        assert_eq!(
            transport_outcome(&Err(NetError("reset".into()))).status,
            CheckStatus::Failed
        );
    }

    #[test]
    fn content_throughput_is_kilobits_per_second() {
        // 125_000 bytes in 1000 ms = 1_000_000 bit/s = 1000 kbit/s.
        let outcome = content_outcome(&Ok(response(200, 125_000, 1000)));
        assert_eq!(outcome.kbps, Some(1000));
        assert_eq!(outcome.status, CheckStatus::Passed);
    }

    #[test]
    fn non_2xx_or_error_content_fails_and_zero_elapsed_is_safe() {
        assert_eq!(
            content_outcome(&Ok(response(403, 1000, 10))).status,
            CheckStatus::Failed
        );
        assert_eq!(
            content_outcome(&Err(NetError("timeout".into()))).status,
            CheckStatus::Failed
        );
        assert_eq!(content_outcome(&Ok(response(200, 800, 0))).kbps, Some(6400));
    }
}
