//! Glue between the pure selection logic in `zapreta-probe` and the real engine
//! and HTTPS client. Mapping helpers are pure and unit-tested; `LiveTester`
//! itself needs a verified engine binary and is exercised only on Windows.

use std::{collections::HashMap, time::Duration};
use tokio::runtime::Handle;
use zapreta_engine::{EngineProcess, VerifiedEngine};
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
#[derive(Debug, Clone)]
pub struct Target {
    pub host: &'static str,
    pub path: &'static str,
    pub max_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct Suite {
    pub control: Target,
    pub tls: Target,
    /// Stand-in for a video chunk: a bounded read from the target site. Real
    /// video-CDN URLs are dynamic and are still an open question.
    pub content: Target,
}

impl Default for Suite {
    fn default() -> Self {
        Self {
            control: Target {
                host: "example.com",
                path: "/",
                max_bytes: 16 * 1024,
            },
            tls: Target {
                host: "www.youtube.com",
                path: "/generate_204",
                max_bytes: 16 * 1024,
            },
            content: Target {
                host: "www.youtube.com",
                path: "/",
                max_bytes: 256 * 1024,
            },
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
    engine: VerifiedEngine,
    argv: HashMap<String, Vec<String>>,
    suite: Suite,
    warmup: Duration,
    process: Option<EngineProcess>,
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
            prober: HttpsProber::new(Duration::from_secs(8))?,
            engine,
            argv,
            suite,
            // Assumption: winws needs about this long to install its filter.
            warmup: Duration::from_millis(1500),
            process: None,
        })
    }

    fn fetch(&self, target: &Target) -> Result<HttpsProbeResult, NetError> {
        let host = AllowedHost::new(target.host, NetworkPurpose::Probe)
            .map_err(|error| NetError(error.to_string()))?;
        self.handle
            .block_on(self.prober.get(&host, target.path, target.max_bytes))
    }
}

impl CandidateTester for LiveTester {
    fn start(&mut self, id: &str) -> Result<(), TesterError> {
        let argv = self
            .argv
            .get(id)
            .ok_or_else(|| TesterError(format!("unknown strategy {id}")))?;
        let process = self
            .engine
            .spawn(argv)
            .map_err(|error| TesterError(error.to_string()))?;
        self.process = Some(process);
        std::thread::sleep(self.warmup);
        Ok(())
    }

    fn run_check(&mut self, _id: &str, kind: CheckKind) -> CheckOutcome {
        match kind {
            CheckKind::Control => transport_outcome(&self.fetch(&self.suite.control)),
            CheckKind::Tls => transport_outcome(&self.fetch(&self.suite.tls)),
            CheckKind::Content => content_outcome(&self.fetch(&self.suite.content)),
        }
    }

    fn stop(&mut self, _id: &str) -> Result<(), TesterError> {
        match self.process.take() {
            Some(mut process) => process
                .stop()
                .map_err(|error| TesterError(error.to_string())),
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
