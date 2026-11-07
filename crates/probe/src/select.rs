//! Pure strategy auto-selection logic: candidate ordering, success criteria,
//! early exit and winner choice. It performs no I/O; the caller supplies a
//! [`CandidateTester`] that starts/stops the single engine instance and runs the
//! checks. All numeric defaults are tunable assumptions, not measured values.

use crate::{CheckStatus, ProbeSignal};
use zapreta_core::ProbeScore;

/// A catalog strategy as seen by the selector. Coverage flags are supplied by
/// the caller because imported snapshots carry only opaque argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub covers_tcp: bool,
    pub covers_udp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchSkip {
    /// Baseline showed no failure, so there is nothing to fix.
    NothingToFix,
    /// The control target is unreachable; enabling an interceptor would hide a
    /// broken network behind a failed search.
    GeneralConnectivity,
    /// DNS-level signals are not addressed by packet desync strategies.
    DnsLayer,
    /// The baseline could not localize the problem.
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchPlan {
    Skip(SearchSkip),
    /// Candidate ids in the order they must be tried.
    Run(Vec<String>),
}

/// Decides whether a search is justified and in which order to try candidates.
/// `preferred` (e.g. a cached winner) is tried first when present. Candidates
/// without TCP coverage go last: every TCP/TLS/content signal needs it.
pub fn plan(signal: ProbeSignal, candidates: &[Candidate], preferred: Option<&str>) -> SearchPlan {
    match signal {
        ProbeSignal::NoObservedFailure => return SearchPlan::Skip(SearchSkip::NothingToFix),
        ProbeSignal::GeneralConnectivityProblem => {
            return SearchPlan::Skip(SearchSkip::GeneralConnectivity);
        }
        ProbeSignal::PossibleDnsDivergence | ProbeSignal::PossibleDnsSinkholeAnswer => {
            return SearchPlan::Skip(SearchSkip::DnsLayer);
        }
        ProbeSignal::Inconclusive => return SearchPlan::Skip(SearchSkip::Inconclusive),
        ProbeSignal::PossibleTcpInterference
        | ProbeSignal::PossibleTlsInterference
        | ProbeSignal::PossibleContentThrottlingOrFailure => {}
    }
    let mut ordered: Vec<&Candidate> = Vec::new();
    for candidate in candidates {
        if !ordered.iter().any(|seen| seen.id == candidate.id) {
            ordered.push(candidate);
        }
    }
    // Stable sort keeps catalog order inside each group.
    ordered.sort_by_key(|candidate| {
        if Some(candidate.id.as_str()) == preferred {
            0
        } else if candidate.covers_tcp {
            1
        } else {
            2
        }
    });
    SearchPlan::Run(ordered.into_iter().map(|c| c.id.clone()).collect())
}

/// Checks run for every candidate, in this order. Control comes first so a
/// candidate that breaks general connectivity is never counted as a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    Control,
    Tls,
    Content,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckOutcome {
    pub status: CheckStatus,
    /// Measured throughput; only meaningful for a passed content check.
    pub kbps: Option<u32>,
}

impl CheckOutcome {
    pub fn passed() -> Self {
        Self {
            status: CheckStatus::Passed,
            kbps: None,
        }
    }

    pub fn content(kbps: u32) -> Self {
        Self {
            status: CheckStatus::Passed,
            kbps: Some(kbps),
        }
    }

    pub fn with_status(status: CheckStatus) -> Self {
        Self { status, kbps: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TesterError(pub String);

/// Implemented by the real engine/probe glue and by mocks in tests. Only one
/// candidate may be running at a time.
pub trait CandidateTester {
    fn start(&mut self, id: &str) -> Result<(), TesterError>;
    fn run_check(&mut self, id: &str, kind: CheckKind) -> CheckOutcome;
    /// Must confirm the engine has exited; a failure aborts the whole search.
    fn stop(&mut self, id: &str) -> Result<(), TesterError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionConfig {
    /// Suite repetitions per candidate.
    pub runs: u8,
    /// Runs in which every check must pass for the candidate to qualify.
    pub min_successful_runs: u8,
    /// A passed content check slower than this counts as throttled/failed.
    pub min_kbps: u32,
    /// Consecutive candidates failing the control check before the search is
    /// abandoned as a network problem.
    pub max_consecutive_control_failures: u8,
    /// Stop at the first candidate that qualifies and revalidates.
    pub stop_at_first: bool,
    /// Suite repetitions for the post-qualification revalidation.
    pub revalidation_runs: u8,
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            runs: 3,
            min_successful_runs: 2,
            min_kbps: 500,
            max_consecutive_control_failures: 3,
            stop_at_first: true,
            revalidation_runs: 2,
        }
    }
}

impl SelectionConfig {
    fn normalized(self) -> Self {
        let runs = self.runs.max(1);
        Self {
            runs,
            min_successful_runs: self.min_successful_runs.clamp(1, runs),
            revalidation_runs: self.revalidation_runs.max(1),
            ..self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateStatus {
    Qualified {
        points: u32,
    },
    /// The control target failed with this candidate active.
    ControlFailed,
    /// No run succeeded; carries the first check that failed.
    CheckFailed(CheckKind),
    /// Some runs succeeded, but fewer than required.
    InsufficientRuns {
        successes: u8,
        required: u8,
    },
    /// Qualified once, then failed the repeat validation.
    RevalidationFailed,
    EngineStartFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateReport {
    pub id: String,
    pub status: CandidateStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// Too many candidates in a row failed the control target.
    NetworkLooksDown,
    /// The engine could not be confirmed stopped; no further candidates run.
    EngineStopFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionOutcome {
    Skipped(SearchSkip),
    Selected { id: String, points: u32 },
    NoWinner,
    Aborted(AbortReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionReport {
    pub outcome: SelectionOutcome,
    pub candidates: Vec<CandidateReport>,
}

struct SuiteResult {
    control_failed: bool,
    successes: u8,
    tls_passes: u8,
    content_passes: u8,
    kbps: Vec<u32>,
    first_failure: Option<CheckKind>,
}

fn run_suite<T: CandidateTester>(
    tester: &mut T,
    id: &str,
    runs: u8,
    required: u8,
    min_kbps: u32,
) -> SuiteResult {
    let mut result = SuiteResult {
        control_failed: false,
        successes: 0,
        tls_passes: 0,
        content_passes: 0,
        kbps: Vec::new(),
        first_failure: None,
    };
    for done in 0..runs {
        if tester.run_check(id, CheckKind::Control).status != CheckStatus::Passed {
            result.control_failed = true;
            break;
        }
        let mut fail = |kind| {
            result.first_failure.get_or_insert(kind);
        };
        let mut run_ok = true;
        if tester.run_check(id, CheckKind::Tls).status == CheckStatus::Passed {
            result.tls_passes += 1;
            let content = tester.run_check(id, CheckKind::Content);
            match (content.status, content.kbps) {
                (CheckStatus::Passed, Some(kbps)) if kbps >= min_kbps => {
                    result.content_passes += 1;
                    result.kbps.push(kbps);
                }
                _ => {
                    fail(CheckKind::Content);
                    run_ok = false;
                }
            }
        } else {
            fail(CheckKind::Tls);
            run_ok = false;
        }
        if run_ok {
            result.successes += 1;
        } else if done == 0 {
            // First run failed a critical check: do not spend the rest of the budget.
            break;
        }
        let remaining = runs - done - 1;
        if result.successes + remaining < required {
            break;
        }
    }
    result
}

fn median(values: &[u32]) -> u32 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.get(sorted.len() / 2).copied().unwrap_or(0)
}

fn judge(suite: &SuiteResult, runs: u8, required: u8) -> CandidateStatus {
    if suite.control_failed {
        return CandidateStatus::ControlFailed;
    }
    if suite.successes == 0 {
        return CandidateStatus::CheckFailed(suite.first_failure.unwrap_or(CheckKind::Content));
    }
    if suite.successes < required {
        return CandidateStatus::InsufficientRuns {
            successes: suite.successes,
            required,
        };
    }
    let score = ProbeScore {
        control_site_ok: true,
        tls_ok: suite.tls_passes >= required,
        content_ok: suite.content_passes >= required,
        median_kbps: median(&suite.kbps),
        successful_runs: suite.successes,
        total_runs: runs,
    };
    match score.points() {
        Some(points) => CandidateStatus::Qualified { points },
        None => CandidateStatus::CheckFailed(suite.first_failure.unwrap_or(CheckKind::Content)),
    }
}

/// Starts one candidate, runs the suite, always stops it again. Used directly
/// for the cached-winner fast path with a one-run config.
pub fn evaluate_candidate<T: CandidateTester>(
    tester: &mut T,
    id: &str,
    config: &SelectionConfig,
) -> Result<CandidateStatus, AbortReason> {
    let config = config.normalized();
    if let Err(error) = tester.start(id) {
        return Ok(CandidateStatus::EngineStartFailed(error.0));
    }
    let suite = run_suite(
        tester,
        id,
        config.runs,
        config.min_successful_runs,
        config.min_kbps,
    );
    tester.stop(id).map_err(|_| AbortReason::EngineStopFailed)?;
    let mut status = judge(&suite, config.runs, config.min_successful_runs);
    if matches!(status, CandidateStatus::Qualified { .. }) {
        // Revalidate on a fresh engine start, requiring every revalidation run.
        if let Err(error) = tester.start(id) {
            return Ok(CandidateStatus::EngineStartFailed(error.0));
        }
        let again = run_suite(
            tester,
            id,
            config.revalidation_runs,
            config.revalidation_runs,
            config.min_kbps,
        );
        tester.stop(id).map_err(|_| AbortReason::EngineStopFailed)?;
        if !matches!(
            judge(&again, config.revalidation_runs, config.revalidation_runs),
            CandidateStatus::Qualified { .. }
        ) {
            status = CandidateStatus::RevalidationFailed;
        }
    }
    Ok(status)
}

/// Tries the planned candidates sequentially and picks the winner.
pub fn select_strategy<T: CandidateTester>(
    tester: &mut T,
    plan: &SearchPlan,
    config: &SelectionConfig,
) -> SelectionReport {
    let ids = match plan {
        SearchPlan::Skip(reason) => {
            return SelectionReport {
                outcome: SelectionOutcome::Skipped(*reason),
                candidates: Vec::new(),
            };
        }
        SearchPlan::Run(ids) => ids,
    };
    let config = config.normalized();
    let mut reports = Vec::new();
    let mut best: Option<(String, u32)> = None;
    let mut control_streak: u8 = 0;
    for id in ids {
        let status = match evaluate_candidate(tester, id, &config) {
            Ok(status) => status,
            Err(reason) => {
                return SelectionReport {
                    outcome: SelectionOutcome::Aborted(reason),
                    candidates: reports,
                };
            }
        };
        control_streak = if status == CandidateStatus::ControlFailed {
            control_streak + 1
        } else {
            0
        };
        if let CandidateStatus::Qualified { points } = status {
            // Strictly greater: ties keep the earlier (higher-priority) candidate.
            if best.as_ref().is_none_or(|(_, top)| points > *top) {
                best = Some((id.clone(), points));
            }
        }
        reports.push(CandidateReport {
            id: id.clone(),
            status,
        });
        if best.is_some() && config.stop_at_first {
            break;
        }
        if control_streak >= config.max_consecutive_control_failures {
            return SelectionReport {
                outcome: SelectionOutcome::Aborted(AbortReason::NetworkLooksDown),
                candidates: reports,
            };
        }
    }
    let outcome = match best {
        Some((id, points)) => SelectionOutcome::Selected { id, points },
        None => SelectionOutcome::NoWinner,
    };
    SelectionReport {
        outcome,
        candidates: reports,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cand(id: &str, tcp: bool, udp: bool) -> Candidate {
        Candidate {
            id: id.into(),
            covers_tcp: tcp,
            covers_udp: udp,
        }
    }

    #[derive(Clone, Copy)]
    enum Behavior {
        Works(u32),
        TlsDrop,
        Throttled(u32),
        BreaksControl,
        FailsOnRepeat(u32),
        StartFails,
        StopFails,
    }

    struct Mock {
        behaviors: HashMap<&'static str, Behavior>,
        log: Vec<String>,
        starts: HashMap<String, u32>,
        running: Option<String>,
    }

    impl Mock {
        fn new(items: &[(&'static str, Behavior)]) -> Self {
            Self {
                behaviors: items.iter().copied().collect(),
                log: Vec::new(),
                starts: HashMap::new(),
                running: None,
            }
        }
        fn checks(&self, id: &str) -> usize {
            self.log
                .iter()
                .filter(|entry| entry.starts_with(&format!("{id}:")))
                .count()
        }
    }

    impl CandidateTester for Mock {
        fn start(&mut self, id: &str) -> Result<(), TesterError> {
            assert!(self.running.is_none(), "parallel engines are forbidden");
            if matches!(self.behaviors[id], Behavior::StartFails) {
                return Err(TesterError("spawn failed".into()));
            }
            *self.starts.entry(id.into()).or_default() += 1;
            self.running = Some(id.into());
            Ok(())
        }
        fn run_check(&mut self, id: &str, kind: CheckKind) -> CheckOutcome {
            assert_eq!(self.running.as_deref(), Some(id));
            self.log.push(format!("{id}:{kind:?}"));
            let start = self.starts[id];
            match (self.behaviors[id], kind) {
                (Behavior::BreaksControl, CheckKind::Control) => {
                    CheckOutcome::with_status(CheckStatus::TimedOut)
                }
                (Behavior::TlsDrop, CheckKind::Tls) => {
                    CheckOutcome::with_status(CheckStatus::Failed)
                }
                (Behavior::Throttled(kbps), CheckKind::Content)
                | (Behavior::Works(kbps), CheckKind::Content) => CheckOutcome::content(kbps),
                (Behavior::FailsOnRepeat(kbps), CheckKind::Content) => {
                    if start >= 2 {
                        CheckOutcome::with_status(CheckStatus::TimedOut)
                    } else {
                        CheckOutcome::content(kbps)
                    }
                }
                _ => CheckOutcome::passed(),
            }
        }
        fn stop(&mut self, id: &str) -> Result<(), TesterError> {
            assert_eq!(self.running.as_deref(), Some(id));
            if matches!(self.behaviors[id], Behavior::StopFails) {
                return Err(TesterError("still running".into()));
            }
            self.running = None;
            Ok(())
        }
    }

    fn run_plan(ids: &[&str]) -> SearchPlan {
        SearchPlan::Run(ids.iter().map(|id| id.to_string()).collect())
    }

    #[test]
    fn no_search_when_baseline_does_not_justify_it() {
        let c = [cand("a", true, false)];
        for (signal, skip) in [
            (ProbeSignal::NoObservedFailure, SearchSkip::NothingToFix),
            (
                ProbeSignal::GeneralConnectivityProblem,
                SearchSkip::GeneralConnectivity,
            ),
            (ProbeSignal::PossibleDnsDivergence, SearchSkip::DnsLayer),
            (ProbeSignal::PossibleDnsSinkholeAnswer, SearchSkip::DnsLayer),
            (ProbeSignal::Inconclusive, SearchSkip::Inconclusive),
        ] {
            assert_eq!(plan(signal, &c, None), SearchPlan::Skip(skip));
        }
    }

    #[test]
    fn order_prefers_cached_winner_then_tcp_coverage_keeping_catalog_order() {
        let c = [
            cand("udp-only", false, true),
            cand("a", true, false),
            cand("b", true, true),
            cand("a", true, false),
            cand("cached", true, false),
        ];
        assert_eq!(
            plan(ProbeSignal::PossibleTlsInterference, &c, Some("cached")),
            run_plan(&["cached", "a", "b", "udp-only"])
        );
    }

    #[test]
    fn first_working_candidate_wins_and_search_stops() {
        let mut mock = Mock::new(&[
            ("a", Behavior::TlsDrop),
            ("b", Behavior::Works(4_000)),
            ("c", Behavior::Works(9_000)),
        ]);
        let report = select_strategy(
            &mut mock,
            &run_plan(&["a", "b", "c"]),
            &SelectionConfig::default(),
        );
        assert!(matches!(
            report.outcome,
            SelectionOutcome::Selected { ref id, .. } if id == "b"
        ));
        assert_eq!(mock.checks("c"), 0);
        assert!(mock.running.is_none());
    }

    #[test]
    fn critical_failure_in_first_run_exits_early() {
        let mut mock = Mock::new(&[("a", Behavior::TlsDrop)]);
        let report = select_strategy(&mut mock, &run_plan(&["a"]), &SelectionConfig::default());
        assert_eq!(report.outcome, SelectionOutcome::NoWinner);
        assert_eq!(
            report.candidates[0].status,
            CandidateStatus::CheckFailed(CheckKind::Tls)
        );
        // One control + one TLS check, no content check, no further runs.
        assert_eq!(mock.checks("a"), 2);
    }

    #[test]
    fn throttled_content_is_not_a_success() {
        let mut mock = Mock::new(&[("a", Behavior::Throttled(50))]);
        let report = select_strategy(&mut mock, &run_plan(&["a"]), &SelectionConfig::default());
        assert_eq!(
            report.candidates[0].status,
            CandidateStatus::CheckFailed(CheckKind::Content)
        );
    }

    #[test]
    fn best_score_wins_when_not_stopping_at_first_and_ties_keep_earlier() {
        let mut mock = Mock::new(&[
            ("slow", Behavior::Works(1_000)),
            ("fast", Behavior::Works(20_000)),
            ("fast2", Behavior::Works(20_000)),
        ]);
        let config = SelectionConfig {
            stop_at_first: false,
            ..SelectionConfig::default()
        };
        let report = select_strategy(&mut mock, &run_plan(&["slow", "fast", "fast2"]), &config);
        assert!(matches!(
            report.outcome,
            SelectionOutcome::Selected { ref id, .. } if id == "fast"
        ));
    }

    #[test]
    fn candidate_that_fails_revalidation_cannot_win() {
        let mut mock = Mock::new(&[
            ("flaky", Behavior::FailsOnRepeat(5_000)),
            ("steady", Behavior::Works(3_000)),
        ]);
        let report = select_strategy(
            &mut mock,
            &run_plan(&["flaky", "steady"]),
            &SelectionConfig::default(),
        );
        assert_eq!(
            report.candidates[0].status,
            CandidateStatus::RevalidationFailed
        );
        assert!(matches!(
            report.outcome,
            SelectionOutcome::Selected { ref id, .. } if id == "steady"
        ));
    }

    #[test]
    fn control_failures_in_a_row_abort_as_network_problem() {
        let mut mock = Mock::new(&[
            ("a", Behavior::BreaksControl),
            ("b", Behavior::BreaksControl),
            ("c", Behavior::BreaksControl),
            ("d", Behavior::Works(5_000)),
        ]);
        let report = select_strategy(
            &mut mock,
            &run_plan(&["a", "b", "c", "d"]),
            &SelectionConfig::default(),
        );
        assert_eq!(
            report.outcome,
            SelectionOutcome::Aborted(AbortReason::NetworkLooksDown)
        );
        assert_eq!(report.candidates.len(), 3);
        assert_eq!(mock.checks("d"), 0);
    }

    #[test]
    fn control_streak_resets_after_a_non_control_result() {
        let mut mock = Mock::new(&[
            ("a", Behavior::BreaksControl),
            ("b", Behavior::BreaksControl),
            ("c", Behavior::TlsDrop),
            ("d", Behavior::BreaksControl),
            ("e", Behavior::BreaksControl),
        ]);
        let report = select_strategy(
            &mut mock,
            &run_plan(&["a", "b", "c", "d", "e"]),
            &SelectionConfig::default(),
        );
        assert_eq!(report.outcome, SelectionOutcome::NoWinner);
        assert_eq!(report.candidates.len(), 5);
    }

    #[test]
    fn start_failure_skips_candidate_and_stop_failure_aborts() {
        let mut mock = Mock::new(&[
            ("nostart", Behavior::StartFails),
            ("stuck", Behavior::StopFails),
            ("never", Behavior::Works(5_000)),
        ]);
        let report = select_strategy(
            &mut mock,
            &run_plan(&["nostart", "stuck", "never"]),
            &SelectionConfig::default(),
        );
        assert_eq!(
            report.candidates[0].status,
            CandidateStatus::EngineStartFailed("spawn failed".into())
        );
        assert_eq!(
            report.outcome,
            SelectionOutcome::Aborted(AbortReason::EngineStopFailed)
        );
        assert_eq!(mock.checks("never"), 0);
    }

    #[test]
    fn skipped_plan_runs_nothing() {
        let mut mock = Mock::new(&[]);
        let report = select_strategy(
            &mut mock,
            &SearchPlan::Skip(SearchSkip::DnsLayer),
            &SelectionConfig::default(),
        );
        assert_eq!(
            report.outcome,
            SelectionOutcome::Skipped(SearchSkip::DnsLayer)
        );
        assert!(mock.log.is_empty());
    }

    #[test]
    fn cached_winner_fast_path_uses_a_single_candidate_evaluation() {
        let mut mock = Mock::new(&[("cached", Behavior::Works(2_000))]);
        let config = SelectionConfig {
            runs: 1,
            min_successful_runs: 1,
            revalidation_runs: 1,
            ..SelectionConfig::default()
        };
        let status = evaluate_candidate(&mut mock, "cached", &config).unwrap();
        assert!(matches!(status, CandidateStatus::Qualified { .. }));
        assert!(mock.running.is_none());
    }
}
