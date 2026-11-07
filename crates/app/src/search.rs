//! Multi-target strategy search. Each target (YouTube, each user site) is
//! judged separately; a strategy wins by fixing more targets than the network
//! does without it, so a site that no strategy can fix (for example because
//! of DNS spoofing) no longer disqualifies a strategy that fixes the others.

/// What happened when a candidate was started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// The engine cannot run at all (conflicting bypass, missing file, ...);
    /// every other candidate would fail the same way.
    Fatal(String),
    /// The engine exited right after starting with this candidate.
    Exited,
}

pub trait Probe {
    fn start(&mut self, id: &str) -> Result<(), StartError>;
    fn stop(&mut self, id: &str) -> Result<(), String>;
    /// Is general internet access fine (any control site answers)?
    fn control(&mut self) -> bool;
    fn target(&mut self, index: usize) -> bool;
    fn cancelled(&self) -> bool;
    fn progress(&mut self, _tried: usize, _total: usize, _id: &str) {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Works { results: Vec<bool> },
    NoImprovement { results: Vec<bool> },
    BreaksInternet,
    Exited,
    RevalidationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub id: String,
    /// Per-target result of the revalidation run; the winner is left running.
    pub results: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchError {
    NoInternet,
    /// Every target already works without a bypass.
    NothingToFix,
    Fatal(String),
    /// Every candidate made the engine exit immediately.
    EngineExits,
    /// Several candidates in a row broke all internet access.
    BreaksInternet,
    NothingHelped,
    StopFailed(String),
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub baseline: Vec<bool>,
    pub verdicts: Vec<(String, Verdict)>,
    pub result: Result<Found, SearchError>,
}

const MAX_BREAKS_IN_A_ROW: usize = 3;

fn score(results: &[bool]) -> usize {
    results.iter().filter(|ok| **ok).count()
}

fn run_targets<P: Probe>(probe: &mut P, count: usize) -> Vec<bool> {
    (0..count)
        .map(|index| !probe.cancelled() && probe.target(index))
        .collect()
}

/// Order: cached winner first, then the given order.
fn ordered(candidates: &[String], cached: Option<&str>) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    if let Some(id) = cached.filter(|id| candidates.iter().any(|c| c == id)) {
        list.push(id.to_owned());
    }
    for id in candidates {
        if !list.contains(id) {
            list.push(id.clone());
        }
    }
    list
}

/// `force`: search even if every target already works (user asked for it).
pub fn search<P: Probe>(
    probe: &mut P,
    candidates: &[String],
    cached: Option<&str>,
    targets: usize,
    force: bool,
) -> Report {
    let mut report = Report {
        baseline: Vec::new(),
        verdicts: Vec::new(),
        result: Err(SearchError::NothingHelped),
    };
    if !probe.control() {
        report.result = Err(if probe.cancelled() {
            SearchError::Cancelled
        } else {
            SearchError::NoInternet
        });
        return report;
    }
    report.baseline = run_targets(probe, targets);
    let base = score(&report.baseline);
    if base == targets && !force {
        report.result = Err(SearchError::NothingToFix);
        return report;
    }

    let order = ordered(candidates, cached);
    let total = order.len();
    // (score, position, id) of every candidate that improved on the baseline.
    let mut qualified: Vec<(usize, usize, String)> = Vec::new();
    let mut breaks_in_a_row = 0;
    let mut exits = 0;
    for (position, id) in order.iter().enumerate() {
        if probe.cancelled() {
            report.result = Err(SearchError::Cancelled);
            return report;
        }
        probe.progress(position + 1, total, id);
        match probe.start(id) {
            Ok(()) => {}
            Err(StartError::Fatal(message)) => {
                report.result = Err(SearchError::Fatal(message));
                return report;
            }
            Err(StartError::Exited) => {
                exits += 1;
                report.verdicts.push((id.clone(), Verdict::Exited));
                continue;
            }
        }
        let control = probe.control();
        let results = if control {
            run_targets(probe, targets)
        } else {
            Vec::new()
        };
        if let Err(message) = probe.stop(id) {
            report.result = Err(SearchError::StopFailed(message));
            return report;
        }
        if probe.cancelled() {
            report.result = Err(SearchError::Cancelled);
            return report;
        }
        if !control {
            breaks_in_a_row += 1;
            report.verdicts.push((id.clone(), Verdict::BreaksInternet));
            if breaks_in_a_row >= MAX_BREAKS_IN_A_ROW {
                report.result = Err(SearchError::BreaksInternet);
                return report;
            }
            continue;
        }
        breaks_in_a_row = 0;
        let got = score(&results);
        // With nothing broken in the baseline (forced run), "no worse" counts.
        let improves = got > base || (base == targets && got == targets);
        if improves {
            qualified.push((got, position, id.clone()));
            report
                .verdicts
                .push((id.clone(), Verdict::Works { results }));
            if got == targets {
                break;
            }
        } else {
            report
                .verdicts
                .push((id.clone(), Verdict::NoImprovement { results }));
        }
    }

    // Best score first; earlier (higher-priority) candidate on ties.
    qualified.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (expected, _, id) in qualified {
        if probe.cancelled() {
            report.result = Err(SearchError::Cancelled);
            return report;
        }
        match probe.start(&id) {
            Ok(()) => {}
            Err(StartError::Fatal(message)) => {
                report.result = Err(SearchError::Fatal(message));
                return report;
            }
            Err(StartError::Exited) => continue,
        }
        let results = if probe.control() {
            run_targets(probe, targets)
        } else {
            Vec::new()
        };
        // Allow one flaky target, but it must still beat the baseline.
        let got = score(&results);
        if got > base.min(targets.saturating_sub(1)) && got + 1 >= expected {
            report.result = Ok(Found { id, results });
            return report;
        }
        if let Err(message) = probe.stop(&id) {
            report.result = Err(SearchError::StopFailed(message));
            return report;
        }
        if let Some(entry) = report.verdicts.iter_mut().find(|(v, _)| *v == id) {
            entry.1 = Verdict::RevalidationFailed;
        }
    }
    report.result = Err(if total > 0 && exits == total {
        SearchError::EngineExits
    } else {
        SearchError::NothingHelped
    });
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Per-candidate target results; `None` = breaks internet.
    struct Mock {
        baseline: Vec<bool>,
        table: HashMap<String, Option<Vec<bool>>>,
        running: Option<String>,
        starts: Vec<String>,
        fatal: Option<String>,
        exits: Vec<String>,
        flaky_second_start: Vec<String>,
    }

    impl Mock {
        fn new(baseline: &[bool], rows: &[(&str, Option<&[bool]>)]) -> Self {
            Self {
                baseline: baseline.to_vec(),
                table: rows
                    .iter()
                    .map(|(id, r)| (id.to_string(), r.map(|r| r.to_vec())))
                    .collect(),
                running: None,
                starts: Vec::new(),
                fatal: None,
                exits: Vec::new(),
                flaky_second_start: Vec::new(),
            }
        }
        fn row(&self) -> Option<Vec<bool>> {
            match &self.running {
                None => Some(self.baseline.clone()),
                Some(id) => {
                    let second = self.starts.iter().filter(|s| *s == id).count() > 1;
                    if second && self.flaky_second_start.contains(id) {
                        return Some(vec![false; self.baseline.len()]);
                    }
                    self.table[id].clone()
                }
            }
        }
    }

    impl Probe for Mock {
        fn start(&mut self, id: &str) -> Result<(), StartError> {
            assert!(self.running.is_none(), "only one engine at a time");
            if let Some(message) = &self.fatal {
                return Err(StartError::Fatal(message.clone()));
            }
            if self.exits.iter().any(|e| e == id) {
                return Err(StartError::Exited);
            }
            self.starts.push(id.to_owned());
            self.running = Some(id.to_owned());
            Ok(())
        }
        fn stop(&mut self, _id: &str) -> Result<(), String> {
            self.running = None;
            Ok(())
        }
        fn control(&mut self) -> bool {
            self.row().is_some()
        }
        fn target(&mut self, index: usize) -> bool {
            self.row().map(|r| r[index]).unwrap_or(false)
        }
        fn cancelled(&self) -> bool {
            false
        }
    }

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn partial_fix_wins_when_one_site_can_never_be_fixed() {
        // Target 0 = YouTube, 1 = a DNS-spoofed site no strategy fixes.
        let mut mock = Mock::new(
            &[false, false],
            &[("a", Some(&[false, false])), ("b", Some(&[true, false]))],
        );
        let report = search(&mut mock, &ids(&["a", "b"]), None, 2, false);
        let found = report.result.unwrap();
        assert_eq!(found.id, "b");
        assert_eq!(found.results, vec![true, false]);
        assert_eq!(mock.running.as_deref(), Some("b"), "winner left running");
    }

    #[test]
    fn full_fix_stops_the_search_early_and_beats_partial() {
        let mut mock = Mock::new(
            &[false, false],
            &[
                ("a", Some(&[true, false])),
                ("b", Some(&[true, true])),
                ("c", Some(&[true, true])),
            ],
        );
        let report = search(&mut mock, &ids(&["a", "b", "c"]), None, 2, false);
        assert_eq!(report.result.unwrap().id, "b");
        assert!(!mock.starts.contains(&"c".to_string()));
    }

    #[test]
    fn conflicting_bypass_aborts_with_its_message_at_once() {
        let mut mock = Mock::new(&[false], &[("a", Some(&[true])), ("b", Some(&[true]))]);
        mock.fatal = Some("winws.exe already running".into());
        let report = search(&mut mock, &ids(&["a", "b"]), None, 1, false);
        assert_eq!(
            report.result,
            Err(SearchError::Fatal("winws.exe already running".into()))
        );
    }

    #[test]
    fn engine_exiting_for_every_candidate_is_reported_as_such() {
        let mut mock = Mock::new(&[false], &[("a", Some(&[true])), ("b", Some(&[true]))]);
        mock.exits = ids(&["a", "b"]);
        let report = search(&mut mock, &ids(&["a", "b"]), None, 1, false);
        assert_eq!(report.result, Err(SearchError::EngineExits));
    }

    #[test]
    fn no_internet_and_nothing_to_fix_do_not_start_the_engine() {
        let mut mock = Mock::new(&[true], &[("a", Some(&[true]))]);
        let report = search(&mut mock, &ids(&["a"]), None, 1, false);
        assert_eq!(report.result, Err(SearchError::NothingToFix));
        assert!(mock.starts.is_empty());
        // A forced run accepts a candidate that keeps everything working.
        let report = search(&mut mock, &ids(&["a"]), None, 1, true);
        assert_eq!(report.result.unwrap().id, "a");
    }

    #[test]
    fn breaking_internet_three_times_in_a_row_aborts() {
        let mut mock = Mock::new(
            &[false],
            &[("a", None), ("b", None), ("c", None), ("d", Some(&[true]))],
        );
        let report = search(&mut mock, &ids(&["a", "b", "c", "d"]), None, 1, false);
        assert_eq!(report.result, Err(SearchError::BreaksInternet));
        assert!(!mock.starts.contains(&"d".to_string()));
    }

    #[test]
    fn flaky_winner_falls_back_to_next_best() {
        let mut mock = Mock::new(
            &[false, false],
            &[("a", Some(&[true, false])), ("b", Some(&[true, false]))],
        );
        mock.flaky_second_start = ids(&["a"]);
        let report = search(&mut mock, &ids(&["a", "b"]), None, 2, false);
        assert_eq!(report.result.unwrap().id, "b");
        assert!(
            report
                .verdicts
                .iter()
                .any(|(id, v)| id == "a" && *v == Verdict::RevalidationFailed)
        );
    }

    #[test]
    fn cached_winner_is_tried_first() {
        let mut mock = Mock::new(&[false], &[("a", Some(&[true])), ("b", Some(&[true]))]);
        let report = search(&mut mock, &ids(&["a", "b"]), Some("b"), 1, false);
        assert_eq!(report.result.unwrap().id, "b");
        assert_eq!(mock.starts[0], "b");
    }

    #[test]
    fn nothing_helped_when_no_candidate_improves() {
        let mut mock = Mock::new(&[false], &[("a", Some(&[false]))]);
        let report = search(&mut mock, &ids(&["a"]), None, 1, false);
        assert_eq!(report.result, Err(SearchError::NothingHelped));
        assert!(mock.running.is_none());
    }
}
