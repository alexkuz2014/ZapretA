//! Background worker that owns the engine: unpacks it, selects a strategy,
//! keeps the winner running, watches for degradation and applies list edits.
//! The UI talks to it through [`Controller`] only.

use crate::{
    autoselect::{self, LiveTester, Loaded, Suite},
    bundle,
    embedded::{ENGINE_ID, SNAPSHOTS, WINWS_SHA256},
    generated,
    lists::{self, ListKind},
    settings::Settings,
};
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    thread,
    time::Duration,
};
use zapreta_probe::{
    ProbeSignal,
    select::{
        Candidate, CandidateStatus, CandidateTester, CheckKind, CheckOutcome, SearchPlan,
        SearchSkip, SelectionConfig, SelectionOutcome, TesterError, evaluate_candidate, plan,
        select_strategy,
    },
};

const HEALTH_INTERVAL: Duration = Duration::from_secs(90);
/// Consecutive failed health checks before a re-search.
const HEALTH_FAILURES: u8 = 2;
const RESEARCH_COOLDOWN: Duration = Duration::from_secs(300);
const MAX_FAILED_RESEARCHES: u8 = 3;
const LOG_LINES: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Off,
    Preparing,
    Checking,
    Searching {
        tried: usize,
        total: usize,
        label: String,
    },
    Running {
        label: String,
    },
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub phase: Phase,
    pub log: Vec<String>,
    pub baseline: Option<ProbeSignal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Enable,
    Disable,
    /// Ignore the cached winner and search all candidates.
    Research,
    /// User lists changed: restart the running strategy so the engine re-reads them.
    ReloadLists,
    Shutdown,
}

struct Shared {
    phase: Phase,
    log: VecDeque<String>,
    baseline: Option<ProbeSignal>,
}

pub struct Controller {
    tx: Sender<Command>,
    shared: Arc<Mutex<Shared>>,
    cancel: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

pub struct Paths {
    pub engine_root: PathBuf,
    pub settings: PathBuf,
}

impl Paths {
    pub fn default_paths() -> Option<Self> {
        let engine_root = bundle::default_root()?;
        let settings = engine_root.parent()?.join("settings.toml");
        Some(Self {
            engine_root,
            settings,
        })
    }
}

impl Controller {
    /// `notify` is called after every state change (e.g. to repaint the UI).
    pub fn spawn(paths: Paths, notify: Box<dyn Fn() + Send>) -> Self {
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(Mutex::new(Shared {
            phase: Phase::Off,
            log: VecDeque::new(),
            baseline: None,
        }));
        let cancel = Arc::new(AtomicBool::new(false));
        let worker = {
            let shared = Arc::clone(&shared);
            let cancel = Arc::clone(&cancel);
            thread::spawn(move || {
                let mut worker = Worker {
                    paths,
                    shared,
                    cancel,
                    notify,
                    rx,
                    tester: None,
                    loaded: Vec::new(),
                    failed_researches: 0,
                    retry_pending: false,
                };
                worker.run();
            })
        };
        Self {
            tx,
            shared,
            cancel,
            worker: Some(worker),
        }
    }

    pub fn send(&self, command: Command) {
        if matches!(
            command,
            Command::Disable | Command::Research | Command::Shutdown
        ) {
            // Drains a running search; the worker clears it before handling.
            self.cancel.store(true, Ordering::SeqCst);
        }
        let _ = self.tx.send(command);
    }

    pub fn snapshot(&self) -> Snapshot {
        let shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        Snapshot {
            phase: shared.phase.clone(),
            log: shared.log.iter().cloned().collect(),
            baseline: shared.baseline,
        }
    }

    /// Stops the engine and waits for the worker to exit.
    pub fn shutdown(&mut self) {
        self.send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Prints progress while the selector runs and honours cancellation.
struct Progress<'a> {
    inner: &'a mut LiveTester,
    shared: &'a Arc<Mutex<Shared>>,
    notify: &'a (dyn Fn() + Send),
    labels: &'a HashMap<String, String>,
    total: usize,
    tried: usize,
}

impl CandidateTester for Progress<'_> {
    fn start(&mut self, id: &str) -> Result<(), TesterError> {
        self.tried += 1;
        let label = self
            .labels
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_owned());
        {
            let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            shared.phase = Phase::Searching {
                tried: self.tried,
                total: self.total,
                label,
            };
        }
        (self.notify)();
        self.inner.start(id)
    }
    fn run_check(&mut self, id: &str, kind: CheckKind) -> CheckOutcome {
        self.inner.run_check(id, kind)
    }
    fn stop(&mut self, id: &str) -> Result<(), TesterError> {
        self.inner.stop(id)
    }
}

/// Upstream default first, then the rest of Flowseal in file order, then ours.
pub fn all_candidates() -> Result<Vec<Loaded>, String> {
    let mut loaded = SNAPSHOTS
        .iter()
        .map(|(name, text)| autoselect::parse_snapshot(text).map_err(|e| format!("{name}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    loaded.sort_by_key(|item| item.id != "flowseal-general-default");
    for item in &mut loaded {
        item.label = format!("Flowseal {}", item.label.trim_end_matches(".bat"));
    }
    loaded.extend(generated::strategies());
    Ok(loaded)
}

/// Which plan to run. An explicit user request overrides the "nothing to fix"
/// and "inconclusive" baselines: the page can load while video is throttled,
/// and the user asked for the bypass. No internet at all still stops it.
pub fn plan_for_request(
    signal: ProbeSignal,
    candidates: &[Candidate],
    cached: Option<&str>,
) -> SearchPlan {
    match plan(signal, candidates, cached) {
        SearchPlan::Skip(SearchSkip::GeneralConnectivity) => {
            SearchPlan::Skip(SearchSkip::GeneralConnectivity)
        }
        SearchPlan::Skip(_) => plan(ProbeSignal::PossibleTlsInterference, candidates, cached),
        run => run,
    }
}

enum Outcome {
    Started,
    Cancelled,
    Failed(String),
}

struct Worker {
    paths: Paths,
    shared: Arc<Mutex<Shared>>,
    cancel: Arc<AtomicBool>,
    notify: Box<dyn Fn() + Send>,
    rx: Receiver<Command>,
    tester: Option<LiveTester>,
    loaded: Vec<Loaded>,
    failed_researches: u8,
    retry_pending: bool,
}

impl Worker {
    fn set_phase(&self, phase: Phase) {
        self.shared.lock().unwrap_or_else(|e| e.into_inner()).phase = phase;
        (self.notify)();
    }

    fn log(&self, line: impl Into<String>) {
        let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        shared.log.push_back(line.into());
        while shared.log.len() > LOG_LINES {
            shared.log.pop_front();
        }
        drop(shared);
        (self.notify)();
    }

    fn settings(&self) -> Settings {
        Settings::load(&self.paths.settings)
    }

    fn label(&self, id: &str) -> String {
        self.loaded
            .iter()
            .find(|item| item.id == id)
            .map_or_else(|| id.to_owned(), |item| item.label.clone())
    }

    fn run(&mut self) {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                self.set_phase(Phase::Failed(format!("Внутренняя ошибка: {error}")));
                return;
            }
        };
        let handle = runtime.handle().clone();
        if self.settings().enable_on_start {
            self.handle_command(Command::Enable, &handle);
        }
        loop {
            let running = self.tester.as_ref().and_then(|t| t.running()).is_some();
            let command = if running && self.settings().watchdog {
                match self.watch() {
                    Some(command) => command,
                    None => continue,
                }
            } else if self.retry_pending {
                match self.rx.recv_timeout(RESEARCH_COOLDOWN) {
                    Ok(command) => command,
                    Err(RecvTimeoutError::Timeout) => Command::Research,
                    Err(RecvTimeoutError::Disconnected) => Command::Shutdown,
                }
            } else {
                match self.rx.recv() {
                    Ok(command) => command,
                    Err(_) => Command::Shutdown,
                }
            };
            if command == Command::Shutdown {
                self.stop_engine();
                break;
            }
            self.handle_command(command, &handle);
        }
        drop(runtime);
    }

    /// Waits for a command while running health checks. Returns `None` when a
    /// check round finished without a command, so the loop re-evaluates.
    fn watch(&mut self) -> Option<Command> {
        let mut failures = 0u8;
        loop {
            match self.rx.recv_timeout(HEALTH_INTERVAL) {
                Ok(command) => return Some(command),
                Err(RecvTimeoutError::Disconnected) => return Some(Command::Shutdown),
                Err(RecvTimeoutError::Timeout) => {}
            }
            if self.healthy() {
                failures = 0;
                continue;
            }
            failures += 1;
            self.log(format!(
                "Проверка доступа не прошла ({failures}/{HEALTH_FAILURES})."
            ));
            if failures >= HEALTH_FAILURES {
                self.log("Доступ ухудшился, подбираю стратегию заново.");
                return Some(Command::Research);
            }
        }
    }

    fn healthy(&mut self) -> bool {
        use zapreta_probe::CheckStatus::Passed;
        let config = SelectionConfig::default();
        let Some(tester) = self.tester.as_mut() else {
            return false;
        };
        tester.run_check("", CheckKind::Control).status == Passed
            && tester.run_check("", CheckKind::Tls).status == Passed
            && tester
                .run_check("", CheckKind::Content)
                .kbps
                .is_some_and(|kbps| kbps >= config.min_kbps)
    }

    fn stop_engine(&mut self) {
        if let Some(tester) = self.tester.as_mut() {
            if tester.running().is_some() {
                let _ = tester.stop("");
            }
        }
    }

    fn handle_command(&mut self, command: Command, handle: &tokio::runtime::Handle) {
        self.cancel.store(false, Ordering::SeqCst);
        if command != Command::Research {
            self.retry_pending = false;
            self.failed_researches = 0;
        }
        match command {
            Command::Disable => {
                self.stop_engine();
                self.set_phase(Phase::Off);
                self.log("Обход выключен.");
            }
            Command::ReloadLists => {
                let running = self
                    .tester
                    .as_ref()
                    .and_then(|t| t.running())
                    .map(str::to_owned);
                if let Some(id) = running {
                    self.log("Списки изменены, перезапускаю движок.");
                    self.stop_engine();
                    self.refresh_suite();
                    if let Some(tester) = self.tester.as_mut() {
                        if let Err(error) = tester.start(&id) {
                            self.set_phase(Phase::Failed(format!(
                                "Не удалось перезапустить движок: {}",
                                error.0
                            )));
                        }
                    }
                }
            }
            Command::Enable | Command::Research => {
                self.stop_engine();
                let force_full = command == Command::Research;
                match self.enable(handle, force_full) {
                    Outcome::Started => self.failed_researches = 0,
                    Outcome::Cancelled => {
                        self.stop_engine();
                        self.set_phase(Phase::Off);
                        self.log("Подбор прерван.");
                    }
                    Outcome::Failed(message) => {
                        self.log(message.clone());
                        self.set_phase(Phase::Failed(message));
                        // A failed re-search (usually watchdog-triggered) is
                        // retried after a cooldown, a limited number of times.
                        if force_full {
                            self.failed_researches += 1;
                            self.retry_pending = self.failed_researches < MAX_FAILED_RESEARCHES;
                        }
                    }
                }
            }
            Command::Shutdown => {}
        }
    }

    fn refresh_suite(&mut self) {
        let settings = self.settings();
        let sites = if settings.test_user_sites {
            lists::read(&self.paths.engine_root, ListKind::Sites)
        } else {
            Vec::new()
        };
        if let Some(tester) = self.tester.as_mut() {
            tester.set_suite(Suite::default().with_user_sites(&sites));
        }
    }

    fn prepare(&mut self, handle: &tokio::runtime::Handle) -> Result<(), String> {
        if self.tester.is_some() {
            return Ok(());
        }
        self.set_phase(Phase::Preparing);
        let root = &self.paths.engine_root;
        let written = bundle::extract_default(root)
            .map_err(|e| format!("Не удалось распаковать движок: {e}"))?;
        self.log(format!("Движок готов ({written} файлов обновлено)."));
        let verified = zapreta_engine::EngineBundle::new(root.join("winws.exe"), WINWS_SHA256)
            .verify()
            .map_err(|e| format!("Движок не прошёл проверку SHA-256: {e}"))?;
        self.loaded = all_candidates()?;
        let argv = self
            .loaded
            .iter()
            .map(|item| (item.id.clone(), item.argv.clone()))
            .collect();
        let mut tester = LiveTester::new(handle.clone(), verified, argv, Suite::default())
            .map_err(|e| format!("Не удалось запустить HTTPS-проверку: {e}"))?;
        tester.set_cancel_flag(Arc::clone(&self.cancel));
        self.tester = Some(tester);
        Ok(())
    }

    fn enable(&mut self, handle: &tokio::runtime::Handle, force_full: bool) -> Outcome {
        if let Err(message) = self.prepare(handle) {
            return Outcome::Failed(message);
        }
        self.refresh_suite();
        let config = SelectionConfig::default();
        let mut settings = self.settings();
        let cached = if force_full {
            None
        } else {
            settings.cached_for(ENGINE_ID).map(str::to_owned)
        };
        let candidates: Vec<Candidate> = self
            .loaded
            .iter()
            .map(|item| Candidate {
                id: item.id.clone(),
                covers_tcp: item.covers_tcp,
                covers_udp: item.covers_udp,
            })
            .collect();
        let labels: HashMap<String, String> = self
            .loaded
            .iter()
            .map(|item| (item.id.clone(), item.label.clone()))
            .collect();

        self.set_phase(Phase::Checking);
        let Some(tester) = self.tester.as_mut() else {
            return Outcome::Failed("Движок не подготовлен.".into());
        };
        let signal = autoselect::baseline_signal(tester, config.min_kbps);
        if self.cancel.load(Ordering::SeqCst) {
            return Outcome::Cancelled;
        }
        self.shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .baseline = Some(signal);
        self.log(format!("Проверка без обхода: {}", describe_signal(signal)));
        let search = plan_for_request(signal, &candidates, cached.as_deref());
        if let SearchPlan::Skip(_) = search {
            return Outcome::Failed(
                "Нет доступа к контрольным сайтам: похоже, интернет не работает. Обход не запускался."
                    .into(),
            );
        }

        let notify: &(dyn Fn() + Send) = &*self.notify;
        let Some(tester) = self.tester.as_mut() else {
            return Outcome::Failed("Движок не подготовлен.".into());
        };
        let mut progress = Progress {
            inner: tester,
            shared: &self.shared,
            notify,
            labels: &labels,
            total: candidates.len(),
            tried: 0,
        };

        let mut winner = None;
        if let Some(id) = cached.as_deref() {
            let fast = SelectionConfig {
                runs: 1,
                min_successful_runs: 1,
                revalidation_runs: 1,
                ..config
            };
            if let Ok(CandidateStatus::Qualified { .. }) =
                evaluate_candidate(&mut progress, id, &fast)
            {
                winner = Some(id.to_owned());
            }
        }
        if winner.is_none() {
            progress.tried = 0;
            let report = select_strategy(&mut progress, &search, &config);
            if self.cancel.load(Ordering::SeqCst) {
                return Outcome::Cancelled;
            }
            for candidate in &report.candidates {
                let label = labels.get(&candidate.id).cloned().unwrap_or_default();
                self.log(format!("  {label}: {}", describe_status(&candidate.status)));
            }
            match report.outcome {
                SelectionOutcome::Selected { id, .. } => winner = Some(id),
                SelectionOutcome::NoWinner => {
                    return Outcome::Failed(
                        "Ни одна из стратегий не дала рабочего доступа. Проверьте антивирус и отключите VPN или другие обходы (GoodbyeDPI, zapret)."
                            .into(),
                    );
                }
                SelectionOutcome::Aborted(reason) => {
                    return Outcome::Failed(match reason {
                        zapreta_probe::select::AbortReason::NetworkLooksDown => {
                            "С включённым движком пропадает весь интернет. Перебор остановлен."
                                .into()
                        }
                        zapreta_probe::select::AbortReason::EngineStopFailed => {
                            "Движок не остановился корректно. Перезапустите программу.".into()
                        }
                    });
                }
                SelectionOutcome::Skipped(_) => {
                    return Outcome::Failed("Перебор не запускался.".into());
                }
            }
        }
        let Some(id) = winner else {
            return Outcome::Failed("Стратегия не выбрана.".into());
        };
        let Some(tester) = self.tester.as_mut() else {
            return Outcome::Failed("Движок не подготовлен.".into());
        };
        if let Err(error) = tester.start(&id) {
            if self.cancel.load(Ordering::SeqCst) {
                return Outcome::Cancelled;
            }
            return Outcome::Failed(format!("Не удалось запустить стратегию: {}", error.0));
        }
        settings.last_strategy = Some(id.clone());
        settings.last_engine = Some(ENGINE_ID.to_owned());
        let _ = settings.save(&self.paths.settings);
        let label = self.label(&id);
        self.log(format!("Работает: {label}."));
        self.set_phase(Phase::Running { label });
        Outcome::Started
    }
}

pub fn describe_signal(signal: ProbeSignal) -> &'static str {
    match signal {
        ProbeSignal::NoObservedFailure => "явных блокировок не видно",
        ProbeSignal::PossibleDnsDivergence | ProbeSignal::PossibleDnsSinkholeAnswer => {
            "возможна подмена DNS"
        }
        ProbeSignal::PossibleTcpInterference => "соединение с YouTube/googlevideo обрывается",
        ProbeSignal::PossibleTlsInterference => "блокируется TLS (по имени сайта)",
        ProbeSignal::PossibleContentThrottlingOrFailure => "контент замедлен или не грузится",
        ProbeSignal::GeneralConnectivityProblem => "нет доступа даже к контрольным сайтам",
        ProbeSignal::Inconclusive => "результат неоднозначный",
    }
}

fn describe_status(status: &CandidateStatus) -> String {
    match status {
        CandidateStatus::Qualified { points } => format!("подходит ({points} баллов)"),
        CandidateStatus::ControlFailed => "ломает доступ к контрольным сайтам".into(),
        CandidateStatus::CheckFailed(CheckKind::Control) => "нет доступа".into(),
        CandidateStatus::CheckFailed(CheckKind::Tls) => "сайт не открывается".into(),
        CandidateStatus::CheckFailed(CheckKind::Content) => {
            "контент не грузится или медленный".into()
        }
        CandidateStatus::InsufficientRuns {
            successes,
            required,
        } => format!("нестабильно ({successes} из {required})"),
        CandidateStatus::RevalidationFailed => "не прошла повторную проверку".into(),
        CandidateStatus::EngineStartFailed(error) => format!("не запустилась: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_are_flowseal_default_first_then_flowseal_then_ours() {
        let all = all_candidates().unwrap();
        assert_eq!(all[0].id, "flowseal-general-default");
        let first_ours = all
            .iter()
            .position(|c| c.id.starts_with("zapreta-"))
            .unwrap();
        assert_eq!(first_ours, SNAPSHOTS.len());
        assert!(
            all[first_ours..]
                .iter()
                .all(|c| c.id.starts_with("zapreta-"))
        );
        assert!(all[0].label.starts_with("Flowseal general"));
    }

    #[test]
    fn explicit_request_searches_even_when_baseline_sees_no_block() {
        let candidates = vec![Candidate {
            id: "a".into(),
            covers_tcp: true,
            covers_udp: false,
        }];
        assert!(matches!(
            plan_for_request(ProbeSignal::NoObservedFailure, &candidates, None),
            SearchPlan::Run(_)
        ));
        assert!(matches!(
            plan_for_request(ProbeSignal::PossibleDnsDivergence, &candidates, None),
            SearchPlan::Run(_)
        ));
        assert_eq!(
            plan_for_request(ProbeSignal::GeneralConnectivityProblem, &candidates, None),
            SearchPlan::Skip(SearchSkip::GeneralConnectivity)
        );
    }
}
