//! Background worker that owns the engine: unpacks it, fixes DNS for the
//! user's sites, searches for a strategy, keeps the winner running, watches
//! for degradation and applies list edits. The UI talks to it only through
//! [`Controller`].

use crate::{
    autoselect::{self, LiveTester, Loaded, Suite, TargetGroup},
    bundle, dnsfix,
    embedded::{ENGINE_ID, SNAPSHOTS, WINWS_SHA256},
    generated,
    lists::{self, ListKind},
    search::{self, Probe, SearchError, StartError, Verdict},
    settings::Settings,
};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    thread,
    time::Duration,
};
use zapreta_probe::select::CandidateTester;

const HEALTH_INTERVAL: Duration = Duration::from_secs(90);
/// Consecutive failed health checks before a re-search.
const HEALTH_FAILURES: u8 = 2;
const RESEARCH_COOLDOWN: Duration = Duration::from_secs(300);
const MAX_FAILED_RESEARCHES: u8 = 3;
const LOG_LINES: usize = 400;
/// User sites judged as separate goals (each costs a request per candidate).
const MAX_SITE_GOALS: usize = 6;

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

/// One goal with its result without the bypass and with the current strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalStatus {
    pub name: String,
    pub before: Option<bool>,
    pub now: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub phase: Phase,
    pub log: Vec<String>,
    pub goals: Vec<GoalStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Enable,
    Disable,
    /// Ignore the cached winner and search all candidates.
    Research,
    /// User lists changed: re-resolve DNS and restart the running strategy.
    ReloadLists,
    Shutdown,
}

struct Shared {
    phase: Phase,
    log: VecDeque<String>,
    goals: Vec<GoalStatus>,
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

fn lock(shared: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(|e| e.into_inner())
}

impl Controller {
    /// `notify` is called after every state change (e.g. to repaint the UI).
    pub fn spawn(paths: Paths, notify: Box<dyn Fn() + Send>) -> Self {
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(Mutex::new(Shared {
            phase: Phase::Off,
            log: VecDeque::new(),
            goals: Vec::new(),
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
                    resolver: None,
                    loaded: Vec::new(),
                    failed_researches: 0,
                    retry_pending: false,
                    running_score: 0,
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
        let shared = lock(&self.shared);
        Snapshot {
            phase: shared.phase.clone(),
            log: shared.log.iter().cloned().collect(),
            goals: shared.goals.clone(),
        }
    }

    /// Stops the engine, removes the hosts block and waits for the worker.
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

/// User-facing explanation of a failed search.
pub fn explain(error: &SearchError, goals: &[GoalStatus]) -> String {
    match error {
        SearchError::NoInternet => {
            "Нет доступа даже к контрольным сайтам (example.com, microsoft.com): похоже, интернет не работает. Обход не запускался.".into()
        }
        SearchError::NothingToFix => "Всё уже открывается без обхода.".into(),
        SearchError::Fatal(message) if message.contains("conflicting") => format!(
            "Уже работает другой обход ({}). Два одновременно работать не могут. Остановите его: \
             для Flowseal — service.bat → Remove Services, либо закройте GoodbyeDPI/zapret, — и нажмите «Включить».",
            message
                .split_once(':')
                .map_or(message.as_str(), |(_, list)| list.trim())
        ),
        SearchError::Fatal(message) => format!("Движок не запускается: {message}"),
        SearchError::EngineExits => {
            "Движок закрывается сразу после запуска. Чаще всего антивирус блокирует драйвер WinDivert. \
             Добавьте папку %LOCALAPPDATA%\\ZapretA в исключения антивируса и нажмите «Подобрать заново»."
                .into()
        }
        SearchError::BreaksInternet => {
            "С включённым движком пропадает весь интернет. Возможно, мешает VPN, фаервол или другой фильтр трафика."
                .into()
        }
        SearchError::NothingHelped => {
            let broken: Vec<&str> = goals
                .iter()
                .filter(|g| g.before == Some(false))
                .map(|g| g.name.as_str())
                .collect();
            if broken.is_empty() {
                "Ни одна стратегия не прошла проверку.".into()
            } else {
                format!(
                    "Ни одна из 51 стратегии не открыла: {}. Если сайт заблокирован по IP-адресу, \
                     обработка пакетов не поможет — нужен VPN или прокси.",
                    broken.join(", ")
                )
            }
        }
        SearchError::StopFailed(message) => {
            format!("Движок не остановился корректно ({message}). Перезапустите программу.")
        }
        SearchError::Cancelled => "Подбор прерван.".into(),
    }
}

enum Outcome {
    Started,
    Cancelled,
    Failed(String),
}

/// Adapts the live tester to the search, reporting progress to the UI.
struct SearchProbe<'a> {
    tester: &'a mut LiveTester,
    shared: &'a Arc<Mutex<Shared>>,
    notify: &'a (dyn Fn() + Send),
    labels: &'a HashMap<String, String>,
}

impl Probe for SearchProbe<'_> {
    fn start(&mut self, id: &str) -> Result<(), StartError> {
        self.tester.start_for_search(id)
    }
    fn stop(&mut self, id: &str) -> Result<(), String> {
        CandidateTester::stop(self.tester, id).map_err(|e| e.0)
    }
    fn control(&mut self) -> bool {
        self.tester.control_ok()
    }
    fn target(&mut self, index: usize) -> bool {
        self.tester.group_ok(index)
    }
    fn cancelled(&self) -> bool {
        self.tester.is_cancelled()
    }
    fn progress(&mut self, tried: usize, total: usize, id: &str) {
        let label = self
            .labels
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_owned());
        lock(self.shared).phase = Phase::Searching {
            tried,
            total,
            label,
        };
        (self.notify)();
    }
}

struct Worker {
    paths: Paths,
    shared: Arc<Mutex<Shared>>,
    cancel: Arc<AtomicBool>,
    notify: Box<dyn Fn() + Send>,
    rx: Receiver<Command>,
    tester: Option<LiveTester>,
    resolver: Option<zapreta_net::DnsResolver>,
    loaded: Vec<Loaded>,
    failed_researches: u8,
    retry_pending: bool,
    /// Goals passing with the running strategy, for the watchdog.
    running_score: usize,
}

impl Worker {
    fn set_phase(&self, phase: Phase) {
        lock(&self.shared).phase = phase;
        (self.notify)();
    }

    fn log(&self, line: impl Into<String>) {
        let mut shared = lock(&self.shared);
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

    fn running(&self) -> Option<String> {
        self.tester
            .as_ref()
            .and_then(|t| t.running())
            .map(str::to_owned)
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
        // A previous crash may have left our hosts block behind.
        self.clear_dns_fix();
        if self.settings().enable_on_start {
            self.handle_command(Command::Enable, &handle);
        }
        loop {
            let command = if self.running().is_some() && self.settings().watchdog {
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
                self.clear_dns_fix();
                break;
            }
            self.handle_command(command, &handle);
        }
        drop(runtime);
    }

    /// Waits for a command while running health checks. Returns `None` when
    /// a check round finished without a command, so the loop re-evaluates.
    fn watch(&mut self) -> Option<Command> {
        let mut failures = 0u8;
        loop {
            match self.rx.recv_timeout(HEALTH_INTERVAL) {
                Ok(command) => return Some(command),
                Err(RecvTimeoutError::Disconnected) => return Some(Command::Shutdown),
                Err(RecvTimeoutError::Timeout) => {}
            }
            let tester = self.tester.as_ref()?;
            // No internet at all is not the strategy's fault: wait it out.
            if !tester.control_ok() {
                continue;
            }
            let score = (0..tester.groups().len())
                .filter(|index| tester.group_ok(*index))
                .count();
            if score >= self.running_score {
                failures = 0;
                continue;
            }
            failures += 1;
            self.log(format!(
                "Проверка доступа: {score} из {} целей ({failures}/{HEALTH_FAILURES}).",
                self.running_score
            ));
            if failures >= HEALTH_FAILURES {
                self.log("Доступ ухудшился, подбираю стратегию заново.");
                return Some(Command::Research);
            }
        }
    }

    fn stop_engine(&mut self) {
        if let Some(tester) = self.tester.as_mut() {
            if tester.running().is_some() {
                let _ = CandidateTester::stop(tester, "");
            }
        }
    }

    fn clear_dns_fix(&self) {
        #[cfg(windows)]
        match dnsfix::system::clear() {
            Ok(true) => self.log("Записи ZapretA удалены из файла hosts."),
            Ok(false) => {}
            Err(error) => self.log(format!("Не удалось очистить файл hosts: {error}")),
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
                self.clear_dns_fix();
                self.set_phase(Phase::Off);
                self.log("Обход выключен.");
            }
            Command::ReloadLists => {
                let Some(id) = self.running() else {
                    return;
                };
                self.log("Списки изменены: обновляю DNS и перезапускаю движок.");
                self.stop_engine();
                self.prepare_goals(handle);
                let result = self.tester.as_mut().map(|t| t.start_for_search(&id));
                match result {
                    Some(Ok(())) => self
                        .log("Готово. Если новый сайт не открывается, нажмите «Подобрать заново»."),
                    _ => {
                        let message = "Не удалось перезапустить движок, нажмите «Включить».";
                        self.log(message);
                        self.set_phase(Phase::Failed(message.into()));
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
                        self.clear_dns_fix();
                        self.set_phase(Phase::Off);
                        self.log("Подбор прерван.");
                    }
                    Outcome::Failed(message) => {
                        self.stop_engine();
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
        #[cfg(windows)]
        if crate::winutil::enable_tcp_timestamps() {
            self.log("Метки времени TCP включены (нужны части стратегий).");
        } else {
            self.log("Не удалось включить метки времени TCP: часть стратегий может не сработать.");
        }
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
        self.resolver = zapreta_net::DnsResolver::new(Duration::from_secs(5)).ok();
        Ok(())
    }

    /// Builds the goal list (YouTube + user sites) and, for user sites whose
    /// system DNS answer looks wrong, switches checks and the browser (via
    /// hosts) to DoH addresses.
    fn prepare_goals(&mut self, handle: &tokio::runtime::Handle) {
        let settings = self.settings();
        let sites = lists::read(&self.paths.engine_root, ListKind::Sites);
        let mut groups = vec![TargetGroup::youtube()];
        if settings.test_user_sites {
            groups.extend(
                sites
                    .iter()
                    .take(MAX_SITE_GOALS)
                    .map(|s| TargetGroup::site(s)),
            );
        }
        let mut overrides: Vec<(String, Vec<IpAddr>)> = Vec::new();
        if settings.fix_dns {
            if let Some(resolver) = self.resolver.as_ref() {
                for site in &sites {
                    for name in [site.clone(), format!("www.{site}")] {
                        if site.starts_with("www.") && name.starts_with("www.www.") {
                            continue;
                        }
                        let system = handle.block_on(resolver.system(&name)).ok();
                        let Ok(doh) = handle.block_on(resolver.doh(&name)) else {
                            continue;
                        };
                        let system_addresses = system.as_ref().map(|r| r.addresses.as_slice());
                        if dnsfix::needs_override(system_addresses, &doh.addresses) {
                            let picked = dnsfix::pick(&doh.addresses);
                            self.log(format!(
                                "DNS: {name} — системный DNS {}, беру адрес из DoH ({}): {}",
                                system_addresses.map_or_else(
                                    || "не ответил".to_owned(),
                                    |a| format!("дал {a:?}")
                                ),
                                doh.provider,
                                picked
                                    .iter()
                                    .map(ToString::to_string)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ));
                            overrides.push((name, picked));
                        }
                    }
                }
            }
        }
        #[cfg(windows)]
        {
            let entries: Vec<(String, IpAddr)> = overrides
                .iter()
                .flat_map(|(name, ips)| ips.iter().map(move |ip| (name.clone(), *ip)))
                .collect();
            match dnsfix::system::apply(&entries) {
                Ok(true) if !entries.is_empty() => {
                    self.log("Адреса из DoH записаны в файл hosts (уберутся при выключении).")
                }
                Ok(_) => {}
                Err(error) => self.log(format!(
                    "Не удалось изменить файл hosts ({error}): возможно, его защищает антивирус. \
                     Сайты с подменой DNS могут не открыться в браузере."
                )),
            }
        }
        if let Some(tester) = self.tester.as_mut() {
            tester.set_overrides(&overrides);
            tester.set_groups(groups);
        }
        let names: Vec<GoalStatus> = self
            .tester
            .as_ref()
            .map(|t| {
                t.groups()
                    .iter()
                    .map(|g| GoalStatus {
                        name: g.name.clone(),
                        before: None,
                        now: None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        lock(&self.shared).goals = names;
    }

    fn enable(&mut self, handle: &tokio::runtime::Handle, force_full: bool) -> Outcome {
        if let Err(message) = self.prepare(handle) {
            return Outcome::Failed(message);
        }
        self.set_phase(Phase::Checking);
        self.prepare_goals(handle);
        let mut settings = self.settings();
        let cached = if force_full {
            None
        } else {
            settings.cached_for(ENGINE_ID).map(str::to_owned)
        };
        let ids: Vec<String> = self.loaded.iter().map(|item| item.id.clone()).collect();
        let labels: HashMap<String, String> = self
            .loaded
            .iter()
            .map(|item| (item.id.clone(), item.label.clone()))
            .collect();
        let goal_names: Vec<String> = lock(&self.shared)
            .goals
            .iter()
            .map(|g| g.name.clone())
            .collect();
        let notify: &(dyn Fn() + Send) = &*self.notify;
        let Some(tester) = self.tester.as_mut() else {
            return Outcome::Failed("Движок не подготовлен.".into());
        };
        let mut probe = SearchProbe {
            tester,
            shared: &self.shared,
            notify,
            labels: &labels,
        };
        // Always search on an explicit request: the page can load while video
        // is throttled, and the user asked for the bypass to be on.
        let report = search::search(&mut probe, &ids, cached.as_deref(), goal_names.len(), true);

        {
            let mut shared = lock(&self.shared);
            for (goal, before) in shared.goals.iter_mut().zip(&report.baseline) {
                goal.before = Some(*before);
            }
        }
        if !report.baseline.is_empty() {
            let summary = goal_names
                .iter()
                .zip(&report.baseline)
                .map(|(name, ok)| {
                    format!(
                        "{name} {}",
                        if *ok {
                            "открывается"
                        } else {
                            "НЕ открывается"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            self.log(format!("Без обхода: {summary}."));
        }
        for (id, verdict) in &report.verdicts {
            let text = match verdict {
                Verdict::Works { results } | Verdict::NoImprovement { results } => goal_names
                    .iter()
                    .zip(results)
                    .map(|(name, ok)| format!("{name} {}", if *ok { "✓" } else { "✗" }))
                    .collect::<Vec<_>>()
                    .join(", "),
                Verdict::BreaksInternet => "пропадает интернет".into(),
                Verdict::Exited => "движок сразу закрылся".into(),
                Verdict::RevalidationFailed => "не подтвердилась при повторной проверке".into(),
            };
            self.log(format!("  {}: {text}", self.label(id)));
        }

        let found = match report.result {
            Ok(found) => found,
            Err(SearchError::Cancelled) => return Outcome::Cancelled,
            Err(error) => {
                let goals = lock(&self.shared).goals.clone();
                return Outcome::Failed(explain(&error, &goals));
            }
        };
        if self.cancel.load(Ordering::SeqCst) {
            return Outcome::Cancelled;
        }
        {
            let mut shared = lock(&self.shared);
            for (goal, now) in shared.goals.iter_mut().zip(&found.results) {
                goal.now = Some(*now);
            }
        }
        self.running_score = found.results.iter().filter(|ok| **ok).count();
        settings.last_strategy = Some(found.id.clone());
        settings.last_engine = Some(ENGINE_ID.to_owned());
        let _ = settings.save(&self.paths.settings);
        let label = self.label(&found.id);
        let still_broken: Vec<&str> = goal_names
            .iter()
            .zip(&found.results)
            .filter(|(_, ok)| !**ok)
            .map(|(name, _)| name.as_str())
            .collect();
        self.log(format!("Работает: {label}."));
        if !still_broken.is_empty() {
            self.log(format!(
                "Не открываются и с обходом: {}. Если сайт заблокирован по IP, нужен VPN или прокси.",
                still_broken.join(", ")
            ));
        }
        self.set_phase(Phase::Running { label });
        Outcome::Started
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
    fn conflict_message_names_the_running_bypass() {
        let text = explain(
            &SearchError::Fatal(
                "conflicting packet-filtering processes detected: winws.exe (PID 42)".into(),
            ),
            &[],
        );
        assert!(text.contains("winws.exe (PID 42)"));
        assert!(text.contains("Remove Services"));
    }

    #[test]
    fn nothing_helped_lists_the_sites_that_stayed_blocked() {
        let goals = vec![
            GoalStatus {
                name: "YouTube".into(),
                before: Some(true),
                now: None,
            },
            GoalStatus {
                name: "rutracker.org".into(),
                before: Some(false),
                now: None,
            },
        ];
        let text = explain(&SearchError::NothingHelped, &goals);
        assert!(text.contains("rutracker.org"));
        assert!(!text.contains("YouTube"));
    }
}
