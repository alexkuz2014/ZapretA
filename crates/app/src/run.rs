//! One-click mode: elevate, unpack the pinned engine, pick a working strategy,
//! keep it running, open the browser, and watch for degradation.

use crate::{
    autoselect::{self, LiveTester, Loaded, Suite},
    bundle,
    elevate::{is_elevated, relaunch_elevated},
    embedded::{ENGINE_ID, SNAPSHOTS, WINWS_SHA256},
};
use std::{collections::HashMap, path::Path, process::ExitCode, time::Duration};
use zapreta_probe::select::{
    CandidateStatus, CandidateTester, CheckKind, CheckOutcome, SearchPlan, SearchSkip,
    SelectionConfig, SelectionOutcome, TesterError, evaluate_candidate, plan, select_strategy,
};

const HEALTH_INTERVAL: Duration = Duration::from_secs(60);
const RETRY_COOLDOWN: Duration = Duration::from_secs(300);
const MAX_FAILED_RESEARCHES: u8 = 3;

/// Cached winner, valid only for the same embedded engine/catalog.
pub fn parse_state(text: &str) -> Option<String> {
    let mut engine = None;
    let mut strategy = None;
    for line in text.lines() {
        match line.split_once('=') {
            Some(("engine", value)) => engine = Some(value.trim()),
            Some(("strategy", value)) => strategy = Some(value.trim()),
            _ => {}
        }
    }
    (engine == Some(ENGINE_ID))
        .then_some(strategy)
        .flatten()
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
}

pub fn render_state(strategy: &str) -> String {
    format!("engine={ENGINE_ID}\nstrategy={strategy}\n")
}

fn load_embedded() -> Result<Vec<Loaded>, String> {
    let mut loaded = SNAPSHOTS
        .iter()
        .map(|(name, text)| autoselect::parse_snapshot(text).map_err(|e| format!("{name}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    // Upstream's own default profile goes first; the rest keep file-name order.
    loaded.sort_by_key(|item| item.id != "flowseal-general-default");
    Ok(loaded)
}

/// Prints which candidate is being tried before delegating.
struct Announcing<'a> {
    inner: LiveTester,
    labels: &'a HashMap<String, String>,
    total: usize,
    tried: usize,
}

impl CandidateTester for Announcing<'_> {
    fn start(&mut self, id: &str) -> Result<(), TesterError> {
        self.tried += 1;
        let label = self.labels.get(id).map_or(id, String::as_str);
        println!("  [{}/{}] пробую {label}", self.tried, self.total);
        self.inner.start(id)
    }
    fn run_check(&mut self, id: &str, kind: CheckKind) -> CheckOutcome {
        self.inner.run_check(id, kind)
    }
    fn stop(&mut self, id: &str) -> Result<(), TesterError> {
        self.inner.stop(id)
    }
}

enum SearchResult {
    Started(String),
    NothingToFix,
    Failed(String),
}

fn search_and_start(
    tester: &mut Announcing<'_>,
    candidates: &[zapreta_probe::select::Candidate],
    cached: Option<&str>,
    config: &SelectionConfig,
) -> SearchResult {
    let signal = autoselect::baseline_signal(&mut tester.inner, config.min_kbps);
    println!("Проверка без обхода: {signal:?}");
    let search = plan(signal, candidates, cached);
    if let SearchPlan::Skip(reason) = &search {
        return match reason {
            SearchSkip::NothingToFix => SearchResult::NothingToFix,
            SearchSkip::GeneralConnectivity => SearchResult::Failed(
                "Нет доступа к контрольному сайту. Проверьте подключение к интернету; обход не запускался.".into(),
            ),
            SearchSkip::DnsLayer => SearchResult::Failed(
                "Похоже на проблему DNS, её этот обход не решает. Запустите zapreta.exe --diagnose.".into(),
            ),
            SearchSkip::Inconclusive => SearchResult::Failed(
                "Не удалось определить причину проблемы, перебор не запускался.".into(),
            ),
        };
    }
    if let Some(id) = cached {
        println!("Проверяю стратегию, сохранённую с прошлого раза.");
        let fast = SelectionConfig {
            runs: 1,
            min_successful_runs: 1,
            revalidation_runs: 1,
            ..*config
        };
        if matches!(
            evaluate_candidate(tester, id, &fast),
            Ok(CandidateStatus::Qualified { .. })
        ) {
            return start_winner(tester, id);
        }
        println!("Сохранённая стратегия больше не подходит, запускаю полный перебор.");
        tester.tried = 0;
    }
    println!("Перебор стратегий. Это может занять несколько минут.");
    let report = select_strategy(tester, &search, config);
    match report.outcome {
        SelectionOutcome::Selected { id, .. } => start_winner(tester, &id),
        SelectionOutcome::NoWinner => SearchResult::Failed(
            "Ни одна стратегия не дала рабочего доступа. Возможно, мешает антивирус или другой обход (VPN, GoodbyeDPI).".into(),
        ),
        SelectionOutcome::Aborted(reason) => {
            SearchResult::Failed(format!("Перебор остановлен: {reason:?}."))
        }
        SelectionOutcome::Skipped(_) => SearchResult::Failed("Перебор не запускался.".into()),
    }
}

fn start_winner(tester: &mut Announcing<'_>, id: &str) -> SearchResult {
    match tester.inner.start(id) {
        Ok(()) => SearchResult::Started(id.to_owned()),
        Err(error) => SearchResult::Failed(format!(
            "Не удалось запустить выбранную стратегию: {}",
            error.0
        )),
    }
}

fn healthy(tester: &mut LiveTester, min_kbps: u32) -> bool {
    use zapreta_probe::CheckStatus::Passed;
    tester.run_check("", CheckKind::Control).status == Passed
        && tester.run_check("", CheckKind::Tls).status == Passed
        && tester
            .run_check("", CheckKind::Content)
            .kbps
            .is_some_and(|kbps| kbps >= min_kbps)
}

fn open_browser() {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", "https://www.youtube.com"])
            .spawn();
    }
}

fn pause() {
    println!("\nНажмите Enter, чтобы закрыть окно.");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

fn work(handle: tokio::runtime::Handle, state_path: &Path, root: &Path) -> Result<(), String> {
    let written =
        bundle::extract_default(root).map_err(|e| format!("Не удалось распаковать движок: {e}"))?;
    println!(
        "Движок готов ({written} файлов обновлено): {}",
        root.display()
    );
    let verified = zapreta_engine::EngineBundle::new(root.join("winws.exe"), WINWS_SHA256)
        .verify()
        .map_err(|e| format!("Движок не прошёл проверку SHA-256: {e}"))?;
    let loaded = load_embedded()?;
    let labels: HashMap<String, String> = loaded
        .iter()
        .map(|l| (l.id.clone(), l.label.clone()))
        .collect();
    let candidates: Vec<_> = loaded
        .iter()
        .map(|l| zapreta_probe::select::Candidate {
            id: l.id.clone(),
            covers_tcp: l.covers_tcp,
            covers_udp: l.covers_udp,
        })
        .collect();
    let argv = loaded
        .iter()
        .map(|l| (l.id.clone(), l.argv.clone()))
        .collect();
    let live = LiveTester::new(handle, verified, argv, Suite::default())
        .map_err(|e| format!("Не удалось запустить HTTPS-проверку: {e}"))?;
    let mut tester = Announcing {
        inner: live,
        labels: &labels,
        total: candidates.len(),
        tried: 0,
    };
    let config = SelectionConfig::default();
    let mut cached = std::fs::read_to_string(state_path)
        .ok()
        .and_then(|t| parse_state(&t));
    let mut failed_researches = 0u8;
    let mut first = true;
    loop {
        tester.tried = 0;
        match search_and_start(&mut tester, &candidates, cached.as_deref(), &config) {
            SearchResult::Started(id) => {
                let _ = std::fs::write(state_path, render_state(&id));
                cached = Some(id.clone());
                let label = labels.get(&id).map_or(id.as_str(), String::as_str);
                println!(
                    "\nГотово: работает стратегия {label}.\nНе закрывайте это окно: при закрытии обход выключится."
                );
                if first {
                    open_browser();
                    first = false;
                }
                failed_researches = 0;
            }
            SearchResult::NothingToFix => {
                println!(
                    "\nБлокировок и замедления не обнаружено, обход не нужен. Если сайт всё же не открывается, запустите zapreta.exe --diagnose."
                );
                return Ok(());
            }
            SearchResult::Failed(message) => {
                if first {
                    return Err(message);
                }
                failed_researches += 1;
                println!("\n{message}");
                if failed_researches >= MAX_FAILED_RESEARCHES {
                    return Err(
                        "Автоматический переподбор не удался несколько раз подряд, остановка."
                            .into(),
                    );
                }
                std::thread::sleep(RETRY_COOLDOWN);
                continue;
            }
        }
        // Watchdog: two failed health checks in a row trigger a quiet re-search.
        let mut bad_checks = 0;
        loop {
            std::thread::sleep(HEALTH_INTERVAL);
            if healthy(&mut tester.inner, config.min_kbps) {
                bad_checks = 0;
                continue;
            }
            bad_checks += 1;
            if bad_checks >= 2 {
                println!("\nДоступ ухудшился, подбираю стратегию заново.");
                let _ = tester.inner.stop("");
                break;
            }
        }
    }
}

pub async fn run() -> ExitCode {
    println!("ZapretA {}", env!("CARGO_PKG_VERSION"));
    if !is_elevated() {
        println!("Нужны права администратора, сейчас появится запрос Windows (UAC).");
        if relaunch_elevated() {
            return ExitCode::SUCCESS;
        }
        println!("Права администратора не получены, без них обход не работает.");
        pause();
        return ExitCode::FAILURE;
    }
    let Some(root) = bundle::default_root() else {
        println!("Не найдена папка %LOCALAPPDATA%.");
        pause();
        return ExitCode::FAILURE;
    };
    let state_path = root.parent().unwrap_or(&root).join("state.txt");
    let handle = tokio::runtime::Handle::current();
    let result = tokio::task::spawn_blocking(move || work(handle, &state_path, &root)).await;
    match result {
        Ok(Ok(())) => {
            pause();
            ExitCode::SUCCESS
        }
        Ok(Err(message)) => {
            println!("\n{message}");
            pause();
            ExitCode::FAILURE
        }
        Err(_) => {
            println!("Внутренняя ошибка.");
            pause();
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_and_ignores_other_engine_versions() {
        assert_eq!(
            parse_state(&render_state("flowseal-general-alt")),
            Some("flowseal-general-alt".into())
        );
        assert_eq!(parse_state("engine=other\nstrategy=x\n"), None);
        assert_eq!(
            parse_state(&format!("engine={ENGINE_ID}\nstrategy=\n")),
            None
        );
        assert_eq!(parse_state("garbage"), None);
    }

    #[test]
    fn embedded_catalog_loads_with_default_first() {
        let loaded = load_embedded().unwrap();
        assert_eq!(loaded.len(), 22);
        assert_eq!(loaded[0].id, "flowseal-general-default");
        assert!(loaded.iter().any(|l| l.covers_tcp));
    }
}
