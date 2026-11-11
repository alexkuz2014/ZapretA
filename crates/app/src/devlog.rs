//! Developer-build diagnostics (`--features devlog`).
//!
//! Records everything needed to understand, after the fact, what happened on
//! a machine we cannot reach: every probe with its raw result and error chain,
//! every engine start with its full argv and output, DNS answers (system vs
//! DoH), the verdict per strategy, the winner, watchdog rounds, the DNS cache
//! (which sites the user actually opened) and the engine's own `--debug` log
//! (per-connection hostnames). Files stay on the local disk in
//! `%LOCALAPPDATA%\ZapretA\devlogs`; nothing is uploaded.
//!
//! In a normal build [`ENABLED`] is false and every entry point returns at
//! once, so call sites need no `cfg`.

use serde_json::{Map, Value, json};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub const ENABLED: bool = cfg!(feature = "devlog");

/// Sessions kept on disk; older ones are deleted at start.
const KEEP_SESSIONS: usize = 8;
/// A running engine's debug log above this size triggers an engine restart
/// onto a fresh file (the debug stream is verbose during video playback).
const ENGINE_LOG_LIMIT: u64 = 40 * 1024 * 1024;
/// Session ids look like `20261110-103000`.
const ID_LEN: usize = 15;
/// Relative to the engine's working directory (`%LOCALAPPDATA%\ZapretA\<engine>`).
const ENGINE_REL_DIR: &str = "../devlogs";

struct Sink {
    dir: PathBuf,
    id: String,
    started: Instant,
    events: File,
    summary: File,
    engine_runs: u32,
    engine_log: Option<PathBuf>,
    dns_seen: HashSet<String>,
}

static SINK: Mutex<Option<Sink>> = Mutex::new(None);

/// Where the engine writes its logs for one candidate.
pub struct EngineLog {
    /// Value for `--debug=@<this>`, relative to the engine's working directory.
    pub debug_arg: String,
    pub debug_path: PathBuf,
    /// Captures stdout/stderr (start-up and driver errors).
    pub output_path: PathBuf,
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// `(YYYYMMDD-HHMMSS, YYYY-MM-DDTHH:MM:SS.mmmZ)` for a Unix time.
fn stamps(secs: u64, millis: u32) -> (String, String) {
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let rest = secs % 86_400;
    let (h, m, s) = (rest / 3600, rest % 3600 / 60, rest % 60);
    (
        format!("{year:04}{month:02}{day:02}-{h:02}{m:02}{s:02}"),
        format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z"),
    )
}

fn now() -> (String, String) {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    stamps(elapsed.as_secs(), elapsed.subsec_millis())
}

fn lock() -> std::sync::MutexGuard<'static, Option<Sink>> {
    SINK.lock().unwrap_or_else(|e| e.into_inner())
}

fn safe_name(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn session_of(file_name: &str) -> Option<&str> {
    let (_, rest) = file_name.split_once('_')?;
    let id = rest.get(..ID_LEN)?;
    let b = id.as_bytes();
    (b[8] == b'-' && id.bytes().filter(u8::is_ascii_digit).count() == ID_LEN - 1).then_some(id)
}

fn prune(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let files: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            session_of(&name).map(|id| (id.to_owned(), e.path()))
        })
        .collect();
    let mut ids: Vec<&String> = files.iter().map(|(id, _)| id).collect();
    ids.sort();
    ids.dedup();
    if ids.len() <= KEEP_SESSIONS {
        return;
    }
    let drop_before = ids[ids.len() - KEEP_SESSIONS].clone();
    for (id, path) in &files {
        if *id < drop_before {
            let _ = fs::remove_file(path);
        }
    }
}

/// Starts a session in `<app_dir>/devlogs`. Returns the directory.
pub fn init(app_dir: &Path, args: &[String]) -> Option<PathBuf> {
    if !ENABLED {
        return None;
    }
    let dir = app_dir.join("devlogs");
    fs::create_dir_all(&dir).ok()?;
    prune(&dir);
    let (id, _) = now();
    let open = |name: String| {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))
    };
    let events = open(format!("session_{id}.jsonl")).ok()?;
    let summary = open(format!("summary_{id}.txt")).ok()?;
    *lock() = Some(Sink {
        dir: dir.clone(),
        id,
        started: Instant::now(),
        events,
        summary,
        engine_runs: 0,
        engine_log: None,
        dns_seen: HashSet::new(),
    });
    install_panic_hook();
    event(
        "session_start",
        json!({
            "app_version": env!("CARGO_PKG_VERSION"),
            "dev_build": true,
            "pid": std::process::id(),
            "args": args,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        }),
    );
    collect_system_info();
    Some(dir)
}

pub fn dir() -> Option<PathBuf> {
    lock().as_ref().map(|s| s.dir.clone())
}

fn emit(sink: &mut Sink, kind: &str, data: Value) {
    let (_, iso) = now();
    let mut object = Map::new();
    object.insert("t".into(), json!(iso));
    object.insert(
        "ms".into(),
        json!(sink.started.elapsed().as_millis() as u64),
    );
    object.insert("kind".into(), json!(kind));
    match data {
        Value::Object(fields) => object.extend(fields),
        Value::Null => {}
        other => {
            object.insert("data".into(), other);
        }
    }
    if let Ok(mut line) = serde_json::to_string(&Value::Object(object)) {
        line.push('\n');
        let _ = sink.events.write_all(line.as_bytes());
        let _ = sink.events.flush();
    }
}

/// Appends one structured event. `data` should be a JSON object.
pub fn event(kind: &str, data: Value) {
    if !ENABLED {
        return;
    }
    if let Some(sink) = lock().as_mut() {
        emit(sink, kind, data);
    }
}

/// Appends a timestamped line to the human-readable summary file.
pub fn note(line: &str) {
    if !ENABLED {
        return;
    }
    if let Some(sink) = lock().as_mut() {
        let (_, iso) = now();
        let _ = writeln!(sink.summary, "[{}] {line}", &iso[11..19]);
        let _ = sink.summary.flush();
    }
}

fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // try_lock: the panic may come from code that holds the lock.
        if let Ok(mut guard) = SINK.try_lock() {
            if let Some(sink) = guard.as_mut() {
                emit(
                    sink,
                    "panic",
                    json!({
                        "info": info.to_string(),
                        "backtrace": std::backtrace::Backtrace::force_capture().to_string(),
                    }),
                );
            }
        }
        default(info);
    }));
}

/// Reserves log files for the next engine start.
pub fn engine_log(candidate: &str) -> Option<EngineLog> {
    if !ENABLED {
        return None;
    }
    let mut guard = lock();
    let sink = guard.as_mut()?;
    sink.engine_runs += 1;
    let stem = format!(
        "engine_{}_{:03}-{}",
        sink.id,
        sink.engine_runs,
        safe_name(candidate)
    );
    let debug_name = format!("{stem}.log");
    let log = EngineLog {
        debug_arg: format!("{ENGINE_REL_DIR}/{debug_name}"),
        debug_path: sink.dir.join(&debug_name),
        output_path: sink.dir.join(format!("{stem}.out.txt")),
    };
    sink.engine_log = Some(log.debug_path.clone());
    Some(log)
}

/// True when the running engine's debug log has grown past the limit.
pub fn engine_log_needs_rotation() -> bool {
    if !ENABLED {
        return false;
    }
    let guard = lock();
    guard
        .as_ref()
        .and_then(|s| s.engine_log.as_ref())
        .and_then(|path| fs::metadata(path).ok())
        .is_some_and(|meta| meta.len() > ENGINE_LOG_LIMIT)
}

/// Last `max` bytes of a text file, lossily decoded. Empty if unreadable.
pub fn read_tail(path: &Path, max: u64) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let length = file.metadata().map_or(0, |m| m.len());
    let _ = file.seek(SeekFrom::Start(length.saturating_sub(max)));
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(windows)]
fn powershell(script_args: &[&str]) -> Option<std::process::Output> {
    crate::winutil::hidden("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
        ])
        .args(script_args)
        .output()
        .ok()
}

/// OS, adapters, DNS servers, TCP settings, antivirus and running programs go
/// to a separate `system_*.txt`, so it can be left out when sharing logs.
/// Contains no MAC or IP addresses of this machine; process names are listed.
fn collect_system_info() {
    #[cfg(windows)]
    {
        let Some((dir, id)) = lock().as_ref().map(|s| (s.dir.clone(), s.id.clone())) else {
            return;
        };
        std::thread::spawn(move || {
            let out = dir.join(format!("system_{id}.txt"));
            let script = dir.join(format!("collect_{id}.ps1"));
            let text = format!(
                r#"$o = '{out}'
function S($t) {{ "`n=== $t ===" | Out-File -FilePath $o -Append -Encoding utf8 }}
function R($b) {{ try {{ & $b 2>&1 | Out-String | Out-File -FilePath $o -Append -Encoding utf8 }} catch {{ "error: $_" | Out-File -FilePath $o -Append -Encoding utf8 }} }}
'' | Out-File -FilePath $o -Encoding utf8
S 'Windows'; R {{ cmd /c ver }}; R {{ Get-ComputerInfo -Property WindowsProductName,WindowsVersion,OsBuildNumber,OsLanguage,TimeZone,CsSystemType | Format-List }}
S 'Network adapters (no MAC/IP)'; R {{ Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed | Format-Table -AutoSize -Wrap }}
S 'DNS servers'; R {{ Get-DnsClientServerAddress | Where-Object {{ $_.ServerAddresses }} | Select-Object InterfaceAlias,AddressFamily,ServerAddresses | Format-Table -AutoSize -Wrap }}
S 'DoH settings'; R {{ Get-DnsClientDohServerAddress }}
S 'TCP global'; R {{ netsh interface tcp show global }}
S 'System proxy'; R {{ netsh winhttp show proxy }}
S 'Antivirus'; R {{ Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState | Format-Table -AutoSize }}
S 'Windows Defender'; R {{ Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled | Format-List }}
S 'Secure boot / HVCI'; R {{ Confirm-SecureBootUEFI }}; R {{ Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard | Select-Object SecurityServicesRunning,SecurityServicesConfigured | Format-List }}
S 'Driver services (WinDivert and similar)'; R {{ Get-Service | Where-Object {{ $_.Name -match 'WinDivert|GoodbyeDPI|zapret|windivert' }} | Format-Table -AutoSize }}
S 'Running programs (names)'; R {{ Get-Process | Select-Object -ExpandProperty ProcessName | Sort-Object -Unique | Out-String -Width 4096 }}
"#,
                out = out.display()
            );
            // A BOM makes Windows PowerShell 5.1 read the script as UTF-8; without
            // it a Cyrillic user name in the path would be mangled.
            if fs::write(&script, format!("\u{feff}{text}")).is_ok() {
                let _ = powershell(&["-File", &script.to_string_lossy()]);
                let _ = fs::remove_file(&script);
            }
            event(
                "system_info",
                json!({ "file": out.file_name().map(|n| n.to_string_lossy().into_owned()) }),
            );
        });
    }
}

/// Windows DNS cache entries seen since the last call: a rough list of the
/// sites the user (and programs) tried to reach.
pub fn snapshot_dns_cache() {
    #[cfg(windows)]
    if ENABLED {
        let Some(output) = powershell(&[
            "-Command",
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-DnsClientCache | ForEach-Object { $_.Entry } | Sort-Object -Unique",
        ]) else {
            return;
        };
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let mut fresh = Vec::new();
        if let Some(sink) = lock().as_mut() {
            for name in text.lines().map(|l| l.trim().to_lowercase()) {
                if !name.is_empty() && sink.dns_seen.insert(name.clone()) {
                    fresh.push(name);
                }
            }
        }
        if !fresh.is_empty() {
            fresh.truncate(500);
            event("dns_cache_new", json!({ "names": fresh }));
        }
    }
}

/// Packs every log of the kept sessions into a zip next to the log folder.
pub fn make_archive() -> Result<PathBuf, String> {
    if !ENABLED {
        return Err("not a dev build".into());
    }
    let (dir, id) = lock()
        .as_ref()
        .map(|s| (s.dir.clone(), s.id.clone()))
        .ok_or("логирование не запущено")?;
    let parent = dir.parent().ok_or("нет родительской папки")?;
    let zip = parent.join(format!("ZapretA-devlogs-{id}.zip"));
    #[cfg(windows)]
    {
        let command = format!(
            "Compress-Archive -Path '{}\\*' -DestinationPath '{}' -Force",
            dir.display(),
            zip.display()
        );
        let output =
            powershell(&["-Command", &command]).ok_or("не удалось запустить PowerShell")?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
        }
        Ok(zip)
    }
    #[cfg(not(windows))]
    {
        let _ = zip;
        Err("архив собирается только в Windows".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_time_is_rendered_as_utc() {
        // 2026-11-10 08:30:56.789 UTC
        let (id, iso) = stamps(1_794_299_456, 789);
        assert_eq!(id, "20261110-083056");
        assert_eq!(iso, "2026-11-10T08:30:56.789Z");
        assert_eq!(stamps(0, 0).0, "19700101-000000");
        assert_eq!(stamps(951_782_400, 0).0, "20000229-000000");
    }

    #[test]
    fn session_id_is_found_in_file_names_only() {
        assert_eq!(
            session_of("engine_20261110-083056_003-flowseal.log"),
            Some("20261110-083056")
        );
        assert_eq!(
            session_of("session_20261110-083056.jsonl"),
            Some("20261110-083056")
        );
        assert_eq!(session_of("notes.txt"), None);
        assert_eq!(session_of("x_short"), None);
    }

    #[test]
    fn candidate_ids_become_safe_file_names() {
        assert_eq!(
            safe_name("flowseal-general (ALT2)/x"),
            "flowseal-general__ALT2__x"
        );
    }

    #[test]
    fn old_sessions_are_pruned_and_new_ones_kept() {
        let dir = std::env::temp_dir().join(format!("zapreta-devlog-prune-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for day in 1..=10 {
            fs::write(
                dir.join(format!("session_202611{day:02}-000000.jsonl")),
                "x",
            )
            .unwrap();
            fs::write(dir.join(format!("summary_202611{day:02}-000000.txt")), "x").unwrap();
        }
        fs::write(dir.join("unrelated.txt"), "x").unwrap();
        prune(&dir);
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert!(names.contains(&"unrelated.txt".to_owned()));
        assert!(!names.contains(&"session_20261102-000000.jsonl".to_owned()));
        assert!(names.contains(&"session_20261103-000000.jsonl".to_owned()));
        assert_eq!(names.len(), 1 + KEEP_SESSIONS * 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_tail_returns_only_the_end() {
        let path = std::env::temp_dir().join(format!("zapreta-devlog-tail-{}", std::process::id()));
        fs::write(&path, "0123456789").unwrap();
        assert_eq!(read_tail(&path, 4), "6789");
        assert_eq!(read_tail(&path, 100), "0123456789");
        assert_eq!(read_tail(Path::new("/nonexistent/zapreta"), 4), "");
        let _ = fs::remove_file(&path);
    }

    #[cfg(feature = "devlog")]
    #[test]
    fn events_and_summary_are_written_as_json_lines_and_text() {
        let root = std::env::temp_dir().join(format!("zapreta-devlog-run-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let dir = init(&root, &["--test".into()]).expect("devlog starts in a dev build");
        event(
            "probe",
            json!({ "host": "example.com", "ok": false, "error": "[timeout] x" }),
        );
        note("Работает: тест");
        let log = engine_log("flowseal general/ALT").unwrap();
        assert!(log.debug_arg.starts_with("../devlogs/engine_"));
        assert!(log.debug_arg.ends_with("-flowseal_general_ALT.log"));
        let jsonl = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().starts_with("session_"))
            .unwrap();
        let text = fs::read_to_string(jsonl.path()).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[0]["kind"], "session_start");
        let probe = lines.iter().find(|l| l["kind"] == "probe").unwrap();
        assert_eq!(probe["host"], "example.com");
        assert!(probe["t"].as_str().unwrap().ends_with('Z'));
        let summary = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().starts_with("summary_"))
            .unwrap();
        assert!(
            fs::read_to_string(summary.path())
                .unwrap()
                .contains("Работает: тест")
        );
        let _ = fs::remove_dir_all(&root);
    }
}
