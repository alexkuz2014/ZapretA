# ZapretA — карта репозитория

Windows-программа на Rust: один exe, который сам подбирает стратегию обхода DPI
(встроенный zapret `winws.exe` + WinDivert), окно egui, трей, фоновый watchdog.
Версия `zapreta` 0.3.0. На реальной сети с DPI не проверялась.

## Крейты (Cargo workspace, edition 2024, toolchain 1.99.1)

| Крейт | Файл | Что делает |
|---|---|---|
| `zapreta-core` | `crates/core/src/lib.rs` | TOML-каталог (`StrategyCatalog`, `Strategy`, `Rule`), `SourceStrategySnapshot` (снимки Flowseal, белый список флагов `REFERENCE_ARGUMENTS`), `rule_argv`/`strategy_argv`, `ProbeScore`. Golden-тест сверяет argv с `tests/fixtures/flowseal/*.bat`. |
| `zapreta-engine` | `crates/engine/src/lib.rs` | `EngineBundle::verify` (SHA-256) → `VerifiedEngine::spawn` → `EngineProcess`; Job Object kill-on-close, старт suspended; `find_conflicting_processes` (winws, GoodbyeDPI). |
| `zapreta-net` | `crates/net/src/lib.rs` | `DnsResolver` (system + DoH Google→Cloudflare с bootstrap IP), `HttpsProber` (без proxy/redirect, лимит тела, `with_overrides` для IP). Mock-тесты на локальном сервере. |
| `zapreta-probe` | `crates/probe/src/lib.rs`, `select.rs` | Классификация сигналов (`classify`, `dns_baseline_signal`); `select`: `plan`, `select_strategy`, трейт `CandidateTester`. Без I/O. |
| `zapreta` (app) | `crates/app/src/` | Бинарник. См. ниже. |

### `crates/app/src`

- `main.rs` — без аргументов/`--tray` → GUI (самоповышение через UAC); иначе CLI: `--version`, `--validate-catalog`, `--validate-source-catalog`, `--diagnose`, `--auto <winws> <sha256> <dir>`.
- `controller.rs` — фоновый поток с tokio runtime: `Controller`/`Worker`, `Phase`, `Command`; распаковка движка, подбор, watchdog (90 с, 2 провала → переподбор, cooldown 5 мин, ≤3 раз), `all_candidates()` (Flowseal `general` первым, затем остальные Flowseal, затем свои), `explain()` — тексты ошибок.
- `search.rs` — подбор по целям (трейт `Probe`, `search()`): YouTube + до 6 сайтов пользователя оцениваются отдельно; выигрывает полное покрытие или лучший частичный. Используется GUI-путём.
- `autoselect.rs` — `LiveTester` (реальный `CandidateTester`), `Target`/`Suite`/`TargetGroup`, `parse_snapshot`.
- `generated.rs` — 29 собственных стратегий по `blockcheck.sh` (zapret v72.9).
- `embedded.rs` — **сгенерирован** `tools/gen_embedded.py`, руками не править: `ENGINE_FILES` (`include_bytes!`), `SNAPSHOTS`, `WINWS_SHA256`, `ENGINE_ID`.
- `bundle.rs` — распаковка в `%LOCALAPPDATA%\ZapretA\<ENGINE_ID>\` с проверкой хешей, атомарная запись.
- `dnsfix.rs` — блок `# BEGIN ZapretA … # END ZapretA` в `hosts` по адресам DoH.
- `lists.rs` — пользовательские списки (`list-general-user.txt`, `ipset-all.txt`, `*-exclude-user.txt`), нормализация ввода.
- `settings.rs` — настройки + кэш победителя по `engine_id`.
- `gui.rs`, `winutil.rs`, `elevate.rs` — только Windows: egui-окно, трей, mutex одной копии, schtasks-автозапуск, UAC.

## Прочее

- `catalog/flowseal/*.toml` — 22 снимка профилей Flowseal (commit `176f56d`), встраиваются в exe.
- `crates/app/assets/engine/` — `bin/`, `lists/` в git; `.gitattributes` запрещает нормализацию.
- `docs/` — `ARCHITECTURE.md` (решения, что проверено/нет, открытые вопросы), `DEV_SETUP.md`, `RESEARCH.md`, `SBOM.md` (хеши), `THIRD_PARTY_NOTICES.md`. `planzapret.md` — исходное ТЗ по этапам.
- `.github/workflows/windows.yml` — fmt, clippy `-D warnings`, test, cargo-audit, cargo-deny, release build; на тег `v*` — GitHub Release (prerelease).
- `push.ps1` — локальный помощник автора (add -A, commit, push).

## Команды

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Известные проблемы (на 2026-11-10)

- `winws.exe`, `WinDivert.dll`, `WinDivert64.sys`, `cygwin1.dll` добавлены в git через `git add -f` (хеши сверены с `embedded.rs`); при обновлении движка заменить все четыре и перегенерировать `embedded.rs`.
- Движок закреплён на Flowseal `176f56d` (соответствует релизу 1.10.4 от 2026-10-20).
- Локальный обход (winws) чинит блокировку/замедление по SNI. Не чинит: блокировку по IP, «заморозку» после ~16 КБ на адресах зарубежных хостингов, геоблок со стороны сервиса, мобильные «белые списки» — это снимается только туннелем. **Решение автора (2026-11-10): VPN, прокси и внешние серверы не используем, только локальные методы** — не предлагать их снова.
- README частично устарел («Готового .exe пока нет», описание `--diagnose` как основной функции) и расходится с разделом «Приложение» в `ARCHITECTURE.md`.

## Правила проекта

- Не выдумывать флаги winws и поведение Windows; непроверенное — в «Открытые вопросы» `ARCHITECTURE.md`.
- Сторонние бинарники — только с зафиксированным источником, лицензией и SHA-256 (`docs/SBOM.md`).
- Чужие процессы/службы не завершать; настройки защиты Windows не отключать.
- Без телеметрии; новые сетевые домены документировать.
- Новые зависимости должны проходить `deny.toml` (лицензии, источники).
- Доки и сообщения пользователю — на русском; код и комментарии в коде — на английском.
