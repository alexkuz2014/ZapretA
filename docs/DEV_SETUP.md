# Настройка разработки ZapretA

## Поддерживаемая конфигурация

- Windows x64, PowerShell 7 или Windows PowerShell 5.1.
- Rust toolchain закреплён в `rust-toolchain.toml` на Rust 1.99.1; Rustup автоматически добавит `rustfmt` и `clippy`.
- Для локальной MSVC-сборки нужен Visual Studio Build Tools с workload **Desktop development with C++** и Windows SDK. GitHub Actions использует `windows-latest` и штатный MSVC ABI как источник истины.
- Cargo workspace фиксирует разрешённые версии в `Cargo.lock`.

Установи Git for Windows, Rustup и Visual Studio Build Tools. После установки открой новый PowerShell в корне репозитория. В локальной среде можно проверить доступность компонентов так:

```powershell
rustup show active-toolchain
rustc --version
cargo --version
where.exe cl
```

Ожидаемая версия Rust — `1.99.1`. Если Cargo предложил установить закреплённый toolchain, подтверди установку и повтори команду.

## Частые команды

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
cargo run -p zapreta -- --version
cargo run -p zapreta -- --validate-catalog catalog/format-example.toml
cargo run -p zapreta -- --validate-source-catalog catalog/flowseal/flowseal-general-default.toml
```

`--diagnose` выполняет настоящие DNS/HTTPS запросы к документированному в README списку доменов. Не используй её как unit-тест или CI smoke test. В автоматизированной проверке сеть нужна только инструментам аудита, которые загружают advisory database и сведения Cargo registry.

Проверка `--validate-source-catalog` читает один из 22 снимков исходных аргументов Flowseal и явно помечает его как неисполняемый. Golden-тесты разбирают MIT-лицензированные `.bat` fixtures, импортируют каждый snapshot в runtime `Strategy`, валидируют каталог и сравнивают production `StrategyCatalog::strategy_argv` со всеми исходными токенами. Это проверяет сохранение аргументов, но не совместимость с конкретной версией движка и не означает, что конфигурации можно запускать.

## Dependency policy checks

Установи версии инструментов, закреплённые в workflow, если нужен локальный повтор:

```powershell
cargo install --locked cargo-audit --version 0.22.2
cargo install --locked cargo-deny --version 0.20.2
cargo audit
cargo deny check
```

`cargo audit` сверяет `Cargo.lock` с RustSec advisory database. `cargo deny check` применяет `deny.toml`: Windows MSVC target, advisory, лицензии, дубли/диапазоны зависимостей и доверенные источники. Не добавляй исключение для предупреждения/уязвимости без отдельной причины и фиксации в ревью.

## Windows CI

`.github/workflows/windows.yml` запускается для push в `main`, pull request и вручную. На `windows-latest` он проверяет форматирование, Clippy с `-D warnings`, тесты, `cargo audit`, `cargo deny`, затем строит `zapreta.exe` для MSVC и прикладывает его вместе с `SHA256SUMS.txt` к workflow run как временный artifact. Артефакт хранится 14 дней; это CI build, не официальный релиз и не подписанный бинарник.

Локальный `x86_64-pc-windows-gnullvm` использовался как запасной вариант, когда в установленном MSVC окружении не хватало `dbghelp.lib`. Он полезен для разработки, но CI и будущие релизы должны собираться целевым `x86_64-pc-windows-msvc`.

Последний локальный цикл на Windows x64 (commit `b7ef330`) прошёл `cargo fmt --all -- --check`, 38 workspace-тестов, Clippy `-D warnings`, release build, `cargo audit` и `cargo deny check`. Deny сообщает о двух парах дублирующихся транзитивных версий (`base64`, `winnow`), остальные проверки политики прошли. Windows CI для того же commit успешно завершил все шаги, включая сборку MSVC exe, SHA-256 manifest и upload artifact: [Windows CI run](https://github.com/alexkuz2014/ZapretA/actions/runs/41055761883).

## Границы текущего приложения

Релизная сборка пока содержит только CLI и код диагностики/каталога. В ней нет упакованных upstream `winws`, WinDivert DLL/SYS, обхода трафика, автоподбора или tray UI. Не встраивай драйверы и бинарники до проверки их точного upstream источника, лицензии, версии и SHA-256. Не отключай Windows security controls ради локального запуска.

## Проверки жизненного цикла в Windows

Без драйвера и upstream engine можно локально проверить только границу дочернего процесса и Job Object:

```powershell
cargo test -p zapreta-engine -- --nocapture
```

Тесты используют системный `cmd.exe` как безопасный дочерний процесс и покрывают обычную остановку, panic unwind и завершение родительского процесса. Это не проверяет управление WinDivert, установку/удаление службы или консольный Ctrl+C в пользовательском приложении.

После выбора и проверки конкретного driver bundle ручной прогон нужно выполнять в восстанавливаемой Windows 10/11 VM: зафиксировать состояние до старта; проверить отказ при уже работающем известном конфликтующем процессе; штатно остановить движок и убедиться, что удалён только собственный процесс/driver service; повторить с Ctrl+C, принудительным завершением процесса и panic; проверить повторный запуск после каждого сценария; повторить при Secure Boot/HVCI включённых. Не останавливать и не удалять сторонние процессы/службы. Сохранять Windows build, состояние защитных настроек, коды возврата и список оставшихся принадлежащих приложению процессов/служб. До интеграции драйвера эти шаги остаются незаполненным VM checklist, а не пройденными тестами.
