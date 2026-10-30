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
```

`--diagnose` выполняет настоящие DNS/HTTPS запросы к документированному в README списку доменов. Не используй её как unit-тест или CI smoke test. В автоматизированной проверке сеть нужна только инструментам аудита, которые загружают advisory database и сведения Cargo registry.

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

На разработческой машине после добавления pinned toolchain локально прошли форматирование, Clippy `-D warnings`, 15 unit-тестов, `cargo audit`, `cargo deny check` и MSVC `cargo build --release -p zapreta`. В `cargo deny` остаются предупреждения о двух парах транзитивных версий (`base64`, `winnow`); checks advisory, bans, licenses и sources завершились успешно. Это локальный результат, он не заменяет выполнение GitHub Actions на чистом runner.

## Границы текущего приложения

Релизная сборка пока содержит только CLI и код диагностики/каталога. В ней нет упакованных upstream `winws`, WinDivert DLL/SYS, обхода трафика, автоподбора или tray UI. Не встраивай драйверы и бинарники до проверки их точного upstream источника, лицензии, версии и SHA-256. Не отключай Windows security controls ради локального запуска.
