# Сторонние компоненты

ZapretA встраивает файлы из Flowseal/zapret-discord-youtube (см. `docs/SBOM.md`):

- **winws.exe, fake-пакеты `bin/*.bin`, списки `lists/*`** — zapret (bol-van) в сборке Flowseal. Лицензия MIT, `Copyright (c) 2016-2026 bol-van`, `Copyright (c) 2024-2026 Flowseal`; полный текст — `crates/app/assets/engine/FLOWSEAL_LICENSE.txt`.
- **WinDivert.dll, WinDivert64.sys** — WinDivert (basil00), https://github.com/basil00/WinDivert. По сведениям автора проекта двойная лицензия LGPLv3 / GPLv2.
- **cygwin1.dll** — Cygwin runtime, https://www.cygwin.com/. LGPLv3 с исключением для линковки.

- **Шрифты интерфейса** — встроенные шрифты egui (`epaint_default_fonts`): Ubuntu Font Licence 1.0 и SIL Open Font License 1.1. Прочие Rust-зависимости — MIT/Apache-2.0/BSD/ISC/Zlib/Unicode-3.0, проверяются `cargo deny`.

Открытое: тексты лицензий WinDivert и Cygwin, а также точные версии этих двух компонентов в архив пока не добавлены и не сверены с первоисточниками; это нужно сделать до публичного распространения. Антивирусы нередко помечают WinDivert как `RiskTool`; драйвер сам по себе не вредоносен, но это ожидаемый ложный или условный детект.
