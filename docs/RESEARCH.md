# Исследование источников ZapretA

Статус: исходное исследование этапа 0 завершено; реализация продолжается, 2026-10-30. Даты активности и лицензии нужно повторно проверить перед включением любых файлов в релиз.

## Реализация диагностического сетевого слоя

Первый инкремент этапа 2 реализует ручную baseline-диагностику. Google документирует JSON API `https://dns.google/resolve`, GET-параметры для DNS query и `edns_client_subnet`; проект отправляет `0.0.0.0/0`, чтобы не передавать публичному резолверу клиентскую подсеть в этом поле. Это не гарантирует анонимность запроса: DNS-соединение к `dns.google` и HTTPS-запросы к проверочным целям всё равно видны соответствующим сетевым узлам. DoH hostname сам разрешается обычным системным DNS.

`reqwest` с rustls используется для прямых HTTPS запросов без proxy из окружения, без redirect и с таймаутом/ограничением чтения тела. Это только HTTP/TLS доступность, не проверка воспроизведения видео. На текущей машине сетевой запуск вернул HTTP 204 для YouTube и HTTP 200 для контрольного `example.com`; DNS-наборы различались наличием IPv6-адресов в DoH. Такие различия могут происходить из-за CDN и поддержки IPv4/IPv6, поэтому не классифицируются как доказанная подмена.

Источники: [Google Public DNS JSON API](https://developers.google.com/speed/public-dns/docs/doh/json), [reqwest documentation](https://docs.rs/reqwest/latest/reqwest/).

## Сверка каталога стратегий Flowseal

Для подготовки полного каталога получен архив ровно за source commit `176f56dc3f11ce5915c26abcdde903f93d835b64`; в нём обнаружено 22 `general*.bat`. `LICENSE.txt` этого среза заявляет MIT для кода и документации и отдельно указывает, что бинарные компоненты имеют собственное происхождение/лицензии. Только 22 текстовых профиля и `service.bat` помещены в `tests/fixtures/flowseal/` с upstream license; тесты читают их, никогда не исполняют. Engine-бинарники и payload-файлы не копировались.

Перед созданием catalog golden fixtures выявлено, что нынешние `Rule`/`strategy_argv` не могут представить все аргументы без потерь. В профилях присутствуют неподдерживаемые поля/варианты: `--filter-l3`, `--hostlist-domains`, `--hostlist-exclude-domains`, `--ip-id`, `--dpi-desync-any-protocol`, `--dpi-desync-fakedsplit-pattern`, `--dpi-desync-fake-tls-mod`, inline fake-значения без файлов, а также повторяющиеся payload-флаги разных типов. Некоторые скрипты используют `%GameFilterTCP%` / `%GameFilterUDP%`, которые в самих профилях не определены и зависят от окружения.

Добавлены 22 `catalog/flowseal/*.toml` как **неисполняемые source snapshots**. Каждый файл содержит нормализованный argv, исходный filename, SHA-256 скрипта и service, commit источника и defaults Game Filter. Golden-тест читает fixture batch, разбирает цепочку команд `winws.exe`, раскрывает `%BIN%`/`%LISTS%` и отключённые по умолчанию `%GameFilterTCP%`/`%GameFilterUDP%` в `12`, затем проверяет весь argv и SHA-256 для каждого из 22 профилей.

Эти goldens пока сравнивают snapshots с upstream batch, но **не сравнивают output production builder `StrategyCatalog::strategy_argv`**: текущая typed-схема не умеет выразить `--filter-l3`, доменные списки, `--ip-id`, `any-protocol`, inline fake значения, часть модификаторов и точный порядок опций. Следующий каталогный шаг — расширить типизированную модель и проверять её реальный argv builder против этих snapshots. До этого source snapshots нельзя запускать. Даже после этого требуется проверить точную версию движка, payload SHA-256 и bundle.

Для `cargo deny` в список допустимых лицензий добавлена `CDLA-Permissive-2.0`, объявленная upstream crate `webpki-roots 1.0.11` (корневые сертификаты для TLS). Это явное разрешение лицензии зависимости, а не подтверждение лицензий будущих upstream executable/driver компонентов; их всё равно нужно разбирать отдельно.

| Источник | Что проверено / полезно | Решение и ограничения |
|---|---|---|
| [Flowseal zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) | Получен архив публичной `main`, локально просмотрены README, service и все 22 `general*.bat`. Профили состоят из нескольких `--filter-* ... --new`; обнаружены fake, fakedsplit, multisplit, multidisorder, syndata, hostfakesplit, QUIC/TLS payload, Discord и Game Filter. README описывает установку службы, диагностику, обновление списков и предупреждает о WinDivert AV-детектах. | Использовать как источник конфигураций только после фиксации commit/tag и сверки лицензий файлов. Не встраивать бинарники из произвольного архива. Значения профилей меняются, результаты сейчас относятся к `main` на момент среза. |
| [bol-van/zapret docs/readme.en.md](https://github.com/bol-van/zapret/blob/master/docs/readme.en.md) | Документирует методы zapret и различия режимов; текущая README сообщает, что zapret 1 EOL, развитие идет в zapret2. | Использовать для семантики только после сверки конкретной версии `winws`, поскольку флаги/режимы между поколениями могут отличаться. Не переносить флаги по памяти. |
| [WinDivert](https://github.com/basil00/WinDivert) | Нужен как первичный источник по драйверу/API, лицензии и Windows требованиям. | Не выбрана конкретная версия/бинарник; до этого этапа нельзя фиксировать вывод о подписи/HVCI/Secure Boot. Требуется сверка release и тест VM. |
| [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-createjobobjectw) | Использованы для привязки дочернего engine-процесса к `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; Microsoft указывает, что закрытие последнего handle завершает процессы в job. Rust bindings: [`windows-sys`](https://docs.rs/windows-sys/latest/windows_sys/Win32/System/JobObjects/index.html). | В коде создан приватный Job Object, задан флаг kill-on-close, затем child process назначается в job. Если назначение не удалось, дочерний процесс завершается, engine не остаётся запущенным. Проверено локальным тестом запуска/остановки `cmd.exe`; тест при закрытии родительского процесса через отдельный VM сценарий ещё не проводился. |
| [dpibreak](https://github.com/dilluti0n/dpibreak) | Указан планом как Rust/WinDivert аналог. | Код, лицензия, последний commit и актуальность не исследованы; не использовать в реализации до проверки. |
| [vane](https://github.com/luluwux/vane) | Указан планом как Rust/Tauri GUI поверх zapret. | Не исследован; молодость/безопасность и лицензия остаются непроверенными. Только идеи UX после аудита. |
| [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) | Альтернативная реализация обхода DPI, упомянутая планом. | Код/лицензия/активность ещё не проверены; не копировать код или бинарники. |
| [ByeDPI](https://github.com/hufrea/byedpi) и [SpoofDPI](https://github.com/xvzc/SpoofDPI) | Сравнительные реализации из списка плана. | Код, лицензии, дата активности не исследованы. Не использовать без отдельной проверки. |
| [zapret-desktop](https://github.com/fecset/zapret-desktop) | Кандидат на идеи диагностики, истории и автоподбора. | Не исследован; не доверять бинарникам и не копировать код до проверки лицензии/хеша. |
| [unblock-pro](https://github.com/by-sonic/unblock-pro) | Кандидат на проверку стратегий реальными запросами. | Не исследован; точность измерений/безопасность не подтверждены. |
| [blockcheckw](https://github.com/rcd27/blockcheckw) | Кандидат на различение проблем SNI и IP. | Не исследован; не использовать как ground truth до изучения кода и методики. |
| [Geneva paper](https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf) | Теоретическая основа для автоматизированного исследования DPI-стратегий. | Не является доказательством работоспособности конкретного профиля/провайдера. Полное изучение отложено. |
| [zapret-desktop UI wrapper](https://github.com/Tchk-zz/cat-zapret) | Указан как пример UX/обновлений. | В плане помечен с другим URL-названием; нужно проверить точную идентичность проекта, лицензию, активность и код перед выводами. |
| [zapret-for-mac](https://github.com/naladwepo/zapret-for-mac) | В плане упомянут как источник идей probe. | Не исследован, не переносить platform-specific код. |

## Вывод

На этом этапе надёжная фактическая база для каталога — только снимок исходных профилей Flowseal. Для MVP выбран предварительный оркестратор поверх закреплённого upstream engine (вариант A); выбор бинарного release и модель привилегий остаются открытыми до одобрения архитектуры и отдельной проверки лицензий/подписей.

