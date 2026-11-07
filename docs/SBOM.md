# Встроенные сторонние файлы

Источник: https://github.com/Flowseal/zapret-discord-youtube, коммит `176f56dc3f11ce5915c26abcdde903f93d835b64` (тот же, что закреплён в `catalog/flowseal/*.toml`). Файлы `bin/*` и `lists/*` проверены на побайтовое совпадение с более новым HEAD `2401b7a` на 2026-11-07 (отличался только `ipset-all.txt.backup`, он не встроен).
Файлы лежат в `crates/app/assets/engine/` и встроены в `zapreta.exe` через `include_bytes!`. Таблицу и `embedded.rs` генерирует `tools/gen_embedded.py`. При запуске файлы распаковываются в `%LOCALAPPDATA%\ZapretA\flowseal-176f56d\`, расходящиеся с хешем перезаписываются, `winws.exe` дополнительно проверяется перед запуском.

Хеши получены нами из git-клона по HTTPS; независимого второго источника подтверждения (подпись релиза, отдельные контрольные суммы автора) нет.

| Файл | Размер, байт | SHA-256 |
|---|---|---|
| `WinDivert.dll` | 47616 | `c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2` |
| `WinDivert64.sys` | 94144 | `8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2` |
| `bin/ACTIVE_DISCORD_UDP.bin` | 1200 | `2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf` |
| `bin/ACTIVE_GAME_UDP.bin` | 1250 | `e065870cb0d13152e6132807bbf42218a9e7cd8d96f5602b61674cc540f3a56e` |
| `bin/quic_initial_4pda_to.bin` | 1250 | `e065870cb0d13152e6132807bbf42218a9e7cd8d96f5602b61674cc540f3a56e` |
| `bin/quic_initial_5ka_ru.bin` | 1250 | `247dcd97f53bfae5482e4b2b66acdb01e48ee6c29c5ca526c9b241fa38c233b5` |
| `bin/quic_initial_lemana_pro.bin` | 1357 | `c2ff932a40d69a61321c1fa091a6182e16a2fb85f36881b6864f864f07508848` |
| `bin/quic_initial_rutube_ru.bin` | 1357 | `74b1dfbdec125263c9407436658b0a848b8f0a934b8063d11571a6a2146a4a7b` |
| `bin/quic_initial_steam_chat_com.bin` | 1357 | `1da1407166f5d2ade80f1d3c86d828178e13f08050c40fda2b0a4d276318642a` |
| `bin/quic_initial_steamcommunity_com.bin` | 1200 | `2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf` |
| `bin/quic_initial_steamstatic_com.bin` | 1357 | `4f1468adcc30ac7ffd9e04627c7289968f8c4ae476626d05f282da8064fe64b4` |
| `bin/quic_initial_tencent_com.bin` | 1231 | `d250051d6200946a7ba0629c59c5641432957fa3513081a6c3c5aaa91a62ac03` |
| `bin/quic_initial_www_google_com.bin` | 1200 | `f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a` |
| `bin/stun.bin` | 100 | `9cd5469309780ca56c0bd97266524a48c7ee529d02c3179cfecb20b260a59641` |
| `bin/stun2.bin` | 120 | `b7c2497496039c541f7337ac8536813f0a1cf52363ab2faa5213b7816d458813` |
| `bin/tls_clienthello_4pda_to.bin` | 284 | `eefeaf09dde8d69b1f176212541f63c68b314a33a335eced99a8a29f17254da8` |
| `bin/tls_clienthello_5ka_ru.bin` | 654 | `1e8871e272591c5a277d38a6166af597c1fecb1cf58e85162e8f1968ec08d018` |
| `bin/tls_clienthello_awswaf_com.bin` | 1100 | `6405e264eff9f33632e727f6d696ff39503d3652f0f0be00921f06f97720a5b0` |
| `bin/tls_clienthello_max_ru.bin` | 664 | `4ee0870abe0a0128600b0095189987ba1d210dae8bf963bc725aff49cf922624` |
| `bin/tls_clienthello_sochi_park.bin` | 244 | `ad552922acfe029521da884ea29f4bb28bb6bdcee9b1a70b46adbfd266c11d4d` |
| `bin/tls_clienthello_steam_chat_com.bin` | 1100 | `388e9a09bb2758ebbce34a0e27d8efa41bbd59954c9c32d8fb74b4bce2d99c67` |
| `bin/tls_clienthello_steamstatic_com.bin` | 1100 | `3f8ba0b0de17a3feda593ef2cd82a1b44ca566f96acaa42f6fccd69f2484ecea` |
| `bin/tls_clienthello_teamspeak_com.bin` | 1100 | `1336b7529c050a9c5a4728368430686311c448d4b3ba61bfc8d1e10a15de438a` |
| `bin/tls_clienthello_www_google_com.bin` | 681 | `936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c` |
| `bin/tls_clienthello_www_sferum_ru.bin` | 661 | `e6dd8d724eecc6a7340bf64e2ebec81c60bc4e078c6f702b4b6ba9bf184180ad` |
| `cygwin1.dll` | 2954293 | `103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b` |
| `lists/ipset-all.txt` | 18 | `19123a22bf1108815c07bda3cda8df282b30bd63e4939949928969c0fd195873` |
| `lists/ipset-exclude.txt` | 135 | `96c03954012765ce4ab03b9c30f29ab1ca1b698c6752224d03828e6d182eb0fc` |
| `lists/list-exclude.txt` | 1726 | `e2de8403e1d2bd8ebd9de6b2cbfaab488d710681cbdcde2b219e71bc4490a56d` |
| `lists/list-general.txt` | 1067 | `9ff3ae9e4bf0edbcf8fecb1bba7aac951aace2036cdb732ec3ef65dfc6db443b` |
| `lists/list-google.txt` | 453 | `4104b8f5119f76a3642e3176987bbcf817d98daa4899a7ecf9ee2c254958e33b` |
| `winws.exe` | 203776 | `affb4f69d2ea302a7abccd5325d81826e140ddae014f1e070bc4a6c0dd555188` |
