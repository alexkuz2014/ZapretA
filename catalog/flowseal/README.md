# Flowseal source snapshots

These 22 TOML files preserve the normalized `winws.exe` argv from the `general*.bat` files in Flowseal commit `176f56dc3f11ce5915c26abcdde903f93d835b64`.

They are audit references and golden-test inputs only. They are **not runnable strategy catalog entries** and are not consumed by the engine. The current typed `StrategyCatalog` builder cannot yet express every observed upstream option. Do not pass these raw arguments to `EngineProcess`.

Each snapshot records the upstream filename and SHA-256. The accompanying test fixtures are under `tests/fixtures/flowseal/`; tests read them as text, never execute them, expand only the documented source path variables, and check the default disabled Game Filter values from the pinned `service.bat`. The included upstream `LICENSE.txt` applies to these source fixtures. No engine executable, DLL, SYS driver, or fake payload is included.

Validate an individual reference file with:

```powershell
cargo run -p zapreta -- --validate-source-catalog catalog/flowseal/flowseal-general-default.toml
```
