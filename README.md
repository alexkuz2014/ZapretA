# ZapretA

[English](README.md) | [Русский](README_RU.md)

**Automatically diagnose and improve access to websites affected by network filtering.** ZapretA is a portable Windows application written in Rust: one exe with an embedded, hash-pinned engine (zapret `winws` + WinDivert), automatic strategy selection, a window, a tray icon and background operation.

> **Project status: early, untested on real filtered networks.** The app builds, its logic is unit-tested and the window was smoke-tested under Wine, but the engine/driver path and strategy search have not yet been verified on Windows behind real DPI. See [Architecture](docs/ARCHITECTURE.md) for what is and is not verified.

Double-click `ZapretA.exe`, accept the UAC prompt, press **Включить**. It tries the 22 Flowseal profiles, then 29 own variants derived from zapret's `blockcheck.sh`, keeps the first one that passes the checks, and re-selects if access degrades. Own sites, IP addresses and exclusions are edited in the window. Embedded third-party files and hashes: [SBOM](docs/SBOM.md), [notices](docs/THIRD_PARTY_NOTICES.md).

## What ZapretA aims to do

Some networks interfere with connections to particular websites. The cause can vary: a DNS response may be altered, a TLS connection may be interrupted, or traffic may be slowed after it starts. A basic “can I connect to this address?” check cannot reliably tell these cases apart.

ZapretA is intended to run a small set of checks, compare the results with a known reachable control site, and test supported strategies one at a time. If a strategy passes the checks, the app will keep it active and show its status in the Windows system tray. It should avoid sending traffic through third-party proxy servers.

The current `--diagnose` command directly queries the configured system DNS resolver and `dns.google`, then makes bounded HTTPS requests to `www.youtube.com` and `example.com`. It does not change system settings or start a traffic engine. Different DNS answers are only a signal for further investigation, not proof of tampering. Run it only if you agree to these network requests. Automatic strategy selection and the other goals remain under development.

## Project documents

- [Architecture proposal](docs/ARCHITECTURE.md) — strategy model, engine options, Windows constraints, and open questions.
- [Research notes](docs/RESEARCH.md) — reviewed sources and items that still need verification.
- [Project plan](planzapret.md) — phased scope and acceptance goals.

## Development status

- [x] Initial research and architecture proposal.
- [x] Approve and start the Rust workspace architecture.
- [x] Build the Rust workspace, catalog validator, and engine process boundary.
- [x] Add initial manual system DNS, bootstrapped Google/Cloudflare DoH fallback, and HTTPS checks.
- [x] Classify probe signals and implement sequential strategy selection.
- [x] Add window, tray status, background watchdog, custom lists and autostart.
- [ ] Verify on Windows behind real DPI; signed CI release build.
- [x] Add Windows MSVC CI, dependency policy checks, and a checksummed CI artifact.
- [ ] Publish a reviewed and verified release.

## Build and run

The CLI can validate the example catalog and run the initial network diagnostic with `cargo run -p zapreta -- --diagnose`. The catalog is only a schema demonstration and cannot start an engine. The diagnostic contacts `dns.google`, `www.youtube.com`, and `example.com`; it does not perform traffic handling or prove that a site works in a browser. Build and check the workspace with `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`. Do not download executables from unofficial sources claiming to be ZapretA.

The repository also contains 22 pinned Flowseal source snapshots under [catalog/flowseal](catalog/flowseal/README.md). They preserve upstream arguments for review and golden tests; they are not runnable strategies and are not passed to an engine.

See [Development setup](docs/DEV_SETUP.md) for the pinned Rust toolchain, MSVC requirements, CI checks, and artifact details. [Windows CI passed](https://github.com/alexkuz2014/ZapretA/actions/runs/41042507801) and uploaded a temporary Windows executable with SHA-256 manifest; this is not an official release or signed binary.

## Security and trust

The planned approach may use a Windows packet-filtering driver. Such a component needs elevated privileges and must be verified carefully. Before any binary is distributed, the project must document its source, license, version, and SHA-256 checksum. The app is planned to modify traffic locally; it is not intended to route traffic through a remote VPN or proxy.

## License

ZapretA is released under the [MIT License](LICENSE). Third-party components retain their own license and attribution requirements.

---

