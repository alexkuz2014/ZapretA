# ZapretA

[English](README.md) | [Русский](README_RU.md)

**Automatically diagnose and improve access to websites affected by network filtering.** ZapretA is a planned portable Windows application written in Rust. It will test network connectivity, try a verified traffic-handling strategy, and report whether the connection improves.

> **Project status: early development.** The Rust workspace, catalog validation, engine process boundary, and an initial manual DNS/HTTPS diagnostic (`--diagnose`) are in place. There is no bundled engine, automatic strategy selection, tray UI, or release build yet.

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
- [x] Add initial manual system DNS, Google DoH, and HTTPS checks.
- [ ] Classify probe signals and implement sequential strategy selection.
- [ ] Add tray status, safe cleanup, and diagnostics.
- [ ] Set up Windows CI and publish a verified release.

## Build and run

The CLI can validate the example catalog and run the initial network diagnostic with `cargo run -p zapreta -- --diagnose`. The catalog is only a schema demonstration and cannot start an engine. The diagnostic contacts `dns.google`, `www.youtube.com`, and `example.com`; it does not perform traffic handling or prove that a site works in a browser. Build and check the workspace with `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`. Do not download executables from unofficial sources claiming to be ZapretA.

## Security and trust

The planned approach may use a Windows packet-filtering driver. Such a component needs elevated privileges and must be verified carefully. Before any binary is distributed, the project must document its source, license, version, and SHA-256 checksum. The app is planned to modify traffic locally; it is not intended to route traffic through a remote VPN or proxy.

## License

The project license has not been selected yet. Third-party components will retain their own license and attribution requirements.

---

