# ZapretA

[English](README.md) | [Русский](README_RU.md)

**Automatically diagnose and improve access to websites affected by network filtering.** ZapretA is a planned portable Windows application written in Rust. It will test network connectivity, try a verified traffic-handling strategy, and report whether the connection improves.

> **Project status: early development.** The Rust workspace, catalog validation, diagnostic signal types, and verified engine process boundary are in place. There is no bundled engine, active network probe, automatic traffic handling, or release build yet.

## What ZapretA aims to do

Some networks interfere with connections to particular websites. The cause can vary: a DNS response may be altered, a TLS connection may be interrupted, or traffic may be slowed after it starts. A basic “can I connect to this address?” check cannot reliably tell these cases apart.

ZapretA is intended to run a small set of checks, compare the results with a known reachable control site, and test supported strategies one at a time. If a strategy passes the checks, the app will keep it active and show its status in the Windows system tray. It should avoid sending traffic through third-party proxy servers.

These are project goals, not features available today. Results will depend on the network, Windows security settings, and the specific filtering behavior in use.

## Project documents

- [Architecture proposal](docs/ARCHITECTURE.md) — strategy model, engine options, Windows constraints, and open questions.
- [Research notes](docs/RESEARCH.md) — reviewed sources and items that still need verification.
- [Project plan](planzapret.md) — phased scope and acceptance goals.

## Development status

- [x] Initial research and architecture proposal.
- [x] Approve and start the Rust workspace architecture.
- [x] Build the Rust workspace, catalog validator, and engine process boundary.
- [ ] Implement network checks and sequential strategy selection.
- [ ] Add tray status, safe cleanup, and diagnostics.
- [ ] Set up Windows CI and publish a verified release.

## Build and run

The current CLI can validate the example catalog. The example is only a schema demonstration and cannot be used to start an engine. Network probing and a bundled engine are not implemented. Build and check the workspace with `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`. Do not download executables from unofficial sources claiming to be ZapretA.

## Security and trust

The planned approach may use a Windows packet-filtering driver. Such a component needs elevated privileges and must be verified carefully. Before any binary is distributed, the project must document its source, license, version, and SHA-256 checksum. The app is planned to modify traffic locally; it is not intended to route traffic through a remote VPN or proxy.

## License

The project license has not been selected yet. Third-party components will retain their own license and attribution requirements.

---

