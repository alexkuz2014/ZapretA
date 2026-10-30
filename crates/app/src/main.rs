use std::{env, path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    match args.next().as_deref() {
        Some(arg) if arg == "--version" => {
            println!("ZapretA {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(arg) if arg == "--validate-catalog" => {
            let Some(path) = args.next() else {
                eprintln!("Usage: zapreta --validate-catalog <catalog.toml>");
                return ExitCode::from(2);
            };
            validate_catalog(PathBuf::from(path))
        }
        Some(arg) if arg == "--validate-source-catalog" => {
            let Some(path) = args.next() else {
                eprintln!("Usage: zapreta --validate-source-catalog <snapshot.toml>");
                return ExitCode::from(2);
            };
            validate_source_catalog(PathBuf::from(path))
        }
        Some(arg) if arg == "--diagnose" => diagnose().await,
        _ => {
            println!("ZapretA — research build. Network engine is not configured yet.");
            println!(
                "Use --version, --validate-catalog <catalog.toml>, --validate-source-catalog <snapshot.toml>, or --diagnose."
            );
            ExitCode::SUCCESS
        }
    }
}

async fn diagnose() -> ExitCode {
    use std::time::Duration;
    use zapreta_net::{AllowedHost, DnsResolver, HttpsProber, NetworkPurpose};

    let resolver = match DnsResolver::new(Duration::from_secs(5)) {
        Ok(resolver) => resolver,
        Err(error) => {
            eprintln!("Не удалось запустить DNS-проверку: {error}");
            return ExitCode::FAILURE;
        }
    };
    let https = match HttpsProber::new(Duration::from_secs(8)) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Не удалось запустить HTTPS-проверку: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("Проверка сети без запуска движка и без изменения трафика.");
    println!(
        "DNS через систему и DoH с резервным провайдером; HTTPS к YouTube и контрольному example.com."
    );

    let mut all_passed = true;
    for hostname in ["www.youtube.com", "example.com"] {
        println!("\nDNS: {hostname}");
        let system = resolver.system(hostname).await;
        let doh = resolver.doh(hostname).await;
        match (&system, &doh) {
            (Ok(system), Ok(doh)) if system.addresses == doh.addresses => {
                println!("  Системный DNS и DoH вернули одинаковые адреса.");
            }
            (Ok(system), Ok(doh)) => {
                println!(
                    "  Полные списки различаются. CDN, ротация адресов или разная поддержка IPv4/IPv6 могут объяснить это; само по себе это не указывает на подмену."
                );
                println!("  System: {:?}", system.addresses);
                println!("  DoH ({}): {:?}", doh.provider, doh.addresses);
            }
            (system, doh) => {
                all_passed = false;
                println!(
                    "  System: {}",
                    format_result(system.as_ref().map(|v| &v.addresses))
                );
                println!(
                    "  DoH:    {}",
                    format_result(doh.as_ref().map(|v| &v.addresses))
                );
            }
        }
    }

    println!("\nHTTPS:");
    for (hostname, path) in [("www.youtube.com", "/generate_204"), ("example.com", "/")] {
        let host = match AllowedHost::new(hostname, NetworkPurpose::Probe) {
            Ok(host) => host,
            Err(error) => {
                eprintln!("  {hostname}: invalid probe target: {error}");
                all_passed = false;
                continue;
            }
        };
        match https.get(&host, path, 16 * 1024).await {
            Ok(result) if (200..300).contains(&result.status_code) => println!(
                "  {hostname}: HTTP {}, {} ms, read {} bytes{}",
                result.status_code,
                result.elapsed_ms,
                result.bytes_read,
                if result.body_limited {
                    " (body limit reached)"
                } else {
                    ""
                }
            ),
            Ok(result) => {
                all_passed = false;
                println!(
                    "  {hostname}: HTTP {} in {} ms",
                    result.status_code, result.elapsed_ms
                );
            }
            Err(error) => {
                all_passed = false;
                println!("  {hostname}: {error}");
            }
        }
    }
    println!("\nДиагностика завершена. Никакая стратегия обхода не запускалась.");
    if all_passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn format_result<T: std::fmt::Debug>(result: Result<&T, &zapreta_net::NetError>) -> String {
    match result {
        Ok(value) => format!("{value:?}"),
        Err(error) => error.to_string(),
    }
}

fn validate_catalog(path: PathBuf) -> ExitCode {
    match zapreta_core::StrategyCatalog::load(&path) {
        Ok(catalog) => {
            println!(
                "Valid catalog: {} strategies; engine {}; source {}",
                catalog.strategies.len(),
                catalog.engine_version,
                catalog.source_revision
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Catalog error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn validate_source_catalog(path: PathBuf) -> ExitCode {
    match std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
        .and_then(|input| {
            zapreta_core::SourceStrategySnapshot::parse_toml(&input)
                .map_err(|error| error.to_string())
        }) {
        Ok(snapshot) => {
            println!(
                "Valid source snapshot (not runnable): {}; {} argv tokens; source {}",
                snapshot.profile_name,
                snapshot.argv.len(),
                snapshot.source_commit
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Source snapshot error: {error}");
            ExitCode::FAILURE
        }
    }
}
