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
    use zapreta_probe::{
        BaselineReport, CheckStatus, DnsBaseline, DnsFamilyResult, DnsResponseState, Observation,
        dns_baseline_signal,
    };

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
    let mut target_dns: Option<(
        Result<zapreta_net::DnsResolution, zapreta_net::NetError>,
        Result<zapreta_net::DnsResolution, zapreta_net::NetError>,
    )> = None;
    for hostname in ["www.youtube.com", "example.com"] {
        println!("\nDNS: {hostname}");
        let system = resolver.system(hostname).await;
        let doh = resolver.doh(hostname).await;
        if hostname == "www.youtube.com" {
            target_dns = Some((system.clone(), doh.clone()));
        }
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
    let mut endpoint_results = Vec::new();
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
            Ok(result) => {
                let passed = (200..300).contains(&result.status_code);
                if !passed {
                    all_passed = false;
                }
                println!(
                    "  {hostname}: HTTP {}, {} ms, read {} bytes{}",
                    result.status_code,
                    result.elapsed_ms,
                    result.bytes_read,
                    if result.body_limited {
                        " (body limit reached)"
                    } else {
                        ""
                    }
                );
                endpoint_results.push((hostname, Some(result.status_code)));
            }
            Err(error) => {
                all_passed = false;
                println!("  {hostname}: {error}");
                endpoint_results.push((hostname, None));
            }
        }
    }
    if let Some((system, doh)) = target_dns {
        let convert = |family: &zapreta_net::DnsFamilyResolution| {
            let (status, response) = match family.state {
                zapreta_net::DnsAnswerState::Answer => (
                    CheckStatus::Passed,
                    Observation::Known(DnsResponseState::Answer),
                ),
                zapreta_net::DnsAnswerState::NoData => (
                    CheckStatus::Passed,
                    Observation::Known(DnsResponseState::NoData),
                ),
                zapreta_net::DnsAnswerState::NxDomain => (
                    CheckStatus::Passed,
                    Observation::Known(DnsResponseState::NxDomain),
                ),
                zapreta_net::DnsAnswerState::Incomplete => {
                    (CheckStatus::Passed, Observation::Unknown)
                }
                zapreta_net::DnsAnswerState::NotQueried => {
                    (CheckStatus::NotRun, Observation::Unknown)
                }
            };
            DnsFamilyResult::from_dns_response(status, response, family.addresses.clone())
        };
        let failed = || {
            DnsFamilyResult::from_dns_response(
                CheckStatus::Failed,
                Observation::Unknown,
                Vec::new(),
            )
        };
        let (system_a, system_aaaa) = match &system {
            Ok(result) => (convert(&result.ipv4), convert(&result.ipv6)),
            Err(_) => (failed(), failed()),
        };
        let (doh_a, doh_aaaa, doh_provider) = match &doh {
            Ok(result) => (
                convert(&result.ipv4),
                convert(&result.ipv6),
                Observation::Known(result.provider.to_owned()),
            ),
            Err(_) => (failed(), failed(), Observation::Unknown),
        };
        let dns = DnsBaseline {
            system_a,
            system_aaaa,
            doh_a,
            doh_aaaa,
            doh_provider,
        };
        println!(
            "\nDNS A/AAAA states: system A {:?}, AAAA {:?}; DoH A {:?}, AAAA {:?}",
            dns.system_a.response,
            dns.system_aaaa.response,
            dns.doh_a.response,
            dns.doh_aaaa.response
        );
        println!("DNS baseline: {:?}", dns_baseline_signal(&dns));
        let tcp_control = endpoint_results
            .iter()
            .find(|(host, _)| *host == "example.com")
            .map(|(_, status)| *status);
        let tcp_target = endpoint_results
            .iter()
            .find(|(host, _)| *host == "www.youtube.com")
            .map(|(_, status)| *status);
        if let (Some(control_status), Some(target_status)) = (tcp_control, tcp_target) {
            let endpoint = |name: &str, status: Option<u16>| zapreta_probe::EndpointResult {
                endpoint: name.to_owned(),
                dns: CheckStatus::Passed,
                // An HTTP response proves TCP and TLS completed, even for 4xx/5xx.
                tcp: if status.is_some() {
                    CheckStatus::Passed
                } else {
                    CheckStatus::NotRun
                },
                tls: if status.is_some() {
                    CheckStatus::Passed
                } else {
                    CheckStatus::NotRun
                },
                content: match status {
                    Some(code) if (200..300).contains(&code) => CheckStatus::Passed,
                    Some(_) => CheckStatus::Failed,
                    None => CheckStatus::NotRun,
                },
            };
            let report = BaselineReport {
                target: "www.youtube.com".into(),
                control: endpoint("example.com", control_status),
                target_result: endpoint("www.youtube.com", target_status),
                signal: dns_baseline_signal(&dns),
                dns,
            };
            println!("\nСводный DNS-сигнал: {:?}", report.signal);
            println!(
                "TLS/HTTPS сигнал: {:?}",
                Observation::Known(zapreta_probe::classify(
                    &report.control,
                    &report.target_result
                ))
            );
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
