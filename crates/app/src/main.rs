use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
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
        _ => {
            println!("ZapretA — research build. Network engine is not configured yet.");
            println!("Use --version or --validate-catalog <catalog.toml>.");
            ExitCode::SUCCESS
        }
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
