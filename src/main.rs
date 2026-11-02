//! ferrotun: containerized WireGuard client with a kill-switch.

mod config;
mod control;
mod dns;
mod firewall;
mod health;
mod netlink;
mod portforward;
mod publicip;
mod qbittorrent;
mod routing;
mod state;
mod supervisor;
mod tls;
mod wgconf;
mod wireguard;

use std::process::ExitCode;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("healthcheck") => health::client_check(),
        Some("version" | "--version" | "-V") => {
            println!("ferrotun {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        None | Some("run") => run(),
        Some("help" | "--help" | "-h") => {
            println!("usage: ferrotun [run|healthcheck|version]");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command '{other}' (run, healthcheck, version)");
            ExitCode::from(2)
        }
    }
}

fn run() -> ExitCode {
    let level = config::env("LOG_LEVEL").unwrap_or_else(|| "info".into()).to_ascii_lowercase();
    let filter =
        EnvFilter::try_new(format!("warn,ferrotun={level}")).unwrap_or_else(|_| EnvFilter::new("warn,ferrotun=info"));
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).with_ansi(ansi).init();

    info!("ferrotun {} starting", env!("CARGO_PKG_VERSION"));
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("invalid configuration: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            error!("tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(supervisor::run(cfg)) {
        Ok(()) => {
            info!("stopped cleanly");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("fatal error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
