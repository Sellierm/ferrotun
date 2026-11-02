//! Tunnel health check and the health server used by the Docker HEALTHCHECK.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream as StdTcpStream},
    process::ExitCode,
    time::Duration,
};

use anyhow::{Result, bail};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use tokio::net::TcpStream;
use tracing::info;

use crate::{config, state::Shared};

const DIAL_TIMEOUT: Duration = Duration::from_secs(8);

/// Healthy if a TCP connection to any target succeeds (exercises DNS and the tunnel).
pub async fn check(targets: &[String]) -> Result<()> {
    let mut errors = vec![];
    for t in targets {
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(t.as_str())).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => errors.push(format!("{t}: {e}")),
            Err(_) => errors.push(format!("{t}: timed out")),
        }
    }
    bail!("{}", errors.join("; "))
}

async fn health_handler(State(shared): State<Shared>) -> (StatusCode, String) {
    let st = shared.status.read().await;
    if st.healthy {
        (StatusCode::OK, "healthy\n".into())
    } else {
        let why = st.last_error.clone().unwrap_or_else(|| format!("VPN state: {:?}", st.vpn));
        (StatusCode::INTERNAL_SERVER_ERROR, format!("unhealthy: {why}\n"))
    }
}

pub async fn serve(addr: SocketAddr, shared: Shared) -> Result<()> {
    let app = Router::new().route("/", get(health_handler)).with_state(shared);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("health server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// `ferrotun healthcheck`, used by the Docker HEALTHCHECK.
pub fn client_check() -> ExitCode {
    let raw = config::env("HEALTH_SERVER_ADDRESS").unwrap_or_else(|| "127.0.0.1:9999".into());
    let mut addr = match config::parse_listen_addr(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid HEALTH_SERVER_ADDRESS: {e}");
            return ExitCode::FAILURE;
        }
    };
    if addr.ip().is_unspecified() {
        addr.set_ip([127, 0, 0, 1].into());
    }
    match query(addr) {
        Ok((true, body)) => {
            print!("{body}");
            ExitCode::SUCCESS
        }
        Ok((false, body)) => {
            eprint!("{body}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("health server unreachable at {addr}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn query(addr: SocketAddr) -> std::io::Result<(bool, String)> {
    let mut s = StdTcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut resp = String::new();
    s.read_to_string(&mut resp)?;
    let ok = resp.lines().next().is_some_and(|l| l.split_whitespace().nth(1) == Some("200"));
    let body = resp.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    Ok((ok, body))
}
