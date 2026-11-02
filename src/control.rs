//! HTTP control API.

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::info;

use crate::{
    state::{Command, Shared, VpnState, unix_secs},
    wireguard,
};

#[derive(Clone)]
struct Api {
    shared: Shared,
    api_key: Option<Arc<str>>,
    log: bool,
}

pub async fn serve(addr: SocketAddr, shared: Shared, api_key: Option<String>, log: bool) -> Result<()> {
    let api = Api { shared, api_key: api_key.map(Arc::from), log };
    let app = Router::new()
        .route("/v1/publicip/ip", get(public_ip))
        .route("/v1/portforward", get(port_forwarded))
        .route("/v1/vpn/status", get(vpn_status).put(set_vpn_status))
        .route("/v1/status", get(full_status))
        .layer(middleware::from_fn_with_state(api.clone(), auth_and_log))
        .with_state(api.clone());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("control API listening on {addr}{}", if api.api_key.is_some() { " (API key required)" } else { "" });
    axum::serve(listener, app).await?;
    Ok(())
}

fn authorized(headers: &HeaderMap, key: &str) -> bool {
    let given = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")));
    given.is_some_and(|g| constant_time_eq(g.trim().as_bytes(), key.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn auth_and_log(State(api): State<Api>, req: Request, next: Next) -> Response {
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    let resp = match &api.api_key {
        Some(key) if !authorized(req.headers(), key) => {
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": "missing or invalid API key" }))).into_response()
        }
        _ => next.run(req).await,
    };
    if api.log {
        info!("api: {method} {path} -> {}", resp.status().as_u16());
    }
    resp
}

fn run_status(s: VpnState) -> &'static str {
    match s {
        VpnState::Stopped => "stopped",
        _ => "running",
    }
}

async fn public_ip(State(api): State<Api>) -> Json<Value> {
    let st = api.shared.status.read().await;
    match &st.public_ip {
        Some(ip) => Json(serde_json::to_value(ip).unwrap_or_default()),
        None => Json(json!({ "public_ip": "" })),
    }
}

async fn port_forwarded(State(api): State<Api>) -> Json<Value> {
    Json(json!({ "port": api.shared.status.read().await.forwarded_port }))
}

async fn vpn_status(State(api): State<Api>) -> Json<Value> {
    Json(json!({ "status": run_status(api.shared.status.read().await.vpn) }))
}

#[derive(Deserialize)]
struct StatusBody {
    status: String,
}

async fn set_vpn_status(State(api): State<Api>, Json(body): Json<StatusBody>) -> (StatusCode, Json<Value>) {
    let cmd = match body.status.as_str() {
        "running" => Command::Start,
        "stopped" => Command::Stop,
        "restarted" | "restart" => Command::Restart,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid status '{other}' (running, stopped, restarted)") })),
            );
        }
    };
    if api.shared.commands.send(cmd).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "supervisor unavailable" })));
    }
    (StatusCode::OK, Json(json!({ "status": body.status })))
}

async fn full_status(State(api): State<Api>) -> Json<Value> {
    let st = api.shared.status.read().await.clone();
    let tunnel = match st.implementation {
        Some(imp) if st.vpn != VpnState::Stopped => wireguard::stats(&api.shared.vpn_interface, imp).await,
        _ => None,
    };
    Json(json!({
        "vpn": {
            "state": st.vpn,
            "healthy": st.healthy,
            "interface": api.shared.vpn_interface,
            "implementation": st.implementation.map(|i| i.to_string()),
            "endpoint": st.endpoint.map(|e| e.to_string()),
            "connected_since": st.connected_since.map(unix_secs),
            "reconnections": st.reconnections,
            "last_error": st.last_error,
            "tunnel": tunnel,
        },
        "public_ip": st.public_ip,
        "port_forward": { "port": st.forwarded_port },
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
