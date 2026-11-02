//! Keeps qBittorrent's listen port in sync with the forwarded port.

use std::time::Duration;

use anyhow::{Result, bail};
use reqwest::{StatusCode, header};

use crate::{config::QbitConfig, tls};

/// Returns `true` if the port had to be changed.
pub async fn ensure_port(cfg: &QbitConfig, port: u16) -> Result<bool> {
    let client = tls::web_client(Duration::from_secs(10))?;
    let mut cookie: Option<String> = None;

    if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        let resp = client
            .post(format!("{}/api/v2/auth/login", cfg.url))
            .form(&[("username", user.as_str()), ("password", pass.as_str())])
            .send()
            .await?;
        cookie = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|v| v.split(';').next())
            .find(|kv| kv.split('=').next().is_some_and(|k| k.contains("SID")))
            .map(String::from);
        // qBittorrent < 5: 200 "Ok." / 200 "Fails."; qBittorrent >= 5: 204 (empty) / 401.
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status == StatusCode::FORBIDDEN {
            bail!("qBittorrent banned this IP after too many failed logins (403)");
        }
        if !status.is_success() || body.trim().starts_with("Fails") {
            bail!("qBittorrent login rejected ({status})");
        }
    }

    let with_cookie = |req: reqwest::RequestBuilder| match &cookie {
        Some(c) => req.header(header::COOKIE, c),
        None => req,
    };

    let resp = with_cookie(client.get(format!("{}/api/v2/app/preferences", cfg.url))).send().await?;
    if resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED {
        bail!(
            "qBittorrent denied access: set QBITTORRENT_USERNAME/QBITTORRENT_PASSWORD \
             or enable \"Bypass authentication for clients on localhost\""
        );
    }
    let prefs: serde_json::Value = resp.error_for_status()?.json().await?;
    if prefs.get("listen_port").and_then(|v| v.as_u64()) == Some(port as u64) {
        return Ok(false);
    }

    let json = serde_json::json!({ "listen_port": port, "random_port": false, "upnp": false }).to_string();
    with_cookie(client.post(format!("{}/api/v2/app/setPreferences", cfg.url)))
        .form(&[("json", json)])
        .send()
        .await?
        .error_for_status()?;
    Ok(true)
}
