//! Private Internet Access port forwarding, same protocol as PIA's official scripts:
//! 1. token: `POST https://www.privateinternetaccess.com/api/client/v2/token`
//! 2. `GET https://<gateway>:19999/getSignature?token=` through the tunnel, verified against
//!    PIA's CA with the server's TLS name (e.g. amsterdam425)
//! 3. `GET https://<gateway>:19999/bindPort?payload=&signature=` every 15 minutes

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::{sync::watch, task::JoinHandle, time::sleep};
use tracing::{error, info, warn};

use crate::{
    config::{PortForwardConfig, QbitConfig},
    firewall::Firewall,
    qbittorrent,
    state::{Shared, write_file},
    tls,
};

const PIA_CA: &[u8] = include_bytes!("../assets/pia-ca.rsa.4096.crt");
const PIA_API_PORT: u16 = 19999;
const BIND_INTERVAL: Duration = Duration::from_secs(15 * 60);
const RENEW_BEFORE_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PfData {
    pub port: u16,
    pub token: String,
    pub signature: String,
    pub expires_at: String,
    /// Base64 payload signed by PIA, sent back as is.
    pub payload: String,
}

impl PfData {
    fn seconds_left(&self) -> Option<i64> {
        let exp = parse_rfc3339(&self.expires_at)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
        Some(exp - now)
    }
}

/// "2026-12-12T21:52:07.43279261Z" -> Unix seconds.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let num = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d, h, mi, se) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.find(|c: char| !c.is_ascii_digit()).unwrap_or(frac.len());
        rest = &frac[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let oh = rest.get(1..3)?.parse::<i64>().ok()?;
            let om = rest.get(4..6)?.parse::<i64>().ok()?;
            sign * (oh * 3600 + om * 60)
        }
    };
    // "days from civil" (H. Hinnant).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se - offset)
}

/// Candidate API gateways: the first host of the WireGuard address's /17
/// (10.14.212.175 -> 10.14.128.1), then the server IP.
pub fn gateways(addresses: &[IpNet], endpoint: IpAddr, forced: Option<IpAddr>) -> Vec<IpAddr> {
    if let Some(g) = forced {
        return vec![g];
    }
    let mut v = vec![];
    if let Some(IpAddr::V4(ip)) = addresses.iter().map(|a| a.addr()).find(IpAddr::is_ipv4) {
        v.push(IpAddr::V4(Ipv4Addr::from((u32::from(ip) & 0xFFFF_8000) | 1)));
    }
    if !v.contains(&endpoint) {
        v.push(endpoint);
    }
    v
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Deserialize)]
struct SignatureResponse {
    status: String,
    #[serde(default)]
    payload: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize)]
struct Payload {
    token: String,
    port: u16,
    expires_at: String,
}

#[derive(Deserialize)]
struct BindResponse {
    status: String,
    #[serde(default)]
    message: Option<String>,
}

enum BindError {
    /// Signature rejected: a new one is needed.
    Rejected(String),
    /// Network failure: retry later with the same data.
    Network(anyhow::Error),
}

pub struct PortForwarder {
    cfg: PortForwardConfig,
    /// One client per gateway, with the TLS name resolved to that gateway.
    api: Vec<(IpAddr, reqwest::Client)>,
    web: reqwest::Client,
}

impl PortForwarder {
    pub fn new(cfg: PortForwardConfig, gateways: Vec<IpAddr>) -> Result<Self> {
        let mut api = vec![];
        for gw in gateways {
            let ca = cfg.ca_override.as_deref().unwrap_or(PIA_CA);
            let client = tls::client_builder(tls::single_ca_config(ca)?, Duration::from_secs(30))
                .resolve(&cfg.server_name, SocketAddr::new(gw, PIA_API_PORT))
                .build()?;
            api.push((gw, client));
        }
        Ok(Self { cfg, api, web: tls::web_client(Duration::from_secs(30))? })
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}:{PIA_API_PORT}/{path}", self.cfg.server_name)
    }

    async fn fetch_token(&self) -> Result<String> {
        let resp = self
            .web
            .post(&self.cfg.token_url)
            .form(&[("username", self.cfg.username.as_str()), ("password", self.cfg.password.as_str())])
            .send()
            .await
            .context("PIA token request")?;
        if matches!(resp.status().as_u16(), 401 | 403) {
            bail!("PIA credentials rejected (VPN_PORT_FORWARDING_USERNAME / PASSWORD)");
        }
        let t: TokenResponse = resp.error_for_status()?.json().await.context("PIA token response")?;
        Ok(t.token)
    }

    async fn get_signature(&self, client: &reqwest::Client, token: &str) -> Result<PfData> {
        let r: SignatureResponse = client
            .get(self.url("getSignature"))
            .query(&[("token", token)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if r.status != "OK" {
            bail!("getSignature rejected: {}", r.message.unwrap_or(r.status));
        }
        let raw = STANDARD.decode(r.payload.trim()).context("invalid base64 payload")?;
        let p: Payload = serde_json::from_slice(&raw).context("invalid JSON payload")?;
        Ok(PfData {
            port: p.port,
            token: p.token,
            signature: r.signature,
            expires_at: p.expires_at,
            payload: r.payload,
        })
    }

    /// New token and signature, with the index of the gateway that answered.
    async fn obtain(&self) -> Result<(PfData, usize)> {
        let token = self.fetch_token().await?;
        let mut errors = vec![];
        for (i, (gw, client)) in self.api.iter().enumerate() {
            match self.get_signature(client, &token).await {
                Ok(d) => return Ok((d, i)),
                Err(e) => errors.push(format!("{gw}: {e:#}")),
            }
        }
        bail!("no PIA gateway answered: {}", errors.join("; "))
    }

    async fn bind(&self, client: &reqwest::Client, data: &PfData) -> Result<(), BindError> {
        let resp = client
            .get(self.url("bindPort"))
            .query(&[("payload", data.payload.as_str()), ("signature", data.signature.as_str())])
            .send()
            .await
            .map_err(|e| BindError::Network(e.into()))?;
        let r: BindResponse = resp.json().await.map_err(|e| BindError::Network(e.into()))?;
        if r.status != "OK" {
            return Err(BindError::Rejected(r.message.unwrap_or(r.status)));
        }
        Ok(())
    }

    fn load(&self) -> Option<PfData> {
        let content = std::fs::read_to_string(&self.cfg.data_file).ok()?;
        match serde_json::from_str::<PfData>(&content) {
            Ok(d) => Some(d),
            Err(e) => {
                warn!("port forwarding: ignoring unreadable {} ({e})", self.cfg.data_file.display());
                None
            }
        }
    }

    fn save(&self, data: &PfData, owner: Option<(u32, u32)>) {
        let json = serde_json::to_string(data).unwrap();
        if let Err(e) = write_file(&self.cfg.data_file, &json, owner) {
            warn!("port forwarding: cannot save data: {e:#}");
        }
    }
}

#[derive(Clone)]
pub struct PfContext {
    pub shared: Shared,
    pub firewall: Firewall,
    pub owner: Option<(u32, u32)>,
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs until aborted by the supervisor on disconnect.
pub async fn run(pf: Arc<PortForwarder>, ctx: PfContext) {
    info!(
        "port forwarding: starting (server {}, gateways {:?})",
        pf.cfg.server_name,
        pf.api.iter().map(|a| a.0).collect::<Vec<_>>()
    );

    let (port_tx, port_rx) = watch::channel::<Option<u16>>(None);
    let _qbit = pf.cfg.qbittorrent.clone().map(|q| AbortOnDrop(tokio::spawn(qbit_sync(q, port_rx))));

    let mut data = pf.load().filter(|d| match d.seconds_left() {
        Some(left) if left > RENEW_BEFORE_SECS => {
            info!("port forwarding: found saved data for port {}", d.port);
            true
        }
        _ => {
            info!("port forwarding: saved data expired, renewing");
            false
        }
    });
    let mut gw = 0usize;
    let mut published: Option<u16> = None;
    let mut backoff = Duration::from_secs(20);

    loop {
        let current = match &data {
            Some(d) => d.clone(),
            None => match pf.obtain().await {
                Ok((d, i)) => {
                    gw = i;
                    pf.save(&d, ctx.owner);
                    data = Some(d.clone());
                    d
                }
                Err(e) => {
                    error!("port forwarding: {e:#} (retrying in {}s)", backoff.as_secs());
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(600));
                    continue;
                }
            },
        };

        // Last working gateway first.
        let order: Vec<usize> = std::iter::once(gw).chain((0..pf.api.len()).filter(|i| *i != gw)).collect();
        let mut result = Err(BindError::Network(anyhow!("no gateway")));
        for i in order {
            result = pf.bind(&pf.api[i].1, &current).await;
            match &result {
                Ok(()) => {
                    gw = i;
                    break;
                }
                Err(BindError::Rejected(_)) => break,
                Err(BindError::Network(_)) => continue,
            }
        }

        match result {
            Ok(()) => {
                backoff = Duration::from_secs(20);
                if published != Some(current.port) {
                    if let Some(old) = published {
                        warn!("port forwarding: port changed ({old} -> {})", current.port);
                        unpublish(&pf.cfg, &ctx, old).await;
                    }
                    publish(&pf.cfg, &ctx, current.port).await;
                    published = Some(current.port);
                    let _ = port_tx.send(Some(current.port));
                    if let Some(left) = current.seconds_left() {
                        info!("port forwarding: data valid for {} more days", left / 86_400);
                    }
                }
                sleep(BIND_INTERVAL).await;
                if current.seconds_left().is_some_and(|l| l < RENEW_BEFORE_SECS) {
                    info!("port forwarding: signature about to expire, renewing");
                    data = None;
                }
            }
            Err(BindError::Rejected(msg)) => {
                warn!("port forwarding: bindPort rejected ({msg}), requesting a new signature");
                data = None;
            }
            Err(BindError::Network(e)) => {
                warn!("port forwarding: bindPort unreachable: {e:#} (retrying in {}s)", backoff.as_secs());
                sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(300));
            }
        }
    }
}

async fn publish(cfg: &PortForwardConfig, ctx: &PfContext, port: u16) {
    info!("port forwarding: forwarded port is {port}");
    ctx.shared.status.write().await.forwarded_port = Some(port);
    if let Err(e) = ctx.firewall.set_forwarded_ports(vec![port], cfg.listening_port).await {
        error!("port forwarding: firewall: {e:#}");
    }
    if let Some(path) = &cfg.status_file {
        match write_file(path, &port.to_string(), ctx.owner) {
            Ok(()) => info!("port forwarding: port written to {}", path.display()),
            Err(e) => warn!("port forwarding: {e:#}"),
        }
    }
    if let Some(cmd) = &cfg.up_command {
        run_hook("up", cmd, port, &ctx.shared.vpn_interface).await;
    }
}

/// Cleanup when the port is no longer valid (disconnect or port change).
pub async fn unpublish(cfg: &PortForwardConfig, ctx: &PfContext, port: u16) {
    if let Some(cmd) = &cfg.down_command {
        run_hook("down", cmd, port, &ctx.shared.vpn_interface).await;
    }
    if let Some(path) = &cfg.status_file {
        let _ = std::fs::remove_file(path);
    }
    if let Err(e) = ctx.firewall.set_forwarded_ports(vec![], None).await {
        error!("port forwarding: firewall: {e:#}");
    }
    ctx.shared.status.write().await.forwarded_port = None;
}

async fn run_hook(kind: &str, template: &str, port: u16, iface: &str) {
    let cmd = template
        .replace("{{PORTS}}", &port.to_string())
        .replace("{{PORT}}", &port.to_string())
        .replace("{{VPN_INTERFACE}}", iface);
    info!("port forwarding: {kind} command: {cmd}");
    let fut = tokio::process::Command::new("/bin/sh").arg("-c").arg(&cmd).kill_on_drop(true).output();
    match tokio::time::timeout(Duration::from_secs(60), fut).await {
        Ok(Ok(out)) => {
            let text =
                String::from_utf8_lossy(&out.stdout).trim().to_string() + String::from_utf8_lossy(&out.stderr).trim();
            if out.status.success() {
                info!("port forwarding: {kind} command succeeded {text}");
            } else {
                warn!("port forwarding: {kind} command failed ({}) {text}", out.status);
            }
        }
        Ok(Err(e)) => warn!("port forwarding: cannot run {kind} command: {e}"),
        Err(_) => warn!("port forwarding: {kind} command killed after 60s"),
    }
}

async fn qbit_sync(cfg: QbitConfig, mut port_rx: watch::Receiver<Option<u16>>) {
    let mut synced_once = false;
    loop {
        let port = *port_rx.borrow_and_update();
        if let Some(port) = port {
            match qbittorrent::ensure_port(&cfg, port).await {
                Ok(changed) => {
                    if changed {
                        info!("qBittorrent: listen port set to {port}");
                    } else if !synced_once {
                        info!("qBittorrent: listen port already {port}");
                    }
                    synced_once = true;
                }
                Err(e) if !synced_once => info!("qBittorrent not reachable yet ({e:#}), retrying in 20s"),
                Err(e) => warn!("qBittorrent: {e:#}"),
            }
        }
        // Retry quickly until the first sync, then check every 5 minutes.
        let wait = if synced_once { Duration::from_secs(300) } else { Duration::from_secs(20) };
        tokio::select! {
            _ = sleep(wait) => {}
            changed = port_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                synced_once = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("2026-12-12T21:52:07.43279261Z"), Some(1_797_112_327));
        assert_eq!(parse_rfc3339("2000-02-29T12:00:00Z"), Some(951_825_600));
        assert_eq!(parse_rfc3339("2026-11-02T10:00:00+02:00"), Some(1_793_606_400));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("garbage"), None);
    }

    #[test]
    fn gateway_derivation() {
        let addrs = vec!["10.14.212.175/32".parse().unwrap()];
        let ep: IpAddr = "195.78.54.71".parse().unwrap();
        assert_eq!(gateways(&addrs, ep, None), vec!["10.14.128.1".parse::<IpAddr>().unwrap(), ep]);
        let forced: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(gateways(&addrs, ep, Some(forced)), vec![forced]);
    }

    #[test]
    fn pia_ca_is_valid() {
        tls::single_ca_config(PIA_CA).unwrap();
    }
}
