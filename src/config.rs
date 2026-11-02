//! Configuration from environment variables.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
use tracing::info;
use wireguard_control::Key;

use crate::wgconf;

const WG_CONF_PATHS: [&str; 2] = ["/ferrotun/wg0.conf", "/run/secrets/wg0.conf"];

#[derive(Clone)]
pub struct Config {
    pub vpn_interface: String,
    pub wireguard: WireguardConfig,
    pub firewall: FirewallConfig,
    pub dns: DnsConfig,
    pub health: HealthConfig,
    pub control: ControlConfig,
    pub public_ip: PublicIpConfig,
    pub port_forward: Option<PortForwardConfig>,
    /// (PUID, PGID) owner of the files we write.
    pub file_owner: Option<(u32, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WgImplementation {
    Auto,
    Kernel,
    Userspace,
}

#[derive(Clone)]
pub struct WireguardConfig {
    pub private_key: Key,
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    pub addresses: Vec<IpNet>,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub allowed_ips: Vec<IpNet>,
    pub keepalive: Option<u16>,
    pub mtu: Option<u32>,
    pub implementation: WgImplementation,
}

#[derive(Clone, Debug)]
pub struct FirewallConfig {
    pub enabled: bool,
    pub outbound_subnets: Vec<IpNet>,
    pub input_ports: Vec<u16>,
    pub vpn_input_ports: Vec<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamKind {
    Plain,
    Dot,
    Doh,
}

#[derive(Clone, Debug)]
pub struct UpstreamServer {
    pub addr: SocketAddr,
    pub tls_name: String,
    pub doh_url: String,
}

#[derive(Clone, Debug)]
pub struct DnsConfig {
    pub enabled: bool,
    pub kind: UpstreamKind,
    pub servers: Vec<UpstreamServer>,
    pub caching: bool,
    pub listen: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct HealthConfig {
    pub server_addr: SocketAddr,
    pub targets: Vec<String>,
    pub interval: Duration,
    pub restart_vpn: bool,
    pub failures_before_restart: u32,
}

#[derive(Clone)]
pub struct ControlConfig {
    pub addr: Option<SocketAddr>,
    pub api_key: Option<String>,
    pub log: bool,
}

#[derive(Clone, Debug)]
pub struct PublicIpConfig {
    pub enabled: bool,
    pub file: Option<PathBuf>,
}

#[derive(Clone)]
pub struct PortForwardConfig {
    pub username: String,
    pub password: String,
    /// PIA server TLS name, e.g. amsterdam425.
    pub server_name: String,
    pub gateway: Option<IpAddr>,
    pub data_file: PathBuf,
    pub status_file: Option<PathBuf>,
    pub up_command: Option<String>,
    pub down_command: Option<String>,
    pub listening_port: Option<u16>,
    pub qbittorrent: Option<QbitConfig>,
    /// Test only (PIA_API_CA_FILE): CA trusted instead of PIA's.
    pub ca_override: Option<Vec<u8>>,
    /// Test only (PIA_TOKEN_URL).
    pub token_url: String,
}

#[derive(Clone)]
pub struct QbitConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let vpn_interface = env("VPN_INTERFACE").unwrap_or_else(|| "wg0".into());
        if vpn_interface.len() > 15 {
            bail!("VPN_INTERFACE is too long (15 characters max)");
        }

        let wireguard = wireguard_from_env()?;
        let port_forward = port_forward_from_env()?;

        let file_owner = match (env_parse::<u32>("PUID")?, env_parse::<u32>("PGID")?) {
            (Some(u), Some(g)) => Some((u, g)),
            (Some(u), None) => Some((u, u)),
            _ => None,
        };

        Ok(Self {
            vpn_interface,
            wireguard,
            firewall: firewall_from_env()?,
            dns: dns_from_env()?,
            health: health_from_env()?,
            control: control_from_env()?,
            public_ip: PublicIpConfig {
                enabled: env_bool("PUBLICIP_ENABLED", true)?,
                file: env_path_or_off("PUBLICIP_FILE", "/tmp/ferrotun/ip"),
            },
            port_forward,
            file_owner,
        })
    }
}

fn wireguard_from_env() -> Result<WireguardConfig> {
    let conf = load_wg_conf()?;

    let private_key = secret("WIREGUARD_PRIVATE_KEY")?
        .or(conf.private_key)
        .ok_or_else(|| anyhow!("missing WireGuard private key (WIREGUARD_PRIVATE_KEY or wg0.conf)"))?;
    let public_key = env("WIREGUARD_PUBLIC_KEY")
        .or(conf.peer_public_key)
        .ok_or_else(|| anyhow!("missing server public key (WIREGUARD_PUBLIC_KEY or wg0.conf)"))?;
    let preshared_key = secret("WIREGUARD_PRESHARED_KEY")?.or(conf.peer_preshared_key);

    let addresses_raw = match secret("WIREGUARD_ADDRESSES")? {
        Some(v) => split_list(&v),
        None => conf.addresses,
    };
    if addresses_raw.is_empty() {
        bail!("missing WireGuard address (WIREGUARD_ADDRESSES or Address in wg0.conf)");
    }
    let addresses =
        addresses_raw.iter().map(|a| parse_net(a)).collect::<Result<Vec<_>>>().context("invalid WireGuard address")?;

    let (conf_host, conf_port) = match &conf.peer_endpoint {
        Some(ep) => {
            let (h, p) = split_host_port(ep).with_context(|| format!("invalid Endpoint: {ep}"))?;
            (Some(h), Some(p))
        }
        None => (None, None),
    };
    let endpoint_host = env("WIREGUARD_ENDPOINT_IP")
        .or(conf_host)
        .ok_or_else(|| anyhow!("missing WireGuard endpoint (WIREGUARD_ENDPOINT_IP or Endpoint in wg0.conf)"))?;
    let endpoint_port = match env_parse::<u16>("WIREGUARD_ENDPOINT_PORT")? {
        Some(p) => p,
        None => conf_port.ok_or_else(|| anyhow!("missing WireGuard endpoint port"))?,
    };

    let allowed_raw = match env("WIREGUARD_ALLOWED_IPS") {
        Some(v) => split_list(&v),
        None => conf.peer_allowed_ips,
    };
    let mut allowed_ips =
        allowed_raw.iter().map(|a| parse_net(a)).collect::<Result<Vec<_>>>().context("invalid AllowedIPs")?;
    if allowed_ips.is_empty() {
        allowed_ips.push("0.0.0.0/0".parse().unwrap());
        if addresses.iter().any(|a| a.addr().is_ipv6()) {
            allowed_ips.push("::/0".parse().unwrap());
        }
    }

    let keepalive = match env("WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL") {
        Some(v) => {
            let d = parse_duration(&v).context("invalid WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL")?;
            (d.as_secs() > 0).then(|| d.as_secs().min(u16::MAX as u64) as u16)
        }
        None => conf.peer_keepalive.filter(|k| *k > 0),
    };

    let mtu = match env_parse::<u32>("WIREGUARD_MTU")? {
        Some(m) => Some(m),
        None => conf.mtu,
    };
    if let Some(m) = mtu
        && !(576..=9000).contains(&m)
    {
        bail!("WIREGUARD_MTU={m} is out of range (576-9000)");
    }

    let implementation = match env("WIREGUARD_IMPLEMENTATION").map(|s| s.to_ascii_lowercase()).as_deref() {
        None | Some("auto") => WgImplementation::Auto,
        Some("kernel") => WgImplementation::Kernel,
        Some("userspace") => WgImplementation::Userspace,
        Some(other) => bail!("invalid WIREGUARD_IMPLEMENTATION={other} (auto, kernel, userspace)"),
    };

    let key = |raw: &str, what: &str| Key::from_base64(raw.trim()).map_err(|_| anyhow!("invalid WireGuard {what}"));
    Ok(WireguardConfig {
        private_key: key(&private_key, "private key")?,
        public_key: key(&public_key, "public key")?,
        preshared_key: preshared_key.map(|k| key(&k, "preshared key")).transpose()?,
        addresses,
        endpoint_host,
        endpoint_port,
        allowed_ips,
        keepalive,
        mtu,
        implementation,
    })
}

fn load_wg_conf() -> Result<wgconf::WgQuickConf> {
    let path = match env("WIREGUARD_CONF_FILE") {
        Some(p) => PathBuf::from(p),
        None => match WG_CONF_PATHS.into_iter().map(PathBuf::from).find(|p| p.is_file()) {
            Some(p) => p,
            None => return Ok(wgconf::WgQuickConf::default()),
        },
    };
    let content = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    info!("reading WireGuard configuration from {}", path.display());
    wgconf::parse(&content).with_context(|| format!("parsing {}", path.display()))
}

fn firewall_from_env() -> Result<FirewallConfig> {
    let enabled = env_bool("FIREWALL_ENABLED", true)?;
    let outbound_subnets = env_list("FIREWALL_OUTBOUND_SUBNETS")
        .iter()
        .map(|s| parse_net(s).map(|n| n.trunc()))
        .collect::<Result<Vec<_>>>()
        .context("invalid FIREWALL_OUTBOUND_SUBNETS")?;
    Ok(FirewallConfig {
        enabled,
        outbound_subnets,
        input_ports: parse_ports("FIREWALL_INPUT_PORTS")?,
        vpn_input_ports: parse_ports("FIREWALL_VPN_INPUT_PORTS")?,
    })
}

fn parse_ports(key: &str) -> Result<Vec<u16>> {
    env_list(key)
        .iter()
        .map(|p| p.parse::<u16>().with_context(|| format!("{key}: invalid port '{p}'")))
        .filter(|p| !matches!(p, Ok(0)))
        .collect()
}

fn dns_from_env() -> Result<DnsConfig> {
    let enabled = env_bool("DNS_SERVER", true)?;

    let kind = match env("DNS_UPSTREAM_RESOLVER_TYPE").map(|s| s.to_ascii_lowercase()).as_deref() {
        None | Some("dot") => UpstreamKind::Dot,
        Some("doh") => UpstreamKind::Doh,
        Some("plain") => UpstreamKind::Plain,
        Some(other) => bail!("invalid DNS_UPSTREAM_RESOLVER_TYPE={other} (dot, doh, plain)"),
    };

    let plain_addrs = env_list("DNS_UPSTREAM_PLAIN_ADDRESSES");

    let servers = if kind == UpstreamKind::Plain && !plain_addrs.is_empty() {
        plain_addrs
            .iter()
            .map(|a| {
                let addr = match a.parse::<SocketAddr>() {
                    Ok(sa) => sa,
                    Err(_) => {
                        SocketAddr::new(a.parse::<IpAddr>().with_context(|| format!("invalid DNS address '{a}'"))?, 53)
                    }
                };
                Ok(UpstreamServer { addr, tls_name: String::new(), doh_url: String::new() })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let mut providers = env_list("DNS_UPSTREAM_RESOLVERS");
        if providers.is_empty() {
            providers.push("cloudflare".into());
        }
        let mut servers = vec![];
        for p in providers {
            servers.extend(provider_servers(&p, kind)?);
        }
        servers
    };

    Ok(DnsConfig {
        enabled,
        kind,
        servers,
        caching: env_bool("DNS_CACHING", true)?,
        listen: "127.0.0.1:53".parse().unwrap(),
    })
}

fn provider_servers(name: &str, kind: UpstreamKind) -> Result<Vec<UpstreamServer>> {
    let (ips, tls_name, doh_url): (&[&str], &str, &str) = match name.to_ascii_lowercase().as_str() {
        "cloudflare" => (&["1.1.1.1", "1.0.0.1"], "cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
        "google" => (&["8.8.8.8", "8.8.4.4"], "dns.google", "https://dns.google/dns-query"),
        "quad9" => (&["9.9.9.9", "149.112.112.112"], "dns.quad9.net", "https://dns.quad9.net/dns-query"),
        "mullvad" => (&["194.242.2.2"], "dns.mullvad.net", "https://dns.mullvad.net/dns-query"),
        other => bail!("DNS_UPSTREAM_RESOLVERS: unknown provider '{other}' (cloudflare, google, quad9, mullvad)"),
    };
    let port = match kind {
        UpstreamKind::Plain => 53,
        UpstreamKind::Dot => 853,
        UpstreamKind::Doh => 443,
    };
    Ok(ips
        .iter()
        .map(|ip| UpstreamServer {
            addr: SocketAddr::new(ip.parse().unwrap(), port),
            tls_name: tls_name.into(),
            doh_url: doh_url.into(),
        })
        .collect())
}

fn health_from_env() -> Result<HealthConfig> {
    let server_addr = parse_listen_addr(&env("HEALTH_SERVER_ADDRESS").unwrap_or_else(|| "127.0.0.1:9999".into()))
        .context("invalid HEALTH_SERVER_ADDRESS")?;
    let mut targets = env_list("HEALTH_TARGET_ADDRESSES");
    if targets.is_empty() {
        targets = vec!["cloudflare.com:443".into(), "github.com:443".into()];
    }
    for t in &targets {
        split_host_port(t)
            .with_context(|| format!("HEALTH_TARGET_ADDRESSES: invalid target '{t}' (expected host:port)"))?;
    }
    let interval = match env("HEALTH_CHECK_INTERVAL") {
        Some(v) => parse_duration(&v).context("invalid HEALTH_CHECK_INTERVAL")?,
        None => Duration::from_secs(30),
    };
    Ok(HealthConfig {
        server_addr,
        targets,
        interval: interval.max(Duration::from_secs(5)),
        restart_vpn: env_bool("HEALTH_RESTART_VPN", true)?,
        failures_before_restart: env_parse::<u32>("HEALTH_FAILURES_BEFORE_RESTART")?.unwrap_or(3).max(1),
    })
}

fn control_from_env() -> Result<ControlConfig> {
    let raw = env("HTTP_CONTROL_SERVER_ADDRESS").unwrap_or_else(|| ":8000".into());
    let addr = if raw.eq_ignore_ascii_case("off") {
        None
    } else {
        Some(parse_listen_addr(&raw).context("invalid HTTP_CONTROL_SERVER_ADDRESS")?)
    };
    Ok(ControlConfig {
        addr,
        api_key: secret("HTTP_CONTROL_SERVER_API_KEY")?,
        log: env_bool("HTTP_CONTROL_SERVER_LOG", true)?,
    })
}

fn port_forward_from_env() -> Result<Option<PortForwardConfig>> {
    if !env_bool("VPN_PORT_FORWARDING", false)? {
        return Ok(None);
    }
    let provider = env("VPN_PORT_FORWARDING_PROVIDER").unwrap_or_else(|| "private internet access".into());
    if !matches!(provider.to_ascii_lowercase().as_str(), "private internet access" | "pia") {
        bail!("VPN_PORT_FORWARDING_PROVIDER={provider} is not supported (only 'private internet access')");
    }
    let username = secret("VPN_PORT_FORWARDING_USERNAME")?
        .ok_or_else(|| anyhow!("VPN_PORT_FORWARDING_USERNAME is required for PIA port forwarding"))?;
    let password = secret("VPN_PORT_FORWARDING_PASSWORD")?
        .ok_or_else(|| anyhow!("VPN_PORT_FORWARDING_PASSWORD is required for PIA port forwarding"))?;
    let server_name = env("VPN_PORT_FORWARDING_SERVER_NAME").ok_or_else(|| {
        anyhow!(
            "VPN_PORT_FORWARDING_SERVER_NAME is required for PIA port forwarding (server TLS name, e.g. amsterdam425)"
        )
    })?;
    let gateway = env("VPN_PORT_FORWARDING_GATEWAY")
        .map(|g| g.parse::<IpAddr>().context("invalid VPN_PORT_FORWARDING_GATEWAY"))
        .transpose()?;

    let qbittorrent = env("QBITTORRENT_URL")
        .map(|url| -> Result<QbitConfig> {
            Ok(QbitConfig {
                url: url.trim_end_matches('/').to_string(),
                username: env("QBITTORRENT_USERNAME"),
                password: secret("QBITTORRENT_PASSWORD")?,
            })
        })
        .transpose()?;

    Ok(Some(PortForwardConfig {
        username: username.trim().to_string(),
        password: password.trim().to_string(),
        server_name,
        gateway,
        data_file: PathBuf::from(
            env("VPN_PORT_FORWARDING_DATA_FILE").unwrap_or_else(|| "/ferrotun/portforward.json".into()),
        ),
        status_file: env_path_or_off("VPN_PORT_FORWARDING_STATUS_FILE", "/tmp/ferrotun/forwarded_port"),
        up_command: env("VPN_PORT_FORWARDING_UP_COMMAND"),
        down_command: env("VPN_PORT_FORWARDING_DOWN_COMMAND"),
        listening_port: env_parse::<u16>("VPN_PORT_FORWARDING_LISTENING_PORT")?.filter(|p| *p != 0),
        qbittorrent,
        ca_override: env("PIA_API_CA_FILE")
            .map(|p| std::fs::read(&p).with_context(|| format!("reading PIA_API_CA_FILE={p}")))
            .transpose()?,
        token_url: env("PIA_TOKEN_URL")
            .unwrap_or_else(|| "https://www.privateinternetaccess.com/api/client/v2/token".into()),
    }))
}

/// Non-empty environment variable.
pub fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// `KEY`, or the content of the file named by `KEY_FILE` (Docker secrets).
fn secret(key: &str) -> Result<Option<String>> {
    if let Some(v) = env(key) {
        return Ok(Some(v));
    }
    let file_key = format!("{key}_FILE");
    let Some(path) = env(&file_key) else { return Ok(None) };
    let content = std::fs::read_to_string(&path).with_context(|| format!("reading {file_key}={path}"))?;
    Ok(Some(content.trim().to_string()).filter(|s| !s.is_empty()))
}

fn env_list(key: &str) -> Vec<String> {
    env(key).map(|v| split_list(&v)).unwrap_or_default()
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

fn env_parse<T: std::str::FromStr>(key: &str) -> Result<Option<T>> {
    match env(key) {
        None => Ok(None),
        Some(v) => v.parse::<T>().map(Some).map_err(|_| anyhow!("{key}={v}: invalid value")),
    }
}

pub fn parse_bool(v: &str) -> Result<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "on" | "yes" | "true" | "1" | "enabled" => Ok(true),
        "off" | "no" | "false" | "0" | "disabled" => Ok(false),
        other => bail!("invalid boolean '{other}' (on/off)"),
    }
}

fn env_bool(key: &str, default: bool) -> Result<bool> {
    match env(key) {
        None => Ok(default),
        Some(v) => parse_bool(&v).with_context(|| format!("variable {key}")),
    }
}

/// A file path that can be disabled with "off".
fn env_path_or_off(key: &str, default: &str) -> Option<PathBuf> {
    match env(key) {
        Some(v) if v.eq_ignore_ascii_case("off") => None,
        Some(v) => Some(PathBuf::from(v)),
        None => Some(PathBuf::from(default)),
    }
}

/// "10.0.0.1/24", or "10.0.0.1" as a host route.
pub fn parse_net(s: &str) -> Result<IpNet> {
    let s = s.trim();
    if let Ok(n) = s.parse::<IpNet>() {
        return Ok(n);
    }
    let ip = s.parse::<IpAddr>().with_context(|| format!("invalid address '{s}'"))?;
    Ok(IpNet::from(ip))
}

/// "host:port", "1.2.3.4:51820" or "[::1]:51820".
pub fn split_host_port(s: &str) -> Result<(String, u16)> {
    let (host, port) = s.trim().rsplit_once(':').ok_or_else(|| anyhow!("missing port"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        bail!("missing host");
    }
    let port = port.parse::<u16>().map_err(|_| anyhow!("invalid port '{port}'"))?;
    Ok((host.to_string(), port))
}

/// ":8000" means 0.0.0.0:8000.
pub fn parse_listen_addr(s: &str) -> Result<SocketAddr> {
    let s = s.trim();
    if let Some(port) = s.strip_prefix(':') {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port.parse::<u16>()?)));
    }
    Ok(s.parse::<SocketAddr>()?)
}

/// "25", "25s", "500ms", "2m", "1h".
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| anyhow!("invalid duration '{s}'"))?;
    Ok(match unit {
        "" | "s" => Duration::from_secs(n),
        "ms" => Duration::from_millis(n),
        "m" => Duration::from_secs(n * 60),
        "h" => Duration::from_secs(n * 3600),
        _ => bail!("invalid duration unit '{unit}'"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("25").unwrap(), Duration::from_secs(25));
        assert_eq!(parse_duration("25s").unwrap(), Duration::from_secs(25));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn host_port() {
        assert_eq!(split_host_port("195.78.54.71:1337").unwrap(), ("195.78.54.71".into(), 1337));
        assert_eq!(split_host_port("[2001:db8::1]:51820").unwrap(), ("2001:db8::1".into(), 51820));
        assert_eq!(split_host_port("vpn.example.com:51820").unwrap(), ("vpn.example.com".into(), 51820));
        assert!(split_host_port("1.2.3.4").is_err());
    }

    #[test]
    fn listen_addr() {
        assert_eq!(parse_listen_addr(":8000").unwrap(), "0.0.0.0:8000".parse().unwrap());
        assert_eq!(parse_listen_addr("127.0.0.1:9999").unwrap(), "127.0.0.1:9999".parse().unwrap());
    }

    #[test]
    fn nets() {
        assert_eq!(parse_net("10.14.212.175/32").unwrap().to_string(), "10.14.212.175/32");
        assert_eq!(parse_net("10.0.0.2").unwrap().to_string(), "10.0.0.2/32");
        assert_eq!(parse_net("172.16.0.0/12").unwrap().to_string(), "172.16.0.0/12");
    }
}
