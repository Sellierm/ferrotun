//! nftables kill-switch, applied atomically to our own `inet ferrotun` table.
//!
//! The output chain has no generic "established,related accept": a connection opened through the
//! tunnel can never leak through eth0 when the tunnel drops. Only connections that came in on eth0
//! (published ports, other containers) get a conntrack mark allowing replies.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex};
use tracing::{debug, info, warn};

use crate::routing::FWMARK;

pub const TABLE: &str = "ferrotun";
const CT_INBOUND: u32 = 0x1;

#[derive(Clone, Debug)]
pub struct FirewallBase {
    pub enabled: bool,
    pub default_if: String,
    pub vpn_if: String,
    pub local_subnets: Vec<IpNet>,
    pub outbound_subnets: Vec<IpNet>,
    pub input_ports: Vec<u16>,
    pub vpn_input_ports: Vec<u16>,
}

#[derive(Clone, Debug, Default)]
struct FirewallState {
    endpoint: Option<SocketAddr>,
    forwarded_ports: Vec<u16>,
    /// (forwarded, local) for VPN_PORT_FORWARDING_LISTENING_PORT.
    redirect: Option<(u16, u16)>,
}

#[derive(Clone)]
pub struct Firewall {
    base: Arc<FirewallBase>,
    state: Arc<Mutex<FirewallState>>,
}

impl Firewall {
    pub fn new(base: FirewallBase) -> Self {
        Self { base: Arc::new(base), state: Arc::new(Mutex::new(FirewallState::default())) }
    }

    pub async fn init(&self) -> Result<()> {
        if !self.base.enabled {
            warn!("FIREWALL DISABLED: nothing prevents traffic from leaking outside the tunnel");
            return Ok(());
        }
        let st = self.state.lock().await;
        apply(&render(&self.base, &st)).await?;
        info!("firewall enabled (default policy: drop)");
        Ok(())
    }

    pub async fn set_endpoint(&self, endpoint: SocketAddr) -> Result<()> {
        let mut st = self.state.lock().await;
        if st.endpoint == Some(endpoint) {
            return Ok(());
        }
        st.endpoint = Some(endpoint);
        if self.base.enabled {
            apply(&render(&self.base, &st)).await?;
            info!("firewall: allowing VPN traffic to {endpoint}/udp via {}", self.base.default_if);
        }
        Ok(())
    }

    pub async fn set_forwarded_ports(&self, ports: Vec<u16>, listening_port: Option<u16>) -> Result<()> {
        let mut st = self.state.lock().await;
        st.redirect = match (ports.first(), listening_port) {
            (Some(&fwd), Some(listen)) if fwd != listen => Some((fwd, listen)),
            _ => None,
        };
        st.forwarded_ports = ports;
        if self.base.enabled {
            apply(&render(&self.base, &st)).await?;
            if st.forwarded_ports.is_empty() {
                info!("firewall: forwarded ports cleared");
            } else {
                info!("firewall: allowing inbound ports on {}: {:?}", self.base.vpn_if, st.forwarded_ports);
            }
        }
        Ok(())
    }
}

fn set_of<T: ToString>(items: &[T]) -> String {
    let v: Vec<String> = items.iter().map(T::to_string).collect();
    if v.len() == 1 { v[0].clone() } else { format!("{{ {} }}", v.join(", ")) }
}

fn render(base: &FirewallBase, st: &FirewallState) -> String {
    let eth = &base.default_if;
    let vpn = &base.vpn_if;
    let mut r = String::new();
    let mut line = |s: String| {
        r.push_str(&s);
        r.push('\n');
    };

    // Create, delete and redefine in one transaction: idempotent and atomic.
    line(format!("table inet {TABLE} {{}}"));
    line(format!("delete table inet {TABLE}"));
    line(format!("table inet {TABLE} {{"));

    line("  chain input {".into());
    line("    type filter hook input priority filter; policy drop;".into());
    line("    iif \"lo\" accept".into());
    line("    ct state established,related accept".into());
    line("    ct state invalid drop".into());
    for net in &base.local_subnets {
        let fam = if net.addr().is_ipv4() { "ip" } else { "ip6" };
        line(format!("    iifname \"{eth}\" {fam} daddr {} ct mark set {CT_INBOUND:#x} accept", net.trunc()));
    }
    line(format!(
        "    iifname \"{eth}\" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept"
    ));
    if !base.input_ports.is_empty() {
        let ports = set_of(&base.input_ports);
        line(format!("    iifname \"{eth}\" tcp dport {ports} ct mark set {CT_INBOUND:#x} accept"));
        line(format!("    iifname \"{eth}\" udp dport {ports} ct mark set {CT_INBOUND:#x} accept"));
    }
    let mut vpn_ports: Vec<u16> = base.vpn_input_ports.clone();
    vpn_ports.extend(&st.forwarded_ports);
    if let Some((_, listen)) = st.redirect {
        vpn_ports.push(listen);
    }
    vpn_ports.sort_unstable();
    vpn_ports.dedup();
    if !vpn_ports.is_empty() {
        let ports = set_of(&vpn_ports);
        line(format!("    iifname \"{vpn}\" tcp dport {ports} accept"));
        line(format!("    iifname \"{vpn}\" udp dport {ports} accept"));
    }
    line("  }".into());

    line("  chain forward {".into());
    line("    type filter hook forward priority filter; policy drop;".into());
    line("  }".into());

    line("  chain output {".into());
    line("    type filter hook output priority filter; policy drop;".into());
    line("    oif \"lo\" accept".into());
    line(format!("    oifname \"{vpn}\" accept"));
    line(format!("    oifname \"{eth}\" ct mark {CT_INBOUND:#x} accept"));
    if let Some(ep) = st.endpoint {
        let fam = if ep.is_ipv4() { "ip" } else { "ip6" };
        line(format!(
            "    oifname \"{eth}\" meta mark {FWMARK:#x} {fam} daddr {} udp dport {} accept",
            ep.ip(),
            ep.port()
        ));
    }
    for net in base.local_subnets.iter().chain(base.outbound_subnets.iter()) {
        let fam = if net.addr().is_ipv4() { "ip" } else { "ip6" };
        line(format!("    oifname \"{eth}\" {fam} daddr {} accept", net.trunc()));
    }
    line(format!(
        "    oifname \"{eth}\" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }} accept"
    ));
    line("  }".into());

    line("  chain mss_clamp {".into());
    line("    type filter hook postrouting priority mangle; policy accept;".into());
    line(format!("    oifname \"{vpn}\" tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu"));
    line("  }".into());

    if let Some((fwd, listen)) = st.redirect {
        line("  chain pf_redirect {".into());
        line("    type nat hook prerouting priority dstnat; policy accept;".into());
        line(format!("    iifname \"{vpn}\" tcp dport {fwd} redirect to :{listen}"));
        line(format!("    iifname \"{vpn}\" udp dport {fwd} redirect to :{listen}"));
        line("  }".into());
    }

    line("}".into());
    r
}

async fn apply(ruleset: &str) -> Result<()> {
    debug!("nftables ruleset:\n{ruleset}");
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("running 'nft' (is nftables installed?)")?;
    child.stdin.take().unwrap().write_all(ruleset.as_bytes()).await?;
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!("nft failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> FirewallBase {
        FirewallBase {
            enabled: true,
            default_if: "eth0".into(),
            vpn_if: "wg0".into(),
            local_subnets: vec!["172.19.0.10/16".parse().unwrap()],
            outbound_subnets: vec!["192.168.0.0/16".parse().unwrap()],
            input_ports: vec![],
            vpn_input_ports: vec![],
        }
    }

    #[test]
    fn initial_ruleset_has_no_endpoint() {
        let r = render(&base(), &FirewallState::default());
        assert!(r.contains("policy drop"));
        assert!(r.contains("iifname \"eth0\" ip daddr 172.19.0.0/16 ct mark set 0x1 accept"));
        assert!(r.contains("oifname \"eth0\" ip daddr 192.168.0.0/16 accept"));
        assert!(!r.contains("udp dport 1337"));
        assert!(!r.contains("pf_redirect"));
        let output = r.split("chain output").nth(1).unwrap().split("chain mss_clamp").next().unwrap();
        assert!(!output.contains("established"));
    }

    #[test]
    fn endpoint_and_forwarded_port() {
        let st = FirewallState {
            endpoint: Some("195.78.54.71:1337".parse().unwrap()),
            forwarded_ports: vec![53117],
            redirect: Some((53117, 6881)),
        };
        let r = render(&base(), &st);
        assert!(r.contains("oifname \"eth0\" meta mark 0xca6c ip daddr 195.78.54.71 udp dport 1337 accept"));
        assert!(r.contains("iifname \"wg0\" tcp dport { 6881, 53117 } accept"));
        assert!(r.contains("iifname \"wg0\" tcp dport 53117 redirect to :6881"));
    }
}
