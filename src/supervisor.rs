//! Startup sequence and the connection state machine.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::{RwLock, mpsc},
    task::JoinHandle,
    time::{Instant, sleep, sleep_until},
};
use tracing::{error, info, warn};

use crate::{
    config::{Config, UpstreamKind, WireguardConfig},
    control, dns,
    firewall::{Firewall, FirewallBase},
    health,
    netlink::Net,
    portforward::{self, PfContext, PortForwarder},
    publicip, routing,
    state::{Command, Shared, Status, VpnState, write_file},
    tls,
    wireguard::{self, Impl},
};

const RESOLV_CONF: &str = "/etc/resolv.conf";
const DOCKER_DNS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 11);
/// Checks (3s apart) allowed for a new tunnel to become usable.
const FIRST_CHECK_ATTEMPTS: u32 = 10;

type CheckFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

pub async fn run(cfg: Config) -> Result<()> {
    let cfg = Arc::new(cfg);
    let net = Net::new()?;

    let default = net.default_route_v4().await.context("detecting the container network")?;
    let ipv6 = net.ipv6_enabled().await;
    let local_subnets = net.interface_subnets(default.if_index).await?;
    info!(
        "network: {} {} (gateway {}, MTU {}), IPv6 {}",
        default.if_name,
        default.subnet,
        default.gateway,
        default.mtu,
        if ipv6 { "enabled" } else { "disabled" }
    );

    // Kill-switch before anything else.
    let firewall = Firewall::new(FirewallBase {
        enabled: cfg.firewall.enabled,
        default_if: default.if_name.clone(),
        vpn_if: cfg.vpn_interface.clone(),
        local_subnets,
        outbound_subnets: cfg.firewall.outbound_subnets.clone(),
        input_ports: cfg.firewall.input_ports.clone(),
        vpn_input_ports: cfg.firewall.vpn_input_ports.clone(),
    });
    firewall.init().await?;

    routing::setup_base(&net, &default, &cfg.firewall.outbound_subnets, ipv6).await?;

    // A hostname endpoint is resolved through Docker's DNS, before resolv.conf is rewritten.
    let resolv_path = Path::new(RESOLV_CONF);
    let resolv = dns::read_resolv_conf(resolv_path);
    let endpoint = resolve_endpoint(&cfg.wireguard).await?;
    firewall.set_endpoint(endpoint).await?;

    if cfg.dns.enabled {
        let docker_dns =
            resolv.original_nameservers.contains(&IpAddr::V4(DOCKER_DNS)).then(|| SocketAddr::from((DOCKER_DNS, 53)));
        let resolver = Arc::new(dns::Resolver::new(&cfg.dns, docker_dns)?);
        let (udp, tcp) = dns::bind(cfg.dns.listen).await?;
        tokio::spawn(dns::serve(resolver, udp, tcp));
        dns::write_resolv_conf(resolv_path, &[cfg.dns.listen.ip()], &resolv)?;
        let kind = match cfg.dns.kind {
            UpstreamKind::Plain => "plain DNS",
            UpstreamKind::Dot => "DNS-over-TLS",
            UpstreamKind::Doh => "DNS-over-HTTPS",
        };
        let servers: Vec<String> = cfg.dns.servers.iter().map(|s| s.addr.to_string()).collect();
        info!(
            "DNS: {kind} via {} (through the tunnel), cache {}, local names -> {}",
            servers.join(", "),
            if cfg.dns.caching { "on" } else { "off" },
            docker_dns.map(|d| d.to_string()).unwrap_or_else(|| "none".into())
        );
    } else {
        let ips: Vec<IpAddr> = cfg.dns.servers.iter().map(|s| s.addr.ip()).collect();
        dns::write_resolv_conf(resolv_path, &ips, &resolv)?;
        warn!("local DNS server disabled: resolv.conf points directly to {ips:?}");
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let shared = Shared {
        status: Arc::new(RwLock::new(Status { endpoint: Some(endpoint), ..Default::default() })),
        commands: cmd_tx,
        vpn_interface: cfg.vpn_interface.clone(),
    };
    {
        let (addr, s) = (cfg.health.server_addr, shared.clone());
        tokio::spawn(async move {
            if let Err(e) = health::serve(addr, s).await {
                error!("health server: {e:#}");
            }
        });
    }
    if let Some(addr) = cfg.control.addr {
        let (s, key, log) = (shared.clone(), cfg.control.api_key.clone(), cfg.control.log);
        if key.is_none() {
            warn!("control API has no authentication (set HTTP_CONTROL_SERVER_API_KEY)");
        }
        tokio::spawn(async move {
            if let Err(e) = control::serve(addr, s, key, log).await {
                error!("control API: {e:#}");
            }
        });
    }

    let pf = match &cfg.port_forward {
        Some(pfc) => {
            let gws = portforward::gateways(&cfg.wireguard.addresses, endpoint.ip(), pfc.gateway);
            Some(Arc::new(PortForwarder::new(pfc.clone(), gws)?))
        }
        None => None,
    };

    // Docker interface MTU minus WireGuard overhead (80 bytes, like wg-quick).
    let mtu = cfg.wireguard.mtu.unwrap_or_else(|| default.mtu.saturating_sub(80).max(1280));

    let sup = Supervisor {
        web: tls::web_client(Duration::from_secs(15))?,
        cfg,
        net,
        firewall,
        shared,
        endpoint,
        mtu,
        ipv6,
        pf,
        imp: None,
        session: vec![],
        connected: false,
        failures: 0,
    };
    sup.run(cmd_rx).await
}

async fn resolve_endpoint(wg: &WireguardConfig) -> Result<SocketAddr> {
    if let Ok(ip) = wg.endpoint_host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, wg.endpoint_port));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((wg.endpoint_host.as_str(), wg.endpoint_port))
        .await
        .with_context(|| format!("resolving endpoint {}", wg.endpoint_host))?
        .collect();
    let ep = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| anyhow!("endpoint {} resolves to no address", wg.endpoint_host))?;
    info!("endpoint {} resolved to {}", wg.endpoint_host, ep.ip());
    Ok(ep)
}

struct Supervisor {
    cfg: Arc<Config>,
    net: Net,
    firewall: Firewall,
    shared: Shared,
    endpoint: SocketAddr,
    mtu: u32,
    ipv6: bool,
    web: reqwest::Client,
    pf: Option<Arc<PortForwarder>>,
    /// Some while the interface is up.
    imp: Option<Impl>,
    /// Per-connection tasks (public IP, port forwarding).
    session: Vec<JoinHandle<()>>,
    /// At least one health check passed since the tunnel came up.
    connected: bool,
    failures: u32,
}

impl Supervisor {
    async fn run(mut self, mut cmd_rx: mpsc::Receiver<Command>) -> Result<()> {
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut desired = true;
        let mut backoff = Duration::from_secs(2);
        let mut next_check = Instant::now();
        let mut check: Option<CheckFuture> = None;

        loop {
            if desired && self.imp.is_none() {
                self.set_state(VpnState::Connecting).await;
                let wg = &self.cfg.wireguard;
                match wireguard::up(&self.net, wg, &self.cfg.vpn_interface, self.endpoint, self.mtu, self.ipv6).await {
                    Ok(imp) => {
                        self.imp = Some(imp);
                        self.shared.status.write().await.implementation = Some(imp);
                        self.connected = false;
                        self.failures = 0;
                        backoff = Duration::from_secs(2);
                        next_check = Instant::now() + Duration::from_secs(1);
                    }
                    Err(e) => {
                        error!("cannot bring the tunnel up: {e:#} (retrying in {}s)", backoff.as_secs());
                        self.shared.status.write().await.last_error = Some(format!("{e:#}"));
                        tokio::select! {
                            _ = sleep(backoff) => {}
                            Some(cmd) = cmd_rx.recv() => {
                                if let Command::Stop = cmd {
                                    desired = false;
                                    self.set_state(VpnState::Stopped).await;
                                }
                            }
                            _ = sigterm.recv() => break,
                            _ = sigint.recv() => break,
                        }
                        backoff = (backoff * 2).min(Duration::from_secs(60));
                        continue;
                    }
                }
            }

            tokio::select! {
                _ = sleep_until(next_check), if self.imp.is_some() && check.is_none() => {
                    let targets = self.cfg.health.targets.clone();
                    check = Some(Box::pin(async move { health::check(&targets).await }));
                }
                res = async { check.as_mut().unwrap().await }, if check.is_some() => {
                    check = None;
                    next_check = self.on_health(res).await;
                }
                Some(cmd) = cmd_rx.recv() => match cmd {
                    Command::Stop => {
                        desired = false;
                        check = None;
                        self.teardown("stopped via the API").await;
                        self.set_state(VpnState::Stopped).await;
                    }
                    Command::Start => {
                        if !desired {
                            info!("VPN start requested via the API");
                            desired = true;
                        }
                    }
                    Command::Restart => {
                        check = None;
                        self.teardown("restart requested via the API").await;
                        desired = true;
                    }
                },
                _ = sigterm.recv() => break,
                _ = sigint.recv() => break,
            }
        }

        info!("shutdown signal received");
        self.teardown("container stopping").await;
        Ok(())
    }

    async fn set_state(&self, vpn: VpnState) {
        let mut st = self.shared.status.write().await;
        st.vpn = vpn;
        if vpn != VpnState::Connected {
            st.healthy = false;
        }
    }

    /// Returns when the next check is due.
    async fn on_health(&mut self, res: Result<()>) -> Instant {
        let now = Instant::now();
        match res {
            Ok(()) => {
                let was_failing = self.failures > 0;
                self.failures = 0;
                if !self.connected {
                    self.connected = true;
                    self.on_connected().await;
                } else if was_failing {
                    info!("tunnel healthy again");
                    let mut st = self.shared.status.write().await;
                    st.vpn = VpnState::Connected;
                    st.healthy = true;
                    st.last_error = None;
                }
                now + self.cfg.health.interval
            }
            Err(e) => {
                self.failures += 1;
                let msg = format!("{e:#}");
                {
                    let mut st = self.shared.status.write().await;
                    st.healthy = false;
                    st.last_error = Some(msg.clone());
                    if self.connected {
                        st.vpn = VpnState::Unhealthy;
                    }
                }
                let restart = self.cfg.health.restart_vpn;
                if !self.connected {
                    if self.failures >= FIRST_CHECK_ATTEMPTS {
                        warn!("tunnel not working after setup: {msg}");
                        if restart {
                            self.reconnect("tunnel not working").await;
                            return now + Duration::from_secs(2);
                        }
                    }
                    return now + Duration::from_secs(3);
                }
                let max = self.cfg.health.failures_before_restart;
                warn!("health check failed ({}/{max}): {msg}", self.failures);
                if self.failures >= max && restart {
                    self.reconnect("health checks failing").await;
                    return now + Duration::from_secs(2);
                }
                now + Duration::from_secs(5)
            }
        }
    }

    async fn reconnect(&mut self, reason: &str) {
        self.teardown(reason).await;
        self.shared.status.write().await.reconnections += 1;
        info!("reconnecting VPN");
    }

    async fn on_connected(&mut self) {
        let iface = &self.cfg.vpn_interface;
        let handshake = match self.imp {
            Some(imp) => wireguard::stats(iface, imp).await.and_then(|s| s.last_handshake_secs_ago),
            None => None,
        };
        {
            let mut st = self.shared.status.write().await;
            st.vpn = VpnState::Connected;
            st.healthy = true;
            st.last_error = None;
            st.connected_since = Some(SystemTime::now());
        }
        match handshake {
            Some(s) => info!("VPN connected (last handshake {s}s ago)"),
            None => info!("VPN connected"),
        }

        if self.cfg.public_ip.enabled {
            let (web, shared, file, owner) =
                (self.web.clone(), self.shared.clone(), self.cfg.public_ip.file.clone(), self.cfg.file_owner);
            self.session.push(tokio::spawn(async move {
                for attempt in 1..=5u64 {
                    match publicip::fetch(&web).await {
                        Ok(ip) => {
                            info!("public IP: {}", ip.summary());
                            if let Some(path) = &file
                                && let Err(e) = write_file(path, &ip.public_ip, owner)
                            {
                                warn!("public IP: {e:#}");
                            }
                            shared.status.write().await.public_ip = Some(ip);
                            return;
                        }
                        Err(e) => {
                            warn!("public IP unavailable ({attempt}/5): {e:#}");
                            sleep(Duration::from_secs(10 * attempt)).await;
                        }
                    }
                }
            }));
        }

        if let Some(pf) = &self.pf {
            let ctx =
                PfContext { shared: self.shared.clone(), firewall: self.firewall.clone(), owner: self.cfg.file_owner };
            self.session.push(tokio::spawn(portforward::run(pf.clone(), ctx)));
        }
    }

    async fn teardown(&mut self, reason: &str) {
        for task in self.session.drain(..) {
            task.abort();
        }
        let port = self.shared.status.read().await.forwarded_port;
        if let (Some(pfc), Some(port)) = (&self.cfg.port_forward, port) {
            let ctx =
                PfContext { shared: self.shared.clone(), firewall: self.firewall.clone(), owner: self.cfg.file_owner };
            portforward::unpublish(pfc, &ctx, port).await;
        }
        if let Some(imp) = self.imp.take() {
            wireguard::down(&self.net, &self.cfg.vpn_interface, imp).await;
            info!("tunnel closed ({reason})");
        }
        if let Some(path) = &self.cfg.public_ip.file {
            let _ = std::fs::remove_file(path);
        }
        let mut st = self.shared.status.write().await;
        st.healthy = false;
        st.public_ip = None;
        st.connected_since = None;
        st.vpn = VpnState::Connecting;
        self.connected = false;
        self.failures = 0;
    }
}
