//! WireGuard interface: kernel module via netlink, or wireguard-go in userspace.

use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow};
use tracing::{info, warn};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, PeerConfigBuilder};

use crate::{
    config::{WgImplementation, WireguardConfig},
    netlink::Net,
    routing::{self, FWMARK},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Impl {
    Kernel,
    Userspace,
}

impl Impl {
    fn backend(self) -> Backend {
        match self {
            Impl::Kernel => Backend::Kernel,
            Impl::Userspace => Backend::Userspace,
        }
    }
}

impl std::fmt::Display for Impl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Impl::Kernel => "kernel",
            Impl::Userspace => "userspace (wireguard-go)",
        })
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TunnelStats {
    pub last_handshake_secs_ago: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

fn iface_name(name: &str) -> Result<InterfaceName> {
    name.parse().map_err(|e| anyhow!("invalid interface name '{name}': {e:?}"))
}

async fn apply(cfg: &WireguardConfig, iface: &str, endpoint: SocketAddr, imp: Impl) -> Result<()> {
    let name = iface_name(iface)?;
    let mut peer = PeerConfigBuilder::new(&cfg.public_key).set_endpoint(endpoint).replace_allowed_ips();
    for net in &cfg.allowed_ips {
        peer = peer.add_allowed_ip(net.network(), net.prefix_len());
    }
    if let Some(psk) = &cfg.preshared_key {
        peer = peer.set_preshared_key(psk.clone());
    }
    if let Some(k) = cfg.keepalive {
        peer = peer.set_persistent_keepalive_interval(k);
    }
    let update =
        DeviceUpdate::new().set_private_key(cfg.private_key.clone()).set_fwmark(FWMARK).replace_peers().add_peer(peer);
    if imp == Impl::Userspace {
        std::fs::create_dir_all("/var/run/wireguard").ok();
    }
    tokio::task::spawn_blocking(move || update.apply(&name, imp.backend())).await?.map_err(anyhow::Error::from)
}

/// Creates the interface with its addresses and tunnel routes; returns the implementation used.
pub async fn up(
    net: &Net,
    cfg: &WireguardConfig,
    iface: &str,
    endpoint: SocketAddr,
    mtu: u32,
    ipv6: bool,
) -> Result<Impl> {
    if let Some(idx) = net.link_index(iface).await? {
        net.delete_link(idx).await?;
    }

    let imp = match cfg.implementation {
        WgImplementation::Kernel => {
            apply(cfg, iface, endpoint, Impl::Kernel).await.context("kernel WireGuard")?;
            Impl::Kernel
        }
        WgImplementation::Userspace => {
            apply(cfg, iface, endpoint, Impl::Userspace).await.context("WireGuard userspace")?;
            Impl::Userspace
        }
        WgImplementation::Auto => match apply(cfg, iface, endpoint, Impl::Kernel).await {
            Ok(()) => Impl::Kernel,
            Err(e) => {
                warn!("kernel WireGuard unavailable ({e:#}), falling back to wireguard-go");
                if let Some(idx) = net.link_index(iface).await? {
                    net.delete_link(idx).await?;
                }
                apply(cfg, iface, endpoint, Impl::Userspace).await.context("WireGuard userspace")?;
                Impl::Userspace
            }
        },
    };

    let index = net.link_index(iface).await?.ok_or_else(|| anyhow!("interface {iface} was not created"))?;
    for addr in &cfg.addresses {
        if addr.addr().is_ipv6() && !ipv6 {
            warn!("IPv6 address {addr} ignored: IPv6 is disabled in the container");
            continue;
        }
        net.add_address(index, *addr).await?;
    }
    net.set_up(index, mtu).await?;
    routing::setup_vpn_routes(net, index, &cfg.allowed_ips, ipv6).await?;

    info!("WireGuard ({imp}): {iface} up, MTU {mtu}, endpoint {endpoint}");
    Ok(imp)
}

pub async fn down(net: &Net, iface: &str, imp: Impl) {
    if imp == Impl::Userspace
        && let Ok(name) = iface_name(iface)
    {
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(dev) = Device::get(&name, Backend::Userspace) {
                let _ = dev.delete();
            }
        })
        .await;
    }
    match net.link_index(iface).await {
        Ok(Some(idx)) => {
            if let Err(e) = net.delete_link(idx).await {
                warn!("deleting {iface}: {e:#}");
            }
        }
        Ok(None) => {}
        Err(e) => warn!("looking up {iface}: {e:#}"),
    }
}

pub async fn stats(iface: &str, imp: Impl) -> Option<TunnelStats> {
    let name = iface_name(iface).ok()?;
    let dev = tokio::task::spawn_blocking(move || Device::get(&name, imp.backend())).await.ok()?.ok()?;
    let peer = dev.peers.first()?;
    let ago = peer
        .stats
        .last_handshake_time
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d: Duration| d.as_secs())
        // The kernel reports the epoch until the first handshake.
        .filter(|s| *s < 10 * 365 * 86_400);
    Some(TunnelStats { last_handshake_secs_ago: ago, rx_bytes: peer.stats.rx_bytes, tx_bytes: peer.stats.tx_bytes })
}
