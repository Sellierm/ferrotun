//! Policy routing, same scheme as wg-quick:
//!
//! | prio | rule                                      | effect                                  |
//! |------|-------------------------------------------|-----------------------------------------|
//! | 98   | to <Docker subnet> lookup main            | local Docker network stays reachable    |
//! | 99   | to <FIREWALL_OUTBOUND_SUBNETS> lookup 199 | allowed subnets bypass the tunnel (LAN) |
//! | 100  | from <eth0 IP> lookup 200                 | replies to connections received on eth0 |
//! | 101  | not fwmark 0xca6c lookup 51820            | everything else goes through the tunnel |
//!
//! WireGuard's own packets carry fwmark 0xca6c, skip rule 101 and leave through Docker's default
//! route. If the tunnel is down, table 51820 is empty, traffic falls back to main and is dropped
//! by the firewall (kill-switch).

use anyhow::Result;
use ipnet::IpNet;
use tracing::{info, warn};

use crate::netlink::{DefaultRoute, Net, Rule};

pub const FWMARK: u32 = 0xca6c;
pub const VPN_TABLE: u32 = 51820;
const OUTBOUND_TABLE: u32 = 199;
const REPLY_TABLE: u32 = 200;
const PRIORITIES: [u32; 4] = [98, 99, 100, 101];

pub async fn setup_base(net: &Net, default: &DefaultRoute, outbound: &[IpNet], ipv6: bool) -> Result<()> {
    net.delete_rules(&PRIORITIES, false).await?;

    net.add_rule(&Rule {
        priority: 98,
        table: 254,
        to: Some(IpNet::V4(default.subnet.trunc())),
        from: None,
        fwmark: None,
        invert: false,
        v6: false,
    })
    .await?;

    for subnet in outbound {
        match subnet {
            IpNet::V4(n) => {
                if default.subnet.trunc().contains(n) {
                    continue; // covered by rule 98
                }
                net.replace_route_via(OUTBOUND_TABLE, *n, default.gateway, default.if_index).await?;
                net.add_rule(&Rule {
                    priority: 99,
                    table: OUTBOUND_TABLE,
                    to: Some(*subnet),
                    from: None,
                    fwmark: None,
                    invert: false,
                    v6: false,
                })
                .await?;
            }
            IpNet::V6(_) => warn!("IPv6 outbound subnet {subnet} ignored (not supported)"),
        }
    }

    net.replace_route_via(REPLY_TABLE, "0.0.0.0/0".parse().unwrap(), default.gateway, default.if_index).await?;
    net.add_rule(&Rule {
        priority: 100,
        table: REPLY_TABLE,
        to: None,
        from: Some(IpNet::V4(ipnet::Ipv4Net::from(default.local_ip))),
        fwmark: None,
        invert: false,
        v6: false,
    })
    .await?;

    net.add_rule(&Rule {
        priority: 101,
        table: VPN_TABLE,
        to: None,
        from: None,
        fwmark: Some(FWMARK),
        invert: true,
        v6: false,
    })
    .await?;

    if ipv6 {
        let rule = Rule {
            priority: 101,
            table: VPN_TABLE,
            to: None,
            from: None,
            fwmark: Some(FWMARK),
            invert: true,
            v6: true,
        };
        if let Err(e) = async {
            net.delete_rules(&PRIORITIES, true).await?;
            net.add_rule(&rule).await
        }
        .await
        {
            warn!("IPv6 routing not configured: {e:#}");
        }
    }

    info!(
        "routing: default via {} ({}), local network {}, {} outbound subnet(s)",
        default.gateway,
        default.if_name,
        default.subnet.trunc(),
        outbound.len()
    );
    Ok(())
}

pub async fn setup_vpn_routes(net: &Net, if_index: u32, allowed: &[IpNet], ipv6: bool) -> Result<()> {
    for dst in allowed {
        if dst.addr().is_ipv6() && !ipv6 {
            continue;
        }
        net.replace_route_dev(VPN_TABLE, dst.trunc(), if_index).await?;
    }
    Ok(())
}
