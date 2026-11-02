//! rtnetlink helpers: links, addresses, routes and rules.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow};
use futures::TryStreamExt;
use ipnet::{IpNet, Ipv4Net};
use netlink_packet_route::{
    address::AddressAttribute,
    link::LinkAttribute,
    route::{RouteAddress, RouteAttribute, RouteHeader, RouteMessage},
    rule::{RuleAction, RuleAttribute, RuleFlags},
};
use rtnetlink::{Handle, IpVersion, LinkUnspec, RouteMessageBuilder};

const EEXIST: i32 = 17;
const ENOENT: i32 = 2;
const ENODEV: i32 = 19;
const ESRCH: i32 = 3;

#[derive(Debug, Clone)]
pub struct DefaultRoute {
    pub if_index: u32,
    pub if_name: String,
    pub gateway: Ipv4Addr,
    pub local_ip: Ipv4Addr,
    pub subnet: Ipv4Net,
    pub mtu: u32,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub priority: u32,
    pub table: u32,
    pub to: Option<IpNet>,
    pub from: Option<IpNet>,
    pub fwmark: Option<u32>,
    pub invert: bool,
    pub v6: bool,
}

#[derive(Clone)]
pub struct Net {
    handle: Handle,
}

fn errno(e: &rtnetlink::Error) -> Option<i32> {
    match e {
        rtnetlink::Error::NetlinkError(m) => Some(m.raw_code().abs()),
        _ => None,
    }
}

fn ignore_exists(r: Result<(), rtnetlink::Error>) -> Result<(), rtnetlink::Error> {
    match r {
        Err(e) if errno(&e) == Some(EEXIST) => Ok(()),
        other => other,
    }
}

fn route_table(msg: &RouteMessage) -> u32 {
    msg.attributes
        .iter()
        .find_map(|a| if let RouteAttribute::Table(t) = a { Some(*t) } else { None })
        .unwrap_or(msg.header.table as u32)
}

impl Net {
    pub fn new() -> Result<Self> {
        let (conn, handle, _) = rtnetlink::new_connection().context("opening netlink socket")?;
        tokio::spawn(conn);
        Ok(Self { handle })
    }

    pub async fn default_route_v4(&self) -> Result<DefaultRoute> {
        let mut routes = self.handle.route().get(RouteMessageBuilder::<Ipv4Addr>::new().build()).execute();
        let mut found = None;
        while let Some(r) = routes.try_next().await? {
            if r.header.destination_prefix_length != 0 || route_table(&r) != RouteHeader::RT_TABLE_MAIN as u32 {
                continue;
            }
            let mut gw = None;
            let mut oif = None;
            for a in &r.attributes {
                match a {
                    RouteAttribute::Gateway(RouteAddress::Inet(ip)) => gw = Some(*ip),
                    RouteAttribute::Oif(i) => oif = Some(*i),
                    _ => {}
                }
            }
            if let (Some(gw), Some(oif)) = (gw, oif) {
                found = Some((gw, oif));
                break;
            }
        }
        let (gateway, if_index) = found.ok_or_else(|| anyhow!("no IPv4 default route found"))?;
        let (if_name, mtu) = self.link_name_mtu(if_index).await?;
        let subnet = self
            .interface_subnets(if_index)
            .await?
            .into_iter()
            .find_map(|n| match n {
                IpNet::V4(n4) if n4.contains(&gateway) => Some(n4),
                _ => None,
            })
            .ok_or_else(|| anyhow!("no IPv4 address on {if_name}"))?;
        Ok(DefaultRoute { if_index, if_name, gateway, local_ip: subnet.addr(), subnet, mtu })
    }

    async fn link_name_mtu(&self, index: u32) -> Result<(String, u32)> {
        let link = self
            .handle
            .link()
            .get()
            .match_index(index)
            .execute()
            .try_next()
            .await?
            .ok_or_else(|| anyhow!("interface {index} not found"))?;
        let mut name = String::new();
        let mut mtu = 1500;
        for a in link.attributes {
            match a {
                LinkAttribute::IfName(n) => name = n,
                LinkAttribute::Mtu(m) => mtu = m,
                _ => {}
            }
        }
        Ok((name, mtu))
    }

    pub async fn link_index(&self, name: &str) -> Result<Option<u32>> {
        match self.handle.link().get().match_name(name).execute().try_next().await {
            Ok(Some(l)) => Ok(Some(l.header.index)),
            Ok(None) => Ok(None),
            Err(e) if matches!(errno(&e), Some(ENODEV) | Some(ENOENT)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn interface_subnets(&self, index: u32) -> Result<Vec<IpNet>> {
        let mut addrs = self.handle.address().get().set_link_index_filter(index).execute();
        let mut out = vec![];
        while let Some(a) = addrs.try_next().await? {
            let ip = a.attributes.iter().find_map(|attr| match attr {
                AddressAttribute::Local(ip) => Some(*ip),
                _ => None,
            });
            let ip = ip.or_else(|| {
                a.attributes.iter().find_map(|attr| match attr {
                    AddressAttribute::Address(ip) => Some(*ip),
                    _ => None,
                })
            });
            if let Some(ip) = ip
                && let Ok(n) = IpNet::new(ip, a.header.prefix_len)
            {
                out.push(n);
            }
        }
        Ok(out)
    }

    pub async fn add_address(&self, index: u32, net: IpNet) -> Result<()> {
        ignore_exists(self.handle.address().add(index, net.addr(), net.prefix_len()).execute().await)
            .with_context(|| format!("adding address {net}"))
    }

    pub async fn set_up(&self, index: u32, mtu: u32) -> Result<()> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).mtu(mtu).up().build())
            .execute()
            .await
            .context("bringing interface up")
    }

    pub async fn delete_link(&self, index: u32) -> Result<()> {
        match self.handle.link().del(index).execute().await {
            Err(e) if matches!(errno(&e), Some(ENODEV) | Some(ENOENT)) => Ok(()),
            r => r.context("deleting interface"),
        }
    }

    pub async fn replace_route_dev(&self, table: u32, dst: IpNet, index: u32) -> Result<()> {
        let msg = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(dst.network(), dst.prefix_len())
            .map_err(|e| anyhow!("{e}"))?
            .output_interface(index)
            .table_id(table)
            .build();
        self.handle
            .route()
            .add(msg)
            .replace()
            .execute()
            .await
            .with_context(|| format!("adding route {dst} (table {table})"))
    }

    pub async fn replace_route_via(&self, table: u32, dst: Ipv4Net, gw: Ipv4Addr, index: u32) -> Result<()> {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(dst.network(), dst.prefix_len())
            .gateway(gw)
            .output_interface(index)
            .table_id(table)
            .build();
        self.handle
            .route()
            .add(msg)
            .replace()
            .execute()
            .await
            .with_context(|| format!("adding route {dst} via {gw} (table {table})"))
    }

    pub async fn add_rule(&self, rule: &Rule) -> Result<()> {
        let res = if rule.v6 {
            let mut r =
                self.handle.rule().add().v6().priority(rule.priority).table_id(rule.table).action(RuleAction::ToTable);
            if let Some(IpNet::V6(n)) = rule.to {
                r = r.destination_prefix(n.network(), n.prefix_len());
            }
            if let Some(IpNet::V6(n)) = rule.from {
                r = r.source_prefix(n.network(), n.prefix_len());
            }
            if let Some(m) = rule.fwmark {
                r = r.fw_mark(m);
            }
            if rule.invert {
                r.message_mut().header.flags |= RuleFlags::Invert;
            }
            r.execute().await
        } else {
            let mut r =
                self.handle.rule().add().v4().priority(rule.priority).table_id(rule.table).action(RuleAction::ToTable);
            if let Some(IpNet::V4(n)) = rule.to {
                r = r.destination_prefix(n.network(), n.prefix_len());
            }
            if let Some(IpNet::V4(n)) = rule.from {
                r = r.source_prefix(n.network(), n.prefix_len());
            }
            if let Some(m) = rule.fwmark {
                r = r.fw_mark(m);
            }
            if rule.invert {
                r.message_mut().header.flags |= RuleFlags::Invert;
            }
            r.execute().await
        };
        ignore_exists(res).with_context(|| format!("adding routing rule {rule:?}"))
    }

    pub async fn delete_rules(&self, priorities: &[u32], v6: bool) -> Result<()> {
        let version = if v6 { IpVersion::V6 } else { IpVersion::V4 };
        let rules: Vec<_> = self.handle.rule().get(version).execute().try_collect().await?;
        for r in rules {
            let prio = r.attributes.iter().find_map(|a| match a {
                RuleAttribute::Priority(p) => Some(*p),
                _ => None,
            });
            if prio.is_some_and(|p| priorities.contains(&p)) {
                match self.handle.rule().del(r).execute().await {
                    Err(e) if matches!(errno(&e), Some(ENOENT) | Some(ESRCH)) => {}
                    other => other.context("deleting routing rule")?,
                }
            }
        }
        Ok(())
    }

    pub async fn ipv6_enabled(&self) -> bool {
        let lo = match self.link_index("lo").await {
            Ok(Some(i)) => i,
            _ => return false,
        };
        let has_v6 = self
            .interface_subnets(lo)
            .await
            .map(|v| v.iter().any(|n| n.addr() == IpAddr::V6(Ipv6Addr::LOCALHOST)))
            .unwrap_or(false);
        has_v6
            && std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
                .map(|s| s.trim() == "0")
                .unwrap_or(false)
    }
}
