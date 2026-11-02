//! wg-quick configuration parser (wg0.conf).

use anyhow::{Result, bail};
use tracing::warn;

#[derive(Default, Debug, PartialEq)]
pub struct WgQuickConf {
    pub private_key: Option<String>,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: Option<u32>,
    pub peer_public_key: Option<String>,
    pub peer_preshared_key: Option<String>,
    pub peer_allowed_ips: Vec<String>,
    pub peer_endpoint: Option<String>,
    pub peer_keepalive: Option<u16>,
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
    Ignored,
}

pub fn parse(content: &str) -> Result<WgQuickConf> {
    let mut conf = WgQuickConf::default();
    let mut section = Section::None;
    let mut peers = 0;

    for (n, raw) in content.lines().enumerate() {
        let line = raw.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = match line[1..line.len() - 1].trim().to_ascii_lowercase().as_str() {
                "interface" => Section::Interface,
                "peer" => {
                    peers += 1;
                    if peers > 1 {
                        warn!("wg0.conf: multiple [Peer] sections, only the first one is used");
                        Section::Ignored
                    } else {
                        Section::Peer
                    }
                }
                other => bail!("line {}: unknown section [{other}]", n + 1),
            };
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("line {}: expected 'key = value'", n + 1);
        };
        let key = key.trim().to_ascii_lowercase();
        // Base64 keys often end with '=': keep everything after the first one.
        let value = value.trim().to_string();
        let list = || value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>();

        match (&section, key.as_str()) {
            (Section::Interface, "privatekey") => conf.private_key = Some(value),
            (Section::Interface, "address") => conf.addresses.extend(list()),
            (Section::Interface, "dns") => conf.dns.extend(list()),
            (Section::Interface, "mtu") => conf.mtu = Some(value.parse()?),
            (
                Section::Interface,
                "listenport" | "fwmark" | "table" | "preup" | "postup" | "predown" | "postdown" | "saveconfig",
            ) => {
                warn!("wg0.conf: '{key}' ignored (handled by ferrotun)");
            }
            (Section::Peer, "publickey") => conf.peer_public_key = Some(value),
            (Section::Peer, "presharedkey") => conf.peer_preshared_key = Some(value),
            (Section::Peer, "allowedips") => conf.peer_allowed_ips.extend(list()),
            (Section::Peer, "endpoint") => conf.peer_endpoint = Some(value),
            (Section::Peer, "persistentkeepalive") => {
                conf.peer_keepalive = if value.eq_ignore_ascii_case("off") { None } else { Some(value.parse()?) }
            }
            (Section::Ignored, _) => {}
            (Section::None, _) => bail!("line {}: key '{key}' outside of a section", n + 1),
            (_, other) => warn!("wg0.conf: unknown key '{other}' ignored"),
        }
    }
    Ok(conf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pia_like_conf() {
        let c = parse(
            "[Interface]\nPrivateKey = aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=\nAddress = 10.14.212.175/32\nDNS = 10.0.0.243\n\
             [Peer]\nPublicKey = cHViIGtleSBwdWIga2V5IHB1YiBrZXkgcHViIGtleTE=\nAllowedIPs = 0.0.0.0/0\n\
             Endpoint = 195.78.54.71:1337\nPersistentKeepalive = 25\n",
        )
        .unwrap();
        assert_eq!(c.private_key.as_deref(), Some("aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28="));
        assert_eq!(c.addresses, vec!["10.14.212.175/32"]);
        assert_eq!(c.dns, vec!["10.0.0.243"]);
        assert_eq!(c.peer_allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(c.peer_endpoint.as_deref(), Some("195.78.54.71:1337"));
        assert_eq!(c.peer_keepalive, Some(25));
    }

    #[test]
    fn comments_and_case() {
        let c = parse("# comment\n[interface]\naddress=10.0.0.2/32, fd00::2/128 # fin\n[PEER]\nendpoint = vpn:51820\n")
            .unwrap();
        assert_eq!(c.addresses, vec!["10.0.0.2/32", "fd00::2/128"]);
        assert_eq!(c.peer_endpoint.as_deref(), Some("vpn:51820"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("PrivateKey = x\n").is_err());
        assert!(parse("[Interface]\ngarbage\n").is_err());
    }
}
