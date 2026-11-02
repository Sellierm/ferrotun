//! Public IP lookup (the tunnel's exit address).

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PublicIp {
    pub public_ip: String,
    pub region: String,
    pub country: String,
    pub city: String,
    pub location: String,
    pub organization: String,
    pub postal_code: String,
    pub timezone: String,
}

#[derive(Deserialize)]
struct IpInfo {
    ip: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    loc: String,
    #[serde(default)]
    org: String,
    #[serde(default)]
    postal: String,
    #[serde(default)]
    timezone: String,
}

#[derive(Deserialize)]
struct IfconfigCo {
    ip: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    region_name: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    zip_code: String,
    #[serde(default)]
    time_zone: String,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    asn_org: String,
}

#[derive(Deserialize)]
struct Ipify {
    ip: String,
}

async fn ipinfo(client: &reqwest::Client) -> Result<PublicIp> {
    let r: IpInfo = client.get("https://ipinfo.io/json").send().await?.error_for_status()?.json().await?;
    Ok(PublicIp {
        public_ip: r.ip,
        region: r.region,
        country: r.country,
        city: r.city,
        location: r.loc,
        organization: r.org,
        postal_code: r.postal,
        timezone: r.timezone,
    })
}

async fn ifconfig_co(client: &reqwest::Client) -> Result<PublicIp> {
    let r: IfconfigCo = client
        .get("https://ifconfig.co/json")
        .header("accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let location = match (r.latitude, r.longitude) {
        (Some(la), Some(lo)) => format!("{la},{lo}"),
        _ => String::new(),
    };
    Ok(PublicIp {
        public_ip: r.ip,
        region: r.region_name,
        country: r.country,
        city: r.city,
        location,
        organization: r.asn_org,
        postal_code: r.zip_code,
        timezone: r.time_zone,
    })
}

async fn ipify(client: &reqwest::Client) -> Result<PublicIp> {
    let r: Ipify = client.get("https://api.ipify.org?format=json").send().await?.error_for_status()?.json().await?;
    Ok(PublicIp { public_ip: r.ip, ..Default::default() })
}

pub async fn fetch(client: &reqwest::Client) -> Result<PublicIp> {
    let mut errors = vec![];
    for (name, res) in [
        ("ipinfo.io", ipinfo(client).await),
        ("ifconfig.co", ifconfig_co(client).await),
        ("ipify.org", ipify(client).await),
    ] {
        match res {
            Ok(ip) if ip.public_ip.parse::<std::net::IpAddr>().is_ok() => return Ok(ip),
            Ok(ip) => errors.push(format!("{name}: invalid response '{}'", ip.public_ip)),
            Err(e) => {
                debug!("public IP via {name}: {e:#}");
                errors.push(format!("{name}: {e}"));
            }
        }
    }
    bail!("{}", errors.join("; "))
}

impl PublicIp {
    pub fn summary(&self) -> String {
        let place: Vec<&str> = [self.country.as_str(), self.region.as_str(), self.city.as_str()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        if place.is_empty() { self.public_ip.clone() } else { format!("{} ({})", self.public_ip, place.join(", ")) }
    }
}
