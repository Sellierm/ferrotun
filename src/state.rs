//! State shared by the supervisor, the control API and the health server.

use std::{
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::{RwLock, mpsc};
use tracing::warn;

use crate::{publicip::PublicIp, wireguard::Impl};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum VpnState {
    #[default]
    Starting,
    Connecting,
    Connected,
    Unhealthy,
    Stopped,
}

#[derive(Debug, Default, Clone)]
pub struct Status {
    pub vpn: VpnState,
    pub healthy: bool,
    pub last_error: Option<String>,
    pub public_ip: Option<PublicIp>,
    pub forwarded_port: Option<u16>,
    pub endpoint: Option<SocketAddr>,
    pub implementation: Option<Impl>,
    pub connected_since: Option<SystemTime>,
    pub reconnections: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum Command {
    Start,
    Stop,
    Restart,
}

#[derive(Clone)]
pub struct Shared {
    pub status: Arc<RwLock<Status>>,
    pub commands: mpsc::Sender<Command>,
    pub vpn_interface: String,
}

pub fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Writes a file, creating parent directories and setting the PUID/PGID owner.
pub fn write_file(path: &Path, content: &str, owner: Option<(u32, u32)>) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(path, content).with_context(|| format!("writing {}", path.display()))?;
    if let Some((uid, gid)) = owner
        && let Err(e) = std::os::unix::fs::chown(path, Some(uid), Some(gid))
    {
        warn!("chown {}: {e}", path.display());
    }
    Ok(())
}
