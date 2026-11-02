//! Local DNS server (127.0.0.1:53): cache and forwarding to DoT, DoH or plain upstreams,
//! always through the tunnel. Single-label names and private PTRs go to Docker's DNS
//! (127.0.0.11) so that containers sharing ferrotun's network can reach others by name.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, info, warn};

use crate::{
    config::{DnsConfig, UpstreamKind, UpstreamServer},
    tls,
};

const UDP_TIMEOUT: Duration = Duration::from_secs(3);
const STREAM_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_MAX_ENTRIES: usize = 10_000;
const MAX_TTL: u32 = 86_400;
const MAX_NEGATIVE_TTL: u32 = 300;
const DOT_POOL_SIZE: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuestionKey {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

fn be16(b: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(pos)?, *b.get(pos + 1)?]))
}

fn be32(b: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(pos..pos + 4)?.try_into().ok()?))
}

/// Reads a possibly compressed name; returns (name, position after it).
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut hops = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = ptr;
            hops += 1;
            if hops > 32 {
                return None;
            }
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        if len == 0 {
            end.get_or_insert(pos + 1);
            break;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|b| (*b as char).to_ascii_lowercase()));
        pos += 1 + len;
        if name.len() > 255 {
            return None;
        }
    }
    Some((name, end?))
}

/// The single question and the end offset of the question section.
pub fn parse_question(msg: &[u8]) -> Option<(QuestionKey, usize)> {
    if msg.len() < 12 || be16(msg, 4)? != 1 {
        return None;
    }
    let (name, pos) = read_name(msg, 12)?;
    Some((QuestionKey { name, qtype: be16(msg, pos)?, qclass: be16(msg, pos + 2)? }, pos + 4))
}

#[derive(Debug, Default)]
pub struct ResponseInfo {
    pub rcode: u8,
    pub truncated: bool,
    pub answers: u16,
    pub min_ttl: Option<u32>,
    pub min_authority_ttl: Option<u32>,
    /// TTL field offsets (excluding OPT), rewritten when serving from cache.
    pub ttl_offsets: Vec<usize>,
    pub edns_udp_size: Option<u16>,
}

pub fn inspect(msg: &[u8]) -> Option<ResponseInfo> {
    if msg.len() < 12 {
        return None;
    }
    let flags = be16(msg, 2)?;
    let (qd, an, ns, ar) = (be16(msg, 4)?, be16(msg, 6)?, be16(msg, 8)?, be16(msg, 10)?);
    let mut info = ResponseInfo {
        rcode: (flags & 0x000F) as u8,
        truncated: flags & 0x0200 != 0,
        answers: an,
        ..Default::default()
    };
    let mut pos = 12;
    for _ in 0..qd {
        pos = read_name(msg, pos)?.1 + 4;
    }
    for i in 0..(an as usize + ns as usize + ar as usize) {
        pos = read_name(msg, pos)?.1;
        let rtype = be16(msg, pos)?;
        let class = be16(msg, pos + 2)?;
        let ttl = be32(msg, pos + 4)?;
        let rdlen = be16(msg, pos + 8)? as usize;
        if rtype == 41 {
            info.edns_udp_size = Some(class);
        } else {
            info.ttl_offsets.push(pos + 4);
            info.min_ttl = Some(info.min_ttl.map_or(ttl, |m| m.min(ttl)));
            if i >= an as usize && i < an as usize + ns as usize {
                info.min_authority_ttl = Some(info.min_authority_ttl.map_or(ttl, |m| m.min(ttl)));
            }
        }
        pos += 10 + rdlen;
        if pos > msg.len() {
            return None;
        }
    }
    Some(info)
}

fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    let (_, qend) = parse_question(query)?;
    let mut r = query[..qend].to_vec();
    // QR=1, keep opcode and RD, RA=1, RCODE=2
    r[2] = 0x80 | (query[2] & 0x79);
    r[3] = 0x80 | 0x02;
    r[6..12].fill(0);
    Some(r)
}

/// TC=1 with no records, so the client retries over TCP.
fn truncated(resp: &[u8]) -> Vec<u8> {
    let qend = parse_question(resp).map(|(_, e)| e).unwrap_or(12).min(resp.len());
    let mut r = resp[..qend].to_vec();
    if r.len() >= 12 {
        r[2] |= 0x02;
        r[6..12].fill(0);
    }
    r
}

/// Whether the name should be resolved by Docker's DNS instead of the upstream.
pub fn is_local_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if !name.contains('.') {
        return true;
    }
    if let Some(rev) = name.strip_suffix(".in-addr.arpa") {
        let octets: Vec<u8> = rev.split('.').rev().filter_map(|o| o.parse().ok()).collect();
        if octets.len() == 4 {
            let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            return ip.is_private() || ip.is_loopback() || ip.is_link_local();
        }
    }
    false
}

struct CacheEntry {
    response: Vec<u8>,
    stored: Instant,
    ttl: u32,
    ttl_offsets: Vec<usize>,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<QuestionKey, CacheEntry>,
}

impl Cache {
    fn get(&mut self, key: &QuestionKey) -> Option<Vec<u8>> {
        let entry = self.entries.get(key)?;
        let elapsed = entry.stored.elapsed().as_secs() as u32;
        if elapsed >= entry.ttl {
            self.entries.remove(key);
            return None;
        }
        let mut r = entry.response.clone();
        for &off in &entry.ttl_offsets {
            let ttl = be32(&r, off).unwrap_or(0).saturating_sub(elapsed);
            r[off..off + 4].copy_from_slice(&ttl.to_be_bytes());
        }
        Some(r)
    }

    fn put(&mut self, key: QuestionKey, response: &[u8]) {
        let Some(info) = inspect(response) else { return };
        if info.truncated {
            return;
        }
        let ttl = match info.rcode {
            0 if info.answers > 0 => info.min_ttl.unwrap_or(0).min(MAX_TTL),
            0 | 3 => info.min_authority_ttl.unwrap_or(60).min(MAX_NEGATIVE_TTL),
            _ => 0,
        };
        if ttl == 0 {
            return;
        }
        if self.entries.len() >= CACHE_MAX_ENTRIES {
            let now = Instant::now();
            self.entries.retain(|_, e| now.duration_since(e.stored).as_secs() < e.ttl as u64);
            if self.entries.len() >= CACHE_MAX_ENTRIES {
                self.entries.clear();
            }
        }
        self.entries.insert(
            key,
            CacheEntry { response: response.to_vec(), stored: Instant::now(), ttl, ttl_offsets: info.ttl_offsets },
        );
    }
}

pub struct Resolver {
    kind: UpstreamKind,
    servers: Vec<UpstreamServer>,
    local: Option<SocketAddr>,
    cache: Option<StdMutex<Cache>>,
    tls: TlsConnector,
    dot_pools: Vec<Mutex<Vec<TlsStream<TcpStream>>>>,
    doh: Option<reqwest::Client>,
    next: AtomicUsize,
}

impl Resolver {
    pub fn new(cfg: &DnsConfig, local: Option<SocketAddr>) -> Result<Self> {
        if cfg.servers.is_empty() {
            bail!("no upstream DNS server configured");
        }
        let tls_config = Arc::new(tls::webpki_config()?);
        let doh = if cfg.kind == UpstreamKind::Doh {
            // DoH hostnames are pinned to their IPs, otherwise we would resolve them through ourselves.
            let mut builder = reqwest::Client::builder()
                .tls_backend_preconfigured(tls::webpki_config()?)
                .timeout(STREAM_TIMEOUT)
                .no_proxy();
            let mut by_host: HashMap<String, Vec<SocketAddr>> = HashMap::new();
            for s in &cfg.servers {
                let host =
                    reqwest::Url::parse(&s.doh_url)?.host_str().ok_or_else(|| anyhow!("invalid DoH URL"))?.to_string();
                by_host.entry(host).or_default().push(s.addr);
            }
            for (host, addrs) in &by_host {
                builder = builder.resolve_to_addrs(host, addrs);
            }
            Some(builder.build()?)
        } else {
            None
        };
        Ok(Self {
            kind: cfg.kind,
            servers: cfg.servers.clone(),
            local,
            cache: cfg.caching.then(|| StdMutex::new(Cache::default())),
            tls: TlsConnector::from(tls_config),
            dot_pools: cfg.servers.iter().map(|_| Mutex::new(Vec::new())).collect(),
            doh,
            next: AtomicUsize::new(0),
        })
    }

    /// Answers a query, with SERVFAIL on failure.
    pub async fn handle(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let question = parse_question(query).map(|(q, _)| q);

        if let (Some(q), Some(cache)) = (&question, &self.cache)
            && let Some(mut r) = cache.lock().unwrap().get(q)
        {
            r[0..2].copy_from_slice(&query[0..2]);
            debug!("dns: {} (type {}) from cache", q.name, q.qtype);
            return Some(r);
        }

        let local = match (&question, self.local) {
            (Some(q), Some(addr)) if is_local_name(&q.name) => Some(addr),
            _ => None,
        };

        let result = match local {
            Some(addr) => exchange_plain(addr, query).await,
            None => self.upstream(query).await,
        };

        match result {
            Ok(resp) => {
                if local.is_none()
                    && let (Some(q), Some(cache)) = (question, &self.cache)
                {
                    cache.lock().unwrap().put(q, &resp);
                }
                Some(resp)
            }
            Err(e) => {
                let name = question.as_ref().map(|q| q.name.as_str()).unwrap_or("?");
                debug!("dns: resolving {name} failed: {e:#}");
                servfail(query)
            }
        }
    }

    async fn upstream(&self, query: &[u8]) -> Result<Vec<u8>> {
        let n = self.servers.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed) % n;
        let mut last_err = anyhow!("no server");
        for i in 0..n {
            let idx = (start + i) % n;
            let server = &self.servers[idx];
            let res = match self.kind {
                UpstreamKind::Plain => exchange_plain(server.addr, query).await,
                UpstreamKind::Dot => self.exchange_dot(idx, query).await,
                UpstreamKind::Doh => self.exchange_doh(server, query).await,
            };
            match res {
                Ok(r) => return Ok(r),
                Err(e) => last_err = e.context(format!("server {}", server.addr)),
            }
        }
        Err(last_err)
    }

    async fn exchange_dot(&self, idx: usize, query: &[u8]) -> Result<Vec<u8>> {
        let pooled = self.dot_pools[idx].lock().await.pop();
        if let Some(mut stream) = pooled
            && let Ok(Ok(r)) = timeout(STREAM_TIMEOUT, stream_exchange(&mut stream, query)).await
        {
            self.give_back(idx, stream).await;
            return Ok(r);
        }
        // Pooled connection closed by the server: open a new one.
        let server = &self.servers[idx];
        let mut stream = timeout(STREAM_TIMEOUT, async {
            let tcp = TcpStream::connect(server.addr).await?;
            tcp.set_nodelay(true)?;
            let name = ServerName::try_from(server.tls_name.clone())?;
            Ok::<_, anyhow::Error>(self.tls.connect(name, tcp).await?)
        })
        .await
        .context("DoT connect timed out")??;
        let r =
            timeout(STREAM_TIMEOUT, stream_exchange(&mut stream, query)).await.context("DoT response timed out")??;
        self.give_back(idx, stream).await;
        Ok(r)
    }

    async fn give_back(&self, idx: usize, stream: TlsStream<TcpStream>) {
        let mut pool = self.dot_pools[idx].lock().await;
        if pool.len() < DOT_POOL_SIZE {
            pool.push(stream);
        }
    }

    async fn exchange_doh(&self, server: &UpstreamServer, query: &[u8]) -> Result<Vec<u8>> {
        let client = self.doh.as_ref().ok_or_else(|| anyhow!("no DoH client"))?;
        let resp = client
            .post(&server.doh_url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query.to_vec())
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.bytes().await?.to_vec())
    }
}

async fn stream_exchange<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, query: &[u8]) -> Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(query.len() + 2);
    msg.extend_from_slice(&(query.len() as u16).to_be_bytes());
    msg.extend_from_slice(query);
    s.write_all(&msg).await?;
    s.flush().await?;
    loop {
        let len = s.read_u16().await? as usize;
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf).await?;
        if buf.len() >= 2 && buf[0..2] == query[0..2] {
            return Ok(buf);
        }
    }
}

/// Plain DNS over UDP, retried over TCP if truncated.
async fn exchange_plain(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let resp = timeout(UDP_TIMEOUT, async {
        loop {
            let n = sock.recv(&mut buf).await?;
            if n >= 12 && buf[0..2] == query[0..2] {
                return Ok::<_, std::io::Error>(buf[..n].to_vec());
            }
        }
    })
    .await
    .context("timed out")??;
    if resp[2] & 0x02 != 0 {
        let mut tcp = timeout(STREAM_TIMEOUT, TcpStream::connect(server)).await??;
        return timeout(STREAM_TIMEOUT, stream_exchange(&mut tcp, query)).await?;
    }
    Ok(resp)
}

/// Separate from `serve` so that bind errors surface at startup.
pub async fn bind(listen: SocketAddr) -> Result<(UdpSocket, TcpListener)> {
    let udp = UdpSocket::bind(listen).await.with_context(|| format!("DNS UDP listen on {listen}"))?;
    let tcp = TcpListener::bind(listen).await.with_context(|| format!("DNS TCP listen on {listen}"))?;
    info!("DNS server listening on {listen}");
    Ok((udp, tcp))
}

pub async fn serve(resolver: Arc<Resolver>, udp: UdpSocket, tcp: TcpListener) {
    let udp = Arc::new(udp);
    let r = resolver.clone();
    tokio::spawn(async move {
        loop {
            match tcp.accept().await {
                Ok((stream, _)) => {
                    let r = r.clone();
                    tokio::spawn(async move {
                        let _ = serve_tcp(r, stream).await;
                    });
                }
                Err(e) => {
                    warn!("dns: TCP accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match udp.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!("dns: UDP receive error: {e}");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        let (r, sock) = (resolver.clone(), udp.clone());
        tokio::spawn(async move {
            if let Some(mut resp) = r.handle(&query).await {
                let limit = inspect(&query).and_then(|i| i.edns_udp_size).unwrap_or(512).max(512) as usize;
                if resp.len() > limit {
                    resp = truncated(&resp);
                }
                let _ = sock.send_to(&resp, peer).await;
            }
        });
    }
}

async fn serve_tcp(resolver: Arc<Resolver>, mut stream: TcpStream) -> Result<()> {
    loop {
        let len = match timeout(Duration::from_secs(10), stream.read_u16()).await {
            Ok(Ok(l)) => l as usize,
            _ => return Ok(()),
        };
        let mut query = vec![0u8; len];
        timeout(Duration::from_secs(10), stream.read_exact(&mut query)).await??;
        if let Some(resp) = resolver.handle(&query).await {
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            out.extend_from_slice(&resp);
            stream.write_all(&out).await?;
        }
    }
}

const ORIGINAL_MARKER: &str = "# ferrotun-original-nameservers:";

pub struct ResolvConf {
    /// Nameservers from before ferrotun rewrote the file.
    pub original_nameservers: Vec<IpAddr>,
    /// Preserved search / domain / options lines.
    pub extra: Vec<String>,
}

pub fn read_resolv_conf(path: &Path) -> ResolvConf {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut nameservers = vec![];
    let mut original = None;
    let mut extra = vec![];
    for line in content.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix(ORIGINAL_MARKER) {
            original = Some(rest.split(',').filter_map(|s| s.trim().parse().ok()).collect::<Vec<IpAddr>>());
        } else if let Some(ns) = l.strip_prefix("nameserver") {
            if let Ok(ip) = ns.trim().parse() {
                nameservers.push(ip);
            }
        } else if l.starts_with("search") || l.starts_with("domain") || l.starts_with("options") {
            extra.push(l.to_string());
        }
    }
    ResolvConf { original_nameservers: original.unwrap_or(nameservers), extra }
}

/// Rewritten in place: it is a Docker bind mount shared with `network_mode: service:` containers.
pub fn write_resolv_conf(path: &Path, nameservers: &[IpAddr], rc: &ResolvConf) -> Result<()> {
    use std::io::Write;
    let mut out = String::from("# Generated by ferrotun\n");
    let orig: Vec<String> = rc.original_nameservers.iter().map(IpAddr::to_string).collect();
    out.push_str(&format!("{ORIGINAL_MARKER} {}\n", orig.join(",")));
    for ns in nameservers {
        out.push_str(&format!("nameserver {ns}\n"));
    }
    for l in &rc.extra {
        out.push_str(l);
        out.push('\n');
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    f.write_all(out.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query for example.com with EDNS (UDP size 1232).
    fn query_example() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        // OPT: root name, type 41, class = UDP size 1232
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
        q
    }

    /// Response with a compressed name and a TTL of 300.
    fn response_example() -> Vec<u8> {
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(b"\x07Example\x03COM\x00");
        r.extend_from_slice(&[0, 1, 0, 1]);
        r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0x01, 0x2C, 0, 4, 93, 184, 216, 34]);
        r
    }

    #[test]
    fn question_parsing() {
        let (q, end) = parse_question(&query_example()).unwrap();
        assert_eq!(q, QuestionKey { name: "example.com".into(), qtype: 1, qclass: 1 });
        assert_eq!(end, 12 + 13 + 4);
        let (q, _) = parse_question(&response_example()).unwrap();
        assert_eq!(q.name, "example.com");
    }

    #[test]
    fn inspect_query_and_response() {
        let i = inspect(&query_example()).unwrap();
        assert_eq!(i.edns_udp_size, Some(1232));
        assert!(i.ttl_offsets.is_empty());
        let r = inspect(&response_example()).unwrap();
        assert_eq!((r.rcode, r.answers, r.min_ttl), (0, 1, Some(300)));
        assert_eq!(r.ttl_offsets.len(), 1);
    }

    #[test]
    fn cache_rewrites_ttl() {
        let mut c = Cache::default();
        let key = parse_question(&response_example()).unwrap().0;
        c.put(key.clone(), &response_example());
        let entry = c.entries.get_mut(&key).unwrap();
        entry.stored -= Duration::from_secs(100);
        let r = c.get(&key).unwrap();
        let off = inspect(&r).unwrap().ttl_offsets[0];
        assert_eq!(be32(&r, off), Some(200));
    }

    #[test]
    fn servfail_and_truncation() {
        let q = query_example();
        let s = servfail(&q).unwrap();
        assert_eq!(s[3] & 0x0F, 2);
        assert_eq!(s[2] & 0x80, 0x80);
        assert_eq!(&s[0..2], &q[0..2]);
        let t = truncated(&response_example());
        assert_eq!(t[2] & 0x02, 0x02);
        assert_eq!(inspect(&t).unwrap().answers, 0);
    }

    #[test]
    fn local_names() {
        assert!(is_local_name("radarr"));
        assert!(is_local_name("10.0.19.172.in-addr.arpa"));
        assert!(!is_local_name("8.8.8.8.in-addr.arpa"));
        assert!(!is_local_name("github.com"));
        assert!(!is_local_name(""));
    }

    #[test]
    fn rejects_pointer_loops() {
        let mut m = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xC0, 12]);
        assert!(parse_question(&m).is_none());
    }
}
