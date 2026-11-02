# ferrotun

A WireGuard VPN client container written in Rust, inspired by [gluetun](https://github.com/qdm12/gluetun).

> [!WARNING]
> This project was generated with AI and is still under review: its behavior has not been fully
> validated yet.

Other containers share its network (`network_mode: service:vpn`): all their traffic goes through
the tunnel, and **nothing leaves if the tunnel goes down** (kill-switch).

## Features

| | |
|---|---|
| **WireGuard** | kernel module driven over netlink; automatic fallback to `wireguard-go` when the module is missing |
| **Kill-switch** | dedicated nftables table, drop policy on input, output and forward, applied before anything else; connections opened through the tunnel can never leave through `eth0` |
| **Routing** | policy routing (fwmark `0xca6c`, table 51820) like wg-quick; the Docker network and allowed LAN subnets bypass the tunnel |
| **DNS** | local caching server on 127.0.0.1:53; DNS-over-TLS (default), DNS-over-HTTPS or plain upstreams, always **through the tunnel**; container names (`radarr`, `sonarr`, ...) are still resolved by Docker's DNS |
| **Health** | periodic TCP check through the tunnel, automatic reconnection, built-in Docker `HEALTHCHECK` |
| **Public IP** | fetched on each connection (ipinfo.io, ifconfig.co, ipify) and written to `/tmp/ferrotun/ip` |
| **PIA port forwarding** | token, signature and `bindPort` renewal every 15 minutes; data persisted across restarts; up/down commands; optional redirect to a local port |
| **qBittorrent** | keeps the listen port in sync with the forwarded port (WebUI API, qBittorrent 4 and 5) |
| **Control API** | status, public IP, forwarded port, stop/start/restart; optional API key |

Not supported yet: OpenVPN, built-in provider server lists (a `wg0.conf` is required), proxies,
DNS blocklists.

## Quick start

```bash
docker build -t ferrotun:latest .
```

```yaml
services:
  vpn:
    image: ferrotun:latest
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun:/dev/net/tun]
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=1
    environment:
      - FIREWALL_OUTBOUND_SUBNETS=192.168.0.0/16   # LAN reachable outside the tunnel
    volumes:
      - ./wg0.conf:/ferrotun/wg0.conf:ro
    ports:
      - 8080:8080            # ports of the containers behind the VPN are published here

  qbittorrent:
    image: lscr.io/linuxserver/qbittorrent:latest
    network_mode: service:vpn
    depends_on:
      vpn:
        condition: service_healthy
```

See [`docker-compose.example.yml`](docker-compose.example.yml) for a full example with PIA and
qBittorrent.

A WireGuard private key can only be used by one client at a time: never run two VPN containers
with the same `wg0.conf`.

## Configuration

Everything is optional except the WireGuard configuration. Secrets can also be read from a file
with the `_FILE` suffix (e.g. `VPN_PORT_FORWARDING_PASSWORD_FILE=/run/secrets/pia_password`).

### WireGuard

Read from `WIREGUARD_CONF_FILE`, otherwise `/ferrotun/wg0.conf` or `/run/secrets/wg0.conf`.
Environment variables override the file.

| Variable | Default | Description |
|---|---|---|
| `VPN_INTERFACE` | `wg0` | tunnel interface name |
| `WIREGUARD_PRIVATE_KEY` | | private key (otherwise `PrivateKey` from the file) |
| `WIREGUARD_PUBLIC_KEY` | | server public key |
| `WIREGUARD_PRESHARED_KEY` | | preshared key |
| `WIREGUARD_ADDRESSES` | | client address(es), e.g. `10.14.212.175/32` |
| `WIREGUARD_ENDPOINT_IP` / `_PORT` | | server IP or hostname, and port |
| `WIREGUARD_ALLOWED_IPS` | `0.0.0.0/0` | networks routed through the tunnel |
| `WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL` | | e.g. `25s` |
| `WIREGUARD_MTU` | eth0 MTU − 80 | tunnel MTU |
| `WIREGUARD_IMPLEMENTATION` | `auto` | `auto`, `kernel` or `userspace` |

### Firewall

| Variable | Default | Description |
|---|---|---|
| `FIREWALL_OUTBOUND_SUBNETS` | | subnets reachable outside the tunnel, e.g. `192.168.0.0/16` |
| `FIREWALL_INPUT_PORTS` | | ports open on `eth0` from anywhere |
| `FIREWALL_VPN_INPUT_PORTS` | | ports open on the tunnel |
| `FIREWALL_ENABLED` | `on` | disables the kill-switch when `off` (don't) |

The container's Docker network is always reachable, and published ports work from any client
address.

### DNS

| Variable | Default | Description |
|---|---|---|
| `DNS_SERVER` | `on` | local DNS server; `off` points `resolv.conf` straight at the upstreams |
| `DNS_UPSTREAM_RESOLVER_TYPE` | `dot` | `dot`, `doh` or `plain` |
| `DNS_UPSTREAM_RESOLVERS` | `cloudflare` | list of `cloudflare`, `google`, `quad9`, `mullvad` |
| `DNS_UPSTREAM_PLAIN_ADDRESSES` | | plain resolvers, e.g. `1.1.1.1,9.9.9.9:53` |
| `DNS_CACHING` | `on` | response cache |

### Health

| Variable | Default | Description |
|---|---|---|
| `HEALTH_TARGET_ADDRESSES` | `cloudflare.com:443,github.com:443` | TCP targets dialed through the tunnel |
| `HEALTH_CHECK_INTERVAL` | `30s` | interval between checks |
| `HEALTH_FAILURES_BEFORE_RESTART` | `3` | consecutive failures before reconnecting |
| `HEALTH_RESTART_VPN` | `on` | reconnect automatically |
| `HEALTH_SERVER_ADDRESS` | `127.0.0.1:9999` | server queried by `ferrotun healthcheck` |

### Port forwarding (PIA)

| Variable | Default | Description |
|---|---|---|
| `VPN_PORT_FORWARDING` | `off` | enables port forwarding |
| `VPN_PORT_FORWARDING_PROVIDER` | `private internet access` | only PIA is supported |
| `VPN_PORT_FORWARDING_USERNAME` / `_PASSWORD` | | PIA credentials (`p1234567`) |
| `VPN_PORT_FORWARDING_SERVER_NAME` | | PIA server TLS name, e.g. `amsterdam425` |
| `VPN_PORT_FORWARDING_GATEWAY` | auto | PIA API gateway (default: first host of the WireGuard address's /17, then the server IP) |
| `VPN_PORT_FORWARDING_STATUS_FILE` | `/tmp/ferrotun/forwarded_port` | file containing the port |
| `VPN_PORT_FORWARDING_DATA_FILE` | `/ferrotun/portforward.json` | persisted token and signature |
| `VPN_PORT_FORWARDING_UP_COMMAND` | | shell command run with the port (`{{PORTS}}`, `{{PORT}}`, `{{VPN_INTERFACE}}`) |
| `VPN_PORT_FORWARDING_DOWN_COMMAND` | | shell command run when the port is no longer valid |
| `VPN_PORT_FORWARDING_LISTENING_PORT` | | redirects the forwarded port to this local port |
| `QBITTORRENT_URL` | | e.g. `http://127.0.0.1:8080`, enables the port sync |
| `QBITTORRENT_USERNAME` / `QBITTORRENT_PASSWORD` | | WebUI credentials (not needed with localhost auth bypass) |

### Other

| Variable | Default | Description |
|---|---|---|
| `HTTP_CONTROL_SERVER_ADDRESS` | `:8000` | control API (`off` to disable) |
| `HTTP_CONTROL_SERVER_API_KEY` | | requires `X-API-Key` (or `Authorization: Bearer`) |
| `HTTP_CONTROL_SERVER_LOG` | `on` | logs requests |
| `PUBLICIP_ENABLED` / `PUBLICIP_FILE` | `on` / `/tmp/ferrotun/ip` | public IP lookup |
| `PUID` / `PGID` | | owner of written files |
| `LOG_LEVEL` | `info` | `debug` also prints the generated nftables ruleset |

## Control API

| Method | Route | Response |
|---|---|---|
| GET | `/v1/publicip/ip` | `{"public_ip":"...","country":"...","region":"...","city":"...",...}` |
| GET | `/v1/portforward` | `{"port":53117}` (`null` without a forwarded port) |
| GET | `/v1/vpn/status` | `{"status":"running"}` or `stopped` |
| PUT | `/v1/vpn/status` | body `{"status":"stopped"}`, `running` or `restarted` |
| GET | `/v1/status` | details: tunnel, last handshake, transferred bytes, reconnections, ... |

## How it works

On startup, in order:

1. detect the Docker network (default route, subnet, MTU) over netlink;
2. **kill-switch**: `inet ferrotun` table, everything blocked except loopback and the local network;
3. policy routing:

   | prio | rule | effect |
   |---|---|---|
   | 98 | `to <Docker subnet> lookup main` | Docker network stays reachable |
   | 99 | `to <FIREWALL_OUTBOUND_SUBNETS> lookup 199` | LAN reachable outside the tunnel |
   | 100 | `from <eth0 IP> lookup 200` | replies to connections received on `eth0` |
   | 101 | `not fwmark 0xca6c lookup 51820` | **everything else goes through the tunnel** |

4. allow UDP to the WireGuard server, only for packets marked `0xca6c` (sent by WireGuard itself);
5. start the local DNS server and rewrite `/etc/resolv.conf` (shared with `network_mode: service:`
   containers);
6. create the WireGuard interface, health check, then public IP and port forwarding.

If the tunnel goes down, table 51820 empties, traffic falls back to the Docker route and the
firewall drops it. The output chain has no generic "established" rule: `eth0` only carries
replies to connections that came in on `eth0` (conntrack mark), so a download started through the
tunnel cannot continue outside of it.

## Development

No local Rust toolchain needed, everything runs in Docker:

```bash
# unit tests (cargo cache in target/, files owned by you)
docker run --rm --user "$(id -u):$(id -g)" -e CARGO_HOME=/src/target/.cargo \
  -v "$PWD":/src -w /src rust:1.99-alpine3.24 cargo test

# image
docker build -t ferrotun:dev .

# end-to-end tests: real WireGuard server, mock PIA API, real qBittorrent
./tests/e2e.sh
EXTRA_ENV="-e WIREGUARD_IMPLEMENTATION=userspace" IMPL_LOG=userspace ./tests/e2e.sh
```

The e2e script checks for leaks while the tunnel is down, DNS, published ports, the API, port
forwarding and the qBittorrent sync. It only creates containers and networks prefixed with
`ferrotun-e2e` and removes them on exit.

| Module | Purpose |
|---|---|
| `config.rs` | environment variables |
| `wgconf.rs` | `wg0.conf` parser |
| `netlink.rs`, `routing.rs` | links, addresses, routes and rules over rtnetlink |
| `firewall.rs` | nftables ruleset generation and atomic apply |
| `wireguard.rs` | WireGuard interface (kernel / wireguard-go) |
| `dns.rs` | DNS server, cache, DoT / DoH / plain, `resolv.conf` |
| `health.rs` | health checks, `ferrotun healthcheck` |
| `portforward.rs`, `qbittorrent.rs` | PIA port forwarding, qBittorrent sync |
| `control.rs` | HTTP API |
| `supervisor.rs` | startup and reconnection logic |

## Roadmap

- native PIA provider (WireGuard key exchange through the PIA API, region selection)
- OpenVPN
- other port forwarding providers (ProtonVPN NAT-PMP)
- built-in HTTP / SOCKS5 proxy
- Prometheus metrics
