#!/usr/bin/env bash
# End-to-end tests against a real local WireGuard server.
#
#   ./tests/e2e.sh                 (tests ferrotun:dev)
#   IMAGE=ferrotun:latest ./tests/e2e.sh
#   EXTRA_ENV="-e WIREGUARD_IMPLEMENTATION=userspace" IMPL_LOG=userspace ./tests/e2e.sh
#   EXTRA_ENV="-e DNS_UPSTREAM_RESOLVER_TYPE=doh" ./tests/e2e.sh
#
# Topology:
#   ferrotun-e2e-wan: WireGuard server (UDP 51820 published on the host IP), NAT to the Internet
#   ferrotun-e2e-lan: ferrotun, an "app" container sharing its network namespace, and a "peer"
#
# Only containers and networks prefixed with ferrotun-e2e are created, and they are removed on exit.

set -uo pipefail

IMAGE=${IMAGE:-ferrotun:dev}
EXTRA_ENV=${EXTRA_ENV:-}
# Expected WireGuard implementation in the logs: "kernel" or "userspace"
IMPL_LOG=${IMPL_LOG:-kernel}
P=ferrotun-e2e
TOOLS=$P-tools
HOST_IP=${HOST_IP:-$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "src") print $(i + 1)}')}
WORK=$(mktemp -d)
PASS=0
FAIL=0

ok() { echo "  ✔ $*"; PASS=$((PASS + 1)); }
ko() { echo "  ✘ $*"; FAIL=$((FAIL + 1)); }
# check / check_not: the command must succeed / fail; check_eq: its output must match
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else ko "$d"; fi; }
check_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ko "$d"; else ok "$d"; fi; }
check_eq() {
  local d=$1 want=$2; shift 2
  local got; got=$("$@" 2>/dev/null | tr -d '\r' | head -c 300)
  if [ "$got" = "$want" ]; then ok "$d"; else ko "$d (expected '$want', got '$got')"; fi
}
section() { echo; echo "== $*"; }

app() { docker exec $P-app "$@"; }
srv() { docker exec $P-server "$@"; }
peer() { docker exec $P-peer "$@"; }
api() { peer curl -s -m 5 -H "X-API-Key: e2e-secret" "http://172.29.77.10:8000$1"; }
VPN=$P-vpn
vpn_healthy() { docker exec $VPN ferrotun healthcheck; }
wait_for() { # wait_for <seconds> command...
  local t=$1; shift
  for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
server_tx() { srv wg show wg0 transfer | awk '{print $3}'; }

remove_containers() {
  docker rm -f $P-app $P-qbit $P-vpn $P-vpn2 $P-mockpia $P-server $P-peer >/dev/null 2>&1
  docker network rm $P-lan $P-wan >/dev/null 2>&1
}
cleanup() {
  remove_containers
  rm -rf "$WORK"
}
trap cleanup EXIT
remove_containers

section "Setup (host IP: $HOST_IP, image: $IMAGE)"
docker build -q -t $TOOLS - >/dev/null <<'EOF'
FROM alpine:3.24
RUN apk add --no-cache curl bind-tools wireguard-tools-wg iptables busybox-extras iproute2
EOF
docker run --rm $TOOLS sh -c 'umask 077; wg genkey | tee /dev/stderr | wg pubkey' 2>"$WORK/client.key" >"$WORK/client.pub"
docker run --rm $TOOLS sh -c 'umask 077; wg genkey | tee /dev/stderr | wg pubkey' 2>"$WORK/server.key" >"$WORK/server.pub"
mkdir -p "$WORK/www/cgi-bin" "$WORK/config" "$WORK/shared"
printf '#!/bin/sh\nprintf "Content-Type: text/plain\\r\\n\\r\\n%%s\\n" "$REMOTE_ADDR"\n' >"$WORK/www/cgi-bin/ip"
chmod 755 "$WORK/www/cgi-bin/ip"
cat >"$WORK/config/wg0.conf" <<EOF
[Interface]
PrivateKey = $(cat "$WORK/client.key")
Address = 10.66.0.2/32
DNS = 10.66.0.1

[Peer]
PublicKey = $(cat "$WORK/server.pub")
AllowedIPs = 0.0.0.0/0
Endpoint = $HOST_IP:51820
PersistentKeepalive = 25
EOF

docker network create --subnet 172.29.78.0/24 $P-wan >/dev/null
docker network create --subnet 172.29.77.0/24 -o com.docker.network.driver.mtu=1400 $P-lan >/dev/null

docker run -d --name $P-server --network $P-wan --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
  -p "$HOST_IP:51820:51820/udp" -p "$HOST_IP:18082:8082" -v "$WORK:/keys:ro" $TOOLS sh -c '
    ip link add wg0 type wireguard &&
    wg set wg0 listen-port 51820 private-key /keys/server.key peer "$(cat /keys/client.pub)" allowed-ips 10.66.0.2/32 &&
    ip addr add 10.66.0.1/24 dev wg0 && ip link set wg0 up &&
    iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE &&
    httpd -p 10.66.0.1:8000 -h /keys/www && httpd -p 8082 -h /keys/www && exec sleep infinity' >/dev/null

docker run -d --name $P-peer --network $P-lan --ip 172.29.77.20 $TOOLS \
  sh -c 'mkdir -p /w && echo peer-ok >/w/index.html && exec httpd -f -p 8081 -h /w' >/dev/null

# start_vpn <name> [extra docker options...]
start_vpn() {
  local name=$1; shift
  docker run -d --name "$name" --network $P-lan --ip 172.29.77.10 --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 --sysctl net.ipv6.conf.default.disable_ipv6=1 \
    -e FIREWALL_OUTBOUND_SUBNETS=192.168.0.0/16 \
    -e HTTP_CONTROL_SERVER_API_KEY=e2e-secret \
    -e HEALTH_CHECK_INTERVAL=10s -e HEALTH_FAILURES_BEFORE_RESTART=2 \
    -e PUID="$(id -u)" -e PGID="$(id -g)" \
    -v "$WORK/config:/ferrotun" -v "$WORK/shared:/tmp/ferrotun" \
    $EXTRA_ENV "$@" "$IMAGE" >/dev/null
}
start_vpn $P-vpn -p 127.0.0.1:18080:8080 -p "$HOST_IP:18080:8080"

section "Startup"
if wait_for 90 vpn_healthy; then ok "ferrotun becomes healthy"; else ko "ferrotun becomes healthy"; docker logs $VPN 2>&1 | tail -30; exit 1; fi
check "log 'VPN connected'" sh -c "docker logs $P-vpn 2>&1 | grep -q 'VPN connected'"
check "WireGuard $IMPL_LOG in use" sh -c "docker logs $P-vpn 2>&1 | grep -q 'WireGuard ($IMPL_LOG'"
docker run -d --name $P-app --network container:$P-vpn $TOOLS \
  sh -c 'mkdir -p /w && echo app-ok >/w/index.html && exec httpd -f -p 8080 -h /w' >/dev/null
sleep 1

section "Tunnel traffic"
check_eq "server sees the tunnel IP (10.66.0.2)" "10.66.0.2" app curl -s -m 5 http://10.66.0.1:8000/cgi-bin/ip
check "Internet route via wg0" sh -c "docker exec $P-app ip route get 1.1.1.1 | grep -q 'dev wg0'"
tx0=$(server_tx)
check "HTTPS download from the Internet" app curl -sf -m 30 -o /dev/null "https://speed.cloudflare.com/__down?bytes=2000000"
tx1=$(server_tx)
if [ $((tx1 - tx0)) -gt 2000000 ]; then ok "2 MB went through the WireGuard server ($((tx1 - tx0)) bytes)"; else ko "traffic not seen by the server ($((tx1 - tx0)) bytes)"; fi

section "DNS"
check "shared resolv.conf -> 127.0.0.1" sh -c "docker exec $P-app cat /etc/resolv.conf | grep -q '^nameserver 127.0.0.1'"
check "Internet name resolution (through the tunnel)" app nslookup -timeout=5 example.com
check "container name resolution (Docker DNS)" app nslookup -timeout=5 $P-peer
check "resolution over TCP" app dig +tcp +short +time=5 cloudflare.com

section "Local network and published ports"
check_eq "neighbour container reachable by name" "peer-ok" app curl -s -m 5 http://$P-peer:8081/
# Reachable, and not through the tunnel (the server would see 10.66.0.2).
seen=$(app curl -s -m 5 "http://$HOST_IP:18082/cgi-bin/ip" | tr -d '\r\n')
if [ -n "$seen" ] && [ "$seen" != "10.66.0.2" ]; then ok "outbound subnet 192.168.0.0/16 reached outside the tunnel (seen source: $seen)"
else ko "outbound subnet 192.168.0.0/16 reached outside the tunnel (got '$seen')"; fi
check_eq "published port from the host (127.0.0.1)" "app-ok" curl -s -m 5 http://127.0.0.1:18080/
check_eq "published port via the LAN IP" "app-ok" curl -s -m 5 "http://$HOST_IP:18080/"
check_eq "published port from a network outside the allowed subnets" "app-ok" \
  docker run --rm $TOOLS curl -s -m 5 "http://$HOST_IP:18080/"

section "Control API"
check "GET /v1/publicip/ip" sh -c "docker exec $P-peer curl -s -m 5 -H 'X-API-Key: e2e-secret' http://172.29.77.10:8000/v1/publicip/ip | grep -q public_ip"
check_eq "API key required" "401" peer curl -s -m 5 -o /dev/null -w '%{http_code}' http://172.29.77.10:8000/v1/vpn/status
check_eq "GET /v1/vpn/status" '{"status":"running"}' api /v1/vpn/status
check_eq "GET /v1/portforward (no PF)" '{"port":null}' api /v1/portforward
check "public IP file owned by PUID" test -O "$WORK/shared/ip"

section "Kill-switch: server down"
srv ip link set wg0 down
sleep 2
check_not "Internet unreachable (tunnel broken)" app curl -s -m 4 http://1.1.1.1/
check_not "Internet DNS unreachable" app nslookup -timeout=2 -retry=1 github.com 1.1.1.1
check_not "bypass via eth0 blocked" app curl -s -m 4 --interface eth0 http://1.1.1.1/
check_eq "local network still reachable" "peer-ok" app curl -s -m 5 http://$P-peer:8081/
leaks=0
for _ in $(seq 1 20); do
  app curl -s -m 2 -o /dev/null http://1.1.1.1/ && leaks=$((leaks + 1))
  app curl -s -m 2 -o /dev/null --interface eth0 http://1.1.1.1/ && leaks=$((leaks + 1))
done
if [ $leaks -eq 0 ]; then ok "no leak during 40s of reconnections"; else ko "$leaks requests leaked"; fi
check "ferrotun detects the outage and reconnects" sh -c "docker logs $P-vpn 2>&1 | grep -q 'reconnecting VPN'"
check_eq "published port still works during the outage" "app-ok" curl -s -m 5 http://127.0.0.1:18080/

section "Recovery"
srv ip link set wg0 up
if wait_for 90 vpn_healthy; then ok "ferrotun healthy again"; else ko "ferrotun healthy again"; fi
check "Internet reachable again" app curl -sf -m 10 -o /dev/null https://www.cloudflare.com/

section "Stop / start via the API"
check_eq "PUT /v1/vpn/status stopped" '{"status":"stopped"}' \
  peer curl -s -m 5 -X PUT -H "X-API-Key: e2e-secret" -H 'content-type: application/json' -d '{"status":"stopped"}' http://172.29.77.10:8000/v1/vpn/status
sleep 1
check_eq "status stopped" '{"status":"stopped"}' api /v1/vpn/status
check_not "wg0 removed" app ip link show wg0
check_not "Internet blocked while the VPN is stopped" app curl -s -m 4 http://1.1.1.1/
check_not "healthcheck fails while the VPN is stopped" vpn_healthy
peer curl -s -m 5 -X PUT -H "X-API-Key: e2e-secret" -H 'content-type: application/json' -d '{"status":"running"}' \
  http://172.29.77.10:8000/v1/vpn/status >/dev/null
if wait_for 60 vpn_healthy; then ok "restarted via the API"; else ko "restarted via the API"; fi

section "Container stop"
docker stop -t 10 $P-vpn >/dev/null
check_eq "exit code 0 on SIGTERM" "0" docker inspect -f '{{.State.ExitCode}}' $P-vpn
check "log 'stopped cleanly'" sh -c "docker logs $P-vpn 2>&1 | grep -q 'stopped cleanly'"

section "PIA port forwarding (mock PIA API) with a real qBittorrent"
docker rm -f $P-app $P-vpn >/dev/null 2>&1
# Test CA and server certificate for the name "e2etest" (VPN_PORT_FORWARDING_SERVER_NAME).
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out "$WORK/config/test-ca.pem" -days 2 \
  -subj "/CN=ferrotun e2e CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/pia.key" -out "$WORK/pia.csr" -subj "/CN=e2etest" 2>/dev/null
printf 'subjectAltName=DNS:e2etest\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' >"$WORK/pia.ext"
openssl x509 -req -in "$WORK/pia.csr" -CA "$WORK/config/test-ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
  -out "$WORK/pia.pem" -days 2 -extfile "$WORK/pia.ext" 2>/dev/null
chmod 644 "$WORK"/*.key
cp "$(dirname "$0")/mock_pia.py" "$WORK/"
# PIA API on 10.66.0.1:19999 (first host of 10.66.0.2's /17), only reachable through the tunnel.
docker run -d --name $P-mockpia --network container:$P-server -v "$WORK:/keys:ro" python:3.13-alpine sh -c \
  'python3 /keys/mock_pia.py 10.66.0.1 19999 /keys/pia.pem /keys/pia.key & exec python3 /keys/mock_pia.py 10.66.0.1 8088' >/dev/null
# qBittorrent: WebUI 8090, admin / e2e-qbit-pass, initial listen port 6881.
mkdir -p "$WORK/qbit/qBittorrent"
python3 - "$WORK/qbit/qBittorrent/qBittorrent.conf" <<'PY'
import base64, hashlib, os, sys
salt = os.urandom(16)
key = hashlib.pbkdf2_hmac("sha512", b"e2e-qbit-pass", salt, 100000, 64)
open(sys.argv[1], "w").write(f"""[LegalNotice]
Accepted=true

[BitTorrent]
Session\\Port=6881

[Preferences]
WebUI\\Port=8090
WebUI\\Username=admin
WebUI\\Password_PBKDF2="@ByteArray({base64.b64encode(salt).decode()}:{base64.b64encode(key).decode()})"
""")
PY
VPN=$P-vpn2
start_vpn $VPN \
  -e VPN_PORT_FORWARDING=on -e "VPN_PORT_FORWARDING_PROVIDER=private internet access" \
  -e VPN_PORT_FORWARDING_USERNAME=p1234567 -e VPN_PORT_FORWARDING_PASSWORD=secret -e VPN_PORT_FORWARDING_SERVER_NAME=e2etest \
  -e PIA_API_CA_FILE=/ferrotun/test-ca.pem -e PIA_TOKEN_URL=http://10.66.0.1:8088/api/client/v2/token \
  -e "VPN_PORT_FORWARDING_UP_COMMAND=/bin/sh -c 'echo {{PORTS}} > /tmp/ferrotun/up-called'" \
  -e "VPN_PORT_FORWARDING_DOWN_COMMAND=/bin/sh -c 'echo {{PORTS}} > /tmp/ferrotun/down-called'" \
  -e QBITTORRENT_URL=http://127.0.0.1:8090 -e QBITTORRENT_USERNAME=admin -e QBITTORRENT_PASSWORD=e2e-qbit-pass
if wait_for 90 vpn_healthy; then ok "ferrotun (with PF) becomes healthy"; else ko "ferrotun (with PF) becomes healthy"; docker logs $VPN 2>&1 | tail -30; fi
check_eq "forwarded port written to forwarded_port" "40123" sh -c "sleep 3; cat '$WORK/shared/forwarded_port'"
check_eq "GET /v1/portforward" '{"port":40123}' api /v1/portforward
check "PF data saved (with payload)" sh -c "grep -q '\"payload\"' '$WORK/config/portforward.json'"
check_eq "up command run with {{PORTS}}" "40123" cat "$WORK/shared/up-called"
check "firewall: port 40123 open on wg0" sh -c "docker exec $VPN nft list table inet ferrotun | grep -q 'iifname \"wg0\" tcp dport 40123 accept'"
docker run -d --name $P-qbit --network container:$VPN -e PUID="$(id -u)" -e PGID="$(id -g)" -e WEBUI_PORT=8090 \
  -v "$WORK/qbit:/config" lscr.io/linuxserver/qbittorrent:latest >/dev/null
if wait_for 120 sh -c "docker logs $VPN 2>&1 | grep -q 'qBittorrent: listen port set to 40123'"; then
  ok "ferrotun sets qBittorrent's listen port"
else
  ko "ferrotun sets qBittorrent's listen port"; docker logs $VPN 2>&1 | grep -i qbit | tail -5
fi
qbit_prefs() {
  docker run --rm --network container:$VPN $TOOLS sh -c \
    'curl -s -c /tmp/c -d "username=admin&password=e2e-qbit-pass" http://127.0.0.1:8090/api/v2/auth/login >/dev/null &&
     curl -s -b /tmp/c http://127.0.0.1:8090/api/v2/app/preferences'
}
prefs=$(qbit_prefs 2>&1)
if echo "$prefs" | grep -q '"listen_port":40123'; then ok "qBittorrent reports listen_port=40123"; else ko "qBittorrent reports listen_port=40123 ($(echo "$prefs" | head -c 200))"; fi
check "forwarded port reachable from the Internet side (through the tunnel)" wait_for 30 srv nc -z -w 3 10.66.0.2 40123
check_not "qBittorrent WebUI NOT reachable through the tunnel" srv nc -z -w 3 10.66.0.2 8090
check_eq "a single signature requested" "1" sh -c "docker logs $P-mockpia 2>&1 | grep -c 'GET /getSignature'"

section "Restart reuses saved port forwarding data"
docker rm -f $P-qbit >/dev/null
docker stop -t 10 $VPN >/dev/null
check_eq "down command run on stop" "40123" cat "$WORK/shared/down-called"
check_not "forwarded_port removed on stop" test -e "$WORK/shared/forwarded_port"
binds=$(docker logs $P-mockpia 2>&1 | grep -c 'GET /bindPort')
docker start $VPN >/dev/null
if wait_for 90 vpn_healthy; then ok "restart"; else ko "restart"; fi
check "saved data reused" wait_for 20 sh -c "docker logs $VPN 2>&1 | grep -q 'found saved data for port 40123'"
check_eq "forwarded port restored" "40123" sh -c "sleep 3; cat '$WORK/shared/forwarded_port'"
check_eq "no new signature requested" "1" sh -c "docker logs $P-mockpia 2>&1 | grep -c 'GET /getSignature'"
check "bindPort called again with the saved payload" sh -c "[ \$(docker logs $P-mockpia 2>&1 | grep -c 'GET /bindPort') -gt $binds ]"

echo
echo "---- last ferrotun logs ----"
docker logs $VPN 2>&1 | tail -25
echo
echo "Result: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
