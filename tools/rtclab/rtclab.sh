#!/bin/bash
# RTC lab: how calls (Discord voice, Telegram/WhatsApp calls, games) fare through the tunnel.
# Client in netns "cli" with the real client engine on a real TUN, server on the host, and a
# voice server (tools/rtclab/udpecho) in netns "inet" behind the server's NAT. tools/rtclab/rtcprobe
# runs a Discord-like IP discovery, a datagram size sweep and a 50 pps voice stream, and reports
# loss and the longest gap.
#
# Needs root, iproute2, iptables. Build first with BUILD=1 (or put the binaries in $OUT).
# Env: UDP=1|0 (direct UDP data channel), MODE=reality|native, DELAY/LOSS (netem, if available),
#      HOST_BLOCK / PRE_BLOCK (iptables commands on the host / in the client netns before
#      connecting), POST_BLOCK (in the client netns after connecting), SETTLE, PROBE_ARGS.
# Examples:
#   BUILD=1 tools/rtclab/rtclab.sh
#   PRE_BLOCK="iptables -A INPUT -p udp --sport 8443 -j DROP" SETTLE=1 PROBE_ARGS="-skip -d 40" tools/rtclab/rtclab.sh
#   HOST_BLOCK="iptables -I INPUT -i vh -p udp --dport 8443 -m hashlimit --hashlimit-above 20/sec --hashlimit-name ul -j DROP" PROBE_ARGS="-skip -d 60" tools/rtclab/rtclab.sh
set -u
OUT=${OUT:-/tmp/rtclab/out}
RES=${RES:-/tmp/rtclab/res}
if [ -n "${BUILD:-}" ]; then
  repo=$(cd "$(dirname "$0")/../.." && pwd)
  mkdir -p "$OUT"
  (cd "$repo" && CGO_ENABLED=0 go build -o "$OUT/server" ./cmd/server && CGO_ENABLED=0 go build -o "$OUT/caph" ./tools/caplab/caph &&
    for t in rtcprobe udpecho tlstarget; do go build -o "$OUT/$t" ./tools/rtclab/$t || exit 1; done) || exit 1
fi
mkdir -p "$RES"
UDP=${UDP:-1}
MODE=${MODE:-reality}
DELAY=${DELAY:-0}
LOSS=${LOSS:-0%}
SNI=www.lab.test
ns() { ip netns exec cli "$@"; }
inet() { ip netns exec inet "$@"; }

cleanup() {
  iptables -D INPUT -i vh -p udp --dport 8443 -j DROP 2>/dev/null
  iptables -D OUTPUT -o vh -p udp --sport 8443 -j DROP 2>/dev/null
  iptables -S INPUT | grep -q hashlimit && iptables -D INPUT 1 2>/dev/null
  pkill -x caph 2>/dev/null; pkill -x server 2>/dev/null
  pkill -x udpecho 2>/dev/null; pkill -x tlstarget 2>/dev/null
  sleep 0.3
  ip netns del cli 2>/dev/null; ip netns del inet 2>/dev/null
  ip link del vh 2>/dev/null; ip link del vhi 2>/dev/null; ip link del obtun0 2>/dev/null
}
cleanup
sysctl -qw net.ipv4.ip_forward=1
ip netns add cli; ip netns add inet
ip link add vh type veth peer name vc; ip link set vc netns cli
ip addr add 172.31.0.1/30 dev vh; ip link set vh up
ns ip addr add 172.31.0.2/30 dev vc; ns ip link set vc up; ns ip link set lo up
ip link add vhi type veth peer name vi; ip link set vi netns inet
ip addr add 198.51.100.1/24 dev vhi; ip link set vhi up
inet ip addr add 198.51.100.2/24 dev vi; inet ip link set vi up; inet ip link set lo up
inet ip route add default via 198.51.100.1
if [ "$DELAY" != 0 ]; then
  tc qdisc add dev vh root netem delay "$DELAY" loss "$LOSS" limit 10000
  ns tc qdisc add dev vc root netem delay "$DELAY" loss "$LOSS" limit 10000
fi
inet "$OUT/udpecho" 198.51.100.2:50001 > "$RES/udpecho.log" 2>&1 &
"$OUT/tlstarget" 127.0.0.1:4443 > "$RES/tls.log" 2>&1 &

eval "$("$OUT/server" -gen-keys | sed -n 's/^server_private_key: */SPRIV=/p; s/^server_public_key: */SPUB=/p; s/^reality_private_key: */RPRIV=/p; s/^reality_public_key: */RPUB=/p; s/^reality_short_id: */SID=/p')"
CPRIV=$("$OUT/server" -gen-keys | sed -n 's/^server_private_key: *//p')
AUTH=$(python3 -c "import os;print(os.urandom(32).hex())")
EU=false; [ "$UDP" = 1 ] && EU=true
SRV='"host":"0.0.0.0","port":"8443","protocol_version":2,"tun_interface":"obtun0","tun_address":"10.8.0.1/24","mtu":1420,"out_interface":"vhi","dns_upstream":"198.51.100.2:53","dns_listen":"10.8.0.1:53","disable_dns_proxy":false,"enable_ipv6":false,"udp_port":"8443","enable_udp_data":'$EU',"udp_socket_buffer_mb":4,"tcp_congestion":"bbr","junk_count":7,"junk_min":50,"junk_max":1000,"noise_min_sec":10,"noise_max_sec":40,"keepalive_sec":20,"profile":"fast-secure","jitter":"off"'"${SRV_EXTRA:+,$SRV_EXTRA}"
CLI='"server_host":"172.31.0.1","server_port":"8443","protocol_version":2,"tun_address":"10.8.0.2/24","dns":"10.8.0.1","mtu":1420,"udp_port":"8443","enable_udp_data":'$EU',"profile":"fast-secure","jitter":"off","fingerprint":"chrome","keepalive_sec":20'"${CLI_EXTRA:+,$CLI_EXTRA}"
if [ "$MODE" = native ]; then
  echo "{$SRV,\"transport\":\"native-reality\",\"server_private_key\":\"$SPRIV\",\"server_public_key\":\"$SPUB\",\"reality_private_key\":\"$RPRIV\",\"reality_short_ids\":[\"$SID\"],\"reality_target\":\"127.0.0.1:4443\",\"reality_server_names\":[\"$SNI\"],\"reality_auth_key\":\"$AUTH\"}" > "$RES/srv.json"
  echo "{$CLI,\"transport\":\"native-reality\",\"server_public_key\":\"$SPUB\",\"client_private_key\":\"$CPRIV\",\"reality_public_key\":\"$RPUB\",\"reality_short_id\":\"$SID\",\"reality_sni\":\"$SNI\",\"allow_direct_udp\":$EU,\"reality_auth_key\":\"$AUTH\"}" > "$RES/cli.json"
else
  echo "{$SRV,\"server_private_key\":\"$SPRIV\",\"server_public_key\":\"$SPUB\",\"reality_target\":\"127.0.0.1:4443\",\"reality_server_names\":[\"$SNI\"],\"reality_auth_key\":\"$AUTH\"}" > "$RES/srv.json"
  echo "{$CLI,\"server_public_key\":\"$SPUB\",\"client_private_key\":\"$CPRIV\",\"reality_enabled\":true,\"reality_sni\":\"$SNI\",\"reality_auth_key\":\"$AUTH\"}" > "$RES/cli.json"
fi
[ -n "${HOST_BLOCK:-}" ] && sh -c "$HOST_BLOCK"
[ -n "${PRE_BLOCK:-}" ] && ns sh -c "$PRE_BLOCK"
"$OUT/server" -config "$RES/srv.json" > "$RES/server.log" 2>&1 &
for _ in $(seq 1 200); do grep -q "listening on" "$RES/server.log" && break; sleep 0.05; done
sleep 0.5
ip netns exec cli env CAPH_TUN=ctun "$OUT/caph" "$RES/cli.json" > "$RES/client.log" 2>&1 &
for _ in $(seq 1 200); do grep -q "PHASE connected" "$RES/client.log" && break; sleep 0.05; done
grep -q "PHASE connected" "$RES/client.log" || { echo "did not connect"; tail -20 "$RES/client.log" "$RES/server.log"; exit 1; }
ns ip link set ctun up mtu "${CLI_MTU:-1420}"
ns ip addr add 10.8.0.2/24 dev ctun
ns ip route add 198.51.100.0/24 dev ctun
[ -n "${POST_BLOCK:-}" ] && ns sh -c "$POST_BLOCK"
sleep ${SETTLE:-0.5}
if [ -n "${NOPROBE:-}" ]; then exit 0; fi
ns "$OUT/rtcprobe" ${PROBE_ARGS:-}
rc=$?
[ -z "${KEEP:-}" ] && cleanup
exit $rc
