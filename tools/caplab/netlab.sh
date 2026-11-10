#!/bin/bash
# Real-TCP lab: client in its own network namespace behind a veth pair with netem, real TUN,
# iperf3 through the tunnel, tcpdump on the host side. Runs Obsidian builds, Xray
# VLESS+REALITY+Vision and kernel WireGuard under the same link conditions.
#
# Needs root, iproute2, tc, iperf3, tcpdump, a built ~/capw/out/{server,caph}-<v> per version and
# ~/capw/out/xray. Usage:
#   DELAY=25ms LOSS=0.5% RATE=100mbit VERSIONS="rel r2" MODES="reality native" T=10 netlab.sh
set -u
OUT=~/capw/out
LAB=~/capw/netlab
mkdir -p "$LAB"
DELAY=${DELAY:-25ms}
LOSS=${LOSS:-0.5%}
RATE=${RATE:-100mbit}
T=${T:-10}
VERSIONS=${VERSIONS:-"rel r2"}
MODES=${MODES:-"reality native"}
TAG=${TAG:-$(echo "d${DELAY}-l${LOSS}-r${RATE}" | tr -d '%')}
RES="$LAB/$TAG"
mkdir -p "$RES"

ns() { ip netns exec cli "$@"; }

setup() {
  ip netns del cli 2>/dev/null
  ip link del vh 2>/dev/null
  ip netns add cli
  ip link add vh type veth peer name vc
  ip link set vc netns cli
  ip addr add 172.31.0.1/30 dev vh
  ip link set vh up
  ns ip addr add 172.31.0.2/30 dev vc
  ns ip link set vc up
  ns ip link set lo up
  tc qdisc add dev vh root netem delay "$DELAY" loss "$LOSS" rate "$RATE" limit 10000
  ns tc qdisc add dev vc root netem delay "$DELAY" loss "$LOSS" rate "$RATE" limit 10000
  pkill -x iperf3 2>/dev/null
  iperf3 -s -D --logfile "$LAB/iperf3-server.log"
  sleep 0.5
}

cpu_of() { # utime+stime of a pid, in clock ticks
  awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0
}

run_iperf() { # name target extra-args
  local name=$1 target=$2; shift 2
  ns iperf3 -c "$target" -t "$T" -O 2 -J "$@" > "$RES/$name.json" 2>&1
  python3 -c "import json,sys; d=json.load(open('$RES/$name.json')); e=d.get('end',{}); s=e.get('sum_received') or e.get('sum',{}); print(round(s.get('bits_per_second',0)/1e6,1))" 2>/dev/null || echo 0
}

keys() {
  eval "$("$OUT/server-r2" -gen-keys | sed -n 's/^server_private_key: */SPRIV=/p; s/^server_public_key: */SPUB=/p; s/^reality_private_key: */RPRIV=/p; s/^reality_public_key: */RPUB=/p; s/^reality_short_id: */SID=/p')"
  CPRIV=$("$OUT/server-r2" -gen-keys | sed -n 's/^server_private_key: *//p')
  AUTH=$(head -c16 /dev/urandom | xxd -p)
}

obsidian() { # version mode
  local v=$1 mode=$2 name="obs-$1-$2"
  local srv='"host":"172.31.0.1","port":"8443","protocol_version":2,"tun_interface":"obtun0","tun_address":"10.8.0.1/24","mtu":1420,"disable_dns_proxy":true,"enable_udp_data":false,"profile":"fast-secure","jitter":"off","tcp_congestion":"bbr"'
  local cli='"server_host":"172.31.0.1","server_port":"8443","protocol_version":2,"tun_address":"10.8.0.2/24","dns":"10.8.0.1","mtu":1420,"enable_udp_data":false,"profile":"fast-secure","jitter":"off","fingerprint":"chrome"'
  if [ "$mode" = native ]; then
    echo "{$srv,\"transport\":\"native-reality\",\"server_private_key\":\"$SPRIV\",\"server_public_key\":\"$SPUB\",\"reality_private_key\":\"$RPRIV\",\"reality_short_ids\":[\"$SID\"],\"reality_target\":\"www.microsoft.com:443\",\"reality_server_names\":[\"www.microsoft.com\"]}" > "$RES/$name.srv.json"
    echo "{$cli,\"transport\":\"native-reality\",\"server_public_key\":\"$SPUB\",\"client_private_key\":\"$CPRIV\",\"reality_public_key\":\"$RPUB\",\"reality_short_id\":\"$SID\",\"reality_sni\":\"www.microsoft.com\",\"allow_direct_udp\":false}" > "$RES/$name.cli.json"
  else
    echo "{$srv,\"server_private_key\":\"$SPRIV\",\"server_public_key\":\"$SPUB\",\"reality_target\":\"www.microsoft.com:443\",\"reality_server_names\":[\"www.microsoft.com\"],\"reality_auth_key\":\"$AUTH\"}" > "$RES/$name.srv.json"
    echo "{$cli,\"server_public_key\":\"$SPUB\",\"client_private_key\":\"$CPRIV\",\"reality_enabled\":true,\"reality_sni\":\"www.microsoft.com\",\"reality_auth_key\":\"$AUTH\"}" > "$RES/$name.cli.json"
  fi
  "$OUT/server-$v" -config "$RES/$name.srv.json" > "$RES/$name.server.log" 2>&1 &
  local spid=$!
  sleep 1.5
  tcpdump -i vh -U -s "${SNAP:-0}" -w "$RES/$name.pcap" tcp port 8443 > /dev/null 2>&1 &
  local dpid=$!
  sleep 0.5
  local t0=$(date +%s%N)
  ns env CAPH_TUN=ctun "$OUT/caph-$v" "$RES/$name.cli.json" > "$RES/$name.client.log" 2>&1 &
  local cpid=$!
  for _ in $(seq 1 200); do grep -q "PHASE connected" "$RES/$name.client.log" && break; sleep 0.05; done
  local t1=$(date +%s%N)
  if ! grep -q "PHASE connected" "$RES/$name.client.log"; then
    echo "$name: did not connect"; cat "$RES/$name.client.log"
    kill $cpid $spid $dpid 2>/dev/null; sleep 1; return
  fi
  ns ip link set ctun up mtu 1420
  ns ip addr add 10.8.0.2/24 dev ctun
  sleep 0.5
  local c0=$(( $(cpu_of $cpid) + $(cpu_of $spid) ))
  local down=$(run_iperf "$name.down" 10.8.0.1 -R)
  local up=$(run_iperf "$name.up" 10.8.0.1)
  local c1=$(( $(cpu_of $cpid) + $(cpu_of $spid) ))
  echo "$name connect_ms=$(( (t1-t0)/1000000 )) down_mbit=$down up_mbit=$up cpu_s=$(echo "scale=2; ($c1-$c0)/100" | bc)" | tee -a "$RES/summary.txt"
  kill -INT $cpid; sleep 0.5
  kill -INT $spid; sleep 0.5
  kill -INT $dpid; sleep 0.5
  kill -9 $cpid $spid 2>/dev/null
}

xray() {
  local name=xray-vision
  local kp; kp=$("$OUT/xray" x25519)
  local xpriv; xpriv=$(echo "$kp" | sed -n 's/^Private[Kk]ey: *//p; s/^PrivateKey: *//p' | head -1)
  local xpub; xpub=$(echo "$kp" | sed -n 's/^Password.*: *//p; s/^Public[Kk]ey: *//p' | head -1)
  local uuid; uuid=$("$OUT/xray" uuid)
  local sid; sid=$(head -c8 /dev/urandom | xxd -p)
  cat > "$RES/$name.srv.json" <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"172.31.0.1","port":9443,"protocol":"vless",
   "settings":{"clients":[{"id":"$uuid","flow":"xtls-rprx-vision"}],"decryption":"none"},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"www.microsoft.com:443","serverNames":["www.microsoft.com"],"privateKey":"$xpriv","shortIds":["$sid"]}}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]}
EOF
  cat > "$RES/$name.cli.json" <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":5201,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":5201,"network":"tcp"}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"172.31.0.1","port":9443,"users":[{"id":"$uuid","flow":"xtls-rprx-vision","encryption":"none"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","fingerprint":"chrome","publicKey":"$xpub","shortId":"$sid"}}}]}
EOF
  "$OUT/xray" run -c "$RES/$name.srv.json" > "$RES/$name.server.log" 2>&1 &
  local spid=$!
  ns "$OUT/xray" run -c "$RES/$name.cli.json" > "$RES/$name.client.log" 2>&1 &
  local cpid=$!
  sleep 1.5
  tcpdump -i vh -U -s "${SNAP:-0}" -w "$RES/$name.pcap" tcp port 9443 > /dev/null 2>&1 &
  local dpid=$!
  sleep 0.5
  local c0=$(( $(cpu_of $cpid) + $(cpu_of $spid) ))
  local down=$(run_iperf "$name.down" 127.0.0.1 -R)
  local up=$(run_iperf "$name.up" 127.0.0.1)
  local c1=$(( $(cpu_of $cpid) + $(cpu_of $spid) ))
  echo "$name down_mbit=$down up_mbit=$up cpu_s=$(echo "scale=2; ($c1-$c0)/100" | bc)" | tee -a "$RES/summary.txt"
  kill -INT $cpid $spid $dpid; sleep 1
  kill -9 $cpid $spid 2>/dev/null
}

wireguard() {
  local name=wireguard
  local sk ck; sk=$(wg genkey 2>/dev/null) || { echo "$name: wg tool missing"; return; }
  ck=$(wg genkey)
  ip link add wgs type wireguard
  wg set wgs listen-port 51820 private-key <(echo "$sk") peer "$(echo "$ck" | wg pubkey)" allowed-ips 10.9.0.2/32
  ip addr add 10.9.0.1/24 dev wgs; ip link set wgs up mtu 1420
  ns ip link add wgc type wireguard
  ns wg set wgc private-key <(echo "$ck") peer "$(echo "$sk" | wg pubkey)" endpoint 172.31.0.1:51820 allowed-ips 10.9.0.0/24
  ns ip addr add 10.9.0.2/24 dev wgc; ns ip link set wgc up mtu 1420
  sleep 0.5
  local down=$(run_iperf "$name.down" 10.9.0.1 -R)
  local up=$(run_iperf "$name.up" 10.9.0.1)
  echo "$name down_mbit=$down up_mbit=$up (kernel, CPU not counted)" | tee -a "$RES/summary.txt"
  ip link del wgs; ns ip link del wgc
}

setup
keys
: > "$RES/summary.txt"
echo "link: delay $DELAY each way, loss $LOSS, rate $RATE, iperf $T s" | tee -a "$RES/summary.txt"
for v in $VERSIONS; do for m in $MODES; do obsidian "$v" "$m"; done; done
[ "${SKIP_XRAY:-}" ] || xray
[ "${SKIP_WG:-}" ] || wireguard
pkill -x iperf3
