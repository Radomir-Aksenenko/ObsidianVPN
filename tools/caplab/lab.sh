#!/bin/bash
# Capture lab: runs the same scripted session against main and branch cores and records pcaps.
# Build first: caph-<v> from tools/caplab/caph and server-<v> from cmd/server of each tree,
# into ~/capw/out. Needs sudo, tcpdump and tshark. Usage: MODES="reality native" RUNS=6 lab.sh
set -u
OUT=~/capw/out
CFG=~/capw/cfg
PC=~/capw/pcap
mkdir -p "$CFG" "$PC"
# Fresh throwaway keys for every lab run.
eval "$("$OUT/server-branch" -gen-keys | sed -n 's/^server_private_key: */SPRIV=/p; s/^server_public_key: */SPUB=/p; s/^reality_private_key: */RPRIV=/p; s/^reality_public_key: */RPUB=/p; s/^reality_short_id: */SID=/p')"
CPRIV=$("$OUT/server-branch" -gen-keys | sed -n 's/^server_private_key: *//p')
AUTH=$(head -c16 /dev/urandom | xxd -p)

common_srv='"host":"127.0.0.1","port":"8443","protocol_version":2,"tun_interface":"obtun0","tun_address":"10.8.0.1/24","mtu":1420,"disable_dns_proxy":true,"enable_udp_data":false,"profile":"fast-secure","jitter":"off","noise_min_sec":10,"noise_max_sec":40,"keepalive_sec":20'
common_cli='"server_host":"127.0.0.1","server_port":"8443","protocol_version":2,"tun_address":"10.8.0.2/24","dns":"10.8.0.1","mtu":1420,"enable_udp_data":false,"profile":"fast-secure","jitter":"off","noise_min_sec":10,"noise_max_sec":40,"keepalive_sec":20,"fingerprint":"chrome"'

cat > "$CFG/srv-reality.json" <<EOF
{$common_srv,"server_private_key":"$SPRIV","server_public_key":"$SPUB","reality_target":"www.microsoft.com:443","reality_server_names":["www.microsoft.com"],"reality_auth_key":"$AUTH"}
EOF
cat > "$CFG/cli-reality.json" <<EOF
{$common_cli,"server_public_key":"$SPUB","client_private_key":"$CPRIV","reality_enabled":true,"reality_sni":"www.microsoft.com","reality_auth_key":"$AUTH"}
EOF
cat > "$CFG/srv-native.json" <<EOF
{$common_srv,"transport":"native-reality","server_private_key":"$SPRIV","server_public_key":"$SPUB","reality_private_key":"$RPRIV","reality_short_ids":["$SID"],"reality_target":"www.microsoft.com:443","reality_server_names":["www.microsoft.com"]}
EOF
cat > "$CFG/cli-native.json" <<EOF
{$common_cli,"transport":"native-reality","server_public_key":"$SPUB","client_private_key":"$CPRIV","reality_public_key":"$RPUB","reality_short_id":"$SID","reality_sni":"www.microsoft.com","allow_direct_udp":false}
EOF

modes=${MODES:-"reality native"}
runs=${RUNS:-6}
for mode in $modes; do
  for v in main branch; do
    for i in $(seq 1 "$runs"); do
      tag="$mode-$v-$i"
      sudo -n "$OUT/server-$v" -config "$CFG/srv-$mode.json" > "$PC/$tag.server.log" 2>&1 &
      sleep 1.5
      sudo -n tcpdump -i lo -U -s 0 -w "$PC/$tag.pcap" tcp port 8443 > /dev/null 2>&1 &
      sleep 0.7
      timeout 60 "$OUT/caph-$v" "$CFG/cli-$mode.json" > "$PC/$tag.client.log" 2>&1
      echo "$tag exit=$? $(grep RX "$PC/$tag.client.log")"
      sleep 0.5
      sudo -n pkill -INT -x tcpdump
      sudo -n pkill -INT -f "^$OUT/server-$v"
      sleep 1
      sudo -n pkill -9 -f "^$OUT/server-$v" 2>/dev/null; true
    done
  done
done
