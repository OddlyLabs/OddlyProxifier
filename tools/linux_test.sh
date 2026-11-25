#!/bin/sh
# Transparent-mode check for Linux. Run as root:
#   sh linux_test.sh /path/to/dir-with-oddlyproxifier-and-testproxy
#
# Everything runs in its own network namespace, so the machine's own
# network rules are not touched. Needs ip, nft or iptables, curl, python3.
# Logs stay in /tmp/oddly-test.
SRC=$(cd "${1:-.}" && pwd)
NS=oddlytest
HOSTIP=10.199.0.1
W=/tmp/oddly-test

if [ "$2" != inside ]; then
    rm -rf $W; mkdir -p $W/www
    cp "$SRC/oddlyproxifier" "$SRC/testproxy" $W/ && chmod +x $W/oddlyproxifier $W/testproxy
    echo hello > $W/www/hello.txt
    ip netns del $NS 2>/dev/null
    ip link del oddly0 2>/dev/null
    ip netns add $NS
    ip link add oddly0 type veth peer name oddly1
    ip link set oddly1 netns $NS
    ip addr add $HOSTIP/24 dev oddly0
    ip link set oddly0 up
    ip netns exec $NS ip addr add 10.199.0.2/24 dev oddly1
    ip netns exec $NS ip link set oddly1 up
    ip netns exec $NS ip link set lo up
    # The "remote" web server lives outside the namespace.
    (cd $W/www && exec python3 -m http.server 8088 --bind $HOSTIP) > $W/web.log 2>&1 &
    WEB=$!
    sleep 1
    ip netns exec $NS sh "$0" "$SRC" inside
    kill $WEB 2>/dev/null
    ip netns del $NS
    ip link del oddly0 2>/dev/null
    exit 0
fi

cd $W
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
URL=http://$HOSTIP:8088/hello.txt

cat > profile.json <<'EOF'
{
 "version": 1,
 "proxies": [{"id": "px", "name": "Test SOCKS5", "type": "socks5", "host": "127.0.0.1", "port": 1091}],
 "rules": [{"id": "curl", "name": "curl via proxy", "enabled": true, "apps": ["curl"],
            "action": {"type": "proxy", "target": "px"}}],
 "default": {"type": "direct"},
 "options": {"intercept": true, "transparent_port": 37080, "inbound": "127.0.0.1:1081",
             "api": "127.0.0.1:9090", "api_token": "testtoken"}
}
EOF

rules() { { nft list ruleset; iptables-save; } 2>/dev/null | grep -ci oddly; }
get() { curl -s -o /dev/null -m 10 -w '%{http_code}' "$URL"; }
proxied() { grep -c -- ' -> ' proxy.log; }
PYGET="import urllib.request as u; print(u.urlopen('$URL', timeout=10).status)"

./testproxy -type socks5 -listen 127.0.0.1:1091 > proxy.log 2>&1 &
PX=$!
sleep 1
echo "0 before the engine starts: curl $(get), proxied $(proxied)   (want 200, 0)"

./oddlyproxifier run -profile profile.json -log debug > engine.log 2>&1 &
ENG=$!
sleep 3
echo "1 engine running: rule lines $(rules)   (want > 0)"
grep -o "interception active.*" engine.log
echo "2 curl, in the rule: $(get), proxied $(proxied)   (want 200, 1)"
echo "3 python, not in the rule: $(python3 -c "$PYGET" 2>&1 | tail -1), proxied $(proxied)   (want 200, 1)"
echo "4 connections seen by the engine (app, pid, destination, rule, route, inbound):"
curl -s -H 'Authorization: Bearer testtoken' http://127.0.0.1:9090/api/connections | python3 -c "
import json, sys
for c in json.load(sys.stdin)['recent']:
    print('    ', {k: c.get(k) for k in ('app', 'pid', 'host', 'ip', 'port', 'rule', 'via', 'inbound') if c.get(k)})"

kill -9 $ENG
sleep 4
echo "5 after kill -9, the guard cleans up: rule lines $(rules), curl $(get), proxied $(proxied)   (want 0, 200, 1)"

./oddlyproxifier run -profile profile.json > engine2.log 2>&1 &
ENG=$!
sleep 3
echo "6 restarted: rule lines $(rules), curl $(get), proxied $(proxied)   (want > 0, 200, 2)"
kill -TERM $ENG
sleep 2
echo "7 after SIGTERM: rule lines $(rules), curl $(get), proxied $(proxied)   (want 0, 200, 2)"
kill $PX 2>/dev/null
