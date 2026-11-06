#!/usr/bin/env bash
# End to end test with real TCP connections over a veth pair.
#
# kcart is attached to the host side of the pair, a stand in server listens
# there, and a client inside a network namespace connects with different
# hostnames. Needs root and a built binary (target/release/kcart by default).
set -euo pipefail

KCART=${KCART:-$(dirname "$0")/../target/release/kcart}
TESTS=$(cd "$(dirname "$0")/../tests" && pwd)
NS=kcart-it
HOST_IP=10.99.0.1
NS_IP=10.99.0.2
PIN=/sys/fs/bpf/kcart-it

cleanup() {
	kill "${KCART_PID:-}" "${SERVER_PID:-}" 2>/dev/null || true
	wait 2>/dev/null || true
	ip netns del $NS 2>/dev/null || true
	ip link del kc0 2>/dev/null || true
	rm -rf $PIN
}
trap cleanup EXIT

ip netns add $NS
ip link add kc0 type veth peer name kc1
ip link set kc1 netns $NS
ip addr add $HOST_IP/24 dev kc0
ip link set kc0 up
ip netns exec $NS ip addr add $NS_IP/24 dev kc1
ip netns exec $NS ip link set kc1 up
ip netns exec $NS ip link set lo up

python3 "$TESTS/fake_server.py" $HOST_IP > /tmp/kcart-it-server.log 2>&1 &
SERVER_PID=$!
# kcart looks for the listener at startup, so the server must be up first
until ss -ltn "sport = :25565" | grep -q LISTEN; do sleep 0.1; done
"$KCART" run --iface kc0 --port 25565 --host play.example.com --host '*.wild.example.org' \
	--pin-dir $PIN --rst > /tmp/kcart-it-kcart.log 2>&1 &
KCART_PID=$!
sleep 1
kill -0 $KCART_PID || { cat /tmp/kcart-it-kcart.log; exit 1; }

client() {
	ip netns exec $NS python3 "$TESTS/mc_client.py" $HOST_IP "$1"
}

fail=0
expect() {
	local want=$1 host=$2 out
	out=$(client "$host")
	if [[ "$out" == *"$want"* ]]; then
		echo "ok   $out"
	else
		echo "FAIL $out (expected $want)"
		fail=1
	fi
}

expect "reply" play.example.com
expect "reply" PLAY.EXAMPLE.COM
expect "reply" eu.wild.example.org
expect "no reply" $HOST_IP
expect "no reply" wild.example.org
expect "no reply" example.com

if ip netns exec $NS python3 "$TESTS/spoof.py" kc1 $HOST_IP play.example.com; then
	:
else
	fail=1
fi

echo
"$KCART" stats --pin-dir $PIN
echo
grep -c "drop reason=host_not_allowed" /tmp/kcart-it-kcart.log | sed 's/^/drop events logged: /'
if grep -q "socket check on" /tmp/kcart-it-kcart.log; then
	echo "ok   socket check detected the server"
else
	echo "FAIL socket check not on"
	fail=1
fi
if grep -q "Connection reset" /tmp/kcart-it-server.log; then
	echo "ok   server saw resets for denied connections"
else
	echo "FAIL server did not see resets"
	fail=1
fi
exit $fail
