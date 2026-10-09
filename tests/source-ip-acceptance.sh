#!/bin/sh
set -eu
# Run only inside the disposable Linux VM prepared for this task.
# Usage: source-ip-acceptance.sh /absolute/path/to/iranmonitor_node-TESTBINARY
TEST_BINARY=${1:?Rust test binary is required}
[ "${IMONITOR_ACCEPT_DISPOSABLE:-}" = 1 ] || { echo 'Set IMONITOR_ACCEPT_DISPOSABLE=1 only inside a disposable Linux VM.' >&2; exit 1; }
CLIENT=imsrc-client-$$
SERVER=imsrc-server-$$
CLIENT_CREATED=0
SERVER_CREATED=0
for name in "$CLIENT" "$SERVER"; do
    if ip netns list | awk '{print $1}' | grep -Fx "$name" >/dev/null; then
        echo "Refusing to replace existing namespace: $name" >&2
        exit 1
    fi
 done
cleanup() {
    [ "$CLIENT_CREATED" = 0 ] || ip netns del "$CLIENT" 2>/dev/null || :
    [ "$SERVER_CREATED" = 0 ] || ip netns del "$SERVER" 2>/dev/null || :
}
trap cleanup EXIT INT TERM
ip netns add "$CLIENT"
CLIENT_CREATED=1
ip netns add "$SERVER"
SERVER_CREATED=1
ip link add vethc type veth peer name veths
ip link set vethc netns "$CLIENT"
ip link set veths netns "$SERVER"
ip -n "$CLIENT" link set lo up
ip -n "$SERVER" link set lo up
ip -n "$CLIENT" link set vethc up
ip -n "$SERVER" link set veths up
ip -n "$CLIENT" addr add 192.0.2.1/24 dev vethc
ip -n "$CLIENT" addr add 198.51.100.9/32 dev vethc
ip -n "$SERVER" addr add 192.0.2.2/24 dev veths
ip -n "$SERVER" route add 198.51.100.9/32 via 192.0.2.1
ip -n "$CLIENT" -6 addr add fd00:1::1/64 dev vethc nodad
ip -n "$CLIENT" -6 addr add fd00:1::9/128 dev vethc nodad
ip -n "$SERVER" -6 addr add fd00:1::2/64 dev veths nodad
for tool in iptables ip6tables; do
    ip netns exec "$CLIENT" "$tool" -w 5 -t nat -N SENTINEL_ACCEPT
    ip netns exec "$CLIENT" "$tool" -w 5 -t nat -A POSTROUTING -j SENTINEL_ACCEPT
    ip netns exec "$CLIENT" "$tool" -w 5 -t nat -A SENTINEL_ACCEPT -d "$(if [ "$tool" = ip6tables ]; then echo fd00:ffff::1; else echo 203.0.113.254; fi)" -j RETURN
 done
for family in ipv4 ipv6; do
    ip netns exec "$CLIENT" env IMONITOR_ACCEPT_DISPOSABLE=1 IMONITOR_ACCEPT_SERVER="$SERVER" IMONITOR_ACCEPT_FAMILY="$family" \
        "$TEST_BINARY" --ignored --exact source_ip::linux_acceptance::linux_network_acceptance_snat --nocapture
 done
printf '%s\n' 'PASS: actual IPv4/IPv6 SNAT, UDP checksums, conntrack replies, deletion and unrelated NAT rules'
ip netns exec "$CLIENT" env IMONITOR_ACCEPT_DISPOSABLE=1 IMONITOR_ACCEPT_SERVER="$SERVER" \
    IMONITOR_BPF_HELPER="${IMONITOR_BPF_HELPER:-/tests/bin/imonitor-bpf}" IMONITOR_ACCEPT_RUNTIME="/tmp/imonitor-paired-acceptance-$$" \
    "$TEST_BINARY" --ignored --exact source_ip::paired_acceptance::linux_network_acceptance_paired --nocapture
printf '%s\n' 'PASS: actual paired IPv4 tc NAT, XDP verifier/attach, UDP checksums, replies and owned cleanup'
ip netns exec "$CLIENT" env IMONITOR_ACCEPT_DISPOSABLE=1 IMONITOR_ACCEPT_SERVER="$SERVER" \
    "$TEST_BINARY" --ignored --exact platform::tests::linux_network_acceptance_controls --nocapture
printf '%s\n' 'PASS: actual IPv4/IPv6 forwarding, overlapping traffic counters, shaping reapply/remove and connection-limit install/clear'
if [ -n "${IMONITOR_BPF_TEST_BINARY:-}" ]; then
    ip netns exec "$CLIENT" env IMONITOR_ACCEPT_DISPOSABLE=1 IMONITOR_ACCEPT_INTERFACE=vethc \
        "$IMONITOR_BPF_TEST_BINARY" --ignored --exact tests::linux_tc_flower_protocol_numbers_round_trip --nocapture
fi
