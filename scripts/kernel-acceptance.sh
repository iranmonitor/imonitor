#!/usr/bin/env bash
# Run only inside a disposable Linux VM. No host interfaces/firewalls are changed.
# Usage: bash kernel-acceptance.sh /path/to/kernel-plans /path/to/linux-test-binary
# Fixtures are exported by runner::tests::export_kernel_acceptance_plans.
set -u
umask 077

[[ ${IMONITOR_ACCEPT_DISPOSABLE:-} == 1 ]] || {
    printf 'Set IMONITOR_ACCEPT_DISPOSABLE=1 only inside a disposable Linux VM.\n' >&2
    exit 64
}

if [[ $# -ne 2 ]]; then
    printf 'Usage: %s PLAN_DIRECTORY LINUX_TEST_BINARY\n' "$0" >&2
    exit 64
fi
PLAN_DIR=$(cd "$1" && pwd) || exit 64
TEST_BIN_DIR=$(cd "$(dirname "$2")" && pwd) || exit 64
TEST_BIN="$TEST_BIN_DIR/$(basename "$2")"
[[ -x "$TEST_BIN" && -f "$PLAN_DIR/modes.txt" ]] || exit 64
[[ $(id -u) -eq 0 ]] || { printf 'Disposable Linux guest root is required.\n' >&2; exit 64; }
for tool in ip ping timeout grep cat; do
    command -v "$tool" >/dev/null || { printf 'Missing required guest tool: %s\n' "$tool" >&2; exit 64; }
done
if ! "$TEST_BIN" --list | grep -q 'runner::tests::linux_kernel_fixture_runtime'; then
    printf 'The supplied binary lacks the Linux runtime acceptance test.\n' >&2
    exit 64
fi

RESULT_DIR="$PLAN_DIR/results-$(date +%s)-$$"
mkdir -p "$RESULT_DIR"
printf 'mode\tresult\n' > "$RESULT_DIR/summary.tsv"
: > "$RESULT_DIR/results.jsonl"
NS_A='' NS_B='' LINK_A='' NS_A_CREATED=0 NS_B_CREATED=0 LINK_CREATED=0
PIDS=()

cleanup() {
    local pid
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
    PIDS=()
    if [[ $NS_A_CREATED -eq 1 ]]; then ip netns del "$NS_A" 2>/dev/null || true; NS_A_CREATED=0; fi
    if [[ $NS_B_CREATED -eq 1 ]]; then ip netns del "$NS_B" 2>/dev/null || true; NS_B_CREATED=0; fi
    if [[ $LINK_CREATED -eq 1 ]]; then ip link del "$LINK_A" 2>/dev/null || true; LINK_CREATED=0; fi
}
trap cleanup EXIT INT TERM

setup_namespaces() {
    NS_A="im-accept-$$-a" NS_B="im-accept-$$-b"
    LINK_A="ima$$" LINK_B="imb$$"
    # An existing name is never adopted or deleted by this harness.
    ! ip netns list | grep -qE "^($NS_A|$NS_B)( |$)" || return 1
    ! ip link show "$LINK_A" >/dev/null 2>&1 || return 1
    ! ip link show "$LINK_B" >/dev/null 2>&1 || return 1
    ip netns add "$NS_A" || return 1
    NS_A_CREATED=1
    ip netns add "$NS_B" || return 1
    NS_B_CREATED=1
    ip link add "$LINK_A" type veth peer name "$LINK_B" || return 1
    LINK_CREATED=1
    ip link set "$LINK_A" netns "$NS_A" || return 1
    LINK_CREATED=0
    ip link set "$LINK_B" netns "$NS_B" || return 1
    ip -n "$NS_A" link set "$LINK_A" name underlay0 || return 1
    ip -n "$NS_B" link set "$LINK_B" name underlay0 || return 1
    for ns in "$NS_A" "$NS_B"; do
        ip -n "$ns" link set lo up || return 1
        ip -n "$ns" link set underlay0 mtu 1500 up || return 1
    done
    ip -n "$NS_A" address add 192.0.2.1/30 dev underlay0 || return 1
    ip -n "$NS_B" address add 192.0.2.2/30 dev underlay0 || return 1
    ip -n "$NS_A" -6 address add 2001:db8:1::1/64 dev underlay0 nodad || return 1
    ip -n "$NS_B" -6 address add 2001:db8:1::2/64 dev underlay0 nodad || return 1
    return 0
}

runtime() {
    local ns=$1 side=$2 expected=${3:-0}
    timeout 25 ip netns exec "$ns" env IMONITOR_KERNEL_CHECK_FILE="$PLAN_DIR/$MODE/$side.json" \
        IMONITOR_EXPECT_PEER="$expected" "$TEST_BIN" --ignored --exact \
        runner::tests::linux_kernel_fixture_runtime --nocapture
}

collect_gue_failure_diagnostics() {
    [[ ${TUNNEL_PROTOCOL:-} == encap ]] || return 0
    local side ns peer
    for side in a b; do
        if [[ $side == a ]]; then ns=$NS_A; peer=$INNER_B
        else ns=$NS_B; peer=$INNER_A; fi
        {
            printf 'GUE failure diagnostics: side=%s namespace=%s peer=%s\n' "$side" "$ns" "$peer"
            printf '\nInterface and addresses\n'
            timeout 5 ip -n "$ns" -d link show imtest0 || true
            timeout 5 ip -n "$ns" -o address show || true
            printf '\nRoutes and selected peer route\n'
            timeout 5 ip -n "$ns" -4 route show table all || true
            timeout 5 ip -n "$ns" -4 route get "$peer" || true
            printf '\nGUE receive ports\n'
            timeout 5 ip netns exec "$ns" ip fou show || true
            printf '\nUnbound inner probe\n'
            timeout 4 ip netns exec "$ns" ping -4 -c 1 -W 2 "$peer" || true
            printf '\nInterface-bound inner probe\n'
            timeout 4 ip netns exec "$ns" ping -4 -I imtest0 -c 1 -W 2 "$peer" || true
        } > "$RESULT_DIR/$MODE-failure-$side.log" 2>&1
    done
}

setup_native_tun() {
    local prod_binary=${IMONITOR_PRODUCTION_BINARY:-/tests/bin/imonitor}
    [[ -x "$prod_binary" ]] || { printf 'Production tun-helper binary is missing: %s\n' "$prod_binary" >&2; return 1; }
    ip netns exec "$NS_B" "$prod_binary" tun-helper --interface imtest0 \
        --listen-addr "$OUTER_B:19011" --lanes "$TUN_LANES" --packet-limit 1400 \
        > "$RESULT_DIR/$MODE-helper-b.log" 2>&1 &
    local listener_pid=$!
    PIDS+=("$listener_pid")
    local attempt ready=0
    for attempt in {1..30}; do
        if ip -n "$NS_B" link show imtest0 >/dev/null 2>&1; then ready=1; break; fi
        sleep 0.1
    done
    [[ $ready -eq 1 ]] || return 1
    local -a connector_args=(tun-helper --interface imtest0 --lanes "$TUN_LANES" --packet-limit 1400 --source-ip "$OUTER_A")
    for ((attempt=0; attempt<TUN_LANES; attempt++)); do connector_args+=(--connect-addr "$OUTER_B:19011"); done
    ip netns exec "$NS_A" "$prod_binary" "${connector_args[@]}" > "$RESULT_DIR/$MODE-helper-a.log" 2>&1 &
    local connector_pid=$!
    PIDS+=("$connector_pid")
    ready=0
    for attempt in {1..30}; do
        if ip -n "$NS_A" link show imtest0 >/dev/null 2>&1; then ready=1; break; fi
        sleep 0.1
    done
    [[ $ready -eq 1 ]] || return 1
    ip -n "$NS_A" link set imtest0 mtu 1400 up || return 1
    ip -n "$NS_B" link set imtest0 mtu 1400 up || return 1
    ip -n "$NS_A" address replace "$INNER_A/30" dev imtest0 || return 1
    ip -n "$NS_B" address replace "$INNER_B/30" dev imtest0 || return 1
    ip -n "$NS_A" -4 route replace "$INNER_B/32" dev imtest0 || return 1
    ip -n "$NS_B" -4 route replace "$INNER_A/32" dev imtest0 || return 1
    kill -0 "$listener_pid" && kill -0 "$connector_pid"
}

check_mode() {
    # This env file and its corresponding configs come from synthetic Rust fixtures.
    source "$PLAN_DIR/$MODE/mode.env"
    setup_namespaces || return 1
    if [[ $TUNNEL_PROTOCOL == tun ]]; then
        setup_native_tun > "$RESULT_DIR/$MODE-setup-a.log" 2>&1 || return 1
    else
        runtime "$NS_A" a 0 > "$RESULT_DIR/$MODE-setup-a.log" 2>&1 || return 1
        runtime "$NS_B" b 0 > "$RESULT_DIR/$MODE-setup-b.log" 2>&1 || return 1
    fi
    ip -n "$NS_A" -d link show imtest0 > "$RESULT_DIR/$MODE-link-a.log" || return 1
    ip -n "$NS_B" -d link show imtest0 > "$RESULT_DIR/$MODE-link-b.log" || return 1
    grep -q 'mtu 1400' "$RESULT_DIR/$MODE-link-a.log" || return 1
    grep -q 'mtu 1400' "$RESULT_DIR/$MODE-link-b.log" || return 1

    local capture_pid='' capture_enabled=0 capture_protocol capture_port='' capture_family capture_filter
    case "$TUNNEL_PROTOCOL" in
        gre|gretap) capture_protocol=47 ;;
        ipip|ipv4_ipinip|ipv4_ip_in_ip) capture_protocol=4 ;;
        ipv6_encapsulation) capture_protocol=41 ;;
        esp) capture_protocol=50 ;;
        encap) capture_protocol=17; capture_port=5555 ;;
        vxlan) capture_protocol=17; capture_port=4789 ;;
        geneve) capture_protocol=17; capture_port=6081 ;;
        wireguard) capture_protocol=17; capture_port=51820 ;;
        l2tp)
            if [[ $MODE == l2tpip ]]; then capture_protocol=115
            else capture_protocol=17; capture_port=1701; fi
            ;;
        tun) capture_protocol=6; capture_port=19011 ;;
        *) printf 'No outer packet assertion is defined for %s.\n' "$TUNNEL_PROTOCOL" >&2; return 1 ;;
    esac
    case "$OUTER_FAMILY" in
        4) capture_family=ip ;;
        6) capture_family=ip6 ;;
        *) printf 'Invalid outer family: %s\n' "$OUTER_FAMILY" >&2; return 1 ;;
    esac
    # Explicit IP family excludes ARP; protocol and port exclude unrelated probes.
    capture_filter="$capture_family and src host $OUTER_A and dst host $OUTER_B and $capture_family proto $capture_protocol"
    if [[ -n $capture_port ]]; then
        if [[ $capture_protocol -eq 6 ]]; then capture_filter+=" and tcp dst port $capture_port"
        else capture_filter+=" and udp dst port $capture_port"; fi
    fi
    printf 'outer_family=%s\nouter_protocol=%s\nouter_destination_port=%s\nfilter=%s\n' \
        "$OUTER_FAMILY" "$capture_protocol" "$capture_port" "$capture_filter" > "$RESULT_DIR/$MODE-outer-filter.log"
    if command -v tcpdump >/dev/null; then
        timeout 10 ip netns exec "$NS_A" tcpdump -nn -i underlay0 -c 1 -U \
            -w "$RESULT_DIR/$MODE-outer-packet.pcap" "$capture_filter" > "$RESULT_DIR/$MODE-outer-capture.log" 2>&1 &
        capture_pid=$!
        PIDS+=("$capture_pid")
        capture_enabled=1
        sleep 0.3
    fi
    ip netns exec "$NS_A" ping "-$INNER_FAMILY" -c 3 -W 2 "$INNER_B" > "$RESULT_DIR/$MODE-ping-a.log" 2>&1 || return 1
    ip netns exec "$NS_B" ping "-$INNER_FAMILY" -c 3 -W 2 "$INNER_A" > "$RESULT_DIR/$MODE-ping-b.log" 2>&1 || return 1
    local payload
    if [[ $INNER_FAMILY -eq 6 ]]; then payload=1352; else payload=1372; fi
    ip netns exec "$NS_A" ping "-$INNER_FAMILY" -c 1 -W 2 -M do -s "$payload" "$INNER_B" \
        > "$RESULT_DIR/$MODE-mtu-at-limit.log" 2>&1 || return 1
    if ip netns exec "$NS_A" ping "-$INNER_FAMILY" -c 1 -W 2 -M do -s "$((payload + 1))" "$INNER_B" \
        > "$RESULT_DIR/$MODE-mtu-over-limit.log" 2>&1; then
        printf 'Oversized inner packet incorrectly succeeded.\n' >> "$RESULT_DIR/$MODE-mtu-over-limit.log"
        return 1
    fi
    if [[ $capture_enabled -eq 1 ]]; then
        wait "$capture_pid" || return 1
        tcpdump -nn -vvv -r "$RESULT_DIR/$MODE-outer-packet.pcap" \
            > "$RESULT_DIR/$MODE-outer-packet.log" 2> "$RESULT_DIR/$MODE-outer-decode.log" || return 1
        # Reapply the exact family, outer endpoints, carrier protocol and port to
        # the recorded packet. This verifies packet bytes independently of text
        # formatting and leaves the PCAP plus asserted filter for inspection.
        tcpdump -nn -q -c 1 -r "$RESULT_DIR/$MODE-outer-packet.pcap" "$capture_filter" \
            > "$RESULT_DIR/$MODE-outer-protocol-assert.log" 2>&1 || return 1
        grep -qE '^[0-9]{2}:[0-9]{2}:[0-9]{2}.* IP6? ' "$RESULT_DIR/$MODE-outer-protocol-assert.log" || return 1
        if [[ $PACKET_SETTINGS -eq 1 ]]; then
            if [[ $OUTER_FAMILY -eq 4 ]]; then
                grep -q 'ttl 64' "$RESULT_DIR/$MODE-outer-packet.log" || return 1
                grep -qi 'tos 0xb8' "$RESULT_DIR/$MODE-outer-packet.log" || return 1
            else
                grep -q 'hlim 64' "$RESULT_DIR/$MODE-outer-packet.log" || return 1
                grep -qi 'class 0xb8' "$RESULT_DIR/$MODE-outer-packet.log" || return 1
            fi
        fi
    else
        printf 'tcpdump unavailable: outer header capture was not verified.\n' > "$RESULT_DIR/$MODE-outer-packet.log"
    fi

    # Re-run the real monitor/runtime after the peer is ready. ESP/GUE assert reuse.
    if [[ $TUNNEL_PROTOCOL != tun ]]; then
        runtime "$NS_A" a 1 > "$RESULT_DIR/$MODE-monitor-a.log" 2>&1 || return 1
        runtime "$NS_B" b 1 > "$RESULT_DIR/$MODE-monitor-b.log" 2>&1 || return 1
    fi
    if [[ $TUNNEL_PROTOCOL == esp ]]; then
        ip -n "$NS_A" xfrm state > "$RESULT_DIR/$MODE-xfrm-state.log" || return 1
        ip -n "$NS_A" xfrm policy > "$RESULT_DIR/$MODE-xfrm-policy.log" || return 1
    elif [[ $TUNNEL_PROTOCOL == wireguard ]]; then
        ip netns exec "$NS_A" wg show imtest0 latest-handshakes > "$RESULT_DIR/$MODE-wg-handshakes.log" || return 1
        awk '$2 > 0 { found=1 } END { exit !found }' "$RESULT_DIR/$MODE-wg-handshakes.log" || return 1
    fi

    # Native authenticated TCP measurement sends actual data across this tunnel.
    timeout 20 ip netns exec "$NS_B" env IMONITOR_KERNEL_CHECK_FILE="$PLAN_DIR/$MODE/b.json" \
        IMONITOR_SPEED_ROLE=server "$TEST_BIN" --ignored --exact \
        runner::tests::linux_native_tunnel_speed_fixture --nocapture > "$RESULT_DIR/$MODE-speed-server.log" 2>&1 &
    local server_pid=$!
    PIDS+=("$server_pid")
    local ready=0 attempt
    for attempt in {1..30}; do
        if grep -q 'Native speed-test peer ready' "$RESULT_DIR/$MODE-speed-server.log"; then ready=1; break; fi
        sleep 0.1
    done
    [[ $ready -eq 1 ]] || return 1
    timeout 15 ip netns exec "$NS_A" env IMONITOR_KERNEL_CHECK_FILE="$PLAN_DIR/$MODE/a.json" \
        IMONITOR_SPEED_ROLE=client "$TEST_BIN" --ignored --exact \
        runner::tests::linux_native_tunnel_speed_fixture --nocapture > "$RESULT_DIR/$MODE-speed-client.log" 2>&1 || return 1
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    ip -n "$NS_A" -s link show imtest0 > "$RESULT_DIR/$MODE-counters-a.log" || return 1
    ip -n "$NS_B" -s link show imtest0 > "$RESULT_DIR/$MODE-counters-b.log" || return 1
    return 0
}

passed=0 failed=0 unsupported=0
cat "$PLAN_DIR/modes.txt" > "$RESULT_DIR/all-modes.txt"
for extra_mode in l2tpudp l2tpip tuntcp1 tuntcp4; do
    if [[ -f "$PLAN_DIR/$extra_mode/mode.env" ]] && ! grep -qx "$extra_mode" "$RESULT_DIR/all-modes.txt"; then
        printf '%s\n' "$extra_mode" >> "$RESULT_DIR/all-modes.txt"
    fi
done
while IFS= read -r MODE || [[ -n $MODE ]]; do
    [[ $MODE =~ ^[a-z0-9]+$ && -f "$PLAN_DIR/$MODE/mode.env" ]] || continue
    if [[ -n ${IMONITOR_KERNEL_MODES:-} && " $IMONITOR_KERNEL_MODES " != *" $MODE "* ]]; then continue; fi
    printf 'Testing %s ...\n' "$MODE"
    if check_mode; then
        STATUS=PASS
        passed=$((passed + 1))
    elif grep -qEi 'operation not supported|unknown device type|protocol not supported|failed to find.*fou' \
        "$RESULT_DIR/$MODE-setup-a.log" "$RESULT_DIR/$MODE-setup-b.log" 2>/dev/null; then
        STATUS=UNSUPPORTED
        unsupported=$((unsupported + 1))
    else
        STATUS=FAIL
        failed=$((failed + 1))
        collect_gue_failure_diagnostics
    fi
    printf '%s\t%s\n' "$MODE" "$STATUS" >> "$RESULT_DIR/summary.tsv"
    printf '{"mode":"%s","result":"%s"}\n' "$MODE" "$STATUS" >> "$RESULT_DIR/results.jsonl"
    printf '%s: %s\n' "$MODE" "$STATUS"
    cleanup
done < "$RESULT_DIR/all-modes.txt"
printf 'Results: %s\nPassed: %s; failed: %s; unsupported: %s\n' "$RESULT_DIR" "$passed" "$failed" "$unsupported"
printf 'Namespace measurements validate this guest; they are not a WAN performance baseline.\n'
[[ $failed -eq 0 && $passed -gt 0 ]]
