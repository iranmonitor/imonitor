#!/usr/bin/env bash
# Optional production TUN UDP / TCP / legacy BIP / ICMP acceptance in a disposable guest.
# Usage: IMONITOR_ACCEPT_DISPOSABLE=1 bash tun-carrier-acceptance.sh RESULT_ROOT TEST_BINARY
set -u
umask 077
[[ ${IMONITOR_ACCEPT_DISPOSABLE:-} == 1 ]] || { printf 'Disposable Linux guest opt-in is required.\n' >&2; exit 64; }
[[ $# -eq 2 && $(id -u) -eq 0 ]] || { printf 'Usage: %s RESULT_ROOT LINUX_TEST_BINARY (guest root required)\n' "$0" >&2; exit 64; }
RESULT_ROOT=$(cd "$1" && pwd) || exit 64
TEST_BIN_DIR=$(cd "$(dirname "$2")" && pwd) || exit 64
TEST_BIN="$TEST_BIN_DIR/$(basename "$2")"
PROD_BIN=${IMONITOR_PRODUCTION_BINARY:-/tests/bin/imonitor}
[[ -x "$TEST_BIN" && -x "$PROD_BIN" && "$RESULT_ROOT" != *"'"* ]] || exit 64
for tool in ip ping sqlite3 timeout awk grep cat cut sed socat ptunnel-ng tcpdump; do
    command -v "$tool" >/dev/null || { printf 'Missing guest prerequisite: %s\n' "$tool" >&2; exit 64; }
done
"$TEST_BIN" --list | grep -q 'runner::tests::linux_native_tunnel_speed_fixture' || exit 64
RESULT_DIR="$RESULT_ROOT/tun-carrier-results-$(date +%s)-$$"
mkdir -p "$RESULT_DIR"
printf 'mode\tresult\tphase\n' > "$RESULT_DIR/summary.tsv"
NS_A='' NS_B='' CREATED_A=0 CREATED_B=0 PIDS=() PHASE=''

cleanup() {
    local pid ns created
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
    PIDS=()
    # Only terminate processes in namespaces this invocation created and owns.
    for created in a b; do
        if [[ $created == a && $CREATED_A -eq 1 ]]; then ns=$NS_A
        elif [[ $created == b && $CREATED_B -eq 1 ]]; then ns=$NS_B
        else continue; fi
        for pid in $(ip netns pids "$ns" 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
        ip netns del "$ns" 2>/dev/null || true
    done
    CREATED_A=0 CREATED_B=0
}
trap cleanup EXIT INT TERM

setup_pair() {
    NS_A="im-carrier-$$-a" NS_B="im-carrier-$$-b"
    local link_a="ica$$" link_b="icb$$" ns
    ! ip netns list | grep -qE "^($NS_A|$NS_B)( |$)" || return 1
    ! ip link show "$link_a" >/dev/null 2>&1 || return 1
    ! ip link show "$link_b" >/dev/null 2>&1 || return 1
    ip netns add "$NS_A" || return 1
    CREATED_A=1
    ip netns add "$NS_B" || return 1
    CREATED_B=1
    ip link add "$link_a" type veth peer name "$link_b" || return 1
    ip link set "$link_a" netns "$NS_A" || { ip link del "$link_a"; return 1; }
    ip link set "$link_b" netns "$NS_B" || return 1
    ip -n "$NS_A" link set "$link_a" name underlay0 || return 1
    ip -n "$NS_B" link set "$link_b" name underlay0 || return 1
    for ns in "$NS_A" "$NS_B"; do
        ip -n "$ns" link set lo up || return 1
        ip -n "$ns" link set underlay0 mtu 1500 up || return 1
    done
    ip -n "$NS_A" addr add 192.0.2.1/30 dev underlay0 || return 1
    ip -n "$NS_B" addr add 192.0.2.2/30 dev underlay0 || return 1
    ip -n "$NS_A" -6 addr add 2001:db8:1::1/64 dev underlay0 nodad || return 1
    ip -n "$NS_B" -6 addr add 2001:db8:1::2/64 dev underlay0 nodad || return 1
}

seed_app() {
    local side=$1 outer=$2 remote=$3 inner=$4 peer=$5
    local db="$MODE_DIR/$side.db" cfg="$MODE_DIR/$side-check.json" lane_json=''
    [[ $TRANSPORT != icmp && $TRANSPORT != tcp ]] || lane_json=",\"tun_lanes\":$LANES"
    "$PROD_BIN" init --db "$db" --data-dir "$MODE_DIR/$side-data" --listen 127.0.0.1:6060 \
        --username fixture --password TEST-ONLY-FIXTURE-PASSWORD > "$MODE_DIR/$side-init.log" 2>&1 || return 1
    cat > "$cfg" <<EOF
{"kind":"tunnel","id":"accept-$MODE-$side","protocol":"tun","tun_transport":"$TRANSPORT","interface":"imtest0","auto_create_interface":true,"local_outer":"$outer","outer_remote":"$remote","source_interface":"underlay0","inner_local_cidr":"$inner/30","inner_probe":"$peer","transport_port":19021,"listen_port":56000,"tunnel_key":"TEST-ONLY-CARRIER-SHARED-SECRET-2026","mtu":1400,"timeout_ms":5000,"interval_secs":10,"require_bidirectional_traffic":false,"ip_version":"ipv4"$lane_json}
EOF
    sqlite3 "$db" <<EOF
DELETE FROM checks;
INSERT OR REPLACE INTO settings(key,value) VALUES('interval_secs','10'),('public_share_enabled','0'),('free_report_enabled','0');
INSERT INTO checks(check_id,label,kind,enabled,public_visible,check_json,created_at_unix,updated_at_unix)
VALUES('accept-$MODE-$side','TUN carrier acceptance','tunnel',1,0,CAST(readfile('$cfg') AS TEXT),0,0);
EOF
}

start_app() {
    local ns=$1 side=$2
    ip netns exec "$ns" "$PROD_BIN" serve --db "$MODE_DIR/$side.db" --data-dir "$MODE_DIR/$side-data" \
        --listen 127.0.0.1:6060 > "$MODE_DIR/$side-serve.log" 2>&1 &
    PIDS+=("$!")
}

wait_result() {
    local side=$1 status=$2 message=${3:-} attempt
    for attempt in {1..120}; do
        sqlite3 "$MODE_DIR/$side.db" 'SELECT results_json FROM snapshots ORDER BY id DESC LIMIT 1;' \
            > "$MODE_DIR/$side-latest-result.json" 2>/dev/null || true
        if grep -q "\"status\":\"$status\"" "$MODE_DIR/$side-latest-result.json"; then
            [[ -n $message ]] || return 0
            grep -Fq "$message" "$MODE_DIR/$side-latest-result.json" && return 0
        fi
        sleep 0.5
    done
    return 1
}

run_speed() {
    local side inner peer attempt ready=0 server_pid
    for side in a b; do
        if [[ $side == a ]]; then inner=10.40.0.1; peer=10.40.0.2; else inner=10.40.0.2; peer=10.40.0.1; fi
        printf '{"id":"accept-carrier-speed-%s","protocol":"tun","interface":"imtest0","inner_local_cidr":"%s/30","inner_probe":"%s"}\n' \
            "$side" "$inner" "$peer" > "$MODE_DIR/$side-speed.json"
    done
    timeout 35 ip netns exec "$NS_B" env IMONITOR_KERNEL_CHECK_FILE="$MODE_DIR/b-speed.json" \
        IMONITOR_SPEED_ROLE=server "$TEST_BIN" --ignored --exact runner::tests::linux_native_tunnel_speed_fixture \
        --nocapture > "$MODE_DIR/speed-server.log" 2>&1 &
    server_pid=$!
    PIDS+=("$server_pid")
    for attempt in {1..40}; do
        if grep -q 'Native speed-test peer ready' "$MODE_DIR/speed-server.log"; then ready=1; break; fi
        sleep 0.1
    done
    [[ $ready -eq 1 ]] || return 1
    timeout 25 ip netns exec "$NS_A" env IMONITOR_KERNEL_CHECK_FILE="$MODE_DIR/a-speed.json" \
        IMONITOR_SPEED_ROLE=client "$TEST_BIN" --ignored --exact runner::tests::linux_native_tunnel_speed_fixture \
        --nocapture > "$MODE_DIR/speed-client.log" 2>&1 || return 1
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}

check_source_rejections() {
    local old_index=$1
    if [[ $TRANSPORT == icmp ]]; then
        # An assigned second address prevents confusing route mismatch with a missing IP.
        ip -n "$NS_A" addr add 192.0.2.9/32 dev underlay0 || return 1
        sqlite3 "$MODE_DIR/a.db" "UPDATE checks SET check_json=json_set(check_json,'$.local_outer','192.0.2.9');" || return 1
        wait_result a down 'Configured Local Outer 192.0.2.9 is not selected' || return 1
        cp "$MODE_DIR/a-latest-result.json" "$MODE_DIR/source-ip-rejected.json" || return 1
        [[ $old_index == $(ip -n "$NS_A" -o link show imtest0 | cut -d: -f1) ]] || return 1
    fi
    sqlite3 "$MODE_DIR/a.db" "UPDATE checks SET check_json=json_set(check_json,'$.local_outer','192.0.2.1','$.source_interface','lo');" || return 1
    wait_result a down 'Configured source interface lo is not selected' || return 1
    cp "$MODE_DIR/a-latest-result.json" "$MODE_DIR/source-interface-rejected.json" || return 1
    [[ $old_index == $(ip -n "$NS_A" -o link show imtest0 | cut -d: -f1) ]] || return 1
    sqlite3 "$MODE_DIR/a.db" "UPDATE checks SET check_json=CAST(readfile('$MODE_DIR/a-check.json') AS TEXT);" || return 1
    wait_result a up || return 1
    record_helpers "$NS_A" "$MODE_DIR/helpers-after-source-recovery.log" || return 1
    [[ "$(cat "$MODE_DIR/helpers-before-a.log")" == "$(cat "$MODE_DIR/helpers-after-source-recovery.log")" ]] || return 1
    [[ $old_index == $(ip -n "$NS_A" -o link show imtest0 | cut -d: -f1) ]] || return 1
    ip netns exec "$NS_A" ping -4 -c 2 -W 2 10.40.0.2 > "$MODE_DIR/ping-after-source-recovery.log" 2>&1 || return 1
}

check_unexpected_peer() {
    local alien=192.0.2.9 target socket_family bind_source attempt ready=0
    for attempt in {1..120}; do
        if ip -n "$NS_A" link show imtest0 >/dev/null 2>&1; then ready=1; break; fi
        sleep 0.5
    done
    [[ $ready -eq 1 ]] || return 1
    sleep 0.2
    if [[ $MODE == tunudp6 ]]; then
        alien=2001:db8:1::9
        ip -n "$NS_B" -6 addr add "$alien/128" dev underlay0 nodad || return 1
        target="[$OUTER_A]" socket_family=UDP6 bind_source="[$alien]"
    else
        ip -n "$NS_B" addr add "$alien/32" dev underlay0 || return 1
        # The alien /32 is outside the /30 underlay. A return route is required
        # so TCP reaches the listener rather than timing out before its filter.
        ip -n "$NS_A" route add "$alien/32" dev underlay0 || return 1
        target=$OUTER_A socket_family=UDP4 bind_source=$alien
    fi
    if [[ $TRANSPORT == tcp ]]; then
        # Keep the connection idle: an unrestricted listener would allocate a
        # lane and wait for a frame. The production listener must close it.
        timeout 8 ip netns exec "$NS_B" env IMONITOR_ACCEPT_DISPOSABLE=1 \
            IMONITOR_KERNEL_CHECK_FILE="$MODE_DIR/a-check.json" IMONITOR_TUN_ALIEN_SOURCE="$alien" \
            "$TEST_BIN" --ignored --exact runner::tests::linux_tun_listener_peer_rejection_fixture \
            --nocapture > "$MODE_DIR/unexpected-peer-rejected.log" 2>&1 || return 1
    else
        # Before the configured peer starts, try to seize UDP-LISTEN's first
        # sender. Subsequent real peer traffic must still establish the tunnel.
        printf 'UNEXPECTED-PEER-TEST-ONLY' | timeout 4 ip netns exec "$NS_B" socat -u - \
            "$socket_family:$target:19021,bind=$bind_source,sourceport=59000" \
            > "$MODE_DIR/unexpected-peer-injection.log" 2>&1 || return 1
    fi
}

record_helpers() {
    local ns=$1 target=$2 pid command
    : > "$target"
    for pid in $(ip netns pids "$ns"); do
        command=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
        case "$command" in
            *' tun-helper '*|*socat*'TUN:'*|*ptunnel-ng*) printf '%s %s\n' "$pid" "$command" >> "$target" ;;
        esac
    done
    sort -o "$target" "$target"
    [[ -s "$target" ]]
}

check_mode() {
    MODE_DIR="$RESULT_DIR/$MODE"
    mkdir -p "$MODE_DIR"
    TRANSPORT=udp LANES=1 OUTER_A=192.0.2.1 OUTER_B=192.0.2.2
    case $MODE in
        tunudp4) ;;
        tunudp6) OUTER_A=2001:db8:1::1; OUTER_B=2001:db8:1::2 ;;
        tunbip4) TRANSPORT=bip ;;
        tuntcp1) TRANSPORT=tcp ;;
        tuntcp4) TRANSPORT=tcp; LANES=4 ;;
        tunicmp1) TRANSPORT=icmp ;;
        tunicmp4) TRANSPORT=icmp; LANES=4 ;;
        *) return 1 ;;
    esac
    PHASE=namespace
    setup_pair > "$MODE_DIR/namespace.log" 2>&1 || return 1
    PHASE=database
    seed_app a "$OUTER_A" "$OUTER_B" 10.40.0.1 10.40.0.2 || return 1
    seed_app b "$OUTER_B" "$OUTER_A" 10.40.0.2 10.40.0.1 || return 1
    PHASE=runtime
    # Sorted endpoint A is the listener. Bring it up before connector B.
    start_app "$NS_A" a
    sleep 0.3
    if [[ $TRANSPORT != icmp ]]; then
        PHASE=unexpected-peer-rejection
        check_unexpected_peer || return 1
    fi
    start_app "$NS_B" b
    wait_result a up && wait_result b up || return 1
    record_helpers "$NS_A" "$MODE_DIR/helpers-before-a.log" || return 1
    record_helpers "$NS_B" "$MODE_DIR/helpers-before-b.log" || return 1
    local index_a index_b capture_pid filter
    index_a=$(ip -n "$NS_A" -o link show imtest0 | cut -d: -f1) || return 1
    index_b=$(ip -n "$NS_B" -o link show imtest0 | cut -d: -f1) || return 1
    ip -n "$NS_A" -o route get 10.40.0.2 > "$MODE_DIR/inner-route-a.log" || return 1
    ip -n "$NS_B" -o route get 10.40.0.1 > "$MODE_DIR/inner-route-b.log" || return 1
    grep -q 'dev imtest0' "$MODE_DIR/inner-route-a.log" && grep -q 'dev imtest0' "$MODE_DIR/inner-route-b.log" || return 1
    for ns in "$NS_A" "$NS_B"; do ip -n "$ns" -d link show imtest0 | grep -q 'mtu 1400' || return 1; done
    PHASE=carrier-source
    if [[ $TRANSPORT == icmp ]]; then filter="icmp and src host $OUTER_A and dst host $OUTER_B"
    elif [[ $TRANSPORT == tcp ]]; then filter="tcp and src host $OUTER_A and dst host $OUTER_B"
    else filter="udp and src host $OUTER_A and dst host $OUTER_B"; fi
    ip netns exec "$NS_A" tcpdump -U -n -i underlay0 -c 1 -w "$MODE_DIR/outer-source.pcap" "$filter" \
        > "$MODE_DIR/capture.log" 2>&1 &
    capture_pid=$!
    PIDS+=("$capture_pid")
    sleep 0.3
    PHASE=bidirectional-ping
    ip netns exec "$NS_A" ping -4 -c 3 -W 3 10.40.0.2 > "$MODE_DIR/ping-a.log" 2>&1 || return 1
    ip netns exec "$NS_B" ping -4 -c 3 -W 3 10.40.0.1 > "$MODE_DIR/ping-b.log" 2>&1 || return 1
    sleep 0.2
    kill "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
    tcpdump -n -r "$MODE_DIR/outer-source.pcap" > "$MODE_DIR/outer-source.log" 2>&1 || return 1
    grep -q "$OUTER_A" "$MODE_DIR/outer-source.log" && grep -q "$OUTER_B" "$MODE_DIR/outer-source.log" || return 1
    PHASE=mtu-boundary
    ip netns exec "$NS_A" ping -4 -c 1 -W 3 -M do -s 1372 10.40.0.2 > "$MODE_DIR/mtu-at-limit.log" 2>&1 || return 1
    if ip netns exec "$NS_A" ping -4 -c 1 -W 3 -M do -s 1373 10.40.0.2 > "$MODE_DIR/mtu-over-limit.log" 2>&1; then return 1; fi
    PHASE=native-speed
    run_speed || return 1
    PHASE=monitor-reuse
    sleep 22
    wait_result a up && wait_result b up || return 1
    # Historical snapshots intentionally omit runtime details. Check the actual
    # helper identities and command lines across several production cycles.
    record_helpers "$NS_A" "$MODE_DIR/helpers-after-a.log" || return 1
    record_helpers "$NS_B" "$MODE_DIR/helpers-after-b.log" || return 1
    [[ "$(cat "$MODE_DIR/helpers-before-a.log")" == "$(cat "$MODE_DIR/helpers-after-a.log")" ]] || return 1
    [[ "$(cat "$MODE_DIR/helpers-before-b.log")" == "$(cat "$MODE_DIR/helpers-after-b.log")" ]] || return 1
    [[ $(sqlite3 "$MODE_DIR/a.db" 'SELECT count(*) FROM snapshots;') -ge 3 ]] || return 1
    [[ $(sqlite3 "$MODE_DIR/b.db" 'SELECT count(*) FROM snapshots;') -ge 3 ]] || return 1
    if [[ $TRANSPORT == tcp ]]; then
        grep -Fq -- "--allowed-peer $OUTER_B" "$MODE_DIR/helpers-after-a.log" || return 1
    elif [[ $TRANSPORT != icmp ]]; then
        if [[ $MODE == tunudp6 ]]; then target_range="range=[$OUTER_B]/128"; else target_range="range=$OUTER_B/32"; fi
        grep -Fq "$target_range" "$MODE_DIR/helpers-after-a.log" || return 1
    fi
    [[ $index_a == $(ip -n "$NS_A" -o link show imtest0 | cut -d: -f1) ]] || return 1
    [[ $index_b == $(ip -n "$NS_B" -o link show imtest0 | cut -d: -f1) ]] || return 1
    if [[ $MODE == tunicmp1 || $MODE == tunudp4 || $MODE == tuntcp1 ]]; then
        PHASE=source-selection-rejection
        check_source_rejections "$index_a" || return 1
    fi
    ip netns exec "$NS_A" ping -4 -c 2 -W 3 10.40.0.2 > "$MODE_DIR/ping-after-cycles.log" 2>&1 || return 1
    sqlite3 "$MODE_DIR/a.db" 'SELECT count(*) FROM snapshots;' > "$MODE_DIR/monitor-cycle-count.log"
    ip -n "$NS_A" -s link show imtest0 > "$MODE_DIR/counters-a.log"
    ip -n "$NS_B" -s link show imtest0 > "$MODE_DIR/counters-b.log"
    ip netns pids "$NS_A" > "$MODE_DIR/runtime-pids-a.log"
    ip netns pids "$NS_B" > "$MODE_DIR/runtime-pids-b.log"
    PHASE=complete
}

failed=0
for MODE in tunudp4 tunudp6 tunbip4 tuntcp1 tuntcp4 tunicmp1 tunicmp4; do
    [[ -z ${IMONITOR_TUN_CARRIER_MODES:-} || " $IMONITOR_TUN_CARRIER_MODES " == *" $MODE "* ]] || continue
    printf 'Testing production %s tunnel ...\n' "$MODE"
    if check_mode; then status=PASS; else
        status=FAIL; failed=$((failed + 1))
        # Preserve actual runtime evidence before retiring owned namespaces.
        for side in a b; do
            if [[ $side == a ]]; then ns=$NS_A; created=$CREATED_A; else ns=$NS_B; created=$CREATED_B; fi
            [[ $created -eq 1 ]] || continue
            ip -n "$ns" -d -s link show > "$MODE_DIR/$side-failure-links.log" 2>&1 || true
            record_helpers "$ns" "$MODE_DIR/$side-failure-helpers.log" || true
            sqlite3 "$MODE_DIR/$side.db" 'SELECT results_json FROM snapshots ORDER BY id DESC LIMIT 1;' \
                > "$MODE_DIR/$side-failure-result.json" 2>/dev/null || true
        done
        # Network namespaces share this filesystem; this is the combined last
        # helper log, not a separate log for each peer.
        [[ ! -f /tmp/iranmonitor-tun-helper-imtest0.log ]] || \
            cp /tmp/iranmonitor-tun-helper-imtest0.log "$MODE_DIR/shared-helper-failure.log"
        for port in 56000 56001 56002 56003; do
            [[ ! -f /tmp/iranmonitor-ptunnel-$port.log ]] || \
                cp "/tmp/iranmonitor-ptunnel-$port.log" "$MODE_DIR/ptunnel-$port-failure.log"
        done
    fi
    printf '%s\t%s\t%s\n' "$MODE" "$status" "$PHASE" >> "$RESULT_DIR/summary.tsv"
    printf '%s: %s (%s)\n' "$MODE" "$status" "$PHASE"
    cleanup
done
printf 'TUN carrier results: %s\nThese guest measurements are not a WAN performance comparison.\n' "$RESULT_DIR"
[[ $failed -eq 0 ]]
