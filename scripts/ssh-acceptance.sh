#!/usr/bin/env bash
# Optional real OpenSSH TUN test. Only run in a disposable Linux guest.
# Usage: IMONITOR_ACCEPT_DISPOSABLE=1 bash ssh-acceptance.sh RESULT_ROOT TEST_BINARY
# Production binary defaults to /tests/bin/imonitor; override IMONITOR_PRODUCTION_BINARY.
set -u
umask 077
[[ ${IMONITOR_ACCEPT_DISPOSABLE:-} == 1 ]] || { printf 'Disposable Linux guest opt-in is required.\n' >&2; exit 64; }
[[ $# -eq 2 && $(id -u) -eq 0 ]] || { printf 'Usage: %s RESULT_ROOT LINUX_TEST_BINARY (guest root required)\n' "$0" >&2; exit 64; }
RESULT_ROOT=$(cd "$1" && pwd) || exit 64
TEST_BIN_DIR=$(cd "$(dirname "$2")" && pwd) || exit 64
TEST_BIN="$TEST_BIN_DIR/$(basename "$2")"
PROD_BIN=${IMONITOR_PRODUCTION_BINARY:-/tests/bin/imonitor}
[[ -x "$TEST_BIN" && -x "$PROD_BIN" && "$RESULT_ROOT" != *"'"* ]] || exit 64
for tool in ip ping sqlite3 ssh ssh-keygen timeout awk grep cat curl; do
    command -v "$tool" >/dev/null || { printf 'Missing guest prerequisite: %s\n' "$tool" >&2; exit 64; }
done
SSHD=${IMONITOR_SSHD_BINARY:-/usr/sbin/sshd}
[[ -x "$SSHD" ]] || exit 64
id sshd >/dev/null 2>&1 || { printf 'Guest needs sshd privilege-separation account (for example UID/GID 74, home /run/sshd, shell /usr/sbin/nologin).\n' >&2; exit 64; }
mkdir -p /run/sshd
"$TEST_BIN" --list | grep -q 'runner::tests::linux_native_tunnel_speed_fixture' || exit 64
RESULT_DIR="$RESULT_ROOT/ssh-results-$(date +%s)-$$"
mkdir -p "$RESULT_DIR"
printf 'mode\tresult\n' > "$RESULT_DIR/summary.tsv"
NS_A='' NS_B='' CREATED_A=0 CREATED_B=0 PIDS=()

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
    NS_A="im-ssh-$$-a" NS_B="im-ssh-$$-b"
    local link_a="isa$$" link_b="isb$$" ns
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
}

seed_app() {
    local side=$1 protocol=$2 managed=$3 outer=$4 remote=$5 inner=$6 peer=$7 key=${8:-}
    local db="$MODE_DIR/$side.db" cfg="$MODE_DIR/$side-check.json"
    "$PROD_BIN" init --db "$db" --data-dir "$MODE_DIR/$side-data" --listen 127.0.0.1:6060 \
        --username fixture --password TEST-ONLY-FIXTURE-PASSWORD > "$MODE_DIR/$side-init.log" 2>&1 || return 1
    cat > "$cfg" <<EOF
{"kind":"tunnel","id":"accept-$MODE-$side","protocol":"$protocol","interface":"tun42","auto_create_interface":$managed,"local_outer":"$outer","outer_remote":"$remote","source_interface":"underlay0","inner_local_cidr":"$inner/30","inner_probe":"$peer","transport_port":2222,"ssh_username":"root","ssh_private_key":"$key","mtu":1400,"timeout_ms":5000,"interval_secs":10,"require_bidirectional_traffic":false,"ip_version":"ipv4"}
EOF
    sqlite3 "$db" <<EOF
DELETE FROM checks;
INSERT OR REPLACE INTO settings(key,value) VALUES('interval_secs','10'),('public_share_enabled','0'),('free_report_enabled','0');
INSERT INTO checks(check_id,label,kind,enabled,public_visible,check_json,created_at_unix,updated_at_unix)
VALUES('accept-$MODE-$side','SSH acceptance','tunnel',1,0,CAST(readfile('$cfg') AS TEXT),0,0);
EOF
}

start_app() {
    local ns=$1 side=$2
    ip netns exec "$ns" "$PROD_BIN" serve --db "$MODE_DIR/$side.db" --data-dir "$MODE_DIR/$side-data" \
        --listen 127.0.0.1:6060 > "$MODE_DIR/$side-serve.log" 2>&1 &
    PIDS+=("$!")
}

wait_healthy() {
    local side=$1 attempt
    for attempt in {1..80}; do
        sqlite3 "$MODE_DIR/$side.db" 'SELECT results_json FROM snapshots ORDER BY id DESC LIMIT 1;' \
            > "$MODE_DIR/$side-latest-result.json" 2>/dev/null || true
        grep -q '"status":"up"' "$MODE_DIR/$side-latest-result.json" && return 0
        sleep 0.5
    done
    return 1
}

check_source_interface_rejection() {
    local side=$1 ns=$2 old_index=$3 attempt rejected=0
    sqlite3 "$MODE_DIR/$side.db" "UPDATE checks SET check_json=json_set(check_json,'$.source_interface','lo');" || return 1
    for attempt in {1..80}; do
        sqlite3 "$MODE_DIR/$side.db" 'SELECT results_json FROM snapshots ORDER BY id DESC LIMIT 1;' \
            > "$MODE_DIR/$side-source-interface-rejected.json" 2>/dev/null || true
        if grep -q '"status":"down"' "$MODE_DIR/$side-source-interface-rejected.json" \
            && grep -Fq 'Configured source interface lo is not selected' "$MODE_DIR/$side-source-interface-rejected.json"; then rejected=1; break; fi
        sleep 0.5
    done
    [[ $rejected -eq 1 && $old_index == $(ip -n "$ns" -o link show tun42 | cut -d: -f1) ]] || return 1
    sqlite3 "$MODE_DIR/$side.db" "UPDATE checks SET check_json=CAST(readfile('$MODE_DIR/$side-check.json') AS TEXT);" || return 1
    wait_healthy "$side" || return 1
    [[ $old_index == $(ip -n "$ns" -o link show tun42 | cut -d: -f1) ]] || return 1
}

run_speed() {
    local side role ns peer inner attempt ready=0 server_pid
    for side in a b; do
        if [[ $side == a ]]; then inner=10.30.0.1; peer=10.30.0.2; else inner=10.30.0.2; peer=10.30.0.1; fi
        # The synthetic interface name is the test's safety marker; the fixture
        # measures its explicit IP pair on the actual production tun42 route.
        printf '{"id":"accept-ssh-speed-%s","protocol":"ssh","interface":"imtest0","inner_local_cidr":"%s/30","inner_probe":"%s"}\n' \
            "$side" "$inner" "$peer" > "$MODE_DIR/$side-speed.json"
    done
    timeout 25 ip netns exec "$NS_B" env IMONITOR_KERNEL_CHECK_FILE="$MODE_DIR/b-speed.json" \
        IMONITOR_SPEED_ROLE=server "$TEST_BIN" --ignored --exact runner::tests::linux_native_tunnel_speed_fixture \
        --nocapture > "$MODE_DIR/speed-server.log" 2>&1 &
    server_pid=$!
    PIDS+=("$server_pid")
    for attempt in {1..40}; do
        if grep -q 'Native speed-test peer ready' "$MODE_DIR/speed-server.log"; then ready=1; break; fi
        sleep 0.1
    done
    [[ $ready -eq 1 ]] || return 1
    timeout 20 ip netns exec "$NS_A" env IMONITOR_KERNEL_CHECK_FILE="$MODE_DIR/a-speed.json" \
        IMONITOR_SPEED_ROLE=client "$TEST_BIN" --ignored --exact runner::tests::linux_native_tunnel_speed_fixture \
        --nocapture > "$MODE_DIR/speed-client.log" 2>&1 || return 1
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}

record_ssh_helper() {
    local pid command target=$1
    : > "$target"
    for pid in $(ip netns pids "$NS_A"); do
        command=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
        case "$command" in
            *' -w 42:42 '*) printf '%s %s\n' "$pid" "$command" >> "$target" ;;
        esac
    done
    sort -o "$target" "$target"
    [[ $(wc -l < "$target") -eq 1 ]]
}

check_mode() {
    MODE_DIR="$RESULT_DIR/$MODE"
    mkdir -p "$MODE_DIR"
    setup_pair || return 1
    ssh-keygen -q -t ed25519 -N '' -C 'DISPOSABLE-ACCEPTANCE-ONLY' -f "$MODE_DIR/client-key" || return 1
    ssh-keygen -q -t ed25519 -N '' -C 'DISPOSABLE-HOST-ONLY' -f "$MODE_DIR/host-key" || return 1
    cat > "$MODE_DIR/sshd.conf" <<EOF
ListenAddress 192.0.2.2
Port 2222
HostKey $MODE_DIR/host-key
AuthorizedKeysFile $MODE_DIR/client-key.pub
PidFile $MODE_DIR/sshd.pid
PermitRootLogin yes
PermitTunnel point-to-point
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PrintMotd no
LogLevel VERBOSE
SetEnv PATH=/usr/sbin:/usr/bin:/sbin:/bin
EOF
    "$SSHD" -t -f "$MODE_DIR/sshd.conf" > "$MODE_DIR/sshd-config-check.log" 2>&1 || return 1
    ip netns exec "$NS_B" "$SSHD" -D -e -f "$MODE_DIR/sshd.conf" > "$MODE_DIR/sshd.log" 2>&1 &
    PIDS+=("$!")
    local key_json attempt ready=0
    key_json=$(awk '{printf "%s\\n", $0}' "$MODE_DIR/client-key")
    seed_app a ssh true 192.0.2.1 192.0.2.2 10.30.0.1 10.30.0.2 "$key_json" || return 1
    if [[ $MODE == reverse_ssh ]]; then
        seed_app b reverse_ssh true 192.0.2.2 192.0.2.1 10.30.0.2 10.30.0.1 || return 1
    else
        seed_app b ssh false 192.0.2.2 192.0.2.1 10.30.0.2 10.30.0.1 || return 1
    fi
    start_app "$NS_B" b
    start_app "$NS_A" a
    wait_healthy a && wait_healthy b || return 1
    record_ssh_helper "$MODE_DIR/ssh-helper-before.log" || return 1
    local index_a index_b
    index_a=$(ip -n "$NS_A" -o link show tun42 | cut -d: -f1) || return 1
    index_b=$(ip -n "$NS_B" -o link show tun42 | cut -d: -f1) || return 1
    for ns in "$NS_A" "$NS_B"; do
        ip -n "$ns" -d link show tun42 | grep -q 'mtu 1400' || return 1
    done
    ip netns exec "$NS_A" ping -4 -c 3 -W 2 10.30.0.2 > "$MODE_DIR/ping-a.log" 2>&1 || return 1
    ip netns exec "$NS_B" ping -4 -c 3 -W 2 10.30.0.1 > "$MODE_DIR/ping-b.log" 2>&1 || return 1
    ip netns exec "$NS_A" ping -4 -c 1 -W 2 -M do -s 1372 10.30.0.2 > "$MODE_DIR/mtu-at-limit.log" 2>&1 || return 1
    if ip netns exec "$NS_A" ping -4 -c 1 -W 2 -M do -s 1373 10.30.0.2 > "$MODE_DIR/mtu-over-limit.log" 2>&1; then return 1; fi
    grep -q 'Connection from 192.0.2.1 ' "$MODE_DIR/sshd.log" || return 1
    run_speed || return 1
    # Verify two more real monitoring cycles reuse the initiator and interfaces.
    sleep 22
    wait_healthy a && wait_healthy b || return 1
    # Compact history omits runtime details; inspect the live SSH process.
    record_ssh_helper "$MODE_DIR/ssh-helper-after.log" || return 1
    [[ "$(cat "$MODE_DIR/ssh-helper-before.log")" == "$(cat "$MODE_DIR/ssh-helper-after.log")" ]] || return 1
    [[ $(sqlite3 "$MODE_DIR/a.db" 'SELECT count(*) FROM snapshots;') -ge 3 ]] || return 1
    [[ $(sqlite3 "$MODE_DIR/b.db" 'SELECT count(*) FROM snapshots;') -ge 3 ]] || return 1
    [[ $index_a == $(ip -n "$NS_A" -o link show tun42 | cut -d: -f1) ]] || return 1
    [[ $index_b == $(ip -n "$NS_B" -o link show tun42 | cut -d: -f1) ]] || return 1
    check_source_interface_rejection a "$NS_A" "$index_a" || return 1
    if [[ $MODE == reverse_ssh ]]; then check_source_interface_rejection b "$NS_B" "$index_b" || return 1; fi
    record_ssh_helper "$MODE_DIR/ssh-helper-after-source-recovery.log" || return 1
    [[ "$(cat "$MODE_DIR/ssh-helper-before.log")" == "$(cat "$MODE_DIR/ssh-helper-after-source-recovery.log")" ]] || return 1
    ip netns exec "$NS_A" ping -4 -c 2 -W 2 10.30.0.2 > "$MODE_DIR/ping-after-cycles.log" 2>&1 || return 1
    sqlite3 "$MODE_DIR/a.db" 'SELECT count(*) FROM snapshots;' > "$MODE_DIR/monitor-cycle-count.log"
    ip -n "$NS_A" -s link show tun42 > "$MODE_DIR/counters-a.log"
    ip -n "$NS_B" -s link show tun42 > "$MODE_DIR/counters-b.log"
}

failed=0
for MODE in ssh reverse_ssh; do
    [[ -z ${IMONITOR_SSH_MODES:-} || " $IMONITOR_SSH_MODES " == *" $MODE "* ]] || continue
    printf 'Testing production %s tunnel ...\n' "$MODE"
    if check_mode; then status=PASS; else status=FAIL; failed=$((failed + 1)); fi
    printf '%s\t%s\n' "$MODE" "$status" >> "$RESULT_DIR/summary.tsv"
    printf '%s: %s\n' "$MODE" "$status"
    cleanup
done
printf 'SSH results: %s\nThese guest measurements are not a WAN performance comparison.\n' "$RESULT_DIR"
[[ $failed -eq 0 ]]
