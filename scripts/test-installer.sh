#!/usr/bin/env bash
# Disposable filesystem and command stubs: never touches a host service or DB.
set -euo pipefail
INSTALLER="$(cd "$(dirname "$0")/.." && pwd)/install.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/imonitor-installer-test-XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT
mkdir -p "$TEST_ROOT/assets"
# Real ZIP fixtures, extracted by the real unzip; their executables only log
# calls and create a marker DB for fresh initialization.
printf '%s' 'UEsDBBQAAAAIADWWSV1exF1HHQEAAJkBAAAIAAAAaW1vbml0b3JdUNtKw0AQfc9XjNtISWF7ezOhlVQjLdQqSSiISkiaiRkIm5DdaLH0392sFMSnObPnwpkdXE062U4yEhMUn5ClsrQkKuDY1dBQg0VKldW0JFQBw2v5JobA7BGD5VLP02YXxf52G4RJHERxstrs/PAludNPkXt7ZtYhldjrZi4/MyBhAZRYNQ5cEumxFqTqFvaX7P+Z62D7nOyDMNo87Vw+H8/GUx3leTqKtNXRE0CWVCiDvkqqEF7BHgD/UDCFdw/y2lDaUGiG2TMGC+A8z3pSlSggzxb23PuNAQ2w0r3N5kFBxp3XAg24VH8Ig2jN7/3YX/lR0Jc3X5Jn5vK/yhPrm1Ja0TfmzFVth2etNxpzyMgBPJKCm2m/o0wP1g9QSwECFAAUAAAACAA1lkldXsRdRx0BAACZAQAACAAAAAAAAAAAAAAAgAEAAAAAaW1vbml0b3JQSwUGAAAAAAEAAQA2AAAAQwEAAAAA' | base64 -d > "$TEST_ROOT/assets/imonitor-v2.1.0-linux-amd64.zip"
printf '%s' 'UEsDBBQAAAAIADWWSV3ihkXDEwAAABEAAAAMAAAAaW1vbml0b3ItYnBmU1bUT8rM0y/O4EqtyCxRMOACAFBLAwQUAAAACAA1lkldkDXGXREAAAAPAAAADQAAAHhkcF9pbmdyZXNzLm9Ly6woKS1K1c1PykpNLuECAFBLAQIUABQAAAAIADWWSV3ihkXDEwAAABEAAAAMAAAAAAAAAAAAAACAAQAAAABpbW9uaXRvci1icGZQSwECFAAUAAAACAA1lkldkDXGXREAAAAPAAAADQAAAAAAAAAAAAAAgAE9AAAAeGRwX2luZ3Jlc3Mub1BLBQYAAAAAAgACAHUAAAB5AAAAAAA=' | base64 -d > "$TEST_ROOT/assets/imonitor-bpf-v2.1.0-amd64.zip"
(cd "$TEST_ROOT/assets" && sha256sum ./*.zip > sha256sums.txt)

assert() { "$@" || { printf 'FAIL: %s\n' "$*" >&2; exit 1; }; }

run_case() (
  trap - EXIT
  local name=$1 mode=$2 expected=$3
  # Source the real functions, then redirect every writable location and every
  # external network/package/service operation to this case's fixture.
  source "$INSTALLER"
  CASE_ROOT="$TEST_ROOT/$name"
  INSTALL_ROOT="$CASE_ROOT/opt/imonitor"
  BIN_DIR="$INSTALL_ROOT/bin"
  RUNTIME_DIR="$INSTALL_ROOT/runtime"
  DB_PATH="$RUNTIME_DIR/iranmonitor.db"
  SYSTEMD_DIR="$CASE_ROOT/etc/systemd/system"
  VENDOR_SYSTEMD_DIR="$CASE_ROOT/lib/systemd/system"
  INITD_DIR="$CASE_ROOT/etc/init.d"
  SYSTEMD_UNIT="$SYSTEMD_DIR/imonitor.service"
  OPENRC_SCRIPT="$INITD_DIR/imonitor"
  CLI_LAUNCHER="$CASE_ROOT/usr/local/bin/imonitor"
  SERVICE_LOG="$CASE_ROOT/service-calls.log"
  DOWNLOAD_LOG="$CASE_ROOT/downloads.log"
  export INSTALLER_TEST_BINARY_CALLS="$CASE_ROOT/binary-calls.log"
  mkdir -p "$BIN_DIR" "$RUNTIME_DIR" "$SYSTEMD_DIR" "$VENDOR_SYSTEMD_DIR" "$INITD_DIR"
  : > "$SERVICE_LOG"; : > "$DOWNLOAD_LOG"; : > "$INSTALLER_TEST_BINARY_CALLS"
  ACTIVE_SERVICE='' CORRUPT='' FIXTURE_MANAGER=systemd
  IMONITOR_DOWNLOAD_ENDPOINT=github
  need_root() { :; }
  print_banner() { :; }
  prompt_for_setup() { :; }
  detect_arch() { printf amd64; }
  detect_package_manager() { printf fixture; }
  detect_service_manager() { printf '%s' "$FIXTURE_MANAGER"; }
  install_packages() { :; }
  panel_host() { printf 127.0.0.1; }
  systemctl() {
    printf '%s\n' "$*" >> "$SERVICE_LOG"
    if [ "${1:-}" = is-active ]; then [ "${*: -1}" = "$ACTIVE_SERVICE" ]; else return 0; fi
  }
  rc-service() {
    printf 'openrc %s\n' "$*" >> "$SERVICE_LOG"
    if [ "${2:-}" = status ]; then [ "${1:-}" = "$ACTIVE_SERVICE" ]; else return 0; fi
  }
  rc-update() { printf 'openrc-enable %s\n' "$*" >> "$SERVICE_LOG"; }
  curl() {
    local url='' output='' filename arg
    while [ $# -gt 0 ]; do
      arg=$1; shift
      if [ "$arg" = -o ]; then output=$1; shift
      elif [[ $arg == https://* ]]; then url=$arg; fi
    done
    printf '%s\n' "$url" >> "$DOWNLOAD_LOG"
    filename=${url##*/}
    [ -f "$TEST_ROOT/assets/$filename" ] || return 22
    cp "$TEST_ROOT/assets/$filename" "$output"
    if [ "$CORRUPT" = "$filename" ]; then printf 'corrupt fixture\n' >> "$output"; fi
  }
  old_binary="$BIN_DIR/imonitor" old_db="$DB_PATH" old_runtime="$RUNTIME_DIR" old_service="$SYSTEMD_UNIT"
  case "$mode" in
    fresh)
      # No host fallback discovery is needed for an absent disposable fixture.
      detect_existing_install() { return 1; }
      ADMIN_PASSWORD=FRESH-ONLY-TEST-PASSWORD
      ;;
    packaged|corrupt-main|corrupt-helper|wrong-version)
      ACTIVE_SERVICE=imonitor.service
      ;;
    node|custom-db|active-node)
      old_runtime="$CASE_ROOT/var/www/imonitor/1.0/runtime"
      old_binary="$CASE_ROOT/var/www/imonitor/1.0/export/iranmonitor_node"
      old_db="$old_runtime/iranmonitor.db"
      old_service="$SYSTEMD_DIR/iranmonitor-node.service"
      ACTIVE_SERVICE=iranmonitor-node.service
      if [ "$mode" = custom-db ]; then
        old_runtime="$CASE_ROOT/data with spaces"
        old_binary="$CASE_ROOT/bin with spaces/iranmonitor_node"
        old_db="$CASE_ROOT/database with spaces/custom-paid.db"
      fi
      ;;
    openrc)
      old_runtime="$CASE_ROOT/custom data/runtime"
      old_binary="$CASE_ROOT/custom bin/paid-node"
      old_db="$CASE_ROOT/custom database/paid.db"
      old_service="$INITD_DIR/iranmonitor-node"
      ACTIVE_SERVICE=iranmonitor-node
      FIXTURE_MANAGER=openrc
      ;;
  esac
  if [ "$mode" != fresh ]; then
    mkdir -p "$(dirname "$old_binary")" "$old_runtime/branding" "$(dirname "$old_db")"
    printf '#!/bin/sh\nprintf "iMonitor V1.2.2\\n"\n' > "$old_binary"
    chmod 0755 "$old_binary"
    printf 'PAID-DB admin-password-hash checks listen=127.0.0.1:7443\n' > "$old_db"
    printf 'WAL-sentinel\n' > "$old_db-wal"
    printf 'SHM-sentinel\n' > "$old_db-shm"
    printf 'engine-key-sentinel\n' > "$old_runtime/.engine.key"
    printf 'monitor-state-sentinel\n' > "$old_runtime/monitor_state.json"
    printf 'branding-sentinel\n' > "$old_runtime/branding/logo.svg"
    if [ "$mode" = openrc ]; then
      cat > "$old_service" <<EOF
#!/sbin/openrc-run
command="$old_binary"
command_args="serve --db \"$old_db\" --data-dir \"$old_runtime\" --listen 127.0.0.1:7443"
directory="$old_runtime"
EOF
    else
      cat > "$old_service" <<EOF
[Service]
WorkingDirectory="$old_runtime"
ExecStart="$old_binary" serve --db "$old_db" --data-dir "$old_runtime" --listen 127.0.0.1:7443
Environment=KEEP-CUSTOM-UNIT-SETTING
EOF
    fi
    if [ "$mode" = active-node ]; then
      printf '[Service]\nExecStart=/missing/inactive/imonitor serve\n' > "$SYSTEMD_UNIT"
    fi
    cp "$old_service" "$CASE_ROOT/original-service"
    cp "$old_db" "$CASE_ROOT/original-database"
    cp "$old_binary" "$CASE_ROOT/original-binary"
  fi
  case "$mode" in
    corrupt-main) CORRUPT=imonitor-v2.1.0-linux-amd64.zip ;;
    corrupt-helper) CORRUPT=imonitor-bpf-v2.1.0-amd64.zip ;;
    wrong-version) export INSTALLER_TEST_HELP_VERSION=1.2.2 ;;
  esac
  # Do not put main in an if/! condition: that would disable its errexit checks.
  local status=0
  set +e
  (set -e; main </dev/null) > "$CASE_ROOT/installer.log" 2>&1
  status=$?
  set -e
  if [ "$expected" = failure ]; then
    assert test "$status" -ne 0
    assert cmp "$old_binary" "$CASE_ROOT/original-binary"
    assert cmp "$old_db" "$CASE_ROOT/original-database"
    assert test "$(grep -Ec '^(stop |restart |openrc .* (stop|restart))' "$SERVICE_LOG" || true)" -eq 0
  else
    if [ "$status" -ne 0 ]; then cat "$CASE_ROOT/installer.log" >&2; exit "$status"; fi
    assert grep -Fq 'https://github.com/iranmonitor/imonitor/releases/download/v2.1.0/imonitor-v2.1.0-linux-amd64.zip' "$DOWNLOAD_LOG"
    if [ "$mode" = fresh ]; then
      assert grep -q '^init ' "$INSTALLER_TEST_BINARY_CALLS"
      assert grep -Fq 'FRESH-DATABASE' "$DB_PATH"
      assert grep -Fq -- "--db \"$DB_PATH\" --data-dir \"$RUNTIME_DIR\"" "$SYSTEMD_UNIT"
      assert grep -q '^enable --now imonitor.service$' "$SERVICE_LOG"
    else
      assert cmp "$old_service" "$CASE_ROOT/original-service"
      assert cmp "$old_db" "$CASE_ROOT/original-database"
      assert test "$(grep -c '^init ' "$INSTALLER_TEST_BINARY_CALLS" || true)" -eq 0
      assert grep -Fq 'engine-key-sentinel' "$old_runtime/.engine.key"
      assert grep -Fq 'monitor-state-sentinel' "$old_runtime/monitor_state.json"
      assert grep -Fq 'branding-sentinel' "$old_runtime/branding/logo.svg"
      assert grep -q 'INSTALLER_TEST_BINARY_CALLS' "$old_binary"
      assert test -f "$(dirname "$old_binary")/imonitor-bpf"
      assert grep -q "restart $ACTIVE_SERVICE\|openrc $ACTIVE_SERVICE restart" "$SERVICE_LOG"
      local backup
      backup=$(find "$old_runtime-backups" -name previous-binary -print -quit)
      assert test -n "$backup"
      assert cmp "$backup" "$CASE_ROOT/original-binary"
      assert cmp "${backup%/*}/database" "$CASE_ROOT/original-database"
      assert cmp "${backup%/*}/database-wal" "$old_db-wal"
      assert cmp "${backup%/*}/database-shm" "$old_db-shm"
      assert tar -tf "${backup%/*}/runtime.tar" ./monitor_state.json >/dev/null
      if [ "$mode" = active-node ]; then assert test "$(grep -c '^stop imonitor.service$' "$SERVICE_LOG" || true)" -eq 0; fi
    fi
  fi
  printf 'PASS %s\n' "$name"
)

run_case fresh-install fresh success
run_case paid-1.2.2-packaged packaged success
run_case original-node-service node success
run_case custom-db-and-quoted-paths custom-db success
run_case quoted-openrc-service openrc success
run_case active-node-over-inactive-unit active-node success
run_case reject-corrupt-main corrupt-main failure
run_case reject-corrupt-helper corrupt-helper failure
run_case reject-wrong-version wrong-version failure

(
  source "$INSTALLER"
  set_download_endpoint iranmonitor.net
  assert test "$DOWNLOAD_BASE_URL" = https://iranmonitor.net/download/imonitor
  set_download_endpoint irnmo.ir
  assert test "$DOWNLOAD_BASE_URL" = https://irnmo.ir/download/imonitor
  IMONITOR_GITHUB_REPOSITORY=example/fork
  set_download_endpoint github
  assert test "$DOWNLOAD_BASE_URL" = https://github.com/example/fork/releases/download/v2.1.0
)
printf 'PASS official-mirrors-and-configurable-repository\nInstaller fixtures: 10 passed\n'
