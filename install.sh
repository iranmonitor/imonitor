#!/usr/bin/env bash
set -euo pipefail

APP_NAME="imonitor"
APP_VERSION="2.1.0"
IMONITOR_GITHUB_REPOSITORY="${IMONITOR_GITHUB_REPOSITORY:-iranmonitor/imonitor}"
IMONITOR_RELEASE_TAG="${IMONITOR_RELEASE_TAG:-v${APP_VERSION}}"
INSTALLER_URL=""
DOWNLOAD_BASE_URL=""
TOOLS_BASE_URL="https://iranmonitor.net/download/imonitor"
INSTALL_ROOT="/opt/imonitor"
BIN_DIR="${INSTALL_ROOT}/bin"
RUNTIME_DIR="${INSTALL_ROOT}/runtime"
DB_PATH="${RUNTIME_DIR}/iranmonitor.db"
CLI_LAUNCHER="/usr/local/bin/imonitor"
SERVICE_NAME="imonitor"
SYSTEMD_DIR="/etc/systemd/system"
VENDOR_SYSTEMD_DIR="/lib/systemd/system"
INITD_DIR="/etc/init.d"
SYSTEMD_UNIT="${SYSTEMD_DIR}/${SERVICE_NAME}.service"
OPENRC_SCRIPT="${INITD_DIR}/${SERVICE_NAME}"
LISTEN_ADDR="${IMONITOR_LISTEN_ADDR:-0.0.0.0:6060}"
ADMIN_USER="${IMONITOR_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${IMONITOR_ADMIN_PASSWORD:-}"
ASKED_FOR_SETUP=0
EXISTING_INSTALL=0
DETECTED_SERVICE_NAME=""
DETECTED_SERVICE_FILE=""
DETECTED_BINARY_PATH=""
BACKUP_DIR=""
SERVICE_STOPPED=0
BINARY_REPLACED=0
ASCII_ART="$(cat <<'EOF'
================================================================================
                                ≠≈∞∞∞≈                                      
                        ∞≈≈≈≈∞≈=÷÷÷÷÷=≠≈√√∞∞∞   π  √                        
                  ≈≈≈≈≈≠=÷÷÷=≠≈≈≈≈∞∞∞∞∞∞≈≠==≠≈√≈∞ -∞√π∞√√√                  
              ≠≠==××==≈≠≈≠≈∞              ≈≈∞≈≠÷=≠=  ≈≠==≠≈√√√              
           ≈≠=÷×÷=≠≠≈                         √≈≠÷÷≠≈  ≈√≈≠÷÷≠≈√=           
       =≠≠=÷×÷=≠≠-    =≠≈∞√        π≈∞∞∞≈∞∞√    ∞≠=÷≠=    π√≈≠==≠∞√√        
     ==÷××÷==≠      ≈≠÷÷÷≠         ∞=÷×÷÷÷÷=≈√    ≈÷÷÷≈      ∞∞∞≈≠÷≠∞∞√     
   ≠=÷×××=≠         ≠×××=   ≠≈≈≠≠≠  -÷×÷÷×÷÷÷=∞   ≠÷÷÷=√         √≠÷÷÷≠∞÷   
 ≈≠÷××-×-          ÷=×××=   ≠×××÷=≠≠÷×÷×××÷××÷∞   ≈÷÷÷÷≈          ÷=÷÷÷=∞   
   =÷÷××÷==         =×××=   ≈=÷××××××÷××÷××÷÷=∞   ≠÷÷÷=∞        ≠≈≠÷÷=≈∞√   
     ===÷×÷÷=≠      ≠÷××÷=    ≠=÷××××××××××÷≠≠    ≠÷=≈∞      √∞≈≠=÷≠∞∞      
        ==÷÷×÷÷==÷   ÷÷÷×÷=     ≠≠≠≠≠≠≠≈≠≈≠≈    π∞∞≈∞     ∞∞≈=÷÷=≈∞≈        
           ≠==÷××÷===  =÷×÷=≠                         √∞≈≠=÷÷=≠∞∞           
              ÷==÷÷×÷÷× -÷÷×÷=≠==÷             ≠==≈≈≈≠=÷÷=≠≈≈               
                  ====≠≠÷  ×≠≠=÷÷÷=≠≠≠≠≠≈≠≠≠≈≠÷÷÷×÷=≠≈≈≈≠≠                  
                        =≠≠    ≠≠=≠≠=÷÷×××÷=≠≈≠≠≠≠≠                         
================================================================================
EOF
)"

log() {
  printf '[iMonitor] %s\n' "$*"
}

print_community_links() {
  printf '\nStay connected with IranMonitor\n'
  printf '  Explore our projects and services: https://iranmonitor.net\n'
  printf '  Join our Telegram channel for news and updates: https://t.me/IranMonitorNet\n\n'
}

fail() {
  printf '[iMonitor] error: %s\n' "$*" >&2
  exit 1
}

set_download_endpoint() {
  case "$1" in
    github|github.com|1)
      [[ ${IMONITOR_GITHUB_REPOSITORY} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "IMONITOR_GITHUB_REPOSITORY must be owner/repository"
      [[ ${IMONITOR_RELEASE_TAG} =~ ^[A-Za-z0-9_.-]+$ ]] || fail "invalid IMONITOR_RELEASE_TAG"
      IMONITOR_DOWNLOAD_ENDPOINT="github"
      DOWNLOAD_BASE_URL="https://github.com/${IMONITOR_GITHUB_REPOSITORY}/releases/download/${IMONITOR_RELEASE_TAG}"
      ;;
    iranmonitor.net|iranmonitor|2)
      IMONITOR_DOWNLOAD_ENDPOINT="iranmonitor.net"
      DOWNLOAD_BASE_URL="https://${IMONITOR_DOWNLOAD_ENDPOINT}/download/imonitor"
      TOOLS_BASE_URL="${DOWNLOAD_BASE_URL}"
      ;;
    irnmo.ir|irnmo|3)
      IMONITOR_DOWNLOAD_ENDPOINT="irnmo.ir"
      DOWNLOAD_BASE_URL="https://${IMONITOR_DOWNLOAD_ENDPOINT}/download/imonitor"
      TOOLS_BASE_URL="${DOWNLOAD_BASE_URL}"
      ;;
    *)
      return 1
      ;;
  esac
  export IMONITOR_DOWNLOAD_ENDPOINT
  INSTALLER_URL="${DOWNLOAD_BASE_URL}/install.sh"
}

choose_download_endpoint() {
  local choice
  if [ -n "${IMONITOR_DOWNLOAD_ENDPOINT:-}" ]; then
    set_download_endpoint "${IMONITOR_DOWNLOAD_ENDPOINT}" || \
      fail "unknown IMONITOR_DOWNLOAD_ENDPOINT: ${IMONITOR_DOWNLOAD_ENDPOINT}"
    return 0
  fi

  if [ ! -t 0 ]; then
    set_download_endpoint "github"
    log "non-interactive install: using GitHub ${IMONITOR_GITHUB_REPOSITORY} (set IMONITOR_DOWNLOAD_ENDPOINT=iranmonitor.net or irnmo.ir for a mirror)"
    return 0
  fi

  printf 'Choose the download endpoint / دامنه دانلود را انتخاب کنید:\n'
  printf '  1) GitHub %s (default)\n' "${IMONITOR_GITHUB_REPOSITORY}"
  printf '  2) iranmonitor.net\n'
  printf '  3) irnmo.ir\n'
  read -r -p '> ' choice || true
  choice="${choice:-1}"
  set_download_endpoint "${choice}" || fail "please choose 1, 2 or 3"
  log "using ${IMONITOR_DOWNLOAD_ENDPOINT}"
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

print_banner() {
  printf '%s\n' "${ASCII_ART}" | awk -v start="1e3e87" -v end="5fbfcf" '
    function hex2dec(h,    value, i) {
      value = 0;
      for (i = 1; i <= length(h); i++) {
        value = value * 16 + index("0123456789abcdef", tolower(substr(h, i, 1))) - 1;
      }
      return value;
    }
    function clamp(x) { return (x < 0 ? 0 : (x > 255 ? 255 : x)); }
    function leading_indent(line,    i, ch) {
      for (i = 1; i <= length(line); i++) {
        ch = substr(line, i, 1);
        if (ch != " " && ch != "\t") return i - 1;
      }
      return length(line);
    }
    BEGIN {
      sr = hex2dec(substr(start,1,2)); sg = hex2dec(substr(start,3,2)); sb = hex2dec(substr(start,5,2));
      er = hex2dec(substr(end,1,2));   eg = hex2dec(substr(end,3,2));   eb = hex2dec(substr(end,5,2));
    }
    {
      sub(/[[:space:]]+$/, "", $0);
      lines[NR] = $0;
    }
    END {
      indent = -1;
      total = NR;
      for (l = 1; l <= total; l++) {
        if (lines[l] ~ /^[[:space:]]*$/) continue;
        current = leading_indent(lines[l]);
        if (indent < 0 || current < indent) indent = current;
      }
      if (indent < 0) indent = 0;
      for (l = 1; l <= total; l++) {
        line = substr(lines[l], indent + 1);
        n = length(line);
        if (n == 0) { print ""; continue; }
        for (i = 1; i <= n; i++) {
          ch = substr(line, i, 1);
          if (ch == " ") { printf " "; continue; }
          tline = (total <= 1) ? 0 : (l - 1) / (total - 1);
          tcol = (n <= 1) ? 0 : 1 - ((i - 1) / (n - 1));
          t = (tline + tcol) / 2;
          r = clamp(int(sr + (er - sr) * t));
          g = clamp(int(sg + (eg - sg) * t));
          b = clamp(int(sb + (eb - sb) * t));
          printf "\033[38;2;%d;%d;%dm%s", r, g, b, ch;
        }
        printf "\033[0m\n";
      }
    }'
  printf '\033[38;2;30;62;135miMonitor V%s Installer\033[0m\n\n' "${APP_VERSION}"
  print_community_links
}

need_root() {
  if [ "$(id -u)" -eq 0 ]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    log "root access is required; retrying with sudo"
    exec sudo -E bash -c "$(curl -fsSL "${INSTALLER_URL}")"
  fi
  fail "please run this installer as root"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    *) return 1 ;;
  esac
}

detect_service_manager() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    printf 'systemd'
    return 0
  fi
  if command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    printf 'openrc'
    return 0
  fi
  printf 'none'
}

parse_service_words() {
  # Parse quoted service arguments without evaluating shell code from the unit.
  local text="$1" word='' quote='' escaped=0 active=0 char index
  SERVICE_WORDS=()
  for ((index=0; index<${#text}; index++)); do
    char="${text:index:1}"
    if [ "${escaped}" -eq 1 ]; then word+="${char}"; escaped=0; active=1; continue; fi
    if [ "${quote}" = "'" ]; then
      if [ "${char}" = "'" ]; then quote=''; else word+="${char}"; fi
    elif [ "${char}" = '\' ]; then
      escaped=1; active=1
    elif [ -n "${quote}" ]; then
      if [ "${char}" = "${quote}" ]; then quote=''; else word+="${char}"; fi
    elif [ "${char}" = '"' ] || [ "${char}" = "'" ]; then
      quote="${char}"; active=1
    elif [[ ${char} == [[:space:]] ]]; then
      if [ "${active}" -eq 1 ]; then SERVICE_WORDS+=("${word}"); word=''; active=0; fi
    else
      word+="${char}"; active=1
    fi
  done
  [ -z "${quote}" ] && [ "${escaped}" -eq 0 ] || fail "could not parse the existing service command; its quoting is incomplete"
  if [ "${active}" -eq 1 ]; then SERVICE_WORDS+=("${word}"); fi
}

service_setting() {
  local value
  value="$(sed -n "s/^$2=//p" "$1" | head -n1)"
  value="$(trim "${value}")"
  if [[ ${value} == \"*\" ]]; then
    value="${value:1:${#value}-2}"
    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
  elif [[ ${value} == \'*\' ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "${value}"
}

absolute_service_path() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$2" "$1" ;;
  esac
}

detect_existing_install() {
  local exec_line service_file='' runtime_candidate='' listen_candidate='' binary_candidate='' db_candidate='' working_dir='' candidate index word active active_file='' seen='|' name
  local candidates=("${SYSTEMD_UNIT}" "${VENDOR_SYSTEMD_DIR}/${SERVICE_NAME}.service" "${SYSTEMD_DIR}/iranmonitor-node.service" "${VENDOR_SYSTEMD_DIR}/iranmonitor-node.service" "${OPENRC_SCRIPT}" "${INITD_DIR}/iranmonitor-node")
  for candidate in "${candidates[@]}"; do
    [ -f "${candidate}" ] || continue
    [ -n "${service_file}" ] || service_file="${candidate}"
    name="$(basename "${candidate}")"
    case "${seen}" in *"|${name}|"*) continue ;; esac
    seen+="${name}|"
    active=0
    if [[ ${candidate} == *.service ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl is-active --quiet "${name}" && active=1
    elif command -v rc-service >/dev/null 2>&1; then
      rc-service "${name}" status >/dev/null 2>&1 && active=1
    fi
    if [ "${active}" -eq 1 ]; then
      [ -z "${active_file}" ] || fail "multiple iMonitor services are active; stop the duplicate before upgrading"
      active_file="${candidate}"
    fi
  done
  [ -z "${active_file}" ] || service_file="${active_file}"

  if [ -n "${service_file}" ]; then
    DETECTED_SERVICE_FILE="${service_file}"
    DETECTED_SERVICE_NAME="$(basename "${service_file}")"
    if [[ ${service_file} == *.service ]]; then
      exec_line="$(sed -n 's/^ExecStart=//p' "${service_file}" | head -n1)"
      working_dir="$(service_setting "${service_file}" WorkingDirectory)"
      parse_service_words "${exec_line}"
      binary_candidate="${SERVICE_WORDS[0]:-}"
      # systemd permits a leading '-' to ignore an ExecStart failure.
      binary_candidate="${binary_candidate#-}"
    else
      binary_candidate="$(service_setting "${service_file}" command)"
      working_dir="$(service_setting "${service_file}" directory)"
      exec_line="$(service_setting "${service_file}" command_args)"
      parse_service_words "${exec_line}"
    fi
    working_dir="${working_dir:-/}"
    for ((index=0; index<${#SERVICE_WORDS[@]}; index++)); do
      word="${SERVICE_WORDS[index]}"
      case "${word}" in
        --data-dir) index=$((index+1)); runtime_candidate="${SERVICE_WORDS[index]:-}" ;;
        --data-dir=*) runtime_candidate="${word#*=}" ;;
        --db) index=$((index+1)); db_candidate="${SERVICE_WORDS[index]:-}" ;;
        --db=*) db_candidate="${word#*=}" ;;
        --listen) index=$((index+1)); listen_candidate="${SERVICE_WORDS[index]:-}" ;;
        --listen=*) listen_candidate="${word#*=}" ;;
      esac
    done
    for candidate in "${binary_candidate}" "${runtime_candidate}" "${db_candidate}"; do
      [[ ${candidate} != *'$'* && ${candidate} != *'%'* ]] || fail "existing service uses dynamic paths; resolve them before upgrading"
    done
    [ -z "${runtime_candidate}" ] || runtime_candidate="$(absolute_service_path "${runtime_candidate}" "${working_dir}")"
    [ -z "${db_candidate}" ] || db_candidate="$(absolute_service_path "${db_candidate}" "${working_dir}")"
    [ -z "${binary_candidate}" ] || binary_candidate="$(absolute_service_path "${binary_candidate}" "${working_dir}")"

    if [ -n "${runtime_candidate}" ]; then
      RUNTIME_DIR="${runtime_candidate}"
      INSTALL_ROOT="$(dirname "${RUNTIME_DIR}")"
      BIN_DIR="${INSTALL_ROOT}/bin"
    fi
    if [ -n "${listen_candidate}" ]; then
      LISTEN_ADDR="${listen_candidate}"
    fi
    if [ -n "${binary_candidate}" ] && [ -x "${binary_candidate}" ]; then
      DETECTED_BINARY_PATH="${binary_candidate}"
      BIN_DIR="$(dirname "${binary_candidate}")"
      INSTALL_ROOT="$(dirname "${BIN_DIR}")"
      if [ -z "${runtime_candidate}" ]; then
        RUNTIME_DIR="${INSTALL_ROOT}/runtime"
      fi
    fi
    [ -z "${db_candidate}" ] || DB_PATH="${db_candidate}"
    [ -n "${db_candidate}" ] || DB_PATH="${RUNTIME_DIR}/iranmonitor.db"
    [ -n "${DETECTED_BINARY_PATH}" ] || fail "existing service executable was not found; refusing to replace its configuration"
  fi

  if [ ! -f "${DB_PATH}" ] && [ -z "${service_file}" ]; then
    for candidate in \
      "/opt/imonitor/runtime" \
      "/usr/local/runtime" \
      "/var/www/imonitor/1.0/runtime" \
      "/var/www/iranmonitor/node_runtime" \
      "/opt/iranmonitor-node/runtime"
    do
      if [ -f "${candidate}/iranmonitor.db" ]; then
        RUNTIME_DIR="${candidate}"
        DB_PATH="${RUNTIME_DIR}/iranmonitor.db"
        INSTALL_ROOT="$(dirname "${RUNTIME_DIR}")"
        if [ -d "${INSTALL_ROOT}/bin" ]; then
          BIN_DIR="${INSTALL_ROOT}/bin"
        fi
        break
      fi
    done
  fi

  if [ ! -f "${DB_PATH}" ] && [ -z "${service_file}" ]; then
    return 1
  fi
  [ -f "${DB_PATH}" ] || fail "existing service database ${DB_PATH} was not found; refusing to initialize replacement credentials"

  EXISTING_INSTALL=1
  return 0
}

detect_package_manager() {
  for manager in apt-get dnf yum zypper pacman apk; do
    if command -v "${manager}" >/dev/null 2>&1; then
      printf '%s' "${manager}"
      return 0
    fi
  done
  return 1
}

write_cli_launcher() {
  local target_binary_path="$1"
  if [ "${target_binary_path}" = "${CLI_LAUNCHER}" ]; then return 0; fi
  mkdir -p "$(dirname "${CLI_LAUNCHER}")"
  rm -f "${CLI_LAUNCHER}"
  cat > "${CLI_LAUNCHER}" <<EOF
#!/usr/bin/env bash
exec "${target_binary_path}" "\$@"
EOF
  chmod 0755 "${CLI_LAUNCHER}"
}

cache_local_installer() {
  local local_installer="${INSTALL_ROOT}/install.sh" source_file="${BASH_SOURCE[0]:-}"
  if [ -n "${source_file}" ] && [ -r "${source_file}" ]; then
    cat "${source_file}" > "${local_installer}"
  else
    curl -fsSL "${INSTALLER_URL}" -o "${local_installer}" || return 0
  fi
  chmod 0700 "${local_installer}"
}

wait_for_apt_locks() {
  local waited=0
  local max_wait=180
  local locks=(
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
    /var/lib/dpkg/lock
    /var/lib/dpkg/lock-frontend
  )

  while command -v fuser >/dev/null 2>&1; do
    local busy=0
    local lock
    for lock in "${locks[@]}"; do
      if fuser "${lock}" >/dev/null 2>&1; then
        busy=1
        break
      fi
    done
    if [ "${busy}" -eq 0 ]; then
      return 0
    fi
    if [ "${waited}" -eq 0 ]; then
      log "another apt/dpkg process is running; waiting for the package manager lock"
    fi
    if [ "${waited}" -ge "${max_wait}" ]; then
      printf '\033[0;31m[iMonitor] warning: apt/dpkg lock did not clear after %ss; continuing with fallback logic.\033[0m\n' "${max_wait}" >&2
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
  return 0
}

download_fallback_binary() {
  local name="$1"
  local target="$2"
  local url="${TOOLS_BASE_URL}/${name}"

  mkdir -p "$(dirname "${target}")"
  if curl -fsSL "${url}" -o "${target}"; then
    chmod 0755 "${target}"
    chown root:root "${target}" 2>/dev/null || true
    log "installed hosted fallback: ${name}"
    return 0
  fi
  return 1
}

ensure_fallback_tools() {
  local missing=()

  if ! command -v bpftool >/dev/null 2>&1 || ! bpftool version >/dev/null 2>&1; then
    if ! download_fallback_binary "bpftool-amd64" "/usr/local/sbin/bpftool"; then
      missing+=("bpftool")
    fi
  fi

  if [ "${#missing[@]}" -gt 0 ]; then
    printf '\033[0;31m[iMonitor] warning: these hosted fallback tools could not be installed:\n' >&2
    printf '\033[0;31m - %s\033[0m\n' "${missing[@]}" >&2
  fi
}

install_packages() {
  local pm="$1"
  local failed=()
  local pkgs
  log "installing required packages with ${pm}"
  case "${pm}" in
    apt-get)
      export DEBIAN_FRONTEND=noninteractive
      local kernel_release
      local extra_bpftool_pkgs=()
      wait_for_apt_locks || true
      if ! apt-get update -y; then
        printf '\033[0;31m[iMonitor] warning: apt-get update failed; continuing with the existing package metadata.\033[0m\n' >&2
      fi
      pkgs=(ca-certificates curl unzip sqlite3 iproute2 iputils-ping iptables dnsutils openssh-client openssh-server sshpass socat ptunnel-ng procps wireguard-tools bpftool)
      if ! apt-get install -y "${pkgs[@]}"; then
        for pkg in "${pkgs[@]}"; do
          if ! apt-get install -y "${pkg}" >/dev/null 2>&1; then
            failed+=("${pkg}")
          fi
        done
      fi
      kernel_release="$(uname -r 2>/dev/null || true)"
      if [ -n "${kernel_release}" ]; then
        extra_bpftool_pkgs=(linux-tools-common linux-cloud-tools-common "linux-tools-${kernel_release}" "linux-cloud-tools-${kernel_release}")
        for pkg in "${extra_bpftool_pkgs[@]}"; do
          apt-get install -y "${pkg}" >/dev/null 2>&1 || true
        done
      fi
      ;;
    dnf)
      pkgs=(ca-certificates curl unzip sqlite iproute iputils iptables bind-utils openssh-clients openssh-server socat procps-ng wireguard-tools bpftool)
      if ! dnf install -y "${pkgs[@]}"; then
        for pkg in "${pkgs[@]}"; do
          if ! dnf install -y "${pkg}" >/dev/null 2>&1; then
            failed+=("${pkg}")
          fi
        done
      fi
      ;;
    yum)
      pkgs=(ca-certificates curl unzip sqlite iproute iputils iptables bind-utils openssh-clients openssh-server socat procps-ng wireguard-tools bpftool)
      if ! yum install -y "${pkgs[@]}"; then
        for pkg in "${pkgs[@]}"; do
          if ! yum install -y "${pkg}" >/dev/null 2>&1; then
            failed+=("${pkg}")
          fi
        done
      fi
      ;;
    zypper)
      if ! zypper --non-interactive refresh; then
        printf '\033[0;31m[iMonitor] warning: zypper refresh failed; continuing with the existing package metadata.\033[0m\n' >&2
      fi
      pkgs=(ca-certificates curl unzip sqlite3 iproute2 iputils iptables bind-utils openssh-clients openssh socat procps wireguard-tools bpftool)
      if ! zypper --non-interactive install "${pkgs[@]}"; then
        for pkg in "${pkgs[@]}"; do
          if ! zypper --non-interactive install "${pkg}" >/dev/null 2>&1; then
            failed+=("${pkg}")
          fi
        done
      fi
      ;;
    pacman)
      pkgs=(ca-certificates curl unzip sqlite iproute2 iputils iptables bind openssh socat procps-ng wireguard-tools bpftool)
      if ! pacman -Sy --noconfirm "${pkgs[@]}"; then
        for pkg in "${pkgs[@]}"; do
          if ! pacman -Sy --noconfirm "${pkg}" >/dev/null 2>&1; then
            failed+=("${pkg}")
          fi
        done
      fi
      ;;
    apk)
      pkgs=(ca-certificates curl unzip sqlite iproute2 iputils iptables bind-tools openssh-client openssh-server socat procps wireguard-tools bpftool openrc)
      if ! apk add --no-cache "${pkgs[@]}"; then
        for pkg in "${pkgs[@]}"; do
          if ! apk add --no-cache "${pkg}" >/dev/null 2>&1; then
            failed+=("${pkg}")
          fi
        done
      fi
      ;;
    *)
      fail "unsupported package manager: ${pm}"
      ;;
  esac

  if [ "${#failed[@]}" -gt 0 ]; then
    printf '\033[0;31m[iMonitor] warning: these packages failed to install automatically:\n' >&2
    printf '\033[0;31m - %s\033[0m\n' "${failed[@]}" >&2
    printf '\033[0;31mPlease install them manually if you need related features.\033[0m\n' >&2
  fi

  ensure_fallback_tools
}

write_systemd_unit() {
  if [ "${EXISTING_INSTALL}" -eq 1 ] && [ -n "${DETECTED_SERVICE_NAME}" ]; then
    systemctl daemon-reload
    systemctl restart "${DETECTED_SERVICE_NAME}"
    SERVICE_STOPPED=0
    return 0
  fi
  cat > "${SYSTEMD_UNIT}" <<EOF
[Unit]
Description=iMonitor V2.1.0
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${RUNTIME_DIR}
ExecStart="${BIN_DIR}/imonitor" serve --db "${DB_PATH}" --data-dir "${RUNTIME_DIR}" --listen "${LISTEN_ADDR}"
Restart=always
RestartSec=5
User=root
Group=root
PrivateTmp=true
ProtectHome=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectSystem=full
ReadWritePaths=${RUNTIME_DIR}
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}.service"
}

write_openrc_service() {
  if [ "${EXISTING_INSTALL}" -eq 1 ] && [ -n "${DETECTED_SERVICE_NAME}" ]; then
    rc-service "${DETECTED_SERVICE_NAME}" restart || rc-service "${DETECTED_SERVICE_NAME}" start
    SERVICE_STOPPED=0
    return 0
  fi
  cat > "${OPENRC_SCRIPT}" <<'EOF'
#!/sbin/openrc-run
name="iMonitor V2.1.0"
description="iMonitor monitoring and tunnel node"
command="__BINARY_PATH__"
command_args="serve --db \"__DB_PATH__\" --data-dir \"__RUNTIME_DIR__\" --listen __LISTEN_ADDR__"
command_background="yes"
pidfile="/run/imonitor.pid"
directory="__RUNTIME_DIR__"
output_log="/var/log/imonitor.log"
error_log="/var/log/imonitor.err"
depend() {
  need net
}
EOF
  sed -i "s#__LISTEN_ADDR__#${LISTEN_ADDR}#g; s#__BINARY_PATH__#${BIN_DIR}/imonitor#g; s#__DB_PATH__#${DB_PATH}#g; s#__RUNTIME_DIR__#${RUNTIME_DIR}#g" "${OPENRC_SCRIPT}"
  chmod 0755 "${OPENRC_SCRIPT}"
  rc-update add "${SERVICE_NAME}" default
  rc-service "${SERVICE_NAME}" restart || rc-service "${SERVICE_NAME}" start
}

generate_password() {
  local password=""
  while [ "${#password}" -lt 16 ]; do
    password="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16 || true)"
  done
  printf '%s' "${password}"
}

panel_host() {
  local host_ip=""
  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  host_ip="$(trim "${host_ip}")"
  if [ -z "${host_ip}" ]; then
    host_ip="127.0.0.1"
  fi
  printf '%s' "${host_ip}"
}

prompt_for_setup() {
  local port_input username_input password_input confirm_input
  [ -t 0 ] || return 0

  ASKED_FOR_SETUP=1
  if [ "${EXISTING_INSTALL}" -eq 1 ]; then
    printf 'Update setup\n'
    printf 'Existing iMonitor service detected. Current runtime and port will be preserved automatically.\n\n'
    return 0
  fi

  printf 'Interactive setup\n'
  printf 'Press Enter to keep defaults shown in brackets.\n\n'

  read -r -p "Panel port [${LISTEN_ADDR##*:}]: " port_input || true
  port_input="${port_input//[[:space:]]/}"
  if [ -n "${port_input}" ]; then
    case "${port_input}" in
      ''|*[!0-9]*)
        fail "panel port must be a number"
        ;;
    esac
    if [ "${port_input}" -lt 1 ] || [ "${port_input}" -gt 65535 ]; then
      fail "panel port must be between 1 and 65535"
    fi
    LISTEN_ADDR="0.0.0.0:${port_input}"
  fi

  read -r -p "Admin username [${ADMIN_USER}]: " username_input || true
  if [ -n "${username_input}" ]; then
    ADMIN_USER="${username_input}"
  fi

  read -r -s -p "Admin password [auto-generate if empty]: " password_input || true
  printf '\n'
  if [ -n "${password_input}" ]; then
    read -r -s -p "Confirm admin password: " confirm_input || true
    printf '\n'
    if [ "${password_input}" != "${confirm_input}" ]; then
      fail "password confirmation does not match"
    fi
    ADMIN_PASSWORD="${password_input}"
  fi

  printf '\n'
}

verify_bundle() {
  local name="$1" scratch="$2" selected
  selected="${scratch}/selected-${name}.sha256"
  awk -v name="${name}" '{ file=$2; sub(/^\*/, "", file); sub(/^\.\//, "", file); if (file == name) print }' "${scratch}/sha256sums.txt" > "${selected}"
  [ "$(wc -l < "${selected}")" -eq 1 ] || fail "release checksum is missing or duplicated for ${name}"
  (cd "${scratch}" && sha256sum -c "${selected}")
}

stop_existing_service() {
  [ -n "${DETECTED_SERVICE_NAME}" ] || return 0
  case "$1" in
    systemd) systemctl stop "${DETECTED_SERVICE_NAME}" ;;
    openrc) rc-service "${DETECTED_SERVICE_NAME}" stop ;;
  esac
  SERVICE_STOPPED=1
}

backup_existing_install() {
  local binary="$1" backup_root="${RUNTIME_DIR}-backups" companion
  [ "${EXISTING_INSTALL}" -eq 1 ] || return 0
  mkdir -p "${backup_root}"
  chmod 0700 "${backup_root}"
  BACKUP_DIR="$(mktemp -d "${backup_root}/pre-${APP_VERSION}-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
  tar -C "${RUNTIME_DIR}" -cpf "${BACKUP_DIR}/runtime.tar" .
  cp -pL "${DB_PATH}" "${BACKUP_DIR}/database"
  for companion in -wal -shm; do
    [ ! -f "${DB_PATH}${companion}" ] || cp -pL "${DB_PATH}${companion}" "${BACKUP_DIR}/database${companion}"
  done
  [ ! -f "${binary}" ] || cp -pL "${binary}" "${BACKUP_DIR}/previous-binary"
  [ -z "${DETECTED_SERVICE_FILE}" ] || cp -a "${DETECTED_SERVICE_FILE}" "${BACKUP_DIR}/service-file"
  printf 'binary=%s\ndatabase=%s\nruntime=%s\nservice=%s\n' "${binary}" "${DB_PATH}" "${RUNTIME_DIR}" "${DETECTED_SERVICE_FILE}" > "${BACKUP_DIR}/paths.txt"
  log "saved pre-upgrade backup: ${BACKUP_DIR}"
}

atomic_install_binary() {
  local source="$1" destination="$2" staged
  mkdir -p "$(dirname "${destination}")"
  staged="$(mktemp "$(dirname "${destination}")/.imonitor-upgrade-XXXXXX")"
  if ! install -m 0755 "${source}" "${staged}" || ! mv -f "${staged}" "${destination}"; then
    rm -f "${staged}"
    fail "could not replace ${destination}"
  fi
}

installer_cleanup() {
  local status=$?
  [ -z "${INSTALL_TMP_DIR:-}" ] || rm -rf "${INSTALL_TMP_DIR}"
  if [ "${status}" -ne 0 ] && [ "${SERVICE_STOPPED}" -eq 1 ]; then
    if [ "${BINARY_REPLACED}" -eq 0 ]; then
      case "${INSTALL_SERVICE_MANAGER}" in
        systemd) systemctl start "${DETECTED_SERVICE_NAME}" || true ;;
        openrc) rc-service "${DETECTED_SERVICE_NAME}" start || true ;;
      esac
    else
      log "upgrade did not finish; backup retained at ${BACKUP_DIR}. Restore that backup before running the previous version."
    fi
  fi
  return "${status}"
}

main() {
  choose_download_endpoint
  need_root
  print_banner

  local arch service_manager package_manager bundle_name bundle_url sums_url tmp_dir bundle_path binary_path target_binary_path init_output fresh_install bpf_bundle_name bpf_bundle_url bpf_bundle_path have_bpf=0
  arch="$(detect_arch)" || fail "unsupported architecture: $(uname -m)"
  if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    fail "This prebuilt bundle requires GNU libc. On Alpine/musl, build iMonitor from source with your native Rust toolchain."
  fi
  service_manager="$(detect_service_manager)"
  INSTALL_SERVICE_MANAGER="${service_manager}"
  [ "${service_manager}" != "none" ] || fail "this installer currently supports systemd or openrc based Linux distributions"
  package_manager="$(detect_package_manager)" || fail "could not detect a supported package manager"
  fresh_install=0

  detect_existing_install || true
  prompt_for_setup

  bundle_name="imonitor-v${APP_VERSION}-linux-${arch}.zip"
  bundle_url="${DOWNLOAD_BASE_URL}/${bundle_name}"
  sums_url="${DOWNLOAD_BASE_URL}/sha256sums.txt"
  bpf_bundle_name="imonitor-bpf-v${APP_VERSION}-${arch}.zip"
  bpf_bundle_url="${DOWNLOAD_BASE_URL}/${bpf_bundle_name}"
  tmp_dir="$(mktemp -d)"
  INSTALL_TMP_DIR="${tmp_dir}"
  bundle_path="${tmp_dir}/${bundle_name}"
  bpf_bundle_path="${tmp_dir}/${bpf_bundle_name}"

  trap installer_cleanup EXIT

  install_packages "${package_manager}"

  log "downloading free iMonitor ${APP_VERSION} bundle"
  curl -fsSL "${bundle_url}" -o "${bundle_path}"
  curl -fsSL "${sums_url}" -o "${tmp_dir}/sha256sums.txt"
  verify_bundle "${bundle_name}" "${tmp_dir}"

  unzip -oq "${bundle_path}" -d "${tmp_dir}/bundle"
  binary_path="${tmp_dir}/bundle/imonitor"
  [ -f "${binary_path}" ] || fail "downloaded bundle did not contain the imonitor binary"
  chmod 0755 "${binary_path}"
  "${binary_path}" help | grep -F "iMonitor V${APP_VERSION}" >/dev/null || fail "downloaded binary does not match installer version ${APP_VERSION}"
  log "downloading source ip engine bundle"
  if curl -fsSL "${bpf_bundle_url}" -o "${bpf_bundle_path}"; then
    verify_bundle "${bpf_bundle_name}" "${tmp_dir}"
    unzip -oq "${bpf_bundle_path}" -d "${tmp_dir}/bpf"
    [ -f "${tmp_dir}/bpf/imonitor-bpf" ] && [ -f "${tmp_dir}/bpf/xdp_ingress.o" ] || fail "source ip engine bundle is incomplete"
    have_bpf=1
  else
    log "warning: source ip engine bundle not available; existing source ip rules and helper files will be preserved"
  fi

  target_binary_path="${BIN_DIR}/imonitor"
  if [ -n "${DETECTED_BINARY_PATH}" ]; then
    target_binary_path="${DETECTED_BINARY_PATH}"
  fi

  stop_existing_service "${service_manager}"
  backup_existing_install "${target_binary_path}"
  mkdir -p "${BIN_DIR}" "${RUNTIME_DIR}"
  if [ "${EXISTING_INSTALL}" -eq 0 ]; then chmod 0700 "${INSTALL_ROOT}" "${BIN_DIR}" "${RUNTIME_DIR}"; fi
  atomic_install_binary "${binary_path}" "${target_binary_path}"
  BINARY_REPLACED=1
  write_cli_launcher "${target_binary_path}"
  cache_local_installer

  if [ "${have_bpf}" -eq 1 ]; then
    atomic_install_binary "${tmp_dir}/bpf/imonitor-bpf" "${BIN_DIR}/imonitor-bpf"
    chmod 0700 "${BIN_DIR}/imonitor-bpf"
    mkdir -p "${INSTALL_ROOT}/bpf"
    install -m 0600 "${tmp_dir}/bpf/xdp_ingress.o" "${INSTALL_ROOT}/bpf/xdp_ingress.o"
    log "source ip engine installed"
  fi

  if [ ! -f "${DB_PATH}" ]; then
    fresh_install=1
    if [ -z "${ADMIN_PASSWORD}" ]; then
      ADMIN_PASSWORD="$(generate_password)"
    fi
    log "initializing iMonitor runtime"
    init_output="$("${target_binary_path}" init --db "${DB_PATH}" --data-dir "${RUNTIME_DIR}" --listen "${LISTEN_ADDR}" --username "${ADMIN_USER}" --password "${ADMIN_PASSWORD}")"
    printf '%s\n' "${init_output}" > "${RUNTIME_DIR}/install-init.json"
    chmod 0600 "${RUNTIME_DIR}/install-init.json"
  else
    log "existing runtime detected at ${RUNTIME_DIR}; preserving current database and admin credentials"
  fi

  case "${service_manager}" in
    systemd) write_systemd_unit ;;
    openrc) write_openrc_service ;;
  esac

  if [ "${EXISTING_INSTALL}" -eq 1 ]; then
    log "update completed"
    if [ -n "${DETECTED_SERVICE_NAME}" ]; then
      log "updated service: ${DETECTED_SERVICE_NAME}"
    fi
    log "updated binary: ${target_binary_path}"
  else
    log "installation completed"
  fi
  log "panel address: http://$(panel_host):${LISTEN_ADDR##*:}/admin/login"
  if [ "${fresh_install}" -eq 1 ]; then
    log "admin username: ${ADMIN_USER}"
    log "admin password: ${ADMIN_PASSWORD}"
  fi
  log "for the local CLI management panel, run: imonitor"
  print_community_links
}

if [[ ${BASH_SOURCE[0]:-$0} == "$0" ]]; then main "$@"; fi
