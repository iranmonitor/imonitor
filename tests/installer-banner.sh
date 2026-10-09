#!/usr/bin/env bash
# Exercise portable awk without executing installation or contacting a server.
set -euo pipefail
installer=${1:-$(dirname "$0")/../install.sh}
[[ $(tail -n 1 "$installer") == 'main "$@"' ]] || {
    printf 'Unexpected installer entry point; refusing to source it.\n' >&2
    exit 1
}
definitions=$(mktemp)
trap 'rm -f "$definitions"' EXIT
sed '$d' "$installer" > "$definitions"
source "$definitions"
banner=$(print_banner)
[[ $banner == *"iMonitor V${APP_VERSION} Installer"* ]]
[[ $banner == *$'\033[38;2;30;62;135m'* ]]
printf 'PASS: portable installer banner, without running installation\n'
