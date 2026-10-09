#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash -n install.sh scripts/package-release.sh
if command -v php >/dev/null 2>&1; then
  php -l deploy/site/services-monitoring/index.php
fi
cargo test --locked --bins
cargo build --locked --release --bins
bash scripts/package-release.sh
