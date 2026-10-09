#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)"
arch="${IMONITOR_RELEASE_ARCH:-amd64}"
out="${IMONITOR_RELEASE_DIR:-dist/release-${version}}"
target="${CARGO_TARGET_DIR:-target}"
binary_dir="${IMONITOR_BINARY_DIR:-${target}/release}"
object="${IMONITOR_BPF_OBJECT:-target/bpf/xdp_ingress.o}"
for file in "${binary_dir}/iranmonitor_node" "${binary_dir}/imonitor-bpf" "$object"; do
  test -f "$file" || { printf 'Missing build artifact: %s\n' "$file" >&2; exit 1; }
done
mkdir -p "$out"
out_dir="$(cd "$out" && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
cp "${binary_dir}/iranmonitor_node" "$scratch/imonitor"
chmod 0755 "$scratch/imonitor"
(cd "$scratch" && zip -q "$out_dir/imonitor-v${version}-linux-${arch}.zip" imonitor)
cp "$out/imonitor-v${version}-linux-${arch}.zip" "$out/imonitor-linux-${arch}.zip"
cp "${binary_dir}/imonitor-bpf" "$scratch/imonitor-bpf"
cp "$object" "$scratch/xdp_ingress.o"
(cd "$scratch" && zip -q "$out_dir/imonitor-bpf-v${version}-${arch}.zip" imonitor-bpf xdp_ingress.o)
cp "$out/imonitor-bpf-v${version}-${arch}.zip" "$out/imonitor-bpf-${arch}.zip"
cp install.sh "$out/install.sh"
printf '%s\n' "$version" > "$out/latest-version.txt"
(cd "$out" && sha256sum ./*.zip install.sh latest-version.txt > sha256sums.txt)
printf 'Staged release %s in %s. Publish all files together.\n' "$version" "$out"
