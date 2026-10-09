# iMonitor 2.1

Free monitoring and tunnel management for Linux servers. Every check and
network tool is available without license keys, feature tiers, or a monitor
count limit. Source is available for inspection and unmodified builds under
the [use license](LICENSE): free personal and commercial use, with
modification and redistribution restricted.

## Install or upgrade with one command

On a supported x86-64 GNU/Linux server, run:

```sh
curl -fsSL https://github.com/iranmonitor/imonitor/releases/latest/download/install.sh | sudo bash
```

The same installer creates a fresh node or upgrades a detected paid/licensed
installation to the current free release. It keeps the existing database,
accounts, monitoring history, runtime files and service settings, backs them
up before replacement, and restarts the detected service. Existing installations
do not receive a new admin password. Application licensing credentials are
retired automatically when the upgraded database opens.

GitHub is the default download source. Website mirrors are awaiting the
2.1.0 publication; use GitHub until they are updated. After that, select the
IranMonitor mirror explicitly:

```sh
curl -fsSL https://iranmonitor.net/download/imonitor/install.sh | sudo env IMONITOR_DOWNLOAD_ENDPOINT=iranmonitor.net bash
```

See [installer details](docs/installer-upgrade.md) for prerequisites, detected
legacy layouts, backups, and rollback. No license key or iperf3 installation
is required.

## Workspaces

- Monitoring: service availability, latency, history, and alerts.
- Tunnels: a three-step setup helper, peer instructions, and diagnostics.
- Getting Started: a permanent guide and replayable first-login tutorial.

The UI uses frosted panels, subtle grain, responsive layouts, and light
bundled IBM Plex Sans and Vazirmatn typography in English and Persian.
Their SIL Open Font Licenses are included under `src/ui/fonts`. Admin and
public status pages have independent sponsored PNG placements.

The tutorial keeps the current control clear and places its card beside it.
Dialogs stay centered in the viewport, including after scrolling and on short
screens. The default logo is a bundled SVG eye; custom branding is supported.
Gaming, Secure and Custom presets use actual transports with editable
MTU, supported outer TTL/traffic class, VNI and native TUN lanes. Managed VXLAN,
GENEVE and GRETAP complement GRE, IPIP, GUE, ESP and WireGuard. See
[tunnel-profiles.md](docs/tunnel-profiles.md) for settings and peer requirements.
Source IP offers connection-tracked IPv4/IPv6 SNAT and the explicit legacy
paired rewrite mode, with cleanup restricted to this node's own rules.

## Build on Linux

Install Rust, a C compiler, Clang with BPF support, Linux development
headers, and SQLite's command-line program. On Debian/Ubuntu:

```sh
sudo apt-get install build-essential clang llvm libc6-dev linux-libc-dev libbpf-dev sqlite3
cargo build --locked --release --bins
cargo test --locked
```

The build script compiles `src/bpf/xdp_ingress.c`. For panel-only builds
or cross-compilation, set `IMONITOR_SKIP_BPF_BUILD=1`; package the XDP object
separately if you use XDP controls. Windows can run parser, UI, database,
and local-network tests. Production tunnel creation requires Linux.

## Start a node

```sh
./target/release/iranmonitor_node init \
  --db ./runtime/iranmonitor.db --data-dir ./runtime \
  --listen 127.0.0.1:6060 --username admin
./target/release/iranmonitor_node serve \
  --db ./runtime/iranmonitor.db --data-dir ./runtime \
  --listen 127.0.0.1:6060
```

Initialization prints a generated admin password. Save it and change it after signing in. Open `/admin` to sign in or
`/` for public status. Use the command above for Linux service setup.
The deprecated `--plan` flag is accepted
for old service configurations and has no effect. Upgrades retain saved
monitors and history and remove old application license credentials.

## Native tunnel speed test

Configure both peers with the same protocol and swap their public and
inner IPs. Copy the generated test token to the other peer and use the same
test port. The app binds its test listener to the local tunnel IP and
restricts it to the configured peer. A standalone peer can run the following;
replace `SHARED_TEST_TOKEN` with the generated UI token (32–128 ASCII characters)
and both sample addresses with the actual tunnel IPs:

```sh
imonitor speedtest-server --bind 10.20.0.2:5201 --peer 10.20.0.1 --token SHARED_TEST_TOKEN
```

The test measures TCP throughput between tunnel endpoints using four
parallel streams, with upload and download measured separately. It sends
test traffic only when requested. Challenge/HMAC authentication does not
transmit the shared token. Duration, transfer size, and concurrency are
bounded. This measures the tunnel path rather than general Internet speed.

GRE/IPIP do not encrypt traffic. WireGuard needs matching public keys;
SSH TUN needs `PermitTunnel`. The Secure preset defaults to WireGuard; new
manual ESP tunnels use AES-256-CBC/HMAC-SHA256 with directional HKDF keys.
Saved legacy GCM tunnels can retain their exact live security states, but the
app refuses unsafe static GCM recreation. Migrate both peers together to the
new ESP settings or WireGuard. Advanced modes depend on kernel support,
firewall rules, and correctly configured peers. The Guide explains setup
and diagnosis. Old local logos outside `runtime/branding` must be moved
into that directory and selected again to use the secured image handler.

## Runtime tools and advertising

HTTP/HTTPS and proxy checks use curl; ICMP uses ping; network controls use
ip, iptables, tc, and optionally bpftool. SSH/SFTP banner checks verify
service reachability rather than user authentication. Radar is opt-in.
TUN UDP uses socat, TUN ICMP uses ptunnel-ng, and password-based SSH uses
sshpass. The Debian/Ubuntu installer requests these tools; on other distributions,
install the matching packages when using those optional modes.

The future advertising API is described in
[docs/advertising-api.md](docs/advertising-api.md). An unavailable API leaves
the placement hidden. No license key, fingerprint, monitor settings, or
tunnel secrets are sent to it. Remote HTML and scripts are never accepted.

## Release preparation

Official source is maintained at [iranmonitor/imonitor](https://github.com/iranmonitor/imonitor).
Matching binaries and checksum manifests are published together under
[GitHub Releases](https://github.com/iranmonitor/imonitor/releases).
Prebuilt bundles target GNU/Linux x86-64 with glibc 2.31 or later; Alpine/musl
requires a native source build.
`dist/release-1.2.2` contains historical binaries and is not rebuilt by
editing source. Do not distribute those files as 2.1.0. The packaging script
in `scripts/` stages binaries, checksums, the installer, and version marker
together.

To run the prepared local bundle before publication, follow
[local-release.md](docs/local-release.md).

Run `scripts/verify-release.sh` on Linux before publication and follow
[the peer acceptance steps](docs/linux-acceptance.md) for kernel features and
throughput verification. Public-source packaging excludes historical billing
backend files; application licensing is removed.
