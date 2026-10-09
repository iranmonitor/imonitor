# Deployment acceptance and benchmarks

The local overhaul compiles for Linux x86-64 and includes checksum-correct
source-IP rewriting with owned tc/XDP cleanup. Disposable Linux namespace
acceptance covers actual kernel traffic; its recorded results accompany the
local release in [local-validation-2.1.0.md](local-validation-2.1.0.md). It does
not establish real cross-server throughput. Use two disposable Linux servers
to complete these deployment checks and follow the reproducible comparison in
[protocol-validation.md](protocol-validation.md).

1. Back up the existing runtime database and settings. Upgrade a 1.2.2 instance
   and confirm monitors, users, folders, and history survive without license keys.
2. Create each supported tunnel on both peers using the UI. Swap outer and inner
   addresses, match keys/ports, and allow the protocol in host/provider firewalls.
   For WireGuard, use each other’s public keys; for SSH TUN, configure PermitTunnel.
3. Ping inner peer IPs, transfer a file, and run the native upload/download test.
   Verify rejection of an incorrect token and traffic binding to inner addresses.
4. Compare throughput, CPU, packet loss, and latency with the original 1.2.2
   on the same path and test duration. Repeat under sustained load. Investigate
   any meaningful regression before releasing; no numeric performance guarantee
   is established by the local loopback suite.
5. Keep tunnels idle and busy through several monitoring intervals. Confirm
   TUN/SSH children remain running and WireGuard/ESP probes preserve live sessions.
   Restart the panel, edit an unrelated label, then disable/delete a tunnel and
   check ownership and helper cleanup. Monitoring-only interfaces must survive.
6. Exercise source-IP/XDP rules, forwarding, enabled/disabled shaping, and
   backups on a disposable interface. Confirm unrelated network state is kept.
7. Check English/Persian login, tour, wizard, diagnostics, alerts, and public
   visibility over a TLS reverse proxy on desktop/mobile. Public status must
   exclude private tunnels and secrets.
8. Publish matching versioned bundles, installer, checksums, and version marker
   together. Configure the proposed ad API separately and the official source
   repository URL in the prepared service-page template.

The provided x86-64 binaries target glibc 2.31 or later. Advanced tunnel modes
require suitable kernel modules and network permissions. Other architectures
can be built from source; a prebuilt ARM installer bundle is not included.
