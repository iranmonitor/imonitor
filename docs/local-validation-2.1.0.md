# iMonitor 2.1.0 local validation

Recorded 2026-10-09. These are local release checks; no deployment or WAN speed guarantee is claimed.

- Windows Rust: 113 passing tests; optional fixtures are recorded separately.
- Linux Rust: 115 passing normal tests, plus explicitly invoked privileged fixtures.
- Browser: 44 served UI checks, 27 checks against the final extracted preview ZIP, and 12 source-guide checks.
- Running app: 46 HTTP/SQLite checks, including legacy migration, visibility, branding and form validation.
- GitHub installer: 10 disposable fixtures pass on Linux, including legacy paths, custom databases, OpenRC and corrupt downloads.
- Shell syntax, the installer banner with Debian mawk, compiled BPF packet fixtures, bundle contents, SHA-256 aliases and Unix executable modes pass.

The disposable guest uses Debian Linux 6.1.0-50-amd64 (6.1.176-1), two emulated CPUs and no external network adapter. Separate namespaces provide actual peer traffic. The final production-helper slice runs the exact packaged release binaries; their hashes are in the accompanying record.

## Actual tunnel checks

| Slice | Configurations | Result |
| --- | --- | --- |
| Kernel and direct native TCP | 21 IPv4/IPv6 configurations: GRE, IPIP, SIT, GRETAP, VXLAN, GENEVE, GUE, ESP CBC/HMAC, WireGuard, L2TP UDP/IP, TCP TUN one/four lanes | Pass |
| Production SSH | SSH initiator and Reverse SSH receiver | Pass |
| Production TUN carriers | UDP IPv4/IPv6, BIP UDP alias, TCP one/four lanes, ICMP one/four lanes | Pass |

The checks exchange pings in both directions, test MTU boundaries, verify outer source/packet settings where supported, authenticate native four-stream upload/download, reject a wrong test token, and inspect interface/helper reuse. Production UDP/TCP reject an unexpected outer peer. Source/interface mismatch checks preserve existing helpers and recover after restoring the valid selection.

Kernel configurations were checked in several slices during development; the corrected GUE mode and all production helper modes pass with the final release. Earlier capture/fixture failures and actual GUE, forwarding, IPv6 UDP bind and speed-test deadline faults were corrected and rerun.

The full release slice recorded one false IPv6 UDP reuse failure: Bash interpreted brackets in the helper command as patterns. After quoting the comparison, the IPv6 UDP slice passed with identical packaged binaries. Both logs are retained, and the Linux normal-test totals come from the full slice.

## Source IP and network controls

Real IPv4/IPv6 SNAT and conntrack replies pass. Paired IPv4 tc NAT and the loaded XDP program exchange checksum-valid traffic and clean up only owned resources. The C packet fixture covers TCP/UDP, zero checksums, ESP payload preservation, IPv4 options, fragments and malformed lengths. Forwarding, overlapping counters, shaping reapply/remove and connection limits pass. Raw protocol selectors round-trip through real tc; this does not claim end-to-end traffic for every possible IP protocol.

## Deployment limits and benchmark

No two-host WAN comparison against 1.2.2 was performed. Follow [protocol-validation.md](protocol-validation.md) and fill [benchmark-record.csv](benchmark-record.csv) on two disposable deployment hosts. Keep the traffic generator, path, crypto, MTU, lane count and monitoring load identical.

EtherIP needs an external implementation; managed Ethernet alternatives are provided. AH address rewriting is rejected. Manual ESP has no automatic rekey, and unsafe static legacy GCM recreation is refused. The prebuilt binaries require x86-64 GNU/Linux with glibc 2.31+; ARM and musl builds are not included. The future advertising API and website mirror deployment are separate.
