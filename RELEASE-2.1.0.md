# iMonitor 2.1.0

- One-command GitHub install or upgrade from paid 1.2.2, with verified downloads,
  preserved runtime/database/service settings, a backup and atomic executable replacement.
- Tutorial spotlight leaves the actual target clear and positions its card beside it.
- Dialogs center in the viewport, scroll internally and restore keyboard focus.
- Gaming, Secure and Custom profiles fill settings for actual transports.
- Managed VXLAN, GENEVE and GRETAP; ESP is identified as IP protocol 50.
- Editable MTU, supported outer TTL/traffic class, VNI and native TUN lane count.
- Local outer address binding for native TCP TUN and SSH; explicit GENEVE route validation.
- Source-interface checks follow the actual bound route for native TCP/UDP and SSH;
  ICMP, WireGuard and GENEVE validate the route-selected outer source.
- Secure defaults to WireGuard. Manual ESP uses authenticated AES-CBC/HMAC-SHA256;
  unchanged live legacy GCM states are preserved while unsafe recreation is rejected.
- Shared GUE receive ports survive monitoring cycles.
- GUE packet-setting updates preserve the configured UDP port on iproute2 6.1.
- Native speed tests allow a bounded drain for slower carriers, count actual
  acknowledged bytes and keep the existing overall test deadline.
- Standard Linux EtherIP creation is rejected with usable managed Ethernet alternatives.
- Connection-tracked IPv4/IPv6 SNAT, explicit legacy paired rewriting and owned cleanup.
- Source-IP validation accepts dedicated protocol numbers and rejects invalid port/family combinations.
- Packet rewriting updates TCP/UDP checksums and handles options and fragmentation;
  shaping rollback retains ownership when cleanup fails and preserves foreign rules.
- XDP packet-length guards load in the Linux 6.1 verifier; port forwarding uses
  valid, separately combined conntrack state matches for translated traffic.
- Managed UDP/TCP TUN listeners restrict incoming carriers to the declared outer
  peer before accepting a sender or allocating a TCP lane.
- IPv6 UDP TUN source binds use socat's required bracketed address format.
- The installer banner works with portable awk, including Debian's default mawk.
- Default SVG eye logo and wordmark are bundled; saved custom branding remains available.

The free UI, native authenticated speed test and source-available usage terms from
2.0 remain. Prebuilt assets support x86-64 GNU/Linux with glibc 2.31 or later.
Website sales removal and mirror deployment are scheduled separately. Real
deployment path throughput must be compared against the previous release before
asserting performance equivalence. See `docs/protocol-validation.md` for the
comparison procedure and `docs/local-validation-2.1.0.md` for recorded local checks.
