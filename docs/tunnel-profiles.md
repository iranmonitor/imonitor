# Tunnel profiles and packet settings

Profiles fill in settings for real transports; they do not introduce proprietary
IP protocol numbers or promise a measured latency improvement. Saved tunnels
retain their existing settings until explicitly edited.

## Choosing a profile

| Profile | Transport | Use and limits |
| --- | --- | --- |
| Gaming | IPIP inside GUE / UDP, port 5555 | Kernel forwarding of IPv4 inner packets between IPv4 outer peers; MTU 1400, outer TTL 64, traffic class 0. It does not encrypt traffic. |
| Secure | WireGuard / UDP | Standard WireGuard private/public keys and an optional shared preshared key, with automatic session key management. MTU is adjustable; the app does not override outer TTL or TOS. |
| Secure manual alternative | ESP, IP protocol 50, AES-CBC/HMAC-SHA256 + HKDF | AES-256-CBC encryption with separate HMAC-SHA256 authentication keys and a 128-bit tag, with the same random shared secret on both peers. Manual ESP does not provide automatic rekey or forward secrecy. |
| Ethernet transports (Custom) | VXLAN / UDP | A managed Ethernet tunnel with matching VNI and port on both peers; GRETAP and GENEVE are alternatives. |
| Custom | Any supported transport | Choose the protocol, mirrored endpoints, keys/identifiers, ports, and supported packet settings directly. |

Kernel GUE avoids adding a userspace TCP carrier around gaming UDP traffic. This
is an architectural distinction, not a benchmark result. Actual path latency,
loss, and throughput require measurement on the deployed hosts.

WireGuard selects its outer source through the host route. If Local Outer or a
source interface is configured, iMonitor verifies that the route matches that
choice before applying the tunnel. Use a literal peer endpoint IP for this
validation; a mismatch produces a diagnostic and requires correcting the host
route or source-IP rules. The app does not silently rewrite host routing.

New managed ESP peers select `esp_cipher=aes_cbc_hmac_sha256` and
`esp_key_derivation=hkdf_sha256`. HKDF derives separate encryption and
authentication keys for each traffic direction; Linux supplies the CBC IVs.
Both peers must use the same cipher, derivation, and newly generated shared
secret. Rotate manual shared secrets deliberately on both peers. Replay state
protects a live SA; manual state recreation cannot preserve its replay history.
WireGuard is the default Secure profile for automatic session key management.

Saved configurations without `esp_cipher` retain `legacy_aes_gcm` identity.
iMonitor reuses their exact existing live states and policies, preserving
traffic and replay counters, but refuses static GCM creation or recreation after
state loss/reboot. Coordinate migration on both peers to CBC/HMAC with a new
random secret, or use externally managed dynamic IKE and select monitoring only.
AES-GCM ESP requires automated key management to prevent nonce/key reuse; see
[RFC 4106 sections 2 and 10](https://www.rfc-editor.org/rfc/rfc4106.html).

MTU and monitoring edits preserve these existing live legacy SAs. An enabled
legacy GCM check cannot be renamed or have its forwarding resources/keys changed
while retaining managed GCM; the save is rejected before teardown. Choose the
new cipher explicitly when coordinating a migration. Deliberate disable/delete
and protocol migration remain available.

## New kernel transports

- **VXLAN:** Ethernet over UDP, explicit destination port 4789 and VNI 42 by
  default. Both peers must use the same VNI and destination port. A fixed unicast
  remote endpoint carries unknown unicast and ARP/ND; dynamic MAC learning is
  disabled for this two-peer setup. Local outer IP and source interface can be
  specified.
- **GENEVE:** Ethernet over UDP, destination port 6081 and VNI 42 by default.
  Mirror the VNI and port. The portable setup uses the source IP/interface chosen
  by the host route to the outer peer. If Local Outer or source interface is set,
  the backend verifies that the selected route matches it and reports a clear
  diagnostic on mismatch. Newer iproute2 versions have additional source-IP
  controls; these are not required by this setup.
- **GRETAP:** Ethernet over GRE, IP protocol 47, using `gretap` for IPv4 outer
  peers and `ip6gretap` for IPv6 outer peers. An optional numeric or dotted-quad
  GRE key (decimal, `0x` hexadecimal, or dotted IPv4-style) must match on both
  peers. GRE keys identify traffic and do not encrypt
  it.

These transports create actual Linux interfaces. They require corresponding
kernel support and firewall access. Standard Linux does not provide the legacy
EtherIP link type used by the old command: EtherIP remains available for
monitoring externally managed interfaces, while GRETAP/VXLAN provide managed
Ethernet alternatives.

## Mirroring two peers

For a sample VXLAN pair, host A uses outer `192.0.2.1`, peer `192.0.2.2`, inner
`10.20.0.1/30`, and probe `10.20.0.2`. Host B swaps these to outer `192.0.2.2`,
peer `192.0.2.1`, inner `10.20.0.2/30`, and probe `10.20.0.1`. Both use VNI 42,
UDP port 4789, and the same MTU. Replace documentation addresses with the real
host addresses. Set a speed-test token separately and copy the same token and
test port to both peers.

GRETAP follows the same address pairing but uses GRE access through the firewall
instead of a UDP destination port. GENEVE uses UDP port 6081 and must have a host
route that selects the intended source. The Gaming profile uses IPv4 pairs and
GUE port 5555. Secure modes add their documented key exchange requirements.

## Packet settings

| JSON/form field | Valid values | Applies to |
| --- | --- | --- |
| `mtu` | 576–9000 bytes; at least 1280 for IPv6 inner packets | All managed interfaces; blank preserves the device default |
| `ttl` | 1–255; blank uses the kernel default | GRE, GRETAP, IPIP, SIT, GUE, VXLAN, GENEVE; maps to hop limit for IPv6 outer tunnels |
| `traffic_class` | 0–255, the outer TOS / traffic-class byte | The same kernel modes; blank preserves the default |
| `vni` | 1–16777215, default 42 | VXLAN and GENEVE only |
| `tun_lanes` | 1–8, default 1 | Native TUN TCP and the existing ICMP carrier only |

MTU limits inner packet size, and outer encapsulation needs additional path MTU.
Match it on both peers and lower it if the path cannot carry encapsulated
packets. The native TCP/ICMP TUN helper also rejects frames larger than the
configured MTU before reading their payload. Existing configurations without an
explicit limit preserve the legacy framing ceiling. Increasing TUN lanes can
reorder packets; retain one lane when predictable packet order matters. ICMP
uses IPv4 outer peers and requires the existing ptunnel-ng prerequisite.

TTL and traffic-class settings are applied through the corresponding Linux
device options; intermediate networks can impose their own forwarding/QoS
behavior. Unsupported combinations produce a validation error rather than
being silently ignored. Monitoring an existing interface does not apply packet
settings or change its addresses.

Managed GUE listeners are reused across monitoring cycles instead of deleting
and recreating their shared receive socket. Native forwarding buffers and wire
framing are otherwise preserved. See [protocol-validation.md](protocol-validation.md)
for the required Linux acceptance and performance comparison before release.

Sources: [iproute2 link options](https://man7.org/linux/man-pages/man8/ip-link.8.html),
[Linux VXLAN documentation](https://www.kernel.org/doc/html/latest/networking/vxlan.html),
[AES-CBC ESP](https://www.rfc-editor.org/rfc/rfc3602.html),
[HMAC-SHA256 ESP](https://www.rfc-editor.org/rfc/rfc4868.html),
[iproute2 IPIP/SIT options](https://github.com/iproute2/iproute2/blob/main/ip/link_iptnl.c),
[current GENEVE implementation](https://github.com/iproute2/iproute2/blob/main/ip/iplink_geneve.c).
