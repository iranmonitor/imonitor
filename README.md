<p align="center">
  <a href="https://iranmonitor.net"><img src="https://img.shields.io/badge/Visit_IranMonitor-Website-0f766e?style=for-the-badge" alt="Visit the IranMonitor website"></a>
  <a href="https://t.me/IranMonitorNet"><img src="https://img.shields.io/badge/Join_Our_Channel-Telegram-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="Join IranMonitor on Telegram"></a>
</p>

<p align="center"><strong>Stay connected with IranMonitor</strong><br>
Explore our projects and services at <a href="https://iranmonitor.net">iranmonitor.net</a>, and join <a href="https://t.me/IranMonitorNet">@IranMonitorNet on Telegram</a> for project news, release announcements, and updates.</p>

<p align="center"><img src="src/ui/brand/imonitor-mark.svg" alt="iMonitor eye logo" width="96"></p>

# iMonitor 2.1.0

**Monitor your services, connect Linux servers, and diagnose the network from one web panel.**

iMonitor combines uptime checks, a public status page, tunnel creation, native tunnel speed tests, alerts, backups, and Linux network controls. Monitoring and Tunnels have separate workspaces, with a three-step tunnel wizard and a replayable first-login tutorial. The interface supports English and Persian, including RTL layouts, frosted glass, subtle grain, bundled IBM Plex Sans/Vazirmatn fonts, and an SVG eye logo.

All application features are free for personal and commercial use, without activation keys, paid tiers, or a monitor-count license limit. The official source is available for inspection and unmodified builds. Modification and redistribution require permission under the [use license](LICENSE).

[Install](#install-or-upgrade) · [Features](#what-you-can-do) · [Create a tunnel](#create-your-first-tunnel) · [Tunnel reference](#tunnel-modes-and-use-cases) · [Packet settings](#packet-settings-and-mtu) · [Troubleshooting](#diagnose-a-problem)

## Install or upgrade

Run this on an **x86-64 GNU/Linux server with glibc 2.31 or later**, using systemd or OpenRC:

```sh
curl -fsSL https://github.com/iranmonitor/imonitor/releases/latest/download/install.sh | sudo bash
```

The same command installs a fresh node or upgrades a detected paid/licensed installation, including the packaged 1.2.2 and original `iranmonitor-node` layouts. It verifies the downloaded release, backs up an existing installation before replacement, preserves its database, accounts, history, runtime files and service settings, and restarts the detected service. An upgrade keeps your existing admin credentials and removes application licensing credentials when the database opens.

A fresh installation uses:

| Item | Default |
| --- | --- |
| Panel address | `http://SERVER_IP:6060/admin` |
| Public status page | `http://SERVER_IP:6060/` |
| Service | `imonitor` |
| Application | `/opt/imonitor/bin/imonitor` |
| Runtime directory | `/opt/imonitor/runtime` |
| Database | `/opt/imonitor/runtime/iranmonitor.db` |
| Admin password | Generated and printed during initialization |

Save the generated password, sign in, and use the local `imonitor` management menu to change credentials or the panel port. Existing installations retain their detected paths and listener. On a fresh systemd installation:

```sh
sudo systemctl status imonitor
sudo journalctl -u imonitor -n 100 --no-pager
sudo systemctl restart imonitor
```

On OpenRC, use `sudo rc-service imonitor status` or `restart`. Use the service name reported by the installer when upgrading a legacy node.

For a panel behind an HTTPS reverse proxy, you can initialize its listener on loopback:

```sh
curl -fsSL https://github.com/iranmonitor/imonitor/releases/latest/download/install.sh |
  sudo env IMONITOR_LISTEN_ADDR=127.0.0.1:6060 bash
```

Panel Settings provides an Nginx TLS configuration snippet; HTTPS termination runs in the reverse proxy. See the [installer guide](docs/installer-upgrade.md) for optional initial settings, backups and rollback. ARM and Alpine/musl require a native source build. The website download mirrors are awaiting deployment; use GitHub for the current release.

## What you can do

| Workspace or feature | What it provides | How to use it |
| --- | --- | --- |
| **Overview** | Current service states, latency, recent activity and host CPU/RAM/swap/disk/load/network metrics | Start here to find failing checks and open their details. |
| **Monitoring** | Service checks with individual intervals, timeouts, address-family selection and public visibility | Add a monitor, choose its check type and expected result, then save. |
| **Monitor Folders** | Group related checks by project, location or service | Create folders and assign monitors for a clearer panel and status page. |
| **Public status page** | Share selected services and their recent status/latency history | Mark only the intended checks public. Customize the title, subtitle and branding in Panel Settings. |
| **Analytics and exports** | Per-monitor status and latency history, sample-based availability, and CSV/PDF/XLSX exports | Open Analytics, choose a preset/custom date range, zoom the chart, and inspect sample counts and average/maximum latency. XLSX generation requires `zip`. |
| **Tunnels** | Managed tunnel interfaces, existing-interface monitoring, endpoint settings and peer instructions | Choose Gaming, Secure or Custom, mirror the settings on the other server, then run diagnostics. |
| **Tunnel diagnostics** | Interface state, RX/TX counters, inner-peer ping and authenticated upload/download measurements | Check the interface and ping first; run the speed test when both peers are ready. |
| **Notifications** | Telegram failure/recovery alerts, consecutive-failure threshold, multiple allowed chat IDs and bot status commands | Save a bot token/chat IDs, send a test message, and set the failure threshold. Optional SOCKS5 settings help the bot reach Telegram. |
| **Server Health** | Host resource information and externally observed reachability | Open the page for host/hardware, package-update summaries and the automatically requested public-target country map. Remote results come from Check-Host probes. |
| **Backups** | Scheduled or manual file archives to FTP, SFTP or S3, with retention | Add a destination, select source paths and an archive format, set the schedule, then use Run Now to verify it. |
| **Network Controls** | Traffic counters, interface egress shaping and TCP connection limits | Save a watcher, speed rule or TCP limit, then use its corresponding Apply action and inspect its recorded status. |
| **Source IP** | IPv4/IPv6 connection-tracked SNAT and an explicit IPv4 paired-rewrite mode | Select mode, interface, destination and an assigned source address; save, then Apply the rules. |
| **Port Forwarding** | Managed TCP/UDP forwarding rules | Set protocol/family, listening port, destination address/port and interface/source restrictions; save, then Apply. |
| **Ports / Sockets** | Socket visibility and controls for ports in use | Inspect listeners/connections; start, stop or restart mapped systemd services, or stop a direct process. Controls for iMonitor itself are disabled. |
| **Panel Settings** | Language, appearance, logo/favicon, contact details and access settings; displayed public/admin URLs and a reverse-proxy snippet | Customize the exposed settings and save; use the Logo/Favicon Upload controls or a direct image URL. Managed uploads are stored under `runtime/branding`. Use the displayed addresses/TLS snippet for deployment. |
| **Getting Started** | Permanent setup guides and a replayable spotlight tutorial | Open the guide or restart the tour at any time. |
| **Local CLI** | Panel port/credentials, service management and update controls | Run `sudo imonitor` on the server. |

### Monitoring check types

| Check | What is checked | Useful settings or limits |
| --- | --- | --- |
| **ICMP** | Ping response and round-trip latency | Host/IP, IPv4 or IPv6, timeout. ICMP filtering can cause a failed ping while other services remain reachable. |
| **TCP** | A TCP connection to a target port | Host/IP and port; useful for databases, application listeners and arbitrary TCP services. |
| **UDP** | A datagram exchange with optional expected response | Payload and response matching. Send-only mode reports unverified/degraded availability because a successful send is not proof of a working service. |
| **HTTP / HTTPS** | Request result and optional content match | Method, path, headers, accepted status codes, body text, connect host, Host header and TLS server name. |
| **DNS** | A query to your selected resolver | Server/port, name, A/AAAA/CNAME/MX/NS/TXT record type and minimum answer count. Truncated UDP responses can fall back to TCP. |
| **SSH / SFTP** | Reachability and SSH banner | Port and expected banner prefix. This is a banner check, not a login or file-transfer test. |
| **RDP** | RDP negotiation response | Target/port, IP family and timeout; identifies a responding remote desktop service. |
| **FTP** | FTP service response, with optional configured authentication | Target/port and optional USER/PASS login; does not test file transfer and is distinct from a backup upload job. |
| **Proxy / V2Ray-style** | Endpoint reachability or a target request through a real proxy entry | HTTP/HTTPS/SOCKS5, VMess, VLESS, Trojan, Shadowsocks and WireGuard configuration/import fields. Direct mode tests the endpoint's TCP listener; it does not prove an authenticated VMess/VLESS/etc. session. |
| **Tunnel** | Configured interface/state, optional peer reachability and traffic requirements | Managed creation or monitoring of an existing interface; diagnostics and speed tests are separate explicit actions. |

Availability is calculated from recorded Up samples rather than a continuously measured, time-weighted SLA.

For your first website monitor, choose HTTPS, enter the host/path, accept the expected status such as `200`, and optionally require a known phrase in the response body. Set a 60-second interval, save, and open Analytics after a few checks. Add a separate DNS monitor if you also need to distinguish resolver failures from website failures.

Share-link imports accept `vmess://`, `vless://`, `trojan://`, `ss://` and WireGuard configuration blocks. For a full proxy-path check, use a working SOCKS5/HTTP/HTTPS entry. Provisioning a local Xray entry requires Xray to be installed separately; importing a link alone does not establish every supported proxy protocol. WireGuard endpoint reachability alone is not a verified handshake.

## Create your first tunnel

You need **two compatible Linux peers**, their reachable outer addresses, an available inner subnet, and firewall access for the chosen carrier. Kernel modes also need the matching kernel modules; userspace carriers need their listed tools.

1. Open **Tunnels**, give the connection a name, and select a profile.
2. Enter this server's local outer address, the other server's outer address, and the inner address pair.
3. Set the protocol-specific keys, ports or identifiers. Choose an MTU, copy the generated peer instructions, and configure the other server.
4. Save both sides. Check their interfaces and inner-peer pings before testing throughput or routing application traffic.

| Example field | Server A | Server B |
| --- | --- | --- |
| Local outer address | `198.51.100.10` | `203.0.113.20` |
| Remote outer address | `203.0.113.20` | `198.51.100.10` |
| Local inner address | `10.20.0.1/30` | `10.20.0.2/30` |
| Inner peer / probe | `10.20.0.2` | `10.20.0.1` |
| MTU | Same chosen value | Same chosen value |
| Speed-test key and port | Same generated key; `5201` | Same generated key; `5201` |

Replace the outer documentation addresses with real reachable addresses. **Local Outer** must be an address available on that host; a public address translated by upstream NAT is not necessarily a local bind address. For a simple pair with publicly assigned outer addresses, the table shows how to swap both sets of endpoints.

Ports, VNI, GRE keys and shared secrets must agree with the peer. L2TP local/peer IDs are reversed across the pair. WireGuard private keys are different on each host: exchange public keys, and use the same optional preshared key. An SSH TUN initiator pairs with a Reverse SSH receiver.

### Profiles

| Profile | Default choice | Use it for |
| --- | --- | --- |
| **Gaming** | IPv4 IPIP inside kernel GUE/UDP, port `5555`, MTU `1400`, TTL `64`, traffic class `0` | Carrying IPv4 traffic, including UDP games, without wrapping it in a TCP carrier. It is unencrypted; real latency/loss still depend on the path. |
| **Secure** | WireGuard over UDP; manual ESP is an alternative | Encrypted server-to-server traffic. WireGuard manages session keys automatically; manual ESP needs coordinated keys and rotation. |
| **Custom** | Your selected supported mode and settings | Matching an existing peer, building an Ethernet overlay, choosing a particular firewall carrier, or tuning packet settings. |

Profiles are configuration presets, not extra proprietary protocols. Creating a tunnel connects the configured endpoints; routing additional LANs or Internet traffic through it requires matching routes, forwarding and any deliberate NAT rules.

## Tunnel modes and use cases

**IP protocol numbers and TCP/UDP ports are different things.** For example, GRE requires IP protocol `47`, and ESP requires IP protocol `50`; opening TCP or UDP port 47/50 does not allow those packets. The following port values are defaults and can be changed where the panel exposes them.

| Mode | Packets and firewall carrier | Typical use | Encryption / support |
| --- | --- | --- | --- |
| **GRE** | Outer IP → GRE → inner IP; IP protocol `47` | Routed links carrying IPv4/IPv6 between Linux peers | No encryption. Optional GRE key identifies a tunnel. |
| **GRETAP** | Outer IP → GRE → Ethernet frame; IP protocol `47` | A point-to-point Ethernet link for bridging or layer-2 workloads | No encryption. Supports IPv4/IPv6 outer peers and an optional GRE key. |
| **IPv4 IP-in-IP / IPIP** | Outer IP → IPv4 packet; IP protocol `4` | A simple routed IPv4 link with small header overhead | No encryption. These two panel selections use the same IPIP backend; outer IPv4/IPv6 variants are selected by the endpoints. |
| **IPv6 encapsulation / SIT** | Outer IP → IPv6 packet; IP protocol `41` | Connecting IPv6 networks over an IPv4 path, or the matching IPv6-outer variant | No encryption. Use IPv6 addresses inside this tunnel. |
| **ENCAP / GUE** | IPv4 → UDP → GUE → IPv4 packet; UDP `5555` | Kernel UDP encapsulation, including the Gaming preset | No encryption. Managed creation uses IPv4 outer and inner packets. |
| **VXLAN** | IP → UDP → VXLAN → Ethernet frame; UDP `4789` | Ethernet overlays between two peers, identified by a VNI | No encryption. Managed fixed unicast peer; VNI defaults to `42`. |
| **GENEVE** | IP → UDP → GENEVE → Ethernet frame; UDP `6081` | An Ethernet overlay with GENEVE-capable peers | No encryption. Matching VNI/port; local source follows the host route. |
| **L2TPv3 over UDP** | IP → UDP → L2TPv3 → Ethernet frame; UDP `1701` | Point-to-point Ethernet pseudowires with matched session IDs | No encryption. This is not a PPP/L2TP remote-access VPN server. |
| **L2TPv3 over IP** | IP → L2TPv3 → Ethernet frame; IP protocol `115` | A raw-IP pseudowire when both peers and the network support it | No encryption. Select IP encapsulation on both peers. |
| **ESP / XFRM** | IP → ESP → encrypted inner IP; IP protocol `50` | Manual encrypted IPsec tunnels between known peers | New managed peers use AES-256-CBC, HMAC-SHA256 and directional HKDF keys. No automatic IKE/rekey, forward secrecy or managed UDP/4500 NAT-T. |
| **WireGuard** | IP → UDP → WireGuard → encrypted inner IP; UDP `51820` | Encrypted IPv4/IPv6 server links with standard public-key peers | Encryption and automatic session-key management. Requires peer public key and suitable Allowed IPs. |
| **TUN / UDP** | IP → UDP → inner IP, using `socat` | A userspace UDP carrier when a kernel encapsulation is unsuitable | No transport encryption. Peer transport ports default within `55000–55899`; local ports within `56000–56899`. Copy the actual peer settings or select explicit matching ports. |
| **TUN / TCP** | IP → TCP stream → framed inner IP | A userspace tunnel on a reachable TCP port | No transport encryption. Transport port defaults within `55000–55899`. TCP retransmissions can delay inner traffic; one to eight lanes are supported. |
| **TUN / ICMP** | IPv4 → ICMP → `ptunnel-ng` relay → framed inner IP | A compatibility path where ICMP is available and the relay is appropriate | No encrypted transport. IPv4 outer peers; one to eight lanes; local TCP bridge ports are not public TCP tunnel ports. |
| **SSH TUN** | IP → TCP → encrypted OpenSSH TUN channel; TCP `22` | Encrypted tunneling through an accessible SSH service | Requires SSH authentication, a usable TUN device and remote `PermitTunnel`. |
| **Reverse SSH TUN** | The receiving end of the peer-initiated SSH TUN session | A receiver for the other host's SSH TUN initiator | Configure this host's SSH server separately; it does not launch a second reverse transport. |
| **EtherIP** | IP → EtherIP → Ethernet frame; IP protocol `97` | Monitoring an interface created by an external EtherIP implementation | Managed creation is unavailable on standard Linux here. Use GRETAP/VXLAN/GENEVE for managed Ethernet links. |
| **Saved BIP TUN profiles** | The existing TUN/UDP carrier | Compatibility with old saved configurations | A legacy UDP alias, not an independent wire protocol or new encapsulation. |

Managed GRE/GRETAP, IPIP, IPv6 encapsulation, VXLAN/GENEVE, L2TPv3, ESP, WireGuard and TCP/UDP/SSH carriers accept matching IPv4 or IPv6 outer peers. Managed GUE and ICMP carriers use IPv4 outer peers only; EtherIP capabilities belong to the external implementation. IPIP carries IPv4 inside; SIT/IP6IP6 carries IPv6. Kernel support and peer configuration determine whether a particular variant can run. UDP carriers can be useful through networks that filter GRE/ESP, but UDP alone does not guarantee NAT traversal or firewall access.

### Protocol-specific setup

- **GRE / GRETAP:** use the same optional numeric GRE key on both sides. A key is an identifier, not a password or cipher.
- **VXLAN / GENEVE:** match the VNI and destination port. The managed setup connects a fixed peer; it does not configure an EVPN control plane or an entire bridge topology for you.
- **L2TPv3:** pair local tunnel/session IDs with the opposite peer's IDs. Choose UDP or raw IP consistently; for UDP, mirror the sender's destination port with the receiver's listening port.
- **WireGuard:** keep each private key on its own node, exchange public keys, and match an optional preshared key. Default Allowed IPs can be limited to the inner peer (`/32` or `/128`); add routed networks deliberately. Local Outer/source-interface selections are checked against the host's route.

  To generate a WireGuard key pair on each host, run:

  ```sh
  umask 077
  wg genkey | tee wg-private.key | wg pubkey > wg-public.key
  ```

  Enter the contents of `wg-private.key` only in that host's local private-key field. Enter the other host's `wg-public.key` in its peer-public-key field.

- **ESP:** generate a random shared secret, select `aes_cbc_hmac_sha256` and `hkdf_sha256` on both peers, and match all endpoint settings. The app derives separate encryption/authentication keys for each direction. Existing live legacy AES-GCM states may be reused, but unsafe static-key creation/recreation is blocked; migrate both peers together or use externally managed IPsec.
- **Native TUN:** match TCP/UDP/ICMP carrier, peer ports, MTU and supported lane count. TCP/UDP bind the configured local address; source-interface selections must match the route. ICMP uses the route-selected source and needs `ptunnel-ng`.
- **SSH:** configure the receiving SSH server with `PermitTunnel yes` or a suitable point-to-point policy, permit the authenticating user to use TUN, and supply a private key or password. Password mode needs `sshpass`. Use the generated peer guide to match device/address settings. The current managed SSH helper disables host-key verification; its encryption does not establish verified server identity. Use a trusted path or an externally managed, host-key-verified SSH tunnel.

## Packet settings and MTU

The **outer packet** travels between the servers' reachable addresses. The **inner packet** is the traffic carried by the tunnel. Encapsulation adds headers, so the inner MTU must leave room within the outer path MTU.

```text
Gaming / GUE: outer IPv4 | UDP | GUE | inner IPv4 | TCP/UDP/etc. | application data
WireGuard:   outer IP   | UDP | WireGuard authenticated/encrypted inner IP
VXLAN:       outer IP   | UDP | VXLAN | inner Ethernet | inner IP | application data
```

| Panel setting | Values | Effect and supported modes |
| --- | --- | --- |
| **MTU** | `576–9000`; at least `1280` for IPv6 inside | Limits inner packet size on managed interfaces. Blank preserves the device default. Match the peer and respect the actual path MTU. |
| **TTL / hop limit** | `1–255` | Outer packet lifetime for GRE, GRETAP, IPIP, SIT, GUE, VXLAN and GENEVE. This is not a latency setting. |
| **Traffic class / TOS** | `0–255` | Outer DSCP/ECN byte for the same kernel modes. Network equipment may remark or ignore it; it does not guarantee priority. |
| **VNI** | `1–16777215`; default `42` | Shared 24-bit overlay identifier for VXLAN and GENEVE. |
| **GRE key** | Decimal, hexadecimal or dotted IPv4-style numeric value | Optional shared identifier for GRE/GRETAP; it adds four header bytes. |
| **Transport/listen ports** | `1–65535` | Peer/listener selection for UDP/TCP carriers, L2TP, WireGuard and SSH. The speed-test port is a separate inner TCP service. |
| **L2TP IDs / encapsulation** | Positive tunnel/session IDs; `udp` or `ip` | Identify the Ethernet pseudowire and its carrier. |
| **ESP cipher / derivation / secret** | Managed CBC/HMAC with HKDF; matching random secret | Encryption/authentication and key derivation for new ESP peers. |
| **WireGuard keys / Allowed IPs** | Local private key, peer public key, optional shared PSK, IP prefixes | Peer authentication and which inner destinations belong to the peer. |
| **TUN lanes** | `1–8`; default `1` | Native TCP and ICMP only. More lanes can reorder packets; one lane keeps ordering more predictable. |
| **Source interface / local outer address** | Available interface/address | Select or validate the outer source depending on the mode. GENEVE, WireGuard and ICMP use route validation rather than silently changing host routing. |
| **Creation mode** | Create/manage, or check an existing interface | Existing-interface monitoring leaves its addresses and packet settings under external management. |
| **Expected state / traffic requirement** | Expected operstate; idle allowed or bidirectional traffic required | Decide whether an idle link is healthy. Enabling traffic requirements expects RX and TX increments between checks. |
| **Check interval / public visibility** | Interval at least `10` seconds; private/public | Control monitoring cadence and whether the check appears on the status page. |

Unsupported packet-setting combinations are rejected rather than silently ignored. The native TCP/ICMP helper also enforces the configured frame-size limit.

### Encapsulation overhead

These figures are **header budgets derived from the packet formats**, not measured throughput. They count bytes added before the inner IP packet; Ethernet tunnel rows include the usual **14-byte inner Ethernet header**. They exclude the outer link's Ethernet header/FCS, VLAN tags, Ethernet padding, IP fragmentation, retransmissions and setup/handshake traffic.

| Carrier | IPv4 outer, bytes added | IPv6 outer, bytes added | What adds to the budget |
| --- | --- | --- | --- |
| **IPIP / SIT / IPv6-in-IPv6** | `20` | `40` base; commonly `48` for the managed IPv6 variant | Outer IP header; the IPv6 encapsulation-limit option can add `8`. |
| **GRE** | `24` | `44` base; commonly `52` managed | IP + `4`-byte base GRE; a GRE key adds another `4`. |
| **GRETAP** | `38` | `58` base; commonly `66` managed | IP + base GRE + inner Ethernet; key adds `4`. |
| **IPIP over GUE** | `32` | Managed IPv6 unavailable | IPv4 `20` + UDP `8` + base GUE `4`. |
| **VXLAN** | `50` | `70` | IP + UDP `8` + VXLAN `8` + inner Ethernet `14`. |
| **GENEVE** | `50` with no options | `70` with no options | Same base budget as VXLAN; GENEVE options add multiples of `4`. The managed setup adds none. |
| **L2TPv3 / UDP** | `54` | `74` | IP + UDP `8` + L2TPv3 UDP session header `8` + default L2-specific sublayer `4` + inner Ethernet `14`. |
| **L2TPv3 / raw IP** | `42` | `62` | IP + session ID `4` + default L2-specific sublayer `4` + inner Ethernet `14`; no configured cookie. |
| **WireGuard data** | `60` plus padding | `80` plus padding | IP + UDP `8` + data header `16` + authentication tag `16`; alignment padding can add up to `15`. |
| **ESP CBC/HMAC data** | `62–77` | `82–97` | IP + SPI/sequence `8` + CBC IV `16` + trailer `2` + authentication tag `16` + `0–15` block-padding bytes. Applies to the current managed cipher. |
| **Native TUN / UDP** | `28` | `48` | IP + UDP `8`; each datagram carries a raw inner IP packet without an extra length prefix. |
| **Native TUN / TCP** | Variable | Variable | A `2`-byte length prefix per inner packet, plus IP/TCP headers per outer TCP segment. Frames may share or span segments. |
| **Native TUN / ICMP** | Variable | IPv4 outer only | ICMP relay headers and the framed TCP bridge; payload segmentation/retransmission depend on the relay. |
| **SSH / Reverse SSH** | Variable | Variable | TCP segmentation plus OpenSSH channel, encryption and authentication framing. |
| **External EtherIP** | `36` baseline | External implementation dependent | IPv4 `20` + EtherIP `2` + inner Ethernet `14`; provided only as an external-format reference. |

The `40`-byte IPv6 figures are base-header values. Current Linux/iproute2 IPv6 IPIP, IP6IP6, GRE and GRETAP setups commonly include an additional `8`-byte destination-options encapsulation-limit header. Other IPv6 extensions or IPv4 options can increase the budget further.

For example, IPv4 GUE with no additional options adds `32` bytes: a `1400`-byte inner IP packet becomes a `1432`-byte outer IP packet. On a 1500-byte path, IPv4 VXLAN's base budget leaves `1450` bytes for the inner IP packet before VLANs or other additions. TCP, SSH and ICMP carriers do not have one fixed per-inner-packet overhead; use path testing and captures instead of subtracting a single constant.

Format references: [IPIP](https://www.rfc-editor.org/rfc/rfc2003.html), [GRE](https://www.rfc-editor.org/rfc/rfc2784.html) and [GRE keys](https://www.rfc-editor.org/rfc/rfc2890.html), [VXLAN](https://www.rfc-editor.org/rfc/rfc7348.html), [GENEVE](https://www.rfc-editor.org/rfc/rfc8926.html), [GUE draft](https://datatracker.ietf.org/doc/html/draft-ietf-intarea-gue-09), [L2TPv3](https://www.rfc-editor.org/rfc/rfc3931.html) and [Linux L2TP](https://www.kernel.org/doc/html/v6.1/networking/l2tp.html), [WireGuard](https://www.wireguard.com/protocol/), [ESP](https://www.rfc-editor.org/rfc/rfc4303.html), [AES-CBC](https://www.rfc-editor.org/rfc/rfc3602.html), [HMAC-SHA256](https://www.rfc-editor.org/rfc/rfc4868.html), and [EtherIP](https://www.rfc-editor.org/rfc/rfc3378.html). The managed IPv6 extension behavior follows [Linux IPv6 tunneling](https://github.com/torvalds/linux/blob/v6.1/net/ipv6/ip6_tunnel.c) and [IPv6 GRE](https://github.com/torvalds/linux/blob/v6.1/net/ipv6/ip6_gre.c).

A conservative starting MTU such as `1400` can help on a 1500-byte path, but it is not a universal answer. Verify the path and peer; lower MTU when larger inner packets fail while smaller ones work. A `9000` value is usable only if the complete encapsulated packet fits every link. Padding, optional headers and actual IP families affect the result.

## Built-in tunnel speed tests

No iperf3 installation is required. Save the same generated **32–128 printable ASCII-character test key, without spaces** and test port on both peers. The listener binds to the local inner tunnel IP and restricts tests to the configured peer; leaving the key blank disables it.

Use the tunnel's Speed Test action. The panel measures upload and download separately, with four TCP streams for ten seconds in each direction. The result reflects the tunnel path, not general Internet speed or a raw UDP loss/jitter benchmark. Tests consume traffic only when explicitly requested. Authentication uses a challenge/HMAC exchange; the test key is separate from tunnel encryption keys and does not encrypt an otherwise unencrypted carrier.

For a standalone peer:

```sh
imonitor speedtest-server --bind 10.20.0.2:5201 --peer 10.20.0.1 --token SHARED_TEST_TOKEN
```

Replace the sample inner IPs and token with your configured values. Test after bidirectional ping works, and keep the native test port reachable through the tunnel.

## Network tools in practice

- **Traffic watchers:** select a port and optional IP filter to inspect input/output totals and current rates.
- **Traffic shaping:** configure a rate on a selected interface's outgoing traffic, matched by TCP/UDP source port. This is interface egress shaping, not a universal incoming-bandwidth limiter.
- **TCP connection limits:** set a destination port and per-source-IP connection limit. Excess new TCP connections are rejected with a reset; IPv4/IPv6 rules are supported.
- **Source IP / SNAT:** choose the destination host/subnet, IP family, outgoing interface and a source address assigned to the server. Conntrack handles reply translation. TCP/UDP can use port filters; raw protocols use their IP protocol number.
- **Paired rewriting:** use the explicit IPv4 mode only for a coordinated stateless mapping. It uses tc/XDP rather than a normal connection-tracked NAT session. IPv6 uses SNAT; authenticated AH packet rewriting is rejected.
- **Raw protocol filters:** GRE `47`, ESP `50`, AH `51`, EtherIP `97`, L2TP/IP `115`, and numeric selectors refer to IP headers. A filtering/rewriting selector does not create a new tunnel implementation.
- **Forwarding:** map TCP/UDP traffic to the intended destination service, then verify firewall access and the return path. Use Ports / Sockets to inspect existing listeners first.

Managed cleanup targets iMonitor's owned resources. Choose monitoring-only mode for tunnels maintained by another tool, and keep a backup before changing routing, NAT or firewall rules.

## Backups, alerts and public status

Backups archive the file paths you choose; they are not a built-in database restore workflow. Select FTP/SFTP/S3, destination credentials, source paths and hidden-file inclusion, an archive type (`tar.gz`, `tar.xz` or ZIP), retention and a minute/hour/day schedule. Use Run Now to check a new target, and keep a copy outside the node. Coordinate consistency when archiving a live database; generic file archiving does not provide an online SQLite snapshot by itself.

Telegram alerts trigger after a configured number of consecutive non-Up results (default `3`) and announce recovery. Allowed chat IDs can use `/start`, `/status`, `/summary` and `/help`. Email/phone fields are displayed contact details, not SMTP or SMS alert transports. The public `/` page and `/status.json` include only enabled checks marked public; folders, titles and branding let you shape the public status page. Admin and public pages have separate sponsored PNG placements.

A retained optional Radar integration can run centrally supplied HTTPS/ICMP probes and submit their measurements. It is disabled by default and has no current web setup controls.

## Diagnose a problem

| Symptom | Check next |
| --- | --- |
| **Interface cannot be created** | Kernel module, required tool, privileges, selected IP family and the error in tunnel details/service logs. EtherIP needs an external implementation. |
| **Interface exists, but peer ping fails** | Swapped inner addresses, matching protocol/keys/IDs, outer firewall rules, peer configuration and return routes. |
| **Wrong local source or source-interface error** | `ip route get PEER_OUTER_IP` (or `ip -6 route get ...`). Select an address/interface that exists and matches the required route; fix host routing if needed. |
| **Small packets work; large ones fail** | MTU and path-MTU restrictions. Account for outer headers and match both peers. |
| **UDP monitor sends successfully but is degraded** | Enable a valid response check. A UDP send-only probe cannot confirm a responsive service. |
| **Proxy endpoint is up but users cannot browse** | A direct check only confirms the listener. Test a real authenticated local proxy entry and its target request. |
| **WireGuard endpoint responds but no tunnel traffic** | Peer public keys/PSK, Allowed IPs, latest handshake, routes and the UDP firewall path. |
| **Speed test fails** | Same test key/port, a configured local inner IP, reachable peer listener and the correct tunnel route. |
| **Slow tunnel under loss or load** | CPU usage, outer path loss/latency, competing traffic and MTU; TCP/SSH carriers can add retransmission delays. Measure on the actual hosts. |
| **Country map shows failures** | Public target selection and external Check-Host/ICMP reachability; this is not a direct measurement of every user's application connection. |

Useful Linux inspection commands:

```sh
ip -br address
ip -s link show dev TUNNEL_INTERFACE
ip route get PEER_OUTER_IP
ping -I TUNNEL_INTERFACE PEER_INNER_IP
sudo wg show                  # WireGuard peers/handshakes
sudo ip xfrm state            # ESP states
sudo ip xfrm policy           # ESP policies
```

Replace the uppercase placeholders. XFRM state output can contain key material; review it before sharing diagnostics.

## Runtime dependencies

| Function | Tools |
| --- | --- |
| HTTP/HTTPS and proxy requests | `curl` |
| ICMP probes | `ping` |
| Kernel interfaces and packet controls | `ip`, `tc`, `iptables` / `ip6tables`; appropriate kernel modules and network administration privileges |
| WireGuard | `wg` / `wireguard-tools` and kernel WireGuard support |
| Source-IP XDP controls | Packaged `imonitor-bpf` + `xdp_ingress.o`, optionally `bpftool`, and a compatible kernel |
| TUN/UDP | `socat` and `/dev/net/tun` |
| TUN/ICMP | `ptunnel-ng` and `/dev/net/tun` |
| SSH TUN | OpenSSH client/server, `/dev/net/tun`; `sshpass` for password mode |
| Local Xray proxy provisioning | A separately installed Xray executable |
| File backups | `tar`, `gzip`; `xz` for tar.xz, `zip` for ZIP, protocol-capable `curl` for FTP/SFTP, `aws` CLI for S3 |
| XLSX export | `zip` |

The installer requests common network tools. Availability varies by distribution; install optional feature dependencies when you use them.

## Build and run from source

Install Rust/Cargo and the Linux build dependencies. On Debian/Ubuntu:

```sh
sudo apt-get install build-essential clang llvm libc6-dev linux-libc-dev libbpf-dev sqlite3
cargo build --locked --release --bins
cargo test --locked
```

The build script compiles `src/bpf/xdp_ingress.c`. For a panel-only or cross-compilation build, set `IMONITOR_SKIP_BPF_BUILD=1`; supply a compatible XDP object separately if you use XDP controls.

Initialize a **new** manual node, then serve it:

```sh
./target/release/iranmonitor_node init \
  --db ./runtime/iranmonitor.db --data-dir ./runtime \
  --listen 127.0.0.1:6060 --username admin
./target/release/iranmonitor_node serve \
  --db ./runtime/iranmonitor.db --data-dir ./runtime \
  --listen 127.0.0.1:6060
```

Initialization prints a generated password. For an existing node, use its original database/runtime paths and run `serve`; do not initialize a replacement database. The old `--plan` option is accepted for compatibility and has no licensing effect.

[Manual binary setup](docs/local-release.md) · [Installer and rollback](docs/installer-upgrade.md) · [Tunnel settings](docs/tunnel-profiles.md)

## Validation and further reading

Recorded local checks include 113 passing Windows Rust tests, 115 normal Linux Rust tests, privileged tunnel/source-IP traffic fixtures, 83 browser checks, 46 running-app HTTP/SQLite checks and 10 installer fixtures. See [the recorded scope](docs/local-validation-2.1.0.md).

Local acceptance establishes behavior on the tested guest. It does not guarantee speed, latency or loss on every network, and a two-host WAN comparison against 1.2.2 is still needed. Use the [protocol validation guide](docs/protocol-validation.md) and [benchmark worksheet](docs/benchmark-record.csv) for repeatable measurements.

- [Official releases and checksums](https://github.com/iranmonitor/imonitor/releases)
- [Linux peer acceptance](docs/linux-acceptance.md)
- [Tunnel profiles and packet settings](docs/tunnel-profiles.md)
- [Source-available use license](LICENSE)

New passwords use Argon2id hashing, and admin session cookies use HttpOnly/SameSite controls.

IBM Plex Sans and Vazirmatn retain their included SIL Open Font Licenses under `src/ui/fonts`.
