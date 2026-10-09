# Protocol validation and performance acceptance

The automated suite checks protocol parsing, configuration validation, local
network exchanges, native throughput accounting, and managed-process lifecycle.
Privileged traffic checks also run inside an isolated Linux 6.1 guest, with
separate network namespaces acting as peers. Recorded results and their exact
scope are in [local-validation-2.1.0.md](local-validation-2.1.0.md). They do not
replace throughput comparisons between two real deployment hosts.

## Changes covered by tests

- DNS ignores mismatched transactions, validates the echoed question and answer
  types, rejects malformed records, and retries truncated UDP responses over TCP.
- TCP tries alternate resolved addresses within one timeout budget. HTTP connects
  to an alternate hostname while retaining the intended Host header; content
  matching checks the complete received body.
- UDP without a requested response reports unverified availability. WireGuard
  endpoint reachability does not imply an authenticated handshake.
- SSH banner reads have an absolute deadline and bounded line lengths. Managed
  SSH connections require literal peer IPs, and managed forwarding helpers remain
  alive between monitoring cycles.
- ESP CBC/HMAC HKDF derivation is symmetric across mirrored peers and separates
  encryption/authentication keys, directions, and secrets. Saved legacy GCM
  identities remain readable and exact active SAs remain reusable; the app
  refuses unsafe static GCM recreation. Both peers must migrate together.
- Native speed tests authenticate the peer, reject invalid requests, count bytes
  actually received, and require the receiver's acknowledgement for upload.
  Loopback tests exercise upload, download, wrong credentials, and four streams.
- Slow TCP-relay fixtures verify queued upload data and fragmented delayed peer
  acknowledgements. Authenticated transfers have a bounded ten-second drain;
  all client workers share the overall requested-duration-plus-twelve-second
  deadline. Throughput uses the peer's received bytes and elapsed transfer time.
- Scheduler and helper lifecycle tests check bounded monitoring concurrency,
  result order, helper reuse, configuration changes, exit recovery, and retirement.
- Cleanup tests protect externally managed tunnels and distinguish forwarding
  changes from monitoring-only changes.
- Kernel command plans cover VXLAN, GENEVE, GRETAP, and the Gaming GUE profile,
  including IPv6 options, source-route checks, and reuse of a GUE receive port.
  Packet-setting tests reject incompatible modes and out-of-range MTU, VNI,
  lane, and framing limits. A local TCP fixture sends an oversized TUN frame
  header and verifies rejection before the payload is read.

The native test measures TCP throughput to the other tunnel endpoint. It is not
an internet speed test. The normal panel test runs four streams for ten seconds
in each direction, sequentially, with source sockets bound to the local tunnel
IP. Each stream uses a reusable 64 KiB buffer; endpoint concurrency, duration,
and bytes are bounded. Scheduled monitoring does not send speed-test payloads.

## Two-host Linux acceptance

For each supported managed protocol, use two disposable Linux hosts with the
required kernel modules and tools. Mirror the outer and inner addresses, keys,
ports, and protocol settings using the panel guide. Allow the required protocol
through both firewalls and verify the routes use the intended tunnel interface.

1. Create the tunnel and confirm traffic reaches the peer's inner IP in both
   directions. Check a valid inner TCP service and a deliberately closed port so
   an unreachable service is not mistaken for healthy traffic.
2. Run monitoring for several cycles without traffic. Confirm the interface and
   any managed forwarding process remain usable between cycles.
3. Configure the same native speed-test token and port on both peers. Run a panel
   speed test in both directions. Confirm the peer listener binds only to the
   intended local tunnel IP, succeeds with the correct token, and rejects an
   incorrect token.
4. Change monitoring cadence and confirm the forwarding process/session is
   retained. Change a forwarding setting, disable the check, and delete it;
   confirm only the resources owned by that check are retired. A check that
   monitors an externally created interface must preserve it.
5. For WireGuard, confirm the real peer handshake and traffic counters, then
   save unchanged settings and check that the session persists. Test IPv6 peer
   endpoints where supported.
6. For ESP, verify installed states and inbound/outbound policies on both hosts,
   exchange protected inner traffic, and save unchanged settings. Replay state
   should persist. Verify mismatched shared secrets fail and that a coordinated
   legacy-to-HKDF migration restores traffic.

SSH forwarding requires the server settings described in the setup guide.
Kernel protocols require their corresponding Linux support. Legacy BIP selection
uses the existing compatibility transport; it is not an independent BIP
implementation.

The optional `scripts/ssh-acceptance.sh` slice exercises the production server
and runner with a temporary OpenSSH server using `PermitTunnel point-to-point`
and fresh test keys inside dedicated guest namespaces. Provide OpenSSH
client/server and dependencies, `sqlite3`, `curl`, `ip`, and `ping`, plus a guest
`sshd` privilege-separation account and `/run/sshd`. For a minimal guest, UID/GID
74, home `/run/sshd`, and a nologin shell are sufficient. These prerequisites
belong only in the disposable guest.

```sh
IMONITOR_ACCEPT_DISPOSABLE=1 \
IMONITOR_PRODUCTION_BINARY=/tests/bin/imonitor \
bash scripts/ssh-acceptance.sh /tests/kernel-plans /tests/iranmonitor_node-tests
```

The slice checks the managed SSH initiator, Reverse SSH passive receiver,
selected outer source, mirrored MTU, ping in both directions, authenticated
native throughput, wrong-token rejection, and reuse across monitoring cycles.
Logs and a TSV result file are retained in the supplied result root; temporary
keys are test-only guest artifacts. Password authentication and third-party SSH
server policies require separate acceptance on deployment hosts. Reverse SSH
relies on the incoming session and does not create a second transport on the
receiver.

## Throughput comparison before release

Compare the original 1.2.2 and updated build on the same two hosts, protocol,
network path, MTU, forwarding settings, and kernel/tool versions. Keep competing
traffic and monitoring load equivalent. Test both directions after a warm-up;
record at least five runs per build, median throughput, spread, CPU usage, and
packet loss. Use one consistent external traffic generator for the baseline
comparison, since the original and native test clients have different timing
and accounting. An external benchmark tool may be used for validation without
becoming an installation dependency.

New transports absent from 1.2.2 also need a control measurement against the same
manually configured Linux kernel interface with the monitoring app stopped.
Treat a change from legacy ESP GCM to CBC/HMAC as a different cryptographic
configuration: compare each against a matching manual kernel setup, rather than
attributing the cipher's cost to the panel. Do not recreate static legacy GCM
states just to obtain a baseline; use an existing safe baseline or dynamic key
management on both sides.

Separate the application changes from normal path variation. Investigate a
repeatable reduction outside the baseline spread before release. Also compare
idle resource usage and a large monitor set: bounded workers should prevent
unbounded thread growth while meeting configured monitoring intervals.

No two-host WAN throughput baseline is claimed. Local kernel traffic results
establish functionality in the tested guest, not an absence of performance
regressions on every path. Actual throughput still needs the comparison above.

### Reproducible comparison worksheet

Keep the 1.2.2 and 2.1.0 binaries and their databases separate. Back up the
baseline database; do not feed a database upgraded by 2.1.0 back into 1.2.2.
Record host/kernel/tool versions, tunnel settings and both inner addresses in
[benchmark-record.csv](benchmark-record.csv). Never include private keys or
speed-test tokens in a shared record.

One practical generator is **optional benchmark-only iperf3**. It is not an
iMonitor installation or panel speed-test dependency. Install the same version
on the two disposable hosts and use a test port distinct from the native panel
listener. The flags below follow the [official iperf3 manual](https://software.es.net/iperf/invoking.html).
With the tunnel already running, on host B:

```sh
iperf3 -s -B B_INNER_IP -p 5202
```

On host A, replace both address placeholders with the actual inner IPs and
replace `BUILD` with `1.2.2` or `2.1.0`. Run a warm-up, then five independent
runs per direction with the same options:

```sh
iperf3 -c B_INNER_IP -B A_INNER_IP -p 5202 -P 4 -t 10 >/dev/null
for run in 1 2 3 4 5; do
  iperf3 -c B_INNER_IP -B A_INNER_IP -p 5202 -P 4 -t 30 -O 3 -J > "BUILD-upload-$run.json"
  iperf3 -c B_INNER_IP -B A_INNER_IP -p 5202 -P 4 -t 30 -O 3 -R -J > "BUILD-download-$run.json"
done
```

Record receiver throughput, not merely sender bytes queued. Save idle and
loaded ping results through the tunnel interface, plus interface counters
before/after and CPU samples on both hosts. For example:

```sh
ping -I TUNNEL_INTERFACE -c 50 -i 0.2 B_INNER_IP > BUILD-idle-ping.txt
ip -s link show dev TUNNEL_INTERFACE > BUILD-interface-before.txt
# Run the throughput test while another terminal records loaded ping and CPU.
ping -I TUNNEL_INTERFACE -c 150 -i 0.2 B_INNER_IP > BUILD-loaded-ping.txt
pidstat -u -p ALL 1 35 > BUILD-cpu.txt
ip -s link show dev TUNNEL_INTERFACE > BUILD-interface-after.txt
```

`pidstat` comes from optional `sysstat`; any equivalent CPU sampler is suitable
if kept identical between builds. For gaming, also run UDP at a fixed offered
rate the baseline can sustain, with the same datagram size (for example 1200
bytes) and duration, and record receiver loss and jitter. Repeat at the same
offered rates on 2.1.0. Test IPv4/IPv6 separately where the transport supports
them, and keep MTU, lane count, encryption and monitor load identical.

Compare the median and range of the five receiver results, CPU use, loaded
latency and loss. Alternate the build order or repeat the baseline afterward
to expose changes in the network path. Investigate a repeatable drop larger
than the baseline's own variation; do not infer a regression from one run.
For a new mode, compare against its manually configured kernel transport using
the same generator and path. The native panel test can be recorded separately
for usability, but its results should not be mixed into the iperf3 baseline.

## Remaining limits

HTTP response matching currently captures the complete curl output in memory.
Checks against very large response bodies can consume substantial memory; this
is not covered by the small local response fixture. Kernel tunnel behavior,
firewall/NAT traversal, SSH permissions, MTU, and routing depend on the deployment
and need the Linux acceptance checks above.

## Disposable Linux namespace harness

`scripts/kernel-acceptance.sh` exercises the real runtime inside two temporary
network namespaces. It uses a Linux Rust test binary with ignored fixtures;
these tests do not add production CLI commands. The base exporter can run on
Windows or Linux and does not execute network commands:

```sh
IMONITOR_KERNEL_PLAN_DIR=/tmp/imonitor-plans cargo test --bin iranmonitor_node \
  runner::tests::export_kernel_acceptance_plans -- --ignored --exact --nocapture
cp -r tests/fixtures/kernel-extra/* /tmp/imonitor-plans/
cargo test --bin iranmonitor_node --no-run
sudo IMONITOR_ACCEPT_DISPOSABLE=1 bash scripts/kernel-acceptance.sh /tmp/imonitor-plans \
  /absolute/path/to/target/debug/deps/iranmonitor_node-TEST_HASH
```

Use a disposable Linux VM with the kernel modules, iproute2, iputils ping,
WireGuard tools, Bash/coreutils, and tcpdump installed. To include the native
TCP TUN helper tests, set `IMONITOR_PRODUCTION_BINARY` to the built production
app path (the guest default is `/tests/bin/imonitor`).
The harness refuses to run unless `IMONITOR_ACCEPT_DISPOSABLE=1` is set; set it
only inside the disposable guest.

The harness covers 17 generated IPv4/IPv6 kernel configurations plus L2TP UDP,
L2TP IP, and native TUN TCP with one/four lanes. It verifies mirrored pings,
the MTU boundary, real monitor/runtime reuse, ESP/GUE state reuse, WireGuard
handshakes, and authenticated native upload/download with four streams. When
tcpdump is available, it also verifies outer source addresses and the requested
TTL/hop limit and traffic class. Each mode writes its logs and status under the
plan directory. Missing kernel features are reported as unsupported, not passed.

Namespace results establish behavior in that guest and kernel. They do not
establish a two-host WAN throughput baseline. The SSH and production TUN slices
below provide the extra server/tool prerequisites for their local checks.

## Optional production TUN carrier acceptance

`scripts/tun-carrier-acceptance.sh` starts two production app instances in owned,
disposable namespaces and covers TUN UDP with IPv4/IPv6 outer peers, the legacy
BIP UDP alias, and TCP/ICMP with one/four lanes. It requires `socat`, `ptunnel-ng`,
SQLite CLI, iproute2, iputils ping, tcpdump, Bash/coreutils, the production app,
and the Linux test binary containing the native throughput fixture:

```sh
sudo IMONITOR_ACCEPT_DISPOSABLE=1 IMONITOR_PRODUCTION_BINARY=/tests/bin/imonitor \
  bash scripts/tun-carrier-acceptance.sh /tmp/imonitor-results \
  /tests/iranmonitor_node-tests
```

Create the result directory first. `IMONITOR_TUN_CARRIER_MODES` can select a
space-separated subset: `tunudp4 tunudp6 tunbip4 tuntcp1 tuntcp4 tunicmp1 tunicmp4`. Each mode
checks mirrored pings through the actual TUN route, the MTU boundary, captured
outer source addresses, authenticated four-stream upload/download and helper
reuse across monitoring cycles. UDP and TCP first try an unexpected outer source
before starting the declared peer, then require successful real forwarding.
The TCP fixture checks that the production listener closes that connection before
allocating a lane. The harness also verifies the generated peer-filter option.
UDP, one-lane TCP and one-lane ICMP also verify source-interface
mismatch rejection; ICMP verifies a source-IP mismatch too. These checks preserve
the existing helpers/interfaces and restore the working selection. Its TSV and per-mode logs distinguish failed
phases. These tests do not establish WAN performance or carrier availability
through a deployment firewall.

The existing ICMP carrier supports IPv4 outer endpoints. ptunnel-ng has no
outer source bind option; its `-L` flag selects packet capture, not the outgoing
route. iMonitor therefore checks the host's route to the peer before creating
or reusing ICMP helpers. Local Outer and source interface must match that route;
align the host route or source-IP rules if the panel reports a mismatch. This
check does not change the packet forwarding path. See the official
[ptunnel-ng options](https://github.com/utoni/ptunnel-ng/blob/master/src/options.c)
and [raw socket implementation](https://github.com/utoni/ptunnel-ng/blob/master/src/ptunnel.c).

UDP/TCP TUN and outgoing SSH bind Local Outer directly. When a source interface
is selected, iMonitor verifies the peer route **from that bound Local Outer**,
so selecting a valid secondary address does not incorrectly require the default
route's source. A device mismatch requires a host route/source-IP rule change.
Reverse SSH verifies that return route; its incoming SSH server remains an
external prerequisite and must accept the intended peer on the selected address.
These interface checks require literal peer IPs, because a hostname can resolve
to multiple routes.

Managed native TCP listeners accept lanes only from the configured peer outer
IP; the helper's optional `--allowed-peer IP` remains optional for standalone
uses. Managed UDP listeners apply socat's exact `/32` or `/128` peer range
before accepting their first sender. Existing hostname peers are resolved once
to a matching-family address when creating the listener; literal peer addresses
provide predictable routing and filtering. These are IP source restrictions,
not encryption or cryptographic peer authentication. Use WireGuard or ESP with
appropriate shared keys when the outer network is untrusted. The forwarding
bridge remains unchanged after acceptance. See the
[socat range option](https://manpages.debian.org/bookworm/socat/socat.1.en.html#range=).

`scripts/ssh-acceptance.sh` provides the separate SSH/Reverse SSH production
fixture. It requires OpenSSH client/server, `ssh-keygen`, and an `sshd`
privilege-separation account in the guest (for example UID/GID 74, home
`/run/sshd`, shell `/usr/sbin/nologin`). It creates fresh test-only keys and a
namespace-isolated peer server with `PermitTunnel point-to-point`, then checks
mirrored pings, MTU, native throughput, source binding, source-interface mismatch
rejection/recovery and persistent reuse.
Run it with the same two result-directory/test-binary arguments and explicit
disposable-guest opt-in. Keys are test fixtures, never deployment credentials.
