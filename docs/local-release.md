# Run the local 2.1.0 Linux release

The supplied ZIP contains the 2.1.0 release for x86-64 GNU/Linux with
glibc 2.31 or later. The GitHub release also provides the installer described in
[installer-upgrade.md](installer-upgrade.md). Use the included binaries directly
for a manual installation or a disposable test node.

Transfer `imonitor-2.1.0-linux-x86_64.zip` to a disposable Linux server. Extract
it, then verify the six release assets against the included checksum manifest:

```sh
unzip imonitor-2.1.0-linux-x86_64.zip
cd imonitor-2.1.0-linux-x86_64
sha256sum -c sha256sums.txt
mkdir -p bin bpf
unzip imonitor-v2.1.0-linux-amd64.zip -d bin
unzip imonitor-bpf-v2.1.0-amd64.zip -d bin
mv bin/xdp_ingress.o bpf/xdp_ingress.o
chmod 0755 bin/imonitor bin/imonitor-bpf
```

The `bin/` and sibling `bpf/` layout lets the app find its helper and XDP
object. Do not extract both the versioned bundles and their identical aliases.
On Debian/Ubuntu, install the tools needed by the features you will use:

```sh
sudo apt-get install ca-certificates curl unzip sqlite3 iproute2 iputils-ping iptables bpftool
# Optional WireGuard, SSH, UDP TUN and ICMP TUN tools:
sudo apt-get install wireguard-tools openssh-client openssh-server sshpass socat ptunnel-ng
```

Kernel tunnel creation and network controls require suitable kernel modules
and root/network administration permissions. Initialize a fresh test node and
start it on loopback:

```sh
sudo ./bin/imonitor init --db ./runtime/iranmonitor.db --data-dir ./runtime \
  --listen 127.0.0.1:6060 --username admin
sudo ./bin/imonitor serve --db ./runtime/iranmonitor.db --data-dir ./runtime \
  --listen 127.0.0.1:6060
```

Save the generated password from initialization, open `/admin` through your
local access or SSH port forwarding, and change the password after login.
Create both peers from the Tunnels workspace and follow its mirrored setup
guide. The native tunnel speed test needs the same generated token and test
port on both peers; it does not require iperf3.

For an upgrade, back up the original runtime directory and stop the old node
before replacing binaries. Retain its runtime directory and use its original
database/data paths. Run only one app instance against that database. A database
upgraded by 2.1.0 must not be passed back to 1.2.2; restore the backup for rollback.

The actual local test matrix is in [local-validation-2.1.0.md](local-validation-2.1.0.md).
Use [protocol-validation.md](protocol-validation.md) and
[benchmark-record.csv](benchmark-record.csv) for the remaining two-host WAN
comparison. The advertising API and website mirror deployment are separate tasks.
