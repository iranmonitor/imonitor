# Install or upgrade iMonitor

Run the same command for a fresh installation or an upgrade from paid 1.2.2:

```sh
curl -fsSL https://github.com/iranmonitor/imonitor/releases/latest/download/install.sh | sudo bash
```

The installer downloads the matching versioned release from GitHub, checks
the main and source-IP engine bundles against `sha256sums.txt`, and checks the
main executable's version before stopping an existing service. The supplied
prebuilt release supports x86-64 GNU/Linux with glibc 2.31 or later and systemd
or OpenRC. ARM and Alpine/musl need a native source build.

For a new node it creates `/opt/imonitor/bin/imonitor`, initializes
`/opt/imonitor/runtime/iranmonitor.db`, and starts the `imonitor` service.
The default listener is `0.0.0.0:6060`. The generated admin password is printed
once. To set initial credentials or a listener explicitly:

```sh
curl -fsSL https://github.com/iranmonitor/imonitor/releases/latest/download/install.sh |
  sudo env IMONITOR_LISTEN_ADDR=127.0.0.1:6060 IMONITOR_ADMIN_USER=admin bash
```

An upgrade keeps the detected executable destination, database path, data
directory, listener and existing service file. It does not run `init` or
replace the stored admin credentials. Both the packaged 1.2.2 layout under
`/opt/imonitor` and the original `iranmonitor-node.service` layout under
`/var/www/imonitor/1.0` are detected. Quoted paths and a custom `--db` filename
are supported. When both service names are installed, the active service is
selected; two active instances require resolving the duplicate first.

There are no license activation prompts. Existing runtime files, including
`.engine.key`, `monitor_state.json`, branding and historical data, are retained.
The existing SQLite configuration also keeps its saved panel listener.

After verified downloads, the installer stops the detected service and saves
a backup under `<data-directory>-backups/pre-2.1.0-<timestamp>-<suffix>/` before
replacing executables by rename. The backup contains the entire runtime as
`runtime.tar`, a separate database and any WAL/SHM companions, the previous
executable, the service file and `paths.txt`. It then restarts the same service.
This causes brief service downtime.

Keep that backup until the upgraded node has been checked. If installation
fails before replacing the main executable, the old service is started again.
If it fails afterward, the backup is retained and the error reports its path.
For rollback, stop the service and restore the previous executable and runtime
from that backup, using `paths.txt` for custom destinations. Restore the
database and its companions together; remove new WAL/SHM files if they were
absent in the backup. A database migrated by 2.1.0 must not be opened with
1.2.2 without restoring the pre-upgrade database first.

To use an official mirror instead of GitHub:

```sh
curl -fsSL https://iranmonitor.net/download/imonitor/install.sh |
  sudo env IMONITOR_DOWNLOAD_ENDPOINT=iranmonitor.net bash

curl -fsSL https://irnmo.ir/download/imonitor/install.sh |
  sudo env IMONITOR_DOWNLOAD_ENDPOINT=irnmo.ir bash
```

Both mirrors must publish the matching bundles, installer and checksums
together. `IMONITOR_DOWNLOAD_ENDPOINT=github` selects GitHub explicitly.
Authorized distribution repositories can set
`IMONITOR_GITHUB_REPOSITORY=owner/repository`; the default is
`iranmonitor/imonitor`. Redistribution otherwise requires written permission
under the [use license](../LICENSE). `IMONITOR_RELEASE_TAG` defaults to `v2.1.0` and must
refer to assets matching this installer's version. The optional hosted
`bpftool` fallback continues to use an official mirror.

The installer fixture suite runs without root and makes no host service,
package or database changes:

```sh
bash -n install.sh
bash -n scripts/test-installer.sh
bash scripts/test-installer.sh
```

It uses disposable directories, stubbed downloads and service commands, real
ZIP extraction, and real checksum verification. The ten checks cover fresh
setup, the two legacy layouts, custom databases and quoted paths, OpenRC,
active-service selection, corrupted bundles, version mismatch, official
mirrors and configurable repository URLs. Application migration and actual
service operation are separate runtime checks.
