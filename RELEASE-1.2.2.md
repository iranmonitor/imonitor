# iMonitor 1.2.2

- License credentials are verified immediately when they are saved; the existing 300-second background verification remains unchanged.
- Successful license replies are cryptographically bound to the current nonce, timestamp, and license key.
- HTTP/HTTPS monitors no longer fail on a separate DNS preflight; the real request performs resolution.
- Tunnel setup accepts a bare local IP such as `10.10.10.2` and adds the appropriate prefix internally.
- Tunnel fields are filtered by protocol, so SSH credentials are only shown for SSH tunnel modes.
- Tunnel traffic-delta enforcement now respects its enabled/disabled setting.
- The monitor workflow and admin UI have been simplified and refreshed while preserving the existing iMonitor palette.
- New and changed admin passwords use Argon2id; existing password hashes remain compatible.
- HTTP request size and connection time limits protect the embedded panel server.
- Concurrent panel connections are bounded, SQLite uses WAL with a busy timeout, and snapshot writes are atomic.
- Historical snapshots omit runtime-only diagnostic blobs and use rolling retention to prevent unbounded database growth.
- Per-monitor analytics queries extract only the selected monitor, avoiding large whole-database responses.
- The installer can use either `iranmonitor.net` or `irnmo.ir` as its download endpoint.
- The radar endpoint validator and release headers were corrected.
