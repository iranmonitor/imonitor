# iMonitor 2.0.0 — local development release

- All monitor protocols and network controls are free with unlimited saved checks.
- License verification, key storage, device fingerprints, and paid feature gates removed.
- Separate Monitoring, Tunnels, and Getting Started pages.
- Three-step tunnel form, protocol-specific peer instructions, and a replayable tour.
- Frosted glass and grain styling, light IBM Plex Sans/Vazirmatn, English/Persian layouts.
- Independent safe PNG sponsor placements, ready for the future IranMonitor API.
- Native authenticated tunnel throughput tests replace iperf3.
- DNS truncation retries over TCP; UDP send-only checks no longer claim peer health.
- Correct tunnel protocol metadata, stronger directional ESP derivation for new peers.
- Legacy ESP configs stay compatible until both peers explicitly change derivation.
- Public status excludes secrets and raw diagnostics; image routes stay inside branding.
- Disabled traffic shaping stays disabled; monitor workers are bounded.
- Source-available terms permit free personal/commercial use of unmodified releases.

Publishing and a Linux peer acceptance test remain separate release steps. Existing
1.2.2 binaries in dist are historical and do not contain these changes.
