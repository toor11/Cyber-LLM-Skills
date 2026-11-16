# Detection Signals and Blue-Team Handoff

> Sub-skill: [`firmware-extraction-and-emulation`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Supply-chain inspection: an incoming firmware image whose entropy profile differs from the previous release, which indicates a new encryption or compression layer.
- Firmware build audit: a rootfs containing a private key or a shared password hash, caught by a build-time scan.
- Device attestation: a firmware measurement that does not match the signed manifest.
- Network telemetry: a device exposing a telnet or an unauthenticated HTTP port, which is the init-script finding in production.
- Update audit: a firmware image fetched over plain HTTP or without a signature check, which is the update-path finding.
- Vulnerability intelligence: a component version extracted from the image matching a published advisory.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
