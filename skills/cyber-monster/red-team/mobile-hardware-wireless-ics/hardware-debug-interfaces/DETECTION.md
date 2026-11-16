# Detection Signals and Blue-Team Handoff

> Sub-skill: [`hardware-debug-interfaces`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Manufacturing audit: a production unit whose fuse state differs from the golden image, which is the debug-locked check.
- Firmware build audit: a bootloader built with an interactive console enabled in a production configuration.
- Field return analysis: a unit with physical tamper evidence at a debug header, which is the physical-access signal.
- Boot log field: a bootloader prompt string in a production unit's logs, which is the interactive-console fingerprint.
- Supply-chain inspection: a device image whose flash read returns plaintext, caught at incoming inspection.
- Secure boot attestation: a device reporting a boot chain that does not match the signed manifest.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
