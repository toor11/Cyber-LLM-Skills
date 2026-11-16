# Detection Signals and Blue-Team Handoff

> Sub-skill: [`hardware-debug-interfaces-jtag-and-swd`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Manufacturing audit: a production unit whose option bytes or fuses leave the debug transport enabled.
- Field return analysis: tamper evidence at a debug header, which is the physical-access precondition.
- Firmware build audit: a debug authentication key compiled into the image rather than provisioned per device.
- Device attestation: a unit reporting an option-byte configuration that differs from the golden image.
- Supply-chain inspection: a device whose flash read returns data rather than erased bytes, caught at incoming inspection.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
