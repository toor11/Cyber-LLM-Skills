# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ieee-802-15-4-and-zigbee-mesh-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Join capture: a Transport Key command encrypted under a link key that does not change between devices, which is the global-key signal.
- Network event: a device joining with an install code already used by another device.
- Firmware audit: the global default key string present in a shipping image.
- Topology audit: a mesh containing devices that never received a Trust Center link-key update.
- Device event: a Touchlink commissioning frame received by a device that should not accept it.
- RF monitoring: repeated join attempts from one extended address, which is the commissioning brute-force shape.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
