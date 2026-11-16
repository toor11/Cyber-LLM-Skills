# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ics-ot-protocol-attacks-protocol-exposure-assessment`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Switch SPAN configuration: a monitoring session added or removed, which changes the assessment's coverage.
- Flow record: a new source-destination pair on a controller port.
- Zeek log: a protocol appearing on a subnet where it has not appeared before.
- IDS alert: a write function code on a link that previously carried only reads.
- Asset inventory drift: a device responding from an address outside its documented range.
- Capture coverage metric: subnets with no observed endpoints in a monitoring window.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
