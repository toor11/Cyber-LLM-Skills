# Detection Signals and Blue-Team Handoff

> Sub-skill: [`automotive-and-can-bus`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- IDS alert: an identifier whose cycle time deviates from the baseline by more than the configured tolerance.
- IDS alert: a SecOC verification failure, which is the MAC rejecting a forged or replayed frame.
- Gateway log: a frame dropped by an identifier rule, which is the segmentation control firing.
- Bus load metric: utilisation above the configured threshold, which is the availability signal.
- Diagnostic session log: a session opened outside a service window or from an unexpected tester.
- Firmware measurement: an ECU image that does not match the signed manifest, which UN R156 scopes to the update path.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
