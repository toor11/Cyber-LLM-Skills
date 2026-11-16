# Detection Signals and Blue-Team Handoff

> Sub-skill: [`iot-thread-and-openthread-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Border router log: a joiner session accepted outside a commissioning window, which is the unbounded-window signal.
- 802.15.4 capture: repeated joiner attempts from one extended address, which is the passcode-brute-force shape.
- Commissioning metric: distinct PSKd values per manufacturing batch, which is the uniqueness check done at scale.
- Device attestation: a device reporting a network key it did not receive through its own commissioning.
- Thread network event: a device joining with steering data that does not match the current commissioner's.
- Build audit: a firmware image whose PSKd is a literal rather than a provisioning read.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
