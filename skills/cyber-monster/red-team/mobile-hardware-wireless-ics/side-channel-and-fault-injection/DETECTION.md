# Detection Signals and Blue-Team Handoff

> Sub-skill: [`side-channel-and-fault-injection`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Device event: a PIN attempt counter that resets without a successful attempt, which is the fault or reset signal.
- Device log: a secure boot verification result that changes without a firmware change.
- Production test: a unit whose power profile differs from the golden sample at the cryptographic operation.
- Tamper response: an enclosure opening or a voltage anomaly detected by the device itself.
- Certification audit: a secure element part number that does not match the evaluated configuration.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
