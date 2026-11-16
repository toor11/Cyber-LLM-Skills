# Detection Signals and Blue-Team Handoff

> Sub-skill: [`gnss-and-satellite-link-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Receiver log field: OSNMA verification failures, which the control produces and which should be monitored.
- Clock metric: the offset between the GNSS-derived time and an independent source, alerted beyond a drift threshold.
- Position metric: a reported position outside a plausibility envelope, or a sudden jump.
- RF monitoring: signal strength or noise floor anomalies in the GNSS band, which indicate jamming.
- Application audit: a certificate or log-ordering decision taken while the clock source was unverified.
- Fleet telemetry: multiple devices reporting the same implausible position, which is the spoofing signature at scale.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
