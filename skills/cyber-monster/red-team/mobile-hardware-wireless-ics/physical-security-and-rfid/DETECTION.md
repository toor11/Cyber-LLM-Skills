# Detection Signals and Blue-Team Handoff

> Sub-skill: [`physical-security-and-rfid`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Access-control log: a badge read that grants access outside the holder's normal hours or zones, which is the cloned-card signal.
- Access log: two badges entering a mantrap within the tailgate window, which is the piggyback pattern.
- Door contact event: a door held open beyond its configured time.
- Controller audit: a rule change that removes a second factor from a sensitive zone.
- Panel sensor: a service panel opened outside a maintenance window.
- Reader log: a card presented whose technical identifier does not match the enrolled credential for that holder.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
