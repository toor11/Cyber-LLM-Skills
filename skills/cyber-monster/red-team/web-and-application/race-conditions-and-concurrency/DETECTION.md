# Detection Signals and Blue-Team Handoff

> Sub-skill: [`race-conditions-and-concurrency`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Database logs with multiple UPDATE statements on the same voucher or wallet id within a few milliseconds.
- Application logs showing more than one success for a one-use code or token in a single session.
- A balance or stock column committing a negative value.
- Duplicate rows violating a business-unique key inserted within the same second.
- Access logs with N near-simultaneous POSTs to a redeem or transfer route from one session.
- APM traces of overlapping transactions touching the same row without a lock wait.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
