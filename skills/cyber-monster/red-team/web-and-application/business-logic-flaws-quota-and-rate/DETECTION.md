# Detection Signals and Blue-Team Handoff

> Sub-skill: [`business-logic-flaws-quota-and-rate`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Rate-limiter store (Redis `INCR`) showing a count for one key exceeding the configured ceiling within a sub-second window.
- Access logs with many concurrent requests to a limited endpoint sharing an identical timestamp to the millisecond.
- Sign-up or redemption events keyed to email addresses that normalise to the same mailbox (plus-tags, dots).
- Authentication attempt counters that stay flat while failed-login events for the same account rise.
- Load-balancer logs where per-node 429 rates diverge for the same client identity.
- Free-tier quota grants exceeding the plan allowance joined on account id over a billing window.
- Repeated window-reset or counter-reset parameters accepted from client requests to the throttling endpoint.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
