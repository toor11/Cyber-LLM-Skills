# Detection Signals and Blue-Team Handoff

> Sub-skill: [`graphql-security-batching-and-dos`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- GraphQL request bodies containing many aliases of the same field in one document.
- POST bodies that are JSON arrays of multiple operations.
- Selection sets whose nesting depth exceeds a configured threshold.
- Resolver-execution counts per request far above the median on the `/graphql` route.
- Rate-limited operations (OTP, coupon, login) succeeding in attempt counts that exceed the per-request limit.
- Latency spikes on `/graphql` correlated with large request-body sizes.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
