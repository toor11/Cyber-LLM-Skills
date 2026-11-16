# Detection Signals and Blue-Team Handoff

> Sub-skill: [`prototype-pollution`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- HTTP bodies or query strings containing __proto__, constructor, or prototype as object keys.
- Node application logs showing an unexpected default value immediately after a merge call.
- APM traces where a config flag or role flips without any configuration change.
- Query strings carrying bracketed [__proto__] keys on endpoints that parse nested objects.
- WAF rule hits on prototype keys followed by a 200 from the origin on the same route.
- Error spikes such as 'x is not a function' correlated with a preceding pollution request.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
