# Detection Signals and Blue-Team Handoff

> Sub-skill: [`type-juggling-javascript-other-languages`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Node or Python logs where a JSON field arrives with an unexpected type on a route expecting a string.
- Application errors mentioning NaN, parseInt, or a type error near an authorization decision.
- Static analysis flagging loose equality in Node auth code or truthy checks in Python views.
- Schema-validation rejections spiking on one field as an attacker probes types.
- Privilege changes where the request body sent a number or boolean for a field normally a string.
- Repeated requests toggling a field between quoted and unquoted JSON values.
- WAF or gateway logs showing array or object values for parameters documented as scalars.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
