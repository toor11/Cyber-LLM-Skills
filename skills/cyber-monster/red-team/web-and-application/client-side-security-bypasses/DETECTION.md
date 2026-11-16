# Detection Signals and Blue-Team Handoff

> Sub-skill: [`client-side-security-bypasses`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- API logs where a request field marked read-only or hidden in the client schema carries a non-default value.
- Requests to endpoints that have no corresponding link or route in the served SPA bundle.
- Write events setting privileged fields (role, tier, price) from sessions without the matching entitlement.
- Input values stored server-side that violate the published client-side validation bounds.
- Direct API calls lacking the usual front-end headers (custom `X-Requested-With`, app version) the SPA attaches.
- Access to admin or report endpoints from accounts whose UI never renders those features.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
