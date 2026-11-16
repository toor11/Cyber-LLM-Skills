# Detection Signals and Blue-Team Handoff

> Sub-skill: [`prototype-pollution-client-side-gadgets`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- CSP violation reports at the report-uri or report-to endpoint for script-src from unexpected origins.
- Trusted Types violation reports arriving at the report-to collector.
- Referrer or analytics logs showing URL fragments or queries containing __proto__[ keys.
- Client-side logging of postMessage payloads that contain __proto__ or constructor keys.
- Synthetic monitoring detecting injected script elements with a foreign src attribute.
- Front-end error telemetry reporting 'is not a function' after a fragment navigation.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
