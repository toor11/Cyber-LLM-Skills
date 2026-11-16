# Detection Signals and Blue-Team Handoff

> Sub-skill: [`dom-based-vulnerabilities`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Client bundle review (SAST or grep) showing a DOM source flowing into `innerHTML`, `document.write`, or `eval` without sanitisation.
- CSP `report-uri` or `report-to` violations citing `require-trusted-types-for` or inline script on single-page routes.
- RUM or error telemetry reporting unexpected DOM nodes created from `location.hash` or `location.search` values.
- `message` event handlers in code lacking an `event.origin` comparison, found in review.
- Client-side error beacons or analytics events carrying `location.hash`-derived values that contain markup characters.
- Dependency scans flagging a DOM sanitizer library absent or disabled on SPA routes.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
