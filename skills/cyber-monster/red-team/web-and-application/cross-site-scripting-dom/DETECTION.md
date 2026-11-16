# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cross-site-scripting-dom`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Client-error or RUM telemetry reporting script activity tied to location.hash or location.search values on a route.
- CSP violation reports naming inline or eval violations originating from client-side rendering code.
- Static analysis of deployed JavaScript bundles flagging innerHTML, document.write, or eval assigned from a DOM source.
- Browser console errors referencing Trusted Types sink rejections where require-trusted-types-for is enforced.
- postMessage listeners registered without an event.origin comparison, observed in bundle review.
- A spike in requests carrying long or markup-like URL fragments to single-page-application routes.
- Third-party script inventory showing a DOMPurify version within the mXSS-affected range noted in the advisories.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
