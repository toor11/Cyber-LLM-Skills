# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cross-site-scripting-mutation`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Client bundle inventory showing a DOMPurify or HTML-sanitizer version inside a known-vulnerable range for the mXSS class.
- Runtime assignments to `innerHTML` or `dangerouslySetInnerHTML` whose source is a sanitizer output rather than textContent, found in code review or SAST.
- CSP violation reports citing `require-trusted-types-for` or inline `script-src` on pages that render user HTML.
- Diff telemetry where a stored HTML field's serialised DOM differs from the bytes that were stored, on the rendering route.
- SCA or dependency-scan alerts pinning a sanitizer package below its fixed release in `package-lock.json`.
- Requests submitting `<svg>` or `<math>`-wrapped markup to fields that accept rich text.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
