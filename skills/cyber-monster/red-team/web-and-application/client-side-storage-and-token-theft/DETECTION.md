# Detection Signals and Blue-Team Handoff

> Sub-skill: [`client-side-storage-and-token-theft`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Authentication events replaying a bearer token from an IP or device fingerprint different from where it was issued.
- Access tokens accepted after the issuing session's logout event.
- Error or CSP reports showing script reads of `localStorage` or `document.cookie` followed by an outbound request to an external host.
- Set-Cookie headers for session cookies missing the `HttpOnly` attribute.
- Static-asset scans finding JWT- or key-shaped strings in deployed JavaScript bundles.
- Repeated use of one access token across many client fingerprints, consistent with a lifted credential.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
