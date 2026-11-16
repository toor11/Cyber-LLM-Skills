# Detection Signals and Blue-Team Handoff

> Sub-skill: [`session-and-token-lifecycle-cookie-attribute-flaws`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Set-Cookie lines for the authentication cookie lacking the Secure attribute.
- Set-Cookie lines for the authentication cookie lacking HttpOnly.
- Set-Cookie lines with SameSite None or no SameSite attribute on the session cookie.
- Session cookies carrying a Domain attribute equal to a registrable parent domain.
- Session cookie names without a host-scoped or secure-scoped prefix in the Set-Cookie header.
- Cookie headers for the session observed on cleartext requests in access logs.
- Duplicate session cookie names arriving in one request, indicating subdomain or path shadowing.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
