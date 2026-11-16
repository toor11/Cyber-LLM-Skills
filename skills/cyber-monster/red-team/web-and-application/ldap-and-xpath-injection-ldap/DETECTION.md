# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ldap-and-xpath-injection-ldap`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- LDAP server access logs (OpenLDAP slapd or AD directory-service logs) where a search filter contains an unbalanced `(` or a bare `*` presence token from an application service account.
- Authentication logs showing a successful bind for a username field containing `)` or `|` characters.
- Application logs where a `uid` or `cn` request parameter includes `)(`, `*)(`, or a %00 byte sequence.
- A spike in directory search operations returning far more entries than the per-request historical median on a login or user-lookup route.
- Repeated searches incrementing a single attribute prefix (a*, b*, c*), characteristic of blind extraction.
- Directory error events for invalid-filter or protocol-error correlated with HTTP requests from one session.
- WAF rule hits for LDAP metacharacters followed by a 200 from the origin on the same route.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
