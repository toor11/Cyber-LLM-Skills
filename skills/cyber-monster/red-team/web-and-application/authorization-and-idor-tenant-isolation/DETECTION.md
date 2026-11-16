# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authorization-and-idor-tenant-isolation`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Requests where X-Org-Id or an org query parameter differs from the org bound to the credential.
- Cache logs serving a response with a tenant-agnostic cache key to sessions from different tenants.
- A bearer token whose org claim does not match the Host or subdomain it is presented on.
- Database query logs where org_id in the WHERE clause is sourced from request input.
- 200 responses to another tenant's resource ids under a single tenant's token.
- A single session touching a rising count of distinct org_id values.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
