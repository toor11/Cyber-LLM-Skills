# Detection Signals and Blue-Team Handoff

> Sub-skill: [`graphql-security-introspection-and-schema`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- POST bodies to `/graphql` containing `__schema` or `__type` meta-fields.
- Repeated near-miss field names from one client, consistent with suggestion-based reconstruction.
- Validation error responses containing did-you-mean field suggestions.
- Introspection queries originating from external IPs rather than internal tooling.
- A spike of distinct field names probed against the endpoint in a short window.
- Schema-dumping tool User-Agents (clairvoyance, graphql-cop) in access logs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
