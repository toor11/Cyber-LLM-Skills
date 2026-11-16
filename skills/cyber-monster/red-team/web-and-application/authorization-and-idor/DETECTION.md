# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authorization-and-idor`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- API gateway logs where one session id accesses object ids owned by many distinct users.
- Access logs showing 200 responses to /api/documents/{id} for ids outside the caller's historical set.
- Authorization middleware logs recording an authentication pass but no object-ownership check for the route.
- A session enumerating sequential object ids with steady 200 responses and a growing distinct-id count.
- Mutation verbs such as PATCH or DELETE succeeding on object ids the caller never created.
- GraphQL resolver logs where a node(id) query returns records across owner boundaries.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
