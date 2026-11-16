# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authorization-and-idor-object-level`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs where sequential invoice or document ids are fetched in order by a single token.
- 200 responses to object ids whose owner_id differs from the authenticated subject in the app log.
- File-download routes serving object UUIDs that never appeared in the caller's own listings.
- A token's distinct-object-id count per minute exceeding its historical baseline.
- Batch or GraphQL node queries returning rows across multiple owner_ids in one response.
- Repeated 200 and 404 toggling characteristic of id enumeration from one session.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
