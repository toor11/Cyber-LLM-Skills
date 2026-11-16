# Detection Signals and Blue-Team Handoff

> Sub-skill: [`graphql-security`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- GraphQL access logs showing full `__schema` introspection queries from non-internal clients.
- Single requests containing many aliased fields or deeply nested selection sets.
- Query operation names or mutations in logs that the official client never issues.
- Resolver-level audit entries where an object is returned without an authorization decision recorded.
- Latency or resolver-count spikes on the `/graphql` route while request volume is flat.
- Error responses reconstructing the schema through field-suggestion messages.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
