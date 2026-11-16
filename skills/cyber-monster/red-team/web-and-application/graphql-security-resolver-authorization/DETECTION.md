# Detection Signals and Blue-Team Handoff

> Sub-skill: [`graphql-security-resolver-authorization`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Resolver audit logs where an object is returned without an ownership decision recorded for the caller.
- GraphQL requests where the object id or ownership argument does not belong to the authenticated principal.
- Access through the global `node(id:)` field to types normally reached by gated typed fields.
- Mutations carrying an `ownerId` or tenant field that differs from the session identity.
- Error-rate differences between typed-field and interface-type access to the same object.
- Two accounts retrieving the same object ids in alternation, consistent with BOLA testing.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
