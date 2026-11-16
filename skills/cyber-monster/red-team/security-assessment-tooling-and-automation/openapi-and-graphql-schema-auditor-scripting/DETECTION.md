# Detection Signals and Blue-Team Handoff

> Sub-skill: [`openapi-and-graphql-schema-auditor-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Introspection queries (`__schema`, `__type`) in GraphQL server logs from a client that never queries data.
- Sequential credentialed and uncredentialed requests to the same operation within seconds.
- Fetches of `openapi.json`, `swagger.json`, or `/.well-known/` paths from a single address.
- A client enumerating operation ids at a constant rate, visible as uniform request spacing across paths.
- 401/403 followed by 200 on the same path from one source address, characteristic of an auth-differential probe.
- GraphQL requests with deeply nested selection sets exceeding the application's normal depth.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
