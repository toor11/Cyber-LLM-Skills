# Detection Signals and Blue-Team Handoff

> Sub-skill: [`rest-and-grpc-api-security`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- API gateway logs where a user token reads object ids outside its owned set.
- 200 responses on PATCH or PUT whose body contains role, isAdmin, or owner_id fields not in the API schema.
- Responses whose payload field count exceeds the documented DTO for the route.
- X-HTTP-Method-Override headers arriving at the API tier.
- Calls to grpc.reflection.v1alpha.ServerReflection from non-administrative clients.
- A per-object shift in the 403-to-200 ratio indicating id enumeration.
- Content-type mismatches between the declared type and the parser that handled the body.
- Batch requests where a subrequest status does not match the same route called alone.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
