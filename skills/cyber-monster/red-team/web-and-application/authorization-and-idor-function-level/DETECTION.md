# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authorization-and-idor-function-level`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs where a low-privilege session receives 200 on /api/admin/* routes.
- Privileged verbs such as PUT or DELETE succeeding on admin endpoints for non-admin roles.
- Requests carrying X-HTTP-Method-Override or _method parameters on gated actions.
- Authorization logs showing an action allowed with only an authentication check and no role assertion.
- Admin function invocations with no corresponding role-grant event for the caller.
- A role's request pattern suddenly including endpoints absent from its normal baseline route set.
- Batch or multiplexed calls where the authorized route name and the executed route name differ.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
