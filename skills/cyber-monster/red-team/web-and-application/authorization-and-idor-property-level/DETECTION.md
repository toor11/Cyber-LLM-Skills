# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authorization-and-idor-property-level`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Update-endpoint request bodies containing fields such as role, is_admin, balance, or verified not present in the UI form.
- ORM audit logs showing a mass-assignment write to a privileged column from a self-service PATCH.
- A user's role or plan column changing with no corresponding admin action event.
- PATCH or PUT bodies with nested objects setting tenant_id or owner_id.
- Schema-validation rejections spiking on an update route after an allowlist is introduced.
- Response payloads exposing properties beyond the documented DTO for a resource.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
