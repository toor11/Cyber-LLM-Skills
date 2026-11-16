# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-enumeration-gpo-and-administrative-discovery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 5136 for a modified `groupPolicyContainer` object, with `Attribute Value` naming the changed `gplink` or `versionNumber`.
- Windows Security 4662 for `WriteProperty` on `CN=Policies,CN=System` from a non-tier-0 account.
- File system auditing on `SYSVOL\Policies` event 4663 for write access by an unexpected principal.
- Group Policy operational log 4016 or 5016 recording policy processing failure across many hosts at once, which often accompanies a malicious edit.
- Security 4728 or 4732 for a member added to a privileged group following a GPO change, the downstream effect of a `Restricted Groups` edit.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
