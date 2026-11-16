# Detection Signals and Blue-Team Handoff

> Sub-skill: [`defense-evasion-and-log-tampering-log-and-audit-evasion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4719 with the changed subcategory and new value, the primary policy-change record.
- Windows Security 4907 for a change to audit settings on an object, which records SACL edits.
- Windows Security 4906 for a change to the system audit policy, where the build emits it.
- `auditpol` execution in Sysmon event 1 with a `/set` argument, where command-line auditing is enabled.
- A host whose 4688 events lack a command line while peers include it, the cross-host differential.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
