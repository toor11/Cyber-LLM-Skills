# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-privilege-escalation-token-and-privilege-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4672 with `Privileges` naming SeImpersonate or SeDebug for an account that normally lacks them.
- Sysmon event 10 for a process opening a SYSTEM-owned process with `PROCESS_DUP_HANDLE` or `PROCESS_QUERY_INFORMATION`.
- Windows Security 4688 for a shell spawned by a service account, where the parent is a service host process.
- Windows Security 4624 logon type 5 (service) or 8 (network cleartext) preceding the escalation, which records the token source.
- Named pipe creation events for the impersonation primitives, visible in Sysmon event 17 or 18.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) | Query authoring, triage logic, and hardening verification |
