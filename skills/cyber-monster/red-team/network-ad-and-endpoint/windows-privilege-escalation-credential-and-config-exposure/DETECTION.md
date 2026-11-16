# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-privilege-escalation-credential-and-config-exposure`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- File access auditing event 4663 on `unattend.xml` or SYSVOL policy files by a principal that does not deploy images.
- Sysmon event 11 for a copy of an unattend or policy file to a user-writable location.
- Windows Security 4624 logon type 2 or 10 using the local account named in an exposed unattend file shortly after file access.
- Windows Security 4662 for reads of the SYSVOL policy container by a non-administrative account.
- Proxy or DLP alert on base64 blobs matching the unattend password element leaving the estate.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) | Query authoring, triage logic, and hardening verification |
