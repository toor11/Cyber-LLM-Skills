# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-privilege-escalation-uac-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 1 for a high-integrity process whose parent is `explorer.exe` or a COM surrogate rather than a user-initiated elevation.
- Windows Security 4688 with `Mandatory Label` recorded, showing a High-integrity child of a Medium-integrity parent.
- Windows Security 4672 for special privileges assigned to an account whose logon was not accompanied by a consent event.
- Registry change events for `ConsentPromptBehaviorAdmin` or `EnableLUA`, which record a policy weakening.
- Sysmon event 7 for a DLL loaded from a user-writable path by an auto-elevating binary.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) | Query authoring, triage logic, and hardening verification |
