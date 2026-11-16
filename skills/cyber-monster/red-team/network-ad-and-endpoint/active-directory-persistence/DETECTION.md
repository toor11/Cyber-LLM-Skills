# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4739 for domain policy change, and 4742 for a computer or user object change, around an unexpected SID history addition.
- Windows Security 5136 for a modified `sIDHistory` or `msDS-KeyVersionNumber` attribute, with the new value in `Attribute Value`.
- Directory service event 2079 or replication warnings around the krbtgt object outside a planned rotation.
- Windows Security 4662 for `Replicating Directory Changes All` used by a principal that is not a domain controller.
- Certificate services event 4886 for issuance from a template that is not part of the standard enrollment profile.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
