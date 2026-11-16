# Detection Signals and Blue-Team Handoff

> Sub-skill: [`defense-evasion-and-log-tampering-indicator-removal`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4699 for a task deleted, and 4698 for the matching creation, which shows the pair.
- Sysmon event 23 or 26 for file deletion and delete-logged events, where configured.
- Sysmon event 11 followed by a deletion of the same path within a short window, the stage-and-remove pattern.
- Windows Security 4688 with `wevtutil`, `vssadmin delete` or `fsutil usn deletejournal` in the command line.
- A host missing prefetch entries for binaries that other hosts recorded, the cross-host differential.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
