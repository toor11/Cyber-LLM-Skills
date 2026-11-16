# Detection Signals and Blue-Team Handoff

> Sub-skill: [`macos-security-bypass-tcc-and-privacy-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- `tccd` unified log entries for a grant or denial, with the responsible process and service name.
- MDM privacy preference payload reports, which show grants deployed versus effective.
- File integrity monitoring on the TCC database path, where the platform permits it.
- Processes reading protected paths such as `~/Library/Mail` or `~/Library/Messages` without a recorded grant.
- Endpoint telemetry for a terminal emulator spawning a process that reads a protected path.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
