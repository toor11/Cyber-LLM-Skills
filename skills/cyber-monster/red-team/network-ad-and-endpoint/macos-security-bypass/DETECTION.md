# Detection Signals and Blue-Team Handoff

> Sub-skill: [`macos-security-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Unified log entries from `com.apple.syspolicy.exec` and `com.apple.securityd` for a launch that skipped assessment.
- MDM compliance drift for `spctl` and `csrutil` state, reported by the management agent.
- TCC database modification events, where endpoint telemetry monitors the database path.
- Launch agent or daemon creation in user or system library paths, visible to file integrity monitoring.
- Unified log for `tccd` denying or granting access, with the responsible process named.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
