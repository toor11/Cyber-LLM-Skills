# Detection Signals and Blue-Team Handoff

> Sub-skill: [`host-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 13 for registry value writes under `Run`, `RunOnce` or `Winlogon`, with the target value in `Details`.
- Windows Security 4698 for a task created, and 4697 for a service installed, outside a change window.
- auditd watch on `/etc/systemd/system`, `/etc/cron.d` and `/etc/ld.so.preload` for writes.
- macOS unified log or an EDR record of a new plist in `/Library/LaunchDaemons` or `~/Library/LaunchAgents`.
- File integrity monitoring on autostart directories with a baseline comparison at every boot.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
