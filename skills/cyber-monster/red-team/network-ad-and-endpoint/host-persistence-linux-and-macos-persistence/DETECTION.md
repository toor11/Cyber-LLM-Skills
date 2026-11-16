# Detection Signals and Blue-Team Handoff

> Sub-skill: [`host-persistence-linux-and-macos-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- auditd watch on `/etc/systemd/system`, `/etc/ld.so.preload` and `/etc/cron.d` for `wa` events.
- File integrity monitoring on `/Library/LaunchDaemons`, `/Library/LaunchAgents` and `/etc/periodic` for new plists.
- macOS unified log entries for `launchd` service load with a path outside `/System` or `/usr/libexec`.
- systemd journal entries for a unit start whose unit file was modified after the last daemon-reload.
- auditd `execve` for a process whose `exe` is under a home directory and whose parent is PID 1 or `systemd`.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
