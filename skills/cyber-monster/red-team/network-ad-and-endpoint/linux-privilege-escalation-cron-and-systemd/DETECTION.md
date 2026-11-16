# Detection Signals and Blue-Team Handoff

> Sub-skill: [`linux-privilege-escalation-cron-and-systemd`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- auditd watch on `/etc/cron.d`, `/var/spool/cron` and `/etc/systemd/system` for `wa` events, which records any job change.
- auditd `execve` records for jobs whose `auid` differs from the cron owner, which indicates a modified job.
- systemd journal entries for a unit reload or start immediately after a file change in the unit directory.
- File integrity monitoring alerts on `/etc/cron*` and `/etc/systemd/system`.
- auditd watch on `/usr/local/sbin` and deployment directories for writes by a non-root user.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) | Query authoring, triage logic, and hardening verification |
