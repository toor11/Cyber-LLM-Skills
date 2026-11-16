# Detection Signals and Blue-Team Handoff

> Sub-skill: [`linux-privilege-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- auditd rule on `execve` for setuid execution: `-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k suid_exec`.
- auditd watch on `/etc/sudoers` and `/etc/sudoers.d` for writes, which records any rule change.
- `/var/log/auth.log` or journald entries for `sudo` command lines, which show the interpreter invoked through a rule.
- auditd watch on `/etc/cron.d` and `/etc/systemd/system` for file creation, the persistence path.
- EDR or auditd record of `unshare`, `nsenter` or a `docker.sock` open, the container-escape precursor.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) | Query authoring, triage logic, and hardening verification |
