# Detection Signals and Blue-Team Handoff

> Sub-skill: [`linux-privilege-escalation-sudo-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- auditd `execve` records where `auid` differs from `euid` and the binary is an interpreter, the sudo-to-shell sequence.
- `/var/log/auth.log` `sudo` entries with the full command line, which records the interpreter invocation.
- auditd watch on `/etc/sudoers.d` for a new file, the usual way a rule is added.
- `journalctl -t sudo` entries for a user whose baseline never uses sudo.
- Sudo version and CVE correlation on the host inventory, for the 2025 sudo chroot issue tracked as CVE-2025-32463.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) | Query authoring, triage logic, and hardening verification |
