# Detection Signals and Blue-Team Handoff

> Sub-skill: [`linux-privilege-escalation-suid-and-capabilities`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Auditd `chmod` and `chown` records for a change to a setuid bit: `-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k suid_change`.
- `setcap` invocation in auditd `execve` records, the way a capability is added.
- File integrity monitoring alerts on `/usr/local/bin` and `/usr/bin` for mode or checksum changes.
- auditd `execve` where `euid` is 0 and `auid` is a normal user for a binary outside the documented setuid list.
- Package verification failures from `dpkg -V` or `rpm -Va` reported to the configuration management system.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) | Query authoring, triage logic, and hardening verification |
