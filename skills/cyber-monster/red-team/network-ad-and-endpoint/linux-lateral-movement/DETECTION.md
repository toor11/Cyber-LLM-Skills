# Detection Signals and Blue-Team Handoff

> Sub-skill: [`linux-lateral-movement`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- `/var/log/auth.log` or journald `sshd` entries with `Accepted publickey` and the key fingerprint, per source address.
- `sshd` entries for a key fingerprint used from an address that never used it before, the strongest movement signal.
- auditd watch on `~/.ssh/authorized_keys` for writes, which records any added key.
- `last` and `wtmp` records showing a login from a host that is not in the account's baseline.
- Sudden appearance of a new SSH key in a configuration management diff, which is the durable form of this technique.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
