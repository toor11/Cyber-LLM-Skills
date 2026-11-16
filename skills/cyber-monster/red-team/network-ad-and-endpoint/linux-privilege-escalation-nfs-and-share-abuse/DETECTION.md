# Detection Signals and Blue-Team Handoff

> Sub-skill: [`linux-privilege-escalation-nfs-and-share-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- NFS server logs or `rpc.mountd` records showing a mount from a host outside the application range.
- File integrity monitoring on exported paths for new setuid files or ownership changes.
- auditd on the exported directory for `chmod` and `chown` events originating from an NFS client.
- `/var/log/messages` on the server for `nfsd` export option changes, which record a weakening.
- File creation events on the export with UID 0 from a client address outside the documented backup host.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) | Query authoring, triage logic, and hardening verification |
