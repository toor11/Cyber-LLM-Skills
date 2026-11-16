# Detection Signals and Blue-Team Handoff

> Sub-skill: [`credential-dumping-dpapi-and-secret-stores`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 1 for `mimikatz`, `SharpDPAPI` or a renamed equivalent with `dpapi::masterkey` in the command line.
- Windows Security 4663 for reads of files under `%APPDATA%\Microsoft\Protect` by a process other than the owning user's session.
- Windows Security 4688 for `cmdkey /list` from an unusual parent, which is the enumeration step before extraction.
- Sysmon event 11 for a copy of a master key file or `Credentials` directory to a temporary path.
- Directory service event 4662 for reads of `CN=BCKUPKEY` objects, which is the domain backup key extraction attempt.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) | Query authoring, triage logic, and hardening verification |
