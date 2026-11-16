# Detection Signals and Blue-Team Handoff

> Sub-skill: [`service-enumeration-ldap-and-directory`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Directory diagnostic event 1644 with an expensive or unindexed search, which is what anonymous one-level queries usually become.
- Domain controller Security 4625 with `Logon Type 3` and an empty or anonymous account immediately followed by LDAP bind traffic.
- Zeek `ldap` log with `baseObject: ''` and many sequential searches from one source.
- Network flow to TCP 389 from a subnet that should only use 636, the usual footprint of a plaintext directory probe.
- LDAP search filter containing `objectClass=*` at scope one with a large result count, visible in proxy or directory audit logs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
