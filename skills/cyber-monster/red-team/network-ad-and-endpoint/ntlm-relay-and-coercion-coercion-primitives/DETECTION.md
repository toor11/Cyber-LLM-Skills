# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ntlm-relay-and-coercion-coercion-primitives`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4624 logon type 3 with a machine account as `Subject` and a listener address as `Source Network Address`.
- RPC telemetry for `MS-RPRN`, `MS-EFSR`, `MS-DFSNM`, `MS-FSRVP` or `MS-EVEN` binds from a host that does not normally use them.
- Spooler operational log event 808 or 809 recording a change notification registration with a remote path.
- Windows Security 5145 on the listener host showing a machine account opening a share it has no reason to access.
- NTLM audit event 8001 or 8004 with `Target Name` equal to the listener, on a host that is being coerced.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
