# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ntlm-relay-and-coercion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4624 logon type 3 where `Workstation Name` is a computer account and `Source Network Address` is a different host, the relay signature.
- Windows Security 4625 with `Status 0xC000035B` or a signing-related failure on a target that rejects the relayed session.
- Windows Security 5145 on a file server for a session established from an unexpected address using a machine account.
- RPC interface binding events or EDR telemetry for `MS-RPRN`, `MS-EFSR`, `MS-DFSNM` and `MS-FSRVP` calls from non-management hosts.
- Domain controller Security 4742 or 5136 for computer or directory object changes immediately after a suspected relay, especially `msDS-AllowedToActOnBehalfOfOtherIdentity`.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
