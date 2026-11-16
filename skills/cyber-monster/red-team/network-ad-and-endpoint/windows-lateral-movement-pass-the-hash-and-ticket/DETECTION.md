# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-lateral-movement-pass-the-hash-and-ticket`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4624 logon type 3 with `Authentication Package: NTLM` for a local account on a host where that account has no history.
- Windows Security 4776 for credential validation with `Package Name: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, which records NTLM validation attempts.
- NTLM audit event 8001 or 8002 with `Target Server` naming an internal host, part of the enhanced NTLM auditing surface.
- Windows Security 4768 and 4769 with unusual `TicketEncryptionType` values for an account whose baseline is AES only.
- Windows Security 4648 for explicit credential use, where a process supplies credentials different from the logged-on session.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
