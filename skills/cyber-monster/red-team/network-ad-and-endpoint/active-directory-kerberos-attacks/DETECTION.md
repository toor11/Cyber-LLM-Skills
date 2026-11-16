# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-kerberos-attacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4769 with `TicketEncryptionType` 0x17 and `ServiceName` not ending in `$`, excluding `krbtgt`.
- Windows Security 4768 with `PreAuthType` 0 for an account that normally uses pre-authentication, the AS-REP signature.
- Burst of more than five distinct SPNs requested by one account and one source IP inside five minutes, the enumeration pattern.
- Windows Security 4769 with `Status 0x0` and `TicketOptions` 0x40810000, a value strongly associated with tool-generated requests.
- Kerberos client events on the requesting host, event 4 or 7 in the Kerberos client log, correlated with a non-standard process.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) | Query authoring, triage logic, and hardening verification |
