# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-kerberos-attacks-asrep-roasting`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4768 with `PreAuthType 0` and `Status 0x0` for an account whose baseline `PreAuthType` is 2, the direct AS-REP signature.
- Windows Security 4768 with `Status 0x6` (`KDC_ERR_C_PRINCIPAL_UNKNOWN`) repeated across many usernames from one source, the username-enumeration pattern.
- Burst of 4768 events with `PreAuthType 0` across more than ten distinct accounts from one IP inside a minute.
- Network flow to TCP 88 from a host that never authenticates to any other service, the unauthenticated-request footprint.
- Kerberos client event 4 on the requesting host correlated with a non-standard parent process, where host telemetry exists.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) | Query authoring, triage logic, and hardening verification |
