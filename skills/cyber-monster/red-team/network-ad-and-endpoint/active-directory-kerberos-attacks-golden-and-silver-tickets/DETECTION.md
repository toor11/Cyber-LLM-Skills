# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-kerberos-attacks-golden-and-silver-tickets`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4768 with `TicketEncryptionType` inconsistent with the account's `msDS-SupportedEncryptionTypes`, especially an RC4 TGT for an AES-only principal.
- Windows Security 4624 on a member server with `Authentication Package: Kerberos` and no corresponding 4769 on any DC in the same second window.
- Windows Security 4672 for a privileged logon by an account that has no matching 4768 in the preceding minutes.
- Directory service event 2079 or replication warnings around the krbtgt object, which accompany unauthorised key changes.
- Anomalous `EventRecordID` gaps or time skew in security logs on domain controllers, which can indicate log manipulation alongside ticket forgery.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) | Query authoring, triage logic, and hardening verification |
