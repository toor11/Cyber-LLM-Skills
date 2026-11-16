# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-kerberos-attacks-kerberoasting`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4769 with `TicketEncryptionType 0x17`, `ServiceName` not ending in `$`, and `ServiceName` not `krbtgt`.
- More than five distinct `ServiceName` values for one `TargetUserName` inside five minutes, the enumeration signature.
- Windows Security 4769 with `TicketOptions 0x40810000`, a request shape associated with tooling rather than normal service access.
- Sysmon event 1 for a process whose command line contains `kerberoast` or a collector name, where Sysmon is deployed on the requesting host.
- Correlation of a 4769 burst with an outbound connection from the same host to a non-standard destination, indicating ticket exfiltration for offline work.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) | Query authoring, triage logic, and hardening verification |
