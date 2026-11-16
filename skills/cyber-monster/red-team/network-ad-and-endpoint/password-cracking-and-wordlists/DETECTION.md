# Detection Signals and Blue-Team Handoff

> Sub-skill: [`password-cracking-and-wordlists`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4769 with RC4 encryption types in volume, the upstream event for any Kerberos ticket cracking.
- Windows Security 4768 with `PreAuthType 0` for pre-auth-disabled accounts, the AS-REP upstream event.
- Endpoint telemetry for GPU-accelerated hashcat on a corporate host, including driver installation events.
- Large outbound transfers from a host holding extracted hashes, where DLP or proxy logs record the destination.
- Process creation for `hashcat` or `john` with a wordlist path, where command-line auditing is enabled.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
