# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-privilege-escalation-kernel-and-driver-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 6 for a driver load, with `Signed` and `Signature` fields naming the signer and validity.
- Code integrity event 3033 or 3077 for a driver that failed the blocklist or signature check.
- Windows Security 4697 for a service installed with a kernel driver type, which records the binary path.
- Service Control Manager event 7045 with `Service Type: kernel driver` and a path outside `System32\drivers`.
- App Control or WDAC event 3077 recording a blocklisted driver hash, the control working as intended.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) | Query authoring, triage logic, and hardening verification |
