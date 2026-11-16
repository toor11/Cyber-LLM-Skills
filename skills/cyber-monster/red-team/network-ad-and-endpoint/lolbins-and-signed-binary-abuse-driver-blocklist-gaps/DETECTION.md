# Detection Signals and Blue-Team Handoff

> Sub-skill: [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 6 for a driver load with `Signed: false` or a signature from an unexpected publisher.
- Code integrity event 3033 or 3077 for a driver rejected by the blocklist, which is the control working.
- Windows Security 4697 with `Service Type: kernel driver` and a path outside `System32\drivers`.
- Service Control Manager event 7045 for a kernel driver service installed, with the image path recorded.
- EDR telemetry for a process loading a driver from `%TEMP%` or a user profile, which is never legitimate.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | Query authoring, triage logic, and hardening verification |
