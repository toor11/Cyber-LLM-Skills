# Detection Signals and Blue-Team Handoff

> Sub-skill: [`lolbins-and-signed-binary-abuse-execution-proxies`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 1 with `ParentImage: explorer.exe` and `Image` ending in `mshta.exe`.
- Command line containing `,#1`, `scrobj.dll` or `/i:http`, the three proxy-pairing markers.
- Sysmon event 7 for a DLL loaded by `rundll32.exe` from a user-writable directory.
- Code integrity event 3077 for a blocked proxy invocation, which is the enforced-policy counterpart.
- Sysmon event 3 for a network connection from `mshta.exe`, `regsvr32.exe` or `installutil.exe`.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | Query authoring, triage logic, and hardening verification |
