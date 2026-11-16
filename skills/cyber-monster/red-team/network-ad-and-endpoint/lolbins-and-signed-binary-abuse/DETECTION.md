# Detection Signals and Blue-Team Handoff

> Sub-skill: [`lolbins-and-signed-binary-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 1 with `ParentImage` naming `explorer.exe` and `Image` naming `mshta.exe`, `rundll32.exe` or `regsvr32.exe`.
- Command lines containing `,#1`, `scrobj.dll`, `@SSL` or a URL passed to a signed binary.
- Sysmon event 22 for a DNS query from a signed binary that normally makes no network requests.
- Code integrity event 3077 when an enforced policy blocks a binary, which is the control working.
- `RunMRU` registry writes (Sysmon 13) with a LOLBin name or URL in `Details`.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | Query authoring, triage logic, and hardening verification |
