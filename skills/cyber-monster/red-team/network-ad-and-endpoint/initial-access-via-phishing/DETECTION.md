# Detection Signals and Blue-Team Handoff

> Sub-skill: [`initial-access-via-phishing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Mail gateway logs for a DMARC fail with `action=delivered`, which is the control failure itself.
- `RunMRU` registry write (Sysmon 13) with a URL or a LOLBin name in `Details`, the instruction-based lure footprint.
- Sysmon 1 for `mshta.exe` or `rundll32.exe` with `explorer.exe` as parent and no file argument.
- Proxy or DNS logs for a newly registered domain contacted by a small number of users in a short window.
- User report events from the mail add-in, which are the fastest reliable signal for a campaign in progress.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`email-security-monitoring`](../../../blue-team/detection-and-monitoring/email-security-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
