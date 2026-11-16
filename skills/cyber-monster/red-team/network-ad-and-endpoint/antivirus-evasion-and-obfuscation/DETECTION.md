# Detection Signals and Blue-Team Handoff

> Sub-skill: [`antivirus-evasion-and-obfuscation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- PowerShell event 4104 with decoded content matching a known pattern, which is the durable post-obfuscation record.
- Defender operational event 1116 or 1117 for a detection and its remediation action, with the threat name.
- Sysmon event 1 with `-EncodedCommand` or `-e` followed by a long base64 argument.
- AMSI event 1116 in the Defender log when a script block is flagged, which records the decoded text.
- Windows Security 4688 with a script host parent and a child process, the decode-then-execute sequence.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
