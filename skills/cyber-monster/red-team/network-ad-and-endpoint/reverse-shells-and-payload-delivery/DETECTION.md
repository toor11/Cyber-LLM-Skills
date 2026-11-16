# Detection Signals and Blue-Team Handoff

> Sub-skill: [`reverse-shells-and-payload-delivery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 3 for a connection from `powershell.exe`, `cmd.exe` or `bash` to an external address.
- Sysmon event 1 with `ParentImage: explorer.exe` and a script host child, the instruction-delivery signature.
- Windows Security 4688 for a shell whose parent is an office application or a browser.
- Proxy logs for an outbound request from a process that normally makes none, correlated with 4688.
- Egress firewall deny logs for connections to unsanctioned destinations, which show the control working.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
