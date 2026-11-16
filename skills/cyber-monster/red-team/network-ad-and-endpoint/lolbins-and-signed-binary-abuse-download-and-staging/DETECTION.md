# Detection Signals and Blue-Team Handoff

> Sub-skill: [`lolbins-and-signed-binary-abuse-download-and-staging`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon 1 for `certutil` or `bitsadmin` with a URL argument in `CommandLine`.
- Sysmon 11 for a file created by those binaries under a user-writable path, with the size in the event.
- Sysmon 22 for a DNS query from a binary whose baseline includes no network activity.
- Proxy logs for a `WebDAV` or `@SSL` request from a workstation, which does not normally use WebDAV.
- Sysmon 15 for the `Zone.Identifier` alternate data stream written on a downloaded file.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | Query authoring, triage logic, and hardening verification |
