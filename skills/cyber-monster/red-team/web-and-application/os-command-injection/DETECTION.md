# Detection Signals and Blue-Team Handoff

> Sub-skill: [`os-command-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Process-creation events (Sysmon Event ID 1 or auditd execve) where a web or app service account spawns sh, bash, or cmd.exe.
- Command lines logged by the application that contain request-derived values alongside separators such as ; | && or $( .
- Child processes like id, whoami, ping, or nslookup parented by the application worker process.
- Outbound DNS or HTTP from the application host immediately after a request to a command-backed route.
- A 500-to-200 transition on one route correlated with separator characters in the request parameters.
- EDR alerts for interpreter spawns whose parent is a long-running web server process.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | Detection queries, triage, and hardening for this technique |
