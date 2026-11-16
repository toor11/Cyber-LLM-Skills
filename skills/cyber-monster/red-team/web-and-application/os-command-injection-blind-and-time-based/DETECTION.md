# Detection Signals and Blue-Team Handoff

> Sub-skill: [`os-command-injection-blind-and-time-based`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Response-latency outliers on one route that correlate with sleep or ping tokens in the request parameters.
- DNS queries from the application host for low-reputation hostnames that embed command-like or encoded labels.
- Outbound HTTP callbacks from the app tier to an unfamiliar host shortly after a request to a command-backed route.
- ping, sleep, nslookup, or curl child processes parented by the web worker with no corresponding feature need.
- Repeated requests to the same parameter with incrementing numeric values matching a timing-probe pattern.
- auditd execve records for timing utilities invoked by the service account.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`fileless-and-living-off-the-land-detection`](../../../blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | Detection queries, triage, and hardening for this technique |
