# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssrf-blind-ssrf`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- DNS query logs for low-reputation single-use subdomains originating from the application subnet.
- Egress connections from the application tier to external hosts with no corresponding user-facing feature.
- Outbound requests whose User-Agent matches the server-side HTTP client arriving at assessor or unknown infrastructure.
- Latency outliers on a fire-and-forget endpoint that correlate with specific destination parameters.
- Connection attempts from the web tier to sequential internal ports characteristic of a port-scan oracle.
- Repeated short-TTL lookups for the same base domain with varying subdomain labels.
- Application error counters staying flat while outbound connection counts rise, indicating swallowed blind fetches.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) | Detection queries, triage, and hardening for this technique |
