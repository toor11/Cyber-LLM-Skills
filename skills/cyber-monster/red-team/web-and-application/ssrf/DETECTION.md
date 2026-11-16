# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssrf`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Egress firewall or VPC flow logs showing the application host connecting to 169.254.169.254, 127.0.0.0/8, or RFC1918 ranges it never contacted before.
- Outbound HTTP requests whose `User-Agent` matches the application's server-side client rather than any browser, arriving at an external host.
- Proxy logs where a permitted hostname is immediately followed by an internal address on the same request chain, indicating a followed redirect.
- DNS queries for a low-reputation host from the application subnet, especially repeated short-TTL lookups characteristic of rebinding.
- Requests to a URL-parameter route where the `url` value is a numeric, octal, or hex-encoded IPv4 literal.
- Connection attempts from the web tier to administrative ports (6379, 9200, 11211, 2375) that the tier has no documented dependency on.
- Application error logs containing internal hostnames or port numbers surfaced by a failed server-side fetch.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) | Detection queries, triage, and hardening for this technique |
