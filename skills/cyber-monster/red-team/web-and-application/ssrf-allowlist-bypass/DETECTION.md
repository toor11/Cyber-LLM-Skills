# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssrf-allowlist-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Egress flow logs showing the application host connecting to RFC1918 or loopback ranges right after an inbound request carrying a url parameter.
- DNS resolver logs with repeated short-TTL lookups for the same hostname from the application subnet.
- Proxy logs where an allowed hostname is followed on the same chain by an internal address, indicating a followed redirect.
- url parameters containing decimal, octal, hex, or bracketed IPv6 literals.
- URLs with a userinfo `@` segment where the authority after the @ is an internal host.
- A single hostname resolving to a public address at validation time and a private address at fetch time.
- Outbound requests whose User-Agent matches the server-side HTTP client rather than any browser.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) | Detection queries, triage, and hardening for this technique |
