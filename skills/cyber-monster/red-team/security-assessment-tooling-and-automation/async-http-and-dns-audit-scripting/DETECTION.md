# Detection Signals and Blue-Team Handoff

> Sub-skill: [`async-http-and-dns-audit-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Web server access logs with a single source address and a near-constant inter-request interval per host: the semaphore signature.
- A high ratio of 404/403 to 200 on one virtual host within a short window, characteristic of content discovery rather than user traffic.
- DNS query logs showing sequential label enumeration against one zone from one resolver address.
- Proxy or WAF events tagged as automated client by user-agent plus request cadence.
- `httpx`/`aiohttp` user-agent strings in the request log where the application expects a browser.
- TLS handshakes with no session resumption from the same client, repeated across many SNI values.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
