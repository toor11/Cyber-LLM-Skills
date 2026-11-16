# Detection Signals and Blue-Team Handoff

> Sub-skill: [`xxe-oob-exfiltration`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- DNS queries from the application subnet for a low-reputation host whose subdomain encodes base32 or hex data.
- Outbound HTTP requests from the XML-parsing host carrying a query string that matches file-content patterns.
- Parser logs recording an external DTD fetch to a non-whitelisted URL during a request.
- Parser error events that contain file-system content folded into the message text.
- A spike in short-lived outbound connections from the parsing tier following an XML POST with no reflected response.
- Egress firewall entries showing the parser reaching an external host it has no documented dependency on.
- Repeated external DTD requests to the same assessor-shaped host within one session.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
