# Detection Signals and Blue-Team Handoff

> Sub-skill: [`xxe-file-disclosure`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- XML request bodies containing `SYSTEM "file://` or `php://filter` on a parsing endpoint.
- Responses that include file-system content such as root: lines or configuration keys within an XML element.
- File-read audit events for /etc/passwd, /etc/hostname, or application config by the web service account.
- Parser logs recording external entity resolution during a request that returned reflected content.
- Requests where the same element alternates between a plain value and a DOCTYPE-bearing value from one session.
- A response-size increase on a parsing route correlated with a request body declaring a SYSTEM entity.
- php://filter or convert.base64-encode substrings appearing in web access or application logs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
