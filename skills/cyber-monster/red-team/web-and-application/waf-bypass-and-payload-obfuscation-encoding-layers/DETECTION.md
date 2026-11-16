# Detection Signals and Blue-Team Handoff

> Sub-skill: [`waf-bypass-and-payload-obfuscation-encoding-layers`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- WAF audit events where a rule id fires on a plaintext request but the same route returns origin 200 for a double percent-encoded variant within one session.
- Access logs containing `%25`, `%u00`, or `%c0%` sequences in the query string or path that resolve to a 200 at the origin.
- Origin application logs containing a decoded payload string that never appeared in the upstream WAF request log for the same request id.
- Requests whose `Content-Type` or charset parameter differs from the application's expected encoding, correlated with a drop in WAF rule hits.
- A spike in NFKC-foldable (full-width or compatibility) code points in request parameters recorded by the application framework.
- Reverse-proxy and origin logs disagreeing on the decoded path for the same `X-Request-Id`.
- Repeated requests to one parameter cycling through URL, double-URL, hex, and base64 forms of a single token.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
